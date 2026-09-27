"""DB backup engine — automated SQLite/MySQL backups with retention.

Provides scheduled database backups using the same threading.Timer pattern
as the fleet and retention reapers. Supports both SQLite (via sqlite3
backup API) and MySQL (via mysqldump with gzip compression).
"""

import gzip
import logging
import os
import subprocess
import threading
import time
from datetime import datetime

from app.models import get_db, get_setting, set_setting
from app.worker_locks import singleton as _singleton_lock

logger = logging.getLogger(__name__)

DEFAULT_BACKUP_DIR = "/var/lib/vespid-server/backups"
DEFAULT_INTERVAL_HOURS = 24
DEFAULT_RETENTION_DAYS = 7
BACKUP_PREFIX = "vespid-backup"


# ── Helpers ─────────────────────────────────────────────────────────────


def _ensure_backup_dir(directory: str) -> None:
    os.makedirs(directory, exist_ok=True)


def _backup_filename(prefix: str, ext: str) -> str:
    ts = datetime.now().strftime("%Y-%m-%d-%H%M%S")
    return f"{prefix}-{ts}.{ext}"


def _format_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1048576:
        return f"{size_bytes / 1024:.1f} KB"
    if size_bytes < 1073741824:
        return f"{size_bytes / 1048576:.1f} MB"
    return f"{size_bytes / 1073741824:.2f} GB"


# ── Core backup logic ───────────────────────────────────────────────────


def perform_backup(db_config, backup_dir: str) -> str | None:
    """Create a consistent database backup.

    For SQLite: uses sqlite3's ``.backup()`` API (safe during writes).
    For MySQL:  shells out to ``mysqldump`` with --single-transaction
                and compresses output with gzip.

    Returns the absolute path to the backup file, or *None* on failure.
    """
    _ensure_backup_dir(backup_dir)
    db_type = (
        db_config.get("DATABASE_TYPE", db_config.get("type", "sqlite")).lower()
        if isinstance(db_config, dict)
        else "sqlite"
    )

    if db_type in ("mysql", "mariadb"):
        return _backup_mysql(db_config, backup_dir)
    return _backup_sqlite(db_config, backup_dir)


def _backup_sqlite(db_path: str, backup_dir: str) -> str | None:
    import sqlite3

    filename = _backup_filename(BACKUP_PREFIX, "db")
    dest = os.path.join(backup_dir, filename)

    try:
        src = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        dst = sqlite3.connect(dest)
        src.backup(dst)
        dst.close()
        src.close()
        logger.info("SQLite backup created: %s (%s)", dest, _format_size(os.path.getsize(dest)))
        return dest
    except Exception:
        logger.exception("SQLite backup failed")
        if os.path.exists(dest):
            try:
                os.remove(dest)
            except OSError:
                pass
        return None


def _backup_mysql(db_config: dict, backup_dir: str) -> str | None:
    filename = _backup_filename(BACKUP_PREFIX, "sql.gz")
    dest = os.path.join(backup_dir, filename)

    try:
        env = os.environ.copy()
        if db_config.get("DATABASE_PASSWORD"):
            env["MYSQL_PWD"] = db_config["DATABASE_PASSWORD"]

        cmd = [
            "mysqldump",
            "--host",
            db_config.get("DATABASE_HOST", "localhost"),
            "--port",
            str(db_config.get("DATABASE_PORT", 3306)),
            "--user",
            db_config.get("DATABASE_USER", "vespid"),
            "--single-transaction",
            "--routines",
            "--triggers",
            "--skip-lock-tables",
            db_config.get("DATABASE_NAME", "vespid"),
        ]

        proc = subprocess.run(cmd, capture_output=True, text=True, env=env, timeout=300)
        if proc.returncode != 0:
            logger.error("mysqldump stderr: %s", proc.stderr[:500])
            return None

        with gzip.open(dest, "wt", encoding="utf-8") as f:
            f.write(proc.stdout)

        logger.info("MySQL backup created: %s (%s)", dest, _format_size(os.path.getsize(dest)))
        return dest
    except FileNotFoundError:
        logger.error("mysqldump not found — mysql-client package required for MySQL backups")
        return None
    except Exception:
        logger.exception("MySQL backup failed")
        if os.path.exists(dest):
            try:
                os.remove(dest)
            except OSError:
                pass
        return None


# ── Retention ───────────────────────────────────────────────────────────


def purge_old_backups(backup_dir: str, retention_days: int) -> int:
    """Delete backup files older than *retention_days*.

    Returns the number of files purged.
    """
    if not os.path.isdir(backup_dir):
        return 0

    cutoff = time.time() - (retention_days * 86400)
    purged = 0

    try:
        for entry in os.scandir(backup_dir):
            if not entry.is_file() or not entry.name.startswith(BACKUP_PREFIX):
                continue
            if entry.stat().st_mtime < cutoff:
                os.remove(entry.path)
                logger.info("Purged old backup: %s", entry.name)
                purged += 1
    except OSError:
        logger.exception("Error purging old backups")

    if purged:
        logger.info("Backup retention: purged %d file(s)", purged)
    return purged


# ── File listing ────────────────────────────────────────────────────────


def get_backup_list(backup_dir: str) -> list[dict]:
    """Return a list of existing backup files with metadata.

    Each dict has keys: ``filename``, ``size`` (bytes), ``mtime`` (unix
    timestamp), ``size_display``.
    """
    backups: list[dict] = []
    if not os.path.isdir(backup_dir):
        return backups

    try:
        for entry in os.scandir(backup_dir):
            if not entry.is_file() or not entry.name.startswith(BACKUP_PREFIX):
                continue
            stat = entry.stat()
            backups.append(
                {
                    "filename": entry.name,
                    "size": stat.st_size,
                    "size_display": _format_size(stat.st_size),
                    "mtime": stat.st_mtime,
                }
            )
    except OSError:
        pass

    backups.sort(key=lambda b: b["mtime"], reverse=True)
    return backups


# ── Scheduler (threading.Timer pattern) ─────────────────────────────────


@_singleton_lock("backup_reaper")
def start_backup_reaper(application, db_config):
    """Start the periodic backup timer (one-shot then recurring).

    Called once per worker process via ``post_fork`` (gunicorn) or
    directly at startup in dev mode.  Follows the same ``threading.Timer``
    recursive pattern used by the fleet and retention reapers.

    Uses a cross-worker singleton flock so only one worker runs the
    backup loop; when that worker is recycled the kernel releases the
    lock and a replacement worker picks it up.

    Settings are re-read from ``app_settings`` on each cycle so that
    interval / enabled / retention changes take effect without a restart.

    On startup, checks the most recent backup file to avoid creating a
    duplicate backup after restarts. If a backup already exists within the
    current interval window, the first run is deferred to the next due time.
    """
    if getattr(application, "_backup_reaper_started", False):
        return
    application._backup_reaper_started = True

    default_dir = application.config.get("BACKUP_DIRECTORY", DEFAULT_BACKUP_DIR)

    def _next_backup_delay(backup_dir: str, interval_hours: int) -> float:
        """Calculate the delay until the next backup should run.

        Scans existing backup files and computes how long to wait so that
        backups stay on the configured interval regardless of restarts.
        Returns seconds.
        """
        interval_seconds = max(3600, interval_hours * 3600)
        most_recent = 0.0

        if os.path.isdir(backup_dir):
            try:
                for entry in os.scandir(backup_dir):
                    if not entry.is_file() or not entry.name.startswith(BACKUP_PREFIX):
                        continue
                    most_recent = max(most_recent, entry.stat().st_mtime)
            except OSError:
                pass

        if most_recent == 0.0:
            return 120  # no backups yet, run soon

        elapsed = time.time() - most_recent
        remaining = interval_seconds - elapsed
        if remaining <= 0:
            return 120  # overdue, run soon
        return remaining

    # Compute initial delay based on existing backups
    try:
        db = get_db(db_config)
        backup_dir = get_setting(db, "backup_directory", default_dir)
        interval_hours = int(get_setting(db, "backup_interval_hours", str(DEFAULT_INTERVAL_HOURS)))
        db.close()
        initial_delay = _next_backup_delay(backup_dir, interval_hours)
    except Exception:
        initial_delay = 120

    def _backup_cycle():
        logger.debug("Backup reaper cycle starting")
        try:
            db = get_db(db_config)
            enabled = get_setting(db, "backup_enabled", "false").lower() in ("true", "1", "yes")
            retention_days = int(
                get_setting(db, "backup_retention_days", str(DEFAULT_RETENTION_DAYS))
            )
            backup_dir = get_setting(db, "backup_directory", default_dir)
            db.close()

            if not enabled:
                logger.debug("Backup reaper: backups disabled, skipping cycle")
            else:
                result = perform_backup(db_config, backup_dir)
                if result:
                    now = datetime.now().isoformat()
                    db2 = get_db(db_config)
                    set_setting(db2, "backup_last_run", now)
                    db2.close()
                purge_old_backups(backup_dir, retention_days)

        except Exception:
            logger.exception("Backup reaper encountered an error")

        # Re-read interval each cycle so settings changes take effect
        try:
            db3 = get_db(db_config)
            next_interval_hours = int(
                get_setting(db3, "backup_interval_hours", str(DEFAULT_INTERVAL_HOURS))
            )
            db3.close()
            next_interval = max(3600, next_interval_hours * 3600)
        except Exception:
            next_interval = DEFAULT_INTERVAL_HOURS * 3600

        timer = threading.Timer(next_interval, _backup_cycle)
        timer.daemon = True
        timer.start()
        next_at = datetime.now().timestamp() + next_interval
        next_at_str = datetime.fromtimestamp(next_at).replace(microsecond=0).isoformat()
        logger.info("Next backup scheduled at %s (in %.1fh)", next_at_str, next_interval / 3600)

    timer = threading.Timer(initial_delay, _backup_cycle)
    timer.daemon = True
    timer.start()
    next_at = datetime.now().timestamp() + initial_delay
    next_at_str = datetime.fromtimestamp(next_at).replace(microsecond=0).isoformat()
    logger.info("First backup scheduled at %s (in %.1fh)", next_at_str, initial_delay / 3600)
