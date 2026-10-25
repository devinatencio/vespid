#!/usr/bin/env python3
"""Repair IP Intelligence block episode counters.

Background
----------
Episode detection used to compare ``last_unblocked_at`` against
``last_blocked_at``. The propagation engine also wrote ``last_blocked_at``
using "now" whenever it created a fleet block, and it runs before the intel
ingest loop. A genuine re-block therefore looked like a continuation of the
previous episode and ``block_episode_count`` was never incremented.

The code fix adds ``ip_intel.last_episode_block_at``, which is advanced only
by the intel upsert path, and compares against that instead. This script
repairs the historical data:

    1. Backfills ``last_episode_block_at`` from the most recent block event
       (or ``last_blocked_at`` when no event history exists).
    2. Recomputes a conservative (never-decreasing) ``block_episode_count``
       from the known block/unblock history.
    3. Promotes corrected repeat offenders and sets ``repeat_offender_since``.

The recomputation is a lower bound: unblock events may have been pruned from
the ``events`` / ``audit_log`` retention windows, so older episodes cannot
always be recovered. The script never decreases an existing counter.

Usage
-----
    # SQLite (default):
    python repair_block_episodes.py --db /path/to/vespid.db

    # MySQL/MariaDB (uses the server config file):
    python repair_block_episodes.py --config /etc/vespid-server/config.yaml

    # Preview without writing:
    python repair_block_episodes.py --db /path/to/vespid.db --dry-run
"""

import argparse
import logging
import sys
from collections import defaultdict
from datetime import UTC, datetime

# Ensure the app package is importable when run from the repo root
sys.path.insert(0, ".")

from app.config import load_config
from app.intel_models import parse_timestamp
from app.models import get_db

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = "/var/lib/vespid-server/vespid.db"

# Unblock sources can report the same transition a few seconds apart.
_UNBLOCK_DEDUPE_SECONDS = 60


def _row_get(row, key, index=0):
    """Read a column from a sqlite3.Row, dict-like row, or plain tuple."""
    if row is None:
        return None
    try:
        return row[key]
    except (KeyError, IndexError, TypeError):
        return row[index]


def _table_exists(conn, name: str) -> bool:
    """Return True when a table exists and is queryable.

    Fully consumes and closes the probe cursor. MySQL's connector refuses to
    open a new cursor while a previous result is still unread.
    """
    try:
        cursor = conn.execute(f"SELECT 1 FROM {name} LIMIT 1")
        try:
            cursor.fetchall()
        finally:
            cursor.close()
        return True
    except Exception:
        return False


def _to_datetime(value):
    """Parse a database timestamp (datetime or string) into UTC datetime."""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=UTC)
        return value.astimezone(UTC)
    return parse_timestamp(value)


def _format_ts(value) -> str | None:
    """Format a datetime/string as the canonical intel timestamp string."""
    dt = _to_datetime(value)
    return dt.strftime("%Y-%m-%d %H:%M:%S") if dt else None


def _merge_datetimes(values, tolerance_seconds: int = _UNBLOCK_DEDUPE_SECONDS):
    """Sort datetimes and collapse duplicates within the tolerance window."""
    parsed = sorted(v for v in (_to_datetime(x) for x in values) if v is not None)
    merged = []
    for dt in parsed:
        if not merged or (dt - merged[-1]).total_seconds() > tolerance_seconds:
            merged.append(dt)
    return merged


def _episode_starts(block_times, unblock_times):
    """Return the block timestamps that begin a new blocking episode.

    ``block_times`` and ``unblock_times`` are iterables of UTC datetimes.
    The first block starts episode 1; each block that follows an unblock
    starts another episode. Blocks while already blocked are part of the
    current episode.
    """
    events = [(dt, 0) for dt in unblock_times] + [(dt, 1) for dt in block_times]
    # Unblocks sort before blocks at the same instant so block → unblock →
    # block sequences are handled deterministically.
    events.sort(key=lambda item: (item[0], item[1]))

    starts = []
    blocked = False
    pending_unblock = False
    for ts, kind in events:
        if kind == 1:  # block
            if not blocked or pending_unblock:
                starts.append(ts)
            blocked = True
            pending_unblock = False
        else:  # unblock
            if blocked:
                pending_unblock = True
                blocked = False
    return starts


def _compute_expected_episodes(block_times, unblock_times, repeat_offender_since=None):
    """Compute a conservative episode count from the available history.

    The result is never lower than the existing counter's logical minimum,
    and uses ``repeat_offender_since`` as an anchor when older unblocks
    have been pruned: that timestamp proves the IP already had two
    episodes, so every later unblock → block transition adds another.
    """
    block_times = sorted(block_times)
    unblock_times = _merge_datetimes(unblock_times)
    if not block_times:
        return 0, []

    starts = _episode_starts(block_times, unblock_times)
    anchor = _to_datetime(repeat_offender_since)
    if anchor is not None:
        base = 2
    else:
        base = 1
        anchor = block_times[0]

    extra = sum(1 for start in starts if start > anchor)
    return max(len(starts), base + extra), starts


def _load_block_times(conn):
    """Load block event timestamps grouped by IP address."""
    block_times = defaultdict(list)
    rows = conn.execute(
        "SELECT ip_address, timestamp FROM ip_intel_events "
        "WHERE event_kind = 'block' ORDER BY ip_address, timestamp"
    ).fetchall()
    for row in rows:
        ip = _row_get(row, "ip_address", 0)
        dt = _to_datetime(_row_get(row, "timestamp", 1))
        if ip and dt is not None:
            block_times[ip].append(dt)
    return block_times


def _load_unblock_times(conn):
    """Load unblock timestamps from every available lifecycle source."""
    unblock_times = defaultdict(list)

    if _table_exists(conn, "events"):
        try:
            rows = conn.execute(
                "SELECT source_ip, timestamp FROM events "
                "WHERE UPPER(action_taken) = 'UNBLOCKED'"
            ).fetchall()
            for row in rows:
                ip = _row_get(row, "source_ip", 0)
                dt = _to_datetime(_row_get(row, "timestamp", 1))
                if ip and dt is not None:
                    unblock_times[ip].append(dt)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Could not read unblock events: %s", exc)

    if _table_exists(conn, "audit_log"):
        try:
            rows = conn.execute(
                "SELECT target, timestamp FROM audit_log "
                "WHERE action_type IN ('fleet_block_expired', 'fleet_block_manual_remove')"
            ).fetchall()
            for row in rows:
                ip = _row_get(row, "target", 0)
                dt = _to_datetime(_row_get(row, "timestamp", 1))
                if ip and dt is not None:
                    unblock_times[ip].append(dt)
        except Exception as exc:  # pragma: no cover - defensive
            logger.warning("Could not read unblock audit rows: %s", exc)

    return unblock_times


def repair(conn, dry_run: bool = False) -> dict:
    """Repair episode counters and return a summary dict.

    Only ever increases ``block_episode_count``. Safe to run repeatedly.
    """
    block_times_by_ip = _load_block_times(conn)
    unblock_times_by_ip = _load_unblock_times(conn)

    rows = conn.execute(
        "SELECT ip_address, block_episode_count, repeat_offender, "
        "repeat_offender_since, last_blocked_at, last_episode_block_at, "
        "last_unblocked_at FROM ip_intel"
    ).fetchall()

    stats = {
        "scanned": 0,
        "counts_changed": 0,
        "repeat_offenders_set": 0,
        "episode_anchor_backfilled": 0,
        "unchanged": 0,
        "dry_run": dry_run,
    }
    samples = []

    for row in rows:
        stats["scanned"] += 1
        ip = _row_get(row, "ip_address", 0)
        if not ip:
            continue

        current_count = _row_get(row, "block_episode_count", 1) or 0
        current_flag = _row_get(row, "repeat_offender", 2) or 0
        current_ros = _row_get(row, "repeat_offender_since", 3)
        last_blocked_at = _row_get(row, "last_blocked_at", 4)
        last_episode_block_at = _row_get(row, "last_episode_block_at", 5)
        last_unblocked_at = _row_get(row, "last_unblocked_at", 6)

        block_times = list(block_times_by_ip.get(ip, []))
        if not block_times and last_blocked_at:
            fallback = _to_datetime(last_blocked_at)
            if fallback is not None:
                block_times = [fallback]

        unblocks = list(unblock_times_by_ip.get(ip, []))
        if last_unblocked_at:
            unblocks.append(last_unblocked_at)

        expected, starts = _compute_expected_episodes(
            block_times, unblocks, current_ros
        )
        if not block_times:
            # No block history at all — leave counters untouched.
            stats["unchanged"] += 1
            continue

        new_count = max(current_count, expected)
        new_flag = 1 if new_count >= 2 else 0

        new_ros = current_ros
        if new_flag and not current_flag:
            if len(starts) >= 2:
                new_ros = _format_ts(starts[1])
            elif block_times:
                new_ros = _format_ts(min(block_times))

        latest_block = max(block_times)
        existing_anchor = _to_datetime(last_episode_block_at)
        new_anchor = last_episode_block_at
        if existing_anchor is None or latest_block > existing_anchor:
            new_anchor = _format_ts(latest_block)

        count_changed = new_count != current_count
        flag_changed = new_flag != current_flag
        anchor_changed = new_anchor != last_episode_block_at

        if count_changed or flag_changed or anchor_changed:
            if count_changed:
                stats["counts_changed"] += 1
            if flag_changed and new_flag:
                stats["repeat_offenders_set"] += 1
            if anchor_changed:
                stats["episode_anchor_backfilled"] += 1

            if len(samples) < 20:
                samples.append(
                    {
                        "ip_address": ip,
                        "block_episode_count": (current_count, new_count),
                        "repeat_offender": (current_flag, new_flag),
                        "last_episode_block_at": (last_episode_block_at, new_anchor),
                    }
                )

            if not dry_run:
                conn.execute(
                    "UPDATE ip_intel SET block_episode_count = ?, "
                    "repeat_offender = ?, repeat_offender_since = ?, "
                    "last_episode_block_at = ? WHERE ip_address = ?",
                    (new_count, new_flag, new_ros, new_anchor, ip),
                )
        else:
            stats["unchanged"] += 1

    if not dry_run:
        conn.commit()

    stats["samples"] = samples
    return stats


def _build_db_config(args):
    """Build a database config from CLI arguments (mirrors the reconcile script)."""
    if args.config:
        config = load_config(args.config)
        db_type = config.get("DATABASE_TYPE", "sqlite").lower()
        if db_type in ("mysql", "mariadb"):
            return {
                "DATABASE_TYPE": db_type,
                "DATABASE_HOST": config.get("DATABASE_HOST", "localhost"),
                "DATABASE_PORT": config.get("DATABASE_PORT", 3306),
                "DATABASE_NAME": config.get("DATABASE_NAME", "vespid"),
                "DATABASE_USER": config.get("DATABASE_USER", "vespid"),
                "DATABASE_PASSWORD": config.get("DATABASE_PASSWORD", ""),
            }
        return config.get("DATABASE_PATH", DEFAULT_DB_PATH)

    if args.mysql:
        return {
            "DATABASE_TYPE": "mysql",
            "DATABASE_HOST": args.host,
            "DATABASE_PORT": args.port,
            "DATABASE_NAME": args.database,
            "DATABASE_USER": args.user,
            "DATABASE_PASSWORD": args.password,
        }

    return args.db


def run(db_config, dry_run: bool = False) -> dict:
    """Open the database, run the repair, and close the connection."""
    conn = get_db(db_config)
    try:
        return repair(conn, dry_run=dry_run)
    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(
        description="Repair IP Intelligence block episode counters."
    )
    parser.add_argument(
        "--db", default=DEFAULT_DB_PATH,
        help="Path to SQLite database (default: %(default)s)",
    )
    parser.add_argument(
        "--config", default=None,
        help="Path to server config YAML (for MySQL/MariaDB)",
    )
    parser.add_argument(
        "--mysql", action="store_true",
        help="Use MySQL backend with explicit parameters",
    )
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=3306)
    parser.add_argument("--database", default="vespid")
    parser.add_argument("--user", default="vespid")
    parser.add_argument("--password", default="")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Preview changes without applying them",
    )

    args = parser.parse_args()
    db_config = _build_db_config(args)

    logger.info("Starting IP Intelligence block episode repair...")
    if args.dry_run:
        logger.info("(DRY RUN mode — no changes will be made)")

    result = run(db_config, dry_run=args.dry_run)
    samples = result.pop("samples", [])

    for sample in samples:
        logger.info(
            "  %s: episodes %s -> %s, repeat_offender %s -> %s, anchor %s -> %s",
            sample["ip_address"],
            sample["block_episode_count"][0],
            sample["block_episode_count"][1],
            sample["repeat_offender"][0],
            sample["repeat_offender"][1],
            sample["last_episode_block_at"][0],
            sample["last_episode_block_at"][1],
        )
    if len(samples) == 20:
        logger.info("  ... (showing first 20 changes)")

    logger.info("Done. Summary: %s", result)


if __name__ == "__main__":
    main()
