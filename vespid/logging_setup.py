"""Centralized logging configuration.

Three sinks:

* **stdout**  - so ``journalctl -u vespid -f`` shows live activity.
* **vespid.log** - rotating human-readable file at /var/log/vespid.
* **decisions.jsonl** - append-only structured audit trail of every block,
  unblock, detection, and feed sync. Easy to grep / ship to a SIEM.

Call :func:`configure_logging` exactly once at daemon startup. Anywhere else
(producers, CLI helpers, tests) just use ``logging.getLogger(...)``.

Use :func:`audit` from any producer to write a one-line JSON record into the
decisions log on top of the normal log line.
"""

from __future__ import annotations

import json
import logging
import logging.handlers
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_LOG_DIR = Path(os.environ.get("VESPID_LOG_DIR", "/var/log/vespid"))
HUMAN_LOG_NAME = "vespid.log"
DECISIONS_LOG_NAME = "decisions.jsonl"

_AUDIT_LOGGER_NAME = "vespid.audit"
_configured = False


class _JsonLineFormatter(logging.Formatter):
    """Formatter that emits one JSON object per record (decisions log)."""

    def format(self, record: logging.LogRecord) -> str:
        payload: dict[str, Any] = {
            "ts": datetime.fromtimestamp(record.created, tz=timezone.utc)
            .isoformat()
            .replace("+00:00", "Z"),
            "level": record.levelname,
            "msg": record.getMessage(),
        }
        extra = getattr(record, "audit", None)
        if isinstance(extra, dict):
            payload.update(extra)
        return json.dumps(payload, separators=(",", ":"), sort_keys=True)


def configure_logging(level: str = "INFO", log_dir: Path | None = None) -> Path:
    """Configure logging for the daemon. Returns the log directory path."""
    global _configured
    if _configured:
        return log_dir or DEFAULT_LOG_DIR

    log_dir = Path(log_dir or DEFAULT_LOG_DIR)
    try:
        log_dir.mkdir(parents=True, exist_ok=True)
    except (PermissionError, OSError):
        # Fall back to a user-writable directory for dev / non-root runs.
        log_dir = Path(os.environ.get("TMPDIR", "/tmp")) / "vespid-logs"
        log_dir.mkdir(parents=True, exist_ok=True)

    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    # Wipe any handler set up by a previous logging.basicConfig() call.
    for h in list(root.handlers):
        root.removeHandler(h)

    human_fmt = logging.Formatter(
        "%(asctime)s %(levelname)-7s %(name)-22s %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S%z",
    )

    stdout = logging.StreamHandler(sys.stdout)
    stdout.setFormatter(human_fmt)
    root.addHandler(stdout)

    human_file = logging.handlers.RotatingFileHandler(
        log_dir / HUMAN_LOG_NAME,
        maxBytes=10 * 1024 * 1024,
        backupCount=5,
        encoding="utf-8",
    )
    human_file.setFormatter(human_fmt)
    root.addHandler(human_file)

    # Audit logger: independent, JSON-line, never propagates.
    audit_logger = logging.getLogger(_AUDIT_LOGGER_NAME)
    audit_logger.setLevel(logging.INFO)
    audit_logger.propagate = False
    for h in list(audit_logger.handlers):
        audit_logger.removeHandler(h)
    audit_file = logging.handlers.RotatingFileHandler(
        log_dir / DECISIONS_LOG_NAME,
        maxBytes=20 * 1024 * 1024,
        backupCount=10,
        encoding="utf-8",
    )
    audit_file.setFormatter(_JsonLineFormatter())
    audit_logger.addHandler(audit_file)

    _configured = True
    logging.getLogger("vespid").info("Logging configured (dir=%s, level=%s)", log_dir, level)
    return log_dir


def audit(event: str, **fields: Any) -> None:
    """Write a structured decision/audit record."""
    logging.getLogger(_AUDIT_LOGGER_NAME).info(event, extra={"audit": {"event": event, **fields}})


def log_path(name: str = HUMAN_LOG_NAME) -> Path:
    return DEFAULT_LOG_DIR / name
