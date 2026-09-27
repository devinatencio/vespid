"""Structured logging configuration for Vespid Server.

Provides a RequestIdFilter that injects request context into all log records,
and supports both human-readable text format (default) and JSON format for
SIEM integration.

Usage:
    from app.logging_config import setup_logging
    setup_logging(app, config)
"""

import logging
import os
import uuid
from logging.handlers import RotatingFileHandler

from flask import g, has_request_context, request


class RequestIdFilter(logging.Filter):
    """Injects request_id, method, path, and remote_addr into log records.

    Gracefully handles non-request contexts (background timers, reapers)
    by using empty strings when Flask request context is unavailable.
    """

    def filter(self, record):
        if has_request_context():
            record.request_id = getattr(g, "request_id", "")
            record.method = request.method
            record.path = request.path
            record.remote_addr = request.remote_addr
        else:
            record.request_id = ""
            record.method = ""
            record.path = ""
            record.remote_addr = ""
        return True


class JsonFormatter(logging.Formatter):
    """Formats log records as JSON for SIEM ingestion.

    Produces one JSON object per line with consistent field names.
    """

    def format(self, record):
        log_entry = {
            "timestamp": self.formatTime(record, self.datefmt),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "request_id": getattr(record, "request_id", ""),
            "method": getattr(record, "method", ""),
            "path": getattr(record, "path", ""),
            "remote_addr": getattr(record, "remote_addr", ""),
        }
        if record.exc_info and record.exc_info[0] is not None:
            log_entry["exception"] = self.formatException(record.exc_info)
        return _json_encode(log_entry)


def _json_encode(obj):
    """Minimal JSON encoder to avoid importing json in hot path.

    Uses the stdlib json module but caches the result of simple_encode
    for performance.
    """
    import json

    return json.dumps(obj, separators=(",", ":"))


def _make_formatter(fmt_type, datefmt="%Y-%m-%dT%H:%M:%S%z"):
    """Create a formatter based on the requested format type.

    Args:
        fmt_type: "text" or "json"
        datefmt: Date format string (only used for text format)

    Returns:
        A logging.Formatter or JsonFormatter instance.
    """
    if fmt_type == "json":
        return JsonFormatter(datefmt=datefmt)

    return logging.Formatter(
        "%(asctime)s %(levelname)-8s %(name)s  [%(request_id)s] %(message)s",
        datefmt=datefmt,
    )


def _setup_handler(handler, fmt_type, log_level):
    """Configure a log handler with the appropriate formatter and filter.

    Args:
        handler: A logging.Handler instance (e.g., RotatingFileHandler)
        fmt_type: "text" or "json"
        log_level: Logging level constant
    """
    handler.setLevel(log_level)
    handler.setFormatter(_make_formatter(fmt_type))
    handler.addFilter(RequestIdFilter())


def setup_logging(app, config):
    """Configure application log handlers with request ID support.

    Sets up rotating file handlers for the main app log, reaper log,
    alert log, and metrics log. All handlers include request ID context
    when available.

    Args:
        app: Flask application instance
        config: Configuration dict (from app.config)
    """
    fmt_type = config.get("LOG_FORMAT", "text").lower()
    if fmt_type not in ("text", "json"):
        fmt_type = "text"

    log_file = config.get("LOG_FILE", "/var/log/vespid-server/vespid-server.log")
    log_level_str = config.get("LOG_LEVEL", "INFO").upper()
    log_level = getattr(logging, log_level_str, logging.INFO)
    log_max_bytes = config.get("LOG_MAX_BYTES", 10485760)
    log_backup_count = config.get("LOG_BACKUP_COUNT", 5)

    try:
        log_dir = os.path.dirname(log_file)
        if log_dir:
            os.makedirs(log_dir, exist_ok=True)

        file_handler = RotatingFileHandler(
            log_file,
            maxBytes=log_max_bytes,
            backupCount=log_backup_count,
        )
        _setup_handler(file_handler, fmt_type, log_level)

        app_logger = logging.getLogger("app")
        app_logger.addHandler(file_handler)
        app_logger.setLevel(log_level)

        app.logger.addHandler(file_handler)
        app.logger.setLevel(log_level)

        logger = logging.getLogger(__name__)
        logger.info(
            "Application log file: %s (level=%s, format=%s)",
            log_file,
            log_level_str,
            fmt_type,
        )

        # ── Reaper log ──
        reaper_log_file = os.path.join(log_dir, "vespid-reaper.log")
        reaper_handler = RotatingFileHandler(
            reaper_log_file,
            maxBytes=log_max_bytes,
            backupCount=log_backup_count,
        )
        _setup_handler(reaper_handler, fmt_type, logging.INFO)
        reaper_logger = logging.getLogger("app.reaper")
        reaper_logger.addHandler(reaper_handler)
        reaper_logger.setLevel(logging.INFO)
        reaper_logger.propagate = False
        logger.info("Reaper log file: %s", reaper_log_file)

        # ── Alert log ──
        alert_log_file = os.path.join(log_dir, "vespid-alerts.log")
        alert_handler = RotatingFileHandler(
            alert_log_file,
            maxBytes=log_max_bytes,
            backupCount=log_backup_count,
        )
        _setup_handler(alert_handler, fmt_type, logging.INFO)
        alert_logger = logging.getLogger("app.alert_manager")
        alert_logger.addHandler(alert_handler)
        alert_logger.setLevel(logging.INFO)
        alert_logger.propagate = False
        logger.info("Alert log file: %s", alert_log_file)

        # ── Metrics log ──
        metrics_log_file = os.path.join(log_dir, "vespid-metrics.log")
        metrics_handler = RotatingFileHandler(
            metrics_log_file,
            maxBytes=log_max_bytes,
            backupCount=log_backup_count,
        )
        _setup_handler(metrics_handler, fmt_type, logging.INFO)
        metrics_logger = logging.getLogger("app.metrics")
        metrics_logger.addHandler(metrics_handler)
        metrics_logger.setLevel(logging.INFO)
        metrics_logger.propagate = False
        logger.info("Metrics log file: %s", metrics_log_file)

        # ── Host threats log ──
        host_threats_log_file = os.path.join(log_dir, "vespid-host-threats.log")
        host_threats_handler = RotatingFileHandler(
            host_threats_log_file,
            maxBytes=log_max_bytes,
            backupCount=log_backup_count,
        )
        _setup_handler(host_threats_handler, fmt_type, logging.INFO)
        host_threats_logger = logging.getLogger("app.routes.host_threats")
        host_threats_logger.addHandler(host_threats_handler)
        host_threats_logger.setLevel(logging.INFO)
        host_threats_logger.propagate = False
        logger.info("Host threats log file: %s", host_threats_log_file)

    except OSError as exc:
        logging.getLogger(__name__).warning(
            "Could not set up log file %s: %s -- logging to stderr only", log_file, exc
        )


def generate_request_id():
    """Propagate the request ID generated by gunicorn's pre_request hook.

    Reads X-Request-Id from incoming headers (set by gunicorn if not
    provided by the client) and stores it in Flask's g object for use
    by RequestIdFilter.

    Returns:
        The request ID string.
    """
    request_id = request.headers.get("X-Request-Id", str(uuid.uuid4())[:12])
    g.request_id = request_id
    return request_id


def inject_request_id(response):
    """Inject X-Request-Id header into the HTTP response.

    Args:
        response: Flask Response object

    Returns:
        The response object (unchanged, with header added).
    """
    response.headers["X-Request-Id"] = getattr(g, "request_id", "")
    return response
