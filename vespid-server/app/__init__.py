"""Vespid Server - Flask application factory.

Creates and configures the Flask application with blueprints,
Flask-Login, database backend (SQLite or MariaDB/MySQL), SSE manager,
rate limiter, and OpenAPI/Swagger documentation.
"""

__version__ = "1.0.0"

import logging
import os
import sys
import threading

from flask import Flask, jsonify, render_template, request
from flask_login import LoginManager
from flask_openapi3 import Info, OpenAPI, SecurityScheme
from flask_openapi3.models import Tag

# ── Monkey-patch flask_openapi3 to pass through undeclared path params ──
# Without this, path parameters like <agent_id>, <rule_id>, etc. are silently
# stripped by _validate_request when no path= Pydantic model is declared.
from flask_openapi3.request import _validate_request as _original_validate_request
from flask_wtf.csrf import CSRFProtect

from app.config import load_config
from app.fleet_sse import FleetSSEManager
from app.models import cleanup_counter_snapshots, get_db, init_db
from app.models.db_core import _close_request_db
from app.propagation_engine import PropagationEngine
from app.rate_limit import limiter
from app.sse import SSEManager


def _patched_validate_request(*args, **kwargs):
    result = _original_validate_request(*args, **kwargs)
    path_kwargs = kwargs.get("path_kwargs", {})
    if path_kwargs:
        result.update(path_kwargs)
    return result


import flask_openapi3.scaffold as _scaffold

_original_view_func_wrapper = _scaffold.APIScaffold._collect_openapi_info

# We can't easily patch the closure variable, so patch _validate_request directly.
# The view_func calls _validate_request which we've patched below.
import flask_openapi3.request as _openapi3_request

_openapi3_request._validate_request = _patched_validate_request

# Also need to re-patch in scaffold's closure. The simplest way is to
# fix the _validate_request module-level function that scaffold imports.
import flask_openapi3.scaffold as _scaffold_module

_scaffold_module._validate_request = _patched_validate_request

logger = logging.getLogger(__name__)

_API_INFO = Info(
    title="Vespid Server API",
    version=__version__,
    description="Vespid is a client/server security platform that monitors system logs for malicious activity, "
    "automatically blocks offending IPs via nftables, and coordinates fleet-wide via a central server. "
    "This API covers event ingestion, fleet management, IP intelligence, agent enrollment, and health checks.",
)

_API_SECURITY_SCHEMES = {
    "BearerAuth": SecurityScheme(
        type="http",
        scheme="bearer",
        bearerFormat="API Key",
        description="Agent API key. Pass as `Authorization: Bearer <api_key>`.",
    ),
    "SessionAuth": SecurityScheme(
        type="apiKey",
        name="session",
        security_scheme_in="cookie",
        description="Web session cookie (for dashboard UI access).",
    ),
}


def create_app(config_path: str | None = None) -> Flask:
    """Flask application factory.

    Loads configuration from JSON file or environment, initializes the
    database backend (SQLite or MariaDB/MySQL), registers blueprints
    (auth, api, dashboard, admin), configures Flask-Login for session
    management, and initializes the SSE manager singleton.

    Args:
        config_path: Optional path to a JSON configuration file.

    Returns:
        A configured Flask application instance.
    """
    app = OpenAPI(
        __name__,
        info=_API_INFO,
        security_schemes=_API_SECURITY_SCHEMES,
        doc_ui=True,
        doc_prefix="/openapi",
    )

    # Load configuration
    config = load_config(config_path)

    # Alerts depends on Metrics — auto-enable when metrics is active
    if config.get("METRICS_ENABLED", False):
        config["ALERTS_ENABLED"] = True

    # Set Flask's SECRET_KEY from config
    app.config["SECRET_KEY"] = config["SECRET_KEY"]

    # Store all Vespid config values in app.config for blueprint access
    for key, value in config.items():
        app.config[key] = value

    if "ALERT_EVAL_INTERVAL_SECONDS" not in app.config:
        app.config["ALERT_EVAL_INTERVAL_SECONDS"] = 30

    # ── Proxy support ──
    # Trust X-Forwarded-For / X-Forwarded-Proto from upstream proxies
    # (HAProxy, nginx, etc.) so request.remote_addr reflects the real client.
    proxy_count = config.get("PROXY_TRUST_COUNT", 1)
    if proxy_count > 0:
        from werkzeug.middleware.proxy_fix import ProxyFix

        app.wsgi_app = ProxyFix(
            app.wsgi_app, x_for=proxy_count, x_proto=0, x_host=0, x_port=0, x_prefix=0
        )
        logger.info("ProxyFix enabled (trust_count=%d)", proxy_count)

    # ── Application log file setup ──
    # Configures rotating log handlers with request ID support.
    # See app/logging_config.py for format options (text/json).
    from app.logging_config import setup_logging

    setup_logging(app, config)

    # ── Startup banner ──
    version = __version__
    banner = (
        "\n"
        "  ┌────────────────────────────────────────────────────────┐\n"
        "  │{:<56}│\n"
        "  │{:<56}│\n"
        "  │{:<56}│\n"
        "  └────────────────────────────────────────────────────────┘"
    ).format(
        "                    Vespid Server",
        f"                      v{version}",
        f"                    PID: {os.getpid()}",
    )
    logging.getLogger("app").info(banner)

    # ── Request ID tracking ──
    # Generates or propagates a request ID for each request, enabling
    # correlation of log entries across all log files for a single request.
    from app.logging_config import generate_request_id, inject_request_id

    @app.before_request
    def _generate_request_id():
        generate_request_id()

    @app.after_request
    def _inject_request_id(response):
        return inject_request_id(response)

    # Determine database backend type
    db_type = config.get("DATABASE_TYPE", "sqlite").lower()

    if db_type == "sqlite":
        # SQLite backend — existing behavior
        logger.info("Database backend: SQLite")
        print("[Vespid] Database backend: SQLite")
        db_path = config["DATABASE_PATH"]
        db_dir = os.path.dirname(os.path.abspath(db_path))

        if not os.path.isdir(db_dir):
            try:
                os.makedirs(db_dir, exist_ok=True)
            except OSError:
                logger.error(
                    "Database directory %s does not exist and cannot be created",
                    db_dir,
                )
                sys.exit(1)

        if not os.access(db_dir, os.W_OK):
            logger.error(
                "Database directory %s is not writable. "
                "Check file permissions and ensure the process user has write access.",
                db_dir,
            )
            sys.exit(1)

        # Initialize the database (create tables if needed)
        init_db(db_path)
        app.config["DATABASE_PATH"] = db_path

        # Run counter snapshot cleanup on startup
        retention_days = config.get("COUNTER_RETENTION_DAYS", 30)
        conn = get_db(db_path)
        try:
            deleted = cleanup_counter_snapshots(conn, retention_days=retention_days)
            if deleted:
                logger.info(
                    "Cleaned up %d counter snapshot(s) older than %d days",
                    deleted,
                    retention_days,
                )
        finally:
            conn.close()

        # db_config used by PropagationEngine and other components
        db_config = db_path

    elif db_type in ("mysql", "mariadb"):
        # MySQL/MariaDB backend — skip file path validation
        db_config_dict = {
            "DATABASE_TYPE": config.get("DATABASE_TYPE", "mysql"),
            "DATABASE_HOST": config.get("DATABASE_HOST", "localhost"),
            "DATABASE_PORT": config.get("DATABASE_PORT", 3306),
            "DATABASE_NAME": config.get("DATABASE_NAME", "vespid"),
            "DATABASE_USER": config.get("DATABASE_USER", "vespid"),
            "DATABASE_PASSWORD": config.get("DATABASE_PASSWORD", ""),
        }

        host = db_config_dict["DATABASE_HOST"]
        port = db_config_dict["DATABASE_PORT"]

        logger.info(
            "Database backend: %s (%s:%s/%s)",
            db_type,
            host,
            port,
            db_config_dict["DATABASE_NAME"],
        )
        print(
            f"[Vespid] Database backend: {db_type} ({host}:{port}/{db_config_dict['DATABASE_NAME']})"
        )

        # Store DB keys in app.config for use by blueprints
        for key in (
            "DATABASE_TYPE",
            "DATABASE_HOST",
            "DATABASE_PORT",
            "DATABASE_NAME",
            "DATABASE_USER",
            "DATABASE_PASSWORD",
        ):
            app.config[key] = db_config_dict[key]

        # Override DATABASE_PATH with the dict so blueprints using
        # get_db(current_app.config["DATABASE_PATH"]) get a MySQL connection
        app.config["DATABASE_PATH"] = db_config_dict

        # Initialize the database (create tables if needed)
        try:
            init_db(db_config_dict)
        except ConnectionError as exc:
            logger.error(
                "Failed to connect to database at %s:%s — %s",
                host,
                port,
                exc,
            )
            sys.exit(1)

        # Run counter snapshot cleanup on startup
        retention_days = config.get("COUNTER_RETENTION_DAYS", 30)
        try:
            conn = get_db(db_config_dict)
        except ConnectionError as exc:
            logger.error(
                "Failed to connect to database at %s:%s — %s",
                host,
                port,
                exc,
            )
            sys.exit(1)
        try:
            deleted = cleanup_counter_snapshots(conn, retention_days=retention_days)
            if deleted:
                logger.info(
                    "Cleaned up %d counter snapshot(s) older than %d days",
                    deleted,
                    retention_days,
                )
        finally:
            conn.close()

        # db_config used by PropagationEngine and other components
        db_config = db_config_dict

    else:
        # Unsupported DATABASE_TYPE
        logger.error(
            "Unsupported DATABASE_TYPE '%s'. Valid options are: sqlite, mysql, mariadb",
            db_type,
        )
        sys.exit(1)

    # Configure Flask-Login
    login_manager = LoginManager()
    login_manager.login_view = "auth.login"
    login_manager.init_app(app)

    # Register blueprints
    from app.routes.admin import admin_bp
    from app.routes.auth import auth_bp, init_login_manager
    from app.routes.dashboard import dashboard_bp

    security_enabled = config.get("SECURITY_ENABLED", True)

    if security_enabled:
        from app.routes.api import api_bp
        from app.routes.config_dashboard import config_dashboard_bp
        from app.routes.config_management import config_mgmt_bp
        from app.routes.config_rollout import config_rollout_bp
        from app.routes.enrollment import enrollment_bp
        from app.routes.fleet import fleet_bp
        from app.routes.fleet_dashboard import fleet_dashboard_bp
        from app.routes.intel_api import intel_bp
        from app.routes.intel_dashboard import intel_dashboard_bp
        from app.routes.rules import rules_bp
        from app.routes.test_rules_blueprint import test_rules_bp
    else:
        api_bp = None

    if config.get("METRICS_ENABLED"):
        from app.routes.metrics import metrics_bp
    else:
        metrics_bp = None

    # Configure the real user_loader from auth module
    init_login_manager(app)

    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)
    app.register_blueprint(admin_bp)

    if security_enabled:
        app.register_api(api_bp)
        app.register_api(enrollment_bp)
        app.register_api(fleet_bp)
        app.register_blueprint(fleet_dashboard_bp)
        app.register_api(rules_bp)
        app.register_api(config_mgmt_bp)
        app.register_blueprint(config_rollout_bp)
        app.register_blueprint(config_dashboard_bp)
        app.register_blueprint(test_rules_bp)
        app.register_api(intel_bp)
        app.register_blueprint(intel_dashboard_bp)

        from app.routes.host_threats import host_threats_bp

        app.register_blueprint(host_threats_bp)

        logger.info("Security subsystem enabled")

    if metrics_bp is not None:
        from app.routes.metrics_api import metrics_api_bp

        app.register_api(metrics_api_bp)
        app.register_blueprint(metrics_bp)
        logger.info(
            "Metrics subsystem enabled — VictoriaMetrics at %s",
            config.get("VICTORIAMETRICS_URL", "http://localhost:8428"),
        )

    # Register inventory dashboard + sync blueprint
    from app.routes.inventory_dashboard import inventory_bp

    app.register_blueprint(inventory_bp)
    from app.routes.inventory_sync import inventory_sync_bp

    app.register_blueprint(inventory_sync_bp)
    logger.info("Inventory dashboard enabled")

    # Register alerts blueprint
    if config.get("ALERTS_ENABLED", True):
        from app.routes.alerts import alerts_bp

        app.register_blueprint(alerts_bp)

        from app.routes.alerts_api import alerts_api_bp

        app.register_api(alerts_api_bp)

        from app.routes.synthetic_checks import synth_bp

        app.register_blueprint(synth_bp)

        from app.routes.synth_api import synth_api_bp

        app.register_api(synth_api_bp)

        logger.info("Alerts subsystem enabled")

    # Initialize CSRF protection for all form endpoints.
    # Token-authenticated / public agent APIs stay exempt — they use Bearer
    # auth (no session cookie), so CSRF does not apply. Browser session
    # blueprints are NOT exempt: the base template auto-injects csrf_token
    # into forms and X-CSRFToken into HTMX and fetch headers.
    csrf = CSRFProtect(app)
    if security_enabled:
        csrf.exempt(api_bp)
        csrf.exempt(enrollment_bp)
        csrf.exempt(intel_bp)
        # Agent config check-in is a Bearer-token POST — exempt this view
        # while the rest of config_mgmt_bp (session admin routes) gets
        # CSRF protection.
        from app.routes.config_management import agent_check_in

        csrf.exempt(agent_check_in)
    if metrics_bp is not None:
        # Agent metrics ingestion (POST /write) is Bearer-token auth —
        # exempt this view while the rest of metrics_api_bp (browser
        # viewer queries) gets CSRF protection.
        from app.routes.metrics_api import write

        csrf.exempt(write)
    if config.get("ALERTS_ENABLED", True):
        # Synthetic-check worker endpoints use Bearer token (require_role agent).
        csrf.exempt(synth_api_bp)
    # Inventory sync is an agent API (require_role agent, non-session).
    csrf.exempt(inventory_sync_bp)

    if security_enabled:
        app.sse_manager = SSEManager(history_size=config.get("SSE_HISTORY_SIZE", 500))

        app.fleet_sse_manager = FleetSSEManager(
            history_size=config.get("FLEET_SSE_HISTORY_SIZE", 1000)
        )

        from app.config_sse import ConfigSSEManager

        app.config_sse_manager = ConfigSSEManager(
            history_size=config.get("CONFIG_SSE_HISTORY_SIZE", 1000)
        )

        from app.check_worker_sse import CheckWorkerSSEManager

        app.check_worker_sse_manager = CheckWorkerSSEManager(
            history_size=config.get("CHECK_WORKER_SSE_HISTORY_SIZE", 500)
        )

        app.propagation_engine = PropagationEngine(
            db_path=db_config,
            fleet_sse=app.fleet_sse_manager,
        )

        sse_redis_url = config.get("SSE_REDIS_URL")
        if sse_redis_url:
            from app.sse_redis import RedisSSEBridge

            bridge = RedisSSEBridge(sse_redis_url)
            app.sse_manager.set_redis(bridge, "vespid:sse:events")
            app.fleet_sse_manager.set_redis(bridge, "vespid:sse:fleet")
            app.config_sse_manager.set_redis(bridge, "vespid:sse:config")
            app._sse_redis_bridge = bridge

            @app.before_request
            def _ensure_sse_redis():
                if not getattr(app, "_sse_redis_started", False):
                    app._sse_redis_bridge.start()
                    app._sse_redis_started = True

        app._fleet_reaper_interval = config.get("FLEET_REAPER_INTERVAL_SECONDS", 60)
        app._fleet_reaper_started = False

    def start_fleet_reaper(application):
        """Start the fleet reaper timer. Called once per worker process.

        Uses an exclusive fcntl lock on a temp file to ensure only one
        worker across the entire process pool runs the reaper.  When the
        owning worker is recycled (e.g. after max_requests), the kernel
        releases the lock and the replacement worker automatically claims
        it in its own post_fork call.

        Runs the first reap 60 seconds after the lock is acquired, then
        at the configured interval.
        """
        if application._fleet_reaper_started:
            return

        # Cross-worker mutual exclusion via a kernel-backed file lock.
        # The lock is released automatically when the owning process exits.
        import fcntl
        import tempfile

        _lock_path = os.path.join(tempfile.gettempdir(), "vespid_fleet_reaper.lock")
        _lock_fd = os.open(_lock_path, os.O_CREAT | os.O_RDWR, 0o644)
        try:
            fcntl.flock(_lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            os.close(_lock_fd)
            logger.debug("Fleet reaper lock held by another worker (pid=%d)", os.getpid())
            return
        application._fleet_reaper_lock_fd = _lock_fd

        application._fleet_reaper_started = True

        reaper_interval = application._fleet_reaper_interval
        initial_delay = 60  # first run 60s after startup

        def _fleet_reaper_loop():
            """Periodically reap expired fleet blocks."""
            logger.debug("Fleet reaper cycle starting")
            try:
                expired = application.propagation_engine.reap_expired()
                if expired:
                    logger.info("Fleet reaper expired %d block(s)", expired)
                purged = application.propagation_engine.purge_old_blocks()
                if purged:
                    logger.info("Fleet reaper purged %d old block(s)", purged)
                if not expired and not purged:
                    logger.debug("Fleet reaper cycle: nothing to reap or purge")
            except Exception:
                logger.exception("Fleet reaper encountered an error")
            # Schedule next run at configured interval
            timer = threading.Timer(reaper_interval, _fleet_reaper_loop)
            timer.daemon = True
            timer.start()

        # First run 60s after startup, then at configured interval thereafter
        reaper_timer = threading.Timer(initial_delay, _fleet_reaper_loop)
        reaper_timer.daemon = True
        reaper_timer.start()
        logger.info(
            "Fleet reaper started (initial_delay=%ds, interval=%ds, pid=%d)",
            initial_delay,
            reaper_interval,
            os.getpid(),
        )

    if security_enabled:
        app.start_fleet_reaper = start_fleet_reaper

        # If running outside gunicorn (e.g. flask run, tests), start immediately
        if os.environ.get("SERVER_SOFTWARE", "").startswith("gunicorn"):
            logger.info(
                "Fleet reaper deferred to post_fork (gunicorn detected, pid=%d)",
                os.getpid(),
            )
        else:
            start_fleet_reaper(app)

    if security_enabled:
        # ── Retention reaper ──────────────────────────────────────────
        # Purges old events / context / counters older than the configured
        # retention window (default 90 days).  Runs once per day plus on
        # startup to catch any backlog after restarts.
        from app.models import get_setting
        from app.models import purge_old_audit_log as _purge_old_audit_log
        from app.models import purge_old_events as _purge_old_events

        app._retention_reaper_started = False
        app._retention_interval = 86400  # once per day

    from app.worker_locks import singleton as _singleton_lock

    @_singleton_lock("retention_reaper")
    def start_retention_reaper(application):
        if application._retention_reaper_started:
            return
        application._retention_reaper_started = True

        initial_delay = 120  # 2 min after startup

        def _retention_reaper_loop():
            logger.debug("Retention reaper cycle starting")
            try:
                db = get_db(db_config)
                retention_days = int(get_setting(db, "event_retention_days", "90"))
                purged = _purge_old_events(db, retention_days)
                audit_retention_days = int(get_setting(db, "audit_retention_days", "90"))
                audit_purged = _purge_old_audit_log(db, audit_retention_days)
                db.close()
                total = sum(purged.values()) + audit_purged
                if total:
                    logger.info(
                        "Retention reaper purged %d rows (events=%d, context=%d, counters=%d, audit=%d, "
                        "event_retention=%dd, audit_retention=%dd)",
                        total,
                        purged["events"],
                        purged["event_context"],
                        purged["counters"],
                        audit_purged,
                        retention_days,
                        audit_retention_days,
                    )
                else:
                    logger.debug(
                        "Retention reaper cycle: nothing to purge "
                        "(event_retention=%dd, audit_retention=%dd)",
                        retention_days,
                        audit_retention_days,
                    )
            except Exception:
                logger.exception("Retention reaper encountered an error")
            timer = threading.Timer(application._retention_interval, _retention_reaper_loop)
            timer.daemon = True
            timer.start()

        reaper_timer = threading.Timer(initial_delay, _retention_reaper_loop)
        reaper_timer.daemon = True
        reaper_timer.start()
        logger.info(
            "Retention reaper started (initial_delay=%ds, interval=%ds, pid=%d)",
            initial_delay,
            application._retention_interval,
            os.getpid(),
        )

    app.start_retention_reaper = start_retention_reaper

    if os.environ.get("SERVER_SOFTWARE", "").startswith("gunicorn"):
        logger.info(
            "Retention reaper deferred to post_fork (gunicorn detected, pid=%d)", os.getpid()
        )
    else:
        start_retention_reaper(app)

    # ── Host events retention reaper ─────────────────────────────
    # Purges old host_events rows older than the configured retention
    # window (default 30 days).  Runs once per day, initial delay 180s.
    if security_enabled:
        from datetime import datetime, timedelta

        app._host_events_reaper_started = False
        app._host_events_reaper_interval = 86400  # once per day

        @_singleton_lock("host_events_reaper")
        def start_host_events_reaper(application):
            if application._host_events_reaper_started:
                return
            application._host_events_reaper_started = True
            initial_delay = 180  # 3 min after startup

            def _host_events_reaper_loop():
                logger.debug("Host events reaper cycle starting")
                try:
                    db = get_db(db_config)
                    retention_days = int(get_setting(db, "host_events_retention_days", "30"))
                    cutoff = (datetime.utcnow() - timedelta(days=retention_days)).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    )
                    result = db.execute("DELETE FROM host_events WHERE ingested_at < ?", (cutoff,))
                    deleted = result.rowcount
                    db.commit()
                    db.close()
                    if deleted:
                        logger.info(
                            "Host events reaper purged %d rows (retention=%dd)",
                            deleted,
                            retention_days,
                        )
                    else:
                        logger.debug(
                            "Host events reaper cycle: nothing to purge (retention=%dd)",
                            retention_days,
                        )
                except Exception:
                    logger.exception("Host events reaper encountered an error")
                timer = threading.Timer(
                    application._host_events_reaper_interval, _host_events_reaper_loop
                )
                timer.daemon = True
                timer.start()

            reaper_timer = threading.Timer(initial_delay, _host_events_reaper_loop)
            reaper_timer.daemon = True
            reaper_timer.start()
            logger.info(
                "Host events reaper started (initial_delay=%ds, interval=%ds, pid=%d)",
                initial_delay,
                application._host_events_reaper_interval,
                os.getpid(),
            )

        app.start_host_events_reaper = start_host_events_reaper

        if os.environ.get("SERVER_SOFTWARE", "").startswith("gunicorn"):
            logger.info(
                "Host events reaper deferred to post_fork (gunicorn detected, pid=%d)",
                os.getpid(),
            )
        else:
            start_host_events_reaper(app)

    # ── Command queue reaper ─────────────────────────────────────
    # Expires stale pending commands and purges old completed/failed
    # commands.  Runs once per hour, initial delay 240s.
    app._command_reaper_started = False
    app._command_reaper_interval = 3600  # once per hour

    @_singleton_lock("command_reaper")
    def start_command_reaper(application):
        if application._command_reaper_started:
            return
        application._command_reaper_started = True
        initial_delay = 240  # 4 min after startup

        from app.models import (
            expire_stale_commands as _expire_stale_commands,
        )
        from app.models import (
            purge_old_commands as _purge_old_commands,
        )

        def _command_reaper_loop():
            logger.debug("Command reaper cycle starting")
            try:
                db = get_db(db_config)
                pending_expiry_hours = int(get_setting(db, "command_pending_expiry_hours", "24"))
                command_retention_days = int(get_setting(db, "command_retention_days", "30"))
                expired = _expire_stale_commands(db, pending_expiry_hours)
                purged = _purge_old_commands(db, command_retention_days)
                db.close()
                if expired or purged:
                    logger.info(
                        "Command reaper: expired=%d pending (>%dh), purged=%d old (>%dd)",
                        expired,
                        pending_expiry_hours,
                        purged,
                        command_retention_days,
                    )
                else:
                    logger.debug("Command reaper cycle: nothing to clean")
            except Exception:
                logger.exception("Command reaper encountered an error")
            timer = threading.Timer(application._command_reaper_interval, _command_reaper_loop)
            timer.daemon = True
            timer.start()

        reaper_timer = threading.Timer(initial_delay, _command_reaper_loop)
        reaper_timer.daemon = True
        reaper_timer.start()
        logger.info(
            "Command reaper started (initial_delay=%ds, interval=%ds, pid=%d)",
            initial_delay,
            application._command_reaper_interval,
            os.getpid(),
        )

    app.start_command_reaper = start_command_reaper

    if os.environ.get("SERVER_SOFTWARE", "").startswith("gunicorn"):
        logger.info("Command reaper deferred to post_fork (gunicorn detected, pid=%d)", os.getpid())
    else:
        start_command_reaper(app)

    # ── DB Backup reaper ─────────────────────────────────────────
    # Automated database backups on configurable interval. Defaults to
    # nightly (24h). Settings are read from app_settings on each cycle
    # so changes via the UI take effect without a restart.
    from app.db_backup import start_backup_reaper

    app._backup_reaper_started = False
    app._db_config = db_config  # stored for gunicorn post_fork access

    if os.environ.get("SERVER_SOFTWARE", "").startswith("gunicorn"):
        logger.info("Backup reaper deferred to post_fork (gunicorn detected, pid=%d)", os.getpid())
    else:
        start_backup_reaper(app, db_config)

    # ── Alert evaluation scheduler ────────────────────────────────────────
    # Uses a simple threading.Timer loop (like fleet/retention reapers)
    # to avoid gevent + APScheduler AssertionError with preload_app=True.
    app._alert_scheduler_started = False
    app._alert_eval_interval = config.get("ALERT_EVAL_INTERVAL_SECONDS", 60)
    app._check_scheduler_started = False

    def _start_alert_evaluator(application):
        """Start the alert evaluation loop.

        Runs the timer in EVERY worker, unlike the flock-gated reapers:
        ``evaluate_rules`` itself takes a DB-level eval lock with a TTL, so
        only one worker actually evaluates per cycle and the lock self-heals
        if the owning worker hangs or is recycled — the safest possible
        design for the component that drives live monitoring status.
        """
        if not application.config.get("ALERTS_ENABLED", True):
            return
        if application._alert_scheduler_started:
            return
        application._alert_scheduler_started = True

        from app.alert_manager import evaluate_rules

        def _alert_eval_loop():
            try:
                evaluate_rules(application)
            except Exception:
                logger.exception("Alert eval loop error")
            timer = threading.Timer(application._alert_eval_interval, _alert_eval_loop)
            timer.daemon = True
            timer.start()

        timer = threading.Timer(5, _alert_eval_loop)
        timer.daemon = True
        timer.start()
        logger.info(
            "Alert evaluator started (interval=%ds, pid=%d)",
            application._alert_eval_interval,
            os.getpid(),
        )

        # Seed default monitoring group on first run — guarded by a one-shot
        # flock so only one worker seeds even though the evaluator runs in
        # every worker (and the seed itself is idempotent via a count check).
        from app.worker_locks import acquire_worker_lock as _acquire_lock
        from app.worker_locks import release_worker_lock as _release_lock

        if _acquire_lock("seed_default_group"):
            try:
                from app.models import get_db as get_db_conn
                from app.models import seed_default_monitoring_group

                db = get_db_conn(db_config)
                try:
                    if seed_default_monitoring_group(db):
                        logger.info(
                            "Seeded default 'Linux Servers' monitoring group with standard checks"
                        )
                except Exception:
                    logger.exception("Failed to seed default monitoring group")
                finally:
                    db.close()
            finally:
                _release_lock("seed_default_group")

    app.start_alert_evaluator = _start_alert_evaluator

    if config.get("ALERTS_ENABLED", True):
        if os.environ.get("SERVER_SOFTWARE", "").startswith("gunicorn"):
            logger.info(
                "Alert evaluator deferred to post_fork (gunicorn detected, pid=%d)", os.getpid()
            )
        else:
            _start_alert_evaluator(app)

    # ── Synthetic check scheduler ────────────────────────────────────────

    @_singleton_lock("check_scheduler")
    def _start_check_scheduler(application):
        """Start the synthetic check scheduler loop in one worker.

        The scheduler assigns synthetic checks to workers, so it must not
        run concurrently in multiple workers — the singleton flock ensures
        only one worker runs it, and it survives worker recycling.
        """
        if not application.config.get("ALERTS_ENABLED", True):
            return
        if application._check_scheduler_started:
            return
        from app.check_scheduler import CheckScheduler

        scheduler = CheckScheduler(application)
        scheduler.start()
        application._check_scheduler = scheduler
        application._check_scheduler_started = True
        logger.info(
            "Check scheduler started (interval=%ds, pid=%d)",
            int(application.config.get("CHECK_SCHEDULER_INTERVAL_SECONDS", 10)),
            os.getpid(),
        )

    app.start_check_scheduler = _start_check_scheduler

    # The synthetic check scheduler historically ran only under gunicorn
    # (via post_fork); in dev (flask run) it is not started to keep parity.

    # Initialize rate limiter
    ratelimit_enabled = config.get("RATELIMIT_ENABLED", True)
    app.config["RATELIMIT_ENABLED"] = ratelimit_enabled
    storage_uri = config.get("RATELIMIT_STORAGE_URI", "memory://")
    app.config["RATELIMIT_STORAGE_URI"] = storage_uri
    limiter.enabled = ratelimit_enabled
    limiter._storage_uri = storage_uri
    limiter.init_app(app)
    logger.info("Rate limiter initialized (enabled=%s, backend=%s)", ratelimit_enabled, storage_uri)

    # Warn when using in-process storage with multiple workers
    if (
        ratelimit_enabled
        and app.config["RATELIMIT_STORAGE_URI"].startswith("memory://")
        and os.environ.get("SERVER_SOFTWARE", "").startswith("gunicorn")
    ):
        logger.warning(
            "Rate limit backend is 'memory://' — limits are per-worker, not global. "
            "Set RATELIMIT_STORAGE_URI=redis://localhost:6379 for multi-worker deployments "
            "(pip install redis)."
        )

    # Custom 429 error handler
    @app.errorhandler(429)
    def ratelimit_handler(e):
        if request.path.startswith("/api/"):
            return jsonify(
                {
                    "error": "rate_limit_exceeded",
                    "message": f"Rate limit exceeded: {e.description}",
                }
            ), 429
        return render_template(
            "error.html",
            title="Too Many Requests",
            message="You're making too many requests. Please slow down and try again in a moment.",
        ), 429

    # Request-scoped database connection lifecycle
    app.teardown_appcontext(_close_request_db)

    # Register custom theme globals for template access
    # Lazy import to avoid circular dependency at module load time
    from app.routes.dashboard import _get_cached_stats
    from app.themes import get_all_themes, get_custom_theme_css

    @app.context_processor
    def _inject_theme_globals():
        theme_dir = app.config.get("CUSTOM_THEME_DIR")
        nav_stats = _get_cached_stats() or {}
        return {
            "custom_theme_css": get_custom_theme_css(theme_dir),
            "all_themes": get_all_themes(theme_dir),
            "nav_stats": nav_stats,
            "app_version": __version__,
        }

    # Disable template caching so file changes are picked up immediately
    app.jinja_env.auto_reload = True

    # Register custom Jinja filters
    import json as _json

    from app.country_codes import country_name

    app.jinja_env.filters["country_name"] = country_name

    def _from_json(value):
        """Parse a JSON string into a dict/list. Returns {} on failure."""
        if not value:
            return {}
        if isinstance(value, dict):
            return value
        try:
            return _json.loads(value)
        except (TypeError, ValueError):
            return {}

    app.jinja_env.filters["from_json"] = _from_json

    def _node_display_name(node_id):
        """Resolve node_id to its display_name, falling back to node_id."""
        if not node_id:
            return "—"
        from flask import current_app, g

        # Cache the lookup map per-request to avoid repeated queries
        if not hasattr(g, "_node_display_map"):
            try:
                db = get_db(current_app.config["DATABASE_PATH"])
                rows = db.execute("SELECT node_id, display_name FROM nodes").fetchall()
                g._node_display_map = {
                    r["node_id"]: r["display_name"] for r in rows if r["display_name"]
                }
                db.close()
            except Exception:
                g._node_display_map = {}

        return g._node_display_map.get(node_id, node_id)

    app.jinja_env.filters["node_display_name"] = _node_display_name

    @app.context_processor
    def _inject_node_display_map():
        """Make node_id→display_name map available to all templates."""
        from flask import current_app

        node_map = {}
        try:
            db = get_db(current_app.config["DATABASE_PATH"])
            rows = db.execute("SELECT node_id, display_name FROM nodes").fetchall()
            node_map = {r["node_id"]: r["display_name"] for r in rows if r["display_name"]}
            db.close()
        except Exception:
            pass
        return dict(node_display_map=node_map)

    def _pretty_duration(seconds):
        """Convert a number of seconds to a human-readable duration string.

        60 → "1m", 3600 → "1h", 86400 → "1d", 90061 → "1d 1h 1m"
        """
        try:
            seconds = int(seconds)
        except (TypeError, ValueError):
            return str(seconds) if seconds else "—"
        if seconds <= 0:
            return "—"
        days = seconds // 86400
        seconds %= 86400
        hours = seconds // 3600
        seconds %= 3600
        minutes = seconds // 60
        seconds %= 60
        parts = []
        if days:
            parts.append(f"{days}d")
        if hours:
            parts.append(f"{hours}h")
        if minutes:
            parts.append(f"{minutes}m")
        if seconds and not parts:
            parts.append(f"{seconds}s")
        return " ".join(parts)

    app.jinja_env.filters["pretty_duration"] = _pretty_duration

    # Initialize connection debug monitor (writes stats to a dedicated log)
    from app.routes.connection_debug import init_connection_debug

    init_connection_debug(app)

    # Log GeoIP database status at startup (eager, not lazy)
    from app.geo import _HAS_MAXMINDDB
    from app.geo import _find_db as _geo_find_db

    if _HAS_MAXMINDDB:
        for _key in ("country", "city", "asn"):
            _path = _geo_find_db(_key)
            if _path:
                logger.info("GeoIP %s DB: %s", _key, _path)
            else:
                logger.info("GeoIP %s DB: not found", _key)
    else:
        logger.info("GeoIP: not available (maxminddb package not installed)")

    # ── GeoIP auto-updater ─────────────────────────────────────────────
    # Downloads fresh DB-IP Lite databases monthly and clears the in-process
    # MMDB reader cache so new lookups open the new files without a restart.
    # Runs on a 24-hour recheck loop so it catches a new monthly release
    # within a day.
    app._geoip_updater_started = False
    _geoip_update_interval = 86400  # recheck every 24h

    @_singleton_lock("geoip_updater")
    def _start_geoip_updater(application):
        if application._geoip_updater_started:
            return
        application._geoip_updater_started = True
        geo_dir = application.config.get("GEOIP_DIR", "/etc/vespid-server/geoip")
        initial_delay = 10  # 10s — quick, but after the app is fully initialized

        def _geoip_update_loop():
            try:
                from app.geo import clear_cache
                from app.geo_updater import update_geoip

                if update_geoip(geo_dir):
                    clear_cache()
                    logger.info(
                        "GeoIP databases updated, reader cache cleared (pid=%d)",
                        os.getpid(),
                    )
            except Exception:
                logger.exception("GeoIP update failed (pid=%d)", os.getpid())
            timer = threading.Timer(_geoip_update_interval, _geoip_update_loop)
            timer.daemon = True
            timer.start()

        timer = threading.Timer(initial_delay, _geoip_update_loop)
        timer.daemon = True
        timer.start()
        logger.info(
            "GeoIP updater started (delay=%ds, interval=%ds, pid=%d)",
            initial_delay,
            _geoip_update_interval,
            os.getpid(),
        )

    app.start_geoip_updater = _start_geoip_updater

    if os.environ.get("SERVER_SOFTWARE", "").startswith("gunicorn"):
        logger.info("GeoIP updater deferred to post_fork (gunicorn detected, pid=%d)")
    else:
        _start_geoip_updater(app)

    logger.info("Vespid Server application created successfully")

    from app.openapi_models import HealthResponse

    _health_tag = [Tag(name="Health", description="Liveness and readiness probes")]

    # ------------------------------------------------------------------ #
    # Health-check endpoints (no auth — for load balancer / k8s probes)
    # ------------------------------------------------------------------ #

    @app.get(
        "/healthz",
        summary="Liveness probe",
        description="Returns 200 when the process is alive. Used by load balancers and orchestrators.",
        tags=_health_tag,
        responses={200: HealthResponse},
    )
    def healthz():
        """Liveness probe — always returns 200 when the process is alive."""
        return jsonify({"status": "ok"}), 200

    @app.get(
        "/readyz",
        summary="Readiness probe",
        description="Returns 200 when the database is reachable, 503 otherwise. "
        "Used by load balancers and orchestrators to determine if the service can accept traffic.",
        tags=_health_tag,
        responses={
            200: HealthResponse,
            503: HealthResponse,
        },
    )
    def readyz():
        """Readiness probe — returns 200 when DB is reachable, 503 otherwise."""
        try:
            db_path = app.config.get("DATABASE_PATH", "")
            db = get_db(db_path)
            db.execute("SELECT 1").fetchone()
            db.close()
            return jsonify({"status": "ok"}), 200
        except Exception:
            return jsonify({"status": "error", "message": "Database unreachable"}), 503

    return app
