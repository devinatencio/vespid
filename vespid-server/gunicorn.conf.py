"""Gunicorn configuration for Vespid Server.

Production settings for running behind systemd. Override individual
values via environment variables (GUNICORN_BIND, GUNICORN_WORKERS, etc.)
or by editing this file directly.

Uses gevent (greenlet-based) workers for high concurrency with minimal
resource usage. Each worker can handle thousands of concurrent connections
via cooperative scheduling — SSE streams that sit idle cost almost nothing.

Sizing guidance:
  - Workers: 1 per CPU core is the sweet spot with gevent. Each worker
    multiplexes many connections internally via greenlets, so you don't
    need extra workers for concurrency.
  - worker_connections: Max simultaneous connections per worker. Set this
    high enough to cover all SSE streams + API requests hitting one worker.
  - With 2 cores: 2 workers × 1000 connections = 2000 concurrent capacity.

Requires: pip install gevent

IMPORTANT: Monkey-patching must happen before anything else is imported.
With preload_app=True the app is loaded in the master process, so we
patch here at module level to ensure threading, queue, socket, etc. are
all gevent-aware before create_app() instantiates SSE managers and timers.
"""

from gevent import monkey

monkey.patch_all()  # must happen before other imports (see docstring above)

import logging
import multiprocessing
import os
import uuid

try:
    from app.config import load_config

    _cfg = load_config()
    _host = _cfg.get("HOST", "0.0.0.0")
    _port = _cfg.get("PORT", 8000)
    _default_bind = f"{_host}:{_port}"
except Exception:
    _default_bind = "127.0.0.1:8000"

# Bind address — from GUNICORN_BIND env var, or app config HOST:PORT, or 127.0.0.1:8000
bind = os.environ.get("GUNICORN_BIND", _default_bind)

# Worker class — gevent uses greenlets (cooperative coroutines) for
# massive concurrency without OS thread overhead. SSE streams, DB waits,
# and idle keepalive connections all multiplex within a single OS thread.
worker_class = os.environ.get("GUNICORN_WORKER_CLASS", "gevent")

# Worker count — with gevent, each worker handles many connections
# internally. One worker per core is sufficient; the greenlet scheduler
# handles the rest.
_cpu = multiprocessing.cpu_count()
workers = int(os.environ.get("GUNICORN_WORKERS", _cpu))

# Max simultaneous connections per worker. Gevent can handle thousands
# of idle connections cheaply. Size this for your peak: number of nodes
# (heartbeats + events) + dashboard SSE streams + API requests.
worker_connections = int(os.environ.get("GUNICORN_WORKER_CONNECTIONS", "1000"))

# Worker timeout in seconds — with gevent this is a heartbeat check on
# the worker process. If a worker is stuck in a blocking C extension
# (not yielding to the gevent hub), it gets killed after this timeout.
timeout = int(os.environ.get("GUNICORN_TIMEOUT", "120"))

# Graceful timeout for worker restart
graceful_timeout = 30

# Keep-alive connections (seconds) — set above the node heartbeat interval
# so persistent connections from nodes stay open between heartbeats.
# Gevent handles idle keepalive connections with near-zero cost.
keepalive = int(os.environ.get("GUNICORN_KEEPALIVE", "65"))

# Max requests per worker before recycling — prevents memory leaks from
# accumulating over long uptimes. Jitter avoids all workers restarting
# at once.
max_requests = int(os.environ.get("GUNICORN_MAX_REQUESTS", "8000"))
max_requests_jitter = int(os.environ.get("GUNICORN_MAX_REQUESTS_JITTER", "800"))

# Preload the app in the master process before forking workers. This means:
#  - Faster worker startups (no redundant imports per worker)
#  - Lower memory usage (shared pages via copy-on-write)
#  - GeoIP readers, config parsing, etc. happen once not N times
# Trade-off: code changes require a full restart (not graceful reload).
preload_app = True

# Logging
accesslog = os.environ.get("GUNICORN_ACCESS_LOG", "/var/log/vespid-server/access.log")
errorlog = os.environ.get("GUNICORN_ERROR_LOG", "/var/log/vespid-server/error.log")
loglevel = os.environ.get("GUNICORN_LOG_LEVEL", "info")

# Suppress GreenletExit tracebacks logged during worker shutdown/reload.
# These are normal teardown noise, not actionable errors.
logging.getLogger("gunicorn.error").addFilter(lambda r: "GreenletExit" not in r.getMessage())

# Access log format — includes X-Request-Id for correlation with app logs.
# Text format (default):
access_log_format = (
    '%(h)s %(l)s %(u)s %(t)s "%(r)s" %(s)s %(b)s "%(f)s" "%(a)s" rid=%({X-Request-Id}i)s D=%(D)s'
)
# To enable JSON access logs for SIEM integration, set GUNICORN_ACCESS_LOG_FORMAT=json:
if os.environ.get("GUNICORN_ACCESS_LOG_FORMAT", "text").lower() == "json":
    access_log_format = (
        '{"time":"%(t)s","rid":"%({X-Request-Id}i)s","method":"%(m)s",'
        '"path":"%(U)s","qs":"%(q)s","status":"%(s)s","size":"%(B)s",'
        '"referer":"%(f)s","agent":"%(a)s","remote_addr":"%(h)s",'
        '"duration_us":"%(D)s","duration_ms":"%(L)s"}'
    )

# Process naming
proc_name = "vespid-server"


def pre_request(worker, req):
    """Generate a request ID before each request.

    Injects X-Request-Id into the WSGI environ so both gunicorn's
    access log and Flask's request.headers can read it.
    """
    has_rid = any(k.lower() == "x-request-id" for k, _ in req.headers)
    if not has_rid:
        req.headers.append(("X-Request-Id", str(uuid.uuid4())[:12]))


def post_fork(server, worker):
    """Called in each worker process after fork.

    Starts the fleet reaper, retention reaper, command reaper, backup
    reaper, alert evaluator, and check scheduler.  Each of these is
    guarded by a kernel-backed singleton lock (flock) so that across the
    worker pool exactly one worker runs each service.  The locks are
    released automatically when the owning process exits, so services
    survive worker recycling (max_requests / crashes / graceful reloads):
    a replacement worker re-acquires the lock in its own post_fork call.
    """
    try:
        app = server.app.wsgi()

        if hasattr(app, "start_fleet_reaper"):
            app.start_fleet_reaper(app)

        if hasattr(app, "start_retention_reaper"):
            app.start_retention_reaper(app)
        if hasattr(app, "start_host_events_reaper"):
            app.start_host_events_reaper(app)
        if hasattr(app, "start_command_reaper"):
            app.start_command_reaper(app)
        if hasattr(app, "start_geoip_updater"):
            app.start_geoip_updater(app)
        if hasattr(app, "_db_config"):
            from app.db_backup import start_backup_reaper

            start_backup_reaper(app, app._db_config)

        # Alert evaluator + synthetic check scheduler — each singleton-locked
        if hasattr(app, "start_alert_evaluator"):
            app.start_alert_evaluator(app)
        if hasattr(app, "start_check_scheduler"):
            app.start_check_scheduler(app)
    except Exception as exc:
        logging.getLogger("app").error("Failed to start services in post_fork: %s", exc)


def on_reload(server):
    """Called in the master when gunicorn receives SIGHUP (graceful reload).

    Resets the app's tracking flags so the freshly forked workers re-attempt
    to start the singleton services.  The kernel releases the old worker's
    flock when it exits, so a new worker acquires each lock in post_fork
    (with a short retry covering the drain window).
    """
    try:
        app = server.app.wsgi()
        if hasattr(app, "start_fleet_reaper"):
            app._fleet_reaper_started = False
        if hasattr(app, "start_retention_reaper"):
            app._retention_reaper_started = False
        if hasattr(app, "start_host_events_reaper"):
            app._host_events_reaper_started = False
        if hasattr(app, "start_command_reaper"):
            app._command_reaper_started = False
        if hasattr(app, "_alert_scheduler_started"):
            app._alert_scheduler_started = False
        if hasattr(app, "_check_scheduler_started"):
            app._check_scheduler_started = False
        if hasattr(app, "_geoip_updater_started"):
            app._geoip_updater_started = False
        if hasattr(app, "_backup_reaper_started"):
            app._backup_reaper_started = False
    except Exception:
        pass
