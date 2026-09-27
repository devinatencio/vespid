"""Connection debug monitor for Vespid Server.

Periodically writes connection statistics to a dedicated debug file so
operators can monitor gevent worker saturation, SSE client counts, and
request throughput without relying on access.log.

The debug file is written as JSON-lines (one JSON object per snapshot)
to /var/log/vespid-server/connection_debug.log by default, configurable
via the CONNECTION_DEBUG_LOG config key or VESPID_CONNECTION_DEBUG_LOG
environment variable.

Also registers a Flask blueprint with a /_debug/connections endpoint
(localhost-only by default) for on-demand inspection.

Includes per-request timing middleware that logs slow requests (>2s) to
help identify what's blocking when the WebUI spins.

Usage:
    In app/__init__.py, after create_app():
        from app.routes.connection_debug import init_connection_debug
        init_connection_debug(app)
"""

from __future__ import annotations

import json
import logging
import os
import threading
import time
from collections import deque
from datetime import UTC, datetime

from flask import Blueprint, current_app, g, jsonify, request

from app.decorators import require_role

logger = logging.getLogger(__name__)

# Default path for the debug log file
_DEFAULT_DEBUG_LOG = "/var/log/vespid-server/connection_debug.log"

# Default snapshot interval in seconds
_DEFAULT_INTERVAL = 30

# Slow request threshold in seconds
_SLOW_REQUEST_THRESHOLD = 2.0

# Blueprint for the debug endpoint
debug_bp = Blueprint("connection_debug", __name__)

# Ring buffer of recent slow requests (shared across the worker process)
_slow_requests: deque[dict] = deque(maxlen=100)

# Ring buffer of all recent requests for throughput tracking
_recent_requests: deque[dict] = deque(maxlen=1000)

# Lock for the request buffers
_request_lock = threading.Lock()


def _get_gevent_stats() -> dict:
    """Collect gevent pool and greenlet statistics.

    Returns a dict with:
      - pool_size: max greenlets in the pool (worker_connections)
      - pool_free: available greenlet slots
      - pool_used: active greenlets handling requests
      - pool_utilization_pct: percentage of pool in use
      - total_greenlets: all greenlets in the hub (includes internal ones)
    """
    stats = {}
    try:
        import gevent
        from gevent.pool import Pool

        stats["total_greenlets"] = len(gevent.get_objects())  # type: ignore[attr-defined]
    except Exception:
        pass

    # Try to get the gunicorn worker's pool info
    try:
        # In a gevent gunicorn worker, the pool is accessible via the
        # worker's server object. We can also inspect it via the
        # gunicorn.workers.ggevent module internals.
        import gc

        from gevent.pool import Pool

        # Find the active gevent pool(s) by scanning gc objects
        pools = [obj for obj in gc.get_referrers(Pool) if isinstance(obj, Pool)]
        if not pools:
            # Alternative: look for Pool instances directly
            pools = [obj for obj in gc.get_objects() if isinstance(obj, Pool)]

        if pools:
            # Use the largest pool (the worker connection pool)
            pool = max(pools, key=lambda p: p.size)
            stats["pool_size"] = pool.size
            stats["pool_free"] = pool.free_count()
            stats["pool_used"] = pool.size - pool.free_count()
            stats["pool_utilization_pct"] = round(
                (stats["pool_used"] / stats["pool_size"]) * 100, 1
            )
        else:
            stats["pool_size"] = None
            stats["pool_free"] = None
            stats["pool_used"] = None
            stats["pool_utilization_pct"] = None
    except Exception as exc:
        stats["pool_error"] = str(exc)

    # Fallback: count greenlets via gevent
    try:
        import greenlet

        stats["total_greenlets"] = greenlet.getcurrent().parent is not None
        # Count all greenlets
        import gc

        greenlet_count = sum(1 for obj in gc.get_objects() if isinstance(obj, greenlet.greenlet))
        stats["total_greenlets"] = greenlet_count
    except Exception:
        pass

    return stats


def _get_sse_stats(app) -> dict:
    """Collect SSE manager connection counts."""
    stats = {}

    if hasattr(app, "sse_manager"):
        stats["sse_events_clients"] = app.sse_manager.client_count

    if hasattr(app, "fleet_sse_manager"):
        stats["sse_fleet_clients"] = app.fleet_sse_manager.client_count

    if hasattr(app, "config_sse_manager"):
        stats["sse_config_clients"] = app.config_sse_manager.client_count
        # Config SSE also tracks which nodes are connected
        try:
            stats["sse_config_nodes"] = app.config_sse_manager.get_connected_nodes()
        except Exception:
            pass

    stats["sse_total_clients"] = (
        stats.get("sse_events_clients", 0)
        + stats.get("sse_fleet_clients", 0)
        + stats.get("sse_config_clients", 0)
    )

    return stats


def _get_worker_info() -> dict:
    """Get gunicorn worker identity info."""
    info = {}
    info["pid"] = os.getpid()
    info["ppid"] = os.getppid()

    # Try to get worker connections setting from env
    info["worker_connections_configured"] = int(
        os.environ.get("GUNICORN_WORKER_CONNECTIONS", "1000")
    )

    return info


def _get_request_stats() -> dict:
    """Compute request throughput and slow request stats from ring buffers."""
    now = time.time()
    stats = {}

    with _request_lock:
        # Requests in the last 60 seconds
        recent_60s = [r for r in _recent_requests if now - r["time"] < 60]
        recent_10s = [r for r in _recent_requests if now - r["time"] < 10]

        stats["requests_last_60s"] = len(recent_60s)
        stats["requests_last_10s"] = len(recent_10s)
        stats["rps_avg_60s"] = round(len(recent_60s) / 60.0, 2)
        stats["rps_avg_10s"] = round(len(recent_10s) / 10.0, 2)

        # Slow requests in the last 5 minutes
        slow_5m = [r for r in _slow_requests if now - r["time"] < 300]
        stats["slow_requests_last_5m"] = len(slow_5m)

        # Top 10 slowest recent requests
        stats["slowest_recent"] = sorted(slow_5m, key=lambda r: r["duration"], reverse=True)[:10]

    return stats


def collect_snapshot(app) -> dict:
    """Collect a full connection debug snapshot.

    Returns a dict with timestamp, gevent pool stats, SSE client counts,
    worker identity info, and request throughput.
    """
    snapshot = {
        "timestamp": datetime.now(UTC).isoformat(),
        "worker": _get_worker_info(),
        "gevent": _get_gevent_stats(),
        "sse": _get_sse_stats(app),
        "requests": _get_request_stats(),
    }

    # Compute overall connection pressure
    pool_size = snapshot["gevent"].get("pool_size")
    sse_total = snapshot["sse"].get("sse_total_clients", 0)
    if pool_size:
        # SSE connections are long-lived and consume a greenlet each
        snapshot["pressure"] = {
            "sse_connections": sse_total,
            "pool_capacity": pool_size,
            "sse_pct_of_pool": round((sse_total / pool_size) * 100, 1),
            "remaining_for_requests": pool_size - sse_total,
            "warning": sse_total > (pool_size * 0.8),
        }
    else:
        snapshot["pressure"] = {
            "sse_connections": sse_total,
            "pool_capacity": "unknown",
            "note": "Could not determine gevent pool size",
        }

    return snapshot


class ConnectionDebugMonitor:
    """Background thread that periodically writes connection snapshots."""

    def __init__(self, app, log_path: str, interval: float):
        self.app = app
        self.log_path = log_path
        self.interval = interval
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._latest_snapshot: dict | None = None

    def start(self):
        """Start the background monitor thread."""
        self._thread = threading.Thread(
            target=self._run, name="connection-debug-monitor", daemon=True
        )
        self._thread.start()
        logger.info(
            "Connection debug monitor started (interval=%ds, log=%s)",
            self.interval,
            self.log_path,
        )

    def stop(self):
        """Signal the monitor thread to stop."""
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)

    def _run(self):
        """Main loop: collect and write snapshots.

        Skips writing if this is the gunicorn master process (ppid=1 or
        no gevent pool detected) since the master doesn't serve requests.
        """
        while not self._stop_event.is_set():
            try:
                with self.app.app_context():
                    snapshot = collect_snapshot(self.app)
                    self._latest_snapshot = snapshot

                    # Skip logging for the gunicorn master process —
                    # it has no gevent pool and doesn't serve requests.
                    if snapshot["gevent"].get("pool_size") is not None:
                        self._write_snapshot(snapshot)
            except Exception:
                logger.exception("Connection debug monitor error")

            self._stop_event.wait(self.interval)

    def _write_snapshot(self, snapshot: dict):
        """Append a JSON-lines entry to the debug log file."""
        try:
            log_dir = os.path.dirname(self.log_path)
            if log_dir and not os.path.isdir(log_dir):
                os.makedirs(log_dir, exist_ok=True)

            with open(self.log_path, "a") as f:
                f.write(json.dumps(snapshot, separators=(",", ":")) + "\n")
        except OSError as exc:
            logger.warning("Failed to write connection debug log: %s", exc)

    @property
    def latest(self) -> dict | None:
        """Return the most recent snapshot (for the debug endpoint)."""
        return self._latest_snapshot


# Module-level reference so the blueprint can access it
_monitor: ConnectionDebugMonitor | None = None


@debug_bp.route("/_debug/connections", methods=["GET"])
@require_role("admin")
def debug_connections():
    """Return current connection statistics as JSON.

    By default restricted to localhost requests. Set
    CONNECTION_DEBUG_ALLOW_REMOTE=true in config to allow remote access.
    """
    allow_remote = current_app.config.get("CONNECTION_DEBUG_ALLOW_REMOTE", False)

    if not allow_remote:
        # Only allow from loopback addresses
        remote = request.remote_addr
        if remote not in ("127.0.0.1", "::1", "localhost"):
            return jsonify({"error": "forbidden"}), 403

    # Collect a fresh snapshot on demand
    snapshot = collect_snapshot(current_app._get_current_object())

    # Also include the last periodic snapshot timestamp for comparison
    if _monitor and _monitor.latest:
        snapshot["last_periodic_snapshot"] = _monitor.latest.get("timestamp")

    return jsonify(snapshot)


@debug_bp.route("/_debug/connections/history", methods=["GET"])
@require_role("admin")
def debug_connections_history():
    """Return the last N lines from the connection debug log.

    Query params:
        lines: number of lines to return (default 50, max 500)
    """
    allow_remote = current_app.config.get("CONNECTION_DEBUG_ALLOW_REMOTE", False)

    if not allow_remote:
        remote = request.remote_addr
        if remote not in ("127.0.0.1", "::1", "localhost"):
            return jsonify({"error": "forbidden"}), 403

    lines_requested = min(int(request.args.get("lines", 50)), 500)

    log_path = current_app.config.get(
        "CONNECTION_DEBUG_LOG",
        os.environ.get("VESPID_CONNECTION_DEBUG_LOG", _DEFAULT_DEBUG_LOG),
    )

    if not os.path.isfile(log_path):
        return jsonify({"error": "no debug log found", "path": log_path}), 404

    try:
        with open(log_path) as f:
            # Read all lines and return the last N
            all_lines = f.readlines()
            tail = all_lines[-lines_requested:]

        entries = []
        for line in tail:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    entries.append({"raw": line})

        return jsonify(
            {
                "total_entries": len(all_lines),
                "returned": len(entries),
                "entries": entries,
            }
        )
    except OSError as exc:
        logger.error("Debug connection history read failed: %s", exc)
        return jsonify({"error": "Unable to read connection debug log"}), 500


@debug_bp.route("/_debug/slow", methods=["GET"])
@require_role("admin")
def debug_slow_requests():
    """Return recent slow requests (>2s response time).

    Useful for identifying which endpoints are blocking when the UI spins.
    """
    allow_remote = current_app.config.get("CONNECTION_DEBUG_ALLOW_REMOTE", False)

    if not allow_remote:
        remote = request.remote_addr
        if remote not in ("127.0.0.1", "::1", "localhost"):
            return jsonify({"error": "forbidden"}), 403

    now = time.time()
    with _request_lock:
        # All slow requests in the last 10 minutes
        slow_10m = [r for r in _slow_requests if now - r["time"] < 600]

    # Group by path
    by_path: dict[str, list] = {}
    for r in slow_10m:
        path = r.get("path", "unknown")
        by_path.setdefault(path, []).append(r)

    summary = []
    for path, reqs in sorted(by_path.items(), key=lambda x: -len(x[1])):
        durations = [r["duration"] for r in reqs]
        summary.append(
            {
                "path": path,
                "count": len(reqs),
                "avg_duration_s": round(sum(durations) / len(durations), 3),
                "max_duration_s": round(max(durations), 3),
                "recent": sorted(reqs, key=lambda r: -r["duration"])[:5],
            }
        )

    return jsonify(
        {
            "slow_threshold_s": _SLOW_REQUEST_THRESHOLD,
            "window_minutes": 10,
            "total_slow": len(slow_10m),
            "by_path": summary,
        }
    )


def init_connection_debug(app) -> ConnectionDebugMonitor:
    """Initialize the connection debug monitor and register the blueprint.

    Call this in create_app() after all SSE managers are initialized.

    Config keys:
        CONNECTION_DEBUG_LOG: Path to the debug log file
            (default: /var/log/vespid-server/connection_debug.log)
        CONNECTION_DEBUG_INTERVAL: Snapshot interval in seconds (default: 30)
        CONNECTION_DEBUG_ENABLED: Set to True to enable (default: False)
        CONNECTION_DEBUG_ALLOW_REMOTE: Allow non-localhost access to
            /_debug/connections (default: False)
    """
    global _monitor

    enabled = app.config.get("CONNECTION_DEBUG_ENABLED", False)
    if not enabled:
        logger.info("Connection debug monitor disabled by config")
        return None  # type: ignore[return-value]

    log_path = app.config.get(
        "CONNECTION_DEBUG_LOG",
        os.environ.get("VESPID_CONNECTION_DEBUG_LOG", _DEFAULT_DEBUG_LOG),
    )
    interval = app.config.get("CONNECTION_DEBUG_INTERVAL", _DEFAULT_INTERVAL)

    # Register the debug blueprint
    app.register_blueprint(debug_bp)

    # Install request timing middleware
    _install_request_timing(app)

    # Create and start the monitor
    _monitor = ConnectionDebugMonitor(app, log_path, interval)
    _monitor.start()

    return _monitor


def _install_request_timing(app):
    """Install before/after request hooks to track request duration.

    Logs slow requests (>2s) to the slow_requests ring buffer and tracks
    all requests for throughput calculation. Also logs slow requests to
    the Python logger so they appear in error.log.
    """

    @app.before_request
    def _start_timer():
        g._debug_start_time = time.time()

    @app.after_request
    def _record_timing(response):
        start = getattr(g, "_debug_start_time", None)
        if start is None:
            return response

        duration = time.time() - start
        path = request.path
        method = request.method

        # Skip SSE streams (they're long-lived by design)
        if "stream" in path or response.content_type == "text/event-stream":
            return response

        # Skip the debug endpoints themselves
        if path.startswith("/_debug/"):
            return response

        entry = {
            "time": time.time(),
            "path": path,
            "method": method,
            "status": response.status_code,
            "duration": round(duration, 4),
        }

        with _request_lock:
            _recent_requests.append(entry)

            if duration >= _SLOW_REQUEST_THRESHOLD:
                entry_with_detail = {
                    **entry,
                    "remote_addr": request.remote_addr,
                    "query_string": request.query_string.decode("utf-8", errors="replace")[:200],
                }
                _slow_requests.append(entry_with_detail)

        # Log slow requests to error.log for immediate visibility
        if duration >= _SLOW_REQUEST_THRESHOLD:
            logger.warning(
                "SLOW REQUEST: %s %s -> %d (%.3fs) from %s",
                method,
                path,
                response.status_code,
                duration,
                request.remote_addr,
            )

        return response
