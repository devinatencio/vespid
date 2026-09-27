"""Metrics API blueprint — agent ingestion, VictoriaMetrics proxy, logfile watches, saved queries.

Endpoints:
    POST /api/v1/metrics/write                    — Ingest metric batch (Bearer auth)
    POST /api/v1/metrics/checks                   — Ingest health-check results (Bearer auth)
    GET  /api/v1/agent/<agent_id>/logfile-watches — Return logfile watches for agent (Bearer auth)
    GET  /api/v1/agent/<agent_id>/exec-scripts    — Return exec scripts for agent (Bearer auth)
    GET  /api/v1/logfile-watches                  — List logfile watches
    POST /api/v1/logfile-watches                  — Create logfile watch
    PUT  /api/v1/logfile-watches/<watch_id>       — Update logfile watch
    DELETE /api/v1/logfile-watches/<watch_id>     — Delete logfile watch
    GET  /metrics/api/summary                     — Fleet metrics summary
    GET  /metrics/api/query_range                 — Proxy PromQL range query
    GET  /metrics/api/labels/<label_name>         — Proxy label values
    GET  /metrics/api/query                       — Proxy PromQL instant query
    GET  /metrics/api/<agent_id>/range            — Agent range data
    GET  /metrics/api/queries                     — List saved queries
    POST /metrics/api/queries                     — Save a query
    PUT  /metrics/api/queries/<query_id>          — Update saved query
    DELETE /metrics/api/queries/<query_id>        — Delete saved query
"""

import json
import logging
import re
from datetime import UTC, datetime, timedelta
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError
from urllib.parse import quote as url_quote

from flask import Response, current_app, jsonify, request
from flask_login import current_user
from flask_openapi3 import APIBlueprint
from flask_openapi3.models import Tag

from app.agent_auth import authenticate_agent_request
from app.decorators import require_role
from app.inventory import ensure_asset
from app.models import (
    create_logfile_watch,
    delete_logfile_watch,
    delete_saved_query,
    get_db,
    get_logfile_watches,
    get_saved_queries,
    list_logfile_watches,
    record_check_result,
    save_query,
    update_logfile_watch,
    update_saved_query,
)

metrics_api_bp = APIBlueprint(
    "metrics_api",
    __name__,
    abp_tags=[
        Tag(
            name="Metrics",
            description="System metrics ingestion, VictoriaMetrics proxy, and logfile watches",
        )
    ],
    abp_security=[{"BearerAuth": []}, {"SessionAuth": []}],
)
logger = logging.getLogger(__name__)


# ── VictoriaMetrics client ────────────────────────────────────────────


def _vm_url(path: str) -> str:
    base = current_app.config.get("VICTORIAMETRICS_URL", "http://localhost:8428")
    return f"{base.rstrip('/')}{path}"


def _vm_write(data: bytes) -> bool:
    req = urllib_request.Request(
        _vm_url("/api/v1/write"),
        data=data,
        method="POST",
        headers={
            "Content-Type": "application/x-protobuf",
            "Content-Encoding": "snappy",
        },
    )
    try:
        urllib_request.urlopen(req, timeout=10)
        return True
    except (URLError, HTTPError) as exc:
        logger.error("VictoriaMetrics write failed: %s", exc)
        return False


def _vm_query(promql: str, time_param: str | None = None) -> dict | None:
    params = f"query={url_quote(promql)}"
    if time_param:
        params += f"&time={url_quote(time_param)}"
    url = _vm_url(f"/api/v1/query?{params}")
    try:
        with urllib_request.urlopen(url, timeout=10) as resp:
            return json.loads(resp.read())
    except (URLError, HTTPError, json.JSONDecodeError) as exc:
        logger.error("VictoriaMetrics query failed: %s (query: %s)", exc, promql)
        return None


def _vm_query_range(promql: str, start: str, end: str, step: str) -> dict | None:
    params = (
        f"query={url_quote(promql)}"
        f"&start={url_quote(start)}"
        f"&end={url_quote(end)}"
        f"&step={url_quote(step)}"
    )
    url = _vm_url(f"/api/v1/query_range?{params}")
    try:
        with urllib_request.urlopen(url, timeout=15) as resp:
            return json.loads(resp.read())
    except (URLError, HTTPError, json.JSONDecodeError) as exc:
        logger.error("VictoriaMetrics query_range failed: %s", exc)
        return None


# ── Metric ingest helpers ─────────────────────────────────────────────


def _metric_to_prometheus_line(metric: dict) -> str | None:
    metric_name = None
    labels = {}
    for lbl in metric.get("labels", []):
        name = lbl.get("name", "")
        value = lbl.get("value", "")
        if name == "__name__":
            metric_name = value
        else:
            labels[name] = value
    if not metric_name:
        return None
    sample = metric.get("sample", {})
    val = sample.get("value")
    ts_ms = sample.get("timestamp_ms")
    if val is None:
        return None
    label_parts = [f'{k}="{v}"' for k, v in sorted(labels.items())]
    label_str = "{" + ",".join(label_parts) + "}" if label_parts else ""
    if ts_ms:
        return f"{metric_name}{label_str} {val} {ts_ms}"
    return f"{metric_name}{label_str} {val}"


def _transform_batch(metrics: list[dict]) -> list[str]:
    lines = []
    for m in metrics:
        line = _metric_to_prometheus_line(m)
        if line:
            lines.append(line)
    return lines


# ── Agent ingest endpoint ─────────────────────────────────────────────


@metrics_api_bp.post(
    "/api/v1/metrics/write",
    summary="Ingest metric batch",
    description="Ingest a metric batch from a monitoring agent. Accepts snappy-compressed protobuf (Prometheus remote write format). Forwards raw bytes to VictoriaMetrics.",
    security=[{"BearerAuth": []}],
)
@require_role("agent")
def write():
    api_key, err = authenticate_agent_request()
    if err is not None:
        return err

    content_type = request.content_type or ""
    if "application/x-protobuf" not in content_type:
        return jsonify({"error": "unsupported_media_type"}), 415

    raw_data = request.get_data()
    if not raw_data:
        return jsonify({"error": "empty_body"}), 400

    if not _vm_write(raw_data):
        return jsonify(
            {"error": "backend_unavailable", "message": "VictoriaMetrics is not reachable"}
        ), 502

    agent_id = request.headers.get("X-Agent-ID", "")
    if agent_id:
        hostname = request.headers.get("X-Hostname", "")
        machine_id = request.headers.get("X-Machine-ID", "")
        virt_type = request.headers.get("X-Virt-Type", "")
        cpu_model = request.headers.get("X-CPU-Model", "")
        agent_version = request.headers.get("X-Agent-Version", "")
        identifiers = {}
        if hostname:
            identifiers["hostname"] = hostname
        if machine_id:
            identifiers["machine_id"] = machine_id
        meta = {}
        if virt_type:
            meta["virt_type"] = virt_type
        if cpu_model:
            meta["cpu_model"] = cpu_model
        if agent_version:
            meta["agent_version"] = agent_version
        if identifiers:
            try:
                db = get_db(current_app.config["DATABASE_PATH"])
                try:
                    aid = ensure_asset(
                        db,
                        asset_type="host",
                        display_name=hostname or agent_id,
                        source="monitor",
                        metadata=meta,
                        **identifiers,
                    )
                    now_str = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
                    try:
                        db.execute(
                            "INSERT INTO config_agent_status "
                            "(node_id, asset_id, last_check_in, config_status, agent_version) "
                            "VALUES (?, ?, ?, ?, ?)",
                            (agent_id, aid, now_str, "ok", agent_version or None),
                        )
                    except Exception:
                        db.rollback()
                        logger.debug(
                            "INSERT into config_agent_status failed, falling back to UPDATE for %s",
                            agent_id,
                        )
                        db.execute(
                            "UPDATE config_agent_status SET asset_id = ?, last_check_in = ?, "
                            "agent_version = COALESCE(?, agent_version) "
                            "WHERE node_id = ?",
                            (aid, now_str, agent_version or None, agent_id),
                        )
                    db.commit()
                finally:
                    db.close()
            except Exception:
                logger.warning("Asset resolution failed for agent %s", agent_id, exc_info=True)

    return Response(status=204)


# ── Dashboard helpers (shared with metrics.py) ────────────────────────


def _get_known_agents() -> list[dict]:
    result = _vm_query("count by (hostname, agent_id) (vespid_monitor_cpu_idle_seconds_total)")
    agents = []
    if result and result.get("status") == "success":
        for series in result.get("data", {}).get("result", []):
            metric = series.get("metric", {})
            agents.append(
                {
                    "agent_id": metric.get("agent_id", ""),
                    "hostname": metric.get("hostname", "unknown"),
                }
            )
    agents.sort(key=lambda a: a["hostname"])
    return agents


def _build_fleet_summary(agents: list[dict]) -> dict:
    agent_count = len(agents)
    total_cpu = 0.0
    total_mem = 0.0
    max_disk = 0.0
    responding = 0
    for agent in agents:
        aid = agent["agent_id"]
        cpu = _get_latest_value(
            f'100 - (avg by (agent_id) (rate(vespid_monitor_cpu_idle_seconds_total{{agent_id="{aid}",cpu!="cpu"}}[2m])) * 100)'
        )
        mem = _get_latest_value(f'vespid_monitor_memory_used_percent{{agent_id="{aid}"}}')
        disk_pct = _get_latest_value(
            f'vespid_monitor_disk_used_percent{{agent_id="{aid}",mountpoint="/"}}'
        )
        agent["cpu_pct"] = cpu
        agent["mem_pct"] = mem
        agent["disk_max_pct"] = disk_pct
        if cpu is not None or mem is not None:
            responding += 1
            total_cpu += cpu or 0
            total_mem += mem or 0
            if disk_pct is not None and disk_pct > max_disk:
                max_disk = disk_pct

    avg_cpu = total_cpu / max(responding, 1)
    avg_mem = total_mem / max(responding, 1)

    _enrich_agent_last_seen(agents)

    return {
        "agent_count": agent_count,
        "responding": responding,
        "avg_cpu_pct": round(avg_cpu, 1),
        "avg_mem_pct": round(avg_mem, 1),
        "max_disk_pct": round(max_disk, 1),
    }


def _enrich_agent_last_seen(agents: list[dict]) -> None:
    result = _vm_query("vespid_monitor_memory_used_percent")
    timestamps: dict[str, float] = {}
    if result and result.get("status") == "success":
        for series in result.get("data", {}).get("result", []):
            aid = series.get("metric", {}).get("agent_id", "")
            if aid:
                value = series.get("value", [None, None])
                if value[0] is not None:
                    timestamps[aid] = float(value[0])
    now = datetime.now(UTC).timestamp()
    for agent in agents:
        ts = timestamps.get(agent["agent_id"])
        agent["last_seen_ts"] = ts
        if ts is not None:
            sec = int(now - ts)
            if sec < 120:
                agent["last_seen_label"] = "just now" if sec < 60 else f"{sec // 60}m ago"
                agent["last_seen_class"] = "seen-fresh"
            elif sec < 300:
                agent["last_seen_label"] = f"{sec // 60}m ago"
                agent["last_seen_class"] = "seen-stale"
            else:
                agent["last_seen_label"] = (
                    f"{sec // 3600}h ago" if sec >= 3600 else f"{sec // 60}m ago"
                )
                agent["last_seen_class"] = "seen-old"
        else:
            agent["last_seen_label"] = None
            agent["last_seen_class"] = None


def _get_latest_value(promql: str) -> float | None:
    result = _vm_query(promql)
    if not result or result.get("status") != "success":
        return None
    data = result.get("data", {}).get("result", [])
    if not data:
        return None
    value = data[0].get("value", [None, None])
    try:
        return float(value[1]) if value[1] is not None else None
    except (ValueError, TypeError):
        return None


# ── Fleet summary API ─────────────────────────────────────────────────


@metrics_api_bp.get(
    "/metrics/api/summary",
    summary="Fleet metrics summary",
    description="Return current metrics summary for the fleet. Viewer+ required.",
)
@require_role("viewer")
def api_summary():
    if not current_app.config.get("METRICS_ENABLED"):
        return jsonify({"error": "metrics disabled"}), 404
    agents = _get_known_agents()
    summary = _build_fleet_summary(agents)
    return jsonify({"agents": agents, "summary": summary})


# ── VictoriaMetrics proxy APIs ────────────────────────────────────────


@metrics_api_bp.get(
    "/metrics/api/query_range",
    summary="PromQL range query",
    description="Proxy a PromQL range query to VictoriaMetrics. Viewer+ required.",
)
@require_role("viewer")
def api_query_range():
    promql = request.args.get("q", "")
    start = request.args.get("start", "-1h")
    step = request.args.get("step", "60s")
    end = request.args.get("end", "")

    if not promql:
        return jsonify({"error": "missing query"}), 400

    now = datetime.now(UTC)
    if not end:
        end = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    if start.startswith("-"):
        m = re.match(r"-(\d+)([smhd])", start)
        if m:
            val = int(m.group(1))
            unit = m.group(2)
            if unit == "s":
                delta = timedelta(seconds=val)
            elif unit == "m":
                delta = timedelta(minutes=val)
            elif unit == "h":
                delta = timedelta(hours=val)
            elif unit == "d":
                delta = timedelta(days=val)
            else:
                delta = timedelta(hours=1)
            start = (now - delta).strftime("%Y-%m-%dT%H:%M:%SZ")

    result = _vm_query_range(promql, start, end, step)
    if result is None:
        return jsonify({"error": "victoriametrics unreachable"}), 502
    return jsonify(result)


@require_role("viewer")
@metrics_api_bp.get(
    "/metrics/api/labels/<label_name>",
    summary="Label values",
    description="Proxy a label values request to VictoriaMetrics. Viewer+ required.",
)
def api_label_values(label_name: str):
    url = _vm_url(f"/api/v1/label/{url_quote(label_name)}/values")
    try:
        with urllib_request.urlopen(url, timeout=10) as resp:
            return jsonify(json.loads(resp.read()))
    except (URLError, HTTPError, json.JSONDecodeError) as exc:
        logger.error("VictoriaMetrics label values failed: %s", exc)
        return jsonify(
            {"status": "error", "error": "Query failed — check VictoriaMetrics connectivity"}
        ), 502


@metrics_api_bp.get(
    "/metrics/api/query",
    summary="PromQL instant query",
    description="Proxy a single PromQL instant query to VictoriaMetrics. Viewer+ required.",
)
@require_role("viewer")
def api_query():
    promql = request.args.get("q", "")
    if not promql:
        return jsonify({"error": "missing query"}), 400
    result = _vm_query(promql)
    if result is None:
        return jsonify({"error": "victoriametrics unreachable"}), 502
    return jsonify(result)


@metrics_api_bp.get(
    "/metrics/api/<agent_id>/range",
    summary="Agent range data",
    description="Return range-query data for a single agent's key metrics. Viewer+ required.",
)
@require_role("viewer")
def api_agent_range(agent_id: str):
    delta = request.args.get("range", "1h")
    step = "60s"

    metric_names = [
        "cpu_usage",
        "memory_used_percent",
        "disk_used_percent",
        "network_bytes_recv",
        "network_bytes_sent",
        "swap_used_percent",
        "process_count_total",
        "process_running",
        "process_zombies_count",
    ]
    promql_map = {
        "cpu_usage": f'100 - (avg by (agent_id) (rate(vespid_monitor_cpu_idle_seconds_total{{agent_id="{agent_id}",cpu!="cpu"}}[2m])) * 100)',
        "memory_used_percent": f'vespid_monitor_memory_used_percent{{agent_id="{agent_id}"}}',
        "disk_used_percent": f'vespid_monitor_disk_used_percent{{agent_id="{agent_id}",mountpoint="/"}}',
        "network_bytes_recv": f'rate(vespid_monitor_network_bytes_recv_total{{agent_id="{agent_id}"}}[2m])',
        "network_bytes_sent": f'rate(vespid_monitor_network_bytes_sent_total{{agent_id="{agent_id}"}}[2m])',
        "swap_used_percent": f'(vespid_monitor_swap_used_bytes{{agent_id="{agent_id}"}} / vespid_monitor_swap_total_bytes{{agent_id="{agent_id}"}}) * 100',
        "process_count_total": f'vespid_monitor_process_count_total{{agent_id="{agent_id}"}}',
        "process_running": f'vespid_monitor_process_running{{agent_id="{agent_id}"}}',
        "process_zombies_count": f'vespid_monitor_process_zombies_count{{agent_id="{agent_id}"}}',
    }

    start = f"{delta}" if delta in ("1h", "6h", "24h", "3d", "7d") else "1h"
    series = {}
    for key in metric_names:
        promql = promql_map.get(key, "")
        if not promql:
            continue
        result = _vm_query_range(promql, start, "", step)
        if result and result.get("status") == "success":
            data = result.get("data", {}).get("result", [])
            points = []
            for r in data:
                for t, v in r.get("values", []):
                    points.append({"t": t, "v": float(v)})
            series[key] = points

    return jsonify({"agent_id": agent_id, "series": series, "range": delta})


# ── Health checks ingest ──────────────────────────────────────────────


@metrics_api_bp.post(
    "/api/v1/metrics/checks",
    summary="Ingest health-check results",
    description="Ingest health-check results from agents running exec scripts. Bearer auth required.",
    security=[{"BearerAuth": []}],
)
@require_role("agent")
def checks_report():
    api_key, err = authenticate_agent_request(body_fields=("agent_id",))
    if err is not None:
        return err

    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid_json"}), 400

    name = data.get("name", "").strip()
    agent_id = data.get("agent_id", "").strip()
    hostname = data.get("hostname", "").strip()
    exit_code = data.get("exit_code", 0)
    output = data.get("output", "")
    duration_ms = data.get("duration_ms", 0)

    if not name or not agent_id:
        return jsonify({"error": "missing_fields"}), 400
    if not isinstance(exit_code, int):
        return jsonify({"error": "invalid_exit_code"}), 400

    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        record_check_result(db, name, agent_id, hostname, exit_code, output, duration_ms)
    finally:
        db.close()

    return Response(status=204)


# ── Logfile Watches API ────────────────────────────────────────────────


@metrics_api_bp.get(
    "/api/v1/agent/<agent_id>/logfile-watches",
    summary="Agent logfile watches",
    description="Return enabled logfile watches for an agent (polled by the agent). Bearer auth required.",
    security=[{"BearerAuth": []}],
)
@require_role("agent")
def agent_logfile_watches(agent_id: str):
    api_key, err = authenticate_agent_request(path_param="agent_id")
    if err is not None:
        return err

    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        watches = get_logfile_watches(db, agent_id)
        return jsonify({"watches": watches})
    finally:
        db.close()


@metrics_api_bp.get(
    "/api/v1/agent/<agent_id>/exec-scripts",
    summary="Agent exec scripts",
    description="Return enabled exec scripts for an agent (polled by the agent). Bearer auth required.",
    security=[{"BearerAuth": []}],
)
@require_role("agent")
def agent_exec_scripts(agent_id: str):
    api_key, err = authenticate_agent_request(path_param="agent_id")
    if err is not None:
        return err

    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        from app.models import get_exec_scripts_for_agent

        scripts = get_exec_scripts_for_agent(db, agent_id)
        return jsonify({"scripts": scripts})
    finally:
        db.close()


@metrics_api_bp.get(
    "/api/v1/logfile-watches",
    summary="List logfile watches",
    description="List logfile watches, optionally filtered by ?agent_id=. Viewer+ required.",
)
@require_role("viewer")
def list_logfile_watches_route():
    agent_id = request.args.get("agent_id")
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        watches = list_logfile_watches(db, agent_id)
        return jsonify({"watches": watches})
    finally:
        db.close()


@metrics_api_bp.post(
    "/api/v1/logfile-watches",
    summary="Create logfile watch",
    description="Create a new logfile watch. Admin only.",
)
@require_role("admin")
def create_logfile_watch_route():
    data = request.get_json(silent=True) or {}
    agent_id = (data.get("agent_id") or "").strip()
    name = (data.get("name") or "").strip()
    path = (data.get("path") or "").strip()
    pattern = (data.get("pattern") or "").strip()
    alert_on_match = data.get("alert_on_match", True)

    if not agent_id or not name or not path or not pattern:
        return jsonify({"error": "agent_id, name, path, and pattern are required"}), 400

    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        watch_id = create_logfile_watch(
            db,
            agent_id,
            name,
            path,
            pattern,
            alert_on_match=alert_on_match,
            created_by=getattr(current_user, "id", None),
        )
        return jsonify({"id": watch_id}), 201
    finally:
        db.close()


@metrics_api_bp.put(
    "/api/v1/logfile-watches/<int:watch_id>",
    summary="Update logfile watch",
    description="Update a logfile watch. Admin only.",
)
@require_role("admin")
def update_logfile_watch_route(watch_id):
    data = request.get_json(silent=True) or {}
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        ok = update_logfile_watch(
            db=db,
            watch_id=watch_id,
            name=data.get("name"),
            path=data.get("path"),
            pattern=data.get("pattern"),
            alert_on_match=data.get("alert_on_match"),
            enabled=data.get("enabled"),
        )
        if not ok:
            return jsonify({"error": "not found"}), 404
        return jsonify({"status": "updated"})
    finally:
        db.close()


@metrics_api_bp.delete(
    "/api/v1/logfile-watches/<int:watch_id>",
    summary="Delete logfile watch",
    description="Delete a logfile watch. Admin only.",
)
@require_role("admin")
def delete_logfile_watch_route(watch_id):
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        ok = delete_logfile_watch(db, watch_id)
        if not ok:
            return jsonify({"error": "not found"}), 404
        return jsonify({"status": "deleted"})
    finally:
        db.close()


# ── Saved Queries API ──────────────────────────────────────────────────


@metrics_api_bp.get(
    "/metrics/api/queries",
    summary="List saved queries",
    description="Return saved queries for the current user. Viewer+ required.",
)
@require_role("viewer")
def list_saved_queries():
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        queries = get_saved_queries(db, current_user.id)
        return jsonify({"queries": queries})
    finally:
        db.close()


@metrics_api_bp.post(
    "/metrics/api/queries",
    summary="Save query",
    description="Save a new query for the current user. Viewer+ required.",
)
@require_role("viewer")
def create_saved_query():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    query_text = (data.get("query") or "").strip()
    if not name or not query_text:
        return jsonify({"error": "name and query are required"}), 400

    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        saved = save_query(db, current_user.id, name, query_text)
        return jsonify({"query": saved}), 201
    finally:
        db.close()


@metrics_api_bp.put(
    "/metrics/api/queries/<int:query_id>",
    summary="Update saved query",
    description="Update a saved query. Viewer+ required.",
)
@require_role("viewer")
def update_saved_query_route(query_id):
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    query_text = (data.get("query") or "").strip()
    if not name or not query_text:
        return jsonify({"error": "name and query are required"}), 400

    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        ok = update_saved_query(db, query_id, current_user.id, name, query_text)
        if not ok:
            return jsonify({"error": "not found"}), 404
        return jsonify({"status": "updated"})
    finally:
        db.close()


@metrics_api_bp.delete(
    "/metrics/api/queries/<int:query_id>",
    summary="Delete saved query",
    description="Delete a saved query. Viewer+ required.",
)
@require_role("viewer")
def delete_saved_query_route(query_id):
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        ok = delete_saved_query(db, query_id, current_user.id)
        if not ok:
            return jsonify({"error": "not found"}), 404
        return jsonify({"status": "deleted"})
    finally:
        db.close()
