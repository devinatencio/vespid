"""Metrics blueprint — dashboard pages only.

API endpoints moved to app/routes/metrics_api.py.

Endpoints:
    GET  /metrics                 — Fleet metrics overview dashboard (viewer+)
    GET  /metrics/<agent_id>      — Per-host metric detail dashboard (viewer+)
    GET  /metrics/query           — PromQL query explorer (viewer+)
    GET  /metrics/checks          — Health checks dashboard (viewer+)
"""

import json
import logging
from datetime import UTC, datetime
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError
from urllib.parse import quote as url_quote

from flask import (
    Blueprint,
    current_app,
    make_response,
    redirect,
    render_template,
    url_for,
)

from app.decorators import require_role
from app.models import (
    get_db,
    get_latest_check_results,
)

metrics_bp = Blueprint("metrics", __name__)
logger = logging.getLogger(__name__)


# ── VictoriaMetrics client ────────────────────────────────────────────


def _vm_url(path: str) -> str:
    base = current_app.config.get("VICTORIAMETRICS_URL", "http://localhost:8428")
    return f"{base.rstrip('/')}{path}"


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


# ── Dashboard helpers ─────────────────────────────────────────────────


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


def _get_host_info(agent_id: str) -> dict | None:
    result = _vm_query(f'vespid_monitor_cpu_idle_seconds_total{{agent_id="{agent_id}"}}')
    if not result or result.get("status") != "success":
        return None
    data = result.get("data", {}).get("result", [])
    if not data:
        return None

    metric = data[0].get("metric", {})
    return {
        "agent_id": agent_id,
        "hostname": metric.get("hostname", agent_id),
    }


# ── Dashboard pages ───────────────────────────────────────────────────


@metrics_bp.route("/metrics")
@require_role("viewer")
def overview():
    vm_url = current_app.config.get("VICTORIAMETRICS_URL", "http://localhost:8428")
    if not current_app.config.get("METRICS_ENABLED"):
        return render_template("metrics/disabled.html")

    agents = _get_known_agents()
    summary = _build_fleet_summary(agents)
    resp = make_response(
        render_template(
            "metrics/overview.html",
            agents=agents,
            summary=summary,
            vm_url=vm_url,
        )
    )
    resp.headers["Cache-Control"] = "no-store, must-revalidate"
    return resp


@metrics_bp.route("/metrics/<agent_id>")
@require_role("viewer")
def host_detail(agent_id: str):
    vm_url = current_app.config.get("VICTORIAMETRICS_URL", "http://localhost:8428")
    if not current_app.config.get("METRICS_ENABLED"):
        return render_template("metrics/disabled.html")

    host_info = _get_host_info(agent_id)
    if not host_info:
        return render_template("metrics/not_found.html", agent_id=agent_id), 404

    return render_template(
        "metrics/host_detail.html",
        agent_id=agent_id,
        host=host_info,
        vm_url=vm_url,
    )


@metrics_bp.route("/metrics/query")
@require_role("viewer")
def query_explorer():
    if not current_app.config.get("METRICS_ENABLED"):
        return redirect(url_for("metrics.overview"))
    return render_template("metrics/query.html")


@metrics_bp.route("/metrics/checks")
@require_role("viewer")
def checks_dashboard():
    if not current_app.config.get("METRICS_ENABLED"):
        return redirect(url_for("metrics.overview"))

    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        results = get_latest_check_results(db)
    finally:
        db.close()

    return render_template("metrics/checks.html", results=results)
