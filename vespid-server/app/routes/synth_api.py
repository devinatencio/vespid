"""Synthetic Checks API blueprint — worker management, check CRUD, alert rules, policies.

Endpoints:
    GET    /api/v1/workers/<worker_id>/stream                   — SSE stream for worker (Bearer auth)
    POST   /api/v1/workers/register                             — Register/heartbeat worker (Bearer auth)
    GET    /api/v1/workers/<worker_id>/jobs                     — Poll assigned jobs (Bearer auth)
    POST   /api/v1/workers/<worker_id>/jobs/<job_id>/result     — Submit job result (Bearer auth)
    GET    /api/v1/synthetic-checks                             — List checks
    POST   /api/v1/synthetic-checks                             — Create check
    GET    /api/v1/synthetic-checks/<check_id>                  — Get check
    PUT    /api/v1/synthetic-checks/<check_id>                  — Update check
    DELETE /api/v1/synthetic-checks/<check_id>                  — Archive check
    GET    /api/v1/synthetic-checks/<check_id>/history          — Check job history
    GET    /api/v1/synthetic-alerts                             — List alert rules
    GET    /api/v1/synthetic-alerts/<rule_id>                   — Get alert rule
    POST   /api/v1/synthetic-alerts                             — Create alert rule
    PUT    /api/v1/synthetic-alerts/<rule_id>                   — Update alert rule
    DELETE /api/v1/synthetic-alerts/<rule_id>                   — Delete alert rule
    POST   /api/v1/synthetic-alerts/<rule_id>/resolve           — Resolve alert
    GET    /api/v1/synthetic-alert-policies                     — List policies
    PUT    /api/v1/synthetic-alert-policies/<policy_id>         — Update policy
    POST   /api/v1/synthetic-alert-policies/reconcile-all       — Reconcile all policies
    POST   /api/v1/synthetic-alert-policies/<policy_id>/reconcile — Reconcile single policy
"""

import json
import logging
from datetime import UTC, datetime

from flask import Response, current_app, jsonify, request
from flask_openapi3 import APIBlueprint
from flask_openapi3.models import Tag

from app.agent_auth import authenticate_agent_request
from app.decorators import require_role
from app.models import get_db

synth_api_bp = APIBlueprint(
    "synth_api",
    __name__,
    abp_tags=[
        Tag(
            name="Synthetic Checks",
            description="Synthetic monitoring checks, workers, alert rules, and policies",
        )
    ],
    abp_security=[{"BearerAuth": []}, {"SessionAuth": []}],
)
logger = logging.getLogger(__name__)


def _validate_http_steps(config: dict) -> str | None:
    steps = config.get("steps")
    if steps is None:
        return None
    if not isinstance(steps, list):
        return "steps must be an array"
    valid_methods = {"GET", "POST", "PUT", "DELETE", "PATCH"}
    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            return f"step {i + 1} must be an object"
        method = step.get("method", "GET")
        if method not in valid_methods:
            return f"step {i + 1} has invalid method: {method}"
    return None


def _now() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Worker SSE Stream ─────────────────────────────────────────────────────


@synth_api_bp.get(
    "/api/v1/workers/<worker_id>/stream",
    summary="Worker SSE stream",
    description="SSE stream for worker job notifications. Bearer auth required.",
    security=[{"BearerAuth": []}],
)
@require_role("agent")
def worker_sse(worker_id: str):
    api_key, err = authenticate_agent_request(path_param="worker_id")
    if err is not None:
        return err

    sse_manager = current_app.check_worker_sse_manager

    def generate():
        yield from sse_manager.subscribe(worker_id, timeout=30.0)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ── Worker Registration ───────────────────────────────────────────────────


@synth_api_bp.post(
    "/api/v1/workers/register",
    summary="Register worker",
    description="Register or heartbeat a synthetic worker node. Bearer auth required.",
    security=[{"BearerAuth": []}],
)
@require_role("agent")
def worker_register():
    api_key, err = authenticate_agent_request(body_fields=("worker_id",))
    if err is not None:
        return err

    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid_json"}), 400

    worker_id = data.get("worker_id", "").strip()
    hostname = data.get("hostname", "").strip()
    version = data.get("version", "0.0.0")
    capabilities = json.dumps(data.get("capabilities", []))
    labels = json.dumps(data.get("labels", {}))
    max_concurrent = int(data.get("max_concurrent", 10))
    running_jobs = int(data.get("running_jobs", 0))
    status = data.get("status", "online")

    if not worker_id:
        return jsonify({"error": "missing worker_id"}), 400

    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        db.execute(
            "REPLACE INTO synthetic_workers "
            "(id, hostname, version, capabilities, labels, max_concurrent, running_jobs, status, last_heartbeat_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                worker_id,
                hostname,
                version,
                capabilities,
                labels,
                max_concurrent,
                running_jobs,
                status,
                _now(),
            ),
        )
        db.commit()
    finally:
        db.close()

    return jsonify({"ok": True})


# ── Job Polling ───────────────────────────────────────────────────────────


@synth_api_bp.get(
    "/api/v1/workers/<worker_id>/jobs",
    summary="Poll worker jobs",
    description="Poll for assigned jobs. Returns up to max_concurrent jobs. Bearer auth required.",
    security=[{"BearerAuth": []}],
)
@require_role("agent")
def worker_jobs(worker_id: str):
    api_key, err = authenticate_agent_request(path_param="worker_id")
    if err is not None:
        return err

    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        worker_row = db.execute(
            "SELECT max_concurrent, running_jobs FROM synthetic_workers WHERE id=?", (worker_id,)
        ).fetchone()
        if worker_row is None:
            return jsonify({"error": "worker not found"}), 404

        max_concurrent = worker_row["max_concurrent"]
        running = worker_row["running_jobs"]
        available = max_concurrent - running
        if available <= 0:
            return jsonify({"jobs": []})

        db.execute(
            "UPDATE synthetic_check_jobs SET status='assigned', assigned_to=?, assigned_at=? "
            "WHERE assigned_to IS NULL AND status='pending' "
            "ORDER BY scheduled_at ASC LIMIT ?",
            (worker_id, _now(), available),
        )
        db.commit()

        rows = db.execute(
            "SELECT * FROM synthetic_check_jobs WHERE assigned_to=? AND status='assigned'",
            (worker_id,),
        ).fetchall()

        jobs = []
        for row in rows:
            check_row = db.execute(
                "SELECT id, name, check_type, target, check_config, timeout_secs "
                "FROM synthetic_checks WHERE id=?",
                (row["check_id"],),
            ).fetchone()
            if check_row is None:
                continue

            job_data = {
                "job_id": row["id"],
                "check_id": check_row["id"],
                "check_name": check_row["name"],
                "check_type": check_row["check_type"],
                "target": check_row["target"],
                "check_config": json.loads(check_row["check_config"]),
                "timeout_secs": check_row["timeout_secs"],
                "location": row["location"],
            }
            jobs.append(job_data)

            db.execute(
                "UPDATE synthetic_workers SET running_jobs = running_jobs + 1, last_heartbeat_at=? "
                "WHERE id=?",
                (_now(), worker_id),
            )

        if jobs:
            db.commit()

        return jsonify({"jobs": jobs})
    finally:
        db.close()


# ── Result Submission ─────────────────────────────────────────────────────


@synth_api_bp.post(
    "/api/v1/workers/<worker_id>/jobs/<int:job_id>/result",
    summary="Submit job result",
    description="Submit result for a completed job. Bearer auth required.",
    security=[{"BearerAuth": []}],
)
@require_role("agent")
def worker_result(worker_id: str, job_id: int):
    api_key, err = authenticate_agent_request(path_param="worker_id")
    if err is not None:
        return err

    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid_json"}), 400

    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        job = db.execute(
            "SELECT * FROM synthetic_check_jobs WHERE id=? AND assigned_to=?",
            (job_id, worker_id),
        ).fetchone()

        if job is None:
            return jsonify({"error": "job not found or not assigned to this worker"}), 404

        success = data.get("success", False)
        duration_ms = data.get("duration_ms", 0)
        error_msg = data.get("error_message")
        result_json = json.dumps(data.get("details", {}))
        status_code = data.get("status_code")
        status = "completed" if success else "failed"

        db.execute(
            "UPDATE synthetic_check_jobs SET status=?, completed_at=?, result_json=?, "
            "error_message=?, duration_ms=? WHERE id=?",
            (status, _now(), result_json, error_msg, duration_ms, job_id),
        )

        db.execute(
            "UPDATE synthetic_workers SET running_jobs = CASE WHEN running_jobs > 0 THEN running_jobs - 1 ELSE 0 END, "
            "last_heartbeat_at=? WHERE id=?",
            (_now(), worker_id),
        )

        db.execute(
            "UPDATE synthetic_checks SET last_result_status=?, last_duration_ms=?, "
            "last_error=?, last_result_at=? WHERE id=?",
            (status if success else "failed", duration_ms, error_msg, _now(), job["check_id"]),
        )
        db.commit()

        check_row = db.execute(
            "SELECT id, name, check_type FROM synthetic_checks WHERE id=?",
            (job["check_id"],),
        ).fetchone()

        if check_row:
            _push_metrics(
                check_row, job["location"], duration_ms, success, status_code, data.get("details")
            )
    finally:
        db.close()

    return jsonify({"ok": True})


def _push_metrics(check, location: str, duration_ms: int, success: bool, status_code, details=None):
    try:
        from urllib import request as urllib_request

        vm_url = current_app.config.get("VICTORIAMETRICS_URL", "http://localhost:8428")
        import_url = f"{vm_url.rstrip('/')}/api/v1/import/prometheus"

        labels = 'check_id="{}",check_name="{}",check_type="{}",location="{}"'.format(
            check["id"], check["name"].replace('"', '\\"'), check["check_type"], location
        )
        now_ms = int(datetime.now(UTC).timestamp() * 1000)

        body = (
            f"vespid_synthetic_check_duration_ms{{{labels}}} {duration_ms} {now_ms}\n"
            f"vespid_synthetic_check_success{{{labels}}} {1 if success else 0} {now_ms}\n"
        )

        if status_code is not None:
            body += f"vespid_synthetic_check_status_code{{{labels}}} {status_code} {now_ms}\n"

        if details:
            check_type = check["check_type"]
            if check_type == "icmp" and details.get("rtt_avg_ms") is not None:
                body += "vespid_synthetic_check_rtt_ms{{{}}} {} {}\n".format(
                    labels, details["rtt_avg_ms"], now_ms
                )
            elif check_type == "http" and details.get("body_match") is not None:
                body += "vespid_synthetic_check_body_match{{{}}} {} {}\n".format(
                    labels, 1 if details["body_match"] else 0, now_ms
                )
            elif check_type == "dns" and details.get("answer_count") is not None:
                body += "vespid_synthetic_check_dns_answers{{{}}} {} {}\n".format(
                    labels, details["answer_count"], now_ms
                )
            elif check_type == "tcp" and details.get("connect_time_ms") is not None:
                body += "vespid_synthetic_check_connect_time_ms{{{}}} {} {}\n".format(
                    labels, details["connect_time_ms"], now_ms
                )
            elif check_type == "ssl" and details.get("days_remaining") is not None:
                body += "vespid_synthetic_check_days_remaining{{{}}} {} {}\n".format(
                    labels, details["days_remaining"], now_ms
                )

        req = urllib_request.Request(
            import_url,
            data=body.encode(),
            method="POST",
            headers={"Content-Type": "text/plain"},
        )
        urllib_request.urlopen(req, timeout=10)
    except Exception:
        logger.warning("Failed to push synthetic check metrics to VictoriaMetrics", exc_info=True)


# ── Check CRUD API ────────────────────────────────────────────────────────


def _row_to_check(row) -> dict:
    check = dict(row)
    for f in ("check_config", "locations"):
        try:
            check[f] = json.loads(check.get(f, "{}"))
        except (json.JSONDecodeError, TypeError):
            check[f] = {} if f == "check_config" else []
    return check


@synth_api_bp.get(
    "/api/v1/synthetic-checks",
    summary="List synthetic checks",
    description="List all synthetic checks. Viewer+ required.",
)
@require_role("viewer")
def list_checks_api():
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        rows = db.execute(
            "SELECT * FROM synthetic_checks WHERE status != 'archived' ORDER BY name"
        ).fetchall()
        checks = []
        for row in rows:
            checks.append(_row_to_check(row))
        return jsonify({"checks": checks})
    finally:
        db.close()


@synth_api_bp.post(
    "/api/v1/synthetic-checks",
    summary="Create synthetic check",
    description="Create a synthetic check. Admin only.",
)
@require_role("admin")
def create_check_api():
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid_json"}), 400

    name = data.get("name", "").strip()
    check_type = data.get("check_type", "").strip()
    target = data.get("target", "").strip()
    check_config = json.dumps(data.get("check_config", {}))
    locations = json.dumps(data.get("locations", []))
    interval_secs = int(data.get("interval_secs", 60))
    timeout_secs = int(data.get("timeout_secs", 30))
    auto_create_rule = data.get("auto_create_rule", True)

    if not name or not check_type or not target:
        return jsonify({"error": "name, check_type, and target are required"}), 400
    if check_type not in ("icmp", "http", "tcp", "dns", "ssl"):
        return jsonify({"error": "invalid check_type"}), 400
    if check_type == "http":
        raw_config = data.get("check_config", {})
        step_err = _validate_http_steps(raw_config)
        if step_err:
            return jsonify({"error": step_err}), 400

    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        cur = db.execute(
            "INSERT INTO synthetic_checks (name, check_type, target, check_config, locations, "
            "interval_secs, timeout_secs, status) VALUES (?, ?, ?, ?, ?, ?, ?, 'active')",
            (name, check_type, target, check_config, locations, interval_secs, timeout_secs),
        )
        db.commit()
        check_id = cur.lastrowid
        check = db.execute("SELECT * FROM synthetic_checks WHERE id=?", (check_id,)).fetchone()
        if auto_create_rule:
            _reconcile_policies_for_check(db, check_id, check_type)
        return jsonify({"check": _row_to_check(check) if check else None}), 201
    finally:
        db.close()


@synth_api_bp.get(
    "/api/v1/synthetic-checks/<int:check_id>",
    summary="Get synthetic check",
    description="Get a single synthetic check. Viewer+ required.",
)
@require_role("viewer")
def get_check_api(check_id: int):
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        row = db.execute("SELECT * FROM synthetic_checks WHERE id=?", (check_id,)).fetchone()
        if row is None:
            return jsonify({"error": "not found"}), 404
        return jsonify({"check": _row_to_check(row)})
    finally:
        db.close()


@synth_api_bp.put(
    "/api/v1/synthetic-checks/<int:check_id>",
    summary="Update synthetic check",
    description="Update a synthetic check. Admin only.",
)
@require_role("admin")
def update_check_api(check_id: int):
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid_json"}), 400

    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        row = db.execute("SELECT * FROM synthetic_checks WHERE id=?", (check_id,)).fetchone()
        if row is None:
            return jsonify({"error": "not found"}), 404

        name = data.get("name", row["name"])
        target = data.get("target", row["target"])
        check_config = json.dumps(data.get("check_config", json.loads(row["check_config"])))
        locations = json.dumps(data.get("locations", json.loads(row["locations"])))
        interval_secs = int(data.get("interval_secs", row["interval_secs"]))
        timeout_secs = int(data.get("timeout_secs", row["timeout_secs"]))
        status = data.get("status", row["status"])

        if "check_config" in data:
            step_err = _validate_http_steps(data["check_config"])
            if step_err:
                return jsonify({"error": step_err}), 400

        db.execute(
            "UPDATE synthetic_checks SET name=?, target=?, check_config=?, locations=?, "
            "interval_secs=?, timeout_secs=?, status=?, next_run_at=NULL WHERE id=?",
            (name, target, check_config, locations, interval_secs, timeout_secs, status, check_id),
        )
        db.commit()
        updated = db.execute("SELECT * FROM synthetic_checks WHERE id=?", (check_id,)).fetchone()
        return jsonify({"check": _row_to_check(updated) if updated else None})
    finally:
        db.close()


@synth_api_bp.delete(
    "/api/v1/synthetic-checks/<int:check_id>",
    summary="Archive synthetic check",
    description="Archive a synthetic check. Admin only.",
)
@require_role("admin")
def delete_check_api(check_id: int):
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        db.execute(
            "UPDATE synthetic_alert_rules SET enabled=0, policy_deleted_check_id=? "
            "WHERE check_id = ? AND policy_id IS NOT NULL AND policy_overridden = 0",
            (check_id, check_id),
        )
        db.execute("UPDATE synthetic_checks SET status='archived' WHERE id=?", (check_id,))
        db.commit()
        return jsonify({"ok": True})
    finally:
        db.close()


@synth_api_bp.get(
    "/api/v1/synthetic-checks/<int:check_id>/history",
    summary="Check job history",
    description="Get job result history for a check. Viewer+ required.",
)
@require_role("viewer")
def check_history_api(check_id: int):
    limit = max(1, min(int(request.args.get("limit", 100)), 500))
    offset = max(0, int(request.args.get("offset", 0) or 0))
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        rows = db.execute(
            "SELECT * FROM synthetic_check_jobs WHERE check_id=? "
            "ORDER BY completed_at DESC LIMIT ? OFFSET ?",
            (check_id, limit, offset),
        ).fetchall()
        jobs = []
        for row in rows:
            job = dict(row)
            if job.get("result_json"):
                try:
                    job["result_json"] = json.loads(job["result_json"])
                except (json.JSONDecodeError, TypeError):
                    pass
            jobs.append(job)
        return jsonify({"jobs": jobs})
    finally:
        db.close()


# ── Alert Rules API ───────────────────────────────────────────────────────


@synth_api_bp.get(
    "/api/v1/synthetic-alerts",
    summary="List alert rules",
    description="List all synthetic alert rules with check names. Viewer+ required.",
)
@require_role("viewer")
def list_alerts_api():
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        rows = db.execute(
            "SELECT r.*, COALESCE(sc.name, '(deleted)') as check_name, sc.target as check_target "
            "FROM synthetic_alert_rules r "
            "LEFT JOIN synthetic_checks sc ON r.check_id = sc.id "
            "WHERE r.policy_deleted_check_id IS NULL "
            "ORDER BY r.name"
        ).fetchall()
        rules = []
        for row in rows:
            r = dict(row)
            try:
                r["notification_channels"] = json.loads(row["notification_channels"])
            except (json.JSONDecodeError, TypeError):
                r["notification_channels"] = []
            rules.append(r)
        return jsonify({"rules": rules})
    finally:
        db.close()


@synth_api_bp.get(
    "/api/v1/synthetic-alerts/<int:rule_id>",
    summary="Get alert rule",
    description="Get a single synthetic alert rule. Viewer+ required.",
)
@require_role("viewer")
def get_alert_api(rule_id: int):
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        row = db.execute("SELECT * FROM synthetic_alert_rules WHERE id=?", (rule_id,)).fetchone()
        if row is None:
            return jsonify({"error": "not found"}), 404
        r = dict(row)
        try:
            r["notification_channels"] = json.loads(r["notification_channels"])
        except (json.JSONDecodeError, TypeError):
            r["notification_channels"] = []
        return jsonify({"rule": r})
    finally:
        db.close()


@synth_api_bp.post(
    "/api/v1/synthetic-alerts",
    summary="Create alert rule",
    description="Create a synthetic alert rule. Admin only.",
)
@require_role("admin")
def create_alert_api():
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid_json"}), 400

    name = data.get("name", "").strip()
    check_id = int(data.get("check_id", 0))
    location = data.get("location") or None
    failures = int(data.get("failures", 3))
    severity = data.get("severity", "critical")
    channels = json.dumps(data.get("notification_channels", []))
    enabled = int(data.get("enabled", True))

    condition_type = data.get("condition_type", "failure")
    if condition_type not in ("failure", "metric", "dns_answer_change"):
        return jsonify(
            {"error": "condition_type must be 'failure', 'metric', or 'dns_answer_change'"}
        ), 400

    metric_name = data.get("metric_name") or None
    metric_operator = data.get("metric_operator") or None
    metric_threshold = data.get("metric_threshold") or None
    consecutive_occurrences = int(data.get("consecutive_occurrences", 3))
    dns_change_persist = int(data.get("dns_change_persist", False))

    if condition_type == "metric":
        if not metric_name:
            return jsonify({"error": "metric_name is required for metric condition"}), 400
        if not metric_threshold:
            return jsonify({"error": "metric_threshold is required for metric condition"}), 400
        if metric_operator not in (">", ">=", "<", "<=", "==", "!="):
            return jsonify({"error": "invalid metric_operator"}), 400

    if not name or not check_id:
        return jsonify({"error": "name and check_id are required"}), 400

    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        check = db.execute("SELECT id FROM synthetic_checks WHERE id=?", (check_id,)).fetchone()
        if check is None:
            return jsonify({"error": "check not found"}), 400

        db.execute(
            "DELETE FROM synthetic_alert_rules WHERE check_id = ? AND policy_id IS NOT NULL AND policy_overridden = 0",
            (check_id,),
        )

        cur = db.execute(
            "INSERT INTO synthetic_alert_rules (name, check_id, location, failures, severity, "
            "notification_channels, enabled, condition_type, metric_name, metric_operator, "
            "metric_threshold, consecutive_occurrences, dns_change_persist) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                name,
                check_id,
                location,
                failures,
                severity,
                channels,
                enabled,
                condition_type,
                metric_name,
                metric_operator,
                metric_threshold,
                consecutive_occurrences,
                dns_change_persist,
            ),
        )
        db.commit()
        row = db.execute(
            "SELECT * FROM synthetic_alert_rules WHERE id=?", (cur.lastrowid,)
        ).fetchone()
        r = dict(row)
        r["notification_channels"] = json.loads(r["notification_channels"])
        return jsonify({"rule": r}), 201
    finally:
        db.close()


@synth_api_bp.put(
    "/api/v1/synthetic-alerts/<int:rule_id>",
    summary="Update alert rule",
    description="Update a synthetic alert rule. Admin only.",
)
@require_role("admin")
def update_alert_api(rule_id: int):
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid_json"}), 400

    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        row = db.execute("SELECT * FROM synthetic_alert_rules WHERE id=?", (rule_id,)).fetchone()
        if row is None:
            return jsonify({"error": "not found"}), 404

        name = data.get("name", row["name"])
        location = data.get("location", row["location"])
        failures = int(data.get("failures", row["failures"]))
        severity = data.get("severity", row["severity"])
        channels = json.dumps(
            data.get(
                "notification_channels",
                json.loads(row["notification_channels"]) if row["notification_channels"] else [],
            )
        )
        enabled = int(data.get("enabled", row["enabled"]))

        condition_type = data.get(
            "condition_type", row["condition_type"] if "condition_type" in row.keys() else "failure"
        )
        metric_name = data.get(
            "metric_name", row["metric_name"] if "metric_name" in row.keys() else None
        )
        metric_operator = data.get(
            "metric_operator", row["metric_operator"] if "metric_operator" in row.keys() else None
        )
        metric_threshold = data.get(
            "metric_threshold",
            row["metric_threshold"] if "metric_threshold" in row.keys() else None,
        )
        consecutive_occurrences = int(
            data.get(
                "consecutive_occurrences",
                row["consecutive_occurrences"] if "consecutive_occurrences" in row.keys() else 3,
            )
        )
        dns_change_persist = int(
            data.get(
                "dns_change_persist",
                row["dns_change_persist"] if "dns_change_persist" in row.keys() else 0,
            )
        )

        if condition_type == "metric":
            if not metric_name:
                return jsonify({"error": "metric_name is required for metric condition"}), 400
            if not metric_threshold:
                return jsonify({"error": "metric_threshold is required for metric condition"}), 400

        db.execute(
            "UPDATE synthetic_alert_rules SET name=?, location=?, failures=?, severity=?, "
            "notification_channels=?, enabled=?, condition_type=?, metric_name=?, "
            "metric_operator=?, metric_threshold=?, consecutive_occurrences=?, dns_change_persist=?, "
            "policy_overridden=1 WHERE id=?",
            (
                name,
                location,
                failures,
                severity,
                channels,
                enabled,
                condition_type,
                metric_name,
                metric_operator,
                metric_threshold,
                consecutive_occurrences,
                dns_change_persist,
                rule_id,
            ),
        )
        db.commit()
        updated = db.execute(
            "SELECT * FROM synthetic_alert_rules WHERE id=?", (rule_id,)
        ).fetchone()
        r = dict(updated)
        r["notification_channels"] = json.loads(r["notification_channels"])
        return jsonify({"rule": r})
    finally:
        db.close()


@synth_api_bp.delete(
    "/api/v1/synthetic-alerts/<int:rule_id>",
    summary="Delete alert rule",
    description="Delete a synthetic alert rule. Admin only.",
)
@require_role("admin")
def delete_alert_api(rule_id: int):
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        row = db.execute(
            "SELECT id, check_id, policy_id FROM synthetic_alert_rules WHERE id=?", (rule_id,)
        ).fetchone()
        if row is None:
            return jsonify({"error": "not found"}), 404
        if row["policy_id"]:
            db.execute(
                "UPDATE synthetic_alert_rules SET enabled=0, policy_deleted_check_id=? WHERE id=?",
                (row["check_id"], rule_id),
            )
        else:
            db.execute("DELETE FROM synthetic_alert_rules WHERE id=?", (rule_id,))
        db.commit()
        return jsonify({"ok": True})
    finally:
        db.close()


@synth_api_bp.post(
    "/api/v1/synthetic-alerts/<int:rule_id>/resolve",
    summary="Resolve alert",
    description="Manually resolve a firing DNS change alert. Admin only.",
)
@require_role("admin")
def resolve_alert_api(rule_id: int):
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        db.execute(
            "UPDATE synthetic_alert_rules SET firing=0, dns_change_count=0 WHERE id=?",
            (rule_id,),
        )
        db.commit()
        logger.info("Synthetic alert manually resolved: id=%d", rule_id)
        return jsonify({"ok": True})
    finally:
        db.close()


# ── Alert Policy Reconciliation helpers ────────────────────────────────────


def _get_relevant_policies(db, check_type, check_config_json):
    try:
        policies = db.execute(
            "SELECT * FROM synthetic_alert_policies WHERE enabled = 1 AND check_type = ?",
            (check_type,),
        ).fetchall()
    except Exception:
        return []

    if check_type != "dns":
        return policies

    try:
        cfg = (
            json.loads(check_config_json)
            if isinstance(check_config_json, str)
            else check_config_json
        )
    except (json.JSONDecodeError, TypeError):
        cfg = {}

    has_expected = bool(cfg.get("expected_value"))
    result = []
    for p in policies:
        try:
            cond = json.loads(p["condition_config"])
        except (json.JSONDecodeError, TypeError):
            cond = {}
        ctype = cond.get("type")
        if has_expected and ctype == "failure":
            result.append(p)
        elif not has_expected and ctype == "dns_answer_change":
            result.append(p)
    return result


def _reconcile_policies_for_check(db, check_id, check_type) -> None:
    chk = db.execute(
        "SELECT id, name, check_config FROM synthetic_checks WHERE id=?", (check_id,)
    ).fetchone()
    if not chk:
        return

    policies = _get_relevant_policies(db, check_type, chk["check_config"])

    for policy in policies:
        pid = policy["id"]
        try:
            cond = json.loads(policy["condition_config"])
        except (json.JSONDecodeError, TypeError):
            cond = {}

        existing = db.execute(
            "SELECT id, policy_overridden FROM synthetic_alert_rules "
            "WHERE policy_id = ? AND check_id = ? AND policy_deleted_check_id IS NULL",
            (pid, check_id),
        ).fetchone()

        if existing:
            if existing["policy_overridden"]:
                continue
            _update_rule_from_policy(db, existing["id"], check_type, cond, pid)
        else:
            has_custom = db.execute(
                "SELECT id FROM synthetic_alert_rules WHERE check_id = ? AND policy_id IS NULL",
                (check_id,),
            ).fetchone()
            if has_custom:
                continue
            _create_rule_from_policy(db, pid, check_type, cond, policy, chk)


def _reconcile_policies(db) -> None:
    try:
        policies = db.execute("SELECT * FROM synthetic_alert_policies WHERE enabled = 1").fetchall()
    except Exception:
        return

    by_type: dict[str, list] = {}
    for p in policies:
        by_type.setdefault(p["check_type"], []).append(p)

    for ctype, ctype_policies in by_type.items():
        checks = db.execute(
            "SELECT id, name, check_config FROM synthetic_checks WHERE check_type = ? AND status != 'archived'",
            (ctype,),
        ).fetchall()

        for chk in checks:
            check_id = chk["id"]
            if ctype == "dns":
                check_policies = _get_relevant_policies(db, ctype, chk["check_config"])
            else:
                check_policies = ctype_policies

            for policy in check_policies:
                pid = policy["id"]
                try:
                    cond = json.loads(policy["condition_config"])
                except (json.JSONDecodeError, TypeError):
                    cond = {}

                db.execute(
                    "DELETE FROM synthetic_alert_rules WHERE policy_id = ? AND policy_deleted_check_id = ?",
                    (pid, check_id),
                )

                existing = db.execute(
                    "SELECT id, policy_overridden FROM synthetic_alert_rules "
                    "WHERE policy_id = ? AND check_id = ? AND policy_deleted_check_id IS NULL",
                    (pid, check_id),
                ).fetchone()

                if existing:
                    if existing["policy_overridden"]:
                        continue
                    _update_rule_from_policy(db, existing["id"], ctype, cond, pid)
                else:
                    has_custom = db.execute(
                        "SELECT id FROM synthetic_alert_rules "
                        "WHERE check_id = ? AND policy_id IS NULL",
                        (check_id,),
                    ).fetchone()
                    if has_custom:
                        continue
                    _create_rule_from_policy(db, pid, ctype, cond, policy, chk)


def _create_rule_from_policy(db, pid, ctype, cond, policy, chk) -> None:
    cond_type = cond.get("type", "failure")
    check_id = chk["id"]
    check_name = chk["name"]
    rule_name = f"{policy['name']} — {check_name}"

    if cond_type == "failure":
        failures = cond.get("failures", 3)
        db.execute(
            "INSERT INTO synthetic_alert_rules "
            "(name, check_id, severity, condition_type, failures, "
            "notification_channels, enabled, consecutive_occurrences, policy_id) "
            "VALUES (?, ?, ?, 'failure', ?, '[]', 1, ?, ?)",
            (rule_name, check_id, policy["severity"], failures, failures, pid),
        )
    elif cond_type == "metric":
        db.execute(
            "INSERT INTO synthetic_alert_rules "
            "(name, check_id, severity, condition_type, metric_name, metric_operator, "
            "metric_threshold, consecutive_occurrences, notification_channels, enabled, policy_id) "
            "VALUES (?, ?, ?, 'metric', ?, ?, ?, ?, '[]', 1, ?)",
            (
                rule_name,
                check_id,
                policy["severity"],
                cond.get("metric_name"),
                cond.get("metric_operator"),
                cond.get("metric_threshold"),
                cond.get("consecutive_occurrences", 3),
                pid,
            ),
        )
    elif cond_type == "dns_answer_change":
        consecutive = cond.get("consecutive_occurrences", 1)
        dns_persist = cond.get("dns_change_persist", 1)
        db.execute(
            "INSERT INTO synthetic_alert_rules "
            "(name, check_id, severity, condition_type, consecutive_occurrences, "
            "dns_change_persist, notification_channels, enabled, policy_id) "
            "VALUES (?, ?, ?, 'dns_answer_change', ?, ?, '[]', 1, ?)",
            (rule_name, check_id, policy["severity"], consecutive, dns_persist, pid),
        )
    db.commit()
    logger.info("Policy rule created: %s (check=%d, policy=%d)", rule_name, check_id, pid)


def _update_rule_from_policy(db, rule_id, ctype, cond, pid) -> None:
    cond_type = cond.get("type", "failure")
    if cond_type == "failure":
        failures = cond.get("failures", 3)
        db.execute(
            "UPDATE synthetic_alert_rules SET failures=?, consecutive_occurrences=? WHERE id=?",
            (failures, failures, rule_id),
        )
    elif cond_type == "metric":
        db.execute(
            "UPDATE synthetic_alert_rules SET metric_name=?, metric_operator=?, "
            "metric_threshold=?, consecutive_occurrences=? WHERE id=?",
            (
                cond.get("metric_name"),
                cond.get("metric_operator"),
                cond.get("metric_threshold"),
                cond.get("consecutive_occurrences", 3),
                rule_id,
            ),
        )
    elif cond_type == "dns_answer_change":
        db.execute(
            "UPDATE synthetic_alert_rules SET consecutive_occurrences=?, dns_change_persist=? WHERE id=?",
            (cond.get("consecutive_occurrences", 1), cond.get("dns_change_persist", 1), rule_id),
        )
    db.commit()


# ── Alert Policy API Endpoints ─────────────────────────────────────────


@synth_api_bp.get(
    "/api/v1/synthetic-alert-policies",
    summary="List alert policies",
    description="List all alert policies with rule counts. Viewer+ required.",
)
@require_role("viewer")
def list_policies_api():
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        rows = db.execute("SELECT * FROM synthetic_alert_policies ORDER BY name").fetchall()
        policies = []
        for row in rows:
            p = dict(row)
            try:
                p["condition_config"] = json.loads(p["condition_config"])
            except (json.JSONDecodeError, TypeError):
                p["condition_config"] = {}
            rule_count = db.execute(
                "SELECT COUNT(*) FROM synthetic_alert_rules WHERE policy_id = ?", (p["id"],)
            ).fetchone()[0]
            firing_count = db.execute(
                "SELECT COUNT(*) FROM synthetic_alert_rules WHERE policy_id = ? AND firing = 1",
                (p["id"],),
            ).fetchone()[0]
            p["rule_count"] = rule_count
            p["firing_count"] = firing_count
            policies.append(p)
        return jsonify({"policies": policies})
    finally:
        db.close()


@synth_api_bp.put(
    "/api/v1/synthetic-alert-policies/<int:policy_id>",
    summary="Update alert policy",
    description="Update an alert policy (toggle enable, change config). Admin only.",
)
@require_role("admin")
def update_policy_api(policy_id: int):
    try:
        data = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid_json"}), 400

    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        row = db.execute(
            "SELECT * FROM synthetic_alert_policies WHERE id=?", (policy_id,)
        ).fetchone()
        if row is None:
            return jsonify({"error": "not found"}), 404

        enabled = int(data.get("enabled", row["enabled"]))
        condition_config = json.dumps(
            data.get("condition_config", json.loads(row["condition_config"]))
        )

        db.execute(
            "UPDATE synthetic_alert_policies SET enabled=?, condition_config=? WHERE id=?",
            (enabled, condition_config, policy_id),
        )
        db.commit()

        _reconcile_policies(db)

        if enabled:
            db.execute(
                "UPDATE synthetic_alert_rules SET enabled=1 WHERE policy_id = ? AND policy_overridden = 0 AND policy_deleted_check_id IS NULL",
                (policy_id,),
            )
        else:
            db.execute(
                "UPDATE synthetic_alert_rules SET enabled=0 WHERE policy_id = ? AND policy_overridden = 0",
                (policy_id,),
            )
        db.commit()

        updated = db.execute(
            "SELECT * FROM synthetic_alert_policies WHERE id=?", (policy_id,)
        ).fetchone()
        return jsonify({"policy": dict(updated)})
    finally:
        db.close()


@synth_api_bp.post(
    "/api/v1/synthetic-alert-policies/reconcile-all",
    summary="Reconcile all policies",
    description="Reconcile all policies with current checks. Admin only.",
)
@require_role("admin")
def reconcile_all_policies_api():
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        _reconcile_policies(db)
        return jsonify({"ok": True})
    finally:
        db.close()


@synth_api_bp.post(
    "/api/v1/synthetic-alert-policies/<int:policy_id>/reconcile",
    summary="Reconcile single policy",
    description="Reconcile a single policy. Admin only.",
)
@require_role("admin")
def reconcile_policy_api(policy_id: int):
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        db.execute("UPDATE synthetic_alert_policies SET enabled=1 WHERE id=?", (policy_id,))
        db.commit()
        _reconcile_policies(db)
        return jsonify({"ok": True})
    finally:
        db.close()
