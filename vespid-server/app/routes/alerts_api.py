"""Alert Manager API blueprint — alert rules, events, channels, silences, monitoring groups.

Endpoints:
    GET    /health/alerts                              — Eval loop health
    GET    /alerts/api/rules                           — List alert rules
    POST   /alerts/api/rules                           — Create alert rule
    PUT    /alerts/api/rules/<id>                      — Update alert rule
    DELETE /alerts/api/rules/<id>                      — Delete alert rule
    GET    /alerts/api/active                          — List firing alerts
    GET    /alerts/api/active/count                    — Alert count
    POST   /alerts/api/events/<id>/ack                 — Acknowledge alert
    POST   /alerts/api/events/<id>/resolve             — Resolve alert
    GET    /alerts/api/history                         — Alert history
    GET    /alerts/api/channels                        — List channels
    POST   /alerts/api/channels                        — Create channel
    PUT    /alerts/api/channels/<id>                   — Update channel
    DELETE /alerts/api/channels/<id>                   — Delete channel
    POST   /alerts/api/channels/<id>/test              — Test channel
    GET    /alerts/api/silences                        — List silences
    GET    /alerts/api/silences/<id>                   — Get silence
    POST   /alerts/api/silences                        — Create silence
    PUT    /alerts/api/silences/<id>                   — Update silence
    DELETE /alerts/api/silences/<id>                   — Delete silence
    GET    /alerts/api/groups                          — List monitoring groups
    POST   /alerts/api/groups                          — Create monitoring group
    GET    /alerts/api/groups/<id>                     — Get monitoring group
    PUT    /alerts/api/groups/<id>                     — Update monitoring group
    DELETE /alerts/api/groups/<id>                     — Delete monitoring group
    POST   /alerts/api/groups/<id>/conditions          — Add condition
    PUT    /alerts/api/groups/<id>/conditions/<cid>    — Update condition
    DELETE /alerts/api/groups/<id>/conditions/<cid>    — Delete condition
    PUT    /alerts/api/groups/<id>/conditions/<cid>/channels — Set condition channels
    GET    /alerts/api/groups/<id>/instances           — List matching instances
    GET    /alerts/api/groups/<id>/active              — List firing alerts for group
    GET    /alerts/api/groups/<id>/status              — Group status matrix
    GET    /alerts/api/agents/<agent_id>               — Agent check statuses
    GET    /alerts/api/agents/<agent_id>/checks/<cid>/history — Check history
    GET    /alerts/api/hosts                           — Hosts overview
"""

import json
import logging
from datetime import UTC, datetime, timedelta

from flask import current_app, jsonify, request
from flask_login import current_user
from flask_openapi3 import APIBlueprint
from flask_openapi3.models import Tag

from app.alert_manager import build_promql, get_eval_health, resolve_agents
from app.decorators import require_role
from app.models import (
    acknowledge_alert_event,
    create_alert_rule,
    create_group_condition,
    create_monitoring_group,
    create_notification_channel,
    create_silence,
    delete_alert_rule,
    delete_group_condition,
    delete_monitoring_group,
    delete_notification_channel,
    delete_silence,
    get_active_alerts,
    get_active_group_events,
    get_agent_checks,
    get_alert_event_count,
    get_alert_history,
    get_alert_rule,
    get_alert_rules,
    get_all_hosts_status,
    get_channels_for_rule,
    get_db,
    get_group_condition,
    get_group_condition_channels,
    get_group_status_matrix,
    get_logfile_watches,
    get_monitoring_group,
    get_notification_channel,
    get_notification_channels,
    get_silence,
    get_silences,
    list_group_conditions,
    list_monitoring_groups,
    resolve_alert_event,
    set_group_condition_channels,
    set_rule_channels,
    update_alert_rule,
    update_group_condition,
    update_monitoring_group,
    update_notification_channel,
    update_silence,
)

alerts_api_bp = APIBlueprint(
    "alerts_api",
    __name__,
    abp_tags=[
        Tag(name="Alerts", description="Alert management, monitoring groups, and notifications")
    ],
    abp_security=[{"SessionAuth": []}],
)
logger = logging.getLogger(__name__)
_sentinel = object()


@alerts_api_bp.get(
    "/health/alerts",
    summary="Eval loop health",
    description="Return eval loop health status for the alert manager.",
)
@require_role("viewer")
def health_alerts():
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        health = get_eval_health(db)
        status = 200 if health["healthy"] else 503
        return jsonify(health), status
    finally:
        db.close()


@alerts_api_bp.get(
    "/alerts/api/rules",
    summary="List alert rules",
    description="List alert rules. Admins see all; users see personal + global.",
)
@require_role("viewer")
def list_rules():
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        admin_view = current_user.role == "admin"
        rules = get_alert_rules(db, user_id=current_user.id, admin_view=admin_view)
        for rule in rules:
            channels = get_channels_for_rule(db, rule["id"], default_to_all=False)
            rule["channel_ids"] = [c["id"] for c in channels]
            if rule.get("tags"):
                try:
                    rule["tags"] = json.loads(rule["tags"])
                except (json.JSONDecodeError, TypeError):
                    rule["tags"] = {}
            else:
                rule["tags"] = {}
        return jsonify({"rules": rules})
    finally:
        db.close()


@alerts_api_bp.post(
    "/alerts/api/rules",
    summary="Create alert rule",
    description="Create a new alert rule. Admin only.",
)
@require_role("admin")
def create_rule():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400

    query = data.get("query")
    check_name = data.get("check_name")
    if not query and not check_name:
        return jsonify({"error": "query or check_name is required"}), 400
    if query and check_name:
        return jsonify({"error": "provide query OR check_name, not both"}), 400

    operator = data.get("operator", ">")
    if operator not in (">", "<", "==", ">=", "<="):
        return jsonify({"error": "invalid operator"}), 400

    severity = data.get("severity", "warning")
    if severity not in ("warning", "critical"):
        return jsonify({"error": "severity must be warning or critical"}), 400

    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        rule = create_alert_rule(
            db,
            user_id=data.get("user_id"),
            name=name,
            query=query,
            check_name=check_name,
            operator=operator,
            threshold=float(data.get("threshold", 0)),
            resolve_threshold=data.get("resolve_threshold"),
            severity=severity,
            for_duration=int(data.get("for_duration", 0)),
            cooldown_secs=data.get("cooldown_secs"),
            interval_secs=int(data.get("interval_secs", 60)),
            tags=data.get("tags"),
            enabled=data.get("enabled", True),
        )
        channel_ids = data.get("channel_ids", [])
        if channel_ids:
            set_rule_channels(db, rule["id"], channel_ids)
        return jsonify({"rule": rule}), 201
    finally:
        db.close()


@alerts_api_bp.put(
    "/alerts/api/rules/<int:rule_id>",
    summary="Update alert rule",
    description="Update an existing alert rule. Admin only.",
)
@require_role("admin")
def update_rule(rule_id: int):
    data = request.get_json(silent=True) or {}
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        rule = get_alert_rule(db, rule_id)
        if rule is None:
            return jsonify({"error": "not found"}), 404

        updates = {}
        for field in (
            "name",
            "query",
            "check_name",
            "operator",
            "threshold",
            "resolve_threshold",
            "severity",
            "for_duration",
            "cooldown_secs",
            "interval_secs",
            "tags",
            "enabled",
        ):
            if field in data:
                updates[field] = data[field]

        if "operator" in updates and updates["operator"] not in (">", "<", "==", ">=", "<="):
            return jsonify({"error": "invalid operator"}), 400
        if "severity" in updates and updates["severity"] not in ("warning", "critical"):
            return jsonify({"error": "invalid severity"}), 400

        updated = update_alert_rule(db, rule_id, **updates)
        if "channel_ids" in data:
            set_rule_channels(db, rule_id, data["channel_ids"])
        return jsonify({"rule": updated})
    finally:
        db.close()


@alerts_api_bp.delete(
    "/alerts/api/rules/<int:rule_id>",
    summary="Delete alert rule",
    description="Delete an alert rule. Admin only.",
)
@require_role("admin")
def delete_rule(rule_id: int):
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        ok = delete_alert_rule(db, rule_id)
        if not ok:
            return jsonify({"error": "not found"}), 404
        return jsonify({"status": "deleted"})
    finally:
        db.close()


@alerts_api_bp.get(
    "/alerts/api/active",
    summary="List firing alerts",
    description="List currently firing alert events.",
)
@require_role("viewer")
def list_active():
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        admin_view = current_user.role == "admin"
        alerts = get_active_alerts(db, user_id=current_user.id, admin_view=admin_view)
        for alert in alerts:
            try:
                alert["labels"] = json.loads(alert.get("labels", "{}"))
            except (json.JSONDecodeError, TypeError):
                alert["labels"] = {}
        return jsonify({"alerts": alerts})
    finally:
        db.close()


@alerts_api_bp.get(
    "/alerts/api/active/count",
    summary="Alert count",
    description="Return count of firing alerts, optionally filtered by severity.",
)
@require_role("viewer")
def active_count():
    severity = request.args.get("severity")
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        count = get_alert_event_count(db, severity=severity)
        return jsonify({"count": count})
    finally:
        db.close()


@alerts_api_bp.post(
    "/alerts/api/events/<int:event_id>/ack",
    summary="Acknowledge alert",
    description="Acknowledge an alert event. Admin only.",
)
@require_role("admin")
def ack_event(event_id: int):
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        ok = acknowledge_alert_event(db, event_id, current_user.id)
        if not ok:
            return jsonify({"error": "not found or already resolved"}), 404
        return jsonify({"status": "acknowledged"})
    finally:
        db.close()


@alerts_api_bp.post(
    "/alerts/api/events/<int:event_id>/resolve",
    summary="Resolve alert",
    description="Manually resolve an alert event. Admin only.",
)
@require_role("admin")
def resolve_event(event_id: int):
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        ok = resolve_alert_event(db, event_id)
        if not ok:
            return jsonify({"error": "not found or already resolved"}), 404
        return jsonify({"status": "resolved"})
    finally:
        db.close()


@alerts_api_bp.get(
    "/alerts/api/history",
    summary="Alert history",
    description="Return paginated resolved/acknowledged alert history.",
)
@require_role("viewer")
def history_api():
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    time_filter = request.args.get("filter", "all")
    search_query = request.args.get("q", "").strip()
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        admin_view = current_user.role == "admin"
        result = get_alert_history(
            db,
            user_id=current_user.id,
            admin_view=admin_view,
            page=page,
            per_page=per_page,
            time_filter=time_filter,
            search_query=search_query,
        )
        for event in result["events"]:
            try:
                event["labels"] = json.loads(event.get("labels", "{}"))
            except (json.JSONDecodeError, TypeError):
                event["labels"] = {}
        return jsonify(result)
    finally:
        db.close()


@alerts_api_bp.get(
    "/alerts/api/channels",
    summary="List notification channels",
    description="List all notification channels. Admin only.",
)
@require_role("admin")
def list_channels():
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        channels = get_notification_channels(db)
        for ch in channels:
            try:
                ch["config"] = json.loads(ch.get("config", "{}"))
            except (json.JSONDecodeError, TypeError):
                ch["config"] = {}
        return jsonify({"channels": channels})
    finally:
        db.close()


@alerts_api_bp.post(
    "/alerts/api/channels",
    summary="Create notification channel",
    description="Create a notification channel. Admin only.",
)
@require_role("admin")
def create_channel():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    channel_type = data.get("type", "").strip()
    config = data.get("config", {})

    if not name:
        return jsonify({"error": "name is required"}), 400
    if channel_type not in ("email", "slack", "webhook", "pagerduty", "discord"):
        return jsonify({"error": "type must be email, slack, webhook, pagerduty, or discord"}), 400

    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        channel = create_notification_channel(
            db, name, channel_type, config, enabled=data.get("enabled", True)
        )
        return jsonify({"channel": channel}), 201
    finally:
        db.close()


@alerts_api_bp.put(
    "/alerts/api/channels/<int:channel_id>",
    summary="Update notification channel",
    description="Update a notification channel. Admin only.",
)
@require_role("admin")
def update_channel(channel_id: int):
    data = request.get_json(silent=True) or {}
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        updates = {}
        for field in ("name", "type", "config", "enabled"):
            if field in data:
                updates[field] = data[field]
        if "type" in updates and updates["type"] not in (
            "email",
            "slack",
            "webhook",
            "pagerduty",
            "discord",
        ):
            return jsonify({"error": "invalid type"}), 400
        updated = update_notification_channel(db, channel_id, **updates)
        if updated is None:
            return jsonify({"error": "not found"}), 404
        return jsonify({"channel": updated})
    finally:
        db.close()


@alerts_api_bp.delete(
    "/alerts/api/channels/<int:channel_id>",
    summary="Delete notification channel",
    description="Delete a notification channel. Admin only.",
)
@require_role("admin")
def delete_channel(channel_id: int):
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        ok = delete_notification_channel(db, channel_id)
        if not ok:
            return jsonify({"error": "not found"}), 404
        return jsonify({"status": "deleted"})
    finally:
        db.close()


@alerts_api_bp.post(
    "/alerts/api/channels/<int:channel_id>/test",
    summary="Test notification channel",
    description="Send a test notification through a channel. Admin only.",
)
@require_role("admin")
def test_channel(channel_id: int):
    from app.alert_manager import _send_to_channel

    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        channel = get_notification_channel(db, channel_id)
        if channel is None:
            return jsonify({"error": "not found"}), 404

        test_rule = {"name": "Test Alert", "severity": "warning"}
        test_event = {
            "value": 42.0,
            "labels": '{"test": "true"}',
            "fired_at": "2024-01-01T00:00:00Z",
        }
        _send_to_channel(channel, test_rule, test_event, state="firing")
        return jsonify({"status": "test sent"})
    finally:
        db.close()


@alerts_api_bp.get(
    "/alerts/api/silences",
    summary="List silences",
    description="List alert silences. Admin only.",
)
@require_role("admin")
def list_silences():
    include_expired = request.args.get("include_expired", "false").lower() == "true"
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        silences = get_silences(db, include_expired=include_expired)
        for s in silences:
            try:
                s["matchers"] = json.loads(s.get("matchers", "[]"))
            except (json.JSONDecodeError, TypeError):
                s["matchers"] = []
        return jsonify({"silences": silences})
    finally:
        db.close()


@alerts_api_bp.get(
    "/alerts/api/silences/<int:silence_id>",
    summary="Get silence",
    description="Get a single alert silence. Admin only.",
)
@require_role("admin")
def get_silence_route(silence_id):
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        silence = get_silence(db, silence_id)
        if silence is None:
            return jsonify({"error": "Silence not found"}), 404
        try:
            silence["matchers"] = json.loads(silence.get("matchers", "[]"))
        except (json.JSONDecodeError, TypeError):
            silence["matchers"] = []
        return jsonify({"silence": silence})
    finally:
        db.close()


@alerts_api_bp.post(
    "/alerts/api/silences",
    summary="Create silence",
    description="Create a new alert silence. Admin only.",
)
@require_role("admin")
def create_silence_route():
    data = request.get_json(silent=True) or {}
    matchers = data.get("matchers", [])
    if not isinstance(matchers, list):
        return jsonify({"error": "matchers must be a list"}), 400

    starts_at = data.get("starts_at", "").strip()
    ends_at = data.get("ends_at", "").strip()
    reason = (data.get("reason") or "").strip()

    if not starts_at or not ends_at:
        return jsonify({"error": "starts_at and ends_at are required"}), 400
    if not reason:
        return jsonify({"error": "reason is required"}), 400

    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        silence = create_silence(
            db,
            matchers=matchers,
            rule_id=data.get("rule_id"),
            starts_at=starts_at,
            ends_at=ends_at,
            reason=reason,
            created_by=current_user.id,
        )
        return jsonify({"silence": silence}), 201
    finally:
        db.close()


@alerts_api_bp.put(
    "/alerts/api/silences/<int:silence_id>",
    summary="Update silence",
    description="Update an existing alert silence. Admin only.",
)
@require_role("admin")
def update_silence_route(silence_id):
    data = request.get_json(silent=True) or {}
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        existing = get_silence(db, silence_id)
        if existing is None:
            return jsonify({"error": "Silence not found"}), 404

        if "matchers" in data:
            matchers = data["matchers"]
            if not isinstance(matchers, list):
                return jsonify({"error": "matchers must be a list"}), 400
        else:
            matchers = None

        silence = update_silence(
            db,
            silence_id=silence_id,
            matchers=matchers,
            rule_id=data.get("rule_id", _sentinel),
            starts_at=data.get("starts_at"),
            ends_at=data.get("ends_at"),
            reason=data.get("reason"),
        )
        if silence is None:
            return jsonify({"error": "Silence not found"}), 404
        try:
            silence["matchers"] = json.loads(silence.get("matchers", "[]"))
        except (json.JSONDecodeError, TypeError):
            silence["matchers"] = []
        return jsonify({"silence": silence})
    finally:
        db.close()


@alerts_api_bp.delete(
    "/alerts/api/silences/<int:silence_id>",
    summary="Delete silence",
    description="Delete an alert silence. Admin only.",
)
@require_role("admin")
def delete_silence_route(silence_id):
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        if delete_silence(db, silence_id):
            return jsonify({"status": "deleted"})
        return jsonify({"error": "Silence not found"}), 404
    finally:
        db.close()


@alerts_api_bp.get(
    "/alerts/api/groups",
    summary="List monitoring groups",
    description="List all monitoring groups.",
)
@require_role("viewer")
def list_groups_api():
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        groups = list_monitoring_groups(db)
        for g in groups:
            try:
                g["match_labels"] = json.loads(g.get("match_labels", "[]"))
            except (json.JSONDecodeError, TypeError):
                g["match_labels"] = []
            conds = list_group_conditions(db, g["id"])
            g["condition_count"] = len(conds)
            active = get_active_group_events(db, group_id=g["id"])
            g["active_count"] = len(active)
            try:
                agents = resolve_agents(g)
                g["instance_count"] = len(agents)
            except Exception:
                logger.exception("Failed to resolve agents for monitoring group %s", g["id"])
                g["instance_count"] = 0
        return jsonify({"groups": groups})
    finally:
        db.close()


@alerts_api_bp.post(
    "/alerts/api/groups",
    summary="Create monitoring group",
    description="Create a new monitoring group. Admin only.",
)
@require_role("admin")
def create_group_api():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400

    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        group = create_monitoring_group(
            db,
            name=name,
            description=data.get("description", ""),
            match_labels=data.get("match_labels", []),
            match_any=data.get("match_any", False),
            enabled=data.get("enabled", True),
        )
        return jsonify({"group": group}), 201
    finally:
        db.close()


@alerts_api_bp.get(
    "/alerts/api/groups/<int:group_id>",
    summary="Get monitoring group",
    description="Get a single monitoring group with conditions.",
)
@require_role("viewer")
def get_group_api(group_id: int):
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        group = get_monitoring_group(db, group_id)
        if group is None:
            return jsonify({"error": "not found"}), 404
        try:
            group["match_labels"] = json.loads(group.get("match_labels", "[]"))
        except (json.JSONDecodeError, TypeError):
            group["match_labels"] = []
        conditions = list_group_conditions(db, group_id)
        for c in conditions:
            try:
                c["metric_params"] = json.loads(c.get("metric_params", "{}"))
            except (json.JSONDecodeError, TypeError):
                c["metric_params"] = {}
            try:
                c["target_labels"] = json.loads(c.get("target_labels", "null")) or []
            except (json.JSONDecodeError, TypeError):
                c["target_labels"] = []
            channels = get_group_condition_channels(db, c["id"], default_to_all=False)
            c["channel_ids"] = [ch["id"] for ch in channels]
        group["conditions"] = conditions
        return jsonify({"group": group})
    finally:
        db.close()


@alerts_api_bp.put(
    "/alerts/api/groups/<int:group_id>",
    summary="Update monitoring group",
    description="Update a monitoring group. Admin only.",
)
@require_role("admin")
def update_group_api(group_id: int):
    data = request.get_json(silent=True) or {}
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        existing = get_monitoring_group(db, group_id)
        if existing is None:
            return jsonify({"error": "not found"}), 404

        updates = {}
        for field in ("name", "description", "match_labels", "match_any", "enabled"):
            if field in data:
                updates[field] = data[field]

        updated = update_monitoring_group(db, group_id, **updates)
        return jsonify({"group": updated})
    finally:
        db.close()


@alerts_api_bp.delete(
    "/alerts/api/groups/<int:group_id>",
    summary="Delete monitoring group",
    description="Delete a monitoring group. Admin only.",
)
@require_role("admin")
def delete_group_api(group_id: int):
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        ok = delete_monitoring_group(db, group_id)
        if not ok:
            return jsonify({"error": "not found"}), 404
        return jsonify({"status": "deleted"})
    finally:
        db.close()


@alerts_api_bp.post(
    "/alerts/api/groups/<int:group_id>/conditions",
    summary="Add group condition",
    description="Add an alert condition to a monitoring group. Admin only.",
)
@require_role("admin")
def create_condition_api(group_id: int):
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"error": "name is required"}), 400

    metric_type = data.get("metric_type", "")
    if metric_type not in (
        "cpu",
        "memory",
        "disk",
        "custom_promql",
        "check_name",
        "service",
        "logfile",
        "exec",
    ):
        return jsonify({"error": "invalid metric_type"}), 400

    operator = data.get("operator", ">")
    if operator not in (">", "<", "==", ">=", "<="):
        return jsonify({"error": "invalid operator"}), 400

    severity = data.get("severity", "warning")
    if severity not in ("warning", "critical"):
        return jsonify({"error": "severity must be warning or critical"}), 400

    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        existing = get_monitoring_group(db, group_id)
        if existing is None:
            return jsonify({"error": "group not found"}), 404

        condition = create_group_condition(
            db,
            group_id=group_id,
            name=name,
            metric_type=metric_type,
            metric_params=data.get("metric_params", {}),
            target_labels=data.get("target_labels"),
            operator=operator,
            threshold=float(data.get("threshold", 0)),
            resolve_threshold=data.get("resolve_threshold"),
            severity=severity,
            for_duration=int(data.get("for_duration", 0)),
            cooldown_secs=data.get("cooldown_secs"),
            interval_secs=int(data.get("interval_secs", 60)),
            enabled=data.get("enabled", True),
        )
        channel_ids = data.get("channel_ids", [])
        if channel_ids:
            set_group_condition_channels(db, condition["id"], channel_ids)
        return jsonify({"condition": condition}), 201
    finally:
        db.close()


@alerts_api_bp.put(
    "/alerts/api/groups/<int:group_id>/conditions/<int:condition_id>",
    summary="Update group condition",
    description="Update a group alert condition. Admin only.",
)
@require_role("admin")
def update_condition_api(group_id: int, condition_id: int):
    data = request.get_json(silent=True) or {}
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        existing = get_group_condition(db, condition_id)
        if existing is None or existing["group_id"] != group_id:
            return jsonify({"error": "not found"}), 404

        updates = {}
        for field in (
            "name",
            "metric_type",
            "metric_params",
            "target_labels",
            "operator",
            "threshold",
            "resolve_threshold",
            "severity",
            "for_duration",
            "cooldown_secs",
            "interval_secs",
            "enabled",
        ):
            if field in data:
                updates[field] = data[field]

        if "operator" in updates and updates["operator"] not in (">", "<", "==", ">=", "<="):
            return jsonify({"error": "invalid operator"}), 400
        if "severity" in updates and updates["severity"] not in ("warning", "critical"):
            return jsonify({"error": "invalid severity"}), 400

        updated = update_group_condition(db, condition_id, **updates)
        if "channel_ids" in data:
            set_group_condition_channels(db, condition_id, data["channel_ids"])
        return jsonify({"condition": updated})
    finally:
        db.close()


@alerts_api_bp.delete(
    "/alerts/api/groups/<int:group_id>/conditions/<int:condition_id>",
    summary="Delete group condition",
    description="Delete a group alert condition. Admin only.",
)
@require_role("admin")
def delete_condition_api(group_id: int, condition_id: int):
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        existing = get_group_condition(db, condition_id)
        if existing is None or existing["group_id"] != group_id:
            return jsonify({"error": "not found"}), 404
        ok = delete_group_condition(db, condition_id)
        if not ok:
            return jsonify({"error": "not found"}), 404
        return jsonify({"status": "deleted"})
    finally:
        db.close()


@alerts_api_bp.put(
    "/alerts/api/groups/<int:group_id>/conditions/<int:condition_id>/channels",
    summary="Set condition channels",
    description="Set channel associations for a group alert condition. Admin only.",
)
@require_role("admin")
def set_condition_channels_api(group_id: int, condition_id: int):
    data = request.get_json(silent=True) or {}
    channel_ids = data.get("channel_ids", [])
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        existing = get_group_condition(db, condition_id)
        if existing is None or existing["group_id"] != group_id:
            return jsonify({"error": "not found"}), 404
        set_group_condition_channels(db, condition_id, channel_ids)
        return jsonify({"status": "updated"})
    finally:
        db.close()


@alerts_api_bp.get(
    "/alerts/api/groups/<int:group_id>/instances",
    summary="List matching instances",
    description="List instances currently matching a monitoring group's matchers.",
)
@require_role("viewer")
def list_group_instances_api(group_id: int):
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        group = get_monitoring_group(db, group_id)
        if group is None:
            return jsonify({"error": "not found"}), 404
        try:
            group["match_labels"] = json.loads(group.get("match_labels", "[]"))
        except (json.JSONDecodeError, TypeError):
            group["match_labels"] = []
        agents = resolve_agents(group)
        return jsonify({"instances": agents, "count": len(agents)})
    finally:
        db.close()


@alerts_api_bp.get(
    "/alerts/api/groups/<int:group_id>/active",
    summary="List firing alerts for group",
    description="List currently firing alerts for a monitoring group.",
)
@require_role("viewer")
def list_group_active_api(group_id: int):
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        events = get_active_group_events(db, group_id=group_id)
        for ev in events:
            try:
                ev["labels"] = json.loads(ev.get("labels", "{}"))
            except (json.JSONDecodeError, TypeError):
                ev["labels"] = {}
        return jsonify({"alerts": events, "count": len(events)})
    finally:
        db.close()


@alerts_api_bp.get(
    "/alerts/api/groups/<int:group_id>/status",
    summary="Group status matrix",
    description="Return the Nagios-style status matrix for a monitoring group.",
)
@require_role("viewer")
def group_status_api(group_id: int):
    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        group = get_monitoring_group(db, group_id)
        if group is None:
            return jsonify({"error": "not found"}), 404
        _db_config = getattr(current_app, "_db_config", current_app.config["DATABASE_PATH"])
        mgdb = get_db(_db_config)
        try:
            matrix = get_group_status_matrix(mgdb, group_id)
            return jsonify(matrix)
        finally:
            mgdb.close()
    finally:
        db.close()


@alerts_api_bp.get(
    "/alerts/api/agents/<agent_id>",
    summary="Agent check statuses",
    description="Return all monitoring check statuses and logfile watches for a specific agent.",
)
@require_role("viewer")
def agent_status_api(agent_id: str):
    _db_config = getattr(current_app, "_db_config", current_app.config["DATABASE_PATH"])
    db = get_db(_db_config)
    try:
        checks = get_agent_checks(db, agent_id)
        watches = get_logfile_watches(db, agent_id)
        return jsonify(
            {
                "agent_id": agent_id,
                "checks": checks,
                "count": len(checks),
                "logfile_watches": watches,
            }
        )
    finally:
        db.close()


@alerts_api_bp.get(
    "/alerts/api/agents/<agent_id>/checks/<int:condition_id>/history",
    summary="Agent check history",
    description="Return time-series history for a single check on an agent. "
    "PromQL-backed metrics come from VictoriaMetrics; check_name types from local check_results.",
)
@require_role("viewer")
def agent_check_history(agent_id: str, condition_id: int):
    from app.routes.metrics import _vm_query_range

    _db_config = getattr(current_app, "_db_config", current_app.config["DATABASE_PATH"])
    db = get_db(_db_config)
    try:
        condition = get_group_condition(db, condition_id)
        if condition is None:
            return jsonify({"error": "condition not found"}), 404

        metric_type = condition.get("metric_type", "")
        range_param = request.args.get("range", "24h")
        step = request.args.get("step", "60s")

        if metric_type in ("check_name", "logfile"):
            metric_params = condition.get("metric_params", "{}")
            try:
                cp = json.loads(metric_params)
                check_name = cp.get("check_name", cp.get("query", ""))
            except (json.JSONDecodeError, TypeError):
                check_name = str(metric_params)

            rows = db.execute(
                "SELECT exit_code, duration_ms, output, created_at FROM check_results "
                "WHERE name = ? AND agent_id = ? "
                "ORDER BY created_at ASC",
                (check_name, agent_id),
            ).fetchall()

            points = []
            for row in rows:
                d = dict(row)
                points.append(
                    {
                        "t": d["created_at"],
                        "v": float(d["exit_code"]),
                        "duration_ms": d.get("duration_ms", 0),
                    }
                )

            return jsonify(
                {
                    "condition_id": condition_id,
                    "condition_name": condition.get("name", ""),
                    "metric_type": metric_type,
                    "threshold": condition.get("threshold"),
                    "operator": condition.get("operator"),
                    "points": points,
                }
            )

        promql = build_promql(condition, agent_id)
        if not promql:
            return jsonify({"error": "no promql available for this metric type"}), 400

        now = datetime.now(UTC)
        start = now - timedelta(hours=24)
        if range_param == "1h":
            start = now - timedelta(hours=1)
        elif range_param == "6h":
            start = now - timedelta(hours=6)
        elif range_param == "7d":
            start = now - timedelta(days=7)

        end_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        start_str = start.strftime("%Y-%m-%dT%H:%M:%SZ")

        result = _vm_query_range(promql, start_str, end_str, step)
        points = []
        if result and result.get("status") == "success":
            for series in result.get("data", {}).get("result", []):
                metric = series.get("metric", {})
                if metric.get("agent_id") and metric["agent_id"] != agent_id:
                    continue
                for t, v in series.get("values", []):
                    points.append({"t": t, "v": float(v)})

        return jsonify(
            {
                "condition_id": condition_id,
                "condition_name": condition.get("name", ""),
                "metric_type": metric_type,
                "threshold": condition.get("threshold"),
                "operator": condition.get("operator"),
                "range": range_param,
                "points": points,
            }
        )
    finally:
        db.close()


@alerts_api_bp.get(
    "/alerts/api/hosts",
    summary="Hosts overview",
    description="Return per-host summary across all monitoring groups.",
)
@require_role("viewer")
def hosts_api():
    _db_config = getattr(current_app, "_db_config", current_app.config["DATABASE_PATH"])
    db = get_db(_db_config)
    try:
        hosts = get_all_hosts_status(db)
        return jsonify({"hosts": hosts, "count": len(hosts)})
    finally:
        db.close()
