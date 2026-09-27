"""Alert Manager — evaluation loop and notification dispatch.

Provides evaluate_rules() which runs on an APScheduler interval, acquires a
distributed DB lock, evaluates all enabled alert rules against PromQL and
check_results data, and dispatches notifications on state transitions.
"""

import json
import logging
import os
import re
import socket
import threading
from datetime import UTC, datetime
from urllib import request as urllib_request
from urllib.error import HTTPError, URLError

from flask import Flask

from app.models import (
    _utcnow_iso,
    acquire_eval_lock,
    create_alert_event,
    get_active_group_event,
    get_alert_rules,
    get_channels_for_rule,
    get_db,
    get_eval_lock_status,
    get_group_condition_channels,
    get_latest_resolved_event,
    get_latest_resolved_group_event,
    is_silenced,
    list_group_conditions,
    list_monitoring_groups,
    prune_group_statuses,
    refresh_eval_lock,
    release_eval_lock,
    resolve_alert_event,
    update_condition_last_eval,
    upsert_group_status,
)

logger = logging.getLogger(__name__)

# In-memory pending state for for_duration debounce.
# Structure: {(rule_id, labels_json): first_seen_iso}
_pending_debounce: dict[tuple[int, str], str] = {}
_debounce_lock = threading.Lock()

WORKER_ID = f"{socket.gethostname()}:{os.getpid()}"


# ── Eval loop entry point ────────────────────────────────────────────────


def evaluate_rules(app: Flask) -> None:
    """Evaluate all enabled alert rules AND monitoring group conditions,
    protected by a DB-based singleton lock."""
    logger.debug("Alert eval cycle starting")
    with app.app_context():
        # Use the full config dict stored by create_app (supports MySQL)
        # Fall back to DATABASE_PATH string for SQLite-only setups.
        _db_config = getattr(app, "_db_config", app.config["DATABASE_PATH"])
        db = get_db(_db_config)
        try:
            if not acquire_eval_lock(db, WORKER_ID, ttl_secs=120):
                logger.debug("Alert eval: another worker holds the lock")
                return

            try:
                # Evaluate regular alert rules
                rules = get_alert_rules(db, enabled=True, admin_view=True)
                logger.debug("Alert eval: evaluating %d rule(s)", len(rules))

                for rule in rules:
                    try:
                        if rule.get("check_name"):
                            _evaluate_check_rule(db, rule)
                        else:
                            _evaluate_promql_rule(db, rule)
                    except Exception:
                        logger.exception(
                            "Alert eval failed for rule %s (id=%s)",
                            rule.get("name"),
                            rule.get("id"),
                        )

                # Evaluate monitoring group conditions
                evaluate_group_rules(db)

                # Background host-threat alert scan (notifications fire on a
                # timer, independent of page views)
                try:
                    from app.routes.host_threats import evaluate_host_threat_alerts

                    evaluate_host_threat_alerts(db)
                except Exception:
                    logger.exception("Host threat alert scan failed")

                refresh_eval_lock(db, WORKER_ID, ttl_secs=120)
            finally:
                release_eval_lock(db, WORKER_ID)
        finally:
            db.close()


# ── PromQL rule evaluation ───────────────────────────────────────────────


def _evaluate_promql_rule(db, rule: dict) -> None:
    """Evaluate a PromQL-backed alert rule."""
    from app.routes.metrics import _vm_query

    query = rule.get("query", "")
    if not query:
        return

    result = _vm_query(query)
    if result is None or result.get("status") != "success":
        logger.warning("PromQL query failed for rule '%s': %s", rule.get("name"), result)
        return

    threshold = float(rule["threshold"])
    operator = rule["operator"]
    resolve_threshold = rule.get("resolve_threshold")
    cooldown_secs = rule.get("cooldown_secs")
    for_duration = rule.get("for_duration", 0)
    rule_id = rule["id"]

    for series in result.get("data", {}).get("result", []):
        metric = series.get("metric", {})
        labels = {k: v for k, v in metric.items()}
        labels_json = json.dumps(labels, sort_keys=True)

        value_data = series.get("value", [None, None])
        try:
            value = float(value_data[1]) if value_data[1] is not None else None
        except (ValueError, TypeError):
            value = None

        if value is None:
            continue

        # Check if already firing
        existing = _get_existing_event(db, rule_id, labels_json)

        # Evaluate fire condition
        fire_condition = _compare(value, operator, threshold)

        if fire_condition:
            if existing is None:
                # Debounce: only fire after for_duration seconds of persistence
                if for_duration and for_duration > 0:
                    if _should_debounce(rule_id, labels_json, for_duration):
                        continue
                # Cooldown: check if recently resolved
                if cooldown_secs and cooldown_secs > 0:
                    resolved = get_latest_resolved_event(db, rule_id, json.loads(labels_json))
                    if resolved and resolved.get("resolved_at"):
                        resolved_dt = _parse_iso(resolved["resolved_at"])
                        if (
                            resolved_dt
                            and (datetime.now(UTC) - resolved_dt).total_seconds() < cooldown_secs
                        ):
                            continue
                # Silence check
                if is_silenced(db, rule_id, labels):
                    continue
                # Fire!
                event = create_alert_event(db, rule_id, labels, value, state="firing")
                _dispatch_notifications(db, rule, event, state="firing")
            else:
                # already firing or acknowledged — resolve any stale duplicates
                db.execute(
                    "UPDATE alert_events SET state = 'resolved', resolved_at = ? "
                    "WHERE rule_id = ? AND labels = ? AND id != ? AND state = 'firing'",
                    (_utcnow_iso(), rule_id, labels_json, existing["id"]),
                )
        else:
            # Check resolve condition
            if existing is not None:
                resolve_ok = True
                if resolve_threshold is not None:
                    resolve_ok = _compare(value, _inverse_operator(operator), resolve_threshold)
                if resolve_ok:
                    resolve_alert_event(db, existing["id"])
                    existing["value"] = value
                    _dispatch_notifications(db, rule, existing, state="resolved")


def _evaluate_check_rule(db, rule: dict) -> None:
    """Evaluate a check_results-backed alert rule."""
    check_name = rule.get("check_name", "")
    threshold = float(rule["threshold"])
    operator = rule["operator"]
    resolve_threshold = rule.get("resolve_threshold")
    cooldown_secs = rule.get("cooldown_secs")
    for_duration = rule.get("for_duration", 0)
    rule_id = rule["id"]

    # Get latest check result per agent_id for this check name
    rows = db.execute(
        "SELECT cr.* FROM check_results cr "
        "INNER JOIN ("
        "  SELECT agent_id, MAX(created_at) AS max_ts "
        "  FROM check_results WHERE name = ? GROUP BY agent_id"
        ") latest ON cr.agent_id = latest.agent_id AND cr.created_at = latest.max_ts "
        "WHERE cr.name = ?",
        (check_name, check_name),
    ).fetchall()

    for row in rows:
        labels = {"agent_id": row["agent_id"], "hostname": row["hostname"] or ""}
        labels_json = json.dumps(labels, sort_keys=True)
        value = float(row["exit_code"])

        existing = _get_existing_event(db, rule_id, labels_json)
        fire_condition = _compare(value, operator, threshold)

        if fire_condition:
            if existing is None:
                if for_duration and for_duration > 0:
                    if _should_debounce(rule_id, labels_json, for_duration):
                        continue
                if cooldown_secs and cooldown_secs > 0:
                    resolved = get_latest_resolved_event(db, rule_id, labels)
                    if resolved and resolved.get("resolved_at"):
                        resolved_dt = _parse_iso(resolved["resolved_at"])
                        if (
                            resolved_dt
                            and (datetime.now(UTC) - resolved_dt).total_seconds() < cooldown_secs
                        ):
                            continue
                if is_silenced(db, rule_id, labels):
                    continue
                event = create_alert_event(db, rule_id, labels, value, state="firing")
                _dispatch_notifications(db, rule, event, state="firing")
            else:
                # already firing or acknowledged — resolve any stale duplicates
                db.execute(
                    "UPDATE alert_events SET state = 'resolved', resolved_at = ? "
                    "WHERE rule_id = ? AND labels = ? AND id != ? AND state = 'firing'",
                    (_utcnow_iso(), rule_id, labels_json, existing["id"]),
                )
        else:
            if existing is not None:
                resolve_ok = True
                if resolve_threshold is not None:
                    resolve_ok = _compare(value, _inverse_operator(operator), resolve_threshold)
                if resolve_ok:
                    resolve_alert_event(db, existing["id"])
                    existing["value"] = value
                    _dispatch_notifications(db, rule, existing, state="resolved")


# ── Helpers ──────────────────────────────────────────────────────────────


def _get_existing_event(db, rule_id: int, labels_json: str) -> dict | None:
    """Find a currently firing or acknowledged event for this rule+labels combination."""
    row = db.execute(
        "SELECT * FROM alert_events WHERE rule_id = ? AND labels = ? AND state IN ('firing', 'acknowledged') ORDER BY id DESC LIMIT 1",
        (rule_id, labels_json),
    ).fetchone()
    if row is None:
        return None
    return dict(row)


def _compare(value: float, operator: str, threshold: float) -> bool:
    """Compare a value against a threshold using the given operator."""
    if operator == ">":
        return value > threshold
    elif operator == "<":
        return value < threshold
    elif operator == "==":
        return value == threshold
    elif operator == ">=":
        return value >= threshold
    elif operator == "<=":
        return value <= threshold
    return False


def _inverse_operator(operator: str) -> str:
    """Return the inverse of the given comparison operator.

    Used so that the auto-resolve condition checks the opposite direction
    from the fire condition, providing proper hysteresis. For example, when
    the fire condition is ``value > threshold``, the resolve condition should
    check ``value <= resolve_threshold``.
    """
    return {
        ">": "<=",
        "<": ">=",
        ">=": "<",
        "<=": ">",
        "==": "!=",
    }.get(operator, "<=")


def _should_debounce(rule_id: int, labels_json: str, for_duration: int) -> bool:
    """Track pending state for for_duration debounce.

    Returns True if the condition has NOT yet persisted for for_duration seconds.
    """
    key = (rule_id, labels_json)
    now = datetime.now(UTC)
    with _debounce_lock:
        first_seen = _pending_debounce.get(key)
        if first_seen is None:
            _pending_debounce[key] = now.isoformat()
            return True  # Not yet persisted long enough
        try:
            first_dt = datetime.fromisoformat(first_seen)
        except (ValueError, TypeError):
            _pending_debounce[key] = now.isoformat()
            return True
        if (now - first_dt).total_seconds() < for_duration:
            return True  # Still debouncing
        # Debounce complete — remove from pending
        del _pending_debounce[key]
        return False


def _parse_iso(iso_str: str) -> datetime | None:
    """Parse an ISO-8601 string or datetime into a timezone-aware datetime.

    MySQL connectors return DATETIME columns as datetime objects (not
    strings), so this handles both cases.
    """
    if isinstance(iso_str, datetime):
        if iso_str.tzinfo is None:
            return iso_str.replace(tzinfo=UTC)
        return iso_str
    if not iso_str:
        return None
    try:
        s = iso_str.replace("Z", "+00:00")
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        return None


# ── Notification Dispatch ────────────────────────────────────────────────


def _dispatch_notifications(db, rule: dict, event: dict, state: str) -> None:
    """Dispatch notifications for an alert state transition."""
    channels = get_channels_for_rule(db, rule["id"], default_to_all=True)
    if not channels:
        logger.debug("No notification channels for rule '%s'", rule.get("name"))
        return

    for channel in channels:
        try:
            _send_to_channel(channel, rule, event, state)
        except Exception:
            logger.exception("Notification dispatch failed for channel %s", channel.get("name"))

    # Mark event as notified if firing
    if state == "firing" and event.get("notified_at") is None:
        db.execute(
            "UPDATE alert_events SET notified_at = ? WHERE id = ?",
            (_utcnow_iso(), event["id"]),
        )
        db.commit()


def _send_to_channel(channel: dict, rule: dict, event: dict, state: str) -> None:
    """Route notification to the appropriate dispatcher by channel type."""
    config = json.loads(channel.get("config", "{}"))
    channel_type = channel.get("type", "")

    if channel_type == "slack":
        _send_slack(config, rule, event, state)
    elif channel_type == "email":
        _send_email(config, rule, event, state)
    elif channel_type == "webhook":
        _send_webhook(config, rule, event, state)
    elif channel_type == "pagerduty":
        _send_pagerduty(config, rule, event, state)
    elif channel_type == "discord":
        _send_discord(config, rule, event, state)
    else:
        logger.warning("Unknown notification channel type: %s", channel_type)


def _format_alert_message(rule: dict, event: dict, state: str) -> str:
    """Format a human-readable alert message."""
    severity_emoji = {"critical": "🔴", "warning": "🟡"}.get(rule.get("severity", ""), "⚪")
    labels = json.loads(event.get("labels", "{}"))
    labels_str = ", ".join(f"{k}={v}" for k, v in labels.items())
    value = event.get("value", "")

    is_disk = labels.get("metric_type") == "disk"
    mountpoint = labels.get("mountpoint", "")

    if is_disk and mountpoint:
        if state == "firing":
            return (
                f"{severity_emoji} *High Disk Usage {mountpoint}* is FIRING\n"
                f"Severity: {rule.get('severity', 'unknown')}\n"
                f"Value: {value:.1f}%\n"
                f"Labels: {labels_str}"
            )
        else:
            return (
                f"🟢 *High Disk Usage {mountpoint}* is RESOLVED\n"
                f"Value: {value:.1f}%\n"
                f"Labels: {labels_str}"
            )

    if state == "firing":
        return (
            f"{severity_emoji} *{rule.get('name', 'Unknown')}* is FIRING\n"
            f"Severity: {rule.get('severity', 'unknown')}\n"
            f"Value: {value}\n"
            f"Labels: {labels_str}"
        )
    else:
        return (
            f"🟢 *{rule.get('name', 'Unknown')}* is RESOLVED\nValue: {value}\nLabels: {labels_str}"
        )


def _send_slack(config: dict, rule: dict, event: dict, state: str) -> None:
    """Send a notification to a Slack webhook."""
    webhook_url = config.get("webhook_url", "")
    if not webhook_url:
        logger.warning("Slack channel missing webhook_url")
        return

    channel = config.get("channel", "")
    message = _format_alert_message(rule, event, state)

    payload = {"text": message}
    if channel:
        payload["channel"] = channel

    body = json.dumps(payload).encode("utf-8")
    req = urllib_request.Request(
        webhook_url,
        data=body,
        method="POST",
        headers={"Content-Type": "application/json"},
    )
    try:
        urllib_request.urlopen(req, timeout=15)
    except (URLError, HTTPError) as exc:
        logger.error("Slack notification failed: %s", exc)


def _send_email(config: dict, rule: dict, event: dict, state: str) -> None:
    """Send an email notification via a configured SMTP relay.

    Required channel config keys:
        recipients: list of email addresses
        smtp_host: SMTP relay hostname or IP
        from_address: sender email address

    Optional channel config keys:
        smtp_port: port number (default: 587 for STARTTLS, 465 for SSL)
        smtp_user: username for SMTP authentication
        smtp_password: password for SMTP authentication
        smtp_tls: TLS mode — "starttls" (default), "ssl", or "none"
        subject_prefix: prefix for subject line (default: "[Vespid]")
    """
    import smtplib
    from email.message import EmailMessage

    recipients = config.get("recipients", [])
    if not recipients:
        logger.warning("Email channel missing recipients")
        return

    smtp_host = config.get("smtp_host", "")
    if not smtp_host:
        logger.warning("Email channel missing smtp_host — cannot send")
        return

    from_address = config.get("from_address", "")
    if not from_address:
        logger.warning("Email channel missing from_address — cannot send")
        return

    tls_mode = config.get("smtp_tls", "starttls").lower()
    smtp_port = config.get("smtp_port")
    if smtp_port is None:
        if tls_mode == "ssl":
            smtp_port = 465
        else:
            smtp_port = 587

    smtp_user = config.get("smtp_user", "")
    smtp_password = config.get("smtp_password", "")

    subject_prefix = config.get("subject_prefix", "[Vespid]")
    subject = f"{subject_prefix} Alert {state.upper()}: {rule.get('name', 'Unknown')}"
    body = _format_alert_message(rule, event, state)

    # Build the email message
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_address
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)

    try:
        if tls_mode == "ssl":
            smtp = smtplib.SMTP_SSL(smtp_host, smtp_port, timeout=15)
        else:
            smtp = smtplib.SMTP(smtp_host, smtp_port, timeout=15)
            if tls_mode == "starttls":
                smtp.starttls()

        if smtp_user and smtp_password:
            smtp.login(smtp_user, smtp_password)

        smtp.send_message(msg)
        smtp.quit()
        logger.info("Email notification sent to %s: %s", recipients, subject)
    except smtplib.SMTPException as exc:
        logger.error("SMTP notification failed: %s", exc)
    except OSError as exc:
        logger.error("SMTP connection failed (%s:%s): %s", smtp_host, smtp_port, exc)


def _send_webhook(config: dict, rule: dict, event: dict, state: str) -> None:
    """Send a notification to a generic webhook endpoint."""
    url = config.get("url", "")
    if not url:
        logger.warning("Webhook channel missing URL")
        return

    method = config.get("method", "POST")
    headers = config.get("headers", {})
    payload = {
        "rule": rule.get("name"),
        "severity": rule.get("severity"),
        "state": state,
        "value": event.get("value"),
        "labels": json.loads(event.get("labels", "{}")),
        "fired_at": event.get("fired_at"),
    }

    body = json.dumps(payload).encode("utf-8")
    req = urllib_request.Request(
        url,
        data=body,
        method=method,
        headers={"Content-Type": "application/json", **headers},
    )
    try:
        urllib_request.urlopen(req, timeout=15)
    except (URLError, HTTPError) as exc:
        logger.error("Webhook notification failed: %s", exc)


def _send_pagerduty(config: dict, rule: dict, event: dict, state: str) -> None:
    """Send a PagerDuty event v2 notification."""
    routing_key = config.get("routing_key", "")
    if not routing_key:
        logger.warning("PagerDuty channel missing routing_key")
        return

    severity_map = config.get("severity_map", {"critical": "critical", "warning": "warning"})
    pd_severity = severity_map.get(rule.get("severity", "warning"), "warning")

    labels = json.loads(event.get("labels", "{}"))
    dedup_key = f"alert-{event.get('rule_id')}-{json.dumps(labels, sort_keys=True)}"

    if state == "firing":
        payload = {
            "routing_key": routing_key,
            "event_action": "trigger",
            "dedup_key": dedup_key,
            "payload": {
                "summary": f"{rule.get('name', 'Unknown')} is firing",
                "severity": pd_severity,
                "source": labels.get("hostname", labels.get("agent_id", "unknown")),
                "custom_details": {
                    "value": event.get("value"),
                    "labels": labels,
                },
            },
        }
    else:
        payload = {
            "routing_key": routing_key,
            "event_action": "resolve",
            "dedup_key": dedup_key,
        }

    body = json.dumps(payload).encode("utf-8")
    req = urllib_request.Request(
        "https://events.pagerduty.com/v2/enqueue",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Vespid/1.0",
        },
    )
    try:
        urllib_request.urlopen(req, timeout=15)
    except (URLError, HTTPError) as exc:
        logger.error("PagerDuty notification failed: %s", exc)


def _send_discord(config: dict, rule: dict, event: dict, state: str) -> None:
    """Send a notification to a Discord webhook."""
    webhook_url = config.get("webhook_url", "")
    if not webhook_url:
        logger.warning("Discord channel missing webhook_url")
        return

    message = _format_alert_message(rule, event, state)
    # Discord uses plain markdown text wrapped in 'content'
    payload = {"content": message}

    body = json.dumps(payload).encode("utf-8")
    req = urllib_request.Request(
        webhook_url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "User-Agent": "Vespid/1.0",
        },
    )
    try:
        urllib_request.urlopen(req, timeout=15)
    except (URLError, HTTPError) as exc:
        logger.error("Discord notification failed: %s", exc)


# ── Monitoring Group Evaluation ────────────────────────────────────────


def resolve_agents(group: dict) -> list[dict]:
    """Resolve agent_ids+hostnames matching a monitoring group's label matchers.

    Queries VictoriaMetrics for all known agents, then filters by
    the group's match_labels. Empty matchers = all agents.

    Args:
        group: Monitoring group dict with match_labels and match_any fields.

    Returns:
        List of dicts with agent_id and hostname keys.
    """
    from app.routes.metrics import _vm_query

    query = "count by (agent_id, hostname) (vespid_monitor_cpu_idle_seconds_total)"
    result = _vm_query(query)

    if not result or result.get("status") != "success":
        logger.warning("resolve_agents: VM query failed for group '%s'", group.get("name"))
        return []

    agents = []
    for series in result.get("data", {}).get("result", []):
        metric = series.get("metric", {})
        agent_id = metric.get("agent_id", "")
        hostname = metric.get("hostname", "")
        if agent_id:
            agents.append({"agent_id": agent_id, "hostname": hostname})

    match_labels_raw = group.get("match_labels", "[]")
    if isinstance(match_labels_raw, str):
        match_labels = json.loads(match_labels_raw) if match_labels_raw else []
    else:
        match_labels = match_labels_raw or []
    if not match_labels:
        return agents

    match_any = group.get("match_any", 0)

    matched = []
    for agent in agents:
        agent_labels = {"agent_id": agent["agent_id"], "hostname": agent["hostname"]}
        results = []
        for matcher in match_labels:
            key = matcher.get("key", "")
            op = matcher.get("op", "=")
            value = matcher.get("value", "")
            label_val = agent_labels.get(key, "")

            if op == "=":
                results.append(label_val == value)
            elif op == "!=":
                results.append(label_val != value)
            elif op == "=~":
                try:
                    results.append(bool(re.search(value, str(label_val))))
                except re.error:
                    results.append(False)
            elif op == "!~":
                try:
                    results.append(not re.search(value, str(label_val)))
                except re.error:
                    results.append(True)
            else:
                results.append(False)

        if match_any:
            if any(results):
                matched.append(agent)
        else:
            if all(results):
                matched.append(agent)

    return matched


def build_promql(condition: dict, agent_regex: str) -> str:
    """Build a PromQL query for a group alert condition.

    Args:
        condition: Group alert condition dict with metric_type, metric_params.
        agent_regex: Regex matching all target agent IDs (e.g. "id1|id2|id3").

    Returns:
        PromQL query string, or empty string if metric_type is check_name.
    """
    mt = condition.get("metric_type", "")
    params = json.loads(condition.get("metric_params", "{}"))

    if mt == "cpu":
        return (
            f"(1 - avg by (agent_id, hostname) ("
            f'rate(vespid_monitor_cpu_idle_seconds_total{{agent_id=~"{agent_regex}"}}[2m])'
            f")) * 100"
        )
    elif mt == "memory":
        return f'vespid_monitor_memory_used_percent{{agent_id=~"{agent_regex}"}}'
    elif mt == "disk":
        return f'vespid_monitor_disk_used_percent{{agent_id=~"{agent_regex}"}}'
    elif mt == "service":
        service_name = params.get("service_name", "")
        return (
            f"vespid_monitor_systemd_unit_active{{"
            f'agent_id=~"{agent_regex}", unit="{service_name}"}}'
        )
    elif mt == "custom_promql":
        query = condition.get("metric_params", "{}")
        try:
            q = json.loads(query).get("query", query)
        except (json.JSONDecodeError, TypeError):
            q = query
        return q.replace("{{agent_ids_regex}}", agent_regex)
    return ""


def _filter_agents(agents: list[dict], match_labels: list[dict]) -> list[dict]:
    """Filter a list of agents by label matchers (same logic as resolve_agents).

    Args:
        agents: List of dicts with agent_id and hostname keys.
        match_labels: List of matchers, each with key, op, value.

    Returns:
        Filtered subset of agents.
    """
    if not match_labels:
        return agents

    matched = []
    for agent in agents:
        agent_labels = {"agent_id": agent["agent_id"], "hostname": agent["hostname"]}
        results = []
        for matcher in match_labels:
            key = matcher.get("key", "")
            op = matcher.get("op", "=")
            value = matcher.get("value", "")
            label_val = agent_labels.get(key, "")

            if op == "=":
                results.append(label_val == value)
            elif op == "!=":
                results.append(label_val != value)
            elif op == "=~":
                try:
                    results.append(bool(re.search(value, str(label_val))))
                except re.error:
                    results.append(False)
            elif op == "!~":
                try:
                    results.append(not re.search(value, str(label_val)))
                except re.error:
                    results.append(True)
            else:
                results.append(False)

        if all(results):
            matched.append(agent)

    return matched


def _evaluate_group_condition(db, group: dict, condition: dict) -> None:
    """Evaluate a single group alert condition against matching agents.

    Uses batched PromQL — one query for all agents — then iterates
    result series and fires/resolves alert events per agent.
    Also persists per-agent status for the Nagios-style matrix view.
    """
    from app.routes.metrics import _vm_query

    metric_type = condition.get("metric_type", "")
    group_id = group["id"]
    group_name = group.get("name", "")
    condition_id = condition["id"]
    condition_name = condition.get("name", "")
    threshold = float(condition["threshold"])
    operator = condition["operator"]
    resolve_threshold = condition.get("resolve_threshold")
    for_duration = condition.get("for_duration", 0)
    cooldown_secs = condition.get("cooldown_secs")
    severity = condition.get("severity", "warning")

    # Resolve matching agents (group-level matchers)
    matching = resolve_agents(group)
    if not matching:
        return

    # Apply per-condition target_labels filter if set
    target_labels_raw = condition.get("target_labels")
    if target_labels_raw:
        if isinstance(target_labels_raw, str):
            try:
                target_labels = json.loads(target_labels_raw) if target_labels_raw else []
            except (json.JSONDecodeError, TypeError):
                target_labels = []
        else:
            target_labels = target_labels_raw or []
        if target_labels:
            matching = _filter_agents(matching, target_labels)
            if not matching:
                return

    active_agent_ids = {a["agent_id"] for a in matching}
    agent_regex = "|".join(a["agent_id"] for a in matching)

    # Track per-agent status for the matrix view
    status_info: dict[str, dict] = {}

    if metric_type in ("check_name", "logfile", "exec"):
        check_name = condition.get("metric_params", "{}")
        path = ""
        pattern = ""
        warning_threshold = 1
        critical_threshold = 2
        try:
            cp = json.loads(check_name)
            check_name = cp.get("check_name", cp.get("query", ""))
            path = cp.get("path", "")
            pattern = cp.get("pattern", "")
            warning_threshold = cp.get("warning_threshold", 1)
            critical_threshold = cp.get("critical_threshold", 2)
        except (json.JSONDecodeError, TypeError):
            check_name = str(check_name)

        # Auto-create logfile watches for each matching agent
        if metric_type == "logfile" and check_name and path and pattern:
            from app.models import ensure_logfile_watch

            for agent in matching:
                ensure_logfile_watch(db, agent["agent_id"], check_name, path, pattern)

        if metric_type == "exec" and check_name:
            _evaluate_group_exec_condition(
                db,
                group,
                condition,
                matching,
                check_name,
                warning_threshold,
                critical_threshold,
                status_info,
            )
        elif check_name:
            _evaluate_group_check_condition(db, group, condition, matching, check_name, status_info)
        _finalize_group_status(db, group_id, condition_id, matching, status_info, active_agent_ids)
        return

    # Build and run PromQL
    promql = build_promql(condition, agent_regex)
    if not promql:
        return

    logger.debug("Group PromQL for '%s': %s", condition_name, promql)
    result = _vm_query(promql)
    if not result or result.get("status") != "success":
        logger.warning("Group PromQL failed for condition '%s': %s", condition_name, result)
        return

    # Build lookup of agent_id -> (value, hostname) and, for disk, all mountpoints
    # Also build a hostname lookup from matching agents as fallback
    agent_hostnames = {a["agent_id"]: a.get("hostname", "") for a in matching}
    seen: dict[str, tuple[float, str]] = {}
    mountpoint_data: dict[str, dict] = {}  # agent_id -> {mountpoint: value}
    for series in result.get("data", {}).get("result", []):
        metric = series.get("metric", {})
        agent_id = metric.get("agent_id", "")
        if not agent_id:
            continue
        hostname = metric.get("hostname", "") or agent_hostnames.get(agent_id, "")
        mountpoint = metric.get("mountpoint", "")
        value_data = series.get("value", [None, None])
        try:
            value = float(value_data[1]) if value_data[1] is not None else None
        except (ValueError, TypeError):
            value = None
        if value is not None:
            if metric_type == "disk" and mountpoint:
                if agent_id not in mountpoint_data:
                    mountpoint_data[agent_id] = {"hostname": hostname, "mountpoints": {}}
                mountpoint_data[agent_id]["mountpoints"][mountpoint] = value
                if agent_id not in seen or value > seen[agent_id][0]:
                    seen[agent_id] = (value, hostname)
            else:
                seen[agent_id] = (value, hostname)

    # Compare each agent/mountpoint against threshold
    if metric_type == "disk":
        _evaluate_disk_conditions(
            db,
            condition,
            matching,
            mountpoint_data,
            threshold,
            operator,
            resolve_threshold,
            for_duration,
            cooldown_secs,
            severity,
            group_id,
            group_name,
            condition_id,
            condition_name,
            status_info,
            active_agent_ids,
        )
    else:
        _evaluate_non_disk_conditions(
            db,
            condition,
            matching,
            seen,
            threshold,
            operator,
            resolve_threshold,
            for_duration,
            cooldown_secs,
            severity,
            group_id,
            group_name,
            condition_id,
            condition_name,
            status_info,
            active_agent_ids,
        )

    _finalize_group_status(db, group_id, condition_id, matching, status_info, active_agent_ids)


def _evaluate_group_check_condition(
    db,
    group: dict,
    condition: dict,
    matching: list[dict],
    check_name: str,
    status_info: dict | None = None,
) -> None:
    """Evaluate a check_name-based group condition against the check_results table."""
    condition_id = condition["id"]
    group_id = group["id"]
    group_name = group.get("name", "")
    condition_name = condition.get("name", "")
    threshold = float(condition["threshold"])
    operator = condition["operator"]
    resolve_threshold = condition.get("resolve_threshold")
    for_duration = condition.get("for_duration", 0)
    cooldown_secs = condition.get("cooldown_secs")
    severity = condition.get("severity", "warning")

    for agent in matching:
        agent_id = agent["agent_id"]
        hostname = agent["hostname"]

        row = db.execute(
            "SELECT exit_code, output FROM check_results "
            "WHERE name = ? AND agent_id = ? "
            "ORDER BY created_at DESC LIMIT 1",
            (check_name, agent_id),
        ).fetchone()
        if row is None:
            if status_info is not None and agent_id not in status_info:
                status_info[agent_id] = {
                    "hostname": hostname,
                    "last_value": None,
                    "status": "unknown",
                }
            continue

        value = float(row["exit_code"])
        labels = {
            "group_id": group_id,
            "group_name": group_name,
            "condition_id": condition_id,
            "condition_name": condition_name,
            "agent_id": agent_id,
            "hostname": hostname,
            "metric_type": "check_name",
            "value": value,
        }

        existing = get_active_group_event(db, condition_id, agent_id)
        fire_condition = _compare(value, operator, threshold)

        if fire_condition:
            if status_info is not None:
                status_info[agent_id] = {
                    "hostname": hostname,
                    "last_value": value,
                    "status": severity,
                }
            if existing is None:
                if is_silenced(db, None, labels):
                    if status_info is not None:
                        status_info[agent_id] = {
                            "hostname": hostname,
                            "last_value": value,
                            "status": "silenced",
                        }
                    continue
                if for_duration and for_duration > 0:
                    if _check_db_debounce(db, group_id, condition_id, agent_id, for_duration):
                        if status_info is not None:
                            status_info[agent_id] = {
                                "hostname": hostname,
                                "last_value": value,
                                "status": "pending",
                            }
                        continue
                if cooldown_secs and cooldown_secs > 0:
                    resolved = get_latest_resolved_group_event(db, condition_id, agent_id)
                    if resolved and resolved.get("resolved_at"):
                        resolved_dt = _parse_iso(resolved["resolved_at"])
                        if (
                            resolved_dt
                            and (datetime.now(UTC) - resolved_dt).total_seconds() < cooldown_secs
                        ):
                            if status_info is not None:
                                status_info[agent_id] = {
                                    "hostname": hostname,
                                    "last_value": value,
                                    "status": "pending",
                                }
                            continue
                event = create_alert_event(
                    db,
                    group_condition_id=condition_id,
                    labels=labels,
                    value=value,
                )
                _dispatch_group_notifications(db, condition, event, "firing")
            elif existing is not None:
                pass  # still firing or acknowledged, nothing to do
        else:
            if status_info is not None:
                status_info[agent_id] = {"hostname": hostname, "last_value": value, "status": "ok"}
            if existing is not None:
                resolve_ok = True
                if resolve_threshold is not None:
                    resolve_ok = _compare(value, _inverse_operator(operator), resolve_threshold)
                if resolve_ok:
                    resolve_alert_event(db, existing["id"])
                    existing["value"] = value
                    _dispatch_group_notifications(db, condition, existing, "resolved")


def _evaluate_group_exec_condition(
    db,
    group: dict,
    condition: dict,
    matching: list[dict],
    check_name: str,
    warning_threshold: int,
    critical_threshold: int,
    status_info: dict | None = None,
) -> None:
    """Evaluate an exec script condition against the check_results table.

    Uses Nagios-style exit code evaluation:
        0 = OK, 1+ = WARNING based on warning_threshold, 2+ = CRITICAL based on critical_threshold.
    """
    from app.models import (
        create_alert_event,
        get_active_group_event,
        get_latest_resolved_group_event,
        is_silenced,
        resolve_alert_event,
    )

    condition_id = condition["id"]
    group_id = group["id"]
    group_name = group.get("name", "")
    condition_name = condition.get("name", "")
    for_duration = condition.get("for_duration", 0)
    cooldown_secs = condition.get("cooldown_secs")
    severity = condition.get("severity", "warning")

    for agent in matching:
        agent_id = agent["agent_id"]
        hostname = agent["hostname"]

        row = db.execute(
            "SELECT exit_code, output, created_at FROM check_results "
            "WHERE name = ? AND agent_id = ? "
            "ORDER BY created_at DESC LIMIT 1",
            (check_name, agent_id),
        ).fetchone()

        if row is None:
            if status_info is not None and agent_id not in status_info:
                status_info[agent_id] = {
                    "hostname": hostname,
                    "last_value": None,
                    "status": "unknown",
                }
            continue

        exit_code = int(row["exit_code"])

        # Determine status based on thresholds
        if exit_code >= critical_threshold:
            fire_severity = "critical"
            value = float(exit_code)
        elif exit_code >= warning_threshold:
            fire_severity = severity or "warning"
            value = float(exit_code)
        else:
            fire_severity = None
            value = 0.0

        labels = {
            "group_id": group_id,
            "group_name": group_name,
            "condition_id": condition_id,
            "condition_name": condition_name,
            "agent_id": agent_id,
            "hostname": hostname,
            "metric_type": "exec",
            "value": value,
            "exit_code": exit_code,
        }
        existing = get_active_group_event(db, condition_id, agent_id)

        if fire_severity:
            if status_info is not None:
                status_info[agent_id] = {
                    "hostname": hostname,
                    "last_value": value,
                    "status": fire_severity,
                }
            if existing is None:
                if is_silenced(db, None, labels):
                    if status_info is not None:
                        status_info[agent_id] = {
                            "hostname": hostname,
                            "last_value": value,
                            "status": "silenced",
                        }
                    continue
                if for_duration and for_duration > 0:
                    if _check_db_debounce(db, group_id, condition_id, agent_id, for_duration):
                        if status_info is not None:
                            status_info[agent_id] = {
                                "hostname": hostname,
                                "last_value": value,
                                "status": "pending",
                            }
                        continue
                if cooldown_secs and cooldown_secs > 0:
                    resolved = get_latest_resolved_group_event(db, condition_id, agent_id)
                    if resolved and resolved.get("resolved_at"):
                        resolved_dt = _parse_iso(resolved["resolved_at"])
                        if (
                            resolved_dt
                            and (datetime.now(UTC) - resolved_dt).total_seconds() < cooldown_secs
                        ):
                            if status_info is not None:
                                status_info[agent_id] = {
                                    "hostname": hostname,
                                    "last_value": value,
                                    "status": "pending",
                                }
                            continue
                event = create_alert_event(
                    db,
                    group_condition_id=condition_id,
                    labels=labels,
                    value=value,
                )
                _dispatch_group_notifications(db, condition, event, "firing")
        else:
            if status_info is not None:
                status_info[agent_id] = {"hostname": hostname, "last_value": 0.0, "status": "ok"}
            if existing is not None:
                resolve_alert_event(db, existing["id"])
                existing["value"] = value
                _dispatch_group_notifications(db, condition, existing, "resolved")


def _evaluate_non_disk_conditions(
    db,
    condition,
    matching: list[dict],
    seen: dict[str, tuple[float, str]],
    threshold: float,
    operator: str,
    resolve_threshold: float | None,
    for_duration: int,
    cooldown_secs: int | None,
    severity: str,
    group_id: int,
    group_name: str,
    condition_id: int,
    condition_name: str,
    status_info: dict[str, dict],
    active_agent_ids: set[str],
) -> None:
    """Evaluate non-disk conditions: one alert per agent, worst value."""
    from app.models import (
        create_alert_event,
        get_active_group_event,
        get_latest_resolved_group_event,
        is_silenced,
        resolve_alert_event,
    )

    for agent_id, (value, hostname) in seen.items():
        labels = {
            "group_id": group_id,
            "group_name": group_name,
            "condition_id": condition_id,
            "condition_name": condition_name,
            "agent_id": agent_id,
            "hostname": hostname,
            "metric_type": condition.get("metric_type", ""),
            "value": value,
        }

        existing = get_active_group_event(db, condition_id, agent_id)
        fire_condition = _compare(value, operator, threshold)

        if fire_condition:
            if status_info is not None:
                status_info[agent_id] = {
                    "hostname": hostname,
                    "last_value": value,
                    "status": severity,
                }
            if existing is None:
                if is_silenced(db, None, labels):
                    if status_info is not None:
                        status_info[agent_id]["status"] = "silenced"
                    continue
                if for_duration and for_duration > 0:
                    if _check_db_debounce(db, group_id, condition_id, agent_id, for_duration):
                        if status_info is not None:
                            status_info[agent_id]["status"] = "pending"
                        continue
                if cooldown_secs and cooldown_secs > 0:
                    resolved = get_latest_resolved_group_event(db, condition_id, agent_id)
                    if resolved and resolved.get("resolved_at"):
                        resolved_dt = _parse_iso(resolved["resolved_at"])
                        if (
                            resolved_dt
                            and (datetime.now(UTC) - resolved_dt).total_seconds() < cooldown_secs
                        ):
                            if status_info is not None:
                                status_info[agent_id]["status"] = "pending"
                            continue
                event = create_alert_event(
                    db,
                    group_condition_id=condition_id,
                    labels=labels,
                    value=value,
                )
                _dispatch_group_notifications(db, condition, event, "firing")
            elif existing is not None:
                pass
        else:
            if status_info is not None:
                status_info[agent_id] = {"hostname": hostname, "last_value": value, "status": "ok"}
            if existing is not None:
                resolve_ok = True
                if resolve_threshold is not None:
                    resolve_ok = _compare(value, _inverse_operator(operator), resolve_threshold)
                if resolve_ok:
                    resolve_alert_event(db, existing["id"])
                    existing["value"] = value
                    _dispatch_group_notifications(db, condition, existing, "resolved")


def _evaluate_disk_conditions(
    db,
    condition,
    matching: list[dict],
    mountpoint_data: dict[str, dict],
    threshold: float,
    operator: str,
    resolve_threshold: float | None,
    for_duration: int,
    cooldown_secs: int | None,
    severity: str,
    group_id: int,
    group_name: str,
    condition_id: int,
    condition_name: str,
    status_info: dict[str, dict],
    active_agent_ids: set[str],
) -> None:
    """Evaluate disk conditions: one alert per mountpoint per agent.

    Each mountpoint fires and resolves independently so a full /dev/sda
    doesn't keep /dev/sdb's alerts alive.
    """
    from app.models import (
        create_alert_event,
        get_active_group_event,
        get_latest_resolved_group_event,
        is_silenced,
        resolve_alert_event,
    )

    for agent_id, data in mountpoint_data.items():
        hostname = data["hostname"]
        mps = data["mountpoints"]
        if not mps:
            continue
        worst_val = max(mps.values())

        # Agent-level status — use the worst mountpoint
        if status_info is not None:
            status_info[agent_id] = {
                "hostname": hostname,
                "last_value": worst_val,
                "status": severity if _compare(worst_val, operator, threshold) else "ok",
                "last_detail": json.dumps(mps),
            }

        # Debounce is per-agent (not per-mountpoint): check once before iterating
        any_above = any(_compare(mp_val, operator, threshold) for mp_val in mps.values())
        existing_events = {}
        if any_above:
            debouncing = (
                for_duration
                and for_duration > 0
                and _check_db_debounce(db, group_id, condition_id, agent_id, for_duration)
            )
        else:
            debouncing = False

        # Preload existing events for this agent
        for mp in mps:
            ev = get_active_group_event(db, condition_id, agent_id, mountpoint=mp)
            if ev:
                existing_events[mp] = ev

        # Per-mountpoint alert lifecycle
        for mp, mp_val in mps.items():
            over = _compare(mp_val, operator, threshold)
            labels = {
                "group_id": group_id,
                "group_name": group_name,
                "condition_id": condition_id,
                "condition_name": condition_name,
                "agent_id": agent_id,
                "hostname": hostname,
                "metric_type": "disk",
                "value": mp_val,
                "mountpoint": mp,
            }
            existing = existing_events.get(mp)

            if over:
                if existing is None:
                    if debouncing:
                        continue
                    if cooldown_secs and cooldown_secs > 0:
                        resolved = get_latest_resolved_group_event(
                            db, condition_id, agent_id, mountpoint=mp
                        )
                        if resolved and resolved.get("resolved_at"):
                            resolved_dt = _parse_iso(resolved["resolved_at"])
                            if (
                                resolved_dt
                                and (datetime.now(UTC) - resolved_dt).total_seconds()
                                < cooldown_secs
                            ):
                                continue
                    if is_silenced(db, None, labels):
                        continue
                    event = create_alert_event(
                        db,
                        group_condition_id=condition_id,
                        labels=labels,
                        value=mp_val,
                    )
                    _dispatch_group_notifications(db, condition, event, "firing")
            else:
                if existing is not None:
                    resolve_ok = True
                    if resolve_threshold is not None:
                        resolve_ok = _compare(
                            mp_val, _inverse_operator(operator), resolve_threshold
                        )
                    if resolve_ok:
                        resolve_alert_event(db, existing["id"])
                        existing["value"] = mp_val
                        _dispatch_group_notifications(db, condition, existing, "resolved")


def _finalize_group_status(
    db,
    group_id: int,
    condition_id: int,
    matching: list[dict],
    status_info: dict[str, dict],
    active_agent_ids: set[str],
) -> None:
    """Upsert per-agent status rows and prune stale entries.

    Called at the end of every condition eval cycle to persist the
    Nagios-style matrix data.
    """
    for agent in matching:
        aid = agent["agent_id"]
        info = status_info.get(aid)
        if info:
            lv = info.get("last_value")
            detail = info.get("last_detail")
            upsert_group_status(
                db,
                group_id,
                condition_id,
                aid,
                info.get("hostname", ""),
                info["status"],
                lv,
                lv,
                last_detail=detail,
            )
        else:
            upsert_group_status(
                db,
                group_id,
                condition_id,
                aid,
                agent.get("hostname", ""),
                "unknown",
                None,
                None,
            )
    prune_group_statuses(db, group_id, active_agent_ids)


def _check_db_debounce(
    db,
    group_id: int,
    condition_id: int,
    agent_id: str,
    for_duration: int,
) -> bool:
    """Debounce check backed by the DB so it survives worker changes.

    Stores 'first seen' timestamp in monitoring_group_status.debounce_started_at.
    Returns True if the condition has NOT yet persisted for for_duration seconds.
    """
    if for_duration <= 0:
        return False

    row = db.execute(
        "SELECT debounce_started_at FROM monitoring_group_status "
        "WHERE group_id = ? AND condition_id = ? AND agent_id = ?",
        (group_id, condition_id, agent_id),
    ).fetchone()

    now_iso = _utcnow_iso()
    now = datetime.now(UTC)

    if row is None:
        db.execute(
            "INSERT INTO monitoring_group_status "
            "(group_id, condition_id, agent_id, hostname, status, debounce_started_at, "
            " last_metric_value, last_evaluated_at, created_at, updated_at) "
            "VALUES (?, ?, ?, '', 'pending', ?, NULL, ?, ?, ?)",
            (group_id, condition_id, agent_id, now_iso, now_iso, now_iso, now_iso),
        )
        db.commit()
        return True

    first_seen = row["debounce_started_at"]
    if first_seen is None:
        db.execute(
            "UPDATE monitoring_group_status SET debounce_started_at = ?, "
            "status = 'pending', updated_at = ? "
            "WHERE group_id = ? AND condition_id = ? AND agent_id = ?",
            (now_iso, now_iso, group_id, condition_id, agent_id),
        )
        db.commit()
        return True

    try:
        first_dt = _parse_iso(first_seen)
        if first_dt and (now - first_dt).total_seconds() < for_duration:
            return True
    except (ValueError, TypeError):
        db.execute(
            "UPDATE monitoring_group_status SET debounce_started_at = ?, "
            "updated_at = ? "
            "WHERE group_id = ? AND condition_id = ? AND agent_id = ?",
            (now_iso, now_iso, group_id, condition_id, agent_id),
        )
        db.commit()
        return True

    db.execute(
        "UPDATE monitoring_group_status SET debounce_started_at = NULL, updated_at = ? "
        "WHERE group_id = ? AND condition_id = ? AND agent_id = ?",
        (now_iso, group_id, condition_id, agent_id),
    )
    db.commit()
    return False


def evaluate_group_rules(db) -> None:
    """Evaluate all enabled monitoring group conditions.

    Called from within evaluate_rules() — the outer function already
    holds the eval lock.

    Args:
        db: Database connection (from evaluate_rules).
    """
    groups = list_monitoring_groups(db, enabled=True)
    if not groups:
        return

    logger.debug("Group eval: evaluating %d group(s)", len(groups))

    for group in groups:
        conditions = list_group_conditions(db, group["id"])
        if not conditions:
            continue

        for condition in conditions:
            if not condition.get("enabled", 1):
                continue

            # Skip if interval_secs not elapsed since last_eval_at
            last_eval = condition.get("last_eval_at")
            interval = condition.get("interval_secs", 60)
            if last_eval and interval > 0:
                last_dt = _parse_iso(last_eval)
                if last_dt and (datetime.now(UTC) - last_dt).total_seconds() < interval:
                    continue

            try:
                _evaluate_group_condition(db, group, condition)
                update_condition_last_eval(db, condition["id"])
            except Exception:
                logger.exception(
                    "Group eval failed for %s/%s (group=%s, condition=%s)",
                    group.get("name"),
                    condition.get("name"),
                    group.get("id"),
                    condition.get("id"),
                )


def _dispatch_group_notifications(db, condition: dict, event: dict, state: str) -> None:
    """Dispatch notifications for a group alert condition state transition.

    Similar to _dispatch_notifications but uses group_condition_channels
    junction table instead of rule_notification_channels.
    """
    channels = get_group_condition_channels(db, condition["id"], default_to_all=True)
    if not channels:
        return

    for channel in channels:
        try:
            # Reuse _send_to_channel — pass condition dict in place of rule
            _send_to_channel(channel, condition, event, state)
        except Exception:
            logger.exception(
                "Group notification dispatch failed for channel %s", channel.get("name")
            )

    if state == "firing" and event.get("notified_at") is None:
        db.execute(
            "UPDATE alert_events SET notified_at = ? WHERE id = ?",
            (_utcnow_iso(), event["id"]),
        )
        db.commit()


# ── Meta-monitoring ──────────────────────────────────────────────────────


def get_eval_health(db) -> dict:
    """Return the eval loop health status.

    Returns:
        Dict with healthy (bool), last_eval_at (str), and message.
    """
    status = get_eval_lock_status(db)
    if status is None:
        return {"healthy": False, "last_eval_at": None, "message": "No eval lock record found"}

    last_eval = status.get("last_eval_at")
    if not last_eval:
        return {"healthy": False, "last_eval_at": None, "message": "Eval loop has not run yet"}

    last_dt = _parse_iso(last_eval)
    if last_dt is None:
        return {
            "healthy": False,
            "last_eval_at": str(last_eval),
            "message": "Invalid last_eval_at timestamp",
        }

    last_iso = last_dt.strftime("%Y-%m-%dT%H:%M:%SZ")
    age_seconds = (datetime.now(UTC) - last_dt).total_seconds()
    if age_seconds > 180:
        return {
            "healthy": False,
            "last_eval_at": last_iso,
            "message": f"Eval loop stale — last run {age_seconds:.0f}s ago",
        }

    return {
        "healthy": True,
        "last_eval_at": last_iso,
        "message": f"Eval loop healthy — last run {age_seconds:.0f}s ago",
    }
