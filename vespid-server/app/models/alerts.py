from __future__ import annotations

import json
import logging
import re
from datetime import UTC, datetime, timedelta
from typing import TYPE_CHECKING

from .db_core import _row_to_dict, _utcnow_iso

if TYPE_CHECKING:
    from ..routes.auth import User

logger = logging.getLogger(__name__)

# ── Alert system helpers ────────────────────────────────────────────────


# ── Alert Rules ──────────────────────────────────────────────────────────


def create_alert_rule(
    db,
    user_id: int | None,
    name: str,
    query: str | None = None,
    check_name: str | None = None,
    operator: str = ">",
    threshold: float = 0.0,
    resolve_threshold: float | None = None,
    severity: str = "warning",
    for_duration: int = 0,
    cooldown_secs: int | None = None,
    interval_secs: int = 60,
    tags: dict | None = None,
    enabled: bool = True,
) -> dict:
    """Create a new alert rule.

    Args:
        db: Database connection.
        user_id: Owner user_id, or None for global rules.
        name: Human-readable rule name.
        query: PromQL query string (mutually exclusive with check_name).
        check_name: Health check name (mutually exclusive with query).
        operator: Comparison operator ('>', '<', '==', '>=', '<=').
        threshold: Value threshold for firing.
        resolve_threshold: Optional separate threshold for resolving.
        severity: 'warning' or 'critical'.
        for_duration: Seconds condition must persist before firing.
        cooldown_secs: Minimum seconds after resolve before re-fire.
        interval_secs: Evaluation interval in seconds.
        tags: Optional dict of tags for future inventory/policy use.
        enabled: Whether the rule is active.

    Returns:
        The created rule as a dict.
    """
    now = _utcnow_iso()
    tags_json = json.dumps(tags) if tags else None
    cursor = db.execute(
        "INSERT INTO alert_rules (user_id, name, query, check_name, operator, threshold, "
        "resolve_threshold, severity, for_duration, cooldown_secs, interval_secs, tags, enabled, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            user_id,
            name,
            query,
            check_name,
            operator,
            threshold,
            resolve_threshold,
            severity,
            for_duration,
            cooldown_secs,
            interval_secs,
            tags_json,
            1 if enabled else 0,
            now,
            now,
        ),
    )
    db.commit()
    row = db.execute("SELECT * FROM alert_rules WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return _row_to_dict(row)


def get_alert_rule(db, rule_id: int) -> dict | None:
    """Fetch a single alert rule by ID."""
    row = db.execute("SELECT * FROM alert_rules WHERE id = ?", (rule_id,)).fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


def get_alert_rules(
    db,
    enabled: bool | None = None,
    user_id: int | None = None,
    admin_view: bool = False,
) -> list[dict]:
    """List alert rules with optional filtering.

    Args:
        db: Database connection.
        enabled: If provided, filter by enabled state.
        user_id: If provided and admin_view=False, return personal + global rules.
        admin_view: If True, return all rules (admin only).

    Returns:
        List of rule dicts.
    """
    where_clauses: list[str] = []
    params: list = []

    if enabled is not None:
        where_clauses.append("enabled = ?")
        params.append(1 if enabled else 0)

    if not admin_view and user_id is not None:
        where_clauses.append("(user_id = ? OR user_id IS NULL)")
        params.append(user_id)

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    rows = db.execute(
        f"SELECT * FROM alert_rules {where_sql} ORDER BY created_at DESC",
        params,
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


def update_alert_rule(db, rule_id: int, **fields) -> dict | None:
    """Update an alert rule. Only provided fields are changed.

    Returns:
        The updated rule dict, or None if not found.
    """
    allowed = {
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
    }
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return get_alert_rule(db, rule_id)

    if "tags" in updates and isinstance(updates["tags"], dict):
        updates["tags"] = json.dumps(updates["tags"])
    if "enabled" in updates:
        updates["enabled"] = 1 if updates["enabled"] else 0

    updates["updated_at"] = _utcnow_iso()
    set_clauses = [f"{k} = ?" for k in updates.keys()]
    params = list(updates.values()) + [rule_id]

    db.execute(
        f"UPDATE alert_rules SET {', '.join(set_clauses)} WHERE id = ?",
        params,
    )
    db.commit()
    return get_alert_rule(db, rule_id)


def delete_alert_rule(db, rule_id: int) -> bool:
    """Delete an alert rule and resolve any firing events.

    Returns:
        True if the rule existed and was deleted.
    """
    row = db.execute("SELECT id FROM alert_rules WHERE id = ?", (rule_id,)).fetchone()
    if row is None:
        return False

    now = _utcnow_iso()
    db.execute(
        "UPDATE alert_events SET state = 'resolved', resolved_at = ? WHERE rule_id = ? AND state = 'firing'",
        (now, rule_id),
    )
    db.execute("DELETE FROM alert_events WHERE rule_id = ?", (rule_id,))
    db.execute("DELETE FROM rule_notification_channels WHERE rule_id = ?", (rule_id,))
    db.execute("DELETE FROM alert_rules WHERE id = ?", (rule_id,))
    db.commit()
    return True


# ── Alert Events ────────────────────────────────────────────────────────


def create_alert_event(
    db,
    rule_id: int | None = None,
    labels: dict | None = None,
    value: float = 0.0,
    state: str = "firing",
    entity_id: int | None = None,
    group_condition_id: int | None = None,
) -> dict:
    """Create a new alert event.

    Args:
        db: Database connection.
        rule_id: The triggering rule ID (mutually exclusive with group_condition_id).
        labels: Dict of runtime labels (e.g. agent_id, hostname).
        value: The value that triggered the alert.
        state: 'firing', 'resolved', or 'acknowledged'.
        entity_id: Optional canonical inventory entity ID.
        group_condition_id: The triggering group condition ID (mutually exclusive with rule_id).

    Returns:
        The created event as a dict.
    """
    now = _utcnow_iso()
    labels_json = json.dumps(labels or {})
    cursor = db.execute(
        "INSERT INTO alert_events (rule_id, entity_id, group_condition_id, labels, value, state, fired_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (rule_id, entity_id, group_condition_id, labels_json, value, state, now),
    )
    db.commit()
    row = db.execute("SELECT * FROM alert_events WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return _row_to_dict(row)


def get_alert_event(db, event_id: int) -> dict | None:
    """Fetch a single alert event by ID."""
    row = db.execute("SELECT * FROM alert_events WHERE id = ?", (event_id,)).fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


def get_active_alerts(db, user_id: int | None = None, admin_view: bool = False) -> list[dict]:
    """Return currently firing events (unresolved + unacknowledged).

    Includes both rule-fired and group-condition-fired events.

    Args:
        db: Database connection.
        user_id: If provided and admin_view=False, filter to personal + global rules.
        admin_view: If True, return all active alerts.

    Returns:
        List of active event dicts joined with rule or condition info.
    """
    sql = (
        "SELECT ae.*, "
        "  COALESCE(ar.name, gac.name) as rule_name, "
        "  COALESCE(ar.severity, gac.severity) as severity "
        "FROM alert_events ae "
        "LEFT JOIN alert_rules ar ON ae.rule_id = ar.id "
        "LEFT JOIN group_alert_conditions gac ON ae.group_condition_id = gac.id "
        "WHERE ae.state IN ('firing', 'acknowledged')"
    )
    params: list = []

    if not admin_view and user_id is not None:
        sql += " AND (ar.user_id = ? OR ar.user_id IS NULL)"
        params.append(user_id)

    sql += " ORDER BY ae.fired_at DESC"
    rows = db.execute(sql, params).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_alert_event_count(db, severity: str | None = None) -> int:
    """Count firing alerts, optionally filtered by severity.

    Includes both rule-fired and group-condition-fired events.

    Args:
        db: Database connection.
        severity: 'warning' or 'critical' to filter, or None for all.

    Returns:
        Count of firing alert events.
    """
    sql = (
        "SELECT COUNT(*) FROM alert_events ae "
        "LEFT JOIN alert_rules ar ON ae.rule_id = ar.id "
        "LEFT JOIN group_alert_conditions gac ON ae.group_condition_id = gac.id "
        "WHERE ae.state = 'firing'"
    )
    params: list = []
    if severity:
        sql += " AND (COALESCE(ar.severity, gac.severity) = ?)"
        params.append(severity)
    return db.execute(sql, params).fetchone()[0]


def resolve_alert_event(db, event_id: int) -> bool:
    """Mark an alert event as resolved.

    Returns:
        True if the event was found and updated.
    """
    now = _utcnow_iso()
    c = db.execute(
        "UPDATE alert_events SET state = 'resolved', resolved_at = ? WHERE id = ? AND state IN ('firing', 'acknowledged')",
        (now, event_id),
    )
    db.commit()
    return c.rowcount > 0


def acknowledge_alert_event(db, event_id: int, user_id: int) -> bool:
    """Mark an alert event as acknowledged by a user.

    Returns:
        True if the event was found and updated.
    """
    c = db.execute(
        "UPDATE alert_events SET state = 'acknowledged', acknowledged_by = ? WHERE id = ? AND state = 'firing'",
        (user_id, event_id),
    )
    db.commit()
    return c.rowcount > 0


def reopen_alert_event(db, event_id: int, value: float = 0.0) -> bool:
    """Revert an acknowledged alert event back to firing state with an updated value.

    Used when a condition continues to fire after a user acknowledged it,
    preventing duplicate events.
    """
    c = db.execute(
        "UPDATE alert_events SET state = 'firing', value = ? WHERE id = ? AND state IN ('firing', 'acknowledged')",
        (value, event_id),
    )
    db.commit()
    return c.rowcount > 0


def get_alert_history(
    db,
    user_id: int | None = None,
    admin_view: bool = False,
    page: int = 1,
    per_page: int = 50,
    time_filter: str = "all",
    search_query: str = "",
) -> dict:
    """Return paginated resolved/acknowledged alert history.

    Includes both rule-fired and group-condition-fired events.
    Supports time_filter (all, 24h, 7d, 30d) and search_query for server-side filtering.

    Returns:
        Dict with keys: events, total, page, per_page.
    """
    per_page = max(1, min(200, per_page))
    offset = (page - 1) * per_page

    base_joins = (
        "FROM alert_events ae "
        "LEFT JOIN alert_rules ar ON ae.rule_id = ar.id "
        "LEFT JOIN group_alert_conditions gac ON ae.group_condition_id = gac.id "
    )
    where = "ae.state IN ('resolved', 'acknowledged')"
    params: list = []

    if not admin_view and user_id is not None:
        where += " AND (ar.user_id = ? OR ar.user_id IS NULL)"
        params.append(user_id)

    if time_filter == "24h":
        where += " AND ae.fired_at >= datetime('now', '-1 day')"
    elif time_filter == "7d":
        where += " AND ae.fired_at >= datetime('now', '-7 days')"
    elif time_filter == "30d":
        where += " AND ae.fired_at >= datetime('now', '-30 days')"

    if search_query:
        like = "%" + search_query + "%"
        where += " AND (COALESCE(ar.name, gac.name) LIKE ? OR ae.labels LIKE ?)"
        params.extend([like, like])

    count_sql = "SELECT COUNT(*) " + base_joins + "WHERE " + where
    data_sql = (
        "SELECT ae.*, "
        "  COALESCE(ar.name, gac.name) as rule_name, "
        "  COALESCE(ar.severity, gac.severity) as severity " + base_joins + "WHERE " + where
    )

    data_sql += " ORDER BY ae.fired_at DESC LIMIT ? OFFSET ?"

    total = db.execute(count_sql, params).fetchone()[0]
    rows = db.execute(data_sql, params + [per_page, offset]).fetchall()

    return {
        "events": [_row_to_dict(r) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": max(1, (total + per_page - 1) // per_page),
    }


def get_latest_resolved_event(db, rule_id: int, labels: dict) -> dict | None:
    """Get the most recent resolved event for a rule+labels combination.

    Used for cooldown checking.
    """
    labels_json = json.dumps(labels, sort_keys=True)
    row = db.execute(
        "SELECT * FROM alert_events WHERE rule_id = ? AND labels = ? AND state = 'resolved' "
        "ORDER BY resolved_at DESC LIMIT 1",
        (rule_id, labels_json),
    ).fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


# ── Notification Channels ────────────────────────────────────────────────


def create_notification_channel(
    db,
    name: str,
    channel_type: str,
    config: dict,
    enabled: bool = True,
) -> dict:
    """Create a notification channel.

    Args:
        db: Database connection.
        name: Human-readable channel name.
        channel_type: 'email', 'slack', 'webhook', or 'pagerduty'.
        config: Dict of type-specific configuration.
        enabled: Whether the channel is active.

    Returns:
        The created channel as a dict.
    """
    now = _utcnow_iso()
    config_json = json.dumps(config)
    cursor = db.execute(
        "INSERT INTO notification_channels (name, type, config, enabled, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (name, channel_type, config_json, 1 if enabled else 0, now, now),
    )
    db.commit()
    row = db.execute(
        "SELECT * FROM notification_channels WHERE id = ?", (cursor.lastrowid,)
    ).fetchone()
    return _row_to_dict(row)


def get_notification_channel(db, channel_id: int) -> dict | None:
    """Fetch a single notification channel by ID."""
    row = db.execute("SELECT * FROM notification_channels WHERE id = ?", (channel_id,)).fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


def get_notification_channels(db, enabled: bool | None = None) -> list[dict]:
    """List notification channels, optionally filtering by enabled state."""
    sql = "SELECT * FROM notification_channels"
    params: list = []
    if enabled is not None:
        sql += " WHERE enabled = ?"
        params.append(1 if enabled else 0)
    sql += " ORDER BY name ASC"
    rows = db.execute(sql, params).fetchall()
    return [_row_to_dict(r) for r in rows]


def update_notification_channel(db, channel_id: int, **fields) -> dict | None:
    """Update a notification channel. Only provided fields are changed."""
    allowed = {"name", "type", "config", "enabled"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return get_notification_channel(db, channel_id)

    if "config" in updates and isinstance(updates["config"], dict):
        updates["config"] = json.dumps(updates["config"])
    if "enabled" in updates:
        updates["enabled"] = 1 if updates["enabled"] else 0
    updates["updated_at"] = _utcnow_iso()

    set_clauses = [f"{k} = ?" for k in updates.keys()]
    params = list(updates.values()) + [channel_id]

    db.execute(
        f"UPDATE notification_channels SET {', '.join(set_clauses)} WHERE id = ?",
        params,
    )
    db.commit()
    return get_notification_channel(db, channel_id)


def delete_notification_channel(db, channel_id: int) -> bool:
    """Delete a notification channel and its rule associations.

    Returns:
        True if the channel existed and was deleted.
    """
    row = db.execute("SELECT id FROM notification_channels WHERE id = ?", (channel_id,)).fetchone()
    if row is None:
        return False
    db.execute("DELETE FROM rule_notification_channels WHERE channel_id = ?", (channel_id,))
    db.execute("DELETE FROM notification_channels WHERE id = ?", (channel_id,))
    db.commit()
    return True


# ── Rule-Channel associations ─────────────────────────────────────────────


def get_channels_for_rule(db, rule_id: int, default_to_all: bool = True) -> list[dict]:
    """Get notification channels linked to a rule.

    If the rule has no explicit channel associations and default_to_all is True,
    returns all enabled channels.

    Args:
        db: Database connection.
        rule_id: The alert rule ID.
        default_to_all: If True and no associations, return all enabled channels.

    Returns:
        List of channel dicts.
    """
    rows = db.execute(
        "SELECT nc.* FROM notification_channels nc "
        "JOIN rule_notification_channels rnc ON nc.id = rnc.channel_id "
        "WHERE rnc.rule_id = ? AND nc.enabled = 1",
        (rule_id,),
    ).fetchall()
    if rows:
        return [_row_to_dict(r) for r in rows]
    if default_to_all:
        return get_notification_channels(db, enabled=True)
    return []


def set_rule_channels(db, rule_id: int, channel_ids: list[int]) -> None:
    """Replace the channel associations for a rule.

    Args:
        db: Database connection.
        rule_id: The alert rule ID.
        channel_ids: List of channel IDs to associate.
    """
    db.execute("DELETE FROM rule_notification_channels WHERE rule_id = ?", (rule_id,))
    for cid in channel_ids:
        db.execute(
            "INSERT INTO rule_notification_channels (rule_id, channel_id) VALUES (?, ?)",
            (rule_id, cid),
        )
    db.commit()


# ── Silences ─────────────────────────────────────────────────────────────


_SENTINEL = object()
_sentinel = _SENTINEL  # for backwards compat if imported


def create_silence(
    db,
    matchers: list[dict],
    rule_id: int | None,
    starts_at: str,
    ends_at: str,
    reason: str,
    created_by: int,
) -> dict:
    """Create an alert silence.

    Args:
        db: Database connection.
        matchers: List of dicts with keys: label, op, value.
        rule_id: Specific rule to silence, or None for all rules.
        starts_at: ISO-8601 start time.
        ends_at: ISO-8601 end time.
        reason: Human-readable reason for the silence.
        created_by: User ID creating the silence.

    Returns:
        The created silence as a dict.
    """
    matchers_json = json.dumps(matchers)
    now = _utcnow_iso()
    cursor = db.execute(
        "INSERT INTO alert_silences (matchers, rule_id, starts_at, ends_at, reason, created_by, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (matchers_json, rule_id, starts_at, ends_at, reason, created_by, now),
    )
    db.commit()
    row = db.execute("SELECT * FROM alert_silences WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return _row_to_dict(row)


def get_silence(db, silence_id: int) -> dict | None:
    """Fetch a single silence by ID."""
    row = db.execute("SELECT * FROM alert_silences WHERE id = ?", (silence_id,)).fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


def get_active_silences(db) -> list[dict]:
    """Return silences where now() is between starts_at and ends_at."""
    now = _utcnow_iso()
    rows = db.execute(
        "SELECT * FROM alert_silences WHERE starts_at <= ? AND ends_at >= ? ORDER BY ends_at DESC",
        (now, now),
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_silences(db, include_expired: bool = False) -> list[dict]:
    """Return all silences, optionally including expired ones."""
    if include_expired:
        rows = db.execute("SELECT * FROM alert_silences ORDER BY created_at DESC").fetchall()
    else:
        now = _utcnow_iso()
        rows = db.execute(
            "SELECT * FROM alert_silences WHERE ends_at >= ? ORDER BY created_at DESC",
            (now,),
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def update_silence(
    db,
    silence_id: int,
    matchers: list[dict] | None = None,
    rule_id: int | None | object = _sentinel,
    starts_at: str | None = None,
    ends_at: str | None = None,
    reason: str | None = None,
) -> dict | None:
    """Update an alert silence. Only provided fields are changed.

    Args:
        db: Database connection.
        silence_id: ID of the silence to update.
        matchers: List of dicts with keys: label, op, value.
        rule_id: Specific rule to silence, or None for all rules.
                Pass the sentinel value (default) to leave unchanged.
        starts_at: ISO-8601 start time.
        ends_at: ISO-8601 end time.
        reason: Human-readable reason for the silence.

    Returns:
        The updated silence as a dict, or None if not found.
    """
    existing = db.execute("SELECT * FROM alert_silences WHERE id = ?", (silence_id,)).fetchone()
    if existing is None:
        return None

    matchers_json = json.dumps(matchers) if matchers is not None else existing["matchers"]
    new_rule_id = rule_id if rule_id is not _sentinel else existing["rule_id"]
    new_starts = starts_at if starts_at is not None else existing["starts_at"]
    new_ends = ends_at if ends_at is not None else existing["ends_at"]
    new_reason = reason if reason is not None else existing["reason"]

    db.execute(
        "UPDATE alert_silences SET matchers=?, rule_id=?, starts_at=?, ends_at=?, reason=? WHERE id=?",
        (matchers_json, new_rule_id, new_starts, new_ends, new_reason, silence_id),
    )
    db.commit()
    row = db.execute("SELECT * FROM alert_silences WHERE id = ?", (silence_id,)).fetchone()
    return _row_to_dict(row)


def delete_silence(db, silence_id: int) -> bool:
    """Remove a silence.

    Returns:
        True if the silence existed and was deleted.
    """
    c = db.execute("DELETE FROM alert_silences WHERE id = ?", (silence_id,))
    db.commit()
    return c.rowcount > 0


def is_silenced(db, rule_id: int | None, labels: dict) -> bool:
    """Check if any active silence matches this rule+labels combination.

    For group-condition events, pass rule_id=None. Silences with
    rule_id IS NULL match all events; silences with a specific rule_id
    only match rule-fired events.

    Args:
        db: Database connection.
        rule_id: The alert rule ID, or None for group-condition events.
        labels: Dict of event labels to match against silence matchers.

    Returns:
        True if the event is silenced.
    """

    now = _utcnow_iso()
    rows = db.execute(
        "SELECT matchers, rule_id FROM alert_silences WHERE starts_at <= ? AND ends_at >= ?",
        (now, now),
    ).fetchall()

    for row in rows:
        # If silence targets a specific rule but we're checking a group event, skip
        if rule_id is None and row["rule_id"] is not None:
            continue
        # If silence targets a different rule, skip
        if rule_id is not None and row["rule_id"] is not None and row["rule_id"] != rule_id:
            continue

        matchers = json.loads(row["matchers"])
        if not isinstance(matchers, list):
            continue

        all_match = True
        for matcher in matchers:
            label = matcher.get("label", "")
            op = matcher.get("op", "=")
            value = matcher.get("value", "")
            label_val = labels.get(label, "")

            if op == "=":
                if label_val != value:
                    all_match = False
                    break
            elif op == "!=":
                if label_val == value:
                    all_match = False
                    break
            elif op == "=~":
                try:
                    if not re.search(value, str(label_val)):
                        all_match = False
                        break
                except re.error:
                    all_match = False
                    break
            elif op == "!~":
                try:
                    if re.search(value, str(label_val)):
                        all_match = False
                        break
                except re.error:
                    all_match = False
                    break
            else:
                # Unknown op — treat as no-match
                all_match = False
                break

        if all_match:
            return True

    return False


# ── Eval Lock ────────────────────────────────────────────────────────────


def acquire_eval_lock(db, worker_id: str, ttl_secs: int = 120) -> bool:
    """Attempt to acquire the singleton eval lock.

    Uses UPDATE with a WHERE that succeeds if:
    - The current lock holder is this same worker_id, OR
    - The lock has expired (expires_at < now)

    Args:
        db: Database connection.
        worker_id: Unique worker identifier (e.g. hostname:pid).
        ttl_secs: Lock time-to-live in seconds.

    Returns:
        True if the lock was acquired, False otherwise.
    """
    now = _utcnow_iso()
    expires = (datetime.now(UTC) + timedelta(seconds=ttl_secs)).strftime("%Y-%m-%dT%H:%M:%SZ")

    c = db.execute(
        "UPDATE alert_eval_lock SET locked_by = ?, locked_at = ?, expires_at = ?, last_eval_at = ? "
        "WHERE id = 1 AND (locked_by = ? OR expires_at < ? OR expires_at IS NULL)",
        (worker_id, now, expires, now, worker_id, now),
    )
    db.commit()
    return c.rowcount > 0


def release_eval_lock(db, worker_id: str) -> bool:
    """Release the eval lock if held by this worker.

    Returns:
        True if the lock was released.
    """
    c = db.execute(
        "UPDATE alert_eval_lock SET locked_by = NULL, locked_at = NULL, expires_at = NULL "
        "WHERE id = 1 AND locked_by = ?",
        (worker_id,),
    )
    db.commit()
    return c.rowcount > 0


def refresh_eval_lock(db, worker_id: str, ttl_secs: int = 120) -> bool:
    """Extend the eval lock TTL (heartbeat during long eval cycles).

    Returns:
        True if the lock was refreshed.
    """
    expires = (datetime.now(UTC) + timedelta(seconds=ttl_secs)).strftime("%Y-%m-%dT%H:%M:%SZ")
    now = _utcnow_iso()
    c = db.execute(
        "UPDATE alert_eval_lock SET expires_at = ?, last_eval_at = ? WHERE id = 1 AND locked_by = ?",
        (expires, now, worker_id),
    )
    db.commit()
    return c.rowcount > 0


def get_eval_lock_status(db) -> dict | None:
    """Return the current eval lock status for health checking.

    Returns:
        Dict with locked_by, locked_at, expires_at, last_eval_at, or None.
    """
    row = db.execute("SELECT * FROM alert_eval_lock WHERE id = 1").fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


# ── Authorization helper ─────────────────────────────────────────────────


def can_manage_rule(rule: dict, user: User | None) -> bool:
    """Check if a user can manage (view/update/delete) an alert rule.

    Admins can manage all rules. Users can manage their own personal rules.
    Global rules (user_id IS NULL) require admin.

    Args:
        rule: The alert rule dict.
        user: The current user object (from Flask-Login).

    Returns:
        True if the user is allowed to manage this rule.
    """
    if user is None or not user.is_authenticated:
        return False
    if user.role == "admin":
        return True
    # Personal rule ownership
    if rule.get("user_id") == user.id:
        return True
    return False
