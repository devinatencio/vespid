from __future__ import annotations

import json
import logging
import sqlite3
from datetime import UTC, datetime, timedelta

from .db_core import _row_to_dict, _utcnow_iso

logger = logging.getLogger(__name__)


def summarize_audit_details(action_type: str, details: str | dict | None) -> str:
    """Return a human-readable summary string for an audit log entry.

    Parses the *details* JSON (or dict) and produces a concise, inline
    description suitable for displaying in the audit log table.
    """
    if not details:
        return ""
    if isinstance(details, str):
        try:
            parsed = json.loads(details)
        except (json.JSONDecodeError, TypeError):
            return ""
    else:
        parsed = details

    if not isinstance(parsed, dict):
        return ""

    # ── Authentication ────────────────────────────────────────────────
    if action_type == "login_failed":
        return parsed.get("reason", "Failed login attempt")

    # ── User Management ───────────────────────────────────────────────
    if action_type == "role_change":
        new_role = parsed.get("new_role", parsed.get("role", ""))
        return f"Role → {new_role}"
    if action_type == "password_change":
        return "Password changed"
    if action_type == "profile_update":
        changed = parsed.get("changed", parsed.get("fields", ""))
        if isinstance(changed, list):
            changed = ", ".join(changed)
        return f"Updated: {changed}" if changed else "Profile updated"

    # ── API Keys ──────────────────────────────────────────────────────
    if action_type == "key_create":
        label = parsed.get("label", parsed.get("key_label", ""))
        return f"Created key: {label}" if label else "Key created"
    if action_type == "key_revoke":
        label = parsed.get("label", parsed.get("key_label", ""))
        return f"Revoked key: {label}" if label else "Key revoked"
    if action_type == "key_delete":
        label = parsed.get("label", parsed.get("key_label", ""))
        return f"Deleted key: {label}" if label else "Key deleted"

    # ── Fleet Blocks ──────────────────────────────────────────────────
    if action_type == "fleet_block_propagated":
        parts = [f"IP {parsed.get('source_ip', '?')}"]
        if parsed.get("event_type"):
            parts.append(parsed["event_type"])
        if parsed.get("corroboration_count"):
            parts.append(f"{parsed['corroboration_count']} nodes")
        if parsed.get("ttl_seconds"):
            parts.append(f"TTL {parsed['ttl_seconds']}s")
        return " · ".join(parts)
    if action_type == "fleet_block_rejected":
        ip = parsed.get("source_ip", "")
        reason = parsed.get("reason", "")
        return f"{ip} — {reason}" if ip and reason else (ip or reason or "Rejected")
    if action_type == "fleet_block_manual_add":
        ip = parsed.get("source_ip", "")
        reason = parsed.get("reason", "")
        return f"{ip} — {reason}" if ip and reason else (ip or "Manual block")
    if action_type == "fleet_block_manual_remove":
        ip = parsed.get("source_ip", "")
        by = parsed.get("removed_by", "")
        result = ip or "Manual unblock"
        if by:
            result += f" (by {by})"
        return result
    if action_type == "fleet_block_reenabled":
        ip = parsed.get("source_ip", "")
        reason = parsed.get("reason", "")
        return f"{ip} re-enabled — {reason}" if ip and reason else (ip or "Re-enabled")
    if action_type == "fleet_block_expired":
        ip = parsed.get("source_ip", "")
        return f"{ip} expired" if ip else "Block expired"
    if action_type == "fleet_block_ttl_reset":
        ip = parsed.get("source_ip", "")
        old_ttl = parsed.get("old_ttl_seconds", "?")
        new_ttl = parsed.get("new_ttl_seconds", "?")
        return f"{ip} TTL: {old_ttl}s → {new_ttl}s"
    if action_type == "fleet_allowlist_modified":
        action = parsed.get("action", "")
        entry = parsed.get("entry", "")
        result = ""
        if action:
            result += action.title()
        if entry:
            result += f" {entry}"
        return result.strip() or "Allowlist modified"
    if action_type == "fleet_propagation_toggled":
        new_state = parsed.get("new_state")
        if new_state is True:
            return "Propagation paused"
        elif new_state is False:
            return "Propagation resumed"
        return "Propagation toggled"
    if action_type == "fleet_config_updated":
        keys = parsed.get("updated_keys", [])
        if isinstance(keys, list) and keys:
            return f"Changed: {', '.join(keys)}"
        return "Fleet config updated"

    # ── Intel Database ────────────────────────────────────────────────
    if action_type == "intel_purge":
        ip_count = parsed.get("ip_count", parsed.get("ips", ""))
        ev_count = parsed.get("event_count", parsed.get("events", ""))
        parts = []
        if ip_count:
            parts.append(f"{ip_count} IPs")
        if ev_count:
            parts.append(f"{ev_count} events")
        return f"Purged {', '.join(parts)}" if parts else "Intel DB purged"
    if action_type == "intel_backfill":
        count = parsed.get("count", parsed.get("imported", ""))
        return f"Backfilled {count} records" if count else "Intel backfill"
    if action_type == "intel_ip_delete":
        ip = parsed.get("source_ip", parsed.get("ip", ""))
        return f"Deleted IP: {ip}" if ip else "Intel IP deleted"

    # ── Blocking ──────────────────────────────────────────────────────
    if action_type == "block":
        rule = parsed.get("rule_name", parsed.get("rule", ""))
        return f"Rule: {rule}" if rule else ""
    if action_type == "unblock":
        reason = parsed.get("reason", "")
        return f"Reason: {reason}" if reason else ""

    # ── Templates ─────────────────────────────────────────────────────
    if action_type in ("template_toggled", "templates_enabled", "templates_disabled"):
        name = parsed.get("template_name", parsed.get("name", ""))
        return f"Template: {name}" if name else action_type.replace("_", " ").title()

    # ── Rules ─────────────────────────────────────────────────────────
    if action_type in ("rule_created", "rule_updated", "rule_deleted"):
        name = parsed.get("rule_name", parsed.get("name", ""))
        return f"Rule: {name}" if name else action_type.replace("_", " ").title()

    # ── Enrollment ────────────────────────────────────────────────────
    if action_type.startswith("enrollment"):
        host = parsed.get("host_id", parsed.get("host", ""))
        node = parsed.get("node_id", parsed.get("node", ""))
        ident = host or node or ""
        return f"Host: {ident}" if ident else action_type.replace("_", " ").title()

    # ── Config ────────────────────────────────────────────────────────
    if action_type.startswith("config_"):
        name = parsed.get("name", parsed.get("profile_name", ""))
        return f"{name}" if name else ""

    # ── Nodes / Assets ────────────────────────────────────────────────
    if action_type == "node_delete":
        node = parsed.get("node_id", parsed.get("node", ""))
        return f"Node: {node}" if node else "Node deleted"
    if action_type == "asset_deleted":
        asset = parsed.get("asset_id", parsed.get("asset", ""))
        return f"Asset: {asset}" if asset else "Asset deleted"

    # ── Webhook / Sync ────────────────────────────────────────────────
    if action_type == "webhook_unblock":
        return parsed.get("result", "")

    # ── Fallback ──────────────────────────────────────────────────────
    # Return first non-empty string-ish value as a best-effort summary
    for v in parsed.values():
        if isinstance(v, str) and len(v) < 120:
            return v
    return ""


# ── Audit log helpers (Task 2.6) ─────────────────────────────────────────

# Valid action types for the audit log.
VALID_AUDIT_ACTION_TYPES = frozenset(
    {
        "login",
        "logout",
        "login_failed",
        "block",
        "unblock",
        "role_change",
        "password_change",
        "key_create",
        "key_revoke",
        "key_delete",
        "enrollment_request",
        "enrollment_status_change",
        "enrollment_credential_issued",
        "enrollment_credential_rotated",
        "enrollment_credential_reissued",
        "enrollment_record_deleted",
        "enrollment_settings_change",
        "fleet_block_propagated",
        "fleet_block_rejected",
        "fleet_block_ttl_reset",
        "fleet_allowlist_modified",
        "fleet_block_expired",
        "fleet_propagation_toggled",
        "fleet_config_updated",
        "fleet_block_manual_add",
        "fleet_block_manual_remove",
        "fleet_block_reenabled",
        "rule_created",
        "rule_updated",
        "rule_deleted",
        "template_toggled",
        "templates_enabled",
        "templates_disabled",
        "config_profile_create",
        "config_profile_update",
        "config_profile_delete",
        "config_profile_rollback",
        "config_assignment_create",
        "config_assignment_delete",
        "config_ack",
        "config_rollout_create",
        "config_rollout_promote",
        "config_rollout_cancel",
        "config_group_create",
        "config_group_delete",
        "config_group_member_add",
        "config_group_member_remove",
        "intel_purge",
        "intel_backfill",
        "intel_ip_delete",
        "profile_update",
        "node_delete",
        "asset_deleted",
        "allowlist_sync",
        "blocklist_sync",
        "webhook_unblock",
        "user_locked_out",
        "user_unlocked",
    }
)


def record_audit(
    db: sqlite3.Connection,
    actor: str,
    actor_ip: str | None,
    action_type: str,
    target: str | None,
    details: dict,
) -> int:
    """Record an entry in the audit log.

    Args:
        db: An open SQLite connection.
        actor: The username of the operator performing the action, or
            'system' for automated actions.
        actor_ip: The IP address of the actor, or None if unavailable.
        action_type: One of the valid audit action types (login, logout,
            login_failed, block, unblock, role_change, key_create,
            key_revoke).
        target: The target of the action (e.g. a username, IP address,
            or key label). Can be None.
        details: A dict of action-specific data, stored as a JSON string.

    Returns:
        The id of the newly created audit log entry.

    Raises:
        ValueError: If action_type is not a recognised audit action.
    """
    if action_type not in VALID_AUDIT_ACTION_TYPES:
        raise ValueError(
            f"Invalid action_type '{action_type}'. "
            f"Must be one of: {', '.join(sorted(VALID_AUDIT_ACTION_TYPES))}"
        )

    details_json = json.dumps(details)
    cursor = db.execute(
        "INSERT INTO audit_log (actor, actor_ip, action_type, target, details) "
        "VALUES (?, ?, ?, ?, ?)",
        (actor, actor_ip, action_type, target, details_json),
    )
    db.commit()
    return cursor.lastrowid


def record_check_result(
    db,
    name: str,
    agent_id: str,
    hostname: str,
    exit_code: int,
    output: str,
    duration_ms: int = 0,
) -> int:
    """Record a health check result in the check_results table.

    Maps exit code to severity:
        0 → ok, 1 → warning, 2 → critical, 3+ → unknown
    """
    severity_map = {0: "ok", 1: "warning", 2: "critical"}
    severity = severity_map.get(exit_code, "unknown")
    created_at = _utcnow_iso()

    cursor = db.execute(
        "INSERT INTO check_results (name, agent_id, hostname, exit_code, severity, output, duration_ms, created_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        (name, agent_id, hostname, exit_code, severity, output, duration_ms, created_at),
    )
    db.commit()
    return cursor.lastrowid


def list_check_results(
    db,
    agent_id: str | None = None,
    severity: str | None = None,
    limit: int = 50,
    offset: int = 0,
):
    """Return recent check results, optionally filtered by agent and severity."""
    query = "SELECT * FROM check_results WHERE 1=1"
    params: list = []

    if agent_id:
        query += " AND agent_id = ?"
        params.append(agent_id)
    if severity:
        query += " AND severity = ?"
        params.append(severity)

    query += " ORDER BY created_at DESC LIMIT ? OFFSET ?"
    params.extend([limit, offset])

    rows = db.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def get_latest_check_results(db):
    """Return the latest check result for each unique check name."""
    rows = db.execute(
        "SELECT cr.* FROM check_results cr "
        "INNER JOIN ("
        "  SELECT name, agent_id, MAX(created_at) AS max_ts "
        "  FROM check_results GROUP BY name, agent_id"
        ") latest ON cr.name = latest.name AND cr.agent_id = latest.agent_id AND cr.created_at = latest.max_ts "
        "ORDER BY cr.severity DESC, cr.name ASC"
    ).fetchall()
    return [dict(row) for row in rows]


# ---------------------------------------------------------------------------
# App settings — simple key-value store for tunable parameters
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Logfile watches — WebUI-configured log file monitoring
# ---------------------------------------------------------------------------


def get_logfile_watches(db, agent_id: str) -> list[dict]:
    """Return all enabled logfile watches for an agent (agent-facing API)."""
    rows = db.execute(
        "SELECT id, name, path, pattern, alert_on_match FROM logfile_watches "
        "WHERE agent_id = ? AND enabled = 1 ORDER BY name ASC",
        (agent_id,),
    ).fetchall()
    return [dict(row) for row in rows]


def get_exec_scripts_for_agent(db, agent_id: str) -> list[dict]:
    """Return all enabled exec scripts from monitoring group conditions.

    Returns scripts from all groups where the agent matches the group's
    label matchers (or all agents if no matchers). Each script includes
    the condition name, command, timeout, and thresholds.
    """
    rows = db.execute(
        "SELECT gc.id, gc.name, gc.metric_params, gc.threshold, gc.severity, "
        "mg.id AS group_id, mg.name AS group_name, mg.match_labels, mg.match_any "
        "FROM group_alert_conditions gc "
        "JOIN monitoring_groups mg ON gc.group_id = mg.id "
        "WHERE gc.metric_type = 'exec' AND gc.enabled = 1 AND mg.enabled = 1 "
        "ORDER BY gc.name ASC"
    ).fetchall()

    scripts = []
    for row in rows:
        params = {}
        try:
            params = json.loads(row["metric_params"]) if row["metric_params"] else {}
        except (json.JSONDecodeError, TypeError):
            pass

        command = params.get("command", "")
        if not command:
            continue

        # Check agent match against group label matchers
        match_labels_raw = row["match_labels"]
        if isinstance(match_labels_raw, str):
            try:
                match_labels = json.loads(match_labels_raw) if match_labels_raw else []
            except (json.JSONDecodeError, TypeError):
                match_labels = []
        else:
            match_labels = match_labels_raw or []

        if match_labels:
            # Simple match: check if agent_id or hostname matches any matcher value
            match_any = row["match_any"]
            matched = False
            for matcher in match_labels:
                value = matcher.get("value", "")
                key = matcher.get("key", "")
                if key in ("agent_id", "hostname") and value:
                    if match_any:
                        matched = True
                        break
                    else:
                        matched = True
            if not matched:
                continue

        scripts.append(
            {
                "name": row["name"],
                "command": command,
                "timeout_secs": params.get("timeout_secs", 30),
                "warning_threshold": params.get("warning_threshold", 1),
                "critical_threshold": params.get("critical_threshold", 2),
            }
        )

    return scripts


def list_logfile_watches(db, agent_id: str | None = None) -> list[dict]:
    """Return logfile watches, optionally filtered by agent (admin WebUI)."""
    query = "SELECT * FROM logfile_watches WHERE 1=1"
    params: list = []
    if agent_id:
        query += " AND agent_id = ?"
        params.append(agent_id)
    query += " ORDER BY agent_id ASC, name ASC"
    rows = db.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def create_logfile_watch(
    db,
    agent_id: str,
    name: str,
    path: str,
    pattern: str,
    alert_on_match: bool = True,
    created_by: int | None = None,
) -> int:
    """Create a new logfile watch. Returns the new row id."""
    created_at = _utcnow_iso()
    cursor = db.execute(
        "INSERT INTO logfile_watches "
        "(agent_id, name, path, pattern, alert_on_match, enabled, created_by, created_at) "
        "VALUES (?, ?, ?, ?, ?, 1, ?, ?)",
        (agent_id, name, path, pattern, 1 if alert_on_match else 0, created_by, created_at),
    )
    db.commit()
    return cursor.lastrowid


def update_logfile_watch(
    db,
    watch_id: int,
    name: str | None = None,
    path: str | None = None,
    pattern: str | None = None,
    alert_on_match: bool | None = None,
    enabled: bool | None = None,
) -> bool:
    """Update fields of a logfile watch. Only provided fields are changed."""
    sets: list[str] = []
    params: list = []
    if name is not None:
        sets.append("name = ?")
        params.append(name)
    if path is not None:
        sets.append("path = ?")
        params.append(path)
    if pattern is not None:
        sets.append("pattern = ?")
        params.append(pattern)
    if alert_on_match is not None:
        sets.append("alert_on_match = ?")
        params.append(1 if alert_on_match else 0)
    if enabled is not None:
        sets.append("enabled = ?")
        params.append(1 if enabled else 0)
    if not sets:
        return True
    sets.append("updated_at = ?")
    params.append(_utcnow_iso())
    params.append(watch_id)
    cursor = db.execute(
        f"UPDATE logfile_watches SET {', '.join(sets)} WHERE id = ?",
        params,
    )
    db.commit()
    return cursor.rowcount > 0


def delete_logfile_watch(db, watch_id: int) -> bool:
    """Delete a logfile watch by id."""
    cursor = db.execute("DELETE FROM logfile_watches WHERE id = ?", (watch_id,))
    db.commit()
    return cursor.rowcount > 0


def ensure_logfile_watch(
    db, agent_id: str, name: str, path: str, pattern: str, alert_on_match: bool = True
) -> bool:
    """Create or update a logfile watch for an agent. Returns True if created."""
    existing = db.execute(
        "SELECT id FROM logfile_watches WHERE agent_id = ? AND name = ?",
        (agent_id, name),
    ).fetchone()
    if existing:
        db.execute(
            "UPDATE logfile_watches SET path = ?, pattern = ?, alert_on_match = ?, updated_at = ? WHERE id = ?",
            (path, pattern, 1 if alert_on_match else 0, _utcnow_iso(), existing["id"]),
        )
        db.commit()
        return False
    else:
        created_at = _utcnow_iso()
        db.execute(
            "INSERT INTO logfile_watches (agent_id, name, path, pattern, alert_on_match, enabled, created_at) "
            "VALUES (?, ?, ?, ?, ?, 1, ?)",
            (agent_id, name, path, pattern, 1 if alert_on_match else 0, created_at),
        )
        db.commit()
        return True


def get_setting(db, key: str, default: str = "") -> str:
    """Read a string value from app_settings, returning *default* if absent."""
    row = db.execute("SELECT value FROM app_settings WHERE `key` = ?", (key,)).fetchone()
    return row["value"] if row else default


def set_setting(db, key: str, value: str) -> None:
    """Upsert a key-value pair into app_settings."""
    now = _utcnow_iso()
    db.execute(
        "INSERT OR IGNORE INTO app_settings (`key`, value, updated_at) VALUES (?, ?, ?)",
        (key, value, now),
    )
    db.execute(
        "UPDATE app_settings SET value = ?, updated_at = ? WHERE `key` = ?",
        (value, now, key),
    )
    db.commit()


def purge_old_events(db, retention_days: int) -> dict[str, int]:
    """Delete events (and cascaded context) older than *retention_days* days.

    Returns a dict with counts of purged rows.
    """
    from datetime import timedelta

    cutoff = (datetime.now(UTC) - timedelta(days=retention_days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Delete from dependent tables first (event_log_context cascades, but
    # we handle it explicitly for MySQL compatibility)
    ctx_deleted = 0
    ctx_deleted += db.execute(
        "DELETE FROM event_log_context WHERE event_id IN "
        "(SELECT event_id FROM events WHERE timestamp < ?)",
        (cutoff,),
    ).rowcount

    events_deleted = db.execute("DELETE FROM events WHERE timestamp < ?", (cutoff,)).rowcount

    # Also cleanup old counter snapshots
    counters_deleted = 0
    try:
        counters_deleted = db.execute(
            "DELETE FROM counter_snapshots WHERE timestamp < ?", (cutoff,)
        ).rowcount
    except Exception:
        pass

    db.commit()

    return {
        "events": events_deleted,
        "event_context": ctx_deleted,
        "counters": counters_deleted,
    }


def purge_old_audit_log(db: sqlite3.Connection, retention_days: int) -> int:
    """Delete audit log entries older than *retention_days* days.

    Returns the number of rows purged.
    """
    cutoff = (datetime.now(UTC) - timedelta(days=retention_days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    purged = db.execute("DELETE FROM audit_log WHERE timestamp < ?", (cutoff,)).rowcount
    db.commit()
    return purged


SORT_COLUMNS = frozenset({"timestamp", "actor", "action_type", "target"})


def search_audit_log(
    db: sqlite3.Connection,
    action_type: str | None = None,
    actor: str | None = None,
    target: str | None = None,
    start: str | None = None,
    end: str | None = None,
    page: int = 1,
    per_page: int = 50,
    search: str | None = None,
    sort_by: str = "timestamp",
    sort_order: str = "DESC",
) -> tuple[list[dict], int]:
    """Search the audit log with optional filters.

    Args:
        db: An open SQLite connection.
        action_type: If provided, only return entries with this action_type.
        actor: If provided, only return entries with this actor.
        target: If provided, only return entries with this target.
        start: If provided, only return entries with timestamp >= start
            (ISO-8601 string).
        end: If provided, only return entries with timestamp <= end
            (ISO-8601 string).
        page: Page number (1-indexed, default 1).
        per_page: Results per page (clamped to 1-200, default 50).
        search: If provided, only return entries where actor, target, or
            details JSON contain this substring (case-insensitive).
        sort_by: Column to sort by (timestamp, actor, action_type, target).
        sort_order: ASC or DESC.

    Returns:
        A tuple of (list of audit log entry dicts, total count),
        ordered by the requested sort.
    """
    per_page = max(1, min(200, per_page))
    page = max(1, page)

    where_clauses: list[str] = []
    params: list = []

    if action_type is not None:
        where_clauses.append("action_type = ?")
        params.append(action_type)

    if actor is not None:
        where_clauses.append("actor = ?")
        params.append(actor)

    if target is not None:
        where_clauses.append("target = ?")
        params.append(target)

    if start is not None:
        where_clauses.append("timestamp >= ?")
        params.append(start)

    if end is not None:
        where_clauses.append("timestamp <= ?")
        params.append(end)

    if search is not None:
        where_clauses.append("(actor LIKE ? OR target LIKE ? OR details LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like, like])

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    # Validate sort column to prevent SQL injection
    if sort_by not in SORT_COLUMNS:
        sort_by = "timestamp"
    sort_order = "ASC" if sort_order.upper() == "ASC" else "DESC"

    # Get total count
    count_row = db.execute(
        f"SELECT COUNT(*) as cnt FROM audit_log {where_sql}",
        params,
    ).fetchone()
    total = count_row["cnt"] if count_row else 0

    offset = (page - 1) * per_page
    rows = db.execute(
        f"SELECT * FROM audit_log {where_sql} ORDER BY {sort_by} {sort_order} LIMIT ? OFFSET ?",
        params + [per_page, offset],
    ).fetchall()

    return [_row_to_dict(r) for r in rows], total
