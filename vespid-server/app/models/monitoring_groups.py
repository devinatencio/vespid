from __future__ import annotations

import json
import logging

from .alerts import get_notification_channels
from .db_core import _row_to_dict, _utcnow_iso

logger = logging.getLogger(__name__)

# ── Monitoring Groups CRUD ─────────────────────────────────────────────


def create_monitoring_group(
    db,
    name: str,
    description: str = "",
    match_labels: list | None = None,
    match_any: bool = False,
    enabled: bool = True,
) -> dict:
    """Create a monitoring group.

    Args:
        db: Database connection.
        name: Human-readable group name.
        description: Optional description.
        match_labels: JSON array of {key, op, value} matchers. Empty = match all agents.
        match_any: True = OR matchers, False = AND.
        enabled: Whether the group is active.

    Returns:
        The created group as a dict.
    """
    now = _utcnow_iso()
    match_labels_json = json.dumps(match_labels) if match_labels else "[]"
    cursor = db.execute(
        "INSERT INTO monitoring_groups (name, description, match_labels, match_any, enabled, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            name,
            description,
            match_labels_json,
            1 if match_any else 0,
            1 if enabled else 0,
            now,
            now,
        ),
    )
    db.commit()
    row = db.execute("SELECT * FROM monitoring_groups WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return _row_to_dict(row)


def list_monitoring_groups(db, enabled: bool | None = None) -> list[dict]:
    """List monitoring groups, optionally filtering by enabled state."""
    sql = "SELECT * FROM monitoring_groups"
    params: list = []
    if enabled is not None:
        sql += " WHERE enabled = ?"
        params.append(1 if enabled else 0)
    sql += " ORDER BY name ASC"
    rows = db.execute(sql, params).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_monitoring_group(db, group_id: int) -> dict | None:
    """Fetch a single monitoring group by ID, with condition count."""
    row = db.execute(
        "SELECT mg.*, "
        "  (SELECT COUNT(*) FROM group_alert_conditions gac WHERE gac.group_id = mg.id) as condition_count "
        "FROM monitoring_groups mg WHERE mg.id = ?",
        (group_id,),
    ).fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


def update_monitoring_group(db, group_id: int, **fields) -> dict | None:
    """Update a monitoring group. Only provided fields are changed.

    Returns:
        The updated group dict, or None if not found.
    """
    allowed = {"name", "description", "match_labels", "match_any", "enabled"}
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return get_monitoring_group(db, group_id)

    if "match_labels" in updates and isinstance(updates["match_labels"], list):
        updates["match_labels"] = json.dumps(updates["match_labels"])
    if "match_any" in updates:
        updates["match_any"] = 1 if updates["match_any"] else 0
    if "enabled" in updates:
        updates["enabled"] = 1 if updates["enabled"] else 0

    updates["updated_at"] = _utcnow_iso()
    set_clauses = [f"{k} = ?" for k in updates.keys()]
    params = list(updates.values()) + [group_id]

    db.execute(
        f"UPDATE monitoring_groups SET {', '.join(set_clauses)} WHERE id = ?",
        params,
    )
    db.commit()
    return get_monitoring_group(db, group_id)


def delete_monitoring_group(db, group_id: int) -> bool:
    """Delete a monitoring group and resolve any firing events.

    Returns:
        True if the group existed and was deleted.
    """
    row = db.execute("SELECT id FROM monitoring_groups WHERE id = ?", (group_id,)).fetchone()
    if row is None:
        return False

    now = _utcnow_iso()
    # Resolve any firing events from this group's conditions
    db.execute(
        "UPDATE alert_events SET state = 'resolved', resolved_at = ? "
        "WHERE group_condition_id IN (SELECT id FROM group_alert_conditions WHERE group_id = ?) "
        "AND state = 'firing'",
        (now, group_id),
    )
    # CASCADE will handle conditions, channels, and events
    db.execute("DELETE FROM monitoring_groups WHERE id = ?", (group_id,))
    db.commit()
    return True


# ── Group Alert Conditions CRUD ────────────────────────────────────────


def create_group_condition(
    db,
    group_id: int,
    name: str,
    metric_type: str,
    metric_params: dict | None = None,
    target_labels: list | None = None,
    operator: str = ">",
    threshold: float = 0.0,
    resolve_threshold: float | None = None,
    severity: str = "warning",
    for_duration: int = 0,
    cooldown_secs: int | None = None,
    interval_secs: int = 60,
    enabled: bool = True,
) -> dict:
    """Create a new alert condition for a monitoring group.

    Args:
        db: Database connection.
        group_id: The parent monitoring group ID.
        name: Human-readable condition name (e.g. "High CPU").
        metric_type: 'cpu', 'memory', 'disk', 'custom_promql', or 'check_name'.
        metric_params: JSON dict of type-specific params (e.g. {"mountpoint": "/"}).
        target_labels: Optional list of label matchers for agent targeting.
        operator: '>', '<', '>=', '<=', '=='.
        threshold: Value threshold for firing.
        resolve_threshold: Optional separate threshold for auto-resolve.
        severity: 'warning' or 'critical'.
        for_duration: Seconds condition must persist before firing.
        cooldown_secs: Min seconds after resolve before re-fire.
        interval_secs: Evaluation interval in seconds.
        enabled: Whether the condition is active.

    Returns:
        The created condition as a dict.
    """
    now = _utcnow_iso()
    params_json = json.dumps(metric_params) if metric_params else "{}"
    target_json = json.dumps(target_labels) if target_labels else None
    cursor = db.execute(
        "INSERT INTO group_alert_conditions "
        "(group_id, name, metric_type, metric_params, target_labels, operator, threshold, resolve_threshold, "
        "severity, for_duration, cooldown_secs, interval_secs, enabled, created_at, updated_at) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            group_id,
            name,
            metric_type,
            params_json,
            target_json,
            operator,
            threshold,
            resolve_threshold,
            severity,
            for_duration,
            cooldown_secs,
            interval_secs,
            1 if enabled else 0,
            now,
            now,
        ),
    )
    db.commit()
    row = db.execute(
        "SELECT * FROM group_alert_conditions WHERE id = ?", (cursor.lastrowid,)
    ).fetchone()
    return _row_to_dict(row)


def list_group_conditions(db, group_id: int) -> list[dict]:
    """List all alert conditions for a monitoring group."""
    rows = db.execute(
        "SELECT * FROM group_alert_conditions WHERE group_id = ? ORDER BY name ASC",
        (group_id,),
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_group_condition(db, condition_id: int) -> dict | None:
    """Fetch a single group alert condition by ID."""
    row = db.execute(
        "SELECT gac.*, mg.name as group_name "
        "FROM group_alert_conditions gac "
        "JOIN monitoring_groups mg ON gac.group_id = mg.id "
        "WHERE gac.id = ?",
        (condition_id,),
    ).fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


def update_group_condition(db, condition_id: int, **fields) -> dict | None:
    """Update a group alert condition. Only provided fields are changed.

    Returns:
        The updated condition dict, or None if not found.
    """
    allowed = {
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
    }
    updates = {k: v for k, v in fields.items() if k in allowed}
    if not updates:
        return get_group_condition(db, condition_id)

    if "metric_params" in updates and isinstance(updates["metric_params"], dict):
        updates["metric_params"] = json.dumps(updates["metric_params"])
    if "target_labels" in updates and isinstance(updates["target_labels"], list):
        updates["target_labels"] = json.dumps(updates["target_labels"])
    if "enabled" in updates:
        updates["enabled"] = 1 if updates["enabled"] else 0

    updates["updated_at"] = _utcnow_iso()
    set_clauses = [f"{k} = ?" for k in updates.keys()]
    params = list(updates.values()) + [condition_id]

    db.execute(
        f"UPDATE group_alert_conditions SET {', '.join(set_clauses)} WHERE id = ?",
        params,
    )
    db.commit()
    return get_group_condition(db, condition_id)


def delete_group_condition(db, condition_id: int) -> bool:
    """Delete a group alert condition and resolve any firing events.

    Returns:
        True if the condition existed and was deleted.
    """
    row = db.execute(
        "SELECT id FROM group_alert_conditions WHERE id = ?", (condition_id,)
    ).fetchone()
    if row is None:
        return False

    now = _utcnow_iso()
    # Resolve firing events for this condition
    db.execute(
        "UPDATE alert_events SET state = 'resolved', resolved_at = ? "
        "WHERE group_condition_id = ? AND state = 'firing'",
        (now, condition_id),
    )
    # CASCADE handles channels then condition
    db.execute("DELETE FROM group_alert_conditions WHERE id = ?", (condition_id,))
    db.commit()
    return True


# ── Group Condition-Channel associations ───────────────────────────────


def get_group_condition_channels(db, condition_id: int, default_to_all: bool = True) -> list[dict]:
    """Get notification channels linked to a group alert condition.

    If the condition has no explicit channel associations and default_to_all
    is True, returns all enabled channels.

    Args:
        db: Database connection.
        condition_id: The group alert condition ID.
        default_to_all: If True and no associations, return all enabled channels.

    Returns:
        List of channel dicts.
    """
    rows = db.execute(
        "SELECT nc.* FROM notification_channels nc "
        "JOIN group_condition_channels gcc ON nc.id = gcc.channel_id "
        "WHERE gcc.condition_id = ? AND nc.enabled = 1",
        (condition_id,),
    ).fetchall()
    if rows:
        return [_row_to_dict(r) for r in rows]
    if default_to_all:
        return get_notification_channels(db, enabled=True)
    return []


def set_group_condition_channels(db, condition_id: int, channel_ids: list[int]) -> None:
    """Replace the channel associations for a group alert condition.

    Args:
        db: Database connection.
        condition_id: The group alert condition ID.
        channel_ids: List of channel IDs to associate.
    """
    db.execute(
        "DELETE FROM group_condition_channels WHERE condition_id = ?",
        (condition_id,),
    )
    for cid in channel_ids:
        db.execute(
            "INSERT INTO group_condition_channels (condition_id, channel_id) VALUES (?, ?)",
            (condition_id, cid),
        )
    db.commit()


# ── Group Event Queries ────────────────────────────────────────────────


def get_active_group_event(
    db, condition_id: int, agent_id: str, mountpoint: str | None = None
) -> dict | None:
    """Get the currently firing or acknowledged event for a group condition + agent combination.

    Args:
        condition_id: The group alert condition ID.
        agent_id: The agent ID to match.
        mountpoint: Optional mountpoint path (for disk conditions).

    Returns:
        The matching event dict, or None.
    """
    import json

    rows = db.execute(
        "SELECT * FROM alert_events "
        "WHERE group_condition_id = ? AND state IN ('firing', 'acknowledged') "
        "ORDER BY fired_at DESC",
        (condition_id,),
    ).fetchall()
    for row in rows:
        d = _row_to_dict(row)
        labels = json.loads(d.get("labels", "{}"))
        if labels.get("agent_id") == agent_id:
            if mountpoint is None or labels.get("mountpoint") == mountpoint:
                return d
    return None


def get_latest_resolved_group_event(
    db, condition_id: int, agent_id: str, mountpoint: str | None = None
) -> dict | None:
    """Get the most recent resolved event for a group condition + agent combination.

    Used for cooldown checking.

    Args:
        condition_id: The group alert condition ID.
        agent_id: The agent ID to match.
        mountpoint: Optional mountpoint path (for disk conditions).
    """
    import json

    rows = db.execute(
        "SELECT * FROM alert_events "
        "WHERE group_condition_id = ? AND state = 'resolved' "
        "ORDER BY resolved_at DESC",
        (condition_id,),
    ).fetchall()
    for row in rows:
        d = _row_to_dict(row)
        labels = json.loads(d.get("labels", "{}"))
        if labels.get("agent_id") == agent_id:
            if mountpoint is None or labels.get("mountpoint") == mountpoint:
                return d
    return None


def get_active_group_events(db, group_id: int | None = None) -> list[dict]:
    """Get all currently firing group-condition events.

    Args:
        db: Database connection.
        group_id: Optional, filter to a specific group.

    Returns:
        List of active event dicts with condition and group info.
    """
    sql = (
        "SELECT ae.*, gac.name as condition_name, gac.severity as condition_severity, "
        "  gac.metric_type, gac.group_id, mg.name as group_name "
        "FROM alert_events ae "
        "JOIN group_alert_conditions gac ON ae.group_condition_id = gac.id "
        "JOIN monitoring_groups mg ON gac.group_id = mg.id "
        "WHERE ae.state = 'firing'"
    )
    params: list = []
    if group_id is not None:
        sql += " AND gac.group_id = ?"
        params.append(group_id)
    sql += " ORDER BY ae.fired_at DESC"
    rows = db.execute(sql, params).fetchall()
    return [_row_to_dict(r) for r in rows]


def update_condition_last_eval(db, condition_id: int) -> None:
    """Update the last_eval_at timestamp for a group alert condition."""
    now = _utcnow_iso()
    db.execute(
        "UPDATE group_alert_conditions SET last_eval_at = ? WHERE id = ?",
        (now, condition_id),
    )
    db.commit()


def seed_default_monitoring_group(db) -> bool:
    """Create a default 'Linux Servers' monitoring group with standard checks
    if no monitoring groups exist yet.

    Returns:
        True if the group was created, False if it already existed.
    """
    rows = db.execute("SELECT COUNT(*) as cnt FROM monitoring_groups").fetchone()
    if rows and rows["cnt"] > 0:
        return False

    group = create_monitoring_group(
        db,
        name="Linux Servers",
        description="Default group — all Linux servers with standard metric checks.",
        match_labels=[],
        match_any=False,
        enabled=True,
    )
    gid = group["id"]

    # High CPU (>90% for 5 min)
    create_group_condition(
        db,
        gid,
        "High CPU",
        "cpu",
        metric_params={},
        operator=">",
        threshold=90.0,
        resolve_threshold=85.0,
        severity="critical",
        for_duration=300,
        cooldown_secs=600,
        interval_secs=60,
        enabled=True,
    )

    # High Memory (>90% for 5 min)
    create_group_condition(
        db,
        gid,
        "High Memory",
        "memory",
        metric_params={},
        operator=">",
        threshold=90.0,
        resolve_threshold=85.0,
        severity="critical",
        for_duration=300,
        cooldown_secs=600,
        interval_secs=60,
        enabled=True,
    )

    # High Disk Usage (>90% for 10 min, auto-discovers all mountpoints)
    create_group_condition(
        db,
        gid,
        "High Disk Usage",
        "disk",
        metric_params={},
        operator=">",
        threshold=90.0,
        resolve_threshold=85.0,
        severity="critical",
        for_duration=600,
        cooldown_secs=600,
        interval_secs=60,
        enabled=True,
    )

    # Zombie Processes (>0 for 5 min) — disabled by default (requires /proc/*/status)
    create_group_condition(
        db,
        gid,
        "Zombie Processes",
        "custom_promql",
        metric_params={
            "query": 'sum by (agent_id) (vespid_monitor_process_zombies_count{agent_id=~"{{agent_ids_regex}}"})'
        },
        operator=">",
        threshold=0,
        severity="warning",
        for_duration=300,
        cooldown_secs=300,
        interval_secs=60,
        enabled=False,
    )

    # High CPU Pressure (>50% for 5 min) — disabled by default (requires CONFIG_PSI)
    create_group_condition(
        db,
        gid,
        "High CPU Pressure",
        "custom_promql",
        metric_params={
            "query": 'vespid_monitor_psi_avg10{agent_id=~"{{agent_ids_regex}}",resource="cpu",level="some"}'
        },
        operator=">",
        threshold=50.0,
        severity="warning",
        for_duration=300,
        cooldown_secs=600,
        interval_secs=60,
        enabled=False,
    )

    # High IO Pressure (>50% for 5 min) — disabled by default (requires CONFIG_PSI)
    create_group_condition(
        db,
        gid,
        "High IO Pressure",
        "custom_promql",
        metric_params={
            "query": 'vespid_monitor_psi_avg10{agent_id=~"{{agent_ids_regex}}",resource="io",level="some"}'
        },
        operator=">",
        threshold=50.0,
        severity="warning",
        for_duration=300,
        cooldown_secs=600,
        interval_secs=60,
        enabled=False,
    )

    # High Memory Pressure (>20% for 5 min) — disabled by default (requires CONFIG_PSI)
    create_group_condition(
        db,
        gid,
        "High Memory Pressure",
        "custom_promql",
        metric_params={
            "query": 'vespid_monitor_psi_avg10{agent_id=~"{{agent_ids_regex}}",resource="memory",level="some"}'
        },
        operator=">",
        threshold=20.0,
        severity="critical",
        for_duration=300,
        cooldown_secs=600,
        interval_secs=60,
        enabled=False,
    )

    # High Load Average 5min (>4 for 5 min)
    create_group_condition(
        db,
        gid,
        "High Load Average (5min)",
        "custom_promql",
        metric_params={"query": 'vespid_monitor_loadavg_5min{agent_id=~"{{agent_ids_regex}}"}'},
        operator=">",
        threshold=4.0,
        severity="warning",
        for_duration=300,
        cooldown_secs=600,
        interval_secs=60,
        enabled=True,
    )

    # ── Disabled-by-default conditions ────────────────────────────────

    # High Process Count (>1000 for 5 min)
    create_group_condition(
        db,
        gid,
        "High Process Count",
        "custom_promql",
        metric_params={
            "query": 'vespid_monitor_process_count_total{agent_id=~"{{agent_ids_regex}}"}'
        },
        operator=">",
        threshold=1000.0,
        severity="warning",
        for_duration=300,
        cooldown_secs=600,
        interval_secs=60,
        enabled=False,
    )

    # High Running Processes (>20 for 5 min)
    create_group_condition(
        db,
        gid,
        "High Running Processes",
        "custom_promql",
        metric_params={"query": 'vespid_monitor_process_running{agent_id=~"{{agent_ids_regex}}"}'},
        operator=">",
        threshold=20.0,
        severity="warning",
        for_duration=300,
        cooldown_secs=600,
        interval_secs=60,
        enabled=False,
    )

    # High Swap Usage (>50% for 5 min)
    create_group_condition(
        db,
        gid,
        "High Swap Usage",
        "custom_promql",
        metric_params={
            "query": 'vespid_monitor_memory_swap_used_percent{agent_id=~"{{agent_ids_regex}}"}'
        },
        operator=">",
        threshold=50.0,
        severity="critical",
        for_duration=300,
        cooldown_secs=600,
        interval_secs=60,
        enabled=True,
    )

    # Network Errors (>0 for 5 min)
    create_group_condition(
        db,
        gid,
        "Network Errors",
        "custom_promql",
        metric_params={
            "query": 'sum by (agent_id) (rate(vespid_monitor_network_errors_sent_total{agent_id=~"{{agent_ids_regex}}"}[5m]))'
        },
        operator=">",
        threshold=0.0,
        severity="warning",
        for_duration=300,
        cooldown_secs=600,
        interval_secs=60,
        enabled=False,
    )

    db.commit()
    return True


# ── Monitoring Group Status ──────────────────────────────────────────


def upsert_group_status(
    db,
    group_id: int,
    condition_id: int,
    agent_id: str,
    hostname: str,
    status: str,
    last_value: float | None = None,
    last_metric_value: float | None = None,
    last_detail: str | None = None,
) -> dict:
    """Upsert a per-agent per-condition monitoring status row.

    Args:
        last_detail: Optional JSON string with per-mountpoint or sub-check
            breakdown (e.g. '{\"/\": 8.2, \"/data\": 95.1}').
    """
    now = _utcnow_iso()
    existing = db.execute(
        "SELECT * FROM monitoring_group_status "
        "WHERE group_id = ? AND condition_id = ? AND agent_id = ?",
        (group_id, condition_id, agent_id),
    ).fetchone()

    if existing:
        if last_detail is not None:
            db.execute(
                "UPDATE monitoring_group_status SET status = ?, last_value = ?, "
                "last_metric_value = ?, last_detail = ?, last_evaluated_at = ?, "
                "updated_at = ?, hostname = ? "
                "WHERE group_id = ? AND condition_id = ? AND agent_id = ?",
                (
                    status,
                    last_value,
                    last_metric_value,
                    last_detail,
                    now,
                    now,
                    hostname,
                    group_id,
                    condition_id,
                    agent_id,
                ),
            )
        else:
            db.execute(
                "UPDATE monitoring_group_status SET status = ?, last_value = ?, "
                "last_metric_value = ?, last_evaluated_at = ?, updated_at = ?, hostname = ? "
                "WHERE group_id = ? AND condition_id = ? AND agent_id = ?",
                (
                    status,
                    last_value,
                    last_metric_value,
                    now,
                    now,
                    hostname,
                    group_id,
                    condition_id,
                    agent_id,
                ),
            )
    else:
        detail = last_detail if last_detail is not None else "{}"
        db.execute(
            "INSERT INTO monitoring_group_status "
            "(group_id, condition_id, agent_id, hostname, status, last_value, "
            " last_metric_value, last_detail, last_evaluated_at, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                group_id,
                condition_id,
                agent_id,
                hostname,
                status,
                last_value,
                last_metric_value,
                detail,
                now,
                now,
                now,
            ),
        )
    db.commit()
    return _row_to_dict(
        db.execute(
            "SELECT * FROM monitoring_group_status "
            "WHERE group_id = ? AND condition_id = ? AND agent_id = ?",
            (group_id, condition_id, agent_id),
        ).fetchone()
    )


def get_group_statuses(db, group_id: int) -> list[dict]:
    """Return all status rows for a group, joined with condition info.

    Returns:
        List of dicts: {agent_id, hostname, condition_id, condition_name,
        metric_type, status, last_value, last_metric_value, last_evaluated_at,
        threshold, operator, severity}
    """
    rows = db.execute(
        "SELECT mgs.*, gac.name AS condition_name, gac.metric_type, "
        "  gac.threshold, gac.operator, gac.severity "
        "FROM monitoring_group_status mgs "
        "JOIN group_alert_conditions gac ON mgs.condition_id = gac.id "
        "WHERE mgs.group_id = ? "
        "ORDER BY mgs.hostname, mgs.agent_id",
        (group_id,),
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_agent_checks(db, agent_id: str) -> list[dict]:
    """Return all monitoring status rows for an agent across all groups.

    Returns:
        List of dicts: {agent_id, hostname, status, last_value,
        last_metric_value, last_evaluated_at, condition_name, condition_id,
        metric_type, threshold, operator, severity, group_id, group_name}
    """
    rows = db.execute(
        "SELECT mgs.*, gac.name AS condition_name, gac.metric_type, "
        "  gac.threshold, gac.operator, gac.severity, "
        "  mg.name AS group_name "
        "FROM monitoring_group_status mgs "
        "JOIN group_alert_conditions gac ON mgs.condition_id = gac.id "
        "JOIN monitoring_groups mg ON mgs.group_id = mg.id "
        "WHERE mgs.agent_id = ? "
        "ORDER BY mg.name, gac.name",
        (agent_id,),
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


def prune_group_statuses(db, group_id: int, active_agent_ids: set[str]) -> int:
    """Remove status rows for agents no longer matching the group.

    Also removes any status rows with empty hostnames — these are
    stale entries from PromQL queries that aggregate away the hostname
    label (e.g. sum by (agent_id, ...)).

    Args:
        db: Database connection.
        group_id: The monitoring group id.
        active_agent_ids: Set of agent_ids that currently match the group.

    Returns:
        Number of rows deleted.
    """
    total = 0
    if active_agent_ids:
        placeholders = ",".join("?" for _ in active_agent_ids)
        deleted = db.execute(
            f"DELETE FROM monitoring_group_status "
            f"WHERE group_id = ? AND agent_id NOT IN ({placeholders})",
            (group_id, *active_agent_ids),
        ).rowcount
        total += deleted
    deleted2 = db.execute(
        "DELETE FROM monitoring_group_status "
        "WHERE group_id = ? AND (hostname IS NULL OR hostname = '')",
        (group_id,),
    ).rowcount
    total += deleted2
    if total > 0:
        db.commit()
    return total


def get_group_status_matrix(db, group_id: int) -> dict:
    """Build a Nagios-style matrix for a group.

    Returns:
        Dict with:
          - conditions: list of {id, name, metric_type, threshold, operator, severity}
          - rows: list of {agent_id, hostname,
                   cells: [{condition_id, status, last_value, last_metric_value,
                            last_evaluated_at}]}
    """
    statuses = get_group_statuses(db, group_id)

    cond_map: dict[int, dict] = {}
    agent_map: dict[str, dict] = {}
    for s in statuses:
        cid = s["condition_id"]
        if cid not in cond_map:
            cond_map[cid] = {
                "id": cid,
                "name": s["condition_name"],
                "metric_type": s["metric_type"],
                "threshold": s["threshold"],
                "operator": s["operator"],
                "severity": s["severity"],
            }
        aid = s["agent_id"]
        if aid not in agent_map:
            agent_map[aid] = {
                "agent_id": aid,
                "hostname": s["hostname"],
                "cells": {},
            }
        agent_map[aid]["cells"][str(cid)] = {
            "condition_id": cid,
            "status": s["status"],
            "last_value": s["last_value"],
            "last_metric_value": s["last_metric_value"],
            "last_evaluated_at": s["last_evaluated_at"],
        }

    from app.alert_manager import resolve_agents

    group = db.execute("SELECT * FROM monitoring_groups WHERE id = ?", (group_id,)).fetchone()
    if group:
        g_dict = _row_to_dict(group)
        try:
            g_dict["match_labels"] = json.loads(g_dict.get("match_labels", "[]"))
        except (json.JSONDecodeError, TypeError):
            g_dict["match_labels"] = []
        raw_agents = resolve_agents(g_dict)
        for a in raw_agents:
            aid = a["agent_id"]
            if aid not in agent_map:
                agent_map[aid] = {
                    "agent_id": aid,
                    "hostname": a.get("hostname", ""),
                    "cells": {},
                }
            for cid in cond_map:
                cid_str = str(cid)
                if cid_str not in agent_map[aid]["cells"]:
                    agent_map[aid]["cells"][cid_str] = {
                        "condition_id": cid,
                        "status": "unknown",
                        "last_value": None,
                        "last_metric_value": None,
                        "last_evaluated_at": None,
                    }

    sorted_agents = sorted(agent_map.values(), key=lambda x: (x["hostname"] or "", x["agent_id"]))
    sorted_conditions = sorted(cond_map.values(), key=lambda x: x["name"])

    return {
        "conditions": sorted_conditions,
        "rows": sorted_agents,
    }


def set_debounce_started_at(
    db, group_id: int, condition_id: int, agent_id: str, started_at: str | None
) -> None:
    """Set or clear the debounce_started_at timestamp for a status row."""
    db.execute(
        "UPDATE monitoring_group_status SET debounce_started_at = ? "
        "WHERE group_id = ? AND condition_id = ? AND agent_id = ?",
        (started_at, group_id, condition_id, agent_id),
    )
    db.commit()


def get_all_hosts_status(db) -> list[dict]:
    """Return a per-host summary across all monitoring groups.

    Each host gets one row with summary counts and the group names
    it belongs to.  Only hosts that have been evaluated at least once
    (i.e. have rows in monitoring_group_status) are included.

    Returns:
        List of dicts:
          {agent_id, hostname, groups (comma-separated), total, ok_count,
           warning_count, critical_count, pending_count, unknown_count,
           last_evaluated_at}
    """
    rows = db.execute(
        "SELECT mgs.agent_id, mgs.hostname, "
        "  COUNT(*) AS total, "
        "  SUM(CASE WHEN mgs.status = 'ok' THEN 1 ELSE 0 END) AS ok_count, "
        "  SUM(CASE WHEN mgs.status = 'warning' THEN 1 ELSE 0 END) AS warning_count, "
        "  SUM(CASE WHEN mgs.status = 'critical' THEN 1 ELSE 0 END) AS critical_count, "
        "  SUM(CASE WHEN mgs.status = 'pending' THEN 1 ELSE 0 END) AS pending_count, "
        "  SUM(CASE WHEN mgs.status NOT IN ('ok','warning','critical','pending') THEN 1 ELSE 0 END) AS unknown_count, "
        "  MAX(mgs.last_evaluated_at) AS last_evaluated_at, "
        "  GROUP_CONCAT(DISTINCT mg.name ORDER BY mg.name SEPARATOR ', ') AS groups "
        "FROM monitoring_group_status mgs "
        "JOIN monitoring_groups mg ON mgs.group_id = mg.id "
        "GROUP BY mgs.agent_id, mgs.hostname "
        "ORDER BY mgs.hostname, mgs.agent_id",
    ).fetchall()
    return [_row_to_dict(r) for r in rows]
