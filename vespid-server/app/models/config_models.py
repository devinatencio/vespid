from __future__ import annotations

import json
import logging
import sqlite3

from .db_core import _row_to_dict, _utcnow_iso

logger = logging.getLogger(__name__)

# ── Configuration Profile query helpers (Task 1.2) ──────────────────────


def create_config_profile(
    db: sqlite3.Connection,
    name: str,
    settings: dict,
    created_by: str,
    description: str = "",
) -> dict:
    """Create a new configuration profile.

    Stores the profile with version=1, is_active=True, and name_lower set
    to the lowercase version of the name for case-insensitive uniqueness.

    Args:
        db: An open SQLite connection.
        name: The profile name (max 128 chars, unique case-insensitively).
        settings: A JSON-serializable dict of configuration settings.
        created_by: The username of the creator.
        description: Optional description (max 512 chars).

    Returns:
        The created profile record as a dict.
    """
    settings_json = json.dumps(settings)
    cursor = db.execute(
        "INSERT INTO config_profiles (name, name_lower, description, version, settings, created_by, is_active) "
        "VALUES (?, ?, ?, 1, ?, ?, 1)",
        (name, name.lower(), description, settings_json, created_by),
    )
    db.commit()
    row = db.execute("SELECT * FROM config_profiles WHERE id = ?", (cursor.lastrowid,)).fetchone()
    return _row_to_dict(row)


def get_config_profile(
    db: sqlite3.Connection,
    profile_id: int,
) -> dict | None:
    """Return an active configuration profile by ID.

    Args:
        db: An open SQLite connection.
        profile_id: The profile's primary key id.

    Returns:
        A dict with profile fields, or None if not found or inactive.
    """
    row = db.execute(
        "SELECT * FROM config_profiles WHERE id = ? AND is_active = 1",
        (profile_id,),
    ).fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


def list_config_profiles(
    db: sqlite3.Connection,
    page: int = 1,
    per_page: int = 50,
) -> dict:
    """Return a paginated list of active configuration profiles.

    Profiles are ordered by created_at descending (newest first).

    Args:
        db: An open SQLite connection.
        page: Page number (1-based).
        per_page: Number of results per page (clamped to 1-200).

    Returns:
        A dict with keys: profiles, total, page, per_page.
    """
    per_page = max(1, min(200, per_page))
    offset = (page - 1) * per_page

    total = db.execute("SELECT COUNT(*) FROM config_profiles WHERE is_active = 1").fetchone()[0]

    rows = db.execute(
        "SELECT * FROM config_profiles WHERE is_active = 1 "
        "ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (per_page, offset),
    ).fetchall()

    return {
        "profiles": [_row_to_dict(r) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
    }


def update_config_profile(
    db: sqlite3.Connection,
    profile_id: int,
    name: str | None = None,
    description: str | None = None,
    settings: dict | None = None,
    changed_by: str = "",
    change_reason: str = "",
) -> dict | None:
    """Update a configuration profile, incrementing its version.

    Only provided fields are updated. A version history record is stored
    with the previous and new settings.

    Args:
        db: An open SQLite connection.
        profile_id: The profile's primary key id.
        name: New name (optional).
        description: New description (optional).
        settings: New settings dict (optional).
        changed_by: Username of the person making the change.
        change_reason: Reason for the change.

    Returns:
        The updated profile as a dict, or None if not found/inactive.
    """
    profile = get_config_profile(db, profile_id)
    if profile is None:
        return None

    previous_settings = profile["settings"]
    new_version = profile["version"] + 1

    # Build SET clause dynamically
    updates = []
    params = []

    if name is not None:
        updates.append("name = ?")
        params.append(name)
        updates.append("name_lower = ?")
        params.append(name.lower())

    if description is not None:
        updates.append("description = ?")
        params.append(description)

    if settings is not None:
        updates.append("settings = ?")
        params.append(json.dumps(settings))

    updates.append("version = ?")
    params.append(new_version)
    updates.append("updated_at = ?")
    params.append(_utcnow_iso())

    params.append(profile_id)

    db.execute(
        f"UPDATE config_profiles SET {', '.join(updates)} WHERE id = ?",
        params,
    )

    # Determine new_settings for history record
    new_settings_value = settings if settings is not None else previous_settings
    # If previous_settings is a string (JSON), keep it as-is for the history
    if isinstance(previous_settings, str):
        prev_json = previous_settings
    else:
        prev_json = json.dumps(previous_settings)

    if isinstance(new_settings_value, str):
        new_json = new_settings_value
    else:
        new_json = json.dumps(new_settings_value)

    # Store version history record
    create_version_history(
        db,
        profile_id=profile_id,
        version=new_version,
        previous_settings=prev_json,
        new_settings=new_json,
        changed_by=changed_by,
        change_reason=change_reason,
    )

    db.commit()

    # Return the updated profile
    return get_config_profile(db, profile_id)


def soft_delete_config_profile(
    db: sqlite3.Connection,
    profile_id: int,
) -> bool:
    """Soft-delete a configuration profile by setting is_active=0.

    Args:
        db: An open SQLite connection.
        profile_id: The profile's primary key id.

    Returns:
        True if the profile was found and deleted, False otherwise.
    """
    row = db.execute(
        "SELECT id FROM config_profiles WHERE id = ? AND is_active = 1",
        (profile_id,),
    ).fetchone()
    if row is None:
        return False

    db.execute(
        "UPDATE config_profiles SET is_active = 0, updated_at = ? WHERE id = ?",
        (_utcnow_iso(), profile_id),
    )
    db.commit()
    return True


# ── Configuration Version History query helpers ─────────────────────────


def create_version_history(
    db: sqlite3.Connection,
    profile_id: int,
    version: int,
    previous_settings: str,
    new_settings: str,
    changed_by: str,
    change_reason: str,
) -> int:
    """Insert a version history record for a configuration profile.

    Args:
        db: An open SQLite connection.
        profile_id: The profile's primary key id.
        version: The new version number.
        previous_settings: JSON string of the previous settings.
        new_settings: JSON string of the new settings.
        changed_by: Username of the person who made the change.
        change_reason: Reason for the change.

    Returns:
        The row id of the inserted history record.
    """
    cursor = db.execute(
        "INSERT INTO config_version_history "
        "(profile_id, version, previous_settings, new_settings, changed_by, change_reason) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (profile_id, version, previous_settings, new_settings, changed_by, change_reason),
    )
    db.commit()
    return cursor.lastrowid


def list_version_history(
    db: sqlite3.Connection,
    profile_id: int,
    page: int = 1,
    per_page: int = 50,
) -> dict:
    """Return paginated version history for a configuration profile.

    History is ordered by version descending (newest first).

    Args:
        db: An open SQLite connection.
        profile_id: The profile's primary key id.
        page: Page number (1-based).
        per_page: Number of results per page (clamped to 1-200).

    Returns:
        A dict with keys: history, total, page, per_page.
    """
    per_page = max(1, min(200, per_page))
    offset = (page - 1) * per_page

    total = db.execute(
        "SELECT COUNT(*) FROM config_version_history WHERE profile_id = ?",
        (profile_id,),
    ).fetchone()[0]

    rows = db.execute(
        "SELECT * FROM config_version_history WHERE profile_id = ? "
        "ORDER BY version DESC LIMIT ? OFFSET ?",
        (profile_id, per_page, offset),
    ).fetchall()

    return {
        "history": [_row_to_dict(r) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
    }


def get_version_settings(
    db: sqlite3.Connection,
    profile_id: int,
    version: int,
) -> dict | None:
    """Return the new_settings for a specific version of a profile.

    Args:
        db: An open SQLite connection.
        profile_id: The profile's primary key id.
        version: The version number to look up.

    Returns:
        A dict of the settings for that version, or None if not found.
    """
    row = db.execute(
        "SELECT new_settings FROM config_version_history WHERE profile_id = ? AND version = ?",
        (profile_id, version),
    ).fetchone()
    if row is None:
        return None
    settings_str = row["new_settings"]
    if isinstance(settings_str, str):
        return json.loads(settings_str)
    return settings_str


# ── Config assignment helpers ────────────────────────────────────────────


def create_assignment(
    db: sqlite3.Connection,
    profile_id: int,
    assigned_by: str,
    node_id: str | None = None,
    group_id: int | None = None,
) -> dict:
    """Create a profile assignment record.

    If node_id is provided, deactivates any previous active direct assignment
    for that node before creating the new one (ensuring at most one active
    direct assignment per agent).

    Args:
        db: An open SQLite connection.
        profile_id: The configuration profile to assign.
        assigned_by: Username of the admin performing the assignment.
        node_id: Target node identifier (for direct assignments).
        group_id: Target group identifier (for group assignments).

    Returns:
        The created assignment record as a dict.
    """
    # Deactivate previous active direct assignment for this node
    if node_id is not None:
        db.execute(
            "UPDATE config_assignments SET is_active = 0 WHERE node_id = ? AND is_active = 1",
            (node_id,),
        )

    cursor = db.execute(
        "INSERT INTO config_assignments (node_id, group_id, profile_id, assigned_by) "
        "VALUES (?, ?, ?, ?)",
        (node_id, group_id, profile_id, assigned_by),
    )
    db.commit()

    row = db.execute(
        "SELECT * FROM config_assignments WHERE id = ?",
        (cursor.lastrowid,),
    ).fetchone()
    return _row_to_dict(row)


def deactivate_assignment(
    db: sqlite3.Connection,
    assignment_id: int,
) -> bool:
    """Deactivate a profile assignment.

    Args:
        db: An open SQLite connection.
        assignment_id: The assignment record to deactivate.

    Returns:
        True if the assignment was found and deactivated, False otherwise.
    """
    row = db.execute(
        "SELECT id FROM config_assignments WHERE id = ? AND is_active = 1",
        (assignment_id,),
    ).fetchone()
    if row is None:
        return False

    db.execute(
        "UPDATE config_assignments SET is_active = 0 WHERE id = ?",
        (assignment_id,),
    )
    db.commit()
    return True


def list_assignments_for_profile(
    db: sqlite3.Connection,
    profile_id: int,
    page: int = 1,
    per_page: int = 50,
) -> dict:
    """List active assignments for a profile with pagination.

    Args:
        db: An open SQLite connection.
        profile_id: The profile to list assignments for.
        page: 1-indexed page number.
        per_page: Number of results per page (clamped to 1–200).

    Returns:
        A dict with keys: assignments, total, page, per_page.
    """
    per_page = max(1, min(200, per_page))
    offset = (page - 1) * per_page

    total = db.execute(
        "SELECT COUNT(*) FROM config_assignments WHERE profile_id = ? AND is_active = 1",
        (profile_id,),
    ).fetchone()[0]

    rows = db.execute(
        "SELECT * FROM config_assignments "
        "WHERE profile_id = ? AND is_active = 1 "
        "ORDER BY assigned_at DESC "
        "LIMIT ? OFFSET ?",
        (profile_id, per_page, offset),
    ).fetchall()

    return {
        "assignments": [_row_to_dict(r) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
    }


# ── Agent group helpers ──────────────────────────────────────────────────


def create_agent_group(
    db: sqlite3.Connection,
    name: str,
    created_by: str,
    description: str = "",
) -> dict:
    """Create an agent group.

    Args:
        db: An open SQLite connection.
        name: Unique group name.
        created_by: Username of the admin creating the group.
        description: Optional group description.

    Returns:
        The created group record as a dict.
    """
    cursor = db.execute(
        "INSERT INTO agent_groups (name, description, created_by) VALUES (?, ?, ?)",
        (name, description, created_by),
    )
    db.commit()

    row = db.execute(
        "SELECT * FROM agent_groups WHERE id = ?",
        (cursor.lastrowid,),
    ).fetchone()
    return _row_to_dict(row)


def list_agent_groups(
    db: sqlite3.Connection,
    page: int = 1,
    per_page: int = 50,
) -> dict:
    """List agent groups with pagination.

    Args:
        db: An open SQLite connection.
        page: 1-indexed page number.
        per_page: Number of results per page (clamped to 1–200).

    Returns:
        A dict with keys: groups, total, page, per_page.
    """
    per_page = max(1, min(200, per_page))
    offset = (page - 1) * per_page

    total = db.execute("SELECT COUNT(*) FROM agent_groups").fetchone()[0]

    rows = db.execute(
        "SELECT * FROM agent_groups ORDER BY created_at DESC LIMIT ? OFFSET ?",
        (per_page, offset),
    ).fetchall()

    return {
        "groups": [_row_to_dict(r) for r in rows],
        "total": total,
        "page": page,
        "per_page": per_page,
    }


def delete_agent_group(
    db: sqlite3.Connection,
    group_id: int,
) -> bool:
    """Delete an agent group with cascade.

    Removes all memberships and deactivates all assignments for this group
    before deleting the group record.

    Args:
        db: An open SQLite connection.
        group_id: The group to delete.

    Returns:
        True if the group was found and deleted, False otherwise.
    """
    row = db.execute(
        "SELECT id FROM agent_groups WHERE id = ?",
        (group_id,),
    ).fetchone()
    if row is None:
        return False

    # Deactivate all assignments targeting this group
    db.execute(
        "UPDATE config_assignments SET is_active = 0 WHERE group_id = ? AND is_active = 1",
        (group_id,),
    )

    # Remove all group memberships
    db.execute(
        "DELETE FROM agent_group_members WHERE group_id = ?",
        (group_id,),
    )

    # Delete the group itself
    db.execute("DELETE FROM agent_groups WHERE id = ?", (group_id,))
    db.commit()
    return True


def add_group_member(
    db: sqlite3.Connection,
    group_id: int,
    node_id: str,
    added_by: str,
) -> dict:
    """Add an agent to a group.

    Args:
        db: An open SQLite connection.
        group_id: The group to add the agent to.
        node_id: The agent's node identifier.
        added_by: Username of the admin adding the member.

    Returns:
        The created membership record as a dict.
    """
    cursor = db.execute(
        "INSERT INTO agent_group_members (group_id, node_id, added_by) VALUES (?, ?, ?)",
        (group_id, node_id, added_by),
    )
    db.commit()

    row = db.execute(
        "SELECT * FROM agent_group_members WHERE id = ?",
        (cursor.lastrowid,),
    ).fetchone()
    return _row_to_dict(row)


def remove_group_member(
    db: sqlite3.Connection,
    group_id: int,
    node_id: str,
) -> bool:
    """Remove an agent from a group.

    Args:
        db: An open SQLite connection.
        group_id: The group to remove the agent from.
        node_id: The agent's node identifier.

    Returns:
        True if the membership was found and removed, False otherwise.
    """
    row = db.execute(
        "SELECT id FROM agent_group_members WHERE group_id = ? AND node_id = ?",
        (group_id, node_id),
    ).fetchone()
    if row is None:
        return False

    db.execute(
        "DELETE FROM agent_group_members WHERE group_id = ? AND node_id = ?",
        (group_id, node_id),
    )
    db.commit()
    return True


# ── Config rollout helpers ───────────────────────────────────────────────


def create_rollout(
    db: sqlite3.Connection,
    profile_id: int,
    target_version: int,
    created_by: str,
    policy: str = "immediate",
    canary_nodes: list[str] | None = None,
    current_percentage: int = 100,
) -> dict:
    """Create a configuration rollout record.

    Args:
        db: An open SQLite connection.
        profile_id: The profile being rolled out.
        target_version: The profile version being distributed.
        created_by: Username of the admin creating the rollout.
        policy: Rollout policy ('immediate', 'canary', or 'staged').
        canary_nodes: List of node_ids for canary rollouts.
        current_percentage: Initial percentage for staged rollouts.

    Returns:
        The created rollout record as a dict.
    """
    canary_json = json.dumps(canary_nodes or [])

    cursor = db.execute(
        "INSERT INTO config_rollouts "
        "(profile_id, target_version, policy, canary_nodes, current_percentage, created_by) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (profile_id, target_version, policy, canary_json, current_percentage, created_by),
    )
    db.commit()

    row = db.execute(
        "SELECT * FROM config_rollouts WHERE id = ?",
        (cursor.lastrowid,),
    ).fetchone()
    return _row_to_dict(row)


def update_rollout_status(
    db: sqlite3.Connection,
    rollout_id: int,
    status: str,
    failure_count: int | None = None,
    success_count: int | None = None,
) -> bool:
    """Update a rollout's status and optionally its counts.

    Args:
        db: An open SQLite connection.
        rollout_id: The rollout to update.
        status: New status ('pending', 'in_progress', 'completed',
            'cancelled', 'failed').
        failure_count: If provided, update the failure count.
        success_count: If provided, update the success count.

    Returns:
        True if the rollout was found and updated, False otherwise.
    """
    row = db.execute(
        "SELECT id FROM config_rollouts WHERE id = ?",
        (rollout_id,),
    ).fetchone()
    if row is None:
        return False

    set_clauses = ["status = ?"]
    params: list = [status]

    if failure_count is not None:
        set_clauses.append("failure_count = ?")
        params.append(failure_count)

    if success_count is not None:
        set_clauses.append("success_count = ?")
        params.append(success_count)

    # Set completed_at when transitioning to a terminal state
    if status in ("completed", "cancelled", "failed"):
        set_clauses.append("completed_at = ?")
        params.append(_utcnow_iso())

    params.append(rollout_id)
    db.execute(
        f"UPDATE config_rollouts SET {', '.join(set_clauses)} WHERE id = ?",
        params,
    )
    db.commit()
    return True


def get_active_rollout(
    db: sqlite3.Connection,
    profile_id: int,
) -> dict | None:
    """Get the active (pending or in_progress) rollout for a profile.

    Args:
        db: An open SQLite connection.
        profile_id: The profile to check for active rollouts.

    Returns:
        The active rollout record as a dict, or None if no active rollout.
    """
    row = db.execute(
        "SELECT * FROM config_rollouts "
        "WHERE profile_id = ? AND status IN ('pending', 'in_progress') "
        "ORDER BY created_at DESC LIMIT 1",
        (profile_id,),
    ).fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


# ── Config agent status helpers ──────────────────────────────────────────


def upsert_agent_config_status(
    db: sqlite3.Connection,
    node_id: str,
    **kwargs,
) -> None:
    """Insert or update an agent's configuration status.

    Uses INSERT OR REPLACE to upsert based on the unique node_id constraint.
    Only updates fields that are explicitly provided in kwargs.

    Args:
        db: An open SQLite connection.
        node_id: The agent's node identifier.
        **kwargs: Fields to set. Valid keys: profile_id, acknowledged_version,
            last_check_in, management_mode, config_status,
            last_failure_reason, agent_version, health_uptime,
            health_active_rules, health_blocked_ips.
    """
    valid_fields = {
        "profile_id",
        "acknowledged_version",
        "last_check_in",
        "management_mode",
        "config_status",
        "last_failure_reason",
        "agent_version",
        "health_uptime",
        "health_active_rules",
        "health_blocked_ips",
    }

    # Filter to only valid fields
    updates = {k: v for k, v in kwargs.items() if k in valid_fields}

    # Check if record exists
    existing = db.execute(
        "SELECT * FROM config_agent_status WHERE node_id = ?",
        (node_id,),
    ).fetchone()

    if existing is None:
        # Insert new record
        columns = ["node_id"] + list(updates.keys())
        placeholders = ["?"] * len(columns)
        values = [node_id] + list(updates.values())

        db.execute(
            f"INSERT INTO config_agent_status ({', '.join(columns)}) "
            f"VALUES ({', '.join(placeholders)})",
            values,
        )
    else:
        # Update existing record
        if updates:
            set_clauses = [f"{k} = ?" for k in updates.keys()]
            values = list(updates.values()) + [node_id]

            db.execute(
                f"UPDATE config_agent_status SET {', '.join(set_clauses)} WHERE node_id = ?",
                values,
            )

    db.commit()


def get_agent_config_status(
    db: sqlite3.Connection,
    node_id: str,
) -> dict | None:
    """Get an agent's configuration status.

    Args:
        db: An open SQLite connection.
        node_id: The agent's node identifier.

    Returns:
        The agent config status record as a dict, or None if not found.
    """
    row = db.execute(
        "SELECT * FROM config_agent_status WHERE node_id = ?",
        (node_id,),
    ).fetchone()
    if row is None:
        return None
    return _row_to_dict(row)
