"""Profile resolution logic for centralized agent management.

Determines the effective configuration profile for an agent based on
assignment priority rules.
"""

import sqlite3


def resolve_effective_profile(db: sqlite3.Connection, node_id: str) -> dict | None:
    """Resolve the effective profile for an agent.

    Priority:
    1. Direct active assignment to node_id → use that profile
    2. Group-based assignment (agent is member of a group that has an active
       assignment) → use the profile from the most recently assigned group
       (latest assigned_at timestamp on the group-to-profile assignment)
    3. None (standalone) → no profile assigned

    Args:
        db: An open SQLite connection.
        node_id: The agent's node identifier.

    Returns:
        A dict with the effective profile data (from config_profiles table)
        including the profile's settings, version, conflict_strategy, etc.
        Returns None if no profile is assigned (agent is standalone).
    """
    # 1. Check for a direct active assignment
    direct = db.execute(
        "SELECT * FROM config_assignments WHERE node_id = ? AND is_active = 1",
        (node_id,),
    ).fetchone()

    if direct is not None:
        profile = db.execute(
            "SELECT * FROM config_profiles WHERE id = ? AND is_active = 1",
            (direct["profile_id"],),
        ).fetchone()
        if profile is not None:
            return dict(profile)

    # 2. Check group-based assignments
    # Find all groups the agent belongs to
    group_rows = db.execute(
        "SELECT group_id FROM agent_group_members WHERE node_id = ?",
        (node_id,),
    ).fetchall()

    if not group_rows:
        return None

    group_ids = [row["group_id"] for row in group_rows]

    # Find active assignments for those groups, ordered by assigned_at DESC
    # Use parameterized placeholders for the IN clause
    placeholders = ",".join("?" for _ in group_ids)
    group_assignment = db.execute(
        f"SELECT * FROM config_assignments "
        f"WHERE group_id IN ({placeholders}) AND is_active = 1 "
        f"ORDER BY assigned_at DESC LIMIT 1",
        group_ids,
    ).fetchone()

    if group_assignment is None:
        return None

    profile = db.execute(
        "SELECT * FROM config_profiles WHERE id = ? AND is_active = 1",
        (group_assignment["profile_id"],),
    ).fetchone()
    if profile is not None:
        return dict(profile)

    return None
