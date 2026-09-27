from __future__ import annotations

import logging
import sqlite3

from .db_core import _row_to_dict

logger = logging.getLogger(__name__)

# ── IP rules helpers ─────────────────────────────────────────────────────


def add_ip_rule(
    db: sqlite3.Connection,
    rule_type: str,
    entry: str,
    reason: str,
    created_by: str,
) -> int:
    """Add an allowlist or blocklist rule.

    Args:
        db: An open SQLite connection.
        rule_type: 'allowlist' or 'blocklist'.
        entry: IP address or CIDR notation.
        reason: Human-readable reason for the rule.
        created_by: Username of the operator.

    Returns:
        The id of the new rule.
    """
    cursor = db.execute(
        "INSERT INTO ip_rules (rule_type, entry, reason, created_by) VALUES (?, ?, ?, ?)",
        (rule_type, entry, reason, created_by),
    )
    db.commit()
    return cursor.lastrowid


def remove_ip_rule(
    db: sqlite3.Connection,
    rule_id: int,
) -> bool:
    """Soft-delete an IP rule by marking it inactive.

    Args:
        db: An open SQLite connection.
        rule_id: The primary key of the rule.

    Returns:
        True if the rule was found and deactivated.
    """
    row = db.execute(
        "SELECT id FROM ip_rules WHERE id = ? AND is_active = 1",
        (rule_id,),
    ).fetchone()
    if row is None:
        return False

    db.execute(
        "UPDATE ip_rules SET is_active = 0 WHERE id = ?",
        (rule_id,),
    )
    db.commit()
    return True


def list_ip_rules(
    db: sqlite3.Connection,
    rule_type: str | None = None,
    active_only: bool = True,
) -> list[dict]:
    """List IP rules with optional filtering.

    Args:
        db: An open SQLite connection.
        rule_type: Filter by 'allowlist' or 'blocklist' (optional).
        active_only: If True, only return active rules.

    Returns:
        A list of rule dicts, newest first.
    """
    where_clauses: list[str] = []
    params: list = []

    if active_only:
        where_clauses.append("is_active = 1")
    if rule_type:
        where_clauses.append("rule_type = ?")
        params.append(rule_type)

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    rows = db.execute(
        f"SELECT * FROM ip_rules {where_sql} ORDER BY created_at DESC",
        params,
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_ip_rule(db: sqlite3.Connection, rule_id: int) -> dict | None:
    """Get a single IP rule by id.

    Args:
        db: An open SQLite connection.
        rule_id: The primary key of the rule.

    Returns:
        A rule dict, or None if not found.
    """
    row = db.execute("SELECT * FROM ip_rules WHERE id = ?", (rule_id,)).fetchone()
    if row is None:
        return None
    return _row_to_dict(row)
