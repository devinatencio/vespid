from __future__ import annotations

import json
import logging
import sqlite3
from datetime import UTC, datetime, timedelta

from .db_core import _row_to_dict, _utcnow_iso

logger = logging.getLogger(__name__)

# ── Command queue helpers ────────────────────────────────────────────────


def create_command(
    db: sqlite3.Connection,
    node_id: str,
    command_type: str,
    payload: dict,
) -> str:
    """Queue a command for a node to pick up.

    Args:
        db: An open SQLite connection.
        node_id: Target node identifier. Use '*' for all nodes.
        command_type: The command type (e.g. 'allowlist_add', 'block').
        payload: Dict of command parameters.

    Returns:
        The generated command_id.
    """
    import uuid

    command_id = str(uuid.uuid4())
    db.execute(
        "INSERT INTO pending_commands (command_id, node_id, command_type, payload) "
        "VALUES (?, ?, ?, ?)",
        (command_id, node_id, command_type, json.dumps(payload)),
    )
    db.commit()
    return command_id


def get_pending_commands(
    db: sqlite3.Connection,
    node_id: str,
) -> list[dict]:
    """Fetch pending commands for a specific node.

    Returns commands targeted at the given node_id or at '*' (all nodes).
    Commands are returned in creation order.

    Args:
        db: An open SQLite connection.
        node_id: The node requesting its commands.

    Returns:
        A list of command dicts.
    """
    rows = db.execute(
        "SELECT * FROM pending_commands "
        "WHERE status = 'pending' AND (node_id = ? OR node_id = '*') "
        "ORDER BY created_at ASC",
        (node_id,),
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


def acknowledge_command(
    db: sqlite3.Connection,
    command_id: str,
    status: str = "acknowledged",
    result: str | None = None,
) -> bool:
    """Mark a command as acknowledged, completed, or failed.

    Args:
        db: An open SQLite connection.
        command_id: The unique command identifier.
        status: New status ('acknowledged', 'completed', 'failed').
        result: Optional result message from the node.

    Returns:
        True if the command was found and updated, False otherwise.
    """
    row = db.execute(
        "SELECT id FROM pending_commands WHERE command_id = ?",
        (command_id,),
    ).fetchone()
    if row is None:
        return False

    db.execute(
        "UPDATE pending_commands SET status = ?, acknowledged_at = ?, result = ? "
        "WHERE command_id = ?",
        (status, _utcnow_iso(), result, command_id),
    )
    db.commit()
    return True


def list_commands(
    db: sqlite3.Connection,
    node_id: str | None = None,
    status: str | None = None,
    limit: int = 100,
) -> list[dict]:
    """List commands with optional filtering.

    Args:
        db: An open SQLite connection.
        node_id: Filter by target node (optional).
        status: Filter by status (optional).
        limit: Maximum number of results.

    Returns:
        A list of command dicts, newest first.
    """
    where_clauses: list[str] = []
    params: list = []

    if node_id:
        where_clauses.append("(node_id = ? OR node_id = '*')")
        params.append(node_id)
    if status:
        where_clauses.append("status = ?")
        params.append(status)

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    rows = db.execute(
        f"SELECT * FROM pending_commands {where_sql} ORDER BY created_at DESC LIMIT ?",
        params + [limit],
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


def expire_stale_commands(db, max_pending_hours: int = 24) -> int:
    """Mark pending commands older than *max_pending_hours* as expired."""
    cutoff = (datetime.now(UTC) - timedelta(hours=max_pending_hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
    result = db.execute(
        "UPDATE pending_commands SET status = 'expired', acknowledged_at = ? "
        "WHERE status = 'pending' AND created_at < ?",
        (_utcnow_iso(), cutoff),
    )
    db.commit()
    return result.rowcount


def purge_old_commands(db, retention_days: int = 30) -> int:
    """Delete completed/failed/expired commands older than *retention_days*."""
    cutoff = (datetime.now(UTC) - timedelta(days=retention_days)).strftime("%Y-%m-%dT%H:%M:%SZ")
    result = db.execute(
        "DELETE FROM pending_commands "
        "WHERE status IN ('completed', 'failed', 'expired') AND created_at < ?",
        (cutoff,),
    )
    db.commit()
    return result.rowcount


def delete_command(db, command_id: str) -> bool:
    """Delete a single command by command_id."""
    result = db.execute("DELETE FROM pending_commands WHERE command_id = ?", (command_id,))
    db.commit()
    return result.rowcount > 0


def count_commands_by_status(db) -> dict[str, int]:
    """Return {status: count} for all commands."""
    rows = db.execute("SELECT status, COUNT(*) FROM pending_commands GROUP BY status").fetchall()
    return {r[0]: r[1] for r in rows}
