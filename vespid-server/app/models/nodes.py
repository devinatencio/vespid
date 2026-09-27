from __future__ import annotations

import json
import logging
import sqlite3
from datetime import UTC, datetime

from .db_core import _row_to_dict

logger = logging.getLogger(__name__)

# ── Node registry helpers (Task 2.5) ────────────────────────────────────


def upsert_node(
    db: sqlite3.Connection,
    node_id: str,
    event_timestamp: str,
    geo_data: dict,
) -> None:
    """Insert a new node or update an existing one after an event is received.

    If the node_id does not exist, a new row is inserted with total_events=1,
    last_event_at set to event_timestamp, and last_geo_data set to the
    JSON-serialised geo_data.

    If the node_id already exists, total_events is incremented by 1.
    last_event_at and last_geo_data are only updated when event_timestamp is
    more recent than the currently stored last_event_at (or when last_event_at
    is NULL).

    Args:
        db: An open SQLite connection.
        node_id: The unique identifier of the node.
        event_timestamp: ISO-8601 UTC timestamp of the event.
        geo_data: A dict of geographic data from the event.
    """
    geo_json = json.dumps(geo_data)

    existing = db.execute(
        "SELECT last_event_at FROM nodes WHERE node_id = ?",
        (node_id,),
    ).fetchone()

    if existing is None:
        # New node — insert
        db.execute(
            "INSERT INTO nodes (node_id, first_seen_at, total_events, last_event_at, last_geo_data) "
            "VALUES (?, ?, 1, ?, ?)",
            (node_id, event_timestamp, event_timestamp, geo_json),
        )
    else:
        # Existing node — always increment total_events
        db.execute(
            "UPDATE nodes SET total_events = total_events + 1 WHERE node_id = ?",
            (node_id,),
        )
        # Only update last_event_at and last_geo_data if the new timestamp is
        # more recent (or the stored value is NULL).
        current_last = existing["last_event_at"]
        # Normalize to string for comparison — MySQL returns datetime objects
        if current_last is not None and not isinstance(current_last, str):
            current_last = current_last.strftime("%Y-%m-%dT%H:%M:%S")
        if current_last is None or event_timestamp > current_last:
            db.execute(
                "UPDATE nodes SET last_event_at = ?, last_geo_data = ? WHERE node_id = ?",
                (event_timestamp, geo_json, node_id),
            )

    db.commit()


def touch_node(
    db: sqlite3.Connection,
    node_id: str,
    timestamp: str,
    geo_data: dict | None = None,
) -> None:
    """Update a node's last_event_at without incrementing total_events.

    Used by the heartbeat endpoint to keep a node showing as healthy
    even when there are no new security events. If the node does not
    exist yet, it is created with total_events=0.

    Args:
        db: An open SQLite connection.
        node_id: The unique identifier of the node.
        timestamp: ISO-8601 UTC timestamp of the heartbeat.
        geo_data: Optional geo data dict. If provided and the timestamp
            is newer, updates last_geo_data as well.
    """
    geo_json = json.dumps(geo_data or {})

    existing = db.execute(
        "SELECT last_event_at FROM nodes WHERE node_id = ?",
        (node_id,),
    ).fetchone()

    if existing is None:
        db.execute(
            "INSERT INTO nodes (node_id, first_seen_at, total_events, last_event_at, last_geo_data) "
            "VALUES (?, ?, 0, ?, ?)",
            (node_id, timestamp, timestamp, geo_json),
        )
    else:
        current_last = existing["last_event_at"]
        # Normalize to string for comparison — MySQL returns datetime objects
        # while SQLite returns strings. ISO-8601 strings compare correctly.
        if current_last is not None and not isinstance(current_last, str):
            current_last = current_last.strftime("%Y-%m-%dT%H:%M:%S")
        if current_last is None or timestamp > current_last:
            if geo_data:
                db.execute(
                    "UPDATE nodes SET last_event_at = ?, last_geo_data = ? WHERE node_id = ?",
                    (timestamp, geo_json, node_id),
                )
            else:
                db.execute(
                    "UPDATE nodes SET last_event_at = ? WHERE node_id = ?",
                    (timestamp, node_id),
                )

    db.commit()


def update_last_seen(db: sqlite3.Connection, node_id: str) -> None:
    """Update a node's last_seen_at timestamp to the current time.

    Called on every agent-facing request (heartbeat, events, commands,
    check-in) to track agent liveness independent of event activity.

    Args:
        db: An open SQLite connection.
        node_id: The unique identifier of the node.
    """
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    db.execute(
        "UPDATE nodes SET last_seen_at = ? WHERE node_id = ?",
        (now, node_id),
    )
    db.commit()


def list_nodes(db: sqlite3.Connection) -> list[dict]:
    """Return all registered nodes ordered by node_id.

    Args:
        db: An open SQLite connection.

    Returns:
        A list of node dicts (id, node_id, first_seen_at, last_event_at,
        total_events, last_geo_data).
    """
    rows = db.execute("SELECT * FROM nodes ORDER BY node_id ASC").fetchall()
    return [_row_to_dict(r) for r in rows]


def get_node(db: sqlite3.Connection, node_id: str) -> dict | None:
    """Look up a single node by its node_id.

    Args:
        db: An open SQLite connection.
        node_id: The unique node identifier string.

    Returns:
        A node dict, or None if not found.
    """
    row = db.execute("SELECT * FROM nodes WHERE node_id = ?", (node_id,)).fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


def delete_node(db: sqlite3.Connection, node_id: str) -> bool:
    """Delete a node from the registry by its node_id.

    Args:
        db: An open database connection.
        node_id: The unique node identifier string.

    Returns:
        True if the node was deleted, False if it did not exist.
    """
    cursor = db.execute("DELETE FROM nodes WHERE node_id = ?", (node_id,))
    db.commit()
    return cursor.rowcount > 0


def get_node_health(
    last_event_at: str | None,
    healthy_seconds: int = 300,
    degraded_seconds: int = 900,
) -> str:
    """Derive a node's health status from its last event timestamp.

    Compares last_event_at against the current UTC time to determine
    the health category.

    Args:
        last_event_at: ISO-8601 UTC timestamp of the node's last event,
            or None if the node has never sent an event.
        healthy_seconds: Maximum age in seconds for 'healthy' status
            (default 300 = 5 minutes).
        degraded_seconds: Maximum age in seconds for 'degraded' status
            (default 900 = 15 minutes). Ages >= this value are 'offline'.

    Returns:
        'healthy' if last_event_at is within healthy_seconds of now,
        'degraded' if between healthy_seconds and degraded_seconds,
        'offline' if >= degraded_seconds or last_event_at is None.
    """
    if last_event_at is None:
        return "offline"

    try:
        # Handle multiple ISO-8601 formats: with Z, +00:00, or no timezone
        ts = last_event_at.replace("Z", "+00:00")
        last_dt = datetime.fromisoformat(ts)
        # If no timezone info, assume UTC
        if last_dt.tzinfo is None:
            last_dt = last_dt.replace(tzinfo=UTC)
    except (ValueError, TypeError):
        return "offline"

    now = datetime.now(UTC)
    delta_seconds = (now - last_dt).total_seconds()

    if delta_seconds < healthy_seconds:
        return "healthy"
    elif delta_seconds < degraded_seconds:
        return "degraded"
    else:
        return "offline"
