from __future__ import annotations

import json
import logging
import sqlite3
from datetime import UTC, datetime, timedelta

from .db_core import _row_to_dict

logger = logging.getLogger(__name__)


def insert_events(db: sqlite3.Connection, events: list[dict]) -> set[str]:
    """Batch INSERT validated events into the events table.

    Flattens geo_data into individual columns and stores the full geo_data
    and metadata dicts as JSON strings.

    Uses INSERT IGNORE (MySQL) / INSERT OR IGNORE (SQLite) to gracefully
    handle duplicate event_ids from node retries after transient failures.

    Args:
        db: An open database connection (sqlite3 or MySQLConnectionWrapper).
        events: A list of validated event dicts matching the SecurityEvent
            schema (node_id, timestamp, source_ip, event_type, action_taken,
            geo_data, event_id, and optionally metadata).

    Returns:
        The set of event_ids that were actually inserted (excludes duplicates
        that were silently ignored).
    """
    if not events:
        return set()

    # Detect backend type from connection object
    from app.db_compat import MySQLConnectionWrapper

    is_mysql = isinstance(db, MySQLConnectionWrapper)

    if is_mysql:
        insert_prefix = "INSERT IGNORE INTO events "
    else:
        insert_prefix = "INSERT OR IGNORE INTO events "

    # Determine which event_ids already exist BEFORE inserting, so we can
    # identify which ones were truly new after the INSERT OR IGNORE.
    all_event_ids = [ev["event_id"] for ev in events]
    pre_existing_ids: set[str] = set()
    batch_size = 500
    for i in range(0, len(all_event_ids), batch_size):
        batch = all_event_ids[i : i + batch_size]
        placeholders = ",".join("?" * len(batch))
        cursor = db.execute(
            f"SELECT event_id FROM events WHERE event_id IN ({placeholders})",
            tuple(batch),
        )
        for row in cursor.fetchall():
            if is_mysql or isinstance(row, dict):
                pre_existing_ids.add(row["event_id"])
            else:
                pre_existing_ids.add(row[0])

    sql = (
        insert_prefix + "(event_id, node_id, timestamp, source_ip, event_type, action_taken, "
        "geo_country, geo_city, geo_asn, geo_org, geo_latitude, geo_longitude, "
        "geo_data, metadata) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    )

    rows = []
    for ev in events:
        geo = ev.get("geo_data") or {}
        meta = ev.get("metadata") or {}
        rows.append(
            (
                ev["event_id"],
                ev["node_id"],
                ev["timestamp"],
                ev["source_ip"],
                ev["event_type"],
                ev["action_taken"],
                geo.get("country"),
                geo.get("city"),
                geo.get("asn"),
                geo.get("org"),
                geo.get("latitude"),
                geo.get("longitude"),
                json.dumps(geo),
                json.dumps(meta),
            )
        )

    db.executemany(sql, rows)
    db.commit()

    # The newly inserted IDs are those that were NOT pre-existing
    return set(all_event_ids) - pre_existing_ids


# ---------------------------------------------------------------------------
# Event log context — raw log lines surrounding a block event.
# ---------------------------------------------------------------------------
def insert_event_context(db: sqlite3.Connection, event_id: str, context_lines: list[dict]) -> None:
    """Store surrounding log context for an event in ``event_log_context``.

    Args:
        db: An open database connection.
        event_id: The event_id this context belongs to.
        context_lines: List of dicts with keys ``raw``, ``parser``,
            ``timestamp`` (optional), ``trigger`` (optional bool),
            ``repeat`` (optional int), ``last_ts`` (optional).
    """
    if not context_lines:
        return
    sql = (
        "INSERT INTO event_log_context "
        "(event_id, line_idx, raw, parser, is_trigger, repeat_count, first_ts, last_ts) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
    )
    rows = []
    for idx, entry in enumerate(context_lines):
        raw = entry.get("raw", "")
        parser = entry.get("parser")
        is_trigger = 1 if entry.get("trigger") else 0
        repeat_count = entry.get("repeat", 1)
        first_ts = str(entry.get("timestamp") or "")
        last_ts = str(entry.get("last_ts") or "")
        rows.append((event_id, idx, raw, parser, is_trigger, repeat_count, first_ts, last_ts))
    db.executemany(sql, rows)
    db.commit()


def get_event_context(db: sqlite3.Connection, event_id: str) -> list[dict]:
    """Retrieve surrounding log context for an event.

    Returns a list of dicts ordered by ``line_idx``, each with keys:
    ``raw``, ``parser``, ``is_trigger``, ``repeat_count``, ``first_ts``, ``last_ts``.
    Returns an empty list if no context exists.
    """
    rows = db.execute(
        "SELECT raw, parser, is_trigger, repeat_count, first_ts, last_ts "
        "FROM event_log_context WHERE event_id = ? ORDER BY line_idx ASC",
        (event_id,),
    ).fetchall()
    result = []
    for row in rows:
        entry = {
            "raw": row["raw"],
            "parser": row["parser"],
            "is_trigger": bool(row["is_trigger"]),
            "repeat": row["repeat_count"],
        }
        if row["first_ts"]:
            entry["first_ts"] = row["first_ts"]
        if row["last_ts"]:
            entry["last_ts"] = row["last_ts"]
        result.append(entry)
    return result


EVENT_SORT_COLUMNS = frozenset(
    {
        "timestamp",
        "source_ip",
        "event_type",
        "geo_country",
        "action_taken",
        "node_id",
    }
)


def search_events(
    db: sqlite3.Connection,
    filters: dict,
    page: int = 1,
    per_page: int = 50,
    *,
    exclude_nft_action: bool = True,
    sort_by: str = "timestamp",
    sort_order: str = "DESC",
) -> tuple[list[dict], int]:
    """Search events with intersection-semantics filtering and pagination.

    Supported filter keys:
        source_ip, node_id, node_name, event_type, start_time, end_time,
        geo_country

    Text filters (source_ip, node_id, event_type, geo_country, node_name)
    use substring matching (LIKE '%value%'). All supplied filters are
    combined with AND.

    Args:
        db: An open SQLite connection.
        filters: Dict of filter key/value pairs. Missing or ``None`` values
            are ignored.
        page: 1-indexed page number.
        per_page: Number of results per page.
        exclude_nft_action: If True (default), exclude NFT_ACTION events
            when no explicit event_type filter is set.
        sort_by: Column to sort by.
        sort_order: ASC or DESC.

    Returns:
        A tuple of (list_of_event_dicts, total_matching_count).
    """
    where_clauses: list[str] = []
    params: list = []
    from_clause = "events"
    need_nodes_join = False

    # Use LIKE ? with % wrapping in Python to avoid || concatenation,
    # which is SQLite-only syntax (MySQL treats || as logical OR).
    _filter_map = {
        "source_ip": "events.source_ip LIKE ?",
        "event_type": "events.event_type LIKE ?",
        "geo_country": "events.geo_country LIKE ?",
    }

    has_event_type_filter = filters.get("event_type") is not None

    for key, clause in _filter_map.items():
        value = filters.get(key)
        if value is not None:
            where_clauses.append(clause)
            params.append(f"%{value}%")

    if exclude_nft_action and not has_event_type_filter:
        where_clauses.append("events.event_type != 'NFT_ACTION'")

    # Combined "node" filter: searches both node_id and display_name via
    # an always-on LEFT JOIN so partial hostname and partial ID both work.
    node_value = filters.get("node") or filters.get("node_id") or filters.get("node_name")
    if node_value is not None:
        need_nodes_join = True
        where_clauses.append("(nodes.display_name LIKE ? OR events.node_id LIKE ?)")
        params.append(f"%{node_value}%")
        params.append(f"%{node_value}%")

    # Quick-search: OR across IP, event type, country, node ID
    q_value = filters.get("q")
    if q_value is not None:
        where_clauses.append(
            "(events.source_ip LIKE ? OR events.event_type LIKE ? "
            "OR events.geo_country LIKE ? OR events.node_id LIKE ?)"
        )
        like = f"%{q_value}%"
        params.extend([like, like, like, like])

    start_time = filters.get("start_time")
    if start_time is not None:
        where_clauses.append("events.timestamp >= ?")
        params.append(start_time)

    end_time = filters.get("end_time")
    if end_time is not None:
        where_clauses.append("events.timestamp <= ?")
        params.append(end_time)

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    if need_nodes_join:
        from_clause = "events LEFT JOIN nodes ON events.node_id = nodes.node_id"

    # Validate sort values to prevent SQL injection
    sort_col = sort_by
    if sort_col not in EVENT_SORT_COLUMNS:
        sort_col = "timestamp"
    sort_dir = "ASC" if sort_order.upper() == "ASC" else "DESC"

    # Total count
    count_sql = f"SELECT COUNT(*) FROM {from_clause} {where_sql}"
    total = db.execute(count_sql, params).fetchone()[0]

    # Paginated results
    offset = (page - 1) * per_page
    if sort_col == "timestamp":
        order_clause = f"events.{sort_col} {sort_dir}, events.id DESC"
    else:
        order_clause = f"events.{sort_col} {sort_dir}, events.timestamp DESC, events.id DESC"
    data_sql = (
        "SELECT events.*, "
        "EXISTS(SELECT 1 FROM fleet_blocks WHERE source_ip = events.source_ip AND status = 'active') AS fleet_blocked "
        f"FROM {from_clause} {where_sql} ORDER BY {order_clause} LIMIT ? OFFSET ?"
    )
    rows = db.execute(data_sql, params + [per_page, offset]).fetchall()

    return [_row_to_dict(r) for r in rows], total


def get_dashboard_stats(db: sqlite3.Connection) -> dict:
    """Compute dashboard summary statistics.

    Returns a dict with:
        total_events_24h: Count of events with timestamp within the last 24h.
        active_nodes: Count of distinct node_ids with events in the last 15 min.
        blocked_ips: Count of distinct source_ips with action_taken='BLOCKED'
            in the last 24h.
        distinct_source_ips: Count of distinct source_ips in the last 24h.
        event_type_breakdown: List of {event_type, count} dicts for the last 24h.
    """

    now = datetime.now(UTC)
    cutoff_24h_str = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    cutoff_15m_str = (now - timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ")

    total_events_24h = db.execute(
        "SELECT COUNT(*) FROM events WHERE timestamp >= ?",
        (cutoff_24h_str,),
    ).fetchone()[0]

    active_nodes = db.execute(
        "SELECT COUNT(DISTINCT node_id) FROM events WHERE timestamp >= ?",
        (cutoff_15m_str,),
    ).fetchone()[0]

    blocked_ips = db.execute(
        "SELECT COUNT(DISTINCT source_ip) FROM events "
        "WHERE action_taken = 'BLOCKED' AND timestamp >= ?",
        (cutoff_24h_str,),
    ).fetchone()[0]

    distinct_source_ips = db.execute(
        "SELECT COUNT(DISTINCT source_ip) FROM events WHERE timestamp >= ?",
        (cutoff_24h_str,),
    ).fetchone()[0]

    breakdown_rows = db.execute(
        "SELECT event_type, COUNT(*) as count FROM events "
        "WHERE timestamp >= ? AND event_type != 'NFT_ACTION' "
        "GROUP BY event_type ORDER BY count DESC",
        (cutoff_24h_str,),
    ).fetchall()

    event_type_breakdown = [
        {"event_type": row["event_type"], "count": row["count"]} for row in breakdown_rows
    ]

    return {
        "total_events_24h": total_events_24h,
        "active_nodes": active_nodes,
        "blocked_ips": blocked_ips,
        "distinct_source_ips": distinct_source_ips,
        "event_type_breakdown": event_type_breakdown,
        "sparkline_24h": _get_sparkline_24h(db),
        "sparkline_blocked_24h": _get_sparkline_blocked_24h(db),
        "sparkline_sources_24h": _get_sparkline_distinct_sources_24h(db),
        "sparkline_nodes_24h": _get_sparkline_nodes_24h(db),
    }


def _get_sparkline_24h(db: sqlite3.Connection) -> list[int]:
    """Return hourly event counts for the last 24 hours (24 values).

    Used to render inline sparkline charts in the dashboard stat cards.
    Index 0 is 24 hours ago, index 23 is the current hour.
    """

    now = datetime.now(UTC)
    cutoff = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")

    rows = db.execute(
        "SELECT SUBSTR(timestamp, 1, 13) as hour, COUNT(*) as cnt "
        "FROM events "
        "WHERE timestamp >= ? "
        "GROUP BY hour ORDER BY hour ASC",
        (cutoff,),
    ).fetchall()

    # Normalize bucket keys: stored timestamps may use 'T' separator (SQLite)
    # or space separator (MySQL, after _normalize_param conversion).
    # Canonicalize to space-separated format for consistent lookup.
    bucket_map = {}
    for row in rows:
        key = row["hour"].replace("T", " ") if row["hour"] else ""
        bucket_map[key] = bucket_map.get(key, 0) + row["cnt"]

    # Build a full 24-slot array using space-separated keys to match
    result = []
    for i in range(24):
        hour = now - timedelta(hours=23 - i)
        key = hour.strftime("%Y-%m-%d %H")
        result.append(bucket_map.get(key, 0))

    return result


def _get_sparkline_blocked_24h(db: sqlite3.Connection) -> list[int]:
    """Return hourly blocked-IP counts for the last 24 hours (24 values).

    Used to render inline sparkline charts in the blocked IPs stat card.
    Index 0 is 24 hours ago, index 23 is the current hour.
    """

    now = datetime.now(UTC)
    cutoff = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")

    rows = db.execute(
        "SELECT SUBSTR(timestamp, 1, 13) as hour, COUNT(*) as cnt "
        "FROM events "
        "WHERE action_taken = 'BLOCKED' "
        "AND timestamp >= ? "
        "GROUP BY hour ORDER BY hour ASC",
        (cutoff,),
    ).fetchall()

    # Normalize bucket keys: handle both 'T' (SQLite) and space (MySQL) separators
    bucket_map = {}
    for row in rows:
        key = row["hour"].replace("T", " ") if row["hour"] else ""
        bucket_map[key] = bucket_map.get(key, 0) + row["cnt"]

    result = []
    for i in range(24):
        hour = now - timedelta(hours=23 - i)
        key = hour.strftime("%Y-%m-%d %H")
        result.append(bucket_map.get(key, 0))

    return result


def _get_sparkline_distinct_sources_24h(db: sqlite3.Connection) -> list[int]:
    """Return hourly distinct source IP counts for the last 24 hours (24 values).

    Used to render inline sparkline charts in the Distinct Sources stat card.
    Index 0 is 24 hours ago, index 23 is the current hour.
    """

    now = datetime.now(UTC)
    cutoff = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")

    rows = db.execute(
        "SELECT SUBSTR(timestamp, 1, 13) as hour, COUNT(DISTINCT source_ip) as cnt "
        "FROM events "
        "WHERE timestamp >= ? "
        "GROUP BY hour ORDER BY hour ASC",
        (cutoff,),
    ).fetchall()

    bucket_map = {}
    for row in rows:
        key = row["hour"].replace("T", " ") if row["hour"] else ""
        bucket_map[key] = bucket_map.get(key, 0) + row["cnt"]

    result = []
    for i in range(24):
        hour = now - timedelta(hours=23 - i)
        key = hour.strftime("%Y-%m-%d %H")
        result.append(bucket_map.get(key, 0))

    return result


def _get_sparkline_nodes_24h(db: sqlite3.Connection) -> list[int]:
    """Return hourly distinct node counts for the last 24 hours (24 values).

    Used to render inline sparkline charts in the Active Nodes stat card.
    Index 0 is 24 hours ago, index 23 is the current hour.
    """

    now = datetime.now(UTC)
    cutoff = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")

    rows = db.execute(
        "SELECT SUBSTR(timestamp, 1, 13) as hour, COUNT(DISTINCT node_id) as cnt "
        "FROM events "
        "WHERE timestamp >= ? "
        "GROUP BY hour ORDER BY hour ASC",
        (cutoff,),
    ).fetchall()

    bucket_map = {}
    for row in rows:
        key = row["hour"].replace("T", " ") if row["hour"] else ""
        bucket_map[key] = bucket_map.get(key, 0) + row["cnt"]

    result = []
    for i in range(24):
        hour = now - timedelta(hours=23 - i)
        key = hour.strftime("%Y-%m-%d %H")
        result.append(bucket_map.get(key, 0))

    return result


def get_recent_events(
    db: sqlite3.Connection, limit: int = 10, *, exclude_fleet: bool = True
) -> list[dict]:
    """Return the most recent events.

    Events are ordered by timestamp DESC, then id DESC.

    Args:
        db: An open SQLite connection.
        limit: Maximum number of events to return (default 10).
        exclude_fleet: If True (default), exclude fleet-propagated events
            (those with metadata.reason starting with 'fleet:') to keep the
            timeline focused on organic local detections.

    Returns:
        A list of event dicts.
    """
    if exclude_fleet:
        rows = db.execute(
            "SELECT events.*, "
            "EXISTS(SELECT 1 FROM fleet_blocks WHERE source_ip = events.source_ip AND status = 'active') AS fleet_blocked "
            "FROM events "
            "WHERE event_type != 'NFT_ACTION' "
            "ORDER BY timestamp DESC, id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT events.*, "
            "EXISTS(SELECT 1 FROM fleet_blocks WHERE source_ip = events.source_ip AND status = 'active') AS fleet_blocked "
            "FROM events ORDER BY timestamp DESC, id DESC LIMIT ?",
            (limit,),
        ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_events_after_id(
    db: sqlite3.Connection, event_id: str, *, exclude_fleet: bool = True
) -> list[dict]:
    """Return events ingested after the event with the given event_id.

    Looks up the internal ``id`` of the event matching *event_id*, then
    returns all events with a higher internal ``id``, ordered ascending.
    This is used for SSE reconnection via Last-Event-ID.

    Args:
        db: An open SQLite connection.
        event_id: The event_id string of the reference event.
        exclude_fleet: If True (default), exclude fleet-propagated events.

    Returns:
        A list of event dicts ingested after the reference event.
        Returns an empty list if the reference event_id is not found.
    """
    ref = db.execute("SELECT id FROM events WHERE event_id = ?", (event_id,)).fetchone()

    if ref is None:
        return []

    internal_id = ref["id"]
    if exclude_fleet:
        rows = db.execute(
            "SELECT * FROM events WHERE id > ? AND event_type != 'NFT_ACTION' ORDER BY id ASC",
            (internal_id,),
        ).fetchall()
    else:
        rows = db.execute(
            "SELECT * FROM events WHERE id > ? ORDER BY id ASC",
            (internal_id,),
        ).fetchall()
    return [_row_to_dict(r) for r in rows]
