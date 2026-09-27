from __future__ import annotations

import logging
import sqlite3
from datetime import UTC, datetime, timedelta

from .db_core import _row_to_dict

logger = logging.getLogger(__name__)

# ── Geographic and trend query helpers (Task 2.7) ────────────────────────


def get_country_breakdown(db: sqlite3.Connection, hours: int | None = None) -> list[dict]:
    """Return event counts grouped by country, sorted by count descending.

    Only events with a non-NULL, non-empty geo_country are included.

    Args:
        db: An open database connection (sqlite3 or MySQLConnectionWrapper).
        hours: If provided, only consider events within the last N hours.

    Returns:
        A list of dicts: [{"country": "US", "count": 42}, ...]
    """
    params: list = []
    time_clause = ""
    if hours is not None:
        from datetime import datetime, timedelta

        cutoff = (datetime.now(UTC) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")
        time_clause = " AND timestamp >= ?"
        params.append(cutoff)

    rows = db.execute(
        "SELECT geo_country, COUNT(*) as cnt FROM events "
        "WHERE geo_country IS NOT NULL AND geo_country != ''" + time_clause + " "
        "GROUP BY geo_country ORDER BY cnt DESC",
        params,
    ).fetchall()
    return [{"country": row["geo_country"], "count": row["cnt"]} for row in rows]


def get_events_by_country(
    db: sqlite3.Connection, country: str, hours: int | None = None
) -> list[dict]:
    """Return recent events from a specific country, ordered by timestamp descending.

    Limited to 200 most recent events to prevent excessive memory usage.

    Args:
        db: An open database connection (sqlite3 or MySQLConnectionWrapper).
        country: The geo_country value to filter on.
        hours: If provided, only consider events within the last N hours.

    Returns:
        A list of event dicts matching the given country.
    """
    params: list = [country]
    time_clause = ""
    if hours is not None:
        from datetime import datetime, timedelta

        cutoff = (datetime.now(UTC) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")
        time_clause = " AND timestamp >= ?"
        params.append(cutoff)

    rows = db.execute(
        "SELECT * FROM events WHERE geo_country = ?"
        + time_clause
        + " ORDER BY timestamp DESC LIMIT 200",
        params,
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


# Mapping from user-facing interval strings to bucket configuration.
# Uses SUBSTR on ISO-8601 text timestamps for cross-database compatibility.
_INTERVAL_CONFIG = {
    "1h": {
        "hours": 1,
        "bucket_format": "%Y-%m-%dT%H:%M",
        # Truncate to 5-minute intervals using SUBSTR (first 14 chars = YYYY-MM-DDTHH:M)
        # For simplicity, bucket by 10-minute intervals: SUBSTR(timestamp, 1, 15) || '0'
        "bucket_expr": "SUBSTR(timestamp, 1, 15) || '0'",
    },
    "6h": {
        "hours": 6,
        "bucket_format": "%Y-%m-%dT%H:%M",
        # Bucket by hour
        "bucket_expr": "SUBSTR(timestamp, 1, 13) || ':00'",
    },
    "24h": {
        "hours": 24,
        "bucket_format": "%Y-%m-%dT%H:00",
        "bucket_expr": "SUBSTR(timestamp, 1, 13) || ':00'",
    },
    "7d": {
        "hours": 168,
        "bucket_format": "%Y-%m-%d",
        "bucket_expr": "SUBSTR(timestamp, 1, 10)",
    },
    "30d": {
        "hours": 720,
        "bucket_format": "%Y-%m-%d",
        "bucket_expr": "SUBSTR(timestamp, 1, 10)",
    },
}

_VALID_GROUP_BY_COLUMNS = frozenset({"event_type", "node_id", "source_ip"})


def get_blocked_ips(
    db: sqlite3.Connection,
    filters: dict | None = None,
    page: int = 1,
    per_page: int = 50,
) -> tuple[list[dict], int]:
    """Return distinct blocked IPs aggregated from events.

    Each row contains the source IP, total block count, first and last
    block timestamps, the most recent event type and country, and the
    list of nodes that reported blocks for this IP.

    Supported filter keys:
        source_ip   - exact match
        node_id     - exact match on any reporting node
        event_type  - exact match on any associated event type
        geo_country - exact match
        time_range  - one of '1h', '6h', '24h', '7d', 'all'

    Args:
        db: An open SQLite connection.
        filters: Optional dict of filter key/value pairs.
        page: 1-indexed page number.
        per_page: Number of results per page.

    Returns:
        A tuple of (list_of_blocked_ip_dicts, total_matching_count).
    """
    filters = filters or {}

    where_clauses = ["action_taken = 'BLOCKED'"]
    params: list = []

    # Time range filter
    time_range = filters.get("time_range", "24h")
    _time_hours = {
        "1h": 1,
        "6h": 6,
        "24h": 24,
        "7d": 168,
    }
    if time_range in _time_hours:
        from datetime import timedelta

        cutoff = (datetime.now(UTC) - timedelta(hours=_time_hours[time_range])).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        where_clauses.append("timestamp >= ?")
        params.append(cutoff)

    if filters.get("source_ip"):
        where_clauses.append("source_ip = ?")
        params.append(filters["source_ip"])

    if filters.get("node_id"):
        where_clauses.append("node_id = ?")
        params.append(filters["node_id"])

    if filters.get("event_type"):
        where_clauses.append("event_type = ?")
        params.append(filters["event_type"])

    if filters.get("geo_country"):
        where_clauses.append("geo_country = ?")
        params.append(filters["geo_country"])

    where_sql = "WHERE " + " AND ".join(where_clauses)

    # Count distinct IPs
    count_sql = f"SELECT COUNT(DISTINCT source_ip) FROM events {where_sql}"
    total = db.execute(count_sql, params).fetchone()[0]

    # Aggregated rows
    offset = (page - 1) * per_page
    data_sql = (
        f"SELECT "
        f"  source_ip, "
        f"  COUNT(*) AS block_count, "
        f"  MIN(timestamp) AS first_blocked, "
        f"  MAX(timestamp) AS last_blocked, "
        f"  GROUP_CONCAT(DISTINCT event_type) AS event_types, "
        f"  GROUP_CONCAT(DISTINCT node_id) AS nodes, "
        f"  GROUP_CONCAT(DISTINCT geo_country) AS countries "
        f"FROM events {where_sql} "
        f"GROUP BY source_ip "
        f"ORDER BY block_count DESC, last_blocked DESC "
        f"LIMIT ? OFFSET ?"
    )
    rows = db.execute(data_sql, params + [per_page, offset]).fetchall()

    results = []
    for row in rows:
        results.append(
            {
                "source_ip": row["source_ip"],
                "block_count": row["block_count"],
                "first_blocked": row["first_blocked"],
                "last_blocked": row["last_blocked"],
                "event_types": (row["event_types"] or "").split(","),
                "nodes": (row["nodes"] or "").split(","),
                "countries": (row["countries"] or "").split(","),
            }
        )

    return results, total


def get_time_series(
    db: sqlite3.Connection,
    interval: str,
    group_by: str | None = None,
) -> list[dict]:
    """Bucket events into time intervals, optionally grouped by a column.

    Args:
        db: An open SQLite connection.
        interval: One of '1h', '6h', '24h', '7d'.
        group_by: Optional column to add a secondary grouping. Must be one
            of 'event_type', 'node_id', or 'source_ip'.

    Returns:
        A list of dicts. Each dict has:
            - "bucket": the time bucket string (e.g. "2025-01-15T10:00")
            - "count": number of events in that bucket
            - "group": (only when group_by is specified) the value of the
              grouped column

    Raises:
        ValueError: If interval is not recognised or group_by is not a
            valid column name.
    """
    config = _INTERVAL_CONFIG.get(interval)
    if config is None:
        raise ValueError(
            f"Invalid interval '{interval}'. Must be one of: "
            f"{', '.join(sorted(_INTERVAL_CONFIG.keys()))}"
        )

    if group_by is not None and group_by not in _VALID_GROUP_BY_COLUMNS:
        raise ValueError(
            f"Invalid group_by '{group_by}'. Must be one of: "
            f"{', '.join(sorted(_VALID_GROUP_BY_COLUMNS))}"
        )

    bucket_expr = config["bucket_expr"]
    hours = config["hours"]

    start_time = (datetime.now(UTC) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

    if group_by is not None:
        sql = (
            f"SELECT {bucket_expr} AS bucket, {group_by} AS grp, COUNT(*) AS count "
            f"FROM events "
            f"WHERE timestamp >= ? "
            f"GROUP BY bucket, grp "
            f"ORDER BY bucket ASC, count DESC"
        )
    else:
        sql = (
            f"SELECT {bucket_expr} AS bucket, COUNT(*) AS count "
            f"FROM events "
            f"WHERE timestamp >= ? "
            f"GROUP BY bucket "
            f"ORDER BY bucket ASC"
        )

    rows = db.execute(sql, (start_time,)).fetchall()

    results = []
    for row in rows:
        entry = {"bucket": row["bucket"], "count": row["count"]}
        if group_by is not None:
            entry["group"] = row["grp"]
        results.append(entry)

    return results
