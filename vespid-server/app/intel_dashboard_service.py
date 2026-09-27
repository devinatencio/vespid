"""Intel Dashboard service layer.

Provides query parsing, search execution, and analytics aggregation
functions for the Intelligence Dashboard UI. Reuses the existing
intel_models.py data layer for filter/sort/pagination on non-CIDR queries
and adds CIDR membership checking via the ipaddress module.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
from datetime import UTC, datetime, timedelta

from app.country_codes import COUNTRY_NAMES
from app.intel_models import search_ip_records

logger = logging.getLogger(__name__)

# Regex for threat tag validation: alphanumeric, hyphens, underscores, 1-64 chars
_THREAT_TAG_RE = re.compile(r"^[a-zA-Z0-9_-]{1,64}$")

# Allowed sort columns (allowlist to prevent SQL injection)
_ALLOWED_SORT_COLUMNS = {
    "last_seen_at",
    "total_times_seen",
    "total_times_blocked",
    "total_reporting_nodes",
    "reputation_score",
    "block_episode_count",
    "total_requests",
}


def parse_search_query(query: str) -> dict:
    """Classify and parse a search query string.

    Classification rules (applied in order):
    1. Valid CIDR notation (contains '/') → cidr
    2. Valid IPv4/IPv6 address → exact_ip
    3. Partial IPv4 (fewer than 4 octets) or incomplete IPv6 prefix → prefix
    4. Alphanumeric with hyphens/underscores, 1-64 chars → threat_tag
    5. Anything else → invalid

    Returns:
        dict with keys:
            - query_type: "exact_ip" | "prefix" | "cidr" | "threat_tag" | "invalid"
            - value: parsed value (ip string, network object, tag string)
            - error: error message if invalid, else None
    """
    if not query or not query.strip():
        return {
            "query_type": "invalid",
            "value": None,
            "error": "Search query cannot be empty",
        }

    query = query.strip()

    # 1. Check for CIDR notation (must check before exact IP since "10.0.0.0/8" contains a valid IP)
    if "/" in query:
        try:
            network = ipaddress.ip_network(query, strict=False)
            return {
                "query_type": "cidr",
                "value": network,
                "error": None,
            }
        except ValueError:
            return {
                "query_type": "invalid",
                "value": None,
                "error": "Invalid CIDR notation. Expected format: 192.168.1.0/24 or 2001:db8::/32",
            }

    # 2. Check for exact IPv4 or IPv6 address
    try:
        addr = ipaddress.ip_address(query)
        return {
            "query_type": "exact_ip",
            "value": str(addr),
            "error": None,
        }
    except ValueError:
        pass

    # 3. Check for partial IPv4 prefix (fewer than 4 octets)
    if _is_partial_ipv4(query):
        return {
            "query_type": "prefix",
            "value": query,
            "error": None,
        }

    # 4. Check for incomplete IPv6 prefix (starts with valid hex and contains colons)
    if _is_partial_ipv6(query):
        return {
            "query_type": "prefix",
            "value": query,
            "error": None,
        }

    # 5. Check for threat tag (alphanumeric, hyphens, underscores, 1-64 chars)
    if _THREAT_TAG_RE.match(query):
        return {
            "query_type": "threat_tag",
            "value": query,
            "error": None,
        }

    # 6. Invalid
    return {
        "query_type": "invalid",
        "value": None,
        "error": (
            "Invalid search query. Accepted formats: IPv4/IPv6 address, "
            "partial IP prefix, CIDR notation (e.g., 192.168.1.0/24), "
            "or threat tag (alphanumeric, hyphens, underscores, max 64 characters)"
        ),
    }


def _is_partial_ipv4(query: str) -> bool:
    """Check if query is a partial IPv4 address (fewer than 4 octets).

    Valid partial IPv4 examples: "192.", "10.0.", "172.16.1.", "192.168"
    Each octet must be 0-255.
    """
    # Must contain at least one dot or be a single number that could be a first octet
    parts = query.rstrip(".").split(".")

    # Must have 1-3 parts (fewer than 4 octets)
    if len(parts) < 1 or len(parts) > 3:
        return False

    # If only one part with no dot, it's ambiguous - could be a tag number
    # Only treat as prefix if it ends with a dot
    if len(parts) == 1 and not query.endswith("."):
        # Single number without trailing dot - only treat as prefix if it's
        # clearly numeric and could be an IP octet (0-255)
        if not parts[0].isdigit():
            return False
        val = int(parts[0])
        if val < 0 or val > 255:
            return False
        # A single number 0-255 without a dot is treated as prefix
        return True

    # Multiple parts or trailing dot - validate each octet
    for part in parts:
        if not part.isdigit():
            return False
        val = int(part)
        if val < 0 or val > 255:
            return False

    return True


def _is_partial_ipv6(query: str) -> bool:
    """Check if query is a partial/incomplete IPv6 prefix.

    Valid partial IPv6 examples: "2001:", "2001:db8:", "fe80::"
    Must start with valid hex characters and contain at least one colon,
    but not be a valid complete IPv6 address (already checked above).
    """
    if ":" not in query:
        return False

    # Must not contain characters invalid for IPv6
    # Valid chars: hex digits (0-9, a-f, A-F) and colons
    cleaned = query.replace(":", "")
    if not all(c in "0123456789abcdefABCDEF" for c in cleaned):
        return False

    # Must have at least one hex group before the first colon
    parts = query.split(":")
    if not parts[0]:
        # Starts with ":" - only valid if it's "::" prefix
        if not query.startswith("::"):
            return False

    # Validate that non-empty groups are valid hex (1-4 chars)
    for part in parts:
        if part and (len(part) > 4 or not all(c in "0123456789abcdefABCDEF" for c in part)):
            return False

    return True


def execute_search(
    conn,
    query: str,
    filters: dict | None = None,
    page: int = 1,
    per_page: int = 50,
    sort_by: str = "last_seen_at",
    sort_order: str = "desc",
) -> tuple[list[dict], int]:
    """Execute a search query against the intelligence database.

    For exact_ip and prefix queries, uses direct SQL with ip_address filtering.
    For threat_tag queries, delegates to search_ip_records with the tag filter.
    For CIDR queries, uses a prefix LIKE filter for performance, then filters
    results in Python using the ipaddress module for exact membership checks.

    Args:
        conn: Database connection.
        query: Raw search query string.
        filters: Additional filter criteria:
            - repeat_offender: bool or None
            - geo_country: str or None
            - min_sighting_count: int or None
        page: Page number (minimum 1). Defaults to 1.
        per_page: Results per page (min 1, max 200). Defaults to 50.
        sort_by: Column to sort by. Defaults to "last_seen_at".
        sort_order: Sort direction ("asc" or "desc"). Defaults to "desc".

    Returns:
        Tuple of (results_list, total_count).
    """
    if filters is None:
        filters = {}

    # Validate and clamp pagination
    if page < 1:
        page = 1
    if per_page < 1:
        per_page = 1
    elif per_page > 200:
        per_page = 200

    # Validate sort parameters
    if sort_by not in _ALLOWED_SORT_COLUMNS:
        sort_by = "last_seen_at"
    if sort_order.lower() not in ("asc", "desc"):
        sort_order = "desc"
    else:
        sort_order = sort_order.lower()

    # Parse the query
    parsed = parse_search_query(query)

    if parsed["query_type"] == "invalid":
        return ([], 0)

    if parsed["query_type"] == "cidr":
        return _execute_cidr_search(
            conn, parsed["value"], filters, page, per_page, sort_by, sort_order
        )

    # For exact_ip and prefix queries, use custom SQL since search_ip_records
    # doesn't support ip_address filtering directly
    if parsed["query_type"] in ("exact_ip", "prefix"):
        return _execute_ip_search(conn, parsed, filters, page, per_page, sort_by, sort_order)

    # For threat_tag queries, use search_ip_records with the tag filter
    # If min_sighting_count is specified, use custom handling
    if filters.get("min_sighting_count") is not None:
        return _execute_filtered_search(conn, parsed, filters, page, per_page, sort_by, sort_order)

    search_filters = {}
    search_filters["threat_tag"] = parsed["value"]

    if filters.get("repeat_offender") is not None:
        search_filters["repeat_offender"] = filters["repeat_offender"]
    if filters.get("geo_country"):
        search_filters["geo_country"] = filters["geo_country"]

    results, total_count = search_ip_records(
        conn,
        filters=search_filters,
        page=page,
        per_page=per_page,
        sort_by=sort_by,
        sort_order=sort_order,
    )

    return (results, total_count)


def _execute_ip_search(
    conn,
    parsed: dict,
    filters: dict,
    page: int,
    per_page: int,
    sort_by: str,
    sort_order: str,
) -> tuple[list[dict], int]:
    """Execute an exact IP or prefix search with additional filters.

    For exact_ip: WHERE ip_address = ?
    For prefix: WHERE ip_address LIKE ?%
    """
    where_clauses = []
    params = []

    if parsed["query_type"] == "exact_ip":
        where_clauses.append("ip_intel.ip_address = ?")
        params.append(parsed["value"])
    else:
        # Prefix search
        prefix = parsed["value"]
        # Ensure the prefix ends with a dot for proper LIKE matching
        # If user typed "192.168" we want to match "192.168.x.x"
        where_clauses.append("ip_intel.ip_address LIKE ?")
        params.append(f"{prefix}%")

    # Apply additional filters
    if filters.get("repeat_offender") is not None:
        where_clauses.append("ip_intel.repeat_offender = ?")
        params.append(1 if filters["repeat_offender"] else 0)

    if filters.get("geo_country"):
        where_clauses.append("ip_intel.geo_country = ?")
        params.append(filters["geo_country"])

    if filters.get("min_sighting_count") is not None:
        where_clauses.append("ip_intel.total_times_seen >= ?")
        params.append(int(filters["min_sighting_count"]))

    where_sql = "WHERE " + " AND ".join(where_clauses)

    # Count query
    count_sql = f"SELECT COUNT(*) FROM ip_intel {where_sql}"
    cursor = conn.execute(count_sql, params)
    row = cursor.fetchone()
    total_count = row[0] if row else 0

    if total_count == 0:
        return ([], 0)

    # Data query with sorting and pagination
    select_columns = (
        "ip_intel.id, ip_intel.ip_address, ip_intel.ip_version, "
        "ip_intel.first_seen_at, ip_intel.last_seen_at, ip_intel.last_blocked_at, "
        "ip_intel.total_times_seen, ip_intel.total_times_blocked, "
        "ip_intel.total_reporting_nodes, ip_intel.total_attack_events, "
        "ip_intel.repeat_offender, ip_intel.first_reporting_node, "
        "ip_intel.most_recent_reporting_node, ip_intel.reporting_node_list, "
        "ip_intel.geo_country, ip_intel.asn, ip_intel.isp_organization, "
        "ip_intel.reputation_score, ip_intel.threat_tags, "
        "ip_intel.last_unblocked_at, ip_intel.block_episode_count, "
        "ip_intel.total_requests"
    )

    offset = (page - 1) * per_page
    data_sql = (
        f"SELECT {select_columns} FROM ip_intel {where_sql} "
        f"ORDER BY ip_intel.{sort_by} {sort_order} "
        f"LIMIT ? OFFSET ?"
    )
    data_params = params + [per_page, offset]

    cursor = conn.execute(data_sql, data_params)
    rows = cursor.fetchall()

    column_names = [
        "id",
        "ip_address",
        "ip_version",
        "first_seen_at",
        "last_seen_at",
        "last_blocked_at",
        "total_times_seen",
        "total_times_blocked",
        "total_reporting_nodes",
        "total_attack_events",
        "repeat_offender",
        "first_reporting_node",
        "most_recent_reporting_node",
        "reporting_node_list",
        "geo_country",
        "asn",
        "isp_organization",
        "reputation_score",
        "threat_tags",
        "last_unblocked_at",
        "block_episode_count",
        "total_requests",
    ]

    records = [_row_to_dict(row, column_names) for row in rows]
    return (records, total_count)


def _execute_filtered_search(
    conn,
    parsed: dict,
    filters: dict,
    page: int,
    per_page: int,
    sort_by: str,
    sort_order: str,
) -> tuple[list[dict], int]:
    """Execute a search with min_sighting_count filter (not supported by search_ip_records).

    Handles threat_tag queries that also need min_sighting_count filtering.
    """
    where_clauses = []
    params = []

    # Apply query-type-specific filter
    if parsed["query_type"] == "threat_tag":
        where_clauses.append("ip_intel.threat_tags LIKE ?")
        params.append(f'%"{parsed["value"]}"%')

    # Apply additional filters
    if filters.get("repeat_offender") is not None:
        where_clauses.append("ip_intel.repeat_offender = ?")
        params.append(1 if filters["repeat_offender"] else 0)

    if filters.get("geo_country"):
        where_clauses.append("ip_intel.geo_country = ?")
        params.append(filters["geo_country"])

    if filters.get("min_sighting_count") is not None:
        where_clauses.append("ip_intel.total_times_seen >= ?")
        params.append(int(filters["min_sighting_count"]))

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    # Count query
    count_sql = f"SELECT COUNT(*) FROM ip_intel {where_sql}"
    cursor = conn.execute(count_sql, params)
    row = cursor.fetchone()
    total_count = row[0] if row else 0

    if total_count == 0:
        return ([], 0)

    # Data query
    select_columns = (
        "ip_intel.id, ip_intel.ip_address, ip_intel.ip_version, "
        "ip_intel.first_seen_at, ip_intel.last_seen_at, ip_intel.last_blocked_at, "
        "ip_intel.total_times_seen, ip_intel.total_times_blocked, "
        "ip_intel.total_reporting_nodes, ip_intel.total_attack_events, "
        "ip_intel.repeat_offender, ip_intel.first_reporting_node, "
        "ip_intel.most_recent_reporting_node, ip_intel.reporting_node_list, "
        "ip_intel.geo_country, ip_intel.asn, ip_intel.isp_organization, "
        "ip_intel.reputation_score, ip_intel.threat_tags, "
        "ip_intel.last_unblocked_at, ip_intel.block_episode_count, "
        "ip_intel.total_requests"
    )

    offset = (page - 1) * per_page
    data_sql = (
        f"SELECT {select_columns} FROM ip_intel {where_sql} "
        f"ORDER BY ip_intel.{sort_by} {sort_order} "
        f"LIMIT ? OFFSET ?"
    )
    data_params = params + [per_page, offset]

    cursor = conn.execute(data_sql, data_params)
    rows = cursor.fetchall()

    column_names = [
        "id",
        "ip_address",
        "ip_version",
        "first_seen_at",
        "last_seen_at",
        "last_blocked_at",
        "total_times_seen",
        "total_times_blocked",
        "total_reporting_nodes",
        "total_attack_events",
        "repeat_offender",
        "first_reporting_node",
        "most_recent_reporting_node",
        "reporting_node_list",
        "geo_country",
        "asn",
        "isp_organization",
        "reputation_score",
        "threat_tags",
        "last_unblocked_at",
        "block_episode_count",
        "total_requests",
    ]

    records = [_row_to_dict(row, column_names) for row in rows]
    return (records, total_count)


def _execute_cidr_search(
    conn,
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    filters: dict,
    page: int,
    per_page: int,
    sort_by: str,
    sort_order: str,
) -> tuple[list[dict], int]:
    """Execute a CIDR-based search with prefix pre-filter and Python membership check.

    Strategy:
    1. Use a SQL LIKE prefix filter to narrow candidates (performance optimization)
    2. Filter candidates in Python using ipaddress module for exact membership
    3. Apply additional filters (repeat_offender, geo_country, min_sighting_count)
    4. Sort and paginate the results
    """
    # Determine the prefix for the LIKE filter
    prefix = _cidr_to_like_prefix(network)

    # Build the SQL query with prefix filter
    where_clauses = []
    params = []

    if prefix:
        where_clauses.append("ip_intel.ip_address LIKE ?")
        params.append(f"{prefix}%")

    # Apply additional filters at SQL level
    if filters.get("repeat_offender") is not None:
        where_clauses.append("ip_intel.repeat_offender = ?")
        params.append(1 if filters["repeat_offender"] else 0)

    if filters.get("geo_country"):
        where_clauses.append("ip_intel.geo_country = ?")
        params.append(filters["geo_country"])

    if filters.get("min_sighting_count") is not None:
        where_clauses.append("ip_intel.total_times_seen >= ?")
        params.append(int(filters["min_sighting_count"]))

    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    # Fetch all candidates (we need to filter in Python for CIDR membership)
    select_columns = (
        "ip_intel.id, ip_intel.ip_address, ip_intel.ip_version, "
        "ip_intel.first_seen_at, ip_intel.last_seen_at, ip_intel.last_blocked_at, "
        "ip_intel.total_times_seen, ip_intel.total_times_blocked, "
        "ip_intel.total_reporting_nodes, ip_intel.total_attack_events, "
        "ip_intel.repeat_offender, ip_intel.first_reporting_node, "
        "ip_intel.most_recent_reporting_node, ip_intel.reporting_node_list, "
        "ip_intel.geo_country, ip_intel.asn, ip_intel.isp_organization, "
        "ip_intel.reputation_score, ip_intel.threat_tags, "
        "ip_intel.last_unblocked_at, ip_intel.block_episode_count, "
        "ip_intel.total_requests"
    )

    sql = f"SELECT {select_columns} FROM ip_intel {where_sql}"
    cursor = conn.execute(sql, params)
    rows = cursor.fetchall()

    # Filter in Python for exact CIDR membership
    column_names = [
        "id",
        "ip_address",
        "ip_version",
        "first_seen_at",
        "last_seen_at",
        "last_blocked_at",
        "total_times_seen",
        "total_times_blocked",
        "total_reporting_nodes",
        "total_attack_events",
        "repeat_offender",
        "first_reporting_node",
        "most_recent_reporting_node",
        "reporting_node_list",
        "geo_country",
        "asn",
        "isp_organization",
        "reputation_score",
        "threat_tags",
        "last_unblocked_at",
        "block_episode_count",
        "total_requests",
    ]

    matching_records = []
    for row in rows:
        record = _row_to_dict(row, column_names)
        try:
            addr = ipaddress.ip_address(record["ip_address"])
            if addr in network:
                matching_records.append(record)
        except ValueError:
            continue

    # Sort the results
    matching_records = _sort_records(matching_records, sort_by, sort_order)

    # Calculate total and paginate
    total_count = len(matching_records)
    offset = (page - 1) * per_page
    paginated = matching_records[offset : offset + per_page]

    return (paginated, total_count)


def _cidr_to_like_prefix(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> str:
    """Convert a CIDR network to a SQL LIKE prefix for pre-filtering.

    For IPv4 networks, extracts the common prefix octets.
    For example:
        192.168.1.0/24 → "192.168.1."
        10.0.0.0/8 → "10."
        172.16.0.0/12 → "172."

    For IPv6 networks, extracts the common prefix groups.
    """
    network_str = str(network.network_address)

    if isinstance(network, ipaddress.IPv4Network):
        # Calculate how many full octets are covered by the prefix length
        full_octets = network.prefixlen // 8
        if full_octets == 0:
            return ""  # Very broad network, no useful prefix filter
        parts = network_str.split(".")
        return ".".join(parts[:full_octets]) + "."
    else:
        # IPv6: calculate full 4-char groups covered
        full_groups = network.prefixlen // 16
        if full_groups == 0:
            return ""
        # Use the exploded form for consistent matching
        exploded = network.network_address.exploded
        parts = exploded.split(":")
        return ":".join(parts[:full_groups]) + ":"


def _row_to_dict(row: tuple, column_names: list[str]) -> dict:
    """Convert a database row tuple to a dictionary with JSON parsing."""
    record = {}
    for i, col_name in enumerate(column_names):
        value = row[i]
        if col_name == "reporting_node_list":
            try:
                value = json.loads(value) if value else []
            except (json.JSONDecodeError, TypeError):
                value = []
        elif col_name == "threat_tags":
            try:
                value = json.loads(value) if value else []
            except (json.JSONDecodeError, TypeError):
                value = []
        elif col_name == "repeat_offender":
            value = bool(value)
        record[col_name] = value
    return record


def _sort_records(records: list[dict], sort_by: str, sort_order: str) -> list[dict]:
    """Sort a list of record dicts by the specified column and order."""
    reverse = sort_order == "desc"

    def sort_key(record):
        val = record.get(sort_by)
        if val is None:
            # Put None values at the end regardless of sort order
            return (1, "")
        return (0, val)

    return sorted(records, key=sort_key, reverse=reverse)


# ── Analytics Aggregation Functions ──────────────────────────────────────


def get_analytics_stats(conn) -> dict:
    """Compute aggregate stats for the analytics dashboard.

    Queries the ip_intel table to compute:
    - total_ips_tracked: total count of records
    - new_ips_24h: records with first_seen_at within last 24 hours
    - new_ips_7d: records with first_seen_at within last 7 days
    - new_ips_30d: records with first_seen_at within last 30 days
    - total_repeat_offenders: records with repeat_offender = 1
    - repeat_offender_percentage: (total_repeat_offenders / total_ips_tracked) * 100

    Args:
        conn: Database connection (sqlite3.Connection or MySQLConnectionWrapper).

    Returns:
        dict with keys: total_ips_tracked, new_ips_24h, new_ips_7d, new_ips_30d,
        total_repeat_offenders, repeat_offender_percentage
    """
    now = datetime.now(UTC)
    boundary_24h = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S")
    boundary_7d = (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S")
    boundary_30d = (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S")

    # Total IPs tracked
    cursor = conn.execute("SELECT COUNT(*) FROM ip_intel")
    row = cursor.fetchone()
    total_ips_tracked = row[0] if row else 0

    # New IPs in time windows
    cursor = conn.execute(
        "SELECT "
        "SUM(CASE WHEN first_seen_at >= ? THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN first_seen_at >= ? THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN first_seen_at >= ? THEN 1 ELSE 0 END) "
        "FROM ip_intel",
        (boundary_24h, boundary_7d, boundary_30d),
    )
    row = cursor.fetchone()
    new_ips_24h = (row[0] or 0) if row else 0
    new_ips_7d = (row[1] or 0) if row else 0
    new_ips_30d = (row[2] or 0) if row else 0

    # Repeat offender stats
    cursor = conn.execute("SELECT COUNT(*) FROM ip_intel WHERE repeat_offender = 1")
    row = cursor.fetchone()
    total_repeat_offenders = row[0] if row else 0

    # Calculate percentage
    if total_ips_tracked > 0:
        repeat_offender_percentage = round((total_repeat_offenders / total_ips_tracked) * 100, 2)
    else:
        repeat_offender_percentage = 0.0

    return {
        "total_ips_tracked": total_ips_tracked,
        "new_ips_24h": new_ips_24h,
        "new_ips_7d": new_ips_7d,
        "new_ips_30d": new_ips_30d,
        "total_repeat_offenders": total_repeat_offenders,
        "repeat_offender_percentage": repeat_offender_percentage,
    }


def get_repeat_offenders(
    conn, page: int = 1, per_page: int = 50, block_count: int | None = None
) -> tuple[list[dict], int]:
    """Return paginated repeat offenders sorted by total_times_seen descending.

    Args:
        conn: Database connection.
        page: Page number (1-indexed).
        per_page: Results per page.
        block_count: Optional. If 2 or 3, filter to exact total_times_blocked.
            If 4 or higher, filter to total_times_blocked >= that value.

    Returns:
        Tuple of (list of dicts with keys: ip_address, total_times_seen,
        total_times_blocked, last_seen_at, first_seen_at, geo_country,
        repeat_offender_since, total_reporting_nodes, total_attack_events,
        total_requests, asn, isp_organization, total_count)
    """
    offset = (page - 1) * per_page

    where_extra = ""
    params_extra: list = []
    if block_count is not None:
        if block_count <= 3:
            where_extra = " AND total_times_blocked = ?"
            params_extra.append(block_count)
        else:
            where_extra = " AND total_times_blocked >= ?"
            params_extra.append(block_count)

    cursor = conn.execute(
        f"SELECT COUNT(*) FROM ip_intel WHERE repeat_offender = 1{where_extra}",
        tuple(params_extra),
    )
    total = cursor.fetchone()[0] or 0

    cursor = conn.execute(
        f"SELECT ip_address, total_times_seen, total_times_blocked, "
        f"last_seen_at, first_seen_at, geo_country, repeat_offender_since, "
        f"total_reporting_nodes, total_attack_events, total_requests, "
        f"asn, isp_organization "
        f"FROM ip_intel WHERE repeat_offender = 1{where_extra} "
        f"ORDER BY total_times_seen DESC LIMIT ? OFFSET ?",
        (*params_extra, per_page, offset),
    )
    rows = cursor.fetchall()

    results = []
    for row in rows:
        results.append(
            {
                "ip_address": row[0],
                "total_times_seen": row[1],
                "total_times_blocked": row[2],
                "last_seen_at": row[3],
                "first_seen_at": row[4],
                "geo_country": row[5],
                "repeat_offender_since": row[6],
                "total_reporting_nodes": row[7],
                "total_attack_events": row[8],
                "total_requests": row[9],
                "asn": row[10],
                "isp_organization": row[11],
            }
        )

    return results, total


def get_repeat_offender_block_distribution(conn) -> dict:
    """Return distribution of repeat offenders by total_times_blocked.

    Returns:
        dict with keys: exact_2, exact_3, over_3 (counts of IPs blocked
        exactly 2, exactly 3, and more than 3 times respectively).
    """
    cursor = conn.execute(
        "SELECT total_times_blocked, COUNT(*) FROM ip_intel "
        "WHERE repeat_offender = 1 GROUP BY total_times_blocked ORDER BY total_times_blocked"
    )
    rows = cursor.fetchall()
    dist = {"exact_2": 0, "exact_3": 0, "over_3": 0}
    for row in rows:
        count = row[0]
        total = row[1]
        if count == 2:
            dist["exact_2"] = total
        elif count == 3:
            dist["exact_3"] = total
        elif count >= 4:
            dist["over_3"] += total
    return dist


def get_top_offenders(conn, limit: int = 10) -> list[dict]:
    """Return top N IPs by total_times_seen descending.

    Args:
        conn: Database connection.
        limit: Maximum number of results to return. Defaults to 10.

    Returns:
        List of dicts with keys: ip_address, total_times_seen, last_seen_at
    """
    cursor = conn.execute(
        "SELECT ip_address, total_times_seen, last_seen_at "
        "FROM ip_intel ORDER BY total_times_seen DESC LIMIT ?",
        (limit,),
    )
    rows = cursor.fetchall()

    results = []
    for row in rows:
        results.append(
            {
                "ip_address": row[0],
                "total_times_seen": row[1],
                "last_seen_at": row[2],
            }
        )

    return results


def get_top_countries(conn, limit: int = 10) -> list[dict]:
    """Return top N countries by IP count with percentage.

    Only includes records with non-null, non-empty geo_country values.
    Percentage is calculated relative to total IPs with a country assigned.

    Args:
        conn: Database connection.
        limit: Maximum number of results to return. Defaults to 10.

    Returns:
        List of dicts with keys: country_code, country_name, ip_count, percentage
    """
    # Get total IPs with a country assigned
    cursor = conn.execute(
        "SELECT COUNT(*) FROM ip_intel WHERE geo_country IS NOT NULL AND geo_country != ''"
    )
    row = cursor.fetchone()
    total_with_country = row[0] if row else 0

    if total_with_country == 0:
        return []

    # Get top countries
    cursor = conn.execute(
        "SELECT geo_country, COUNT(*) as ip_count "
        "FROM ip_intel WHERE geo_country IS NOT NULL AND geo_country != '' "
        "GROUP BY geo_country ORDER BY ip_count DESC LIMIT ?",
        (limit,),
    )
    rows = cursor.fetchall()

    results = []
    for row in rows:
        country_code = row[0]
        ip_count = row[1]
        percentage = round((ip_count / total_with_country) * 100, 2)
        country_name = COUNTRY_NAMES.get(country_code, country_code)
        results.append(
            {
                "country_code": country_code,
                "country_name": country_name,
                "ip_count": ip_count,
                "percentage": percentage,
            }
        )

    return results


def get_top_asns(conn, limit: int = 10) -> list[dict]:
    """Return top N ASNs by IP count.

    Only includes records with non-null asn values. Groups by asn and
    picks the most common isp_organization for each ASN.

    Args:
        conn: Database connection.
        limit: Maximum number of results to return. Defaults to 10.

    Returns:
        List of dicts with keys: asn, isp_organization, ip_count
    """
    cursor = conn.execute(
        "SELECT asn, isp_organization, COUNT(*) as ip_count "
        "FROM ip_intel WHERE asn IS NOT NULL AND asn != 0 "
        "GROUP BY asn ORDER BY ip_count DESC LIMIT ?",
        (limit,),
    )
    rows = cursor.fetchall()

    results = []
    for row in rows:
        results.append(
            {
                "asn": row[0],
                "isp_organization": row[1],
                "ip_count": row[2],
            }
        )

    return results


def get_chart_data(conn, interval: str) -> dict:
    """Compute time-series data for Chart.js charts.

    Generates daily data points for the specified interval:
    - labels: array of date strings (YYYY-MM-DD)
    - datasets.new_ips: count of ip_intel records with first_seen_at on each day
    - datasets.sightings: count of ip_intel_events with event_kind='sighting' on each day
    - datasets.blocklist_growth: cumulative count of ip_intel records with
      first_seen_at on or before each day (monotonically non-decreasing)

    Args:
        conn: Database connection.
        interval: Time interval - "7d", "30d", or "90d".

    Returns:
        dict with keys: labels, datasets (containing new_ips, sightings,
        blocklist_growth arrays)

    Raises:
        ValueError: If interval is not one of "7d", "30d", "90d".
    """
    # Parse interval to number of days
    interval_days = _parse_interval(interval)
    if interval_days is None:
        raise ValueError("Invalid interval. Accepted values: 7d, 30d, 90d")

    now = datetime.now(UTC)
    # Start date is interval_days ago (inclusive)
    start_date = (now - timedelta(days=interval_days - 1)).date()
    end_date = now.date()

    # Generate all date labels for the interval
    labels = []
    current_date = start_date
    while current_date <= end_date:
        labels.append(current_date.strftime("%Y-%m-%d"))
        current_date += timedelta(days=1)

    # Query new IPs per day (based on first_seen_at)
    start_str = start_date.strftime("%Y-%m-%d")
    cursor = conn.execute(
        "SELECT DATE(first_seen_at) as day, COUNT(*) as count "
        "FROM ip_intel WHERE DATE(first_seen_at) >= ? "
        "GROUP BY DATE(first_seen_at) ORDER BY day",
        (start_str,),
    )
    new_ips_by_day = {}
    for row in cursor.fetchall():
        # Handle both SQLite (returns string) and MySQL (returns datetime.date)
        day_key = row[0]
        if hasattr(day_key, "strftime"):
            day_key = day_key.strftime("%Y-%m-%d")
        elif day_key is not None:
            day_key = str(day_key)
        if day_key:
            new_ips_by_day[day_key] = row[1]

    # Query sightings per day (based on timestamp in ip_intel_events)
    cursor = conn.execute(
        "SELECT DATE(timestamp) as day, COUNT(*) as count "
        "FROM ip_intel_events WHERE event_kind = 'sighting' AND DATE(timestamp) >= ? "
        "GROUP BY DATE(timestamp) ORDER BY day",
        (start_str,),
    )
    sightings_by_day = {}
    for row in cursor.fetchall():
        # Handle both SQLite (returns string) and MySQL (returns datetime.date)
        day_key = row[0]
        if hasattr(day_key, "strftime"):
            day_key = day_key.strftime("%Y-%m-%d")
        elif day_key is not None:
            day_key = str(day_key)
        if day_key:
            sightings_by_day[day_key] = row[1]

    # Query cumulative blocklist growth
    # Get the count of IPs with first_seen_at before the start of our interval
    cursor = conn.execute(
        "SELECT COUNT(*) FROM ip_intel WHERE DATE(first_seen_at) < ?",
        (start_str,),
    )
    row = cursor.fetchone()
    cumulative_before_start = row[0] if row else 0

    # Build the arrays
    new_ips = []
    sightings = []
    blocklist_growth = []
    cumulative = cumulative_before_start

    for label in labels:
        day_new_ips = new_ips_by_day.get(label, 0)
        day_sightings = sightings_by_day.get(label, 0)

        new_ips.append(day_new_ips)
        sightings.append(day_sightings)

        # Cumulative growth: add new IPs discovered on this day
        cumulative += day_new_ips
        blocklist_growth.append(cumulative)

    return {
        "labels": labels,
        "datasets": {
            "new_ips": new_ips,
            "sightings": sightings,
            "blocklist_growth": blocklist_growth,
        },
    }


def _parse_interval(interval: str) -> int | None:
    """Parse an interval string to number of days.

    Args:
        interval: One of "7d", "30d", "90d".

    Returns:
        Number of days as int, or None if invalid.
    """
    valid_intervals = {"7d": 7, "30d": 30, "90d": 90}
    return valid_intervals.get(interval)


def get_recent_activity(conn, limit: int = 20) -> list[dict]:
    """Return the most recent intel events across all IPs.

    Fetches recent events from ip_intel_events joined with ip_intel
    to include geo_country information.

    Args:
        conn: Database connection.
        limit: Maximum number of events to return. Defaults to 20.

    Returns:
        List of dicts with keys: ip_address, event_type, event_kind,
        timestamp, node_id, geo_country, detection_rule
    """
    cursor = conn.execute(
        "SELECT e.id, e.ip_address, e.event_type, e.event_kind, e.timestamp, "
        "e.node_id, e.detection_rule, e.request_count, e.log_context, "
        "i.geo_country, n.display_name "
        "FROM ip_intel_events e "
        "LEFT JOIN ip_intel i ON e.ip_address = i.ip_address "
        "LEFT JOIN nodes n ON e.node_id = n.node_id "
        "WHERE e.event_kind = 'block' "
        "ORDER BY e.timestamp DESC LIMIT ?",
        (limit,),
    )
    rows = cursor.fetchall()

    results = []
    for row in rows:
        log_context = _parse_log_context(row[8])
        results.append(
            {
                "id": row[0],
                "ip_address": row[1],
                "event_type": row[2],
                "event_kind": row[3],
                "timestamp": row[4],
                "node_id": row[5],
                "detection_rule": row[6] or "",
                "request_count": row[7] or 0,
                "log_context": log_context,
                "geo_country": row[9] or "",
                "node_display": row[10] or "",
            }
        )

    return results


def get_event_detail(conn, event_id: int) -> dict | None:
    """Return full detail for a single ip_intel_events record.

    Args:
        conn: Database connection.
        event_id: The event ID to fetch.

    Returns:
        Dict with keys: id, ip_address, event_type, event_kind, timestamp,
        node_id, detection_rule, block_ttl_seconds, request_count, event_id,
        log_context, node_display, geo_country, or None if not found.
    """
    cursor = conn.execute(
        "SELECT e.id, e.ip_address, e.event_type, e.event_kind, e.timestamp, "
        "e.node_id, e.detection_rule, e.block_ttl_seconds, e.request_count, "
        "e.event_id, e.log_context, i.geo_country, n.display_name "
        "FROM ip_intel_events e "
        "LEFT JOIN ip_intel i ON e.ip_address = i.ip_address "
        "LEFT JOIN nodes n ON e.node_id = n.node_id "
        "WHERE e.id = ?",
        (event_id,),
    )
    row = cursor.fetchone()
    if not row:
        return None

    return {
        "id": row[0],
        "ip_address": row[1],
        "event_type": row[2],
        "event_kind": row[3],
        "timestamp": row[4],
        "node_id": row[5],
        "detection_rule": row[6] or "",
        "block_ttl_seconds": row[7] or 0,
        "request_count": row[8] or 0,
        "event_id": row[9] or "",
        "log_context": _parse_log_context(row[10]),
        "geo_country": row[11] or "",
        "node_display": row[12] or "",
    }


def get_threat_tag_distribution(conn, limit: int = 10) -> list[dict]:
    """Return distribution of threat tags by IP count.

    Parses the JSON threat_tags array from ip_intel and counts
    occurrences of each tag.

    Args:
        conn: Database connection.
        limit: Maximum number of tags to return. Defaults to 10.

    Returns:
        List of dicts with keys: tag, ip_count, sorted by ip_count descending.
    """
    # Fetch all threat_tags JSON arrays
    cursor = conn.execute("SELECT threat_tags FROM ip_intel WHERE threat_tags != '[]'")
    rows = cursor.fetchall()

    # Count tag occurrences
    tag_counts: dict[str, int] = {}
    for row in rows:
        try:
            tags = json.loads(row[0]) if row[0] else []
            for tag in tags:
                if tag and isinstance(tag, str):
                    tag_counts[tag] = tag_counts.get(tag, 0) + 1
        except (json.JSONDecodeError, TypeError):
            continue

    # Sort by count descending and limit
    sorted_tags = sorted(tag_counts.items(), key=lambda x: x[1], reverse=True)[:limit]

    return [{"tag": tag, "ip_count": count} for tag, count in sorted_tags]


def get_hourly_distribution(conn) -> list[int]:
    """Return event distribution by hour of day (0-23).

    Counts events in ip_intel_events grouped by the hour extracted
    from the timestamp.

    Args:
        conn: Database connection.

    Returns:
        List of 24 integers representing event counts for hours 0-23.
    """
    # Initialize all hours to 0
    hourly_counts = [0] * 24

    # SQLite: use strftime to extract hour
    # MySQL: use HOUR() function
    # Try SQLite syntax first, fall back to MySQL
    try:
        cursor = conn.execute(
            "SELECT CAST(strftime('%H', timestamp) AS INTEGER) as hour, COUNT(*) "
            "FROM ip_intel_events GROUP BY hour ORDER BY hour"
        )
    except Exception:
        # MySQL/MariaDB syntax
        cursor = conn.execute(
            "SELECT HOUR(timestamp) as hour, COUNT(*) "
            "FROM ip_intel_events GROUP BY hour ORDER BY hour"
        )

    for row in cursor.fetchall():
        hour = row[0]
        count = row[1]
        if hour is not None and 0 <= hour <= 23:
            hourly_counts[hour] = count

    return hourly_counts


def get_ip_version_breakdown(conn) -> dict:
    """Return count of IPv4 vs IPv6 addresses in the intel database.

    Args:
        conn: Database connection.

    Returns:
        Dict with keys: ipv4_count, ipv6_count, ipv4_percentage, ipv6_percentage
    """
    cursor = conn.execute("SELECT ip_version, COUNT(*) FROM ip_intel GROUP BY ip_version")
    rows = cursor.fetchall()

    counts = {"v4": 0, "v6": 0}
    for row in rows:
        version = row[0]
        count = row[1]
        if version in counts:
            counts[version] = count

    total = counts["v4"] + counts["v6"]
    if total > 0:
        ipv4_pct = round((counts["v4"] / total) * 100, 1)
        ipv6_pct = round((counts["v6"] / total) * 100, 1)
    else:
        ipv4_pct = 0.0
        ipv6_pct = 0.0

    return {
        "ipv4_count": counts["v4"],
        "ipv6_count": counts["v6"],
        "ipv4_percentage": ipv4_pct,
        "ipv6_percentage": ipv6_pct,
    }


def get_top_reporting_nodes(conn, limit: int = 10) -> list[dict]:
    """Return top reporting nodes by event count.

    Args:
        conn: Database connection.
        limit: Maximum number of nodes to return. Defaults to 10.

    Returns:
        List of dicts with keys: node_id, display_name, event_count
    """
    cursor = conn.execute(
        "SELECT i.node_id, n.display_name, COUNT(*) as event_count "
        "FROM ip_intel_events i "
        "LEFT JOIN nodes n ON i.node_id = n.node_id "
        "GROUP BY i.node_id "
        "ORDER BY event_count DESC LIMIT ?",
        (limit,),
    )
    rows = cursor.fetchall()

    return [
        {"node_id": row[0], "display_name": row[1] or "", "event_count": row[2]} for row in rows
    ]


def get_blocks_vs_sightings(conn) -> dict:
    """Return count of block events vs sighting events.

    Args:
        conn: Database connection.

    Returns:
        Dict with keys: blocks, sightings, blocks_percentage, sightings_percentage
    """
    cursor = conn.execute("SELECT event_kind, COUNT(*) FROM ip_intel_events GROUP BY event_kind")
    rows = cursor.fetchall()

    counts = {"block": 0, "sighting": 0}
    for row in rows:
        kind = row[0]
        count = row[1]
        if kind in counts:
            counts[kind] = count

    total = counts["block"] + counts["sighting"]
    if total > 0:
        blocks_pct = round((counts["block"] / total) * 100, 1)
        sightings_pct = round((counts["sighting"] / total) * 100, 1)
    else:
        blocks_pct = 0.0
        sightings_pct = 0.0

    return {
        "blocks": counts["block"],
        "sightings": counts["sighting"],
        "blocks_percentage": blocks_pct,
        "sightings_percentage": sightings_pct,
    }


def has_sightings_data(conn) -> bool:
    """Check if there are any sighting events in the database.

    Used to determine whether to show the sightings chart.

    Args:
        conn: Database connection.

    Returns:
        True if at least one sighting event exists, False otherwise.
    """
    cursor = conn.execute("SELECT 1 FROM ip_intel_events WHERE event_kind = 'sighting' LIMIT 1")
    return cursor.fetchone() is not None


def _parse_log_context(raw: str | list | None) -> list[dict] | None:
    """Parse a JSON log_context value from ip_intel_events into a list.

    Handles both string JSON (SQLite) and native Python types (MySQL).
    """
    if raw is None:
        return None
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        return [raw]
    if isinstance(raw, str):
        stripped = raw.strip()
        if not stripped:
            return None
        try:
            parsed = json.loads(stripped)
            if isinstance(parsed, list):
                return parsed
            if isinstance(parsed, dict):
                return [parsed]
        except (json.JSONDecodeError, TypeError):
            pass
    return None


def get_ip_events_paginated(
    conn,
    ip_address: str,
    page: int = 1,
    per_page: int = 50,
    exclude_kinds: list[str] | None = None,
) -> tuple[list[dict], int]:
    """Fetch paginated event history for a single IP.

    Returns events sorted by timestamp descending (most recent first).

    Args:
        conn: Database connection.
        ip_address: The IP address to fetch events for.
        page: Page number (minimum 1). Defaults to 1.
        per_page: Results per page (min 1, max 200). Defaults to 50.

    Returns:
        Tuple of (events_list, total_count) where events_list is a list of
        dicts with keys: id, ip_address, node_id, event_type, event_kind,
        timestamp, detection_rule, block_ttl_seconds
    """
    # Validate and clamp pagination
    if page < 1:
        page = 1
    if per_page < 1:
        per_page = 1
    elif per_page > 200:
        per_page = 200

    # Build base WHERE clause
    where_clause = "ip_address = ?"
    params: list = [ip_address]
    if exclude_kinds:
        placeholders = ",".join("?" * len(exclude_kinds))
        where_clause += f" AND event_kind NOT IN ({placeholders})"
        params.extend(exclude_kinds)

    # Get total count — now that ingestion only records NFT_ACTION for
    # blocks (not upstream detection events), we can show all events in
    # the history without risk of duplicates.
    cursor = conn.execute(
        f"SELECT COUNT(*) FROM ip_intel_events WHERE {where_clause}",
        tuple(params),
    )
    row = cursor.fetchone()
    total_count = row[0] if row else 0

    if total_count == 0:
        return ([], 0)

    # Fetch paginated events sorted by timestamp descending
    offset_val = (page - 1) * per_page
    select_params = params + [per_page, offset_val]
    cursor = conn.execute(
        "SELECT id, ip_address, node_id, event_type, event_kind, "
        "timestamp, detection_rule, block_ttl_seconds, request_count, event_id, log_context "
        f"FROM ip_intel_events WHERE {where_clause} "
        "ORDER BY timestamp DESC LIMIT ? OFFSET ?",
        tuple(select_params),
    )
    rows = cursor.fetchall()

    events = []
    node_ids_seen: set[str] = set()
    for row in rows:
        node_ids_seen.add(row[2])
        events.append(
            {
                "id": row[0],
                "ip_address": row[1],
                "node_id": row[2],
                "event_type": row[3],
                "event_kind": row[4],
                "timestamp": row[5],
                "detection_rule": row[6],
                "block_ttl_seconds": row[7],
                "request_count": row[8],
                "event_id": row[9] if len(row) > 9 else "",
                "log_context": _parse_log_context(row[10] if len(row) > 10 else None),
            }
        )

    # Resolve node_id -> display_name for friendly rendering
    node_display: dict[str, str] = {}
    if node_ids_seen:
        placeholders = ",".join("?" * len(node_ids_seen))
        node_rows = conn.execute(
            f"SELECT node_id, display_name FROM nodes WHERE node_id IN ({placeholders})",
            tuple(node_ids_seen),
        ).fetchall()
        for nr in node_rows:
            if nr["display_name"]:
                node_display[nr["node_id"]] = nr["display_name"]
    for ev in events:
        ev["node_display"] = node_display.get(ev["node_id"])

    return (events, total_count)
