"""Intelligence Database models and schema management.

Provides init_intel_db() for creating the ip_intel and ip_intel_events tables
with all required columns and indexes. Supports both SQLite and MySQL/MariaDB
backends via the existing db_compat patterns.
"""

import ipaddress
import json
import logging
import re
from datetime import UTC, datetime, timedelta

logger = logging.getLogger(__name__)

# Regex for ISO 3166-1 alpha-2 country code validation
_GEO_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")

# ── Generic/meaningless tags that should be skipped during accumulation ──
# These derived tags don't represent specific attack vectors and would pollute
# the threat_tags array with non-informative entries. (Req 20, AC 3)
GENERIC_TAGS: frozenset[str] = frozenset(
    {
        "log-match",
        "unknown",
        "other",
        "nft-action",
        "generic",
        "none",
        "unclassified",
    }
)


# ── SQLite schema for intelligence tables ────────────────────────────────

_INTEL_SCHEMA_SQLITE = """\
CREATE TABLE IF NOT EXISTS ip_intel (
    id                        INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address                TEXT    NOT NULL UNIQUE,
    ip_version                TEXT    NOT NULL CHECK(ip_version IN ('v4', 'v6')),
    first_seen_at             TEXT    NOT NULL,
    last_seen_at              TEXT    NOT NULL,
    last_blocked_at           TEXT,
    total_times_seen          INTEGER NOT NULL DEFAULT 0,
    total_times_blocked       INTEGER NOT NULL DEFAULT 0,
    total_reporting_nodes     INTEGER NOT NULL DEFAULT 0,
    total_attack_events       INTEGER NOT NULL DEFAULT 0,
    total_requests            INTEGER NOT NULL DEFAULT 0,
    last_unblocked_at         TEXT,
    block_episode_count       INTEGER NOT NULL DEFAULT 0,
    repeat_offender           INTEGER NOT NULL DEFAULT 0,
    repeat_offender_since     TEXT,
    first_reporting_node      TEXT    NOT NULL,
    most_recent_reporting_node TEXT   NOT NULL,
    reporting_node_list       TEXT    NOT NULL DEFAULT '[]',
    geo_country               TEXT,
    asn                       INTEGER,
    isp_organization          TEXT,
    reputation_score          REAL,
    threat_tags               TEXT    NOT NULL DEFAULT '[]'
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_ip_intel_address ON ip_intel(ip_address);
CREATE INDEX IF NOT EXISTS idx_ip_intel_last_seen ON ip_intel(last_seen_at);
CREATE INDEX IF NOT EXISTS idx_ip_intel_times_seen ON ip_intel(total_times_seen);
CREATE INDEX IF NOT EXISTS idx_ip_intel_repeat ON ip_intel(repeat_offender);
CREATE INDEX IF NOT EXISTS idx_ip_intel_geo ON ip_intel(geo_country);

CREATE TABLE IF NOT EXISTS ip_intel_events (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address        TEXT    NOT NULL,
    node_id           TEXT    NOT NULL,
    event_type        TEXT    NOT NULL,
    event_kind        TEXT    NOT NULL CHECK(event_kind IN ('sighting', 'block', 'fleet_block')),
    timestamp         TEXT    NOT NULL,
    detection_rule    TEXT    NOT NULL DEFAULT '',
    block_ttl_seconds INTEGER NOT NULL DEFAULT 0,
    request_count     INTEGER NOT NULL DEFAULT 1,
    server_received_at TEXT   NOT NULL DEFAULT '',
    event_id          TEXT    NOT NULL DEFAULT '',
    log_context       TEXT
);

CREATE INDEX IF NOT EXISTS idx_ip_intel_events_ip ON ip_intel_events(ip_address);
CREATE INDEX IF NOT EXISTS idx_ip_intel_events_ts ON ip_intel_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_ip_intel_events_ip_ts ON ip_intel_events(ip_address, timestamp);
"""


# ── MySQL/MariaDB schema for intelligence tables ─────────────────────────

_INTEL_SCHEMA_MYSQL = [
    """CREATE TABLE IF NOT EXISTS ip_intel (
    id                        INT AUTO_INCREMENT PRIMARY KEY,
    ip_address                VARCHAR(45) NOT NULL UNIQUE,
    ip_version                VARCHAR(2) NOT NULL,
    first_seen_at             VARCHAR(255) NOT NULL,
    last_seen_at              VARCHAR(255) NOT NULL,
    last_blocked_at           VARCHAR(255),
    total_times_seen          INT NOT NULL DEFAULT 0,
    total_times_blocked       INT NOT NULL DEFAULT 0,
    total_reporting_nodes     INT NOT NULL DEFAULT 0,
    total_attack_events       INT NOT NULL DEFAULT 0,
    total_requests            INT NOT NULL DEFAULT 0,
    last_unblocked_at          VARCHAR(255),
    block_episode_count        INT NOT NULL DEFAULT 0,
    repeat_offender            INT NOT NULL DEFAULT 0,
    repeat_offender_since      VARCHAR(255),
    first_reporting_node      VARCHAR(128) NOT NULL,
    most_recent_reporting_node VARCHAR(128) NOT NULL,
    reporting_node_list       TEXT NOT NULL,
    geo_country               VARCHAR(2),
    asn                       BIGINT,
    isp_organization          VARCHAR(256),
    reputation_score          DOUBLE,
    threat_tags               TEXT NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",
    """CREATE UNIQUE INDEX idx_ip_intel_address ON ip_intel(ip_address)""",
    """CREATE INDEX idx_ip_intel_last_seen ON ip_intel(last_seen_at)""",
    """CREATE INDEX idx_ip_intel_times_seen ON ip_intel(total_times_seen)""",
    """CREATE INDEX idx_ip_intel_repeat ON ip_intel(repeat_offender)""",
    """CREATE INDEX idx_ip_intel_geo ON ip_intel(geo_country)""",
    """CREATE TABLE IF NOT EXISTS ip_intel_events (
    id                INT AUTO_INCREMENT PRIMARY KEY,
    ip_address        VARCHAR(45) NOT NULL,
    node_id           VARCHAR(128) NOT NULL,
    event_type        VARCHAR(64) NOT NULL,
    event_kind        VARCHAR(16) NOT NULL,
    timestamp         VARCHAR(255) NOT NULL,
    detection_rule    VARCHAR(128) NOT NULL DEFAULT '',
    block_ttl_seconds INT NOT NULL DEFAULT 0,
    request_count     INT NOT NULL DEFAULT 1,
    server_received_at VARCHAR(255) NOT NULL DEFAULT '',
    event_id          VARCHAR(255) NOT NULL DEFAULT '',
    log_context       TEXT
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""",
    """CREATE INDEX idx_ip_intel_events_ip ON ip_intel_events(ip_address)""",
    """CREATE INDEX idx_ip_intel_events_ts ON ip_intel_events(timestamp)""",
    """CREATE INDEX idx_ip_intel_events_ip_ts ON ip_intel_events(ip_address, timestamp)""",
]


def init_intel_db(conn, db_type: str = "sqlite") -> None:
    """Create intelligence tables and indexes if they don't exist.

    Supports both SQLite (using executescript with IF NOT EXISTS) and
    MySQL/MariaDB (executing statements individually, ignoring duplicate
    index errors for idempotency).

    Also runs schema migrations to add columns that may be missing from
    tables created by earlier versions of the code.

    Args:
        conn: Database connection (sqlite3.Connection or MySQLConnectionWrapper).
        db_type: The database backend type ('sqlite', 'mysql', or 'mariadb').
            Defaults to 'sqlite'.
    """
    if db_type == "sqlite":
        conn.executescript(_INTEL_SCHEMA_SQLITE)
        conn.commit()

        # ── Schema migrations: add columns missing from older SQLite tables ──
        try:
            conn.execute("ALTER TABLE ip_intel_events ADD COLUMN event_id TEXT NOT NULL DEFAULT ''")
            conn.commit()
        except Exception:
            pass  # column already exists
        try:
            conn.execute("ALTER TABLE ip_intel_events ADD COLUMN log_context TEXT")
            conn.commit()
        except Exception:
            pass  # column already exists
    else:
        # MySQL/MariaDB — execute each statement individually
        # Ignore error 1061 (duplicate key name) for idempotent index creation
        import mysql.connector.errors

        for stmt in _INTEL_SCHEMA_MYSQL:
            try:
                conn.execute(stmt)
            except mysql.connector.errors.ProgrammingError as e:
                # Error 1061 = Duplicate key name (index already exists)
                if e.errno == 1061:
                    pass
                else:
                    raise
        conn.commit()

        # ── Schema migrations: add columns missing from older table versions ──
        _migrate_mysql_schema(conn)

    logger.info("Intelligence database tables initialized (backend=%s)", db_type)


# ── MySQL schema migration for existing tables ───────────────────────────

_MYSQL_MIGRATIONS = [
    # ip_intel table — columns added in the intel-event-ingestion-pipeline spec
    "ALTER TABLE ip_intel ADD COLUMN total_requests INT NOT NULL DEFAULT 0",
    "ALTER TABLE ip_intel ADD COLUMN last_unblocked_at VARCHAR(255) DEFAULT NULL",
    "ALTER TABLE ip_intel ADD COLUMN block_episode_count INT NOT NULL DEFAULT 0",
    "ALTER TABLE ip_intel ADD COLUMN repeat_offender_since VARCHAR(255) DEFAULT NULL",
    # ip_intel_events table — columns added in the intel-event-ingestion-pipeline spec
    "ALTER TABLE ip_intel_events ADD COLUMN request_count INT NOT NULL DEFAULT 1",
    "ALTER TABLE ip_intel_events ADD COLUMN server_received_at VARCHAR(255) NOT NULL DEFAULT ''",
    # Widen event_kind from varchar(10) to varchar(16) to fit 'fleet_block' (11 chars)
    "ALTER TABLE ip_intel_events MODIFY COLUMN event_kind VARCHAR(16) NOT NULL",
    # Add event_id to ip_intel_events for traceability back to the originating SecurityEvent
    "ALTER TABLE ip_intel_events ADD COLUMN event_id VARCHAR(255) NOT NULL DEFAULT ''",
    # Add log_context to ip_intel_events for long-term log line storage independent of events table
    "ALTER TABLE ip_intel_events ADD COLUMN log_context TEXT",
]


def _migrate_mysql_schema(conn) -> None:
    """Add missing columns to existing MySQL/MariaDB tables.

    Runs ALTER TABLE ADD COLUMN statements for columns that may not exist
    in tables created by earlier versions of the code. Each statement is
    executed independently — errors for duplicate columns are caught and
    silently ignored, making this fully idempotent.
    """
    for alter_stmt in _MYSQL_MIGRATIONS:
        try:
            conn.execute(alter_stmt)
            conn.commit()
        except Exception as e:
            err_str = str(e).lower()
            # MySQL/MariaDB: "Duplicate column name" (error 1060)
            if "duplicate column" in err_str or "1060" in err_str:
                pass
            else:
                logger.warning("Migration failed: %s — %s", alter_stmt, e)

    logger.info("MySQL/MariaDB schema migrations applied")


# ── Allowed sort columns (allowlist to prevent SQL injection) ────────────

_ALLOWED_SORT_COLUMNS = {
    "last_seen_at",
    "total_times_seen",
    "total_times_blocked",
    "total_reporting_nodes",
    "reputation_score",
    "block_episode_count",
    "total_requests",
}


def search_ip_records(
    conn,
    filters: dict,
    page: int = 1,
    per_page: int = 50,
    sort_by: str = "last_seen_at",
    sort_order: str = "desc",
) -> tuple[list[dict], int]:
    """Search IP records with filtering, pagination, and sorting.

    Args:
        conn: Database connection (sqlite3.Connection or MySQLConnectionWrapper).
        filters: Dictionary of filter criteria. Supported keys:
            - event_type: Filter by event type (joins ip_intel_events).
            - threat_tag: Filter by threat tag (JSON contains pattern).
            - geo_country: Filter by ISO 3166-1 alpha-2 country code.
            - repeat_offender: Filter by repeat offender flag (bool).
            - q: Search query — prefix match on ip_address.
        page: Page number (minimum 1). Defaults to 1.
        per_page: Results per page (min 1, max 200). Defaults to 50.
        sort_by: Column to sort by. Must be one of: last_seen_at,
            total_times_seen, total_times_blocked, total_reporting_nodes.
            Defaults to 'last_seen_at'.
        sort_order: Sort direction ('asc' or 'desc'). Defaults to 'desc'.

    Returns:
        A tuple of (records_list, total_count) where records_list is a list
        of dicts representing IP records and total_count is the total number
        of matching records (for pagination metadata).
    """
    # ── Validate and clamp pagination parameters ─────────────────────────
    if page < 1:
        page = 1
    if per_page < 1:
        per_page = 1
    elif per_page > 200:
        per_page = 200

    # ── Validate sort parameters ─────────────────────────────────────────
    if sort_by not in _ALLOWED_SORT_COLUMNS:
        sort_by = "last_seen_at"
    if sort_order.lower() not in ("asc", "desc"):
        sort_order = "desc"
    else:
        sort_order = sort_order.lower()

    # ── Build query components ───────────────────────────────────────────
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

    from_clause = "FROM ip_intel"
    where_clauses = []
    params = []
    needs_join = False

    # ── Apply filters ────────────────────────────────────────────────────
    event_type = filters.get("event_type")
    if event_type:
        needs_join = True
        where_clauses.append("ip_intel_events.event_type = ?")
        params.append(event_type)

    threat_tag = filters.get("threat_tag")
    if threat_tag:
        # Use LIKE with JSON contains pattern for SQLite compatibility
        where_clauses.append("ip_intel.threat_tags LIKE ?")
        params.append(f'%"{threat_tag}"%')

    geo_country = filters.get("geo_country")
    if geo_country:
        where_clauses.append("ip_intel.geo_country = ?")
        params.append(geo_country)

    repeat_offender = filters.get("repeat_offender")
    if repeat_offender is not None:
        where_clauses.append("ip_intel.repeat_offender = ?")
        params.append(1 if repeat_offender else 0)

    q = filters.get("q")
    if q:
        like_pattern = q.replace("*", "%").replace("?", "_")
        if "%" not in like_pattern and "_" not in like_pattern:
            like_pattern += "%"
        where_clauses.append("ip_intel.ip_address LIKE ?")
        params.append(like_pattern)

    # ── Build JOIN clause if needed ──────────────────────────────────────
    if needs_join:
        from_clause = (
            "FROM ip_intel JOIN ip_intel_events ON ip_intel.ip_address = ip_intel_events.ip_address"
        )

    # ── Assemble WHERE clause ────────────────────────────────────────────
    where_sql = ""
    if where_clauses:
        where_sql = "WHERE " + " AND ".join(where_clauses)

    # ── Count query (total matching records) ─────────────────────────────
    if needs_join:
        count_sql = f"SELECT COUNT(DISTINCT ip_intel.id) {from_clause} {where_sql}"
    else:
        count_sql = f"SELECT COUNT(*) {from_clause} {where_sql}"

    cursor = conn.execute(count_sql, params)
    row = cursor.fetchone()
    total_count = row[0] if row else 0

    if total_count == 0:
        return ([], 0)

    # ── Data query with sorting and pagination ───────────────────────────
    distinct_clause = "DISTINCT " if needs_join else ""
    offset = (page - 1) * per_page

    data_sql = (
        f"SELECT {distinct_clause}{select_columns} {from_clause} {where_sql} "
        f"ORDER BY ip_intel.{sort_by} {sort_order} "
        f"LIMIT ? OFFSET ?"
    )
    data_params = params + [per_page, offset]

    cursor = conn.execute(data_sql, data_params)
    rows = cursor.fetchall()

    # ── Parse rows into dicts ────────────────────────────────────────────
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

    records = []
    for row in rows:
        record = {}
        for i, col_name in enumerate(column_names):
            value = row[i]
            # Parse JSON fields
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
            # Convert repeat_offender from 0/1 to boolean
            elif col_name == "repeat_offender":
                value = bool(value)
            record[col_name] = value
        records.append(record)

    return (records, total_count)


def get_ip_record(conn, ip_address: str) -> dict | None:
    """Fetch a single IP record by address.

    Retrieves the row from ip_intel for the given IP address, parses JSON
    fields (reporting_node_list, threat_tags), and returns a complete dict
    with all fields. Returns None if the IP is not found.

    Args:
        conn: Database connection (sqlite3.Connection or MySQLConnectionWrapper).
        ip_address: The IPv4 or IPv6 address to look up.

    Returns:
        A dict containing all IP record fields, or None if not found.
    """
    cursor = conn.execute(
        "SELECT id, ip_address, ip_version, first_seen_at, last_seen_at, "
        "last_blocked_at, total_times_seen, total_times_blocked, "
        "total_reporting_nodes, total_attack_events, repeat_offender, "
        "first_reporting_node, most_recent_reporting_node, "
        "reporting_node_list, geo_country, asn, isp_organization, "
        "reputation_score, threat_tags "
        "FROM ip_intel WHERE ip_address = ?",
        (ip_address,),
    )
    row = cursor.fetchone()
    if row is None:
        return None

    # Build the record dict from the row tuple
    record = {
        "id": row[0],
        "ip_address": row[1],
        "ip_version": row[2],
        "first_seen_at": row[3],
        "last_seen_at": row[4],
        "last_blocked_at": row[5],
        "total_times_seen": row[6],
        "total_times_blocked": row[7],
        "total_reporting_nodes": row[8],
        "total_attack_events": row[9],
        "repeat_offender": bool(row[10]),
        "first_reporting_node": row[11],
        "most_recent_reporting_node": row[12],
        "reporting_node_list": json.loads(row[13]),
        "geo_country": row[14],
        "asn": row[15],
        "isp_organization": row[16],
        "reputation_score": row[17],
        "threat_tags": json.loads(row[18]),
    }
    return record


def compute_recency(conn, ip_address: str) -> dict:
    """Compute rolling-window recency counters from ip_intel_events timestamps.

    Calculates the number of events for the given IP address within the last
    24 hours, 7 days, and 30 days from the current UTC time. Uses
    SUM(CASE WHEN ...) pattern for SQLite compatibility (SQLite does not
    support the FILTER clause).

    Args:
        conn: Database connection (sqlite3.Connection or MySQLConnectionWrapper).
        ip_address: The IPv4 or IPv6 address to compute recency for.

    Returns:
        A dict with keys: times_seen_last_24h, times_seen_last_7d,
        times_seen_last_30d. All values are integers (0 if no events found).
    """
    now = datetime.now(UTC)
    boundary_24h = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S")
    boundary_7d = (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S")
    boundary_30d = (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S")

    cursor = conn.execute(
        "SELECT "
        "SUM(CASE WHEN timestamp >= ? THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN timestamp >= ? THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN timestamp >= ? THEN 1 ELSE 0 END) "
        "FROM ip_intel_events WHERE ip_address = ? AND event_kind IN ('block', 'sighting')",
        (boundary_24h, boundary_7d, boundary_30d, ip_address),
    )
    row = cursor.fetchone()

    # SUM returns NULL when there are no matching rows; coerce to 0
    return {
        "times_seen_last_24h": row[0] or 0,
        "times_seen_last_7d": row[1] or 0,
        "times_seen_last_30d": row[2] or 0,
    }


def _detect_ip_version(ip_address: str) -> str:
    """Detect whether an IP address is IPv4 or IPv6.

    Args:
        ip_address: A valid IPv4 or IPv6 address string.

    Returns:
        'v4' for IPv4 addresses, 'v6' for IPv6 addresses.
    """
    addr = ipaddress.ip_address(ip_address)
    return "v4" if addr.version == 4 else "v6"


def _validate_geo_country(value) -> str | None:
    """Validate a geo_country value against ISO 3166-1 alpha-2 format.

    Returns the value if valid, None otherwise.
    """
    if value is None or not isinstance(value, str):
        return None
    if _GEO_COUNTRY_RE.match(value):
        return value
    return None


def upsert_ip_record(
    conn,
    ip_address: str,
    node_id: str,
    event_type: str,
    timestamp: str,
    is_block: bool,
    metadata: dict | None,
    request_count: int = 1,
    event_id: str = "",
    log_context: str | None = None,
) -> dict:
    """Atomic upsert of an IP intelligence record.

    Creates a new IP record if none exists for the given address, or updates
    the existing record with new counters, timestamps, and metadata. All
    modifications are wrapped in a single transaction.

    Args:
        conn: Database connection (sqlite3.Connection or MySQLConnectionWrapper).
        ip_address: The IPv4 or IPv6 address string.
        node_id: The reporting node identifier.
        event_type: The type of event (e.g., 'ssh_bruteforce').
        timestamp: ISO-8601 UTC timestamp of the event.
        is_block: True if this is a block event, False for a sighting.
        metadata: Optional dict with enrichment data (geo_country, asn,
            isp_organization, threat_tag, detection_rule, block_ttl_seconds).
        request_count: Number of raw requests that triggered this event.
            Defaults to 1 if not provided.
        event_id: The originating SecurityEvent UUID for traceability.
        log_context: JSON array of matching log lines (only for block events).

    Returns:
        A dict representing the updated IP record with all fields.
    """
    if metadata is None:
        metadata = {}

    ip_version = _detect_ip_version(ip_address)
    event_kind = "block" if is_block else "sighting"

    # ── Step 1: Atomic INSERT to handle first-observation race ──
    # This ensures exactly one record is created even under concurrent access.
    # Detect backend: MySQLConnectionWrapper vs sqlite3.Connection
    from .db_compat import MySQLConnectionWrapper as _MySQLConn

    _is_mysql = isinstance(conn, _MySQLConn)

    # ── Transaction boundary for reporting_node_list read-modify-write ──
    # The entire upsert (INSERT → SELECT → UPDATE → INSERT event → COMMIT)
    # must execute within a single transaction to prevent lost updates to
    # reporting_node_list under concurrent access from multiple nodes.
    #
    # For SQLite: implicit transaction via autocommit=False + WAL mode is
    # sufficient because SQLite serializes all write transactions.
    #
    # For MySQL: we start an explicit transaction with READ COMMITTED
    # isolation level (or higher) to ensure the SELECT in Step 2 reads
    # committed data and the subsequent UPDATE is not lost when concurrent
    # upserts target the same IP address.
    if _is_mysql:
        conn.start_transaction(isolation_level="READ COMMITTED")

    if _is_mysql:
        # MySQL: Use INSERT ... ON DUPLICATE KEY UPDATE for atomic upsert.
        # If the row already exists, this atomically updates last_seen_at
        # without a race window between INSERT and UPDATE.
        conn.execute(
            "INSERT INTO ip_intel "
            "(ip_address, ip_version, first_seen_at, last_seen_at, "
            "total_times_seen, total_times_blocked, total_reporting_nodes, "
            "total_attack_events, total_requests, repeat_offender, first_reporting_node, "
            "most_recent_reporting_node, reporting_node_list, threat_tags) "
            "VALUES (?, ?, ?, ?, 0, 0, 0, 0, 0, 0, ?, ?, '[]', '[]') "
            "ON DUPLICATE KEY UPDATE last_seen_at = VALUES(last_seen_at)",
            (ip_address, ip_version, timestamp, timestamp, node_id, node_id),
        )
    else:
        # SQLite: Use INSERT OR IGNORE + separate UPDATE pattern.
        conn.execute(
            "INSERT OR IGNORE INTO ip_intel "
            "(ip_address, ip_version, first_seen_at, last_seen_at, "
            "total_times_seen, total_times_blocked, total_reporting_nodes, "
            "total_attack_events, total_requests, repeat_offender, first_reporting_node, "
            "most_recent_reporting_node, reporting_node_list, threat_tags) "
            "VALUES (?, ?, ?, ?, 0, 0, 0, 0, 0, 0, ?, ?, '[]', '[]')",
            (ip_address, ip_version, timestamp, timestamp, node_id, node_id),
        )

    # ── Step 2: Fetch current record state for list/tag management ──
    row = conn.execute(
        "SELECT reporting_node_list, threat_tags, total_times_seen, "
        "total_times_blocked, total_reporting_nodes, total_attack_events, "
        "repeat_offender, geo_country, asn, isp_organization, "
        "last_unblocked_at, block_episode_count, last_blocked_at, total_requests "
        "FROM ip_intel WHERE ip_address = ?",
        (ip_address,),
    ).fetchone()

    reporting_node_list = json.loads(row["reporting_node_list"])
    threat_tags = json.loads(row["threat_tags"])
    current_times_seen = row["total_times_seen"]
    current_times_blocked = row["total_times_blocked"]
    current_reporting_nodes = row["total_reporting_nodes"]
    current_attack_events = row["total_attack_events"]
    current_repeat_offender = row["repeat_offender"]
    current_geo_country = row["geo_country"]
    current_asn = row["asn"]
    current_isp_org = row["isp_organization"]
    current_last_unblocked_at = row["last_unblocked_at"]
    current_block_episode_count = row["block_episode_count"]
    current_last_blocked_at = row["last_blocked_at"]
    current_total_requests = row["total_requests"]

    # ── Step 3: Manage reporting_node_list (within transaction) ──
    # This read-modify-write is protected by the enclosing transaction:
    # - Read: reporting_node_list fetched in Step 2
    # - Modify: append node_id if not already present (below)
    # - Write: UPDATE in Step 8 writes the modified list back
    # The transaction (implicit for SQLite, explicit for MySQL) ensures
    # atomicity — no concurrent upsert can interleave between the read
    # and write, preventing lost node additions.
    # Only increment total_reporting_nodes when a new node is actually added
    node_is_new = node_id not in reporting_node_list
    node_was_added = False
    if node_is_new and len(reporting_node_list) < 1000:
        reporting_node_list.append(node_id)
        node_was_added = True

    new_total_reporting_nodes = current_reporting_nodes + (1 if node_was_added else 0)

    # ── Step 4: Compute counter increments ──
    new_times_seen = current_times_seen + 1
    new_times_blocked = current_times_blocked + (1 if is_block else 0)
    new_attack_events = current_attack_events + (1 if is_block else 0)
    new_total_requests = current_total_requests + request_count

    # ── Step 5: Handle threat_tag accumulation ──
    # Derive threat_tag from metadata.threat_tag first, fall back to detection_rule
    threat_tag = metadata.get("threat_tag")
    if not threat_tag or not isinstance(threat_tag, str):
        threat_tag = metadata.get("detection_rule")
    # Accumulate into threat_tags array only if non-empty, string, not generic,
    # and not already present (Req 20, AC 3: skip generic/meaningless tags)
    if (
        threat_tag
        and isinstance(threat_tag, str)
        and threat_tag.strip()
        and threat_tag not in GENERIC_TAGS
        and threat_tag not in threat_tags
        and len(threat_tags) < 50
    ):
        threat_tags.append(threat_tag)

    # ── Step 6: Handle enrichment field updates ──
    # geo_country: validate ISO 3166-1 alpha-2 format, discard invalid
    new_geo_country = current_geo_country
    geo_value = metadata.get("geo_country")
    validated_geo = _validate_geo_country(geo_value)
    if validated_geo is not None:
        new_geo_country = validated_geo

    # asn: validate range 1–4294967295
    new_asn = current_asn
    asn_value = metadata.get("asn")
    if asn_value is not None and isinstance(asn_value, int) and 1 <= asn_value <= 4294967295:
        new_asn = asn_value

    # isp_organization: truncate to 256 chars
    new_isp_org = current_isp_org
    isp_value = metadata.get("isp_organization")
    if isp_value is not None and isinstance(isp_value, str):
        new_isp_org = isp_value[:256]

    # ── Step 7: Apply block episode detection logic ──
    # Detect new blocking episodes: a new episode starts when a block event
    # occurs after an unblock (last_unblocked_at is set and >= last_blocked_at).
    # The first block event ever sets block_episode_count = 1.
    new_block_episode_count = current_block_episode_count
    if is_block:
        if current_block_episode_count == 0:
            # First block ever for this IP — start first episode
            new_block_episode_count = 1
        elif current_last_unblocked_at is not None and (
            current_last_blocked_at is None or current_last_unblocked_at >= current_last_blocked_at
        ):
            # IP was unblocked after the last block — new episode begins
            new_block_episode_count = current_block_episode_count + 1

    # ── Step 7b: Apply repeat_offender logic ──
    # repeat_offender is set to 1 IFF the IP has been blocked in >= 2 distinct
    # episodes (block → unblock → block). Many blocks within a single episode
    # do NOT qualify. Once set to true (1), never revert to false (0).
    new_repeat_offender = current_repeat_offender
    repeat_offender_since_value = None
    if not current_repeat_offender:
        if new_block_episode_count >= 2:
            new_repeat_offender = 1
            repeat_offender_since_value = timestamp

    # ── Step 8: Build and execute the UPDATE statement ──
    update_fields = [
        "last_seen_at = ?",
        "total_times_seen = ?",
        "total_times_blocked = ?",
        "total_reporting_nodes = ?",
        "total_attack_events = ?",
        "total_requests = ?",
        "repeat_offender = ?",
        "most_recent_reporting_node = ?",
        "reporting_node_list = ?",
        "threat_tags = ?",
        "geo_country = ?",
        "asn = ?",
        "isp_organization = ?",
        "block_episode_count = ?",
    ]
    update_params = [
        timestamp,
        new_times_seen,
        new_times_blocked,
        new_total_reporting_nodes,
        new_attack_events,
        new_total_requests,
        new_repeat_offender,
        node_id,
        json.dumps(reporting_node_list),
        json.dumps(threat_tags),
        new_geo_country,
        new_asn,
        new_isp_org,
        new_block_episode_count,
    ]

    # Update last_blocked_at only for block events
    if is_block:
        update_fields.append("last_blocked_at = ?")
        update_params.append(timestamp)

    # Record repeat_offender_since when transitioning from 0 to 1
    if repeat_offender_since_value is not None:
        update_fields.append("repeat_offender_since = ?")
        update_params.append(repeat_offender_since_value)

    update_sql = "UPDATE ip_intel SET " + ", ".join(update_fields) + " WHERE ip_address = ?"
    update_params.append(ip_address)

    conn.execute(update_sql, tuple(update_params))

    # ── Step 9: Insert event row into ip_intel_events for recency tracking ──
    detection_rule = metadata.get("detection_rule", "") if is_block else ""
    block_ttl_seconds = metadata.get("block_ttl_seconds", 0) if is_block else 0
    # Ensure block_ttl_seconds is an int
    if not isinstance(block_ttl_seconds, int):
        block_ttl_seconds = 0

    server_received_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S")

    conn.execute(
        "INSERT INTO ip_intel_events "
        "(ip_address, node_id, event_type, event_kind, timestamp, "
        "detection_rule, block_ttl_seconds, request_count, server_received_at, "
        "event_id, log_context) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            ip_address,
            node_id,
            event_type,
            event_kind,
            timestamp,
            detection_rule if isinstance(detection_rule, str) else "",
            block_ttl_seconds,
            request_count,
            server_received_at,
            event_id or "",
            log_context,
        ),
    )

    # ── Step 10: Commit the transaction ──
    conn.commit()

    # ── Return the updated record ──
    updated_row = conn.execute(
        "SELECT * FROM ip_intel WHERE ip_address = ?",
        (ip_address,),
    ).fetchone()

    return {
        "id": updated_row["id"],
        "ip_address": updated_row["ip_address"],
        "ip_version": updated_row["ip_version"],
        "first_seen_at": updated_row["first_seen_at"],
        "last_seen_at": updated_row["last_seen_at"],
        "last_blocked_at": updated_row["last_blocked_at"],
        "total_times_seen": updated_row["total_times_seen"],
        "total_times_blocked": updated_row["total_times_blocked"],
        "total_reporting_nodes": updated_row["total_reporting_nodes"],
        "total_attack_events": updated_row["total_attack_events"],
        "total_requests": updated_row["total_requests"],
        "repeat_offender": bool(updated_row["repeat_offender"]),
        "first_reporting_node": updated_row["first_reporting_node"],
        "most_recent_reporting_node": updated_row["most_recent_reporting_node"],
        "reporting_node_list": json.loads(updated_row["reporting_node_list"]),
        "threat_tags": json.loads(updated_row["threat_tags"]),
        "geo_country": updated_row["geo_country"],
        "asn": updated_row["asn"],
        "isp_organization": updated_row["isp_organization"],
        "reputation_score": updated_row["reputation_score"],
        "block_episode_count": updated_row["block_episode_count"],
        "last_unblocked_at": updated_row["last_unblocked_at"],
        "repeat_offender_since": updated_row["repeat_offender_since"],
    }


def process_fleet_block_event(
    conn,
    ip_address: str,
    node_id: str,
    timestamp: str,
    event_type: str = "NFT_ACTION",
    event_id: str = "",
) -> dict:
    """Process a fleet block event for operational visibility.

    Inserts a row into ip_intel_events with event_kind="fleet_block" to record
    that a node applied a preemptive block via fleet sync. Creates the ip_intel
    record if the IP is not yet tracked (INSERT OR IGNORE), but does NOT
    increment any counters (total_times_seen, total_times_blocked) and does NOT
    modify reporting_node_list or total_reporting_nodes.

    This ensures fleet-propagated blocks are visible on the IP Detail page
    without inflating threat counters.

    Args:
        conn: Database connection (sqlite3.Connection or MySQLConnectionWrapper).
        ip_address: The IPv4 or IPv6 address string.
        node_id: The node that applied the preemptive block.
        timestamp: ISO-8601 UTC timestamp of the fleet block event.
        event_type: The original event type (default "NFT_ACTION").
        event_id: The originating SecurityEvent UUID for traceability.

    Returns:
        A dict with keys: status, ip_address, event_kind.
    """
    ip_version = _detect_ip_version(ip_address)

    # ── Step 1: INSERT OR IGNORE to create ip_intel record if IP not yet tracked ──
    from .db_compat import MySQLConnectionWrapper as _MySQLConn

    _is_mysql = isinstance(conn, _MySQLConn)
    _ignore_prefix = "INSERT IGNORE" if _is_mysql else "INSERT OR IGNORE"
    conn.execute(
        f"{_ignore_prefix} INTO ip_intel "
        "(ip_address, ip_version, first_seen_at, last_seen_at, "
        "total_times_seen, total_times_blocked, total_reporting_nodes, "
        "total_attack_events, total_requests, repeat_offender, first_reporting_node, "
        "most_recent_reporting_node, reporting_node_list, threat_tags) "
        "VALUES (?, ?, ?, ?, 0, 0, 0, 0, 0, 0, ?, ?, '[]', '[]')",
        (ip_address, ip_version, timestamp, timestamp, node_id, node_id),
    )

    # ── Step 2: Insert event row into ip_intel_events with event_kind="fleet_block" ──
    # Do NOT increment total_times_seen, total_times_blocked, or total_requests
    # Do NOT modify reporting_node_list or total_reporting_nodes
    server_received_at = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%S")

    conn.execute(
        "INSERT INTO ip_intel_events "
        "(ip_address, node_id, event_type, event_kind, timestamp, "
        "detection_rule, block_ttl_seconds, request_count, server_received_at, "
        "event_id, log_context) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            ip_address,
            node_id,
            event_type,
            "fleet_block",
            timestamp,
            "",
            0,
            0,
            server_received_at,
            event_id or "",
            None,
        ),
    )

    # ── Step 3: Commit the transaction ──
    conn.commit()

    return {
        "status": "accepted",
        "ip_address": ip_address,
        "event_kind": "fleet_block",
    }


def get_attack_vectors(conn, ip_address: str) -> list[dict]:
    """Query distinct detection rules and their fire counts for an IP address.

    Returns each distinct detection_rule that triggered for the IP along with
    the count of times it fired, considering only block and sighting events.
    Empty or NULL detection_rule values are excluded.

    Used by the IP Detail page to render the "Attack Vectors" summary section
    showing multi-vector attack visibility.

    Args:
        conn: Database connection (sqlite3.Connection or MySQLConnectionWrapper).
        ip_address: The IPv4 or IPv6 address to query attack vectors for.

    Returns:
        A list of dicts, each with keys: detection_rule, fire_count.
        Ordered by fire_count descending (most frequent rule first).
        Empty list if no qualifying events exist for the IP.
    """
    cursor = conn.execute(
        "SELECT detection_rule, COUNT(*) as fire_count "
        "FROM ip_intel_events "
        "WHERE ip_address = ? AND event_kind IN ('block', 'sighting') "
        "AND detection_rule IS NOT NULL AND detection_rule != '' "
        "GROUP BY detection_rule "
        "ORDER BY fire_count DESC",
        (ip_address,),
    )
    rows = cursor.fetchall()

    results = []
    for row in rows:
        results.append(
            {
                "detection_rule": row[0]
                if isinstance(row, (list, tuple))
                else row["detection_rule"],
                "fire_count": row[1] if isinstance(row, (list, tuple)) else row["fire_count"],
            }
        )

    return results


def get_primary_threat_tag(conn, ip_address: str) -> str | None:
    """Determine the most frequent threat tag for an IP from event history.

    Queries ip_intel_events to find the detection_rule that fired most often
    for the given IP (considering only block and sighting events with a
    non-empty detection_rule). Returns the most frequent rule as the primary
    threat tag.

    If no detection_rule events exist, falls back to the first element of
    the ip_intel threat_tags array.

    Used by the Search Results page to display the "Primary Threat" column
    per Requirement 13, AC 6.

    Args:
        conn: Database connection (sqlite3.Connection or MySQLConnectionWrapper).
        ip_address: The IPv4 or IPv6 address to determine primary threat for.

    Returns:
        The most frequent threat tag string, or None if no tags exist.
    """
    # Query the most frequent detection_rule from events
    cursor = conn.execute(
        "SELECT detection_rule, COUNT(*) as fire_count "
        "FROM ip_intel_events "
        "WHERE ip_address = ? AND event_kind IN ('block', 'sighting') "
        "AND detection_rule IS NOT NULL AND detection_rule != '' "
        "GROUP BY detection_rule "
        "ORDER BY fire_count DESC "
        "LIMIT 1",
        (ip_address,),
    )
    row = cursor.fetchone()
    if row:
        return row[0] if isinstance(row, (list, tuple)) else row["detection_rule"]

    # Fallback: use first element of threat_tags array from ip_intel
    cursor = conn.execute(
        "SELECT threat_tags FROM ip_intel WHERE ip_address = ?",
        (ip_address,),
    )
    row = cursor.fetchone()
    if row:
        tags_raw = row[0] if isinstance(row, (list, tuple)) else row["threat_tags"]
        try:
            tags = json.loads(tags_raw) if tags_raw else []
        except (json.JSONDecodeError, TypeError):
            tags = []
        if tags:
            return tags[0]

    return None


def _normalize_fleet_ts(ts):
    """Convert a timestamp value to a consistent ISO-8601 string.

    Handles MySQL DATETIME strings (space-separated), ISO-8601 (T-separated),
    and Unix epoch floats/ints. Always returns an ISO-8601 string or "—".
    """
    if ts is None or ts == "" or ts == "—":
        return "—"
    from datetime import datetime

    if isinstance(ts, (int, float)):
        try:
            return datetime.fromtimestamp(ts, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (OSError, ValueError, OverflowError):
            return "—"
    if isinstance(ts, str):
        ts_str = ts.strip()
        if not ts_str:
            return "—"
        # Already ISO-8601?
        if "T" in ts_str:
            if not ts_str.endswith("Z"):
                ts_str += "Z"
            return ts_str
        # MySQL format: "2026-05-24 21:25:08"
        if " " in ts_str:
            ts_str = ts_str.replace(" ", "T") + "Z"
            return ts_str
        # Try parsing as epoch string
        try:
            return datetime.fromtimestamp(float(ts_str), tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        except (ValueError, OSError, OverflowError):
            pass
        return ts_str + "Z" if not ts_str.endswith("Z") else ts_str
    return str(ts)


def get_fleet_blocks(conn, ip_address: str) -> list[dict]:
    """Query nodes that currently have an active fleet block for a given IP.

    Joins fleet_block_reports with the active fleet_blocks record and resolves
    node display names from the nodes table.

    Used by the IP Detail page to render the "Fleet Blocks" section showing
    which hosts are currently enforcing the block.

    Args:
        conn: Database connection (sqlite3.Connection or MySQLConnectionWrapper).
        ip_address: The IPv4 or IPv6 address to query fleet blocks for.

    Returns:
        A list of dicts, each with keys: node_id, node_display, reported_at.
        Empty list if no active fleet block or no reports exist for the IP.
    """
    # Match reports either by fleet_block_id FK or by source_ip when
    # fleet_block_id hasn't been backfilled yet.
    cursor = conn.execute(
        "SELECT fbr.node_id, fbr.reported_at, n.display_name "
        "FROM fleet_block_reports fbr "
        "INNER JOIN fleet_blocks fb "
        "  ON fb.source_ip = fbr.source_ip "
        "  AND fb.status = 'active' "
        "LEFT JOIN nodes n ON n.node_id = fbr.node_id "
        "WHERE fbr.source_ip = ? "
        "ORDER BY fbr.reported_at DESC",
        (ip_address,),
    )
    rows = cursor.fetchall()

    results = []
    reported_nodes = set()
    for row in rows:
        if isinstance(row, (list, tuple)):
            node_id = row[0]
            reported_at = row[1]
            display_name = row[2]
        else:
            node_id = row["node_id"]
            reported_at = row["reported_at"]
            display_name = row["display_name"]
        reported_nodes.add(node_id)
        results.append(
            {
                "node_id": node_id,
                "node_display": display_name or node_id,
                "reported_at": _normalize_fleet_ts(reported_at),
            }
        )

    # Also check node_blocks for fleet-propagated blocks that don't have
    # a fleet_block_reports entry.
    if results:
        node_rows = conn.execute(
            "SELECT nb.node_id, n.display_name, nb.blocked_at "
            "FROM node_blocks nb "
            "LEFT JOIN nodes n ON n.node_id = nb.node_id "
            "WHERE nb.ip = ?",
            (ip_address,),
        ).fetchall()
        for nr in node_rows:
            if isinstance(nr, (list, tuple)):
                nid = nr[0]
                ndisplay = nr[1]
                ts_raw = nr[2]
            else:
                nid = nr["node_id"]
                ndisplay = nr["display_name"]
                ts_raw = nr["blocked_at"]
            if nid in reported_nodes:
                continue
            ts = None
            if ts_raw is not None and isinstance(ts_raw, (int, float)):
                from datetime import datetime

                try:
                    ts = datetime.fromtimestamp(ts_raw, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
                except (OSError, ValueError, OverflowError):
                    ts = "—"
            results.append(
                {
                    "node_id": nid,
                    "node_display": ndisplay or nid,
                    "reported_at": ts or "—",
                }
            )

    return results


def process_unblock_event(conn, ip_address: str, timestamp: str) -> dict:
    """Process an UNBLOCKED event for an IP address.

    Updates the `last_unblocked_at` timestamp on the ip_intel record for the
    given IP address. Does NOT increment `total_times_seen` or
    `total_times_blocked` counters. If the IP does not exist in ip_intel,
    the function is a no-op (we only track unblocks for known IPs).

    This implements Requirement 17 (AC 1, AC 4):
    - Records the unblock timestamp in ip_intel last_unblocked_at column
    - UNBLOCKED events SHALL NOT increment total_times_seen or total_times_blocked

    Args:
        conn: Database connection (sqlite3.Connection or MySQLConnectionWrapper).
        ip_address: The IPv4 or IPv6 address that was unblocked.
        timestamp: ISO-8601 UTC timestamp of the unblock event.

    Returns:
        A dict with keys:
        - status: "accepted" if the IP was found and updated, "skipped" if
          the IP does not exist in ip_intel.
        - ip_address: The IP address processed.
    """
    # Check if the IP exists in ip_intel
    cursor = conn.execute(
        "SELECT ip_address FROM ip_intel WHERE ip_address = ?",
        (ip_address,),
    )
    row = cursor.fetchone()

    if row is None:
        # IP not tracked — no-op
        return {
            "status": "skipped",
            "ip_address": ip_address,
        }

    # Update last_unblocked_at without touching any counters
    conn.execute(
        "UPDATE ip_intel SET last_unblocked_at = ? WHERE ip_address = ?",
        (timestamp, ip_address),
    )
    conn.commit()

    return {
        "status": "accepted",
        "ip_address": ip_address,
    }


def delete_ip_record(conn, ip_address: str) -> tuple[int, int]:
    """Delete an IP record and all its associated events.

    Removes the row from ip_intel and all matching rows from
    ip_intel_events for the given IP address.

    Args:
        conn: Database connection (sqlite3.Connection or MySQLConnectionWrapper).
        ip_address: The IPv4 or IPv6 address to delete.

    Returns:
        A tuple of (ip_records_deleted, event_records_deleted).
    """
    event_count = conn.execute(
        "SELECT COUNT(*) FROM ip_intel_events WHERE ip_address = ?",
        (ip_address,),
    ).fetchone()[0]

    conn.execute("DELETE FROM ip_intel_events WHERE ip_address = ?", (ip_address,))
    conn.execute("DELETE FROM ip_intel WHERE ip_address = ?", (ip_address,))
    conn.commit()

    return (1, event_count)
