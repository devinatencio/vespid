"""Database core — connection, schema, migrations, and seed data.

Provides init_db() for schema creation, get_db() for obtaining connections,
schema introspection helpers, and seed data functions.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from datetime import UTC, datetime

logger = logging.getLogger(__name__)


def _utcnow_iso() -> str:
    """Return current UTC time as ISO-8601 string.

    Used in UPDATE statements instead of SQLite's strftime('...', 'now')
    for cross-database compatibility (SQLite + MySQL/MariaDB).
    """
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _deserialize_tags(raw: str | list | None) -> list[str]:
    """Deserialize tags from a JSON string or list to a list of strings."""
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    if isinstance(raw, str):
        import json

        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, list) else []
        except (json.JSONDecodeError, TypeError):
            return []
    return []


def get_db(db_config: str | dict):
    """Return a database connection for the configured backend.

    Accepts either a file path string (SQLite) or a configuration dictionary
    (MySQL/MariaDB) to maintain backward compatibility with existing callers.

    For MySQL/MariaDB: if a connection pool has been initialized (via
    ``init_pool()`` at app startup), connections are borrowed from the pool.
    Calling ``.close()`` on the returned wrapper returns the connection to
    the pool rather than destroying it. If no pool exists (e.g. during
    ``init_db()`` before the app is fully started), a fresh connection is
    created directly.

    Args:
        db_config: Either a file path string for SQLite, or a dict containing
            DATABASE_TYPE, DATABASE_HOST, DATABASE_PORT, DATABASE_NAME,
            DATABASE_USER, DATABASE_PASSWORD for MySQL/MariaDB.

    Returns:
        A configured connection object. For SQLite, a sqlite3.Connection with
        WAL mode, foreign keys, and sqlite3.Row. For MySQL/MariaDB, a
        MySQLConnectionWrapper providing sqlite3-compatible interface.

    Raises:
        ValueError: If DATABASE_TYPE is not sqlite/mysql/mariadb.
        ConnectionError: If MySQL/MariaDB connection fails or pool is exhausted.
        ImportError: If mysql-connector-python is not installed.
    """
    if isinstance(db_config, str):
        # SQLite path — existing behavior
        conn = sqlite3.connect(db_config)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    if isinstance(db_config, dict):
        db_type = db_config.get("DATABASE_TYPE", "sqlite").lower()

        if db_type == "sqlite":
            # Dict config but sqlite type — use DATABASE_PATH
            db_path = db_config.get("DATABASE_PATH", "")
            conn = sqlite3.connect(db_path)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode=WAL")
            conn.execute("PRAGMA foreign_keys=ON")
            return conn

        if db_type not in ("mysql", "mariadb"):
            raise ValueError(
                f"Unsupported DATABASE_TYPE '{db_type}'. "
                f"Supported options are: sqlite, mysql, mariadb"
            )

        # MySQL/MariaDB — direct connection with retry on transient failures
        host = db_config.get("DATABASE_HOST", "localhost")
        port = db_config.get("DATABASE_PORT", 3306)
        database = db_config.get("DATABASE_NAME", "vespid")
        user = db_config.get("DATABASE_USER", "vespid")
        password = db_config.get("DATABASE_PASSWORD", "")

        try:
            import mysql.connector
            import mysql.connector.errors
        except ImportError as exc:
            raise ImportError(
                "mysql-connector-python is required. "
                "Install with: pip install mysql-connector-python"
            ) from exc

        max_retries = 3
        backoff = [5, 10, 15]
        last_exc = None
        for attempt in range(max_retries):
            try:
                raw_conn = mysql.connector.connect(
                    host=host,
                    port=port,
                    database=database,
                    user=user,
                    password=password,
                    connection_timeout=10,
                    autocommit=False,
                    charset="utf8mb4",
                    collation="utf8mb4_unicode_ci",
                )
                last_exc = None
                break
            except Exception as exc:
                last_exc = exc
                exc_msg = str(exc).lower()
                # Don't retry auth or missing-database errors
                if "access denied" in exc_msg or "authentication" in exc_msg:
                    category = "authentication error"
                    raise ConnectionError(
                        f"Failed to connect to {host}:{port} ({category}): {exc}"
                    ) from exc
                if "unknown database" in exc_msg or "doesn't exist" in exc_msg or "1049" in exc_msg:
                    category = "missing database"
                    raise ConnectionError(
                        f"Failed to connect to {host}:{port} ({category}): {exc}"
                    ) from exc
                if attempt < max_retries - 1:
                    logger.warning(
                        "DB connection attempt %d/%d failed, retrying in %ds: %s",
                        attempt + 1,
                        max_retries,
                        backoff[attempt],
                        exc,
                    )
                    time.sleep(backoff[attempt])

        if last_exc is not None:
            raise ConnectionError(
                f"Failed to connect to {host}:{port} (network error): {last_exc}"
            ) from last_exc

        from app.db_compat import MySQLConnectionWrapper

        # Set session-level isolation to READ COMMITTED to prevent dirty reads
        # during concurrent upserts from multiple nodes (Req 18, AC 3).
        cursor = raw_conn.cursor()
        cursor.execute("SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED")
        cursor.execute("SET SESSION group_concat_max_len = 102400")
        cursor.close()

        return MySQLConnectionWrapper(raw_conn)

    raise ValueError("db_config must be a str (SQLite path) or dict (MySQL/MariaDB config)")


def get_request_db() -> sqlite3.Connection:
    """Return a database connection scoped to the current Flask request.

    On first call within a request, opens a new connection and stores it
    on ``flask.g``.  Subsequent calls return the same connection so that
    all database operations in a single request share one connection and
    one transaction.

    The connection is automatically closed at the end of the request by
    the ``_close_request_db`` teardown hook registered in the app factory.

    Requires a Flask application context (raises ``RuntimeError`` if
    called outside a request).

    Returns:
        A database connection (SQLite or MySQL wrapper).
    """
    from flask import g

    if not hasattr(g, "_request_db"):
        from flask import current_app

        db_config = current_app.config.get("DATABASE_PATH", "")
        if not db_config:
            # Fall back to dict config
            db_config = {
                "DATABASE_TYPE": current_app.config.get("DATABASE_TYPE", "sqlite"),
                "DATABASE_PATH": current_app.config.get("DATABASE_PATH", ""),
                "DATABASE_HOST": current_app.config.get("DATABASE_HOST", "localhost"),
                "DATABASE_PORT": current_app.config.get("DATABASE_PORT", 3306),
                "DATABASE_NAME": current_app.config.get("DATABASE_NAME", "vespid"),
                "DATABASE_USER": current_app.config.get("DATABASE_USER", "vespid"),
                "DATABASE_PASSWORD": current_app.config.get("DATABASE_PASSWORD", ""),
            }
        g._request_db = get_db(db_config)
    return g._request_db


def _close_request_db(exception: Exception | None) -> None:
    """Close the request-scoped database connection at end of request.

    Registered as a Flask ``teardown_appcontext`` handler.
    """
    from flask import g

    db = getattr(g, "_request_db", None)
    if db is not None:
        try:
            if exception is None:
                db.commit()
            else:
                db.rollback()
        except Exception:
            pass
        finally:
            try:
                db.close()
            except Exception:
                pass
        del g._request_db


def init_db(db_config: str | dict) -> None:
    """Initialize the database schema.

    Creates all tables and indexes defined in the design. Safe to call
    multiple times — all CREATE statements use IF NOT EXISTS.

    Also runs lightweight migrations for schema changes (e.g. adding columns
    to existing tables) so that existing databases are upgraded in place.

    Args:
        db_config: Either a file path string for SQLite, or a dict containing
            DATABASE_TYPE and connection parameters for MySQL/MariaDB.

    Raises:
        ValueError: If DATABASE_TYPE is not sqlite/mysql/mariadb.
    """
    if isinstance(db_config, str):
        # SQLite path — existing behavior
        conn = get_db(db_config)
        try:
            conn.executescript(_SCHEMA_SQL)
            conn.commit()
            _migrate(conn)
        finally:
            conn.close()
        return

    if isinstance(db_config, dict):
        db_type = db_config.get("DATABASE_TYPE", "sqlite").lower()

        if db_type == "sqlite":
            # Dict config but sqlite type — use DATABASE_PATH
            db_path = db_config.get("DATABASE_PATH", "")
            conn = get_db(db_path)
            try:
                conn.executescript(_SCHEMA_SQL)
                conn.commit()
                _migrate(conn)
            finally:
                conn.close()
            return

        if db_type in ("mysql", "mariadb"):
            conn = get_db(db_config)
            try:
                # Read schema_mysql.sql relative to the vespid-server root.
                # db_core.py is at app/models/db_core.py — up three levels.
                from pathlib import Path

                schema_path = str(
                    Path(__file__).resolve().parent.parent.parent / "schema_mysql.sql"
                )
                with open(schema_path) as f:
                    schema_sql = f.read()

                # Split on ';' and execute each non-empty statement.
                # Ignore "duplicate key name" errors (1061) for CREATE INDEX
                # so that init_db() is idempotent on MySQL.
                import mysql.connector.errors

                statements = schema_sql.split(";")
                for stmt in statements:
                    stmt = stmt.strip()
                    if stmt:
                        try:
                            conn.execute(stmt)
                        except mysql.connector.errors.ProgrammingError as e:
                            # Error 1061 = Duplicate key name (index already exists)
                            # Error 1072 = Key column doesn't exist in table
                            #   (index references a column added by migration;
                            #    _migrate will create it after the column exists)
                            if e.errno in (1061, 1072):
                                pass
                            else:
                                raise
                conn.commit()

                # Run migrations for MySQL backend
                _migrate(conn, db_type)
            finally:
                conn.close()
            return

        raise ValueError(
            f"Unsupported DATABASE_TYPE '{db_type}'. Supported options are: sqlite, mysql, mariadb"
        )

    raise ValueError("db_config must be a str (SQLite path) or dict (MySQL/MariaDB config)")


def _get_table_columns(conn, table_name: str, db_type: str) -> set:
    """Return set of lowercase column names for a table using backend-appropriate query.

    Args:
        conn: Database connection (sqlite3.Connection or MySQLConnectionWrapper).
        table_name: Name of the table to inspect.
        db_type: One of 'sqlite', 'mysql', 'mariadb'.

    Returns:
        A set of lowercase column name strings.
    """
    if db_type == "sqlite":
        rows = conn.execute(f"PRAGMA table_info({table_name})").fetchall()
        return {row[1].lower() for row in rows}
    else:
        # mysql / mariadb
        rows = conn.execute(
            "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS "
            "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?",
            (table_name,),
        ).fetchall()
        return {row[0].lower() for row in rows}


def _index_exists(conn, index_name: str, table_name: str, db_type: str) -> bool:
    """Return True if an index with the given name exists on the given table."""
    if db_type == "sqlite":
        rows = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE type = 'index' AND name = ?", (index_name,)
        ).fetchall()
        return bool(rows)
    rows = conn.execute(
        "SELECT 1 FROM INFORMATION_SCHEMA.STATISTICS "
        "WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND INDEX_NAME = ?",
        (table_name, index_name),
    ).fetchall()
    return bool(rows)


def _add_index_if_missing(
    conn, table_name: str, index_name: str, column: str, db_type: str
) -> None:
    """Create an index on (table_name.column) if it does not already exist."""
    if _index_exists(conn, index_name, table_name, db_type):
        return
    if db_type == "sqlite":
        conn.execute(f"CREATE INDEX IF NOT EXISTS {index_name} ON {table_name}({column})")
    else:
        conn.execute(f"CREATE INDEX {index_name} ON {table_name}({column})")
    conn.commit()


def _get_tables(conn, db_type: str) -> set:
    """Return set of lowercase table names using backend-appropriate query.

    Args:
        conn: Database connection (sqlite3.Connection or MySQLConnectionWrapper).
        db_type: One of 'sqlite', 'mysql', 'mariadb'.

    Returns:
        A set of lowercase table name strings.
    """
    if db_type == "sqlite":
        rows = conn.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()
        return {row[0].lower() for row in rows}
    else:
        # mysql / mariadb
        rows = conn.execute(
            "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = DATABASE()"
        ).fetchall()
        return {row[0].lower() for row in rows}


def _insert_ignore(db_type: str) -> str:
    """Return the INSERT IGNORE syntax appropriate for the backend.

    Args:
        db_type: One of 'sqlite', 'mysql', 'mariadb'.

    Returns:
        'INSERT OR IGNORE' for sqlite, 'INSERT IGNORE' for mysql/mariadb.
    """
    if db_type == "sqlite":
        return "INSERT OR IGNORE"
    return "INSERT IGNORE"


def _migrate(conn, db_type: str = "sqlite") -> None:
    """Apply incremental schema migrations to an existing database.

    Each migration checks whether it has already been applied (e.g. column
    exists) before running, so this is safe to call on every startup.

    Args:
        conn: Database connection (sqlite3.Connection or MySQLConnectionWrapper).
        db_type: The database backend type ('sqlite', 'mysql', or 'mariadb').
            Defaults to 'sqlite' for backward compatibility.
    """
    # Lazy imports to avoid circular dependency with detection_rules module
    from .detection_rules import (
        _seed_apache_attack_templates,
        _seed_default_noise_suppression,
        _seed_detection_rules,
    )

    # Migration 1: add 'result' column to pending_commands
    cols = _get_table_columns(conn, "pending_commands", db_type)
    if "result" not in cols:
        conn.execute("ALTER TABLE pending_commands ADD COLUMN result TEXT")
        conn.commit()

    # Migration 2: add 'last_whitelist' and related columns to nodes.
    # Note: 'last_block_list' is intentionally NOT added — block list data
    # lives in the node_blocks table (see Migration 6/7).
    node_cols = _get_table_columns(conn, "nodes", db_type)
    if "last_whitelist" not in node_cols:
        conn.execute("ALTER TABLE nodes ADD COLUMN last_whitelist TEXT NOT NULL DEFAULT '[]'")
        conn.commit()
    if "last_allowlist" not in node_cols:
        conn.execute("ALTER TABLE nodes ADD COLUMN last_allowlist TEXT NOT NULL DEFAULT '[]'")
        conn.commit()
    # Copy existing whitelist data to allowlist
    conn.execute(
        "UPDATE nodes SET last_allowlist = last_whitelist WHERE last_allowlist = '[]' AND last_whitelist != '[]'"
    )
    conn.commit()
    if "last_feeds" not in node_cols:
        conn.execute("ALTER TABLE nodes ADD COLUMN last_feeds TEXT NOT NULL DEFAULT '[]'")
        conn.commit()
    if "last_counters" not in node_cols:
        conn.execute("ALTER TABLE nodes ADD COLUMN last_counters TEXT NOT NULL DEFAULT '[]'")
        conn.commit()
    if "last_host_info" not in node_cols:
        conn.execute("ALTER TABLE nodes ADD COLUMN last_host_info TEXT NOT NULL DEFAULT '{}'")
        conn.commit()

    # Migration 6: create node_blocks table for block list data
    if db_type == "mysql":
        conn.execute(
            "CREATE TABLE IF NOT EXISTS node_blocks ("
            "  node_id     VARCHAR(255) NOT NULL,"
            "  ip          VARCHAR(45) NOT NULL,"
            "  reason      VARCHAR(255) NOT NULL DEFAULT '',"
            "  blocked_at  DOUBLE NOT NULL,"
            "  expires_at  DOUBLE NOT NULL,"
            "  strike      INT NOT NULL DEFAULT 1,"
            "  PRIMARY KEY (node_id, ip),"
            "  INDEX idx_nb_ip (ip)"
            ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
        )
    else:
        conn.execute(
            "CREATE TABLE IF NOT EXISTS node_blocks ("
            "  node_id     TEXT NOT NULL,"
            "  ip          TEXT NOT NULL,"
            "  reason      TEXT NOT NULL DEFAULT '',"
            "  blocked_at  REAL NOT NULL,"
            "  expires_at  REAL NOT NULL,"
            "  strike      INTEGER NOT NULL DEFAULT 1,"
            "  PRIMARY KEY (node_id, ip)"
            ")"
        )
    conn.commit()

    # Migration 7: drop obsolete last_block_list column (data now in node_blocks).
    # Runs on both backends so databases created before this change converge.
    try:
        conn.execute("ALTER TABLE nodes DROP COLUMN last_block_list")
        conn.commit()
    except Exception:
        pass  # May not exist if already dropped, or DROP COLUMN unsupported

    # Seed feed catalog if empty
    count = conn.execute("SELECT COUNT(*) FROM feed_catalog").fetchone()[0]
    if count == 0:
        _seed_feed_catalog(conn, db_type)

    # Migration: add enhanced metadata columns to feed_catalog
    fc_cols = _get_table_columns(conn, "feed_catalog", db_type)
    if "provider" not in fc_cols:
        conn.execute("ALTER TABLE feed_catalog ADD COLUMN provider TEXT NOT NULL DEFAULT ''")
        conn.commit()
    if "confidence" not in fc_cols:
        conn.execute(
            "ALTER TABLE feed_catalog ADD COLUMN confidence TEXT NOT NULL DEFAULT 'medium'"
        )
        conn.commit()
    if "detects" not in fc_cols:
        conn.execute("ALTER TABLE feed_catalog ADD COLUMN detects TEXT NOT NULL DEFAULT ''")
        conn.commit()
    if "recommended_usage" not in fc_cols:
        conn.execute(
            "ALTER TABLE feed_catalog ADD COLUMN recommended_usage TEXT NOT NULL DEFAULT ''"
        )
        conn.commit()
    # Backfill enhanced metadata for existing default feeds
    if "provider" in _get_table_columns(conn, "feed_catalog", db_type):
        for feed in _DEFAULT_FEEDS:
            conn.execute(
                "UPDATE feed_catalog SET provider = ?, confidence = ?, "
                "detects = ?, recommended_usage = ?, description = ? "
                "WHERE name = ? AND provider = ''",
                (
                    feed.get("provider", ""),
                    feed.get("confidence", "medium"),
                    feed.get("detects", ""),
                    feed.get("recommended_usage", ""),
                    feed["description"],
                    feed["name"],
                ),
            )
        conn.commit()

    # Migration: update binarydefense feed URL (www.binarydefense.com → binarydefense.com)
    conn.execute(
        "UPDATE feed_catalog SET url = ? WHERE name = 'binarydefense'"
        " AND url = 'https://www.binarydefense.com/banlist.txt'",
        ("https://binarydefense.com/banlist.txt",),
    )
    conn.commit()

    # Migration 3: create enrollment tables for existing databases
    tables = _get_tables(conn, db_type)
    if "enrollment_requests" not in tables:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS enrollment_requests (
                id                    INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id               TEXT    NOT NULL,
                hostname              TEXT    NOT NULL,
                source_ip             TEXT,
                source                TEXT    NOT NULL DEFAULT 'agent',
                status                TEXT    NOT NULL DEFAULT 'pending'
                                      CHECK(status IN ('pending', 'approved', 'rejected', 'revoked')),
                requested_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                decided_at            TEXT,
                decided_by            TEXT,
                api_key_id            INTEGER REFERENCES api_keys(id),
                credentials_retrieved INTEGER NOT NULL DEFAULT 0,
                pending_token         TEXT,
                host_id               TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_enrollment_node_id ON enrollment_requests(node_id);
            CREATE INDEX IF NOT EXISTS idx_enrollment_status  ON enrollment_requests(status);
            CREATE INDEX IF NOT EXISTS idx_enrollment_host_id ON enrollment_requests(host_id);
        """)
        conn.commit()
    else:
        # Migration: add pending_token column if missing
        er_cols = _get_table_columns(conn, "enrollment_requests", db_type)
        if "pending_token" not in er_cols:
            conn.execute("ALTER TABLE enrollment_requests ADD COLUMN pending_token TEXT")
            conn.commit()
        # Migration: add host_id column (links security and monitor agents on
        # the same physical host). Added for the Monitor Agent enrollment work.
        if "host_id" not in er_cols:
            conn.execute("ALTER TABLE enrollment_requests ADD COLUMN host_id TEXT")
            conn.commit()
        # Migration: add source column (which agent flavor enrolled). Default
        # 'agent' for back-compat with existing rows.
        if "source" not in er_cols:
            conn.execute(
                "ALTER TABLE enrollment_requests ADD COLUMN source TEXT NOT NULL DEFAULT 'agent'"
            )
            conn.commit()

    # Migration: add host_id index if missing
    _add_index_if_missing(conn, "enrollment_requests", "idx_enrollment_host_id", "host_id", db_type)

    if "enrollment_settings" not in tables:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS enrollment_settings (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                setting_key   TEXT    NOT NULL UNIQUE,
                setting_value TEXT    NOT NULL,
                updated_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                updated_by    TEXT    NOT NULL DEFAULT 'system'
            );
        """)
        conn.commit()

    # Seed default enrollment settings if empty
    es_count = conn.execute("SELECT COUNT(*) FROM enrollment_settings").fetchone()[0]
    if es_count == 0:
        conn.execute(
            "INSERT INTO enrollment_settings (setting_key, setting_value) VALUES (?, ?)",
            ("enrollment_enabled", "false"),
        )
        conn.execute(
            "INSERT INTO enrollment_settings (setting_key, setting_value) VALUES (?, ?)",
            ("enrollment_mode", "manual_approval"),
        )
        conn.execute(
            "INSERT INTO enrollment_settings (setting_key, setting_value) VALUES (?, ?)",
            ("enrollment_token", ""),
        )
        conn.commit()

    # Migration 2a: seed enrollment_token if not present (for existing databases)
    existing_token = conn.execute(
        "SELECT COUNT(*) FROM enrollment_settings WHERE setting_key = 'enrollment_token'"
    ).fetchone()[0]
    if existing_token == 0:
        conn.execute(
            "INSERT INTO enrollment_settings (setting_key, setting_value) VALUES (?, ?)",
            ("enrollment_token", ""),
        )
        conn.commit()

    # Migration 2b: seed allow_unrestricted_api_keys (default 'true' for
    # back-compat). When 'false', the admin UI hides the "Any node" option
    # and create_key_endpoint rejects keys with no node_id_restriction.
    existing_unrestricted = conn.execute(
        "SELECT COUNT(*) FROM enrollment_settings WHERE setting_key = 'allow_unrestricted_api_keys'"
    ).fetchone()[0]
    if existing_unrestricted == 0:
        conn.execute(
            "INSERT INTO enrollment_settings (setting_key, setting_value) VALUES (?, ?)",
            ("allow_unrestricted_api_keys", "true"),
        )
        conn.commit()

    # Migration 3a: add host_id to api_keys (links keys for the same physical
    # host across multiple agents). Existing rows have host_id=NULL.
    if "api_keys" in _get_tables(conn, db_type):
        ak_cols = _get_table_columns(conn, "api_keys", db_type)
        if "host_id" not in ak_cols:
            conn.execute("ALTER TABLE api_keys ADD COLUMN host_id TEXT")
            conn.commit()
        _add_index_if_missing(conn, "api_keys", "idx_api_keys_host_id", "host_id", db_type)

    # Migration 4: create fleet blocklist tables for existing databases
    if "fleet_blocks" not in tables:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS fleet_blocks (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                fleet_block_id  TEXT    NOT NULL UNIQUE,
                source_ip       TEXT    NOT NULL,
                status          TEXT    NOT NULL DEFAULT 'pending'
                                CHECK(status IN ('pending', 'active', 'expired', 'removed')),
                first_reported_at TEXT  NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                last_renewed_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                approved_at     TEXT,
                expires_at      TEXT    NOT NULL,
                reporting_node_count INTEGER NOT NULL DEFAULT 1,
                originating_node_id TEXT NOT NULL,
                event_type      TEXT    NOT NULL,
                detection_rule  TEXT    NOT NULL DEFAULT '',
                reason          TEXT    NOT NULL DEFAULT '',
                ttl_seconds     INTEGER NOT NULL DEFAULT 3600
            );

            CREATE INDEX IF NOT EXISTS idx_fleet_blocks_source_ip ON fleet_blocks(source_ip);
            CREATE INDEX IF NOT EXISTS idx_fleet_blocks_status    ON fleet_blocks(status);
            CREATE INDEX IF NOT EXISTS idx_fleet_blocks_expires   ON fleet_blocks(expires_at);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_fleet_blocks_ip_active
                ON fleet_blocks(source_ip) WHERE status = 'active';
        """)
        conn.commit()

    if "fleet_block_reports" not in tables:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS fleet_block_reports (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                source_ip       TEXT    NOT NULL,
                node_id         TEXT    NOT NULL,
                event_type      TEXT    NOT NULL,
                detection_rule  TEXT    NOT NULL DEFAULT '',
                block_ttl_seconds INTEGER NOT NULL DEFAULT 86400,
                reported_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                fleet_block_id  TEXT    REFERENCES fleet_blocks(fleet_block_id)
            );

            CREATE INDEX IF NOT EXISTS idx_fbr_source_ip  ON fleet_block_reports(source_ip);
            CREATE INDEX IF NOT EXISTS idx_fbr_node_id    ON fleet_block_reports(node_id);
            CREATE INDEX IF NOT EXISTS idx_fbr_reported   ON fleet_block_reports(reported_at);
            CREATE UNIQUE INDEX IF NOT EXISTS idx_fbr_ip_node
                ON fleet_block_reports(source_ip, node_id);
        """)
        conn.commit()

    # Migration: add event_id column to fleet_block_reports (Req 19)
    fbr_cols = _get_table_columns(conn, "fleet_block_reports", db_type)
    if "event_id" not in fbr_cols:
        conn.execute("ALTER TABLE fleet_block_reports ADD COLUMN event_id TEXT NOT NULL DEFAULT ''")
        conn.commit()

    if "fleet_allowlist" not in tables:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS fleet_allowlist (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                entry       TEXT    NOT NULL UNIQUE,
                reason      TEXT    NOT NULL DEFAULT '',
                created_by  TEXT    NOT NULL,
                created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                is_active   INTEGER NOT NULL DEFAULT 1
            );

            CREATE INDEX IF NOT EXISTS idx_fleet_al_active ON fleet_allowlist(is_active);
        """)
        conn.commit()

    if "fleet_config" not in tables:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS fleet_config (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                config_key    TEXT    NOT NULL UNIQUE,
                config_value  TEXT    NOT NULL,
                updated_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                updated_by    TEXT    NOT NULL DEFAULT 'system'
            );
        """)
        conn.commit()

    # Seed fleet_config with default values if empty
    fc_count = conn.execute("SELECT COUNT(*) FROM fleet_config").fetchone()[0]
    if fc_count == 0:
        _seed_fleet_config(conn, db_type)

    # Migration 5: create detection rules tables for existing databases
    if "detection_rules_brute_force" not in tables:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS detection_rules_brute_force (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                name            TEXT    NOT NULL UNIQUE,
                event_type      TEXT    NOT NULL,
                max_attempts    INTEGER NOT NULL,
                window_seconds  INTEGER NOT NULL,
                parser          TEXT    NOT NULL,
                enabled         INTEGER NOT NULL DEFAULT 1,
                is_template     INTEGER NOT NULL DEFAULT 0,
                created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                created_by      TEXT    NOT NULL DEFAULT 'system'
            );

            CREATE TABLE IF NOT EXISTS detection_rules_custom (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                name            TEXT    NOT NULL UNIQUE,
                event_type      TEXT    NOT NULL,
                regex           TEXT    NOT NULL,
                log_sources     TEXT    NOT NULL DEFAULT '["*"]',
                max_attempts    INTEGER NOT NULL,
                window_seconds  INTEGER NOT NULL,
                enabled         INTEGER NOT NULL DEFAULT 1,
                is_template     INTEGER NOT NULL DEFAULT 0,
                pack_name       TEXT    NOT NULL DEFAULT '',
                tags            TEXT    NOT NULL DEFAULT '[]',
                sigma_id        TEXT    NOT NULL DEFAULT '',
                sigma_status    TEXT    NOT NULL DEFAULT '',
                content_hash    TEXT    NOT NULL DEFAULT '',
                user_modified   INTEGER NOT NULL DEFAULT 0,
                created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                created_by      TEXT    NOT NULL DEFAULT 'system'
            );

            CREATE TABLE IF NOT EXISTS detection_rules_revision (
                id              INTEGER PRIMARY KEY CHECK (id = 1),
                revision        INTEGER NOT NULL DEFAULT 0,
                updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
            );
        """)
        conn.execute(
            f"{_insert_ignore(db_type)} INTO detection_rules_revision (id, revision) VALUES (1, 0)"
        )
        conn.commit()

    # Seed detection rules if empty
    dr_count = conn.execute("SELECT COUNT(*) FROM detection_rules_brute_force").fetchone()[0]
    if dr_count == 0:
        _seed_detection_rules(conn, db_type)

    # Migration: add pack_name column to detection_rules_custom if missing
    drc_cols = _get_table_columns(conn, "detection_rules_custom", db_type)
    if "pack_name" not in drc_cols:
        conn.execute(
            "ALTER TABLE detection_rules_custom ADD COLUMN pack_name TEXT NOT NULL DEFAULT ''"
        )
        # Backfill pack_name for existing apache templates
        conn.execute(
            "UPDATE detection_rules_custom SET pack_name = 'apache-attacks' "
            "WHERE is_template = 1 AND log_sources LIKE '%apache%'"
        )
        conn.commit()

    # Migration: add tags, sigma_id, sigma_status columns to detection_rules_custom if missing
    drc_cols2 = _get_table_columns(conn, "detection_rules_custom", db_type)
    if "tags" not in drc_cols2:
        conn.execute(
            "ALTER TABLE detection_rules_custom ADD COLUMN tags TEXT NOT NULL DEFAULT '[]'"
        )
    if "sigma_id" not in drc_cols2:
        conn.execute(
            "ALTER TABLE detection_rules_custom ADD COLUMN sigma_id TEXT NOT NULL DEFAULT ''"
        )
    if "sigma_status" not in drc_cols2:
        conn.execute(
            "ALTER TABLE detection_rules_custom ADD COLUMN sigma_status TEXT NOT NULL DEFAULT ''"
        )
    if "tags" not in drc_cols2 or "sigma_id" not in drc_cols2 or "sigma_status" not in drc_cols2:
        conn.commit()

    # Migration: add content_hash + user_modified to detection_rules_custom.
    # These power non-destructive pack reconcile: content_hash tracks the
    # pack-shipped definition so updates only refresh rules the user hasn't
    # modified; user_modified is set when a user edits a rule. Backfill of
    # baseline hashes (divergence detection) happens in the reconcile pass.
    drc_cols3 = _get_table_columns(conn, "detection_rules_custom", db_type)
    if "content_hash" not in drc_cols3:
        conn.execute(
            "ALTER TABLE detection_rules_custom ADD COLUMN content_hash TEXT NOT NULL DEFAULT ''"
        )
    if "user_modified" not in drc_cols3:
        conn.execute(
            "ALTER TABLE detection_rules_custom ADD COLUMN user_modified INTEGER NOT NULL DEFAULT 0"
        )
    if "content_hash" not in drc_cols3 or "user_modified" not in drc_cols3:
        conn.commit()

    # Migration: reconcile pack template rules from YAML (non-destructive).
    # Inserts new rules, refreshes unmodified rules whose shipped definition
    # changed, and never clobbers user-modified rules.
    _seed_apache_attack_templates(conn, db_type)

    # Migration 7: create correlation rules table for multi-signal detection
    if "detection_rules_correlation" not in tables:
        if db_type == "sqlite":
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS detection_rules_correlation (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    name            TEXT    NOT NULL UNIQUE,
                    event_type      TEXT    NOT NULL,
                    min_categories  INTEGER NOT NULL DEFAULT 3,
                    window_seconds  INTEGER NOT NULL DEFAULT 600,
                    enabled         INTEGER NOT NULL DEFAULT 1,
                    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                    created_by      TEXT    NOT NULL DEFAULT 'system'
                );
            """)
        else:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS detection_rules_correlation ("
                "  id              INT AUTO_INCREMENT PRIMARY KEY,"
                "  name            VARCHAR(255) NOT NULL UNIQUE,"
                "  event_type      VARCHAR(255) NOT NULL,"
                "  min_categories  INT NOT NULL DEFAULT 3,"
                "  window_seconds  INT NOT NULL DEFAULT 600,"
                "  enabled         INT NOT NULL DEFAULT 1,"
                "  created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "  updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,"
                "  created_by      VARCHAR(255) NOT NULL DEFAULT 'system'"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
            )
        conn.commit()

    # Seed default correlation rule if table is empty
    corr_count = conn.execute("SELECT COUNT(*) FROM detection_rules_correlation").fetchone()[0]
    if corr_count == 0:
        conn.execute(
            f"{_insert_ignore(db_type)} INTO detection_rules_correlation "
            "(name, event_type, min_categories, window_seconds) "
            "VALUES (?, ?, ?, ?)",
            ("recon_correlation", "RECON_CORRELATION", 3, 600),
        )
        conn.commit()

    # Migration: bump recon_correlation min_categories from 2 to 3.
    # A single log line matching multiple parsers was inflating the category
    # count, causing false positives at min_categories=2.
    existing_corr = conn.execute(
        "SELECT id, min_categories FROM detection_rules_correlation "
        "WHERE name = 'recon_correlation' AND min_categories = 2"
    ).fetchone()
    if existing_corr:
        conn.execute(
            "UPDATE detection_rules_correlation SET min_categories = 3 "
            "WHERE name = 'recon_correlation' AND min_categories = 2"
        )
        conn.execute(
            "UPDATE detection_rules_revision SET revision = revision + 1, updated_at = ? WHERE id = 1",
            (_utcnow_iso(),),
        )
        conn.commit()

    # Migration 6: create centralized agent management tables for existing databases
    if "config_profiles" not in tables:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS config_profiles (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                name            TEXT    NOT NULL,
                name_lower      TEXT    NOT NULL UNIQUE,
                description     TEXT    NOT NULL DEFAULT '',
                version         INTEGER NOT NULL DEFAULT 1,
                settings        TEXT    NOT NULL DEFAULT '{}',
                created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                created_by      TEXT    NOT NULL,
                is_active       INTEGER NOT NULL DEFAULT 1
            );

            CREATE INDEX IF NOT EXISTS idx_config_profiles_active ON config_profiles(is_active);
            CREATE INDEX IF NOT EXISTS idx_config_profiles_created ON config_profiles(created_at);
        """)
        conn.commit()

    if "config_version_history" not in tables:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS config_version_history (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id      INTEGER NOT NULL REFERENCES config_profiles(id),
                version         INTEGER NOT NULL,
                previous_settings TEXT NOT NULL DEFAULT '{}',
                new_settings    TEXT    NOT NULL DEFAULT '{}',
                changed_by      TEXT    NOT NULL,
                changed_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                change_reason   TEXT    NOT NULL
            );

            CREATE INDEX IF NOT EXISTS idx_cvh_profile_id ON config_version_history(profile_id);
            CREATE INDEX IF NOT EXISTS idx_cvh_version ON config_version_history(profile_id, version);
        """)
        conn.commit()

    if "config_assignments" not in tables:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS config_assignments (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id         TEXT,
                group_id        INTEGER,
                profile_id      INTEGER NOT NULL REFERENCES config_profiles(id),
                assigned_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                assigned_by     TEXT    NOT NULL,
                is_active       INTEGER NOT NULL DEFAULT 1
            );

            CREATE INDEX IF NOT EXISTS idx_ca_node_id ON config_assignments(node_id);
            CREATE INDEX IF NOT EXISTS idx_ca_group_id ON config_assignments(group_id);
            CREATE INDEX IF NOT EXISTS idx_ca_profile_id ON config_assignments(profile_id);
            CREATE INDEX IF NOT EXISTS idx_ca_active ON config_assignments(is_active);
        """)
        conn.commit()

    if "agent_groups" not in tables:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS agent_groups (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                name            TEXT    NOT NULL UNIQUE,
                description     TEXT    NOT NULL DEFAULT '',
                created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                created_by      TEXT    NOT NULL
            );
        """)
        conn.commit()

    if "agent_group_members" not in tables:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS agent_group_members (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                group_id        INTEGER NOT NULL REFERENCES agent_groups(id),
                node_id         TEXT    NOT NULL,
                added_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                added_by        TEXT    NOT NULL,
                UNIQUE(group_id, node_id)
            );

            CREATE INDEX IF NOT EXISTS idx_agm_group_id ON agent_group_members(group_id);
            CREATE INDEX IF NOT EXISTS idx_agm_node_id ON agent_group_members(node_id);
        """)
        conn.commit()

    if "config_rollouts" not in tables:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS config_rollouts (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id      INTEGER NOT NULL REFERENCES config_profiles(id),
                target_version  INTEGER NOT NULL,
                policy          TEXT    NOT NULL DEFAULT 'immediate'
                                CHECK(policy IN ('immediate', 'canary', 'staged')),
                status          TEXT    NOT NULL DEFAULT 'pending'
                                CHECK(status IN ('pending', 'in_progress', 'completed', 'cancelled', 'failed')),
                canary_nodes    TEXT    NOT NULL DEFAULT '[]',
                current_percentage INTEGER NOT NULL DEFAULT 100,
                created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                created_by      TEXT    NOT NULL,
                completed_at    TEXT,
                failure_count   INTEGER NOT NULL DEFAULT 0,
                success_count   INTEGER NOT NULL DEFAULT 0,
                total_targeted  INTEGER NOT NULL DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_cr_profile_id ON config_rollouts(profile_id);
            CREATE INDEX IF NOT EXISTS idx_cr_status ON config_rollouts(status);
        """)
        conn.commit()

    if "config_agent_status" not in tables:
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS config_agent_status (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                node_id         TEXT    NOT NULL,
                profile_id      INTEGER REFERENCES config_profiles(id),
                acknowledged_version INTEGER,
                last_check_in   TEXT,
                management_mode TEXT    NOT NULL DEFAULT 'standalone',
                config_status   TEXT    NOT NULL DEFAULT 'unknown'
                                CHECK(config_status IN ('unknown', 'up_to_date', 'pending', 'failed')),
                last_failure_reason TEXT,
                agent_version   TEXT,
                health_uptime   INTEGER,
                health_active_rules INTEGER,
                health_blocked_ips INTEGER,
                UNIQUE(node_id)
            );

            CREATE INDEX IF NOT EXISTS idx_cas_node_id ON config_agent_status(node_id);
            CREATE INDEX IF NOT EXISTS idx_cas_profile_id ON config_agent_status(profile_id);
        """)
        conn.commit()

    # Migration 7: create intelligence database tables
    from app.intel_models import init_intel_db

    init_intel_db(conn, db_type)

    # Migration 8: add 'role' column to api_keys for CLI/API auth
    ak_cols = _get_table_columns(conn, "api_keys", db_type)
    if "role" not in ak_cols:
        conn.execute("ALTER TABLE api_keys ADD COLUMN role TEXT NOT NULL DEFAULT 'agent'")
        conn.commit()

    # Migration 9: add 'display_name' column to users
    user_cols = _get_table_columns(conn, "users", db_type)
    if "display_name" not in user_cols:
        conn.execute("ALTER TABLE users ADD COLUMN display_name TEXT NOT NULL DEFAULT ''")
        conn.commit()

    # Migration 10: add 'theme' column to users
    user_cols = _get_table_columns(conn, "users", db_type)
    if "theme" not in user_cols:
        conn.execute("ALTER TABLE users ADD COLUMN theme TEXT NOT NULL DEFAULT 'dark'")
        conn.commit()

    # Migration 11: add 'display_name' column to nodes
    node_cols = _get_table_columns(conn, "nodes", db_type)
    if "display_name" not in node_cols:
        conn.execute("ALTER TABLE nodes ADD COLUMN display_name TEXT NOT NULL DEFAULT ''")
        conn.commit()

    # Migration 12: add lockout columns to users table
    user_cols = _get_table_columns(conn, "users", db_type)
    if "failed_login_attempts" not in user_cols:
        conn.execute(
            "ALTER TABLE users ADD COLUMN failed_login_attempts INTEGER NOT NULL DEFAULT 0"
        )
        conn.commit()
    if "locked_until" not in user_cols:
        conn.execute("ALTER TABLE users ADD COLUMN locked_until TEXT")
        conn.commit()

    # Migration 13: add onboarding_dismissed to users
    user_cols = _get_table_columns(conn, "users", db_type)
    if "onboarding_dismissed" not in user_cols:
        conn.execute("ALTER TABLE users ADD COLUMN onboarding_dismissed INTEGER NOT NULL DEFAULT 0")
        conn.commit()

    # Migration 14: add brand_beam_enabled to users
    user_cols = _get_table_columns(conn, "users", db_type)
    if "brand_beam_enabled" not in user_cols:
        conn.execute("ALTER TABLE users ADD COLUMN brand_beam_enabled INTEGER NOT NULL DEFAULT 1")
        conn.commit()

    # Migration 15: add check_results table for health-check / Nagios-style results
    if "check_results" not in tables:
        if db_type == "sqlite":
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS check_results (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    name        TEXT    NOT NULL,
                    agent_id    TEXT    NOT NULL,
                    hostname    TEXT    NOT NULL DEFAULT '',
                    exit_code   INTEGER NOT NULL DEFAULT 0,
                    severity    TEXT    NOT NULL DEFAULT 'ok',
                    output      TEXT    NOT NULL DEFAULT '',
                    duration_ms INTEGER NOT NULL DEFAULT 0,
                    created_at  TEXT    NOT NULL DEFAULT ''
                );
                CREATE INDEX IF NOT EXISTS idx_cr_name ON check_results(name);
                CREATE INDEX IF NOT EXISTS idx_cr_agent ON check_results(agent_id);
                CREATE INDEX IF NOT EXISTS idx_cr_severity ON check_results(severity);
                CREATE INDEX IF NOT EXISTS idx_cr_created ON check_results(created_at);
            """)
        else:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS check_results ("
                "  id          INT AUTO_INCREMENT PRIMARY KEY,"
                "  name        VARCHAR(255) NOT NULL,"
                "  agent_id    VARCHAR(36) NOT NULL,"
                "  hostname    VARCHAR(255) NOT NULL DEFAULT '',"
                "  exit_code   INT NOT NULL DEFAULT 0,"
                "  severity    VARCHAR(16) NOT NULL DEFAULT 'ok',"
                "  output      TEXT NOT NULL,"
                "  duration_ms INT NOT NULL DEFAULT 0,"
                "  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "  INDEX idx_cr_name (name),"
                "  INDEX idx_cr_agent (agent_id),"
                "  INDEX idx_cr_severity (severity),"
                "  INDEX idx_cr_created (created_at)"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
            )
        conn.commit()

    # Migration 16: saved_queries table for per-user query storage
    if "saved_queries" not in tables:
        if db_type == "sqlite":
            conn.executescript("""
                CREATE TABLE saved_queries (
                    id          INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                    name        TEXT    NOT NULL,
                    query       TEXT    NOT NULL,
                    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                    updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
                );
                CREATE INDEX idx_sq_user ON saved_queries(user_id);
            """)
        else:
            conn.execute(
                "CREATE TABLE saved_queries ("
                "  id          INT AUTO_INCREMENT PRIMARY KEY,"
                "  user_id     INT NOT NULL,"
                "  name        VARCHAR(255) NOT NULL,"
                "  query       TEXT NOT NULL,"
                "  created_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "  updated_at  DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,"
                "  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,"
                "  INDEX idx_sq_user (user_id)"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
            )
        conn.commit()

    # Migration 17: alert system tables (rules, events, channels, silences, eval lock)
    if "alert_rules" not in tables:
        if db_type == "sqlite":
            conn.executescript("""
                CREATE TABLE alert_rules (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    user_id         INTEGER REFERENCES users(id),
                    name            TEXT    NOT NULL,
                    query           TEXT,
                    check_name      TEXT,
                    operator        TEXT    NOT NULL CHECK(operator IN ('>', '<', '==', '>=', '<=')),
                    threshold       REAL    NOT NULL,
                    resolve_threshold REAL,
                    severity        TEXT    NOT NULL CHECK(severity IN ('warning', 'critical')),
                    for_duration    INTEGER NOT NULL DEFAULT 0,
                    cooldown_secs   INTEGER,
                    interval_secs   INTEGER NOT NULL DEFAULT 60,
                    tags            TEXT,
                    enabled         INTEGER NOT NULL DEFAULT 1,
                    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
                );
                CREATE INDEX idx_alert_rules_enabled ON alert_rules(enabled);
                CREATE INDEX idx_alert_rules_user ON alert_rules(user_id);

                CREATE TABLE alert_events (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id         INTEGER NOT NULL REFERENCES alert_rules(id),
                    entity_id       INTEGER,
                    labels          TEXT    NOT NULL DEFAULT '{}',
                    value           REAL    NOT NULL,
                    state           TEXT    NOT NULL DEFAULT 'firing' CHECK(state IN ('firing', 'resolved', 'acknowledged')),
                    fired_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                    resolved_at     TEXT,
                    acknowledged_by INTEGER REFERENCES users(id),
                    notified_at     TEXT
                );
                CREATE INDEX idx_alert_events_state ON alert_events(state);
                CREATE INDEX idx_alert_events_rule ON alert_events(rule_id);
                CREATE INDEX idx_alert_events_entity ON alert_events(entity_id);

                CREATE TABLE notification_channels (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    name            TEXT    NOT NULL,
    type            TEXT    NOT NULL,
                    config          TEXT    NOT NULL DEFAULT '{}',
                    enabled         INTEGER NOT NULL DEFAULT 1,
                    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
                );
                CREATE INDEX idx_notification_channels_enabled ON notification_channels(enabled);

                CREATE TABLE rule_notification_channels (
                    rule_id         INTEGER NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
                    channel_id      INTEGER NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
                    PRIMARY KEY (rule_id, channel_id)
                );

                CREATE TABLE alert_silences (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    matchers        TEXT    NOT NULL DEFAULT '[]',
                    rule_id         INTEGER REFERENCES alert_rules(id) ON DELETE CASCADE,
                    starts_at       TEXT    NOT NULL,
                    ends_at         TEXT    NOT NULL,
                    reason          TEXT    NOT NULL,
                    created_by      INTEGER NOT NULL REFERENCES users(id),
                    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
                );
                CREATE INDEX idx_alert_silences_active ON alert_silences(starts_at, ends_at);

                CREATE TABLE alert_eval_lock (
                    id              INTEGER PRIMARY KEY CHECK (id = 1),
                    locked_by       TEXT,
                    locked_at       TEXT,
                    expires_at      TEXT,
                    last_eval_at    TEXT
                );
                INSERT OR IGNORE INTO alert_eval_lock (id, locked_by, locked_at, expires_at, last_eval_at)
                VALUES (1, NULL, NULL, NULL, NULL);
            """)
        else:
            # MySQL/MariaDB
            conn.execute(
                "CREATE TABLE alert_rules ("
                "  id              INT AUTO_INCREMENT PRIMARY KEY,"
                "  user_id         INT,"
                "  name            VARCHAR(255) NOT NULL,"
                "  query           TEXT,"
                "  check_name      VARCHAR(255),"
                "  operator        VARCHAR(4) NOT NULL CHECK(operator IN ('>', '<', '==', '>=', '<=')),"
                "  threshold       DOUBLE NOT NULL,"
                "  resolve_threshold DOUBLE,"
                "  severity        VARCHAR(8) NOT NULL CHECK(severity IN ('warning', 'critical')),"
                "  for_duration    INT NOT NULL DEFAULT 0,"
                "  cooldown_secs   INT,"
                "  interval_secs   INT NOT NULL DEFAULT 60,"
                "  tags            TEXT,"
                "  enabled         TINYINT(1) NOT NULL DEFAULT 1,"
                "  created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "  updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,"
                "  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,"
                "  INDEX idx_alert_rules_enabled (enabled),"
                "  INDEX idx_alert_rules_user (user_id)"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
            )
            conn.execute(
                "CREATE TABLE alert_events ("
                "  id              INT AUTO_INCREMENT PRIMARY KEY,"
                "  rule_id         INT NOT NULL,"
                "  entity_id       INT,"
                "  labels          TEXT NOT NULL DEFAULT '{}',"
                "  value           DOUBLE NOT NULL,"
                "  state           VARCHAR(16) NOT NULL DEFAULT 'firing',"
                "  fired_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "  resolved_at     DATETIME,"
                "  acknowledged_by INT,"
                "  notified_at     DATETIME,"
                "  FOREIGN KEY (rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE,"
                "  FOREIGN KEY (acknowledged_by) REFERENCES users(id),"
                "  INDEX idx_alert_events_state (state),"
                "  INDEX idx_alert_events_rule (rule_id),"
                "  INDEX idx_alert_events_entity (entity_id)"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
            )
            conn.execute(
                "CREATE TABLE notification_channels ("
                "  id              INT AUTO_INCREMENT PRIMARY KEY,"
                "  name            VARCHAR(255) NOT NULL,"
                "  type            VARCHAR(16) NOT NULL,"
                "  config          TEXT NOT NULL DEFAULT '{}',"
                "  enabled         TINYINT(1) NOT NULL DEFAULT 1,"
                "  created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "  updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,"
                "  INDEX idx_notification_channels_enabled (enabled)"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
            )
            conn.execute(
                "CREATE TABLE rule_notification_channels ("
                "  rule_id         INT NOT NULL,"
                "  channel_id      INT NOT NULL,"
                "  PRIMARY KEY (rule_id, channel_id),"
                "  FOREIGN KEY (rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE,"
                "  FOREIGN KEY (channel_id) REFERENCES notification_channels(id) ON DELETE CASCADE"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
            )
            conn.execute(
                "CREATE TABLE alert_silences ("
                "  id              INT AUTO_INCREMENT PRIMARY KEY,"
                "  matchers        TEXT NOT NULL DEFAULT '[]',"
                "  rule_id         INT,"
                "  starts_at       DATETIME NOT NULL,"
                "  ends_at         DATETIME NOT NULL,"
                "  reason          TEXT NOT NULL,"
                "  created_by      INT NOT NULL,"
                "  created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "  FOREIGN KEY (rule_id) REFERENCES alert_rules(id) ON DELETE CASCADE,"
                "  FOREIGN KEY (created_by) REFERENCES users(id),"
                "  INDEX idx_alert_silences_active (starts_at, ends_at)"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
            )
            conn.execute(
                "CREATE TABLE alert_eval_lock ("
                "  id              INT PRIMARY KEY,"
                "  locked_by       VARCHAR(255),"
                "  locked_at       DATETIME,"
                "  expires_at      DATETIME,"
                "  last_eval_at    DATETIME"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
            )
            conn.execute(
                "INSERT IGNORE INTO alert_eval_lock (id, locked_by, locked_at, expires_at, last_eval_at) "
                "VALUES (1, NULL, NULL, NULL, NULL)"
            )
        conn.commit()

    # Migration 18: monitoring groups (grouped alert conditions + label-based targeting)
    if "monitoring_groups" not in tables:
        if db_type == "sqlite":
            conn.executescript("""
                CREATE TABLE monitoring_groups (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    name            TEXT    NOT NULL,
                    description     TEXT    NOT NULL DEFAULT '',
                    match_labels    TEXT    NOT NULL DEFAULT '[]',
                    match_any       INTEGER NOT NULL DEFAULT 0,
                    enabled         INTEGER NOT NULL DEFAULT 1,
                    created_at      TEXT    NOT NULL DEFAULT (strftime('%%Y-%%m-%%dT%%H:%%M:%%SZ', 'now')),
                    updated_at      TEXT    NOT NULL DEFAULT (strftime('%%Y-%%m-%%dT%%H:%%M:%%SZ', 'now'))
                );
                CREATE INDEX idx_monitoring_groups_enabled ON monitoring_groups(enabled);

                CREATE TABLE group_alert_conditions (
                    id                INTEGER PRIMARY KEY AUTOINCREMENT,
                    group_id          INTEGER NOT NULL REFERENCES monitoring_groups(id) ON DELETE CASCADE,
                    name              TEXT    NOT NULL,
                    metric_type       TEXT    NOT NULL,
                    metric_params     TEXT    NOT NULL DEFAULT '{}',
                    target_labels     TEXT,
                    operator          TEXT    NOT NULL,
                    threshold         REAL    NOT NULL,
                    resolve_threshold REAL,
                    severity          TEXT    NOT NULL DEFAULT 'warning',
                    for_duration      INTEGER NOT NULL DEFAULT 0,
                    cooldown_secs     INTEGER,
                    interval_secs     INTEGER NOT NULL DEFAULT 60,
                    last_eval_at      TEXT,
                    enabled           INTEGER NOT NULL DEFAULT 1,
                    created_at        TEXT    NOT NULL DEFAULT (strftime('%%Y-%%m-%%dT%%H:%%M:%%SZ', 'now')),
                    updated_at        TEXT    NOT NULL DEFAULT (strftime('%%Y-%%m-%%dT%%H:%%M:%%SZ', 'now'))
                );
                CREATE INDEX idx_group_alert_conditions_group ON group_alert_conditions(group_id);
                CREATE INDEX idx_group_alert_conditions_enabled ON group_alert_conditions(enabled);

                CREATE TABLE group_condition_channels (
                    condition_id  INTEGER NOT NULL REFERENCES group_alert_conditions(id) ON DELETE CASCADE,
                    channel_id    INTEGER NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
                    PRIMARY KEY (condition_id, channel_id)
                );
            """)
        else:
            conn.execute(
                "CREATE TABLE monitoring_groups ("
                "  id              INT AUTO_INCREMENT PRIMARY KEY,"
                "  name            VARCHAR(255) NOT NULL,"
                "  description     TEXT NOT NULL DEFAULT '',"
                "  match_labels    TEXT NOT NULL DEFAULT '[]',"
                "  match_any       TINYINT(1) NOT NULL DEFAULT 0,"
                "  enabled         TINYINT(1) NOT NULL DEFAULT 1,"
                "  created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "  updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,"
                "  INDEX idx_monitoring_groups_enabled (enabled)"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
            )
            conn.execute(
                "CREATE TABLE group_alert_conditions ("
                "  id                INT AUTO_INCREMENT PRIMARY KEY,"
                "  group_id          INT NOT NULL,"
                "  name              VARCHAR(255) NOT NULL,"
                "  metric_type       VARCHAR(50) NOT NULL,"
                "  metric_params     TEXT NOT NULL DEFAULT '{}',"
                "  target_labels     TEXT,"
                "  operator          VARCHAR(4) NOT NULL,"
                "  threshold         DOUBLE NOT NULL,"
                "  resolve_threshold DOUBLE,"
                "  severity          VARCHAR(8) NOT NULL DEFAULT 'warning',"
                "  for_duration      INT NOT NULL DEFAULT 0,"
                "  cooldown_secs     INT,"
                "  interval_secs     INT NOT NULL DEFAULT 60,"
                "  last_eval_at      DATETIME,"
                "  enabled           TINYINT(1) NOT NULL DEFAULT 1,"
                "  created_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "  updated_at        DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,"
                "  FOREIGN KEY (group_id) REFERENCES monitoring_groups(id) ON DELETE CASCADE,"
                "  INDEX idx_group_alert_conditions_group (group_id),"
                "  INDEX idx_group_alert_conditions_enabled (enabled)"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
            )
            conn.execute(
                "CREATE TABLE group_condition_channels ("
                "  condition_id  INT NOT NULL,"
                "  channel_id    INT NOT NULL,"
                "  PRIMARY KEY (condition_id, channel_id),"
                "  FOREIGN KEY (condition_id) REFERENCES group_alert_conditions(id) ON DELETE CASCADE,"
                "  FOREIGN KEY (channel_id) REFERENCES notification_channels(id) ON DELETE CASCADE"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
            )
        conn.commit()

    # Migration 18b: add group_condition_id to alert_events, make rule_id nullable
    cols = _get_table_columns(conn, "alert_events", db_type)
    if "group_condition_id" not in cols:
        if db_type == "sqlite":
            # SQLite doesn't support ALTER COLUMN, so rebuild the table
            conn.executescript("""
                CREATE TABLE alert_events_new (
                    id                INTEGER PRIMARY KEY AUTOINCREMENT,
                    rule_id           INTEGER REFERENCES alert_rules(id),
                    entity_id         INTEGER,
                    group_condition_id INTEGER REFERENCES group_alert_conditions(id),
                    labels            TEXT    NOT NULL DEFAULT '{}',
                    value             REAL    NOT NULL,
                    state             TEXT    NOT NULL DEFAULT 'firing' CHECK(state IN ('firing', 'resolved', 'acknowledged')),
                    fired_at          TEXT    NOT NULL DEFAULT (strftime('%%Y-%%m-%%dT%%H:%%M:%%SZ', 'now')),
                    resolved_at       TEXT,
                    acknowledged_by   INTEGER REFERENCES users(id),
                    notified_at       TEXT
                );
                INSERT INTO alert_events_new (id, rule_id, entity_id, labels, value, state, fired_at, resolved_at, acknowledged_by, notified_at)
                    SELECT id, rule_id, entity_id, labels, value, state, fired_at, resolved_at, acknowledged_by, notified_at FROM alert_events;
                DROP TABLE alert_events;
                ALTER TABLE alert_events_new RENAME TO alert_events;
                CREATE INDEX idx_alert_events_state ON alert_events(state);
                CREATE INDEX idx_alert_events_rule ON alert_events(rule_id);
                CREATE INDEX idx_alert_events_entity ON alert_events(entity_id);
                CREATE INDEX idx_alert_events_group_condition ON alert_events(group_condition_id);
            """)
        else:
            conn.execute(
                "ALTER TABLE alert_events ADD COLUMN group_condition_id INT NULL AFTER entity_id"
            )
            conn.execute("ALTER TABLE alert_events MODIFY rule_id INT NULL")
            # Clean up orphaned group_condition_id values before adding FK
            conn.execute(
                "UPDATE alert_events SET group_condition_id = NULL "
                "WHERE group_condition_id IS NOT NULL "
                "AND group_condition_id NOT IN (SELECT id FROM group_alert_conditions)"
            )
            conn.execute(
                "CREATE INDEX idx_alert_events_group_condition ON alert_events(group_condition_id)"
            )
            conn.execute(
                "ALTER TABLE alert_events ADD FOREIGN KEY fk_ae_group_condition (group_condition_id) "
                "REFERENCES group_alert_conditions(id) ON DELETE CASCADE"
            )
        conn.commit()

    # Migration 19: per-agent per-condition status table for Nagios-style matrix view
    cols = _get_table_columns(conn, "monitoring_group_status", db_type)
    if not cols:
        if db_type == "sqlite":
            conn.execute("""CREATE TABLE monitoring_group_status (
                group_id        INTEGER NOT NULL,
                condition_id    INTEGER NOT NULL,
                agent_id        TEXT    NOT NULL,
                hostname        TEXT    NOT NULL DEFAULT '',
                status          TEXT    NOT NULL DEFAULT 'unknown',
                last_value      REAL,
                last_metric_value REAL,
                debounce_started_at TEXT,
                last_detail     TEXT    NOT NULL DEFAULT '{}',
                created_at      TEXT    NOT NULL DEFAULT (strftime('%%Y-%%m-%%dT%%H:%%M:%%SZ', 'now')),
                updated_at      TEXT    NOT NULL DEFAULT (strftime('%%Y-%%m-%%dT%%H:%%M:%%SZ', 'now')),
                PRIMARY KEY (group_id, condition_id, agent_id),
                FOREIGN KEY (group_id) REFERENCES monitoring_groups(id) ON DELETE CASCADE,
                FOREIGN KEY (condition_id) REFERENCES group_alert_conditions(id) ON DELETE CASCADE
            )""")
        else:
            conn.execute("""CREATE TABLE monitoring_group_status (
                group_id       INT    NOT NULL,
                condition_id   INT    NOT NULL,
                agent_id       VARCHAR(255) NOT NULL,
                hostname       VARCHAR(255) NOT NULL DEFAULT '',
                status         VARCHAR(16) NOT NULL DEFAULT 'unknown',
                last_value     DOUBLE,
                last_metric_value DOUBLE,
                last_evaluated_at DATETIME,
                debounce_started_at DATETIME,
                last_detail    TEXT    NOT NULL DEFAULT '{}',
                created_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at     DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                PRIMARY KEY (group_id, condition_id, agent_id),
                FOREIGN KEY (group_id) REFERENCES monitoring_groups(id) ON DELETE CASCADE,
                FOREIGN KEY (condition_id) REFERENCES group_alert_conditions(id) ON DELETE CASCADE
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci""")
        conn.commit()

    # Migration 19b: add debounce_started_at to monitoring_group_status
    cols = _get_table_columns(conn, "monitoring_group_status", db_type)
    if "debounce_started_at" not in cols:
        if db_type == "sqlite":
            conn.execute("ALTER TABLE monitoring_group_status ADD COLUMN debounce_started_at TEXT")
        else:
            conn.execute(
                "ALTER TABLE monitoring_group_status ADD COLUMN debounce_started_at DATETIME NULL"
            )
        conn.commit()

    # Migration 19c: add last_detail for per-mountpoint breakdown etc.
    cols = _get_table_columns(conn, "monitoring_group_status", db_type)
    if "last_detail" not in cols:
        if db_type == "sqlite":
            conn.execute(
                "ALTER TABLE monitoring_group_status ADD COLUMN last_detail TEXT DEFAULT '{}'"
            )
        else:
            conn.execute(
                "ALTER TABLE monitoring_group_status ADD COLUMN last_detail TEXT DEFAULT '{}'"
            )
        conn.commit()

    # Migration 21: synthetic monitoring workers, checks, and job queue
    tables = _get_tables(conn, db_type)
    if "synthetic_workers" not in tables:
        if db_type == "sqlite":
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS synthetic_workers (
                    id              TEXT PRIMARY KEY,
                    hostname        TEXT NOT NULL DEFAULT '',
                    version         TEXT NOT NULL DEFAULT '',
                    capabilities    TEXT NOT NULL DEFAULT '[]',
                    labels          TEXT NOT NULL DEFAULT '{}',
                    max_concurrent  INTEGER NOT NULL DEFAULT 10,
                    running_jobs    INTEGER NOT NULL DEFAULT 0,
                    last_heartbeat_at TEXT NOT NULL DEFAULT '',
                    status          TEXT NOT NULL DEFAULT 'online',
                    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
                );
                CREATE INDEX IF NOT EXISTS idx_sw_status ON synthetic_workers(status);
                CREATE INDEX IF NOT EXISTS idx_sw_heartbeat ON synthetic_workers(last_heartbeat_at);
            """)
        else:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS synthetic_workers ("
                "  id              VARCHAR(36) PRIMARY KEY,"
                "  hostname        VARCHAR(255) NOT NULL DEFAULT '',"
                "  version         VARCHAR(32) NOT NULL DEFAULT '',"
                "  capabilities    JSON NOT NULL,"
                "  labels          JSON NOT NULL,"
                "  max_concurrent  INT NOT NULL DEFAULT 10,"
                "  running_jobs    INT NOT NULL DEFAULT 0,"
                "  last_heartbeat_at TIMESTAMP NULL,"
                "  status          VARCHAR(16) NOT NULL DEFAULT 'online',"
                "  created_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
                "  updated_at      TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,"
                "  INDEX idx_sw_status (status),"
                "  INDEX idx_sw_heartbeat (last_heartbeat_at)"
                ")"
            )
        conn.commit()

    if "synthetic_checks" not in tables:
        if db_type == "sqlite":
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS synthetic_checks (
                    id                INTEGER PRIMARY KEY AUTOINCREMENT,
                    name              TEXT NOT NULL,
                    check_type        TEXT NOT NULL,
                    target            TEXT NOT NULL,
                    check_config      TEXT NOT NULL DEFAULT '{}',
                    locations         TEXT NOT NULL DEFAULT '[]',
                    interval_secs     INTEGER NOT NULL DEFAULT 60,
                    timeout_secs      INTEGER NOT NULL DEFAULT 30,
                    status            TEXT NOT NULL DEFAULT 'active',
                    last_result_status TEXT,
                    last_duration_ms  INTEGER,
                    last_error        TEXT,
                    last_result_at    TEXT,
                    next_run_at       TEXT,
                    created_by        INTEGER,
                    created_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                    updated_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
                );
                CREATE INDEX IF NOT EXISTS idx_sc_next_run ON synthetic_checks(status, next_run_at);
                CREATE INDEX IF NOT EXISTS idx_sc_type ON synthetic_checks(check_type);
            """)
        else:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS synthetic_checks ("
                "  id                INT AUTO_INCREMENT PRIMARY KEY,"
                "  name              VARCHAR(255) NOT NULL,"
                "  check_type        VARCHAR(32) NOT NULL,"
                "  target            VARCHAR(512) NOT NULL,"
                "  check_config      JSON NOT NULL,"
                "  locations         JSON NOT NULL,"
                "  interval_secs     INT NOT NULL DEFAULT 60,"
                "  timeout_secs      INT NOT NULL DEFAULT 30,"
                "  status            VARCHAR(16) NOT NULL DEFAULT 'active',"
                "  last_result_status VARCHAR(16),"
                "  last_duration_ms  INT,"
                "  last_error        TEXT,"
                "  last_result_at    TIMESTAMP NULL,"
                "  next_run_at       TIMESTAMP NULL,"
                "  created_by        INT,"
                "  created_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
                "  updated_at        TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,"
                "  INDEX idx_sc_next_run (status, next_run_at),"
                "  INDEX idx_sc_type (check_type)"
                ")"
            )
        conn.commit()

    if "synthetic_check_jobs" not in tables:
        if db_type == "sqlite":
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS synthetic_check_jobs (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    check_id        INTEGER NOT NULL,
                    location        TEXT NOT NULL,
                    scheduled_at    TEXT NOT NULL,
                    status          TEXT NOT NULL DEFAULT 'pending',
                    assigned_to     TEXT,
                    assigned_at     TEXT,
                    started_at      TEXT,
                    completed_at    TEXT,
                    attempt_count   INTEGER NOT NULL DEFAULT 0,
                    max_attempts    INTEGER NOT NULL DEFAULT 3,
                    result_json     TEXT,
                    error_message   TEXT,
                    duration_ms     INTEGER
                );
                CREATE INDEX IF NOT EXISTS idx_scj_status ON synthetic_check_jobs(status, scheduled_at);
                CREATE INDEX IF NOT EXISTS idx_scj_check ON synthetic_check_jobs(check_id, completed_at);
                CREATE INDEX IF NOT EXISTS idx_scj_assigned ON synthetic_check_jobs(assigned_to, status);
            """)
        else:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS synthetic_check_jobs ("
                "  id              BIGINT AUTO_INCREMENT PRIMARY KEY,"
                "  check_id        INT NOT NULL,"
                "  location        VARCHAR(64) NOT NULL,"
                "  scheduled_at    TIMESTAMP NOT NULL,"
                "  status          VARCHAR(16) NOT NULL DEFAULT 'pending',"
                "  assigned_to     VARCHAR(36),"
                "  assigned_at     TIMESTAMP NULL,"
                "  started_at      TIMESTAMP NULL,"
                "  completed_at    TIMESTAMP NULL,"
                "  attempt_count   INT DEFAULT 0,"
                "  max_attempts    INT DEFAULT 3,"
                "  result_json     JSON,"
                "  error_message   TEXT,"
                "  duration_ms     INT,"
                "  INDEX idx_scj_status (status, scheduled_at),"
                "  INDEX idx_scj_check (check_id, completed_at),"
                "  INDEX idx_scj_assigned (assigned_to, status)"
                ")"
            )
        conn.commit()

    if "synthetic_alert_rules" not in tables:
        if db_type == "sqlite":
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS synthetic_alert_rules (
                    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
                    name                TEXT NOT NULL,
                    check_id            INTEGER NOT NULL,
                    location            TEXT,
                    failures            INTEGER NOT NULL DEFAULT 3,
                    severity            TEXT NOT NULL DEFAULT 'critical',
                    notification_channels TEXT NOT NULL DEFAULT '[]',
                    enabled             INTEGER NOT NULL DEFAULT 1,
                    last_fired_at       TEXT,
                    firing              INTEGER NOT NULL DEFAULT 0,
                    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
                );
                CREATE INDEX IF NOT EXISTS idx_sar_check ON synthetic_alert_rules(check_id);
            """)
        else:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS synthetic_alert_rules ("
                "  id                  INT AUTO_INCREMENT PRIMARY KEY,"
                "  name                VARCHAR(255) NOT NULL,"
                "  check_id            INT NOT NULL,"
                "  location            VARCHAR(64),"
                "  failures            INT NOT NULL DEFAULT 3,"
                "  severity            VARCHAR(16) NOT NULL DEFAULT 'critical',"
                "  notification_channels JSON NOT NULL,"
                "  enabled             TINYINT(1) DEFAULT 1,"
                "  last_fired_at       TIMESTAMP NULL,"
                "  firing              TINYINT(1) DEFAULT 0,"
                "  created_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP,"
                "  updated_at          TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,"
                "  INDEX idx_sar_check (check_id)"
                ")"
            )
        conn.commit()

    # Migration 22: add metric-based alert condition columns to synthetic_alert_rules
    if "synthetic_alert_rules" in tables:
        cols = _get_table_columns(conn, "synthetic_alert_rules", db_type)
        if "condition_type" not in cols:
            conn.execute(
                "ALTER TABLE synthetic_alert_rules ADD COLUMN condition_type VARCHAR(16) NOT NULL DEFAULT 'failure'"
            )
        if "metric_name" not in cols:
            conn.execute("ALTER TABLE synthetic_alert_rules ADD COLUMN metric_name VARCHAR(32)")
        if "metric_operator" not in cols:
            conn.execute("ALTER TABLE synthetic_alert_rules ADD COLUMN metric_operator VARCHAR(4)")
        if "metric_threshold" not in cols:
            conn.execute(
                "ALTER TABLE synthetic_alert_rules ADD COLUMN metric_threshold VARCHAR(32)"
            )
        if "consecutive_occurrences" not in cols:
            conn.execute(
                "ALTER TABLE synthetic_alert_rules ADD COLUMN consecutive_occurrences INT NOT NULL DEFAULT 3"
            )
        conn.commit()

    # Migration 23: add dns_answer_change columns to synthetic_alert_rules
    if "synthetic_alert_rules" in tables:
        cols = _get_table_columns(conn, "synthetic_alert_rules", db_type)
        if "dns_last_answers" not in cols:
            conn.execute("ALTER TABLE synthetic_alert_rules ADD COLUMN dns_last_answers TEXT")
        if "dns_change_count" not in cols:
            conn.execute(
                "ALTER TABLE synthetic_alert_rules ADD COLUMN dns_change_count INTEGER NOT NULL DEFAULT 0"
            )
        conn.commit()

    # Migration 24: widen condition_type column for dns_answer_change (18 chars)
    if "synthetic_alert_rules" in tables and db_type in ("mysql", "mariadb"):
        cols = _get_table_columns(conn, "synthetic_alert_rules", db_type)
        # Read all results from INFORMATION_SCHEMA to avoid unread result errors
        try:
            conn.execute(
                "ALTER TABLE synthetic_alert_rules MODIFY COLUMN condition_type "
                "VARCHAR(32) NOT NULL DEFAULT 'failure'"
            )
            conn.commit()
        except Exception:
            pass

    # Migration 25: add dns_change_persist column for sticky DNS change alerts
    if "synthetic_alert_rules" in tables:
        cols = _get_table_columns(conn, "synthetic_alert_rules", db_type)
        if "dns_change_persist" not in cols:
            conn.execute(
                "ALTER TABLE synthetic_alert_rules ADD COLUMN dns_change_persist INTEGER NOT NULL DEFAULT 0"
            )
            conn.commit()

    # Migration 20: add discord to notification_channels allowed types
    # SQLite: drop CHECK constraint by recreating the table (safe when empty)
    if db_type == "sqlite":
        nch_count = conn.execute("SELECT COUNT(*) FROM notification_channels").fetchone()[0]
        if nch_count == 0:
            # Recreate table without CHECK constraint so discord type is allowed
            conn.executescript("""
                DROP TABLE IF EXISTS notification_channels;
                CREATE TABLE notification_channels (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    name            TEXT    NOT NULL,
                    type            TEXT    NOT NULL,
                    config          TEXT    NOT NULL DEFAULT '{}',
                    enabled         INTEGER NOT NULL DEFAULT 1,
                    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
                );
                CREATE INDEX IF NOT EXISTS idx_notification_channels_enabled ON notification_channels(enabled);
            """)
            conn.commit()

    # Migration 23: logfile_watches table for WebUI-configured log file monitoring
    if "logfile_watches" not in tables:
        if db_type == "sqlite":
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS logfile_watches (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    agent_id        TEXT    NOT NULL,
                    name            TEXT    NOT NULL,
                    path            TEXT    NOT NULL,
                    pattern         TEXT    NOT NULL,
                    alert_on_match  INTEGER NOT NULL DEFAULT 1,
                    enabled         INTEGER NOT NULL DEFAULT 1,
                    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                    created_by      INTEGER REFERENCES users(id),
                    UNIQUE(agent_id, name)
                );
                CREATE INDEX IF NOT EXISTS idx_lw_agent ON logfile_watches(agent_id);
                CREATE INDEX IF NOT EXISTS idx_lw_enabled ON logfile_watches(enabled);
            """)
        else:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS logfile_watches ("
                "  id              INT AUTO_INCREMENT PRIMARY KEY,"
                "  agent_id        VARCHAR(36) NOT NULL,"
                "  name            VARCHAR(255) NOT NULL,"
                "  path            TEXT NOT NULL,"
                "  pattern         TEXT NOT NULL,"
                "  alert_on_match  TINYINT(1) NOT NULL DEFAULT 1,"
                "  enabled         TINYINT(1) NOT NULL DEFAULT 1,"
                "  created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "  updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,"
                "  created_by      INT,"
                "  UNIQUE KEY uq_lw_agent_name (agent_id, name),"
                "  INDEX idx_lw_agent (agent_id),"
                "  INDEX idx_lw_enabled (enabled),"
                "  FOREIGN KEY (created_by) REFERENCES users(id)"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
            )
        conn.commit()

    # Migration 26: synthetic_alert_policies table + policy columns on alert_rules
    if "synthetic_alert_policies" not in tables:
        if db_type == "sqlite":
            conn.executescript("""
                CREATE TABLE synthetic_alert_policies (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    name            TEXT NOT NULL,
                    check_type      TEXT NOT NULL,
                    condition_config TEXT NOT NULL DEFAULT '{}',
                    severity        TEXT NOT NULL DEFAULT 'critical',
                    enabled         INTEGER NOT NULL DEFAULT 1,
                    created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                    updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
                );
            """)
            conn.commit()
        else:
            conn.execute("""
                CREATE TABLE synthetic_alert_policies (
                    id              INT AUTO_INCREMENT PRIMARY KEY,
                    name            VARCHAR(255) NOT NULL,
                    check_type      VARCHAR(32) NOT NULL,
                    condition_config JSON NOT NULL,
                    severity        VARCHAR(32) NOT NULL DEFAULT 'critical',
                    enabled         TINYINT(1) NOT NULL DEFAULT 1,
                    created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
                ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
            """)
            conn.commit()

        # Seed default policies
        _seed_default_policies(conn, db_type)

    if "synthetic_alert_rules" in tables:
        cols = _get_table_columns(conn, "synthetic_alert_rules", db_type)
        if "policy_id" not in cols:
            if db_type == "sqlite":
                conn.execute(
                    "ALTER TABLE synthetic_alert_rules ADD COLUMN policy_id INTEGER REFERENCES synthetic_alert_policies(id)"
                )
            else:
                conn.execute("ALTER TABLE synthetic_alert_rules ADD COLUMN policy_id INT")
            conn.execute(
                "ALTER TABLE synthetic_alert_rules ADD COLUMN policy_overridden INTEGER NOT NULL DEFAULT 0"
            )
            conn.execute(
                "ALTER TABLE synthetic_alert_rules ADD COLUMN policy_deleted_check_id INTEGER"
            )
            conn.commit()

    # Migration 27: inventory tables (assets, asset_aliases, asset_relationships)
    if "assets" not in tables:
        if db_type == "sqlite":
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS assets (
                    asset_id         TEXT    PRIMARY KEY,
                    asset_type       TEXT    NOT NULL DEFAULT 'host',
                    display_name     TEXT    NOT NULL,
                    parent_id        TEXT    REFERENCES assets(asset_id),
                    metadata         TEXT    NOT NULL DEFAULT '{}',
                    labels           TEXT    NOT NULL DEFAULT '{}',
                    first_seen_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                    last_seen_at     TEXT,
                    status           TEXT    NOT NULL DEFAULT 'active'
                                        CHECK(status IN ('active', 'stale', 'gone')),
                    created_by_source TEXT   NOT NULL DEFAULT 'agent'
                );
                CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);
                CREATE INDEX IF NOT EXISTS idx_assets_parent ON assets(parent_id);
                CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);
            """)
        else:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS assets ("
                "  asset_id         CHAR(36) PRIMARY KEY,"
                "  asset_type       VARCHAR(32) NOT NULL DEFAULT 'host',"
                "  display_name     VARCHAR(255) NOT NULL,"
                "  parent_id        CHAR(36),"
                "  metadata         TEXT NOT NULL DEFAULT ('{}'),"
                "  labels           TEXT NOT NULL DEFAULT ('{}'),"
                "  first_seen_at    DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "  last_seen_at     DATETIME,"
                "  status           VARCHAR(16) NOT NULL DEFAULT 'active',"
                "  created_by_source VARCHAR(64) NOT NULL DEFAULT 'agent',"
                "  FOREIGN KEY (parent_id) REFERENCES assets(asset_id),"
                "  INDEX idx_assets_type (asset_type),"
                "  INDEX idx_assets_parent (parent_id),"
                "  INDEX idx_assets_status (status)"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
            )
        conn.commit()

    if "asset_aliases" not in tables:
        if db_type == "sqlite":
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS asset_aliases (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    asset_id         TEXT    NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
                    alias_type       TEXT    NOT NULL,
                    alias_value      TEXT    NOT NULL,
                    source           TEXT    NOT NULL,
                    confidence       INTEGER NOT NULL DEFAULT 100,
                    first_claimed_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                    last_confirmed_at TEXT,
                    UNIQUE(alias_type, alias_value)
                );
                CREATE INDEX IF NOT EXISTS idx_aa_asset ON asset_aliases(asset_id);
            """)
        else:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS asset_aliases ("
                "  id               INT AUTO_INCREMENT PRIMARY KEY,"
                "  asset_id         CHAR(36) NOT NULL,"
                "  alias_type       VARCHAR(64) NOT NULL,"
                "  alias_value      VARCHAR(255) NOT NULL,"
                "  source           VARCHAR(64) NOT NULL,"
                "  confidence       TINYINT NOT NULL DEFAULT 100,"
                "  first_claimed_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "  last_confirmed_at DATETIME,"
                "  UNIQUE KEY idx_aa_type_value (alias_type, alias_value),"
                "  FOREIGN KEY (asset_id) REFERENCES assets(asset_id) ON DELETE CASCADE,"
                "  INDEX idx_aa_asset (asset_id)"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
            )
        conn.commit()

    if "asset_relationships" not in tables:
        if db_type == "sqlite":
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS asset_relationships (
                    id               INTEGER PRIMARY KEY AUTOINCREMENT,
                    source_asset_id  TEXT    NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
                    target_asset_id  TEXT    NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
                    relationship     TEXT    NOT NULL,
                    metadata         TEXT    NOT NULL DEFAULT '{}',
                    created_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                    UNIQUE(source_asset_id, target_asset_id, relationship)
                );
                CREATE INDEX IF NOT EXISTS idx_ar_target ON asset_relationships(target_asset_id);
                CREATE INDEX IF NOT EXISTS idx_ar_relationship ON asset_relationships(relationship);
            """)
        else:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS asset_relationships ("
                "  id               INT AUTO_INCREMENT PRIMARY KEY,"
                "  source_asset_id  CHAR(36) NOT NULL,"
                "  target_asset_id  CHAR(36) NOT NULL,"
                "  relationship     VARCHAR(32) NOT NULL,"
                "  metadata         TEXT NOT NULL DEFAULT ('{}'),"
                "  created_at       DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "  UNIQUE KEY idx_ar_src_tgt_rel (source_asset_id, target_asset_id, relationship),"
                "  FOREIGN KEY (source_asset_id) REFERENCES assets(asset_id) ON DELETE CASCADE,"
                "  FOREIGN KEY (target_asset_id) REFERENCES assets(asset_id) ON DELETE CASCADE,"
                "  INDEX idx_ar_target (target_asset_id),"
                "  INDEX idx_ar_relationship (relationship)"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
            )
        conn.commit()

    # Migration 27b: add asset_id FK column to nodes, enrollment_requests, config_agent_status
    for table, col in [
        ("nodes", "asset_id"),
        ("enrollment_requests", "asset_id"),
        ("config_agent_status", "asset_id"),
    ]:
        tbl_cols = _get_table_columns(conn, table, db_type)
        if col not in tbl_cols:
            if db_type == "sqlite":
                conn.execute(
                    f"ALTER TABLE {table} ADD COLUMN {col} TEXT REFERENCES assets(asset_id)"
                )
            else:
                conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} CHAR(36)")
            conn.commit()

    # Migration 27c: additional indexes for inventory (created_by_source, last_seen_at,
    # display_name sort, alias_value lookup). These are created idempotently so the
    # migration is safe to re-run.
    _add_index_if_missing(conn, "assets", "idx_assets_source", "created_by_source", db_type)
    _add_index_if_missing(conn, "assets", "idx_assets_last_seen", "last_seen_at", db_type)
    _add_index_if_missing(conn, "assets", "idx_assets_display_name", "display_name", db_type)
    _add_index_if_missing(conn, "asset_aliases", "idx_aa_value", "alias_value", db_type)

    # Migration 28: host_events table for auditd pipeline detections
    tables = _get_tables(conn, db_type)
    if "host_events" not in tables:
        if db_type == "sqlite":
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS host_events (
                    id              INTEGER PRIMARY KEY AUTOINCREMENT,
                    hostname        VARCHAR(255) NOT NULL,
                    timestamp       VARCHAR(64)  NOT NULL,
                    event_type      VARCHAR(128) NOT NULL,
                    rule_name       VARCHAR(128) NOT NULL,
                    pid             INTEGER      NOT NULL,
                    ppid            INTEGER      NOT NULL,
                    exe             VARCHAR(1024) NOT NULL,
                    command_line    TEXT         NOT NULL,
                    uid             INTEGER      NOT NULL,
                    auid            INTEGER      NOT NULL,
                    raw_line        TEXT         NOT NULL,
                    node_id         VARCHAR(128) NOT NULL,
                    ingested_at     TEXT         NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
                );
                CREATE INDEX IF NOT EXISTS idx_host_events_hostname  ON host_events(hostname);
                CREATE INDEX IF NOT EXISTS idx_host_events_timestamp ON host_events(timestamp);
                CREATE INDEX IF NOT EXISTS idx_host_events_node_id   ON host_events(node_id);
            """)
        else:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS host_events ("
                "  id              INT AUTO_INCREMENT PRIMARY KEY,"
                "  hostname        VARCHAR(255) NOT NULL,"
                "  timestamp       VARCHAR(64)  NOT NULL,"
                "  event_type      VARCHAR(128) NOT NULL,"
                "  rule_name       VARCHAR(128) NOT NULL,"
                "  pid             INT          NOT NULL,"
                "  ppid            INT          NOT NULL,"
                "  exe             VARCHAR(1024) NOT NULL,"
                "  command_line    TEXT         NOT NULL,"
                "  uid             INT          NOT NULL,"
                "  auid            INT          NOT NULL,"
                "  raw_line        TEXT         NOT NULL,"
                "  node_id         VARCHAR(128) NOT NULL,"
                "  ingested_at     DATETIME     NOT NULL DEFAULT CURRENT_TIMESTAMP,"
                "  INDEX idx_host_events_hostname (hostname),"
                "  INDEX idx_host_events_timestamp (timestamp),"
                "  INDEX idx_host_events_node_id (node_id)"
                ") ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci"
            )
        conn.commit()

    # Migration 29: add target_labels column to group_alert_conditions
    if "group_alert_conditions" in tables:
        cols = _get_table_columns(conn, "group_alert_conditions", db_type)
        if "target_labels" not in cols:
            if db_type == "sqlite":
                conn.execute("ALTER TABLE group_alert_conditions ADD COLUMN target_labels TEXT")
            else:
                conn.execute("ALTER TABLE group_alert_conditions ADD COLUMN target_labels TEXT")
            conn.commit()

    # Migration 30: add composite (hostname, timestamp) and ingested_at indexes for host_events performance
    if "host_events" in tables:
        if not _index_exists(conn, "idx_host_events_hostname_timestamp", "host_events", db_type):
            if db_type == "sqlite":
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_host_events_hostname_timestamp "
                    "ON host_events(hostname, timestamp)"
                )
            else:
                conn.execute(
                    "CREATE INDEX idx_host_events_hostname_timestamp "
                    "ON host_events(hostname, timestamp)"
                )
            conn.commit()

        if not _index_exists(conn, "idx_host_events_ingested_at", "host_events", db_type):
            if db_type == "sqlite":
                conn.execute(
                    "CREATE INDEX IF NOT EXISTS idx_host_events_ingested_at "
                    "ON host_events(ingested_at)"
                )
            else:
                conn.execute("CREATE INDEX idx_host_events_ingested_at ON host_events(ingested_at)")
            conn.commit()

    # Migration 31: update old rule_type values (whitelist→allowlist, blacklist→blocklist)
    conn.execute("UPDATE ip_rules SET rule_type = 'allowlist' WHERE rule_type = 'whitelist'")
    conn.execute("UPDATE ip_rules SET rule_type = 'blocklist' WHERE rule_type = 'blacklist'")
    conn.commit()

    # Migration 32: seed default noise suppression rules into existing config profiles
    _seed_default_noise_suppression(conn)

    # Migration 33: create host_threat_notifications table for alert dispatch tracking
    if db_type == "sqlite":
        conn.execute("""
            CREATE TABLE IF NOT EXISTS host_threat_notifications (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                hostname        TEXT NOT NULL,
                profile_id      INTEGER NOT NULL REFERENCES config_profiles(id),
                channel_type    TEXT NOT NULL,
                channel_target  TEXT NOT NULL DEFAULT '',
                score           REAL NOT NULL DEFAULT 0,
                threshold       REAL NOT NULL DEFAULT 100,
                severity_tier   REAL NOT NULL DEFAULT 0,
                status          TEXT NOT NULL DEFAULT 'sent',
                acknowledged_at TEXT,
                acknowledged_by TEXT,
                error_message   TEXT,
                created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
            )
        """)
    else:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS host_threat_notifications (
                id              INT AUTO_INCREMENT PRIMARY KEY,
                hostname        VARCHAR(255) NOT NULL,
                profile_id      INT NOT NULL,
                channel_type    VARCHAR(32) NOT NULL,
                channel_target  TEXT NOT NULL DEFAULT '',
                score           DECIMAL(10,2) NOT NULL DEFAULT 0,
                threshold       DECIMAL(10,2) NOT NULL DEFAULT 100,
                severity_tier   DECIMAL(10,2) NOT NULL DEFAULT 0,
                status          VARCHAR(32) NOT NULL DEFAULT 'sent',
                acknowledged_at DATETIME,
                acknowledged_by VARCHAR(255),
                error_message   TEXT,
                created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)
    conn.commit()
    logger.info("Migration 33: ensured host_threat_notifications table exists")

    # Migration 34: create host_threat_alert_config table, migrate data from
    # profile settings, and remove the old keys from profile settings.
    _migrate_host_threat_alert_config(conn, db_type)

    # Migration 35: add last_seen_at column to nodes for agent liveness tracking
    node_cols = _get_table_columns(conn, "nodes", db_type)
    if "last_seen_at" not in node_cols:
        if db_type == "sqlite":
            conn.execute("ALTER TABLE nodes ADD COLUMN last_seen_at TEXT")
        else:
            conn.execute("ALTER TABLE nodes ADD COLUMN last_seen_at DATETIME DEFAULT NULL")
        conn.commit()
        logger.info("Migration 35: added last_seen_at column to nodes")

    # Migration 36: add agent_version column to nodes for vespid daemon version tracking
    node_cols = _get_table_columns(conn, "nodes", db_type)
    if "agent_version" not in node_cols:
        if db_type == "sqlite":
            conn.execute("ALTER TABLE nodes ADD COLUMN agent_version TEXT")
        else:
            conn.execute("ALTER TABLE nodes ADD COLUMN agent_version VARCHAR(32) DEFAULT NULL")
        conn.commit()

    # Migration 37: add resolved_at column to host_threat_notifications for
    # episode-based alerting (a notification is 'resolved' when the host's
    # score drops back below threshold; a new crossing then re-alerts).
    notif_cols = _get_table_columns(conn, "host_threat_notifications", db_type)
    if "resolved_at" not in notif_cols:
        if db_type == "sqlite":
            conn.execute("ALTER TABLE host_threat_notifications ADD COLUMN resolved_at TEXT")
        else:
            conn.execute(
                "ALTER TABLE host_threat_notifications ADD COLUMN resolved_at DATETIME DEFAULT NULL"
            )
        conn.commit()
        logger.info("Migration 37: added resolved_at column to host_threat_notifications")

    # Migration 38: add severity_tier to host_threat_notifications for
    # escalation-based alerting (re-alert when the host's max detection
    # severity tier increases while an episode is active).
    notif_cols = _get_table_columns(conn, "host_threat_notifications", db_type)
    if "severity_tier" not in notif_cols:
        if db_type == "sqlite":
            conn.execute(
                "ALTER TABLE host_threat_notifications ADD COLUMN severity_tier REAL NOT NULL DEFAULT 0"
            )
        else:
            conn.execute(
                "ALTER TABLE host_threat_notifications ADD COLUMN severity_tier DECIMAL(10,2) NOT NULL DEFAULT 0"
            )
        conn.commit()
        logger.info("Migration 38: added severity_tier column to host_threat_notifications")


def _migrate_host_threat_alert_config(conn, db_type: str) -> None:
    """Create host_threat_alert_config table and migrate existing data.

    Moves host_threat_threshold, host_threat_cooldown_seconds, and
    host_threat_notify_channel out of profile settings into their own
    table so they are never synced to agents.
    """

    # Create the table
    if db_type == "sqlite":
        conn.execute("""
            CREATE TABLE IF NOT EXISTS host_threat_alert_config (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                profile_id      INTEGER NOT NULL REFERENCES config_profiles(id) ON DELETE CASCADE,
                threshold       REAL NOT NULL DEFAULT 100.0,
                cooldown_seconds INTEGER NOT NULL DEFAULT 900,
                notify_channel  TEXT NOT NULL DEFAULT '{}',
                created_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                updated_at      TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
                UNIQUE(profile_id)
            )
        """)
    else:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS host_threat_alert_config (
                id              INT AUTO_INCREMENT PRIMARY KEY,
                profile_id      INT NOT NULL UNIQUE,
                threshold       DECIMAL(10,2) NOT NULL DEFAULT 100.00,
                cooldown_seconds INT NOT NULL DEFAULT 900,
                notify_channel  TEXT NOT NULL DEFAULT '{}',
                created_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at      DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP,
                UNIQUE KEY uq_host_threat_alert_profile (profile_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci
        """)
    conn.commit()

    # Migrate existing data from profile settings
    rows = conn.execute("SELECT id, settings FROM config_profiles WHERE is_active = 1").fetchall()

    migrated_count = 0
    for row in rows:
        try:
            settings = (
                json.loads(row["settings"]) if isinstance(row["settings"], str) else row["settings"]
            )
        except (json.JSONDecodeError, TypeError):
            settings = {}

        threshold = settings.pop("host_threat_threshold", None)
        cooldown = settings.pop("host_threat_cooldown_seconds", None)
        channel = settings.pop("host_threat_notify_channel", None)

        # If none of the keys existed, skip
        if threshold is None and cooldown is None and channel is None:
            continue

        # Check if a row already exists for this profile
        existing = conn.execute(
            "SELECT id FROM host_threat_alert_config WHERE profile_id = ?",
            (row["id"],),
        ).fetchone()

        if existing:
            # Update existing row if any value changed
            if threshold is not None:
                conn.execute(
                    "UPDATE host_threat_alert_config SET threshold = ?, updated_at = ? WHERE profile_id = ?",
                    (threshold, _utcnow_iso(), row["id"]),
                )
            if cooldown is not None:
                conn.execute(
                    "UPDATE host_threat_alert_config SET cooldown_seconds = ?, updated_at = ? WHERE profile_id = ?",
                    (cooldown, _utcnow_iso(), row["id"]),
                )
            if channel is not None:
                conn.execute(
                    "UPDATE host_threat_alert_config SET notify_channel = ?, updated_at = ? WHERE profile_id = ?",
                    (json.dumps(channel), _utcnow_iso(), row["id"]),
                )
        else:
            # Insert new row
            conn.execute(
                "INSERT INTO host_threat_alert_config "
                "(profile_id, threshold, cooldown_seconds, notify_channel) "
                "VALUES (?, ?, ?, ?)",
                (
                    row["id"],
                    threshold or 100.0,
                    cooldown or 900,
                    json.dumps(channel) if channel else "{}",
                ),
            )

        # Write back settings without the migrated keys
        # Also scrub these keys if they exist as null/empty
        settings.pop("host_threat_threshold", None)
        settings.pop("host_threat_cooldown_seconds", None)
        settings.pop("host_threat_notify_channel", None)
        settings_json = json.dumps(settings)
        conn.execute(
            "UPDATE config_profiles SET settings = ? WHERE id = ?",
            (settings_json, row["id"]),
        )
        migrated_count += 1

    if migrated_count:
        conn.commit()
        logger.info(
            "Migration 34: migrated host threat alert config for %d profile(s)",
            migrated_count,
        )
    logger.info("Migration 34: ensured host_threat_alert_config table exists")


DEFAULT_POLICIES = [
    {
        "name": "SSL Certificate Expiry",
        "check_type": "ssl",
        "condition_config": '{"type":"metric","metric_name":"days_remaining","metric_operator":"<","metric_threshold":"14","consecutive_occurrences":1}',
        "severity": "critical",
        "enabled": 1,
    },
    {
        "name": "DNS Failure",
        "check_type": "dns",
        "condition_config": '{"type":"failure","failures":3}',
        "severity": "critical",
        "enabled": 1,
    },
    {
        "name": "DNS Answer Change",
        "check_type": "dns",
        "condition_config": '{"type":"dns_answer_change","consecutive_occurrences":1,"dns_change_persist":1}',
        "severity": "critical",
        "enabled": 1,
    },
    {
        "name": "HTTP Failure",
        "check_type": "http",
        "condition_config": '{"type":"failure","failures":3}',
        "severity": "critical",
        "enabled": 1,
    },
    {
        "name": "TCP Failure",
        "check_type": "tcp",
        "condition_config": '{"type":"failure","failures":3}',
        "severity": "critical",
        "enabled": 1,
    },
    {
        "name": "ICMP Failure",
        "check_type": "icmp",
        "condition_config": '{"type":"failure","failures":3}',
        "severity": "critical",
        "enabled": 1,
    },
]


def _seed_default_policies(conn, db_type: str = "sqlite") -> None:
    """Insert default alert policies if the table is empty."""
    existing = conn.execute("SELECT COUNT(*) FROM synthetic_alert_policies").fetchone()[0]
    if existing > 0:
        return
    ignore = _insert_ignore(db_type)
    for p in DEFAULT_POLICIES:
        conn.execute(
            f"{ignore} INTO synthetic_alert_policies (name, check_type, condition_config, severity, enabled) "
            "VALUES (?, ?, ?, ?, ?)",
            (p["name"], p["check_type"], p["condition_config"], p["severity"], p["enabled"]),
        )
    conn.commit()


_DEFAULT_FLEET_CONFIG = [
    ("corroboration_threshold", "1"),
    ("corroboration_window_seconds", "1h"),
    ("fleet_block_ttl_seconds", "1d"),
    ("fleet_recidive_tiers", "[86400, 259200, 604800, 2592000]"),
    ("fleet_recidive_decay_seconds", "30d"),
    ("max_fleet_blocks_per_hour", "100"),
    ("max_reports_per_node_per_hour", "50"),
    ("propagation_paused", "false"),
    ("excluded_event_types", "[]"),
    ("reaper_interval_seconds", "60"),
    ("expired_block_retention_seconds", "1d"),
    ("unlock_webhook_secret", ""),
]


def _seed_fleet_config(conn, db_type: str = "sqlite") -> None:
    """Insert default fleet configuration values."""
    ignore = _insert_ignore(db_type)
    for key, value in _DEFAULT_FLEET_CONFIG:
        conn.execute(
            f"{ignore} INTO fleet_config (config_key, config_value) VALUES (?, ?)",
            (key, value),
        )
    conn.commit()


_DEFAULT_FEEDS = [
    {
        "name": "firehol_level1",
        "url": "https://iplists.firehol.org/files/firehol_level1.netset",
        "provider": "FireHOL / iplists.firehol.org",
        "description": (
            "FireHOL Level 1 is a curated aggregation of several high-confidence "
            "blocklists that have been verified to have an extremely low false-positive "
            "rate. It combines data from multiple upstream sources (including Spamhaus, "
            "DShield, and abuse.ch) into a single deduplicated netset."
        ),
        "detects": (
            "Known command-and-control servers; hijacked/stolen IP ranges; "
            "active exploit and malware distribution infrastructure; "
            "confirmed spam sources; IPs with zero legitimate traffic profile."
        ),
        "confidence": "very_high",
        "recommended_usage": (
            "Safe to auto-block at the network perimeter. Suitable for inline "
            "blocking on firewalls, WAFs, and IDS/IPS prefilters with no manual review."
        ),
        "format": "cidr",
        "refresh_seconds": 21600,
        "category": "aggregated",
        "is_default": 1,
    },
    {
        "name": "firehol_level2",
        "url": "https://iplists.firehol.org/files/firehol_level2.netset",
        "provider": "FireHOL / iplists.firehol.org",
        "description": (
            "FireHOL Level 2 extends Level 1 with additional upstream sources that "
            "provide broader coverage but carry a slightly higher false-positive risk. "
            "It includes feeds with shorter observation windows and less stringent "
            "inclusion criteria."
        ),
        "detects": (
            "Everything in Level 1 plus: recently observed scanning hosts; "
            "brute-force attackers from community sensor networks; "
            "IPs flagged by multiple honeypot systems."
        ),
        "confidence": "high",
        "recommended_usage": (
            "Recommended for perimeter blocking with periodic review. Consider "
            "log-and-alert mode for environments where false positives are costly."
        ),
        "format": "cidr",
        "refresh_seconds": 21600,
        "category": "aggregated",
        "is_default": 0,
    },
    {
        "name": "spamhaus_drop",
        "url": "https://www.spamhaus.org/drop/drop.txt",
        "provider": "Spamhaus",
        "description": (
            "The Spamhaus DROP (Don't Route Or Peer) list identifies netblocks that "
            "have been hijacked or leased by professional spam and cyber-crime "
            "operations. These ranges are entirely controlled by criminals and carry "
            "zero legitimate traffic. The list now includes former EDROP ranges."
        ),
        "detects": (
            "Hijacked IP space used for spam campaigns; bulletproof hosting ranges; "
            "netblocks allocated to cyber-criminal organizations; "
            "IP ranges with no legitimate routing justification."
        ),
        "confidence": "very_high",
        "recommended_usage": (
            "Safe to null-route or drop at the network edge with zero risk of "
            "false positives. Recommended for all environments without exception."
        ),
        "format": "cidr",
        "refresh_seconds": 43200,
        "category": "hijacked",
        "is_default": 1,
    },
    {
        "name": "abuse_ch_feodo",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "provider": "abuse.ch",
        "description": (
            "The Feodo Tracker blocklist identifies active command-and-control (C2) "
            "servers used by banking trojans and loader malware families including "
            "Emotet, Dridex, TrickBot, and QakBot. IPs are verified through active "
            "probing and malware sample analysis by the abuse.ch research team."
        ),
        "detects": (
            "Active botnet C2 infrastructure; banking trojan callback servers; "
            "malware loader distribution points; Emotet/Dridex/TrickBot/QakBot "
            "communication endpoints."
        ),
        "confidence": "very_high",
        "recommended_usage": (
            "Safe to auto-block at the perimeter. Critical for preventing data "
            "exfiltration and lateral movement from infected hosts. Also useful as "
            "an IOC source for threat hunting in DNS/proxy logs."
        ),
        "format": "plain",
        "refresh_seconds": 3600,
        "category": "botnet",
        "is_default": 1,
    },
    {
        "name": "abuse_ch_sslbl",
        "url": "https://sslbl.abuse.ch/blacklist/sslipblacklist.txt",
        "provider": "abuse.ch",
        "description": (
            "The SSL Blacklist (SSLBL) identifies IPs associated with malicious SSL "
            "certificates used by botnet C2 channels. Certificates are fingerprinted "
            "and tracked by the abuse.ch team; IPs are listed when they serve a known "
            "bad certificate."
        ),
        "detects": (
            "C2 servers using SSL/TLS for encrypted botnet communication; "
            "malware distribution sites with known-bad certificates; "
            "IPs hosting phishing infrastructure with fraudulent SSL certs."
        ),
        "confidence": "high",
        "recommended_usage": (
            "Safe to auto-block at the perimeter. Complements Feodo Tracker by "
            "catching C2 infrastructure identified through certificate analysis "
            "rather than malware samples alone."
        ),
        "format": "plain",
        "refresh_seconds": 3600,
        "category": "botnet",
        "is_default": 0,
    },
    {
        "name": "blocklist_de",
        "url": "https://lists.blocklist.de/lists/all.txt",
        "provider": "Blocklist.de",
        "description": (
            "Blocklist.de aggregates attack reports from over 600 participating "
            "servers running fail2ban and similar intrusion detection systems. IPs "
            "are listed after being reported for attacks against SSH, mail, web, "
            "and FTP services across the sensor network."
        ),
        "detects": (
            "SSH brute-force attackers; SMTP abuse and spam relay attempts; "
            "web application attacks (SQL injection, path traversal); "
            "FTP brute-force; IRC abuse; general port scanning."
        ),
        "confidence": "medium",
        "recommended_usage": (
            "Good for perimeter blocking with periodic review. High volume list — "
            "consider using in log-and-alert mode for sensitive environments, or "
            "combine with rate-limiting rather than hard blocks."
        ),
        "format": "plain",
        "refresh_seconds": 3600,
        "category": "attacks",
        "is_default": 0,
    },
    {
        "name": "ci_army",
        "url": "https://cinsscore.com/list/ci-badguys.txt",
        "provider": "CINS Score / CINS Army",
        "description": (
            'The CINS Army "Badguys" list is a high-confidence IP reputation feed '
            "built from real attack telemetry collected by a global network of "
            "distributed sensors. IPs are added after repeatedly triggering malicious "
            "behavior across multiple participating networks and receiving a very poor "
            "CINS reputation score."
        ),
        "detects": (
            "Internet-wide scanning and reconnaissance; "
            "SSH/RDP/FTP brute-force attempts; "
            "exploit and vulnerability probing; "
            "botnet and malware callback activity; "
            "general abusive automated traffic."
        ),
        "confidence": "high",
        "recommended_usage": (
            "Safe to auto-block at the network perimeter (firewall, WAF, IDS/IPS "
            "prefilter). Requires repeated malicious activity observed across "
            "multiple independent sensors before listing."
        ),
        "format": "plain",
        "refresh_seconds": 7200,
        "category": "attacks",
        "is_default": 0,
    },
    {
        "name": "et_compromised",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "provider": "Proofpoint / Emerging Threats",
        "description": (
            "The Emerging Threats compromised IP list identifies hosts that have been "
            "verified as actively participating in attacks. Unlike scanner lists, "
            "these are typically legitimate servers or endpoints that have been "
            "compromised and are being used as attack infrastructure."
        ),
        "detects": (
            "Compromised web servers used for malware distribution; "
            "hacked hosts participating in DDoS botnets; "
            "breached mail servers relaying spam; "
            "infected endpoints acting as proxy nodes for criminal operations."
        ),
        "confidence": "high",
        "recommended_usage": (
            "Safe to auto-block at the perimeter. Useful for identifying compromised "
            "infrastructure in your supply chain. IPs may rotate back to legitimate "
            "use after cleanup — the feed reflects current state."
        ),
        "format": "plain",
        "refresh_seconds": 7200,
        "category": "compromised",
        "is_default": 0,
    },
    {
        "name": "dshield_top20",
        "url": "https://feeds.dshield.org/block.txt",
        "provider": "SANS Internet Storm Center (ISC)",
        "description": (
            "The DShield block list identifies the top attacking subnets observed "
            "across the SANS ISC global sensor network. It represents the most "
            "aggressive /24 networks based on packet volume and target diversity "
            "reported by thousands of participating firewalls worldwide."
        ),
        "detects": (
            "Top attacking subnets by volume; mass port scanning operations; "
            "large-scale brute-force campaigns; worm propagation sources; "
            "networks hosting widespread automated attack tools."
        ),
        "confidence": "high",
        "recommended_usage": (
            "Safe to auto-block at the perimeter. Updated daily — represents the "
            "current worst offenders. Good complement to more granular per-IP feeds."
        ),
        "format": "cidr",
        "refresh_seconds": 86400,
        "category": "attacks",
        "is_default": 0,
    },
    {
        "name": "tor_exit_nodes",
        "url": "https://check.torproject.org/torbulkexitlist",
        "provider": "The Tor Project",
        "description": (
            "The official Tor exit node list published by the Tor Project. Contains "
            "IP addresses of all currently active Tor exit relays. These are the "
            "endpoints from which Tor traffic emerges onto the public internet."
        ),
        "detects": (
            "Tor exit relay IPs used for anonymous browsing; "
            "traffic sources that cannot be attributed to a specific user; "
            "potential vectors for anonymous abuse, scraping, or credential stuffing."
        ),
        "confidence": "very_high",
        "recommended_usage": (
            "Use with caution — blocking Tor exits also blocks legitimate privacy-"
            "conscious users. Best used for rate-limiting, enhanced authentication "
            "requirements, or CAPTCHA challenges rather than outright blocking. "
            "Appropriate to hard-block only for services with no legitimate "
            "anonymous use case."
        ),
        "format": "plain",
        "refresh_seconds": 3600,
        "category": "anonymizers",
        "is_default": 0,
    },
    {
        "name": "binarydefense",
        "url": "https://binarydefense.com/banlist.txt",
        "provider": "Binary Defense",
        "description": (
            "The Binary Defense ban list is generated from their Artillery honeypot "
            "network. IPs are listed after being observed actively connecting to "
            "honeypot services and performing scanning, exploitation attempts, or "
            "brute-force attacks against the decoy infrastructure."
        ),
        "detects": (
            "Active port scanners targeting common services; "
            "automated exploitation attempts against honeypots; "
            "brute-force attackers probing SSH, RDP, and web services; "
            "reconnaissance tools mapping internet-facing infrastructure."
        ),
        "confidence": "high",
        "recommended_usage": (
            "Safe to auto-block at the network perimeter. Honeypot-sourced data "
            "has very low false-positive rates since no legitimate traffic should "
            "reach honeypot services."
        ),
        "format": "plain",
        "refresh_seconds": 7200,
        "category": "attacks",
        "is_default": 0,
    },
]


def _seed_feed_catalog(conn, db_type: str = "sqlite") -> None:
    """Insert default feed catalog entries."""
    ignore = _insert_ignore(db_type)
    for feed in _DEFAULT_FEEDS:
        conn.execute(
            f"{ignore} INTO feed_catalog "
            "(name, url, description, format, refresh_seconds, category, "
            "is_default, provider, confidence, detects, recommended_usage, created_by) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'system')",
            (
                feed["name"],
                feed["url"],
                feed["description"],
                feed["format"],
                feed["refresh_seconds"],
                feed["category"],
                feed["is_default"],
                feed.get("provider", ""),
                feed.get("confidence", "medium"),
                feed.get("detects", ""),
                feed.get("recommended_usage", ""),
            ),
        )
    conn.commit()


_SCHEMA_SQL = """\
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

-- Events table: stores all ingested SecurityEvents
CREATE TABLE IF NOT EXISTS events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        TEXT    NOT NULL UNIQUE,
    node_id         TEXT    NOT NULL,
    timestamp       TEXT    NOT NULL,
    source_ip       TEXT    NOT NULL,
    event_type      TEXT    NOT NULL,
    action_taken    TEXT    NOT NULL,
    geo_country     TEXT,
    geo_city        TEXT,
    geo_asn         TEXT,
    geo_org         TEXT,
    geo_latitude    TEXT,
    geo_longitude   TEXT,
    geo_data        TEXT    NOT NULL DEFAULT '{}',
    metadata        TEXT    NOT NULL DEFAULT '{}',
    ingested_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_events_timestamp   ON events(timestamp);
CREATE INDEX IF NOT EXISTS idx_events_source_ip   ON events(source_ip);
CREATE INDEX IF NOT EXISTS idx_events_node_id     ON events(node_id);
CREATE INDEX IF NOT EXISTS idx_events_event_type  ON events(event_type);
CREATE INDEX IF NOT EXISTS idx_events_geo_country ON events(geo_country);
CREATE INDEX IF NOT EXISTS idx_events_ingested    ON events(ingested_at);

-- Event log context: raw log lines surrounding a blocked event.
-- Stored separately from events.metadata so the events table stays
-- lean and context can be lazy-loaded in the UI.
CREATE TABLE IF NOT EXISTS event_log_context (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id        TEXT    NOT NULL REFERENCES events(event_id) ON DELETE CASCADE,
    line_idx        INTEGER NOT NULL,
    raw             TEXT    NOT NULL,
    parser          TEXT,
    is_trigger      INTEGER NOT NULL DEFAULT 0,
    repeat_count    INTEGER NOT NULL DEFAULT 1,
    first_ts        TEXT,
    last_ts         TEXT
);

CREATE INDEX IF NOT EXISTS idx_elc_event_id ON event_log_context(event_id);

-- App settings: simple key-value store for tunable parameters
CREATE TABLE IF NOT EXISTS app_settings (
    `key`           VARCHAR(64) PRIMARY KEY,
    value           TEXT    NOT NULL,
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

-- Users table: dashboard operators
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT    NOT NULL UNIQUE,
    password_hash   TEXT    NOT NULL,
    role            TEXT    NOT NULL DEFAULT 'viewer'
                    CHECK(role IN ('admin', 'analyst', 'viewer')),
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_login_at   TEXT,
    display_name    TEXT    NOT NULL DEFAULT '',
    theme           TEXT    NOT NULL DEFAULT 'dark'
                    CHECK(theme IN ('dark', 'light', 'nord', 'vespid')),
    failed_login_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until    TEXT,
    onboarding_dismissed INTEGER NOT NULL DEFAULT 0,
    brand_beam_enabled INTEGER NOT NULL DEFAULT 1
);

-- API Keys table: bearer tokens for node authentication
CREATE TABLE IF NOT EXISTS api_keys (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    key_hash        TEXT    NOT NULL UNIQUE,
    key_prefix      TEXT    NOT NULL,
    label           TEXT    NOT NULL,
    role            TEXT    NOT NULL DEFAULT 'agent',
    node_id_restriction TEXT,
    is_active       INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_used_at    TEXT,
    created_by      INTEGER REFERENCES users(id),
    host_id         TEXT
);

-- Nodes table: auto-registered node registry
CREATE TABLE IF NOT EXISTS nodes (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id         TEXT    NOT NULL UNIQUE,
    display_name    TEXT    NOT NULL DEFAULT '',
    first_seen_at   TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_event_at   TEXT,
    total_events    INTEGER NOT NULL DEFAULT 0,
    last_geo_data   TEXT    NOT NULL DEFAULT '{}',
    -- last_block_list moved to node_blocks table
    last_allowlist  MEDIUMTEXT NOT NULL DEFAULT '[]',
    last_feeds      MEDIUMTEXT NOT NULL DEFAULT '[]',
    last_counters   MEDIUMTEXT NOT NULL DEFAULT '[]',
    last_host_info  TEXT    NOT NULL DEFAULT '{}'
);

-- Node blocks: indexed block list entries pushed by the daemon
CREATE TABLE IF NOT EXISTS node_blocks (
    node_id     TEXT NOT NULL,
    ip          TEXT NOT NULL,
    reason      TEXT NOT NULL DEFAULT '',
    blocked_at  REAL NOT NULL,
    expires_at  REAL NOT NULL,
    strike      INTEGER NOT NULL DEFAULT 1,
    PRIMARY KEY (node_id, ip)
);

-- Audit Log table
CREATE TABLE IF NOT EXISTS audit_log (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    actor           TEXT    NOT NULL,
    actor_ip        TEXT,
    action_type     TEXT    NOT NULL,
    target          TEXT,
    details         TEXT    NOT NULL DEFAULT '{}'
);

CREATE INDEX IF NOT EXISTS idx_audit_timestamp   ON audit_log(timestamp);
CREATE INDEX IF NOT EXISTS idx_audit_action_type ON audit_log(action_type);

-- Pending Commands table
CREATE TABLE IF NOT EXISTS pending_commands (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    command_id      TEXT    NOT NULL UNIQUE,
    node_id         TEXT    NOT NULL,
    command_type    TEXT    NOT NULL,
    payload         TEXT    NOT NULL DEFAULT '{}',
    status          TEXT    NOT NULL DEFAULT 'pending'
                    CHECK(status IN ('pending', 'acknowledged', 'completed', 'failed', 'expired')),
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    acknowledged_at TEXT,
    result          TEXT
);

CREATE INDEX IF NOT EXISTS idx_commands_node_id ON pending_commands(node_id);
CREATE INDEX IF NOT EXISTS idx_commands_status  ON pending_commands(status);

-- IP Rules table: tracks allowlist/blocklist entries managed from the dashboard
CREATE TABLE IF NOT EXISTS ip_rules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_type       TEXT    NOT NULL CHECK(rule_type IN ('allowlist', 'blocklist')),
    entry           TEXT    NOT NULL,
    reason          TEXT    NOT NULL DEFAULT '',
    created_by      TEXT    NOT NULL,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    is_active       INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_ip_rules_type   ON ip_rules(rule_type);
CREATE INDEX IF NOT EXISTS idx_ip_rules_active ON ip_rules(is_active);

-- Feed Catalog table: centrally managed threat intelligence feeds
CREATE TABLE IF NOT EXISTS feed_catalog (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    url             TEXT    NOT NULL,
    description     TEXT    NOT NULL DEFAULT '',
    format          TEXT    NOT NULL DEFAULT 'plain'
                    CHECK(format IN ('plain', 'cidr')),
    refresh_seconds INTEGER NOT NULL DEFAULT 3600,
    category        TEXT    NOT NULL DEFAULT 'general',
    provider        TEXT    NOT NULL DEFAULT '',
    confidence      TEXT    NOT NULL DEFAULT 'medium'
                    CHECK(confidence IN ('low', 'medium', 'high', 'very_high')),
    detects         TEXT    NOT NULL DEFAULT '',
    recommended_usage TEXT  NOT NULL DEFAULT '',
    is_default      INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    created_by      TEXT    NOT NULL DEFAULT 'system'
);

CREATE INDEX IF NOT EXISTS idx_feed_catalog_category ON feed_catalog(category);

-- Counter Snapshots table: historical time-series counter data from heartbeats
CREATE TABLE IF NOT EXISTS counter_snapshots (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id     TEXT    NOT NULL,
    timestamp   TEXT    NOT NULL,
    set_name    TEXT    NOT NULL,
    chain       TEXT    NOT NULL DEFAULT '',
    family      TEXT    NOT NULL DEFAULT '',
    packets     INTEGER NOT NULL DEFAULT 0,
    bytes       INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_cs_node_set_ts
    ON counter_snapshots(node_id, set_name, timestamp);

CREATE INDEX IF NOT EXISTS idx_cs_timestamp
    ON counter_snapshots(timestamp);

-- Enrollment Requests table: tracks agent enrollment lifecycle
CREATE TABLE IF NOT EXISTS enrollment_requests (
    id                    INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id               TEXT    NOT NULL,
    hostname              TEXT    NOT NULL,
    source_ip             TEXT,
    status                TEXT    NOT NULL DEFAULT 'pending'
                          CHECK(status IN ('pending', 'approved', 'rejected', 'revoked')),
    requested_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    decided_at            TEXT,
    decided_by            TEXT,
    api_key_id            INTEGER REFERENCES api_keys(id),
    credentials_retrieved INTEGER NOT NULL DEFAULT 0,
    pending_token         TEXT
);

CREATE INDEX IF NOT EXISTS idx_enrollment_node_id ON enrollment_requests(node_id);
CREATE INDEX IF NOT EXISTS idx_enrollment_status  ON enrollment_requests(status);

-- Enrollment Settings table: server-wide enrollment configuration
CREATE TABLE IF NOT EXISTS enrollment_settings (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    setting_key   TEXT    NOT NULL UNIQUE,
    setting_value TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_by    TEXT    NOT NULL DEFAULT 'system'
);

-- Fleet Blocks table: active fleet-wide blocklist
CREATE TABLE IF NOT EXISTS fleet_blocks (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    fleet_block_id  TEXT    NOT NULL UNIQUE,
    source_ip       TEXT    NOT NULL,
    status          TEXT    NOT NULL DEFAULT 'pending'
                    CHECK(status IN ('pending', 'active', 'expired', 'removed')),
    first_reported_at TEXT  NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_renewed_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    approved_at     TEXT,
    expires_at      TEXT    NOT NULL,
    reporting_node_count INTEGER NOT NULL DEFAULT 1,
    originating_node_id TEXT NOT NULL,
    event_type      TEXT    NOT NULL,
    detection_rule  TEXT    NOT NULL DEFAULT '',
    reason          TEXT    NOT NULL DEFAULT '',
    ttl_seconds     INTEGER NOT NULL DEFAULT 3600
);

CREATE INDEX IF NOT EXISTS idx_fleet_blocks_source_ip ON fleet_blocks(source_ip);
CREATE INDEX IF NOT EXISTS idx_fleet_blocks_status    ON fleet_blocks(status);
CREATE INDEX IF NOT EXISTS idx_fleet_blocks_expires   ON fleet_blocks(expires_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_fleet_blocks_ip_active
    ON fleet_blocks(source_ip) WHERE status = 'active';

-- Fleet Block Reports table: individual node reports for corroboration tracking
CREATE TABLE IF NOT EXISTS fleet_block_reports (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    source_ip       TEXT    NOT NULL,
    node_id         TEXT    NOT NULL,
    event_type      TEXT    NOT NULL,
    detection_rule  TEXT    NOT NULL DEFAULT '',
    block_ttl_seconds INTEGER NOT NULL DEFAULT 86400,
    reported_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    fleet_block_id  TEXT    REFERENCES fleet_blocks(fleet_block_id),
    event_id        TEXT    NOT NULL DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_fbr_source_ip  ON fleet_block_reports(source_ip);
CREATE INDEX IF NOT EXISTS idx_fbr_node_id    ON fleet_block_reports(node_id);
CREATE INDEX IF NOT EXISTS idx_fbr_reported   ON fleet_block_reports(reported_at);
CREATE UNIQUE INDEX IF NOT EXISTS idx_fbr_ip_node
    ON fleet_block_reports(source_ip, node_id);

-- Fleet Allowlist table: global allow-list for fleet blocklist
CREATE TABLE IF NOT EXISTS fleet_allowlist (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    entry       TEXT    NOT NULL UNIQUE,
    reason      TEXT    NOT NULL DEFAULT '',
    created_by  TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    is_active   INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_fleet_al_active ON fleet_allowlist(is_active);

-- Fleet Config table: propagation configuration (key-value)
CREATE TABLE IF NOT EXISTS fleet_config (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    config_key    TEXT    NOT NULL UNIQUE,
    config_value  TEXT    NOT NULL,
    updated_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_by    TEXT    NOT NULL DEFAULT 'system'
);

-- Detection Rules: brute force type
CREATE TABLE IF NOT EXISTS detection_rules_brute_force (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    event_type      TEXT    NOT NULL,
    max_attempts    INTEGER NOT NULL,
    window_seconds  INTEGER NOT NULL,
    parser          TEXT    NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 1,
    is_template     INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    created_by      TEXT    NOT NULL DEFAULT 'system'
);

-- Detection Rules: custom regex type
CREATE TABLE IF NOT EXISTS detection_rules_custom (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    event_type      TEXT    NOT NULL,
    regex           TEXT    NOT NULL,
    log_sources     TEXT    NOT NULL DEFAULT '["*"]',
    max_attempts    INTEGER NOT NULL,
    window_seconds  INTEGER NOT NULL,
    enabled         INTEGER NOT NULL DEFAULT 1,
    is_template     INTEGER NOT NULL DEFAULT 0,
    pack_name       TEXT    NOT NULL DEFAULT '',
    tags            TEXT    NOT NULL DEFAULT '[]',
    sigma_id        TEXT    NOT NULL DEFAULT '',
    sigma_status    TEXT    NOT NULL DEFAULT '',
    content_hash    TEXT    NOT NULL DEFAULT '',
    user_modified   INTEGER NOT NULL DEFAULT 0,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    created_by      TEXT    NOT NULL DEFAULT 'system'
);

-- Detection Rules: revision counter (single-row)
CREATE TABLE IF NOT EXISTS detection_rules_revision (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    revision        INTEGER NOT NULL DEFAULT 0,
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

INSERT OR IGNORE INTO detection_rules_revision (id, revision) VALUES (1, 0);

-- Detection Rules: correlation (multi-signal) type
CREATE TABLE IF NOT EXISTS detection_rules_correlation (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    event_type      TEXT    NOT NULL,
    min_categories  INTEGER NOT NULL DEFAULT 3,
    window_seconds  INTEGER NOT NULL DEFAULT 600,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    created_by      TEXT    NOT NULL DEFAULT 'system'
);

-- Configuration Profiles table: centralized agent configuration templates
CREATE TABLE IF NOT EXISTS config_profiles (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,
    name_lower      TEXT    NOT NULL UNIQUE,
    description     TEXT    NOT NULL DEFAULT '',
    version         INTEGER NOT NULL DEFAULT 1,
    settings        TEXT    NOT NULL DEFAULT '{}',
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    created_by      TEXT    NOT NULL,
    is_active       INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_config_profiles_active ON config_profiles(is_active);
CREATE INDEX IF NOT EXISTS idx_config_profiles_created ON config_profiles(created_at);

-- Configuration Version History table: tracks profile changes over time
CREATE TABLE IF NOT EXISTS config_version_history (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id      INTEGER NOT NULL REFERENCES config_profiles(id),
    version         INTEGER NOT NULL,
    previous_settings TEXT NOT NULL DEFAULT '{}',
    new_settings    TEXT    NOT NULL DEFAULT '{}',
    changed_by      TEXT    NOT NULL,
    changed_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    change_reason   TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_cvh_profile_id ON config_version_history(profile_id);
CREATE INDEX IF NOT EXISTS idx_cvh_version ON config_version_history(profile_id, version);

-- Configuration Assignments table: maps profiles to agents or groups
CREATE TABLE IF NOT EXISTS config_assignments (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id         TEXT,
    group_id        INTEGER,
    profile_id      INTEGER NOT NULL REFERENCES config_profiles(id),
    assigned_at     TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    assigned_by     TEXT    NOT NULL,
    is_active       INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_ca_node_id ON config_assignments(node_id);
CREATE INDEX IF NOT EXISTS idx_ca_group_id ON config_assignments(group_id);
CREATE INDEX IF NOT EXISTS idx_ca_profile_id ON config_assignments(profile_id);
CREATE INDEX IF NOT EXISTS idx_ca_active ON config_assignments(is_active);

-- Agent Groups table: logical grouping of agents for bulk assignment
CREATE TABLE IF NOT EXISTS agent_groups (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL UNIQUE,
    description     TEXT    NOT NULL DEFAULT '',
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    created_by      TEXT    NOT NULL
);

-- Agent Group Members table: maps agents to groups
CREATE TABLE IF NOT EXISTS agent_group_members (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id        INTEGER NOT NULL REFERENCES agent_groups(id),
    node_id         TEXT    NOT NULL,
    added_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    added_by        TEXT    NOT NULL,
    UNIQUE(group_id, node_id)
);

CREATE INDEX IF NOT EXISTS idx_agm_group_id ON agent_group_members(group_id);
CREATE INDEX IF NOT EXISTS idx_agm_node_id ON agent_group_members(node_id);

-- Configuration Rollouts table: tracks staged/canary rollout state
CREATE TABLE IF NOT EXISTS config_rollouts (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    profile_id      INTEGER NOT NULL REFERENCES config_profiles(id),
    target_version  INTEGER NOT NULL,
    policy          TEXT    NOT NULL DEFAULT 'immediate'
                    CHECK(policy IN ('immediate', 'canary', 'staged')),
    status          TEXT    NOT NULL DEFAULT 'pending'
                    CHECK(status IN ('pending', 'in_progress', 'completed', 'cancelled', 'failed')),
    canary_nodes    TEXT    NOT NULL DEFAULT '[]',
    current_percentage INTEGER NOT NULL DEFAULT 100,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    created_by      TEXT    NOT NULL,
    completed_at    TEXT,
    failure_count   INTEGER NOT NULL DEFAULT 0,
    success_count   INTEGER NOT NULL DEFAULT 0,
    total_targeted  INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_cr_profile_id ON config_rollouts(profile_id);
CREATE INDEX IF NOT EXISTS idx_cr_status ON config_rollouts(status);

-- Configuration Agent Status table: per-agent config state for rollout tracking
CREATE TABLE IF NOT EXISTS config_agent_status (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    node_id         TEXT    NOT NULL,
    profile_id      INTEGER REFERENCES config_profiles(id),
    acknowledged_version INTEGER,
    last_check_in   TEXT,
    management_mode TEXT    NOT NULL DEFAULT 'standalone',
    config_status   TEXT    NOT NULL DEFAULT 'unknown'
                    CHECK(config_status IN ('unknown', 'up_to_date', 'pending', 'failed')),
    last_failure_reason TEXT,
    agent_version   TEXT,
    health_uptime   INTEGER,
    health_active_rules INTEGER,
    health_blocked_ips INTEGER,
    UNIQUE(node_id)
);

CREATE INDEX IF NOT EXISTS idx_cas_node_id ON config_agent_status(node_id);
CREATE INDEX IF NOT EXISTS idx_cas_profile_id ON config_agent_status(profile_id);

CREATE TABLE IF NOT EXISTS saved_queries (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    name        TEXT    NOT NULL,
    query       TEXT    NOT NULL,
    created_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at  TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_sq_user ON saved_queries(user_id);

-- Alert Rules table: per-user and global alerting rules
CREATE TABLE IF NOT EXISTS alert_rules (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER REFERENCES users(id),
    name            TEXT    NOT NULL,
    query           TEXT,
    check_name      TEXT,
    operator        TEXT    NOT NULL CHECK(operator IN ('>', '<', '==', '>=', '<=')),
    threshold       REAL    NOT NULL,
    resolve_threshold REAL,
    severity        TEXT    NOT NULL CHECK(severity IN ('warning', 'critical')),
    for_duration    INTEGER NOT NULL DEFAULT 0,
    cooldown_secs   INTEGER,
    interval_secs   INTEGER NOT NULL DEFAULT 60,
    tags            TEXT,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_alert_rules_enabled ON alert_rules(enabled);
CREATE INDEX IF NOT EXISTS idx_alert_rules_user ON alert_rules(user_id);

-- Alert Events table: individual firing/resolved/acknowledged events
CREATE TABLE IF NOT EXISTS alert_events (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    rule_id           INTEGER REFERENCES alert_rules(id),
    entity_id         INTEGER,
    group_condition_id INTEGER REFERENCES group_alert_conditions(id),
    labels            TEXT    NOT NULL DEFAULT '{}',
    value             REAL    NOT NULL,
    state             TEXT    NOT NULL DEFAULT 'firing' CHECK(state IN ('firing', 'resolved', 'acknowledged')),
    fired_at          TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    resolved_at       TEXT,
    acknowledged_by   INTEGER REFERENCES users(id),
    notified_at       TEXT
);

CREATE INDEX IF NOT EXISTS idx_alert_events_state ON alert_events(state);
CREATE INDEX IF NOT EXISTS idx_alert_events_rule ON alert_events(rule_id);
CREATE INDEX IF NOT EXISTS idx_alert_events_entity ON alert_events(entity_id);
CREATE INDEX IF NOT EXISTS idx_alert_events_group_condition ON alert_events(group_condition_id);

-- Notification Channels table: Slack, email, webhook, PagerDuty configs
CREATE TABLE IF NOT EXISTS notification_channels (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,
                    type            TEXT    NOT NULL,
    config          TEXT    NOT NULL DEFAULT '{}',
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_notification_channels_enabled ON notification_channels(enabled);

-- Rule-Channel associations (many-to-many)
CREATE TABLE IF NOT EXISTS rule_notification_channels (
    rule_id         INTEGER NOT NULL REFERENCES alert_rules(id) ON DELETE CASCADE,
    channel_id      INTEGER NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    PRIMARY KEY (rule_id, channel_id)
);

-- Alert Silences table: maintenance windows and suppression
CREATE TABLE IF NOT EXISTS alert_silences (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    matchers        TEXT    NOT NULL DEFAULT '[]',
    rule_id         INTEGER REFERENCES alert_rules(id) ON DELETE CASCADE,
    starts_at       TEXT    NOT NULL,
    ends_at         TEXT    NOT NULL,
    reason          TEXT    NOT NULL,
    created_by      INTEGER NOT NULL REFERENCES users(id),
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_alert_silences_active ON alert_silences(starts_at, ends_at);

-- Monitoring Groups: named groups with label matchers for instance targeting
CREATE TABLE IF NOT EXISTS monitoring_groups (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    name            TEXT    NOT NULL,
    description     TEXT    NOT NULL DEFAULT '',
    match_labels    TEXT    NOT NULL DEFAULT '[]',
    match_any       INTEGER NOT NULL DEFAULT 0,
    enabled         INTEGER NOT NULL DEFAULT 1,
    created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_monitoring_groups_enabled ON monitoring_groups(enabled);

-- Group Alert Conditions: predefined metric checks per group
CREATE TABLE IF NOT EXISTS group_alert_conditions (
    id                INTEGER PRIMARY KEY AUTOINCREMENT,
    group_id          INTEGER NOT NULL REFERENCES monitoring_groups(id) ON DELETE CASCADE,
    name              TEXT    NOT NULL,
    metric_type       TEXT    NOT NULL,
    metric_params     TEXT    NOT NULL DEFAULT '{}',
    target_labels     TEXT,
    operator          TEXT    NOT NULL,
    threshold         REAL    NOT NULL,
    resolve_threshold REAL,
    severity          TEXT    NOT NULL DEFAULT 'warning',
    for_duration      INTEGER NOT NULL DEFAULT 0,
    cooldown_secs     INTEGER,
    interval_secs     INTEGER NOT NULL DEFAULT 60,
    last_eval_at      TEXT,
    enabled           INTEGER NOT NULL DEFAULT 1,
    created_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    updated_at        TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_group_alert_conditions_group ON group_alert_conditions(group_id);
CREATE INDEX IF NOT EXISTS idx_group_alert_conditions_enabled ON group_alert_conditions(enabled);

-- Group-Condition-Channel associations (many-to-many)
CREATE TABLE IF NOT EXISTS group_condition_channels (
    condition_id  INTEGER NOT NULL REFERENCES group_alert_conditions(id) ON DELETE CASCADE,
    channel_id    INTEGER NOT NULL REFERENCES notification_channels(id) ON DELETE CASCADE,
    PRIMARY KEY (condition_id, channel_id)
);

-- Alert Eval Lock table: singleton row for distributed eval coordination
CREATE TABLE IF NOT EXISTS alert_eval_lock (
    id              INTEGER PRIMARY KEY CHECK (id = 1),
    locked_by       TEXT,
    locked_at       TEXT,
    expires_at      TEXT,
    last_eval_at    TEXT
);

INSERT OR IGNORE INTO alert_eval_lock (id, locked_by, locked_at, expires_at, last_eval_at) VALUES (1, NULL, NULL, NULL, NULL);

-- ============================================================================
-- Assets table: canonical inventory record for all infrastructure
-- ============================================================================
CREATE TABLE IF NOT EXISTS assets (
    asset_id         TEXT    PRIMARY KEY,
    asset_type       TEXT    NOT NULL DEFAULT 'host',
    display_name     TEXT    NOT NULL,
    parent_id        TEXT    REFERENCES assets(asset_id),
    metadata         TEXT    NOT NULL DEFAULT '{}',
    labels           TEXT    NOT NULL DEFAULT '{}',
    first_seen_at    TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_seen_at     TEXT,
    status           TEXT    NOT NULL DEFAULT 'active'
                        CHECK(status IN ('active', 'stale', 'gone')),
    created_by_source TEXT   NOT NULL DEFAULT 'agent'
);

CREATE INDEX IF NOT EXISTS idx_assets_type ON assets(asset_type);
CREATE INDEX IF NOT EXISTS idx_assets_parent ON assets(parent_id);
CREATE INDEX IF NOT EXISTS idx_assets_status ON assets(status);

-- ============================================================================
-- Asset Aliases table: maps external identifiers to canonical asset_id
-- ============================================================================
CREATE TABLE IF NOT EXISTS asset_aliases (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    asset_id         TEXT    NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    alias_type       TEXT    NOT NULL,
    alias_value      TEXT    NOT NULL,
    source           TEXT    NOT NULL,
    confidence       INTEGER NOT NULL DEFAULT 100,
    first_claimed_at TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    last_confirmed_at TEXT,
    UNIQUE(alias_type, alias_value)
);

CREATE INDEX IF NOT EXISTS idx_aa_asset ON asset_aliases(asset_id);

-- ============================================================================
-- Asset Relationships table: graph edges between assets
-- ============================================================================
CREATE TABLE IF NOT EXISTS asset_relationships (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    source_asset_id  TEXT    NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    target_asset_id  TEXT    NOT NULL REFERENCES assets(asset_id) ON DELETE CASCADE,
    relationship     TEXT    NOT NULL,
    metadata         TEXT    NOT NULL DEFAULT '{}',
    created_at       TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
    UNIQUE(source_asset_id, target_asset_id, relationship)
);

CREATE INDEX IF NOT EXISTS idx_ar_target ON asset_relationships(target_asset_id);
CREATE INDEX IF NOT EXISTS idx_ar_relationship ON asset_relationships(relationship);

-- ============================================================================
-- Host events table: stores host-level process creation detections (auditd pipeline)
-- ============================================================================
CREATE TABLE IF NOT EXISTS host_events (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname        VARCHAR(255) NOT NULL,
    timestamp       VARCHAR(64)  NOT NULL,
    event_type      VARCHAR(128) NOT NULL,
    rule_name       VARCHAR(128) NOT NULL,
    pid             INTEGER      NOT NULL,
    ppid            INTEGER      NOT NULL,
    exe             VARCHAR(1024) NOT NULL,
    command_line    TEXT         NOT NULL,
    uid             INTEGER      NOT NULL,
    auid            INTEGER      NOT NULL,
    raw_line        TEXT         NOT NULL,
    node_id         VARCHAR(128) NOT NULL,
    ingested_at     TEXT         NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now'))
);

CREATE INDEX IF NOT EXISTS idx_host_events_hostname  ON host_events(hostname);
CREATE INDEX IF NOT EXISTS idx_host_events_timestamp ON host_events(timestamp);
CREATE INDEX IF NOT EXISTS idx_host_events_node_id   ON host_events(node_id);
CREATE INDEX IF NOT EXISTS idx_host_events_hostname_timestamp ON host_events(hostname, timestamp);
CREATE INDEX IF NOT EXISTS idx_host_events_ingested_at ON host_events(ingested_at);
"""


def _row_to_dict(row: sqlite3.Row) -> dict:
    """Convert a sqlite3.Row to a plain dict."""
    return dict(row)
