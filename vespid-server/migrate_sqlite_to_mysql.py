#!/usr/bin/env python3
"""Migrate Vespid Server data from SQLite to MySQL.

Reads all rows from the SQLite database and inserts them into a MySQL
database that already has the schema created (via schema_mysql.sql).

Usage:
    python migrate_sqlite_to_mysql.py \\
        --sqlite /path/to/vespid.db \\
        --host localhost \\
        --port 3306 \\
        --database vespid \\
        --user vespid \\
        --password 'yourpassword'

Or using environment variables:
    export MYSQL_HOST=localhost
    export MYSQL_PORT=3306
    export MYSQL_DATABASE=vespid
    export MYSQL_USER=vespid
    export MYSQL_PASSWORD=yourpassword
    python migrate_sqlite_to_mysql.py --sqlite /path/to/vespid.db

Prerequisites:
    pip install mysql-connector-python

Notes:
    - Run schema_mysql.sql FIRST to create the target tables.
    - Existing rows in MySQL are skipped (INSERT IGNORE).
    - The script migrates in dependency order to respect foreign keys.
    - Auto-increment IDs are preserved from SQLite.
    - Progress is printed per table.
"""

import argparse
import json
import os
import sqlite3
import sys
import time

try:
    import mysql.connector
except ImportError:
    print("ERROR: mysql-connector-python is required.")
    print("Install it with: pip install mysql-connector-python")
    sys.exit(1)


# Tables in dependency order (parents before children).
TABLES = [
    "users",
    "api_keys",
    "nodes",
    "events",
    "audit_log",
    "pending_commands",
    "ip_rules",
    "feed_catalog",
    "counter_snapshots",
    "enrollment_settings",
    "enrollment_requests",
    "fleet_blocks",
    "fleet_block_reports",
    "fleet_allowlist",
    "fleet_config",
    "detection_rules_brute_force",
    "detection_rules_custom",
    "detection_rules_revision",
    "agent_groups",
    "config_profiles",
    "config_version_history",
    "config_assignments",
    "agent_group_members",
    "config_rollouts",
    "config_agent_status",
    "ip_intel",
    "ip_intel_events",
]

# Batch size for inserts.
BATCH_SIZE = 500


def get_sqlite_connection(path: str) -> sqlite3.Connection:
    """Open a read-only SQLite connection."""
    if not os.path.exists(path):
        print(f"ERROR: SQLite database not found: {path}")
        sys.exit(1)
    conn = sqlite3.connect(f"file:{path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    return conn


def get_mysql_connection(host, port, database, user, password):
    """Open a MySQL connection."""
    return mysql.connector.connect(
        host=host,
        port=port,
        database=database,
        user=user,
        password=password,
        charset="utf8mb4",
        collation="utf8mb4_unicode_ci",
        autocommit=False,
    )


def get_table_columns(sqlite_conn: sqlite3.Connection, table: str) -> list[str]:
    """Get column names for a table from SQLite."""
    cursor = sqlite_conn.execute(f"PRAGMA table_info({table})")
    return [row[1] for row in cursor.fetchall()]


def table_exists_in_sqlite(sqlite_conn: sqlite3.Connection, table: str) -> bool:
    """Check if a table exists in the SQLite database."""
    row = sqlite_conn.execute(
        "SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name=?",
        (table,),
    ).fetchone()
    return row[0] > 0


def table_exists_in_mysql(mysql_conn, table: str) -> bool:
    """Check if a table exists in the MySQL database."""
    cursor = mysql_conn.cursor()
    cursor.execute(
        "SELECT COUNT(*) FROM information_schema.tables "
        "WHERE table_schema = DATABASE() AND table_name = %s",
        (table,),
    )
    row = cursor.fetchone()
    cursor.close()
    return row[0] > 0


def migrate_table(
    sqlite_conn: sqlite3.Connection,
    mysql_conn,
    table: str,
) -> int:
    """Migrate all rows from a single table. Returns row count."""
    if not table_exists_in_sqlite(sqlite_conn, table):
        print(f"  ⏭  {table} — does not exist in SQLite, skipping")
        return 0

    if not table_exists_in_mysql(mysql_conn, table):
        print(f"  ⚠  {table} — does not exist in MySQL (run schema_mysql.sql first), skipping")
        return 0

    columns = get_table_columns(sqlite_conn, table)
    if not columns:
        print(f"  ⏭  {table} — no columns found, skipping")
        return 0

    # Count rows
    count = sqlite_conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
    if count == 0:
        print(f"  ⏭  {table} — empty, skipping")
        return 0

    # Build INSERT IGNORE statement
    col_list = ", ".join(columns)
    placeholders = ", ".join(["%s"] * len(columns))
    insert_sql = f"INSERT IGNORE INTO {table} ({col_list}) VALUES ({placeholders})"

    # Read all rows from SQLite
    rows = sqlite_conn.execute(f"SELECT {col_list} FROM {table}").fetchall()

    # Insert in batches
    cursor = mysql_conn.cursor()
    migrated = 0
    skipped = 0

    for i in range(0, len(rows), BATCH_SIZE):
        batch = rows[i : i + BATCH_SIZE]
        values = []
        for row in batch:
            row_values = []
            for col_idx, col_name in enumerate(columns):
                val = row[col_idx]
                # Convert Python dicts/lists to JSON strings for JSON columns
                if isinstance(val, (dict, list)):
                    val = json.dumps(val)
                row_values.append(val)
            values.append(tuple(row_values))

        cursor.executemany(insert_sql, values)
        migrated += cursor.rowcount

    mysql_conn.commit()
    skipped = count - migrated
    status = f"  ✓  {table} — {migrated} rows migrated"
    if skipped > 0:
        status += f" ({skipped} duplicates skipped)"
    print(status)

    cursor.close()
    return migrated


def reset_auto_increment(mysql_conn, table: str) -> None:
    """Set AUTO_INCREMENT to max(id) + 1 so new rows get correct IDs."""
    cursor = mysql_conn.cursor()
    cursor.execute(f"SELECT MAX(id) FROM {table}")
    row = cursor.fetchone()
    max_id = row[0] if row[0] is not None else 0
    if max_id > 0:
        cursor.execute(f"ALTER TABLE {table} AUTO_INCREMENT = {max_id + 1}")
        mysql_conn.commit()
    cursor.close()


def main():
    parser = argparse.ArgumentParser(
        description="Migrate Vespid data from SQLite to MySQL"
    )
    parser.add_argument(
        "--sqlite",
        required=True,
        help="Path to the SQLite database file",
    )
    parser.add_argument(
        "--host",
        default=os.environ.get("MYSQL_HOST", "localhost"),
        help="MySQL host (default: localhost or $MYSQL_HOST)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=int(os.environ.get("MYSQL_PORT", "3306")),
        help="MySQL port (default: 3306 or $MYSQL_PORT)",
    )
    parser.add_argument(
        "--database",
        default=os.environ.get("MYSQL_DATABASE", "vespid"),
        help="MySQL database name (default: vespid or $MYSQL_DATABASE)",
    )
    parser.add_argument(
        "--user",
        default=os.environ.get("MYSQL_USER", "vespid"),
        help="MySQL user (default: vespid or $MYSQL_USER)",
    )
    parser.add_argument(
        "--password",
        default=os.environ.get("MYSQL_PASSWORD", ""),
        help="MySQL password (default: $MYSQL_PASSWORD)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Show what would be migrated without writing to MySQL",
    )

    args = parser.parse_args()

    if not args.password:
        print("ERROR: MySQL password is required (--password or $MYSQL_PASSWORD)")
        sys.exit(1)

    print("=" * 60)
    print("Vespid — SQLite to MySQL Migration")
    print("=" * 60)
    print(f"  Source:  {args.sqlite}")
    print(f"  Target:  mysql://{args.user}@{args.host}:{args.port}/{args.database}")
    print()

    # Connect to SQLite
    sqlite_conn = get_sqlite_connection(args.sqlite)

    if args.dry_run:
        print("DRY RUN — no data will be written\n")
        for table in TABLES:
            if not table_exists_in_sqlite(sqlite_conn, table):
                print(f"  ⏭  {table} — does not exist in SQLite")
                continue
            count = sqlite_conn.execute(f"SELECT COUNT(*) FROM {table}").fetchone()[0]
            print(f"  📋 {table} — {count} rows to migrate")
        sqlite_conn.close()
        return

    # Connect to MySQL
    try:
        mysql_conn = get_mysql_connection(
            args.host, args.port, args.database, args.user, args.password
        )
    except mysql.connector.Error as e:
        print(f"ERROR: Could not connect to MySQL: {e}")
        sys.exit(1)

    print("Connected to both databases. Starting migration...\n")

    # Pre-flight check: verify MySQL schema exists
    preflight_cursor = mysql_conn.cursor()
    preflight_cursor.execute(
        "SELECT COUNT(*) FROM information_schema.tables "
        "WHERE table_schema = DATABASE()"
    )
    mysql_table_count = preflight_cursor.fetchone()[0]
    preflight_cursor.close()

    if mysql_table_count == 0:
        print("ERROR: The MySQL database has no tables.")
        print("       Run schema_mysql.sql first to create the schema:")
        print(f"         mysql -u root -p < schema_mysql.sql")
        sqlite_conn.close()
        mysql_conn.close()
        sys.exit(1)

    # Disable foreign key checks during migration for performance
    cursor = mysql_conn.cursor()
    cursor.execute("SET FOREIGN_KEY_CHECKS = 0")
    mysql_conn.commit()
    cursor.close()

    start_time = time.time()
    total_rows = 0

    for table in TABLES:
        rows = migrate_table(sqlite_conn, mysql_conn, table)
        total_rows += rows
        # Reset auto-increment after migrating each table
        if rows > 0:
            reset_auto_increment(mysql_conn, table)

    # Re-enable foreign key checks
    cursor = mysql_conn.cursor()
    cursor.execute("SET FOREIGN_KEY_CHECKS = 1")
    mysql_conn.commit()
    cursor.close()

    elapsed = time.time() - start_time

    print()
    print("=" * 60)
    print(f"Migration complete: {total_rows} total rows in {elapsed:.1f}s")
    print("=" * 60)

    sqlite_conn.close()
    mysql_conn.close()


if __name__ == "__main__":
    main()
