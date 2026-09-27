#!/usr/bin/env python3
"""Migrate a node from old-style node_id to a new UUID.

This is a one-time migration script for nodes that were registered before
the UUID scheme was introduced. It updates the node_id across all server
tables and writes the new UUID to the agent's node_id file.

Usage:
    # Using server config (MySQL):
    python migrate_node_id_to_uuid.py --config /etc/vespid-server/config.yaml \
        --old-id "web01-abc123"

    # Specify a UUID (otherwise one is generated):
    python migrate_node_id_to_uuid.py --config /etc/vespid-server/config.yaml \
        --old-id "web01-abc123" --new-id "550e8400-e29b-41d4-a716-446655440000"

    # SQLite:
    python migrate_node_id_to_uuid.py --db /var/lib/vespid-server/vespid.db \
        --old-id "web01-abc123"

    # Dry run (preview changes without applying):
    python migrate_node_id_to_uuid.py --config /etc/vespid-server/config.yaml \
        --old-id "web01-abc123" --dry-run

After running this on the server, update the agent's node_id file:
    echo "<new-uuid>" > /var/lib/vespid/node_id
    systemctl restart vespid

The script prints the new UUID so you can copy it to the agent.
"""

import argparse
import logging
import sys
import uuid

sys.path.insert(0, ".")

from app.config import load_config
from app.models import get_db

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = "/var/lib/vespid-server/vespid.db"

# All tables that contain a node_id column referencing the node identity.
TABLES_WITH_NODE_ID = [
    ("nodes", "node_id"),
    ("events", "node_id"),
    ("enrollment_requests", "node_id"),
    ("pending_commands", "node_id"),
    ("fleet_blocks", "originating_node_id"),
    ("fleet_block_reports", "node_id"),
    ("counter_snapshots", "node_id"),
    ("config_assignments", "node_id"),
    ("agent_group_members", "node_id"),
    ("config_agent_status", "node_id"),
    ("api_keys", "node_id_restriction"),
    ("intel_sightings", "node_id"),
]


def _build_db_config(args) -> str | dict:
    """Build a database config from CLI arguments."""
    if args.config:
        config = load_config(args.config)
        db_type = config.get("DATABASE_TYPE", "sqlite").lower()
        if db_type in ("mysql", "mariadb"):
            return {
                "DATABASE_TYPE": db_type,
                "DATABASE_HOST": config.get("DATABASE_HOST", "localhost"),
                "DATABASE_PORT": config.get("DATABASE_PORT", 3306),
                "DATABASE_NAME": config.get("DATABASE_NAME", "vespid"),
                "DATABASE_USER": config.get("DATABASE_USER", "vespid"),
                "DATABASE_PASSWORD": config.get("DATABASE_PASSWORD", ""),
            }
        else:
            return config.get("DATABASE_PATH", DEFAULT_DB_PATH)

    if args.mysql:
        return {
            "DATABASE_TYPE": "mysql",
            "DATABASE_HOST": args.host,
            "DATABASE_PORT": args.port,
            "DATABASE_NAME": args.database,
            "DATABASE_USER": args.user,
            "DATABASE_PASSWORD": args.password,
        }

    return args.db


def migrate_node_id(db_config, old_id: str, new_id: str, dry_run: bool = False) -> None:
    """Update node_id from old_id to new_id across all tables."""
    conn = get_db(db_config)

    try:
        # Verify the old node_id exists
        row = conn.execute(
            "SELECT node_id, display_name FROM nodes WHERE node_id = ?", (old_id,)
        ).fetchone()

        if row is None:
            logger.error("Node '%s' not found in the nodes table.", old_id)
            logger.info("Existing nodes:")
            for r in conn.execute("SELECT node_id, display_name FROM nodes").fetchall():
                logger.info("  %s (%s)", r["node_id"], r["display_name"] or "no display name")
            sys.exit(1)

        display_name = row["display_name"] or old_id
        logger.info("Found node: %s (display_name='%s')", old_id, display_name)
        logger.info("New UUID: %s", new_id)

        if dry_run:
            logger.info("--- DRY RUN — no changes will be made ---")

        total_updated = 0

        for table, column in TABLES_WITH_NODE_ID:
            # Check if table exists (may not on all deployments)
            try:
                count_row = conn.execute(
                    f"SELECT COUNT(*) as cnt FROM {table} WHERE {column} = ?", (old_id,)
                ).fetchone()
                count = count_row["cnt"] if count_row else 0
            except Exception:
                logger.debug("Table '%s' does not exist, skipping.", table)
                continue

            if count == 0:
                logger.info("  %-25s — no rows to update", table)
                continue

            if not dry_run:
                conn.execute(
                    f"UPDATE {table} SET {column} = ? WHERE {column} = ?",
                    (new_id, old_id),
                )

            logger.info("  %-25s — %d row(s) updated", table, count)
            total_updated += count

        if not dry_run:
            conn.commit()
            logger.info("")
            logger.info("Migration complete. %d total row(s) updated.", total_updated)
            logger.info("")
            logger.info("Next steps on the AGENT machine:")
            logger.info("  echo '%s' > /var/lib/vespid/node_id", new_id)
            logger.info("  systemctl restart vespid")
        else:
            logger.info("")
            logger.info("Dry run complete. %d row(s) would be updated.", total_updated)

    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(
        description="Migrate a node from old-style node_id to UUID."
    )
    parser.add_argument(
        "--old-id", required=True,
        help="The current (old-style) node_id to migrate."
    )
    parser.add_argument(
        "--new-id", default=None,
        help="The new UUID to assign. If omitted, a random UUID4 is generated."
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Preview changes without applying them."
    )

    # Database options
    parser.add_argument(
        "--db", default=DEFAULT_DB_PATH,
        help="Path to SQLite database (default: %(default)s)."
    )
    parser.add_argument(
        "--config", default=None,
        help="Path to server config YAML (for MySQL/MariaDB)."
    )
    parser.add_argument("--mysql", action="store_true", help="Use MySQL with explicit parameters.")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=3306)
    parser.add_argument("--database", default="vespid")
    parser.add_argument("--user", default="vespid")
    parser.add_argument("--password", default="")

    args = parser.parse_args()

    new_id = args.new_id or str(uuid.uuid4())

    # Validate the new ID looks like a UUID
    try:
        uuid.UUID(new_id)
    except ValueError:
        logger.error("--new-id '%s' is not a valid UUID.", new_id)
        sys.exit(1)

    db_config = _build_db_config(args)
    migrate_node_id(db_config, args.old_id, new_id, dry_run=args.dry_run)


if __name__ == "__main__":
    main()
