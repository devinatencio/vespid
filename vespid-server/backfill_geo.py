#!/usr/bin/env python3
"""Backfill missing geo_country data on existing events using GeoIP lookup.

Usage:
    # SQLite (default):
    python backfill_geo.py --db /path/to/vespid.db

    # MySQL/MariaDB (uses server config file or env vars):
    python backfill_geo.py --config /etc/vespid-server/config.yaml

    # MySQL via explicit parameters:
    python backfill_geo.py --mysql --host 127.0.0.1 --port 3306 \
        --database vespid --user vespid --password secret

    # Dry run (preview without changes):
    python backfill_geo.py --config /etc/vespid-server/config.yaml --dry-run

    # Batch size control for large tables:
    python backfill_geo.py --config /etc/vespid-server/config.yaml --batch-size 500

This script finds all events where geo_country is NULL or empty, performs a
GeoIP lookup on the source_ip, and updates the geo columns in place.

Requires the GeoIP databases to be installed in one of the standard locations
(see app/geo.py for search paths) or configured via environment variables.
"""

import argparse
import json
import logging
import sys

# Ensure the app package is importable
sys.path.insert(0, ".")

from app.config import load_config
from app.geo import lookup as geo_lookup, is_available as geo_is_available
from app.models import get_db

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = "/var/lib/vespid-server/vespid.db"


def _build_db_config(args) -> str | dict:
    """Build a database config from CLI arguments.

    Returns either a SQLite path string or a MySQL config dict,
    compatible with get_db().
    """
    # If a server config file is specified, use it
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

    # Explicit MySQL mode
    if args.mysql:
        return {
            "DATABASE_TYPE": "mysql",
            "DATABASE_HOST": args.host,
            "DATABASE_PORT": args.port,
            "DATABASE_NAME": args.database,
            "DATABASE_USER": args.user,
            "DATABASE_PASSWORD": args.password,
        }

    # Default: SQLite path
    return args.db


def backfill(db_config, dry_run: bool = False, batch_size: int = 1000) -> int:
    """Backfill geo data for events missing geo_country.

    Args:
        db_config: SQLite path string or MySQL config dict (passed to get_db).
        dry_run: If True, only log what would be updated.
        batch_size: Number of rows to fetch and update per batch.

    Returns the number of events updated.
    """
    if not geo_is_available():
        logger.error("No GeoIP databases available. Cannot backfill.")
        logger.error("Install GeoLite2 or db-ip databases, or set VESPID_GEOIP_DB env var.")
        return 0

    db = get_db(db_config)
    try:
        # Count total rows needing backfill
        total_row = db.execute(
            "SELECT COUNT(*) as cnt FROM events "
            "WHERE geo_country IS NULL OR geo_country = ''"
        ).fetchone()
        total = total_row["cnt"] if hasattr(total_row, "keys") else total_row[0]

        if total == 0:
            logger.info("No events need geo backfill.")
            return 0

        logger.info("Found %d events missing geo_country.", total)

        updated = 0
        offset = 0

        while offset < total:
            rows = db.execute(
                "SELECT event_id, source_ip, geo_data FROM events "
                "WHERE geo_country IS NULL OR geo_country = '' "
                "LIMIT ? OFFSET ?",
                (batch_size, offset),
            ).fetchall()

            if not rows:
                break

            for row in rows:
                event_id = row["event_id"]
                source_ip = row["source_ip"]

                geo_result = geo_lookup(source_ip)
                if not geo_result.get("country"):
                    continue

                # Merge with existing geo_data JSON
                existing_geo_str = row["geo_data"]
                try:
                    existing_geo = json.loads(existing_geo_str) if existing_geo_str else {}
                except (json.JSONDecodeError, TypeError):
                    existing_geo = {}

                existing_geo.update({k: v for k, v in geo_result.items() if v is not None})

                if dry_run:
                    logger.info(
                        "  [DRY RUN] event_id=%s ip=%s -> country=%s asn=%s org=%s",
                        event_id, source_ip,
                        geo_result.get("country"),
                        geo_result.get("asn"),
                        geo_result.get("org"),
                    )
                else:
                    db.execute(
                        "UPDATE events SET "
                        "geo_country = ?, geo_asn = ?, geo_org = ?, geo_data = ? "
                        "WHERE event_id = ?",
                        (
                            geo_result.get("country"),
                            geo_result.get("asn"),
                            geo_result.get("org"),
                            json.dumps(existing_geo),
                            event_id,
                        ),
                    )
                updated += 1

            if not dry_run:
                db.commit()

            offset += batch_size
            logger.info("  Progress: processed %d / %d rows...", min(offset, total), total)

        logger.info(
            "%s %d events with geo data.",
            "Would update" if dry_run else "Updated",
            updated,
        )
        return updated
    finally:
        db.close()


def main():
    parser = argparse.ArgumentParser(
        description="Backfill GeoIP data on events missing geo_country"
    )

    # Database source options (mutually supportive, not exclusive)
    parser.add_argument(
        "--config",
        help="Path to vespid-server config file (YAML/JSON). "
             "Reads DATABASE_TYPE and connection settings from it.",
    )
    parser.add_argument(
        "--db", default=DEFAULT_DB_PATH,
        help=f"Path to SQLite database (default: {DEFAULT_DB_PATH}). "
             "Ignored if --config or --mysql is used.",
    )

    # Explicit MySQL options
    mysql_group = parser.add_argument_group("MySQL/MariaDB options")
    mysql_group.add_argument(
        "--mysql", action="store_true",
        help="Use MySQL/MariaDB with explicit connection parameters.",
    )
    mysql_group.add_argument("--host", default="localhost", help="MySQL host (default: localhost)")
    mysql_group.add_argument("--port", type=int, default=3306, help="MySQL port (default: 3306)")
    mysql_group.add_argument("--database", default="vespid", help="Database name (default: vespid)")
    mysql_group.add_argument("--user", default="vespid", help="MySQL user (default: vespid)")
    mysql_group.add_argument("--password", default="", help="MySQL password (default: empty)")

    # Behavior options
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Show what would be updated without making changes.",
    )
    parser.add_argument(
        "--batch-size", type=int, default=1000,
        help="Number of rows to process per batch (default: 1000).",
    )

    args = parser.parse_args()
    db_config = _build_db_config(args)

    # Log which backend we're using
    if isinstance(db_config, dict):
        logger.info(
            "Connecting to %s at %s:%s/%s",
            db_config["DATABASE_TYPE"],
            db_config["DATABASE_HOST"],
            db_config["DATABASE_PORT"],
            db_config["DATABASE_NAME"],
        )
    else:
        logger.info("Using SQLite database: %s", db_config)

    backfill(db_config, dry_run=args.dry_run, batch_size=args.batch_size)


if __name__ == "__main__":
    main()
