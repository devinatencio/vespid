#!/usr/bin/env python3
"""Reconcile IP Intelligence block status against actual fleet/node state.

Fixes stale "Active" block status in ip_intel records that were never
updated with last_unblocked_at when their fleet blocks expired. This is
a one-time cleanup script to correct historical data.

Logic:
    1. Find all IPs in ip_intel that appear "Active" (last_blocked_at is set
       AND last_unblocked_at is NULL or last_blocked_at > last_unblocked_at).
    2. Check if the IP has an active fleet block in fleet_blocks.
    3. Check if the IP appears in any node's last_block_list (heartbeat data).
    4. If the IP is NOT actively blocked anywhere, set last_unblocked_at = now.

Usage:
    # SQLite (default):
    python reconcile_intel_block_status.py --db /path/to/vespid.db

    # MySQL/MariaDB (uses server config file):
    python reconcile_intel_block_status.py --config /etc/vespid-server/config.yaml

    # Dry run (preview without changes):
    python reconcile_intel_block_status.py --db /path/to/vespid.db --dry-run
"""

import argparse
import json
import logging
import sys
from datetime import datetime, timezone

# Ensure the app package is importable
sys.path.insert(0, ".")

from app.config import load_config
from app.models import get_db

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

DEFAULT_DB_PATH = "/var/lib/vespid-server/vespid.db"


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


def _get_actively_blocked_ips(conn) -> set:
    """Get the set of IPs that are genuinely blocked right now.

    Combines:
    - IPs with active fleet blocks (status='active' in fleet_blocks)
    - IPs in any node's last_block_list (heartbeat-reported local blocks)
    """
    actively_blocked = set()

    # 1. Active fleet blocks
    rows = conn.execute(
        "SELECT source_ip FROM fleet_blocks WHERE status = 'active'"
    ).fetchall()
    for row in rows:
        ip = row["source_ip"] if isinstance(row, dict) else row[0]
        actively_blocked.add(ip)

    # 2. Node blocks table (pushed by daemon on change)
    node_rows = conn.execute(
        "SELECT DISTINCT ip FROM node_blocks"
    ).fetchall()
    for row in node_rows:
        ip = row["ip"] if isinstance(row, dict) else row[0]
        if ip:
            actively_blocked.add(ip)

    return actively_blocked


def _get_stale_active_ips(conn) -> list:
    """Get IPs that show as 'Active' in ip_intel block status.

    Active means: last_blocked_at is set AND (last_unblocked_at is NULL
    OR last_blocked_at > last_unblocked_at).
    """
    rows = conn.execute(
        "SELECT ip_address, last_blocked_at, last_unblocked_at "
        "FROM ip_intel "
        "WHERE last_blocked_at IS NOT NULL "
        "AND (last_unblocked_at IS NULL OR last_blocked_at > last_unblocked_at)"
    ).fetchall()

    results = []
    for row in rows:
        results.append({
            "ip_address": row["ip_address"] if isinstance(row, dict) else row[0],
            "last_blocked_at": row["last_blocked_at"] if isinstance(row, dict) else row[1],
            "last_unblocked_at": row["last_unblocked_at"] if isinstance(row, dict) else row[2],
        })
    return results


def reconcile(db_config, dry_run: bool = False) -> dict:
    """Run the reconciliation.

    Returns a summary dict with counts.
    """
    now_str = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    conn = get_db(db_config)
    try:
        # Get ground truth: what's actually blocked right now
        actively_blocked = _get_actively_blocked_ips(conn)
        logger.info("Found %d IPs actively blocked (fleet + node heartbeats)",
                    len(actively_blocked))

        # Get IPs that ip_intel thinks are "Active"
        stale_candidates = _get_stale_active_ips(conn)
        logger.info("Found %d IPs showing as 'Active' in IP Intelligence",
                    len(stale_candidates))

        # Find the ones that are stale (not actually blocked anywhere)
        to_fix = []
        for record in stale_candidates:
            if record["ip_address"] not in actively_blocked:
                to_fix.append(record["ip_address"])

        logger.info("%d IPs are stale (showing Active but not actually blocked)",
                    len(to_fix))

        if not to_fix:
            logger.info("Nothing to reconcile — all Active statuses are correct.")
            return {"checked": len(stale_candidates), "fixed": 0, "skipped": 0}

        if dry_run:
            logger.info("DRY RUN — would fix %d records:", len(to_fix))
            for ip in to_fix[:20]:
                logger.info("  %s", ip)
            if len(to_fix) > 20:
                logger.info("  ... and %d more", len(to_fix) - 20)
            return {"checked": len(stale_candidates), "fixed": 0,
                    "would_fix": len(to_fix)}

        # Apply the fix: set last_unblocked_at = now for stale IPs
        fixed = 0
        for ip in to_fix:
            conn.execute(
                "UPDATE ip_intel SET last_unblocked_at = ? WHERE ip_address = ?",
                (now_str, ip),
            )
            fixed += 1

        conn.commit()
        logger.info("Fixed %d stale records (set last_unblocked_at = %s)",
                    fixed, now_str)

        return {"checked": len(stale_candidates), "fixed": fixed, "skipped": 0}

    finally:
        conn.close()


def main():
    parser = argparse.ArgumentParser(
        description="Reconcile IP Intelligence block status against actual state."
    )
    parser.add_argument(
        "--db", default=DEFAULT_DB_PATH,
        help="Path to SQLite database (default: %(default)s)"
    )
    parser.add_argument(
        "--config", default=None,
        help="Path to server config YAML (for MySQL/MariaDB)"
    )
    parser.add_argument(
        "--mysql", action="store_true",
        help="Use MySQL backend with explicit parameters"
    )
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=3306)
    parser.add_argument("--database", default="vespid")
    parser.add_argument("--user", default="vespid")
    parser.add_argument("--password", default="")
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Preview changes without applying them"
    )

    args = parser.parse_args()
    db_config = _build_db_config(args)

    logger.info("Starting IP Intelligence block status reconciliation...")
    if args.dry_run:
        logger.info("(DRY RUN mode — no changes will be made)")

    result = reconcile(db_config, dry_run=args.dry_run)

    logger.info("Done. Summary: %s", result)


if __name__ == "__main__":
    main()
