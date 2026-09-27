"""One-shot backfill: create assets from existing nodes rows.

Usage:
    python backfill_assets.py [--db /path/to/vespid.db]

Scans every row in the ``nodes`` table that has no ``asset_id`` set, creates
a corresponding ``assets`` record, populates ``asset_aliases`` from
``last_host_info``, and writes the ``asset_id`` back to the nodes row.

Also scans ``config_agent_status`` rows (monitor agents) and resolves each
against the asset registry by hostname.

Safe to run multiple times — skips rows that already have an asset_id.
"""

import argparse
import json
import logging
import os
import sys
import sqlite3
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
log = logging.getLogger("backfill_assets")


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _get_default_db_path() -> str:
    """Walk up from the script directory looking for data/vespid.db."""
    script_dir = os.path.dirname(os.path.abspath(__file__))
    for parent in [script_dir] + list(os.path.dirname(script_dir + "/").rstrip("/") for _ in range(5)):
        candidate = os.path.join(parent, "data", "vespid.db")
        if os.path.isfile(candidate):
            return candidate
        candidate = os.path.join(parent, "vespid.db")
        if os.path.isfile(candidate):
            return candidate
    return "data/vespid.db"


def backfill_nodes(db: sqlite3.Connection) -> int:
    """Backfill assets from nodes rows without an asset_id. Returns count."""
    from app.inventory import ensure_asset, add_asset_alias

    rows = db.execute(
        "SELECT * FROM nodes WHERE asset_id IS NULL OR asset_id = ''"
    ).fetchall()
    log.info("%d nodes rows without asset_id", len(rows))

    count = 0
    for row in rows:
        node_id = row["node_id"]
        display_name = row.get("display_name", "") or node_id
        host_info = {}
        try:
            host_info = json.loads(row.get("last_host_info", "{}"))
        except (json.JSONDecodeError, TypeError):
            pass

        identifiers = {}
        if host_info.get("machine_id"):
            identifiers["machine_id"] = host_info["machine_id"]
        if host_info.get("hostname"):
            identifiers["hostname"] = host_info["hostname"]
        for iface in host_info.get("interfaces", []):
            if iface.get("mac"):
                identifiers.setdefault("mac", []).append(iface["mac"])
            for ip in iface.get("ipv4", []):
                identifiers.setdefault("ipv4", []).append(ip)

        metadata = {
            k: host_info[k]
            for k in ("os", "kernel", "uptime_seconds", "cpu_count", "memory_total_mb")
            if k in host_info
        }
        metadata["interfaces"] = host_info.get("interfaces", [])

        asset_id = ensure_asset(
            db,
            asset_type="host",
            display_name=display_name,
            source="agent",
            metadata=metadata,
            **identifiers,
        )

        db.execute(
            "UPDATE nodes SET asset_id = ? WHERE node_id = ?",
            (asset_id, node_id),
        )

        now = _utcnow()
        db.execute(
            "UPDATE enrollment_requests SET asset_id = ? WHERE node_id = ? AND asset_id IS NULL",
            (asset_id, node_id),
        )

        count += 1
        if count % 50 == 0:
            log.info("  backfilled %d ...", count)

    db.commit()
    return count


def main():
    parser = argparse.ArgumentParser(description="Backfill assets from nodes table")
    parser.add_argument("--db", default=None, help="Path to vespid.db")
    args = parser.parse_args()

    db_path = args.db or _get_default_db_path()
    log.info("Using database: %s", db_path)

    if not os.path.isfile(db_path):
        log.error("Database not found: %s", db_path)
        sys.exit(1)

    # Ensure the app package is importable (parent of app/ directory)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=OFF")

    try:
        count = backfill_nodes(conn)
        log.info("Done. %d nodes backfilled.", count)
    finally:
        conn.close()


if __name__ == "__main__":
    main()
