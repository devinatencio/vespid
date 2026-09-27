"""Inventory sync API — batch asset import from discovery sources.

Endpoints:
    POST /api/v1/inventory/sync  — Receive a batch of discovered assets
"""

import json
import logging
from datetime import UTC, datetime

from flask import Blueprint, current_app, jsonify, request

from app.decorators import require_role
from app.inventory import (
    add_relationship,
    ensure_asset,
    resolve_asset,
)
from app.models import get_db
from app.rate_limit import limiter

logger = logging.getLogger(__name__)

inventory_sync_bp = Blueprint("inventory_sync", __name__, url_prefix="/api/v1/inventory")


# ── Validation limits ──────────────────────────────────────────────────────

_MAX_BATCH_SIZE = 5000
_MAX_STRING_LEN = 255
_MAX_JSON_BYTES = 64 * 1024  # 64 KB per metadata/labels/aliases blob
_ALLOWED_ASSET_TYPES = frozenset({"host", "vm", "container", "hypervisor", "storage"})


def _validate_str(value, field: str, max_len: int = _MAX_STRING_LEN, required: bool = False):
    """Validate a string field: type, length, required."""
    if value is None:
        if required:
            return None, f"{field} is required"
        return "", None
    if not isinstance(value, str):
        return None, f"{field} must be a string"
    v = value.strip()
    if not v and required:
        return None, f"{field} is required"
    if len(v) > max_len:
        return None, f"{field} exceeds max length {max_len}"
    return v, None


def _validate_json_blob(value, field: str) -> tuple[dict | None, str | None]:
    """Validate a JSON object blob: must be a dict, serialized size <= 64KB."""
    if value is None or value == {}:
        return {}, None
    if not isinstance(value, dict):
        return None, f"{field} must be a JSON object"
    try:
        encoded = json.dumps(value)
    except (TypeError, ValueError) as exc:
        return None, f"{field} is not JSON-serializable: {exc}"
    if len(encoded) > _MAX_JSON_BYTES:
        return None, f"{field} exceeds {_MAX_JSON_BYTES} bytes"
    return value, None


@inventory_sync_bp.route("/sync", methods=["POST"])
@limiter.limit(lambda: current_app.config.get("RATELIMIT_INVENTORY_SYNC", "30 per minute"))
@require_role("agent")
def sync():
    """Ingest a batch of discovered assets from a sync provider.

    Expected JSON body:
    .. code-block:: json

        {
          "provider": "proxmox",
          "cluster": "homelab",
          "assets": [
            {
              "external_id": "qemu/102",
              "display_name": "web01",
              "asset_type": "vm",
              "parent_external_id": "node/pve1",
              "metadata": {"cpu_cores": 4, "memory_mb": 8192},
              "labels": {"pool": "production"},
              "aliases": {"hostname": "web01.internal", "mac": "aa:bb:cc:dd:ee:ff", "ipv4": "10.0.1.5"},
              "status": "running"
            }
          ]
        }

    Returns the count of created/updated assets and relationships.
    """
    body = request.get_json(silent=True)
    if body is None or not isinstance(body, dict):
        return jsonify({"error": "invalid_json"}), 400

    provider, err = _validate_str(body.get("provider"), "provider", required=True)
    if err:
        return jsonify({"error": err}), 400
    cluster, _ = _validate_str(body.get("cluster"), "cluster")
    raw_assets = body.get("assets")
    if not isinstance(raw_assets, list) or not raw_assets:
        return jsonify({"error": "assets array is required and must be non-empty"}), 400
    if len(raw_assets) > _MAX_BATCH_SIZE:
        return jsonify(
            {
                "error": "batch_too_large",
                "max": _MAX_BATCH_SIZE,
                "received": len(raw_assets),
            }
        ), 413

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        # Collect the set of fully-qualified sync_ids (provider:external_id) in
        # this batch for stale detection. We store the prefix-qualified form
        # to match the alias_value format in the DB.
        batch_sync_ids = set()
        created_count = 0
        updated_count = 0
        alias_count = 0
        rel_count = 0

        # First pass: upsert all assets
        # Track sync_ids that existed before this batch to distinguish create vs update
        seen_before = {
            row["alias_value"]
            for row in db.execute(
                "SELECT alias_value FROM asset_aliases WHERE alias_type = 'sync_id' AND alias_value LIKE ?",
                (f"{provider}:%",),
            ).fetchall()
        }
        for entry in raw_assets:
            if not isinstance(entry, dict):
                continue
            # Validate the entry. Skip-and-log invalid entries rather than
            # failing the whole batch — the spec is permissive by design.
            external_id, _ = _validate_str(entry.get("external_id"), "external_id", required=True)
            display_name, _ = _validate_str(
                entry.get("display_name"), "display_name", required=True
            )
            asset_type_raw, _ = _validate_str(entry.get("asset_type"), "asset_type")
            if not external_id or not display_name:
                continue

            sync_key = f"{provider}:{external_id}"
            was_created = sync_key not in seen_before
            result = _upsert_sync_asset(db, provider, cluster, entry)
            if result is None:
                continue
            asset_id, aliases_added = result
            batch_sync_ids.add(sync_key)
            alias_count += aliases_added
            if was_created:
                created_count += 1
            else:
                updated_count += 1

        # Second pass: resolve relationships from parent_external_id
        for entry in raw_assets:
            if not isinstance(entry, dict):
                continue
            external_id, _ = _validate_str(entry.get("external_id"), "external_id", required=True)
            parent_id, _ = _validate_str(entry.get("parent_external_id"), "parent_external_id")
            if external_id and parent_id:
                child = resolve_asset(db, sync_id=provider + ":" + external_id)
                parent = resolve_asset(db, sync_id=provider + ":" + parent_id)
                if child[0] and parent[0]:
                    if add_relationship(db, child[0], parent[0], "RUNS_ON"):
                        rel_count += 1

        # Cluster-level relationships
        if cluster:
            cluster_sync_id = f"{provider}:{cluster}"
            for entry in raw_assets:
                if not isinstance(entry, dict):
                    continue
                # Link hypervisors to cluster
                if entry.get("asset_type") == "hypervisor":
                    eid, _ = _validate_str(entry.get("external_id"), "external_id", required=True)
                    if eid:
                        resolved = resolve_asset(db, sync_id=cluster_sync_id)
                        if resolved[0]:
                            node_asset = resolve_asset(db, sync_id=provider + ":" + eid)
                            if node_asset[0]:
                                if add_relationship(db, node_asset[0], resolved[0], "BELONGS_TO"):
                                    rel_count += 1

        # Stale detection: mark assets from this provider not in batch
        stale_count = _mark_stale_external(db, provider, batch_sync_ids)

        db.commit()

        logger.info(
            "Sync %s/%s: %d created, %d updated, %d stale, %d aliases, %d relationships",
            provider,
            cluster or "*",
            created_count,
            updated_count,
            stale_count,
            alias_count,
            rel_count,
        )

        return jsonify(
            {
                "status": "ok",
                "created": created_count,
                "updated": updated_count,
                "stale": stale_count,
                "aliases": alias_count,
                "relationships": rel_count,
            }
        ), 200

    except Exception:
        logger.exception("Sync batch failed for provider %s", provider)
        db.rollback()
        return jsonify({"error": "sync_failed", "message": "An internal error occurred"}), 500
    finally:
        db.close()


def _upsert_sync_asset(db, provider: str, cluster: str, entry: dict) -> tuple[str | None, int]:
    """Create or update a single asset from a sync provider entry.

    Returns ``(asset_id, aliases_added)`` on success, or ``(None, 0)`` if the
    entry is invalid. ``aliases_added`` counts new alias rows created (not
    alias values that already existed).
    """
    external_id = (entry.get("external_id") or "").strip()
    display_name = (entry.get("display_name") or "").strip()
    asset_type = (entry.get("asset_type") or "vm").strip()
    entry_metadata = entry.get("metadata") or {}
    labels = entry.get("labels") or {}
    raw_aliases = entry.get("aliases") or {}
    status = (entry.get("status") or "unknown").strip()

    if not external_id or not display_name:
        return None, 0

    # Build identifiers from the entry's aliases + sync_id
    identifiers = {"sync_id": f"{provider}:{external_id}"}
    if isinstance(raw_aliases, dict):
        for alias_type, alias_value in raw_aliases.items():
            if alias_type and alias_value:
                if isinstance(alias_value, str) and alias_value.strip():
                    identifiers[alias_type] = alias_value.strip()
                elif isinstance(alias_value, list):
                    identifiers[alias_type] = [
                        v.strip() for v in alias_value if isinstance(v, str) and v.strip()
                    ]

    # Use aliases hostname if available, otherwise the configured display_name
    effective_name = display_name
    if isinstance(raw_aliases, dict) and raw_aliases.get("hostname"):
        effective_name = raw_aliases["hostname"]

    # Merge sync metadata with labels
    full_metadata = dict(entry_metadata)
    full_metadata["sync_source"] = provider
    full_metadata["cluster"] = cluster
    if labels:
        full_metadata["labels"] = labels

    asset_type_override = "host"
    if asset_type in _ALLOWED_ASSET_TYPES:
        asset_type_override = asset_type

    asset_id = ensure_asset(
        db,
        asset_type=asset_type_override,
        display_name=effective_name,
        source="sync",
        metadata=full_metadata,
        **identifiers,
    )

    if not asset_id:
        return None, 0

    # Mark status. Map incoming status to one of the allowed DB statuses.
    # Priority: explicit lifecycle (running/stopped/paused) wins, otherwise
    # "active" if unknown, "stale" for anything else.
    if status in ("running", "stopped", "paused"):
        db_status = status
    elif status == "active":
        db_status = "active"
    else:
        db_status = "stale"
    db.execute("UPDATE assets SET status = ? WHERE asset_id = ?", (db_status, asset_id))

    return asset_id, len(identifiers)


def _mark_stale_external(db, provider: str, active_sync_ids: set) -> int:
    """Mark assets from this provider not in the current batch as stale.

    ``active_sync_ids`` must be the fully-qualified ``provider:external_id``
    values (matching ``asset_aliases.alias_value`` for ``alias_type='sync_id'``).
    """
    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    count = 0
    rows = db.execute(
        "SELECT aa.asset_id, aa.alias_value "
        "FROM asset_aliases aa "
        "JOIN assets a ON aa.asset_id = a.asset_id "
        "WHERE aa.alias_type = 'sync_id' AND aa.alias_value LIKE ? "
        "AND a.status = 'active'",
        (f"{provider}:%",),
    ).fetchall()
    for row in rows:
        if row["alias_value"] not in active_sync_ids:
            db.execute(
                "UPDATE assets SET status = 'stale', last_seen_at = ? WHERE asset_id = ?",
                (now, row["asset_id"]),
            )
            count += 1
    return count
