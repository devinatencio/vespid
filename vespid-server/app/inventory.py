"""Inventory service — authoritative asset registry and entity resolution.

Provides functions for resolving, creating, updating, and merging asset
records. All external identifiers (machine-id, hostname, MAC, IP) are stored
in ``asset_aliases`` for cross-source entity resolution.
"""

import json
import logging
import uuid
from datetime import UTC, datetime

logger = logging.getLogger(__name__)


def _utcnow() -> str:
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _new_asset_id() -> str:
    return str(uuid.uuid4())


# ── Alias priority ordering ──────────────────────────────────────────────

_ALIAS_PRIORITY = {
    "machine_id": 100,
    "uuid": 100,
    "serial": 100,
    "sync_id": 98,
    "vmid": 95,
    "mac": 85,
    "hostname": 70,
    "fqdn": 65,
    "ipv4": 50,
    "ipv6": 40,
}


_LOCALHOST_NAMES = frozenset(
    {"localhost", "localhost.localdomain", "localhost6", "localhost6.localdomain6"}
)
_LOCALHOST_IPS = frozenset({"127.0.0.1", "127.0.1.1", "::1", "0.0.0.0"})
_NULL_MACS = frozenset({"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"})


def _is_localhost_display_name(name: str) -> bool:
    if not name:
        return True
    lower = name.lower().strip()
    return lower in _LOCALHOST_NAMES or lower.startswith("localhost")


def _is_noise(key: str, value: str) -> bool:
    """Return True if this identifier is noise (localhost, loopback, etc.) and should be skipped."""
    if key in ("hostname", "fqdn") and value.lower() in _LOCALHOST_NAMES:
        return True
    if key == "mac" and value.lower() in _NULL_MACS:
        return True
    if key in ("ipv4", "ipv6") and value.lower() in _LOCALHOST_IPS:
        return True
    if key == "hostname" and value.lower().startswith("localhost"):
        return True
    return False


def _extract_identifiers(**kwargs) -> list[tuple[str, str, int]]:
    """Build a sorted list of (alias_type, value, confidence) from a kwargs dict.

    Keys match alias_type names. Values can be a single string or a list.
    Confidence comes from _ALIAS_PRIORITY or the value itself if it includes
    a tuple (type, value, confidence). Localhost/loopback values are skipped.
    """
    aliases: list[tuple[str, str, int]] = []
    for key, value in kwargs.items():
        if value is None:
            continue
        base_confidence = _ALIAS_PRIORITY.get(key, 50)
        if isinstance(value, list):
            for v in value:
                if v and isinstance(v, str) and v.strip() and not _is_noise(key, v.strip()):
                    aliases.append((key, v.strip(), base_confidence))
        elif isinstance(value, str) and value.strip() and not _is_noise(key, value.strip()):
            aliases.append((key, value.strip(), base_confidence))
    aliases.sort(key=lambda x: x[2], reverse=True)
    return aliases


# ── CRUD helpers ─────────────────────────────────────────────────────────


def get_asset(db, asset_id: str) -> dict | None:
    """Return an asset record by asset_id, or None."""
    row = db.execute("SELECT * FROM assets WHERE asset_id = ?", (asset_id,)).fetchone()
    return dict(row) if row else None


def get_asset_by_node(db, node_id: str) -> dict | None:
    """Return the asset linked to a node_id (nodes.asset_id)."""
    row = db.execute(
        "SELECT a.* FROM assets a JOIN nodes n ON a.asset_id = n.asset_id WHERE n.node_id = ?",
        (node_id,),
    ).fetchone()
    return dict(row) if row else None


def list_assets(
    db, asset_type: str | None = None, status: str | None = None, limit: int = 200
) -> list[dict]:
    """Return assets, optionally filtered by type and/or status."""
    parts = ["SELECT * FROM assets WHERE 1=1"]
    params = []
    if asset_type:
        parts.append("AND asset_type = ?")
        params.append(asset_type)
    if status:
        parts.append("AND status = ?")
        params.append(status)
    parts.append("ORDER BY display_name")
    parts.append("LIMIT ?")
    params.append(limit)
    rows = db.execute(" ".join(parts), params).fetchall()
    return [dict(r) for r in rows]


# ── Alias management ─────────────────────────────────────────────────────


def add_asset_alias(
    db, asset_id: str, alias_type: str, alias_value: str, source: str, confidence: int
) -> bool:
    """Add an alias mapping. Returns True if inserted, False if already exists."""
    now = _utcnow()
    from app.db_compat import MySQLConnectionWrapper as _MySQLConn

    _is_mysql = isinstance(db, _MySQLConn)
    _ignore = "INSERT IGNORE" if _is_mysql else "INSERT OR IGNORE"
    try:
        cur = db.execute(
            f"{_ignore} INTO asset_aliases (asset_id, alias_type, alias_value, source, "
            f"confidence, first_claimed_at, last_confirmed_at) "
            f"VALUES (?, ?, ?, ?, ?, ?, ?)",
            (asset_id, alias_type, alias_value, source, confidence, now, now),
        )
        # On MySQL, rowcount=1 means inserted, 0 means ignored (already existed).
        # On SQLite, rowcount=1 means inserted, 0 means ignored.
        # rowcount is unreliable for INSERT OR IGNORE on some SQLite versions, so
        # fall back to rowcount==0 detection vs. previous check.
        inserted = (cur.rowcount == 1) if cur.rowcount is not None else True
        if not inserted:
            db.execute(
                "UPDATE asset_aliases SET last_confirmed_at = ? "
                "WHERE alias_type = ? AND alias_value = ? AND asset_id = ?",
                (now, alias_type, alias_value, asset_id),
            )
        db.commit()
        return inserted
    except Exception:
        db.rollback()
        logger.exception("add_asset_alias failed for %s=%s", alias_type, alias_value)
        return False


def get_aliases_for_asset(db, asset_id: str) -> list[dict]:
    """Return all aliases for an asset."""
    rows = db.execute("SELECT * FROM asset_aliases WHERE asset_id = ?", (asset_id,)).fetchall()
    return [dict(r) for r in rows]


# ── Delete ───────────────────────────────────────────────────────────────


def delete_asset(db, asset_id: str) -> None:
    """Delete an asset and its cascading records.

    Foreign-key linkages on existing tables are set to NULL (orphaned)
    rather than deleting data owned by other subsystems.

    ``asset_aliases`` and ``asset_relationships`` are cascade-deleted by
    the database.
    """
    db.execute("UPDATE nodes SET asset_id = NULL WHERE asset_id = ?", (asset_id,))
    db.execute("UPDATE enrollment_requests SET asset_id = NULL WHERE asset_id = ?", (asset_id,))
    db.execute("UPDATE config_agent_status SET asset_id = NULL WHERE asset_id = ?", (asset_id,))
    db.execute("UPDATE assets SET parent_id = NULL WHERE parent_id = ?", (asset_id,))
    db.execute("DELETE FROM assets WHERE asset_id = ?", (asset_id,))
    db.commit()


def list_assets_by_ids(db, asset_ids: list[str]) -> list[dict]:
    """Return assets matching the given list of IDs."""
    if not asset_ids:
        return []
    placeholders = ",".join("?" for _ in asset_ids)
    rows = db.execute(
        f"SELECT * FROM assets WHERE asset_id IN ({placeholders}) ORDER BY display_name",
        asset_ids,
    ).fetchall()
    return [dict(r) for r in rows]


# ── Admin cleanup ─────────────────────────────────────────────────────────


def find_stale_assets(db, older_than_hours: int = 24) -> list[dict]:
    """Return assets with 'stale' or 'gone' status older than the threshold."""
    from datetime import datetime, timedelta

    cutoff = datetime.now(UTC) - timedelta(hours=older_than_hours)
    cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")
    rows = db.execute(
        "SELECT a.*, "
        "(SELECT COUNT(*) FROM asset_aliases WHERE asset_id = a.asset_id) AS alias_count, "
        "(SELECT COUNT(*) FROM asset_relationships WHERE source_asset_id = a.asset_id OR target_asset_id = a.asset_id) AS rel_count "
        "FROM assets a "
        "WHERE a.status IN ('stale', 'gone') AND a.last_seen_at < ? "
        "ORDER BY a.last_seen_at",
        (cutoff_str,),
    ).fetchall()
    return [dict(r) for r in rows]


def find_duplicate_assets(db) -> list[dict]:
    """Find potential duplicate assets sharing the same hostname or machine_id alias.

    Uses a self-join on ``asset_aliases`` filtered to high-confidence
    identifier types. While a self-join is O(N²) in the worst case, the
    ``UNIQUE(alias_type, alias_value)`` constraint means duplicate-detection
    queries are cheap in practice (only assets sharing identifiers are joined).
    """
    rows = db.execute(
        "SELECT aa1.alias_value AS shared_value, "
        "aa1.alias_type AS shared_type, "
        "aa1.asset_id AS asset_id_1, a1.display_name AS name_1, a1.created_by_source AS source_1, a1.first_seen_at AS first_1, "
        "aa2.asset_id AS asset_id_2, a2.display_name AS name_2, a2.created_by_source AS source_2, a2.first_seen_at AS first_2 "
        "FROM asset_aliases aa1 "
        "JOIN asset_aliases aa2 ON aa1.alias_value = aa2.alias_value AND aa1.alias_type = aa2.alias_type AND aa1.asset_id < aa2.asset_id "
        "JOIN assets a1 ON aa1.asset_id = a1.asset_id "
        "JOIN assets a2 ON aa2.asset_id = a2.asset_id "
        "WHERE aa1.alias_type IN ('hostname', 'machine_id', 'mac', 'serial', 'uuid') "
        "AND a1.status = 'active' AND a2.status = 'active' "
        "ORDER BY aa1.alias_type, aa1.alias_value"
    ).fetchall()
    return [dict(r) for r in rows]


def find_orphaned_aliases(db) -> list[dict]:
    """Return aliases pointing to non-existent assets (shouldn't happen with FKs)."""
    rows = db.execute(
        "SELECT aa.* FROM asset_aliases aa "
        "LEFT JOIN assets a ON aa.asset_id = a.asset_id "
        "WHERE a.asset_id IS NULL"
    ).fetchall()
    return [dict(r) for r in rows]


def purge_stale_assets(db, older_than_hours: int = 24) -> int:
    """Delete all stale/gone assets older than the threshold. Returns count."""
    stale = find_stale_assets(db, older_than_hours)
    count = 0
    for asset in stale:
        delete_asset(db, asset["asset_id"])
        count += 1
    return count


# ── Labels ───────────────────────────────────────────────────────────────


def update_asset_labels(db, asset_id: str, labels: dict) -> None:
    """Deep-merge a set of labels into an asset."""
    existing = get_asset(db, asset_id)
    if not existing:
        return
    current = json.loads(existing.get("labels", "{}"))
    merged = _merge_metadata(current, labels)
    db.execute("UPDATE assets SET labels = ? WHERE asset_id = ?", (json.dumps(merged), asset_id))
    db.commit()


def remove_asset_label(db, asset_id: str, key: str) -> None:
    """Remove a single label key from an asset."""
    existing = get_asset(db, asset_id)
    if not existing:
        return
    current = json.loads(existing.get("labels", "{}"))
    current.pop(key, None)
    db.execute("UPDATE assets SET labels = ? WHERE asset_id = ?", (json.dumps(current), asset_id))
    db.commit()


# ── Grouped listing ──────────────────────────────────────────────────────


def list_assets_grouped(db) -> list[dict]:
    """Return assets with their parent display_name attached for grouping.

    Each row includes a ``_parent_name`` field set to the parent's
    ``display_name``, or ``None`` for root-level assets.
    """
    rows = db.execute(
        "SELECT a.*, p.display_name AS _parent_name "
        "FROM assets a "
        "LEFT JOIN assets p ON a.parent_id = p.asset_id "
        "ORDER BY a.created_by_source, a.asset_type, a.display_name"
    ).fetchall()
    return [dict(r) for r in rows]


# ── Search ───────────────────────────────────────────────────────────────


def search_assets(
    db,
    query: str = "",
    asset_type: str | None = None,
    source: str | None = None,
    status: str | None = None,
    label: str | None = None,
    parent_id: str | None = None,
    limit: int = 100,
    offset: int = 0,
) -> tuple[list[dict], int]:
    """Search assets with filters and full-text search across name and aliases.

    Returns ``(assets, total_count)``.
    """
    clauses = ["1=1"]
    params: list = []

    if query:
        like = f"%{query}%"
        clauses.append(
            "(a.display_name LIKE ? OR EXISTS ("
            "SELECT 1 FROM asset_aliases aa WHERE aa.asset_id = a.asset_id "
            "AND aa.alias_value LIKE ?))"
        )
        params.extend([like, like])
    if asset_type:
        clauses.append("a.asset_type = ?")
        params.append(asset_type)
    if source:
        clauses.append("a.created_by_source = ?")
        params.append(source)
    if status:
        clauses.append("a.status = ?")
        params.append(status)
    if label and "=" in label:
        k, v = label.split("=", 1)
        clauses.append("a.labels LIKE ?")
        params.append(f'%"{k}":%"{v}"%')
    if parent_id:
        clauses.append("a.parent_id = ?")
        params.append(parent_id)

    where = " AND ".join(clauses)

    count_row = db.execute(f"SELECT COUNT(*) AS cnt FROM assets a WHERE {where}", params).fetchone()
    total = count_row["cnt"] if count_row else 0

    rows = db.execute(
        f"SELECT a.* FROM assets a WHERE {where} ORDER BY a.display_name LIMIT ? OFFSET ?",
        [*params, limit, offset],
    ).fetchall()

    return [dict(r) for r in rows], total


# ── Entity resolution ────────────────────────────────────────────────────


def resolve_asset(db, **identifiers) -> tuple[str | None, int]:
    """Find an existing asset by its known aliases.

    Checks identifiers in priority order (machine_id > serial > vmid >
    mac > hostname > ip). Returns ``(asset_id, confidence)`` or ``(None, 0)``.

    Args:
        db: An open SQLite connection.
        **identifiers: Keyword args where keys are alias_type (machine_id,
            hostname, mac, ipv4, etc.) and values are strings or lists.

    Returns:
        ``(asset_id, confidence)`` — best match found, or ``(None, 0)``.
    """
    candidates = _extract_identifiers(**identifiers)
    seen_assets: dict[str, int] = {}  # asset_id → highest confidence
    for alias_type, alias_value, confidence in candidates:
        row = db.execute(
            "SELECT asset_id FROM asset_aliases WHERE alias_type = ? AND alias_value = ?",
            (alias_type, alias_value),
        ).fetchone()
        if row:
            aid = row["asset_id"]
            existing = seen_assets.get(aid, 0)
            if confidence > existing:
                seen_assets[aid] = confidence

    if not seen_assets:
        return None, 0

    # Return the highest-confidence match
    best_id = max(seen_assets, key=lambda k: seen_assets[k])
    return best_id, seen_assets[best_id]


def ensure_asset(
    db,
    asset_type: str = "host",
    display_name: str = "",
    source: str = "agent",
    metadata: dict | None = None,
    **identifiers,
) -> str:
    """Resolve an asset or create one if no match exists.

    Checks known aliases. If found, merges in new aliases and metadata.
    If not found, creates a new asset with a fresh UUID.

    Args:
        db: An open SQLite connection.
        asset_type: ``'host'``, ``'vm'``, ``'container'``, etc.
        display_name: Human-readable name (hostname).
        source: Discovery source (``'agent'``, ``'monitor'``, ``'proxmox'``).
        metadata: Dict of asset metadata (OS, kernel, cpu, memory, etc.).
        **identifiers: Alias key/values (machine_id, hostname, mac, ipv4, …).

    Returns:
        The canonical ``asset_id``.
    """
    asset_id, confidence = resolve_asset(db, **identifiers)

    now = _utcnow()
    # Strip localhost hostname from incoming metadata before merge
    if (
        metadata
        and isinstance(metadata, dict)
        and _is_localhost_display_name(metadata.get("hostname", ""))
    ):
        metadata.pop("hostname", None)
    if asset_id:
        # Existing asset — update last_seen, only write metadata if changed
        existing = get_asset(db, asset_id) if (metadata or display_name) else None
        if existing:
            current_meta = json.loads(existing.get("metadata", "{}"))
            merged = _merge_metadata(current_meta, metadata or {})
            needs_update = merged != current_meta or display_name
            # Upgrade asset_type from 'host' to 'vm' when virt hints appear
            virt = (metadata or {}).get("virt_type") or (merged or {}).get("virt_type")
            current_type = existing.get("asset_type", "host")
            if virt == "vm" and current_type == "host":
                needs_update = True
            if needs_update:
                set_clauses = ["last_seen_at = ?"]
                set_params = [now]
                if merged != current_meta:
                    set_clauses.append("metadata = ?")
                    set_params.append(json.dumps(merged))
                existing_dn = existing.get("display_name", "")
                clean_dn = display_name if not _is_localhost_display_name(display_name) else ""
                if clean_dn and (not existing_dn or _is_localhost_display_name(existing_dn)):
                    set_clauses.append("display_name = ?")
                    set_params.append(clean_dn)
                if virt == "vm" and current_type == "host":
                    set_clauses.append("asset_type = ?")
                    set_params.append("vm")
                set_params.append(asset_id)
                db.execute(
                    f"UPDATE assets SET {', '.join(set_clauses)} WHERE asset_id = ?",
                    set_params,
                )
                db.commit()
            else:
                db.execute("UPDATE assets SET last_seen_at = ? WHERE asset_id = ?", (now, asset_id))
                db.commit()
        # Add any new aliases that don't exist yet
        candidates = _extract_identifiers(**identifiers)
        for alias_type, alias_value, confidence_val in candidates:
            add_asset_alias(db, asset_id, alias_type, alias_value, source, confidence_val)
        return asset_id

    # No match — create a new asset
    virt = (metadata or {}).get("virt_type") if metadata else None
    effective_type = asset_type
    if effective_type == "host" and virt == "vm":
        effective_type = "vm"
    asset_id = _new_asset_id()
    clean_dn = display_name if not _is_localhost_display_name(display_name) else ""
    metadata_json = json.dumps(metadata or {})
    db.execute(
        "INSERT INTO assets (asset_id, asset_type, display_name, metadata, "
        "first_seen_at, last_seen_at, status, created_by_source) "
        "VALUES (?, ?, ?, ?, ?, ?, 'active', ?)",
        (asset_id, effective_type, clean_dn, metadata_json, now, now, source),
    )
    candidates = _extract_identifiers(**identifiers)
    for alias_type, alias_value, confidence_val in candidates:
        try:
            db.execute(
                "INSERT INTO asset_aliases (asset_id, alias_type, alias_value, source, confidence, "
                "first_claimed_at, last_confirmed_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (asset_id, alias_type, alias_value, source, confidence_val, now, now),
            )
        except Exception:
            db.rollback()
    db.commit()
    return asset_id


def _is_dummy_mac(mac: str | None) -> bool:
    """Return True for absent, None, empty, or all-zero MAC addresses.

    Linux tunnel/virtual interfaces (gre, sit, tunl, etc.) often report
    ``00:00:00:00:00:00`` or all-zero EUI-64 for IPv6 tunnels.
    """
    if not mac:
        return True
    clean = mac.replace(":", "").replace("-", "").replace(".", "")
    return all(c == "0" for c in clean)


def _relevant_interfaces(ifaces: list) -> list:
    """Filter out tunnel/virtual interfaces that carry no traffic.

    Keeps interfaces that have at least one assigned IP *or* a non-dummy
    MAC address.  This excludes Linux tunnel devices (gre, sit, tunl,
    ip6tnl, erspan, bonding_masters, …) that have no IPs and a fabricated
    all-zero MAC.
    """
    return [
        iface
        for iface in ifaces
        if isinstance(iface, dict)
        and (iface.get("ipv4") or iface.get("ipv6") or not _is_dummy_mac(iface.get("mac")))
    ]


def update_asset_seen(db, asset_id: str, metadata: dict | None = None) -> None:
    """Update ``last_seen_at`` every call. Write metadata only when it differs.

    Compares the incoming metadata JSON against the current value — if
    nothing changed the UPDATE is skipped. This keeps per-second I/O low
    for systems with hundreds of agents.

    Also syncs IPv4/IPv6 addresses from ``metadata.interfaces`` into
    ``asset_aliases`` so they show up on the inventory overview cards.

    Args:
        db: An open SQLite connection.
        asset_id: The canonical asset UUID.
        metadata: Optional dict of host metadata (OS, kernel, interfaces…).
            Stored only if it differs from the current value.
    """
    now = _utcnow()

    # Sync IP and MAC aliases from interfaces metadata (skipping tunnel/virtual ifaces)
    if metadata:
        ifaces = _relevant_interfaces(metadata.get("interfaces") or [])
        seen_ips = {}
        seen_macs = set()
        for iface in ifaces:
            if not isinstance(iface, dict):
                continue
            for ip in iface.get("ipv4") or []:
                if ip and isinstance(ip, str) and ip.strip():
                    seen_ips.setdefault("ipv4", set()).add(ip.strip())
            for ip in iface.get("ipv6") or []:
                if ip and isinstance(ip, str) and ip.strip():
                    seen_ips.setdefault("ipv6", set()).add(ip.strip())
            mac = iface.get("mac", "") or ""
            if mac.strip() and not _is_dummy_mac(mac):
                seen_macs.add(mac.strip().lower())
        for alias_type, ips in seen_ips.items():
            for ip in sorted(ips):
                add_asset_alias(db, asset_id, alias_type, ip, source="heartbeat", confidence=100)
        for mac in sorted(seen_macs):
            add_asset_alias(db, asset_id, "mac", mac, source="heartbeat", confidence=100)

    if metadata:
        existing = get_asset(db, asset_id)
        if existing:
            current_meta = json.loads(existing.get("metadata", "{}"))
            if metadata != current_meta:
                merged = _merge_metadata(current_meta, metadata)
                if merged != current_meta:
                    db.execute(
                        "UPDATE assets SET last_seen_at = ?, metadata = ? WHERE asset_id = ?",
                        (now, json.dumps(merged), asset_id),
                    )
                    db.commit()
                    return
    db.execute(
        "UPDATE assets SET last_seen_at = ? WHERE asset_id = ?",
        (now, asset_id),
    )
    db.commit()


# ── Metadata merge ───────────────────────────────────────────────────────


def _merge_metadata(existing: dict, incoming: dict) -> dict:
    """Deep-merge incoming metadata into existing.

    Lists (e.g. interfaces, packages) are replaced wholesale by the incoming
    value when present. Scalar fields are overwritten by incoming.
    """
    merged = dict(existing)
    for key, value in incoming.items():
        if value is None:
            continue
        if isinstance(value, dict) and isinstance(merged.get(key), dict):
            merged[key] = _merge_metadata(merged[key], value)
        else:
            merged[key] = value
    return merged


# ── Asset merging ────────────────────────────────────────────────────────


def merge_assets(db, keep_asset_id: str, discard_asset_id: str) -> int:
    """Merge two assets into one. Moves all aliases and relationships from
    discard to keep, then deletes the discarded asset.

    Returns the number of aliases moved.
    """
    now = _utcnow()

    # Move aliases from discard to keep
    moved = 0
    alias_rows = db.execute(
        "SELECT * FROM asset_aliases WHERE asset_id = ?", (discard_asset_id,)
    ).fetchall()
    for alias in alias_rows:
        try:
            db.execute(
                "UPDATE asset_aliases SET asset_id = ?, last_confirmed_at = ? WHERE id = ?",
                (keep_asset_id, now, alias["id"]),
            )
            moved += 1
        except Exception:
            # Duplicate alias on keep — delete from discard
            db.execute("DELETE FROM asset_aliases WHERE id = ?", (alias["id"],))
            moved += 1

    # Move relationships — re-parent source or target
    for col in ("source_asset_id", "target_asset_id"):
        rel_rows = db.execute(
            f"SELECT * FROM asset_relationships WHERE {col} = ?",
            (discard_asset_id,),
        ).fetchall()
        for rel in rel_rows:
            try:
                db.execute(
                    f"UPDATE asset_relationships SET {col} = ? WHERE id = ?",
                    (keep_asset_id, rel["id"]),
                )
            except Exception:
                db.execute("DELETE FROM asset_relationships WHERE id = ?", (rel["id"],))

    # Re-parent children of the discarded asset
    db.execute(
        "UPDATE assets SET parent_id = ? WHERE parent_id = ?",
        (keep_asset_id, discard_asset_id),
    )

    # Delete the discarded asset
    db.execute("DELETE FROM assets WHERE asset_id = ?", (discard_asset_id,))
    db.commit()
    return moved


# ── Relationships ────────────────────────────────────────────────────────


def add_relationship(
    db,
    source_asset_id: str,
    target_asset_id: str,
    relationship: str,
    metadata: dict | None = None,
) -> bool:
    """Create a relationship edge between two assets.

    ``relationship`` should be an uppercase constant like ``'RUNS_ON'``,
    ``'BELONGS_TO'``, ``'DEPENDS_ON'``, ``'CONNECTS_TO'``, ``'HOSTS'``.

    Returns True if inserted, False if already exists.
    """
    now = _utcnow()
    try:
        db.execute(
            "INSERT INTO asset_relationships (source_asset_id, target_asset_id, "
            "relationship, metadata, created_at) VALUES (?, ?, ?, ?, ?)",
            (source_asset_id, target_asset_id, relationship, json.dumps(metadata or {}), now),
        )
        db.commit()
        return True
    except Exception:
        db.rollback()
        return False


def get_relationships(db, asset_id: str, relationship: str | None = None) -> list[dict]:
    """Return all relationships for an asset, optionally filtered by type."""
    parts = ["SELECT * FROM asset_relationships WHERE source_asset_id = ? OR target_asset_id = ?"]
    params = [asset_id, asset_id]
    if relationship:
        parts.append("AND relationship = ?")
        params.append(relationship)
    rows = db.execute(" ".join(parts), params).fetchall()
    return [dict(r) for r in rows]
