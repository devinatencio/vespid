"""Inventory dashboard blueprint — asset browsing, entity resolution, detail views.

Endpoints:
    GET /inventory                    — Asset list / overview (supports ?view=)
    GET /inventory/<asset_id>         — Asset detail page
    GET /inventory/query              — CMDB query explorer
    GET /inventory/api/query          — Rich JSON query API with filters
    GET /inventory/api/export         — Full JSON/CSV export
    GET /inventory/api/graph          — Relationship graph as nodes+edges
    GET /inventory/api/<id>/relationships — Per-asset relationships
    POST /inventory/<id>/delete       — Delete asset (admin only)
    POST /inventory/<id>/labels       — Merge key/value labels
    DELETE /inventory/<id>/labels/<k> — Remove a label
"""

import hashlib
import json
import logging

from flask import (
    Blueprint,
    Response,
    current_app,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user

from app.decorators import require_role
from app.inventory import (
    delete_asset as delete_asset_fn,
)
from app.inventory import (
    get_aliases_for_asset,
    get_asset,
    get_relationships,
    list_assets,
    list_assets_by_ids,
    remove_asset_label,
    search_assets,
    update_asset_labels,
)
from app.models import get_db, record_audit

logger = logging.getLogger(__name__)

inventory_bp = Blueprint("inventory", __name__, url_prefix="/inventory")


_LABEL_COLORS = [
    "#6366f1",
    "#8b5cf6",
    "#a855f7",
    "#d946ef",
    "#ec4899",
    "#f43f5e",
    "#ef4444",
    "#f97316",
    "#eab308",
    "#22c55e",
    "#14b8a6",
    "#06b6d4",
    "#3b82f6",
    "#0ea5e9",
    "#2563eb",
    "#7c3aed",
    "#db2777",
    "#dc2626",
    "#ea580c",
    "#d97706",
    "#65a30d",
    "#16a34a",
    "#0d9488",
    "#0891b2",
]


def label_color(key: str) -> str:
    """Return a ``background-color`` for a label key — consistent per key."""
    idx = int(hashlib.sha256(key.encode()).hexdigest(), 16) % len(_LABEL_COLORS)
    return f"--lbg:{_LABEL_COLORS[idx]}"


@inventory_bp.context_processor
def _inject_globals():
    return dict(label_color=label_color)


# ── Dashboard pages ─────────────────────────────────────────────────────


@inventory_bp.route("")
@require_role("viewer")
def overview():
    """Asset list / overview page with optional view mode.

    Query params:
        view=all      — flat list (default)
        view=grouped  — grouped by source / parent hierarchy
        view=hosts    — physical hosts and hypervisors only
    """
    view = request.args.get("view", "all")
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        raw = list_assets(db, limit=500)
        _enrich_aliases(db, raw)
        summary = _build_summary(raw)

        if view == "hosts":
            raw = [a for a in raw if a.get("asset_type") in ("host", "hypervisor")]
        elif view != "grouped":
            pass

        if view == "grouped":
            try:
                grouped = _build_grouped(raw)
            except Exception:
                logger.warning("Failed to build grouped view", exc_info=True)
                grouped = {}
        else:
            grouped = None
        resp = make_response(
            render_template(
                "inventory/overview.html",
                assets=raw,
                summary=summary,
                view=view,
                grouped=grouped,
            )
        )
    finally:
        db.close()

    resp.headers["Cache-Control"] = "no-store, must-revalidate"
    return resp


def _enrich_aliases(db, assets):
    """Attach aliases and agent types to each asset dict in-place (batched)."""
    if not assets:
        return
    asset_ids = [a["asset_id"] for a in assets]
    aliases_by_id = _bulk_get_aliases_for_assets(db, asset_ids)
    agent_types_by_id = _bulk_get_agent_types(db, asset_ids)
    for a in assets:
        aliases = aliases_by_id.get(a["asset_id"], [])
        a["_aliases"] = [al for al in aliases if al.get("alias_type") not in ("hostname", "fqdn")]
        a["_agent_types"] = agent_types_by_id.get(a["asset_id"], [])


def _bulk_get_aliases_for_assets(db, asset_ids: list[str]) -> dict[str, list[dict]]:
    """Return {asset_id: [aliases]} for a list of asset IDs in a single query."""
    if not asset_ids:
        return {}
    placeholders = ",".join("?" for _ in asset_ids)
    rows = db.execute(
        f"SELECT * FROM asset_aliases WHERE asset_id IN ({placeholders})",
        asset_ids,
    ).fetchall()
    out: dict[str, list[dict]] = {aid: [] for aid in asset_ids}
    for r in rows:
        out.setdefault(r["asset_id"], []).append(dict(r))
    return out


def _bulk_get_agent_types(db, asset_ids: list[str]) -> dict[str, list[str]]:
    """Return {asset_id: [agent_types]} in two bulk queries instead of 2N."""
    if not asset_ids:
        return {}
    placeholders = ",".join("?" for _ in asset_ids)
    out: dict[str, list[str]] = {aid: [] for aid in asset_ids}

    monitor_rows = db.execute(
        f"SELECT DISTINCT asset_id FROM config_agent_status WHERE asset_id IN ({placeholders})",
        asset_ids,
    ).fetchall()
    for r in monitor_rows:
        out.setdefault(r["asset_id"], []).append("monitor")

    agent_rows = db.execute(
        f"SELECT DISTINCT asset_id FROM nodes WHERE asset_id IN ({placeholders})",
        asset_ids,
    ).fetchall()
    for r in agent_rows:
        lst = out.setdefault(r["asset_id"], [])
        if "agent" not in lst:
            lst.append("agent")
    return out


def _get_agent_types(db, asset_id: str) -> list[str]:
    """Return agent type strings linked to a single asset (kept for detail page)."""
    types = []
    row = db.execute(
        "SELECT 1 FROM config_agent_status WHERE asset_id = ? LIMIT 1", (asset_id,)
    ).fetchone()
    if row:
        types.append("monitor")
    row = db.execute("SELECT 1 FROM nodes WHERE asset_id = ? LIMIT 1", (asset_id,)).fetchone()
    if row:
        types.append("agent")
    return types


@inventory_bp.route("/<asset_id>")
@require_role("viewer")
def detail(asset_id: str):
    """Asset detail page."""
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        asset = get_asset(db, asset_id)
        if not asset:
            return render_template("inventory/not_found.html", asset_id=asset_id), 404
        aliases = get_aliases_for_asset(db, asset_id)
        relationships = get_relationships(db, asset_id)
        children = _get_child_assets(db, asset_id)
        agents = _get_linked_agents(db, asset_id)
    finally:
        db.close()

    meta = _safe_json(asset.get("metadata", "{}"))
    if "uptime_seconds" in meta:
        meta["uptime"] = _format_uptime(meta.pop("uptime_seconds"))

    # Filter out tunnel/virtual interfaces with no IPs from metadata display
    ifaces = meta.get("interfaces") or []
    if isinstance(ifaces, list):
        meta["interfaces"] = [
            i
            for i in ifaces
            if isinstance(i, dict)
            and (
                i.get("ipv4")
                or i.get("ipv6")
                or (i.get("mac") or "").replace(":", "").replace("-", "").strip("0")
            )
        ]

    labels_raw = asset.get("labels", "{}")
    parsed_labels = _safe_json(labels_raw) if isinstance(labels_raw, str) else labels_raw or {}
    asset["labels_parsed"] = parsed_labels

    # Extract primary IPv4 from interfaces metadata for the stats card
    primary_ip = ""
    for iface in meta.get("interfaces") or []:
        for ip in iface.get("ipv4") or []:
            if ip and not ip.startswith("127.") and not ip.startswith("169.254."):
                primary_ip = ip
                break
        if primary_ip:
            break
    if not primary_ip:
        # Fall back to ipv4 aliases
        for a in aliases:
            if a.get("alias_type") == "ipv4" and a["alias_value"]:
                val = a["alias_value"]
                if not val.startswith("127.") and not val.startswith("169.254."):
                    primary_ip = val
                    break
    asset["ip_address"] = primary_ip

    return render_template(
        "inventory/detail.html",
        asset=asset,
        meta=meta,
        labels_dict=parsed_labels,
        aliases=aliases,
        relationships=relationships,
        children=children,
        agents=agents,
    )


# ── Query page ────────────────────────────────────────────────────────────


@inventory_bp.route("/query")
@require_role("viewer")
def query_page():
    """CMDB query explorer — build and run inventory queries."""
    return render_template("inventory/query.html")


# ── Delete ────────────────────────────────────────────────────────────────


@inventory_bp.route("/<asset_id>/delete", methods=["POST"])
@require_role("admin")
def delete(asset_id: str):
    """Delete an asset and cascade-clean foreign key references."""
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        asset = get_asset(db, asset_id)
        if not asset:
            return render_template("inventory/not_found.html", asset_id=asset_id), 404
        name = asset.get("display_name", asset_id)
        delete_asset_fn(db, asset_id)
        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="asset_deleted",
            target=name,
            details={"asset_id": asset_id},
        )
    finally:
        db.close()
    return redirect(url_for("inventory.overview"))


# ── Labels ────────────────────────────────────────────────────────────────


@inventory_bp.route("/<asset_id>/labels", methods=["POST"])
@require_role("viewer")
def set_labels(asset_id: str):
    """Merge key/value labels into an asset."""
    data = request.get_json(silent=True) or {}
    if not isinstance(data, dict) or not data:
        return jsonify({"error": "expected JSON object with label key/value pairs"}), 400
    # Reject too-large or malformed payloads
    try:
        encoded = json.dumps(data)
    except (TypeError, ValueError) as exc:
        return jsonify({"error": f"label payload not JSON-serializable: {exc}"}), 400
    if len(encoded) > 64 * 1024:
        return jsonify({"error": "label payload exceeds 64KB"}), 413
    for k, v in data.items():
        if not isinstance(k, str) or not k.strip() or len(k) > 64:
            return jsonify({"error": "label keys must be non-empty strings ≤ 64 chars"}), 400
        if not isinstance(v, (str, int, float, bool)) and v is not None:
            return jsonify(
                {"error": "label values must be strings, numbers, booleans, or null"}
            ), 400
        if isinstance(v, str) and len(v) > 1024:
            return jsonify({"error": "label string values must be ≤ 1024 chars"}), 400
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        if not get_asset(db, asset_id):
            return jsonify({"error": "not_found"}), 404
        update_asset_labels(db, asset_id, data)
        asset = get_asset(db, asset_id)
        labels = _safe_json(asset.get("labels", "{}"))
    finally:
        db.close()
    return jsonify({"status": "ok", "labels": labels})


@inventory_bp.route("/<asset_id>/labels/<key>", methods=["DELETE"])
@require_role("viewer")
def delete_label(asset_id: str, key: str):
    """Remove a single label key from an asset."""
    if not key or len(key) > 64:
        return jsonify({"error": "invalid label key"}), 400
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        if not get_asset(db, asset_id):
            return jsonify({"error": "not_found"}), 404
        remove_asset_label(db, asset_id, key)
        asset = get_asset(db, asset_id)
        labels = _safe_json(asset.get("labels", "{}"))
    finally:
        db.close()
    return jsonify({"status": "ok", "labels": labels})


# ── CMDB API endpoints ───────────────────────────────────────────────────


@inventory_bp.route("/api/query")
@require_role("viewer")
def api_query():
    """Rich asset query endpoint. Supports filters, search, pagination.

    Query params:
        q          — free-text search (name + aliases)
        type       — asset_type filter
        source     — created_by_source filter
        status     — status filter
        label      — label filter (key=value)
        parent     — parent_id filter
        limit      — max results (default 100, max 1000)
        offset     — pagination offset
        aliases    — include aliases (true/false, default true)
        metadata   — include parsed metadata (true/false, default false)

    Returns:
        {
          "assets": [...],
          "total": 25,
          "limit": 100,
          "offset": 0
        }
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        assets, total = search_assets(
            db,
            query=request.args.get("q", ""),
            asset_type=request.args.get("type") or None,
            source=request.args.get("source") or None,
            status=request.args.get("status") or None,
            label=request.args.get("label") or None,
            parent_id=request.args.get("parent") or None,
            limit=min(int(request.args.get("limit", 100)), 1000),
            offset=int(request.args.get("offset", 0)),
        )
        with_aliases = request.args.get("aliases", "true").lower() != "false"
        with_meta = request.args.get("metadata", "false").lower() == "true"
        for a in assets:
            if with_aliases:
                a["aliases"] = get_aliases_for_asset(db, a["asset_id"])
            if with_meta:
                a["meta_parsed"] = _safe_json(a.get("metadata", "{}"))
    finally:
        db.close()
    return jsonify(
        {
            "assets": assets,
            "total": total,
            "limit": min(int(request.args.get("limit", 100)), 1000),
            "offset": int(request.args.get("offset", 0)),
        }
    )


@inventory_bp.route("/api/asset/<asset_id>")
@require_role("viewer")
def api_asset_detail(asset_id: str):
    """Return full asset details as JSON for the CMDB query modal."""
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        asset = get_asset(db, asset_id)
        if not asset:
            return jsonify({"error": "not found"}), 404
        aliases = get_aliases_for_asset(db, asset_id)
        meta = _safe_json(asset.get("metadata", "{}"))
    finally:
        db.close()

    asset["aliases"] = aliases
    asset["meta_parsed"] = meta
    return jsonify(asset)


@inventory_bp.route("/api/export")
@require_role("viewer")
def api_export():
    """Full JSON export of all assets with aliases, relationships, and metadata.

    Query params:
        format — ``json`` (default) or ``csv``
    """
    fmt = request.args.get("format", "json")
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        raw = list_assets(db, limit=5000)
        asset_ids = [a["asset_id"] for a in raw]
        aliases_by_id = _bulk_get_aliases_for_assets(db, asset_ids)
        rels_by_id = _bulk_get_relationships_for_assets(db, asset_ids)
        result = []
        for a in raw:
            entry = {
                "asset_id": a["asset_id"],
                "asset_type": a["asset_type"],
                "display_name": a["display_name"],
                "status": a["status"],
                "source": a["created_by_source"],
                "first_seen_at": a.get("first_seen_at", ""),
                "last_seen_at": a.get("last_seen_at", ""),
                "parent_id": a.get("parent_id"),
                "metadata": _safe_json(a.get("metadata", "{}")),
                "labels": _safe_json(a.get("labels", "{}")),
                "aliases": [
                    {
                        "type": r["alias_type"],
                        "value": r["alias_value"],
                        "source": r["source"],
                        "confidence": r["confidence"],
                    }
                    for r in aliases_by_id.get(a["asset_id"], [])
                ],
                "relationships": [
                    {
                        "source": r["source_asset_id"],
                        "target": r["target_asset_id"],
                        "type": r["relationship"],
                    }
                    for r in rels_by_id.get(a["asset_id"], [])
                ],
            }
            result.append(entry)
    finally:
        db.close()

    if fmt == "csv":
        import csv
        import io

        out = io.StringIO()
        w = csv.writer(out)
        w.writerow(
            [
                "asset_id",
                "asset_type",
                "display_name",
                "status",
                "source",
                "first_seen",
                "last_seen",
                "parent_id",
                "labels",
                "metadata",
            ]
        )
        for a in result:
            w.writerow(
                [
                    a["asset_id"],
                    a["asset_type"],
                    a["display_name"],
                    a["status"],
                    a["source"],
                    a["first_seen_at"],
                    a["last_seen_at"],
                    a["parent_id"],
                    json.dumps(a["labels"]),
                    json.dumps(a["metadata"]),
                ]
            )
        return Response(
            out.getvalue(),
            mimetype="text/csv",
            headers={"Content-Disposition": "attachment; filename=vespid-inventory.csv"},
        )

    return jsonify({"assets": result, "total": len(result)})


def _bulk_get_relationships_for_assets(db, asset_ids: list[str]) -> dict[str, list[dict]]:
    """Return {asset_id: [relationships]} for a list of asset IDs in a single query.

    Includes relationships where the asset is either source or target.
    """
    if not asset_ids:
        return {}
    placeholders = ",".join("?" for _ in asset_ids)
    rows = db.execute(
        f"SELECT * FROM asset_relationships "
        f"WHERE source_asset_id IN ({placeholders}) "
        f"OR target_asset_id IN ({placeholders})",
        [*asset_ids, *asset_ids],
    ).fetchall()
    out: dict[str, list[dict]] = {aid: [] for aid in asset_ids}
    asset_id_set = set(asset_ids)
    for r in rows:
        d = dict(r)
        if r["source_asset_id"] in asset_id_set:
            out[r["source_asset_id"]].append(d)
        if r["target_asset_id"] in asset_id_set:
            out[r["target_asset_id"]].append(d)
    return out


@inventory_bp.route("/api/graph")
@require_role("viewer")
def api_graph():
    """Return the full relationship graph as a nodes+edges payload.

    Query params:
        asset_id — limit to subgraph around this asset (optional)
    """
    asset_id = request.args.get("asset_id")
    limit = min(int(request.args.get("limit", 500)), 5000)
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        if asset_id:
            rels = get_relationships(db, asset_id)
            ids = {asset_id}
            for r in rels:
                ids.add(r["source_asset_id"])
                ids.add(r["target_asset_id"])
            nodes = list_assets_by_ids(db, list(ids))
        else:
            nodes = list_assets(db, limit=limit)
            ids = {a["asset_id"] for a in nodes}
            all_ids = list(ids)
            if all_ids:
                placeholders = ",".join("?" for _ in all_ids)
                rel_rows = db.execute(
                    f"SELECT * FROM asset_relationships "
                    f"WHERE source_asset_id IN ({placeholders}) "
                    f"OR target_asset_id IN ({placeholders})",
                    [*all_ids, *all_ids],
                ).fetchall()
                rels = [dict(r) for r in rel_rows]
            else:
                rels = []

        node_list = []
        for n in nodes:
            node_list.append(
                {
                    "id": n["asset_id"],
                    "label": n["display_name"],
                    "type": n["asset_type"],
                    "source": n["created_by_source"],
                    "status": n["status"],
                }
            )

        edge_list = []
        seen_edges = set()
        for r in rels:
            key = (r["source_asset_id"], r["target_asset_id"], r["relationship"])
            if key not in seen_edges:
                seen_edges.add(key)
                edge_list.append(
                    {
                        "source": r["source_asset_id"],
                        "target": r["target_asset_id"],
                        "relationship": r["relationship"],
                    }
                )
    finally:
        db.close()
    return jsonify({"nodes": node_list, "edges": edge_list, "total_nodes": len(node_list)})


@inventory_bp.route("/api/<asset_id>/relationships")
@require_role("viewer")
def api_relationships(asset_id: str):
    """JSON relationships for a single asset."""
    rel_type = request.args.get("type")
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        rels = get_relationships(db, asset_id, relationship=rel_type)
        # Batch-fetch the related assets' display names (1 query instead of 2N).
        other_ids = set()
        for r in rels:
            other_ids.add(r["source_asset_id"])
            other_ids.add(r["target_asset_id"])
        names = {}
        if other_ids:
            placeholders = ",".join("?" for _ in other_ids)
            rows = db.execute(
                f"SELECT asset_id, display_name FROM assets WHERE asset_id IN ({placeholders})",
                list(other_ids),
            ).fetchall()
            names = {r["asset_id"]: r["display_name"] for r in rows}
        result = []
        for r in rels:
            result.append(
                {
                    "id": r["id"],
                    "source_asset_id": r["source_asset_id"],
                    "source_name": names.get(r["source_asset_id"], r["source_asset_id"]),
                    "target_asset_id": r["target_asset_id"],
                    "target_name": names.get(r["target_asset_id"], r["target_asset_id"]),
                    "relationship": r["relationship"],
                    "metadata": _safe_json(r.get("metadata", "{}")),
                }
            )
    finally:
        db.close()
    return jsonify({"relationships": result})


# ── Helpers ─────────────────────────────────────────────────────────────


def _safe_json(raw: str) -> dict:
    if not raw:
        return {}
    try:
        return json.loads(raw) if isinstance(raw, str) else raw
    except (json.JSONDecodeError, TypeError) as exc:
        logger.warning(
            "Corrupt JSON in DB column (%s) — returning empty dict: %s", type(exc).__name__, exc
        )
        return {}


def _format_uptime(seconds: int) -> str:
    """Convert uptime-seconds to human-readable string."""
    if not seconds or not isinstance(seconds, (int, float)):
        return str(seconds) if seconds is not None else "—"
    s = int(seconds)
    days, s = divmod(s, 86400)
    hours, s = divmod(s, 3600)
    minutes, s = divmod(s, 60)
    parts = []
    if days:
        parts.append(f"{days}d")
    if hours:
        parts.append(f"{hours}h")
    if minutes:
        parts.append(f"{minutes}m")
    if s or not parts:
        parts.append(f"{s}s")
    return " ".join(parts)


def _build_summary(assets: list[dict]) -> dict:
    total = len(assets)
    by_type: dict[str, int] = {}
    by_source: dict[str, int] = {}
    for a in assets:
        t = a.get("asset_type", "unknown") or "unknown"
        by_type[t] = by_type.get(t, 0) + 1
        s = a.get("created_by_source", "unknown") or "unknown"
        by_source[s] = by_source.get(s, 0) + 1
    return {
        "total": total,
        "by_type": by_type,
        "by_source": by_source,
    }


def _build_grouped(assets: list[dict]) -> dict:
    """Group assets by source AND linked agent types for the grouped view.

    Returns a dict mapping section keys (proxmox, monitor, agent, sync, manual)
    to a unique list of asset dicts that belong in that section.
    """
    sections = {
        "agent": {"icon": "🛡️", "label": "Agent"},
        "monitor": {"icon": "📊", "label": "Monitor"},
        "proxmox": {"icon": "🗄️", "label": "Proxmox"},
        "sync": {"icon": "🔗", "label": "Sync"},
        "manual": {"icon": "✏️", "label": "Manual"},
    }
    seen: dict[str, set] = {k: set() for k in sections}
    result: dict[str, list[dict]] = {k: [] for k in sections}

    for a in assets:
        src = a.get("created_by_source", "")
        agent_types = a.get("_agent_types", []) or []
        assigned_sections = set()

        # Always include in its creation source
        if src in sections:
            assigned_sections.add(src)

        # Also include in sections matching linked agent types
        for at in agent_types:
            if at in sections:
                assigned_sections.add(at)

        for sec in assigned_sections:
            aid = a["asset_id"]
            if aid not in seen[sec]:
                seen[sec].add(aid)
                result[sec].append(a)

    return result


def _get_child_assets(db, parent_id: str) -> list[dict]:
    rows = db.execute(
        "SELECT asset_id, asset_type, display_name, last_seen_at, status "
        "FROM assets WHERE parent_id = ? ORDER BY display_name",
        (parent_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def _get_linked_agents(db, asset_id: str) -> list[dict]:
    """Return monitor and security agents linked to this asset."""
    agents = []

    # Monitor agent (from config_agent_status)
    rows = db.execute(
        "SELECT node_id AS agent_id, 'monitor' AS agent_type, "
        "last_check_in, config_status, acknowledged_version, management_mode, agent_version "
        "FROM config_agent_status WHERE asset_id = ?",
        (asset_id,),
    ).fetchall()
    for r in rows:
        agents.append({k: r[k] for k in r.keys()})

    # Security agent (from nodes)
    rows = db.execute(
        "SELECT node_id AS agent_id, 'security' AS agent_type, "
        "last_event_at AS last_check_in, display_name, "
        "total_events, first_seen_at, agent_version "
        "FROM nodes WHERE asset_id = ?",
        (asset_id,),
    ).fetchall()
    for r in rows:
        d = {k: r[k] for k in r.keys()}
        d["config_status"] = "active" if d.get("last_check_in") else "unknown"
        d["management_mode"] = "enrolled"
        agents.append(d)

    return agents
