"""Dashboard blueprint — overview, events, nodes, geo, trends.

Endpoints:
    GET /           — Dashboard overview with stats cards
    GET /events     — Event search/filter page
    GET /nodes      — Node management page
    GET /geo        — Geographic breakdown page
    GET /geo/filter — Filter events by country (HTMX fragment)
    GET /trends     — Trend charts page
    GET /trends/data — JSON chart data for Chart.js

Requirements: 4.1, 4.2, 4.3, 4.4, 5.4, 6.1-6.6, 7.1-7.4,
              8.1-8.3, 9.1-9.3, 14.2, 16.3
"""

import csv
import io
import json
import math
import time
from datetime import UTC, datetime, timedelta

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    make_response,
    redirect,
    render_template,
    request,
    url_for,
)
from flask import (
    Response as FlaskResponse,
)
from flask_login import current_user

from app.config_resolution import resolve_effective_profile
from app.decorators import require_role
from app.models import (
    add_feed_to_catalog,
    add_ip_rule,
    compute_deltas,
    create_assignment,
    create_command,
    delete_node,
    get_api_keys_for_node,
    get_blocked_ips,
    get_counter_history,
    get_country_breakdown,
    get_dashboard_stats,
    get_db,
    get_events_by_country,
    get_feed_by_name,
    get_feed_catalog_categories,
    get_feed_catalog_entry,
    get_ip_rule,
    get_node,
    get_node_health,
    get_recent_events,
    get_time_series,
    list_commands,
    list_config_profiles,
    list_feed_catalog,
    list_ip_rules,
    list_nodes,
    record_audit,
    remove_feed_from_catalog,
    remove_ip_rule,
    search_events,
)
from app.pack_loader import load_packs
from app.routes.fleet_dashboard import _get_fleet_summary_stats, get_recent_fleet_propagations
from app.routes.rules import _get_node_active_parsers, _log_sources_match

dashboard_bp = Blueprint("dashboard", __name__)

import logging  # noqa: E402
import threading  # noqa: E402

logger = logging.getLogger(__name__)

# In-memory cache for nav pill stats.  The first /api/stats request
# populates it, and subsequent requests return the cached value as long
# as it is less than 60 seconds old.  When stale, the next request
# recomputes inline.  This caps DB queries at 1 per 60 seconds regardless
# of how many clients are polling.
_nav_stats_cache: dict = {}
_nav_stats_ts: float = 0.0
_nav_stats_ttl: float = 60.0  # seconds
_nav_stats_lock = threading.Lock()


def _compute_nav_stats(db) -> dict:
    now = datetime.now(UTC)
    cutoff_24h = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    cutoff_15m = (now - timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ")

    return {
        "active_blocks": db.execute(
            "SELECT COUNT(*) FROM fleet_blocks WHERE status = 'active'"
        ).fetchone()[0],
        "active_nodes": db.execute(
            "SELECT COUNT(*) FROM nodes WHERE last_event_at >= ?",
            (cutoff_15m,),
        ).fetchone()[0],
        "total_nodes": db.execute("SELECT COUNT(*) FROM nodes").fetchone()[0],
        "events_24h": db.execute(
            "SELECT COUNT(*) FROM events WHERE timestamp >= ?",
            (cutoff_24h,),
        ).fetchone()[0],
        "countries_24h": db.execute(
            "SELECT COUNT(DISTINCT geo_country) FROM events "
            "WHERE geo_country IS NOT NULL AND geo_country != '' AND timestamp >= ?",
            (cutoff_24h,),
        ).fetchone()[0],
    }


@dashboard_bp.route("/api/stats")
@require_role("viewer")
def nav_stats():
    """Return cached fleet-wide stats for the nav bar pill.

    Stats are computed at most once every 60 seconds regardless of how
    many clients poll.  The first request always computes inline.
    """
    global _nav_stats_ts

    with _nav_stats_lock:
        if _nav_stats_cache and (time.monotonic() - _nav_stats_ts) < _nav_stats_ttl:
            return jsonify(dict(_nav_stats_cache))

    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        stats = _compute_nav_stats(db)
        with _nav_stats_lock:
            _nav_stats_cache.clear()
            _nav_stats_cache.update(stats)
            _nav_stats_ts = time.monotonic()
    finally:
        db.close()

    return jsonify(stats)


def _get_cached_stats():
    """Return the cached stats dict, computing inline if cache is cold."""
    global _nav_stats_ts

    with _nav_stats_lock:
        if _nav_stats_cache and (time.monotonic() - _nav_stats_ts) < _nav_stats_ttl:
            return dict(_nav_stats_cache)

    # Cache miss — compute inline
    from flask import current_app

    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        stats = _compute_nav_stats(db)
        with _nav_stats_lock:
            _nav_stats_cache.clear()
            _nav_stats_cache.update(stats)
            _nav_stats_ts = time.monotonic()
        return dict(stats)
    finally:
        db.close()


@dashboard_bp.route("/")
@require_role("viewer")
def index():
    """Dashboard overview page.

    Full page load renders dashboard.html with stats cards, event type
    breakdown, and recent events. HTMX requests (detected via HX-Request
    header) return only the stats_cards.html fragment for auto-refresh.

    Requirements: 4.1, 4.2, 4.3, 4.4, 14.2
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        stats = get_dashboard_stats(db)
        recent = get_recent_events(db, limit=20)
        try:
            fleet_stats = _get_fleet_summary_stats(db)
        except Exception:
            logger.exception("Failed to compute fleet summary stats")
            fleet_stats = None
        try:
            fleet_propagations = get_recent_fleet_propagations(db, limit=5)
        except Exception:
            logger.exception("Failed to fetch recent fleet propagations")
            fleet_propagations = None
    finally:
        db.close()

    # HTMX partial update — return only the stats cards fragment
    if request.headers.get("HX-Request"):
        now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
        since_24h = (datetime.now(UTC) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M")
        return render_template(
            "fragments/stats_cards.html",
            stats=stats,
            now=now,
            since_24h=since_24h,
            fleet_stats=fleet_stats,
        )

    now = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
    since_24h = (datetime.now(UTC) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M")
    resp = make_response(
        render_template(
            "dashboard.html",
            stats=stats,
            events=recent,
            now=now,
            since_24h=since_24h,
            fleet_stats=fleet_stats,
            fleet_propagations=fleet_propagations,
        )
    )
    resp.headers["Cache-Control"] = "no-store, must-revalidate"
    return resp


@dashboard_bp.route("/events")
@require_role("viewer")
def events():
    """Event search page.

    Full page load renders events.html with search form and default/empty
    results. HTMX requests return the search_results.html fragment with
    paginated results from search_events().

    Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6, 5.4, 14.2
    """
    # Collect filter parameters
    filters = {}
    for key in (
        "source_ip",
        "node",
        "node_id",
        "node_name",
        "event_type",
        "geo_country",
        "start_time",
        "end_time",
        "q",
    ):
        value = request.args.get(key, "").strip()
        if value:
            filters[key] = value

    # Normalize start/end time to match stored format (YYYY-MM-DDTHH:MM:SSZ)
    # Keep raw values for form display
    start_raw_display = filters.get("start_time", "")
    end_raw_display = filters.get("end_time", "")
    start_raw = start_raw_display
    if start_raw and ":" in start_raw and start_raw.count(":") < 2:
        filters["start_time"] = start_raw + ":00Z"
    elif start_raw and not start_raw.endswith("Z"):
        filters["start_time"] = start_raw + "Z"
    end_raw = end_raw_display
    if end_raw and ":" in end_raw and end_raw.count(":") < 2:
        filters["end_time"] = end_raw + ":59:59Z"
    elif end_raw and not end_raw.endswith("Z"):
        if ":" in end_raw and end_raw.count(":") >= 2:
            filters["end_time"] = end_raw + "Z"

    exclude_nft = True
    raw_event_type = request.args.get("event_type", "").strip()
    if raw_event_type == "__all__":
        exclude_nft = False
        filters.pop("event_type", None)
    elif raw_event_type:
        exclude_nft = False

    page = request.args.get("page", 1, type=int)
    if page < 1:
        page = 1
    per_page = request.args.get("per_page", current_app.config.get("EVENTS_PER_PAGE", 50), type=int)
    sort_by = request.args.get("sort_by", "timestamp").strip()
    sort_order = request.args.get("sort_order", "DESC").strip().upper()
    export = request.args.get("export", "").strip().lower()

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        event_list, total = search_events(
            db,
            filters,
            page=page,
            per_page=per_page,
            exclude_nft_action=exclude_nft,
            sort_by=sort_by,
            sort_order=sort_order,
        )

        # Summary stats
        unique_ips = len(set(e.get("source_ip", "") for e in event_list if e.get("source_ip")))
        unique_types = len(set(e.get("event_type", "") for e in event_list if e.get("event_type")))

        event_types = [
            row[0]
            for row in db.execute(
                "SELECT DISTINCT event_type FROM events ORDER BY event_type"
            ).fetchall()
        ]
    finally:
        db.close()

    # CSV export
    if export == "csv":
        return _export_events_csv(event_list)

    total_pages = max(1, math.ceil(total / per_page))

    # JSON response for API/CLI clients
    accept = request.headers.get("Accept", "")
    auth = request.headers.get("Authorization", "")
    if "application/json" in accept or auth.startswith("Bearer "):
        return jsonify(
            {"events": event_list, "total": total, "page": page, "total_pages": total_pages}
        )

    ctx = dict(
        events=event_list,
        total=total,
        page=page,
        total_pages=total_pages,
        filters=filters,
        sort_by=sort_by,
        sort_order=sort_order,
        per_page=per_page,
        unique_ips=unique_ips,
        unique_types=unique_types,
        start_raw_display=start_raw_display,
        end_raw_display=end_raw_display,
    )

    # HTMX request — return search results fragment only
    if request.headers.get("HX-Request"):
        return render_template("fragments/search_results.html", **ctx)

    return render_template(
        "events.html",
        event_types=event_types,
        selected_event_type=raw_event_type,
        **ctx,
    )


@dashboard_bp.route("/blocked")
@require_role("viewer")
def blocked_ips():
    """Blocked IPs page.

    Shows two views:
    - "Active Now" (default): Live blocks from all nodes' last heartbeat data.
      This shows what's actually blocked right now on the agents.
    - "History": Historical block events from the events table, filtered by time range.
    """
    view = request.args.get("view", "active").strip()

    filters = {}
    for key in ("source_ip", "node_id", "event_type", "geo_country", "time_range"):
        value = request.args.get(key, "").strip()
        if value:
            filters[key] = value

    page = request.args.get("page", 1, type=int)
    if page < 1:
        page = 1
    per_page = current_app.config.get("EVENTS_PER_PAGE", 50)

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        if view == "active":
            # Live blocks from node_blocks table
            blocked_list, total = _get_active_blocks(db, filters, page=page, per_page=per_page)
        else:
            # Historical view from events table
            if "time_range" not in filters:
                filters["time_range"] = "24h"
            blocked_list, total = get_blocked_ips(db, filters, page=page, per_page=per_page)
    finally:
        db.close()

    total_pages = max(1, math.ceil(total / per_page))

    if request.headers.get("HX-Request"):
        return render_template(
            "fragments/blocked_results.html",
            blocked=blocked_list,
            total=total,
            page=page,
            total_pages=total_pages,
            filters=filters,
            view=view,
        )

    return render_template(
        "blocked.html",
        blocked=blocked_list,
        total=total,
        page=page,
        total_pages=total_pages,
        filters=filters,
        view=view,
    )


def _export_events_csv(events: list[dict]) -> FlaskResponse:
    """Return filtered events as a CSV download."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "Timestamp",
            "Node ID",
            "Source IP",
            "Event Type",
            "Action",
            "Country",
            "ASN",
            "Org",
            "Event ID",
        ]
    )
    for e in events:
        writer.writerow(
            [
                e.get("timestamp", ""),
                e.get("node_id", ""),
                e.get("source_ip", ""),
                e.get("event_type", ""),
                e.get("action_taken", ""),
                e.get("geo_country", ""),
                e.get("geo_asn", ""),
                e.get("geo_org", ""),
                e.get("event_id", ""),
            ]
        )
    output.seek(0)
    return FlaskResponse(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=events.csv"},
    )


def _get_active_blocks(
    db, filters: dict, page: int = 1, per_page: int = 50
) -> tuple[list[dict], int]:
    """Get currently active blocks from node_blocks table.

    Aggregates block entries across all nodes, deduplicates by IP (showing
    the most recent block if the same IP is blocked on multiple nodes),
    and applies optional filters.

    Returns (list_of_block_dicts, total_count).
    """

    def _normalize_ts(value) -> str:
        """Convert a timestamp value to ISO-8601 string."""
        if value is None or value == "":
            return ""
        if isinstance(value, (int, float)):
            try:
                return datetime.fromtimestamp(value, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            except (OSError, ValueError, OverflowError):
                return str(value)
        if isinstance(value, str):
            try:
                epoch = float(value)
                return datetime.fromtimestamp(epoch, tz=UTC).strftime("%Y-%m-%dT%H:%M:%SZ")
            except (ValueError, OSError, OverflowError):
                pass
        return str(value)

    # Build query conditions
    conditions = ["1=1"]
    params: list = []
    if filters.get("source_ip"):
        conditions.append("nb.ip LIKE ?")
        params.append(f"%{filters['source_ip']}%")
    if filters.get("node_id"):
        conditions.append("(nb.node_id LIKE ? OR n.display_name LIKE ?)")
        params.append(f"%{filters['node_id']}%")
        params.append(f"%{filters['node_id']}%")
    if filters.get("event_type"):
        conditions.append("LOWER(nb.reason) LIKE ?")
        params.append(f"%{filters['event_type'].lower()}%")

    where = " AND ".join(conditions)

    # Count total
    count_row = db.execute(
        f"SELECT COUNT(DISTINCT nb.ip) as cnt FROM node_blocks nb "
        f"LEFT JOIN nodes n ON n.node_id = nb.node_id "
        f"WHERE {where}",
        params,
    ).fetchone()
    total = count_row["cnt"] if count_row else 0

    # Fetch aggregated blocks grouped by IP
    rows = db.execute(
        f"SELECT nb.ip, nb.reason, nb.blocked_at, nb.expires_at, nb.strike, "
        f"nb.node_id, n.display_name "
        f"FROM node_blocks nb "
        f"LEFT JOIN nodes n ON n.node_id = nb.node_id "
        f"WHERE {where} "
        f"ORDER BY nb.blocked_at DESC",
        params,
    ).fetchall()

    now_ts = datetime.now(UTC).timestamp()

    # Aggregate by IP
    all_blocks: dict[str, dict] = {}
    for row in rows:
        ip = row["ip"]
        node_id = row["node_id"]
        ts_raw = row["blocked_at"] or 0
        blocked_at = _normalize_ts(ts_raw)
        expires = row["expires_at"] or 0
        ttl_remaining = max(0, int(expires - now_ts)) if expires else 0
        strike = row["strike"] or 1

        if ip in all_blocks:
            existing = all_blocks[ip]
            if node_id not in existing["nodes"]:
                existing["nodes"].append(node_id)
            if blocked_at > existing.get("last_blocked", ""):
                existing["last_blocked"] = blocked_at
                existing["reason"] = row["reason"] or ""
                existing["strike"] = strike
                existing["ttl_remaining"] = ttl_remaining
        else:
            all_blocks[ip] = {
                "source_ip": ip,
                "reason": row["reason"] or "",
                "blocked_at": blocked_at,
                "last_blocked": blocked_at,
                "first_blocked": blocked_at,
                "ttl_remaining": ttl_remaining,
                "strike": strike,
                "nodes": [node_id],
                "event_types": [row["reason"] or "unknown"],
                "countries": [],
                "block_count": strike,
            }

    sorted_blocks = sorted(
        all_blocks.values(),
        key=lambda b: b.get("last_blocked", ""),
        reverse=True,
    )
    start = (page - 1) * per_page
    paginated = sorted_blocks[start : start + per_page]
    return paginated, total


@dashboard_bp.route("/nodes")
@require_role("viewer")
def nodes():
    """Node management page.

    Queries list_nodes(), computes health status for each node, and
    renders nodes.html with a node table including a disabled
    "Send Command" button placeholder.

    Requirements: 7.1, 7.2, 7.3, 7.4, 16.3
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        node_list = list_nodes(db)
        # Fetch available profiles for the assignment dropdown
        profiles_result = list_config_profiles(db, page=1, per_page=200)
        profiles = profiles_result["profiles"]
        # Resolve effective profile for each node
        node_profiles = {}
        for node in node_list:
            nid = node.get("node_id", "")
            effective = resolve_effective_profile(db, nid)
            if effective:
                node_profiles[nid] = effective

        # Fetch agent versions from config_agent_status
        node_versions = {}
        if node_list:
            node_ids = [n["node_id"] for n in node_list if n.get("node_id")]
            if node_ids:
                placeholders = ",".join(["?"] * len(node_ids))
                cas_rows = db.execute(
                    f"SELECT node_id, agent_version FROM config_agent_status WHERE node_id IN ({placeholders})",
                    node_ids,
                ).fetchall()
                for row in cas_rows:
                    if row["agent_version"]:
                        node_versions[row["node_id"]] = row["agent_version"]
    finally:
        db.close()

    healthy_seconds = current_app.config.get("NODE_HEALTHY_SECONDS", 300)
    degraded_seconds = current_app.config.get("NODE_DEGRADED_SECONDS", 900)

    # Enrich each node with computed health and location
    enriched_nodes = []
    for node in node_list:
        health = get_node_health(
            node.get("last_event_at"),
            healthy_seconds=healthy_seconds,
            degraded_seconds=degraded_seconds,
        )
        # Parse last_geo_data for location display
        location = None
        geo_raw = node.get("last_geo_data", "{}")
        try:
            geo = json.loads(geo_raw) if isinstance(geo_raw, str) else geo_raw
            parts = []
            if geo.get("city"):
                parts.append(geo["city"])
            if geo.get("country"):
                parts.append(geo["country"])
            if parts:
                location = ", ".join(parts)
        except (json.JSONDecodeError, TypeError):
            pass

        # Parse last_host_info for OS display
        os_name = None
        host_info_raw = node.get("last_host_info", "{}")
        try:
            host_info = (
                json.loads(host_info_raw) if isinstance(host_info_raw, str) else host_info_raw
            )
            os_name = host_info.get("os") or None
        except (json.JSONDecodeError, TypeError):
            pass

        node_display_name = node.get("display_name", "") or ""
        enriched_nodes.append(
            {
                **node,
                "health": health,
                "location": location,
                "os_name": os_name,
                "node_display": node_display_name,
                "agent_version": node_versions.get(node.get("node_id", ""), ""),
            }
        )

    # JSON response for API/CLI clients
    accept = request.headers.get("Accept", "")
    auth = request.headers.get("Authorization", "")
    if "application/json" in accept or auth.startswith("Bearer "):
        return jsonify({"nodes": enriched_nodes})

    return render_template(
        "nodes.html", nodes=enriched_nodes, profiles=profiles, node_profiles=node_profiles
    )


@dashboard_bp.route("/nodes/<node_id>/assign-profile", methods=["POST"])
@require_role("admin")
def node_assign_profile(node_id):
    """Assign or change a config profile for a node directly from the nodes page."""
    profile_id = request.form.get("profile_id", type=int)

    if not profile_id:
        flash("Please select a profile.", "error")
        return redirect(url_for("dashboard.nodes"))

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        assignment = create_assignment(
            db,
            profile_id=profile_id,
            node_id=node_id,
            assigned_by=current_user.username,
        )
        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="config_assignment_create",
            target=node_id,
            details={
                "profile_id": profile_id,
                "assignment_id": assignment["id"],
                "source": "nodes_page",
            },
        )
    except Exception as e:
        logger.exception("Failed to assign profile %s to node %s", profile_id, node_id)
        flash(f"Failed to assign profile: {e}", "error")
        return redirect(url_for("dashboard.nodes"))
    finally:
        db.close()

    flash(f"Profile assigned to {node_id}.", "success")
    return redirect(url_for("dashboard.nodes"))


@dashboard_bp.route("/nodes/<node_id>/rename", methods=["POST"])
@require_role("admin")
def node_rename(node_id):
    """Update a node's display name."""
    display_name = request.form.get("display_name", "").strip()
    if not display_name:
        flash("Display name cannot be empty.", "error")
        return redirect(url_for("dashboard.node_detail", node_id=node_id))

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        node = get_node(db, node_id)
        if node is None:
            flash(f"Node '{node_id}' not found.", "error")
            return redirect(url_for("dashboard.nodes"))

        db.execute("UPDATE nodes SET display_name = ? WHERE node_id = ?", (display_name, node_id))
        db.commit()

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="node_rename",
            target=node_id,
            details={"old_name": node.get("display_name", ""), "new_name": display_name},
        )
    finally:
        db.close()

    flash(f"Node renamed to '{display_name}'.", "success")
    return redirect(url_for("dashboard.node_detail", node_id=node_id))


@dashboard_bp.route("/nodes/<node_id>/delete", methods=["POST"])
@require_role("admin")
def node_delete(node_id):
    """Delete a node from the registry.

    Permanently removes the node record from the database. The node will
    be re-registered automatically if it sends another heartbeat or event.
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        deleted = delete_node(db, node_id)
        if not deleted:
            flash(f"Node '{node_id}' not found.", "error")
            return redirect(url_for("dashboard.nodes"))

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="node_delete",
            target=node_id,
            details={},
        )
    finally:
        db.close()

    flash(f"Node '{node_id}' has been deleted.", "success")
    return redirect(url_for("dashboard.nodes"))


@dashboard_bp.route("/nodes/<node_id>")
@require_role("viewer")
def node_detail(node_id):
    """Per-node detail page showing active blocks and allowlist.

    Displays the node's last-reported block list and allowlist (sent
    with each heartbeat), along with quick-action buttons to unblock
    IPs or add allowlist entries targeted at this specific node.
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        node = get_node(db, node_id)
        if node is None:
            flash(f"Node '{node_id}' not found.", "error")
            return redirect(url_for("dashboard.nodes"))

        # Fetch agent version from config_agent_status
        cas_row = db.execute(
            "SELECT agent_version FROM config_agent_status WHERE node_id = ?",
            (node_id,),
        ).fetchone()
        node["agent_version"] = (
            cas_row["agent_version"] if cas_row and cas_row["agent_version"] else ""
        )

        recent_cmds = list_commands(db, node_id=node_id, limit=20)

        # Check if this node participates in Fleet
        # A node is "in fleet" if:
        # 1. It reported fleet_enabled in its last heartbeat host_info, OR
        # 2. It has submitted block reports, OR
        # 3. It has a config profile with fleet enabled.
        in_fleet = False

        # Check host_info from last heartbeat
        raw_hi = node.get("last_host_info", "{}")
        try:
            hi = json.loads(raw_hi) if isinstance(raw_hi, str) else raw_hi
            if hi.get("fleet_enabled"):
                in_fleet = True
        except (json.JSONDecodeError, TypeError):
            pass

        if not in_fleet:
            fleet_report_count = db.execute(
                "SELECT COUNT(*) as cnt FROM fleet_block_reports WHERE node_id = ?",
                (node_id,),
            ).fetchone()["cnt"]
            in_fleet = fleet_report_count > 0

        if not in_fleet:
            profile = resolve_effective_profile(db, node_id)
            if profile is not None:
                settings = profile.get("settings", "{}")
                if isinstance(settings, str):
                    try:
                        settings = json.loads(settings)
                    except (json.JSONDecodeError, TypeError):
                        settings = {}
                in_fleet = settings.get("fleet_blocklist_report_enabled", False) or settings.get(
                    "fleet_blocklist_subscribe_enabled", False
                )

        # ── Detection Packs: compute which packs are relevant to this node ──
        active_parsers, pack_mode = _get_node_active_parsers(db, node_id)

        # Build node_packs list with metadata + assignment info
        node_packs = []
        if active_parsers is not None:
            all_packs = load_packs()

            if pack_mode == "explicit":
                # active_parsers holds pack names in explicit mode
                explicit_packs = active_parsers
                for pack in all_packs:
                    if pack["pack_name"] in explicit_packs:
                        # Count enabled rules for this pack from DB
                        row = db.execute(
                            "SELECT COUNT(*) as cnt FROM detection_rules_custom "
                            "WHERE is_template = 1 AND pack_name = ? AND enabled = 1",
                            (pack["pack_name"],),
                        ).fetchone()
                        enabled_count = row["cnt"] if row else 0
                        node_packs.append(
                            {
                                "pack_name": pack["pack_name"],
                                "display_name": pack["display_name"],
                                "icon": pack["icon"],
                                "description": pack["description"],
                                "enabled_count": enabled_count,
                                "assignment_type": "explicit",
                            }
                        )
                # In explicit mode, resolve actual parsers for display
                # (from profile log_sources or heartbeat)
                display_parsers = []
                profile = resolve_effective_profile(db, node_id)
                if profile:
                    p_settings = (
                        json.loads(profile["settings"])
                        if isinstance(profile["settings"], str)
                        else profile["settings"]
                    )
                    log_sources = p_settings.get("log_sources", [])
                    if log_sources:
                        display_parsers = list(
                            set(ls.get("parser", "") for ls in log_sources if ls.get("parser"))
                        )
                if not display_parsers:
                    node_row = db.execute(
                        "SELECT last_host_info FROM nodes WHERE node_id = ?", (node_id,)
                    ).fetchone()
                    if node_row:
                        hi = (
                            json.loads(node_row["last_host_info"])
                            if isinstance(node_row["last_host_info"], str)
                            else node_row["last_host_info"]
                        )
                        display_parsers = hi.get("active_parsers", [])
                active_parsers_display = display_parsers
            else:
                # Auto mode: match packs by log_sources overlap
                for pack in all_packs:
                    # Determine pack's log_sources from its rules
                    pack_log_sources = set()
                    for rule in pack.get("rules", []):
                        ls = rule.get("log_sources", '["*"]')
                        if isinstance(ls, str):
                            try:
                                ls = json.loads(ls)
                            except (json.JSONDecodeError, TypeError):
                                ls = ["*"]
                        for s in ls:
                            pack_log_sources.add(s)

                    if _log_sources_match(list(pack_log_sources), active_parsers):
                        row = db.execute(
                            "SELECT COUNT(*) as cnt FROM detection_rules_custom "
                            "WHERE is_template = 1 AND pack_name = ? AND enabled = 1",
                            (pack["pack_name"],),
                        ).fetchone()
                        enabled_count = row["cnt"] if row else 0
                        node_packs.append(
                            {
                                "pack_name": pack["pack_name"],
                                "display_name": pack["display_name"],
                                "icon": pack["icon"],
                                "description": pack["description"],
                                "enabled_count": enabled_count,
                                "assignment_type": "auto",
                            }
                        )
                active_parsers_display = active_parsers
        else:
            # "all" mode — all packs are relevant (legacy node)
            all_packs = load_packs()
            for pack in all_packs:
                row = db.execute(
                    "SELECT COUNT(*) as cnt FROM detection_rules_custom "
                    "WHERE is_template = 1 AND pack_name = ? AND enabled = 1",
                    (pack["pack_name"],),
                ).fetchone()
                enabled_count = row["cnt"] if row else 0
                node_packs.append(
                    {
                        "pack_name": pack["pack_name"],
                        "display_name": pack["display_name"],
                        "icon": pack["icon"],
                        "description": pack["description"],
                        "enabled_count": enabled_count,
                        "assignment_type": "all",
                    }
                )
            active_parsers_display = None

        # Query block list from node_blocks table (pushed by daemon on change)
        # Joins ip_intel for total block count across all nodes
        block_list = []
        try:
            rows = db.execute(
                """SELECT nb.*, COALESCE(ii.total_times_blocked, 0) as total_blocks
                   FROM node_blocks nb
                   LEFT JOIN ip_intel ii ON nb.ip = ii.ip_address
                   WHERE nb.node_id = ? ORDER BY nb.expires_at""",
                (node_id,),
            ).fetchall()
            now_ts = datetime.now(UTC).timestamp()
            for row in rows:
                entry = dict(row)
                expires = entry.get("expires_at", 0)
                if expires:
                    entry["ttl_remaining"] = max(0, int(expires - now_ts))
                else:
                    entry["ttl_remaining"] = 0
                block_list.append(entry)
        except Exception:
            pass
    finally:
        db.close()

    healthy_seconds = current_app.config.get("NODE_HEALTHY_SECONDS", 300)
    degraded_seconds = current_app.config.get("NODE_DEGRADED_SECONDS", 900)
    health = get_node_health(
        node.get("last_event_at"),
        healthy_seconds=healthy_seconds,
        degraded_seconds=degraded_seconds,
    )

    # Parse location
    location = None
    geo_raw = node.get("last_geo_data", "{}")
    try:
        geo = json.loads(geo_raw) if isinstance(geo_raw, str) else geo_raw
        parts = []
        if geo.get("city"):
            parts.append(geo["city"])
        if geo.get("country"):
            parts.append(geo["country"])
        if parts:
            location = ", ".join(parts)
    except (json.JSONDecodeError, TypeError):
        pass

    allowlist = []
    raw_wl = node.get("last_allowlist", "[]")
    try:
        allowlist = json.loads(raw_wl) if isinstance(raw_wl, str) else raw_wl
    except (json.JSONDecodeError, TypeError):
        pass

    # Parse feed status (sorted alphabetically by name)
    feeds = []
    raw_feeds = node.get("last_feeds", "[]")
    try:
        feeds = json.loads(raw_feeds) if isinstance(raw_feeds, str) else raw_feeds
    except (json.JSONDecodeError, TypeError):
        pass
    feeds.sort(key=lambda f: f.get("name", "").lower())

    # Parse command payloads
    for cmd in recent_cmds:
        raw = cmd.get("payload", "{}")
        if isinstance(raw, str):
            try:
                cmd["payload"] = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                cmd["payload"] = {}

    # Parse host info from the node's last heartbeat
    host_info = {}
    raw_hi = node.get("last_host_info", "{}")
    try:
        host_info = json.loads(raw_hi) if isinstance(raw_hi, str) else raw_hi
    except (json.JSONDecodeError, TypeError):
        pass

    # Fetch API keys associated with this node (admin only)
    node_api_keys = []
    if current_user.role == "admin":
        db = get_db(db_path)
        try:
            node_api_keys = get_api_keys_for_node(db, node_id)
        finally:
            db.close()

    # JSON response for API/CLI clients
    accept = request.headers.get("Accept", "")
    auth = request.headers.get("Authorization", "")
    if "application/json" in accept or auth.startswith("Bearer "):
        return jsonify(
            {
                "node": {**node, "health": health, "location": location},
                "block_list": block_list,
                "allowlist": allowlist,
                "feeds": feeds,
                "host_info": host_info,
                "in_fleet": in_fleet,
            }
        )

    return render_template(
        "node_detail.html",
        node=node,
        health=health,
        location=location,
        block_list=block_list,
        allowlist=allowlist,
        feeds=feeds,
        host_info=host_info,
        recent_commands=recent_cmds,
        in_fleet=in_fleet,
        node_packs=node_packs,
        active_parsers=active_parsers_display,
        pack_mode=pack_mode,
        node_api_keys=node_api_keys,
        agent_version=node.get("agent_version", ""),
    )


@dashboard_bp.route("/nodes/<node_id>/unblock", methods=["POST"])
@require_role("analyst")
def node_unblock(node_id):
    """Unblock a specific IP on a specific node."""
    ip = request.form.get("ip", "").strip()
    if not ip:
        flash("IP address is required.", "error")
        return redirect(url_for("dashboard.node_detail", node_id=node_id))

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        create_command(db, node_id, "unblock", {"ip": ip, "reason": "dashboard_node_unblock"})
        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="unblock",
            target=ip,
            details={"node_id": node_id, "source": "node_detail"},
        )
    finally:
        db.close()

    flash(f"Unblock command for {ip} queued for {node_id}.", "success")
    return redirect(url_for("dashboard.node_detail", node_id=node_id))


@dashboard_bp.route("/nodes/<node_id>/allowlist", methods=["POST"])
@require_role("analyst")
def node_allowlist_add(node_id):
    """Add an allowlist entry on a specific node."""
    entry = request.form.get("entry", "").strip()
    reason = request.form.get("reason", "").strip()
    if not entry:
        flash("IP address or CIDR is required.", "error")
        return redirect(url_for("dashboard.node_detail", node_id=node_id))

    if not _validate_ip_or_cidr(entry):
        flash(f"Invalid IP address or CIDR notation: {entry}", "error")
        return redirect(url_for("dashboard.node_detail", node_id=node_id))

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        create_command(db, node_id, "allowlist_add", {"entry": entry})
        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="unblock",
            target=entry,
            details={"action": "allowlist_add", "node_id": node_id, "reason": reason},
        )
    finally:
        db.close()

    flash(f"Allowlist command for {entry} queued for {node_id}.", "success")
    return redirect(url_for("dashboard.node_detail", node_id=node_id))


@dashboard_bp.route("/nodes/<node_id>/feed/<feed_name>/toggle", methods=["POST"])
@require_role("analyst")
def node_feed_toggle(node_id, feed_name):
    """Enable or disable a subscription feed on a specific node."""
    action = request.form.get("action", "").strip()
    if action not in ("enable", "disable"):
        flash("Invalid action.", "error")
        return redirect(url_for("dashboard.node_detail", node_id=node_id))

    command_type = f"feed_{action}"

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        create_command(db, node_id, command_type, {"name": feed_name})
        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="block" if action == "enable" else "unblock",
            target=feed_name,
            details={"action": command_type, "node_id": node_id, "feed": feed_name},
        )
    finally:
        db.close()

    label = "enabled" if action == "enable" else "disabled"
    flash(f"Feed '{feed_name}' {label} command queued for {node_id}.", "success")
    return redirect(url_for("dashboard.node_detail", node_id=node_id))


@dashboard_bp.route("/geo")
@require_role("viewer")
def geo():
    """Geographic breakdown page.

    Queries get_country_breakdown() and renders geo.html with a country
    table. Each country row has a click-to-filter button that loads
    events via HTMX.

    Query params:
        range: Time range — "1d", "3d", "5d", or "all" (default: "all").
               When set, only events within the last N days are included.

    Requirements: 8.1, 8.2, 8.3
    """
    range_param = request.args.get("range", "1d").strip()
    hours: int | None = _parse_geo_range(range_param)

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        countries = get_country_breakdown(db, hours=hours)
    finally:
        db.close()

    return render_template("geo.html", countries=countries, range=range_param)


def _parse_geo_range(range_str: str) -> int | None:
    """Parse a geo range string into hours.  Returns None for 'all'."""
    mapping = {"1d": 24, "3d": 72, "5d": 120}
    return mapping.get(range_str.strip().lower())


@dashboard_bp.route("/geo/filter")
@require_role("viewer")
def geo_filter():
    """Filter events by selected country (HTMX fragment).

    Returns an HTML table of events for the specified country.

    Query params:
        country: Geo country code to filter by (e.g. "CN").
        range: Time range — "1d", "3d", "5d", or "all" (default: "all").

    Requirements: 8.3
    """
    country = request.args.get("country", "").strip()
    if not country:
        return "<p>No country specified.</p>"

    range_param = request.args.get("range", "1d").strip()
    hours: int | None = _parse_geo_range(range_param)

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        event_list = get_events_by_country(db, country, hours=hours)
    finally:
        db.close()

    if not event_list:
        return f"<p>No events found for country: {country}</p>"

    return render_template("fragments/event_feed.html", events=event_list)


@dashboard_bp.route("/trends")
@require_role("viewer")
def trends():
    """Trend charts page.

    Renders trends.html with Chart.js canvas elements and an interval
    selector. Chart data is loaded via JavaScript from /trends/data.

    Requirements: 9.1, 9.2, 9.3
    """
    return render_template("trends.html")


@dashboard_bp.route("/trends/data")
@require_role("viewer")
def trends_data():
    """Return JSON chart data for Chart.js consumption.

    Query params:
        interval: 1h, 6h, 24h, 7d, 30d (default 7d)
        group_by: event_type, node_id, source_ip (optional)

    Requirements: 9.1, 9.2, 9.3
    """
    interval = request.args.get("interval", "7d")
    group_by = request.args.get("group_by", None)
    if group_by == "":
        group_by = None

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        series = get_time_series(db, interval, group_by=group_by)
    except ValueError as exc:
        logger.error("Invalid time series request: %s", exc)
        return jsonify({"error": "Invalid time series parameters"}), 400
    finally:
        db.close()

    if group_by is None:
        # Simple ungrouped data
        labels = [entry["bucket"] for entry in series]
        counts = [entry["count"] for entry in series]
        return jsonify({"labels": labels, "counts": counts})
    else:
        # Grouped data — build datasets per group value
        # Collect all unique buckets and groups
        all_buckets = sorted(set(entry["bucket"] for entry in series))
        groups = {}
        for entry in series:
            grp = entry.get("group", "unknown")
            if grp not in groups:
                groups[grp] = {}
            groups[grp][entry["bucket"]] = entry["count"]

        # Build Chart.js datasets
        colors = [
            "rgb(37, 99, 235)",
            "rgb(220, 38, 38)",
            "rgb(22, 163, 74)",
            "rgb(234, 179, 8)",
            "rgb(147, 51, 234)",
            "rgb(236, 72, 153)",
            "rgb(20, 184, 166)",
            "rgb(249, 115, 22)",
        ]
        datasets = []
        for i, (grp_name, bucket_map) in enumerate(groups.items()):
            color = colors[i % len(colors)]
            datasets.append(
                {
                    "label": grp_name,
                    "data": [bucket_map.get(b, 0) for b in all_buckets],
                    "borderColor": color,
                    "backgroundColor": color.replace("rgb", "rgba").replace(")", ", 0.1)"),
                    "fill": False,
                }
            )

        return jsonify(
            {
                "labels": all_buckets,
                "datasets": datasets,
            }
        )


@dashboard_bp.route("/trends/analytics")
@require_role("viewer")
def trends_analytics():
    """Return rich analytics data for the enhanced trends page.

    Query params:
        interval: 1h, 6h, 24h, 7d, 30d (default 7d)

    Returns JSON with:
        - summary: total events, unique IPs, unique nodes, top event type
        - action_breakdown: counts per action_taken value
        - top_sources: top 10 source IPs by event count
        - geo_breakdown: top 10 countries by event count
        - event_type_breakdown: counts per event_type
        - fleet_blocks_over_time: fleet block creation bucketed over time
    """
    interval = request.args.get("interval", "7d")
    config = {"1h": 1, "6h": 6, "24h": 24, "7d": 168, "30d": 720}
    hours = config.get(interval, 168)

    from datetime import timedelta

    start_time = (datetime.now(UTC) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        # Summary stats
        row = db.execute(
            "SELECT COUNT(*) as total, "
            "COUNT(DISTINCT source_ip) as unique_ips, "
            "COUNT(DISTINCT node_id) as unique_nodes "
            "FROM events WHERE timestamp >= ?",
            (start_time,),
        ).fetchone()
        summary = {
            "total_events": row["total"],
            "unique_ips": row["unique_ips"],
            "unique_nodes": row["unique_nodes"],
        }

        # Top event type
        top_type_row = db.execute(
            "SELECT event_type, COUNT(*) as cnt "
            "FROM events WHERE timestamp >= ? "
            "GROUP BY event_type ORDER BY cnt DESC LIMIT 1",
            (start_time,),
        ).fetchone()
        summary["top_event_type"] = top_type_row["event_type"] if top_type_row else "—"
        summary["top_event_type_count"] = top_type_row["cnt"] if top_type_row else 0

        # Action breakdown (BLOCKED vs OBSERVED etc.)
        action_rows = db.execute(
            "SELECT action_taken, COUNT(*) as cnt "
            "FROM events WHERE timestamp >= ? "
            "GROUP BY action_taken ORDER BY cnt DESC",
            (start_time,),
        ).fetchall()
        action_breakdown = {r["action_taken"]: r["cnt"] for r in action_rows}

        # Top 10 source IPs
        top_sources = db.execute(
            "SELECT source_ip, COUNT(*) as cnt, "
            "MAX(geo_country) as country "
            "FROM events WHERE timestamp >= ? "
            "GROUP BY source_ip ORDER BY cnt DESC LIMIT 10",
            (start_time,),
        ).fetchall()
        top_sources_list = [
            {
                "ip": r["source_ip"],
                "count": r["cnt"],
                "country": r["country"] or "—",
            }
            for r in top_sources
        ]

        # Geo breakdown (top 10 countries)
        geo_rows = db.execute(
            "SELECT geo_country, COUNT(*) as cnt "
            "FROM events WHERE timestamp >= ? AND geo_country IS NOT NULL "
            "AND geo_country != '' "
            "GROUP BY geo_country ORDER BY cnt DESC LIMIT 10",
            (start_time,),
        ).fetchall()
        geo_breakdown = {r["geo_country"]: r["cnt"] for r in geo_rows}

        # Event type breakdown
        type_rows = db.execute(
            "SELECT event_type, COUNT(*) as cnt "
            "FROM events WHERE timestamp >= ? "
            "GROUP BY event_type ORDER BY cnt DESC LIMIT 10",
            (start_time,),
        ).fetchall()
        event_type_breakdown = {r["event_type"]: r["cnt"] for r in type_rows}

        # Fleet blocks over time
        bucket_expr = {
            "1h": "SUBSTR(first_reported_at, 1, 15) || '0'",
            "6h": "SUBSTR(first_reported_at, 1, 13) || ':00'",
            "24h": "SUBSTR(first_reported_at, 1, 13) || ':00'",
            "7d": "SUBSTR(first_reported_at, 1, 10)",
            "30d": "SUBSTR(first_reported_at, 1, 10)",
        }.get(interval, "SUBSTR(first_reported_at, 1, 13) || ':00'")

        fleet_rows = db.execute(
            f"SELECT {bucket_expr} AS bucket, COUNT(*) as cnt "
            f"FROM fleet_blocks WHERE first_reported_at >= ? "
            f"GROUP BY bucket ORDER BY bucket ASC",
            (start_time,),
        ).fetchall()
        fleet_blocks_over_time = {
            "labels": [r["bucket"] for r in fleet_rows],
            "counts": [r["cnt"] for r in fleet_rows],
        }

        return jsonify(
            {
                "summary": summary,
                "action_breakdown": action_breakdown,
                "top_sources": top_sources_list,
                "geo_breakdown": geo_breakdown,
                "event_type_breakdown": event_type_breakdown,
                "fleet_blocks_over_time": fleet_blocks_over_time,
            }
        )
    finally:
        db.close()


# ── IP Rules Management ──────────────────────────────────────────────────


@dashboard_bp.route("/rules")
@require_role("analyst")
def rules():
    """IP rules management page — allowlist and blocklist.

    Shows active allowlist and blocklist entries with the ability to
    add new rules and remove existing ones. Adding/removing rules
    queues commands to all connected nodes.
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        allowlist = list_ip_rules(db, rule_type="allowlist")
        blocklist = list_ip_rules(db, rule_type="blocklist")
        node_list = list_nodes(db)
        recent_cmds = list_commands(db, limit=20)
    finally:
        db.close()

    # Parse command payloads
    for cmd in recent_cmds:
        raw = cmd.get("payload", "{}")
        if isinstance(raw, str):
            try:
                cmd["payload"] = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                cmd["payload"] = {}

    return render_template(
        "rules.html",
        allowlist=allowlist,
        blocklist=blocklist,
        nodes=node_list,
        recent_commands=recent_cmds,
    )


@dashboard_bp.route("/rules/allowlist", methods=["POST"])
@require_role("analyst")
def add_allowlist():
    """Add an IP/CIDR to the allowlist and queue commands to all nodes."""
    entry = request.form.get("entry", "").strip()
    reason = request.form.get("reason", "").strip()
    target_nodes = request.form.getlist("target_nodes")

    if not entry:
        flash("IP address or CIDR is required.", "error")
        return redirect(url_for("dashboard.rules"))

    # Basic IP/CIDR validation
    if not _validate_ip_or_cidr(entry):
        flash(f"Invalid IP address or CIDR notation: {entry}", "error")
        return redirect(url_for("dashboard.rules"))

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        add_ip_rule(db, "allowlist", entry, reason or "Added from dashboard", current_user.username)

        engine = getattr(current_app, "propagation_engine", None)
        if engine:
            try:
                engine.add_allowlist_entry(entry, actor=current_user.username)
            except Exception:
                logger.exception("Propagation engine add_allowlist_entry failed for %s", entry)

        nodes_targeted = target_nodes if target_nodes else ["*"]
        for node_id in nodes_targeted:
            create_command(db, node_id, "allowlist_add", {"entry": entry})

        try:
            current_app.config_sse_manager.publish_list_update("add", "allowlist", entry)
        except Exception:
            logger.exception("SSE publish failed for allowlist add: %s", entry)

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="unblock",
            target=entry,
            details={
                "action": "allowlist_add",
                "reason": reason,
                "nodes": nodes_targeted,
            },
        )
    finally:
        db.close()

    flash(
        f"Allowlisted {entry} — command queued for {len(nodes_targeted)} node(s).",
        "success",
    )
    return redirect(url_for("dashboard.rules"))


@dashboard_bp.route("/rules/allowlist/<int:rule_id>/remove", methods=["POST"])
@require_role("analyst")
def remove_allowlist(rule_id):
    """Remove an IP from the allowlist and queue removal commands."""
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        rule = get_ip_rule(db, rule_id)
        if rule is None or rule["rule_type"] != "allowlist":
            flash("Allowlist entry not found.", "error")
            return redirect(url_for("dashboard.rules"))

        entry = rule["entry"]
        remove_ip_rule(db, rule_id)

        create_command(db, "*", "allowlist_remove", {"entry": entry})

        try:
            current_app.config_sse_manager.publish_list_update("remove", "allowlist", entry)
        except Exception:
            logger.exception("SSE publish failed for allowlist remove: %s", entry)

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="unblock",
            target=entry,
            details={"action": "allowlist_remove"},
        )
    finally:
        db.close()

    flash(
        f"Removed {entry} from allowlist — removal command queued.",
        "success",
    )
    return redirect(url_for("dashboard.rules"))


@dashboard_bp.route("/rules/blocklist", methods=["POST"])
@require_role("analyst")
def add_blocklist():
    """Manually block an IP and queue block commands to nodes."""
    entry = request.form.get("entry", "").strip()
    reason = request.form.get("reason", "").strip()
    target_nodes = request.form.getlist("target_nodes")

    if not entry:
        flash("IP address is required.", "error")
        return redirect(url_for("dashboard.rules"))

    if not _validate_ip_or_cidr(entry):
        flash(f"Invalid IP address or CIDR notation: {entry}", "error")
        return redirect(url_for("dashboard.rules"))

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        add_ip_rule(
            db,
            "blocklist",
            entry,
            reason or "Manually blocked from dashboard",
            current_user.username,
        )

        nodes_targeted = target_nodes if target_nodes else ["*"]
        for node_id in nodes_targeted:
            create_command(
                db, node_id, "block", {"ip": entry, "reason": reason or "manual_dashboard_block"}
            )

        try:
            current_app.config_sse_manager.publish_list_update("add", "blocklist", entry)
        except Exception:
            logger.exception("SSE publish failed for blocklist add: %s", entry)

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="block",
            target=entry,
            details={
                "action": "block",
                "reason": reason,
                "nodes": nodes_targeted,
            },
        )
    finally:
        db.close()

    flash(
        f"Blocked {entry} — command queued for {len(nodes_targeted)} node(s).",
        "success",
    )
    return redirect(url_for("dashboard.rules"))


@dashboard_bp.route("/rules/blocklist/<int:rule_id>/remove", methods=["POST"])
@require_role("analyst")
def remove_blocklist(rule_id):
    """Remove an IP from the blocklist and queue unblock commands."""
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        rule = get_ip_rule(db, rule_id)
        if rule is None or rule["rule_type"] != "blocklist":
            flash("Blocklist entry not found.", "error")
            return redirect(url_for("dashboard.rules"))

        entry = rule["entry"]
        remove_ip_rule(db, rule_id)

        create_command(db, "*", "unblock", {"ip": entry, "reason": "removed_from_dashboard"})

        try:
            current_app.config_sse_manager.publish_list_update("remove", "blocklist", entry)
        except Exception:
            logger.exception("SSE publish failed for blocklist remove: %s", entry)

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="unblock",
            target=entry,
            details={"action": "unblock"},
        )
    finally:
        db.close()

    flash(
        f"Unblocked {entry} — unblock command queued.",
        "success",
    )
    return redirect(url_for("dashboard.rules"))


@dashboard_bp.route("/rules/commands")
@require_role("analyst")
def rules_commands():
    """HTMX fragment: return recent commands table for auto-refresh."""
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        recent_cmds = list_commands(db, limit=20)
    finally:
        db.close()

    for cmd in recent_cmds:
        raw = cmd.get("payload", "{}")
        if isinstance(raw, str):
            try:
                cmd["payload"] = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                cmd["payload"] = {}

    return render_template("fragments/command_log.html", recent_commands=recent_cmds)


# ── Feed Catalog Management ──────────────────────────────────────────────


@dashboard_bp.route("/feeds")
@require_role("analyst")
def feeds():
    """Feed catalog management page.

    Shows all available threat intelligence feeds organized by category,
    with per-node deployment status aggregated from heartbeat data.
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        catalog = list_feed_catalog(db)
        categories = get_feed_catalog_categories(db)
        node_list = list_nodes(db)
    finally:
        db.close()

    # Build per-feed deployment stats from node heartbeat data
    feed_stats = {}
    for feed in catalog:
        feed_stats[feed["name"]] = {
            "nodes_active": 0,
            "nodes_inactive": 0,
            "total_ips": 0,
            "deployed_nodes": [],  # list of node_ids with this feed active
            "disabled_nodes": [],  # list of node_ids with this feed disabled
        }

    for node in node_list:
        raw_feeds = node.get("last_feeds", "[]")
        try:
            node_feeds = json.loads(raw_feeds) if isinstance(raw_feeds, str) else raw_feeds
        except (json.JSONDecodeError, TypeError):
            node_feeds = []
        for nf in node_feeds:
            name = nf.get("name", "")
            if name in feed_stats:
                if nf.get("enabled"):
                    feed_stats[name]["nodes_active"] += 1
                    feed_stats[name]["total_ips"] += nf.get("last_sync_count", 0)
                    feed_stats[name]["deployed_nodes"].append(node["node_id"])
                else:
                    feed_stats[name]["nodes_inactive"] += 1
                    feed_stats[name]["disabled_nodes"].append(node["node_id"])

    # Group catalog by category
    grouped = {}
    for feed in catalog:
        cat = feed["category"]
        if cat not in grouped:
            grouped[cat] = []
        feed["stats"] = feed_stats.get(feed["name"], {})
        grouped[cat].append(feed)

    return render_template(
        "feeds.html",
        grouped=grouped,
        categories=categories,
        catalog=catalog,
        nodes=node_list,
        feed_stats=feed_stats,
    )


@dashboard_bp.route("/feeds/add", methods=["POST"])
@require_role("admin")
def feeds_add():
    """Add a custom feed to the catalog."""
    name = request.form.get("name", "").strip()
    url = request.form.get("url", "").strip()
    description = request.form.get("description", "").strip()
    fmt = request.form.get("format", "plain").strip()
    refresh_hours = request.form.get("refresh_hours", "1").strip()
    category = request.form.get("category", "custom").strip()
    provider = request.form.get("provider", "").strip()
    confidence = request.form.get("confidence", "medium").strip()
    detects = request.form.get("detects", "").strip()
    recommended_usage = request.form.get("recommended_usage", "").strip()

    if not name or not url:
        flash("Name and URL are required.", "error")
        return redirect(url_for("dashboard.feeds"))

    if fmt not in ("plain", "cidr"):
        flash("Format must be 'plain' or 'cidr'.", "error")
        return redirect(url_for("dashboard.feeds"))

    if confidence not in ("low", "medium", "high", "very_high"):
        confidence = "medium"

    try:
        refresh_seconds = int(float(refresh_hours) * 3600)
    except (ValueError, TypeError):
        refresh_seconds = 3600

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        existing = get_feed_by_name(db, name)
        if existing:
            flash(f"Feed '{name}' already exists.", "error")
            return redirect(url_for("dashboard.feeds"))

        add_feed_to_catalog(
            db,
            name,
            url,
            description or f"Custom feed: {name}",
            fmt,
            refresh_seconds,
            category,
            current_user.username,
            provider=provider,
            confidence=confidence,
            detects=detects,
            recommended_usage=recommended_usage,
        )
        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="key_create",
            target=name,
            details={"action": "feed_catalog_add", "url": url, "category": category},
        )
    finally:
        db.close()

    flash(f"Feed '{name}' added to catalog.", "success")
    return redirect(url_for("dashboard.feeds"))


@dashboard_bp.route("/feeds/<int:feed_id>/remove", methods=["POST"])
@require_role("admin")
def feeds_remove(feed_id):
    """Remove a feed from the catalog."""
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        feed = get_feed_catalog_entry(db, feed_id)
        if feed is None:
            flash("Feed not found.", "error")
            return redirect(url_for("dashboard.feeds"))

        remove_feed_from_catalog(db, feed_id)

        # Retract the feed from all nodes so it's removed from their
        # subscriptions and nftables sets, not just the catalog.
        create_command(db, "*", "feed_remove", {"name": feed["name"]})

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="key_revoke",
            target=feed["name"],
            details={"action": "feed_catalog_remove", "retracted": True},
        )
    finally:
        db.close()

    flash(
        f"Feed '{feed['name']}' removed from catalog and retract queued for all nodes.", "success"
    )
    return redirect(url_for("dashboard.feeds"))


@dashboard_bp.route("/feeds/<int:feed_id>/deploy", methods=["POST"])
@require_role("analyst")
def feeds_deploy(feed_id):
    """Deploy a feed to selected nodes (or all nodes).

    Skips nodes that already have the feed active (based on heartbeat
    data) to avoid duplicate feed_add commands and confusing logs.
    """
    target_nodes = request.form.getlist("target_nodes")

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        feed = get_feed_catalog_entry(db, feed_id)
        if feed is None:
            flash("Feed not found.", "error")
            return redirect(url_for("dashboard.feeds"))

        # Determine which nodes already have this feed active
        all_nodes = list_nodes(db)
        nodes_with_feed = set()
        for node in all_nodes:
            raw_feeds = node.get("last_feeds", "[]")
            try:
                node_feeds = json.loads(raw_feeds) if isinstance(raw_feeds, str) else raw_feeds
            except (json.JSONDecodeError, TypeError):
                node_feeds = []
            for nf in node_feeds:
                if nf.get("name") == feed["name"] and nf.get("enabled"):
                    nodes_with_feed.add(node["node_id"])

        # Filter out nodes that already have the feed
        if target_nodes:
            nodes_to_deploy = [n for n in target_nodes if n not in nodes_with_feed]
            skipped = [n for n in target_nodes if n in nodes_with_feed]
        else:
            # Deploying to all — use wildcard only if no node has it yet,
            # otherwise target only the nodes that don't have it.
            all_node_ids = [n["node_id"] for n in all_nodes]
            nodes_to_deploy = [n for n in all_node_ids if n not in nodes_with_feed]
            skipped = [n for n in all_node_ids if n in nodes_with_feed]

        if not nodes_to_deploy:
            skip_label = f"{len(skipped)} node(s)" if skipped else "all nodes"
            flash(
                f"Feed '{feed['name']}' is already active on {skip_label}. Nothing to deploy.",
                "warning",
            )
            return redirect(url_for("dashboard.feeds"))

        for node_id in nodes_to_deploy:
            create_command(
                db,
                node_id,
                "feed_add",
                {
                    "name": feed["name"],
                    "url": feed["url"],
                    "format": feed["format"],
                    "refresh_seconds": feed["refresh_seconds"],
                },
            )

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="block",
            target=feed["name"],
            details={
                "action": "feed_deploy",
                "nodes": nodes_to_deploy,
                "skipped_already_active": skipped,
            },
        )
    finally:
        db.close()

    msg = f"Feed '{feed['name']}' deploy command queued for {len(nodes_to_deploy)} node(s)."
    if skipped:
        msg += f" Skipped {len(skipped)} node(s) where it's already active."
    flash(msg, "success")
    return redirect(url_for("dashboard.feeds"))


@dashboard_bp.route("/feeds/<int:feed_id>/retract", methods=["POST"])
@require_role("analyst")
def feeds_retract(feed_id):
    """Remove a feed from all nodes."""
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        feed = get_feed_catalog_entry(db, feed_id)
        if feed is None:
            flash("Feed not found.", "error")
            return redirect(url_for("dashboard.feeds"))

        create_command(db, "*", "feed_remove", {"name": feed["name"]})

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="unblock",
            target=feed["name"],
            details={"action": "feed_retract"},
        )
    finally:
        db.close()

    flash(f"Feed '{feed['name']}' retract command queued for all nodes.", "success")
    return redirect(url_for("dashboard.feeds"))


def _validate_ip_or_cidr(entry: str) -> bool:
    """Validate an IP address or CIDR notation string.

    Accepts IPv4, IPv6, and CIDR notation (e.g. 10.0.0.0/8, ::1/128).
    """
    import ipaddress

    try:
        # Try as a network (CIDR)
        ipaddress.ip_network(entry, strict=False)
        return True
    except ValueError:
        pass

    try:
        # Try as a single IP
        ipaddress.ip_address(entry)
        return True
    except ValueError:
        return False


def _friendly_set_name(raw_name: str, include_icon: bool = True) -> str:
    """Convert an nftables set name into a human-readable label.

    Examples:
        shield_feed_firehol_level1  → 📋 Firehol Level1  (with icon)
        shield_feed_firehol_level1  → Firehol Level1      (without icon)
        shield_feed_abuse_ch_feodo  → 📋 Abuse Ch Feodo
        shield_local_blocks         → 🔒 Local Blocks
        shield_local                → 🔒 Local
        some_other_set              → Some Other Set
    """
    display = raw_name
    icon = ""
    if display.startswith("shield_feed_"):
        display = display[len("shield_feed_") :]
        if include_icon:
            icon = "📋 "
    elif display.startswith("shield_local"):
        display = display[len("shield_local") :]
        if display.startswith("_"):
            display = display[1:]
        if include_icon:
            icon = "🔒 "
        if not display:
            display = "Local Blocks"
    # Replace underscores with spaces and title-case each word
    display = display.replace("_", " ").strip().title()
    return f"{icon}{display}"


# ── Fleet Counters ───────────────────────────────────────────────────────


@dashboard_bp.route("/counters")
@require_role("viewer")
def counters():
    """Fleet-wide nftables counters page.

    Aggregates the last-reported packet/byte counters from every node
    (sent with each heartbeat) and renders a chart-ready overview.
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        node_list = list_nodes(db)
    finally:
        db.close()

    return render_template("counters.html", nodes=node_list)


@dashboard_bp.route("/counters/data")
@require_role("viewer")
def counters_data():
    """Return JSON counter data for Chart.js consumption.

    Aggregates per-set counters across all nodes (or a single node if
    ``?node_id=`` is provided). Returns data shaped for a horizontal
    bar chart: one bar per set, stacked by node.
    """
    filter_node = request.args.get("node_id", "")

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        node_list = list_nodes(db)
    finally:
        db.close()

    # Collect per-node, per-set aggregated counters
    # Structure: { set_name: { node_id: { packets, bytes } } }
    set_data: dict[str, dict[str, dict[str, int]]] = {}
    node_ids: list[str] = []

    for node in node_list:
        nid = node["node_id"]
        if filter_node and nid != filter_node:
            continue

        raw = node.get("last_counters", "[]")
        try:
            raw_counters = json.loads(raw) if isinstance(raw, str) else raw
        except (json.JSONDecodeError, TypeError):
            raw_counters = []

        if not raw_counters:
            continue

        node_ids.append(nid)

        # Aggregate by set name (sum across chains within a node)
        node_agg: dict[str, dict[str, int]] = {}
        for entry in raw_counters:
            if not isinstance(entry, dict):
                continue
            sname = entry.get("set", "")
            if not sname:
                continue
            if sname not in node_agg:
                node_agg[sname] = {"packets": 0, "bytes": 0}
            node_agg[sname]["packets"] += entry.get("packets", 0)
            node_agg[sname]["bytes"] += entry.get("bytes", 0)

        for sname, totals in node_agg.items():
            if sname not in set_data:
                set_data[sname] = {}
            set_data[sname][nid] = totals

    # Sort sets by total packets descending, excluding sets with 0 packets
    sorted_sets = sorted(
        (s for s in set_data.keys() if sum(n["packets"] for n in set_data[s].values()) > 0),
        key=lambda s: sum(n["packets"] for n in set_data[s].values()),
        reverse=True,
    )

    # Build Chart.js stacked bar datasets (one dataset per node)
    colors = [
        "rgb(59, 130, 246)",
        "rgb(239, 68, 68)",
        "rgb(34, 197, 94)",
        "rgb(234, 179, 8)",
        "rgb(168, 85, 247)",
        "rgb(236, 72, 153)",
        "rgb(20, 184, 166)",
        "rgb(249, 115, 22)",
        "rgb(99, 102, 241)",
        "rgb(244, 63, 94)",
    ]

    # Friendly labels for chart (no emoji — canvas renders them as boxes)
    labels = []
    for s in sorted_sets:
        display = _friendly_set_name(s, include_icon=False)
        labels.append(display)

    datasets = []
    for i, nid in enumerate(sorted(node_ids)):
        color = colors[i % len(colors)]
        datasets.append(
            {
                "label": nid,
                "data": [set_data[s].get(nid, {}).get("packets", 0) for s in sorted_sets],
                "backgroundColor": color.replace("rgb", "rgba").replace(")", ", 0.7)"),
                "borderColor": color,
                "borderWidth": 1,
            }
        )

    # Also build a summary table
    summary = []
    for s in sorted_sets:
        total_pkts = sum(n["packets"] for n in set_data[s].values())
        total_bytes = sum(n["bytes"] for n in set_data[s].values())
        node_count = len(set_data[s])
        summary.append(
            {
                "set": s,
                "packets": total_pkts,
                "bytes": total_bytes,
                "nodes": node_count,
            }
        )

    return jsonify(
        {
            "labels": labels,
            "raw_sets": sorted_sets,
            "datasets": datasets,
            "summary": summary,
            "node_ids": sorted(node_ids),
        }
    )


# Valid time ranges for counter history queries
_VALID_HISTORY_RANGES = {"1h", "6h", "24h", "7d"}


@dashboard_bp.route("/counters/history")
@require_role("viewer")
def counters_history():
    """Return JSON time-series delta data for the counter history chart.

    Query params:
        range: 1h, 6h, 24h, 7d (default 24h)
        node_id: optional node filter

    Returns JSON with labels, datasets (including resets), and lifetime_totals.
    Returns 400 for invalid range values.

    Requirements: 4.2, 5.1, 5.2, 6.1, 6.2, 6.3
    """
    time_range = request.args.get("range", "24h")
    node_id = request.args.get("node_id", "").strip() or None

    if time_range not in _VALID_HISTORY_RANGES:
        return jsonify(
            {"error": f"Invalid range '{time_range}'. Must be one of: 1h, 6h, 24h, 7d"}
        ), 400

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        data = get_counter_history(db, time_range, node_id)
    finally:
        db.close()

    return jsonify(data)


@dashboard_bp.route("/counters/summary")
@require_role("viewer")
def counters_summary():
    """Return per-set counter summary (packets, bytes, nodes) for a time range.

    Query params:
        range: 1h, 6h, 24h, 7d (default 24h)
        node_id: optional node filter

    Returns JSON: { summary: [{ set, packets, bytes, nodes }] }
    """
    time_range = request.args.get("range", "24h")
    node_id = request.args.get("node_id", "").strip() or None

    if time_range not in _VALID_HISTORY_RANGES:
        return jsonify(
            {"error": f"Invalid range '{time_range}'. Must be one of: 1h, 6h, 24h, 7d"}
        ), 400

    range_config = {
        "1h": {"hours": 1},
        "6h": {"hours": 6},
        "24h": {"hours": 24},
        "7d": {"days": 7},
    }[time_range]
    now = datetime.now(UTC)
    cutoff = now - timedelta(**range_config)
    cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        # Fetch in-window rows
        if node_id:
            rows = db.execute(
                "SELECT node_id, set_name, timestamp, packets, bytes "
                "FROM counter_snapshots "
                "WHERE timestamp >= ? AND node_id = ? "
                "ORDER BY node_id, set_name, timestamp ASC",
                (cutoff_str, node_id),
            ).fetchall()
            lookback_rows = db.execute(
                "SELECT cs.node_id, cs.set_name, cs.timestamp, cs.packets, cs.bytes "
                "FROM counter_snapshots cs "
                "INNER JOIN ("
                "  SELECT node_id, set_name, MAX(timestamp) AS max_ts "
                "  FROM counter_snapshots "
                "  WHERE timestamp < ? AND node_id = ? "
                "  GROUP BY node_id, set_name"
                ") latest ON cs.node_id = latest.node_id "
                "  AND cs.set_name = latest.set_name "
                "  AND cs.timestamp = latest.max_ts",
                (cutoff_str, node_id),
            ).fetchall()
        else:
            rows = db.execute(
                "SELECT node_id, set_name, timestamp, packets, bytes "
                "FROM counter_snapshots "
                "WHERE timestamp >= ? "
                "ORDER BY node_id, set_name, timestamp ASC",
                (cutoff_str,),
            ).fetchall()
            lookback_rows = db.execute(
                "SELECT cs.node_id, cs.set_name, cs.timestamp, cs.packets, cs.bytes "
                "FROM counter_snapshots cs "
                "INNER JOIN ("
                "  SELECT node_id, set_name, MAX(timestamp) AS max_ts "
                "  FROM counter_snapshots "
                "  WHERE timestamp < ? "
                "  GROUP BY node_id, set_name"
                ") latest ON cs.node_id = latest.node_id "
                "  AND cs.set_name = latest.set_name "
                "  AND cs.timestamp = latest.max_ts",
                (cutoff_str,),
            ).fetchall()
    finally:
        db.close()

    if not rows:
        return jsonify({"summary": []})

    # Group by (node_id, set_name) and compute deltas
    from collections import defaultdict

    lookback_timestamps: set[str] = set()
    for row in lookback_rows:
        lookback_timestamps.add(row["timestamp"])

    raw_groups: dict[tuple[str, str], dict[str, dict]] = defaultdict(dict)

    for row in lookback_rows:
        key = (row["node_id"], row["set_name"])
        ts = row["timestamp"]
        if ts not in raw_groups[key]:
            raw_groups[key][ts] = {"packets": 0, "bytes": 0}
        raw_groups[key][ts]["packets"] += row["packets"]
        raw_groups[key][ts]["bytes"] += row["bytes"]

    for row in rows:
        key = (row["node_id"], row["set_name"])
        ts = row["timestamp"]
        if ts not in raw_groups[key]:
            raw_groups[key][ts] = {"packets": 0, "bytes": 0}
        raw_groups[key][ts]["packets"] += row["packets"]
        raw_groups[key][ts]["bytes"] += row["bytes"]

    groups: dict[tuple[str, str], list[dict]] = {}
    for key, ts_map in raw_groups.items():
        groups[key] = [
            {"timestamp": ts, "packets": vals["packets"], "bytes": vals["bytes"]}
            for ts, vals in sorted(ts_map.items())
        ]

    # Compute deltas and aggregate per set
    # { set_name: { "packets": int, "bytes": int, "nodes": set } }
    set_totals: dict[str, dict] = defaultdict(lambda: {"packets": 0, "bytes": 0, "nodes": set()})

    for (nid, set_name), snapshots in groups.items():
        deltas = compute_deltas(snapshots)
        for d in deltas:
            ts = d["timestamp"]
            if ts in lookback_timestamps and ts < cutoff_str:
                continue
            set_totals[set_name]["packets"] += d["delta_packets"]
            set_totals[set_name]["bytes"] += d["delta_bytes"]
            set_totals[set_name]["nodes"].add(nid)

    # Build summary sorted by packets descending
    summary = sorted(
        [
            {
                "set": s,
                "packets": t["packets"],
                "bytes": t["bytes"],
                "nodes": len(t["nodes"]),
            }
            for s, t in set_totals.items()
            if t["packets"] > 0
        ],
        key=lambda x: x["packets"],
        reverse=True,
    )

    return jsonify({"summary": summary})


# ── Block Set Stats (new panel below Historical Block Deltas) ──


@dashboard_bp.route("/counters/block-set-stats")
@require_role("viewer")
def counters_block_set_stats():
    """Return block counts per detection rule over a time range.

    Query params:
        range: 1h, 6h, 24h, 7d (default 24h)

    Returns JSON with a list of objects:
        rule_name       — detection rule (or event_type if empty)
        total_blocks    — total fleet blocks created
        active          — currently active blocks
        expired         — expired blocks
        removed         — manually removed blocks
        pending         — pending blocks
        unique_ips      — distinct IPs blocked
    """
    time_range = request.args.get("range", "24h")

    if time_range not in _VALID_HISTORY_RANGES:
        return jsonify(
            {"error": f"Invalid range '{time_range}'. Must be one of: 1h, 6h, 24h, 7d"}
        ), 400

    from datetime import timedelta

    _range_map = {
        "1h": {"hours": 1},
        "6h": {"hours": 6},
        "24h": {"hours": 24},
        "7d": {"days": 7},
    }
    range_config = _range_map.get(time_range)
    now = datetime.now(UTC)
    cutoff = now - timedelta(**range_config)
    cutoff_str = cutoff.strftime("%Y-%m-%dT%H:%M:%SZ")

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        rows = db.execute(
            "SELECT "
            "  COALESCE(NULLIF(detection_rule, ''), event_type, '(manual)') as rule_name, "
            "  COUNT(*) as total_blocks, "
            "  SUM(CASE WHEN status = 'active' THEN 1 ELSE 0 END) as active_count, "
            "  SUM(CASE WHEN status = 'expired' THEN 1 ELSE 0 END) as expired_count, "
            "  SUM(CASE WHEN status = 'removed' THEN 1 ELSE 0 END) as removed_count, "
            "  SUM(CASE WHEN status = 'pending' THEN 1 ELSE 0 END) as pending_count, "
            "  COUNT(DISTINCT source_ip) as unique_ips "
            "FROM fleet_blocks "
            "WHERE first_reported_at >= ? "
            "GROUP BY rule_name "
            "ORDER BY total_blocks DESC",
            (cutoff_str,),
        ).fetchall()
    finally:
        db.close()

    results = [
        {
            "rule_name": r["rule_name"],
            "total_blocks": r["total_blocks"],
            "active": r["active_count"],
            "expired": r["expired_count"],
            "removed": r["removed_count"],
            "pending": r["pending_count"],
            "unique_ips": r["unique_ips"],
        }
        for r in rows
    ]

    return jsonify(results)
