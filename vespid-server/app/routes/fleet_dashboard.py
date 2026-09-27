"""Fleet Dashboard blueprint — fleet-wide blocklist management UI.

Provides web pages and HTMX fragments for managing fleet blocks,
the global allow-list, and propagation configuration. Mutations are
proxied through the PropagationEngine; reads query the database directly.

Endpoints:
    GET  /fleet/                              — Fleet blocks page
    GET  /fleet/allowlist                     — Allow-list management page
    GET  /fleet/config                        — Propagation config editor

    GET  /fleet/fragments/blocks-table        — Blocks table fragment (HTMX)
    GET  /fleet/fragments/allowlist-table     — Allowlist table fragment (HTMX)
    GET  /fleet/fragments/block-detail/<ip>   — IP reporting history (HTMX)
    GET  /fleet/fragments/activity-feed       — Activity feed fragment (HTMX)
    GET  /fleet/fragments/pause-toggle        — Pause toggle component (HTMX)
    GET  /fleet/fragments/fleet-summary-card  — Summary card for main dashboard

    POST   /fleet/blocks/add                  — Add a manual fleet block
    DELETE /fleet/blocks/<ip>/remove           — Remove a fleet block
    POST   /fleet/allowlist/add               — Add an allow-list entry
    DELETE /fleet/allowlist/<entry_id>/remove  — Remove an allow-list entry
    POST   /fleet/config/update               — Update propagation config
    POST   /fleet/pause/toggle                — Toggle propagation pause

Requirements: 2, 3, 4, 5, 8
"""

import csv
import io
import json
import math
from datetime import UTC, datetime, timedelta

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask import (
    Response as FlaskResponse,
)
from flask_login import current_user

from app.decorators import require_role
from app.models import _utcnow_iso, get_db, record_audit
from app.propagation_engine import parse_duration

fleet_dashboard_bp = Blueprint(
    "fleet_dashboard",
    __name__,
    url_prefix="/fleet",
    template_folder="templates",
)


# ── Helper functions ─────────────────────────────────────────────────────


def _get_fleet_config(db):
    """Load fleet configuration from the database.

    Returns a dict with typed values.
    """
    rows = db.execute("SELECT config_key, config_value FROM fleet_config").fetchall()

    config = {}
    for row in rows:
        key = row["config_key"]
        value = row["config_value"]

        if key in (
            "corroboration_threshold",
            "max_fleet_blocks_per_hour",
            "max_reports_per_node_per_hour",
            "reaper_interval_seconds",
        ):
            config[key] = int(value)
        elif key in (
            "corroboration_window_seconds",
            "fleet_block_ttl_seconds",
            "expired_block_retention_seconds",
        ):
            config[key] = parse_duration(value)
            if key == "expired_block_retention_seconds":
                config["expired_block_retention_raw"] = value
            elif key == "fleet_block_ttl_seconds":
                config["fleet_block_ttl_raw"] = value
            elif key == "corroboration_window_seconds":
                config["corroboration_window_raw"] = value
        elif key == "propagation_paused":
            config[key] = value.lower() in ("true", "1", "yes")
        elif key == "excluded_event_types":
            try:
                config[key] = json.loads(value)
            except (json.JSONDecodeError, TypeError):
                config[key] = []
        else:
            config[key] = value

    return config


def _get_fleet_summary_stats(db):
    """Return fleet summary metrics for the stat card.

    Returns:
        {
            "active_blocks": int,
            "blocks_24h": int,
            "propagation_paused": bool,
            "corroboration_threshold": int,
            "sparkline_fleet_24h": list[int],
        }
    """
    active_row = db.execute(
        "SELECT COUNT(*) as cnt FROM fleet_blocks WHERE status = 'active'"
    ).fetchone()
    active_blocks = active_row["cnt"] if active_row else 0

    cutoff_24h = (datetime.now(UTC) - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
    blocks_24h_row = db.execute(
        "SELECT COUNT(*) as cnt FROM fleet_blocks WHERE approved_at >= ?",
        (cutoff_24h,),
    ).fetchone()
    blocks_24h = blocks_24h_row["cnt"] if blocks_24h_row else 0

    config = _get_fleet_config(db)

    return {
        "active_blocks": active_blocks,
        "blocks_24h": blocks_24h,
        "propagation_paused": config.get("propagation_paused", False),
        "corroboration_threshold": config.get("corroboration_threshold", 1),
        "sparkline_fleet_24h": _get_sparkline_fleet_blocks_24h(db),
    }


FLEET_BLOCKS_SORT_COLUMNS = frozenset(
    {
        "source_ip",
        "status",
        "first_reported_at",
        "last_renewed_at",
        "approved_at",
        "expires_at",
        "reporting_node_count",
        "originating_node_id",
        "event_type",
        "ttl_seconds",
    }
)


def _query_fleet_blocks(
    db,
    filters: dict,
    page: int = 1,
    per_page: int = 50,
    sort_by: str = "approved_at",
    sort_order: str = "DESC",
    search: str | None = None,
):
    """Query fleet blocks with filters, pagination, sorting, and search.

    Returns (blocks, total, filters, total_pages, stats) tuple.
    """
    conditions = []
    params = []

    source_ip = filters.get("source_ip", "")
    if source_ip:
        conditions.append("source_ip LIKE ?")
        params.append(f"%{source_ip}%")

    event_type = filters.get("event_type", "")
    if event_type:
        conditions.append("event_type = ?")
        params.append(event_type)

    status = filters.get("status", "")
    if status and status != "all":
        conditions.append("status = ?")
        params.append(status)
    elif not status:
        status = "active"
        filters["status"] = "active"
        conditions.append("status = ?")
        params.append(status)

    node_id = filters.get("node_id", "")
    if node_id:
        conditions.append("originating_node_id = ?")
        params.append(node_id)

    if search:
        conditions.append("(source_ip LIKE ? OR originating_node_id LIKE ? OR event_type LIKE ?)")
        like = f"%{search}%"
        params.extend([like, like, like])

    where_clause = ""
    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    if sort_by not in FLEET_BLOCKS_SORT_COLUMNS:
        sort_by = "approved_at"
    sort_order = "ASC" if sort_order.upper() == "ASC" else "DESC"

    count_sql = f"SELECT COUNT(*) as cnt FROM fleet_blocks {where_clause}"
    total = db.execute(count_sql, params).fetchone()["cnt"]

    offset = (page - 1) * per_page
    query_sql = (
        f"SELECT * FROM fleet_blocks {where_clause} "
        f"ORDER BY {sort_by} {sort_order} LIMIT ? OFFSET ?"
    )
    rows = db.execute(query_sql, params + [per_page, offset]).fetchall()
    blocks = [dict(row) for row in rows]

    total_pages = max(1, math.ceil(total / per_page))

    # Summary stats — counts by status
    stats = {}
    for s in ("active", "expired", "removed", "pending"):
        r = db.execute("SELECT COUNT(*) as cnt FROM fleet_blocks WHERE status = ?", (s,)).fetchone()
        stats[s] = r["cnt"] if r else 0

    return blocks, total, filters, total_pages, stats


def _export_fleet_csv(blocks: list[dict]) -> FlaskResponse:
    """Return fleet blocks as a CSV download."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(
        [
            "Source IP",
            "Status",
            "Event Type",
            "First Reported",
            "Last Renewed",
            "Approved At",
            "Expires At",
            "TTL (s)",
            "Node Count",
            "Origin Node",
            "Detection Rule",
            "Reason",
        ]
    )
    for b in blocks:
        writer.writerow(
            [
                b.get("source_ip", ""),
                b.get("status", ""),
                b.get("event_type", ""),
                b.get("first_reported_at", ""),
                b.get("last_renewed_at", ""),
                b.get("approved_at", ""),
                b.get("expires_at", ""),
                b.get("ttl_seconds", ""),
                b.get("reporting_node_count", ""),
                b.get("originating_node_id", ""),
                b.get("detection_rule", ""),
                b.get("reason", ""),
            ]
        )
    output.seek(0)
    return FlaskResponse(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=fleet_blocks.csv"},
    )


def _get_sparkline_fleet_blocks_24h(db):
    """Return hourly fleet block counts for the last 24 hours (24 values).

    Counts fleet blocks by their approved_at timestamp per hour bucket.
    Index 0 is 24 hours ago, index 23 is the current hour.
    """
    now = datetime.now(UTC)
    cutoff = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")

    rows = db.execute(
        "SELECT SUBSTR(approved_at, 1, 13) as hour, COUNT(*) as cnt "
        "FROM fleet_blocks "
        "WHERE approved_at >= ? "
        "GROUP BY hour ORDER BY hour ASC",
        (cutoff,),
    ).fetchall()

    bucket_map = {}
    for row in rows:
        key = row["hour"].replace("T", " ") if row["hour"] else ""
        bucket_map[key] = bucket_map.get(key, 0) + row["cnt"]

    result = []
    for i in range(24):
        hour = now - timedelta(hours=23 - i)
        key = hour.strftime("%Y-%m-%d %H")
        result.append(bucket_map.get(key, 0))

    return result


def _approved_at_timestamp(approved_at) -> float | None:
    """Convert a fleet block approved_at value to a Unix timestamp.

    Handles MySQL datetime objects, ISO-8601 strings, and numeric values.
    """
    if approved_at is None:
        return None
    if isinstance(approved_at, (int, float)):
        return float(approved_at)
    if isinstance(approved_at, str):
        # MySQL returns "2026-06-15 15:54:41"; ensure UTC interpretation.
        dt = datetime.strptime(approved_at, "%Y-%m-%d %H:%M:%S")
        return dt.replace(tzinfo=UTC).timestamp()
    if isinstance(approved_at, datetime):
        if approved_at.tzinfo is None:
            approved_at = approved_at.replace(tzinfo=UTC)
        return approved_at.timestamp()
    return None


def _count_fleet_propagated_nodes_from_events(db, source_ip, approved_at) -> int:
    """Count nodes that reported a fleet_block event for source_ip after approval.

    Fast but best-effort: events can be delayed or dropped, so this is used
    alongside _count_fleet_propagated_nodes() and the larger value wins.
    """
    row = db.execute(
        "SELECT COUNT(DISTINCT node_id) as cnt FROM ip_intel_events "
        "WHERE ip_address = ? AND event_kind = 'fleet_block' AND timestamp >= ?",
        (source_ip, approved_at),
    ).fetchone()
    return row["cnt"] or 0


def _count_fleet_propagated_nodes(db, source_ip, approved_at, originating_node_id) -> int:
    """Count nodes (excluding originator) that currently have source_ip blocked via fleet.

    Uses node_blocks table rather than ip_intel_events so the count reflects
    the actual state on each node, even if a fleet_block confirmation event was
    dropped or delayed.
    """
    approved_ts = _approved_at_timestamp(approved_at)
    rows = db.execute(
        "SELECT nb.node_id, nb.blocked_at FROM node_blocks nb "
        "WHERE nb.node_id != ? AND nb.ip = ? AND nb.reason LIKE 'fleet:%'",
        (originating_node_id, source_ip),
    ).fetchall()

    confirmed: set[str] = set()
    for row in rows:
        node_id = row["node_id"]
        blocked_at = row["blocked_at"]
        if isinstance(blocked_at, (int, float)) and approved_ts is not None:
            if blocked_at < approved_ts:
                continue
        confirmed.add(node_id)

    return len(confirmed)


def get_recent_fleet_propagations(db, limit=5):
    """Return recent fleet propagations with confirmation counts.

    Used by the dashboard widget to show propagation status at a glance.

    Returns:
        {
            "total_nodes": int,
            "propagations": [
                {
                    "source_ip": str,
                    "status": str,
                    "approved_at": str,
                    "event_type": str,
                    "detection_rule": str,
                    "originating_node_id": str,
                    "confirmed_nodes": int,
                },
                ...
            ]
        }
    """
    total_nodes = db.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]

    rows = db.execute(
        "SELECT fb.source_ip, fb.status, fb.approved_at, fb.event_type, "
        "fb.detection_rule, fb.originating_node_id "
        "FROM fleet_blocks fb "
        "WHERE fb.approved_at IS NOT NULL "
        "ORDER BY fb.approved_at DESC LIMIT ?",
        (limit,),
    ).fetchall()

    propagations = []
    for row in rows:
        row_dict = dict(row)
        event_count = _count_fleet_propagated_nodes_from_events(
            db,
            row_dict["source_ip"],
            row_dict["approved_at"],
        )
        blocklist_count = _count_fleet_propagated_nodes(
            db,
            row_dict["source_ip"],
            row_dict["approved_at"],
            row_dict["originating_node_id"],
        )
        # Use the larger of the two: events give fast updates, blocklists
        # catch dropped/delayed confirmations.
        row_dict["confirmed_nodes"] = max(event_count, blocklist_count)
        propagations.append(row_dict)

    return {
        "total_nodes": total_nodes,
        "propagations": propagations,
    }


# ── Full page routes ─────────────────────────────────────────────────────


@fleet_dashboard_bp.route("/")
@require_role("analyst")
def blocks_page():
    """Fleet blocks management page.

    Full page load renders fleet_blocks.html with the blocks table,
    filter controls, manual add form, and activity feed sidebar.
    HTMX requests return only the blocks table fragment.

    Defaults to showing only active blocks unless a status filter is
    explicitly provided (use status=all to see all statuses).

    Requirements: 2, 5, 6, 7, 8
    """
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    sort_by = request.args.get("sort_by", "approved_at").strip()
    sort_order = request.args.get("sort_order", "DESC").strip().upper()
    search = request.args.get("search", "").strip() or None
    export = request.args.get("export", "").strip().lower()

    filters = {
        "source_ip": request.args.get("source_ip", "").strip(),
        "event_type": request.args.get("event_type", "").strip(),
        "status": request.args.get("status", "").strip() or "active",
        "node_id": request.args.get("node_id", "").strip(),
    }

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        blocks, total, filters, total_pages, stats = _query_fleet_blocks(
            db,
            filters,
            page=page,
            per_page=per_page,
            sort_by=sort_by,
            sort_order=sort_order,
            search=search,
        )
        config = _get_fleet_config(db)
    finally:
        db.close()

    # CSV export
    if export == "csv":
        return _export_fleet_csv(blocks)

    ctx = dict(
        blocks=blocks,
        total=total,
        page=page,
        total_pages=total_pages,
        filters=filters,
        fleet_config=config,
        search=search or "",
        sort_by=sort_by,
        sort_order=sort_order,
        per_page=per_page,
        stats=stats,
    )

    if request.headers.get("HX-Request"):
        return render_template("fragments/fleet_blocks_table.html", **ctx)

    return render_template("fleet_blocks.html", **ctx)


@fleet_dashboard_bp.route("/allowlist")
@require_role("analyst")
def allowlist_page():
    """Fleet allow-list management page.

    Full page load renders fleet_allowlist.html with the allowlist table
    and add form. HTMX requests return only the allowlist table fragment.

    Requirements: 3, 5, 7, 8
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        rows = db.execute("SELECT * FROM fleet_allowlist ORDER BY created_at DESC").fetchall()
        entries = [dict(row) for row in rows]

        config = _get_fleet_config(db)
    finally:
        db.close()

    if request.headers.get("HX-Request"):
        return render_template(
            "fragments/fleet_allowlist_table.html",
            entries=entries,
        )

    return render_template(
        "fleet_allowlist.html",
        entries=entries,
        fleet_config=config,
    )


@fleet_dashboard_bp.route("/config")
@require_role("admin")
def config_page():
    """Propagation configuration editor page.

    Displays the current fleet config values in an editable form.
    Only accessible to admin users.

    Requirements: 4, 5, 7, 8
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        config = _get_fleet_config(db)
    finally:
        db.close()

    return render_template(
        "fleet_config.html",
        fleet_config=config,
    )


# ── HTMX fragment routes ────────────────────────────────────────────────


@fleet_dashboard_bp.route("/fragments/blocks-table")
@require_role("analyst")
def fragment_blocks_table():
    """Return the fleet blocks table fragment.

    Supports the same filter and pagination params as the full page.
    Defaults to showing only active blocks unless a status filter is
    explicitly provided (use status=all to see all statuses).

    Requirements: 2, 8
    """
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    sort_by = request.args.get("sort_by", "approved_at").strip()
    sort_order = request.args.get("sort_order", "DESC").strip().upper()
    search = request.args.get("search", "").strip() or None
    export = request.args.get("export", "").strip().lower()

    filters = {
        "source_ip": request.args.get("source_ip", "").strip(),
        "event_type": request.args.get("event_type", "").strip(),
        "status": request.args.get("status", "").strip() or "active",
        "node_id": request.args.get("node_id", "").strip(),
    }

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        blocks, total, filters, total_pages, stats = _query_fleet_blocks(
            db,
            filters,
            page=page,
            per_page=per_page,
            sort_by=sort_by,
            sort_order=sort_order,
            search=search,
        )
    finally:
        db.close()

    if export == "csv":
        return _export_fleet_csv(blocks)

    return render_template(
        "fragments/fleet_blocks_table.html",
        blocks=blocks,
        total=total,
        page=page,
        total_pages=total_pages,
        filters=filters,
        search=search or "",
        sort_by=sort_by,
        sort_order=sort_order,
        per_page=per_page,
        stats=stats,
    )


@fleet_dashboard_bp.route("/fragments/allowlist-table")
@require_role("analyst")
def fragment_allowlist_table():
    """Return the fleet allowlist table fragment.

    Requirements: 3, 8
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        rows = db.execute("SELECT * FROM fleet_allowlist ORDER BY created_at DESC").fetchall()
        entries = [dict(row) for row in rows]
    finally:
        db.close()

    return render_template(
        "fragments/fleet_allowlist_table.html",
        entries=entries,
    )


@fleet_dashboard_bp.route("/fragments/block-detail/<path:ip>")
@require_role("analyst")
def fragment_block_detail(ip):
    """Return the reporting history detail panel for a specific IP.

    Requirements: 9, 8
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        reports = db.execute(
            "SELECT * FROM fleet_block_reports WHERE source_ip = ? ORDER BY reported_at DESC",
            (ip,),
        ).fetchall()

        blocks = db.execute(
            "SELECT * FROM fleet_blocks WHERE source_ip = ? ORDER BY first_reported_at DESC",
            (ip,),
        ).fetchall()
    finally:
        db.close()

    return render_template(
        "fragments/fleet_block_detail.html",
        source_ip=ip,
        reports=[dict(r) for r in reports],
        blocks=[dict(b) for b in blocks],
    )


@fleet_dashboard_bp.route("/fragments/activity-feed")
@require_role("analyst")
def fragment_activity_feed():
    """Return the activity feed fragment.

    Shows recent fleet activity from the audit log.

    Requirements: 6, 8
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        rows = db.execute(
            "SELECT * FROM audit_log "
            "WHERE action_type IN ("
            "'fleet_block_propagated', 'fleet_block_manual_add', "
            "'fleet_block_manual_remove', 'fleet_block_expired', "
            "'fleet_allowlist_modified', 'fleet_propagation_toggled', "
            "'fleet_config_updated', 'fleet_block_reenabled', "
            "'fleet_block_ttl_reset'"
            ") ORDER BY timestamp DESC LIMIT 50"
        ).fetchall()
        events = [dict(r) for r in rows]
    finally:
        db.close()

    # Parse details JSON for each event
    for event in events:
        raw = event.get("details", "{}")
        if isinstance(raw, str):
            try:
                event["details"] = json.loads(raw)
            except (json.JSONDecodeError, TypeError):
                event["details"] = {}

    return render_template(
        "fragments/fleet_activity_feed.html",
        events=events,
    )


@fleet_dashboard_bp.route("/fragments/pause-toggle")
@require_role("analyst")
def fragment_pause_toggle():
    """Return the pause toggle component fragment.

    Requirements: 5, 8
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        config = _get_fleet_config(db)
    finally:
        db.close()

    return render_template(
        "fragments/fleet_pause_toggle.html",
        propagation_paused=config.get("propagation_paused", False),
    )


@fleet_dashboard_bp.route("/fragments/fleet-summary-card")
@require_role("analyst")
def fragment_fleet_summary_card():
    """Return the fleet summary stat card fragment.

    Used on the main dashboard for the fleet metrics card.

    Requirements: 1, 8
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        stats = _get_fleet_summary_stats(db)
    finally:
        db.close()

    return render_template(
        "fragments/fleet_summary_card.html",
        stats=stats,
    )


# ── Action routes (mutations) ────────────────────────────────────────────


@fleet_dashboard_bp.route("/blocks/add", methods=["POST"])
@require_role("admin")
def add_block():
    """Manually add a fleet block via the PropagationEngine.

    Requirements: 2, 8
    """
    source_ip = request.form.get("source_ip", "").strip()
    reason = request.form.get("reason", "").strip()

    if not source_ip:
        flash("Source IP is required.", "error")
        return redirect(url_for("fleet_dashboard.blocks_page"))

    if not reason:
        flash("Reason is required.", "error")
        return redirect(url_for("fleet_dashboard.blocks_page"))

    engine = current_app.propagation_engine
    actor = current_user.username

    result = engine.manual_add(source_ip, reason, actor)

    if result["status"] == "rejected":
        flash(f"Block rejected: {result['reason']}", "error")
    elif result["status"] == "exists":
        flash(f"IP {source_ip} is already actively blocked.", "warning")
    else:
        flash(f"Fleet block added for {source_ip}.", "success")

    # If HTMX request, return the updated blocks table
    if request.headers.get("HX-Request"):
        return redirect(url_for("fleet_dashboard.fragment_blocks_table"))

    return redirect(url_for("fleet_dashboard.blocks_page"))


@fleet_dashboard_bp.route("/blocks/<path:ip>/remove", methods=["DELETE"])
@require_role("admin")
def remove_block(ip):
    """Remove a fleet block via the PropagationEngine.

    Requirements: 2, 8
    """
    engine = current_app.propagation_engine
    actor = current_user.username

    result = engine.manual_remove(ip, actor)

    if result["status"] == "not_found":
        flash(f"No active fleet block found for {ip}.", "error")
    else:
        flash(f"Fleet block for {ip} removed.", "success")

    if request.headers.get("HX-Request"):
        return redirect(url_for("fleet_dashboard.fragment_blocks_table"))

    return redirect(url_for("fleet_dashboard.blocks_page"))


@fleet_dashboard_bp.route("/blocks/<path:ip>/reenable", methods=["POST"])
@require_role("admin")
def reenable_block(ip):
    """Re-enable an expired or removed fleet block with a fresh TTL.

    Requirements: 2, 8
    """
    engine = current_app.propagation_engine
    actor = current_user.username

    result = engine.reenable_block(ip, actor)

    if result["status"] == "not_found":
        flash(f"No expired or removed block found for {ip}.", "error")
    elif result["status"] == "rejected":
        flash(f"Cannot re-enable: {result['reason']}", "error")
    elif result["status"] == "exists":
        flash(f"IP {ip} is already actively blocked.", "error")
    else:
        flash(f"Fleet block for {ip} re-enabled.", "success")

    if request.headers.get("HX-Request"):
        return redirect(url_for("fleet_dashboard.fragment_blocks_table"))

    return redirect(url_for("fleet_dashboard.blocks_page"))


@fleet_dashboard_bp.route("/blocks/<path:ip>/reset-ttl", methods=["POST"])
@require_role("admin")
def reset_block_ttl(ip):
    """Reset an active fleet block's TTL to the fleet default.

    Requirements: 2, 8
    """
    engine = current_app.propagation_engine
    actor = current_user.username

    result = engine.reset_block_ttl(ip, actor)

    if result["status"] == "not_found":
        flash(f"No active block found for {ip}.", "error")
    else:
        flash(f"TTL for {ip} reset to fleet default ({result['ttl_seconds']}s).", "success")

    if request.headers.get("HX-Request"):
        return redirect(url_for("fleet_dashboard.fragment_blocks_table"))

    return redirect(url_for("fleet_dashboard.blocks_page"))


@fleet_dashboard_bp.route("/allowlist/add", methods=["POST"])
@require_role("admin")
def add_allowlist():
    """Add an entry to the global allow-list via the PropagationEngine.

    Requirements: 3, 8
    """
    entry = request.form.get("entry", "").strip()

    if not entry:
        flash("Entry (IP or CIDR) is required.", "error")
        return redirect(url_for("fleet_dashboard.allowlist_page"))

    engine = current_app.propagation_engine
    actor = current_user.username

    result = engine.add_allowlist_entry(entry, actor)

    if result["status"] == "added":
        msg = f"Allow-list entry added: {entry}"
        if result.get("blocks_removed", 0) > 0:
            msg += f" ({result['blocks_removed']} active block(s) removed)"
        flash(msg, "success")
    else:
        flash(f"Failed to add allow-list entry: {result.get('reason', 'unknown error')}", "error")

    if request.headers.get("HX-Request"):
        return redirect(url_for("fleet_dashboard.fragment_allowlist_table"))

    return redirect(url_for("fleet_dashboard.allowlist_page"))


@fleet_dashboard_bp.route("/allowlist/<int:entry_id>/remove", methods=["DELETE"])
@require_role("admin")
def remove_allowlist(entry_id):
    """Remove an allow-list entry via the PropagationEngine.

    Requirements: 3, 8
    """
    engine = current_app.propagation_engine
    actor = current_user.username

    result = engine.remove_allowlist_entry(entry_id, actor)

    if result["status"] == "not_found":
        flash(f"Allow-list entry {entry_id} not found.", "error")
    else:
        flash(f"Allow-list entry '{result.get('entry', '')}' removed.", "success")

    if request.headers.get("HX-Request"):
        return redirect(url_for("fleet_dashboard.fragment_allowlist_table"))

    return redirect(url_for("fleet_dashboard.allowlist_page"))


@fleet_dashboard_bp.route("/config/update", methods=["POST"])
@require_role("admin")
def update_config():
    """Update propagation configuration.

    Requirements: 4, 8
    """
    # Collect form values
    allowed_keys = {
        "corroboration_threshold",
        "corroboration_window_seconds",
        "fleet_block_ttl_seconds",
        "max_fleet_blocks_per_hour",
        "max_reports_per_node_per_hour",
        "reaper_interval_seconds",
        "expired_block_retention_seconds",
    }

    string_keys = {
        "unlock_webhook_secret",
    }

    duration_keys = {
        "expired_block_retention_seconds",
        "fleet_block_ttl_seconds",
        "corroboration_window_seconds",
    }

    updates = {}
    for key in allowed_keys:
        value = request.form.get(key, "").strip()
        if value:
            if key in duration_keys:
                # Accept duration strings like 5m, 1h, 1d, 0m
                try:
                    parse_duration(value)
                    updates[key] = value
                except ValueError:
                    flash(
                        f"Invalid value for {key}: use a duration like 0m, 30m, 6h, 1d or plain seconds.",
                        "error",
                    )
                    return redirect(url_for("fleet_dashboard.config_page"))
            else:
                try:
                    int_val = int(value)
                    if int_val < 0:
                        flash(f"Invalid value for {key}: must be a positive integer.", "error")
                        return redirect(url_for("fleet_dashboard.config_page"))
                    updates[key] = str(int_val)
                except ValueError:
                    flash(f"Invalid value for {key}: must be an integer.", "error")
                    return redirect(url_for("fleet_dashboard.config_page"))

    # Handle plain string keys (allow empty to clear the value)
    for key in string_keys:
        value = request.form.get(key, "")
        updates[key] = value.strip()

    # Handle excluded_event_types separately (comma-separated or JSON)
    excluded_raw = request.form.get("excluded_event_types", "").strip()
    if excluded_raw:
        try:
            # Try JSON array first
            excluded = json.loads(excluded_raw)
            if not isinstance(excluded, list):
                raise ValueError("Must be a list")
        except (json.JSONDecodeError, ValueError):
            # Fall back to comma-separated
            excluded = [e.strip() for e in excluded_raw.split(",") if e.strip()]
        updates["excluded_event_types"] = json.dumps(excluded)

    if not updates:
        flash("No configuration values to update.", "warning")
        return redirect(url_for("fleet_dashboard.config_page"))

    actor = current_user.username
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        for key, value in updates.items():
            db.execute(
                "UPDATE fleet_config SET config_value = ?, "
                "updated_at = ?, "
                "updated_by = ? WHERE config_key = ?",
                (value, _utcnow_iso(), actor, key),
            )
        db.commit()

        record_audit(
            db,
            actor=actor,
            actor_ip=request.remote_addr,
            action_type="fleet_config_updated",
            target="fleet_config",
            details={"updated_keys": list(updates.keys()), "values": updates},
        )
    finally:
        db.close()

    flash("Configuration updated successfully.", "success")
    return redirect(url_for("fleet_dashboard.config_page"))


@fleet_dashboard_bp.route("/pause/toggle", methods=["POST"])
@require_role("admin")
def toggle_pause():
    """Toggle propagation pause state.

    Requirements: 5, 8
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        row = db.execute(
            "SELECT config_value FROM fleet_config WHERE config_key = 'propagation_paused'"
        ).fetchone()

        current_state = False
        if row:
            current_state = row["config_value"].lower() in ("true", "1", "yes")

        new_state = not current_state
        new_value = "true" if new_state else "false"
        actor = current_user.username

        db.execute(
            "UPDATE fleet_config SET config_value = ?, "
            "updated_at = ?, "
            "updated_by = ? WHERE config_key = 'propagation_paused'",
            (new_value, _utcnow_iso(), actor),
        )
        db.commit()

        record_audit(
            db,
            actor=actor,
            actor_ip=request.remote_addr,
            action_type="fleet_propagation_toggled",
            target="propagation_paused",
            details={"previous_state": current_state, "new_state": new_state},
        )
    finally:
        db.close()

    state_label = "paused" if new_state else "resumed"
    flash(f"Fleet propagation {state_label}.", "success")

    # If HTMX request, return the updated pause toggle fragment
    if request.headers.get("HX-Request"):
        return render_template(
            "fragments/fleet_pause_toggle.html",
            propagation_paused=new_state,
        )

    return redirect(url_for("fleet_dashboard.blocks_page"))
