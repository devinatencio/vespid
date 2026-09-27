"""Intel Dashboard blueprint — intelligence search, detail, and analytics UI.

Provides web pages and HTMX fragments for searching IP intelligence records,
viewing detailed threat profiles, and analyzing aggregate threat metrics.

Endpoints:
    GET /intel                              — IP search interface
    GET /intel/ip/<ip_address>              — IP detail view
    GET /intel/ip/<ip_address>/events       — Event history fragment (HTMX)
    GET /intel/analytics                    — Analytics dashboard
    GET /intel/analytics/stats              — JSON stats endpoint
    GET /intel/analytics/top-offenders      — JSON top offenders
    GET /intel/analytics/top-countries      — JSON top countries
    GET /intel/analytics/top-asns           — JSON top ASNs
    GET /intel/analytics/data              — JSON time-series chart data

Requirements: 1, 2, 3, 4, 6, 7, 8
"""

import ipaddress as _ipaddress
import logging
import math
from datetime import UTC, datetime, timedelta
from html import escape as _escape_html

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user

from app.decorators import require_role
from app.geo import lookup as geo_lookup
from app.intel_dashboard_service import (
    execute_search,
    get_analytics_stats,
    get_blocks_vs_sightings,
    get_chart_data,
    get_event_detail,
    get_hourly_distribution,
    get_ip_events_paginated,
    get_ip_version_breakdown,
    get_recent_activity,
    get_repeat_offender_block_distribution,
    get_repeat_offenders,
    get_threat_tag_distribution,
    get_top_asns,
    get_top_countries,
    get_top_offenders,
    get_top_reporting_nodes,
    has_sightings_data,
    parse_search_query,
)
from app.intel_models import (
    delete_ip_record,
    get_attack_vectors,
    get_fleet_blocks,
    get_primary_threat_tag,
    search_ip_records,
)
from app.intel_score import compute_threat_score
from app.models import get_db, record_audit
from app.rate_limit import limiter

logger = logging.getLogger(__name__)

intel_dashboard_bp = Blueprint(
    "intel_dashboard",
    __name__,
    url_prefix="/intel",
)


# ── Search route ─────────────────────────────────────────────────────────


@intel_dashboard_bp.route("/")
@require_role("analyst")
def search_page():
    """IP intelligence search interface.

    Full page load renders search.html with the search form, filter controls,
    and results area. HTMX requests (detected via HX-Request header) return
    only the search_results.html fragment for partial page updates.

    Query parameters:
        q: Search query string (IP, prefix, CIDR, or threat tag)
        repeat_offender: Filter by repeat offender status ("true" or "false")
        geo_country: Filter by ISO 3166-1 alpha-2 country code
        min_sighting_count: Minimum total_times_seen value (integer)
        page: Page number (default 1)
        per_page: Results per page (default 50, max 200)
        sort_by: Sort column (last_seen_at, total_times_seen,
                 total_times_blocked, total_reporting_nodes)
        sort_order: Sort direction ("asc" or "desc", default "desc")

    Requirements: 1.1, 1.6, 1.7, 1.8, 1.9, 1.10, 1.11, 1.12, 1.13, 1.14,
                  6.5, 6.6, 6.8, 6.9
    """
    # Parse query parameters
    query = request.args.get("q", "").strip()
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    sort_by = request.args.get("sort_by", "last_seen_at").strip()
    sort_order = request.args.get("sort_order", "desc").strip()

    # Clamp pagination values
    page = max(1, page)
    per_page = max(1, min(200, per_page))

    # Build filters dict from query params
    filters = {}

    repeat_offender = request.args.get("repeat_offender", "").strip()
    if repeat_offender == "true":
        filters["repeat_offender"] = True
    elif repeat_offender == "false":
        filters["repeat_offender"] = False

    geo_country = request.args.get("geo_country", "").strip()
    if geo_country:
        filters["geo_country"] = geo_country

    min_sighting_count = request.args.get("min_sighting_count", "").strip()
    if min_sighting_count:
        try:
            count_val = int(min_sighting_count)
            if 1 <= count_val <= 999999:
                filters["min_sighting_count"] = count_val
        except (ValueError, TypeError):
            pass

    results = []
    total = 0
    total_pages = 0
    error = None
    query_type = None

    # Always show results on the search page — even with no query/filters
    should_search = True

    if query:
        # Validate query first
        parsed = parse_search_query(query)
        query_type = parsed["query_type"]
        if parsed["query_type"] == "invalid":
            error = parsed["error"]
        else:
            try:
                db_path = current_app.config["DATABASE_PATH"]
                db = get_db(db_path)
                try:
                    results, total = execute_search(
                        db,
                        query,
                        filters=filters,
                        page=page,
                        per_page=per_page,
                        sort_by=sort_by,
                        sort_order=sort_order,
                    )
                    for r in results:
                        recency = _compute_recency(db, r["ip_address"])
                        score_input = dict(r)
                        score_input.update(recency)
                        try:
                            r["reputation_score"] = compute_threat_score(score_input)
                        except Exception:
                            logger.exception(
                                "Failed to compute threat score for IP %s", r.get("ip_address")
                            )
                            r["reputation_score"] = None
                        r["primary_threat_tag"] = get_primary_threat_tag(db, r["ip_address"])
                finally:
                    db.close()
                total_pages = max(1, math.ceil(total / per_page)) if total > 0 else 0
            except Exception as exc:
                logger.exception("Search failed for query %r: %s", query, exc)
                error = "Search could not be completed. Please try again."
    elif should_search:
        # Filter-only or no-filter search — show all matching IPs
        try:
            db_path = current_app.config["DATABASE_PATH"]
            db = get_db(db_path)
            try:
                results, total = search_ip_records(
                    db,
                    filters=filters,
                    page=page,
                    per_page=per_page,
                    sort_by=sort_by,
                    sort_order=sort_order,
                )
                for r in results:
                    recency = _compute_recency(db, r["ip_address"])
                    score_input = dict(r)
                    score_input.update(recency)
                    try:
                        r["reputation_score"] = compute_threat_score(score_input)
                    except Exception:
                        logger.exception(
                            "Failed to compute threat score for IP %s", r.get("ip_address")
                        )
                        r["reputation_score"] = None
                    r["primary_threat_tag"] = get_primary_threat_tag(db, r["ip_address"])
            finally:
                db.close()
            total_pages = max(1, math.ceil(total / per_page)) if total > 0 else 0
        except Exception as exc:
            logger.exception("Filter search failed: %s", exc)
            error = "Search could not be completed. Please try again."

    # Template context shared between full page and HTMX fragment
    context = {
        "query": query,
        "query_type": query_type,
        "filters": {
            "repeat_offender": repeat_offender,
            "geo_country": geo_country,
            "min_sighting_count": min_sighting_count,
        },
        "results": results,
        "total": total,
        "page": page,
        "per_page": per_page,
        "total_pages": total_pages,
        "sort_by": sort_by,
        "sort_order": sort_order,
        "error": error,
    }

    # HTMX request — return only the search results fragment
    if request.headers.get("HX-Request"):
        return render_template("intel/fragments/search_results.html", **context)

    return render_template("intel/search.html", **context)


# ── IP Detail View ───────────────────────────────────────────────────────


@intel_dashboard_bp.route("/ip/<ip_address>")
@require_role("analyst")
def ip_detail(ip_address):
    """IP detail view showing full threat profile for a single IP.

    Validates the IP format, fetches the record from the intelligence
    database, computes recency counters, and renders the detail template.

    Handles:
    - Malformed IP → error template with back-to-search link
    - IP not found → not-found template with back-to-search link
    - Success → full detail template with all intelligence data

    Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 2.10,
                  2.11, 2.12, 2.13, 2.14, 2.15
    """
    # Validate IP address format
    try:
        _ipaddress.ip_address(ip_address)
    except ValueError:
        return render_template(
            "intel/ip_detail.html",
            record=None,
            error="malformed_ip",
            ip_address=ip_address,
        )

    # Fetch the IP record via service layer (exact IP search)
    try:
        db_path = current_app.config["DATABASE_PATH"]
        db = get_db(db_path)
        try:
            results, total = execute_search(
                db,
                ip_address,
                filters={},
                page=1,
                per_page=1,
                sort_by="last_seen_at",
                sort_order="desc",
            )

            if not results:
                return render_template(
                    "intel/ip_detail.html",
                    record=None,
                    error="not_found",
                    ip_address=ip_address,
                )

            record = results[0]

            # GeoIP fallback: if geo_country, asn, or isp_organization are
            # missing from the record, attempt a live lookup to fill them in
            # for display purposes.
            if (
                not record.get("geo_country")
                or not record.get("asn")
                or not record.get("isp_organization")
            ):
                geo = geo_lookup(ip_address)
                if geo.get("country") and not record.get("geo_country"):
                    record["geo_country"] = geo["country"]
                if geo.get("asn") and not record.get("asn"):
                    record["asn"] = geo["asn"]
                if geo.get("org") and not record.get("isp_organization"):
                    record["isp_organization"] = geo["org"]

            # Compute recency counters from event history
            recency = _compute_recency(db, ip_address)

            # Compute reputation score at read time
            score_input = dict(record)
            score_input.update(recency)
            try:
                record["reputation_score"] = compute_threat_score(score_input)
            except Exception:
                logger.error("Score computation failed for %s", ip_address, exc_info=True)
                record["reputation_score"] = None

            # Fetch initial page of events for the detail view
            events, events_total = get_ip_events_paginated(
                db, ip_address, page=1, per_page=50, exclude_kinds=["fleet_block"]
            )
            events_total_pages = max(1, math.ceil(events_total / 50)) if events_total > 0 else 0

            # Fetch attack vectors (distinct detection rules with fire counts)
            attack_vectors = get_attack_vectors(db, ip_address)

            # Only show Fleet Blocks section if there's a currently active
            # fleet block for this IP (prevents stale entries from showing
            # after a block has expired or been removed)
            has_active_fleet_block = db.execute(
                "SELECT 1 FROM fleet_blocks WHERE source_ip = ? AND status = 'active' LIMIT 1",
                (ip_address,),
            ).fetchone()

            if has_active_fleet_block:
                fleet_blocks = get_fleet_blocks(db, ip_address)
            else:
                fleet_blocks = []

        finally:
            db.close()

    except Exception as exc:
        logger.exception("IP detail load failed for %s: %s", ip_address, exc)
        return render_template(
            "intel/ip_detail.html",
            record=None,
            error="db_error",
            ip_address=ip_address,
        )

    return render_template(
        "intel/ip_detail.html",
        record=record,
        error=None,
        ip_address=ip_address,
        recency=recency,
        events=events,
        events_total=events_total,
        events_page=1,
        events_total_pages=events_total_pages,
        attack_vectors=attack_vectors,
        fleet_blocks=fleet_blocks,
    )


@intel_dashboard_bp.route("/ip/<ip_address>/events")
@require_role("analyst")
def ip_events_fragment(ip_address):
    """HTMX fragment returning paginated event history for an IP.

    Query params:
        page: Page number (default 1)
        per_page: Results per page (default 50, max 200)

    Returns the event_history.html fragment for HTMX swap.

    Requirements: 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 8.7
    """
    # Validate IP address format
    try:
        _ipaddress.ip_address(ip_address)
    except ValueError:
        return render_template(
            "intel/fragments/event_history.html",
            events=[],
            events_total=0,
            events_page=1,
            events_total_pages=0,
            ip_address=ip_address,
            error="malformed_ip",
        )

    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)

    # Clamp pagination values
    page = max(1, page)
    per_page = max(1, min(200, per_page))

    try:
        db_path = current_app.config["DATABASE_PATH"]
        db = get_db(db_path)
        try:
            events, events_total = get_ip_events_paginated(
                db, ip_address, page=page, per_page=per_page, exclude_kinds=["fleet_block"]
            )
        finally:
            db.close()
    except Exception as exc:
        logger.exception("Event history load failed for %s: %s", ip_address, exc)
        events = []
        events_total = 0

    events_total_pages = max(1, math.ceil(events_total / per_page)) if events_total > 0 else 0

    return render_template(
        "intel/fragments/event_history.html",
        events=events,
        events_total=events_total,
        events_page=page,
        events_total_pages=events_total_pages,
        ip_address=ip_address,
        error=None,
    )


@intel_dashboard_bp.route("/ip/<ip_address>/delete", methods=["POST"])
@require_role("admin")
def ip_delete(ip_address):
    """Delete an IP record and all associated intelligence data.

    Removes the IP from ip_intel and all its events from ip_intel_events.
    Requires admin role. Redirects to the intel search page on success.
    """
    # Validate IP address format
    try:
        _ipaddress.ip_address(ip_address)
    except ValueError:
        flash(f"Invalid IP address: {ip_address}", "error")
        return redirect(url_for("intel_dashboard.search_page"))

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        ip_count, event_count = delete_ip_record(db, ip_address)

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="intel_ip_delete",
            target=ip_address,
            details={
                "ip_records_deleted": ip_count,
                "event_records_deleted": event_count,
            },
        )
    finally:
        db.close()

    flash(
        f"IP {ip_address} deleted: {ip_count} IP record and {event_count} event"
        f"{'s' if event_count != 1 else ''} removed.",
        "success",
    )
    return redirect(url_for("intel_dashboard.search_page"))


# ── Helper Functions ─────────────────────────────────────────────────────


def _compute_recency(conn, ip_address: str) -> dict:
    """Compute recency counters for an IP address.

    Counts events in the ip_intel_events table within the last 24 hours,
    7 days, and 30 days.

    Args:
        conn: Database connection.
        ip_address: The IP address to compute recency for.

    Returns:
        dict with keys: times_seen_last_24h, times_seen_last_7d, times_seen_last_30d
    """
    now = datetime.now(UTC)
    boundary_24h = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%S")
    boundary_7d = (now - timedelta(days=7)).strftime("%Y-%m-%dT%H:%M:%S")
    boundary_30d = (now - timedelta(days=30)).strftime("%Y-%m-%dT%H:%M:%S")

    cursor = conn.execute(
        "SELECT "
        "SUM(CASE WHEN timestamp >= ? THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN timestamp >= ? THEN 1 ELSE 0 END), "
        "SUM(CASE WHEN timestamp >= ? THEN 1 ELSE 0 END) "
        "FROM ip_intel_events WHERE ip_address = ? AND event_kind IN ('block', 'sighting')",
        (boundary_24h, boundary_7d, boundary_30d, ip_address),
    )
    row = cursor.fetchone()

    return {
        "times_seen_last_24h": (row[0] or 0) if row else 0,
        "times_seen_last_7d": (row[1] or 0) if row else 0,
        "times_seen_last_30d": (row[2] or 0) if row else 0,
    }


# ── Analytics routes ─────────────────────────────────────────────────────

# Valid interval values for chart data endpoint
_VALID_INTERVALS = {"7d", "30d", "90d"}


@intel_dashboard_bp.route("/analytics")
@require_role("analyst")
def analytics_page():
    """Analytics dashboard page.

    Renders the full analytics template with stats cards, ranked lists,
    and Chart.js chart canvases. Chart data is loaded via JavaScript
    from the JSON endpoints.

    Requirements: 3.1, 3.9
    """
    return render_template("intel/analytics.html")


@intel_dashboard_bp.route("/analytics/stats")
@require_role("analyst")
@limiter.limit("60/minute")
def analytics_stats():
    """Return JSON aggregate stats for the analytics dashboard.

    Returns:
        JSON with: total_ips_tracked, new_ips_24h, new_ips_7d, new_ips_30d,
        total_repeat_offenders, repeat_offender_percentage

    Requirements: 3.2, 3.3, 3.8, 7.1, 7.8
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        stats = get_analytics_stats(db)
    except Exception as exc:
        logger.exception("Failed to load analytics stats: %s", exc)
        return jsonify({"error": "Analytics data could not be loaded"}), 500
    finally:
        db.close()

    return jsonify(stats)


@intel_dashboard_bp.route("/analytics/top-offenders")
@require_role("analyst")
@limiter.limit("60/minute")
def analytics_top_offenders():
    """Return JSON top offending IPs sorted by total_times_seen descending.

    Returns:
        JSON array of objects with: ip_address, total_times_seen, last_seen_at

    Requirements: 3.4, 7.2, 7.8
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        offenders = get_top_offenders(db)
    except Exception as exc:
        logger.exception("Failed to load top offenders: %s", exc)
        return jsonify({"error": "Analytics data could not be loaded"}), 500
    finally:
        db.close()

    return jsonify(offenders)


@intel_dashboard_bp.route("/analytics/repeat-offenders")
@require_role("analyst")
@limiter.limit("60/minute")
def analytics_repeat_offenders():
    """Return paginated list of repeat offenders.

    HTMX requests return the repeat_offenders_list.html fragment.
    Regular requests return JSON.

    Query parameters:
        page: Page number (default 1)
        per_page: Results per page (default 50, max 200)

    Requirements: 3.8
    """
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 20, type=int)
    block_count = request.args.get("block_count", type=int)
    page = max(1, page)
    per_page = max(1, min(200, per_page))

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        offenders, total = get_repeat_offenders(
            db, page=page, per_page=per_page, block_count=block_count
        )
        distribution = get_repeat_offender_block_distribution(db)
    except Exception as exc:
        logger.exception("Failed to load repeat offenders: %s", exc)
        if request.headers.get("HX-Request"):
            return (
                '<p class="text-muted" style="text-align:center; padding:2rem;">Failed to load repeat offenders.</p>',
                500,
            )
        return jsonify({"error": "Analytics data could not be loaded"}), 500
    finally:
        db.close()

    total_pages = max(1, math.ceil(total / per_page)) if total > 0 else 0

    if request.headers.get("HX-Request"):
        return render_template(
            "intel/fragments/repeat_offenders_list.html",
            offenders=offenders,
            page=page,
            per_page=per_page,
            total=total,
            total_pages=total_pages,
            distribution=distribution,
            block_count=block_count,
        )

    return jsonify(
        {
            "offenders": offenders,
            "page": page,
            "per_page": per_page,
            "total": total,
            "total_pages": total_pages,
            "distribution": distribution,
            "block_count": block_count,
        }
    )


@intel_dashboard_bp.route("/analytics/top-countries")
@require_role("analyst")
@limiter.limit("60/minute")
def analytics_top_countries():
    """Return JSON top countries by IP count.

    Returns:
        JSON array of objects with: country_code, country_name, ip_count, percentage

    Requirements: 3.5, 7.3, 7.8
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        countries = get_top_countries(db)
    except Exception as exc:
        logger.exception("Failed to load top countries: %s", exc)
        return jsonify({"error": "Analytics data could not be loaded"}), 500
    finally:
        db.close()

    return jsonify(countries)


@intel_dashboard_bp.route("/analytics/top-asns")
@require_role("analyst")
@limiter.limit("60/minute")
def analytics_top_asns():
    """Return JSON top ASNs by IP count.

    Returns:
        JSON array of objects with: asn, isp_organization, ip_count

    Requirements: 3.6, 7.4, 7.8
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        asns = get_top_asns(db)
    except Exception as exc:
        logger.exception("Failed to load top ASNs: %s", exc)
        return jsonify({"error": "Analytics data could not be loaded"}), 500
    finally:
        db.close()

    return jsonify(asns)


@intel_dashboard_bp.route("/analytics/data")
@require_role("analyst")
@limiter.limit("60/minute")
def analytics_chart_data():
    """Return JSON time-series data for Chart.js charts.

    Query parameters:
        interval: Time range — "7d", "30d", or "90d" (default "30d")

    Returns:
        JSON with: labels (date strings), datasets (new_ips, sightings,
        blocklist_growth arrays)

    Error responses:
        400: Invalid interval parameter
        500: Database error

    Requirements: 4.1, 4.2, 4.4, 4.7, 4.8, 7.5, 7.6, 7.8
    """
    interval = request.args.get("interval", "30d").strip()

    # Validate interval parameter
    if interval not in _VALID_INTERVALS:
        return jsonify({"error": "Invalid interval. Accepted values: 7d, 30d, 90d"}), 400

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        chart_data = get_chart_data(db, interval)
    except ValueError as exc:
        logger.error("Invalid chart data request: %s", exc)
        return jsonify({"error": "Invalid chart data parameters"}), 400
    except Exception as exc:
        logger.exception("Failed to load chart data: %s", exc)
        return jsonify({"error": "Analytics data could not be loaded"}), 500
    finally:
        db.close()

    return jsonify(chart_data)


@intel_dashboard_bp.route("/analytics/recent-activity")
@require_role("analyst")
@limiter.limit("60/minute")
def analytics_recent_activity():
    """Return JSON list of most recent intel events.

    Query parameters:
        limit: Maximum number of events (default 20, max 100)

    Returns:
        JSON array of objects with: ip_address, event_type, event_kind,
        timestamp, node_id, geo_country, detection_rule
    """
    limit = request.args.get("limit", 20, type=int)
    limit = max(1, min(100, limit))

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        activity = get_recent_activity(db, limit=limit)
    except Exception as exc:
        logger.exception("Failed to load recent activity: %s", exc)
        return jsonify({"error": "Analytics data could not be loaded"}), 500
    finally:
        db.close()

    return jsonify(activity)


@intel_dashboard_bp.route("/analytics/event-detail/<int:event_id>")
@require_role("analyst")
@limiter.limit("60/minute")
def analytics_event_detail(event_id: int):
    """Return HTML fragment for a single intel event detail modal.

    Matches the rendering style of the main page's event_detail_modal.

    Args:
        event_id: The ip_intel_events row ID.
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        event = get_event_detail(db, event_id)
    except Exception as exc:
        logger.exception("Failed to load event detail: %s", exc)
        return (
            '<div class="error" style="text-align:center;padding:2rem;color:#ef4444;">Event detail could not be loaded.</div>',
            500,
        )
    finally:
        db.close()

    if not event:
        return '<div class="event-modal-loading">Event not found.</div>', 404

    parts = []

    # -- Event metadata section --
    parts.append('<div class="event-modal-section">')
    parts.append('<div class="event-modal-section-title">Event Information</div>')
    parts.append('<div class="event-modal-meta">')

    meta_items = [
        ("Event ID", str(event["id"])),
        (
            "IP Address",
            f'<a href="/intel/ip/{_escape_html(event["ip_address"])}"><code>{_escape_html(event["ip_address"])}</code></a>',
        ),
        ("Event Kind", '<span style="color:#ef4444;font-weight:600;">BLOCK</span>'),
        ("Event Type", _escape_html(event["event_type"] or "—")),
        ("Detection Rule", _escape_html(event["detection_rule"] or "—")),
        (
            "Timestamp",
            f'<span data-ts="{_escape_html(event["timestamp"] or "")}">{_escape_html(event["timestamp"] or "—")}</span>',
        ),
        ("Node", f"<code>{_escape_html(event['node_display'] or event['node_id'] or '—')}</code>"),
        ("Country", _escape_html(event["geo_country"] or "—")),
        ("Block TTL", f"{event['block_ttl_seconds']}s" if event.get("block_ttl_seconds") else "—"),
        ("Request Count", str(event["request_count"] or "—")),
    ]
    if event.get("event_id"):
        meta_items.append(("Event UUID", f"<code>{_escape_html(event['event_id'])}</code>"))

    for label, value in meta_items:
        parts.append(
            f'<div class="event-modal-meta-item">'
            f'<span class="event-modal-meta-label">{_escape_html(label)}</span>'
            f'<span class="event-modal-meta-value">{value}</span>'
            f"</div>"
        )

    parts.append("</div></div>")

    # -- Log context section --
    log_context = event.get("log_context")
    if log_context:
        total_count = sum(ln.get("repeat", 1) if isinstance(ln, dict) else 1 for ln in log_context)
        parts.append('<div class="event-modal-section">')
        parts.append(
            f'<div class="event-modal-section-title">Surrounding Log Context ({total_count} lines)</div>'
        )
        parts.append('<pre class="event-modal-log-lines">')
        for ln in log_context:
            if isinstance(ln, dict):
                raw = ln.get("raw", "")
                repeat = ln.get("repeat", 1)
                is_trigger = ln.get("trigger", False)
                prefix = f"<b>\u00d7{repeat}</b>  " if repeat > 1 else ""
                cls = ' class="log-line-trigger"' if is_trigger else ""
                parts.append(f"<span{cls}>{prefix}{_escape_html(raw)}</span>\n")
            else:
                parts.append(f"<span>{_escape_html(str(ln))}</span>\n")
        parts.append("</pre>")
        parts.append("</div>")
    else:
        parts.append('<div class="event-modal-section">')
        parts.append('<div class="event-modal-section-title">Log Context</div>')
        parts.append(
            '<p style="color:var(--text-muted);font-size:0.8rem;">No surrounding log context available for this event.</p>'
        )
        parts.append("</div>")

    return "".join(parts)


@intel_dashboard_bp.route("/analytics/threat-tags")
@require_role("analyst")
@limiter.limit("60/minute")
def analytics_threat_tags():
    """Return JSON distribution of threat tags by IP count.

    Returns:
        JSON array of objects with: tag, ip_count
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        tags = get_threat_tag_distribution(db)
    except Exception as exc:
        logger.exception("Failed to load threat tag distribution: %s", exc)
        return jsonify({"error": "Analytics data could not be loaded"}), 500
    finally:
        db.close()

    return jsonify(tags)


@intel_dashboard_bp.route("/analytics/hourly-distribution")
@require_role("analyst")
@limiter.limit("60/minute")
def analytics_hourly_distribution():
    """Return JSON array of event counts by hour of day (0-23).

    Returns:
        JSON array of 24 integers representing event counts for each hour
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        hourly = get_hourly_distribution(db)
    except Exception as exc:
        logger.exception("Failed to load hourly distribution: %s", exc)
        return jsonify({"error": "Analytics data could not be loaded"}), 500
    finally:
        db.close()

    return jsonify(hourly)


@intel_dashboard_bp.route("/analytics/ip-versions")
@require_role("analyst")
@limiter.limit("60/minute")
def analytics_ip_versions():
    """Return JSON breakdown of IPv4 vs IPv6 addresses.

    Returns:
        JSON with: ipv4_count, ipv6_count, ipv4_percentage, ipv6_percentage
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        breakdown = get_ip_version_breakdown(db)
    except Exception as exc:
        logger.exception("Failed to load IP version breakdown: %s", exc)
        return jsonify({"error": "Analytics data could not be loaded"}), 500
    finally:
        db.close()

    return jsonify(breakdown)


@intel_dashboard_bp.route("/analytics/top-nodes")
@require_role("analyst")
@limiter.limit("60/minute")
def analytics_top_nodes():
    """Return JSON top reporting nodes by event count.

    Returns:
        JSON array of objects with: node_id, event_count
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        nodes = get_top_reporting_nodes(db)
    except Exception as exc:
        logger.exception("Failed to load top reporting nodes: %s", exc)
        return jsonify({"error": "Analytics data could not be loaded"}), 500
    finally:
        db.close()

    return jsonify(nodes)


@intel_dashboard_bp.route("/analytics/event-breakdown")
@require_role("analyst")
@limiter.limit("60/minute")
def analytics_event_breakdown():
    """Return JSON breakdown of blocks vs sightings.

    Returns:
        JSON with: blocks, sightings, blocks_percentage, sightings_percentage
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        breakdown = get_blocks_vs_sightings(db)
    except Exception as exc:
        logger.exception("Failed to load event breakdown: %s", exc)
        return jsonify({"error": "Analytics data could not be loaded"}), 500
    finally:
        db.close()

    return jsonify(breakdown)


@intel_dashboard_bp.route("/analytics/has-sightings")
@require_role("analyst")
@limiter.limit("60/minute")
def analytics_has_sightings():
    """Check if sightings data exists in the database.

    Returns:
        JSON with: has_sightings (boolean)
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        has_data = has_sightings_data(db)
    except Exception as exc:
        logger.exception("Failed to check sightings data: %s", exc)
        return jsonify({"error": "Analytics data could not be loaded"}), 500
    finally:
        db.close()

    return jsonify({"has_sightings": has_data})


# ── Admin routes ─────────────────────────────────────────────────────────


@intel_dashboard_bp.route("/admin")
@require_role("admin")
def admin_page():
    """Intel database administration page.

    Provides controls for purging and backfilling the intelligence database.
    Shows current record counts and last backfill status.
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        # Get current counts
        ip_count = db.execute("SELECT COUNT(*) FROM ip_intel").fetchone()[0]
        event_count = db.execute("SELECT COUNT(*) FROM ip_intel_events").fetchone()[0]

        # Get count of BLOCKED events in the main events table (potential backfill source)
        blocked_24h = _count_blocked_events(db, hours=24)
        blocked_7d = _count_blocked_events(db, hours=168)
        blocked_all = _count_blocked_events(db, hours=None)

        # Get counts for NFT_ACTION only
        nft_24h = _count_blocked_events(db, hours=24, event_type="NFT_ACTION")
        nft_7d = _count_blocked_events(db, hours=168, event_type="NFT_ACTION")
        nft_all = _count_blocked_events(db, hours=None, event_type="NFT_ACTION")
    finally:
        db.close()

    return render_template(
        "intel/admin.html",
        ip_count=ip_count,
        event_count=event_count,
        blocked_24h=blocked_24h,
        blocked_7d=blocked_7d,
        blocked_all=blocked_all,
        nft_24h=nft_24h,
        nft_7d=nft_7d,
        nft_all=nft_all,
    )


@intel_dashboard_bp.route("/admin/purge", methods=["POST"])
@require_role("admin")
def admin_purge():
    """Purge all records from the intelligence database.

    Deletes all rows from ip_intel and ip_intel_events tables.
    This is a destructive operation requiring admin role.
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        # Get counts before purge for audit log
        ip_count = db.execute("SELECT COUNT(*) FROM ip_intel").fetchone()[0]
        event_count = db.execute("SELECT COUNT(*) FROM ip_intel_events").fetchone()[0]

        # Purge both tables
        db.execute("DELETE FROM ip_intel_events")
        db.execute("DELETE FROM ip_intel")
        db.commit()

        # Record audit log
        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="intel_purge",
            target="ip_intel",
            details={
                "ip_records_deleted": ip_count,
                "event_records_deleted": event_count,
            },
        )
    finally:
        db.close()

    flash(
        f"Intelligence database purged: {ip_count} IP records and {event_count} event records deleted.",
        "success",
    )
    return redirect(url_for("intel_dashboard.admin_page"))


@intel_dashboard_bp.route("/admin/backfill", methods=["POST"])
@require_role("admin")
def admin_backfill():
    """Backfill intelligence database from historical BLOCKED events.

    Scans the events table for BLOCKED events within the specified time
    range and upserts them into the intelligence database.

    Form parameters:
        hours: Number of hours to look back (24, 168, or 'all')
    """
    from app.intel_service import ValidationError, process_block_event

    hours_param = request.form.get("hours", "24").strip()
    event_type_filter = request.form.get("event_type", "").strip() or None

    if hours_param == "all":
        hours = None
    else:
        try:
            hours = int(hours_param)
            if hours not in (24, 168):
                hours = 24
        except (ValueError, TypeError):
            hours = 24

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        # Fetch BLOCKED events from the events table
        events = _fetch_blocked_events(db, hours=hours, event_type=event_type_filter)

        processed = 0
        skipped = 0
        errors = 0

        for ev in events:
            try:
                # Build intel payload from event
                metadata = ev.get("metadata") or {}
                if isinstance(metadata, str):
                    import json

                    try:
                        metadata = json.loads(metadata)
                    except (json.JSONDecodeError, TypeError):
                        metadata = {}

                intel_payload = {
                    "source_ip": ev.get("source_ip", ""),
                    "node_id": ev.get("node_id", ""),
                    "event_type": ev.get("event_type", ""),
                    "timestamp": ev.get("timestamp", ""),
                    "detection_rule": metadata.get("detection_rule_name", ""),
                    "block_ttl_seconds": metadata.get("block_ttl_seconds", 0),
                    "metadata": {
                        "geo_country": ev.get("geo_country"),
                        "asn": _parse_asn_number(ev.get("geo_asn")),
                        "isp_organization": ev.get("geo_org"),
                        "threat_tag": metadata.get("threat_tag"),
                    },
                }
                if metadata.get("threat_tag"):
                    intel_payload["threat_tag"] = metadata["threat_tag"]

                process_block_event(db, intel_payload)
                processed += 1

            except ValidationError:
                skipped += 1
            except Exception as exc:
                logger.warning("Backfill error for event %s: %s", ev.get("event_id"), exc)
                errors += 1

        # Record audit log
        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="intel_backfill",
            target="ip_intel",
            details={
                "hours": hours if hours else "all",
                "event_type_filter": event_type_filter or "all",
                "events_scanned": len(events),
                "processed": processed,
                "skipped": skipped,
                "errors": errors,
            },
        )
    finally:
        db.close()

    time_desc = f"last {hours} hours" if hours else "all time"
    filter_desc = " [NFT_ACTION only]" if event_type_filter == "NFT_ACTION" else ""
    flash(
        f"Backfill complete ({time_desc}{filter_desc}): {processed} events processed, "
        f"{skipped} skipped, {errors} errors.",
        "success",
    )
    return redirect(url_for("intel_dashboard.admin_page"))


def _count_blocked_events(db, hours: int | None, event_type: str | None = None) -> int:
    """Count BLOCKED events in the events table within the time range.

    Args:
        db: Database connection.
        hours: Number of hours to look back, or None for all time.
        event_type: Optional event_type filter (e.g. 'NFT_ACTION').
    """
    conditions = ["action_taken = 'BLOCKED'"]
    params: list = []

    if event_type:
        conditions.append("event_type = ?")
        params.append(event_type)

    if hours is not None:
        cutoff = (datetime.now(UTC) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        conditions.append("timestamp >= ?")
        params.append(cutoff)

    where = " AND ".join(conditions)
    row = db.execute(f"SELECT COUNT(*) FROM events WHERE {where}", params).fetchone()
    return row[0] if row else 0


def _fetch_blocked_events(db, hours: int | None, event_type: str | None = None) -> list[dict]:
    """Fetch BLOCKED events from the events table within the time range.

    Args:
        db: Database connection.
        hours: Number of hours to look back, or None for all time.
        event_type: Optional event_type filter (e.g. 'NFT_ACTION').
    """
    conditions = ["action_taken = 'BLOCKED'"]
    params: list = []

    if event_type:
        conditions.append("event_type = ?")
        params.append(event_type)

    if hours is not None:
        cutoff = (datetime.now(UTC) - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        conditions.append("timestamp >= ?")
        params.append(cutoff)

    where = " AND ".join(conditions)
    rows = db.execute(
        "SELECT event_id, node_id, timestamp, source_ip, event_type, "
        "action_taken, geo_country, geo_asn, geo_org, metadata "
        f"FROM events WHERE {where} "
        "ORDER BY timestamp ASC",
        params,
    ).fetchall()

    return [dict(r) for r in rows]


def _parse_asn_number(asn_str) -> int | None:
    """Parse ASN number from string like 'AS12345' or '12345'."""
    if asn_str is None:
        return None
    if isinstance(asn_str, int):
        return asn_str
    asn_str = str(asn_str).strip().upper()
    if asn_str.startswith("AS"):
        asn_str = asn_str[2:]
    try:
        return int(asn_str)
    except (ValueError, TypeError):
        return None


@intel_dashboard_bp.route("/api/quick-search")
@require_role("viewer")
def quick_search():
    """Autocomplete endpoint for the nav search bar.

    Returns up to 8 matching IPs from the intelligence database ordered by
    most recently seen, plus threat indicators for display in the dropdown.
    """
    q = request.args.get("q", "").strip()
    if len(q) < 1:
        return jsonify({"results": []})

    db = get_db(current_app.config["DATABASE_PATH"])
    try:
        rows = db.execute(
            "SELECT ip_address, total_times_blocked, repeat_offender, "
            "last_seen_at, geo_country "
            "FROM ip_intel WHERE ip_address LIKE ? "
            "ORDER BY last_seen_at DESC LIMIT 8",
            (q + "%",),
        ).fetchall()
        results = [dict(r) for r in rows]
        # Ensure booleans are JSON-friendly
        for r in results:
            r["repeat_offender"] = bool(r.get("repeat_offender", 0))
    finally:
        db.close()

    return jsonify({"results": results})
