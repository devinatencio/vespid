"""Intelligence API blueprint — sighting/block ingestion and IP query endpoints.

Endpoints:
    POST /api/v1/intel/sightings       — Submit a single sighting (Bearer auth)
    POST /api/v1/intel/blocks          — Submit a single block event (Bearer auth)
    POST /api/v1/intel/batch           — Submit up to 500 events (Bearer auth)
    GET  /api/v1/intel/ips             — Query IP records (Session/Bearer auth)
    GET  /api/v1/intel/ips/<ip>        — Get single IP record (Session/Bearer auth)
    GET  /api/v1/intel/blocklist       — Export IP blocklist (Session/Bearer auth)

Requirements: 2.8, 2.9, 2.10, 3.1, 3.6, 3.7, 3.8, 5.1, 5.2, 5.3, 5.4,
              5.5, 5.6, 5.7, 5.8, 5.9, 8.5, 8.6, 9.1, 9.2, 9.3, 9.4,
              9.5, 9.6, 11.1, 11.2, 11.3, 11.5, 11.6, 11.7, 11.9, 11.10
"""

import logging

from flask import Response, jsonify, request
from flask_login import current_user
from flask_openapi3 import APIBlueprint
from flask_openapi3.models import Tag

from app.intel_service import (
    ValidationError,
    process_batch,
    process_block_event,
    process_sighting,
    query_ip_record,
    query_ip_records,
)
from app.models import get_request_db
from app.openapi_models import IPIntelQueryResponse
from app.rate_limit import limiter
from app.routes.auth import authenticate_bearer_token

logger = logging.getLogger(__name__)

intel_bp = APIBlueprint("intel", __name__, url_prefix="/api/v1/intel")

_intel_tag = [Tag(name="Intelligence", description="IP reputation and threat intelligence")]
_either_auth = [{"SessionAuth": []}, {"BearerAuth": []}]


# ---------------------------------------------------------------------------
# Authentication helpers
# ---------------------------------------------------------------------------


_authenticate_api_key = authenticate_bearer_token


def _authenticate_session_or_bearer():
    """Authenticate using session cookie OR Bearer token.

    For query endpoints that support both session-based (operator UI)
    and Bearer token (programmatic) authentication.

    Returns:
        A tuple of (authenticated, error_response). If authentication
        succeeds, error_response is None. If it fails, authenticated is
        False and error_response is a Flask response tuple.
    """
    # Check session auth first (Flask-Login)
    if current_user.is_authenticated:
        return True, None

    # Fall back to Bearer token
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        api_key, error_response = _authenticate_api_key()
        if error_response is not None:
            return False, error_response
        return True, None

    # Neither session nor Bearer token present
    return False, (
        jsonify({"error": "unauthorized", "message": "Authentication required"}),
        401,
    )


def _check_analyst_role():
    """Check that the current user has analyst+ role.

    For session-authenticated users, checks the role hierarchy.
    Bearer-authenticated requests (from nodes) are assumed to have
    sufficient privileges for query endpoints.

    Returns:
        An error response tuple if forbidden, or None if authorized.
    """
    # If authenticated via session, check role
    if current_user.is_authenticated:
        role_hierarchy = {"admin": 3, "analyst": 2, "viewer": 1}
        user_level = role_hierarchy.get(current_user.role, 0)
        required_level = role_hierarchy.get("analyst", 2)
        if user_level < required_level:
            return (
                jsonify(
                    {
                        "error": "forbidden",
                        "message": "Insufficient permissions. Analyst role or higher required.",
                    }
                ),
                403,
            )
    return None


# ---------------------------------------------------------------------------
# Submission endpoints (Bearer auth only)
# ---------------------------------------------------------------------------


@intel_bp.route("/sightings", methods=["POST"])
@limiter.limit("120 per minute")
def submit_sighting():
    """Submit a single sighting observation.

    Authenticates via Bearer token, validates the payload, processes
    the sighting, and returns the updated counter.

    Requirements: 2.8, 2.9, 2.10, 9.1, 9.3
    """
    api_key, error_response = _authenticate_api_key()
    if error_response is not None:
        return error_response

    # Parse JSON body
    try:
        payload = request.get_json(force=True)
    except Exception:
        return jsonify(
            {"error": "validation_error", "errors": ["Request body is not valid JSON"]}
        ), 400

    if payload is None:
        return jsonify(
            {"error": "validation_error", "errors": ["Request body is not valid JSON"]}
        ), 400

    # Process sighting
    db = get_request_db()
    try:
        result = process_sighting(db, payload)
        return jsonify(result), 200
    except ValidationError as e:
        return jsonify({"error": "validation_error", "errors": e.errors}), 400
    except Exception as e:
        logger.exception("Failed to process sighting: %s", str(e))
        return jsonify(
            {
                "error": "internal_error",
                "message": "An internal error occurred while processing the sighting",
            }
        ), 500


@intel_bp.route("/blocks", methods=["POST"])
@limiter.limit("120 per minute")
def submit_block():
    """Submit a single block event.

    Authenticates via Bearer token, validates the payload, processes
    the block event, and returns the updated status.

    Requirements: 3.1, 3.6, 3.7, 3.8, 9.1, 9.3
    """
    api_key, error_response = _authenticate_api_key()
    if error_response is not None:
        return error_response

    # Parse JSON body
    try:
        payload = request.get_json(force=True)
    except Exception:
        return jsonify(
            {"error": "validation_error", "errors": ["Request body is not valid JSON"]}
        ), 400

    if payload is None:
        return jsonify(
            {"error": "validation_error", "errors": ["Request body is not valid JSON"]}
        ), 400

    # Process block event
    db = get_request_db()
    try:
        result = process_block_event(db, payload)
        return jsonify(result), 200
    except ValidationError as e:
        return jsonify({"error": "validation_error", "errors": e.errors}), 400
    except Exception as e:
        logger.exception("Failed to process block event: %s", str(e))
        return jsonify(
            {
                "error": "internal_error",
                "message": "An internal error occurred while processing the block event",
            }
        ), 500


@intel_bp.route("/batch", methods=["POST"])
@limiter.limit("20 per minute")
def submit_batch():
    """Submit a batch of up to 500 events (sightings and/or blocks).

    Authenticates via Bearer token, validates the batch envelope and
    each event independently, processes valid events, and returns
    per-event results.

    Response codes:
        200 — All events accepted
        207 — Mixed results (some accepted, some rejected)
        400 — All events rejected OR batch envelope invalid

    Requirements: 11.1, 11.2, 11.3, 11.5, 11.6, 11.7, 11.9, 11.10, 9.1
    """
    api_key, error_response = _authenticate_api_key()
    if error_response is not None:
        return error_response

    # Parse JSON body
    try:
        payload = request.get_json(force=True)
    except Exception:
        return jsonify(
            {"error": "validation_error", "errors": ["Request body is not valid JSON"]}
        ), 400

    if payload is None:
        return jsonify(
            {"error": "validation_error", "errors": ["Request body is not valid JSON"]}
        ), 400

    # Process batch
    db = get_request_db()
    try:
        result = process_batch(db, payload)

        # Determine response code based on results
        total_accepted = result["total_accepted"]
        total_rejected = result["total_rejected"]

        if total_rejected == 0:
            # All events accepted
            return jsonify(result), 200
        elif total_accepted == 0:
            # All events rejected
            return jsonify(result), 400
        else:
            # Mixed results
            return jsonify(result), 207

    except ValidationError as e:
        # Check if this is a batch_too_large error (envelope validation)
        if any("batch size" in err for err in e.errors):
            return jsonify(
                {"error": "batch_too_large", "message": "Maximum 500 events per batch"}
            ), 400
        return jsonify({"error": "validation_error", "errors": e.errors}), 400
    except Exception as e:
        logger.exception("Failed to process batch: %s", str(e))
        return jsonify(
            {
                "error": "internal_error",
                "message": "An internal error occurred while processing the batch",
            }
        ), 500


# ---------------------------------------------------------------------------
# Query endpoints (Session OR Bearer auth, analyst+ role)
# ---------------------------------------------------------------------------


@intel_bp.get(
    "/ips",
    summary="Query IP records",
    description="Query IP intelligence records with filters and pagination. "
    "Supports filtering by event type, threat tag, country, repeat offender status, and free-text search. "
    "Requires analyst+ role for session auth.",
    tags=_intel_tag,
    security=_either_auth,
    responses={200: IPIntelQueryResponse},
)
@limiter.limit("60 per minute")
def list_ips():
    """Query IP records with filters and pagination.

    Authenticates via session or Bearer token. Requires analyst+ role
    for session-authenticated users.

    Query parameters:
        - event_type: Filter by event type
        - threat_tag: Filter by threat tag
        - geo_country: Filter by ISO 3166-1 alpha-2 country code
        - repeat_offender: Filter by repeat offender flag (true/false)
        - page: Page number (default 1)
        - per_page: Results per page (default 50, max 200)
        - sort_by: Sort field (default last_seen_at)
        - sort_order: Sort direction (asc/desc, default desc)

    Requirements: 5.1, 5.2, 5.3, 5.4, 5.6, 5.7, 5.8, 5.9, 9.2, 9.4
    """
    authenticated, error_response = _authenticate_session_or_bearer()
    if error_response is not None:
        return error_response

    # Check analyst+ role for session-authenticated users
    role_error = _check_analyst_role()
    if role_error is not None:
        return role_error

    # Collect filter parameters
    filters = {}
    for key in ("event_type", "threat_tag", "geo_country", "repeat_offender", "q"):
        value = request.args.get(key)
        if value is not None:
            filters[key] = value

    # Pagination and sorting parameters
    page = request.args.get("page", 1)
    per_page = request.args.get("per_page", 50)
    sort_by = request.args.get("sort_by", "last_seen_at")
    sort_order = request.args.get("sort_order", "desc")

    # Convert page/per_page to integers
    try:
        page = int(page)
    except (ValueError, TypeError):
        return jsonify({"error": "validation_error", "errors": ["page must be an integer"]}), 400

    try:
        per_page = int(per_page)
    except (ValueError, TypeError):
        return jsonify(
            {"error": "validation_error", "errors": ["per_page must be an integer"]}
        ), 400

    # Query records
    db = get_request_db()
    try:
        result = query_ip_records(
            db,
            filters=filters,
            page=page,
            per_page=per_page,
            sort_by=sort_by,
            sort_order=sort_order,
        )
        # Map service response to API response format
        response = {
            "results": result["records"],
            "total_count": result["total_count"],
            "current_page": result["current_page"],
            "total_pages": result["total_pages"],
            "per_page": per_page,
        }
        return jsonify(response), 200
    except ValidationError as e:
        return jsonify({"error": "validation_error", "errors": e.errors}), 400
    except Exception as e:
        logger.exception("Failed to query IP records: %s", str(e))
        return jsonify(
            {
                "error": "internal_error",
                "message": "An internal error occurred while querying IP records",
            }
        ), 500


@intel_bp.route("/ips/<ip_address>", methods=["GET"])
@limiter.limit("60 per minute")
def get_ip(ip_address):
    """Get a single IP record by address.

    Authenticates via session or Bearer token. Requires analyst+ role
    for session-authenticated users.

    Requirements: 5.1, 5.5, 5.6, 5.7, 9.2, 9.4
    """
    authenticated, error_response = _authenticate_session_or_bearer()
    if error_response is not None:
        return error_response

    # Check analyst+ role for session-authenticated users
    role_error = _check_analyst_role()
    if role_error is not None:
        return role_error

    # Query single record
    db = get_request_db()
    try:
        record = query_ip_record(db, ip_address)
        if record is None:
            return jsonify({"error": "not_found", "message": "IP address not found"}), 404
        return jsonify(record), 200
    except Exception as e:
        logger.exception("Failed to query IP record for %s: %s", ip_address, str(e))
        return jsonify(
            {
                "error": "internal_error",
                "message": "An internal error occurred while querying the IP record",
            }
        ), 500


# ---------------------------------------------------------------------------
# Blocklist export endpoint (Session OR Bearer auth, analyst+ role)
# ---------------------------------------------------------------------------


@intel_bp.route("/blocklist", methods=["GET"])
@limiter.limit("30 per minute")
def export_blocklist():
    """Export the intel IP list as a plain-text blocklist (one IP per line).

    Returns all IPs tracked by the intelligence database, optionally
    filtered by minimum threat score, minimum sightings, threat tag,
    country, or repeat-offender status. Output is plain text suitable
    for ingestion by firewalls, fail2ban, or other blocklist consumers.

    Query parameters:
        - min_score: Minimum reputation score (0-100, default 0)
        - min_sightings: Minimum total_times_seen (default 1)
        - threat_tag: Filter by threat tag
        - geo_country: Filter by ISO 3166-1 alpha-2 country code
        - repeat_offender: Only repeat offenders (true/false)
        - format: Output format — 'plain' (default) or 'json'

    Authenticates via session or Bearer token. Requires analyst+ role
    for session-authenticated users.
    """
    authenticated, error_response = _authenticate_session_or_bearer()
    if error_response is not None:
        return error_response

    role_error = _check_analyst_role()
    if role_error is not None:
        return role_error

    # Parse filter parameters
    min_score = request.args.get("min_score", 0)
    min_sightings = request.args.get("min_sightings", 1)
    threat_tag = request.args.get("threat_tag", "").strip() or None
    geo_country = request.args.get("geo_country", "").strip() or None
    repeat_offender = request.args.get("repeat_offender", "").strip().lower()
    output_format = request.args.get("format", "plain").strip().lower()

    try:
        min_score = int(min_score)
    except (ValueError, TypeError):
        return jsonify(
            {"error": "validation_error", "errors": ["min_score must be an integer"]}
        ), 400

    try:
        min_sightings = int(min_sightings)
    except (ValueError, TypeError):
        return jsonify(
            {"error": "validation_error", "errors": ["min_sightings must be an integer"]}
        ), 400

    # Build SQL query
    where_clauses = ["total_times_seen >= ?"]
    params: list = [min_sightings]

    if min_score > 0:
        where_clauses.append("COALESCE(reputation_score, 0) >= ?")
        params.append(min_score)

    if threat_tag:
        where_clauses.append("threat_tags LIKE ?")
        params.append(f'%"{threat_tag}"%')

    if geo_country:
        where_clauses.append("geo_country = ?")
        params.append(geo_country)

    if repeat_offender in ("true", "1", "yes"):
        where_clauses.append("repeat_offender = 1")

    where_sql = " AND ".join(where_clauses)

    db = get_request_db()
    try:
        rows = db.execute(
            f"SELECT ip_address FROM ip_intel WHERE {where_sql} ORDER BY last_seen_at DESC",
            params,
        ).fetchall()

        ips = [row["ip_address"] for row in rows]

        if output_format == "json":
            return jsonify(
                {
                    "count": len(ips),
                    "ips": ips,
                }
            ), 200

        # Plain text: one IP per line
        body = "\n".join(ips) + ("\n" if ips else "")
        return Response(
            body,
            mimetype="text/plain",
            headers={
                "Content-Disposition": "inline; filename=blocklist.txt",
            },
        )

    except Exception as e:
        logger.exception("Failed to export blocklist: %s", str(e))
        return jsonify(
            {
                "error": "internal_error",
                "message": "An internal error occurred while exporting the blocklist",
            }
        ), 500


# ---------------------------------------------------------------------------
# Error handler for rate limiting (429)
# ---------------------------------------------------------------------------


@intel_bp.errorhandler(429)
def ratelimit_handler(e):
    """Return 429 with Retry-After header when rate limit is exceeded.

    Requirements: 9.5
    """
    response = jsonify(
        {
            "error": "rate_limited",
            "message": f"Rate limit exceeded: {e.description}",
        }
    )
    response.status_code = 429
    # Flask-Limiter sets Retry-After header automatically via the
    # app-level error handler, but we ensure it's present here too.
    response.headers["Retry-After"] = (
        str(e.retry_after) if hasattr(e, "retry_after") and e.retry_after else "60"
    )
    return response
