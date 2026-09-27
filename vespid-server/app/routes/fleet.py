"""Fleet API blueprint — fleet-wide blocklist management, SSE streaming, and config.

Endpoints:
    GET    /api/v1/fleet/blocks            — List active fleet blocks (paginated, filterable)
    POST   /api/v1/fleet/blocks            — Manually add a fleet block (admin)
    DELETE  /api/v1/fleet/blocks/<ip>       — Remove a fleet block (admin)
    GET    /api/v1/fleet/blocks/<ip>/history — Reporting history for an IP
    GET    /api/v1/fleet/blocks/stream     — Fleet SSE channel (Bearer token auth)
    GET    /api/v1/fleet/blocks/active     — All active blocks for agent initial sync (Bearer token)
    GET    /api/v1/fleet/allowlist         — List global allow-list entries
    POST   /api/v1/fleet/allowlist         — Add allow-list entry (admin)
    DELETE  /api/v1/fleet/allowlist/<id>    — Remove allow-list entry (admin)
    GET    /api/v1/fleet/config            — Get propagation config
    PUT    /api/v1/fleet/config            — Update propagation config (admin)
    POST   /api/v1/fleet/pause             — Toggle propagation pause (admin)

Requirements: 2.1, 2.2, 2.4, 2.5, 4.5, 5.2, 5.3, 5.4, 7.3, 7.4, 8.1, 8.2, 8.3, 8.4, 8.5
"""

import ipaddress
import json
import logging
import math
from datetime import UTC

from flask import Response, current_app, jsonify, request
from flask_login import current_user
from flask_openapi3 import APIBlueprint
from flask_openapi3.models import Tag

from app.decorators import require_role
from app.models import _utcnow_iso, get_request_db, record_audit
from app.openapi_models import FleetBlockListResponse
from app.propagation_engine import parse_duration
from app.rate_limit import limiter
from app.routes.auth import authenticate_bearer_token

logger = logging.getLogger(__name__)

fleet_bp = APIBlueprint("fleet", __name__, url_prefix="/api/v1/fleet")

_fleet_tag = [Tag(name="Fleet", description="Fleet-wide blocklist management")]
_session_auth = [{"SessionAuth": []}]


# ---------------------------------------------------------------------------
# Authentication helpers
# ---------------------------------------------------------------------------


_authenticate_bearer_token = authenticate_bearer_token


# ---------------------------------------------------------------------------
# Fleet Blocks endpoints
# ---------------------------------------------------------------------------


@fleet_bp.get(
    "/blocks",
    summary="List fleet blocks",
    description="List active fleet blocks with pagination and filters. "
    "Requires analyst+ role for session auth.",
    tags=_fleet_tag,
    security=_session_auth,
    responses={200: FleetBlockListResponse},
)
@limiter.limit(lambda: current_app.config.get("RATELIMIT_FLEET_BLOCKS", "60 per minute"))
@require_role("analyst")
def list_fleet_blocks():
    """List active fleet blocks with pagination and filters.

    Query params:
        page (int): Page number (default: 1)
        per_page (int): Items per page (default: 50)
        source_ip (str): Filter by source IP
        node_id (str): Filter by originating node ID
        event_type (str): Filter by event type
        status (str): Filter by status (active, expired, removed)

    Requirements: 8.1
    """
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)

    # Clamp values
    page = max(1, page)
    per_page = max(1, min(per_page, 200))

    # Build filter conditions
    conditions = []
    params = []

    source_ip = request.args.get("source_ip")
    if source_ip:
        conditions.append("source_ip = ?")
        params.append(source_ip)

    node_id = request.args.get("node_id")
    if node_id:
        conditions.append("originating_node_id = ?")
        params.append(node_id)

    event_type = request.args.get("event_type")
    if event_type:
        conditions.append("event_type = ?")
        params.append(event_type)

    status = request.args.get("status")
    if status:
        conditions.append("status = ?")
        params.append(status)

    where_clause = ""
    if conditions:
        where_clause = "WHERE " + " AND ".join(conditions)

    db = get_request_db()

    # Get total count
    count_sql = f"SELECT COUNT(*) as cnt FROM fleet_blocks {where_clause}"
    total = db.execute(count_sql, params).fetchone()["cnt"]

    # Get paginated results
    offset = (page - 1) * per_page
    query_sql = (
        f"SELECT * FROM fleet_blocks {where_clause} ORDER BY approved_at DESC LIMIT ? OFFSET ?"
    )
    rows = db.execute(query_sql, params + [per_page, offset]).fetchall()

    items = [dict(row) for row in rows]
    pages = math.ceil(total / per_page) if per_page > 0 else 0

    return jsonify(
        {
            "items": items,
            "total": total,
            "page": page,
            "per_page": per_page,
            "pages": pages,
        }
    ), 200


@fleet_bp.post(
    "/blocks",
    summary="Add fleet block",
    description="Manually add a fleet-wide block. Requires admin role.",
    tags=_fleet_tag,
    security=_session_auth,
    responses={
        201: {"description": "Block added successfully"},
        400: {"description": "Invalid request body or missing fields"},
        409: {"description": "Block already exists or was rejected"},
    },
)
@limiter.limit(lambda: current_app.config.get("RATELIMIT_FLEET_ADMIN", "30 per minute"))
@require_role("admin")
def add_fleet_block():
    """Manually add a fleet block (admin only).

    Request body (JSON):
        {
            "source_ip": "192.168.1.100",
            "reason": "Manual block for suspicious activity"
        }

    Requirements: 8.2, 8.4
    """
    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid_json", "message": "Request body is not valid JSON"}), 400

    if not body or not isinstance(body, dict):
        return jsonify({"error": "invalid_json", "message": "Request body is not valid JSON"}), 400

    source_ip = body.get("source_ip", "").strip()
    reason = body.get("reason", "").strip()

    if not source_ip:
        return jsonify({"error": "missing_field", "message": "source_ip is required"}), 400

    if not reason:
        return jsonify({"error": "missing_field", "message": "reason is required"}), 400

    # Validate IP address format
    try:
        ipaddress.ip_address(source_ip)
    except ValueError:
        return jsonify(
            {"error": "invalid_ip", "message": f"'{source_ip}' is not a valid IP address"}
        ), 400

    engine = current_app.propagation_engine
    actor = current_user.username

    result = engine.manual_add(source_ip, reason, actor)

    if result["status"] == "rejected":
        return jsonify(result), 409

    if result["status"] == "exists":
        return jsonify(result), 409

    return jsonify(result), 201


@fleet_bp.route("/blocks/<path:ip>", methods=["DELETE"])
@limiter.limit(lambda: current_app.config.get("RATELIMIT_FLEET_ADMIN", "30 per minute"))
@require_role("admin")
def remove_fleet_block(ip):
    """Remove a fleet block and publish unblock directive (admin only).

    Requirements: 8.3, 8.4
    """
    engine = current_app.propagation_engine
    actor = current_user.username

    result = engine.manual_remove(ip, actor)

    if result["status"] == "not_found":
        return jsonify(result), 404

    return jsonify(result), 200


@fleet_bp.route("/blocks/<path:ip>/reenable", methods=["POST"])
@limiter.limit(lambda: current_app.config.get("RATELIMIT_FLEET_ADMIN", "30 per minute"))
@require_role("admin")
def reenable_fleet_block(ip):
    """Re-enable an expired or removed fleet block with a fresh TTL (admin only).

    Re-activates the most recent expired/removed block for the given IP,
    resets its TTL to the current configured default, and publishes a
    block directive via SSE.

    Requirements: 8.2, 8.4
    """
    engine = current_app.propagation_engine
    actor = current_user.username

    result = engine.reenable_block(ip, actor)

    if result["status"] == "not_found":
        return jsonify(result), 404

    if result["status"] == "rejected":
        return jsonify(result), 409

    if result["status"] == "exists":
        return jsonify(result), 409

    return jsonify(result), 200


@fleet_bp.route("/blocks/<path:ip>/history", methods=["GET"])
@limiter.limit(lambda: current_app.config.get("RATELIMIT_FLEET_BLOCKS", "60 per minute"))
@require_role("analyst")
def fleet_block_history(ip):
    """Return reporting history for a specific IP.

    Requirements: 8.5
    """
    db = get_request_db()
    reports = db.execute(
        "SELECT * FROM fleet_block_reports WHERE source_ip = ? ORDER BY reported_at DESC",
        (ip,),
    ).fetchall()

    blocks = db.execute(
        "SELECT * FROM fleet_blocks WHERE source_ip = ? ORDER BY first_reported_at DESC",
        (ip,),
    ).fetchall()

    return jsonify(
        {
            "source_ip": ip,
            "reports": [dict(r) for r in reports],
            "blocks": [dict(b) for b in blocks],
        }
    ), 200


@fleet_bp.route("/blocks/stream", methods=["GET"])
@limiter.exempt
def fleet_block_stream():
    """Fleet SSE channel endpoint with Bearer token auth.

    Streams fleet block events to subscribed nodes. Supports
    Last-Event-ID for reconnection replay and sends keepalive
    comments every 15 seconds.

    Requirements: 2.1, 2.4, 2.5
    """
    api_key, error_response = _authenticate_bearer_token()
    if error_response is not None:
        return error_response

    last_event_id = request.headers.get("Last-Event-ID")
    fleet_sse = current_app.fleet_sse_manager

    def generate():
        """Yield SSE messages with periodic keepalive comments.

        Uses a 15-second timeout on queue.get() so we can emit an SSE
        comment as a keepalive. This prevents reverse proxies and load
        balancers from closing idle connections.
        """
        client_queue = fleet_sse.create_client(last_event_id=last_event_id)
        try:
            while True:
                try:
                    message = client_queue.get(timeout=15)
                except Exception:
                    # queue.Empty — no events for 15s, send keepalive
                    yield ": keepalive\n\n"
                    continue
                if message is None:
                    # Sentinel — server is shutting down
                    return
                yield message
        except GeneratorExit:
            # Client disconnected
            pass
        finally:
            fleet_sse.remove_client(client_queue)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


@fleet_bp.route("/blocks/active", methods=["GET"])
@limiter.limit(lambda: current_app.config.get("RATELIMIT_FLEET_BLOCKS", "60 per minute"))
def fleet_blocks_active():
    """Return all currently active fleet blocks for agent initial sync.

    Used by agents on first SSE connection to bulk-ingest fleet blocks
    that were issued before the agent joined. Authenticated via Bearer
    token (same as the SSE stream).

    Returns a flat list of block directives in the same format as SSE
    events, so the agent can apply them using the same code path.
    """
    api_key, error_response = _authenticate_bearer_token()
    if error_response is not None:
        return error_response

    db = get_request_db()
    rows = db.execute(
        "SELECT source_ip, event_type, originating_node_id, "
        "fleet_block_id, approved_at, ttl_seconds, expires_at "
        "FROM fleet_blocks WHERE status = 'active' "
        "ORDER BY approved_at DESC"
    ).fetchall()

    # Compute remaining TTL from expires_at so agents get an accurate
    # local timeout rather than the original full TTL value.
    from datetime import datetime

    now_dt = datetime.now(UTC)

    blocks = []
    for row in rows:
        remaining_ttl = row["ttl_seconds"]  # fallback to original
        if row["expires_at"]:
            try:
                expires_val = row["expires_at"]
                # MySQL returns native datetime objects; SQLite returns strings
                if isinstance(expires_val, datetime):
                    expires_dt = expires_val
                    if expires_dt.tzinfo is None:
                        expires_dt = expires_dt.replace(tzinfo=UTC)
                else:
                    expires_dt = datetime.fromisoformat(str(expires_val).replace("Z", "+00:00"))
                remaining = int((expires_dt - now_dt).total_seconds())
                if remaining > 0:
                    remaining_ttl = remaining
                else:
                    continue  # already expired — skip
            except (ValueError, TypeError):
                pass

        blocks.append(
            {
                "action": "block",
                "source_ip": row["source_ip"],
                "fleet_block_id": row["fleet_block_id"],
                "reason": row["event_type"] or "fleet_block",
                "ttl_seconds": remaining_ttl,
                "originating_node_id": row["originating_node_id"],
                "approved_at": row["approved_at"],
            }
        )

    return jsonify({"blocks": blocks, "total": len(blocks)}), 200


# ---------------------------------------------------------------------------
# Allow-list endpoints
# ---------------------------------------------------------------------------


@fleet_bp.route("/allowlist", methods=["GET"])
@limiter.limit(lambda: current_app.config.get("RATELIMIT_FLEET_ADMIN", "30 per minute"))
@require_role("admin")
def list_allowlist():
    """List global allow-list entries.

    Requirements: 5.4
    """
    db = get_request_db()
    rows = db.execute("SELECT * FROM fleet_allowlist ORDER BY created_at DESC").fetchall()

    return jsonify(
        {
            "items": [dict(r) for r in rows],
            "total": len(rows),
        }
    ), 200


@fleet_bp.route("/allowlist", methods=["POST"])
@limiter.limit(lambda: current_app.config.get("RATELIMIT_FLEET_ADMIN", "30 per minute"))
@require_role("admin")
def add_allowlist_entry():
    """Add an entry to the global allow-list.

    Request body (JSON):
        {
            "entry": "192.168.1.0/24"
        }

    Requirements: 5.2, 5.4
    """
    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid_json", "message": "Request body is not valid JSON"}), 400

    if not body or not isinstance(body, dict):
        return jsonify({"error": "invalid_json", "message": "Request body is not valid JSON"}), 400

    entry = body.get("entry", "").strip()
    if not entry:
        return jsonify({"error": "missing_field", "message": "entry is required"}), 400

    engine = current_app.propagation_engine
    actor = current_user.username

    result = engine.add_allowlist_entry(entry, actor)

    return jsonify(result), 201


@fleet_bp.route("/allowlist/<int:entry_id>", methods=["DELETE"])
@limiter.limit(lambda: current_app.config.get("RATELIMIT_FLEET_ADMIN", "30 per minute"))
@require_role("admin")
def remove_allowlist_entry(entry_id):
    """Remove an allow-list entry.

    Requirements: 5.4
    """
    engine = current_app.propagation_engine
    actor = current_user.username

    result = engine.remove_allowlist_entry(entry_id, actor)

    if result["status"] == "not_found":
        return jsonify(result), 404

    return jsonify(result), 200


# ---------------------------------------------------------------------------
# On-demand reaper trigger
# ---------------------------------------------------------------------------


@fleet_bp.route("/reap", methods=["POST"])
@limiter.limit(lambda: current_app.config.get("RATELIMIT_FLEET_ADMIN", "30 per minute"))
@require_role("admin")
def trigger_reap():
    """Manually trigger a fleet block reap + purge cycle."""
    engine = current_app.propagation_engine
    try:
        expired = engine.reap_expired()
    except Exception as exc:
        logger.error("Failed to reap expired fleet blocks: %s", exc)
        return jsonify({"error": "reap_failed", "message": "An internal error occurred"}), 500
    try:
        purged = engine.purge_old_blocks()
    except Exception as exc:
        logger.error("Failed to purge old fleet blocks: %s", exc)
        return jsonify({"error": "purge_failed", "message": "An internal error occurred"}), 500
    return jsonify({"ok": True, "expired": expired, "purged": purged}), 200


# ---------------------------------------------------------------------------
# Config endpoints
# ---------------------------------------------------------------------------


@fleet_bp.route("/config", methods=["GET"])
@limiter.limit(lambda: current_app.config.get("RATELIMIT_FLEET_ADMIN", "30 per minute"))
@require_role("admin")
def get_config():
    """Get current propagation configuration.

    Requirements: 8.1
    """
    db = get_request_db()
    rows = db.execute(
        "SELECT config_key, config_value, updated_at, updated_by FROM fleet_config"
    ).fetchall()

    config = {}
    for row in rows:
        key = row["config_key"]
        value = row["config_value"]

        # Parse typed values for the response
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
        elif key == "propagation_paused":
            config[key] = value.lower() in ("true", "1", "yes")
        elif key == "excluded_event_types":
            try:
                config[key] = json.loads(value)
            except (json.JSONDecodeError, TypeError):
                config[key] = []
        else:
            config[key] = value

    return jsonify(config), 200


@fleet_bp.route("/config", methods=["PUT"])
@limiter.limit(lambda: current_app.config.get("RATELIMIT_FLEET_ADMIN", "30 per minute"))
@require_role("admin")
def update_config():
    """Update propagation configuration.

    Request body (JSON): A dict of config keys to update. Valid keys:
        - corroboration_threshold (int)
        - corroboration_window_seconds (int)
        - fleet_block_ttl_seconds (int)
        - max_fleet_blocks_per_hour (int)
        - max_reports_per_node_per_hour (int)
        - excluded_event_types (list)
        - reaper_interval_seconds (int)
        - expired_block_retention_seconds (int)

    Requirements: 8.1
    """
    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid_json", "message": "Request body is not valid JSON"}), 400

    if not body or not isinstance(body, dict):
        return jsonify({"error": "invalid_json", "message": "Request body is not valid JSON"}), 400

    # Allowed config keys that can be updated
    allowed_keys = {
        "corroboration_threshold",
        "corroboration_window_seconds",
        "fleet_block_ttl_seconds",
        "max_fleet_blocks_per_hour",
        "max_reports_per_node_per_hour",
        "excluded_event_types",
        "reaper_interval_seconds",
        "expired_block_retention_seconds",
        "unlock_webhook_secret",
    }

    duration_keys = {
        "expired_block_retention_seconds",
        "fleet_block_ttl_seconds",
        "corroboration_window_seconds",
    }

    updates = {}
    for key, value in body.items():
        if key not in allowed_keys:
            return jsonify(
                {
                    "error": "invalid_key",
                    "message": f"Config key '{key}' is not updatable via this endpoint",
                }
            ), 400
        # Validate duration format for duration keys
        if key in duration_keys:
            try:
                parse_duration(str(value))
            except ValueError:
                return jsonify(
                    {
                        "error": "invalid_value",
                        "message": f"Invalid duration for '{key}': use formats like 0m, 30m, 6h, 1d or plain seconds",
                    }
                ), 400
            updates[key] = str(value)
        # Serialize lists as JSON strings
        elif isinstance(value, list):
            updates[key] = json.dumps(value)
        else:
            updates[key] = str(value)

    if not updates:
        return jsonify({"error": "empty_body", "message": "No config keys to update"}), 400

    actor = current_user.username
    db = get_request_db()
    for key, value in updates.items():
        db.execute(
            "UPDATE fleet_config SET config_value = ?, updated_at = ?, "
            "updated_by = ? "
            "WHERE config_key = ?",
            (value, _utcnow_iso(), actor, key),
        )
    db.commit()

    # Audit the config change
    record_audit(
        db,
        actor=actor,
        actor_ip=request.remote_addr,
        action_type="fleet_config_updated",
        target="fleet_config",
        details={"updated_keys": list(updates.keys()), "values": updates},
    )

    return jsonify({"status": "updated", "keys": list(updates.keys())}), 200


# ---------------------------------------------------------------------------
# Pause/Resume endpoint
# ---------------------------------------------------------------------------


@fleet_bp.route("/pause", methods=["POST"])
@limiter.limit(lambda: current_app.config.get("RATELIMIT_FLEET_ADMIN", "30 per minute"))
@require_role("admin")
def toggle_pause():
    """Toggle propagation pause (emergency kill switch).

    Request body (JSON):
        {
            "paused": true
        }

    If no body is provided, toggles the current state.

    Requirements: 4.5, 7.4
    """
    db = get_request_db()
    # Get current state
    row = db.execute(
        "SELECT config_value FROM fleet_config WHERE config_key = 'propagation_paused'"
    ).fetchone()

    current_state = False
    if row:
        current_state = row["config_value"].lower() in ("true", "1", "yes")

    # Determine new state
    try:
        body = request.get_json(silent=True) or {}
    except Exception:
        logger.exception("Failed to parse JSON body in fleet/pause")
        return jsonify({"error": "invalid_json"}), 400

    if body and isinstance(body, dict) and "paused" in body:
        new_state = bool(body["paused"])
    else:
        new_state = not current_state

    new_value = "true" if new_state else "false"
    actor = current_user.username

    db.execute(
        "UPDATE fleet_config SET config_value = ?, updated_at = ?, "
        "updated_by = ? "
        "WHERE config_key = 'propagation_paused'",
        (new_value, _utcnow_iso(), actor),
    )
    db.commit()

    # Audit the toggle
    record_audit(
        db,
        actor=actor,
        actor_ip=request.remote_addr,
        action_type="fleet_propagation_toggled",
        target="propagation_paused",
        details={"previous_state": current_state, "new_state": new_state},
    )

    return jsonify(
        {
            "status": "updated",
            "propagation_paused": new_state,
        }
    ), 200
