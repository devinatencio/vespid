"""Enrollment API blueprint — agent auto-enrollment endpoints.

Provides endpoints for agents to request enrollment and retrieve credentials
without prior authentication. Uses IP-based rate limiting to prevent abuse.

Endpoints:
    POST /api/v1/enroll              — Submit enrollment request
    GET  /api/v1/enroll/status/<id>  — Poll enrollment status / retrieve credentials

Self-healing key rotation:
    An agent that already has an approved enrollment may present its
    still-active API key in the ``X-Existing-Credentials`` header. If the
    same ``node_id`` and ``host_id`` are present in the body, the server
    revokes the old key and issues a new one in place. This is the
    self-heal path used when a monitor agent loses its ``credentials.json``
    but its ``agent_id`` file survives.

Requirements: 1.2, 1.3, 2.1, 2.2, 2.3, 3.1, 4.1, 4.2, 4.3, 4.4,
              5.1, 5.2, 5.3, 5.4, 11.1, 11.3, 13.1, 13.2, 13.3, 13.4,
              13.5, 14.1, 14.2
"""

import hashlib
import uuid

from flask import current_app, jsonify, request
from flask_limiter.util import get_remote_address
from flask_openapi3 import APIBlueprint
from flask_openapi3.models import Tag

from app.enrollment_models import (
    approve_enrollment,
    auto_rotate_on_reenroll,
    create_enrollment_request,
    get_approved_enrollment_by_node_id,
    get_enrollment_by_node_id,
    get_enrollment_settings,
    get_host_id_for_machine,
    get_host_id_for_node,
    mark_credentials_retrieved,
)
from app.inventory import ensure_asset
from app.models import get_db
from app.openapi_models import EnrollmentStatusResponse
from app.rate_limit import limiter

enrollment_bp = APIBlueprint("enrollment", __name__, url_prefix="/api/v1/enroll")

_enroll_tag = [Tag(name="Enrollment", description="Agent auto-enrollment")]


def _ip_key_func():
    """Rate limit key based on source IP only (no auth for enrollment)."""
    return "ip:" + get_remote_address()


def _extract_identifiers_from_interfaces(interfaces: list) -> dict:
    """Extract MAC and IPv4/IPv6 identifiers from an interfaces list.

    Each interface dict may have keys: ``name``, ``mac``, ``ipv4``, ``ipv6``.
    """
    ids: dict[str, list[str]] = {}
    for iface in interfaces if isinstance(interfaces, list) else []:
        if not isinstance(iface, dict):
            continue
        mac = iface.get("mac", "") or ""
        if mac.strip():
            ids.setdefault("mac", []).append(mac.strip())
        for ip in iface.get("ipv4", []):
            if ip and isinstance(ip, str) and ip.strip():
                ids.setdefault("ipv4", []).append(ip.strip())
    return ids


def _resolve_existing_credentials() -> dict | None:
    """Read and validate the X-Existing-Credentials header.

    Returns the matching ``api_keys`` row dict, or None if the header is
    absent, malformed, or refers to a revoked/unknown key.
    """
    auth = request.headers.get("X-Existing-Credentials", "")
    if not auth.startswith("Bearer "):
        return None
    token = auth[7:].strip()
    if not token:
        return None
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        key_hash = hashlib.sha256(token.encode()).hexdigest()
        row = db.execute(
            "SELECT * FROM api_keys WHERE key_hash = ? AND is_active = 1",
            (key_hash,),
        ).fetchone()
        if row is None:
            return None
        return dict(row)
    finally:
        db.close()


def _resolve_pending_rotation(
    db, node_id: str, auth_header: str, body_host_id: str | None = None
) -> dict | None:
    """Return a pending rotated token if the presented (revoked) key legitimately
    belongs to this node.

    The dashboard's credential rotation revokes the old API key immediately
    and stores the replacement token in the enrollment record's
    ``pending_token`` field. When an agent reconnects after such a rotation
    it presents the now-revoked key in ``X-Existing-Credentials``; the normal
    resolution path rejects it because it is no longer active. This helper
    verifies that:

      1. The presented token hashes to a real, REVOKED key,
      2. that key was restricted to this ``node_id``,
      3. the key's ``host_id`` (if any) matches the enrollment's ``host_id``
         or the ``host_id`` presented in the request body,
      4. an approved enrollment record for this node still has a
         ``pending_token`` that has not been retrieved yet.

    If all hold, the pending token is returned so the agent can adopt the
    rotated key in place (no fresh re-enrollment, no orphaned rotation).

    Returns:
        A dict with ``raw_token``, ``asset_id``, ``hostname``, ``host_id``
        if a pending rotation applies, else None.
    """
    token = auth_header[7:].strip() if auth_header.startswith("Bearer ") else ""
    if not token:
        return None
    key_hash = hashlib.sha256(token.encode()).hexdigest()
    key = db.execute(
        "SELECT id, node_id_restriction, host_id FROM api_keys "
        "WHERE key_hash = ? AND is_active = 0",
        (key_hash,),
    ).fetchone()
    if key is None:
        return None
    if key["node_id_restriction"] != node_id:
        return None

    approved = get_approved_enrollment_by_node_id(db, node_id)
    if approved is None:
        return None
    if approved["status"] != "approved":
        return None
    if approved["credentials_retrieved"] or not approved.get("pending_token"):
        return None

    # Host linkage defense: if either side has a host_id, require a match
    # between the revoked key, the enrollment, and the presented body host.
    key_host = key["host_id"]
    approved_host = approved.get("host_id")
    if key_host and approved_host and key_host != approved_host:
        return None
    if body_host_id and approved_host and body_host_id != approved_host:
        return None
    if key_host and body_host_id and key_host != body_host_id:
        return None

    return {
        "raw_token": approved["pending_token"],
        "asset_id": approved.get("asset_id") or "",
        "hostname": approved.get("hostname") or "",
        "host_id": approved.get("host_id"),
        "record_id": approved["id"],
    }


def _enroll_response(
    status: str,
    node_id: str,
    asset_id: str,
    display_name: str,
    raw_token: str | None = None,
    host_id: str | None = None,
    rotated: bool = False,
):
    """Build a standardized enrollment response body."""
    body: dict = {
        "status": status,
        "node_id": node_id,
        "asset_id": asset_id,
        "display_name": display_name,
    }
    if raw_token is not None:
        body["api_key"] = raw_token
        body["server_url"] = request.url_root.rstrip("/") + "/api/v1/events"
    if host_id:
        body["host_id"] = host_id
    if rotated:
        body["rotated"] = True
    return jsonify(body)


@enrollment_bp.post(
    "",
    summary="Submit enrollment request",
    description="Submit an agent enrollment request. Behavior depends on the active enrollment mode "
    "(open, manual-approval, or restricted). "
    "Self-heal: if the same node_id already has approved credentials and the request includes "
    "the old key in X-Existing-Credentials header, the server auto-rotates to a new key.",
    tags=_enroll_tag,
    responses={
        200: {"description": "Credentials issued (open/restricted/auto-rotate mode)"},
        202: EnrollmentStatusResponse,
        400: {"description": "Missing required fields"},
        403: {"description": "Enrollment disabled or invalid token"},
        409: {"description": "Duplicate enrollment"},
        429: {"description": "Rate limit exceeded"},
    },
)
@limiter.limit("10 per minute", key_func=_ip_key_func)
def enroll():
    """Submit an enrollment request.

    Validates the request, checks enrollment settings, and processes
    the request according to the active enrollment mode.

    Self-heal path:
        If the same ``node_id`` already has an approved enrollment and
        the request includes the matching old key in the
        ``X-Existing-Credentials`` header, the server revokes the old
        key and issues a new one (auto-rotate). This lets a monitor agent
        re-enroll automatically when its ``credentials.json`` is lost.

    Returns:
        200: Credentials issued (open / restricted / auto-rotate)
        202: Request accepted, pending approval (manual_approval mode)
        400: Missing required fields
        403: Enrollment disabled / invalid token / revoked enrollment re-enroll
        409: Duplicate enrollment (already enrolled or pending)
        429: Rate limit exceeded
    """
    # Parse JSON body
    body = request.get_json(silent=True)
    if body is None or not isinstance(body, dict):
        return jsonify(
            {
                "error": "validation_error",
                "missing_fields": ["node_id", "hostname"],
            }
        ), 400

    # Validate required fields
    node_id = body.get("node_id", "")
    hostname = body.get("hostname", "")
    display_name = body.get("display_name", "")
    source = (body.get("source", "agent") or "agent").strip() or "agent"
    body_host_id = (body.get("host_id", "") or "").strip() or None
    machine_id = (body.get("machine_id", "") or "").strip()

    missing_fields = []
    if not node_id or not isinstance(node_id, str) or not node_id.strip():
        missing_fields.append("node_id")
    if not hostname or not isinstance(hostname, str) or not hostname.strip():
        missing_fields.append("hostname")

    if missing_fields:
        return jsonify(
            {
                "error": "validation_error",
                "missing_fields": missing_fields,
            }
        ), 400

    node_id = node_id.strip()
    hostname = hostname.strip()
    display_name = display_name.strip() if display_name else hostname
    source_ip = get_remote_address()

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        # Check if enrollment is enabled
        settings = get_enrollment_settings(db)
        enrollment_enabled = settings.get("enrollment_enabled", "true")
        if enrollment_enabled != "true":
            return jsonify(
                {
                    "error": "enrollment_disabled",
                    "message": "Auto-enrollment is currently disabled.",
                }
            ), 403

        enrollment_mode = settings.get("enrollment_mode", "manual_approval")

        # ── Validate X-Existing-Credentials header.
        # The header is optional, but if present it MUST be a valid,
        # active Bearer token. We check it explicitly so that a
        # malformed or unknown key is rejected with 401 instead of
        # silently falling through to the duplicate-enrollment path.
        x_existing = request.headers.get("X-Existing-Credentials", "").strip()
        if x_existing:
            if not x_existing.startswith("Bearer "):
                return jsonify(
                    {
                        "error": "invalid_existing_credentials",
                        "message": ("X-Existing-Credentials must be 'Bearer <token>'"),
                    }
                ), 401
            existing_key = _resolve_existing_credentials()
            if existing_key is None:
                # The presented key is revoked, unknown, or malformed.
                # Before rejecting outright, check whether this node has a
                # pending rotation: the dashboard's rotate action revokes
                # the old key immediately and stashes the new token in
                # pending_token. If the presented key is a REVOKED key that
                # was bound to this node_id, hand back the pending token so
                # the agent picks up the rotated key instead of re-enrolling
                # from scratch (which would orphan the rotation).
                pending = _resolve_pending_rotation(db, node_id, x_existing, body_host_id)
                if pending is not None:
                    mark_credentials_retrieved(db, pending["record_id"])
                    return _enroll_response(
                        status="approved",
                        node_id=node_id,
                        asset_id=pending["asset_id"] or "",
                        display_name=pending["hostname"] or display_name,
                        raw_token=pending["raw_token"],
                        host_id=pending["host_id"],
                        rotated=True,
                    ), 200
                return jsonify(
                    {
                        "error": "invalid_existing_credentials",
                        "message": (
                            "X-Existing-Credentials token is unknown, revoked, or malformed."
                        ),
                    }
                ), 401
        else:
            existing_key = None

        # ── Self-heal / rotation path: the same node_id re-enrolls while
        # presenting a still-active key via X-Existing-Credentials. The
        # server validates the key, revokes it, and issues a replacement
        # in place (zero-downtime rotation). This also lets a monitor
        # agent recover after losing its credentials.json while its
        # agent_id file survives.
        approved = get_approved_enrollment_by_node_id(db, node_id)
        if existing_key and approved:
            same_host = (
                not body_host_id or not approved["host_id"] or body_host_id == approved["host_id"]
            )
            if same_host and approved["host_id"]:
                raw_token = auto_rotate_on_reenroll(db, approved["id"], "auto-rotate:reenroll")
                return _enroll_response(
                    status="approved",
                    node_id=node_id,
                    asset_id=approved["asset_id"] or "",
                    display_name=approved["hostname"] or display_name,
                    raw_token=raw_token,
                    host_id=approved["host_id"],
                    rotated=True,
                ), 200
            if approved["status"] == "approved" and not approved["host_id"]:
                # Approved enrollment without host_id linkage: cannot
                # auto-rotate safely. Fall through to the normal flow
                # so the operator can decide.
                pass

        # If a client supplied a host_id that contradicts an existing
        # approved enrollment on this node, reject the request with
        # 403. This catches the case where a malicious or misconfigured
        # agent tries to claim a different host than the one already
        # bound to its node_id. We only enforce this when an approved
        # record with a host_id actually exists (i.e. there is a
        # real linkage to compare against).
        if (
            body_host_id
            and approved
            and approved["host_id"]
            and body_host_id != approved["host_id"]
        ):
            return jsonify(
                {
                    "error": "host_id_mismatch",
                    "message": (
                        f"node_id '{node_id}' is already bound to a "
                        f"different host. Refusing to re-link."
                    ),
                }
            ), 403

        # Block re-enrollment for revoked/rejected records with the
        # same node_id. Operator must explicitly reissue from the UI.
        # Look at the most recent record regardless of status to detect
        # this.
        latest = db.execute(
            "SELECT status, host_id FROM enrollment_requests "
            "WHERE node_id = ? ORDER BY requested_at DESC LIMIT 1",
            (node_id,),
        ).fetchone()
        if latest and latest["status"] in ("revoked", "rejected"):
            return jsonify(
                {
                    "error": "enrollment_" + latest["status"],
                    "message": (
                        f"Enrollment for node {node_id} was {latest['status']}; "
                        "operator must explicitly reissue from the admin UI."
                    ),
                }
            ), 403

        # Check for duplicate active enrollment (pending or approved)
        existing = get_enrollment_by_node_id(db, node_id)
        if existing is not None:
            if existing["status"] == "approved":
                # ── Stale-credentials recovery path ──
                # The agent has an approved enrollment but didn't present
                # X-Existing-Credentials (credentials.json was lost).
                # If the approved record has a host_id linkage, verify
                # the re-enrolling agent is the same host (machine_id or
                # hostname match) and auto-rotate credentials in place.
                if not existing_key and existing.get("host_id"):
                    # Proof of host identity is required: the agent must
                    # present a machine_id that maps to this host. We must
                    # NOT fall back to the node's own stored host_id — that
                    # would let anyone who knows the node_id mint a fresh
                    # API key without credentials.
                    recovered_host_id = (
                        get_host_id_for_machine(db, machine_id) if machine_id else None
                    )
                    if recovered_host_id and recovered_host_id == existing["host_id"]:
                        raw_token = auto_rotate_on_reenroll(
                            db, existing["id"], "auto-rotate:stale-credentials"
                        )
                        return _enroll_response(
                            status="approved",
                            node_id=node_id,
                            asset_id=existing["asset_id"] or "",
                            display_name=existing["hostname"] or display_name,
                            raw_token=raw_token,
                            host_id=existing["host_id"],
                            rotated=True,
                        ), 200
                return jsonify(
                    {
                        "error": "already_enrolled",
                        "status": existing["status"],
                    }
                ), 409
            elif existing["status"] == "pending":
                return jsonify(
                    {
                        "error": "already_pending",
                        "status": existing["status"],
                    }
                ), 409

        # Handle restricted mode: validate token against stored enrollment token
        if enrollment_mode == "restricted":
            token = body.get("token", "")
            if not token or not isinstance(token, str) or not token.strip():
                return jsonify(
                    {
                        "error": "invalid_token",
                        "message": "A valid enrollment token is required in restricted mode.",
                    }
                ), 403

            stored_token = settings.get("enrollment_token", "").strip()
            if stored_token and token.strip() != stored_token:
                return jsonify(
                    {
                        "error": "invalid_token",
                        "message": "The provided enrollment token is invalid.",
                    }
                ), 403

        # ── Resolve host_id (the host linkage) ──
        resolved_host_id = body_host_id
        if not resolved_host_id:
            # 1) Try machine_id match against an existing approved host.
            if machine_id:
                resolved_host_id = get_host_id_for_machine(db, machine_id)
            # 2) Try the node_id's own previously approved host.
            if not resolved_host_id:
                resolved_host_id = get_host_id_for_node(db, node_id)
            # 3) Mint a new one.
            if not resolved_host_id:
                resolved_host_id = uuid.uuid4().hex

        # Create enrollment request record
        record = create_enrollment_request(
            db,
            node_id,
            hostname,
            source_ip,
            display_name,
            source=source,
            host_id=resolved_host_id,
        )

        # Resolve or create an asset for this host
        interfaces = body.get("interfaces")
        identifiers = {"hostname": hostname}
        if machine_id:
            identifiers["machine_id"] = machine_id
        if interfaces is not None:
            iface_ids = _extract_identifiers_from_interfaces(interfaces)
            identifiers.update(iface_ids)
        metadata = {}
        if machine_id:
            metadata["machine_id"] = machine_id
        asset_id = ensure_asset(
            db,
            asset_type="host",
            display_name=display_name,
            source=source if source in ("agent", "monitor", "sync") else "agent",
            metadata=metadata,
            **identifiers,
        )

        # Store asset_id on the enrollment record
        db.execute(
            "UPDATE enrollment_requests SET asset_id = ? WHERE id = ?", (asset_id, record["id"])
        )
        db.commit()

        if enrollment_mode in ("open", "restricted"):
            # Immediately approve and issue credentials
            raw_token = approve_enrollment(db, record["id"], "system", host_id=resolved_host_id)
            return _enroll_response(
                status="approved",
                node_id=node_id,
                asset_id=asset_id,
                display_name=display_name,
                raw_token=raw_token,
                host_id=resolved_host_id,
            ), 200

        elif enrollment_mode == "manual_approval":
            # Leave as pending
            return _enroll_response(
                status="pending",
                node_id=node_id,
                asset_id=asset_id,
                display_name=display_name,
                host_id=resolved_host_id,
            ), 202

        else:
            # Unknown mode — treat as manual_approval
            return _enroll_response(
                status="pending",
                node_id=node_id,
                asset_id=asset_id,
                display_name=display_name,
                host_id=resolved_host_id,
            ), 202

    finally:
        db.close()


@enrollment_bp.get(
    "/status/<node_id>",
    summary="Check enrollment status",
    description="Poll enrollment status by node_id. Returns credentials when approved. "
    "Agents should poll this endpoint after submitting an enrollment request.",
    tags=_enroll_tag,
    responses={
        200: {"description": "Approved — credentials included on first retrieval"},
        202: EnrollmentStatusResponse,
        403: {"description": "Rejected or revoked"},
        404: {"description": "No enrollment record found"},
    },
)
@limiter.limit("10 per minute", key_func=_ip_key_func)
def enrollment_status(node_id):
    """Check enrollment status and retrieve credentials if approved.

    Returns:
        200: Approved — credentials included (first retrieval) or status only
        202: Still pending approval
        403: Rejected or revoked
        404: No enrollment record for this node_id
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        # Look up enrollment record — check all statuses, not just active
        row = db.execute(
            "SELECT * FROM enrollment_requests WHERE node_id = ? "
            "ORDER BY requested_at DESC LIMIT 1",
            (node_id,),
        ).fetchone()

        if row is None:
            return jsonify(
                {
                    "error": "not_found",
                    "message": "No enrollment record found for this node_id.",
                }
            ), 404

        record = dict(row)
        status = record["status"]
        host_id = record.get("host_id") or ""

        asset_id = record.get("asset_id") or ""
        if asset_id:
            from app.inventory import update_asset_seen

            update_asset_seen(db, asset_id)

        if status == "pending":
            return jsonify(
                {
                    "status": "pending",
                    "node_id": node_id,
                    "asset_id": asset_id,
                    "display_name": record.get("hostname", ""),
                    **({"host_id": host_id} if host_id else {}),
                }
            ), 202

        elif status in ("rejected", "revoked"):
            return jsonify(
                {
                    "error": "enrollment_" + status,
                    "status": status,
                    "asset_id": asset_id,
                    "message": f"Enrollment has been {status}.",
                }
            ), 403

        elif status == "approved":
            if not record["credentials_retrieved"] and record.get("pending_token"):
                raw_token = record["pending_token"]
                mark_credentials_retrieved(db, record["id"])
                server_url = request.url_root.rstrip("/") + "/api/v1/events"

                return jsonify(
                    {
                        "status": "approved",
                        "api_key": raw_token,
                        "node_id": node_id,
                        "asset_id": asset_id,
                        "display_name": record.get("hostname", ""),
                        "server_url": server_url,
                        **({"host_id": host_id} if host_id else {}),
                    }
                ), 200
            else:
                return jsonify(
                    {
                        "status": "approved",
                        "node_id": node_id,
                        "asset_id": asset_id,
                        "display_name": record.get("hostname", ""),
                        **({"host_id": host_id} if host_id else {}),
                    }
                ), 200

        else:
            return jsonify(
                {
                    "error": "unknown_status",
                    "status": status,
                }
            ), 500

    finally:
        db.close()
