"""Shared agent authentication helper.

Centralises Bearer-token authentication plus ``node_id_restriction``
enforcement for agent-side API endpoints. This is the Gap 2 fix: prior
to this module, the ``@require_role("agent")`` decorator only checked
role hierarchy and never verified that the key was used by the node it
was bound to, which allowed any active key to write metrics/inventory/
synthetic-checks data attributed to any other node.

Usage::

    from app.agent_auth import authenticate_agent_request

    @metrics_bp.route("/api/v1/metrics/write", methods=["POST"])
    @require_role("agent")
    def write():
        api_key, err = authenticate_agent_request()
        if err is not None:
            return err
        # ... proceed; the key has been verified for this agent ...
"""

import hashlib
import logging
from datetime import UTC, datetime

from flask import jsonify, request

from app.models import get_request_db

logger = logging.getLogger(__name__)


_AGENT_ID_HEADERS = ("X-Agent-ID",)
_WORKER_ID_HEADERS = ("X-Worker-ID",)

logger = logging.getLogger(__name__)


def _touch_key_usage(key_id: int) -> None:
    """Stamp ``last_used_at`` on the API key row."""
    db = get_request_db()
    try:
        db.execute(
            "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
            (datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"), key_id),
        )
        db.commit()
    except Exception:
        logger.warning("Failed to update last_used_at for key %d", key_id, exc_info=True)


def _resolve_agent_id(
    *,
    path_param: str | None = None,
    body_fields: tuple | None = None,
) -> str:
    """Resolve the agent/worker identity from the current request.

    Resolution order:
        1. ``X-Agent-ID`` header (metric/check/logfile-watches paths).
        2. ``X-Worker-ID`` header (synthetic-checks paths).
        3. URL path parameter (``agent_id`` or ``worker_id``).
        4. JSON body field (``agent_id`` / ``worker_id`` / ``node_id``).

    The first non-empty value wins. An empty result is allowed when the
    caller intends to use the key's own ``node_id_restriction`` to
    determine the identity.
    """
    for header in _AGENT_ID_HEADERS:
        value = request.headers.get(header, "").strip()
        if value:
            return value
    for header in _WORKER_ID_HEADERS:
        value = request.headers.get(header, "").strip()
        if value:
            return value

    if path_param:
        value = request.view_args.get(path_param, "") if request.view_args else ""
        if isinstance(value, str) and value.strip():
            return value.strip()

    if body_fields:
        body = request.get_json(silent=True) or {}
        if isinstance(body, dict):
            for field in body_fields:
                value = body.get(field, "")
                if isinstance(value, str) and value.strip():
                    return value.strip()

    return ""


def authenticate_agent_request(
    *,
    path_param: str | None = None,
    body_fields: tuple | None = None,
) -> tuple[dict | None, tuple | None]:
    """Authenticate a Bearer token AND enforce ``node_id_restriction``.

    This is the canonical guard for agent-side endpoints. It combines:

    1. Bearer-token authentication (re-using the same SHA-256 lookup
       as ``app.api._authenticate_api_key``). Returns 401 on missing,
       invalid, or revoked keys.
    2. ``node_id_restriction`` enforcement. If the key is restricted to
       a particular node_id, the request must present a matching
       identity via the X-Agent-ID / X-Worker-ID header, the URL path
       parameter, or one of the configured body fields. Mismatches
       return 403.

    The 403 response includes an ``X-Node-ID-Restriction`` header so the
    agent can detect the binding and surface a clear "wrong host" error
    in its logs (mirrors the existing ``node_id_mismatch`` pattern in
    ``app.api.ingest_events``).

    Args:
        path_param: View-arg name carrying the agent/worker id
            (e.g. ``"agent_id"`` or ``"worker_id"``).
        body_fields: Tuple of JSON body field names to inspect for the
            agent/worker id. Useful for ``POST`` endpoints that carry
            the identity in the body (e.g. ``"agent_id"``,
            ``"worker_id"``, ``"node_id"``).

    Returns:
        A 2-tuple ``(api_key_row, error_response)``. On success,
        ``api_key_row`` is the dict-like sqlite row from ``api_keys``
        and ``error_response`` is ``None``. On failure, ``api_key_row``
        is ``None`` and ``error_response`` is the Flask response tuple
        to return directly.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None, (
            jsonify({"error": "unauthorized", "message": "Missing or invalid Bearer token"}),
            401,
        )

    token = auth_header[7:].strip()
    if not token:
        return None, (
            jsonify({"error": "unauthorized", "message": "Missing or invalid Bearer token"}),
            401,
        )

    db = get_request_db()
    key_hash = hashlib.sha256(token.encode()).hexdigest()
    row = db.execute("SELECT * FROM api_keys WHERE key_hash = ?", (key_hash,)).fetchone()

    if row is None:
        return None, (
            jsonify({"error": "unauthorized", "message": "Invalid API key"}),
            401,
        )

    if not row["is_active"]:
        return None, (
            jsonify({"error": "key_revoked", "message": "API key has been revoked"}),
            401,
        )

    api_key = dict(row)
    node_id_restriction = api_key.get("node_id_restriction") or ""

    # Stamp last_used_at so the admin/keys UI reflects live usage.
    _touch_key_usage(api_key["id"])

    if not node_id_restriction:
        return api_key, None

    claimed_id = _resolve_agent_id(
        path_param=path_param,
        body_fields=body_fields,
    )

    if not claimed_id:
        return None, (
            jsonify(
                {
                    "error": "node_id_required",
                    "message": (
                        "This API key is bound to a specific node. "
                        "Send X-Agent-ID (or X-Worker-ID) header, or "
                        "include the id in the request body / URL."
                    ),
                }
            ),
            400,
        )

    if claimed_id != node_id_restriction:
        logger.warning(
            "Agent binding violation: key restricted to '%s' but request presented '%s'",
            node_id_restriction,
            claimed_id,
        )
        response = jsonify(
            {
                "error": "node_id_mismatch",
                "message": (f"API key is restricted to node '{node_id_restriction}'"),
                "node_id_restriction": node_id_restriction,
            }
        )
        response.headers["X-Node-ID-Restriction"] = node_id_restriction
        return None, (response, 403)

    return api_key, None
