"""Rate limiting configuration for the Vespid Server API.

Uses Flask-Limiter to enforce per-key rate limits on API endpoints.
The limiter is created as a module-level singleton and initialized
with the Flask app in the factory (init_app pattern).

Rate limits are keyed by API key hash for authenticated endpoints,
falling back to remote IP for unauthenticated requests.

When a node_id can be determined from the request (URL path param,
query string, or JSON body), the rate limit key includes it so that
limits apply per-node even when nodes share the same API key:

    apikey:669a20cc:node:3fa812ab-.../heartbeat/30/1/minute

Configuration (via config file or environment variables):
    RATELIMIT_EVENTS_INGEST  — Limit for POST /api/v1/events (default: 60/min)
    RATELIMIT_HEARTBEAT      — Limit for POST /api/v1/heartbeat (default: 30/min)
    RATELIMIT_COMMANDS       — Limit for GET /api/v1/nodes/<id>/commands (default: 60/min)
    RATELIMIT_EXPORT         — Limit for GET /api/v1/events/export (default: 10/min)
    RATELIMIT_STORAGE_URI    — Backend for counters (default: memory://)
    RATELIMIT_ENABLED        — Master switch (default: True)
"""

import hashlib

from flask import request
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address


def _resolve_node_id() -> str | None:
    """Try to determine the calling node's ID from the request."""
    node_id = request.view_args.get("node_id") if request.view_args else None
    if node_id:
        return node_id
    return request.args.get("node_id")


def _key_func():
    """Return a rate limit key scoped to API key + node when possible.

    Priority:
        1. apikey:<hash>:node:<node_id>  (authenticated + node known)
        2. apikey:<hash>                 (authenticated, no node)
        3. ip:<addr>                     (unauthenticated)
    """
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:].strip()
        if token:
            key_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
            node_id = _resolve_node_id()
            if node_id:
                return f"apikey:{key_hash}:node:{node_id}"
            return f"apikey:{key_hash}"
    return "ip:" + get_remote_address()


def _key_func_body_node():
    """Key function for endpoints where node_id is in the JSON body.

    Only attempts body parsing for POST/PUT requests with JSON content.
    Falls back to the standard _key_func if node_id cannot be determined.
    """
    if request.method in ("POST", "PUT") and request.is_json:
        try:
            body = request.get_json(force=True, silent=True)
            if body and isinstance(body, dict):
                for key in ("agent_id", "node_id"):
                    node_id = body.get(key)
                    if node_id and isinstance(node_id, str) and node_id.strip():
                        auth_header = request.headers.get("Authorization", "")
                        if auth_header.startswith("Bearer "):
                            token = auth_header[7:].strip()
                            if token:
                                key_hash = hashlib.sha256(token.encode()).hexdigest()[:16]
                                return f"apikey:{key_hash}:node:{node_id.strip()}"
        except Exception:
            pass
    return _key_func()


# Module-level limiter instance — initialized with app in create_app()
limiter = Limiter(
    key_func=_key_func,
    storage_uri="memory://",
    default_limits=[],
)
