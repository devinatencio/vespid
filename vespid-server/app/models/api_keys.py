from __future__ import annotations

import hashlib
import logging
import secrets
import sqlite3

from .db_core import _row_to_dict, _utcnow_iso

logger = logging.getLogger(__name__)

# ── API key query helpers (Task 2.4) ────────────────────────────────────


def create_api_key(
    db: sqlite3.Connection,
    label: str,
    node_id_restriction: str | None,
    created_by: int,
    host_id: str | None = None,
) -> str:
    """Generate a new API key, store its SHA-256 hash, and return the raw token.

    The raw token is returned exactly once. Only the hash and an 8-character
    prefix are persisted so the original token cannot be recovered.

    Args:
        db: An open SQLite connection.
        label: A human-readable label for the key.
        node_id_restriction: If set, the key may only be used to ingest
            events from this specific node_id. ``None`` means any node.
        created_by: The user id of the admin who created the key.
        host_id: Optional host linkage (links multiple keys for the same
            physical host, e.g. security-agent and monitor-agent on the
            same host). ``None`` means no host linkage.

    Returns:
        The raw API token (shown to the admin once).
    """
    raw_token = secrets.token_urlsafe(32)
    key_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    key_prefix = raw_token[:8]

    db.execute(
        "INSERT INTO api_keys (key_hash, key_prefix, label, node_id_restriction, created_by, host_id) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (key_hash, key_prefix, label, node_id_restriction, created_by, host_id),
    )
    db.commit()
    return raw_token


def verify_api_key(
    db: sqlite3.Connection,
    token: str,
) -> dict | None:
    """Look up an API key by its SHA-256 hash and check it is active.

    Args:
        db: An open SQLite connection.
        token: The raw API token presented by the client.

    Returns:
        A dict with the key record if the token is valid and active,
        or ``None`` if the token is unknown or the key has been revoked.
    """
    key_hash = hashlib.sha256(token.encode()).hexdigest()
    row = db.execute(
        "SELECT * FROM api_keys WHERE key_hash = ? AND is_active = 1",
        (key_hash,),
    ).fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


def revoke_api_key(
    db: sqlite3.Connection,
    key_id: int,
) -> None:
    """Revoke an API key so it can no longer be used for authentication.

    Args:
        db: An open SQLite connection.
        key_id: The primary key id of the API key to revoke.
    """
    db.execute(
        "UPDATE api_keys SET is_active = 0 WHERE id = ?",
        (key_id,),
    )
    db.commit()


def list_api_keys(db: sqlite3.Connection) -> list[dict]:
    """Return all API keys (without exposing the full hash).

    Returns columns useful for the admin key management UI: id, key_prefix,
    label, node_id_restriction, is_active, created_at, last_used_at,
    created_by.

    Args:
        db: An open SQLite connection.

    Returns:
        A list of API key dicts ordered by id ascending.
    """
    rows = db.execute(
        "SELECT id, key_prefix, label, node_id_restriction, is_active, "
        "created_at, last_used_at, created_by, host_id "
        "FROM api_keys ORDER BY id ASC"
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


def get_api_keys_for_node(db: sqlite3.Connection, node_id: str) -> list[dict]:
    """Return API keys associated with a specific node.

    Looks up keys where node_id_restriction matches the given node_id.
    Returns metadata useful for the admin UI without exposing the full hash.

    Args:
        db: An open SQLite connection.
        node_id: The node identifier to look up keys for.

    Returns:
        A list of API key dicts for this node, ordered by created_at DESC.
    """
    rows = db.execute(
        "SELECT id, key_prefix, label, node_id_restriction, is_active, "
        "created_at, last_used_at, created_by "
        "FROM api_keys WHERE node_id_restriction = ? "
        "ORDER BY created_at DESC",
        (node_id,),
    ).fetchall()
    return [_row_to_dict(r) for r in rows]


def update_api_key_last_used(
    db: sqlite3.Connection,
    key_id: int,
) -> None:
    """Update the last_used_at timestamp for an API key to the current time.

    Called after a successful event ingestion request authenticated with
    this key.

    Args:
        db: An open SQLite connection.
        key_id: The primary key id of the API key.
    """
    db.execute(
        "UPDATE api_keys SET last_used_at = ? WHERE id = ?",
        (_utcnow_iso(), key_id),
    )
    db.commit()
