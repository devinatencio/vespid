"""Enrollment models and query helpers.

Provides functions for managing auto-enrollment lifecycle: settings,
enrollment requests, approval/rejection/revocation, credential rotation,
and audit logging.
"""

import hashlib
import sqlite3
from datetime import UTC, datetime

from .models import create_api_key, record_audit


def _row_to_dict(row: sqlite3.Row) -> dict:
    """Convert a sqlite3.Row to a plain dict."""
    return dict(row)


def _utcnow() -> str:
    """Return current UTC time as ISO-8601 string."""
    return datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Enrollment Settings ──────────────────────────────────────────────────


def get_enrollment_settings(db: sqlite3.Connection) -> dict:
    """Return current enrollment settings as a dict.

    Returns a dict mapping setting_key to setting_value for all rows
    in the enrollment_settings table.

    Args:
        db: An open SQLite connection.

    Returns:
        A dict like {"enrollment_enabled": "false", "enrollment_mode": "manual_approval"}.
    """
    rows = db.execute("SELECT setting_key, setting_value FROM enrollment_settings").fetchall()
    return {row["setting_key"]: row["setting_value"] for row in rows}


def get_enrollment_setting(
    db: sqlite3.Connection,
    key: str,
    default: str | None = None,
) -> str | None:
    """Return a single enrollment setting value, or ``default`` if unset.

    Args:
        db: An open SQLite connection.
        key: The setting key to look up (e.g. ``"enrollment_mode"``).
        default: Value to return if the setting is not present in the
            ``enrollment_settings`` table.

    Returns:
        The string value stored for ``key`` or ``default``.
    """
    row = db.execute(
        "SELECT setting_value FROM enrollment_settings WHERE setting_key = ?",
        (key,),
    ).fetchone()
    return row["setting_value"] if row else default


def update_enrollment_setting(
    db: sqlite3.Connection,
    key: str,
    value: str,
    updated_by: str,
) -> None:
    """Update a single enrollment setting and create an audit log entry.

    Args:
        db: An open SQLite connection.
        key: The setting key to update (e.g. 'enrollment_enabled').
        value: The new value for the setting.
        updated_by: The username of the admin making the change.
    """
    # Get the previous value for audit logging
    row = db.execute(
        "SELECT setting_value FROM enrollment_settings WHERE setting_key = ?",
        (key,),
    ).fetchone()
    previous_value = row["setting_value"] if row else None

    now = _utcnow()
    db.execute(
        "UPDATE enrollment_settings SET setting_value = ?, updated_at = ?, updated_by = ? "
        "WHERE setting_key = ?",
        (value, now, updated_by, key),
    )
    db.commit()

    record_audit(
        db,
        actor=updated_by,
        actor_ip=None,
        action_type="enrollment_settings_change",
        target=key,
        details={
            "previous_value": previous_value,
            "new_value": value,
        },
    )


# ── Enrollment Requests ──────────────────────────────────────────────────


def create_enrollment_request(
    db: sqlite3.Connection,
    node_id: str,
    hostname: str,
    source_ip: str = "",
    display_name: str = "",
    source: str = "agent",
    host_id: str | None = None,
) -> dict:
    """Insert a new enrollment request record.

    Creates a new enrollment_requests row with status 'pending' and records
    an audit log entry.

    Args:
        db: An open SQLite connection.
        node_id: The agent's unique node identifier.
        hostname: The agent's hostname.
        source_ip: The IP address the request originated from.
        display_name: Optional human-readable label for the node.
        source: Which agent flavor is enrolling (e.g. ``"agent"`` for the
            security agent, ``"monitor"`` for the monitor agent). Defaults
            to ``"agent"`` for back-compat.
        host_id: Optional host linkage. If provided, this enrollment is
            linked to the same physical host as other agents sharing the
            same host_id.

    Returns:
        A dict representing the newly created enrollment record.
    """
    now = _utcnow()
    display_name = display_name or hostname
    cursor = db.execute(
        "INSERT INTO enrollment_requests "
        "(node_id, hostname, source_ip, source, host_id, requested_at) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (node_id, hostname, source_ip, source, host_id, now),
    )
    db.commit()

    record_audit(
        db,
        actor="system",
        actor_ip=source_ip,
        action_type="enrollment_request",
        target=node_id,
        details={
            "hostname": hostname,
            "display_name": display_name,
            "source_ip": source_ip,
            "source": source,
            "host_id": host_id,
        },
    )

    row = db.execute(
        "SELECT * FROM enrollment_requests WHERE id = ?",
        (cursor.lastrowid,),
    ).fetchone()
    return _row_to_dict(row)


def get_enrollment_by_node_id(
    db: sqlite3.Connection,
    node_id: str,
) -> dict | None:
    """Look up an enrollment record by node_id.

    Returns the most recent enrollment record for the given node_id that
    is in 'pending' or 'approved' status. Returns None if no active record
    exists.

    Args:
        db: An open SQLite connection.
        node_id: The node identifier to search for.

    Returns:
        A dict with the enrollment record, or None if not found.
    """
    row = db.execute(
        "SELECT * FROM enrollment_requests WHERE node_id = ? "
        "AND status IN ('pending', 'approved') "
        "ORDER BY requested_at DESC LIMIT 1",
        (node_id,),
    ).fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


def get_approved_enrollment_by_node_id(
    db: sqlite3.Connection,
    node_id: str,
) -> dict | None:
    """Return the most recent approved enrollment record for node_id.

    Used by the enrollment endpoint's auto-rotate path. Returns None if
    there is no approved enrollment for the given node_id.
    """
    row = db.execute(
        "SELECT * FROM enrollment_requests WHERE node_id = ? "
        "AND status = 'approved' "
        "ORDER BY requested_at DESC LIMIT 1",
        (node_id,),
    ).fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


def list_enrollments_for_host(
    db: sqlite3.Connection,
    host_id: str,
) -> list[dict]:
    """Return all enrollment records linked to a given host_id, most recent first.

    Used by the admin UI's per-host view to show the security and monitor
    agents side-by-side.
    """
    rows = db.execute(
        "SELECT * FROM enrollment_requests WHERE host_id = ? ORDER BY requested_at DESC",
        (host_id,),
    ).fetchall()
    return [_row_to_dict(row) for row in rows]


def list_enrollment_requests(
    db: sqlite3.Connection,
    status: str | None = None,
) -> list[dict]:
    """List enrollment records, optionally filtered by status.

    Args:
        db: An open SQLite connection.
        status: If provided, only return records with this status.

    Returns:
        A list of enrollment record dicts, ordered by requested_at DESC.
    """
    if status is not None:
        rows = db.execute(
            "SELECT * FROM enrollment_requests WHERE status = ? ORDER BY requested_at DESC",
            (status,),
        ).fetchall()
    else:
        rows = db.execute("SELECT * FROM enrollment_requests ORDER BY requested_at DESC").fetchall()
    return [_row_to_dict(row) for row in rows]


# ── Enrollment Lifecycle ─────────────────────────────────────────────────


def approve_enrollment(
    db: sqlite3.Connection,
    record_id: int,
    approved_by: str,
    host_id: str | None = None,
) -> str:
    """Approve a pending enrollment record and issue credentials.

    Generates an API key restricted to the record's node_id, links it to
    the enrollment record, transitions the record to 'approved', and creates
    audit log entries.

    Args:
        db: An open SQLite connection.
        record_id: The id of the enrollment record to approve.
        approved_by: The username of the admin approving the request.
        host_id: Optional host linkage. If provided, the issued API key
            is stamped with this host_id and the enrollment_requests row
            is also stamped, linking the security-agent and monitor-agent
            keys on the same physical host.

    Returns:
        The raw API token (to be returned to the agent exactly once).

    Raises:
        ValueError: If the record does not exist or is not in 'pending' status.
    """
    row = db.execute(
        "SELECT * FROM enrollment_requests WHERE id = ?",
        (record_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"Enrollment record {record_id} not found")
    if row["status"] != "pending":
        raise ValueError(f"Enrollment record {record_id} is not pending (status: {row['status']})")

    node_id = row["node_id"]
    now = _utcnow()

    # Resolve host_id: explicit param wins, otherwise fall back to whatever
    # the enrollment row already has (in case this is a re-approval of a
    # record that was previously stamped).
    resolved_host_id = host_id or row["host_id"]

    # Generate API key with node_id restriction
    label = f"auto-enrolled:{node_id}:{now}"
    raw_token = create_api_key(
        db,
        label=label,
        node_id_restriction=node_id,
        created_by=None,
        host_id=resolved_host_id,
    )

    # Get the api_key_id by looking up the hash
    key_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    key_row = db.execute(
        "SELECT id FROM api_keys WHERE key_hash = ?",
        (key_hash,),
    ).fetchone()
    api_key_id = key_row["id"]

    # Update enrollment record — store raw token for one-time retrieval
    db.execute(
        "UPDATE enrollment_requests SET status = 'approved', decided_at = ?, "
        "decided_by = ?, api_key_id = ?, pending_token = ?, host_id = ? WHERE id = ?",
        (now, approved_by, api_key_id, raw_token, resolved_host_id, record_id),
    )
    db.commit()

    # Audit: status change
    record_audit(
        db,
        actor=approved_by,
        actor_ip=None,
        action_type="enrollment_status_change",
        target=node_id,
        details={
            "record_id": record_id,
            "previous_status": "pending",
            "new_status": "approved",
            "host_id": resolved_host_id,
        },
    )

    # Audit: credential issued
    record_audit(
        db,
        actor=approved_by,
        actor_ip=None,
        action_type="enrollment_credential_issued",
        target=node_id,
        details={"record_id": record_id, "api_key_id": api_key_id, "host_id": resolved_host_id},
    )

    return raw_token


def reject_enrollment(
    db: sqlite3.Connection,
    record_id: int,
    rejected_by: str,
) -> None:
    """Reject a pending enrollment record.

    Transitions the record to 'rejected' and creates an audit log entry.

    Args:
        db: An open SQLite connection.
        record_id: The id of the enrollment record to reject.
        rejected_by: The username of the admin rejecting the request.

    Raises:
        ValueError: If the record does not exist or is not in 'pending' status.
    """
    row = db.execute(
        "SELECT * FROM enrollment_requests WHERE id = ?",
        (record_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"Enrollment record {record_id} not found")
    if row["status"] != "pending":
        raise ValueError(f"Enrollment record {record_id} is not pending (status: {row['status']})")

    node_id = row["node_id"]
    now = _utcnow()

    db.execute(
        "UPDATE enrollment_requests SET status = 'rejected', decided_at = ?, "
        "decided_by = ? WHERE id = ?",
        (now, rejected_by, record_id),
    )
    db.commit()

    record_audit(
        db,
        actor=rejected_by,
        actor_ip=None,
        action_type="enrollment_status_change",
        target=node_id,
        details={
            "record_id": record_id,
            "previous_status": "pending",
            "new_status": "rejected",
        },
    )


def revoke_enrollment(
    db: sqlite3.Connection,
    record_id: int,
    revoked_by: str,
) -> None:
    """Revoke an approved enrollment record.

    Deactivates the associated API key, transitions the record to 'revoked',
    and creates an audit log entry.

    Args:
        db: An open SQLite connection.
        record_id: The id of the enrollment record to revoke.
        revoked_by: The username of the admin revoking the enrollment.

    Raises:
        ValueError: If the record does not exist or is not in 'approved' status.
    """
    row = db.execute(
        "SELECT * FROM enrollment_requests WHERE id = ?",
        (record_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"Enrollment record {record_id} not found")
    if row["status"] != "approved":
        raise ValueError(f"Enrollment record {record_id} is not approved (status: {row['status']})")

    node_id = row["node_id"]
    api_key_id = row["api_key_id"]
    now = _utcnow()

    # Deactivate the API key
    if api_key_id is not None:
        db.execute(
            "UPDATE api_keys SET is_active = 0 WHERE id = ?",
            (api_key_id,),
        )
        db.commit()

    # Update enrollment record
    db.execute(
        "UPDATE enrollment_requests SET status = 'revoked', decided_at = ?, "
        "decided_by = ? WHERE id = ?",
        (now, revoked_by, record_id),
    )
    db.commit()

    record_audit(
        db,
        actor=revoked_by,
        actor_ip=None,
        action_type="enrollment_status_change",
        target=node_id,
        details={
            "record_id": record_id,
            "previous_status": "approved",
            "new_status": "revoked",
            "api_key_id": api_key_id,
        },
    )


def rotate_enrollment_credentials(
    db: sqlite3.Connection,
    record_id: int,
    rotated_by: str,
) -> str:
    """Rotate credentials for an approved enrollment record.

    Revokes the old API key, generates a new one with the same node_id
    restriction, updates the enrollment record, resets credentials_retrieved,
    and creates an audit log entry.

    Args:
        db: An open SQLite connection.
        record_id: The id of the enrollment record to rotate.
        rotated_by: The username of the admin initiating rotation.

    Returns:
        The new raw API token.

    Raises:
        ValueError: If the record does not exist or is not in 'approved' status.
    """
    row = db.execute(
        "SELECT * FROM enrollment_requests WHERE id = ?",
        (record_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"Enrollment record {record_id} not found")
    if row["status"] != "approved":
        raise ValueError(f"Enrollment record {record_id} is not approved (status: {row['status']})")

    node_id = row["node_id"]
    old_api_key_id = row["api_key_id"]
    host_id = row["host_id"]
    now = _utcnow()

    # Revoke old key
    if old_api_key_id is not None:
        db.execute(
            "UPDATE api_keys SET is_active = 0 WHERE id = ?",
            (old_api_key_id,),
        )
        db.commit()

    # Generate new key with same node_id restriction and host_id
    label = f"auto-enrolled:{node_id}:{now}"
    raw_token = create_api_key(
        db,
        label=label,
        node_id_restriction=node_id,
        created_by=None,
        host_id=host_id,
    )

    # Get the new api_key_id
    key_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    key_row = db.execute(
        "SELECT id FROM api_keys WHERE key_hash = ?",
        (key_hash,),
    ).fetchone()
    new_api_key_id = key_row["id"]

    # Update enrollment record
    db.execute(
        "UPDATE enrollment_requests SET api_key_id = ?, credentials_retrieved = 0, "
        "pending_token = ? WHERE id = ?",
        (new_api_key_id, raw_token, record_id),
    )
    db.commit()

    record_audit(
        db,
        actor=rotated_by,
        actor_ip=None,
        action_type="enrollment_credential_rotated",
        target=node_id,
        details={
            "record_id": record_id,
            "old_api_key_id": old_api_key_id,
            "new_api_key_id": new_api_key_id,
        },
    )

    return raw_token


def mark_credentials_retrieved(
    db: sqlite3.Connection,
    record_id: int,
) -> None:
    """Mark credentials as retrieved and clear the pending token.

    Args:
        db: An open SQLite connection.
        record_id: The id of the enrollment record.
    """
    db.execute(
        "UPDATE enrollment_requests SET credentials_retrieved = 1, pending_token = NULL WHERE id = ?",
        (record_id,),
    )
    db.commit()


def delete_enrollment(
    db: sqlite3.Connection,
    record_id: int,
    deleted_by: str,
) -> None:
    """Permanently delete a revoked or rejected enrollment record.

    Only records with status 'revoked' or 'rejected' can be deleted.
    Active (pending/approved) records must be revoked or rejected first.

    Args:
        db: An open SQLite connection.
        record_id: The id of the enrollment record to delete.
        deleted_by: The username of the admin performing the deletion.

    Raises:
        ValueError: If the record does not exist or is not in a deletable status.
    """
    row = db.execute(
        "SELECT * FROM enrollment_requests WHERE id = ?",
        (record_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"Enrollment record {record_id} not found")
    if row["status"] not in ("revoked", "rejected"):
        raise ValueError(
            f"Enrollment record {record_id} cannot be deleted "
            f"(status: {row['status']}). Only revoked or rejected records can be deleted."
        )

    node_id = row["node_id"]

    db.execute(
        "DELETE FROM enrollment_requests WHERE id = ?",
        (record_id,),
    )
    db.commit()

    record_audit(
        db,
        actor=deleted_by,
        actor_ip=None,
        action_type="enrollment_record_deleted",
        target=node_id,
        details={"record_id": record_id, "previous_status": row["status"]},
    )


def reissue_enrollment(
    db: sqlite3.Connection,
    record_id: int,
    reissued_by: str,
) -> str:
    """Re-issue credentials for a revoked enrollment.

    Transitions the record back to 'approved', generates a fresh API key,
    and stores it in pending_token for the agent to retrieve on its next
    poll. The agent's existing enrollment poll loop will pick up the new
    credentials automatically.

    Args:
        db: An open SQLite connection.
        record_id: The id of the enrollment record to re-issue.
        reissued_by: The username of the admin performing the re-issue.

    Returns:
        The raw API token (stored in pending_token for agent retrieval).

    Raises:
        ValueError: If the record does not exist or is not in 'revoked' status.
    """
    row = db.execute(
        "SELECT * FROM enrollment_requests WHERE id = ?",
        (record_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"Enrollment record {record_id} not found")
    if row["status"] != "revoked":
        raise ValueError(
            f"Enrollment record {record_id} is not revoked (status: {row['status']}). "
            f"Use 'Rotate' for approved records."
        )

    node_id = row["node_id"]
    host_id = row["host_id"]
    now = _utcnow()

    # Generate a new API key with node_id restriction and host_id
    label = f"reissued:{node_id}:{now}"
    raw_token = create_api_key(
        db,
        label=label,
        node_id_restriction=node_id,
        created_by=None,
        host_id=host_id,
    )

    # Get the new api_key_id
    key_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    key_row = db.execute(
        "SELECT id FROM api_keys WHERE key_hash = ?",
        (key_hash,),
    ).fetchone()
    new_api_key_id = key_row["id"]

    # Transition back to approved with fresh credentials
    db.execute(
        "UPDATE enrollment_requests SET status = 'approved', decided_at = ?, "
        "decided_by = ?, api_key_id = ?, pending_token = ?, credentials_retrieved = 0 "
        "WHERE id = ?",
        (now, reissued_by, new_api_key_id, raw_token, record_id),
    )
    db.commit()

    record_audit(
        db,
        actor=reissued_by,
        actor_ip=None,
        action_type="enrollment_credential_reissued",
        target=node_id,
        details={
            "record_id": record_id,
            "new_api_key_id": new_api_key_id,
            "previous_status": "revoked",
        },
    )

    return raw_token


# ── Host linkage helpers ──────────────────────────────────────────────────


def get_host_id_for_node(
    db: sqlite3.Connection,
    node_id: str,
) -> str | None:
    """Return the host_id of the most recent approved enrollment for node_id.

    Used by the enrollment endpoint to link a new agent enrollment to an
    existing host. Returns None if no approved enrollment exists for the
    given node_id.
    """
    row = db.execute(
        "SELECT host_id FROM enrollment_requests "
        "WHERE node_id = ? AND status = 'approved' AND host_id IS NOT NULL "
        "ORDER BY requested_at DESC LIMIT 1",
        (node_id,),
    ).fetchone()
    if row is None:
        return None
    return row["host_id"]


def get_host_id_for_machine(
    db: sqlite3.Connection,
    machine_id: str,
) -> str | None:
    """Return the host_id of an approved enrollment whose asset has the
    given machine_id.

    This is how the second agent (e.g. monitor) on a host discovers the
    host_id created by the first agent (e.g. security). The asset's
    machine_id is set when the first agent enrolled (see
    ``app/enrollment.py``).

    Returns None if no matching approved enrollment is found.
    """
    if not machine_id:
        return None
    row = db.execute(
        "SELECT er.host_id FROM enrollment_requests er "
        "JOIN assets a ON a.asset_id = er.asset_id "
        "JOIN asset_aliases aa ON aa.asset_id = a.asset_id "
        "WHERE aa.alias_type = 'machine_id' AND aa.alias_value = ? "
        "  AND er.status = 'approved' AND er.host_id IS NOT NULL "
        "ORDER BY er.requested_at DESC LIMIT 1",
        (machine_id,),
    ).fetchone()
    if row is None:
        return None
    return row["host_id"]


def auto_rotate_on_reenroll(
    db: sqlite3.Connection,
    record_id: int,
    rotated_by: str = "auto-rotate:reenroll",
) -> str:
    """Revoke the existing key on an approved enrollment and issue a new one.

    Used by the enrollment endpoint's self-heal path: the same node_id
    re-enrolls and presents a still-active old key (via the
    X-Existing-Credentials header). The server rotates the key in place
    and returns the new raw token.

    Args:
        db: An open SQLite connection.
        record_id: The id of the approved enrollment record to rotate.
        rotated_by: The actor recorded in the audit log. Defaults to
            ``"auto-rotate:reenroll"``.

    Returns:
        The new raw API token.

    Raises:
        ValueError: If the record does not exist or is not in 'approved'
            status, or if the record has no host_id linkage.
    """
    row = db.execute(
        "SELECT * FROM enrollment_requests WHERE id = ?",
        (record_id,),
    ).fetchone()
    if row is None:
        raise ValueError(f"Enrollment record {record_id} not found")
    if row["status"] != "approved":
        raise ValueError(f"Enrollment record {record_id} is not approved (status: {row['status']})")

    node_id = row["node_id"]
    host_id = row["host_id"]
    old_api_key_id = row["api_key_id"]
    if not host_id:
        raise ValueError(
            f"Enrollment record {record_id} has no host_id linkage; cannot auto-rotate"
        )

    now = _utcnow()

    # Revoke the existing key.
    if old_api_key_id is not None:
        db.execute(
            "UPDATE api_keys SET is_active = 0 WHERE id = ?",
            (old_api_key_id,),
        )
        db.commit()

    # Issue a new key with the same node_id restriction and host_id.
    label = f"auto-rotated:{node_id}:{now}"
    raw_token = create_api_key(
        db,
        label=label,
        node_id_restriction=node_id,
        created_by=None,
        host_id=host_id,
    )

    # Look up the new api_key_id.
    key_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    key_row = db.execute(
        "SELECT id FROM api_keys WHERE key_hash = ?",
        (key_hash,),
    ).fetchone()
    new_api_key_id = key_row["id"]

    # Update the enrollment record with the new key and reset retrieval flag.
    db.execute(
        "UPDATE enrollment_requests SET api_key_id = ?, credentials_retrieved = 0, "
        "pending_token = ? WHERE id = ?",
        (new_api_key_id, raw_token, record_id),
    )
    db.commit()

    record_audit(
        db,
        actor=rotated_by,
        actor_ip=None,
        action_type="enrollment_credential_rotated",
        target=node_id,
        details={
            "record_id": record_id,
            "old_api_key_id": old_api_key_id,
            "new_api_key_id": new_api_key_id,
            "host_id": host_id,
            "auto": True,
        },
    )

    return raw_token
