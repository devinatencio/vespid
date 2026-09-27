"""Host threat event ingest handling for the auditd pipeline.

Provides validation and storage for host_threat events received
via POST /api/v1/ingest. These events originate from the agent-side
auditd detection pipeline and are stored in the host_events table.

Requirements: 8.2, 8.5
"""

import logging

log = logging.getLogger(__name__)

# Required fields for host_threat events (all must be non-empty)
_REQUIRED_FIELDS = [
    "hostname",
    "timestamp",
    "event_type",
    "rule_name",
    "pid",
    "ppid",
    "exe",
    "command_line",
    "uid",
    "auid",
    "raw_line",
]

# Fields that must be integers
_INTEGER_FIELDS = ["pid", "ppid", "uid", "auid"]

# Numeric severity weight (from agent-side HostScorer) → severity name.
# Mirrors the mapping used by scoring/alerting (_SEVERITY_WEIGHTS).
_SEVERITY_NAME_BY_WEIGHT = {
    50: "critical",
    25: "high",
    10: "medium",
    5: "low",
    1: "informational",
}


def _resolve_severity_name(severity_weight) -> str | None:
    """Map a numeric severity weight to its severity name."""
    try:
        return _SEVERITY_NAME_BY_WEIGHT.get(int(severity_weight))
    except (ValueError, TypeError):
        return None


def validate_host_threat(event: dict) -> list[str]:
    """Validate a host_threat event payload.

    Checks that all required fields are present and non-empty, and that
    pid/ppid/uid/auid are integers (or integer-coercible strings).

    Args:
        event: A dict representing a host_threat event.

    Returns:
        A list of error strings. An empty list means the event is valid.
    """
    errors: list[str] = []

    # Check required fields are present and non-empty
    for field in _REQUIRED_FIELDS:
        val = event.get(field)
        if val is None or val == "":
            errors.append(f"missing or empty required field: {field}")

    # Check integer fields
    for field in _INTEGER_FIELDS:
        val = event.get(field)
        if val is None:
            # Already reported as missing above
            continue
        if not isinstance(val, int):
            try:
                int(val)
            except (ValueError, TypeError):
                errors.append(f"{field} must be an integer, got: {type(val).__name__}")

    return errors


def store_host_threat(db, event: dict, node_id: str) -> None:
    """Store a validated host_threat event in the host_events table.

    Args:
        db: An open database connection (sqlite3.Connection).
        event: A validated host_threat event dict.
        node_id: The node_id from the event or API key context.
    """
    db.execute(
        """INSERT INTO host_events
           (hostname, timestamp, event_type, rule_name, pid, ppid,
            exe, command_line, uid, auid, raw_line, node_id)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
        (
            str(event["hostname"]),
            str(event["timestamp"]),
            str(event["event_type"]),
            str(event["rule_name"]),
            int(event["pid"]),
            int(event["ppid"]),
            str(event["exe"])[:1024],
            str(event["command_line"])[:32768],
            int(event["uid"]),
            int(event["auid"]),
            str(event["raw_line"])[:65535],
            node_id,
        ),
    )
    db.commit()


def process_host_threat_events(
    db, events: list[dict], node_id_restriction: str | None = None
) -> tuple[int, list[dict]]:
    """Validate and store a list of host_threat events.

    Separates valid events (stored in host_events table) from invalid ones
    (returned with error reasons).

    Args:
        db: An open database connection.
        events: List of (index, event) tuples where index is the position
                in the original batch.
        node_id_restriction: If set, only events with this node_id are accepted.

    Returns:
        A tuple of (accepted_count, rejected_list) where rejected_list
        contains dicts with 'index' and 'errors' keys.
    """
    accepted = 0
    rejected: list[dict] = []

    for index, event in events:
        # Flatten metadata fields to top level — the agent wraps host_threat
        # fields inside SecurityEvent.metadata, but validate/store expect them
        # at the top level of the event dict.
        meta = event.get("metadata")
        if isinstance(meta, dict):
            for key in (
                "hostname",
                "timestamp",
                "event_type",
                "rule_name",
                "pid",
                "ppid",
                "exe",
                "command_line",
                "uid",
                "auid",
                "raw_line",
                "severity_weight",
                "parent_exe",
                "parent_command_line",
            ):
                if key not in event and key in meta:
                    event[key] = meta[key]

        # The agent publishes the bus-level event_type ("host_threat") at the
        # top level and the rule's real severity only as a numeric weight in
        # metadata. Derive a severity name so scoring/alerting tiers are based
        # on the actual detection rather than a constant placeholder.
        severity_name = _resolve_severity_name(event.get("severity_weight"))
        if severity_name:
            event["event_type"] = severity_name

        errors = validate_host_threat(event)

        # Enforce node_id restriction if present
        node_id = event.get("node_id", "")
        if node_id_restriction and node_id != node_id_restriction:
            errors.append(f"node_id mismatch: key is restricted to '{node_id_restriction}'")

        if errors:
            rejected.append({"index": index, "errors": errors})
        else:
            try:
                store_host_threat(db, event, node_id)
                accepted += 1
            except Exception:
                log.exception("Failed to store host_threat event at index %d", index)
                rejected.append({"index": index, "errors": ["internal storage error"]})

    return accepted, rejected
