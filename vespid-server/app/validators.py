"""Schema validation for SecurityEvent payloads.

Validates incoming event dicts against the canonical SecurityEvent schema
before they are persisted to the database.

Validation rules:
- node_id: required, non-empty string
- timestamp: required, valid ISO-8601 datetime string
- source_ip: required, valid IPv4 or IPv6 address
- event_type: required, non-empty string
- action_taken: required, non-empty string
- geo_data: required, must be a dict
- event_id: required, non-empty string, unique within batch
- metadata: optional, must be a dict if present
"""

import ipaddress
from dataclasses import dataclass, field
from datetime import datetime


@dataclass
class ValidationResult:
    """Result of validating a batch of events.

    Attributes:
        valid: Events that passed all validation checks.
        errors: One entry per invalid event, each containing:
            - index: position in the original batch
            - event_id: the event_id if present, else None
            - errors: list of human-readable error strings
    """

    valid: list[dict] = field(default_factory=list)
    errors: list[dict] = field(default_factory=list)


# Fields that must be present and non-empty strings.
_REQUIRED_STRING_FIELDS = ("node_id", "event_type", "action_taken", "event_id")


def _validate_ip(value: str) -> bool:
    """Return True if *value* is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def _validate_timestamp(value: str) -> bool:
    """Return True if *value* is a valid ISO-8601 datetime string."""
    try:
        datetime.fromisoformat(value)
        return True
    except (ValueError, TypeError):
        return False


def validate_event(event: dict) -> list[str]:
    """Validate a single event dict against the SecurityEvent schema.

    Args:
        event: A dict representing a SecurityEvent.

    Returns:
        A list of error strings. An empty list means the event is valid.
    """
    errors: list[str] = []

    # Check that event is actually a dict
    if not isinstance(event, dict):
        return ["event must be a dict"]

    # Required non-empty string fields
    for field_name in _REQUIRED_STRING_FIELDS:
        value = event.get(field_name)
        if value is None:
            errors.append(f"missing required field: {field_name}")
        elif not isinstance(value, str):
            errors.append(f"{field_name} must be a string")
        elif not value.strip():
            errors.append(f"{field_name} must not be empty")

    # timestamp: required, valid ISO-8601
    ts = event.get("timestamp")
    if ts is None:
        errors.append("missing required field: timestamp")
    elif not isinstance(ts, str):
        errors.append("timestamp must be a string")
    elif not _validate_timestamp(ts):
        errors.append("timestamp must be a valid ISO-8601 datetime")

    # source_ip: required, valid IPv4 or IPv6
    ip = event.get("source_ip")
    if ip is None:
        errors.append("missing required field: source_ip")
    elif not isinstance(ip, str):
        errors.append("source_ip must be a string")
    elif not _validate_ip(ip):
        errors.append("source_ip must be a valid IPv4 or IPv6 address")

    # geo_data: required, must be a dict
    geo = event.get("geo_data")
    if geo is None:
        errors.append("missing required field: geo_data")
    elif not isinstance(geo, dict):
        errors.append("geo_data must be a dict")

    # metadata: optional, but must be a dict if present
    if "metadata" in event:
        meta = event["metadata"]
        if not isinstance(meta, dict):
            errors.append("metadata must be a dict if present")

    return errors


def validate_batch(events: list[dict]) -> ValidationResult:
    """Validate a batch of events, separating valid from invalid.

    In addition to per-event validation, this function checks that
    event_id values are unique within the batch. Duplicate event_ids
    cause the later occurrences to be marked as invalid.

    Args:
        events: A list of event dicts.

    Returns:
        A ValidationResult with valid events and error details.
    """
    result = ValidationResult()
    seen_event_ids: set[str] = set()

    for index, event in enumerate(events):
        errors = validate_event(event)

        # Check event_id uniqueness within the batch
        event_id = event.get("event_id") if isinstance(event, dict) else None
        if isinstance(event_id, str) and event_id.strip():
            if event_id in seen_event_ids:
                errors.append(f"duplicate event_id in batch: {event_id}")
            else:
                seen_event_ids.add(event_id)

        if errors:
            result.errors.append(
                {
                    "index": index,
                    "event_id": event_id if isinstance(event_id, str) else None,
                    "errors": errors,
                }
            )
        else:
            result.valid.append(event)

    return result
