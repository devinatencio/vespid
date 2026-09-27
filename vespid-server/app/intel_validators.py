"""Input validation for Intelligence Database payloads.

Validates sighting, block event, batch, and query payloads against the
Intelligence API schema before they reach the service/database layer.

Validation rules follow the same pattern as app/validators.py:
each function returns a list of error strings (empty list = valid).
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import datetime

# Maximum sizes and ranges
_MAX_NODE_ID_LEN = 128
_MAX_EVENT_TYPE_LEN = 64
_MAX_DETECTION_RULE_LEN = 128
_MAX_THREAT_TAG_LEN = 64
_MAX_METADATA_BYTES = 4096
_MAX_BLOCK_TTL = 604800  # 7 days in seconds
_MAX_BATCH_SIZE = 500
_MIN_PAGE = 1
_MIN_PER_PAGE = 1
_MAX_PER_PAGE = 200
_DEFAULT_PER_PAGE = 50

# Regex for valid threat_tag: alphanumeric, hyphens, underscores
_THREAT_TAG_RE = re.compile(r"^[a-zA-Z0-9_-]+$")

# Regex for ISO 3166-1 alpha-2 country code: exactly 2 uppercase letters
_GEO_COUNTRY_RE = re.compile(r"^[A-Z]{2}$")


def _validate_ip(value: str) -> bool:
    """Return True if value is a valid IPv4 or IPv6 address."""
    try:
        ipaddress.ip_address(value)
        return True
    except (ValueError, TypeError):
        return False


def _validate_timestamp(value: str) -> bool:
    """Return True if value is a valid ISO-8601 datetime string."""
    try:
        datetime.fromisoformat(value)
        return True
    except (ValueError, TypeError):
        return False


def validate_sighting(payload: dict) -> list[str]:
    """Validate a sighting payload.

    Required fields:
        - source_ip: valid IPv4 or IPv6 address
        - node_id: non-empty string, max 128 characters
        - event_type: non-empty string, max 64 characters
        - timestamp: valid ISO-8601 datetime string

    Optional fields:
        - metadata: dict, max 4096 bytes when serialized to JSON
        - threat_tag: alphanumeric/hyphens/underscores, max 64 characters

    Returns:
        A list of error strings. An empty list means the payload is valid.
    """
    errors: list[str] = []

    if not isinstance(payload, dict):
        return ["payload must be a dict"]

    # source_ip: required, valid IPv4 or IPv6
    ip = payload.get("source_ip")
    if ip is None:
        errors.append("missing required field: source_ip")
    elif not isinstance(ip, str):
        errors.append("source_ip must be a string")
    elif not _validate_ip(ip):
        errors.append("source_ip: invalid IPv4/IPv6 address")

    # node_id: required, non-empty, max 128 chars
    node_id = payload.get("node_id")
    if node_id is None:
        errors.append("missing required field: node_id")
    elif not isinstance(node_id, str):
        errors.append("node_id must be a string")
    elif not node_id.strip():
        errors.append("node_id must not be empty")
    elif len(node_id) > _MAX_NODE_ID_LEN:
        errors.append(f"node_id must be at most {_MAX_NODE_ID_LEN} characters")

    # event_type: required, non-empty, max 64 chars
    event_type = payload.get("event_type")
    if event_type is None:
        errors.append("missing required field: event_type")
    elif not isinstance(event_type, str):
        errors.append("event_type must be a string")
    elif not event_type.strip():
        errors.append("event_type must not be empty")
    elif len(event_type) > _MAX_EVENT_TYPE_LEN:
        errors.append(f"event_type must be at most {_MAX_EVENT_TYPE_LEN} characters")

    # timestamp: required, valid ISO-8601
    ts = payload.get("timestamp")
    if ts is None:
        errors.append("missing required field: timestamp")
    elif not isinstance(ts, str):
        errors.append("timestamp must be a string")
    elif not _validate_timestamp(ts):
        errors.append("timestamp must be a valid ISO-8601 datetime")

    # metadata: optional, must be a dict, max 4096 bytes serialized
    if "metadata" in payload:
        meta = payload["metadata"]
        if meta is not None:
            if not isinstance(meta, dict):
                errors.append("metadata must be a dict")
            else:
                try:
                    serialized = json.dumps(meta)
                    if len(serialized.encode("utf-8")) > _MAX_METADATA_BYTES:
                        errors.append(
                            f"metadata must be at most {_MAX_METADATA_BYTES} bytes when serialized"
                        )
                except (TypeError, ValueError):
                    errors.append("metadata must be JSON-serializable")

    # threat_tag: optional, alphanumeric/hyphens/underscores, max 64 chars
    if "threat_tag" in payload:
        tag = payload["threat_tag"]
        if tag is not None:
            if not isinstance(tag, str):
                errors.append("threat_tag must be a string")
            elif not tag:
                errors.append("threat_tag must not be empty")
            elif len(tag) > _MAX_THREAT_TAG_LEN:
                errors.append(f"threat_tag must be at most {_MAX_THREAT_TAG_LEN} characters")
            elif not _THREAT_TAG_RE.match(tag):
                errors.append(
                    "threat_tag must contain only alphanumeric characters, hyphens, and underscores"
                )

    return errors


def validate_block_event(payload: dict) -> list[str]:
    """Validate a block event payload.

    Required fields:
        - source_ip: valid IPv4 or IPv6 address
        - node_id: 1 to 128 characters
        - event_type: 1 to 64 characters
        - detection_rule: 0 to 128 characters (can be empty string)
        - block_ttl_seconds: integer, 0 to 604800
        - timestamp: valid ISO-8601 UTC datetime string

    Returns:
        A list of error strings. An empty list means the payload is valid.
    """
    errors: list[str] = []

    if not isinstance(payload, dict):
        return ["payload must be a dict"]

    # source_ip: required, valid IPv4 or IPv6
    ip = payload.get("source_ip")
    if ip is None:
        errors.append("missing required field: source_ip")
    elif not isinstance(ip, str):
        errors.append("source_ip must be a string")
    elif not _validate_ip(ip):
        errors.append("source_ip: invalid IPv4/IPv6 address")

    # node_id: required, 1-128 chars
    node_id = payload.get("node_id")
    if node_id is None:
        errors.append("missing required field: node_id")
    elif not isinstance(node_id, str):
        errors.append("node_id must be a string")
    elif not node_id.strip():
        errors.append("node_id must not be empty")
    elif len(node_id) > _MAX_NODE_ID_LEN:
        errors.append(f"node_id must be at most {_MAX_NODE_ID_LEN} characters")

    # event_type: required, 1-64 chars
    event_type = payload.get("event_type")
    if event_type is None:
        errors.append("missing required field: event_type")
    elif not isinstance(event_type, str):
        errors.append("event_type must be a string")
    elif not event_type.strip():
        errors.append("event_type must not be empty")
    elif len(event_type) > _MAX_EVENT_TYPE_LEN:
        errors.append(f"event_type must be at most {_MAX_EVENT_TYPE_LEN} characters")

    # detection_rule: required field, 0-128 chars (empty string is valid)
    detection_rule = payload.get("detection_rule")
    if detection_rule is None:
        errors.append("missing required field: detection_rule")
    elif not isinstance(detection_rule, str):
        errors.append("detection_rule must be a string")
    elif len(detection_rule) > _MAX_DETECTION_RULE_LEN:
        errors.append(f"detection_rule must be at most {_MAX_DETECTION_RULE_LEN} characters")

    # block_ttl_seconds: required, integer 0-604800
    ttl = payload.get("block_ttl_seconds")
    if ttl is None:
        errors.append("missing required field: block_ttl_seconds")
    elif isinstance(ttl, bool) or not isinstance(ttl, int):
        errors.append("block_ttl_seconds must be an integer")
    elif ttl < 0 or ttl > _MAX_BLOCK_TTL:
        errors.append(f"block_ttl_seconds must be between 0 and {_MAX_BLOCK_TTL}")

    # timestamp: required, valid ISO-8601
    ts = payload.get("timestamp")
    if ts is None:
        errors.append("missing required field: timestamp")
    elif not isinstance(ts, str):
        errors.append("timestamp must be a string")
    elif not _validate_timestamp(ts):
        errors.append("timestamp must be a valid ISO-8601 datetime")

    return errors


def validate_batch_event(event: dict) -> list[str]:
    """Validate a single event within a batch.

    Checks the event_kind field ("sighting" or "block") and delegates
    to the appropriate validator.

    Returns:
        A list of error strings. An empty list means the event is valid.
    """
    errors: list[str] = []

    if not isinstance(event, dict):
        return ["event must be a dict"]

    event_kind = event.get("event_kind")
    if event_kind is None:
        errors.append("missing required field: event_kind")
        return errors
    elif not isinstance(event_kind, str):
        errors.append("event_kind must be a string")
        return errors
    elif event_kind not in ("sighting", "block"):
        errors.append('event_kind must be "sighting" or "block"')
        return errors

    # Delegate to the appropriate validator
    if event_kind == "sighting":
        errors.extend(validate_sighting(event))
    else:
        errors.extend(validate_block_event(event))

    return errors


def validate_batch_request(payload: dict) -> list[str]:
    """Validate the batch request envelope.

    Checks:
        - events field is present and is a list
        - events list length is <= 500

    Returns:
        A list of error strings. An empty list means the envelope is valid.
    """
    errors: list[str] = []

    if not isinstance(payload, dict):
        return ["payload must be a dict"]

    events = payload.get("events")
    if events is None:
        errors.append("missing required field: events")
    elif not isinstance(events, list):
        errors.append("events must be a list")
    elif len(events) > _MAX_BATCH_SIZE:
        errors.append(f"batch size must not exceed {_MAX_BATCH_SIZE} events")

    return errors


def validate_query_params(params: dict) -> list[str]:
    """Validate query filter parameters.

    Validates:
        - geo_country: ISO 3166-1 alpha-2 format (2 uppercase letters)
        - repeat_offender: boolean-like value ("true", "false", "1", "0")
        - page: integer >= 1
        - per_page: integer 1-200

    Returns:
        A list of error strings. An empty list means the params are valid.
    """
    errors: list[str] = []

    if not isinstance(params, dict):
        return ["params must be a dict"]

    # geo_country: optional, must be 2 uppercase letters if present
    if "geo_country" in params:
        geo = params["geo_country"]
        if geo is not None:
            if not isinstance(geo, str):
                errors.append("geo_country must be a string")
            elif not _GEO_COUNTRY_RE.match(geo):
                errors.append(
                    "geo_country must be a valid ISO 3166-1 alpha-2 code (2 uppercase letters)"
                )

    # repeat_offender: optional, must be a boolean-like value
    if "repeat_offender" in params:
        ro = params["repeat_offender"]
        if ro is not None:
            valid_values = ("true", "false", "1", "0", True, False)
            if ro not in valid_values:
                errors.append("repeat_offender must be a boolean value (true/false)")

    # page: optional, integer >= 1
    if "page" in params:
        page = params["page"]
        if page is not None:
            try:
                page_int = int(page)
                if page_int < _MIN_PAGE:
                    errors.append(f"page must be >= {_MIN_PAGE}")
            except (ValueError, TypeError):
                errors.append("page must be an integer")

    # per_page: optional, integer 1-200
    if "per_page" in params:
        per_page = params["per_page"]
        if per_page is not None:
            try:
                pp_int = int(per_page)
                if pp_int < _MIN_PER_PAGE or pp_int > _MAX_PER_PAGE:
                    errors.append(f"per_page must be between {_MIN_PER_PAGE} and {_MAX_PER_PAGE}")
            except (ValueError, TypeError):
                errors.append("per_page must be an integer")

    return errors
