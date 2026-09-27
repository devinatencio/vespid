"""Unit tests for schema validation edge cases.

Tests empty strings, wrong types, missing fields, extra fields, invalid IPs,
invalid timestamps, and batch-level uniqueness checks.

Requirements: 1.1, 1.3, 1.5
"""

import pytest

from app.validators import ValidationResult, validate_batch, validate_event


# ── Helpers ──────────────────────────────────────────────────────────────


def _valid_event(**overrides) -> dict:
    """Return a minimal valid SecurityEvent dict, with optional overrides."""
    event = {
        "node_id": "node-01",
        "timestamp": "2025-01-15T10:30:00Z",
        "source_ip": "203.0.113.42",
        "event_type": "SSH_BRUTE",
        "action_taken": "BLOCKED",
        "geo_data": {"country": "US", "city": "Dallas"},
        "event_id": "evt-001",
        "metadata": {},
    }
    event.update(overrides)
    return event


# ── validate_event: missing fields ───────────────────────────────────────


class TestValidateEventMissingFields:
    """Test that each required field produces an error when absent."""

    @pytest.mark.parametrize("field", [
        "node_id", "timestamp", "source_ip", "event_type",
        "action_taken", "geo_data", "event_id",
    ])
    def test_missing_required_field(self, field):
        event = _valid_event()
        del event[field]
        errors = validate_event(event)
        assert any(field in e for e in errors), (
            f"Expected error mentioning '{field}', got {errors}"
        )

    def test_all_fields_missing(self):
        errors = validate_event({})
        # Should have at least one error per required field
        assert len(errors) >= 7


# ── validate_event: empty strings ────────────────────────────────────────


class TestValidateEventEmptyStrings:
    """Test that empty or whitespace-only strings are rejected."""

    @pytest.mark.parametrize("field", [
        "node_id", "event_type", "action_taken", "event_id",
    ])
    def test_empty_string(self, field):
        event = _valid_event(**{field: ""})
        errors = validate_event(event)
        assert any("empty" in e or field in e for e in errors)

    @pytest.mark.parametrize("field", [
        "node_id", "event_type", "action_taken", "event_id",
    ])
    def test_whitespace_only_string(self, field):
        event = _valid_event(**{field: "   "})
        errors = validate_event(event)
        assert any("empty" in e or field in e for e in errors)


# ── validate_event: wrong types ──────────────────────────────────────────


class TestValidateEventWrongTypes:
    """Test that non-string values for string fields are rejected."""

    @pytest.mark.parametrize("field,bad_value", [
        ("node_id", 123),
        ("event_type", True),
        ("action_taken", ["BLOCKED"]),
        ("event_id", 42),
        ("timestamp", 12345),
        ("source_ip", 192),
    ])
    def test_wrong_type_for_string_field(self, field, bad_value):
        event = _valid_event(**{field: bad_value})
        errors = validate_event(event)
        assert len(errors) > 0

    def test_geo_data_not_dict(self):
        event = _valid_event(geo_data="not a dict")
        errors = validate_event(event)
        assert any("geo_data" in e for e in errors)

    def test_geo_data_is_list(self):
        event = _valid_event(geo_data=["US", "Dallas"])
        errors = validate_event(event)
        assert any("geo_data" in e for e in errors)

    def test_metadata_not_dict(self):
        event = _valid_event(metadata="not a dict")
        errors = validate_event(event)
        assert any("metadata" in e for e in errors)

    def test_metadata_is_list(self):
        event = _valid_event(metadata=[1, 2, 3])
        errors = validate_event(event)
        assert any("metadata" in e for e in errors)

    def test_event_not_dict(self):
        errors = validate_event("not a dict")
        assert len(errors) > 0


# ── validate_event: invalid IPs ──────────────────────────────────────────


class TestValidateEventInvalidIPs:
    """Test IP address validation for both IPv4 and IPv6."""

    @pytest.mark.parametrize("ip", [
        "999.999.999.999",
        "256.1.1.1",
        "1.2.3",
        "not-an-ip",
        "192.168.1.1.1",
        "",
    ])
    def test_invalid_ipv4(self, ip):
        event = _valid_event(source_ip=ip)
        errors = validate_event(event)
        assert any("source_ip" in e for e in errors)

    def test_valid_ipv4(self):
        event = _valid_event(source_ip="192.168.1.1")
        errors = validate_event(event)
        assert not any("source_ip" in e for e in errors)

    def test_valid_ipv6(self):
        event = _valid_event(source_ip="2001:db8::1")
        errors = validate_event(event)
        assert not any("source_ip" in e for e in errors)

    def test_valid_ipv6_full(self):
        event = _valid_event(source_ip="2001:0db8:85a3:0000:0000:8a2e:0370:7334")
        errors = validate_event(event)
        assert not any("source_ip" in e for e in errors)

    def test_invalid_ipv6(self):
        event = _valid_event(source_ip="2001:db8::xyz")
        errors = validate_event(event)
        assert any("source_ip" in e for e in errors)


# ── validate_event: invalid timestamps ───────────────────────────────────


class TestValidateEventInvalidTimestamps:
    """Test ISO-8601 timestamp validation."""

    @pytest.mark.parametrize("ts", [
        "not-a-timestamp",
        "2025-13-01T00:00:00Z",
        "2025-01-32T00:00:00Z",
        "",
    ])
    def test_invalid_timestamp(self, ts):
        event = _valid_event(timestamp=ts)
        errors = validate_event(event)
        assert any("timestamp" in e for e in errors)

    def test_valid_timestamp_with_timezone(self):
        event = _valid_event(timestamp="2025-01-15T10:30:00+05:00")
        errors = validate_event(event)
        assert not any("timestamp" in e for e in errors)

    def test_valid_timestamp_utc(self):
        event = _valid_event(timestamp="2025-01-15T10:30:00Z")
        errors = validate_event(event)
        assert not any("timestamp" in e for e in errors)

    def test_valid_timestamp_no_tz(self):
        event = _valid_event(timestamp="2025-01-15T10:30:00")
        errors = validate_event(event)
        assert not any("timestamp" in e for e in errors)


# ── validate_event: extra fields ─────────────────────────────────────────


class TestValidateEventExtraFields:
    """Test that extra fields do not cause validation errors."""

    def test_extra_fields_allowed(self):
        event = _valid_event(extra_field="hello", another=42)
        errors = validate_event(event)
        assert len(errors) == 0


# ── validate_event: valid event ──────────────────────────────────────────


class TestValidateEventValid:
    """Test that a fully valid event produces no errors."""

    def test_valid_event_no_errors(self):
        event = _valid_event()
        errors = validate_event(event)
        assert errors == []

    def test_valid_event_without_metadata(self):
        event = _valid_event()
        del event["metadata"]
        errors = validate_event(event)
        assert errors == []

    def test_valid_event_with_empty_geo_data(self):
        event = _valid_event(geo_data={})
        errors = validate_event(event)
        assert errors == []


# ── validate_batch ───────────────────────────────────────────────────────


class TestValidateBatch:
    """Test batch validation including event_id uniqueness."""

    def test_all_valid(self):
        events = [
            _valid_event(event_id="evt-001"),
            _valid_event(event_id="evt-002"),
        ]
        result = validate_batch(events)
        assert len(result.valid) == 2
        assert len(result.errors) == 0

    def test_all_invalid(self):
        events = [{}, {"node_id": 123}]
        result = validate_batch(events)
        assert len(result.valid) == 0
        assert len(result.errors) == 2

    def test_mixed_valid_and_invalid(self):
        events = [
            _valid_event(event_id="evt-001"),
            {},  # invalid
            _valid_event(event_id="evt-002"),
        ]
        result = validate_batch(events)
        assert len(result.valid) == 2
        assert len(result.errors) == 1
        assert result.errors[0]["index"] == 1

    def test_duplicate_event_ids(self):
        events = [
            _valid_event(event_id="evt-dup"),
            _valid_event(event_id="evt-dup"),
        ]
        result = validate_batch(events)
        # First should be valid, second should be rejected as duplicate
        assert len(result.valid) == 1
        assert len(result.errors) == 1
        assert result.errors[0]["index"] == 1
        assert any("duplicate" in e for e in result.errors[0]["errors"])

    def test_empty_batch(self):
        result = validate_batch([])
        assert len(result.valid) == 0
        assert len(result.errors) == 0

    def test_error_entry_has_event_id(self):
        events = [_valid_event(event_id="evt-001", source_ip="bad-ip")]
        result = validate_batch(events)
        assert len(result.errors) == 1
        assert result.errors[0]["event_id"] == "evt-001"

    def test_error_entry_has_none_event_id_when_missing(self):
        events = [{"node_id": "n1"}]
        result = validate_batch(events)
        assert len(result.errors) == 1
        assert result.errors[0]["event_id"] is None

    def test_result_is_validation_result(self):
        result = validate_batch([_valid_event()])
        assert isinstance(result, ValidationResult)

    def test_error_entries_have_nonempty_errors_list(self):
        events = [{}]
        result = validate_batch(events)
        assert len(result.errors) == 1
        assert len(result.errors[0]["errors"]) > 0
