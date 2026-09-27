"""Unit tests for validate_event_timestamp() function.

Validates Requirement 21 (AC 2, AC 3):
- Rejects timestamps more than 5 minutes in the future
- Accepts timestamps in the past without modification
"""

from datetime import datetime, timedelta, timezone
from unittest.mock import patch

from app.routes.api import validate_event_timestamp


class TestValidateEventTimestamp:
    """Tests for validate_event_timestamp()."""

    def test_current_timestamp_accepted(self):
        """A timestamp equal to server time is accepted."""
        now = datetime.now(timezone.utc)
        ts_str = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        is_valid, error = validate_event_timestamp(ts_str)
        assert is_valid is True
        assert error == ""

    def test_past_timestamp_accepted(self):
        """Timestamps in the past are always accepted (AC 3)."""
        past = datetime.now(timezone.utc) - timedelta(days=2)
        ts_str = past.strftime("%Y-%m-%dT%H:%M:%SZ")
        is_valid, error = validate_event_timestamp(ts_str)
        assert is_valid is True
        assert error == ""

    def test_far_past_timestamp_accepted(self):
        """Even very old timestamps are accepted (delayed events are normal)."""
        far_past = datetime.now(timezone.utc) - timedelta(days=60)
        ts_str = far_past.strftime("%Y-%m-%dT%H:%M:%SZ")
        is_valid, error = validate_event_timestamp(ts_str)
        assert is_valid is True
        assert error == ""

    def test_within_5_minutes_future_accepted(self):
        """Timestamps within 5 minutes of the future are accepted."""
        future = datetime.now(timezone.utc) + timedelta(minutes=4, seconds=59)
        ts_str = future.strftime("%Y-%m-%dT%H:%M:%SZ")
        is_valid, error = validate_event_timestamp(ts_str)
        assert is_valid is True
        assert error == ""

    def test_exactly_5_minutes_future_accepted(self):
        """Timestamp exactly at the 5-minute boundary is accepted (not more than 5 min)."""
        # Use a fixed server time to avoid race conditions
        fixed_now = datetime(2025, 1, 15, 12, 0, 0, tzinfo=timezone.utc)
        future_ts = fixed_now + timedelta(minutes=5)
        ts_str = future_ts.strftime("%Y-%m-%dT%H:%M:%SZ")
        with patch("app.routes.api.datetime") as mock_dt:
            mock_dt.now.return_value = fixed_now
            mock_dt.fromisoformat = datetime.fromisoformat
            is_valid, error = validate_event_timestamp(ts_str)
        assert is_valid is True
        assert error == ""

    def test_more_than_5_minutes_future_rejected(self):
        """Timestamps more than 5 minutes in the future are rejected (AC 2)."""
        future = datetime.now(timezone.utc) + timedelta(minutes=6)
        ts_str = future.strftime("%Y-%m-%dT%H:%M:%SZ")
        is_valid, error = validate_event_timestamp(ts_str)
        assert is_valid is False
        assert "more than 5 minutes in the future" in error
        assert ts_str in error

    def test_10_minutes_future_rejected(self):
        """Timestamps 10 minutes in the future are rejected."""
        future = datetime.now(timezone.utc) + timedelta(minutes=10)
        ts_str = future.strftime("%Y-%m-%dT%H:%M:%SZ")
        is_valid, error = validate_event_timestamp(ts_str)
        assert is_valid is False
        assert "more than 5 minutes in the future" in error

    def test_iso_format_without_z_suffix(self):
        """Timestamps without Z suffix are handled correctly."""
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        ts_str = past.strftime("%Y-%m-%dT%H:%M:%S")
        is_valid, error = validate_event_timestamp(ts_str)
        assert is_valid is True
        assert error == ""

    def test_iso_format_with_z_suffix(self):
        """Timestamps with Z suffix are handled correctly."""
        past = datetime.now(timezone.utc) - timedelta(hours=1)
        ts_str = past.strftime("%Y-%m-%dT%H:%M:%SZ")
        is_valid, error = validate_event_timestamp(ts_str)
        assert is_valid is True
        assert error == ""

    def test_error_message_includes_timestamp(self):
        """Error message includes the rejected timestamp for debugging."""
        future = datetime.now(timezone.utc) + timedelta(minutes=10)
        ts_str = future.strftime("%Y-%m-%dT%H:%M:%SZ")
        is_valid, error = validate_event_timestamp(ts_str)
        assert is_valid is False
        assert ts_str in error
