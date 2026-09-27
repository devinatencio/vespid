"""Tests for DataBus fleet_block event shipping.

Validates:
- Fleet-originated events (metadata.reason starts with "fleet:") are shipped
  to the server with event_kind="fleet_block" marker in a separate payload.
- Non-fleet events are still shipped in the standard intel payload without
  event_kind marker.
- Fleet events are excluded from the intel payload (existing behavior).
"""

from __future__ import annotations

import sys
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def setup_state_dir(tmp_path, monkeypatch):
    """Use a temporary directory for STATE_DIR during tests."""
    monkeypatch.setenv("VESPID_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("VESPID_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv("VESPID_ID_FILE", str(tmp_path / "node_id"))
    return tmp_path


@pytest.fixture
def mock_config(tmp_path):
    """Create a minimal mock config for DataBus."""
    config = MagicMock()
    config.node_id = "test-node-001"
    config.queue_max_size = 1000
    config.flush_batch_size = 10
    config.flush_interval_seconds = 1.0
    config.spool_path = str(tmp_path / "spool.jsonl")
    config.upload_enabled = True
    config.SERVER_URL = "https://test-server.example.com/api/v1/events"
    config.API_KEY = "test-api-key"
    config.fleet_queue_dir = str(tmp_path / "fleet_queue")
    config.fleet_queue_max_size = 100
    config.fleet_blocklist_report_enabled = False
    config.fleet_blocklist_subscribe_enabled = False
    config.heartbeat_interval_seconds = 300
    config.log_sources = []
    return config


@pytest.fixture
def databus_module(tmp_path):
    """Import the databus module with FleetReportQueue patched to avoid /var/lib access."""
    with patch.dict("sys.modules", {}):
        # We need to patch FleetReportQueue before DataBus.__init__ runs
        with patch("vespid.fleet_queue.FleetReportQueue.__init__", return_value=None):
            # Remove cached module to force re-import with patches
            for mod_name in list(sys.modules.keys()):
                if "vespid.databus" in mod_name:
                    del sys.modules[mod_name]
            import vespid.databus

            yield vespid.databus


@pytest.fixture
def databus(mock_config, tmp_path):
    """Create a DataBus instance with mocked config."""
    with patch("vespid.fleet_queue.FleetReportQueue.__init__", return_value=None):
        # Remove cached module if needed
        for mod_name in list(sys.modules.keys()):
            if mod_name == "vespid.databus":
                del sys.modules[mod_name]
        from vespid.databus import DataBus

        bus = DataBus(config=mock_config)
    return bus


def _make_event(source_ip, event_type, action_taken, reason=None):
    """Helper to create a SecurityEvent for testing."""
    with patch("vespid.fleet_queue.FleetReportQueue.__init__", return_value=None):
        from vespid.databus import SecurityEvent
    metadata = {}
    if reason:
        metadata["reason"] = reason
    return SecurityEvent(
        node_id="test-node-001",
        timestamp="2024-01-15T10:00:00Z",
        source_ip=source_ip,
        event_type=event_type,
        action_taken=action_taken,
        geo_data={"country": "US"},
        metadata=metadata,
    )


class TestFleetBlockShipping:
    """Tests for fleet_block event shipping in _handle_batch()."""

    def test_fleet_events_shipped_with_event_kind_marker(self, databus):
        """Fleet events are shipped to server with event_kind='fleet_block'."""
        fleet_event = _make_event("10.0.0.1", "NFT_ACTION", "BLOCKED", reason="fleet:node-abc")

        shipped_payloads = []

        def mock_ship(payload):
            shipped_payloads.append(payload)
            return (True, False)

        databus._ship = mock_ship
        databus._handle_batch([fleet_event])

        # Should have shipped one payload (fleet_block only, no intel payload)
        assert len(shipped_payloads) == 1
        fleet_payload = shipped_payloads[0]
        assert len(fleet_payload) == 1
        assert fleet_payload[0]["event_kind"] == "fleet_block"
        assert fleet_payload[0]["source_ip"] == "10.0.0.1"
        assert fleet_payload[0]["metadata"]["reason"] == "fleet:node-abc"

    def test_fleet_events_excluded_from_intel_payload(self, databus):
        """Fleet events are NOT included in the intel payload."""
        fleet_event = _make_event("10.0.0.1", "NFT_ACTION", "BLOCKED", reason="fleet:node-abc")
        intel_event = _make_event("192.168.1.1", "NFT_ACTION", "BLOCKED", reason="ssh-brute")

        shipped_payloads = []

        def mock_ship(payload):
            shipped_payloads.append(payload)
            return (True, False)

        databus._ship = mock_ship
        databus._handle_batch([fleet_event, intel_event])

        # Should have two ship calls: intel payload and fleet payload
        assert len(shipped_payloads) == 2

        # First call is the intel payload (non-fleet events)
        intel_payload = shipped_payloads[0]
        assert len(intel_payload) == 1
        assert intel_payload[0]["source_ip"] == "192.168.1.1"
        assert "event_kind" not in intel_payload[0]

        # Second call is the fleet payload
        fleet_payload = shipped_payloads[1]
        assert len(fleet_payload) == 1
        assert fleet_payload[0]["source_ip"] == "10.0.0.1"
        assert fleet_payload[0]["event_kind"] == "fleet_block"

    def test_non_fleet_events_shipped_without_event_kind(self, databus):
        """Non-fleet events are shipped normally without event_kind marker."""
        intel_event = _make_event("192.168.1.1", "NFT_ACTION", "BLOCKED", reason="ssh-brute")

        shipped_payloads = []

        def mock_ship(payload):
            shipped_payloads.append(payload)
            return (True, False)

        databus._ship = mock_ship
        databus._handle_batch([intel_event])

        assert len(shipped_payloads) == 1
        intel_payload = shipped_payloads[0]
        assert len(intel_payload) == 1
        assert "event_kind" not in intel_payload[0]
        assert intel_payload[0]["source_ip"] == "192.168.1.1"

    def test_mixed_batch_separates_fleet_and_intel(self, databus):
        """A batch with both fleet and non-fleet events ships them separately."""
        events = [
            _make_event("10.0.0.1", "NFT_ACTION", "BLOCKED", reason="fleet:node-a"),
            _make_event("192.168.1.1", "NFT_ACTION", "BLOCKED", reason="ssh-brute"),
            _make_event("10.0.0.2", "NFT_ACTION", "BLOCKED", reason="fleet:node-b"),
            _make_event("192.168.1.2", "SSH_BRUTE", "OBSERVED"),
        ]

        shipped_payloads = []

        def mock_ship(payload):
            shipped_payloads.append(payload)
            return (True, False)

        databus._ship = mock_ship
        databus._handle_batch(events)

        # Two ship calls: intel payload then fleet payload
        assert len(shipped_payloads) == 2

        intel_payload = shipped_payloads[0]
        assert len(intel_payload) == 2
        intel_ips = {e["source_ip"] for e in intel_payload}
        assert intel_ips == {"192.168.1.1", "192.168.1.2"}
        for e in intel_payload:
            assert "event_kind" not in e

        fleet_payload = shipped_payloads[1]
        assert len(fleet_payload) == 2
        fleet_ips = {e["source_ip"] for e in fleet_payload}
        assert fleet_ips == {"10.0.0.1", "10.0.0.2"}
        for e in fleet_payload:
            assert e["event_kind"] == "fleet_block"

    def test_fleet_ship_failure_does_not_affect_intel_success(self, databus):
        """If fleet_block shipping fails, intel payload is still counted as shipped."""
        events = [
            _make_event("10.0.0.1", "NFT_ACTION", "BLOCKED", reason="fleet:node-a"),
            _make_event("192.168.1.1", "NFT_ACTION", "BLOCKED", reason="ssh-brute"),
        ]

        call_count = [0]

        def mock_ship(payload):
            call_count[0] += 1
            if call_count[0] == 1:
                # Intel payload succeeds
                return (True, False)
            else:
                # Fleet payload fails
                return (False, True)

        databus._ship = mock_ship
        databus._handle_batch(events)

        stats = databus.stats()
        # Intel event shipped successfully
        assert stats["shipped"] == 1
        # No spooling since intel succeeded
        assert stats["spooled"] == 0

    def test_no_fleet_events_no_fleet_ship_call(self, databus):
        """When there are no fleet events, no fleet ship call is made."""
        events = [
            _make_event("192.168.1.1", "NFT_ACTION", "BLOCKED", reason="ssh-brute"),
            _make_event("192.168.1.2", "SSH_BRUTE", "OBSERVED"),
        ]

        shipped_payloads = []

        def mock_ship(payload):
            shipped_payloads.append(payload)
            return (True, False)

        databus._ship = mock_ship
        databus._handle_batch(events)

        # Only one ship call (intel payload), no fleet payload
        assert len(shipped_payloads) == 1
        assert len(shipped_payloads[0]) == 2

    def test_fleet_event_preserves_original_fields(self, databus):
        """Fleet events shipped to server preserve all original event fields."""
        fleet_event = _make_event("10.0.0.1", "NFT_ACTION", "BLOCKED", reason="fleet:node-xyz")

        shipped_payloads = []

        def mock_ship(payload):
            shipped_payloads.append(payload)
            return (True, False)

        databus._ship = mock_ship
        databus._handle_batch([fleet_event])

        fleet_payload = shipped_payloads[0]
        event = fleet_payload[0]
        assert event["source_ip"] == "10.0.0.1"
        assert event["event_type"] == "NFT_ACTION"
        assert event["action_taken"] == "BLOCKED"
        assert event["node_id"] == "test-node-001"
        assert event["timestamp"] == "2024-01-15T10:00:00Z"
        assert event["metadata"]["reason"] == "fleet:node-xyz"
        # The event_kind is added on top of existing fields
        assert event["event_kind"] == "fleet_block"

    def test_upload_disabled_no_fleet_shipping(self, databus, mock_config):
        """When upload is disabled, fleet events are not shipped."""
        mock_config.upload_enabled = False

        fleet_event = _make_event("10.0.0.1", "NFT_ACTION", "BLOCKED", reason="fleet:node-abc")

        shipped_payloads = []

        def mock_ship(payload):
            shipped_payloads.append(payload)
            return (True, False)

        databus._ship = mock_ship
        databus._handle_batch([fleet_event])

        # No ship calls when upload is disabled
        assert len(shipped_payloads) == 0
