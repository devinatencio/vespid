"""Tests for Config_Subscriber atomic configuration application.

Validates:
- _apply_config applies settings atomically across all categories
- If any category fails, all categories are rolled back to checkpoint state
- Detection rules trigger on_rules_updated callback
- Subscription feeds update SubscriptionManager
- Allowlist updates NFTablesManager
- Telemetry and fleet settings update ShieldConfig fields
- Success logs version and changed keys
- Failure stores reason for next check-in
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
def mock_config():
    """Create a mock ShieldConfig with realistic defaults."""
    config = MagicMock()
    config.management_mode = "server-managed"
    config.config_conflict_strategy = "server-wins"
    config.SERVER_URL = "https://server.example.com/api/v1/events"
    config.API_KEY = "test-api-key"
    config.node_id = "test-node-123"
    config.brute_force_rules = []
    config.custom_rules = []
    config.subscriptions = []
    config.allowlist = ["127.0.0.1/32", "::1/128"]
    config.flush_interval_seconds = 5
    config.flush_batch_size = 100
    config.heartbeat_interval_seconds = 300
    config.fleet_blocklist_report_enabled = True
    config.fleet_blocklist_subscribe_enabled = True
    config.fleet_block_ttl_seconds = 3600
    config.fleet_local_allow_list = []
    config.to_dict.return_value = {
        "management_mode": "server-managed",
        "allowlist": ["127.0.0.1/32", "::1/128"],
        "flush_interval_seconds": 5,
        "flush_batch_size": 100,
        "heartbeat_interval_seconds": 300,
    }
    return config


@pytest.fixture
def subscriber(mock_config, tmp_path, monkeypatch):
    """Create a ConfigSubscriber instance for testing."""
    # Mock the problematic imports to avoid filesystem side effects
    nft_mock = MagicMock()
    sub_mock = MagicMock()

    with patch.dict(
        sys.modules,
        {
            "vespid.nftables_manager": nft_mock,
            "vespid.subscription_manager": sub_mock,
            "vespid.databus": MagicMock(),
            "vespid.fleet_queue": MagicMock(),
        },
    ):
        nft_mock.NFTablesManager = MagicMock
        sub_mock.SubscriptionManager = MagicMock

        # Force reimport with mocked dependencies
        if "vespid.config_subscriber" in sys.modules:
            del sys.modules["vespid.config_subscriber"]

        import vespid.config_subscriber as cs_module
        from vespid.config_subscriber import ConfigSubscriber

        # Patch STATE_DIR on the module
        monkeypatch.setattr(cs_module, "STATE_DIR", tmp_path)
        monkeypatch.setattr(cs_module, "_CACHE_FILE", tmp_path / "config_cache.json")

        on_rules_updated = MagicMock()
        subscription_manager = MagicMock()
        subscription_manager.config = mock_config
        nft_manager = MagicMock()
        nft_manager.config = mock_config
        nft_manager._normalize_allowlist = MagicMock(return_value=[])

        sub = ConfigSubscriber(
            config=mock_config,
            on_rules_updated=on_rules_updated,
            subscription_manager=subscription_manager,
            nft_manager=nft_manager,
        )
        return sub


class TestApplyConfigSuccess:
    """Tests for successful configuration application."""

    def test_apply_telemetry_settings(self, subscriber):
        """Should update telemetry settings on ShieldConfig."""
        settings = {
            "flush_interval_seconds": 10,
            "flush_batch_size": 200,
        }

        subscriber._apply_config(settings, version=2)

        assert subscriber.config.flush_interval_seconds == 10
        assert subscriber.config.flush_batch_size == 200

    def test_apply_fleet_settings(self, subscriber):
        """Should update fleet settings on ShieldConfig."""
        settings = {
            "fleet_blocklist_report_enabled": False,
            "fleet_block_ttl_seconds": 7200,
        }

        subscriber._apply_config(settings, version=3)

        assert subscriber.config.fleet_blocklist_report_enabled is False
        assert subscriber.config.fleet_block_ttl_seconds == 7200

    def test_apply_allowlist_updates_nft_manager(self, subscriber):
        """Should update NFTablesManager allowlist."""
        new_allowlist = ["10.0.0.0/8", "192.168.0.0/16"]
        settings = {"allowlist": new_allowlist}

        subscriber._apply_config(settings, version=4)

        assert subscriber.config.allowlist == new_allowlist
        assert subscriber._nft_manager.config.allowlist == new_allowlist
        subscriber._nft_manager._normalize_allowlist.assert_called_with(new_allowlist)

    def test_apply_rules_triggers_callback(self, subscriber):
        """Should call on_rules_updated with new rules."""
        settings = {
            "brute_force_rules": [
                {
                    "name": "ssh_fast",
                    "event_type": "SSH_BRUTE",
                    "max_attempts": 3,
                    "window_seconds": 60,
                    "parser": "secure",
                }
            ],
            "custom_rules": [],
        }

        subscriber._apply_config(settings, version=5)

        subscriber._on_rules_updated.assert_called_once()
        call_args = subscriber._on_rules_updated.call_args[0]
        # First arg is brute_force_rules
        assert len(call_args[0]) == 1
        assert call_args[0][0].name == "ssh_fast"
        # Second arg is custom_rules
        assert call_args[1] == []

    def test_apply_feeds_updates_subscription_manager(self, subscriber):
        """Should update SubscriptionManager feed list."""
        settings = {
            "subscriptions": [
                {
                    "name": "test_feed",
                    "url": "https://example.com/feed.txt",
                    "format": "plain",
                    "refresh_seconds": 3600,
                    "enabled": True,
                }
            ]
        }

        subscriber._apply_config(settings, version=6)

        assert len(subscriber.config.subscriptions) == 1
        assert subscriber.config.subscriptions[0].name == "test_feed"
        assert (
            subscriber._subscription_manager.config.subscriptions == subscriber.config.subscriptions
        )

    def test_apply_no_changes_detected(self, subscriber):
        """Should succeed without errors when no changes are detected."""
        # Settings that match current config
        settings = {
            "flush_interval_seconds": 5,  # same as default
        }

        # Should not raise
        subscriber._apply_config(settings, version=7)

    def test_apply_multiple_categories(self, subscriber):
        """Should apply changes across multiple categories atomically."""
        settings = {
            "flush_interval_seconds": 15,
            "allowlist": ["10.0.0.0/8"],
            "fleet_block_ttl_seconds": 1800,
        }

        subscriber._apply_config(settings, version=8)

        assert subscriber.config.flush_interval_seconds == 15
        assert subscriber.config.allowlist == ["10.0.0.0/8"]
        assert subscriber.config.fleet_block_ttl_seconds == 1800


class TestApplyConfigRollback:
    """Tests for atomic rollback on failure."""

    def test_rollback_on_allowlist_failure(self, subscriber):
        """If allowlist application fails, all categories should rollback."""
        original_flush = subscriber.config.flush_interval_seconds

        # Make allowlist application fail
        subscriber._nft_manager._normalize_allowlist.side_effect = ValueError("bad allowlist")

        settings = {
            "flush_interval_seconds": 99,
            "allowlist": ["invalid"],
        }

        with pytest.raises(ValueError, match="bad allowlist"):
            subscriber._apply_config(settings, version=9)

        # Telemetry was applied before allowlist, but should be rolled back
        assert subscriber.config.flush_interval_seconds == original_flush

    def test_rollback_on_rules_failure(self, subscriber):
        """If rules callback fails, all categories should rollback."""
        subscriber._on_rules_updated.side_effect = RuntimeError("callback failed")

        settings = {
            "brute_force_rules": [
                {
                    "name": "test",
                    "event_type": "TEST",
                    "max_attempts": 5,
                    "window_seconds": 60,
                    "parser": "secure",
                }
            ],
        }

        with pytest.raises(RuntimeError, match="callback failed"):
            subscriber._apply_config(settings, version=10)

        # Rules should be rolled back to original (empty list)
        assert subscriber.config.brute_force_rules == []

    def test_rollback_on_feeds_failure(self, subscriber):
        """If feeds application fails, rules should be rolled back."""

        # Make _apply_feeds raise an error
        def failing_apply_feeds(settings):
            raise RuntimeError("feed update failed")

        subscriber._apply_feeds = failing_apply_feeds

        settings = {
            "brute_force_rules": [
                {
                    "name": "test",
                    "event_type": "TEST",
                    "max_attempts": 5,
                    "window_seconds": 60,
                    "parser": "secure",
                }
            ],
            "subscriptions": [
                {
                    "name": "bad_feed",
                    "url": "https://example.com/bad",
                    "format": "plain",
                    "refresh_seconds": 3600,
                    "enabled": True,
                }
            ],
        }

        with pytest.raises(RuntimeError, match="feed update failed"):
            subscriber._apply_config(settings, version=11)

        # Rules should be rolled back
        assert subscriber.config.brute_force_rules == []

    def test_rollback_preserves_all_original_values(self, subscriber):
        """After rollback, all config values should match the checkpoint."""
        # Set some initial values
        subscriber.config.flush_interval_seconds = 5
        subscriber.config.flush_batch_size = 100
        subscriber.config.heartbeat_interval_seconds = 300
        subscriber.config.fleet_blocklist_report_enabled = True
        subscriber.config.fleet_block_ttl_seconds = 3600
        subscriber.config.allowlist = ["127.0.0.1/32"]

        # Make fleet settings fail (last category)
        def fail_on_fleet_local_allow_list(value):
            raise RuntimeError("fleet setting failed")

        # Apply telemetry first (should succeed), then fail on fleet
        settings = {
            "flush_interval_seconds": 99,
            "fleet_block_ttl_seconds": 9999,
            "fleet_local_allow_list": ["10.0.0.1"],
        }

        # Make setattr fail for fleet_local_allow_list
        original_setattr = type(subscriber.config).__setattr__
        call_count = [0]

        def conditional_setattr(self, name, value):
            if name == "fleet_local_allow_list":
                call_count[0] += 1
                if call_count[0] == 1:
                    raise RuntimeError("fleet setting failed")
            original_setattr(self, name, value)

        type(subscriber.config).__setattr__ = conditional_setattr

        try:
            with pytest.raises(RuntimeError, match="fleet setting failed"):
                subscriber._apply_config(settings, version=12)
        finally:
            type(subscriber.config).__setattr__ = original_setattr

        # Telemetry should be rolled back
        assert subscriber.config.flush_interval_seconds == 5

    def test_failure_stores_reason_for_checkin(self, subscriber):
        """Failed application should store failure reason for next check-in."""
        subscriber._on_rules_updated.side_effect = RuntimeError("callback exploded")

        settings = {
            "brute_force_rules": [
                {
                    "name": "test",
                    "event_type": "TEST",
                    "max_attempts": 5,
                    "window_seconds": 60,
                    "parser": "secure",
                }
            ],
        }

        with pytest.raises(RuntimeError):
            subscriber._apply_config(settings, version=13)

        assert subscriber._last_apply_failure is not None
        assert "callback exploded" in subscriber._last_apply_failure


class TestCheckinPayloadFailureReporting:
    """Tests for failure reporting on next check-in."""

    def test_checkin_includes_failure_reason(self, subscriber):
        """Check-in payload should include last failure reason."""
        subscriber._last_apply_failure = "Category 'rules' failed: callback error"

        payload = subscriber._build_checkin_payload()

        assert "last_failure_reason" in payload
        assert "callback error" in payload["last_failure_reason"]

    def test_checkin_clears_failure_after_reporting(self, subscriber):
        """Failure reason should be cleared after being reported."""
        subscriber._last_apply_failure = "some failure"

        subscriber._build_checkin_payload()

        assert subscriber._last_apply_failure is None

    def test_checkin_no_failure_field_when_none(self, subscriber):
        """Check-in payload should not include failure field when no failure."""
        subscriber._last_apply_failure = None

        payload = subscriber._build_checkin_payload()

        assert "last_failure_reason" not in payload


class TestChangeDetection:
    """Tests for change detection helpers."""

    def test_detect_rules_no_change(self, subscriber):
        """Should return False when rules haven't changed."""
        subscriber.config.brute_force_rules = []
        assert subscriber._detect_rules_changes({"brute_force_rules": []}) is False

    def test_detect_rules_change(self, subscriber):
        """Should return True when rules have changed."""
        subscriber.config.brute_force_rules = []
        settings = {
            "brute_force_rules": [
                {"name": "new", "event_type": "TEST", "max_attempts": 5, "window_seconds": 60}
            ]
        }
        assert subscriber._detect_rules_changes(settings) is True

    def test_detect_feeds_no_key(self, subscriber):
        """Should return False when subscriptions key is absent."""
        assert subscriber._detect_feeds_changes({}) is False

    def test_detect_allowlist_change(self, subscriber):
        """Should return True when allowlist has changed."""
        subscriber.config.allowlist = ["127.0.0.1/32"]
        assert subscriber._detect_allowlist_changes({"allowlist": ["10.0.0.0/8"]}) is True

    def test_detect_allowlist_no_change(self, subscriber):
        """Should return False when allowlist is the same."""
        subscriber.config.allowlist = ["127.0.0.1/32"]
        assert subscriber._detect_allowlist_changes({"allowlist": ["127.0.0.1/32"]}) is False

    def test_detect_telemetry_change(self, subscriber):
        """Should return True when telemetry settings differ."""
        subscriber.config.flush_interval_seconds = 5
        assert subscriber._detect_telemetry_changes({"flush_interval_seconds": 10}) is True

    def test_detect_telemetry_no_change(self, subscriber):
        """Should return False when telemetry settings are the same."""
        subscriber.config.flush_interval_seconds = 5
        assert subscriber._detect_telemetry_changes({"flush_interval_seconds": 5}) is False

    def test_detect_fleet_change(self, subscriber):
        """Should return True when fleet settings differ."""
        subscriber.config.fleet_block_ttl_seconds = 3600
        assert subscriber._detect_fleet_changes({"fleet_block_ttl_seconds": 7200}) is True


class TestCreateRollbackCheckpoint:
    """Tests for _create_rollback_checkpoint."""

    def test_checkpoint_captures_all_categories(self, subscriber):
        """Checkpoint should capture all modifiable setting categories."""
        subscriber.config.brute_force_rules = ["rule1"]
        subscriber.config.custom_rules = ["custom1"]
        subscriber.config.subscriptions = ["feed1"]
        subscriber.config.allowlist = ["10.0.0.0/8"]
        subscriber.config.flush_interval_seconds = 10
        subscriber.config.flush_batch_size = 50
        subscriber.config.heartbeat_interval_seconds = 120
        subscriber.config.fleet_blocklist_report_enabled = False
        subscriber.config.fleet_blocklist_subscribe_enabled = True
        subscriber.config.fleet_block_ttl_seconds = 1800
        subscriber.config.fleet_local_allow_list = ["192.168.1.1"]

        checkpoint = subscriber._create_rollback_checkpoint()

        assert checkpoint["brute_force_rules"] == ["rule1"]
        assert checkpoint["custom_rules"] == ["custom1"]
        assert checkpoint["subscriptions"] == ["feed1"]
        assert checkpoint["allowlist"] == ["10.0.0.0/8"]
        assert checkpoint["flush_interval_seconds"] == 10
        assert checkpoint["flush_batch_size"] == 50
        assert checkpoint["heartbeat_interval_seconds"] == 120
        assert checkpoint["fleet_blocklist_report_enabled"] is False
        assert checkpoint["fleet_blocklist_subscribe_enabled"] is True
        assert checkpoint["fleet_block_ttl_seconds"] == 1800
        assert checkpoint["fleet_local_allow_list"] == ["192.168.1.1"]

    def test_checkpoint_creates_copies_of_lists(self, subscriber):
        """Checkpoint lists should be independent copies."""
        original_allowlist = ["10.0.0.0/8"]
        subscriber.config.allowlist = original_allowlist

        checkpoint = subscriber._create_rollback_checkpoint()

        # Modifying original should not affect checkpoint
        original_allowlist.append("192.168.0.0/16")
        assert checkpoint["allowlist"] == ["10.0.0.0/8"]
