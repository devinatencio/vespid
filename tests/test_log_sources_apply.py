"""Tests for log_sources application from config profiles.

Validates that managed nodes receiving log_sources from config profiles
correctly update self.config.log_sources, ensuring the heartbeat's
active_parsers derivation reflects the profile's log sources.
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
    """Create a mock ShieldConfig with realistic defaults including log_sources."""
    config = MagicMock()
    config.management_mode = "server-managed"
    config.config_conflict_strategy = "server-wins"
    config.SERVER_URL = "https://server.example.com/api/v1/events"
    config.API_KEY = "test-api-key"
    config.node_id = "test-node-123"
    config.brute_force_rules = []
    config.custom_rules = []
    config.subscriptions = []
    config.allowlist = ["127.0.0.1/32"]
    config.log_sources = []
    config.flush_interval_seconds = 5
    config.flush_batch_size = 100
    config.heartbeat_interval_seconds = 300
    config.fleet_blocklist_report_enabled = True
    config.fleet_blocklist_subscribe_enabled = True
    config.fleet_block_ttl_seconds = 3600
    config.fleet_local_allow_list = []
    config.to_dict.return_value = {
        "management_mode": "server-managed",
        "allowlist": ["127.0.0.1/32"],
        "log_sources": [],
    }
    return config


@pytest.fixture
def subscriber(mock_config, tmp_path, monkeypatch):
    """Create a ConfigSubscriber instance for testing."""
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

        if "vespid.config_subscriber" in sys.modules:
            del sys.modules["vespid.config_subscriber"]

        import vespid.config_subscriber as cs_module
        from vespid.config_subscriber import ConfigSubscriber

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


class TestLogSourcesApplication:
    """Tests for log_sources application from config profiles."""

    def test_apply_log_sources_updates_config(self, subscriber):
        """When a profile includes log_sources, config.log_sources should be updated."""
        settings = {
            "log_sources": [
                {"path": "/var/log/apache2/access.log", "parser": "apache"},
                {"path": "/var/log/secure", "parser": "secure"},
            ]
        }

        subscriber._apply_config(settings, version=1)

        assert len(subscriber.config.log_sources) == 2
        assert subscriber.config.log_sources[0].path == "/var/log/apache2/access.log"
        assert subscriber.config.log_sources[0].parser == "apache"
        assert subscriber.config.log_sources[1].path == "/var/log/secure"
        assert subscriber.config.log_sources[1].parser == "secure"

    def test_active_parsers_derived_from_applied_log_sources(self, subscriber):
        """After applying log_sources, active_parsers derivation should reflect the new sources."""
        settings = {
            "log_sources": [
                {"path": "/var/log/apache2/access.log", "parser": "apache"},
                {"path": "/var/log/apache2/error.log", "parser": "apache"},
                {"path": "/var/log/secure", "parser": "secure"},
            ]
        }

        subscriber._apply_config(settings, version=2)

        # Derive active_parsers the same way the heartbeat does
        active_parsers = list(set(ls.parser for ls in subscriber.config.log_sources))
        assert sorted(active_parsers) == ["apache", "secure"]

    def test_apply_empty_log_sources(self, subscriber):
        """Applying empty log_sources should result in empty active_parsers."""
        settings = {"log_sources": []}

        subscriber._apply_config(settings, version=3)

        assert subscriber.config.log_sources == []
        active_parsers = list(set(ls.parser for ls in subscriber.config.log_sources))
        assert active_parsers == []

    def test_log_sources_rollback_on_failure(self, subscriber):
        """If a later category fails, log_sources should be rolled back."""
        # Set initial log_sources
        from vespid.config import LogSource

        original_sources = [LogSource(path="/var/log/messages", parser="messages")]
        subscriber.config.log_sources = original_sources

        # Make fleet settings fail after log_sources is applied
        original_setattr = type(subscriber.config).__setattr__
        call_count = [0]

        def conditional_setattr(self, name, value):
            if name == "fleet_local_allow_list":
                call_count[0] += 1
                if call_count[0] == 1:
                    raise RuntimeError("fleet setting failed")
            original_setattr(self, name, value)

        type(subscriber.config).__setattr__ = conditional_setattr

        settings = {
            "log_sources": [
                {"path": "/var/log/apache2/access.log", "parser": "apache"},
            ],
            "fleet_local_allow_list": ["10.0.0.1"],
        }

        try:
            with pytest.raises(RuntimeError, match="fleet setting failed"):
                subscriber._apply_config(settings, version=4)
        finally:
            type(subscriber.config).__setattr__ = original_setattr

        # log_sources should be rolled back to original
        assert subscriber.config.log_sources == original_sources

    def test_detect_log_sources_no_change(self, subscriber):
        """Should return False when log_sources haven't changed."""
        from vespid.config import LogSource

        subscriber.config.log_sources = [LogSource(path="/var/log/secure", parser="secure")]
        settings = {"log_sources": [{"path": "/var/log/secure", "parser": "secure"}]}
        assert subscriber._detect_log_sources_changes(settings) is False

    def test_detect_log_sources_change(self, subscriber):
        """Should return True when log_sources have changed."""
        from vespid.config import LogSource

        subscriber.config.log_sources = [LogSource(path="/var/log/secure", parser="secure")]
        settings = {"log_sources": [{"path": "/var/log/apache2/access.log", "parser": "apache"}]}
        assert subscriber._detect_log_sources_changes(settings) is True

    def test_detect_log_sources_no_key(self, subscriber):
        """Should return False when log_sources key is absent from settings."""
        assert subscriber._detect_log_sources_changes({}) is False

    def test_apply_log_sources_invokes_reconcile_callback(self, subscriber):
        """Applying log_sources must notify the tailer reconcile callback."""
        from vespid.config import LogSource

        callback = MagicMock()
        subscriber._on_log_sources_updated = callback

        settings = {
            "log_sources": [
                {"path": "/var/log/haproxy/access.log", "parser": "haproxy"},
            ]
        }
        subscriber._apply_log_sources(settings)

        callback.assert_called_once()
        passed = callback.call_args[0][0]
        assert len(passed) == 1
        assert isinstance(passed[0], LogSource)
        assert passed[0].path == "/var/log/haproxy/access.log"
        assert passed[0].parser == "haproxy"

    def test_apply_log_sources_callback_failure_is_swallowed(self, subscriber):
        """A failing reconcile callback must not break config application."""
        subscriber._on_log_sources_updated = MagicMock(side_effect=RuntimeError("boom"))

        subscriber._apply_log_sources(
            {"log_sources": [{"path": "/var/log/secure", "parser": "secure"}]}
        )

        assert subscriber.config.log_sources[0].path == "/var/log/secure"

    def test_local_log_sources_baseline_captured_at_init(self, subscriber):
        """The pristine baseline reflects the startup config, not later edits."""
        assert (
            subscriber._local_log_sources == subscriber.config.to_dict.return_value["log_sources"]
        )

    def test_resolve_uses_pristine_log_sources_baseline(self, subscriber):
        """Removing a source from the profile must remove a source the profile
        previously added, even though the in-memory config now shows it as local."""
        from vespid.config import LogSource

        # Startup baseline: only the local default source.
        subscriber._local_log_sources = [{"path": "/var/log/secure", "parser": "secure"}]
        # In-memory config polluted by a previously-applied profile.
        subscriber.config.log_sources = [
            LogSource(path="/var/log/secure", parser="secure"),
            LogSource(path="/var/log/vespid-server/access.log", parser="apache"),
        ]
        subscriber.config.to_dict.return_value = {
            "management_mode": "server-managed",
            "allowlist": ["127.0.0.1/32"],
            "log_sources": [
                {"path": "/var/log/secure", "parser": "secure"},
                {"path": "/var/log/vespid-server/access.log", "parser": "apache"},
            ],
        }

        resolved = subscriber._resolve_conflicts({"log_sources": []}, "server-wins")

        paths = [ls["path"] if isinstance(ls, dict) else ls.path for ls in resolved["log_sources"]]
        assert "/var/log/vespid-server/access.log" not in paths
        assert "/var/log/secure" in paths

    def test_checkpoint_includes_log_sources(self, subscriber):
        """Rollback checkpoint should capture log_sources."""
        from vespid.config import LogSource

        subscriber.config.log_sources = [LogSource(path="/var/log/secure", parser="secure")]

        checkpoint = subscriber._create_rollback_checkpoint()

        assert "log_sources" in checkpoint
        assert len(checkpoint["log_sources"]) == 1


class TestManagedNodeActiveParsersIntegration:
    """Integration tests verifying that managed nodes report correct active_parsers
    after receiving log_sources from config profiles.

    The key invariant: ConfigSubscriber and DataBus share the same ShieldConfig
    instance, so when _apply_log_sources updates config.log_sources, the next
    heartbeat's active_parsers derivation automatically reflects the change.
    """

    def test_shared_config_active_parsers_after_profile_apply(self, subscriber):
        """After config profile applies log_sources, active_parsers derivation
        on the shared config object should reflect the profile's parsers."""

        # Simulate initial state: node has no log_sources
        subscriber.config.log_sources = []

        # Profile pushes log_sources for apache and postfix
        settings = {
            "log_sources": [
                {"path": "/var/log/apache2/access.log", "parser": "apache"},
                {"path": "/var/log/apache2/error.log", "parser": "apache"},
                {"path": "/var/log/mail.log", "parser": "postfix"},
            ]
        }
        subscriber._apply_config(settings, version=5)

        # Verify: the same derivation used in databus._attempt_heartbeat()
        # produces the correct active_parsers from the shared config
        active_parsers = list(set(ls.parser for ls in subscriber.config.log_sources))
        assert sorted(active_parsers) == ["apache", "postfix"]

    def test_profile_update_replaces_previous_log_sources(self, subscriber):
        """A new profile version should fully replace previous log_sources,
        and active_parsers should reflect only the new set."""

        # First profile version: apache + secure
        settings_v1 = {
            "log_sources": [
                {"path": "/var/log/apache2/access.log", "parser": "apache"},
                {"path": "/var/log/secure", "parser": "secure"},
            ]
        }
        subscriber._apply_config(settings_v1, version=6)
        active_v1 = sorted(set(ls.parser for ls in subscriber.config.log_sources))
        assert active_v1 == ["apache", "secure"]

        # Second profile version: only postfix
        settings_v2 = {
            "log_sources": [
                {"path": "/var/log/mail.log", "parser": "postfix"},
            ]
        }
        subscriber._apply_config(settings_v2, version=7)
        active_v2 = sorted(set(ls.parser for ls in subscriber.config.log_sources))
        assert active_v2 == ["postfix"]

    def test_config_object_identity_shared(self, subscriber):
        """ConfigSubscriber's config is the same object that DataBus would use,
        so mutations to log_sources are visible to both."""

        # Get a reference to the config object
        shared_config = subscriber.config

        # Apply log_sources via the subscriber
        settings = {
            "log_sources": [
                {"path": "/var/log/nginx/access.log", "parser": "nginx"},
            ]
        }
        subscriber._apply_config(settings, version=8)

        # The shared_config reference sees the update (same object)
        assert len(shared_config.log_sources) == 1
        assert shared_config.log_sources[0].parser == "nginx"
        active_parsers = list(set(ls.parser for ls in shared_config.log_sources))
        assert active_parsers == ["nginx"]
