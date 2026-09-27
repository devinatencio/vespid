"""Tests for Config_Subscriber cache persistence and offline resilience.

Validates:
- _persist_cache writes valid JSON to STATE_DIR/config_cache.json
- _load_cache reads and validates cached config
- _load_cache handles corrupted cache (deletes file, returns None)
- _create_checkpoint creates timestamped snapshot files
- On startup: cached config is applied when server is unreachable
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def setup_state_dir(tmp_path, monkeypatch):
    """Use a temporary directory for STATE_DIR during tests."""
    monkeypatch.setenv("VESPID_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("VESPID_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv("VESPID_ID_FILE", str(tmp_path / "node_id"))

    if "vespid.config_subscriber" in sys.modules:
        monkeypatch.setattr("vespid.config_subscriber.STATE_DIR", tmp_path)
        monkeypatch.setattr("vespid.config_subscriber._CACHE_FILE", tmp_path / "config_cache.json")
    return tmp_path


@pytest.fixture
def mock_config():
    """Create a mock ShieldConfig for testing."""
    config = MagicMock()
    config.management_mode = "server-managed"
    config.config_conflict_strategy = "server-wins"
    config.SERVER_URL = "https://server.example.com/api/v1/events"
    config.API_KEY = "test-api-key"
    config.node_id = "test-node-123"
    config.brute_force_rules = []
    config.custom_rules = []
    config.to_dict.return_value = {
        "management_mode": "server-managed",
        "config_conflict_strategy": "server-wins",
        "SERVER_URL": "https://server.example.com/api/v1/events",
        "API_KEY": "test-api-key",
        "node_id": "test-node-123",
        "allowlist": ["127.0.0.1/32"],
        "flush_interval_seconds": 5,
    }
    return config


@pytest.fixture
def subscriber(mock_config, tmp_path, monkeypatch):
    """Create a ConfigSubscriber instance for testing."""
    monkeypatch.setenv("VESPID_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("VESPID_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv("VESPID_ID_FILE", str(tmp_path / "node_id"))

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

        # Patch STATE_DIR and _CACHE_FILE on the module
        monkeypatch.setattr(cs_module, "STATE_DIR", tmp_path)
        monkeypatch.setattr(cs_module, "_CACHE_FILE", tmp_path / "config_cache.json")

        on_rules_updated = MagicMock()
        subscription_manager = MagicMock()
        nft_manager = MagicMock()

        sub = ConfigSubscriber(
            config=mock_config,
            on_rules_updated=on_rules_updated,
            subscription_manager=subscription_manager,
            nft_manager=nft_manager,
        )
        # Store module reference for tests that need it
        sub._cs_module = cs_module
        return sub


class TestPersistCache:
    """Tests for _persist_cache method."""

    def test_persist_cache_writes_valid_json(self, subscriber, tmp_path):
        """Cache file should contain valid JSON with expected fields."""
        payload = {
            "profile_name": "production-standard",
            "version": 5,
            "settings": {"allowlist": ["10.0.0.0/8"]},
            "updated_at": "2025-01-15T10:30:00Z",
            "conflict_strategy": "server-wins",
        }

        subscriber._persist_cache(payload)

        cache_file = tmp_path / "config_cache.json"
        assert cache_file.exists()

        data = json.loads(cache_file.read_text())
        assert data["profile_name"] == "production-standard"
        assert data["version"] == 5
        assert data["settings"] == {"allowlist": ["10.0.0.0/8"]}
        assert data["updated_at"] == "2025-01-15T10:30:00Z"
        assert data["conflict_strategy"] == "server-wins"
        assert "cached_at" in data

    def test_persist_cache_creates_parent_directory(self, subscriber, tmp_path):
        """Cache persistence should create parent directories if needed."""
        cs_module = subscriber._cs_module
        nested_dir = tmp_path / "nested" / "dir"
        original = cs_module._CACHE_FILE
        try:
            cs_module._CACHE_FILE = nested_dir / "config_cache.json"
            payload = {"version": 1, "settings": {"allowlist": []}}
            subscriber._persist_cache(payload)
            assert (nested_dir / "config_cache.json").exists()
        finally:
            cs_module._CACHE_FILE = original

    def test_persist_cache_handles_write_error(self, subscriber):
        """Cache persistence should log warning on write failure, not raise."""
        cs_module = subscriber._cs_module
        original = cs_module._CACHE_FILE
        try:
            cs_module._CACHE_FILE = Path("/nonexistent/path/cache.json")
            payload = {"version": 1, "settings": {}}
            # Should not raise
            subscriber._persist_cache(payload)
        finally:
            cs_module._CACHE_FILE = original


class TestLoadCache:
    """Tests for _load_cache method."""

    def test_load_cache_returns_none_when_no_file(self, subscriber):
        """Should return None when no cache file exists."""
        result = subscriber._load_cache()
        assert result is None

    def test_load_cache_returns_valid_data(self, subscriber, tmp_path):
        """Should return parsed dict when cache file is valid."""
        cache_data = {
            "profile_name": "test-profile",
            "version": 3,
            "settings": {"flush_interval_seconds": 10},
            "cached_at": "2025-01-15T10:30:05Z",
        }
        cache_file = tmp_path / "config_cache.json"
        cache_file.write_text(json.dumps(cache_data))

        result = subscriber._load_cache()
        assert result is not None
        assert result["version"] == 3
        assert result["settings"] == {"flush_interval_seconds": 10}

    def test_load_cache_deletes_corrupted_json(self, subscriber, tmp_path):
        """Should delete cache file with invalid JSON and return None."""
        cache_file = tmp_path / "config_cache.json"
        cache_file.write_text("not valid json {{{")

        result = subscriber._load_cache()
        assert result is None
        assert not cache_file.exists()

    def test_load_cache_deletes_non_dict_json(self, subscriber, tmp_path):
        """Should delete cache file that contains non-dict JSON."""
        cache_file = tmp_path / "config_cache.json"
        cache_file.write_text(json.dumps([1, 2, 3]))

        result = subscriber._load_cache()
        assert result is None
        assert not cache_file.exists()

    def test_load_cache_deletes_missing_required_fields(self, subscriber, tmp_path):
        """Should delete cache file missing 'version' or 'settings' fields."""
        cache_file = tmp_path / "config_cache.json"
        # Missing 'settings' field
        cache_file.write_text(json.dumps({"version": 1}))

        result = subscriber._load_cache()
        assert result is None
        assert not cache_file.exists()

    def test_load_cache_deletes_missing_version(self, subscriber, tmp_path):
        """Should delete cache file missing 'version' field."""
        cache_file = tmp_path / "config_cache.json"
        cache_file.write_text(json.dumps({"settings": {"allowlist": []}}))

        result = subscriber._load_cache()
        assert result is None
        assert not cache_file.exists()


class TestCreateCheckpoint:
    """Tests for _create_checkpoint method."""

    def test_create_checkpoint_writes_file(self, subscriber, tmp_path, monkeypatch):
        """Should create a checkpoint file in the checkpoints directory."""
        cs_module = subscriber._cs_module
        monkeypatch.setattr(cs_module, "STATE_DIR", tmp_path)

        subscriber._create_checkpoint()

        checkpoint_dir = tmp_path / "config_checkpoints"
        assert checkpoint_dir.exists()

        files = list(checkpoint_dir.glob("checkpoint_*.json"))
        assert len(files) == 1

        data = json.loads(files[0].read_text())
        assert "timestamp" in data
        assert data["trigger"] == "config_reload"
        assert "config_snapshot" in data
        assert "config_version" in data

    def test_create_checkpoint_includes_config_snapshot(self, subscriber, tmp_path, monkeypatch):
        """Checkpoint should contain the full config snapshot."""
        cs_module = subscriber._cs_module
        monkeypatch.setattr(cs_module, "STATE_DIR", tmp_path)
        subscriber._current_config_version = 7

        subscriber._create_checkpoint()

        checkpoint_dir = tmp_path / "config_checkpoints"
        files = list(checkpoint_dir.glob("checkpoint_*.json"))
        data = json.loads(files[0].read_text())

        assert data["config_version"] == 7
        assert data["previous_mode"] == "server-managed"
        assert isinstance(data["config_snapshot"], dict)

    def test_create_checkpoint_handles_error(self, subscriber, monkeypatch):
        """Should log warning on failure, not raise."""
        cs_module = subscriber._cs_module
        monkeypatch.setattr(cs_module, "STATE_DIR", Path("/nonexistent/readonly/path"))

        # Should not raise
        subscriber._create_checkpoint()


class TestOfflineResilience:
    """Tests for offline resilience behavior on startup."""

    def test_startup_applies_cache_when_server_unreachable(self, subscriber, tmp_path, monkeypatch):
        """When server is unreachable, cached config should be applied."""
        import asyncio

        # Write a valid cache file
        cache_data = {
            "profile_name": "cached-profile",
            "version": 5,
            "settings": {"flush_interval_seconds": 15},
            "cached_at": "2025-01-15T10:30:05Z",
            "conflict_strategy": "server-wins",
        }
        cache_file = tmp_path / "config_cache.json"
        cache_file.write_text(json.dumps(cache_data))

        # Mock _initial_check_in to raise (server unreachable)
        async def failing_checkin():
            raise ConnectionError("Server unreachable")

        monkeypatch.setattr(subscriber, "_initial_check_in", failing_checkin)

        # Mock _handle_config_event to track calls
        handled_events = []

        def track_handle(event_data):
            handled_events.append(event_data)

        monkeypatch.setattr(subscriber, "_handle_config_event", track_handle)

        # Mock _connect_sse to stop the loop
        async def stop_sse():
            subscriber.stop()

        monkeypatch.setattr(subscriber, "_connect_sse", stop_sse)

        # Make it not standalone
        subscriber.config.management_mode = "server-managed"
        subscriber.config.SERVER_URL = "https://real-server.example.com/api/v1/events"
        monkeypatch.setattr(subscriber, "_is_standalone", lambda: False)

        asyncio.run(subscriber.run())

        # Verify cached config was applied
        assert len(handled_events) == 1
        assert handled_events[0]["version"] == 5
        assert handled_events[0]["settings"] == {"flush_interval_seconds": 15}
