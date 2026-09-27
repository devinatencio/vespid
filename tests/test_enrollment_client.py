"""Tests for vespid.enrollment_client.

Covers:
- Credential detection and loading (has_credentials, load_credentials)
- Enrollment flow: open mode (200), pending (202), rejected (403),
  conflict (409), rate-limited (429), network errors
- Credential persistence (atomic write, mode 0600)
- Rotation check (200 with key, 200 without key, 403, network error)
- Server URL parsing (strip /api/v1/events suffix)
"""

from __future__ import annotations

import json
import os
import stat
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture(autouse=True)
def _isolate(tmp_path, monkeypatch):
    """Redirect state/config to tmp_path so no system paths are touched."""
    monkeypatch.setenv("VESPID_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("VESPID_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv("VESPID_ID_FILE", str(tmp_path / "node_id"))


@pytest.fixture
def config(tmp_path):
    """Minimal ShieldConfig for enrollment tests."""
    from vespid.config import ShieldConfig

    return ShieldConfig(
        node_id="test-node-001",
        SERVER_URL="https://server.example.com/api/v1/events",
        API_KEY="",
        spool_path=str(tmp_path / "spool.jsonl"),
        fleet_queue_dir=str(tmp_path / "fleet_queue"),
        subscriptions=[],
    )


@pytest.fixture
def client(config, tmp_path):
    """Create an EnrollmentClient with credentials path in tmp_path."""
    from vespid.enrollment_client import EnrollmentClient

    ec = EnrollmentClient(config)
    # Override the class-level path to use tmp_path
    ec.CREDENTIALS_PATH = tmp_path / "credentials.json"
    return ec


# ---------------------------------------------------------------------------
# Server URL parsing
# ---------------------------------------------------------------------------


class TestServerURLParsing:
    def test_strips_api_v1_events(self, client):
        assert client.server_url == "https://server.example.com"

    def test_no_api_path(self, config, tmp_path):
        from vespid.enrollment_client import EnrollmentClient

        config.SERVER_URL = "https://myserver.io"
        ec = EnrollmentClient(config)
        ec.CREDENTIALS_PATH = tmp_path / "credentials.json"
        assert ec.server_url == "https://myserver.io"


# ---------------------------------------------------------------------------
# Credential detection and loading
# ---------------------------------------------------------------------------


class TestCredentials:
    def test_has_credentials_false_when_missing(self, client):
        assert client.has_credentials() is False

    def test_has_credentials_true_when_present(self, client):
        client.CREDENTIALS_PATH.write_text(
            json.dumps(
                {
                    "api_key": "key123",
                    "server_url": "https://server.example.com",
                    "node_id": "test-node-001",
                }
            )
        )
        assert client.has_credentials() is True

    def test_load_credentials_valid(self, client):
        creds = {
            "api_key": "key123",
            "server_url": "https://server.example.com",
            "node_id": "test-node-001",
        }
        client.CREDENTIALS_PATH.write_text(json.dumps(creds))
        loaded = client.load_credentials()
        assert loaded is not None
        assert loaded["api_key"] == "key123"

    def test_load_credentials_missing_field(self, client):
        client.CREDENTIALS_PATH.write_text(
            json.dumps(
                {
                    "api_key": "key123",
                    # Missing server_url and node_id
                }
            )
        )
        assert client.load_credentials() is None

    def test_load_credentials_invalid_json(self, client):
        client.CREDENTIALS_PATH.write_text("not valid json{{{")
        assert client.load_credentials() is None

    def test_load_credentials_missing_file(self, client):
        assert client.load_credentials() is None


# ---------------------------------------------------------------------------
# Enrollment flow
# ---------------------------------------------------------------------------


class TestEnroll:
    def test_open_mode_returns_api_key(self, client):
        """200 response returns the API key and persists credentials."""
        import httpx

        mock_response = httpx.Response(
            200,
            json={"api_key": "issued-key-abc", "server_url": "https://server.example.com"},
        )
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value.__enter__ = lambda s: s
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_client_cls.return_value.post = MagicMock(return_value=mock_response)

            result = client.enroll()

        assert result == "issued-key-abc"
        assert client.CREDENTIALS_PATH.exists()
        saved = json.loads(client.CREDENTIALS_PATH.read_text())
        assert saved["api_key"] == "issued-key-abc"

    def test_pending_returns_none(self, client):
        """202 response returns None (pending approval)."""
        import httpx

        mock_response = httpx.Response(202, json={"status": "pending"})
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value.__enter__ = lambda s: s
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_client_cls.return_value.post = MagicMock(return_value=mock_response)

            result = client.enroll()

        assert result is None
        assert not client.CREDENTIALS_PATH.exists()

    def test_rejected_raises_enrollment_error(self, client):
        """403 response raises EnrollmentError."""
        import httpx

        from vespid.enrollment_client import EnrollmentError

        mock_response = httpx.Response(403, json={"error": "enrollment disabled"})
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value.__enter__ = lambda s: s
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_client_cls.return_value.post = MagicMock(return_value=mock_response)

            with pytest.raises(EnrollmentError, match="rejected"):
                client.enroll()

    def test_conflict_raises_enrollment_error(self, client):
        """409 response raises EnrollmentError."""
        import httpx

        from vespid.enrollment_client import EnrollmentError

        mock_response = httpx.Response(409, json={"error": "already enrolled"})
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value.__enter__ = lambda s: s
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_client_cls.return_value.post = MagicMock(return_value=mock_response)

            with pytest.raises(EnrollmentError, match="conflict"):
                client.enroll()

    def test_rate_limited_raises_enrollment_error(self, client):
        """429 response raises EnrollmentError."""
        import httpx

        from vespid.enrollment_client import EnrollmentError

        mock_response = httpx.Response(429, text="rate limited")
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value.__enter__ = lambda s: s
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_client_cls.return_value.post = MagicMock(return_value=mock_response)

            with pytest.raises(EnrollmentError, match="Rate limited"):
                client.enroll()

    def test_network_error_raises_enrollment_error(self, client):
        """httpx.HTTPError raises EnrollmentError."""
        import httpx

        from vespid.enrollment_client import EnrollmentError

        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value.__enter__ = lambda s: s
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_client_cls.return_value.post = MagicMock(
                side_effect=httpx.ConnectError("Connection refused")
            )

            with pytest.raises(EnrollmentError, match="Network error"):
                client.enroll()


# ---------------------------------------------------------------------------
# Credential persistence
# ---------------------------------------------------------------------------


class TestPersistCredentials:
    def test_persist_creates_file(self, client):
        client._persist_credentials("my-key", "https://server.example.com")
        assert client.CREDENTIALS_PATH.exists()
        data = json.loads(client.CREDENTIALS_PATH.read_text())
        assert data["api_key"] == "my-key"
        assert data["node_id"] == "test-node-001"
        assert "enrolled_at" in data

    def test_persist_sets_mode_0600(self, client):
        client._persist_credentials("my-key", "https://server.example.com")
        mode = stat.S_IMODE(os.stat(client.CREDENTIALS_PATH).st_mode)
        assert mode == 0o600

    def test_persist_includes_asset_id(self, client):
        client._persist_credentials("key", "https://s.example.com", asset_id="asset-xyz")
        data = json.loads(client.CREDENTIALS_PATH.read_text())
        assert data["asset_id"] == "asset-xyz"


# ---------------------------------------------------------------------------
# Rotation check
# ---------------------------------------------------------------------------


class TestCheckRotation:
    def test_rotation_returns_new_key(self, client):
        """200 with api_key returns the new key and persists it."""
        import httpx

        mock_response = httpx.Response(
            200,
            json={"api_key": "rotated-key-999", "server_url": "https://server.example.com"},
        )
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value.__enter__ = lambda s: s
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_client_cls.return_value.get = MagicMock(return_value=mock_response)

            result = client.check_rotation()

        assert result == "rotated-key-999"
        assert client.CREDENTIALS_PATH.exists()

    def test_rotation_no_key_returns_none(self, client):
        """200 without api_key returns None."""
        import httpx

        mock_response = httpx.Response(200, json={"status": "approved"})
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value.__enter__ = lambda s: s
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_client_cls.return_value.get = MagicMock(return_value=mock_response)

            result = client.check_rotation()

        assert result is None

    def test_rotation_revoked_returns_none(self, client):
        """403 means revoked — returns None."""
        import httpx

        mock_response = httpx.Response(403, json={"error": "revoked"})
        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value.__enter__ = lambda s: s
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_client_cls.return_value.get = MagicMock(return_value=mock_response)

            result = client.check_rotation()

        assert result is None

    def test_rotation_network_error_returns_none(self, client):
        """Network errors return None gracefully."""
        import httpx

        with patch("httpx.Client") as mock_client_cls:
            mock_client_cls.return_value.__enter__ = lambda s: s
            mock_client_cls.return_value.__exit__ = MagicMock(return_value=False)
            mock_client_cls.return_value.get = MagicMock(side_effect=httpx.ConnectError("timeout"))

            result = client.check_rotation()

        assert result is None
