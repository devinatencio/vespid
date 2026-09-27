"""Unit tests for the agent check-in endpoint (POST /api/v1/config/check-in).

Tests authentication, payload parsing, health status updates, profile
resolution, rollout engine integration, and audit logging.

Requirements: 5.4, 5.5, 5.6, 5.7, 10.2, 10.3, 11.3, 16.3, 16.4, 16.5, 16.6, 16.7, 16.8, 16.9, 16.10
"""

import json

import pytest

from app import create_app
from app.models import (
    create_api_key,
    create_config_profile,
    create_user,
    get_db,
    upsert_agent_config_status,
    upsert_node,
)


@pytest.fixture()
def app(tmp_path):
    """Create a Flask app with a test database for check-in tests."""
    db_path = str(tmp_path / "test_checkin.db")
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({
        "SECRET_KEY": "test-secret-key-checkin",
        "DATABASE_PATH": db_path,
        "RATELIMIT_ENABLED": False,
    }))
    application = create_app(str(config_file))
    application.config["TESTING"] = True
    application.config["WTF_CSRF_ENABLED"] = False
    return application


@pytest.fixture()
def client(app):
    """Return a Flask test client."""
    return app.test_client()


@pytest.fixture()
def api_token(app):
    """Create an admin user and API key, return the raw token."""
    db = get_db(app.config["DATABASE_PATH"])
    try:
        admin_id = create_user(db, "checkin_admin", "admin_pass", "admin")
        token = create_api_key(db, "checkin-test-key", None, admin_id)
    finally:
        db.close()
    return token


def _seed_node(app, node_id):
    """Register a node in the nodes table."""
    db = get_db(app.config["DATABASE_PATH"])
    try:
        upsert_node(db, node_id, "2025-01-15T10:00:00Z", {})
    finally:
        db.close()


def _seed_profile_and_assign(app, node_id, settings=None, version=1):
    """Create a profile and assign it directly to a node.

    Returns the profile dict.
    """
    if settings is None:
        settings = {"flush_interval_seconds": 30}

    db = get_db(app.config["DATABASE_PATH"])
    try:
        profile = create_config_profile(
            db,
            name=f"profile-for-{node_id}",
            settings=settings,
            created_by="admin",
            description="Test profile",
        )
        # Manually set version if needed
        if version > 1:
            db.execute(
                "UPDATE config_profiles SET version = ? WHERE id = ?",
                (version, profile["id"]),
            )
            db.commit()

        # Create direct assignment
        db.execute(
            "INSERT INTO config_assignments (node_id, profile_id, assigned_by, is_active) "
            "VALUES (?, ?, 'admin', 1)",
            (node_id, profile["id"]),
        )
        db.commit()
        return profile
    finally:
        db.close()


# ── Authentication Tests ─────────────────────────────────────────────────


class TestCheckInAuth:
    """Test Bearer token authentication for check-in endpoint."""

    def test_missing_auth_header_returns_401(self, client):
        resp = client.post(
            "/api/v1/config/check-in",
            json={"node_id": "node-1", "management_mode": "standalone"},
        )
        assert resp.status_code == 401
        data = resp.get_json()
        assert data["error"] == "unauthorized"

    def test_invalid_token_returns_401(self, client):
        resp = client.post(
            "/api/v1/config/check-in",
            json={"node_id": "node-1", "management_mode": "standalone"},
            headers={"Authorization": "Bearer invalid-token-xyz"},
        )
        assert resp.status_code == 401

    def test_valid_token_succeeds(self, client, api_token):
        resp = client.post(
            "/api/v1/config/check-in",
            json={"node_id": "node-1", "management_mode": "standalone"},
            headers={"Authorization": f"Bearer {api_token}"},
        )
        assert resp.status_code == 200

    def test_empty_bearer_returns_401(self, client):
        resp = client.post(
            "/api/v1/config/check-in",
            json={"node_id": "node-1"},
            headers={"Authorization": "Bearer "},
        )
        assert resp.status_code == 401


# ── Payload Validation Tests ─────────────────────────────────────────────


class TestCheckInValidation:
    """Test request body validation."""

    def test_missing_node_id_returns_400(self, client, api_token):
        resp = client.post(
            "/api/v1/config/check-in",
            json={"management_mode": "standalone"},
            headers={"Authorization": f"Bearer {api_token}"},
        )
        assert resp.status_code == 400
        data = resp.get_json()
        assert "node_id" in data["message"]

    def test_invalid_json_returns_400(self, client, api_token):
        resp = client.post(
            "/api/v1/config/check-in",
            data="not json",
            content_type="application/json",
            headers={"Authorization": f"Bearer {api_token}"},
        )
        assert resp.status_code == 400

    def test_empty_body_returns_400(self, client, api_token):
        resp = client.post(
            "/api/v1/config/check-in",
            json={},
            headers={"Authorization": f"Bearer {api_token}"},
        )
        assert resp.status_code == 400


# ── Standalone Mode Tests ────────────────────────────────────────────────


class TestCheckInStandalone:
    """Test standalone mode check-in behavior."""

    def test_standalone_returns_null_config_update(self, client, api_token):
        resp = client.post(
            "/api/v1/config/check-in",
            json={
                "node_id": "node-standalone",
                "current_config_version": 0,
                "management_mode": "standalone",
                "agent_version": "1.5.0",
                "health": {"uptime": 3600, "active_rules": 5, "blocked_ips": 10},
            },
            headers={"Authorization": f"Bearer {api_token}"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["config_update"] is None

    def test_standalone_updates_agent_status(self, app, client, api_token):
        resp = client.post(
            "/api/v1/config/check-in",
            json={
                "node_id": "node-health-test",
                "current_config_version": 0,
                "management_mode": "standalone",
                "agent_version": "2.0.0",
                "health": {"uptime": 7200, "active_rules": 10, "blocked_ips": 42},
            },
            headers={"Authorization": f"Bearer {api_token}"},
        )
        assert resp.status_code == 200

        # Verify status was recorded
        db = get_db(app.config["DATABASE_PATH"])
        try:
            row = db.execute(
                "SELECT * FROM config_agent_status WHERE node_id = ?",
                ("node-health-test",),
            ).fetchone()
            assert row is not None
            assert row["management_mode"] == "standalone"
            assert row["agent_version"] == "2.0.0"
            assert row["health_uptime"] == 7200
            assert row["health_active_rules"] == 10
            assert row["health_blocked_ips"] == 42
            assert row["last_check_in"] is not None
        finally:
            db.close()


# ── Server-Managed Mode Tests ────────────────────────────────────────────


class TestCheckInServerManaged:
    """Test server-managed mode check-in behavior."""

    def test_no_profile_assigned_returns_null(self, app, client, api_token):
        """Agent with no profile assignment gets no config update."""
        _seed_node(app, "node-no-profile")
        resp = client.post(
            "/api/v1/config/check-in",
            json={
                "node_id": "node-no-profile",
                "current_config_version": 0,
                "management_mode": "server-managed",
                "agent_version": "1.5.0",
            },
            headers={"Authorization": f"Bearer {api_token}"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["config_update"] is None

    def test_stale_version_returns_full_settings(self, app, client, api_token):
        """Agent with stale version receives full config update."""
        _seed_node(app, "node-stale")
        settings = {"flush_interval_seconds": 60, "heartbeat_interval_seconds": 120}
        _seed_profile_and_assign(app, "node-stale", settings=settings, version=5)

        resp = client.post(
            "/api/v1/config/check-in",
            json={
                "node_id": "node-stale",
                "current_config_version": 3,
                "management_mode": "server-managed",
                "agent_version": "1.5.0",
            },
            headers={"Authorization": f"Bearer {api_token}"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["config_update"] is not None
        assert data["config_update"]["version"] == 5
        assert data["config_update"]["settings"] == settings
        assert "profile_name" in data["config_update"]
        assert "conflict_strategy" in data["config_update"]

    def test_current_version_returns_null(self, app, client, api_token):
        """Agent with current version gets no config update."""
        _seed_node(app, "node-current")
        _seed_profile_and_assign(app, "node-current", version=5)

        resp = client.post(
            "/api/v1/config/check-in",
            json={
                "node_id": "node-current",
                "current_config_version": 5,
                "management_mode": "server-managed",
                "agent_version": "1.5.0",
            },
            headers={"Authorization": f"Bearer {api_token}"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["config_update"] is None

    def test_stale_version_records_audit_log(self, app, client, api_token):
        """Config acknowledgment is recorded in audit log."""
        _seed_node(app, "node-audit")
        _seed_profile_and_assign(app, "node-audit", version=3)

        resp = client.post(
            "/api/v1/config/check-in",
            json={
                "node_id": "node-audit",
                "current_config_version": 1,
                "management_mode": "server-managed",
                "agent_version": "1.5.0",
            },
            headers={"Authorization": f"Bearer {api_token}"},
        )
        assert resp.status_code == 200

        # Verify audit log entry
        db = get_db(app.config["DATABASE_PATH"])
        try:
            row = db.execute(
                "SELECT * FROM audit_log WHERE action_type = 'config_ack' "
                "AND actor = 'node-audit' ORDER BY id DESC LIMIT 1",
            ).fetchone()
            assert row is not None
            details = json.loads(row["details"])
            assert details["node_id"] == "node-audit"
            assert details["version"] == 3
            assert details["previous_version"] == 1
        finally:
            db.close()


# ── Rollout Engine Integration Tests ─────────────────────────────────────


class TestCheckInRollout:
    """Test rollout engine integration with check-in."""

    def test_canary_rollout_blocks_non_canary_node(self, app, client, api_token):
        """Node not in canary set does not receive update even if version is stale."""
        _seed_node(app, "node-not-canary")
        _seed_profile_and_assign(app, "node-not-canary", version=5)

        # Create a canary rollout that does NOT include this node
        db = get_db(app.config["DATABASE_PATH"])
        try:
            profile = db.execute(
                "SELECT id FROM config_profiles WHERE name = ?",
                ("profile-for-node-not-canary",),
            ).fetchone()
            db.execute(
                "INSERT INTO config_rollouts "
                "(profile_id, target_version, policy, status, canary_nodes, "
                "current_percentage, created_by, total_targeted) "
                "VALUES (?, 5, 'canary', 'in_progress', ?, 100, 'admin', 2)",
                (profile["id"], json.dumps(["node-other-1", "node-other-2"])),
            )
            db.commit()
        finally:
            db.close()

        resp = client.post(
            "/api/v1/config/check-in",
            json={
                "node_id": "node-not-canary",
                "current_config_version": 2,
                "management_mode": "server-managed",
                "agent_version": "1.5.0",
            },
            headers={"Authorization": f"Bearer {api_token}"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        # Rollout blocks distribution to this node
        assert data["config_update"] is None

    def test_canary_rollout_allows_canary_node(self, app, client, api_token):
        """Node in canary set receives the update."""
        _seed_node(app, "node-canary")
        _seed_profile_and_assign(app, "node-canary", version=5)

        # Create a canary rollout that includes this node
        db = get_db(app.config["DATABASE_PATH"])
        try:
            profile = db.execute(
                "SELECT id FROM config_profiles WHERE name = ?",
                ("profile-for-node-canary",),
            ).fetchone()
            db.execute(
                "INSERT INTO config_rollouts "
                "(profile_id, target_version, policy, status, canary_nodes, "
                "current_percentage, created_by, total_targeted) "
                "VALUES (?, 5, 'canary', 'in_progress', ?, 100, 'admin', 2)",
                (profile["id"], json.dumps(["node-canary", "node-other"])),
            )
            db.commit()
        finally:
            db.close()

        resp = client.post(
            "/api/v1/config/check-in",
            json={
                "node_id": "node-canary",
                "current_config_version": 2,
                "management_mode": "server-managed",
                "agent_version": "1.5.0",
            },
            headers={"Authorization": f"Bearer {api_token}"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["config_update"] is not None
        assert data["config_update"]["version"] == 5
