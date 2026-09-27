"""Unit tests for Fleet API blueprint endpoints.

Tests authentication, authorization, pagination, filtering, manual block
management, allow-list CRUD, config get/put, pause/resume toggle, and
SSE stream endpoint.

Requirements: 2.1, 4.5, 5.4, 8.1, 8.2, 8.3, 8.4, 8.5
"""

import hashlib
import json

import pytest

from app import create_app
from app.models import create_api_key, create_user, get_db


@pytest.fixture()
def app(tmp_path):
    """Create a Flask app with a test database for fleet API tests."""
    db_path = str(tmp_path / "test_fleet.db")
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({
        "SECRET_KEY": "test-secret-key-fleet",
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
def auth_client(app):
    """Factory fixture that returns an authenticated test client for a given role."""
    _counter = {"n": 0}

    def _make_auth_client(role: str):
        _counter["n"] += 1
        username = f"fleet_test_{role}_{_counter['n']}"
        password = f"password_{role}_{_counter['n']}"

        conn = get_db(app.config["DATABASE_PATH"])
        try:
            create_user(conn, username, password, role)
        finally:
            conn.close()

        test_client = app.test_client()
        test_client.post("/login", data={
            "username": username,
            "password": password,
        })
        return test_client

    return _make_auth_client


@pytest.fixture()
def api_key_token(app):
    """Create an admin user and an API key, return the raw token."""
    db = get_db(app.config["DATABASE_PATH"])
    try:
        row = db.execute("SELECT id FROM users WHERE username = 'fleet_admin'").fetchone()
        if row:
            admin_id = row["id"]
        else:
            admin_id = create_user(db, "fleet_admin", "admin_pass", "admin")
        token = create_api_key(db, "fleet-test-key", None, admin_id)
    finally:
        db.close()
    return token


def _seed_fleet_block(app, source_ip="10.0.0.1", status="active"):
    """Insert a fleet block directly into the database for testing."""
    db = get_db(app.config["DATABASE_PATH"])
    try:
        db.execute(
            "INSERT INTO fleet_blocks "
            "(fleet_block_id, source_ip, status, first_reported_at, "
            "last_renewed_at, approved_at, expires_at, "
            "reporting_node_count, originating_node_id, event_type, "
            "detection_rule, reason, ttl_seconds) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                f"fb-test-{source_ip}",
                source_ip,
                status,
                "2025-01-15T10:00:00Z",
                "2025-01-15T10:00:00Z",
                "2025-01-15T10:00:00Z",
                "2025-01-15T11:00:00Z",
                1,
                "node-alpha",
                "SSH_BRUTE",
                "ssh_brute_rule",
                "Test block",
                3600,
            ),
        )
        db.commit()
    finally:
        db.close()


# ── Authentication and Authorization Tests ───────────────────────────────


class TestFleetBlocksAuth:
    """Test authentication and authorization for fleet endpoints.

    Validates: Requirements 2.1, 8.1, 8.2, 8.3
    """

    def test_list_blocks_unauthenticated_redirects(self, client):
        """Unauthenticated GET /api/v1/fleet/blocks should redirect to login."""
        response = client.get("/api/v1/fleet/blocks")
        assert response.status_code == 302
        assert "/login" in response.headers.get("Location", "")

    def test_list_blocks_viewer_denied(self, auth_client):
        """Viewer role should be denied access to list fleet blocks."""
        c = auth_client("viewer")
        response = c.get("/api/v1/fleet/blocks")
        assert response.status_code == 403

    def test_list_blocks_analyst_allowed(self, auth_client):
        """Analyst role should have access to list fleet blocks."""
        c = auth_client("analyst")
        response = c.get("/api/v1/fleet/blocks")
        assert response.status_code == 200

    def test_list_blocks_admin_allowed(self, auth_client):
        """Admin role should have access to list fleet blocks."""
        c = auth_client("admin")
        response = c.get("/api/v1/fleet/blocks")
        assert response.status_code == 200

    def test_add_block_viewer_denied(self, auth_client):
        """Viewer role should be denied access to add fleet blocks."""
        c = auth_client("viewer")
        response = c.post(
            "/api/v1/fleet/blocks",
            data=json.dumps({"source_ip": "10.0.0.1", "reason": "test"}),
            content_type="application/json",
        )
        assert response.status_code == 403

    def test_add_block_analyst_denied(self, auth_client):
        """Analyst role should be denied access to add fleet blocks (admin only)."""
        c = auth_client("analyst")
        response = c.post(
            "/api/v1/fleet/blocks",
            data=json.dumps({"source_ip": "10.0.0.1", "reason": "test"}),
            content_type="application/json",
        )
        assert response.status_code == 403

    def test_add_block_admin_allowed(self, auth_client):
        """Admin role should be able to add fleet blocks."""
        c = auth_client("admin")
        response = c.post(
            "/api/v1/fleet/blocks",
            data=json.dumps({"source_ip": "192.168.50.1", "reason": "manual test"}),
            content_type="application/json",
        )
        assert response.status_code == 201

    def test_remove_block_viewer_denied(self, auth_client, app):
        """Viewer role should be denied access to remove fleet blocks."""
        _seed_fleet_block(app, "10.0.0.99")
        c = auth_client("viewer")
        response = c.delete("/api/v1/fleet/blocks/10.0.0.99")
        assert response.status_code == 403

    def test_remove_block_analyst_denied(self, auth_client, app):
        """Analyst role should be denied access to remove fleet blocks."""
        _seed_fleet_block(app, "10.0.0.98")
        c = auth_client("analyst")
        response = c.delete("/api/v1/fleet/blocks/10.0.0.98")
        assert response.status_code == 403

    def test_remove_block_admin_allowed(self, auth_client, app):
        """Admin role should be able to remove fleet blocks."""
        _seed_fleet_block(app, "10.0.0.97")
        c = auth_client("admin")
        response = c.delete("/api/v1/fleet/blocks/10.0.0.97")
        assert response.status_code == 200

    def test_allowlist_unauthenticated_redirects(self, client):
        """Unauthenticated GET /api/v1/fleet/allowlist should redirect."""
        response = client.get("/api/v1/fleet/allowlist")
        assert response.status_code == 302

    def test_config_unauthenticated_redirects(self, client):
        """Unauthenticated GET /api/v1/fleet/config should redirect."""
        response = client.get("/api/v1/fleet/config")
        assert response.status_code == 302

    def test_pause_unauthenticated_redirects(self, client):
        """Unauthenticated POST /api/v1/fleet/pause should redirect."""
        response = client.post("/api/v1/fleet/pause")
        assert response.status_code == 302


# ── Pagination and Filtering Tests ───────────────────────────────────────


class TestFleetBlocksPagination:
    """Test pagination and filtering on GET /api/v1/fleet/blocks.

    Validates: Requirement 8.1
    """

    def test_empty_list_returns_zero_items(self, auth_client):
        """Empty fleet blocks table should return empty items list."""
        c = auth_client("admin")
        response = c.get("/api/v1/fleet/blocks")
        assert response.status_code == 200
        data = response.get_json()
        assert data["items"] == []
        assert data["total"] == 0
        assert data["page"] == 1

    def test_pagination_defaults(self, auth_client, app):
        """Default pagination should return page 1 with per_page 50."""
        _seed_fleet_block(app, "10.0.0.1")
        c = auth_client("admin")
        response = c.get("/api/v1/fleet/blocks")
        data = response.get_json()
        assert data["page"] == 1
        assert data["per_page"] == 50
        assert data["total"] == 1
        assert len(data["items"]) == 1

    def test_pagination_custom_page_size(self, auth_client, app):
        """Custom per_page should limit results."""
        for i in range(5):
            _seed_fleet_block(app, f"10.0.1.{i}")
        c = auth_client("admin")
        response = c.get("/api/v1/fleet/blocks?per_page=2&page=1")
        data = response.get_json()
        assert data["per_page"] == 2
        assert len(data["items"]) == 2
        assert data["total"] == 5
        assert data["pages"] == 3

    def test_pagination_page_2(self, auth_client, app):
        """Page 2 should return the next set of results."""
        for i in range(5):
            _seed_fleet_block(app, f"10.0.2.{i}")
        c = auth_client("admin")
        response = c.get("/api/v1/fleet/blocks?per_page=2&page=2")
        data = response.get_json()
        assert data["page"] == 2
        assert len(data["items"]) == 2

    def test_filter_by_source_ip(self, auth_client, app):
        """Filter by source_ip should return only matching blocks."""
        _seed_fleet_block(app, "10.0.3.1")
        _seed_fleet_block(app, "10.0.3.2")
        c = auth_client("admin")
        response = c.get("/api/v1/fleet/blocks?source_ip=10.0.3.1")
        data = response.get_json()
        assert data["total"] == 1
        assert data["items"][0]["source_ip"] == "10.0.3.1"

    def test_filter_by_status(self, auth_client, app):
        """Filter by status should return only matching blocks."""
        _seed_fleet_block(app, "10.0.4.1", status="active")
        _seed_fleet_block(app, "10.0.4.2", status="expired")
        c = auth_client("admin")
        response = c.get("/api/v1/fleet/blocks?status=expired")
        data = response.get_json()
        assert data["total"] == 1
        assert data["items"][0]["source_ip"] == "10.0.4.2"

    def test_filter_by_node_id(self, auth_client, app):
        """Filter by node_id should return only matching blocks."""
        _seed_fleet_block(app, "10.0.5.1")
        c = auth_client("admin")
        response = c.get("/api/v1/fleet/blocks?node_id=node-alpha")
        data = response.get_json()
        assert data["total"] == 1

    def test_filter_by_event_type(self, auth_client, app):
        """Filter by event_type should return only matching blocks."""
        _seed_fleet_block(app, "10.0.6.1")
        c = auth_client("admin")
        response = c.get("/api/v1/fleet/blocks?event_type=SSH_BRUTE")
        data = response.get_json()
        assert data["total"] == 1

    def test_filter_no_match_returns_empty(self, auth_client, app):
        """Filter with no matching results should return empty."""
        _seed_fleet_block(app, "10.0.7.1")
        c = auth_client("admin")
        response = c.get("/api/v1/fleet/blocks?source_ip=99.99.99.99")
        data = response.get_json()
        assert data["total"] == 0
        assert data["items"] == []


# ── Manual Add/Remove Fleet Block Tests ──────────────────────────────────


class TestFleetBlockManagement:
    """Test manual add/remove fleet block flows.

    Validates: Requirements 8.2, 8.3, 8.4
    """

    def test_add_block_success(self, auth_client):
        """Admin can manually add a fleet block."""
        c = auth_client("admin")
        response = c.post(
            "/api/v1/fleet/blocks",
            data=json.dumps({"source_ip": "192.168.1.100", "reason": "Suspicious activity"}),
            content_type="application/json",
        )
        assert response.status_code == 201
        data = response.get_json()
        assert data["status"] == "propagated"
        assert "fleet_block_id" in data

    def test_add_block_missing_source_ip(self, auth_client):
        """Adding a block without source_ip should return 400."""
        c = auth_client("admin")
        response = c.post(
            "/api/v1/fleet/blocks",
            data=json.dumps({"reason": "test"}),
            content_type="application/json",
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "missing_field"

    def test_add_block_missing_reason(self, auth_client):
        """Adding a block without reason should return 400."""
        c = auth_client("admin")
        response = c.post(
            "/api/v1/fleet/blocks",
            data=json.dumps({"source_ip": "10.0.0.1"}),
            content_type="application/json",
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "missing_field"

    def test_add_block_invalid_json(self, auth_client):
        """Adding a block with invalid JSON should return 400."""
        c = auth_client("admin")
        response = c.post(
            "/api/v1/fleet/blocks",
            data="not json",
            content_type="application/json",
        )
        assert response.status_code == 400

    def test_add_block_duplicate_returns_409(self, auth_client, app):
        """Adding a block for an already-active IP should return 409."""
        _seed_fleet_block(app, "10.0.8.1")
        c = auth_client("admin")
        response = c.post(
            "/api/v1/fleet/blocks",
            data=json.dumps({"source_ip": "10.0.8.1", "reason": "duplicate"}),
            content_type="application/json",
        )
        assert response.status_code == 409

    def test_remove_block_success(self, auth_client, app):
        """Admin can remove an active fleet block."""
        _seed_fleet_block(app, "10.0.9.1")
        c = auth_client("admin")
        response = c.delete("/api/v1/fleet/blocks/10.0.9.1")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "removed"

    def test_remove_block_not_found(self, auth_client):
        """Removing a non-existent block should return 404."""
        c = auth_client("admin")
        response = c.delete("/api/v1/fleet/blocks/99.99.99.99")
        assert response.status_code == 404
        data = response.get_json()
        assert data["status"] == "not_found"

    def test_block_history_endpoint(self, auth_client, app):
        """GET /api/v1/fleet/blocks/<ip>/history returns reporting history."""
        _seed_fleet_block(app, "10.0.10.1")
        c = auth_client("admin")
        response = c.get("/api/v1/fleet/blocks/10.0.10.1/history")
        assert response.status_code == 200
        data = response.get_json()
        assert data["source_ip"] == "10.0.10.1"
        assert "reports" in data
        assert "blocks" in data
        assert len(data["blocks"]) == 1


# ── Allow-List CRUD Tests ────────────────────────────────────────────────


class TestFleetAllowlist:
    """Test allow-list CRUD operations.

    Validates: Requirement 5.4
    """

    def test_list_allowlist_empty(self, auth_client):
        """Empty allow-list should return empty items."""
        c = auth_client("admin")
        response = c.get("/api/v1/fleet/allowlist")
        assert response.status_code == 200
        data = response.get_json()
        assert data["items"] == []
        assert data["total"] == 0

    def test_add_allowlist_entry(self, auth_client):
        """Admin can add an allow-list entry."""
        c = auth_client("admin")
        response = c.post(
            "/api/v1/fleet/allowlist",
            data=json.dumps({"entry": "192.168.0.0/16"}),
            content_type="application/json",
        )
        assert response.status_code == 201
        data = response.get_json()
        assert data["status"] == "added"
        assert "entry_id" in data

    def test_add_allowlist_missing_entry(self, auth_client):
        """Adding allow-list entry without 'entry' field should return 400."""
        c = auth_client("admin")
        response = c.post(
            "/api/v1/fleet/allowlist",
            data=json.dumps({"entry": ""}),
            content_type="application/json",
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "missing_field"

    def test_list_allowlist_after_add(self, auth_client):
        """After adding an entry, it should appear in the list."""
        c = auth_client("admin")
        c.post(
            "/api/v1/fleet/allowlist",
            data=json.dumps({"entry": "10.10.0.0/16"}),
            content_type="application/json",
        )
        response = c.get("/api/v1/fleet/allowlist")
        data = response.get_json()
        assert data["total"] == 1
        assert data["items"][0]["entry"] == "10.10.0.0/16"

    def test_remove_allowlist_entry(self, auth_client):
        """Admin can remove an allow-list entry."""
        c = auth_client("admin")
        # Add first
        add_resp = c.post(
            "/api/v1/fleet/allowlist",
            data=json.dumps({"entry": "172.16.0.0/12"}),
            content_type="application/json",
        )
        entry_id = add_resp.get_json()["entry_id"]

        # Remove
        response = c.delete(f"/api/v1/fleet/allowlist/{entry_id}")
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "removed"

    def test_remove_allowlist_not_found(self, auth_client):
        """Removing a non-existent allow-list entry should return 404."""
        c = auth_client("admin")
        response = c.delete("/api/v1/fleet/allowlist/99999")
        assert response.status_code == 404
        data = response.get_json()
        assert data["status"] == "not_found"

    def test_allowlist_viewer_denied(self, auth_client):
        """Viewer role should be denied access to allow-list endpoints."""
        c = auth_client("viewer")
        response = c.get("/api/v1/fleet/allowlist")
        assert response.status_code == 403

    def test_allowlist_analyst_denied(self, auth_client):
        """Analyst role should be denied access to allow-list endpoints."""
        c = auth_client("analyst")
        response = c.get("/api/v1/fleet/allowlist")
        assert response.status_code == 403


# ── Config Get/Put Tests ─────────────────────────────────────────────────


class TestFleetConfig:
    """Test config get/put operations.

    Validates: Requirement 8.1
    """

    def test_get_config(self, auth_client):
        """Admin can retrieve propagation config."""
        c = auth_client("admin")
        response = c.get("/api/v1/fleet/config")
        assert response.status_code == 200
        data = response.get_json()
        # Check default values are present
        assert "corroboration_threshold" in data
        assert data["corroboration_threshold"] == 1
        assert "fleet_block_ttl_seconds" in data
        assert data["fleet_block_ttl_seconds"] == 86400
        assert "propagation_paused" in data
        assert data["propagation_paused"] is False

    def test_get_config_viewer_denied(self, auth_client):
        """Viewer role should be denied access to config."""
        c = auth_client("viewer")
        response = c.get("/api/v1/fleet/config")
        assert response.status_code == 403

    def test_get_config_analyst_denied(self, auth_client):
        """Analyst role should be denied access to config."""
        c = auth_client("analyst")
        response = c.get("/api/v1/fleet/config")
        assert response.status_code == 403

    def test_update_config(self, auth_client):
        """Admin can update propagation config values."""
        c = auth_client("admin")
        response = c.put(
            "/api/v1/fleet/config",
            data=json.dumps({"corroboration_threshold": 3}),
            content_type="application/json",
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "updated"
        assert "corroboration_threshold" in data["keys"]

        # Verify the change persisted
        get_resp = c.get("/api/v1/fleet/config")
        config = get_resp.get_json()
        assert config["corroboration_threshold"] == 3

    def test_update_config_multiple_keys(self, auth_client):
        """Admin can update multiple config keys at once."""
        c = auth_client("admin")
        response = c.put(
            "/api/v1/fleet/config",
            data=json.dumps({
                "fleet_block_ttl_seconds": 7200,
                "max_fleet_blocks_per_hour": 200,
            }),
            content_type="application/json",
        )
        assert response.status_code == 200
        data = response.get_json()
        assert len(data["keys"]) == 2

    def test_update_config_invalid_key(self, auth_client):
        """Updating a non-allowed config key should return 400."""
        c = auth_client("admin")
        response = c.put(
            "/api/v1/fleet/config",
            data=json.dumps({"propagation_paused": "true"}),
            content_type="application/json",
        )
        assert response.status_code == 400
        data = response.get_json()
        assert data["error"] == "invalid_key"

    def test_update_config_empty_body(self, auth_client):
        """Empty update body should return 400."""
        c = auth_client("admin")
        response = c.put(
            "/api/v1/fleet/config",
            data=json.dumps({}),
            content_type="application/json",
        )
        assert response.status_code == 400

    def test_update_config_invalid_json(self, auth_client):
        """Invalid JSON body should return 400."""
        c = auth_client("admin")
        response = c.put(
            "/api/v1/fleet/config",
            data="not json",
            content_type="application/json",
        )
        assert response.status_code == 400


# ── Pause/Resume Propagation Tests ───────────────────────────────────────


class TestFleetPause:
    """Test pause/resume propagation toggle.

    Validates: Requirement 4.5
    """

    def test_pause_propagation(self, auth_client):
        """Admin can pause propagation."""
        c = auth_client("admin")
        response = c.post(
            "/api/v1/fleet/pause",
            data=json.dumps({"paused": True}),
            content_type="application/json",
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "updated"
        assert data["propagation_paused"] is True

    def test_resume_propagation(self, auth_client):
        """Admin can resume propagation."""
        c = auth_client("admin")
        # First pause
        c.post(
            "/api/v1/fleet/pause",
            data=json.dumps({"paused": True}),
            content_type="application/json",
        )
        # Then resume
        response = c.post(
            "/api/v1/fleet/pause",
            data=json.dumps({"paused": False}),
            content_type="application/json",
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["propagation_paused"] is False

    def test_toggle_propagation_no_body(self, auth_client):
        """POST without body should toggle the current state."""
        c = auth_client("admin")
        # Initially not paused, toggle should pause
        response = c.post("/api/v1/fleet/pause")
        assert response.status_code == 200
        data = response.get_json()
        assert data["propagation_paused"] is True

        # Toggle again should resume
        response = c.post("/api/v1/fleet/pause")
        assert response.status_code == 200
        data = response.get_json()
        assert data["propagation_paused"] is False

    def test_pause_viewer_denied(self, auth_client):
        """Viewer role should be denied access to pause endpoint."""
        c = auth_client("viewer")
        response = c.post("/api/v1/fleet/pause")
        assert response.status_code == 403

    def test_pause_analyst_denied(self, auth_client):
        """Analyst role should be denied access to pause endpoint."""
        c = auth_client("analyst")
        response = c.post("/api/v1/fleet/pause")
        assert response.status_code == 403


# ── SSE Stream Endpoint Tests ────────────────────────────────────────────


class TestFleetSSEStream:
    """Test SSE stream endpoint requires auth and returns correct content-type.

    Validates: Requirement 2.1
    """

    def test_stream_no_auth_returns_401(self, client):
        """GET /api/v1/fleet/blocks/stream without Bearer token returns 401."""
        response = client.get("/api/v1/fleet/blocks/stream")
        assert response.status_code == 401
        data = response.get_json()
        assert data["error"] == "unauthorized"

    def test_stream_empty_bearer_returns_401(self, client):
        """GET /api/v1/fleet/blocks/stream with empty Bearer returns 401."""
        response = client.get(
            "/api/v1/fleet/blocks/stream",
            headers={"Authorization": "Bearer "},
        )
        assert response.status_code == 401

    def test_stream_invalid_token_returns_401(self, client, app):
        """GET /api/v1/fleet/blocks/stream with invalid token returns 401."""
        response = client.get(
            "/api/v1/fleet/blocks/stream",
            headers={"Authorization": "Bearer totally-bogus-token"},
        )
        assert response.status_code == 401

    def test_stream_revoked_key_returns_401(self, client, app, api_key_token):
        """GET /api/v1/fleet/blocks/stream with revoked key returns 401."""
        # Revoke the key
        db = get_db(app.config["DATABASE_PATH"])
        try:
            key_hash = hashlib.sha256(api_key_token.encode()).hexdigest()
            db.execute("UPDATE api_keys SET is_active = 0 WHERE key_hash = ?", (key_hash,))
            db.commit()
        finally:
            db.close()

        response = client.get(
            "/api/v1/fleet/blocks/stream",
            headers={"Authorization": f"Bearer {api_key_token}"},
        )
        assert response.status_code == 401

    def test_stream_valid_token_returns_sse_content_type(self, client, api_key_token):
        """GET /api/v1/fleet/blocks/stream with valid token returns text/event-stream."""
        response = client.get(
            "/api/v1/fleet/blocks/stream",
            headers={"Authorization": f"Bearer {api_key_token}"},
        )
        # The response should be a streaming response with correct content-type
        assert response.status_code == 200
        assert "text/event-stream" in response.content_type

    def test_stream_non_bearer_auth_returns_401(self, client):
        """GET /api/v1/fleet/blocks/stream with Basic auth returns 401."""
        response = client.get(
            "/api/v1/fleet/blocks/stream",
            headers={"Authorization": "Basic dXNlcjpwYXNz"},
        )
        assert response.status_code == 401
