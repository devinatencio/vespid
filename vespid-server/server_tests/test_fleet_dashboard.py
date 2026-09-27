"""Unit tests for Fleet Dashboard blueprint endpoints.

Tests page routes, HTMX fragment routes, role-based access control,
manual block add/remove, allowlist add/remove, config update, and
pause toggle.

Requirements: 2, 3, 4, 5, 8
"""

import json

import pytest

from app import create_app
from app.models import create_user, get_db


@pytest.fixture()
def app(tmp_path):
    """Create a Flask app with a test database for fleet dashboard tests."""
    db_path = str(tmp_path / "test_fleet_dashboard.db")
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({
        "SECRET_KEY": "test-secret-key-fleet-dashboard",
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
        username = f"fleet_dash_{role}_{_counter['n']}"
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
                f"fb-dash-test-{source_ip}",
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


def _seed_allowlist_entry(app, entry="192.168.1.0/24", reason="Test entry"):
    """Insert an allowlist entry directly into the database for testing."""
    db = get_db(app.config["DATABASE_PATH"])
    try:
        db.execute(
            "INSERT INTO fleet_allowlist (entry, reason, created_by) "
            "VALUES (?, ?, ?)",
            (entry, reason, "test_admin"),
        )
        db.commit()
        row = db.execute(
            "SELECT id FROM fleet_allowlist WHERE entry = ?", (entry,)
        ).fetchone()
        return row["id"]
    finally:
        db.close()


# ── Page Route Tests ─────────────────────────────────────────────────────


class TestFleetDashboardPageRoutes:
    """Test that all fleet dashboard page routes return 200 for authenticated users.

    Validates: Requirements 2, 3, 4, 8
    """

    def test_blocks_page_admin(self, auth_client):
        """Admin can access the fleet blocks page."""
        c = auth_client("admin")
        response = c.get("/fleet/")
        assert response.status_code == 200

    def test_blocks_page_analyst(self, auth_client):
        """Analyst can access the fleet blocks page."""
        c = auth_client("analyst")
        response = c.get("/fleet/")
        assert response.status_code == 200

    def test_allowlist_page_admin(self, auth_client):
        """Admin can access the fleet allowlist page."""
        c = auth_client("admin")
        response = c.get("/fleet/allowlist")
        assert response.status_code == 200

    def test_allowlist_page_analyst(self, auth_client):
        """Analyst can access the fleet allowlist page."""
        c = auth_client("analyst")
        response = c.get("/fleet/allowlist")
        assert response.status_code == 200

    def test_config_page_admin(self, auth_client):
        """Admin can access the fleet config page."""
        c = auth_client("admin")
        response = c.get("/fleet/config")
        assert response.status_code == 200


# ── HTMX Fragment Route Tests ────────────────────────────────────────────


class TestFleetDashboardHTMXFragments:
    """Test HTMX fragment routes return fragments (not full pages).

    Validates: Requirements 2, 3, 5, 8
    """

    def test_blocks_table_fragment(self, auth_client):
        """GET /fleet/fragments/blocks-table returns a fragment with HX-Request."""
        c = auth_client("admin")
        response = c.get(
            "/fleet/fragments/blocks-table",
            headers={"HX-Request": "true"},
        )
        assert response.status_code == 200
        html = response.data.decode()
        # Fragment should NOT contain full page structure
        assert "<!DOCTYPE" not in html
        assert "</html>" not in html

    def test_fleet_summary_card_fragment(self, auth_client):
        """GET /fleet/fragments/fleet-summary-card returns a fragment."""
        c = auth_client("analyst")
        response = c.get(
            "/fleet/fragments/fleet-summary-card",
            headers={"HX-Request": "true"},
        )
        assert response.status_code == 200
        html = response.data.decode()
        assert "<!DOCTYPE" not in html
        assert "</html>" not in html

    def test_blocks_page_htmx_returns_fragment(self, auth_client):
        """GET /fleet/ with HX-Request returns only the table fragment."""
        c = auth_client("admin")
        response = c.get(
            "/fleet/",
            headers={"HX-Request": "true"},
        )
        assert response.status_code == 200
        html = response.data.decode()
        # Should be a fragment, not a full page
        assert "<!DOCTYPE" not in html
        assert "</html>" not in html

    def test_allowlist_page_htmx_returns_fragment(self, auth_client):
        """GET /fleet/allowlist with HX-Request returns only the table fragment."""
        c = auth_client("admin")
        response = c.get(
            "/fleet/allowlist",
            headers={"HX-Request": "true"},
        )
        assert response.status_code == 200
        html = response.data.decode()
        assert "<!DOCTYPE" not in html
        assert "</html>" not in html

    def test_pause_toggle_fragment(self, auth_client):
        """GET /fleet/fragments/pause-toggle returns a fragment."""
        c = auth_client("analyst")
        response = c.get(
            "/fleet/fragments/pause-toggle",
            headers={"HX-Request": "true"},
        )
        assert response.status_code == 200
        html = response.data.decode()
        assert "<!DOCTYPE" not in html
        assert "</html>" not in html


# ── Role-Based Access Control Tests ──────────────────────────────────────


class TestFleetDashboardRBAC:
    """Test role-based access control for fleet dashboard routes.

    Validates: Requirements 5, 8
    """

    def test_blocks_page_viewer_denied(self, auth_client):
        """Viewer role should be denied access to fleet blocks page."""
        c = auth_client("viewer")
        response = c.get("/fleet/")
        assert response.status_code == 403

    def test_allowlist_page_viewer_denied(self, auth_client):
        """Viewer role should be denied access to fleet allowlist page."""
        c = auth_client("viewer")
        response = c.get("/fleet/allowlist")
        assert response.status_code == 403

    def test_config_page_viewer_denied(self, auth_client):
        """Viewer role should be denied access to fleet config page."""
        c = auth_client("viewer")
        response = c.get("/fleet/config")
        assert response.status_code == 403

    def test_config_page_analyst_denied(self, auth_client):
        """Analyst role should be denied access to fleet config page (admin only)."""
        c = auth_client("analyst")
        response = c.get("/fleet/config")
        assert response.status_code == 403

    def test_add_block_analyst_denied(self, auth_client):
        """Analyst role should be denied access to add fleet blocks."""
        c = auth_client("analyst")
        response = c.post("/fleet/blocks/add", data={
            "source_ip": "10.0.0.1",
            "reason": "test",
        })
        assert response.status_code == 403

    def test_add_block_viewer_denied(self, auth_client):
        """Viewer role should be denied access to add fleet blocks."""
        c = auth_client("viewer")
        response = c.post("/fleet/blocks/add", data={
            "source_ip": "10.0.0.1",
            "reason": "test",
        })
        assert response.status_code == 403

    def test_remove_block_analyst_denied(self, auth_client, app):
        """Analyst role should be denied access to remove fleet blocks."""
        _seed_fleet_block(app, "10.0.0.50")
        c = auth_client("analyst")
        response = c.delete("/fleet/blocks/10.0.0.50/remove")
        assert response.status_code == 403

    def test_config_update_analyst_denied(self, auth_client):
        """Analyst role should be denied access to update config."""
        c = auth_client("analyst")
        response = c.post("/fleet/config/update", data={
            "corroboration_threshold": "3",
        })
        assert response.status_code == 403

    def test_pause_toggle_analyst_denied(self, auth_client):
        """Analyst role should be denied access to toggle pause."""
        c = auth_client("analyst")
        response = c.post("/fleet/pause/toggle")
        assert response.status_code == 403

    def test_add_allowlist_analyst_denied(self, auth_client):
        """Analyst role should be denied access to add allowlist entries."""
        c = auth_client("analyst")
        response = c.post("/fleet/allowlist/add", data={
            "entry": "10.0.0.0/8",
        })
        assert response.status_code == 403

    def test_remove_allowlist_analyst_denied(self, auth_client, app):
        """Analyst role should be denied access to remove allowlist entries."""
        entry_id = _seed_allowlist_entry(app)
        c = auth_client("analyst")
        response = c.delete(f"/fleet/allowlist/{entry_id}/remove")
        assert response.status_code == 403

    def test_unauthenticated_blocks_page_redirects(self, client):
        """Unauthenticated access to fleet blocks page should redirect to login."""
        response = client.get("/fleet/")
        assert response.status_code == 302
        assert "/login" in response.headers.get("Location", "")

    def test_unauthenticated_config_page_redirects(self, client):
        """Unauthenticated access to fleet config page should redirect to login."""
        response = client.get("/fleet/config")
        assert response.status_code == 302
        assert "/login" in response.headers.get("Location", "")


# ── Manual Block Add/Remove Tests ────────────────────────────────────────


class TestFleetDashboardBlockManagement:
    """Test manual block add/remove flows via the dashboard.

    Validates: Requirements 2, 8
    """

    def test_add_block_success(self, auth_client):
        """Admin can manually add a fleet block via the dashboard form."""
        c = auth_client("admin")
        response = c.post("/fleet/blocks/add", data={
            "source_ip": "192.168.50.1",
            "reason": "Suspicious activity",
        }, follow_redirects=True)
        assert response.status_code == 200
        html = response.data.decode()
        assert "Fleet block added" in html or "192.168.50.1" in html

    def test_add_block_missing_ip(self, auth_client):
        """Adding a block without source_ip shows error flash."""
        c = auth_client("admin")
        response = c.post("/fleet/blocks/add", data={
            "source_ip": "",
            "reason": "test",
        }, follow_redirects=True)
        assert response.status_code == 200
        html = response.data.decode()
        assert "required" in html.lower() or "error" in html.lower()

    def test_add_block_missing_reason(self, auth_client):
        """Adding a block without reason shows error flash."""
        c = auth_client("admin")
        response = c.post("/fleet/blocks/add", data={
            "source_ip": "10.0.0.1",
            "reason": "",
        }, follow_redirects=True)
        assert response.status_code == 200
        html = response.data.decode()
        assert "required" in html.lower() or "error" in html.lower()

    def test_remove_block_success(self, auth_client, app):
        """Admin can remove an active fleet block via the dashboard."""
        _seed_fleet_block(app, "10.0.0.77")
        c = auth_client("admin")
        response = c.delete("/fleet/blocks/10.0.0.77/remove", follow_redirects=True)
        assert response.status_code == 200

    def test_remove_block_not_found(self, auth_client):
        """Removing a non-existent block shows error flash."""
        c = auth_client("admin")
        response = c.delete(
            "/fleet/blocks/99.99.99.99/remove", follow_redirects=True
        )
        assert response.status_code == 200
        html = response.data.decode()
        assert "not found" in html.lower() or "error" in html.lower() or "No active" in html


# ── Allowlist Add/Remove Tests ───────────────────────────────────────────


class TestFleetDashboardAllowlist:
    """Test allowlist add/remove flows via the dashboard.

    Validates: Requirements 3, 8
    """

    def test_add_allowlist_success(self, auth_client):
        """Admin can add an allowlist entry via the dashboard form."""
        c = auth_client("admin")
        response = c.post("/fleet/allowlist/add", data={
            "entry": "172.16.0.0/12",
            "reason": "Internal network",
        }, follow_redirects=True)
        assert response.status_code == 200
        html = response.data.decode()
        assert "added" in html.lower() or "172.16.0.0/12" in html

    def test_add_allowlist_missing_entry(self, auth_client):
        """Adding an allowlist entry without entry field shows error flash."""
        c = auth_client("admin")
        response = c.post("/fleet/allowlist/add", data={
            "entry": "",
            "reason": "test",
        }, follow_redirects=True)
        assert response.status_code == 200
        html = response.data.decode()
        assert "required" in html.lower() or "error" in html.lower()

    def test_remove_allowlist_success(self, auth_client, app):
        """Admin can remove an allowlist entry via the dashboard."""
        entry_id = _seed_allowlist_entry(app, "10.10.0.0/16")
        c = auth_client("admin")
        response = c.delete(
            f"/fleet/allowlist/{entry_id}/remove", follow_redirects=True
        )
        assert response.status_code == 200

    def test_remove_allowlist_not_found(self, auth_client):
        """Removing a non-existent allowlist entry shows error flash."""
        c = auth_client("admin")
        response = c.delete(
            "/fleet/allowlist/99999/remove", follow_redirects=True
        )
        assert response.status_code == 200
        html = response.data.decode()
        assert "not found" in html.lower() or "error" in html.lower()


# ── Config Update Tests ──────────────────────────────────────────────────


class TestFleetDashboardConfig:
    """Test config update flow via the dashboard.

    Validates: Requirements 4, 8
    """

    def test_update_config_success(self, auth_client):
        """Admin can update propagation config via the dashboard form."""
        c = auth_client("admin")
        response = c.post("/fleet/config/update", data={
            "corroboration_threshold": "3",
            "fleet_block_ttl_seconds": "7200",
        }, follow_redirects=True)
        assert response.status_code == 200
        html = response.data.decode()
        assert "updated" in html.lower() or "success" in html.lower()

    def test_update_config_invalid_value(self, auth_client):
        """Submitting a non-integer value shows error flash."""
        c = auth_client("admin")
        response = c.post("/fleet/config/update", data={
            "corroboration_threshold": "not_a_number",
        }, follow_redirects=True)
        assert response.status_code == 200
        html = response.data.decode()
        assert "invalid" in html.lower() or "error" in html.lower()

    def test_update_config_negative_value(self, auth_client):
        """Submitting a negative value shows error flash."""
        c = auth_client("admin")
        response = c.post("/fleet/config/update", data={
            "corroboration_threshold": "-1",
        }, follow_redirects=True)
        assert response.status_code == 200
        html = response.data.decode()
        assert "invalid" in html.lower() or "error" in html.lower() or "positive" in html.lower()

    def test_update_config_empty_body(self, auth_client):
        """Submitting empty config form shows warning flash."""
        c = auth_client("admin")
        response = c.post("/fleet/config/update", data={}, follow_redirects=True)
        assert response.status_code == 200
        html = response.data.decode()
        assert "no configuration" in html.lower() or "warning" in html.lower()


# ── Pause Toggle Tests ───────────────────────────────────────────────────


class TestFleetDashboardPauseToggle:
    """Test pause toggle flow via the dashboard.

    Validates: Requirements 5, 8
    """

    def test_toggle_pause_admin(self, auth_client, app):
        """Admin can toggle propagation pause state."""
        c = auth_client("admin")
        response = c.post("/fleet/pause/toggle", follow_redirects=True)
        assert response.status_code == 200
        html = response.data.decode()
        assert "paused" in html.lower() or "resumed" in html.lower()

    def test_toggle_pause_htmx_returns_fragment(self, auth_client):
        """POST /fleet/pause/toggle with HX-Request returns a fragment."""
        c = auth_client("admin")
        response = c.post(
            "/fleet/pause/toggle",
            headers={"HX-Request": "true"},
        )
        assert response.status_code == 200
        html = response.data.decode()
        # Should be a fragment, not a full page
        assert "<!DOCTYPE" not in html
        assert "</html>" not in html

    def test_toggle_pause_twice_resumes(self, auth_client, app):
        """Toggling pause twice should resume propagation."""
        c = auth_client("admin")
        # First toggle: pause
        c.post("/fleet/pause/toggle")
        # Second toggle: resume
        response = c.post("/fleet/pause/toggle", follow_redirects=True)
        assert response.status_code == 200
        html = response.data.decode()
        assert "resumed" in html.lower()
