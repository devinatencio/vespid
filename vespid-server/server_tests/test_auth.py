"""Unit tests for authentication flows.

Tests login success, login failure (generic message), logout,
and session creation/destruction.

Requirements: 2.2, 2.3, 2.4
"""

import json

import pytest

from app import create_app
from app.models import create_user, get_db, search_audit_log


@pytest.fixture()
def app(tmp_path):
    """Create a Flask app with a test database and a pre-created user."""
    db_path = str(tmp_path / "test_auth.db")
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({
        "SECRET_KEY": "test-secret-key",
        "DATABASE_PATH": db_path,
    }))
    app = create_app(str(config_file))
    app.config["TESTING"] = True

    # Create test users
    db = get_db(db_path)
    try:
        create_user(db, "admin_user", "admin_pass", "admin")
        create_user(db, "viewer_user", "viewer_pass", "viewer")
        create_user(db, "analyst_user", "analyst_pass", "analyst")
    finally:
        db.close()

    return app


@pytest.fixture()
def client(app):
    """Return a Flask test client."""
    return app.test_client()


class TestLoginSuccess:
    """Test successful login flow. Validates: Requirement 2.2"""

    def test_valid_credentials_redirect_to_dashboard(self, client):
        """POST /login with valid credentials should redirect to dashboard."""
        response = client.post("/login", data={
            "username": "admin_user",
            "password": "admin_pass",
        })
        assert response.status_code == 302
        assert "/" in response.headers["Location"]

    def test_session_created_after_login(self, client):
        """After login, accessing a protected page should succeed."""
        client.post("/login", data={
            "username": "admin_user",
            "password": "admin_pass",
        })
        response = client.get("/")
        assert response.status_code == 200

    def test_login_records_audit_log(self, app, client):
        """Successful login should create an audit log entry."""
        client.post("/login", data={
            "username": "admin_user",
            "password": "admin_pass",
        })
        db = get_db(app.config["DATABASE_PATH"])
        try:
            entries, _ = search_audit_log(db, action_type="login")
            assert len(entries) >= 1
            assert entries[0]["actor"] == "admin_user"
        finally:
            db.close()


class TestLoginFailure:
    """Test failed login flow. Validates: Requirement 2.3"""

    def test_wrong_password_returns_401(self, client):
        """POST /login with wrong password should return 401."""
        response = client.post("/login", data={
            "username": "admin_user",
            "password": "wrong_password",
        })
        assert response.status_code == 401

    def test_wrong_username_returns_401(self, client):
        """POST /login with non-existent username should return 401."""
        response = client.post("/login", data={
            "username": "nonexistent_user",
            "password": "some_password",
        })
        assert response.status_code == 401

    def test_generic_error_message_on_wrong_password(self, client):
        """Failed login should show generic message, not reveal which field was wrong."""
        response = client.post("/login", data={
            "username": "admin_user",
            "password": "wrong_password",
        })
        html = response.data.decode()
        assert "Invalid username or password" in html

    def test_generic_error_message_on_wrong_username(self, client):
        """Failed login with bad username should show same generic message."""
        response = client.post("/login", data={
            "username": "nonexistent_user",
            "password": "some_password",
        })
        html = response.data.decode()
        assert "Invalid username or password" in html

    def test_failed_login_records_audit_log(self, app, client):
        """Failed login should create an audit log entry with login_failed action."""
        client.post("/login", data={
            "username": "admin_user",
            "password": "wrong_password",
        })
        db = get_db(app.config["DATABASE_PATH"])
        try:
            entries, _ = search_audit_log(db, action_type="login_failed")
            assert len(entries) >= 1
            assert entries[0]["actor"] == "admin_user"
        finally:
            db.close()

    def test_no_session_after_failed_login(self, client):
        """After failed login, accessing a protected page should redirect."""
        client.post("/login", data={
            "username": "admin_user",
            "password": "wrong_password",
        })
        response = client.get("/")
        assert response.status_code == 302
        assert "/login" in response.headers["Location"]


class TestLogout:
    """Test logout flow. Validates: Requirement 2.4"""

    def test_logout_redirects_to_login(self, client):
        """POST /logout should redirect to login page."""
        # Login first
        client.post("/login", data={
            "username": "admin_user",
            "password": "admin_pass",
        })
        response = client.post("/logout")
        assert response.status_code == 302
        assert "/login" in response.headers["Location"]

    def test_session_destroyed_after_logout(self, client):
        """After logout, accessing a protected page should redirect to login."""
        # Login
        client.post("/login", data={
            "username": "admin_user",
            "password": "admin_pass",
        })
        # Verify session works
        response = client.get("/")
        assert response.status_code == 200

        # Logout
        client.post("/logout")

        # Session should be destroyed
        response = client.get("/")
        assert response.status_code == 302
        assert "/login" in response.headers["Location"]

    def test_logout_records_audit_log(self, app, client):
        """Logout should create an audit log entry."""
        client.post("/login", data={
            "username": "admin_user",
            "password": "admin_pass",
        })
        client.post("/logout")
        db = get_db(app.config["DATABASE_PATH"])
        try:
            entries, _ = search_audit_log(db, action_type="logout")
            assert len(entries) >= 1
            assert entries[0]["actor"] == "admin_user"
        finally:
            db.close()


class TestLoginPage:
    """Test the login page rendering."""

    def test_get_login_returns_200(self, client):
        """GET /login should return the login form."""
        response = client.get("/login")
        assert response.status_code == 200

    def test_login_page_has_form(self, client):
        """Login page should contain a form with username and password fields."""
        response = client.get("/login")
        html = response.data.decode()
        assert 'name="username"' in html
        assert 'name="password"' in html

    def test_authenticated_user_redirected_from_login(self, client):
        """An already-authenticated user visiting /login should be redirected."""
        client.post("/login", data={
            "username": "admin_user",
            "password": "admin_pass",
        })
        response = client.get("/login")
        assert response.status_code == 302
