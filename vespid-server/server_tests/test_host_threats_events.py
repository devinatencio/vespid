"""Unit tests for the GET /admin/host-threats/events endpoint.

Tests cover:
- Basic JSON response with pagination metadata
- Hostname filtering (optional)
- Pagination defaults (page=1, per_page=200)
- pid and ppid included in each event dict
- Suppression filtering applied
- Page clamping behavior
- Empty results handling
"""

import json
from datetime import datetime, timedelta, timezone

import pytest

from app import create_app
from app.models import get_db

# ── Helpers ──────────────────────────────────────────────────────────────


def _create_app(tmp_path):
    """Create a test Flask app with in-memory SQLite."""
    db_path = str(tmp_path / "test.db")
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({
        "SECRET_KEY": "test-secret-key",
        "DATABASE_PATH": db_path,
        "DEBUG": False,
        "ALERTS_ENABLED": False,
    }))
    app = create_app(str(config_file))
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    return app


def _create_user(db):
    """Create an admin user for login."""
    from app.models import create_user
    return create_user(db, "admin", "admin", "admin")


def _login(client):
    """Log in as admin."""
    client.post("/login", data={"username": "admin", "password": "admin"})


def _insert_host_event(db, hostname, rule_name, timestamp, node_id="node-1",
                       event_type="medium", pid=1234, ppid=1):
    """Insert a host event into the database."""
    db.execute(
        "INSERT INTO host_events (hostname, timestamp, event_type, rule_name, "
        "pid, ppid, exe, command_line, uid, auid, raw_line, node_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (hostname, timestamp, event_type, rule_name,
         pid, ppid, "/usr/bin/test", "test --arg", 0, 1000, "raw log line", node_id),
    )
    db.commit()


def _recent_timestamp(minutes_ago=5):
    """Return an ISO timestamp for N minutes ago."""
    dt = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Tests: Basic functionality ───────────────────────────────────────────


class TestEventsBasic:
    """Basic events endpoint functionality."""

    def test_returns_json_with_pagination_metadata(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            _insert_host_event(db, "web-01", "sigma_whoami", _recent_timestamp(5))
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/events")
        assert resp.status_code == 200
        data = resp.get_json()

        assert "events" in data
        assert "total" in data
        assert "page" in data
        assert "total_pages" in data
        assert "has_next" in data
        assert "has_prev" in data

    def test_events_contain_pid_and_ppid(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            _insert_host_event(db, "web-01", "sigma_whoami", _recent_timestamp(5),
                               pid=4567, ppid=1234)
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/events")
        data = resp.get_json()
        assert len(data["events"]) == 1
        event = data["events"][0]
        assert "pid" in event
        assert "ppid" in event
        assert event["pid"] == 4567
        assert event["ppid"] == 1234

    def test_events_contain_expected_fields(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            _insert_host_event(db, "web-01", "sigma_whoami", _recent_timestamp(5))
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/events")
        data = resp.get_json()
        event = data["events"][0]
        expected_fields = ["id", "hostname", "timestamp", "event_type",
                          "rule_name", "pid", "ppid", "exe", "command_line",
                          "uid", "auid"]
        for field in expected_fields:
            assert field in event, f"Missing field: {field}"

    def test_empty_database_returns_empty_events(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/events")
        data = resp.get_json()
        assert data["events"] == []
        assert data["total"] == 0
        assert data["page"] == 1
        assert data["total_pages"] == 1
        assert data["has_next"] is False
        assert data["has_prev"] is False


# ── Tests: Hostname filtering ────────────────────────────────────────────


class TestEventsHostnameFilter:
    """Hostname filtering returns only matching events."""

    def test_filters_to_single_host(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            _insert_host_event(db, "web-01", "sigma_a", _recent_timestamp(5), "node-1")
            _insert_host_event(db, "web-02", "sigma_b", _recent_timestamp(4), "node-2")
            _insert_host_event(db, "web-03", "sigma_c", _recent_timestamp(3), "node-3")
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/events?hostname=web-01")
        data = resp.get_json()
        assert data["total"] == 1
        assert all(e["hostname"] == "web-01" for e in data["events"])

    def test_empty_hostname_returns_all(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            _insert_host_event(db, "web-01", "sigma_a", _recent_timestamp(5), "node-1")
            _insert_host_event(db, "web-02", "sigma_b", _recent_timestamp(4), "node-2")
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/events?hostname=")
        data = resp.get_json()
        assert data["total"] == 2

    def test_nonexistent_hostname_returns_empty(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            _insert_host_event(db, "web-01", "sigma_a", _recent_timestamp(5))
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/events?hostname=nonexistent")
        data = resp.get_json()
        assert data["total"] == 0
        assert data["events"] == []


# ── Tests: Pagination ────────────────────────────────────────────────────


class TestEventsPagination:
    """Pagination with default per_page=200."""

    def test_default_per_page_is_200(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            # Insert 250 events
            for i in range(250):
                _insert_host_event(db, "web-01", f"sigma_{i}",
                                   _recent_timestamp(i), "node-1", pid=i)
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/events")
        data = resp.get_json()
        assert data["total"] == 250
        assert data["total_pages"] == 2  # ceil(250/200) = 2
        assert len(data["events"]) <= 200
        assert data["page"] == 1
        assert data["has_next"] is True
        assert data["has_prev"] is False

    def test_page_2(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            for i in range(250):
                _insert_host_event(db, "web-01", f"sigma_{i}",
                                   _recent_timestamp(i), "node-1", pid=i)
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/events?page=2")
        data = resp.get_json()
        assert data["page"] == 2
        assert data["has_prev"] is True
        assert data["has_next"] is False

    def test_custom_per_page(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            for i in range(50):
                _insert_host_event(db, "web-01", f"sigma_{i}",
                                   _recent_timestamp(i), "node-1", pid=i)
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/events?per_page=10")
        data = resp.get_json()
        assert data["total"] == 50
        assert data["total_pages"] == 5  # ceil(50/10)
        assert len(data["events"]) <= 10

    def test_page_clamped_to_1_for_zero(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            _insert_host_event(db, "web-01", "sigma_a", _recent_timestamp(5))
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/events?page=0")
        data = resp.get_json()
        assert data["page"] == 1


# ── Tests: Suppression filtering ─────────────────────────────────────────


class TestEventsSuppression:
    """Suppression filtering is applied to events."""

    def test_suppressed_events_excluded(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)

            # Create a config profile with suppress_rules
            db.execute(
                "INSERT INTO config_profiles (name, name_lower, settings, is_active, created_by) "
                "VALUES (?, ?, ?, 1, ?)",
                ("test-profile", "test-profile",
                 json.dumps({"suppress_rules": ["sigma_noisy"]}), "admin"),
            )
            profile_id = db.execute(
                "SELECT id FROM config_profiles WHERE name = 'test-profile'"
            ).fetchone()["id"]

            # Assign profile to node-1
            db.execute(
                "INSERT INTO config_assignments (profile_id, node_id, is_active, assigned_at, assigned_by) "
                "VALUES (?, ?, 1, datetime('now'), ?)",
                (profile_id, "node-1", "admin"),
            )
            db.commit()

            # Insert events - noisy ones should be suppressed
            _insert_host_event(db, "web-01", "sigma_noisy", _recent_timestamp(5), "node-1")
            _insert_host_event(db, "web-01", "sigma_noisy", _recent_timestamp(4), "node-1")
            _insert_host_event(db, "web-01", "sigma_real", _recent_timestamp(3), "node-1")
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/events")
        data = resp.get_json()
        # Only sigma_real should remain after suppression
        rule_names = [e["rule_name"] for e in data["events"]]
        assert "sigma_noisy" not in rule_names
        assert "sigma_real" in rule_names
