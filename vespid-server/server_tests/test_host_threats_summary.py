"""Unit tests for the enhanced host_summary_cards endpoint.

Tests cover:
- Hostname filtering (single host)
- Pagination (>50 hosts triggers pagination)
- Mode status from nodes.last_host_info
- Learning remaining hours computation
- Suppression filtering integration
- Pagination metadata (total, page, total_pages, has_next, has_prev)
- Sort order (effective_score descending)
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


def _insert_host_event(db, hostname, rule_name, timestamp, node_id="node-1", event_type="medium"):
    """Insert a host event into the database."""
    db.execute(
        "INSERT INTO host_events (hostname, timestamp, event_type, rule_name, "
        "pid, ppid, exe, command_line, uid, auid, raw_line, node_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (hostname, timestamp, event_type, rule_name,
         1234, 1, "/usr/bin/test", "test --arg", 0, 1000, "raw log line", node_id),
    )
    db.commit()


def _insert_node(db, node_id, host_info=None):
    """Insert a node record with last_host_info."""
    if host_info is None:
        host_info = {}
    db.execute(
        "INSERT OR REPLACE INTO nodes (node_id, last_host_info) VALUES (?, ?)",
        (node_id, json.dumps(host_info)),
    )
    db.commit()


def _recent_timestamp(minutes_ago=5):
    """Return an ISO timestamp for N minutes ago."""
    dt = datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


# ── Tests: Basic functionality ───────────────────────────────────────────


class TestSummaryBasic:
    """Basic summary endpoint functionality."""

    def test_returns_json_with_pagination_metadata(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            _insert_host_event(db, "web-01", "sigma_whoami", _recent_timestamp(5))
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/summary")
        assert resp.status_code == 200
        data = resp.get_json()

        # Response should have pagination metadata
        assert "cards" in data
        assert "total" in data
        assert "page" in data
        assert "total_pages" in data
        assert "has_next" in data
        assert "has_prev" in data

    def test_cards_contain_mode_field(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            _insert_node(db, "node-1", {"auditd": {"mode": "alerting"}})
            _insert_host_event(db, "web-01", "sigma_whoami", _recent_timestamp(5), "node-1")
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/summary")
        data = resp.get_json()
        assert len(data["cards"]) == 1
        card = data["cards"][0]
        assert "mode" in card
        assert card["mode"] == "alerting"
        assert "learning_remaining_hours" in card
        assert card["learning_remaining_hours"] is None

    def test_cards_contain_learning_remaining_hours(self, tmp_path):
        app = _create_app(tmp_path)
        now_epoch = datetime.now(timezone.utc).timestamp()
        # Started learning 10 hours ago, duration is 24 hours
        learning_started = now_epoch - (10 * 3600)

        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            _insert_node(db, "node-1", {
                "auditd": {
                    "mode": "learning",
                    "learning_started_at": learning_started,
                    "learning_duration_hours": 24,
                }
            })
            _insert_host_event(db, "web-01", "sigma_whoami", _recent_timestamp(5), "node-1")
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/summary")
        data = resp.get_json()
        card = data["cards"][0]
        assert card["mode"] == "learning"
        # 24 - 10 = 14 hours remaining
        assert card["learning_remaining_hours"] == 14

    def test_unknown_mode_when_no_node(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            # No node record for node-1
            _insert_host_event(db, "web-01", "sigma_whoami", _recent_timestamp(5), "node-1")
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/summary")
        data = resp.get_json()
        card = data["cards"][0]
        assert card["mode"] == "unknown"


# ── Tests: Hostname filtering ────────────────────────────────────────────


class TestHostnameFilter:
    """Hostname filtering returns only matching host."""

    def test_filters_to_single_host(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            _insert_host_event(db, "web-01", "sigma_whoami", _recent_timestamp(5), "node-1")
            _insert_host_event(db, "web-02", "sigma_whoami", _recent_timestamp(5), "node-2")
            _insert_host_event(db, "web-03", "sigma_whoami", _recent_timestamp(5), "node-3")
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/summary?hostname=web-01")
        data = resp.get_json()
        assert data["total"] == 1
        assert len(data["cards"]) == 1
        assert data["cards"][0]["hostname"] == "web-01"

    def test_empty_hostname_returns_all(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            _insert_host_event(db, "web-01", "sigma_whoami", _recent_timestamp(5), "node-1")
            _insert_host_event(db, "web-02", "sigma_whoami", _recent_timestamp(5), "node-2")
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/summary?hostname=")
        data = resp.get_json()
        assert data["total"] == 2

    def test_nonexistent_hostname_returns_empty(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            _insert_host_event(db, "web-01", "sigma_whoami", _recent_timestamp(5), "node-1")
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/summary?hostname=nonexistent")
        data = resp.get_json()
        assert data["total"] == 0
        assert data["cards"] == []


# ── Tests: Pagination ────────────────────────────────────────────────────


class TestPagination:
    """Pagination when >50 hosts have detections."""

    def test_no_pagination_under_50_hosts(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            # Insert 10 hosts
            for i in range(10):
                _insert_host_event(db, f"host-{i:03d}", "sigma_whoami",
                                   _recent_timestamp(5), f"node-{i}")
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/summary")
        data = resp.get_json()
        assert data["total"] == 10
        assert data["total_pages"] == 1
        assert len(data["cards"]) == 10
        assert data["has_next"] is False
        assert data["has_prev"] is False

    def test_pagination_over_50_hosts(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            # Insert 60 hosts
            for i in range(60):
                _insert_host_event(db, f"host-{i:03d}", "sigma_whoami",
                                   _recent_timestamp(5), f"node-{i}")
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/summary?page=1")
        data = resp.get_json()
        assert data["total"] == 60
        assert data["total_pages"] == 2  # ceil(60/30) = 2
        assert len(data["cards"]) == 30
        assert data["page"] == 1
        assert data["has_next"] is True
        assert data["has_prev"] is False

    def test_pagination_page_2(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            # Insert 60 hosts
            for i in range(60):
                _insert_host_event(db, f"host-{i:03d}", "sigma_whoami",
                                   _recent_timestamp(5), f"node-{i}")
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/summary?page=2")
        data = resp.get_json()
        assert data["total"] == 60
        assert data["page"] == 2
        assert len(data["cards"]) == 30
        assert data["has_next"] is False
        assert data["has_prev"] is True

    def test_page_clamped_to_max(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            for i in range(60):
                _insert_host_event(db, f"host-{i:03d}", "sigma_whoami",
                                   _recent_timestamp(5), f"node-{i}")
            db.close()

        client = app.test_client()
        _login(client)
        # Page 100 should be clamped to max page
        resp = client.get("/admin/host-threats/summary?page=100")
        data = resp.get_json()
        assert data["page"] == 2  # clamped to total_pages

    def test_page_clamped_to_1_for_zero(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            for i in range(60):
                _insert_host_event(db, f"host-{i:03d}", "sigma_whoami",
                                   _recent_timestamp(5), f"node-{i}")
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/summary?page=0")
        data = resp.get_json()
        assert data["page"] == 1

    def test_custom_per_page(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            for i in range(60):
                _insert_host_event(db, f"host-{i:03d}", "sigma_whoami",
                                   _recent_timestamp(5), f"node-{i}")
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/summary?per_page=20")
        data = resp.get_json()
        assert data["total"] == 60
        assert data["total_pages"] == 3  # ceil(60/20) = 3
        assert len(data["cards"]) == 20


# ── Tests: Sort order ────────────────────────────────────────────────────


class TestSortOrder:
    """Cards sorted by effective_score descending."""

    def test_sorted_by_score_descending(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            # Insert events with different severities to produce different scores
            _insert_host_event(db, "low-host", "sigma_a", _recent_timestamp(5),
                               "node-1", event_type="low")
            _insert_host_event(db, "high-host", "sigma_b", _recent_timestamp(5),
                               "node-2", event_type="critical")
            _insert_host_event(db, "mid-host", "sigma_c", _recent_timestamp(5),
                               "node-3", event_type="medium")
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/summary")
        data = resp.get_json()
        scores = [c["effective_score"] for c in data["cards"]]
        assert scores == sorted(scores, reverse=True)


# ── Tests: Suppression integration ──────────────────────────────────────


class TestSuppressionIntegration:
    """Suppression filtering is applied to events before scoring."""

    def test_suppressed_events_excluded_from_cards(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            _insert_node(db, "node-1", {})

            # Create a config profile with suppress_rules
            db.execute(
                "INSERT INTO config_profiles (name, name_lower, settings, is_active, created_by) "
                "VALUES (?, ?, ?, 1, ?)",
                ("test-profile", "test-profile", json.dumps({"suppress_rules": ["sigma_noisy"]}), "admin"),
            )
            profile_id = db.execute("SELECT id FROM config_profiles WHERE name = 'test-profile'").fetchone()["id"]

            # Assign profile to node-1
            db.execute(
                "INSERT INTO config_assignments (profile_id, node_id, is_active, assigned_at, assigned_by) "
                "VALUES (?, ?, 1, datetime('now'), ?)",
                (profile_id, "node-1", "admin"),
            )
            db.commit()

            # Insert events - one noisy (should be suppressed), one real
            _insert_host_event(db, "web-01", "sigma_noisy", _recent_timestamp(5), "node-1")
            _insert_host_event(db, "web-01", "sigma_noisy", _recent_timestamp(4), "node-1")
            _insert_host_event(db, "web-01", "sigma_real", _recent_timestamp(3), "node-1")
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/summary")
        data = resp.get_json()
        card = data["cards"][0]
        # Only 1 event should remain after suppression
        assert card["event_count"] == 1
        top_rule_names = [r["name"] if isinstance(r, dict) else r for r in card["top_rules"]]
        assert "sigma_noisy" not in top_rule_names
        assert "sigma_real" in top_rule_names
