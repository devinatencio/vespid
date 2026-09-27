"""Unit tests for the /admin/host-threats/score-history endpoint.

Tests cover:
- Empty hostname returns a 200 empty series (dashboard "select a host" state)
- Default window is 24h with 288 sample points
- The `hours` query param is echoed back and clamped to 1..168
- Events older than the window are excluded; widening the window includes them
- Response shape (labels, scores, threshold, hostname, hours)
"""

import json
from datetime import datetime, timedelta, timezone

from app import create_app
from app.models import get_db


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
    from app.models import create_user
    return create_user(db, "admin", "admin", "admin")


def _login(client):
    client.post("/login", data={"username": "admin", "password": "admin"})


def _insert_host_event(db, hostname, rule_name, timestamp, node_id="node-1", event_type="medium"):
    db.execute(
        "INSERT INTO host_events (hostname, timestamp, event_type, rule_name, "
        "pid, ppid, exe, command_line, uid, auid, raw_line, node_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (hostname, timestamp, event_type, rule_name,
         1234, 1, "/usr/bin/test", "test --arg", 0, 1000, "raw log line", node_id),
    )
    db.commit()


def _ts(hours_ago):
    """Return an ISO UTC timestamp for N hours ago."""
    dt = datetime.now(timezone.utc) - timedelta(hours=hours_ago)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class TestScoreHistoryBasics:
    """Basic endpoint behavior."""

    def test_empty_hostname_returns_empty_series(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            _insert_host_event(db, "web-01", "sigma_whoami", _ts(1))
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/score-history")
        assert resp.status_code == 200  # was 400 before the fix
        data = resp.get_json()
        assert data["labels"] == []
        assert data["scores"] == []
        assert data["hostname"] == ""
        assert data["hours"] == 24

    def test_default_window_is_24h_288_points(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            _insert_host_event(db, "web-01", "sigma_whoami", _ts(1))
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/score-history?hostname=web-01")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data["labels"]) == 288
        assert len(data["scores"]) == 288
        assert data["hours"] == 24
        assert data["hostname"] == "web-01"
        assert "threshold" in data

    def test_hours_param_echoed(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            _insert_host_event(db, "web-01", "sigma_whoami", _ts(1))
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/score-history?hostname=web-01&hours=72")
        data = resp.get_json()
        assert data["hours"] == 72
        assert len(data["labels"]) == 288

    def test_hours_clamped_to_168(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            _insert_host_event(db, "web-01", "sigma_whoami", _ts(1))
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/score-history?hostname=web-01&hours=999")
        data = resp.get_json()
        assert data["hours"] == 168


class TestScoreHistoryWindow:
    """Window controls which historical events are scored."""

    def test_event_older_than_window_excluded(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            # Event 30 hours ago: inside a 72h window, outside a 24h window
            _insert_host_event(db, "web-01", "sigma_whoami", _ts(30))
            db.close()

        client = app.test_client()
        _login(client)

        resp = client.get("/admin/host-threats/score-history?hostname=web-01&hours=24")
        data = resp.get_json()
        assert max(data["scores"]) == 0  # excluded from 24h window

        resp = client.get("/admin/host-threats/score-history?hostname=web-01&hours=72")
        data = resp.get_json()
        assert max(data["scores"]) > 0  # included in 72h window

    def test_recent_event_scores_positive(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            # Medium weight (10) event 10 minutes ago
            _insert_host_event(db, "web-01", "sigma_whoami", _ts(10.0 / 60.0))
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/score-history?hostname=web-01&hours=24")
        data = resp.get_json()
        # Event decays from weight 10 across the window; peak near the end
        assert max(data["scores"]) > 0
        assert max(data["scores"]) <= 10
        # Last sample is ~5 min before now, so the tail should still be > 0
        assert data["scores"][-1] > 0

    def test_score_rise_in_final_interval_reflected_at_tail(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _create_user(db)
            # Event 2 minutes ago: inside the final 5-min interval of a 24h
            # window. The last sample must land on `now` so the raise is shown.
            _insert_host_event(db, "web-01", "sigma_whoami", _ts(2.0 / 60.0))
            db.close()

        client = app.test_client()
        _login(client)
        resp = client.get("/admin/host-threats/score-history?hostname=web-01&hours=24")
        assert resp.status_code == 200
        data = resp.get_json()
        # The raise must appear in the final sample, not be dropped because the
        # last sample point lagged an interval behind `now`.
        assert data["scores"][-1] > 0
        assert data["scores"][-1] > data["scores"][-2]
