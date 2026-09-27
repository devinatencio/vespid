"""Unit tests for host-threat severity-tier escalation re-alerting.

Covers the active-episode redesign: while a host's score stays above
threshold, a notification is only re-dispatched when the maximum detection
severity tier increases (or an episode first crosses the threshold).
"""

import json
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

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
        "ALERTS_ENABLED": True,
    }))
    app = create_app(str(config_file))
    app.config["TESTING"] = True
    return app


def _insert_host_event(db, rule_name, event_type, node_id="node-1", hostname="web-01",
                       minutes_ago=0):
    """Insert a host event timestamped N minutes ago (default: now)."""
    ts = (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")
    db.execute(
        "INSERT INTO host_events (hostname, timestamp, event_type, rule_name, "
        "pid, ppid, exe, command_line, uid, auid, raw_line, node_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (hostname, ts, event_type, rule_name,
         1234, 1, "/usr/bin/test", "test --arg", 0, 1000, "raw log line", node_id),
    )
    db.commit()


def _insert_profile_and_alert_config(db, threshold=4, cooldown=900):
    """Create a config profile assigned to node-1 with an alert config row."""
    db.execute(
        "INSERT INTO config_profiles (name, name_lower, settings, is_active, created_by) "
        "VALUES (?, ?, ?, 1, ?)",
        ("test-profile", "test-profile", json.dumps({"suppress_rules": []}), "admin"),
    )
    profile_id = db.execute("SELECT id FROM config_profiles WHERE name = 'test-profile'").fetchone()["id"]
    db.execute(
        "INSERT INTO config_assignments (profile_id, node_id, is_active, assigned_at, assigned_by) "
        "VALUES (?, ?, 1, datetime('now'), ?)",
        (profile_id, "node-1", "admin"),
    )
    db.execute(
        "INSERT INTO host_threat_alert_config (profile_id, threshold, cooldown_seconds, notify_channel) "
        "VALUES (?, ?, ?, ?)",
        (profile_id, threshold, cooldown,
         json.dumps({"type": "discord", "url": "https://discord.invalid/webhook"})),
    )
    db.commit()
    return profile_id


def _notifications(db):
    return db.execute(
        "SELECT id, severity_tier, resolved_at FROM host_threat_notifications "
        "WHERE hostname = 'web-01' ORDER BY id"
    ).fetchall()


class _FakeResponse:
    ok = True
    status_code = 200

    def raise_for_status(self):
        return None


def _run_scan(app, db):
    """Run the background host-threat alert scan with requests.post mocked."""
    from app.routes.host_threats import evaluate_host_threat_alerts
    with patch("requests.post", return_value=_FakeResponse()):
        evaluate_host_threat_alerts(db)


class TestSeverityEscalation:
    """Escalation re-alerting within an active episode."""

    def test_initial_alert_then_escalation(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _insert_profile_and_alert_config(db)
            _insert_host_event(db, "sigma_low", "low")

            # First crossing → one notification at tier=5
            _run_scan(app, db)
            notifs = _notifications(db)
            assert len(notifs) == 1
            assert float(notifs[0]["severity_tier"]) == 5
            assert notifs[0]["resolved_at"] is None

            # Same tier, no new events → no duplicate
            _run_scan(app, db)
            assert len(_notifications(db)) == 1

            # New high detection → escalation: previous episode resolved,
            # new notification at tier=25
            _insert_host_event(db, "sigma_high", "high")
            _run_scan(app, db)
            notifs = _notifications(db)
            assert len(notifs) == 2
            assert notifs[0]["resolved_at"] is not None
            assert float(notifs[1]["severity_tier"]) == 25
            assert notifs[1]["resolved_at"] is None
            db.close()

    def test_same_tier_new_events_do_not_re_alert(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _insert_profile_and_alert_config(db)
            _insert_host_event(db, "sigma_a", "medium")

            _run_scan(app, db)
            assert len(_notifications(db)) == 1

            # More medium detections: tier stays at 10, no escalation
            _insert_host_event(db, "sigma_b", "medium")
            _insert_host_event(db, "sigma_c", "medium")
            _run_scan(app, db)
            notifs = _notifications(db)
            assert len(notifs) == 1
            assert float(notifs[0]["severity_tier"]) == 10
            db.close()

    def test_legacy_episode_records_baseline_without_re_alert(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            profile_id = _insert_profile_and_alert_config(db)
            _insert_host_event(db, "sigma_low", "low")

            # Pre-existing unresolved notification with no tier (pre-migration)
            db.execute(
                "INSERT INTO host_threat_notifications "
                "(hostname, profile_id, channel_type, channel_target, score, threshold, status) "
                "VALUES (?, ?, 'discord', 'https://discord.invalid/webhook', 5, 4, 'sent')",
                ("web-01", profile_id),
            )
            db.commit()

            # New high detection on a legacy episode: record baseline, no re-alert
            _insert_host_event(db, "sigma_high", "high")
            _run_scan(app, db)
            notifs = _notifications(db)
            assert len(notifs) == 1
            assert float(notifs[0]["severity_tier"]) == 25
            assert notifs[0]["resolved_at"] is None
            db.close()

    def test_episode_resolves_below_threshold(self, tmp_path):
        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _insert_profile_and_alert_config(db)
            _insert_host_event(db, "sigma_high", "high")

            _run_scan(app, db)
            assert len(_notifications(db)) == 1

            # A drop below threshold resolves the episode (e.g. after decay)
            from app.routes.host_threats import _dispatch_host_alert_notification
            with patch("requests.post", return_value=_FakeResponse()):
                _dispatch_host_alert_notification(
                    db, "web-01", "node-1", score=3.0, profile_id=1,
                    max_severity_weight=25,
                )
            notifs = _notifications(db)
            assert len(notifs) == 1
            assert notifs[0]["resolved_at"] is not None
            db.close()


class TestMaxSeverityTracking:
    """compute_host_threat_active reports max_severity_weight per host."""

    def test_max_severity_weight_tracked(self, tmp_path):
        from app.routes.host_threats import compute_host_threat_active

        app = _create_app(tmp_path)
        with app.app_context():
            db = get_db(app.config["DATABASE_PATH"])
            _insert_host_event(db, "sigma_low", "low", minutes_ago=5)
            _insert_host_event(db, "sigma_crit", "critical", minutes_ago=5)

            now = datetime.now(timezone.utc)
            since = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
            active = compute_host_threat_active(db, since, now.timestamp(), 28800, 100)

            assert len(active) == 1
            assert active[0]["max_severity_weight"] == 50
            db.close()
