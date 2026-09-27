"""Tests for the Alert Manager subsystem.

Covers: schema creation, model CRUD, eval loop helpers, API endpoints,
silence matching, and eval locking.
"""

import json
import time

import pytest

from app.models import (
    acquire_eval_lock,
    acknowledge_alert_event,
    can_manage_rule,
    create_alert_event,
    create_alert_rule,
    create_notification_channel,
    create_silence,
    delete_alert_rule,
    delete_notification_channel,
    delete_silence,
    get_active_alerts,
    get_alert_event_count,
    get_alert_history,
    get_alert_rule,
    get_alert_rules,
    get_channels_for_rule,
    get_eval_lock_status,
    get_notification_channels,
    get_silences,
    is_silenced,
    release_eval_lock,
    resolve_alert_event,
    set_rule_channels,
    update_alert_rule,
    update_notification_channel,
)


# ── Fixtures ───────────────────────────────────────────────────────────────


@pytest.fixture()
def alert_admin_user(app, db):
    """Create an admin user and return the user_id."""
    from app.models import create_user
    return create_user(db, "alert_admin", "password", "admin")


@pytest.fixture()
def alert_rule(db, alert_admin_user):
    """Create a PromQL alert rule."""
    return create_alert_rule(
        db,
        user_id=None,
        name="High CPU",
        query='100 - (avg(rate(cpu_idle[2m])) * 100)',
        operator=">",
        threshold=90.0,
        severity="critical",
        for_duration=60,
        cooldown_secs=300,
        interval_secs=60,
    )


@pytest.fixture()
def check_rule(db, alert_admin_user):
    """Create a check-based alert rule."""
    return create_alert_rule(
        db,
        user_id=None,
        name="Disk Check",
        check_name="disk_root",
        operator=">=",
        threshold=2.0,
        severity="warning",
        interval_secs=120,
    )


@pytest.fixture()
def notification_channel(db):
    """Create a Slack notification channel."""
    return create_notification_channel(
        db,
        name="Ops Slack",
        channel_type="slack",
        config={"webhook_url": "https://hooks.slack.com/test", "channel": "#alerts"},
    )


# ── Schema Tests ─────────────────────────────────────────────────────────


class TestAlertSchema:
    def test_alert_tables_exist(self, db):
        """All alert tables are created by init_db."""
        cursor = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name LIKE 'alert_%'"
        )
        tables = {r[0] for r in cursor.fetchall()}
        assert "alert_rules" in tables
        assert "alert_events" in tables
        assert "alert_silences" in tables
        assert "alert_eval_lock" in tables

    def test_notification_tables_exist(self, db):
        """Notification tables are created."""
        cursor = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND "
            "(name LIKE 'notification_%' OR name LIKE 'rule_notification_%')"
        )
        tables = {r[0] for r in cursor.fetchall()}
        assert "notification_channels" in tables
        assert "rule_notification_channels" in tables


# ── Rule CRUD Tests ────────────────────────────────────────────────────────


class TestAlertRules:
    def test_create_promql_rule(self, db, alert_rule):
        assert alert_rule["name"] == "High CPU"
        assert alert_rule["query"] == '100 - (avg(rate(cpu_idle[2m])) * 100)'
        assert alert_rule["check_name"] is None
        assert alert_rule["operator"] == ">"
        assert alert_rule["threshold"] == 90.0
        assert alert_rule["severity"] == "critical"
        assert alert_rule["for_duration"] == 60
        assert alert_rule["cooldown_secs"] == 300
        assert alert_rule["enabled"] == 1

    def test_create_check_rule(self, db, check_rule):
        assert check_rule["check_name"] == "disk_root"
        assert check_rule["query"] is None

    def test_get_alert_rule(self, db, alert_rule):
        fetched = get_alert_rule(db, alert_rule["id"])
        assert fetched is not None
        assert fetched["name"] == "High CPU"

    def test_get_alert_rule_missing(self, db):
        assert get_alert_rule(db, 99999) is None

    def test_get_alert_rules(self, db, alert_rule, check_rule):
        rules = get_alert_rules(db, admin_view=True)
        assert len(rules) == 2

    def test_get_alert_rules_enabled_filter(self, db, alert_rule):
        rules = get_alert_rules(db, enabled=True, admin_view=True)
        assert len(rules) == 1
        rules = get_alert_rules(db, enabled=False, admin_view=True)
        assert len(rules) == 0

    def test_update_alert_rule(self, db, alert_rule):
        updated = update_alert_rule(db, alert_rule["id"], threshold=95.0, severity="warning")
        assert updated["threshold"] == 95.0
        assert updated["severity"] == "warning"

    def test_delete_alert_rule(self, db, alert_rule):
        ok = delete_alert_rule(db, alert_rule["id"])
        assert ok is True
        assert get_alert_rule(db, alert_rule["id"]) is None

    def test_delete_resolves_and_removes_firing_events(self, db, alert_rule):
        event = create_alert_event(db, alert_rule["id"], {"host": "web-1"}, 95.0)
        delete_alert_rule(db, alert_rule["id"])
        # Events are resolved then deleted along with the rule
        rows = db.execute(
            "SELECT state FROM alert_events WHERE id = ?", (event["id"],)
        ).fetchall()
        assert len(rows) == 0


# ── Event Tests ────────────────────────────────────────────────────────────


class TestAlertEvents:
    def test_create_event(self, db, alert_rule):
        event = create_alert_event(db, alert_rule["id"], {"host": "web-1"}, 95.0)
        assert event["state"] == "firing"
        assert event["value"] == 95.0
        assert json.loads(event["labels"]) == {"host": "web-1"}

    def test_get_active_alerts(self, db, alert_rule):
        create_alert_event(db, alert_rule["id"], {"host": "web-1"}, 95.0)
        active = get_active_alerts(db, admin_view=True)
        assert len(active) == 1
        assert active[0]["rule_name"] == "High CPU"

    def test_get_active_alerts_empty(self, db):
        active = get_active_alerts(db, admin_view=True)
        assert active == []

    def test_get_alert_event_count(self, db, alert_rule):
        create_alert_event(db, alert_rule["id"], {"host": "web-1"}, 95.0)
        assert get_alert_event_count(db) == 1
        assert get_alert_event_count(db, severity="critical") == 1
        assert get_alert_event_count(db, severity="warning") == 0

    def test_resolve_alert_event(self, db, alert_rule):
        event = create_alert_event(db, alert_rule["id"], {"host": "web-1"}, 95.0)
        ok = resolve_alert_event(db, event["id"])
        assert ok is True
        row = db.execute("SELECT state FROM alert_events WHERE id = ?", (event["id"],)).fetchone()
        assert row[0] == "resolved"

    def test_acknowledge_alert_event(self, db, alert_rule, alert_admin_user):
        event = create_alert_event(db, alert_rule["id"], {"host": "web-1"}, 95.0)
        ok = acknowledge_alert_event(db, event["id"], alert_admin_user)
        assert ok is True
        row = db.execute("SELECT state FROM alert_events WHERE id = ?", (event["id"],)).fetchone()
        assert row[0] == "acknowledged"

    def test_get_alert_history(self, db, alert_rule):
        event = create_alert_event(db, alert_rule["id"], {"host": "web-1"}, 95.0)
        resolve_alert_event(db, event["id"])
        history = get_alert_history(db, admin_view=True)
        assert history["total"] == 1
        assert len(history["events"]) == 1


# ── Notification Channel Tests ─────────────────────────────────────────────


class TestNotificationChannels:
    def test_create_channel(self, db, notification_channel):
        assert notification_channel["name"] == "Ops Slack"
        assert notification_channel["type"] == "slack"
        assert json.loads(notification_channel["config"])["webhook_url"] == "https://hooks.slack.com/test"

    def test_get_channels(self, db, notification_channel):
        channels = get_notification_channels(db)
        assert len(channels) == 1

    def test_update_channel(self, db, notification_channel):
        updated = update_notification_channel(db, notification_channel["id"], name="Updated Slack")
        assert updated["name"] == "Updated Slack"

    def test_delete_channel(self, db, notification_channel):
        ok = delete_notification_channel(db, notification_channel["id"])
        assert ok is True
        assert get_notification_channels(db) == []

    def test_rule_channel_association(self, db, alert_rule, notification_channel):
        set_rule_channels(db, alert_rule["id"], [notification_channel["id"]])
        channels = get_channels_for_rule(db, alert_rule["id"], default_to_all=False)
        assert len(channels) == 1
        assert channels[0]["name"] == "Ops Slack"

    def test_rule_channel_default_to_all(self, db, alert_rule, notification_channel):
        # No explicit association — should return all enabled channels
        channels = get_channels_for_rule(db, alert_rule["id"], default_to_all=True)
        assert len(channels) == 1


# ── Silence Tests ──────────────────────────────────────────────────────────


class TestSilences:
    def test_create_silence(self, db, alert_admin_user):
        silence = create_silence(
            db,
            matchers=[{"label": "host", "op": "=", "value": "web-1"}],
            rule_id=None,
            starts_at="2024-01-01T00:00:00Z",
            ends_at="2027-12-31T23:59:59Z",
            reason="Deploy window",
            created_by=alert_admin_user,
        )
        assert silence["reason"] == "Deploy window"

    def test_is_silenced_exact_match(self, db, alert_admin_user):
        create_silence(
            db,
            matchers=[{"label": "host", "op": "=", "value": "web-1"}],
            rule_id=None,
            starts_at="2024-01-01T00:00:00Z",
            ends_at="2027-12-31T23:59:59Z",
            reason="Deploy",
            created_by=alert_admin_user,
        )
        assert is_silenced(db, 999, {"host": "web-1"}) is True
        assert is_silenced(db, 999, {"host": "web-2"}) is False

    def test_is_silenced_regex_match(self, db, alert_admin_user):
        create_silence(
            db,
            matchers=[{"label": "host", "op": "=~", "value": "web-.*"}],
            rule_id=None,
            starts_at="2024-01-01T00:00:00Z",
            ends_at="2027-12-31T23:59:59Z",
            reason="Deploy",
            created_by=alert_admin_user,
        )
        assert is_silenced(db, 999, {"host": "web-1"}) is True
        assert is_silenced(db, 999, {"host": "db-1"}) is False

    def test_is_silenced_rule_specific(self, db, alert_rule, alert_admin_user):
        create_silence(
            db,
            matchers=[{"label": "host", "op": "=", "value": "web-1"}],
            rule_id=alert_rule["id"],
            starts_at="2024-01-01T00:00:00Z",
            ends_at="2027-12-31T23:59:59Z",
            reason="Deploy",
            created_by=alert_admin_user,
        )
        assert is_silenced(db, alert_rule["id"], {"host": "web-1"}) is True
        assert is_silenced(db, 999, {"host": "web-1"}) is False

    def test_is_silenced_expired(self, db, alert_admin_user):
        create_silence(
            db,
            matchers=[{"label": "host", "op": "=", "value": "web-1"}],
            rule_id=None,
            starts_at="2020-01-01T00:00:00Z",
            ends_at="2020-01-02T00:00:00Z",
            reason="Old deploy",
            created_by=alert_admin_user,
        )
        assert is_silenced(db, 999, {"host": "web-1"}) is False

    def test_get_silences(self, db, alert_admin_user):
        create_silence(
            db,
            matchers=[{"label": "host", "op": "=", "value": "web-1"}],
            rule_id=None,
            starts_at="2024-01-01T00:00:00Z",
            ends_at="2027-12-31T23:59:59Z",
            reason="Deploy",
            created_by=alert_admin_user,
        )
        active = get_silences(db, include_expired=False)
        assert len(active) == 1
        all_silences = get_silences(db, include_expired=True)
        assert len(all_silences) == 1

    def test_delete_silence(self, db, alert_admin_user):
        silence = create_silence(
            db,
            matchers=[{"label": "host", "op": "=", "value": "web-1"}],
            rule_id=None,
            starts_at="2024-01-01T00:00:00Z",
            ends_at="2027-12-31T23:59:59Z",
            reason="Deploy",
            created_by=alert_admin_user,
        )
        ok = delete_silence(db, silence["id"])
        assert ok is True
        assert get_silences(db, include_expired=True) == []


# ── Eval Lock Tests ────────────────────────────────────────────────────────


class TestEvalLock:
    def test_acquire_and_release(self, db):
        ok = acquire_eval_lock(db, "worker-1", ttl_secs=60)
        assert ok is True
        status = get_eval_lock_status(db)
        assert status["locked_by"] == "worker-1"

        ok = release_eval_lock(db, "worker-1")
        assert ok is True
        status = get_eval_lock_status(db)
        assert status["locked_by"] is None

    def test_second_worker_blocked(self, db):
        acquire_eval_lock(db, "worker-1", ttl_secs=60)
        ok = acquire_eval_lock(db, "worker-2", ttl_secs=60)
        assert ok is False
        release_eval_lock(db, "worker-1")

    def test_same_worker_reacquire(self, db):
        acquire_eval_lock(db, "worker-1", ttl_secs=60)
        ok = acquire_eval_lock(db, "worker-1", ttl_secs=60)
        assert ok is True
        release_eval_lock(db, "worker-1")

    def test_expired_lock_available(self, db):
        acquire_eval_lock(db, "worker-1", ttl_secs=1)
        time.sleep(2)
        ok = acquire_eval_lock(db, "worker-2", ttl_secs=60)
        assert ok is True
        release_eval_lock(db, "worker-2")


# ── Authorization Tests ────────────────────────────────────────────────────


class TestCanManageRule:
    class FakeUser:
        def __init__(self, id, role, authenticated=True):
            self.id = id
            self.role = role
            self._authenticated = authenticated

        @property
        def is_authenticated(self):
            return self._authenticated

    def test_admin_can_manage_any(self):
        admin = self.FakeUser(1, "admin")
        rule = {"user_id": 2}
        assert can_manage_rule(rule, admin) is True

    def test_user_can_manage_own(self):
        user = self.FakeUser(2, "viewer")
        rule = {"user_id": 2}
        assert can_manage_rule(rule, user) is True

    def test_user_cannot_manage_others(self):
        user = self.FakeUser(2, "viewer")
        rule = {"user_id": 3}
        assert can_manage_rule(rule, user) is False

    def test_anonymous_cannot_manage(self):
        anon = self.FakeUser(0, "viewer", authenticated=False)
        rule = {"user_id": None}
        assert can_manage_rule(rule, anon) is False


# ── API Tests ──────────────────────────────────────────────────────────────


class TestAlertsAPI:
    def test_list_rules(self, admin_client, db, alert_rule):
        resp = admin_client.get("/alerts/api/rules")
        assert resp.status_code == 200
        data = resp.get_json()
        assert len(data["rules"]) == 1
        assert data["rules"][0]["name"] == "High CPU"

    def test_create_rule(self, admin_client):
        payload = {
            "name": "Memory Alert",
            "query": "memory_used_percent > 90",
            "operator": ">",
            "threshold": 90,
            "severity": "critical",
        }
        resp = admin_client.post("/alerts/api/rules", json=payload)
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["rule"]["name"] == "Memory Alert"

    def test_create_rule_missing_fields(self, admin_client):
        resp = admin_client.post("/alerts/api/rules", json={"name": "Bad"})
        assert resp.status_code == 400

    def test_update_rule(self, admin_client, db, alert_rule):
        resp = admin_client.put(f"/alerts/api/rules/{alert_rule['id']}", json={"threshold": 95})
        assert resp.status_code == 200
        assert resp.get_json()["rule"]["threshold"] == 95

    def test_delete_rule(self, admin_client, db, alert_rule):
        resp = admin_client.delete(f"/alerts/api/rules/{alert_rule['id']}")
        assert resp.status_code == 200

    def test_list_active_alerts(self, admin_client, db, alert_rule):
        create_alert_event(db, alert_rule["id"], {"host": "web-1"}, 95.0)
        resp = admin_client.get("/alerts/api/active")
        assert resp.status_code == 200
        assert len(resp.get_json()["alerts"]) == 1

    def test_active_count(self, admin_client, db, alert_rule):
        create_alert_event(db, alert_rule["id"], {"host": "web-1"}, 95.0)
        resp = admin_client.get("/alerts/api/active/count")
        assert resp.status_code == 200
        assert resp.get_json()["count"] == 1

    def test_ack_event(self, admin_client, db, alert_rule, alert_admin_user):
        event = create_alert_event(db, alert_rule["id"], {"host": "web-1"}, 95.0)
        resp = admin_client.post(f"/alerts/api/events/{event['id']}/ack")
        assert resp.status_code == 200

    def test_list_channels(self, admin_client, db, notification_channel):
        resp = admin_client.get("/alerts/api/channels")
        assert resp.status_code == 200
        assert len(resp.get_json()["channels"]) == 1

    def test_create_channel(self, admin_client):
        resp = admin_client.post("/alerts/api/channels", json={
            "name": "Email Ops",
            "type": "email",
            "config": {"recipients": ["ops@example.com"]},
        })
        assert resp.status_code == 201

    def test_list_silences(self, admin_client, db, alert_admin_user):
        create_silence(
            db,
            matchers=[{"label": "host", "op": "=", "value": "web-1"}],
            rule_id=None,
            starts_at="2024-01-01T00:00:00Z",
            ends_at="2027-12-31T23:59:59Z",
            reason="Deploy",
            created_by=alert_admin_user,
        )
        resp = admin_client.get("/alerts/api/silences")
        assert resp.status_code == 200
        assert len(resp.get_json()["silences"]) == 1

    def test_health_endpoint(self, admin_client):
        resp = admin_client.get("/health/alerts")
        assert resp.status_code in (200, 503)

    def test_viewer_can_read_rules(self, viewer_client, db, alert_rule):
        resp = viewer_client.get("/alerts/api/rules")
        assert resp.status_code == 200

    def test_viewer_cannot_create_rule(self, viewer_client):
        resp = viewer_client.post("/alerts/api/rules", json={"name": "X"})
        assert resp.status_code == 403

    def test_history_endpoint(self, admin_client, db, alert_rule):
        event = create_alert_event(db, alert_rule["id"], {"host": "web-1"}, 95.0)
        resolve_alert_event(db, event["id"])
        resp = admin_client.get("/alerts/api/history")
        assert resp.status_code == 200
        assert resp.get_json()["total"] == 1
