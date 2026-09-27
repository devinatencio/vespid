"""Tests for audit log retention / purge."""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest
from app.models import get_setting, purge_old_audit_log, record_audit


@pytest.fixture()
def audit_db():
    """In-memory SQLite DB with the audit_log table."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute(
        "CREATE TABLE audit_log ("
        " id INTEGER PRIMARY KEY AUTOINCREMENT,"
        " timestamp TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),"
        " actor TEXT NOT NULL,"
        " actor_ip TEXT,"
        " action_type TEXT NOT NULL,"
        " target TEXT,"
        " details TEXT NOT NULL DEFAULT '{}')"
    )
    conn.execute("CREATE INDEX idx_audit_timestamp ON audit_log(timestamp)")
    yield conn
    conn.close()


def _add_entry_with_age(conn, age_days, action_type="block"):
    """Insert an audit entry with a timestamp *age_days* in the past."""
    ts = (datetime.now(timezone.utc) - timedelta(days=age_days)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )
    conn.execute(
        "INSERT INTO audit_log (timestamp, actor, action_type, details) "
        "VALUES (?, 'test-user', ?, '{}')",
        (ts, action_type),
    )
    conn.commit()


def test_purge_old_audit_log_removes_only_expired_entries(audit_db):
    _add_entry_with_age(audit_db, age_days=120)
    _add_entry_with_age(audit_db, age_days=120)
    _add_entry_with_age(audit_db, age_days=30)

    purged = purge_old_audit_log(audit_db, 90)

    assert purged == 2
    remaining = audit_db.execute("SELECT COUNT(*) AS c FROM audit_log").fetchone()["c"]
    assert remaining == 1


def test_purge_old_audit_log_zero_when_all_fresh(audit_db):
    _add_entry_with_age(audit_db, age_days=10)
    _add_entry_with_age(audit_db, age_days=0)

    purged = purge_old_audit_log(audit_db, 90)

    assert purged == 0
    assert audit_db.execute("SELECT COUNT(*) AS c FROM audit_log").fetchone()["c"] == 2


def test_purge_old_audit_log_uses_record_audit_entries(audit_db):
    record_audit(audit_db, "admin", "127.0.0.1", "login", "console", {})
    audit_db.execute(
        "UPDATE audit_log SET timestamp = ?",
        ((datetime.now(timezone.utc) - timedelta(days=100)).strftime("%Y-%m-%dT%H:%M:%SZ"),),
    )
    audit_db.commit()

    purged = purge_old_audit_log(audit_db, 90)

    assert purged == 1
    assert audit_db.execute("SELECT COUNT(*) AS c FROM audit_log").fetchone()["c"] == 0


def test_record_audit_and_purge_roundtrip(audit_db):
    record_audit(audit_db, "admin", "127.0.0.1", "login", "console", {})

    purged = purge_old_audit_log(audit_db, 90)

    assert purged == 0
    assert audit_db.execute("SELECT COUNT(*) AS c FROM audit_log").fetchone()["c"] == 1


# ── Cleanup route integration ──────────────────────────────────────────────


def test_cleanup_page_shows_audit_section(admin_client):
    resp = admin_client.get("/admin/cleanup")
    assert resp.status_code == 200
    assert b"Audit Log Retention" in resp.data
    assert b"audit_retention_days" in resp.data


def test_save_retention_updates_audit_setting(admin_client, db):
    resp = admin_client.post(
        "/admin/cleanup",
        data={"action": "save_retention", "retention_days": "60", "audit_retention_days": "120"},
    )
    assert resp.status_code == 200
    assert get_setting(db, "audit_retention_days") == "120"
    assert get_setting(db, "event_retention_days") == "60"


def test_save_retention_without_audit_keeps_existing(admin_client, db):
    from app.models import set_setting

    set_setting(db, "audit_retention_days", "365")
    resp = admin_client.post(
        "/admin/cleanup",
        data={"action": "save_retention", "retention_days": "30"},
    )
    assert resp.status_code == 200
    assert get_setting(db, "audit_retention_days") == "365"


def test_purge_now_purges_expired_audit_entries(admin_client, db):
    record_audit(db, "old-actor", "127.0.0.1", "login", "console", {})
    db.execute(
        "UPDATE audit_log SET timestamp = ? WHERE actor = 'old-actor'",
        ((datetime.now(timezone.utc) - timedelta(days=120)).strftime("%Y-%m-%dT%H:%M:%SZ"),),
    )
    db.commit()

    resp = admin_client.post("/admin/cleanup", data={"action": "purge_now"})
    assert resp.status_code == 200
    remaining = db.execute(
        "SELECT COUNT(*) AS c FROM audit_log WHERE actor = 'old-actor'"
    ).fetchone()["c"]
    assert remaining == 0


def test_purge_now_keeps_fresh_audit_entries(admin_client, db):
    record_audit(db, "fresh-actor", "127.0.0.1", "login", "console", {})
    db.commit()

    resp = admin_client.post("/admin/cleanup", data={"action": "purge_now"})
    assert resp.status_code == 200
    remaining = db.execute(
        "SELECT COUNT(*) AS c FROM audit_log WHERE actor = 'fresh-actor'"
    ).fetchone()["c"]
    assert remaining == 1
