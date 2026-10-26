"""Tests for the read-only role and method-aware role enforcement."""

import sqlite3

from app.models import get_db, get_user_by_username
from app.models.db_core import _migrate_sqlite_users_readonly_role


def _insert_host_event(db, hostname="web-01", node_id="node-1"):
    db.execute(
        "INSERT INTO host_events "
        "(hostname, timestamp, event_type, rule_name, pid, ppid, exe, "
        " command_line, uid, auid, raw_line, node_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            hostname,
            "2026-10-25 17:43:00",
            "medium",
            "sigma_whoami",
            1,
            0,
            "/usr/bin/whoami",
            "whoami",
            0,
            0,
            "raw line",
            node_id,
        ),
    )
    db.commit()


class TestReadonlyReadAccess:
    def test_readonly_can_open_analyst_pages(self, auth_client):
        client = auth_client("readonly")
        assert client.get("/intel/").status_code == 200
        assert client.get("/fleet/").status_code == 200
        assert client.get("/admin/host-threats").status_code == 200

    def test_readonly_can_open_viewer_pages(self, auth_client):
        client = auth_client("readonly")
        assert client.get("/").status_code == 200

    def test_readonly_cannot_open_admin_pages(self, auth_client):
        client = auth_client("readonly")
        assert client.get("/admin/users").status_code == 403

    def test_viewer_cannot_open_analyst_pages(self, auth_client):
        client = auth_client("viewer")
        assert client.get("/intel/").status_code == 403
        assert client.get("/fleet/").status_code == 403


class TestReadonlyWriteDenied:
    def test_readonly_cannot_set_host_mode(self, auth_client):
        client = auth_client("readonly")
        resp = client.post(
            "/admin/host-threats/set-mode",
            json={"hostname": "web-01", "mode": "alerting"},
        )
        assert resp.status_code == 403

    def test_readonly_cannot_suppress_rules(self, auth_client):
        client = auth_client("readonly")
        resp = client.post(
            "/admin/host-threats/suppress",
            json={"hostname": "web-01", "rules": ["sigma_whoami"]},
        )
        assert resp.status_code == 403

    def test_readonly_cannot_edit_inventory_labels(self, auth_client):
        client = auth_client("readonly")
        resp = client.post("/inventory/asset-1/labels", json={"env": "test"})
        assert resp.status_code == 403

    def test_viewer_cannot_set_host_mode(self, auth_client):
        client = auth_client("viewer")
        resp = client.post(
            "/admin/host-threats/set-mode",
            json={"hostname": "web-01", "mode": "alerting"},
        )
        assert resp.status_code == 403

    def test_analyst_can_still_set_host_mode(self, app, auth_client):
        db = get_db(app.config["DATABASE_PATH"])
        try:
            _insert_host_event(db)
        finally:
            db.close()

        client = auth_client("analyst")
        resp = client.post(
            "/admin/host-threats/set-mode",
            json={"hostname": "web-01", "mode": "alerting"},
        )
        assert resp.status_code == 200

    def test_readonly_is_denied_on_viewer_level_write_probe(self, app, auth_client):
        """The method check applies even when a route only requires viewer."""
        from app.decorators import require_role

        @app.route("/_readonly_probe", methods=["GET", "POST"])
        @require_role("viewer")
        def _probe():
            return "ok"

        client = auth_client("readonly")
        assert client.get("/_readonly_probe").status_code == 200
        assert client.post("/_readonly_probe").status_code == 403


class TestReadonlyUserManagement:
    def test_admin_can_create_readonly_user(self, app, auth_client):
        client = auth_client("admin")
        resp = client.post(
            "/admin/users",
            data={
                "username": "readonly_user",
                "password": "readonly_pass",
                "role": "readonly",
                "display_name": "Read Only",
            },
        )
        assert resp.status_code in (302, 303)

        db = get_db(app.config["DATABASE_PATH"])
        try:
            user = get_user_by_username(db, "readonly_user")
            assert user is not None
            assert user["role"] == "readonly"
        finally:
            db.close()


def test_sqlite_users_migration_allows_readonly(tmp_path):
    """Existing SQLite databases rebuild the users CHECK to accept readonly."""
    db_path = str(tmp_path / "legacy_users.db")
    conn = sqlite3.connect(db_path)
    conn.executescript("""
        CREATE TABLE users (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            username        TEXT    NOT NULL UNIQUE,
            password_hash   TEXT    NOT NULL,
            role            TEXT    NOT NULL DEFAULT 'viewer'
                            CHECK(role IN ('admin', 'analyst', 'viewer')),
            created_at      TEXT    NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%SZ', 'now')),
            last_login_at   TEXT,
            display_name    TEXT    NOT NULL DEFAULT '',
            theme           TEXT    NOT NULL DEFAULT 'dark'
                            CHECK(theme IN ('dark', 'light', 'nord', 'vespid')),
            failed_login_attempts INTEGER NOT NULL DEFAULT 0,
            locked_until    TEXT,
            onboarding_dismissed INTEGER NOT NULL DEFAULT 0,
            brand_beam_enabled INTEGER NOT NULL DEFAULT 1
        );
        INSERT INTO users (username, password_hash, role)
        VALUES ('legacy_admin', 'hash', 'admin');
    """)
    conn.commit()

    _migrate_sqlite_users_readonly_role(conn)

    legacy = conn.execute(
        "SELECT role FROM users WHERE username = 'legacy_admin'"
    ).fetchone()
    assert legacy[0] == "admin"

    conn.execute(
        "INSERT INTO users (username, password_hash, role) "
        "VALUES ('readonly_user', 'hash', 'readonly')"
    )
    conn.commit()
    assert conn.execute(
        "SELECT COUNT(*) FROM users WHERE role = 'readonly'"
    ).fetchone()[0] == 1

    # Idempotent: running again does not duplicate or lose rows.
    _migrate_sqlite_users_readonly_role(conn)
    assert conn.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 2
    conn.close()
