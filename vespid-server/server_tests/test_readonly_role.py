"""Tests for the read-only role and method-aware role enforcement."""

import sqlite3

from app.models import add_ip_rule, get_db, get_user_by_username
from app.models.db_core import _migrate_sqlite_users_readonly_role


def _enable_metrics_nav(app):
    """Expose the monitoring nav in the test app so role gating can be checked."""
    from app.routes.metrics import metrics_bp

    app.config["METRICS_ENABLED"] = True
    if "metrics.overview" not in app.view_functions:
        app.register_blueprint(metrics_bp)


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
        assert client.get("/alerts/channels").status_code == 403
        assert client.get("/alerts/silences").status_code == 403

    def test_readonly_nav_hides_admin_only_alert_pages(self, app, auth_client):
        _enable_metrics_nav(app)
        client = auth_client("readonly")
        resp = client.get("/alerts")
        assert resp.status_code == 200
        assert b">Channels</a>" not in resp.data
        assert b">Silences</a>" not in resp.data

    def test_admin_nav_shows_alert_configuration_pages(self, app, auth_client):
        _enable_metrics_nav(app)
        client = auth_client("admin")
        resp = client.get("/alerts")
        assert resp.status_code == 200
        assert b">Channels</a>" in resp.data
        assert b">Silences</a>" in resp.data

    def test_readonly_feed_page_hides_deploy_and_retract(self, auth_client):
        client = auth_client("readonly")
        resp = client.get("/feeds")
        assert resp.status_code == 200
        assert b'class="feed-catalog-actions"' not in resp.data
        assert b'class="retract-form"' not in resp.data

    def test_analyst_feed_page_shows_deploy_and_retract(self, auth_client):
        client = auth_client("analyst")
        resp = client.get("/feeds")
        assert resp.status_code == 200
        assert b'class="feed-catalog-actions"' in resp.data
        assert b'class="retract-form"' in resp.data

    def test_readonly_rules_page_hides_write_controls(self, db, auth_client):
        add_ip_rule(db, "allowlist", "10.0.0.0/8", "internal", "admin")
        add_ip_rule(db, "blocklist", "203.0.113.42", "abuse", "admin")

        client = auth_client("readonly")
        resp = client.get("/rules")
        assert resp.status_code == 200
        assert b"Add to Allowlist" not in resp.data
        assert b"Block IP" not in resp.data
        assert b"Remove from allowlist" not in resp.data
        assert b">Unblock</button>" not in resp.data

    def test_analyst_rules_page_shows_write_controls(self, db, auth_client):
        add_ip_rule(db, "allowlist", "10.0.0.0/8", "internal", "admin")
        add_ip_rule(db, "blocklist", "203.0.113.42", "abuse", "admin")

        client = auth_client("analyst")
        resp = client.get("/rules")
        assert resp.status_code == 200
        assert b"Add to Allowlist" in resp.data
        assert b"Block IP" in resp.data
        assert b"Remove from allowlist" in resp.data
        assert b">Unblock</button>" in resp.data

    def test_readonly_alert_pages_hide_write_controls(self, auth_client):
        client = auth_client("readonly")

        rules = client.get("/alerts/rules")
        assert rules.status_code == 200
        assert b"+ New Rule" not in rules.data
        assert b"var ADMIN = false;" in rules.data

        groups = client.get("/alerts/groups")
        assert groups.status_code == 200
        assert b"+ New Group" not in groups.data
        assert b"var ADMIN = false;" in groups.data

        checks = client.get("/alerts/synthetic-checks")
        assert checks.status_code == 200
        assert b"+ New Check" not in checks.data
        assert b"+ New Rule" not in checks.data
        assert b">Sync All</a>" not in checks.data
        assert b"var ADMIN = false;" in checks.data

    def test_admin_alert_pages_show_write_controls(self, auth_client):
        client = auth_client("admin")

        rules = client.get("/alerts/rules")
        assert b"+ New Rule" in rules.data
        assert b"var ADMIN = true;" in rules.data

        groups = client.get("/alerts/groups")
        assert b"+ New Group" in groups.data
        assert b"var ADMIN = true;" in groups.data

        checks = client.get("/alerts/synthetic-checks")
        assert b"+ New Check" in checks.data
        assert b"+ New Rule" in checks.data
        assert b">Sync All</a>" in checks.data
        assert b"var ADMIN = true;" in checks.data

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
