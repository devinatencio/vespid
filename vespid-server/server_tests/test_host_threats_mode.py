"""Tests for host-threat mode changes and confirmation reporting.

Regression coverage for the dashboard mode selector: a hostname can have
events from more than one node_id (re-enrollment, cloned VM), so the command
must target the node that is reporting today, not an arbitrary historical
row. The confirmation endpoint also has to surface a failed agent command
instead of leaving the UI stuck on "pending".
"""

import json

from app import create_app
from app.models import get_db


def _create_app(tmp_path):
    db_path = str(tmp_path / "test.db")
    config_file = tmp_path / "config.json"
    config_file.write_text(
        json.dumps(
            {
                "SECRET_KEY": "test-secret-key",
                "DATABASE_PATH": db_path,
                "DEBUG": False,
                "ALERTS_ENABLED": False,
            }
        )
    )
    app = create_app(str(config_file))
    app.config["TESTING"] = True
    app.config["WTF_CSRF_ENABLED"] = False
    return app


def _create_user(db):
    from app.models import create_user

    return create_user(db, "admin", "admin", "admin")


def _login(client):
    client.post("/login", data={"username": "admin", "password": "admin"})


def _insert_host_event(db, hostname, timestamp, node_id):
    db.execute(
        "INSERT INTO host_events (hostname, timestamp, event_type, rule_name, "
        "pid, ppid, exe, command_line, uid, auid, raw_line, node_id) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            hostname,
            timestamp,
            "medium",
            "sigma_whoami",
            1234,
            1,
            "/usr/bin/test",
            "test --arg",
            0,
            1000,
            "raw log line",
            node_id,
        ),
    )
    db.commit()


def _insert_node(db, node_id, display_name="", host_info=None):
    db.execute(
        "INSERT OR REPLACE INTO nodes (node_id, display_name, last_host_info, last_seen_at) "
        "VALUES (?, ?, ?, ?)",
        (node_id, display_name, json.dumps(host_info or {}), "2026-10-30T12:00:00Z"),
    )
    db.commit()


def _commands(db):
    return db.execute(
        "SELECT command_id, node_id, command_type, payload, status FROM pending_commands"
    ).fetchall()


def test_set_mode_targets_most_recent_node(tmp_path):
    """A re-enrolled host must receive the command on its current node_id."""
    app = _create_app(tmp_path)
    with app.app_context():
        db = get_db(app.config["DATABASE_PATH"])
        _create_user(db)
        _insert_node(db, "node-old")
        _insert_node(db, "node-new")
        _insert_host_event(db, "web-01", "2026-10-20 12:00:00", "node-old")
        _insert_host_event(db, "web-01", "2026-10-30 12:00:00", "node-new")
        db.close()

    client = app.test_client()
    _login(client)
    resp = client.post(
        "/admin/host-threats/set-mode",
        json={"hostname": "web-01", "mode": "alerting"},
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["success"] is True
    assert body["command_id"]

    with app.app_context():
        db = get_db(app.config["DATABASE_PATH"])
        rows = _commands(db)
        db.close()

    assert len(rows) == 1
    assert rows[0]["command_type"] == "set_auditd_mode"
    assert rows[0]["node_id"] == "node-new"
    assert json.loads(rows[0]["payload"]) == {"mode": "alerting"}


def test_set_mode_falls_back_to_node_display_name(tmp_path):
    """Hosts with no events in the window can still have their mode changed."""
    app = _create_app(tmp_path)
    with app.app_context():
        db = get_db(app.config["DATABASE_PATH"])
        _create_user(db)
        _insert_node(db, "node-1", display_name="web-01")
        db.close()

    client = app.test_client()
    _login(client)
    resp = client.post(
        "/admin/host-threats/set-mode",
        json={"hostname": "web-01", "mode": "detecting"},
    )
    assert resp.status_code == 200

    with app.app_context():
        db = get_db(app.config["DATABASE_PATH"])
        rows = _commands(db)
        db.close()

    assert len(rows) == 1
    assert rows[0]["node_id"] == "node-1"


def test_mode_status_reports_agent_failure(tmp_path):
    """A failed agent command is reported instead of appearing pending."""
    command_id = "cmd-failed"
    app = _create_app(tmp_path)
    with app.app_context():
        db = get_db(app.config["DATABASE_PATH"])
        _create_user(db)
        _insert_node(
            db,
            "node-1",
            display_name="web-01",
            host_info={"auditd": {"mode": "detecting"}},
        )
        db.execute(
            "INSERT INTO pending_commands "
            "(command_id, node_id, command_type, payload, status, result) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (
                command_id,
                "node-1",
                "set_auditd_mode",
                json.dumps({"mode": "alerting"}),
                "failed",
                "unknown command type: set_auditd_mode",
            ),
        )
        db.commit()
        db.close()

    client = app.test_client()
    _login(client)
    resp = client.get(
        "/admin/host-threats/mode-status",
        query_string={"hostname": "web-01", "command_id": command_id},
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["mode"] == "detecting"
    assert body["command_status"] == "failed"
    assert "unknown command type" in body["command_result"]


def test_mode_status_hides_other_nodes_command(tmp_path):
    """A command id belonging to another node must not be disclosed."""
    app = _create_app(tmp_path)
    with app.app_context():
        db = get_db(app.config["DATABASE_PATH"])
        _create_user(db)
        _insert_node(
            db,
            "node-1",
            display_name="web-01",
            host_info={"auditd": {"mode": "detecting"}},
        )
        db.execute(
            "INSERT INTO pending_commands "
            "(command_id, node_id, command_type, payload, status) "
            "VALUES (?, ?, ?, ?, ?)",
            ("cmd-other", "node-2", "set_auditd_mode", "{}", "failed"),
        )
        db.commit()
        db.close()

    client = app.test_client()
    _login(client)
    resp = client.get(
        "/admin/host-threats/mode-status",
        query_string={"hostname": "web-01", "command_id": "cmd-other"},
    )
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["command_status"] is None
    assert body["command_result"] is None
