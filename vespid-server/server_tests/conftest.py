"""Shared pytest fixtures for Vespid Server tests.

Provides in-memory SQLite databases, test clients, and pre-created
API keys for integration tests.
"""

import json
import os
import threading
from pathlib import Path
from unittest.mock import patch

import pytest

from app import create_app
from app.models import (
    create_api_key,
    create_user,
    get_db,
    insert_events,
)


# ── Reusable test data ───────────────────────────────────────────────────

TEST_SECRET_KEY = "test-secret-key-for-testing"


@pytest.fixture(autouse=True)
def _disable_csrf_for_tests(app):
    """Disable CSRF for all tests — API endpoints use Bearer tokens, not forms."""
    app.config["WTF_CSRF_ENABLED"] = False


# ── Hooks to isolate test state from production directories ──────────────
# Without this, the server under test (running in a foreground worker) would
# try to write to real system directories such as /var/lib/vespid-server.
# We also redirect the log dir so tests never attempt to write to
# /var/log/vespid-server.

_original_environ = os.environ.copy()


@pytest.fixture(autouse=True)
def _isolate_log_dir(tmp_path, monkeypatch):
    """Prevent the app factory from writing logs to the system log directory."""
    log_dir = str(tmp_path / "logs")
    monkeypatch.setenv("VESPID_LOG_DIR", log_dir)


# ── Database helpers ─────────────────────────────────────────────────────


def _suppress_log():
    """Suppress application startup logging during tests."""
    import logging
    logging.getLogger("app").setLevel(logging.ERROR)
    logging.getLogger("app.models").setLevel(logging.ERROR)


def _create_test_user(db, username="admin", password="admin", role="admin"):
    """Create a test user and return the user id. Safe to call multiple times."""
    try:
        user_id = create_user(db, username, password, role)
    except Exception:
        # Username already exists — look it up
        row = db.execute(
            "SELECT id FROM users WHERE username = ?", (username,)
        ).fetchone()
        if row is None:
            raise
        return row["id"]
    return user_id


def _create_test_api_key(db, label="test-key", node_id_restriction=None, created_by=None):
    """Create a test API key and return the raw token."""
    raw_token = create_api_key(
        db,
        label=label,
        node_id_restriction=node_id_restriction,
        created_by=created_by,
    )
    return raw_token


# ── Clean up after test module ───────────────────────────────────────────


@pytest.fixture(autouse=True)
def _reset_sse_singleton():
    """Ensure each test starts without a lingering SSE manager singleton.

    The SSE manager singleton (app.sse_manager) is created per-app in
    create_app, so tests that construct fresh apps are inherently isolated.
    This fixture provides a hook for any future global state that may need
    resetting and is safe for parallel (xdist) execution.
    """
    yield
    # This intentionally left as a no-op for now; the SSE manager is app-scoped
    # and each test recreates its app.  If any module-level singletons are added,
    # their cleanup should be placed here.


# ── Flask client helpers ─────────────────────────────────────────────────


def login(client, username, password):
    """Log in via the session-based login endpoint and return the response."""
    return client.post(
        "/login",
        data={"username": username, "password": password},
    )


def auth_header(token):
    """Return a dict with an Authorization Bearer header."""
    return {"Authorization": f"Bearer {token}"}


# ══════════════════════════════════════════════════════════════════════════
# Event helper
# ══════════════════════════════════════════════════════════════════════════

VALID_EVENT_TEMPLATE = {
    "node_id": "test-node-1",
    "event_id": "evt-test-001",
    "timestamp": "2025-01-15T10:30:00Z",
    "source_ip": "192.168.1.100",
    "event_type": "BRUTE_FORCE",
    "action_taken": "BLOCKED",
    "geo_data": {"country": "US", "asn": 15169, "org": "Google"},
    "metadata": {"detection_rule": "ssh_brute_force", "block_ttl_seconds": 3600},
}


def make_event(**overrides):
    """Return a copy of VALID_EVENT_TEMPLATE with the given overrides applied."""
    event = dict(VALID_EVENT_TEMPLATE)
    event.update(overrides)
    return event


# ══════════════════════════════════════════════════════════════════════════
# Base event validation tests — shared across test files
# ══════════════════════════════════════════════════════════════════════════

VALID_BATCH = {"events": [make_event()]}


# ── Simple heartbeat payload ─────────────────────────────────────────────

VALID_HEARTBEAT = {
    "node_id": "test-node-1",
    "timestamp": "2025-01-15T10:30:00Z",
}


# ── Admin role ───────────────────────────────────────────────────────────

@pytest.fixture()
def admin_user(app):
    """Create an admin user in the test database. Returns the user_id."""
    db = get_db(app.config["DATABASE_PATH"])
    try:
        user_id = _create_test_user(db, "admin", "admin", "admin")
    finally:
        db.close()
    return user_id


@pytest.fixture()
def admin_user_id(app):
    """Create an admin user in the test database. Returns the user_id.

    Alias for admin_user to match the name used in property-based tests.
    """
    db = get_db(app.config["DATABASE_PATH"])
    try:
        user_id = _create_test_user(db, "admin", "admin", "admin")
    finally:
        db.close()
    return user_id


@pytest.fixture()
def admin_user_and_client(admin_user, client):
    """Return a client logged in as the admin user."""
    client.post("/login", data={"username": "admin", "password": "admin"})
    return client


@pytest.fixture()
def admin_client(client, admin_user):
    """Return a client logged in as admin (shorter name)."""
    client.post("/login", data={"username": "admin", "password": "admin"})
    return client


# ── Analyst role ─────────────────────────────────────────────────────────

@pytest.fixture()
def analyst_user(app):
    """Create an analyst user in the test database. Returns the user_id."""
    db = get_db(app.config["DATABASE_PATH"])
    try:
        user_id = _create_test_user(db, "analyst", "analyst_pass", "analyst")
    finally:
        db.close()
    return user_id


@pytest.fixture()
def analyst_client(client, analyst_user):
    """Return a client logged in as analyst."""
    client.post("/login", data={"username": "analyst", "password": "analyst_pass"})
    return client


# ── Viewer role ──────────────────────────────────────────────────────────

@pytest.fixture()
def viewer_user(app):
    """Create a viewer user in the test database. Returns the user_id."""
    db = get_db(app.config["DATABASE_PATH"])
    try:
        user_id = _create_test_user(db, "viewer", "viewer_pass", "viewer")
    finally:
        db.close()
    return user_id


@pytest.fixture()
def viewer_client(client, viewer_user):
    """Return a client logged in as viewer."""
    client.post("/login", data={"username": "viewer", "password": "viewer_pass"})
    return client


# ── Fleet Config seed helpers ────────────────────────────────────────────

def seed_fleet_config(
    db,
    corroboration_threshold=1,
    corroboration_window_seconds=3600,
    fleet_block_ttl_seconds=3600,
    max_fleet_blocks_per_hour=100,
    max_reports_per_node_per_hour=50,
    propagation_paused=False,
):
    """Insert or update fleet configuration rows in the test database."""
    rows = [
        ("corroboration_threshold", str(corroboration_threshold)),
        ("corroboration_window_seconds", str(corroboration_window_seconds)),
        ("fleet_block_ttl_seconds", str(fleet_block_ttl_seconds)),
        ("max_fleet_blocks_per_hour", str(max_fleet_blocks_per_hour)),
        ("max_reports_per_node_per_hour", str(max_reports_per_node_per_hour)),
        ("propagation_paused", "true" if propagation_paused else "false"),
        ("excluded_event_types", "[]"),
    ]
    for key, value in rows:
        existing = db.execute(
            "SELECT id FROM fleet_config WHERE config_key = ?", (key,)
        ).fetchone()
        if existing:
            db.execute(
                "UPDATE fleet_config SET config_value = ? WHERE config_key = ?",
                (value, key),
            )
        else:
            db.execute(
                "INSERT INTO fleet_config (config_key, config_value) VALUES (?, ?)",
                (key, value),
            )
    db.commit()


# ══════════════════════════════════════════════════════════════════════════
# Event helper
# ══════════════════════════════════════════════════════════════════════════

def _event_payload(*, node_id="test-node-1", event_type="BRUTE_FORCE", source_ip="192.168.1.100",
                   event_id="evt-test-001", action_taken="BLOCKED", extra_meta=None):
    meta = {
        "detection_rule": "ssh_brute_force",
        "block_ttl_seconds": 3600,
    }
    if extra_meta:
        meta.update(extra_meta)
    return {
        "events": [{
            "node_id": node_id,
            "event_id": event_id,
            "timestamp": "2025-01-15T10:30:00Z",
            "source_ip": source_ip,
            "event_type": event_type,
            "action_taken": action_taken,
            "geo_data": {"country": "US"},
            "metadata": meta,
        }]
    }


# ── Insert helpers ───────────────────────────────────────────────────────

def insert_event(app, **overrides):
    """Insert a single event and return the database row."""
    payload = _event_payload(**overrides)
    db = get_db(app.config["DATABASE_PATH"])
    try:
        inserted = insert_events(db, payload["events"])
        db.commit()
        if inserted:
            return db.execute(
                "SELECT * FROM events WHERE event_id = ?",
                (payload["events"][0]["event_id"],),
            ).fetchone()
        return None
    finally:
        db.close()


# ── Existing Fixtures ────────────────────────────────────────────────────


@pytest.fixture()
def app(tmp_path):
    """Create a Flask app with test config and in-memory SQLite.

    Uses tmp_path to create an isolated database for each test.
    Sets TESTING=True and WTF_CSRF_ENABLED=False for test convenience.
    """
    db_path = str(tmp_path / "test.db")
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({
        "SECRET_KEY": "test-secret-key-for-testing",
        "DATABASE_PATH": db_path,
        "DEBUG": False,
        "ALERTS_ENABLED": True,
    }))
    application = create_app(str(config_file))
    application.config["TESTING"] = True
    application.config["WTF_CSRF_ENABLED"] = False
    return application


@pytest.fixture()
def client(app):
    """Return a Flask test client bound to the test app."""
    return app.test_client()


@pytest.fixture()
def db(app):
    """Return an initialized database connection for the test app.

    The connection is automatically closed after the test completes.
    """
    conn = get_db(app.config["DATABASE_PATH"])
    yield conn
    conn.close()


@pytest.fixture()
def api_key(app, db):
    """Create an admin user and an unrestricted API key for testing.

    Returns the raw token string for use in Authorization headers.
    """
    _create_test_user(db, "admin", "admin", "admin")
    token = _create_test_api_key(db, label="test-api-key")
    return token


@pytest.fixture()
def auth_client(app, client):
    """Return a factory that creates an authenticated client for any role.

    Calling ``auth_client("admin")`` creates an admin user, logs them in,
    and returns the Flask test client.
    """

    def _auth(role: str):
        from app.models import get_db as _get_db

        db = _get_db(app.config["DATABASE_PATH"])
        try:
            _create_test_user(db, role, f"{role}_pass", role)
        finally:
            db.close()
        c = app.test_client()
        c.post("/login", data={"username": role, "password": f"{role}_pass"})
        return c

    return _auth


@pytest.fixture()
def intel_db():
    """Provide an in-memory SQLite connection for intel property tests.

    Tables are created via init_intel_db so that tests can operate on
    a fresh database for each test function.
    """
    import sqlite3

    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    try:
        from app.intel_models import init_intel_db

        init_intel_db(conn, "sqlite")
    except Exception:
        # Some intel tests use a raw DB without the full table init
        pass
    yield conn
    conn.close()
