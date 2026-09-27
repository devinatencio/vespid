"""Unit tests for the RolloutEngine class and rollout API endpoints.

Tests the rollout engine logic (should_distribute, check_failure_threshold,
promote) and the API endpoints (create, promote, cancel).

Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, 10.8, 11.4
"""

import json

import pytest

from app import create_app
from app.routes.config_rollout import RolloutEngine
from app.models import (
    create_rollout,
    create_user,
    get_db,
    init_db,
    update_rollout_status,
)


# ── RolloutEngine unit tests ─────────────────────────────────────────────


class TestShouldDistribute:
    """Tests for RolloutEngine.should_distribute()."""

    def setup_method(self):
        self.engine = RolloutEngine()

    def test_immediate_always_true(self):
        rollout = {"policy": "immediate", "canary_nodes": "[]", "current_percentage": 100}
        assert self.engine.should_distribute(rollout, "node-1") is True
        assert self.engine.should_distribute(rollout, "node-999") is True

    def test_canary_includes_listed_nodes(self):
        rollout = {
            "policy": "canary",
            "canary_nodes": json.dumps(["node-1", "node-2"]),
            "current_percentage": 100,
        }
        assert self.engine.should_distribute(rollout, "node-1") is True
        assert self.engine.should_distribute(rollout, "node-2") is True

    def test_canary_excludes_unlisted_nodes(self):
        rollout = {
            "policy": "canary",
            "canary_nodes": json.dumps(["node-1", "node-2"]),
            "current_percentage": 100,
        }
        assert self.engine.should_distribute(rollout, "node-3") is False
        assert self.engine.should_distribute(rollout, "node-99") is False

    def test_canary_with_list_instead_of_json_string(self):
        rollout = {
            "policy": "canary",
            "canary_nodes": ["node-a", "node-b"],
            "current_percentage": 100,
        }
        assert self.engine.should_distribute(rollout, "node-a") is True
        assert self.engine.should_distribute(rollout, "node-c") is False

    def test_staged_deterministic_selection(self):
        """Staged rollout uses hash-based deterministic selection."""
        rollout = {"policy": "staged", "canary_nodes": "[]", "current_percentage": 50}
        # Same node always gets the same result
        result1 = self.engine.should_distribute(rollout, "node-test-1")
        result2 = self.engine.should_distribute(rollout, "node-test-1")
        assert result1 == result2

    def test_staged_100_percent_includes_all(self):
        rollout = {"policy": "staged", "canary_nodes": "[]", "current_percentage": 100}
        # All nodes should be included at 100%
        for i in range(20):
            assert self.engine.should_distribute(rollout, f"node-{i}") is True

    def test_staged_0_percent_excludes_all(self):
        rollout = {"policy": "staged", "canary_nodes": "[]", "current_percentage": 0}
        # No nodes should be included at 0%
        for i in range(20):
            assert self.engine.should_distribute(rollout, f"node-{i}") is False

    def test_staged_percentage_roughly_correct(self):
        """With enough nodes, staged percentage should be approximately correct."""
        rollout = {"policy": "staged", "canary_nodes": "[]", "current_percentage": 50}
        included = sum(
            1 for i in range(1000)
            if self.engine.should_distribute(rollout, f"node-{i}")
        )
        # Should be roughly 50% (within 10% tolerance)
        assert 400 <= included <= 600

    def test_unknown_policy_returns_false(self):
        rollout = {"policy": "unknown", "canary_nodes": "[]", "current_percentage": 100}
        assert self.engine.should_distribute(rollout, "node-1") is False


class TestCheckFailureThreshold:
    """Tests for RolloutEngine.check_failure_threshold()."""

    @pytest.fixture()
    def db(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        init_db(db_path)
        conn = get_db(db_path)
        conn.execute(
            "INSERT INTO config_profiles (name, name_lower, settings, created_by) "
            "VALUES ('test-profile', 'test-profile', '{\"allowlist\": []}', 'admin')"
        )
        conn.commit()
        yield conn
        conn.close()

    def setup_method(self):
        self.engine = RolloutEngine()

    def test_no_failures_returns_false(self, db):
        r = create_rollout(db, profile_id=1, target_version=2, created_by="admin")
        db.execute(
            "UPDATE config_rollouts SET failure_count = 0, success_count = 5, total_targeted = 10 WHERE id = ?",
            (r["id"],),
        )
        db.commit()
        assert self.engine.check_failure_threshold(db, r["id"]) is False

    def test_over_50_percent_failures_returns_true(self, db):
        r = create_rollout(db, profile_id=1, target_version=2, created_by="admin")
        db.execute(
            "UPDATE config_rollouts SET failure_count = 6, success_count = 4, total_targeted = 10 WHERE id = ?",
            (r["id"],),
        )
        db.commit()
        assert self.engine.check_failure_threshold(db, r["id"]) is True

    def test_exactly_50_percent_returns_false(self, db):
        r = create_rollout(db, profile_id=1, target_version=2, created_by="admin")
        db.execute(
            "UPDATE config_rollouts SET failure_count = 5, success_count = 5, total_targeted = 10 WHERE id = ?",
            (r["id"],),
        )
        db.commit()
        assert self.engine.check_failure_threshold(db, r["id"]) is False

    def test_nonexistent_rollout_returns_false(self, db):
        assert self.engine.check_failure_threshold(db, 9999) is False

    def test_fallback_when_total_targeted_zero(self, db):
        """When total_targeted is 0, uses success+failure as denominator."""
        r = create_rollout(db, profile_id=1, target_version=2, created_by="admin")
        db.execute(
            "UPDATE config_rollouts SET failure_count = 3, success_count = 2, total_targeted = 0 WHERE id = ?",
            (r["id"],),
        )
        db.commit()
        # 3 failures out of 5 total = 60% > 50%
        assert self.engine.check_failure_threshold(db, r["id"]) is True


class TestPromote:
    """Tests for RolloutEngine.promote()."""

    @pytest.fixture()
    def db(self, tmp_path):
        db_path = str(tmp_path / "test.db")
        init_db(db_path)
        conn = get_db(db_path)
        conn.execute(
            "INSERT INTO config_profiles (name, name_lower, settings, created_by) "
            "VALUES ('test-profile', 'test-profile', '{\"allowlist\": []}', 'admin')"
        )
        conn.commit()
        yield conn
        conn.close()

    def setup_method(self):
        self.engine = RolloutEngine()

    def test_promote_canary_to_full(self, db):
        r = create_rollout(
            db, profile_id=1, target_version=2, created_by="admin",
            policy="canary", canary_nodes=["node-1"],
        )
        update_rollout_status(db, r["id"], "in_progress")
        result = self.engine.promote(db, r["id"])
        assert result["policy"] == "immediate"
        assert result["status"] == "in_progress"
        assert result["current_percentage"] == 100

    def test_promote_staged_to_next_percentage(self, db):
        r = create_rollout(
            db, profile_id=1, target_version=2, created_by="admin",
            policy="staged", current_percentage=25,
        )
        update_rollout_status(db, r["id"], "in_progress")
        result = self.engine.promote(db, r["id"], next_percentage=50)
        assert result["current_percentage"] == 50
        assert result["status"] == "in_progress"

    def test_promote_staged_defaults_to_100(self, db):
        r = create_rollout(
            db, profile_id=1, target_version=2, created_by="admin",
            policy="staged", current_percentage=50,
        )
        update_rollout_status(db, r["id"], "in_progress")
        result = self.engine.promote(db, r["id"])
        assert result["current_percentage"] == 100

    def test_promote_immediate_raises(self, db):
        r = create_rollout(db, profile_id=1, target_version=2, created_by="admin")
        update_rollout_status(db, r["id"], "in_progress")
        with pytest.raises(ValueError, match="Cannot promote an immediate rollout"):
            self.engine.promote(db, r["id"])

    def test_promote_completed_raises(self, db):
        r = create_rollout(
            db, profile_id=1, target_version=2, created_by="admin",
            policy="canary", canary_nodes=["node-1"],
        )
        update_rollout_status(db, r["id"], "completed")
        with pytest.raises(ValueError, match="Cannot promote rollout"):
            self.engine.promote(db, r["id"])

    def test_promote_nonexistent_raises(self, db):
        with pytest.raises(ValueError, match="not found"):
            self.engine.promote(db, 9999)

    def test_promote_invalid_percentage_raises(self, db):
        r = create_rollout(
            db, profile_id=1, target_version=2, created_by="admin",
            policy="staged", current_percentage=25,
        )
        update_rollout_status(db, r["id"], "in_progress")
        with pytest.raises(ValueError, match="next_percentage must be between"):
            self.engine.promote(db, r["id"], next_percentage=0)
        with pytest.raises(ValueError, match="next_percentage must be between"):
            self.engine.promote(db, r["id"], next_percentage=101)


# ── API endpoint tests ────────────────────────────────────────────────────


@pytest.fixture()
def app(tmp_path):
    """Create a Flask app with a test database."""
    db_path = str(tmp_path / "test_rollout.db")
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({
        "SECRET_KEY": "test-secret-key-rollout",
        "DATABASE_PATH": db_path,
        "RATELIMIT_ENABLED": False,
    }))
    application = create_app(str(config_file))
    application.config["TESTING"] = True
    application.config["WTF_CSRF_ENABLED"] = False
    return application


@pytest.fixture()
def client(app):
    """Return a Flask test client."""
    return app.test_client()


@pytest.fixture()
def auth_client(app):
    """Factory fixture that returns an authenticated test client for a given role."""
    _counter = {"n": 0}

    def _make_auth_client(role: str):
        _counter["n"] += 1
        username = f"rollout_test_{role}_{_counter['n']}"
        password = f"password_{role}_{_counter['n']}"

        conn = get_db(app.config["DATABASE_PATH"])
        try:
            create_user(conn, username, password, role)
        finally:
            conn.close()

        test_client = app.test_client()
        test_client.post("/login", data={
            "username": username,
            "password": password,
        })
        return test_client

    return _make_auth_client


@pytest.fixture()
def profile_id(app):
    """Create a test profile and return its ID."""
    conn = get_db(app.config["DATABASE_PATH"])
    try:
        cursor = conn.execute(
            "INSERT INTO config_profiles (name, name_lower, settings, created_by) "
            "VALUES ('rollout-test', 'rollout-test', '{\"allowlist\": [\"1.2.3.4\"]}', 'admin')"
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


class TestCreateRolloutEndpoint:
    """Tests for POST /api/v1/config/rollouts."""

    def test_create_immediate_rollout(self, auth_client, profile_id):
        c = auth_client("admin")
        resp = c.post("/api/v1/config/rollouts", json={"profile_id": profile_id})
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["policy"] == "immediate"
        assert data["status"] == "in_progress"
        assert data["profile_id"] == profile_id

    def test_create_canary_rollout(self, auth_client, profile_id):
        c = auth_client("admin")
        resp = c.post("/api/v1/config/rollouts", json={
            "profile_id": profile_id,
            "policy": "canary",
            "canary_nodes": ["node-1", "node-2"],
        })
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["policy"] == "canary"
        assert data["canary_nodes"] == ["node-1", "node-2"]

    def test_create_staged_rollout(self, auth_client, profile_id):
        c = auth_client("admin")
        resp = c.post("/api/v1/config/rollouts", json={
            "profile_id": profile_id,
            "policy": "staged",
            "initial_percentage": 25,
        })
        assert resp.status_code == 201
        data = resp.get_json()
        assert data["policy"] == "staged"
        assert data["current_percentage"] == 25

    def test_default_policy_is_immediate(self, auth_client, profile_id):
        c = auth_client("admin")
        resp = c.post("/api/v1/config/rollouts", json={"profile_id": profile_id})
        assert resp.status_code == 201
        assert resp.get_json()["policy"] == "immediate"

    def test_missing_profile_id(self, auth_client):
        c = auth_client("admin")
        resp = c.post("/api/v1/config/rollouts", json={})
        assert resp.status_code == 400

    def test_nonexistent_profile(self, auth_client):
        c = auth_client("admin")
        resp = c.post("/api/v1/config/rollouts", json={"profile_id": 9999})
        assert resp.status_code == 404

    def test_duplicate_active_rollout(self, auth_client, profile_id):
        c = auth_client("admin")
        resp1 = c.post("/api/v1/config/rollouts", json={"profile_id": profile_id})
        assert resp1.status_code == 201
        resp2 = c.post("/api/v1/config/rollouts", json={"profile_id": profile_id})
        assert resp2.status_code == 409

    def test_invalid_policy(self, auth_client, profile_id):
        c = auth_client("admin")
        resp = c.post("/api/v1/config/rollouts", json={
            "profile_id": profile_id,
            "policy": "invalid",
        })
        assert resp.status_code == 422

    def test_canary_without_nodes(self, auth_client, profile_id):
        c = auth_client("admin")
        resp = c.post("/api/v1/config/rollouts", json={
            "profile_id": profile_id,
            "policy": "canary",
        })
        assert resp.status_code == 422

    def test_staged_invalid_percentage(self, auth_client, profile_id):
        c = auth_client("admin")
        resp = c.post("/api/v1/config/rollouts", json={
            "profile_id": profile_id,
            "policy": "staged",
            "initial_percentage": 0,
        })
        assert resp.status_code == 422

    def test_analyst_cannot_create(self, auth_client, profile_id):
        c = auth_client("analyst")
        resp = c.post("/api/v1/config/rollouts", json={"profile_id": profile_id})
        assert resp.status_code == 403

    def test_audit_log_recorded(self, app, auth_client, profile_id):
        c = auth_client("admin")
        c.post("/api/v1/config/rollouts", json={"profile_id": profile_id})
        conn = get_db(app.config["DATABASE_PATH"])
        try:
            row = conn.execute(
                "SELECT * FROM audit_log WHERE action_type = 'config_rollout_create'"
            ).fetchone()
            assert row is not None
            assert "rollout-test" in (row["target"] or "")
        finally:
            conn.close()


class TestPromoteRolloutEndpoint:
    """Tests for POST /api/v1/config/rollouts/<id>/promote."""

    def test_promote_canary(self, app, auth_client, profile_id):
        c = auth_client("admin")
        # Create canary rollout
        resp = c.post("/api/v1/config/rollouts", json={
            "profile_id": profile_id,
            "policy": "canary",
            "canary_nodes": ["node-1"],
        })
        rollout_id = resp.get_json()["id"]
        # Set to in_progress
        conn = get_db(app.config["DATABASE_PATH"])
        try:
            update_rollout_status(conn, rollout_id, "in_progress")
        finally:
            conn.close()
        # Promote
        resp = c.post(f"/api/v1/config/rollouts/{rollout_id}/promote", json={})
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["policy"] == "immediate"
        assert data["current_percentage"] == 100

    def test_promote_staged(self, app, auth_client, profile_id):
        c = auth_client("admin")
        resp = c.post("/api/v1/config/rollouts", json={
            "profile_id": profile_id,
            "policy": "staged",
            "initial_percentage": 25,
        })
        rollout_id = resp.get_json()["id"]
        conn = get_db(app.config["DATABASE_PATH"])
        try:
            update_rollout_status(conn, rollout_id, "in_progress")
        finally:
            conn.close()
        resp = c.post(f"/api/v1/config/rollouts/{rollout_id}/promote", json={
            "next_percentage": 75,
        })
        assert resp.status_code == 200
        assert resp.get_json()["current_percentage"] == 75

    def test_promote_nonexistent(self, auth_client):
        c = auth_client("admin")
        resp = c.post("/api/v1/config/rollouts/9999/promote", json={})
        assert resp.status_code == 404

    def test_promote_completed_fails(self, app, auth_client, profile_id):
        c = auth_client("admin")
        resp = c.post("/api/v1/config/rollouts", json={
            "profile_id": profile_id,
            "policy": "canary",
            "canary_nodes": ["node-1"],
        })
        rollout_id = resp.get_json()["id"]
        conn = get_db(app.config["DATABASE_PATH"])
        try:
            update_rollout_status(conn, rollout_id, "completed")
        finally:
            conn.close()
        resp = c.post(f"/api/v1/config/rollouts/{rollout_id}/promote", json={})
        assert resp.status_code == 422

    def test_promote_audit_log(self, app, auth_client, profile_id):
        c = auth_client("admin")
        resp = c.post("/api/v1/config/rollouts", json={
            "profile_id": profile_id,
            "policy": "canary",
            "canary_nodes": ["node-1"],
        })
        rollout_id = resp.get_json()["id"]
        conn = get_db(app.config["DATABASE_PATH"])
        try:
            update_rollout_status(conn, rollout_id, "in_progress")
        finally:
            conn.close()
        c.post(f"/api/v1/config/rollouts/{rollout_id}/promote", json={})
        conn = get_db(app.config["DATABASE_PATH"])
        try:
            row = conn.execute(
                "SELECT * FROM audit_log WHERE action_type = 'config_rollout_promote'"
            ).fetchone()
            assert row is not None
        finally:
            conn.close()


class TestCancelRolloutEndpoint:
    """Tests for POST /api/v1/config/rollouts/<id>/cancel."""

    def test_cancel_in_progress(self, app, auth_client, profile_id):
        c = auth_client("admin")
        resp = c.post("/api/v1/config/rollouts", json={"profile_id": profile_id})
        rollout_id = resp.get_json()["id"]
        resp = c.post(f"/api/v1/config/rollouts/{rollout_id}/cancel", json={})
        assert resp.status_code == 200
        assert resp.get_json()["status"] == "cancelled"

    def test_cancel_nonexistent(self, auth_client):
        c = auth_client("admin")
        resp = c.post("/api/v1/config/rollouts/9999/cancel", json={})
        assert resp.status_code == 404

    def test_cancel_already_cancelled(self, app, auth_client, profile_id):
        c = auth_client("admin")
        resp = c.post("/api/v1/config/rollouts", json={"profile_id": profile_id})
        rollout_id = resp.get_json()["id"]
        c.post(f"/api/v1/config/rollouts/{rollout_id}/cancel", json={})
        resp = c.post(f"/api/v1/config/rollouts/{rollout_id}/cancel", json={})
        assert resp.status_code == 422

    def test_cancel_audit_log(self, app, auth_client, profile_id):
        c = auth_client("admin")
        resp = c.post("/api/v1/config/rollouts", json={"profile_id": profile_id})
        rollout_id = resp.get_json()["id"]
        c.post(f"/api/v1/config/rollouts/{rollout_id}/cancel", json={})
        conn = get_db(app.config["DATABASE_PATH"])
        try:
            row = conn.execute(
                "SELECT * FROM audit_log WHERE action_type = 'config_rollout_cancel'"
            ).fetchone()
            assert row is not None
        finally:
            conn.close()

    def test_analyst_cannot_cancel(self, app, auth_client, profile_id):
        c_admin = auth_client("admin")
        resp = c_admin.post("/api/v1/config/rollouts", json={"profile_id": profile_id})
        rollout_id = resp.get_json()["id"]
        c_analyst = auth_client("analyst")
        resp = c_analyst.post(f"/api/v1/config/rollouts/{rollout_id}/cancel", json={})
        assert resp.status_code == 403
