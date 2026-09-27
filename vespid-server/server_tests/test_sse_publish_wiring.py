"""Tests for SSE publish wiring in profile update and rollout creation flows.

Verifies that config_updated SSE events are pushed to connected agents when:
- A profile is updated via PUT /api/v1/config/profiles/<id>
- An immediate rollout is created via POST /api/v1/config/rollouts

Rollout policy targeting is also verified:
- Canary rollouts: only canary_nodes receive the event
- Staged rollouts: only nodes within the percentage bucket receive the event
- Immediate rollouts: all connected agents receive the event

Requirements: 5.2, 10.1, 10.2, 10.3
"""

import hashlib
import json

import pytest

from app import create_app
from app.config_sse import ConfigSSEManager
from app.models import create_user, get_db, init_db


# ── Fixtures ──────────────────────────────────────────────────────────────


@pytest.fixture()
def app(tmp_path):
    """Create a Flask app with a test database and a real ConfigSSEManager."""
    db_path = str(tmp_path / "test_sse_wiring.db")
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({
        "SECRET_KEY": "test-secret-key-sse-wiring",
        "DATABASE_PATH": db_path,
        "RATELIMIT_ENABLED": False,
    }))
    application = create_app(str(config_file))
    application.config["TESTING"] = True
    application.config["WTF_CSRF_ENABLED"] = False
    return application


@pytest.fixture()
def auth_client(app):
    """Factory fixture that returns an authenticated test client for a given role."""
    _counter = {"n": 0}

    def _make_auth_client(role: str):
        _counter["n"] += 1
        username = f"sse_wiring_{role}_{_counter['n']}"
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
            "VALUES ('sse-test-profile', 'sse-test-profile', "
            "'{\"allowlist\": [\"1.2.3.4\"]}', 'admin')"
        )
        conn.commit()
        return cursor.lastrowid
    finally:
        conn.close()


# ── Profile update SSE publish tests ─────────────────────────────────────


class TestProfileUpdateSSEPublish:
    """Tests that PUT /profiles/<id> publishes SSE events to connected agents."""

    def test_profile_update_publishes_sse_event(self, app, auth_client, profile_id):
        """Updating a profile should push a config_updated event to connected agents."""
        sse_mgr = app.config_sse_manager
        client_queue = sse_mgr.create_client("node-1")

        c = auth_client("admin")
        resp = c.put(
            f"/api/v1/config/profiles/{profile_id}",
            json={
                "settings": {"allowlist": ["10.0.0.1"]},
                "change_reason": "Test update",
            },
        )
        assert resp.status_code == 200

        # The SSE event should have been published
        assert not client_queue.empty()
        msg = client_queue.get(timeout=1)
        assert "event: config_updated" in msg
        assert "id:" in msg

        sse_mgr.remove_client("node-1")

    def test_profile_update_event_contains_correct_data(self, app, auth_client, profile_id):
        """The SSE event data should contain profile_name, version, settings."""
        sse_mgr = app.config_sse_manager
        client_queue = sse_mgr.create_client("node-1")

        c = auth_client("admin")
        resp = c.put(
            f"/api/v1/config/profiles/{profile_id}",
            json={
                "settings": {"allowlist": ["192.168.1.1"]},
                "change_reason": "Update allowlist",
            },
        )
        assert resp.status_code == 200
        updated = resp.get_json()

        msg = client_queue.get(timeout=1)

        # Parse the data line from the SSE message
        data_str = None
        for line in msg.split("\n"):
            if line.startswith("data: "):
                data_str = line[len("data: "):]
                break
        assert data_str is not None, "No data: line found in SSE message"

        event_data = json.loads(data_str)
        assert event_data["profile_name"] == "sse-test-profile"
        assert event_data["version"] == updated["version"]
        assert event_data["settings"]["allowlist"] == ["192.168.1.1"]
        assert "updated_at" in event_data
        assert "conflict_strategy" in event_data

        sse_mgr.remove_client("node-1")

    def test_profile_update_no_active_rollout_pushes_to_all(self, app, auth_client, profile_id):
        """Without an active rollout, all connected agents receive the event."""
        sse_mgr = app.config_sse_manager
        q1 = sse_mgr.create_client("node-1")
        q2 = sse_mgr.create_client("node-2")
        q3 = sse_mgr.create_client("node-3")

        c = auth_client("admin")
        resp = c.put(
            f"/api/v1/config/profiles/{profile_id}",
            json={"change_reason": "Broadcast update"},
        )
        assert resp.status_code == 200

        # All three nodes should receive the event
        assert not q1.empty()
        assert not q2.empty()
        assert not q3.empty()

        sse_mgr.remove_client("node-1")
        sse_mgr.remove_client("node-2")
        sse_mgr.remove_client("node-3")

    def test_profile_update_with_canary_rollout_targets_canary_nodes(
        self, app, auth_client, profile_id
    ):
        """With an active canary rollout, only canary nodes receive the event."""
        # Create a canary rollout
        c = auth_client("admin")
        resp = c.post("/api/v1/config/rollouts", json={
            "profile_id": profile_id,
            "policy": "canary",
            "canary_nodes": ["node-canary-1", "node-canary-2"],
        })
        assert resp.status_code == 201

        sse_mgr = app.config_sse_manager
        q_canary1 = sse_mgr.create_client("node-canary-1")
        q_canary2 = sse_mgr.create_client("node-canary-2")
        q_other = sse_mgr.create_client("node-other")

        resp = c.put(
            f"/api/v1/config/profiles/{profile_id}",
            json={"change_reason": "Canary update"},
        )
        assert resp.status_code == 200

        # Canary nodes should receive the event
        assert not q_canary1.empty()
        assert not q_canary2.empty()
        # Non-canary node should NOT receive the event
        assert q_other.empty()

        sse_mgr.remove_client("node-canary-1")
        sse_mgr.remove_client("node-canary-2")
        sse_mgr.remove_client("node-other")

    def test_profile_update_with_staged_rollout_targets_percentage_nodes(
        self, app, auth_client, profile_id
    ):
        """With an active staged rollout, only nodes in the percentage bucket receive the event."""
        # Create a staged rollout at 100% so we can verify deterministic targeting
        c = auth_client("admin")
        resp = c.post("/api/v1/config/rollouts", json={
            "profile_id": profile_id,
            "policy": "staged",
            "initial_percentage": 99,
        })
        assert resp.status_code == 201

        # Add node assignments so the staged targeting logic finds them
        conn = get_db(app.config["DATABASE_PATH"])
        try:
            for nid in ["node-staged-1", "node-staged-2"]:
                conn.execute(
                    "INSERT OR IGNORE INTO nodes (node_id) VALUES (?)",
                    (nid,),
                )
                conn.execute(
                    "INSERT INTO config_assignments "
                    "(node_id, profile_id, assigned_by, is_active) "
                    "VALUES (?, ?, 'admin', 1)",
                    (nid, profile_id),
                )
            conn.commit()
        finally:
            conn.close()

        sse_mgr = app.config_sse_manager
        q1 = sse_mgr.create_client("node-staged-1")
        q2 = sse_mgr.create_client("node-staged-2")

        resp = c.put(
            f"/api/v1/config/profiles/{profile_id}",
            json={"change_reason": "Staged update"},
        )
        assert resp.status_code == 200

        # At 99%, both nodes should receive the event (very high probability)
        # We use 99% because the API rejects 100% for staged rollouts
        # Both nodes hash to buckets < 99 with very high probability
        # If a node doesn't receive it, it's because its hash bucket is >= 99
        # which is only 1% chance per node
        import hashlib as _h
        for nid, q in [("node-staged-1", q1), ("node-staged-2", q2)]:
            bucket = int(_h.sha256(nid.encode()).hexdigest(), 16) % 100
            if bucket < 99:
                assert not q.empty(), f"{nid} (bucket={bucket}) should have received event"
            else:
                assert q.empty(), f"{nid} (bucket={bucket}) should NOT have received event"

        sse_mgr.remove_client("node-staged-1")
        sse_mgr.remove_client("node-staged-2")

    def test_profile_update_staged_0_percent_excludes_all(
        self, app, auth_client, profile_id
    ):
        """With a staged rollout at 0%, no nodes receive the event."""
        # Create a staged rollout at 0% and add node assignments
        conn = get_db(app.config["DATABASE_PATH"])
        try:
            conn.execute(
                "INSERT INTO config_rollouts "
                "(profile_id, target_version, policy, status, current_percentage, created_by) "
                "VALUES (?, 1, 'staged', 'in_progress', 0, 'admin')",
                (profile_id,),
            )
            # Create node enrollments and assignments
            for nid in ["node-1", "node-2"]:
                conn.execute(
                    "INSERT OR IGNORE INTO nodes (node_id) VALUES (?)",
                    (nid,),
                )
                conn.execute(
                    "INSERT INTO config_assignments "
                    "(node_id, profile_id, assigned_by, is_active) "
                    "VALUES (?, ?, 'admin', 1)",
                    (nid, profile_id),
                )
            conn.commit()
        finally:
            conn.close()

        sse_mgr = app.config_sse_manager
        q1 = sse_mgr.create_client("node-1")
        q2 = sse_mgr.create_client("node-2")

        c = auth_client("admin")
        resp = c.put(
            f"/api/v1/config/profiles/{profile_id}",
            json={"change_reason": "Zero percent staged update"},
        )
        assert resp.status_code == 200

        # At 0%, no nodes should receive the event
        assert q1.empty()
        assert q2.empty()

        sse_mgr.remove_client("node-1")
        sse_mgr.remove_client("node-2")

    def test_profile_update_no_connected_clients_does_not_error(
        self, app, auth_client, profile_id
    ):
        """Updating a profile with no connected SSE clients should not raise an error."""
        c = auth_client("admin")
        resp = c.put(
            f"/api/v1/config/profiles/{profile_id}",
            json={"change_reason": "No clients connected"},
        )
        assert resp.status_code == 200

    def test_profile_update_404_does_not_publish_sse(self, app, auth_client):
        """A failed profile update (404) should not publish any SSE event."""
        sse_mgr = app.config_sse_manager
        q = sse_mgr.create_client("node-1")

        c = auth_client("admin")
        resp = c.put(
            "/api/v1/config/profiles/99999",
            json={"change_reason": "Should not publish"},
        )
        assert resp.status_code == 404
        assert q.empty()

        sse_mgr.remove_client("node-1")


# ── Rollout creation SSE publish tests ───────────────────────────────────


class TestRolloutCreationSSEPublish:
    """Tests that creating an immediate rollout publishes SSE events."""

    def test_immediate_rollout_publishes_sse_event(self, app, auth_client, profile_id):
        """Creating an immediate rollout should push a config_updated event to all agents."""
        sse_mgr = app.config_sse_manager
        q = sse_mgr.create_client("node-1")

        c = auth_client("admin")
        resp = c.post("/api/v1/config/rollouts", json={"profile_id": profile_id})
        assert resp.status_code == 201

        # The SSE event should have been published
        assert not q.empty()
        msg = q.get(timeout=1)
        assert "event: config_updated" in msg

        sse_mgr.remove_client("node-1")

    def test_immediate_rollout_event_contains_profile_data(self, app, auth_client, profile_id):
        """The SSE event from an immediate rollout should contain profile settings."""
        sse_mgr = app.config_sse_manager
        q = sse_mgr.create_client("node-1")

        c = auth_client("admin")
        resp = c.post("/api/v1/config/rollouts", json={"profile_id": profile_id})
        assert resp.status_code == 201
        rollout = resp.get_json()

        msg = q.get(timeout=1)

        # Parse the data line
        data_str = None
        for line in msg.split("\n"):
            if line.startswith("data: "):
                data_str = line[len("data: "):]
                break
        assert data_str is not None

        event_data = json.loads(data_str)
        assert event_data["profile_name"] == "sse-test-profile"
        assert event_data["version"] == rollout["target_version"]
        assert "settings" in event_data

        sse_mgr.remove_client("node-1")

    def test_immediate_rollout_pushes_to_all_connected_agents(self, app, auth_client, profile_id):
        """An immediate rollout should push to all connected agents (target_nodes=None)."""
        sse_mgr = app.config_sse_manager
        q1 = sse_mgr.create_client("node-1")
        q2 = sse_mgr.create_client("node-2")
        q3 = sse_mgr.create_client("node-3")

        c = auth_client("admin")
        resp = c.post("/api/v1/config/rollouts", json={"profile_id": profile_id})
        assert resp.status_code == 201

        assert not q1.empty()
        assert not q2.empty()
        assert not q3.empty()

        sse_mgr.remove_client("node-1")
        sse_mgr.remove_client("node-2")
        sse_mgr.remove_client("node-3")

    def test_canary_rollout_does_not_publish_sse(self, app, auth_client, profile_id):
        """Creating a canary rollout should NOT push an SSE event (agents wait for check-in)."""
        sse_mgr = app.config_sse_manager
        q = sse_mgr.create_client("node-1")

        c = auth_client("admin")
        resp = c.post("/api/v1/config/rollouts", json={
            "profile_id": profile_id,
            "policy": "canary",
            "canary_nodes": ["node-1"],
        })
        assert resp.status_code == 201

        # Canary rollout should NOT push SSE (only immediate does)
        assert q.empty()

        sse_mgr.remove_client("node-1")

    def test_staged_rollout_does_not_publish_sse(self, app, auth_client, profile_id):
        """Creating a staged rollout should NOT push an SSE event."""
        sse_mgr = app.config_sse_manager
        q = sse_mgr.create_client("node-1")

        c = auth_client("admin")
        resp = c.post("/api/v1/config/rollouts", json={
            "profile_id": profile_id,
            "policy": "staged",
            "initial_percentage": 25,
        })
        assert resp.status_code == 201

        # Staged rollout should NOT push SSE
        assert q.empty()

        sse_mgr.remove_client("node-1")

    def test_immediate_rollout_no_connected_clients_does_not_error(
        self, app, auth_client, profile_id
    ):
        """Creating an immediate rollout with no connected clients should not raise."""
        c = auth_client("admin")
        resp = c.post("/api/v1/config/rollouts", json={"profile_id": profile_id})
        assert resp.status_code == 201


# ── Staged rollout targeting helper tests ────────────────────────────────


class TestStagedRolloutTargeting:
    """Tests for the staged rollout percentage-based node targeting in SSE publish."""

    def test_staged_50_percent_targets_correct_nodes(self, app, auth_client, profile_id):
        """Staged rollout at 50% should target nodes deterministically by hash."""
        # Create a staged rollout at 50% directly in the DB
        conn = get_db(app.config["DATABASE_PATH"])
        try:
            conn.execute(
                "INSERT INTO config_rollouts "
                "(profile_id, target_version, policy, status, current_percentage, created_by) "
                "VALUES (?, 1, 'staged', 'in_progress', 50, 'admin')",
                (profile_id,),
            )
            # Create node enrollments and assignments for the test nodes
            test_nodes = [f"node-{i}" for i in range(20)]
            for nid in test_nodes:
                conn.execute(
                    "INSERT OR IGNORE INTO nodes (node_id) VALUES (?)",
                    (nid,),
                )
                conn.execute(
                    "INSERT INTO config_assignments "
                    "(node_id, profile_id, assigned_by, is_active) "
                    "VALUES (?, ?, 'admin', 1)",
                    (nid, profile_id),
                )
            conn.commit()
        finally:
            conn.close()

        # Determine which nodes should be in the 50% bucket
        expected_in = [
            nid for nid in test_nodes
            if (int(hashlib.sha256(nid.encode()).hexdigest(), 16) % 100) < 50
        ]
        expected_out = [nid for nid in test_nodes if nid not in expected_in]

        sse_mgr = app.config_sse_manager
        queues = {nid: sse_mgr.create_client(nid) for nid in test_nodes}

        c = auth_client("admin")
        resp = c.put(
            f"/api/v1/config/profiles/{profile_id}",
            json={"change_reason": "Staged 50% update"},
        )
        assert resp.status_code == 200

        # Nodes in the bucket should receive the event
        for nid in expected_in:
            assert not queues[nid].empty(), f"{nid} should have received event"

        # Nodes outside the bucket should NOT receive the event
        for nid in expected_out:
            assert queues[nid].empty(), f"{nid} should NOT have received event"

        for nid in test_nodes:
            sse_mgr.remove_client(nid)
