"""Tests for config assignment, group, rollout, and agent status query helpers.

Validates the query helper functions added in Task 1.3 for centralized
agent management.
"""

import json
import sqlite3

import pytest

from app.models import (
    add_group_member,
    create_agent_group,
    create_assignment,
    create_rollout,
    deactivate_assignment,
    delete_agent_group,
    get_active_rollout,
    get_agent_config_status,
    get_db,
    init_db,
    list_agent_groups,
    list_assignments_for_profile,
    remove_group_member,
    update_rollout_status,
    upsert_agent_config_status,
)


@pytest.fixture()
def db(tmp_path):
    """Return an initialized database connection with a test profile."""
    db_path = str(tmp_path / "test.db")
    init_db(db_path)
    conn = get_db(db_path)
    # Create a test profile for foreign key references
    conn.execute(
        "INSERT INTO config_profiles (name, name_lower, settings, created_by) "
        "VALUES ('test-profile', 'test-profile', '{\"allowlist\": []}', 'admin')"
    )
    conn.commit()
    yield conn
    conn.close()


# ── Assignment tests ─────────────────────────────────────────────────────


class TestCreateAssignment:
    def test_creates_direct_assignment(self, db):
        result = create_assignment(db, profile_id=1, assigned_by="admin", node_id="node-1")
        assert result["node_id"] == "node-1"
        assert result["profile_id"] == 1
        assert result["assigned_by"] == "admin"
        assert result["is_active"] == 1

    def test_creates_group_assignment(self, db):
        group = create_agent_group(db, name="grp", created_by="admin")
        result = create_assignment(db, profile_id=1, assigned_by="admin", group_id=group["id"])
        assert result["group_id"] == group["id"]
        assert result["node_id"] is None
        assert result["is_active"] == 1

    def test_deactivates_previous_assignment_for_same_node(self, db):
        a1 = create_assignment(db, profile_id=1, assigned_by="admin", node_id="node-1")
        a2 = create_assignment(db, profile_id=1, assigned_by="admin", node_id="node-1")

        # First assignment should be deactivated
        row = db.execute(
            "SELECT is_active FROM config_assignments WHERE id = ?", (a1["id"],)
        ).fetchone()
        assert row["is_active"] == 0
        assert a2["is_active"] == 1


class TestDeactivateAssignment:
    def test_deactivates_existing(self, db):
        a = create_assignment(db, profile_id=1, assigned_by="admin", node_id="node-1")
        assert deactivate_assignment(db, a["id"]) is True

        row = db.execute(
            "SELECT is_active FROM config_assignments WHERE id = ?", (a["id"],)
        ).fetchone()
        assert row["is_active"] == 0

    def test_returns_false_for_nonexistent(self, db):
        assert deactivate_assignment(db, 9999) is False

    def test_returns_false_for_already_inactive(self, db):
        a = create_assignment(db, profile_id=1, assigned_by="admin", node_id="node-1")
        deactivate_assignment(db, a["id"])
        assert deactivate_assignment(db, a["id"]) is False


class TestListAssignmentsForProfile:
    def test_returns_active_assignments(self, db):
        create_assignment(db, profile_id=1, assigned_by="admin", node_id="node-1")
        create_assignment(db, profile_id=1, assigned_by="admin", node_id="node-2")

        result = list_assignments_for_profile(db, profile_id=1)
        assert result["total"] == 2
        assert len(result["assignments"]) == 2
        assert result["page"] == 1
        assert result["per_page"] == 50

    def test_excludes_inactive_assignments(self, db):
        a = create_assignment(db, profile_id=1, assigned_by="admin", node_id="node-1")
        deactivate_assignment(db, a["id"])

        result = list_assignments_for_profile(db, profile_id=1)
        assert result["total"] == 0

    def test_pagination(self, db):
        for i in range(5):
            create_assignment(db, profile_id=1, assigned_by="admin", node_id=f"node-{i}")

        result = list_assignments_for_profile(db, profile_id=1, page=1, per_page=2)
        assert result["total"] == 5
        assert len(result["assignments"]) == 2
        assert result["per_page"] == 2


# ── Group tests ──────────────────────────────────────────────────────────


class TestCreateAgentGroup:
    def test_creates_group(self, db):
        result = create_agent_group(db, name="production", created_by="admin", description="Prod")
        assert result["name"] == "production"
        assert result["description"] == "Prod"
        assert result["created_by"] == "admin"

    def test_unique_name_constraint(self, db):
        create_agent_group(db, name="production", created_by="admin")
        with pytest.raises(sqlite3.IntegrityError):
            create_agent_group(db, name="production", created_by="admin")


class TestListAgentGroups:
    def test_lists_groups(self, db):
        create_agent_group(db, name="group-1", created_by="admin")
        create_agent_group(db, name="group-2", created_by="admin")

        result = list_agent_groups(db)
        assert result["total"] == 2
        assert len(result["groups"]) == 2

    def test_pagination(self, db):
        for i in range(5):
            create_agent_group(db, name=f"group-{i}", created_by="admin")

        result = list_agent_groups(db, page=2, per_page=2)
        assert result["total"] == 5
        assert len(result["groups"]) == 2
        assert result["page"] == 2


class TestDeleteAgentGroup:
    def test_deletes_group(self, db):
        g = create_agent_group(db, name="test", created_by="admin")
        assert delete_agent_group(db, g["id"]) is True

        row = db.execute("SELECT id FROM agent_groups WHERE id = ?", (g["id"],)).fetchone()
        assert row is None

    def test_cascades_memberships(self, db):
        g = create_agent_group(db, name="test", created_by="admin")
        add_group_member(db, group_id=g["id"], node_id="node-1", added_by="admin")

        delete_agent_group(db, g["id"])

        members = db.execute(
            "SELECT * FROM agent_group_members WHERE group_id = ?", (g["id"],)
        ).fetchall()
        assert len(members) == 0

    def test_cascades_assignments(self, db):
        g = create_agent_group(db, name="test", created_by="admin")
        create_assignment(db, profile_id=1, assigned_by="admin", group_id=g["id"])

        delete_agent_group(db, g["id"])

        assignments = db.execute(
            "SELECT * FROM config_assignments WHERE group_id = ? AND is_active = 1",
            (g["id"],),
        ).fetchall()
        assert len(assignments) == 0

    def test_returns_false_for_nonexistent(self, db):
        assert delete_agent_group(db, 9999) is False


class TestGroupMembers:
    def test_add_member(self, db):
        g = create_agent_group(db, name="test", created_by="admin")
        m = add_group_member(db, group_id=g["id"], node_id="node-1", added_by="admin")
        assert m["group_id"] == g["id"]
        assert m["node_id"] == "node-1"
        assert m["added_by"] == "admin"

    def test_unique_constraint(self, db):
        g = create_agent_group(db, name="test", created_by="admin")
        add_group_member(db, group_id=g["id"], node_id="node-1", added_by="admin")
        with pytest.raises(sqlite3.IntegrityError):
            add_group_member(db, group_id=g["id"], node_id="node-1", added_by="admin")

    def test_remove_member(self, db):
        g = create_agent_group(db, name="test", created_by="admin")
        add_group_member(db, group_id=g["id"], node_id="node-1", added_by="admin")
        assert remove_group_member(db, group_id=g["id"], node_id="node-1") is True

    def test_remove_nonexistent_member(self, db):
        g = create_agent_group(db, name="test", created_by="admin")
        assert remove_group_member(db, group_id=g["id"], node_id="node-999") is False


# ── Rollout tests ────────────────────────────────────────────────────────


class TestCreateRollout:
    def test_creates_immediate_rollout(self, db):
        r = create_rollout(db, profile_id=1, target_version=2, created_by="admin")
        assert r["profile_id"] == 1
        assert r["target_version"] == 2
        assert r["policy"] == "immediate"
        assert r["status"] == "pending"
        assert r["current_percentage"] == 100

    def test_creates_canary_rollout(self, db):
        r = create_rollout(
            db, profile_id=1, target_version=2, created_by="admin",
            policy="canary", canary_nodes=["node-1", "node-2"],
        )
        assert r["policy"] == "canary"
        assert json.loads(r["canary_nodes"]) == ["node-1", "node-2"]

    def test_creates_staged_rollout(self, db):
        r = create_rollout(
            db, profile_id=1, target_version=2, created_by="admin",
            policy="staged", current_percentage=25,
        )
        assert r["policy"] == "staged"
        assert r["current_percentage"] == 25


class TestUpdateRolloutStatus:
    def test_updates_status(self, db):
        r = create_rollout(db, profile_id=1, target_version=2, created_by="admin")
        assert update_rollout_status(db, r["id"], "in_progress") is True

        row = db.execute(
            "SELECT status FROM config_rollouts WHERE id = ?", (r["id"],)
        ).fetchone()
        assert row["status"] == "in_progress"

    def test_updates_counts(self, db):
        r = create_rollout(db, profile_id=1, target_version=2, created_by="admin")
        update_rollout_status(db, r["id"], "in_progress", failure_count=2, success_count=8)

        row = db.execute(
            "SELECT failure_count, success_count FROM config_rollouts WHERE id = ?",
            (r["id"],),
        ).fetchone()
        assert row["failure_count"] == 2
        assert row["success_count"] == 8

    def test_sets_completed_at_on_terminal_status(self, db):
        r = create_rollout(db, profile_id=1, target_version=2, created_by="admin")
        update_rollout_status(db, r["id"], "completed")

        row = db.execute(
            "SELECT completed_at FROM config_rollouts WHERE id = ?", (r["id"],)
        ).fetchone()
        assert row["completed_at"] is not None

    def test_returns_false_for_nonexistent(self, db):
        assert update_rollout_status(db, 9999, "failed") is False


class TestGetActiveRollout:
    def test_returns_active_rollout(self, db):
        create_rollout(db, profile_id=1, target_version=2, created_by="admin")
        result = get_active_rollout(db, profile_id=1)
        assert result is not None
        assert result["status"] == "pending"

    def test_returns_none_when_no_active(self, db):
        assert get_active_rollout(db, profile_id=1) is None

    def test_returns_none_after_completion(self, db):
        r = create_rollout(db, profile_id=1, target_version=2, created_by="admin")
        update_rollout_status(db, r["id"], "completed")
        assert get_active_rollout(db, profile_id=1) is None


# ── Agent status tests ───────────────────────────────────────────────────


class TestUpsertAgentConfigStatus:
    def test_inserts_new_record(self, db):
        upsert_agent_config_status(
            db, "node-1",
            profile_id=1,
            management_mode="server-managed",
            config_status="up_to_date",
        )
        status = get_agent_config_status(db, "node-1")
        assert status["node_id"] == "node-1"
        assert status["management_mode"] == "server-managed"
        assert status["config_status"] == "up_to_date"

    def test_updates_existing_record(self, db):
        upsert_agent_config_status(db, "node-1", management_mode="standalone")
        upsert_agent_config_status(db, "node-1", management_mode="server-managed", acknowledged_version=5)

        status = get_agent_config_status(db, "node-1")
        assert status["management_mode"] == "server-managed"
        assert status["acknowledged_version"] == 5

    def test_ignores_invalid_fields(self, db):
        upsert_agent_config_status(db, "node-1", invalid_field="ignored", management_mode="standalone")
        status = get_agent_config_status(db, "node-1")
        assert status["management_mode"] == "standalone"


class TestGetAgentConfigStatus:
    def test_returns_none_for_nonexistent(self, db):
        assert get_agent_config_status(db, "node-999") is None

    def test_returns_full_record(self, db):
        upsert_agent_config_status(
            db, "node-1",
            profile_id=1,
            acknowledged_version=3,
            management_mode="server-managed",
            config_status="pending",
            agent_version="2.0.0",
            health_uptime=7200,
            health_active_rules=10,
            health_blocked_ips=42,
        )
        status = get_agent_config_status(db, "node-1")
        assert status["profile_id"] == 1
        assert status["acknowledged_version"] == 3
        assert status["agent_version"] == "2.0.0"
        assert status["health_uptime"] == 7200
        assert status["health_active_rules"] == 10
        assert status["health_blocked_ips"] == 42
