"""Tests for version history and rollback endpoints in config_management.py.

Validates Task 5.5 endpoints:
- GET /api/v1/config/profiles/<id>/history
- GET /api/v1/config/profiles/<id>/history/<ver>
- GET /api/v1/config/profiles/<id>/diff
- POST /api/v1/config/profiles/<id>/rollback

Requirements: 9.1, 9.2, 9.3, 9.4, 9.5, 9.6, 9.7, 9.8, 9.9, 11.1
"""

import json

import pytest


@pytest.fixture()
def admin_client(auth_client):
    """Return an authenticated admin client."""
    return auth_client("admin")


@pytest.fixture()
def analyst_client(auth_client):
    """Return an authenticated analyst client."""
    return auth_client("analyst")


@pytest.fixture()
def profile_with_history(admin_client):
    """Create a profile and update it twice to generate version history."""
    # Create profile (version 1)
    resp = admin_client.post(
        "/api/v1/config/profiles",
        json={
            "name": "test-history-profile",
            "settings": {"flush_interval_seconds": 30},
            "description": "Test profile for history",
        },
    )
    assert resp.status_code == 201
    profile = resp.get_json()
    profile_id = profile["id"]

    # Update to version 2
    resp = admin_client.put(
        f"/api/v1/config/profiles/{profile_id}",
        json={
            "settings": {"flush_interval_seconds": 60},
            "change_reason": "Increase flush interval",
        },
    )
    assert resp.status_code == 200

    # Update to version 3
    resp = admin_client.put(
        f"/api/v1/config/profiles/{profile_id}",
        json={
            "settings": {"flush_interval_seconds": 90, "flush_batch_size": 100},
            "change_reason": "Add batch size",
        },
    )
    assert resp.status_code == 200

    return profile_id


class TestVersionHistory:
    """Tests for GET /profiles/<id>/history."""

    def test_returns_version_history(self, analyst_client, profile_with_history):
        resp = analyst_client.get(
            f"/api/v1/config/profiles/{profile_with_history}/history"
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert "history" in data
        assert "total" in data
        assert data["total"] >= 2  # At least 2 updates
        assert data["page"] == 1
        assert data["per_page"] == 50

    def test_history_ordered_newest_first(self, analyst_client, profile_with_history):
        resp = analyst_client.get(
            f"/api/v1/config/profiles/{profile_with_history}/history"
        )
        data = resp.get_json()
        versions = [h["version"] for h in data["history"]]
        assert versions == sorted(versions, reverse=True)

    def test_history_pagination(self, analyst_client, profile_with_history):
        resp = analyst_client.get(
            f"/api/v1/config/profiles/{profile_with_history}/history?page=1&per_page=1"
        )
        data = resp.get_json()
        assert len(data["history"]) == 1
        assert data["per_page"] == 1

    def test_history_404_for_nonexistent_profile(self, analyst_client):
        resp = analyst_client.get("/api/v1/config/profiles/9999/history")
        assert resp.status_code == 404

    def test_history_requires_auth(self, client):
        resp = client.get("/api/v1/config/profiles/1/history")
        # Should redirect to login or return 401/403
        assert resp.status_code in (302, 401, 403)


class TestVersionDetail:
    """Tests for GET /profiles/<id>/history/<ver>."""

    def test_returns_version_settings(self, analyst_client, profile_with_history):
        resp = analyst_client.get(
            f"/api/v1/config/profiles/{profile_with_history}/history/2"
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["version"] == 2
        assert "settings" in data
        assert data["settings"]["flush_interval_seconds"] == 60

    def test_returns_latest_version_settings(self, analyst_client, profile_with_history):
        resp = analyst_client.get(
            f"/api/v1/config/profiles/{profile_with_history}/history/3"
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["version"] == 3
        assert data["settings"]["flush_interval_seconds"] == 90
        assert data["settings"]["flush_batch_size"] == 100

    def test_404_for_nonexistent_version(self, analyst_client, profile_with_history):
        resp = analyst_client.get(
            f"/api/v1/config/profiles/{profile_with_history}/history/999"
        )
        assert resp.status_code == 404

    def test_404_for_nonexistent_profile(self, analyst_client):
        resp = analyst_client.get("/api/v1/config/profiles/9999/history/1")
        assert resp.status_code == 404


class TestVersionDiff:
    """Tests for GET /profiles/<id>/diff."""

    def test_returns_diff_between_versions(self, analyst_client, profile_with_history):
        resp = analyst_client.get(
            f"/api/v1/config/profiles/{profile_with_history}/diff"
            "?from_version=2&to_version=3"
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["from_version"] == 2
        assert data["to_version"] == 3
        assert "diff" in data
        diff = data["diff"]
        assert "added" in diff
        assert "removed" in diff
        assert "modified" in diff
        # flush_batch_size was added in version 3
        assert "flush_batch_size" in diff["added"]
        # flush_interval_seconds changed from 60 to 90
        assert "flush_interval_seconds" in diff["modified"]

    def test_400_when_missing_from_version(self, analyst_client, profile_with_history):
        resp = analyst_client.get(
            f"/api/v1/config/profiles/{profile_with_history}/diff?to_version=3"
        )
        assert resp.status_code == 400

    def test_400_when_missing_to_version(self, analyst_client, profile_with_history):
        resp = analyst_client.get(
            f"/api/v1/config/profiles/{profile_with_history}/diff?from_version=2"
        )
        assert resp.status_code == 400

    def test_400_when_missing_both_params(self, analyst_client, profile_with_history):
        resp = analyst_client.get(
            f"/api/v1/config/profiles/{profile_with_history}/diff"
        )
        assert resp.status_code == 400

    def test_404_for_nonexistent_from_version(self, analyst_client, profile_with_history):
        resp = analyst_client.get(
            f"/api/v1/config/profiles/{profile_with_history}/diff"
            "?from_version=999&to_version=3"
        )
        assert resp.status_code == 404

    def test_404_for_nonexistent_to_version(self, analyst_client, profile_with_history):
        resp = analyst_client.get(
            f"/api/v1/config/profiles/{profile_with_history}/diff"
            "?from_version=2&to_version=999"
        )
        assert resp.status_code == 404

    def test_404_for_nonexistent_profile(self, analyst_client):
        resp = analyst_client.get(
            "/api/v1/config/profiles/9999/diff?from_version=1&to_version=2"
        )
        assert resp.status_code == 404


class TestRollback:
    """Tests for POST /profiles/<id>/rollback."""

    def test_rollback_creates_new_version(self, admin_client, profile_with_history):
        resp = admin_client.post(
            f"/api/v1/config/profiles/{profile_with_history}/rollback",
            json={"target_version": 2, "reason": "Reverting bad change"},
        )
        assert resp.status_code == 200
        data = resp.get_json()
        # Should be version 4 (was at 3, rollback increments)
        assert data["version"] == 4
        # Settings should match version 2
        assert data["settings"]["flush_interval_seconds"] == 60

    def test_rollback_records_audit(self, admin_client, profile_with_history, db):
        admin_client.post(
            f"/api/v1/config/profiles/{profile_with_history}/rollback",
            json={"target_version": 2, "reason": "Reverting bad change"},
        )
        # Check audit log
        row = db.execute(
            "SELECT * FROM audit_log WHERE action_type = 'config_profile_rollback' "
            "ORDER BY id DESC LIMIT 1"
        ).fetchone()
        assert row is not None
        details = json.loads(row["details"])
        assert details["target_version"] == 2
        assert details["source_version"] == 3

    def test_rollback_404_for_nonexistent_version(self, admin_client, profile_with_history):
        resp = admin_client.post(
            f"/api/v1/config/profiles/{profile_with_history}/rollback",
            json={"target_version": 999, "reason": "Bad version"},
        )
        assert resp.status_code == 404

    def test_rollback_404_for_nonexistent_profile(self, admin_client):
        resp = admin_client.post(
            "/api/v1/config/profiles/9999/rollback",
            json={"target_version": 1, "reason": "No profile"},
        )
        assert resp.status_code == 404

    def test_rollback_422_when_missing_target_version(self, admin_client, profile_with_history):
        resp = admin_client.post(
            f"/api/v1/config/profiles/{profile_with_history}/rollback",
            json={"reason": "Missing version"},
        )
        assert resp.status_code == 422

    def test_rollback_422_when_missing_reason(self, admin_client, profile_with_history):
        resp = admin_client.post(
            f"/api/v1/config/profiles/{profile_with_history}/rollback",
            json={"target_version": 2},
        )
        assert resp.status_code == 422

    def test_rollback_requires_admin_role(self, analyst_client, profile_with_history):
        resp = analyst_client.post(
            f"/api/v1/config/profiles/{profile_with_history}/rollback",
            json={"target_version": 2, "reason": "Should fail"},
        )
        assert resp.status_code == 403
