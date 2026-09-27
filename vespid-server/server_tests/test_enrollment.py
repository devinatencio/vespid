"""Property-based tests for enrollment API endpoints.

Uses Hypothesis to verify correctness properties of the enrollment service
across randomised inputs. Each test is annotated with the property number
and the requirements it validates.

Feature: auto-enrollment
"""

import hashlib
import json

import pytest
from hypothesis import given, settings, strategies as st, assume, HealthCheck

from app import create_app
from app.enrollment_models import (
    create_enrollment_request,
    approve_enrollment,
    get_enrollment_settings,
    mark_credentials_retrieved,
    revoke_enrollment,
    update_enrollment_setting,
)
from app.models import get_db, init_db, create_api_key, create_user


# ── Fixtures ─────────────────────────────────────────────────────────────


@pytest.fixture()
def app(tmp_path):
    """Create a Flask app with test config and in-memory SQLite."""
    db_path = str(tmp_path / "test_enrollment.db")
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({
        "SECRET_KEY": "test-secret-key-for-enrollment",
        "DATABASE_PATH": db_path,
        "DEBUG": False,
        "RATELIMIT_ENABLED": False,
    }))
    application = create_app(str(config_file))
    application.config["TESTING"] = True
    application.config["WTF_CSRF_ENABLED"] = False
    return application


@pytest.fixture()
def client(app):
    """Return a Flask test client bound to the test app."""
    return app.test_client()


# ── Hypothesis Strategies ────────────────────────────────────────────────

# Valid node_id: non-empty strings with printable ASCII characters (no whitespace-only)
VALID_NODE_ID_CHARS = st.characters(
    whitelist_categories=("L", "N"),
    whitelist_characters="-_.",
)

st_node_id = st.text(alphabet=VALID_NODE_ID_CHARS, min_size=1, max_size=30).filter(
    lambda s: s.strip() != ""
)

# Valid hostname: non-empty strings with hostname-valid characters
VALID_HOSTNAME_CHARS = st.characters(
    whitelist_categories=("L", "N"),
    whitelist_characters="-_.",
)

st_hostname = st.text(alphabet=VALID_HOSTNAME_CHARS, min_size=1, max_size=50).filter(
    lambda s: s.strip() != ""
)


@st.composite
def st_enrollment_request(draw):
    """Composite strategy that generates a valid enrollment request body."""
    node_id = draw(st_node_id)
    hostname = draw(st_hostname)
    return {"node_id": node_id, "hostname": hostname}


# ── Helpers ──────────────────────────────────────────────────────────────


def enable_enrollment(app, mode="open"):
    """Enable enrollment with the specified mode in the test database."""
    db = get_db(app.config["DATABASE_PATH"])
    try:
        update_enrollment_setting(db, "enrollment_enabled", "true", "test")
        update_enrollment_setting(db, "enrollment_mode", mode, "test")
    finally:
        db.close()


def disable_enrollment(app):
    """Disable enrollment in the test database."""
    db = get_db(app.config["DATABASE_PATH"])
    try:
        update_enrollment_setting(db, "enrollment_enabled", "false", "test")
    finally:
        db.close()


def count_enrollment_records(app):
    """Count total enrollment records in the database."""
    db = get_db(app.config["DATABASE_PATH"])
    try:
        row = db.execute("SELECT COUNT(*) as cnt FROM enrollment_requests").fetchone()
        return row["cnt"]
    finally:
        db.close()


def clear_enrollment_records(app):
    """Remove all enrollment records from the database."""
    db = get_db(app.config["DATABASE_PATH"])
    try:
        db.execute("DELETE FROM enrollment_requests")
        db.commit()
    finally:
        db.close()


# ── Property 1: Disabled enrollment rejects all requests ─────────────────
# **Validates: Requirements 1.2**


class TestDisabledEnrollmentRejectsAll:
    """Property 1: Disabled enrollment rejects all requests.

    For any valid enrollment request, when auto-enrollment is globally
    disabled, the endpoint returns HTTP 403 and no new enrollment records
    are created.
    """

    @given(req=st_enrollment_request())
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_disabled_enrollment_returns_403(self, app, client, req):
        """**Validates: Requirements 1.2**"""
        # Ensure enrollment is disabled
        disable_enrollment(app)
        clear_enrollment_records(app)

        count_before = count_enrollment_records(app)

        response = client.post(
            "/api/v1/enroll",
            json=req,
            content_type="application/json",
        )

        assert response.status_code == 403, (
            f"Expected 403 when enrollment disabled, got {response.status_code}"
        )

        data = response.get_json()
        assert data["error"] == "enrollment_disabled"

        count_after = count_enrollment_records(app)
        assert count_after == count_before, (
            f"No records should be created when disabled. "
            f"Before: {count_before}, After: {count_after}"
        )


# ── Property 2: Open enrollment issues correctly restricted credentials ──
# **Validates: Requirements 2.1, 2.2, 2.3, 5.1, 5.3, 5.4**


class TestOpenEnrollmentIssuesCredentials:
    """Property 2: Open enrollment issues correctly restricted credentials.

    For any valid enrollment request while mode is `open`, the service
    returns a response containing a raw API token, and the DB contains an
    API key with correct key_hash (SHA-256 of token), key_prefix (first 8
    chars), node_id_restriction matching the requesting node_id, and
    enrollment record with status `approved`.
    """

    @given(req=st_enrollment_request())
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_open_enrollment_issues_correct_credentials(self, app, client, req):
        """**Validates: Requirements 2.1, 2.2, 2.3, 5.1, 5.3, 5.4**"""
        enable_enrollment(app, mode="open")
        clear_enrollment_records(app)

        response = client.post(
            "/api/v1/enroll",
            json=req,
            content_type="application/json",
        )

        assert response.status_code == 200, (
            f"Expected 200 for open enrollment, got {response.status_code}"
        )

        data = response.get_json()
        assert "api_key" in data, "Response must contain api_key"
        assert data["status"] == "approved"
        assert data["node_id"] == req["node_id"]

        raw_token = data["api_key"]

        # Verify the DB contains the correct API key
        expected_hash = hashlib.sha256(raw_token.encode()).hexdigest()
        expected_prefix = raw_token[:8]

        db = get_db(app.config["DATABASE_PATH"])
        try:
            # Check API key record
            key_row = db.execute(
                "SELECT * FROM api_keys WHERE key_hash = ?",
                (expected_hash,),
            ).fetchone()
            assert key_row is not None, "API key with correct hash not found in DB"
            assert key_row["key_prefix"] == expected_prefix, (
                f"Expected prefix '{expected_prefix}', got '{key_row['key_prefix']}'"
            )
            assert key_row["node_id_restriction"] == req["node_id"], (
                f"Expected node_id_restriction '{req['node_id']}', "
                f"got '{key_row['node_id_restriction']}'"
            )

            # Check enrollment record
            enroll_row = db.execute(
                "SELECT * FROM enrollment_requests WHERE node_id = ? "
                "ORDER BY requested_at DESC LIMIT 1",
                (req["node_id"],),
            ).fetchone()
            assert enroll_row is not None, "Enrollment record not found"
            assert enroll_row["status"] == "approved", (
                f"Expected status 'approved', got '{enroll_row['status']}'"
            )
        finally:
            db.close()


# ── Property 3: Manual enrollment creates pending record ─────────────────
# **Validates: Requirements 3.1**


class TestManualEnrollmentCreatesPending:
    """Property 3: Manual enrollment creates pending record.

    For any valid enrollment request while mode is `manual_approval`, the
    service returns HTTP 202 and the DB contains an enrollment record with
    status `pending` and no associated API key.
    """

    @given(req=st_enrollment_request())
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_manual_enrollment_creates_pending(self, app, client, req):
        """**Validates: Requirements 3.1**"""
        enable_enrollment(app, mode="manual_approval")
        clear_enrollment_records(app)

        response = client.post(
            "/api/v1/enroll",
            json=req,
            content_type="application/json",
        )

        assert response.status_code == 202, (
            f"Expected 202 for manual_approval mode, got {response.status_code}"
        )

        data = response.get_json()
        assert data["status"] == "pending"
        assert data["node_id"] == req["node_id"]

        # Verify DB record
        db = get_db(app.config["DATABASE_PATH"])
        try:
            row = db.execute(
                "SELECT * FROM enrollment_requests WHERE node_id = ? "
                "ORDER BY requested_at DESC LIMIT 1",
                (req["node_id"],),
            ).fetchone()
            assert row is not None, "Enrollment record not found"
            assert row["status"] == "pending"
            assert row["api_key_id"] is None, (
                "Pending record should have no associated API key"
            )
        finally:
            db.close()


# ── Property 6: Invalid enrollment requests are rejected ─────────────────
# **Validates: Requirements 4.1, 4.2**


# Strategies for invalid requests
st_empty_or_missing_node_id = st.sampled_from([
    {},  # missing node_id entirely
    {"node_id": ""},  # empty node_id
    {"node_id": "   "},  # whitespace-only node_id
])

st_empty_or_missing_hostname = st.sampled_from([
    {},  # missing hostname entirely
    {"hostname": ""},  # empty hostname
    {"hostname": "   "},  # whitespace-only hostname
])


@st.composite
def st_invalid_enrollment_request(draw):
    """Generate an enrollment request with at least one invalid field."""
    # Decide which fields to make invalid
    invalid_choice = draw(st.sampled_from([
        "missing_node_id",
        "missing_hostname",
        "both_missing",
        "empty_node_id",
        "empty_hostname",
        "both_empty",
    ]))

    valid_node_id = draw(st_node_id)
    valid_hostname = draw(st_hostname)

    if invalid_choice == "missing_node_id":
        return {"hostname": valid_hostname}
    elif invalid_choice == "missing_hostname":
        return {"node_id": valid_node_id}
    elif invalid_choice == "both_missing":
        return {}
    elif invalid_choice == "empty_node_id":
        return {"node_id": "", "hostname": valid_hostname}
    elif invalid_choice == "empty_hostname":
        return {"node_id": valid_node_id, "hostname": ""}
    elif invalid_choice == "both_empty":
        return {"node_id": "", "hostname": ""}
    return {}


class TestInvalidEnrollmentRejected:
    """Property 6: Invalid enrollment requests are rejected with field-specific errors.

    For any request where node_id is empty/missing OR hostname is empty/missing,
    the service returns HTTP 400 with error message listing each missing field,
    and no new enrollment records are created.
    """

    @given(req=st_invalid_enrollment_request())
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_invalid_request_returns_400(self, app, client, req):
        """**Validates: Requirements 4.1, 4.2**"""
        enable_enrollment(app, mode="open")
        clear_enrollment_records(app)

        count_before = count_enrollment_records(app)

        response = client.post(
            "/api/v1/enroll",
            json=req,
            content_type="application/json",
        )

        assert response.status_code == 400, (
            f"Expected 400 for invalid request {req}, got {response.status_code}"
        )

        data = response.get_json()
        assert data["error"] == "validation_error"
        assert "missing_fields" in data

        # Verify the missing fields are correctly identified
        node_id = req.get("node_id", "")
        hostname = req.get("hostname", "")

        if not node_id or not node_id.strip():
            assert "node_id" in data["missing_fields"], (
                f"Expected 'node_id' in missing_fields for request {req}"
            )
        if not hostname or not hostname.strip():
            assert "hostname" in data["missing_fields"], (
                f"Expected 'hostname' in missing_fields for request {req}"
            )

        count_after = count_enrollment_records(app)
        assert count_after == count_before, (
            f"No records should be created for invalid requests. "
            f"Before: {count_before}, After: {count_after}"
        )


# ── Property 7: Duplicate enrollment returns 409 ─────────────────────────
# **Validates: Requirements 4.3, 4.4**


class TestDuplicateEnrollmentReturns409:
    """Property 7: Duplicate enrollment returns 409.

    For any node_id that already has a pending or approved enrollment record,
    a new request returns HTTP 409 and the existing record remains unchanged.
    """

    @given(req=st_enrollment_request(), mode=st.sampled_from(["open", "manual_approval"]))
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_duplicate_enrollment_returns_409(self, app, client, req, mode):
        """**Validates: Requirements 4.3, 4.4**"""
        enable_enrollment(app, mode=mode)
        clear_enrollment_records(app)

        # First request should succeed
        response1 = client.post(
            "/api/v1/enroll",
            json=req,
            content_type="application/json",
        )
        expected_first_status = 200 if mode == "open" else 202
        assert response1.status_code == expected_first_status, (
            f"First request expected {expected_first_status}, got {response1.status_code}"
        )

        # Capture the record state after first request
        db = get_db(app.config["DATABASE_PATH"])
        try:
            original_row = db.execute(
                "SELECT * FROM enrollment_requests WHERE node_id = ? "
                "ORDER BY requested_at DESC LIMIT 1",
                (req["node_id"],),
            ).fetchone()
            original_record = dict(original_row)
        finally:
            db.close()

        # Second request with same node_id should return 409
        response2 = client.post(
            "/api/v1/enroll",
            json=req,
            content_type="application/json",
        )

        assert response2.status_code == 409, (
            f"Expected 409 for duplicate enrollment, got {response2.status_code}"
        )

        # Verify the existing record is unchanged
        db = get_db(app.config["DATABASE_PATH"])
        try:
            current_row = db.execute(
                "SELECT * FROM enrollment_requests WHERE node_id = ? "
                "ORDER BY requested_at DESC LIMIT 1",
                (req["node_id"],),
            ).fetchone()
            current_record = dict(current_row)
        finally:
            db.close()

        assert current_record["status"] == original_record["status"]
        assert current_record["id"] == original_record["id"]


# ── Property 10: Status endpoint returns correct response per state ──────
# **Validates: Requirements 13.2, 13.5**


class TestStatusEndpointResponses:
    """Property 10: Status endpoint returns correct response per enrollment state.

    For any node_id, the status endpoint returns: 404 if no record exists,
    202 if pending, 403 if rejected/revoked, 200 with credentials if approved
    and not yet retrieved.
    """

    @given(node_id=st_node_id)
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_status_404_when_no_record(self, app, client, node_id):
        """**Validates: Requirements 13.5**

        Status endpoint returns 404 if no enrollment record exists.
        """
        clear_enrollment_records(app)

        response = client.get(f"/api/v1/enroll/status/{node_id}")
        assert response.status_code == 404, (
            f"Expected 404 for unknown node_id, got {response.status_code}"
        )

    @given(req=st_enrollment_request())
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_status_202_when_pending(self, app, client, req):
        """**Validates: Requirements 13.2**

        Status endpoint returns 202 if the record status is pending.
        """
        enable_enrollment(app, mode="manual_approval")
        clear_enrollment_records(app)

        # Create a pending enrollment
        client.post("/api/v1/enroll", json=req, content_type="application/json")

        response = client.get(f"/api/v1/enroll/status/{req['node_id']}")
        assert response.status_code == 202, (
            f"Expected 202 for pending record, got {response.status_code}"
        )
        data = response.get_json()
        assert data["status"] == "pending"

    @given(req=st_enrollment_request())
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_status_403_when_rejected(self, app, client, req):
        """**Validates: Requirements 13.2**

        Status endpoint returns 403 if the record status is rejected.
        """
        enable_enrollment(app, mode="manual_approval")
        clear_enrollment_records(app)

        # Create and reject an enrollment
        db = get_db(app.config["DATABASE_PATH"])
        try:
            record = create_enrollment_request(db, req["node_id"], req["hostname"], "127.0.0.1")
            from app.enrollment_models import reject_enrollment
            reject_enrollment(db, record["id"], "admin")
        finally:
            db.close()

        response = client.get(f"/api/v1/enroll/status/{req['node_id']}")
        assert response.status_code == 403, (
            f"Expected 403 for rejected record, got {response.status_code}"
        )

    @given(req=st_enrollment_request())
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_status_200_when_approved_not_retrieved(self, app, client, req):
        """**Validates: Requirements 13.2**

        Status endpoint returns 200 with credentials if approved and not yet retrieved.
        """
        enable_enrollment(app, mode="manual_approval")
        clear_enrollment_records(app)

        # Create and approve an enrollment
        db = get_db(app.config["DATABASE_PATH"])
        try:
            record = create_enrollment_request(db, req["node_id"], req["hostname"], "127.0.0.1")
            approve_enrollment(db, record["id"], "admin")
        finally:
            db.close()

        response = client.get(f"/api/v1/enroll/status/{req['node_id']}")
        assert response.status_code == 200, (
            f"Expected 200 for approved record, got {response.status_code}"
        )
        data = response.get_json()
        assert data["status"] == "approved"
        assert "api_key" in data, "First retrieval should include api_key"


# ── Property 11: Credentials are retrievable exactly once ────────────────
# **Validates: Requirements 13.3**


class TestCredentialsRetrievableOnce:
    """Property 11: Credentials are retrievable exactly once.

    For any approved enrollment record where credentials have not been
    retrieved, the first GET returns the raw API token and marks
    credentials_retrieved=1. Subsequent GETs return 200 without the token.
    """

    @given(req=st_enrollment_request())
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_credentials_retrievable_once(self, app, client, req):
        """**Validates: Requirements 13.3**"""
        enable_enrollment(app, mode="manual_approval")
        clear_enrollment_records(app)

        # Create and approve an enrollment
        db = get_db(app.config["DATABASE_PATH"])
        try:
            record = create_enrollment_request(db, req["node_id"], req["hostname"], "127.0.0.1")
            approve_enrollment(db, record["id"], "admin")
        finally:
            db.close()

        # First GET should return credentials
        response1 = client.get(f"/api/v1/enroll/status/{req['node_id']}")
        assert response1.status_code == 200
        data1 = response1.get_json()
        assert "api_key" in data1, "First retrieval must include api_key"
        assert data1["status"] == "approved"

        # Second GET should NOT return credentials
        response2 = client.get(f"/api/v1/enroll/status/{req['node_id']}")
        assert response2.status_code == 200
        data2 = response2.get_json()
        assert data2["status"] == "approved"
        assert "api_key" not in data2, (
            "Subsequent retrieval must NOT include api_key"
        )

        # Verify credentials_retrieved is set in DB
        db = get_db(app.config["DATABASE_PATH"])
        try:
            row = db.execute(
                "SELECT credentials_retrieved FROM enrollment_requests WHERE node_id = ?",
                (req["node_id"],),
            ).fetchone()
            assert row["credentials_retrieved"] == 1
        finally:
            db.close()


# ── Property 15: Restricted mode rejects requests without valid token ────
# **Validates: Requirements 14.1, 14.2**


class TestRestrictedModeRejectsWithoutToken:
    """Property 15: Restricted mode rejects requests without valid token.

    For any enrollment request while mode is `restricted`, if no valid token
    is provided, the service returns HTTP 403 and creates no enrollment record.
    """

    @given(req=st_enrollment_request())
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_restricted_mode_rejects_no_token(self, app, client, req):
        """**Validates: Requirements 14.1, 14.2**"""
        enable_enrollment(app, mode="restricted")
        clear_enrollment_records(app)

        count_before = count_enrollment_records(app)

        # Request without token
        response = client.post(
            "/api/v1/enroll",
            json=req,
            content_type="application/json",
        )

        assert response.status_code == 403, (
            f"Expected 403 for restricted mode without token, got {response.status_code}"
        )

        data = response.get_json()
        assert data["error"] == "invalid_token"

        count_after = count_enrollment_records(app)
        assert count_after == count_before, (
            f"No records should be created without valid token. "
            f"Before: {count_before}, After: {count_after}"
        )

    @given(req=st_enrollment_request())
    @settings(
        max_examples=20,
        deadline=None,
        suppress_health_check=[HealthCheck.function_scoped_fixture],
    )
    def test_restricted_mode_rejects_empty_token(self, app, client, req):
        """**Validates: Requirements 14.1, 14.2**"""
        enable_enrollment(app, mode="restricted")
        clear_enrollment_records(app)

        count_before = count_enrollment_records(app)

        # Request with empty token
        req_with_empty_token = {**req, "token": ""}
        response = client.post(
            "/api/v1/enroll",
            json=req_with_empty_token,
            content_type="application/json",
        )

        assert response.status_code == 403, (
            f"Expected 403 for restricted mode with empty token, got {response.status_code}"
        )

        data = response.get_json()
        assert data["error"] == "invalid_token"

        count_after = count_enrollment_records(app)
        assert count_after == count_before, (
            f"No records should be created with empty token. "
            f"Before: {count_before}, After: {count_after}"
        )


# ══════════════════════════════════════════════════════════════════════════
# Integration Tests — End-to-End Enrollment Flows
# ══════════════════════════════════════════════════════════════════════════


class TestOpenEnrollmentFlowIntegration:
    """Integration test: full open enrollment flow.

    Agent enrolls → credentials issued → agent authenticates with issued key.
    Validates: Requirements 2.1, 13.4
    """

    def test_open_enrollment_then_authenticate(self, app, client):
        """Agent enrolls in open mode and uses issued key to hit a protected endpoint."""
        enable_enrollment(app, mode="open")

        # Step 1: Agent enrolls
        response = client.post(
            "/api/v1/enroll",
            json={"node_id": "integ-node-001", "hostname": "integ-host.local"},
            content_type="application/json",
        )
        assert response.status_code == 200
        data = response.get_json()
        assert data["status"] == "approved"
        api_key = data["api_key"]
        assert api_key  # non-empty

        # Step 2: Agent authenticates with the issued key on a protected endpoint
        event_payload = {
            "events": [
                {
                    "event_id": "evt-integ-001",
                    "node_id": "integ-node-001",
                    "timestamp": "2025-01-15T10:00:00Z",
                    "source_ip": "192.168.1.100",
                    "event_type": "brute_force",
                    "action_taken": "block",
                    "geo_data": {},
                }
            ]
        }
        auth_response = client.post(
            "/api/v1/events",
            json=event_payload,
            headers={"Authorization": f"Bearer {api_key}"},
            content_type="application/json",
        )
        assert auth_response.status_code == 200
        auth_data = auth_response.get_json()
        assert auth_data["accepted"] == 1


class TestManualApprovalFlowIntegration:
    """Integration test: full manual approval flow.

    Agent enrolls → admin approves → agent retrieves credentials → agent authenticates.
    Validates: Requirements 3.1, 3.2, 13.4
    """

    def test_manual_approval_then_authenticate(self, app, client):
        """Agent enrolls in manual mode, admin approves, agent retrieves and uses key."""
        enable_enrollment(app, mode="manual_approval")

        # Step 1: Agent enrolls — gets 202 pending
        response = client.post(
            "/api/v1/enroll",
            json={"node_id": "manual-node-001", "hostname": "manual-host.local"},
            content_type="application/json",
        )
        assert response.status_code == 202
        data = response.get_json()
        assert data["status"] == "pending"

        # Step 2: Admin approves the enrollment
        db = get_db(app.config["DATABASE_PATH"])
        try:
            row = db.execute(
                "SELECT id FROM enrollment_requests WHERE node_id = ?",
                ("manual-node-001",),
            ).fetchone()
            record_id = row["id"]
            approve_enrollment(db, record_id, "admin-user")
        finally:
            db.close()

        # Step 3: Agent retrieves credentials via status endpoint
        status_response = client.get("/api/v1/enroll/status/manual-node-001")
        assert status_response.status_code == 200
        status_data = status_response.get_json()
        assert status_data["status"] == "approved"
        api_key = status_data["api_key"]
        assert api_key  # non-empty

        # Step 4: Agent authenticates with the retrieved key
        event_payload = {
            "events": [
                {
                    "event_id": "evt-manual-001",
                    "node_id": "manual-node-001",
                    "timestamp": "2025-01-15T11:00:00Z",
                    "source_ip": "10.0.0.50",
                    "event_type": "port_scan",
                    "action_taken": "log",
                    "geo_data": {},
                }
            ]
        }
        auth_response = client.post(
            "/api/v1/events",
            json=event_payload,
            headers={"Authorization": f"Bearer {api_key}"},
            content_type="application/json",
        )
        assert auth_response.status_code == 200
        auth_data = auth_response.get_json()
        assert auth_data["accepted"] == 1


class TestRotationFlowIntegration:
    """Integration test: credential rotation flow.

    Admin rotates → old key returns 401 → agent retrieves new credentials via status endpoint.
    Validates: Requirements 10.1, 10.2, 9.4
    """

    def test_rotation_old_key_fails_new_key_works(self, app, client):
        """After rotation, old key is rejected and new key works."""
        enable_enrollment(app, mode="open")

        # Step 1: Agent enrolls and gets initial credentials
        response = client.post(
            "/api/v1/enroll",
            json={"node_id": "rotate-node-001", "hostname": "rotate-host.local"},
            content_type="application/json",
        )
        assert response.status_code == 200
        old_api_key = response.get_json()["api_key"]

        # Verify old key works
        event_payload = {
            "events": [
                {
                    "event_id": "evt-rotate-001",
                    "node_id": "rotate-node-001",
                    "timestamp": "2025-01-15T12:00:00Z",
                    "source_ip": "172.16.0.1",
                    "event_type": "brute_force",
                    "action_taken": "block",
                    "geo_data": {},
                }
            ]
        }
        auth_response = client.post(
            "/api/v1/events",
            json=event_payload,
            headers={"Authorization": f"Bearer {old_api_key}"},
            content_type="application/json",
        )
        assert auth_response.status_code == 200

        # Step 2: Admin rotates credentials
        from app.enrollment_models import rotate_enrollment_credentials
        db = get_db(app.config["DATABASE_PATH"])
        try:
            row = db.execute(
                "SELECT id FROM enrollment_requests WHERE node_id = ?",
                ("rotate-node-001",),
            ).fetchone()
            record_id = row["id"]
            rotate_enrollment_credentials(db, record_id, "admin-user")
        finally:
            db.close()

        # Step 3: Old key now returns 401
        auth_response_old = client.post(
            "/api/v1/events",
            json=event_payload,
            headers={"Authorization": f"Bearer {old_api_key}"},
            content_type="application/json",
        )
        assert auth_response_old.status_code == 401

        # Step 4: Agent retrieves new credentials via status endpoint
        status_response = client.get("/api/v1/enroll/status/rotate-node-001")
        assert status_response.status_code == 200
        status_data = status_response.get_json()
        assert status_data["status"] == "approved"
        new_api_key = status_data["api_key"]
        assert new_api_key
        assert new_api_key != old_api_key

        # Step 5: New key works
        event_payload_2 = {
            "events": [
                {
                    "event_id": "evt-rotate-002",
                    "node_id": "rotate-node-001",
                    "timestamp": "2025-01-15T12:05:00Z",
                    "source_ip": "172.16.0.1",
                    "event_type": "brute_force",
                    "action_taken": "block",
                    "geo_data": {},
                }
            ]
        }
        auth_response_new = client.post(
            "/api/v1/events",
            json=event_payload_2,
            headers={"Authorization": f"Bearer {new_api_key}"},
            content_type="application/json",
        )
        assert auth_response_new.status_code == 200


class TestRevocationFlowIntegration:
    """Integration test: credential revocation flow.

    Admin revokes → agent gets 401 → status endpoint returns 403.
    Validates: Requirements 9.1, 9.4
    """

    def test_revocation_blocks_agent(self, app, client):
        """After revocation, agent key is rejected and status returns 403."""
        enable_enrollment(app, mode="open")

        # Step 1: Agent enrolls
        response = client.post(
            "/api/v1/enroll",
            json={"node_id": "revoke-node-001", "hostname": "revoke-host.local"},
            content_type="application/json",
        )
        assert response.status_code == 200
        api_key = response.get_json()["api_key"]

        # Verify key works initially
        event_payload = {
            "events": [
                {
                    "event_id": "evt-revoke-001",
                    "node_id": "revoke-node-001",
                    "timestamp": "2025-01-15T13:00:00Z",
                    "source_ip": "10.10.10.1",
                    "event_type": "port_scan",
                    "action_taken": "log",
                    "geo_data": {},
                }
            ]
        }
        auth_response = client.post(
            "/api/v1/events",
            json=event_payload,
            headers={"Authorization": f"Bearer {api_key}"},
            content_type="application/json",
        )
        assert auth_response.status_code == 200

        # Step 2: Admin revokes the enrollment
        from app.enrollment_models import revoke_enrollment
        db = get_db(app.config["DATABASE_PATH"])
        try:
            row = db.execute(
                "SELECT id FROM enrollment_requests WHERE node_id = ?",
                ("revoke-node-001",),
            ).fetchone()
            record_id = row["id"]
            revoke_enrollment(db, record_id, "admin-user")
        finally:
            db.close()

        # Step 3: Agent gets 401 when trying to authenticate
        auth_response_revoked = client.post(
            "/api/v1/events",
            json=event_payload,
            headers={"Authorization": f"Bearer {api_key}"},
            content_type="application/json",
        )
        assert auth_response_revoked.status_code == 401

        # Step 4: Status endpoint returns 403 (revoked)
        status_response = client.get("/api/v1/enroll/status/revoke-node-001")
        assert status_response.status_code == 403
        status_data = status_response.get_json()
        assert status_data["status"] == "revoked"


class TestRateLimitingIntegration:
    """Integration test: rate limiting on enrollment endpoint.

    Verifies 10 req/min limit — 11th request gets 429.
    Validates: Requirements 13.4
    """

    def test_enrollment_rate_limit(self, tmp_path):
        """Sending 11 requests to enrollment endpoint triggers rate limit on 11th."""
        # Create app with rate limiting ENABLED
        db_path = str(tmp_path / "test_ratelimit.db")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "SECRET_KEY": "test-secret-key-ratelimit",
            "DATABASE_PATH": db_path,
            "DEBUG": False,
            "RATELIMIT_ENABLED": True,
        }))
        application = create_app(str(config_file))
        application.config["TESTING"] = True
        application.config["WTF_CSRF_ENABLED"] = False

        # Enable enrollment
        db = get_db(db_path)
        try:
            update_enrollment_setting(db, "enrollment_enabled", "true", "test")
            update_enrollment_setting(db, "enrollment_mode", "open", "test")
        finally:
            db.close()

        test_client = application.test_client()

        # Send 10 requests (should all succeed or get 409 for duplicates)
        responses = []
        for i in range(11):
            resp = test_client.post(
                "/api/v1/enroll",
                json={"node_id": f"ratelimit-node-{i:03d}", "hostname": f"host-{i}.local"},
                content_type="application/json",
            )
            responses.append(resp.status_code)

        # The first 10 should succeed (200 for open mode)
        for i in range(10):
            assert responses[i] == 200, (
                f"Request {i+1} expected 200, got {responses[i]}"
            )

        # The 11th should be rate limited (429)
        assert responses[10] == 429, (
            f"Request 11 expected 429 (rate limited), got {responses[10]}"
        )


class TestDatabaseMigrationIntegration:
    """Integration test: database migration creates tables idempotently.

    Calling init_db twice should not raise errors and tables should exist.
    Validates: Requirements 15.3
    """

    def test_init_db_idempotent(self, tmp_path):
        """Calling init_db twice creates tables without errors."""
        db_path = str(tmp_path / "test_migration.db")

        # First call — creates all tables
        init_db(db_path)

        # Second call — should be idempotent (no errors)
        init_db(db_path)

        # Verify enrollment tables exist
        db = get_db(db_path)
        try:
            tables = {
                row[0]
                for row in db.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                ).fetchall()
            }
            assert "enrollment_requests" in tables
            assert "enrollment_settings" in tables
            assert "api_keys" in tables
            assert "events" in tables
            assert "users" in tables
            assert "audit_log" in tables

            # Verify enrollment settings are seeded
            settings = db.execute(
                "SELECT setting_key, setting_value FROM enrollment_settings"
            ).fetchall()
            settings_dict = {row["setting_key"]: row["setting_value"] for row in settings}
            assert settings_dict["enrollment_enabled"] == "false"
            assert settings_dict["enrollment_mode"] == "manual_approval"

            # Verify indexes exist
            indexes = {
                row[1]
                for row in db.execute("PRAGMA index_list(enrollment_requests)").fetchall()
            }
            assert "idx_enrollment_node_id" in indexes
            assert "idx_enrollment_status" in indexes
        finally:
            db.close()


# ── Auto-rotate & host_id linking tests ──────────────────────────────────
# **Validates: Requirements auto-rotate, host_id linking, X-Existing-Credentials**


class TestHostIdLinking:
    """host_id flows from request → DB row → response → agent store.

    The same host_id returned to the security agent on its first
    enrollment must be (1) persisted on the enrollment_requests row,
    (2) returned in the response, and (3) returned in subsequent
    /status lookups so the monitor agent can discover the linkage
    and present it on its own enrollment.
    """

    def test_open_enrollment_returns_host_id(self, app, client):
        """Open enrollment issues a server-minted host_id and stores it."""
        enable_enrollment(app, mode="open")
        clear_enrollment_records(app)

        response = client.post(
            "/api/v1/enroll",
            json={"node_id": "node-A", "hostname": "host-a"},
            content_type="application/json",
        )
        assert response.status_code == 200
        data = response.get_json()
        assert "host_id" in data
        assert len(data["host_id"]) == 32  # uuid4().hex format

        db = get_db(app.config["DATABASE_PATH"])
        try:
            row = db.execute(
                "SELECT host_id FROM enrollment_requests WHERE node_id = ?",
                ("node-A",),
            ).fetchone()
            assert row["host_id"] == data["host_id"]

            key_row = db.execute(
                "SELECT host_id FROM api_keys WHERE node_id_restriction = ?",
                ("node-A",),
            ).fetchone()
            assert key_row["host_id"] == data["host_id"]
        finally:
            db.close()

    def test_explicit_host_id_is_preserved(self, app, client):
        """A client-supplied host_id is preserved (security-agent link case)."""
        enable_enrollment(app, mode="open")
        clear_enrollment_records(app)

        explicit = "11111111-2222-3333-4444-555555555555"
        response = client.post(
            "/api/v1/enroll",
            json={
                "node_id": "node-B",
                "hostname": "host-b",
                "host_id": explicit,
            },
            content_type="application/json",
        )
        assert response.status_code == 200
        assert response.get_json()["host_id"] == explicit

    def test_source_is_persisted(self, app, client):
        """The ``source`` field is persisted on the enrollment row."""
        enable_enrollment(app, mode="open")
        clear_enrollment_records(app)

        client.post(
            "/api/v1/enroll",
            json={
                "node_id": "node-C",
                "hostname": "host-c",
                "source": "monitor",
            },
            content_type="application/json",
        )

        db = get_db(app.config["DATABASE_PATH"])
        try:
            row = db.execute(
                "SELECT source FROM enrollment_requests WHERE node_id = ?",
                ("node-C",),
            ).fetchone()
            assert row["source"] == "monitor"
        finally:
            db.close()

    def test_status_endpoint_returns_host_id(self, app, client):
        """The /status endpoint surfaces host_id for the agent to discover."""
        enable_enrollment(app, mode="open")
        clear_enrollment_records(app)

        client.post(
            "/api/v1/enroll",
            json={"node_id": "node-D", "hostname": "host-d"},
            content_type="application/json",
        )

        resp = client.get("/api/v1/enroll/status/node-D")
        assert resp.status_code == 200
        data = resp.get_json()
        assert "host_id" in data
        assert len(data["host_id"]) == 32


class TestAutoRotate:
    """Auto-rotate via X-Existing-Credentials header.

    The self-heal flow: an already-approved node re-enrolls with its
    current valid key, and the server revokes the old key + issues a
    new one in place. Mismatches (wrong host_id, revoked records,
    missing X-Existing-Credentials) must be rejected.
    """

    def _do_first_enroll(self, app, client, node_id="node-R", source="agent"):
        enable_enrollment(app, mode="open")
        clear_enrollment_records(app)
        resp = client.post(
            "/api/v1/enroll",
            json={"node_id": node_id, "hostname": "host-r", "source": source},
            content_type="application/json",
        )
        assert resp.status_code == 200
        return resp.get_json()

    def test_auto_rotate_with_valid_existing_credentials(self, app, client):
        """Self-heal: same node + valid X-Existing-Credentials → new key, old key revoked."""
        first = self._do_first_enroll(app, client, node_id="node-R1")
        old_key = first["api_key"]
        host_id = first["host_id"]

        resp = client.post(
            "/api/v1/enroll",
            json={"node_id": "node-R1", "hostname": "host-r", "host_id": host_id},
            content_type="application/json",
            headers={"X-Existing-Credentials": f"Bearer {old_key}"},
        )
        assert resp.status_code == 200, resp.get_json()
        data = resp.get_json()
        assert data["status"] == "approved"
        assert data["rotated"] is True
        new_key = data["api_key"]
        assert new_key != old_key

        # Old key must be revoked
        db = get_db(app.config["DATABASE_PATH"])
        try:
            old_hash = hashlib.sha256(old_key.encode()).hexdigest()
            old_row = db.execute(
                "SELECT is_active FROM api_keys WHERE key_hash = ?",
                (old_hash,),
            ).fetchone()
            assert old_row["is_active"] == 0, "old key should be revoked after rotate"

            new_hash = hashlib.sha256(new_key.encode()).hexdigest()
            new_row = db.execute(
                "SELECT is_active, host_id, node_id_restriction FROM api_keys "
                "WHERE key_hash = ?",
                (new_hash,),
            ).fetchone()
            assert new_row["is_active"] == 1
            assert new_row["host_id"] == host_id
            assert new_row["node_id_restriction"] == "node-R1"
        finally:
            db.close()

    def test_auto_rotate_rejects_wrong_host_id(self, app, client):
        """Self-heal: same node + valid creds but wrong host_id → 403."""
        first = self._do_first_enroll(app, client, node_id="node-R2")
        old_key = first["api_key"]

        resp = client.post(
            "/api/v1/enroll",
            json={
                "node_id": "node-R2",
                "hostname": "host-r",
                "host_id": "00000000-0000-0000-0000-000000000000",  # wrong
            },
            content_type="application/json",
            headers={"X-Existing-Credentials": f"Bearer {old_key}"},
        )
        assert resp.status_code == 403
        assert resp.get_json()["error"] == "host_id_mismatch"

    def test_auto_rotate_rejects_missing_credentials(self, app, client):
        """Self-heal: same node but no X-Existing-Credentials → 409 conflict."""
        self._do_first_enroll(app, client, node_id="node-R3")

        resp = client.post(
            "/api/v1/enroll",
            json={"node_id": "node-R3", "hostname": "host-r"},
            content_type="application/json",
        )
        # Falls through to the "already_enrolled" path because no creds
        # were presented to trigger the self-heal branch.
        assert resp.status_code == 409
        assert resp.get_json()["error"] == "already_enrolled"

    def test_auto_rotate_rejects_invalid_credentials(self, app, client):
        """Self-heal: same node + garbage X-Existing-Credentials → 401."""
        self._do_first_enroll(app, client, node_id="node-R4")

        resp = client.post(
            "/api/v1/enroll",
            json={"node_id": "node-R4", "hostname": "host-r"},
            content_type="application/json",
            headers={"X-Existing-Credentials": "Bearer not-a-real-key"},
        )
        assert resp.status_code == 401
        assert resp.get_json()["error"] == "invalid_existing_credentials"

    def test_reenroll_revoked_record_blocked(self, app, client):
        """A revoked enrollment cannot be re-used as a self-heal handle."""
        from app.enrollment_models import (
            approve_enrollment,
            create_enrollment_request,
            revoke_enrollment,
        )

        enable_enrollment(app, mode="open")
        clear_enrollment_records(app)

        # Approve, then revoke
        db = get_db(app.config["DATABASE_PATH"])
        try:
            record = create_enrollment_request(db, "node-R5", "host-r5", host_id="abc")
            raw = approve_enrollment(db, record["id"], approved_by="test", host_id="abc")
            revoke_enrollment(db, record["id"], revoked_by="test")
        finally:
            db.close()

        resp = client.post(
            "/api/v1/enroll",
            json={"node_id": "node-R5", "hostname": "host-r5", "host_id": "abc"},
            content_type="application/json",
            headers={"X-Existing-Credentials": f"Bearer {raw}"},
        )
        # Old key is revoked, so the X-Existing-Credentials check fails
        # BEFORE the self-heal branch can match. Returns 401.
        assert resp.status_code in (401, 403)


class TestAllowUnrestrictedPolicy:
    """The server policy flag ``allow_unrestricted_api_keys`` blocks
    admin-created keys that have no node binding when set to ``false``."""

    def test_unrestricted_blocked_when_policy_off(self, app, client):
        """Admin key creation with no node binding returns 400 when policy off."""
        from app.models import init_db

        init_db(app.config["DATABASE_PATH"])

        db = get_db(app.config["DATABASE_PATH"])
        try:
            create_user(db, "admin", "pass", "admin")
            update_enrollment_setting(db, "allow_unrestricted_api_keys", "false", "test")
        finally:
            db.close()

        # Log in and try to create an unrestricted key
        client.post("/login", data={"username": "admin", "password": "pass"})

        resp = client.post(
            "/admin/keys",
            json={"label": "test", "node_id_restriction": ""},
            content_type="application/json",
            headers={"Accept": "application/json"},
        )
        assert resp.status_code == 400
        assert resp.get_json()["error"] == "node_id_required"

    def test_unrestricted_allowed_when_policy_on(self, app, client):
        """Admin key creation with no node binding succeeds when policy on (default)."""
        from app.models import init_db

        init_db(app.config["DATABASE_PATH"])
        db = get_db(app.config["DATABASE_PATH"])
        try:
            create_user(db, "admin", "pass", "admin")
            update_enrollment_setting(db, "allow_unrestricted_api_keys", "true", "test")
        finally:
            db.close()

        client.post("/login", data={"username": "admin", "password": "pass"})

        resp = client.post(
            "/admin/keys",
            json={"label": "test", "node_id_restriction": ""},
            content_type="application/json",
            headers={"Accept": "application/json"},
        )
        assert resp.status_code == 201
        assert "key" in resp.get_json()


class TestBindingEnforcement:
    """The ``authenticate_agent_request`` helper enforces
    ``node_id_restriction`` on agent endpoints. A key bound to node-X
    cannot write metrics/checks/etc. for node-Y."""

    @pytest.fixture()
    def metrics_app(self, tmp_path):
        """App fixture that also enables the metrics blueprint."""
        from app import create_app

        db_path = str(tmp_path / "test_bind.db")
        config_file = tmp_path / "config.json"
        config_file.write_text(json.dumps({
            "SECRET_KEY": "test-secret-key-for-binding",
            "DATABASE_PATH": db_path,
            "DEBUG": False,
            "RATELIMIT_ENABLED": False,
            "METRICS_ENABLED": True,
        }))
        application = create_app(str(config_file))
        application.config["TESTING"] = True
        application.config["WTF_CSRF_ENABLED"] = False
        return application

    @pytest.fixture()
    def metrics_client(self, metrics_app):
        return metrics_app.test_client()

    def _make_bound_key(self, app, node_id):
        db = get_db(app.config["DATABASE_PATH"])
        try:
            create_user(db, "admin", "pass", "admin")
            return create_api_key(
                db, "agent-key", node_id_restriction=node_id, created_by=1
            )
        finally:
            db.close()

    def test_writes_rejected_for_wrong_agent_id(self, metrics_app, metrics_client):
        """X-Agent-ID mismatched against key's node_id_restriction → 403."""
        from app.routes import metrics_api as metrics_module
        metrics_module._vm_write = lambda raw: True

        key = self._make_bound_key(metrics_app, "real-node")

        resp = metrics_client.post(
            "/api/v1/metrics/write",
            data=b"\x00\x00\x00\x00",
            content_type="application/x-protobuf",
            headers={
                "Authorization": f"Bearer {key}",
                "X-Agent-ID": "impostor-node",
            },
        )
        assert resp.status_code == 403, resp.get_json()
        assert resp.get_json()["error"] == "node_id_mismatch"
        assert resp.headers.get("X-Node-ID-Restriction") == "real-node"

    def test_writes_allowed_for_matching_agent_id(self, metrics_app, metrics_client):
        """X-Agent-ID matching key's node_id_restriction → 204."""
        from app.routes import metrics_api as metrics_module
        metrics_module._vm_write = lambda raw: True

        key = self._make_bound_key(metrics_app, "real-node")

        resp = metrics_client.post(
            "/api/v1/metrics/write",
            data=b"\x00\x00\x00\x00",
            content_type="application/x-protobuf",
            headers={
                "Authorization": f"Bearer {key}",
                "X-Agent-ID": "real-node",
            },
        )
        assert resp.status_code == 204

    def test_unrestricted_key_does_not_require_agent_id(self, metrics_app, metrics_client):
        """A key with no node_id_restriction may omit X-Agent-ID."""
        from app.routes import metrics_api as metrics_module
        metrics_module._vm_write = lambda raw: True

        db = get_db(metrics_app.config["DATABASE_PATH"])
        try:
            create_user(db, "admin", "pass", "admin")
            key = create_api_key(
                db, "unrestricted", node_id_restriction=None, created_by=1
            )
        finally:
            db.close()

        resp = metrics_client.post(
            "/api/v1/metrics/write",
            data=b"\x00\x00\x00\x00",
            content_type="application/x-protobuf",
            headers={"Authorization": f"Bearer {key}"},
        )
        assert resp.status_code == 204

    def test_synthetic_worker_register_rejects_wrong_id(
        self, metrics_app, metrics_client
    ):
        """Synthetic worker register with mismatched worker_id → 403."""
        # The synthetic blueprint is registered unconditionally; the
        # worker_register endpoint requires X-Worker-ID via body
        # "worker_id" or the URL. We use the body field.
        db = get_db(metrics_app.config["DATABASE_PATH"])
        try:
            create_user(db, "admin", "pass", "admin")
            key = create_api_key(
                db, "worker-key", node_id_restriction="real-worker", created_by=1
            )
        finally:
            db.close()

        resp = metrics_client.post(
            "/api/v1/workers/register",
            json={"worker_id": "impostor-worker", "hostname": "x"},
            content_type="application/json",
            headers={"Authorization": f"Bearer {key}"},
        )
        assert resp.status_code == 403, resp.get_json()
        assert resp.get_json()["error"] == "node_id_mismatch"
