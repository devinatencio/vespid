"""Integration tests for service-layer threat score computation.

Tests that query_ip_record and query_ip_records correctly compute and return
reputation_score, that the score is NOT written back to the database, and that
graceful degradation works when compute_threat_score raises an exception.

Also tests that the API JSON response from GET /api/v1/intel/ips/<ip> includes
the reputation_score field.

Requirements: 4.1–4.5, 6.3–6.4
"""

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from app import create_app
from app.intel_models import init_intel_db
from app.intel_service import query_ip_record, query_ip_records
from app.models import create_api_key, create_user, get_db


# ── Fixtures ─────────────────────────────────────────────────────────────


@pytest.fixture()
def intel_db():
    """Create an in-memory SQLite database with intel tables initialized."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_intel_db(conn, "sqlite")
    yield conn
    conn.close()


@pytest.fixture()
def app(tmp_path):
    """Create a Flask app with test config and in-memory SQLite."""
    db_path = str(tmp_path / "test.db")
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({
        "SECRET_KEY": "test-secret-key-for-testing",
        "DATABASE_PATH": db_path,
        "DEBUG": False,
    }))
    application = create_app(str(config_file))
    application.config["TESTING"] = True
    application.config["WTF_CSRF_ENABLED"] = False
    return application


@pytest.fixture()
def api_key_token(app):
    """Create an admin user and an unrestricted API key, return the raw token."""
    db = get_db(app.config["DATABASE_PATH"])
    try:
        admin_id = create_user(db, "admin", "admin_pass", "admin")
        token = create_api_key(db, "test-key", None, admin_id)
    finally:
        db.close()
    return token


# ── Helpers ──────────────────────────────────────────────────────────────


def _insert_ip_record(conn, ip_address="192.168.1.1", ip_version="v4", **kwargs):
    """Helper to insert a test IP record with sensible defaults."""
    defaults = {
        "first_seen_at": "2024-01-01T00:00:00",
        "last_seen_at": "2024-01-02T00:00:00",
        "last_blocked_at": None,
        "total_times_seen": 1,
        "total_times_blocked": 0,
        "total_reporting_nodes": 1,
        "total_attack_events": 0,
        "repeat_offender": 0,
        "first_reporting_node": "node-1",
        "most_recent_reporting_node": "node-1",
        "reporting_node_list": '["node-1"]',
        "geo_country": None,
        "asn": None,
        "isp_organization": None,
        "reputation_score": None,
        "threat_tags": "[]",
    }
    defaults.update(kwargs)
    conn.execute(
        "INSERT INTO ip_intel (ip_address, ip_version, first_seen_at, last_seen_at, "
        "last_blocked_at, total_times_seen, total_times_blocked, total_reporting_nodes, "
        "total_attack_events, repeat_offender, first_reporting_node, "
        "most_recent_reporting_node, reporting_node_list, geo_country, asn, "
        "isp_organization, reputation_score, threat_tags) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            ip_address, ip_version,
            defaults["first_seen_at"], defaults["last_seen_at"],
            defaults["last_blocked_at"], defaults["total_times_seen"],
            defaults["total_times_blocked"], defaults["total_reporting_nodes"],
            defaults["total_attack_events"], defaults["repeat_offender"],
            defaults["first_reporting_node"], defaults["most_recent_reporting_node"],
            defaults["reporting_node_list"], defaults["geo_country"],
            defaults["asn"], defaults["isp_organization"],
            defaults["reputation_score"], defaults["threat_tags"],
        ),
    )
    conn.commit()


def _insert_event(conn, ip_address, timestamp, node_id="node-1",
                  event_type="ssh_brute", event_kind="sighting"):
    """Helper to insert a test event."""
    conn.execute(
        "INSERT INTO ip_intel_events (ip_address, node_id, event_type, event_kind, timestamp) "
        "VALUES (?, ?, ?, ?, ?)",
        (ip_address, node_id, event_type, event_kind, timestamp),
    )
    conn.commit()


# ── Test: query_ip_record returns reputation_score as float ──────────────


class TestQueryIpRecordScore:
    """Tests for reputation_score in query_ip_record results."""

    def test_returns_reputation_score_as_float_with_activity(self, intel_db):
        """query_ip_record returns a record with reputation_score as a float
        (not None) when the IP has activity.

        Validates: Requirements 4.1, 4.3
        """
        _insert_ip_record(
            intel_db, "192.168.1.1",
            total_times_seen=10,
            total_times_blocked=5,
            total_reporting_nodes=3,
            repeat_offender=1,
            threat_tags='["ssh_bruteforce", "port_scan"]',
        )
        # Insert a recent event so recency counters are non-zero
        now = datetime.now(timezone.utc)
        ts = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")
        _insert_event(intel_db, "192.168.1.1", ts)

        record = query_ip_record(intel_db, "192.168.1.1")

        assert record is not None
        assert "reputation_score" in record
        assert isinstance(record["reputation_score"], float)
        assert record["reputation_score"] > 0.0
        assert 0.0 <= record["reputation_score"] <= 100.0

    def test_returns_zero_score_for_zero_times_seen(self, intel_db):
        """query_ip_record returns reputation_score = 0.0 for an IP with
        total_times_seen = 0.

        Validates: Requirements 4.1, 1.2
        """
        _insert_ip_record(
            intel_db, "10.0.0.1",
            total_times_seen=0,
            total_times_blocked=0,
            total_reporting_nodes=0,
        )

        record = query_ip_record(intel_db, "10.0.0.1")

        assert record is not None
        assert record["reputation_score"] == 0.0


# ── Test: query_ip_records returns reputation_score in each record ────────


class TestQueryIpRecordsScore:
    """Tests for reputation_score in query_ip_records results."""

    def test_returns_reputation_score_in_each_record(self, intel_db):
        """query_ip_records returns reputation_score in each record of the
        result set.

        Validates: Requirements 4.2
        """
        _insert_ip_record(
            intel_db, "192.168.1.1",
            total_times_seen=5,
            total_times_blocked=2,
            total_reporting_nodes=2,
        )
        _insert_ip_record(
            intel_db, "192.168.1.2",
            total_times_seen=20,
            total_times_blocked=10,
            total_reporting_nodes=5,
            repeat_offender=1,
            threat_tags='["ssh_bruteforce"]',
        )
        _insert_ip_record(
            intel_db, "10.0.0.1",
            total_times_seen=0,
            total_times_blocked=0,
            total_reporting_nodes=0,
        )

        result = query_ip_records(intel_db, filters={})

        assert result["total_count"] == 3
        for record in result["records"]:
            assert "reputation_score" in record
            assert record["reputation_score"] is not None
            assert isinstance(record["reputation_score"], float)
            assert 0.0 <= record["reputation_score"] <= 100.0


# ── Test: score is NOT written back to ip_intel table ────────────────────


class TestScoreNotWrittenToDb:
    """Tests that computed score is not persisted to the database."""

    def test_score_not_written_back_to_db(self, intel_db):
        """The computed score is NOT written back to the ip_intel table.
        Query DB directly after calling query function.

        Validates: Requirements 4.4
        """
        _insert_ip_record(
            intel_db, "192.168.1.1",
            total_times_seen=10,
            total_times_blocked=5,
            total_reporting_nodes=3,
        )

        # Call query_ip_record which computes the score
        record = query_ip_record(intel_db, "192.168.1.1")
        assert record is not None
        assert record["reputation_score"] is not None
        assert record["reputation_score"] > 0.0

        # Verify the database still has NULL for reputation_score
        cursor = intel_db.execute(
            "SELECT reputation_score FROM ip_intel WHERE ip_address = ?",
            ("192.168.1.1",),
        )
        row = cursor.fetchone()
        assert row["reputation_score"] is None

    def test_score_not_written_back_after_query_ip_records(self, intel_db):
        """query_ip_records also does not write scores back to the database.

        Validates: Requirements 4.4
        """
        _insert_ip_record(
            intel_db, "192.168.1.1",
            total_times_seen=10,
            total_times_blocked=5,
            total_reporting_nodes=3,
        )

        # Call query_ip_records which computes scores
        result = query_ip_records(intel_db, filters={})
        assert result["records"][0]["reputation_score"] > 0.0

        # Verify the database still has NULL for reputation_score
        cursor = intel_db.execute(
            "SELECT reputation_score FROM ip_intel WHERE ip_address = ?",
            ("192.168.1.1",),
        )
        row = cursor.fetchone()
        assert row["reputation_score"] is None


# ── Test: graceful degradation when compute_threat_score raises ──────────


class TestGracefulDegradation:
    """Tests that query functions handle score computation failures gracefully."""

    def test_query_ip_record_graceful_on_score_error(self, intel_db):
        """When compute_threat_score raises, reputation_score is None and
        query still succeeds.

        Validates: Requirements 4.5
        """
        _insert_ip_record(
            intel_db, "192.168.1.1",
            total_times_seen=10,
            total_times_blocked=5,
        )

        with patch("app.intel_service.compute_threat_score", side_effect=RuntimeError("score engine failure")):
            record = query_ip_record(intel_db, "192.168.1.1")

        assert record is not None
        assert record["reputation_score"] is None
        # Other fields should still be present and correct
        assert record["ip_address"] == "192.168.1.1"
        assert record["total_times_seen"] == 10

    def test_query_ip_records_graceful_on_score_error(self, intel_db):
        """When compute_threat_score raises for all records, reputation_score
        is None in each record and the query still succeeds.

        Validates: Requirements 4.5
        """
        _insert_ip_record(intel_db, "192.168.1.1", total_times_seen=5)
        _insert_ip_record(intel_db, "10.0.0.1", total_times_seen=3)

        with patch("app.intel_service.compute_threat_score", side_effect=ValueError("broken")):
            result = query_ip_records(intel_db, filters={})

        assert result["total_count"] == 2
        for record in result["records"]:
            assert record["reputation_score"] is None
            assert record["ip_address"] is not None


# ── Test: API JSON response includes reputation_score ────────────────────


class TestApiReputationScoreField:
    """Tests that the API JSON response includes reputation_score."""

    def test_get_ip_returns_reputation_score_in_json(self, app, api_key_token):
        """GET /api/v1/intel/ips/<ip> returns reputation_score field in JSON.

        Validates: Requirements 6.3, 6.4
        """
        # Insert a record with activity into the app's database
        db = get_db(app.config["DATABASE_PATH"])
        try:
            from app.intel_models import init_intel_db
            init_intel_db(db, "sqlite")
            _insert_ip_record(
                db, "203.0.113.50",
                total_times_seen=15,
                total_times_blocked=7,
                total_reporting_nodes=4,
                repeat_offender=1,
                threat_tags='["ssh_bruteforce", "port_scan"]',
            )
        finally:
            db.close()

        client = app.test_client()
        response = client.get(
            "/api/v1/intel/ips/203.0.113.50",
            headers={"Authorization": f"Bearer {api_key_token}"},
        )

        assert response.status_code == 200
        data = response.get_json()
        assert "reputation_score" in data
        assert isinstance(data["reputation_score"], float)
        assert 0.0 <= data["reputation_score"] <= 100.0
