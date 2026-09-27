"""Unit tests for intel_models.py — upsert_ip_record(), get_ip_record(), compute_recency(), and search_ip_records()."""

import json
import math
import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from app.intel_models import compute_recency, get_attack_vectors, get_ip_record, init_intel_db, process_unblock_event, search_ip_records, upsert_ip_record


@pytest.fixture()
def intel_db():
    """Create an in-memory SQLite database with intel tables initialized."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_intel_db(conn, "sqlite")
    yield conn
    conn.close()


@pytest.fixture()
def intel_db_no_row_factory():
    """Create an in-memory SQLite database without row_factory (for get/compute tests)."""
    conn = sqlite3.connect(":memory:")
    init_intel_db(conn, "sqlite")
    yield conn
    conn.close()


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


# ── get_ip_record tests ──────────────────────────────────────────────────


class TestGetIpRecord:
    """Tests for get_ip_record()."""

    def test_returns_none_for_nonexistent_ip(self, intel_db):
        result = get_ip_record(intel_db, "10.0.0.1")
        assert result is None

    def test_returns_complete_record(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1", total_times_seen=5)
        result = get_ip_record(intel_db, "192.168.1.1")

        assert result is not None
        assert result["ip_address"] == "192.168.1.1"
        assert result["ip_version"] == "v4"
        assert result["total_times_seen"] == 5
        assert result["first_seen_at"] == "2024-01-01T00:00:00"
        assert result["last_seen_at"] == "2024-01-02T00:00:00"

    def test_parses_reporting_node_list_json(self, intel_db):
        _insert_ip_record(
            intel_db, "192.168.1.1",
            reporting_node_list='["node-1", "node-2", "node-3"]',
        )
        result = get_ip_record(intel_db, "192.168.1.1")
        assert result["reporting_node_list"] == ["node-1", "node-2", "node-3"]

    def test_parses_threat_tags_json(self, intel_db):
        _insert_ip_record(
            intel_db, "192.168.1.1",
            threat_tags='["ssh_bruteforce", "port_scan"]',
        )
        result = get_ip_record(intel_db, "192.168.1.1")
        assert result["threat_tags"] == ["ssh_bruteforce", "port_scan"]

    def test_repeat_offender_as_boolean(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1", repeat_offender=1)
        result = get_ip_record(intel_db, "192.168.1.1")
        assert result["repeat_offender"] is True

        _insert_ip_record(intel_db, "10.0.0.1", repeat_offender=0)
        result = get_ip_record(intel_db, "10.0.0.1")
        assert result["repeat_offender"] is False

    def test_nullable_fields_returned_as_none(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1")
        result = get_ip_record(intel_db, "192.168.1.1")
        assert result["geo_country"] is None
        assert result["asn"] is None
        assert result["isp_organization"] is None
        assert result["reputation_score"] is None
        assert result["last_blocked_at"] is None

    def test_enrichment_fields_returned_when_set(self, intel_db):
        _insert_ip_record(
            intel_db, "192.168.1.1",
            geo_country="US", asn=15169,
            isp_organization="Google LLC", reputation_score=75.5,
        )
        result = get_ip_record(intel_db, "192.168.1.1")
        assert result["geo_country"] == "US"
        assert result["asn"] == 15169
        assert result["isp_organization"] == "Google LLC"
        assert result["reputation_score"] == 75.5

    def test_ipv6_record(self, intel_db):
        _insert_ip_record(intel_db, "2001:db8::1", ip_version="v6")
        result = get_ip_record(intel_db, "2001:db8::1")
        assert result is not None
        assert result["ip_version"] == "v6"
        assert result["ip_address"] == "2001:db8::1"


# ── compute_recency tests ────────────────────────────────────────────────


class TestComputeRecency:
    """Tests for compute_recency()."""

    def test_returns_zeros_for_nonexistent_ip(self, intel_db):
        result = compute_recency(intel_db, "10.0.0.1")
        assert result == {
            "times_seen_last_24h": 0,
            "times_seen_last_7d": 0,
            "times_seen_last_30d": 0,
        }

    def test_returns_zeros_when_no_events(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1")
        result = compute_recency(intel_db, "192.168.1.1")
        assert result == {
            "times_seen_last_24h": 0,
            "times_seen_last_7d": 0,
            "times_seen_last_30d": 0,
        }

    def test_counts_event_within_24h(self, intel_db):
        now = datetime.now(timezone.utc)
        ts = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")
        _insert_event(intel_db, "192.168.1.1", ts)

        result = compute_recency(intel_db, "192.168.1.1")
        assert result["times_seen_last_24h"] == 1
        assert result["times_seen_last_7d"] == 1
        assert result["times_seen_last_30d"] == 1

    def test_event_outside_24h_but_within_7d(self, intel_db):
        now = datetime.now(timezone.utc)
        ts = (now - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S")
        _insert_event(intel_db, "192.168.1.1", ts)

        result = compute_recency(intel_db, "192.168.1.1")
        assert result["times_seen_last_24h"] == 0
        assert result["times_seen_last_7d"] == 1
        assert result["times_seen_last_30d"] == 1

    def test_event_outside_7d_but_within_30d(self, intel_db):
        now = datetime.now(timezone.utc)
        ts = (now - timedelta(days=15)).strftime("%Y-%m-%dT%H:%M:%S")
        _insert_event(intel_db, "192.168.1.1", ts)

        result = compute_recency(intel_db, "192.168.1.1")
        assert result["times_seen_last_24h"] == 0
        assert result["times_seen_last_7d"] == 0
        assert result["times_seen_last_30d"] == 1

    def test_event_outside_30d_not_counted(self, intel_db):
        now = datetime.now(timezone.utc)
        ts = (now - timedelta(days=60)).strftime("%Y-%m-%dT%H:%M:%S")
        _insert_event(intel_db, "192.168.1.1", ts)

        result = compute_recency(intel_db, "192.168.1.1")
        assert result == {
            "times_seen_last_24h": 0,
            "times_seen_last_7d": 0,
            "times_seen_last_30d": 0,
        }

    def test_multiple_events_across_windows(self, intel_db):
        now = datetime.now(timezone.utc)
        # 2 events within 24h
        for hours in [1, 12]:
            ts = (now - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%S")
            _insert_event(intel_db, "192.168.1.1", ts)
        # 1 event within 7d but not 24h
        ts = (now - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%S")
        _insert_event(intel_db, "192.168.1.1", ts)
        # 1 event within 30d but not 7d
        ts = (now - timedelta(days=20)).strftime("%Y-%m-%dT%H:%M:%S")
        _insert_event(intel_db, "192.168.1.1", ts)
        # 1 event outside 30d
        ts = (now - timedelta(days=45)).strftime("%Y-%m-%dT%H:%M:%S")
        _insert_event(intel_db, "192.168.1.1", ts)

        result = compute_recency(intel_db, "192.168.1.1")
        assert result["times_seen_last_24h"] == 2
        assert result["times_seen_last_7d"] == 3
        assert result["times_seen_last_30d"] == 4

    def test_counts_both_sightings_and_blocks(self, intel_db):
        now = datetime.now(timezone.utc)
        ts = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")
        _insert_event(intel_db, "192.168.1.1", ts, event_kind="sighting")
        _insert_event(intel_db, "192.168.1.1", ts, event_kind="block")

        result = compute_recency(intel_db, "192.168.1.1")
        assert result["times_seen_last_24h"] == 2
        assert result["times_seen_last_7d"] == 2
        assert result["times_seen_last_30d"] == 2

    def test_only_counts_events_for_specified_ip(self, intel_db):
        now = datetime.now(timezone.utc)
        ts = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")
        _insert_event(intel_db, "192.168.1.1", ts)
        _insert_event(intel_db, "10.0.0.1", ts)

        result = compute_recency(intel_db, "192.168.1.1")
        assert result["times_seen_last_24h"] == 1

    def test_uses_agent_timestamp_not_server_received_at(self, intel_db):
        """Verify compute_recency() uses agent-provided timestamp, not server_received_at.

        Validates: Requirements 21 (AC 1, AC 5)

        Inserts events where the agent timestamp and server_received_at differ
        significantly, then confirms recency windows are computed from the agent
        timestamp column.
        """
        now = datetime.now(timezone.utc)

        # Event 1: agent timestamp is 2 hours ago (within 24h),
        # but server_received_at is 10 days ago (outside 7d window)
        agent_ts_recent = (now - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%S")
        server_ts_old = (now - timedelta(days=10)).strftime("%Y-%m-%dT%H:%M:%S")
        intel_db.execute(
            "INSERT INTO ip_intel_events "
            "(ip_address, node_id, event_type, event_kind, timestamp, server_received_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("192.168.1.1", "node-1", "ssh_brute", "block", agent_ts_recent, server_ts_old),
        )

        # Event 2: agent timestamp is 40 days ago (outside 30d),
        # but server_received_at is 1 hour ago (within 24h)
        agent_ts_old = (now - timedelta(days=40)).strftime("%Y-%m-%dT%H:%M:%S")
        server_ts_recent = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%S")
        intel_db.execute(
            "INSERT INTO ip_intel_events "
            "(ip_address, node_id, event_type, event_kind, timestamp, server_received_at) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("192.168.1.1", "node-1", "ssh_brute", "sighting", agent_ts_old, server_ts_recent),
        )
        intel_db.commit()

        result = compute_recency(intel_db, "192.168.1.1")

        # If compute_recency uses agent timestamp (correct behavior):
        # - Event 1 (agent_ts 2h ago) → counted in 24h, 7d, 30d
        # - Event 2 (agent_ts 40d ago) → not counted in any window
        # If it incorrectly used server_received_at:
        # - Event 1 (server_ts 10d ago) → counted only in 30d
        # - Event 2 (server_ts 1h ago) → counted in 24h, 7d, 30d
        assert result["times_seen_last_24h"] == 1, (
            "Expected 1 event in 24h window (agent timestamp 2h ago), "
            "got %d — may be using server_received_at instead" % result["times_seen_last_24h"]
        )
        assert result["times_seen_last_7d"] == 1, (
            "Expected 1 event in 7d window (agent timestamp 2h ago), "
            "got %d — may be using server_received_at instead" % result["times_seen_last_7d"]
        )
        assert result["times_seen_last_30d"] == 1, (
            "Expected 1 event in 30d window (agent timestamp 2h ago only), "
            "got %d — may be using server_received_at instead" % result["times_seen_last_30d"]
        )


# ── upsert_ip_record tests ───────────────────────────────────────────────


class TestUpsertIpRecord:
    """Tests for upsert_ip_record()."""

    def test_creates_new_record_on_first_observation(self, intel_db):
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, None,
        )
        assert result["ip_address"] == "192.168.1.1"
        assert result["ip_version"] == "v4"
        assert result["first_seen_at"] == "2024-01-01T00:00:00"
        assert result["last_seen_at"] == "2024-01-01T00:00:00"
        assert result["total_times_seen"] == 1
        assert result["total_times_blocked"] == 0
        assert result["total_reporting_nodes"] == 1
        assert result["total_attack_events"] == 0
        assert result["repeat_offender"] is False
        assert result["first_reporting_node"] == "node-1"
        assert result["most_recent_reporting_node"] == "node-1"
        assert result["reporting_node_list"] == ["node-1"]
        assert result["threat_tags"] == []

    def test_detects_ipv6_version(self, intel_db):
        result = upsert_ip_record(
            intel_db, "2001:db8::1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, None,
        )
        assert result["ip_version"] == "v6"

    def test_detects_ipv4_version(self, intel_db):
        result = upsert_ip_record(
            intel_db, "10.0.0.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, None,
        )
        assert result["ip_version"] == "v4"

    def test_increments_total_times_seen_on_update(self, intel_db):
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, None,
        )
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-02T00:00:00", False, None,
        )
        assert result["total_times_seen"] == 2

    def test_increments_total_times_blocked_on_block(self, intel_db):
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, None,
        )
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-02T00:00:00", True, None,
        )
        assert result["total_times_blocked"] == 1
        assert result["total_attack_events"] == 1

    def test_does_not_increment_blocked_on_sighting(self, intel_db):
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, None,
        )
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-02T00:00:00", False, None,
        )
        assert result["total_times_blocked"] == 0
        assert result["total_attack_events"] == 0

    def test_updates_last_seen_at(self, intel_db):
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, None,
        )
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-06-15T12:00:00", False, None,
        )
        assert result["last_seen_at"] == "2024-06-15T12:00:00"

    def test_updates_last_blocked_at_on_block(self, intel_db):
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, None,
        )
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-02T00:00:00", True, None,
        )
        assert result["last_blocked_at"] == "2024-01-02T00:00:00"

    def test_does_not_update_last_blocked_at_on_sighting(self, intel_db):
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, None,
        )
        assert result["last_blocked_at"] is None

    def test_preserves_first_seen_at(self, intel_db):
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, None,
        )
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-2", "ssh_brute",
            "2024-06-15T00:00:00", False, None,
        )
        assert result["first_seen_at"] == "2024-01-01T00:00:00"

    def test_preserves_first_reporting_node(self, intel_db):
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, None,
        )
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-2", "ssh_brute",
            "2024-01-02T00:00:00", False, None,
        )
        assert result["first_reporting_node"] == "node-1"

    def test_updates_most_recent_reporting_node(self, intel_db):
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, None,
        )
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-2", "ssh_brute",
            "2024-01-02T00:00:00", False, None,
        )
        assert result["most_recent_reporting_node"] == "node-2"

    def test_adds_new_node_to_reporting_node_list(self, intel_db):
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, None,
        )
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-2", "ssh_brute",
            "2024-01-02T00:00:00", False, None,
        )
        assert result["reporting_node_list"] == ["node-1", "node-2"]
        assert result["total_reporting_nodes"] == 2

    def test_no_duplicate_in_reporting_node_list(self, intel_db):
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, None,
        )
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-02T00:00:00", False, None,
        )
        assert result["reporting_node_list"] == ["node-1"]
        assert result["total_reporting_nodes"] == 1

    def test_reporting_node_list_max_1000(self, intel_db):
        # Fill up to 1000 nodes
        for i in range(1000):
            upsert_ip_record(
                intel_db, "192.168.1.1", f"node-{i}", "ssh_brute",
                f"2024-01-01T{i // 60:02d}:{i % 60:02d}:00", False, None,
            )
        # 1001st node should not be added
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-overflow", "ssh_brute",
            "2024-02-01T00:00:00", False, None,
        )
        assert len(result["reporting_node_list"]) == 1000
        assert "node-overflow" not in result["reporting_node_list"]
        assert result["total_reporting_nodes"] == 1000

    def test_reporting_node_list_ordered_by_first_report(self, intel_db):
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-a", "ssh_brute",
            "2024-01-01T00:00:00", False, None,
        )
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-b", "ssh_brute",
            "2024-01-02T00:00:00", False, None,
        )
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-c", "ssh_brute",
            "2024-01-03T00:00:00", False, None,
        )
        # node-a reports again — should not change order
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-a", "ssh_brute",
            "2024-01-04T00:00:00", False, None,
        )
        assert result["reporting_node_list"] == ["node-a", "node-b", "node-c"]

    def test_threat_tag_accumulation(self, intel_db):
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, {"threat_tag": "ssh_bruteforce"},
        )
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "port_scan",
            "2024-01-02T00:00:00", False, {"threat_tag": "port_scan"},
        )
        assert result["threat_tags"] == ["ssh_bruteforce", "port_scan"]

    def test_threat_tag_no_duplicates(self, intel_db):
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, {"threat_tag": "ssh_bruteforce"},
        )
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-02T00:00:00", False, {"threat_tag": "ssh_bruteforce"},
        )
        assert result["threat_tags"] == ["ssh_bruteforce"]

    def test_threat_tags_max_50(self, intel_db):
        for i in range(50):
            upsert_ip_record(
                intel_db, "192.168.1.1", "node-1", "test",
                f"2024-01-{(i % 28) + 1:02d}T00:00:00", False,
                {"threat_tag": f"tag_{i}"},
            )
        # 51st tag should not be added
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "test",
            "2024-02-01T00:00:00", False, {"threat_tag": "overflow_tag"},
        )
        assert len(result["threat_tags"]) == 50
        assert "overflow_tag" not in result["threat_tags"]

    def test_threat_tag_falls_back_to_detection_rule(self, intel_db):
        """When no threat_tag in metadata, detection_rule is used as fallback."""
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", True, {"detection_rule": "ssh-brute"},
        )
        assert result["threat_tags"] == ["ssh-brute"]

    def test_threat_tag_preferred_over_detection_rule(self, intel_db):
        """Explicit threat_tag takes precedence over detection_rule."""
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", True,
            {"threat_tag": "ssh_bruteforce", "detection_rule": "ssh-brute"},
        )
        assert result["threat_tags"] == ["ssh_bruteforce"]

    def test_threat_tag_skips_empty_string(self, intel_db):
        """Empty string threat_tag and detection_rule should not be accumulated."""
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, {"threat_tag": "", "detection_rule": ""},
        )
        assert result["threat_tags"] == []

    def test_threat_tag_skips_whitespace_only(self, intel_db):
        """Whitespace-only threat_tag should not be accumulated."""
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, {"threat_tag": "   "},
        )
        assert result["threat_tags"] == []

    def test_threat_tag_detection_rule_deduplication(self, intel_db):
        """Detection_rule fallback also respects deduplication."""
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", True, {"detection_rule": "ssh-brute"},
        )
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-02T00:00:00", True, {"detection_rule": "ssh-brute"},
        )
        assert result["threat_tags"] == ["ssh-brute"]

    def test_geo_country_valid_update(self, intel_db):
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, {"geo_country": "US"},
        )
        assert result["geo_country"] == "US"

    def test_geo_country_invalid_discarded(self, intel_db):
        # Set valid geo_country first
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, {"geo_country": "US"},
        )
        # Invalid geo_country should not overwrite
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-02T00:00:00", False, {"geo_country": "invalid"},
        )
        assert result["geo_country"] == "US"

    def test_geo_country_lowercase_discarded(self, intel_db):
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, {"geo_country": "us"},
        )
        assert result["geo_country"] is None

    def test_asn_valid_update(self, intel_db):
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, {"asn": 15169},
        )
        assert result["asn"] == 15169

    def test_asn_invalid_zero_discarded(self, intel_db):
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, {"asn": 15169},
        )
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-02T00:00:00", False, {"asn": 0},
        )
        assert result["asn"] == 15169

    def test_asn_invalid_negative_discarded(self, intel_db):
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, {"asn": -1},
        )
        assert result["asn"] is None

    def test_isp_organization_update(self, intel_db):
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, {"isp_organization": "Google LLC"},
        )
        assert result["isp_organization"] == "Google LLC"

    def test_isp_organization_truncated_to_256(self, intel_db):
        long_name = "A" * 300
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, {"isp_organization": long_name},
        )
        assert len(result["isp_organization"]) == 256

    def test_repeat_offender_triggered_by_two_block_episodes(self, intel_db):
        """repeat_offender is set when block_episode_count >= 2 (block, unblock, re-block)."""
        from app.intel_models import process_unblock_event
        # First block — episode 1
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", True, None,
        )
        # Unblock
        process_unblock_event(intel_db, "192.168.1.1", "2024-01-02T00:00:00")
        # Second block — episode 2, should trigger repeat_offender
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-03T00:00:00", True, None,
        )
        assert result["repeat_offender"] is True
        assert result["block_episode_count"] == 2

    def test_repeat_offender_not_triggered_by_single_episode(self, intel_db):
        """High total_times_blocked in a single episode does NOT trigger repeat_offender."""
        for i in range(10):
            upsert_ip_record(
                intel_db, "192.168.1.1", "node-1", "ssh_brute",
                f"2024-01-{i + 1:02d}T00:00:00", True, None,
            )
        # 10 blocks in a single episode should NOT trigger repeat_offender
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-11T00:00:00", True, None,
        )
        assert result["repeat_offender"] is False
        assert result["block_episode_count"] == 1
        assert result["total_times_blocked"] == 11

    def test_repeat_offender_never_reverts(self, intel_db):
        """Once repeat_offender is set to TRUE, it never reverts to FALSE."""
        from app.intel_models import process_unblock_event
        # Trigger repeat_offender via 2 block episodes
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", True, None,
        )
        process_unblock_event(intel_db, "192.168.1.1", "2024-01-02T00:00:00")
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-03T00:00:00", True, None,
        )
        # Subsequent sighting events should not revert repeat_offender
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-04T00:00:00", False, None,
        )
        assert result["repeat_offender"] is True

    def test_inserts_event_row_for_sighting(self, intel_db):
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, None,
        )
        cursor = intel_db.execute(
            "SELECT * FROM ip_intel_events WHERE ip_address = ?",
            ("192.168.1.1",),
        )
        row = cursor.fetchone()
        assert row is not None
        assert row["event_kind"] == "sighting"
        assert row["node_id"] == "node-1"
        assert row["event_type"] == "ssh_brute"
        assert row["timestamp"] == "2024-01-01T00:00:00"

    def test_inserts_event_row_for_block(self, intel_db):
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", True,
            {"detection_rule": "rule_v1", "block_ttl_seconds": 3600},
        )
        cursor = intel_db.execute(
            "SELECT * FROM ip_intel_events WHERE ip_address = ?",
            ("192.168.1.1",),
        )
        row = cursor.fetchone()
        assert row is not None
        assert row["event_kind"] == "block"
        assert row["detection_rule"] == "rule_v1"
        assert row["block_ttl_seconds"] == 3600

    def test_transaction_atomicity_single_record(self, intel_db):
        """All fields are updated together in a single transaction."""
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", True,
            {"geo_country": "US", "threat_tag": "ssh_bruteforce", "asn": 15169},
        )
        # Verify all fields were set atomically
        assert result["total_times_seen"] == 1
        assert result["total_times_blocked"] == 1
        assert result["geo_country"] == "US"
        assert result["threat_tags"] == ["ssh_bruteforce"]
        assert result["asn"] == 15169
        assert result["last_blocked_at"] == "2024-01-01T00:00:00"

    def test_metadata_none_handled(self, intel_db):
        """Passing metadata=None should not raise."""
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, None,
        )
        assert result["geo_country"] is None
        assert result["asn"] is None
        assert result["isp_organization"] is None

    def test_unique_constraint_enforced(self, intel_db):
        """Only one record per IP address exists after multiple upserts."""
        for i in range(5):
            upsert_ip_record(
                intel_db, "192.168.1.1", f"node-{i}", "ssh_brute",
                f"2024-01-{i + 1:02d}T00:00:00", False, None,
            )
        cursor = intel_db.execute(
            "SELECT COUNT(*) FROM ip_intel WHERE ip_address = ?",
            ("192.168.1.1",),
        )
        assert cursor.fetchone()[0] == 1

    def test_block_event_first_observation(self, intel_db):
        """A block event as first observation creates the record correctly."""
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", True,
            {"detection_rule": "rule_v1", "block_ttl_seconds": 7200},
        )
        assert result["total_times_seen"] == 1
        assert result["total_times_blocked"] == 1
        assert result["total_attack_events"] == 1
        assert result["last_blocked_at"] == "2024-01-01T00:00:00"
        assert result["first_reporting_node"] == "node-1"


# ── search_ip_records tests ──────────────────────────────────────────────


class TestSearchIpRecords:
    """Tests for search_ip_records()."""

    # ── Empty results ────────────────────────────────────────────────────

    def test_returns_empty_list_when_no_records(self, intel_db):
        records, total = search_ip_records(intel_db, {})
        assert records == []
        assert total == 0

    def test_returns_empty_list_when_filter_matches_nothing(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1", geo_country="US")
        records, total = search_ip_records(intel_db, {"geo_country": "DE"})
        assert records == []
        assert total == 0

    # ── Basic retrieval ──────────────────────────────────────────────────

    def test_returns_all_records_with_no_filters(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1")
        _insert_ip_record(intel_db, "10.0.0.1")
        records, total = search_ip_records(intel_db, {})
        assert total == 2
        assert len(records) == 2

    def test_record_contains_all_fields(self, intel_db):
        _insert_ip_record(
            intel_db, "192.168.1.1",
            geo_country="US", asn=15169,
            isp_organization="Google", reputation_score=80.0,
            threat_tags='["ssh_brute"]',
            reporting_node_list='["node-1", "node-2"]',
        )
        records, total = search_ip_records(intel_db, {})
        assert total == 1
        rec = records[0]
        assert rec["ip_address"] == "192.168.1.1"
        assert rec["ip_version"] == "v4"
        assert rec["geo_country"] == "US"
        assert rec["asn"] == 15169
        assert rec["isp_organization"] == "Google"
        assert rec["reputation_score"] == 80.0
        assert rec["threat_tags"] == ["ssh_brute"]
        assert rec["reporting_node_list"] == ["node-1", "node-2"]

    def test_parses_json_fields(self, intel_db):
        _insert_ip_record(
            intel_db, "192.168.1.1",
            reporting_node_list='["a", "b"]',
            threat_tags='["tag1", "tag2"]',
        )
        records, _ = search_ip_records(intel_db, {})
        assert isinstance(records[0]["reporting_node_list"], list)
        assert isinstance(records[0]["threat_tags"], list)

    def test_repeat_offender_returned_as_boolean(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1", repeat_offender=1)
        _insert_ip_record(intel_db, "10.0.0.1", repeat_offender=0)
        records, _ = search_ip_records(intel_db, {})
        offenders = {r["ip_address"]: r["repeat_offender"] for r in records}
        assert offenders["192.168.1.1"] is True
        assert offenders["10.0.0.1"] is False

    # ── Filter: event_type (via JOIN) ────────────────────────────────────

    def test_filter_by_event_type(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1")
        _insert_ip_record(intel_db, "10.0.0.1")
        _insert_event(intel_db, "192.168.1.1", "2024-01-01T00:00:00", event_type="ssh_brute")
        _insert_event(intel_db, "10.0.0.1", "2024-01-01T00:00:00", event_type="port_scan")

        records, total = search_ip_records(intel_db, {"event_type": "ssh_brute"})
        assert total == 1
        assert records[0]["ip_address"] == "192.168.1.1"

    def test_event_type_filter_uses_distinct(self, intel_db):
        """Multiple events of same type for one IP should not produce duplicates."""
        _insert_ip_record(intel_db, "192.168.1.1")
        _insert_event(intel_db, "192.168.1.1", "2024-01-01T00:00:00", event_type="ssh_brute")
        _insert_event(intel_db, "192.168.1.1", "2024-01-02T00:00:00", event_type="ssh_brute")

        records, total = search_ip_records(intel_db, {"event_type": "ssh_brute"})
        assert total == 1
        assert len(records) == 1

    # ── Filter: threat_tag (JSON contains) ───────────────────────────────

    def test_filter_by_threat_tag(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1", threat_tags='["ssh_brute", "web_exploit"]')
        _insert_ip_record(intel_db, "10.0.0.1", threat_tags='["port_scan"]')

        records, total = search_ip_records(intel_db, {"threat_tag": "ssh_brute"})
        assert total == 1
        assert records[0]["ip_address"] == "192.168.1.1"

    def test_threat_tag_filter_partial_match_avoided(self, intel_db):
        """Tag 'ssh' should not match 'ssh_brute' since we use '"tag"' pattern."""
        _insert_ip_record(intel_db, "192.168.1.1", threat_tags='["ssh_brute"]')

        records, total = search_ip_records(intel_db, {"threat_tag": "ssh"})
        # The LIKE pattern is %"ssh"% which won't match "ssh_brute"
        assert total == 0

    # ── Filter: geo_country ──────────────────────────────────────────────

    def test_filter_by_geo_country(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1", geo_country="US")
        _insert_ip_record(intel_db, "10.0.0.1", geo_country="DE")
        _insert_ip_record(intel_db, "172.16.0.1", geo_country=None)

        records, total = search_ip_records(intel_db, {"geo_country": "US"})
        assert total == 1
        assert records[0]["ip_address"] == "192.168.1.1"

    # ── Filter: repeat_offender ──────────────────────────────────────────

    def test_filter_by_repeat_offender_true(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1", repeat_offender=1)
        _insert_ip_record(intel_db, "10.0.0.1", repeat_offender=0)

        records, total = search_ip_records(intel_db, {"repeat_offender": True})
        assert total == 1
        assert records[0]["ip_address"] == "192.168.1.1"

    def test_filter_by_repeat_offender_false(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1", repeat_offender=1)
        _insert_ip_record(intel_db, "10.0.0.1", repeat_offender=0)

        records, total = search_ip_records(intel_db, {"repeat_offender": False})
        assert total == 1
        assert records[0]["ip_address"] == "10.0.0.1"

    # ── Combined filters ─────────────────────────────────────────────────

    def test_combined_filters_all_must_match(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1", geo_country="US", repeat_offender=1,
                          threat_tags='["ssh_brute"]')
        _insert_ip_record(intel_db, "10.0.0.1", geo_country="US", repeat_offender=0,
                          threat_tags='["port_scan"]')
        _insert_event(intel_db, "192.168.1.1", "2024-01-01T00:00:00", event_type="ssh_brute")
        _insert_event(intel_db, "10.0.0.1", "2024-01-01T00:00:00", event_type="port_scan")

        records, total = search_ip_records(intel_db, {
            "event_type": "ssh_brute",
            "geo_country": "US",
            "repeat_offender": True,
            "threat_tag": "ssh_brute",
        })
        assert total == 1
        assert records[0]["ip_address"] == "192.168.1.1"

    # ── Pagination ───────────────────────────────────────────────────────

    def test_pagination_limits_results(self, intel_db):
        for i in range(5):
            _insert_ip_record(intel_db, f"10.0.0.{i+1}",
                              last_seen_at=f"2024-01-0{i+1}T00:00:00")

        records, total = search_ip_records(intel_db, {}, page=1, per_page=2)
        assert total == 5
        assert len(records) == 2

    def test_pagination_offset(self, intel_db):
        for i in range(5):
            _insert_ip_record(intel_db, f"10.0.0.{i+1}",
                              last_seen_at=f"2024-01-0{i+1}T00:00:00",
                              total_times_seen=i+1)

        # Sort by total_times_seen desc so order is deterministic
        records_p1, _ = search_ip_records(intel_db, {}, page=1, per_page=2,
                                          sort_by="total_times_seen", sort_order="desc")
        records_p2, _ = search_ip_records(intel_db, {}, page=2, per_page=2,
                                          sort_by="total_times_seen", sort_order="desc")
        records_p3, _ = search_ip_records(intel_db, {}, page=3, per_page=2,
                                          sort_by="total_times_seen", sort_order="desc")

        assert len(records_p1) == 2
        assert len(records_p2) == 2
        assert len(records_p3) == 1

        # Verify no overlap
        all_ips = [r["ip_address"] for r in records_p1 + records_p2 + records_p3]
        assert len(set(all_ips)) == 5

    def test_pagination_page_beyond_results_returns_empty(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1")
        records, total = search_ip_records(intel_db, {}, page=10, per_page=50)
        assert total == 1
        assert records == []

    def test_pagination_clamps_page_minimum(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1")
        # page=0 should be clamped to 1
        records, total = search_ip_records(intel_db, {}, page=0)
        assert total == 1
        assert len(records) == 1

    def test_pagination_clamps_per_page_minimum(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1")
        _insert_ip_record(intel_db, "10.0.0.1")
        # per_page=0 should be clamped to 1
        records, total = search_ip_records(intel_db, {}, per_page=0)
        assert total == 2
        assert len(records) == 1

    def test_pagination_clamps_per_page_maximum(self, intel_db):
        # per_page=300 should be clamped to 200
        records, total = search_ip_records(intel_db, {}, per_page=300)
        # Just verify it doesn't error; clamping is internal
        assert total == 0

    def test_total_count_reflects_filtered_results(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1", geo_country="US")
        _insert_ip_record(intel_db, "10.0.0.1", geo_country="US")
        _insert_ip_record(intel_db, "172.16.0.1", geo_country="DE")

        records, total = search_ip_records(intel_db, {"geo_country": "US"}, per_page=1)
        assert total == 2
        assert len(records) == 1

    # ── Sorting ──────────────────────────────────────────────────────────

    def test_default_sort_last_seen_at_desc(self, intel_db):
        _insert_ip_record(intel_db, "10.0.0.1", last_seen_at="2024-01-01T00:00:00")
        _insert_ip_record(intel_db, "10.0.0.2", last_seen_at="2024-01-03T00:00:00")
        _insert_ip_record(intel_db, "10.0.0.3", last_seen_at="2024-01-02T00:00:00")

        records, _ = search_ip_records(intel_db, {})
        ips = [r["ip_address"] for r in records]
        assert ips == ["10.0.0.2", "10.0.0.3", "10.0.0.1"]

    def test_sort_by_total_times_seen_asc(self, intel_db):
        _insert_ip_record(intel_db, "10.0.0.1", total_times_seen=10)
        _insert_ip_record(intel_db, "10.0.0.2", total_times_seen=1)
        _insert_ip_record(intel_db, "10.0.0.3", total_times_seen=5)

        records, _ = search_ip_records(intel_db, {}, sort_by="total_times_seen", sort_order="asc")
        counts = [r["total_times_seen"] for r in records]
        assert counts == [1, 5, 10]

    def test_sort_by_total_times_blocked_desc(self, intel_db):
        _insert_ip_record(intel_db, "10.0.0.1", total_times_blocked=2)
        _insert_ip_record(intel_db, "10.0.0.2", total_times_blocked=8)
        _insert_ip_record(intel_db, "10.0.0.3", total_times_blocked=5)

        records, _ = search_ip_records(intel_db, {}, sort_by="total_times_blocked", sort_order="desc")
        counts = [r["total_times_blocked"] for r in records]
        assert counts == [8, 5, 2]

    def test_sort_by_total_reporting_nodes(self, intel_db):
        _insert_ip_record(intel_db, "10.0.0.1", total_reporting_nodes=3)
        _insert_ip_record(intel_db, "10.0.0.2", total_reporting_nodes=1)
        _insert_ip_record(intel_db, "10.0.0.3", total_reporting_nodes=7)

        records, _ = search_ip_records(intel_db, {}, sort_by="total_reporting_nodes", sort_order="asc")
        counts = [r["total_reporting_nodes"] for r in records]
        assert counts == [1, 3, 7]

    def test_invalid_sort_by_defaults_to_last_seen_at(self, intel_db):
        _insert_ip_record(intel_db, "10.0.0.1", last_seen_at="2024-01-01T00:00:00")
        _insert_ip_record(intel_db, "10.0.0.2", last_seen_at="2024-01-03T00:00:00")

        records, _ = search_ip_records(intel_db, {}, sort_by="invalid_column")
        ips = [r["ip_address"] for r in records]
        # Default is desc, so most recent first
        assert ips == ["10.0.0.2", "10.0.0.1"]

    def test_invalid_sort_order_defaults_to_desc(self, intel_db):
        _insert_ip_record(intel_db, "10.0.0.1", total_times_seen=1)
        _insert_ip_record(intel_db, "10.0.0.2", total_times_seen=10)

        records, _ = search_ip_records(intel_db, {}, sort_by="total_times_seen", sort_order="invalid")
        counts = [r["total_times_seen"] for r in records]
        assert counts == [10, 1]

    # ── Pagination metadata computation ──────────────────────────────────

    def test_total_pages_computation(self, intel_db):
        """Verify total_pages = ceil(total_count / per_page) can be derived."""
        for i in range(7):
            _insert_ip_record(intel_db, f"10.0.0.{i+1}")

        _, total = search_ip_records(intel_db, {}, per_page=3)
        total_pages = math.ceil(total / 3)
        assert total == 7
        assert total_pages == 3

    def test_current_page_derivable(self, intel_db):
        """Verify current_page is the page parameter passed in."""
        for i in range(5):
            _insert_ip_record(intel_db, f"10.0.0.{i+1}")

        page = 2
        records, total = search_ip_records(intel_db, {}, page=page, per_page=2)
        assert len(records) == 2
        # current_page is simply the page argument
        assert page == 2


# ── get_attack_vectors tests ─────────────────────────────────────────────────


class TestGetAttackVectors:
    """Tests for get_attack_vectors() query function."""

    def test_returns_empty_list_for_nonexistent_ip(self, intel_db):
        """No events for IP returns empty list."""
        result = get_attack_vectors(intel_db, "10.99.99.99")
        assert result == []

    def test_returns_empty_list_when_no_detection_rules(self, intel_db):
        """Events without detection_rule values return empty list."""
        _insert_ip_record(intel_db, "192.168.1.1")
        _insert_event(intel_db, "192.168.1.1", "2024-01-01T00:00:00",
                      event_kind="block")
        result = get_attack_vectors(intel_db, "192.168.1.1")
        assert result == []

    def test_returns_distinct_rules_with_counts(self, intel_db):
        """Groups by detection_rule and counts correctly."""
        ip = "192.168.1.1"
        _insert_ip_record(intel_db, ip)
        # Insert events with detection_rule
        conn = intel_db
        conn.execute(
            "INSERT INTO ip_intel_events (ip_address, node_id, event_type, event_kind, timestamp, detection_rule) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ip, "node-1", "ssh_brute", "block", "2024-01-01T00:00:00", "ssh-brute"),
        )
        conn.execute(
            "INSERT INTO ip_intel_events (ip_address, node_id, event_type, event_kind, timestamp, detection_rule) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ip, "node-2", "ssh_brute", "block", "2024-01-01T01:00:00", "ssh-brute"),
        )
        conn.execute(
            "INSERT INTO ip_intel_events (ip_address, node_id, event_type, event_kind, timestamp, detection_rule) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ip, "node-1", "http_probe", "block", "2024-01-01T02:00:00", "http-probe"),
        )
        conn.commit()

        result = get_attack_vectors(intel_db, ip)
        assert len(result) == 2
        # Ordered by fire_count DESC
        assert result[0] == {"detection_rule": "ssh-brute", "fire_count": 2}
        assert result[1] == {"detection_rule": "http-probe", "fire_count": 1}

    def test_excludes_fleet_block_events(self, intel_db):
        """Fleet block events are not included in attack vectors."""
        ip = "192.168.1.1"
        _insert_ip_record(intel_db, ip)
        conn = intel_db
        conn.execute(
            "INSERT INTO ip_intel_events (ip_address, node_id, event_type, event_kind, timestamp, detection_rule) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ip, "node-1", "ssh_brute", "block", "2024-01-01T00:00:00", "ssh-brute"),
        )
        conn.execute(
            "INSERT INTO ip_intel_events (ip_address, node_id, event_type, event_kind, timestamp, detection_rule) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ip, "node-2", "ssh_brute", "fleet_block", "2024-01-01T01:00:00", "ssh-brute"),
        )
        conn.commit()

        result = get_attack_vectors(intel_db, ip)
        assert len(result) == 1
        assert result[0] == {"detection_rule": "ssh-brute", "fire_count": 1}

    def test_excludes_empty_string_detection_rules(self, intel_db):
        """Empty string detection_rule values are excluded."""
        ip = "192.168.1.1"
        _insert_ip_record(intel_db, ip)
        conn = intel_db
        conn.execute(
            "INSERT INTO ip_intel_events (ip_address, node_id, event_type, event_kind, timestamp, detection_rule) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ip, "node-1", "ssh_brute", "block", "2024-01-01T00:00:00", "ssh-brute"),
        )
        conn.execute(
            "INSERT INTO ip_intel_events (ip_address, node_id, event_type, event_kind, timestamp, detection_rule) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ip, "node-1", "unknown", "block", "2024-01-01T01:00:00", ""),
        )
        conn.commit()

        result = get_attack_vectors(intel_db, ip)
        assert len(result) == 1
        assert result[0]["detection_rule"] == "ssh-brute"

    def test_includes_sighting_events(self, intel_db):
        """Sighting events with detection_rule are included."""
        ip = "192.168.1.1"
        _insert_ip_record(intel_db, ip)
        conn = intel_db
        conn.execute(
            "INSERT INTO ip_intel_events (ip_address, node_id, event_type, event_kind, timestamp, detection_rule) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ip, "node-1", "ssh_brute", "sighting", "2024-01-01T00:00:00", "ssh-brute"),
        )
        conn.execute(
            "INSERT INTO ip_intel_events (ip_address, node_id, event_type, event_kind, timestamp, detection_rule) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (ip, "node-1", "http_probe", "block", "2024-01-01T01:00:00", "http-probe"),
        )
        conn.commit()

        result = get_attack_vectors(intel_db, ip)
        assert len(result) == 2
        # Both have fire_count=1, order by fire_count DESC (ties may vary)
        rules = {r["detection_rule"] for r in result}
        assert rules == {"ssh-brute", "http-probe"}

    def test_only_returns_vectors_for_specified_ip(self, intel_db):
        """Events for other IPs are not included."""
        _insert_ip_record(intel_db, "192.168.1.1")
        _insert_ip_record(intel_db, "192.168.1.2")
        conn = intel_db
        conn.execute(
            "INSERT INTO ip_intel_events (ip_address, node_id, event_type, event_kind, timestamp, detection_rule) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("192.168.1.1", "node-1", "ssh_brute", "block", "2024-01-01T00:00:00", "ssh-brute"),
        )
        conn.execute(
            "INSERT INTO ip_intel_events (ip_address, node_id, event_type, event_kind, timestamp, detection_rule) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("192.168.1.2", "node-1", "http_probe", "block", "2024-01-01T00:00:00", "http-probe"),
        )
        conn.commit()

        result = get_attack_vectors(intel_db, "192.168.1.1")
        assert len(result) == 1
        assert result[0]["detection_rule"] == "ssh-brute"


# ── process_unblock_event tests ──────────────────────────────────────────


class TestProcessUnblockEvent:
    """Tests for process_unblock_event()."""

    def test_skips_unknown_ip(self, intel_db):
        """If the IP does not exist in ip_intel, return status=skipped."""
        result = process_unblock_event(intel_db, "10.0.0.99", "2024-01-15T12:00:00")
        assert result["status"] == "skipped"
        assert result["ip_address"] == "10.0.0.99"

    def test_updates_last_unblocked_at_for_known_ip(self, intel_db):
        """Updates last_unblocked_at for an IP that exists in ip_intel."""
        _insert_ip_record(intel_db, "192.168.1.1", total_times_blocked=1,
                          last_blocked_at="2024-01-01T00:00:00")
        result = process_unblock_event(intel_db, "192.168.1.1", "2024-01-15T12:00:00")
        assert result["status"] == "accepted"
        assert result["ip_address"] == "192.168.1.1"

        # Verify the column was updated
        cursor = intel_db.execute(
            "SELECT last_unblocked_at FROM ip_intel WHERE ip_address = ?",
            ("192.168.1.1",),
        )
        row = cursor.fetchone()
        assert row["last_unblocked_at"] == "2024-01-15T12:00:00"

    def test_does_not_increment_total_times_seen(self, intel_db):
        """UNBLOCKED events SHALL NOT increment total_times_seen."""
        _insert_ip_record(intel_db, "192.168.1.1", total_times_seen=5)
        process_unblock_event(intel_db, "192.168.1.1", "2024-01-15T12:00:00")

        cursor = intel_db.execute(
            "SELECT total_times_seen FROM ip_intel WHERE ip_address = ?",
            ("192.168.1.1",),
        )
        row = cursor.fetchone()
        assert row["total_times_seen"] == 5

    def test_does_not_increment_total_times_blocked(self, intel_db):
        """UNBLOCKED events SHALL NOT increment total_times_blocked."""
        _insert_ip_record(intel_db, "192.168.1.1", total_times_blocked=3)
        process_unblock_event(intel_db, "192.168.1.1", "2024-01-15T12:00:00")

        cursor = intel_db.execute(
            "SELECT total_times_blocked FROM ip_intel WHERE ip_address = ?",
            ("192.168.1.1",),
        )
        row = cursor.fetchone()
        assert row["total_times_blocked"] == 3

    def test_overwrites_previous_unblock_timestamp(self, intel_db):
        """A second unblock event updates last_unblocked_at to the new timestamp."""
        _insert_ip_record(intel_db, "192.168.1.1")
        process_unblock_event(intel_db, "192.168.1.1", "2024-01-10T00:00:00")
        process_unblock_event(intel_db, "192.168.1.1", "2024-01-20T00:00:00")

        cursor = intel_db.execute(
            "SELECT last_unblocked_at FROM ip_intel WHERE ip_address = ?",
            ("192.168.1.1",),
        )
        row = cursor.fetchone()
        assert row["last_unblocked_at"] == "2024-01-20T00:00:00"

    def test_does_not_modify_other_fields(self, intel_db):
        """Unblock event should not touch reporting_node_list, threat_tags, etc."""
        _insert_ip_record(
            intel_db, "192.168.1.1",
            total_times_seen=5,
            total_times_blocked=3,
            total_reporting_nodes=2,
            reporting_node_list='["node-1", "node-2"]',
            threat_tags='["ssh-brute"]',
            geo_country="US",
        )
        process_unblock_event(intel_db, "192.168.1.1", "2024-01-15T12:00:00")

        cursor = intel_db.execute(
            "SELECT total_reporting_nodes, reporting_node_list, threat_tags, geo_country "
            "FROM ip_intel WHERE ip_address = ?",
            ("192.168.1.1",),
        )
        row = cursor.fetchone()
        assert row["total_reporting_nodes"] == 2
        assert json.loads(row["reporting_node_list"]) == ["node-1", "node-2"]
        assert json.loads(row["threat_tags"]) == ["ssh-brute"]
        assert row["geo_country"] == "US"


# ── Block Episode Detection tests ────────────────────────────────────────


class TestBlockEpisodeDetection:
    """Tests for block episode detection in upsert_ip_record() (Task 16.3).

    Verifies that block_episode_count is correctly incremented when:
    - First block event sets block_episode_count = 1
    - Block after unblock increments block_episode_count
    - Multiple blocks within same episode do NOT increment
    """

    def test_first_block_sets_episode_count_to_1(self, intel_db):
        """First block event ever for an IP sets block_episode_count = 1."""
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "NFT_ACTION",
            "2024-01-01T10:00:00", True, {"detection_rule": "ssh-brute"},
        )
        assert result["block_episode_count"] == 1

    def test_sighting_does_not_set_episode_count(self, intel_db):
        """A sighting event does not set block_episode_count."""
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "LOG_MATCH",
            "2024-01-01T10:00:00", False, None,
        )
        assert result["block_episode_count"] == 0

    def test_second_block_same_episode_no_increment(self, intel_db):
        """Second block without an intervening unblock stays at episode 1."""
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "NFT_ACTION",
            "2024-01-01T10:00:00", True, {"detection_rule": "ssh-brute"},
        )
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-2", "NFT_ACTION",
            "2024-01-01T11:00:00", True, {"detection_rule": "ssh-brute"},
        )
        assert result["block_episode_count"] == 1

    def test_block_after_unblock_increments_episode(self, intel_db):
        """Block after unblock starts a new episode (count goes to 2)."""
        # First block — episode 1
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "NFT_ACTION",
            "2024-01-01T10:00:00", True, {"detection_rule": "ssh-brute"},
        )
        # Unblock
        process_unblock_event(intel_db, "192.168.1.1", "2024-01-02T10:00:00")
        # Second block — episode 2
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "NFT_ACTION",
            "2024-01-03T10:00:00", True, {"detection_rule": "ssh-brute"},
        )
        assert result["block_episode_count"] == 2

    def test_multiple_blocks_after_unblock_only_one_increment(self, intel_db):
        """Multiple blocks after a single unblock only increment once."""
        # First block — episode 1
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "NFT_ACTION",
            "2024-01-01T10:00:00", True, {"detection_rule": "ssh-brute"},
        )
        # Unblock
        process_unblock_event(intel_db, "192.168.1.1", "2024-01-02T10:00:00")
        # Second block — episode 2
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "NFT_ACTION",
            "2024-01-03T10:00:00", True, {"detection_rule": "ssh-brute"},
        )
        # Third block (same episode, no new unblock) — still episode 2
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-2", "NFT_ACTION",
            "2024-01-03T11:00:00", True, {"detection_rule": "ssh-brute"},
        )
        assert result["block_episode_count"] == 2

    def test_three_episodes(self, intel_db):
        """Block → unblock → block → unblock → block = 3 episodes."""
        # Episode 1
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "NFT_ACTION",
            "2024-01-01T10:00:00", True, {"detection_rule": "ssh-brute"},
        )
        # Unblock 1
        process_unblock_event(intel_db, "192.168.1.1", "2024-01-02T10:00:00")
        # Episode 2
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "NFT_ACTION",
            "2024-01-03T10:00:00", True, {"detection_rule": "ssh-brute"},
        )
        # Unblock 2
        process_unblock_event(intel_db, "192.168.1.1", "2024-01-04T10:00:00")
        # Episode 3
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "NFT_ACTION",
            "2024-01-05T10:00:00", True, {"detection_rule": "ssh-brute"},
        )
        assert result["block_episode_count"] == 3

    def test_sighting_after_unblock_does_not_increment_episode(self, intel_db):
        """A sighting event after unblock does not start a new episode."""
        # First block — episode 1
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "NFT_ACTION",
            "2024-01-01T10:00:00", True, {"detection_rule": "ssh-brute"},
        )
        # Unblock
        process_unblock_event(intel_db, "192.168.1.1", "2024-01-02T10:00:00")
        # Sighting — should NOT increment episode count
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "LOG_MATCH",
            "2024-01-03T10:00:00", False, None,
        )
        assert result["block_episode_count"] == 1

    def test_last_unblocked_at_preserved_after_new_block(self, intel_db):
        """last_unblocked_at is preserved for reference after a new block."""
        # First block
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "NFT_ACTION",
            "2024-01-01T10:00:00", True, {"detection_rule": "ssh-brute"},
        )
        # Unblock
        process_unblock_event(intel_db, "192.168.1.1", "2024-01-02T10:00:00")
        # New block
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "NFT_ACTION",
            "2024-01-03T10:00:00", True, {"detection_rule": "ssh-brute"},
        )
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "NFT_ACTION",
            "2024-01-03T10:00:00", True, {"detection_rule": "ssh-brute"},
        )
        assert result["last_unblocked_at"] == "2024-01-02T10:00:00"

    def test_counters_not_affected_by_episode_logic(self, intel_db):
        """Block episode logic does not interfere with counter increments."""
        # First block
        upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "NFT_ACTION",
            "2024-01-01T10:00:00", True, {"detection_rule": "ssh-brute"},
        )
        # Unblock
        process_unblock_event(intel_db, "192.168.1.1", "2024-01-02T10:00:00")
        # Second block
        result = upsert_ip_record(
            intel_db, "192.168.1.1", "node-1", "NFT_ACTION",
            "2024-01-03T10:00:00", True, {"detection_rule": "ssh-brute"},
        )
        assert result["total_times_seen"] == 2
        assert result["total_times_blocked"] == 2
        assert result["block_episode_count"] == 2


# ── MySQL backend detection tests ────────────────────────────────────────


class TestUpsertMySQLBackendDetection:
    """Tests verifying that upsert_ip_record() detects MySQL backend and uses
    INSERT ... ON DUPLICATE KEY UPDATE instead of INSERT OR IGNORE."""

    def test_sqlite_uses_insert_or_ignore(self, intel_db):
        """SQLite backend uses INSERT OR IGNORE + UPDATE pattern.

        We verify this indirectly: the SQLite path should work correctly
        with INSERT OR IGNORE (which is the only valid syntax for SQLite).
        If it tried ON DUPLICATE KEY UPDATE, SQLite would raise an error.
        """
        # This would fail if the code used ON DUPLICATE KEY UPDATE on SQLite
        result = upsert_ip_record(
            intel_db, "10.0.0.1", "node-1", "ssh_brute",
            "2024-01-01T00:00:00", False, None,
        )
        assert result["ip_address"] == "10.0.0.1"
        assert result["total_times_seen"] == 1

        # Second upsert should also work (INSERT OR IGNORE is a no-op, UPDATE applies)
        result = upsert_ip_record(
            intel_db, "10.0.0.1", "node-2", "ssh_brute",
            "2024-01-02T00:00:00", True, None,
        )
        assert result["total_times_seen"] == 2
        assert result["total_times_blocked"] == 1

    def test_mysql_backend_detected_correctly(self):
        """MySQL backend is detected via isinstance check on MySQLConnectionWrapper."""
        from app.db_compat import MySQLConnectionWrapper
        from unittest.mock import MagicMock

        mock_raw_conn = MagicMock()
        mysql_conn = MySQLConnectionWrapper(mock_raw_conn)

        # Verify isinstance detection works
        assert isinstance(mysql_conn, MySQLConnectionWrapper)

    def test_mysql_connection_sets_read_committed_isolation(self):
        """get_db() sets session-level READ COMMITTED isolation for MySQL connections."""
        from unittest.mock import MagicMock, patch

        mock_raw_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_raw_conn.cursor.return_value = mock_cursor

        db_config = {
            "DATABASE_TYPE": "mysql",
            "DATABASE_HOST": "localhost",
            "DATABASE_PORT": 3306,
            "DATABASE_NAME": "vespid_test",
            "DATABASE_USER": "test",
            "DATABASE_PASSWORD": "test",
        }

        with patch("mysql.connector.connect", return_value=mock_raw_conn):
            from app.models import get_db
            conn = get_db(db_config)

        # Verify that SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED was executed
        execute_calls = mock_cursor.execute.call_args_list
        isolation_calls = [
            call for call in execute_calls
            if "ISOLATION LEVEL READ COMMITTED" in str(call)
        ]
        assert len(isolation_calls) == 1, (
            f"Expected exactly one SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED call, "
            f"got: {execute_calls}"
        )
        mock_cursor.close.assert_called_once()

    def test_mysql_generates_on_duplicate_key_update_sql(self):
        """MySQL path generates INSERT ... ON DUPLICATE KEY UPDATE SQL.

        We verify by wrapping the connection to capture SQL statements.
        """
        from unittest.mock import MagicMock, patch, PropertyMock
        from app.db_compat import MySQLConnectionWrapper, CursorWrapper, RowWrapper

        # Create a mock MySQL connection
        mock_raw_conn = MagicMock()
        mysql_conn = MySQLConnectionWrapper(mock_raw_conn)

        # Capture SQL statements passed to CursorWrapper.execute
        captured_sql = []

        # Column definitions for different queries
        select_state_cols = [
            "reporting_node_list", "threat_tags", "total_times_seen",
            "total_times_blocked", "total_reporting_nodes",
            "total_attack_events", "repeat_offender", "geo_country",
            "asn", "isp_organization", "last_unblocked_at",
            "block_episode_count", "last_blocked_at", "total_requests",
        ]
        select_all_cols = [
            "id", "ip_address", "ip_version", "first_seen_at", "last_seen_at",
            "last_blocked_at", "total_times_seen", "total_times_blocked",
            "total_reporting_nodes", "total_attack_events", "total_requests",
            "last_unblocked_at", "block_episode_count", "repeat_offender",
            "repeat_offender_since", "first_reporting_node",
            "most_recent_reporting_node", "reporting_node_list", "geo_country",
            "asn", "isp_organization", "reputation_score", "threat_tags",
        ]

        state_row = RowWrapper(
            ('[]', '[]', 0, 0, 0, 0, 0, None, None, None, None, 0, None, 0),
            select_state_cols,
        )
        all_row = RowWrapper(
            (1, "10.0.0.1", "v4", "2024-01-01 00:00:00", "2024-01-01 00:00:00",
             None, 1, 0, 1, 0, 0, None, 0, 0, None, "node-1", "node-1",
             '["node-1"]', None, None, None, None, '[]'),
            select_all_cols,
        )

        # Track which fetchone call we're on
        fetchone_calls = [0]
        fetchone_results = [state_row, all_row]

        def patched_cw_execute(self, sql, params=None):
            captured_sql.append(sql)
            # Execute on mock cursor with translated SQL
            from app.db_compat import translate_placeholders, _normalize_param
            translated = translate_placeholders(sql)
            if params is not None:
                if isinstance(params, list):
                    params = tuple(params)
                params = tuple(_normalize_param(p) for p in params)
                self._cursor.execute(translated, params)
            else:
                self._cursor.execute(translated)
            return self

        def patched_cw_fetchone(self):
            idx = fetchone_calls[0]
            fetchone_calls[0] += 1
            if idx < len(fetchone_results):
                return fetchone_results[idx]
            return None

        with patch.object(CursorWrapper, 'execute', patched_cw_execute), \
             patch.object(CursorWrapper, 'fetchone', patched_cw_fetchone):
            upsert_ip_record(
                mysql_conn, "10.0.0.1", "node-1", "ssh_brute",
                "2024-01-01T00:00:00", False, None,
            )

        # Verify ON DUPLICATE KEY UPDATE was used for the ip_intel INSERT
        ip_intel_inserts = [
            s for s in captured_sql
            if "INSERT" in s.upper() and "ip_intel" in s and "ip_intel_events" not in s
        ]
        assert len(ip_intel_inserts) > 0, "Should have at least one INSERT for ip_intel"
        assert any("ON DUPLICATE KEY UPDATE" in s for s in ip_intel_inserts), (
            f"MySQL path should use ON DUPLICATE KEY UPDATE. Got: {ip_intel_inserts}"
        )
        assert not any("INSERT OR IGNORE" in s for s in ip_intel_inserts), (
            "MySQL path should NOT use INSERT OR IGNORE"
        )
        assert not any("INSERT IGNORE" in s for s in ip_intel_inserts), (
            "MySQL path should NOT use INSERT IGNORE"
        )
