"""Unit tests for the PropagationEngine.

Tests core functionality: process_block_report, corroboration, rate limits,
allow-list matching, TTL renewal, reap_expired, and audit log entries.

Requirements: 1.3, 1.4, 1.5, 3.1, 3.2, 4.1, 4.3, 5.5, 7.1, 7.2, 9.2, 9.3
"""

import json
import sqlite3
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest

from app.fleet_sse import FleetSSEManager
from app.models import get_db, init_db
from app.propagation_engine import PropagationEngine, _format_ts, _utcnow


@pytest.fixture()
def db_path(tmp_path):
    """Create a temporary database with fleet tables initialized."""
    path = str(tmp_path / "test_fleet.db")
    init_db(path)
    return path


@pytest.fixture()
def fleet_sse():
    """Create a FleetSSEManager instance for testing."""
    return FleetSSEManager(history_size=100)


@pytest.fixture()
def engine(db_path, fleet_sse):
    """Create a PropagationEngine instance for testing."""
    return PropagationEngine(db_path, fleet_sse)


class TestCheckAllowlist:
    """Tests for check_allowlist method."""

    def test_empty_allowlist_returns_false(self, engine):
        assert engine.check_allowlist("192.168.1.1") is False

    def test_exact_ip_match(self, db_path, engine):
        conn = get_db(db_path)
        conn.execute(
            "INSERT INTO fleet_allowlist (entry, created_by) VALUES (?, ?)",
            ("10.0.0.1", "admin"),
        )
        conn.commit()
        conn.close()

        assert engine.check_allowlist("10.0.0.1") is True
        assert engine.check_allowlist("10.0.0.2") is False

    def test_cidr_match(self, db_path, engine):
        conn = get_db(db_path)
        conn.execute(
            "INSERT INTO fleet_allowlist (entry, created_by) VALUES (?, ?)",
            ("192.168.1.0/24", "admin"),
        )
        conn.commit()
        conn.close()

        assert engine.check_allowlist("192.168.1.100") is True
        assert engine.check_allowlist("192.168.2.1") is False

    def test_inactive_entry_not_matched(self, db_path, engine):
        conn = get_db(db_path)
        conn.execute(
            "INSERT INTO fleet_allowlist (entry, created_by, is_active) "
            "VALUES (?, ?, ?)",
            ("10.0.0.1", "admin", 0),
        )
        conn.commit()
        conn.close()

        assert engine.check_allowlist("10.0.0.1") is False


class TestCheckCorroboration:
    """Tests for check_corroboration method."""

    def test_no_reports_returns_zero(self, engine):
        assert engine.check_corroboration("1.2.3.4") == 0

    def test_counts_distinct_nodes(self, db_path, engine):
        conn = get_db(db_path)
        now = _format_ts(_utcnow())
        for i in range(3):
            conn.execute(
                "INSERT INTO fleet_block_reports "
                "(source_ip, node_id, event_type, reported_at) "
                "VALUES (?, ?, ?, ?)",
                ("1.2.3.4", f"node-{i}", "SSH_BRUTE", now),
            )
        conn.commit()
        conn.close()

        assert engine.check_corroboration("1.2.3.4") == 3

    def test_old_reports_not_counted(self, db_path, engine):
        conn = get_db(db_path)
        old_time = _format_ts(_utcnow() - timedelta(hours=2))
        conn.execute(
            "INSERT INTO fleet_block_reports "
            "(source_ip, node_id, event_type, reported_at) "
            "VALUES (?, ?, ?, ?)",
            ("1.2.3.4", "node-old", "SSH_BRUTE", old_time),
        )
        conn.commit()
        conn.close()

        assert engine.check_corroboration("1.2.3.4") == 0


class TestCheckRateLimits:
    """Tests for check_rate_limits method."""

    def test_no_activity_returns_ok(self, engine):
        fleet_ok, node_ok = engine.check_rate_limits("node-1")
        assert fleet_ok is True
        assert node_ok is True

    def test_node_rate_limit_exceeded(self, db_path, fleet_sse):
        config = {
            "corroboration_threshold": 1,
            "corroboration_window_seconds": 3600,
            "fleet_block_ttl_seconds": 3600,
            "max_fleet_blocks_per_hour": 100,
            "max_reports_per_node_per_hour": 5,
            "propagation_paused": False,
            "excluded_event_types": [],
            "reaper_interval_seconds": 60,
        }
        engine = PropagationEngine(db_path, fleet_sse, config=config)

        conn = get_db(db_path)
        now = _format_ts(_utcnow())
        for i in range(5):
            conn.execute(
                "INSERT INTO fleet_block_reports "
                "(source_ip, node_id, event_type, reported_at) "
                "VALUES (?, ?, ?, ?)",
                (f"10.0.0.{i}", "node-1", "SSH_BRUTE", now),
            )
        conn.commit()
        conn.close()

        fleet_ok, node_ok = engine.check_rate_limits("node-1")
        assert fleet_ok is True
        assert node_ok is False


class TestProcessBlockReport:
    """Tests for process_block_report method."""

    def test_missing_fields_rejected(self, engine):
        result = engine.process_block_report({"source_ip": "1.2.3.4"})
        assert result["status"] == "rejected"

    def test_valid_report_accepted_and_propagated(self, engine):
        """With threshold=1, a single report should propagate immediately."""
        result = engine.process_block_report({
            "source_ip": "10.0.0.1",
            "node_id": "node-alpha",
            "event_type": "SSH_BRUTE",
            "detection_rule": "ssh_brute_force",
        })
        assert result["status"] == "propagated"
        assert "fleet_block_id" in result

    def test_allowlisted_ip_rejected(self, db_path, engine):
        conn = get_db(db_path)
        conn.execute(
            "INSERT INTO fleet_allowlist (entry, created_by) VALUES (?, ?)",
            ("10.0.0.1", "admin"),
        )
        conn.commit()
        conn.close()

        result = engine.process_block_report({
            "source_ip": "10.0.0.1",
            "node_id": "node-alpha",
            "event_type": "SSH_BRUTE",
        })
        assert result["status"] == "rejected"
        assert "allow-list" in result["reason"]

    def test_excluded_event_type_rejected(self, db_path, fleet_sse):
        config = {
            "corroboration_threshold": 1,
            "corroboration_window_seconds": 3600,
            "fleet_block_ttl_seconds": 3600,
            "max_fleet_blocks_per_hour": 100,
            "max_reports_per_node_per_hour": 50,
            "propagation_paused": False,
            "excluded_event_types": ["NOISE_EVENT"],
            "reaper_interval_seconds": 60,
        }
        engine = PropagationEngine(db_path, fleet_sse, config=config)

        result = engine.process_block_report({
            "source_ip": "10.0.0.1",
            "node_id": "node-alpha",
            "event_type": "NOISE_EVENT",
        })
        assert result["status"] == "rejected"
        assert "excluded" in result["reason"]

    def test_corroboration_threshold_requires_multiple_nodes(self, db_path, fleet_sse):
        config = {
            "corroboration_threshold": 3,
            "corroboration_window_seconds": 3600,
            "fleet_block_ttl_seconds": 3600,
            "max_fleet_blocks_per_hour": 100,
            "max_reports_per_node_per_hour": 50,
            "propagation_paused": False,
            "excluded_event_types": [],
            "reaper_interval_seconds": 60,
        }
        engine = PropagationEngine(db_path, fleet_sse, config=config)

        # First report - not enough corroboration
        result = engine.process_block_report({
            "source_ip": "10.0.0.1",
            "node_id": "node-1",
            "event_type": "SSH_BRUTE",
        })
        assert result["status"] == "accepted"

        # Second report - still not enough
        result = engine.process_block_report({
            "source_ip": "10.0.0.1",
            "node_id": "node-2",
            "event_type": "SSH_BRUTE",
        })
        assert result["status"] == "accepted"

        # Third report - threshold met, should propagate
        result = engine.process_block_report({
            "source_ip": "10.0.0.1",
            "node_id": "node-3",
            "event_type": "SSH_BRUTE",
        })
        assert result["status"] == "propagated"

    def test_duplicate_report_same_node_updates_timestamp(self, db_path, fleet_sse):
        config = {
            "corroboration_threshold": 2,
            "corroboration_window_seconds": 3600,
            "fleet_block_ttl_seconds": 3600,
            "max_fleet_blocks_per_hour": 100,
            "max_reports_per_node_per_hour": 50,
            "propagation_paused": False,
            "excluded_event_types": [],
            "reaper_interval_seconds": 60,
        }
        engine = PropagationEngine(db_path, fleet_sse, config=config)

        # Submit same report twice from same node
        engine.process_block_report({
            "source_ip": "10.0.0.1",
            "node_id": "node-1",
            "event_type": "SSH_BRUTE",
        })
        engine.process_block_report({
            "source_ip": "10.0.0.1",
            "node_id": "node-1",
            "event_type": "SSH_BRUTE",
        })

        # Should only have 1 report record (idempotent)
        conn = get_db(db_path)
        count = conn.execute(
            "SELECT COUNT(*) as cnt FROM fleet_block_reports "
            "WHERE source_ip = '10.0.0.1' AND node_id = 'node-1'"
        ).fetchone()["cnt"]
        conn.close()

        assert count == 1

    def test_ttl_renewal_on_existing_active_block(self, db_path, engine):
        # First report propagates (threshold=1)
        result1 = engine.process_block_report({
            "source_ip": "10.0.0.1",
            "node_id": "node-1",
            "event_type": "SSH_BRUTE",
        })
        assert result1["status"] == "propagated"

        # Second report from different node renews TTL
        result2 = engine.process_block_report({
            "source_ip": "10.0.0.1",
            "node_id": "node-2",
            "event_type": "SSH_BRUTE",
        })
        assert result2["status"] == "accepted"
        assert "TTL renewed" in result2["reason"]

    def test_paused_propagation_stores_but_does_not_publish(self, db_path, fleet_sse):
        config = {
            "corroboration_threshold": 1,
            "corroboration_window_seconds": 3600,
            "fleet_block_ttl_seconds": 3600,
            "max_fleet_blocks_per_hour": 100,
            "max_reports_per_node_per_hour": 50,
            "propagation_paused": True,
            "excluded_event_types": [],
            "reaper_interval_seconds": 60,
        }
        engine = PropagationEngine(db_path, fleet_sse, config=config)

        # Subscribe to SSE to check no messages are published
        client_queue = fleet_sse.create_client()

        result = engine.process_block_report({
            "source_ip": "10.0.0.1",
            "node_id": "node-1",
            "event_type": "SSH_BRUTE",
        })
        assert result["status"] == "accepted"
        assert "paused" in result["reason"]

        # Verify no SSE message was published
        assert client_queue.empty()

        fleet_sse.remove_client(client_queue)

    def test_expired_block_not_renewed(self, db_path, fleet_sse):
        """A stale active block past its expires_at is expired and a fresh block created."""
        config = {
            "corroboration_threshold": 1,
            "corroboration_window_seconds": 3600,
            "fleet_block_ttl_seconds": 3600,
            "fleet_recidive_tiers": [86400, 259200],
            "fleet_recidive_decay_seconds": 2592000,
            "max_fleet_blocks_per_hour": 100,
            "max_reports_per_node_per_hour": 50,
            "propagation_paused": False,
            "excluded_event_types": [],
            "reaper_interval_seconds": 60,
        }
        engine = PropagationEngine(db_path, fleet_sse, config=config)

        # Insert an active block whose expires_at is already in the past
        conn = get_db(db_path)
        past_expires = _format_ts(_utcnow() - timedelta(hours=2))
        conn.execute(
            "INSERT INTO fleet_blocks "
            "(fleet_block_id, source_ip, status, first_reported_at, "
            "last_renewed_at, approved_at, expires_at, "
            "reporting_node_count, originating_node_id, event_type, "
            "detection_rule, reason, ttl_seconds) "
            "VALUES (?, ?, 'active', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("fb-stale-1", "10.0.1.1",
             _format_ts(_utcnow() - timedelta(hours=3)),
             _format_ts(_utcnow() - timedelta(hours=3)),
             _format_ts(_utcnow() - timedelta(hours=3)),
             past_expires,
             1, "node-1", "SSH_BRUTE", "ssh_medium_brute", "Test", 3600),
        )
        conn.commit()
        conn.close()

        result = engine.process_block_report({
            "source_ip": "10.0.1.1",
            "node_id": "node-1",
            "event_type": "SSH_BRUTE",
            "detection_rule": "ssh_medium_brute",
        })
        # Should not renew — should create a fresh block via normal approval
        assert result["status"] == "propagated"
        assert "fleet_block_id" in result

        # The old block should now be expired
        conn = get_db(db_path)
        old = conn.execute(
            "SELECT status FROM fleet_blocks WHERE fleet_block_id = 'fb-stale-1'"
        ).fetchone()
        conn.close()
        assert old["status"] == "expired"


class TestManualAdd:
    """Tests for manual_add method."""

    def test_manual_add_creates_active_block(self, engine):
        result = engine.manual_add("10.0.0.1", "Known attacker", "admin")
        assert result["status"] == "propagated"
        assert "fleet_block_id" in result

    def test_manual_add_rejects_allowlisted_ip(self, db_path, engine):
        conn = get_db(db_path)
        conn.execute(
            "INSERT INTO fleet_allowlist (entry, created_by) VALUES (?, ?)",
            ("10.0.0.1", "admin"),
        )
        conn.commit()
        conn.close()

        result = engine.manual_add("10.0.0.1", "Test", "admin")
        assert result["status"] == "rejected"

    def test_manual_add_existing_returns_exists(self, engine):
        engine.manual_add("10.0.0.1", "First", "admin")
        result = engine.manual_add("10.0.0.1", "Second", "admin")
        assert result["status"] == "exists"


class TestManualRemove:
    """Tests for manual_remove method."""

    def test_manual_remove_publishes_unblock(self, engine, fleet_sse):
        client_queue = fleet_sse.create_client()

        engine.manual_add("10.0.0.1", "Test", "admin")
        # Drain the block message
        client_queue.get(timeout=1)

        result = engine.manual_remove("10.0.0.1", "admin")
        assert result["status"] == "removed"

        # Check unblock message was published
        msg = client_queue.get(timeout=1)
        assert "unblock" in msg

        fleet_sse.remove_client(client_queue)

    def test_manual_remove_not_found(self, engine):
        result = engine.manual_remove("10.0.0.1", "admin")
        assert result["status"] == "not_found"


class TestAddAllowlistEntry:
    """Tests for add_allowlist_entry method."""

    def test_add_entry_removes_matching_blocks(self, engine, fleet_sse):
        # Add a block first
        engine.manual_add("10.0.0.1", "Test", "admin")

        # Now add allowlist entry that matches
        result = engine.add_allowlist_entry("10.0.0.1", "admin")
        assert result["status"] == "added"
        assert result["blocks_removed"] == 1

    def test_add_cidr_removes_matching_blocks(self, engine, fleet_sse):
        engine.manual_add("192.168.1.50", "Test", "admin")

        result = engine.add_allowlist_entry("192.168.1.0/24", "admin")
        assert result["status"] == "added"
        assert result["blocks_removed"] == 1


class TestRemoveAllowlistEntry:
    """Tests for remove_allowlist_entry method."""

    def test_remove_deactivates_entry(self, db_path, engine):
        conn = get_db(db_path)
        conn.execute(
            "INSERT INTO fleet_allowlist (entry, created_by) VALUES (?, ?)",
            ("10.0.0.1", "admin"),
        )
        conn.commit()
        entry_id = conn.execute(
            "SELECT id FROM fleet_allowlist WHERE entry = '10.0.0.1'"
        ).fetchone()["id"]
        conn.close()

        result = engine.remove_allowlist_entry(entry_id, "admin")
        assert result["status"] == "removed"

        # Verify it's deactivated
        conn = get_db(db_path)
        row = conn.execute(
            "SELECT is_active FROM fleet_allowlist WHERE id = ?",
            (entry_id,),
        ).fetchone()
        conn.close()
        assert row["is_active"] == 0

    def test_remove_nonexistent_returns_not_found(self, engine):
        result = engine.remove_allowlist_entry(9999, "admin")
        assert result["status"] == "not_found"


class TestReapExpired:
    """Tests for reap_expired method."""

    def test_reap_expires_old_blocks(self, db_path, engine, fleet_sse):
        # Insert an expired block directly
        past = _format_ts(_utcnow() - timedelta(hours=1))
        conn = get_db(db_path)
        conn.execute(
            "INSERT INTO fleet_blocks "
            "(fleet_block_id, source_ip, status, expires_at, "
            "originating_node_id, event_type) "
            "VALUES (?, ?, 'active', ?, ?, ?)",
            ("fb-expired-1", "10.0.0.1", past, "node-1", "SSH_BRUTE"),
        )
        conn.commit()
        conn.close()

        client_queue = fleet_sse.create_client()
        count = engine.reap_expired()
        assert count == 1

        # Verify unblock message published
        msg = client_queue.get(timeout=1)
        assert "unblock" in msg
        assert "10.0.0.1" in msg

        fleet_sse.remove_client(client_queue)

    def test_reap_does_not_expire_future_blocks(self, db_path, engine):
        future = _format_ts(_utcnow() + timedelta(hours=1))
        conn = get_db(db_path)
        conn.execute(
            "INSERT INTO fleet_blocks "
            "(fleet_block_id, source_ip, status, expires_at, "
            "originating_node_id, event_type) "
            "VALUES (?, ?, 'active', ?, ?, ?)",
            ("fb-future-1", "10.0.0.2", future, "node-1", "SSH_BRUTE"),
        )
        conn.commit()
        conn.close()

        count = engine.reap_expired()
        assert count == 0

    def test_reap_no_expired_returns_zero(self, engine):
        count = engine.reap_expired()
        assert count == 0


class TestAuditLogging:
    """Tests for audit log entries created by the engine."""

    def test_report_does_not_create_audit_entry(self, db_path, engine):
        engine.process_block_report({
            "source_ip": "10.0.0.1",
            "node_id": "node-1",
            "event_type": "SSH_BRUTE",
        })

        conn = get_db(db_path)
        entries = conn.execute(
            "SELECT action_type, target, details FROM audit_log "
            "WHERE action_type = 'fleet_block_reported'"
        ).fetchall()
        conn.close()

        assert len(entries) == 0

    def test_propagation_creates_audit_entry(self, db_path, engine):
        engine.process_block_report({
            "source_ip": "10.0.0.1",
            "node_id": "node-1",
            "event_type": "SSH_BRUTE",
        })

        conn = get_db(db_path)
        entries = conn.execute(
            "SELECT action_type, target, details FROM audit_log "
            "WHERE action_type = 'fleet_block_propagated'"
        ).fetchall()
        conn.close()

        assert len(entries) == 1
        details = json.loads(entries[0]["details"])
        assert "fleet_block_id" in details

    def test_rejection_creates_audit_entry(self, db_path, engine):
        conn = get_db(db_path)
        conn.execute(
            "INSERT INTO fleet_allowlist (entry, created_by) VALUES (?, ?)",
            ("10.0.0.1", "admin"),
        )
        conn.commit()
        conn.close()

        engine.process_block_report({
            "source_ip": "10.0.0.1",
            "node_id": "node-1",
            "event_type": "SSH_BRUTE",
        })

        conn = get_db(db_path)
        entries = conn.execute(
            "SELECT action_type, details FROM audit_log "
            "WHERE action_type = 'fleet_block_rejected'"
        ).fetchall()
        conn.close()

        assert len(entries) >= 1
        details = json.loads(entries[0]["details"])
        assert details["reason"] == "allowlisted"

    def test_expired_block_creates_audit_entry(self, db_path, engine):
        past = _format_ts(_utcnow() - timedelta(hours=1))
        conn = get_db(db_path)
        conn.execute(
            "INSERT INTO fleet_blocks "
            "(fleet_block_id, source_ip, status, expires_at, "
            "originating_node_id, event_type) "
            "VALUES (?, ?, 'active', ?, ?, ?)",
            ("fb-exp-audit", "10.0.0.99", past, "node-1", "SSH_BRUTE"),
        )
        conn.commit()
        conn.close()

        engine.reap_expired()

        conn = get_db(db_path)
        entries = conn.execute(
            "SELECT action_type, target FROM audit_log "
            "WHERE action_type = 'fleet_block_expired'"
        ).fetchall()
        conn.close()

        assert len(entries) == 1
        assert entries[0]["target"] == "10.0.0.99"


class TestFleetRecidive:
    """Tests for fleet-wide recidive (repeat offender) TTL escalation.

    The propagation engine queries ``ip_intel.total_times_blocked`` — the
    full history of every block across the fleet — to determine the recidive
    strike.  The strike maps to an escalated TTL via ``fleet_recidive_tiers``.
    Decay is applied via ``fleet_recidive_decay_seconds`` against the
    ``last_blocked_at`` timestamp.
    """

    RECIDIVE_CONFIG = {
        "corroboration_threshold": 1,
        "corroboration_window_seconds": 3600,
        "fleet_block_ttl_seconds": 3600,
        "fleet_recidive_tiers": [86400, 259200, 604800, 2592000],
        "fleet_recidive_decay_seconds": 2592000,
        "max_fleet_blocks_per_hour": 100,
        "max_reports_per_node_per_hour": 50,
        "propagation_paused": False,
        "excluded_event_types": [],
        "reaper_interval_seconds": 86400,
        "expired_block_retention_seconds": 86400,
    }

    @staticmethod
    def _seed_intel_block_count(db_path, ip: str, count: int, last_blocked_offset_days: int | None = None):
        """Seed the ip_intel table with a given total_times_blocked value."""
        from datetime import timedelta

        now = _utcnow()
        last_blocked = None
        if last_blocked_offset_days is not None:
            last_blocked = _format_ts(now + timedelta(days=last_blocked_offset_days))
        conn = get_db(db_path)
        conn.execute(
            "INSERT OR REPLACE INTO ip_intel "
            "(ip_address, ip_version, first_seen_at, last_seen_at, "
            "last_blocked_at, total_times_seen, total_times_blocked, "
            "total_reporting_nodes, total_attack_events, total_requests, "
            "block_episode_count, repeat_offender, "
            "first_reporting_node, most_recent_reporting_node, "
            "reporting_node_list) "
            "VALUES (?, 'v4', ?, ?, ?, ?, ?, 1, ?, 1, ?, ?, 'node-test', 'node-test', '[]')",
            (
                ip,
                _format_ts(now),
                _format_ts(now),
                last_blocked or _format_ts(now),
                max(count, 1),
                count,
                count,
                count,
                1 if count >= 2 else 0,
            ),
        )
        conn.commit()
        conn.close()

    def test_strike_zero_never_seen_uses_first_tier(self, db_path, fleet_sse):
        """IP with no Intel record (strike=0) → first tier (1 day)."""
        engine = PropagationEngine(db_path, fleet_sse, config=self.RECIDIVE_CONFIG)
        ttl = engine._ttl_for_fleet_strike(0)
        assert ttl == 86400  # 1 day

    def test_strike_one_uses_second_tier(self, db_path, fleet_sse):
        """IP blocked once before (strike=1) → second tier (3 days)."""
        engine = PropagationEngine(db_path, fleet_sse, config=self.RECIDIVE_CONFIG)
        ttl = engine._ttl_for_fleet_strike(1)
        assert ttl == 259200  # 3 days

    def test_strike_two_uses_third_tier(self, db_path, fleet_sse):
        """IP blocked twice before (strike=2) → third tier (7 days)."""
        engine = PropagationEngine(db_path, fleet_sse, config=self.RECIDIVE_CONFIG)
        ttl = engine._ttl_for_fleet_strike(2)
        assert ttl == 604800  # 7 days

    def test_strike_three_uses_fourth_tier(self, db_path, fleet_sse):
        """IP blocked three times before (strike=3) → fourth tier (30 days)."""
        engine = PropagationEngine(db_path, fleet_sse, config=self.RECIDIVE_CONFIG)
        ttl = engine._ttl_for_fleet_strike(3)
        assert ttl == 2592000  # 30 days

    def test_strike_exceeds_tiers_caps_at_last(self, db_path, fleet_sse):
        """Strike beyond available tiers caps at the last tier."""
        engine = PropagationEngine(db_path, fleet_sse, config=self.RECIDIVE_CONFIG)
        ttl = engine._ttl_for_fleet_strike(10)
        assert ttl == 2592000  # 30 days (capped)

    def test_no_tiers_falls_back_to_default_ttl(self, db_path, fleet_sse):
        """When tiers list is empty, fall back to fleet_block_ttl_seconds."""
        config = dict(self.RECIDIVE_CONFIG)
        config["fleet_recidive_tiers"] = []
        engine = PropagationEngine(db_path, fleet_sse, config=config)
        ttl = engine._ttl_for_fleet_strike(2)
        assert ttl == 3600  # default TTL

    def test_get_fleet_strike_returns_zero_for_unknown_ip(self, db_path, fleet_sse):
        """IP with no prior fleet blocks returns strike=0."""
        engine = PropagationEngine(db_path, fleet_sse, config=self.RECIDIVE_CONFIG)
        strike = engine._get_fleet_strike("10.99.99.99")
        assert strike == 0

    def test_get_fleet_strike_counts_prior_blocks(self, db_path, fleet_sse):
        """IP with two prior blocks in intel returns strike=2."""
        self._seed_intel_block_count(db_path, "10.0.0.55", 2)
        engine = PropagationEngine(db_path, fleet_sse, config=self.RECIDIVE_CONFIG)
        strike = engine._get_fleet_strike("10.0.0.55")
        assert strike == 2

    def test_first_block_new_ip_gets_one_day(self, db_path, fleet_sse):
        """End-to-end: brand new IP blocked for the first time → 1d TTL."""
        engine = PropagationEngine(db_path, fleet_sse, config=self.RECIDIVE_CONFIG)

        result = engine.process_block_report({
            "source_ip": "10.0.0.100",
            "node_id": "node-1",
            "event_type": "SSH_BRUTE",
            "detection_rule": "ssh_brute_medium",
        })
        assert result["status"] == "propagated"

        # Verify the block was created with 1d TTL
        conn = get_db(db_path)
        row = conn.execute(
            "SELECT ttl_seconds, expires_at, first_reported_at FROM fleet_blocks "
            "WHERE source_ip = '10.0.0.100' AND status = 'active'"
        ).fetchone()
        conn.close()

        assert row is not None
        assert row["ttl_seconds"] == 86400  # 1 day

    def test_second_block_same_ip_gets_three_days(self, db_path, fleet_sse):
        """End-to-end: IP with one prior intel block → second block gets 3d TTL."""
        self._seed_intel_block_count(db_path, "10.0.0.200", 1)

        engine = PropagationEngine(db_path, fleet_sse, config=self.RECIDIVE_CONFIG)

        result = engine.process_block_report({
            "source_ip": "10.0.0.200",
            "node_id": "node-1",
            "event_type": "SSH_BRUTE",
            "detection_rule": "ssh_brute_medium",
        })
        assert result["status"] == "propagated"

        conn = get_db(db_path)
        row = conn.execute(
            "SELECT ttl_seconds FROM fleet_blocks "
            "WHERE source_ip = '10.0.0.200' AND status = 'active'"
        ).fetchone()
        conn.close()

        assert row is not None
        assert row["ttl_seconds"] == 259200  # 3 days

    def test_renewal_escalates_ttl(self, db_path, fleet_sse):
        """Renewing an existing block uses escalated TTL from intel."""
        self._seed_intel_block_count(db_path, "10.0.0.150", 3)

        engine = PropagationEngine(db_path, fleet_sse, config=self.RECIDIVE_CONFIG)

        # First report creates the block with escalated TTL
        result1 = engine.process_block_report({
            "source_ip": "10.0.0.150",
            "node_id": "node-1",
            "event_type": "SSH_BRUTE",
            "detection_rule": "ssh_brute_medium",
        })
        assert result1["status"] == "propagated"

        # Second report (different node) triggers renewal with escalated TTL
        result2 = engine.process_block_report({
            "source_ip": "10.0.0.150",
            "node_id": "node-2",
            "event_type": "SSH_BRUTE",
            "detection_rule": "ssh_brute_medium",
        })
        assert result2["status"] == "accepted"
        assert "TTL renewed" in result2["reason"]

        conn = get_db(db_path)
        row = conn.execute(
            "SELECT ttl_seconds FROM fleet_blocks "
            "WHERE source_ip = '10.0.0.150' AND status = 'active'"
        ).fetchone()
        conn.close()

        assert row is not None
        assert row["ttl_seconds"] == 2592000  # 30 days (strike=3 → tier 4)

    def test_same_node_renewal_does_not_escalate(self, db_path, fleet_sse):
        """Renewal from the originating node preserves the existing TTL."""
        self._seed_intel_block_count(db_path, "10.0.0.151", 3)

        engine = PropagationEngine(db_path, fleet_sse, config=self.RECIDIVE_CONFIG)

        result1 = engine.process_block_report({
            "source_ip": "10.0.0.151",
            "node_id": "node-1",
            "event_type": "SSH_BRUTE",
            "detection_rule": "ssh_brute_medium",
        })
        assert result1["status"] == "propagated"

        conn = get_db(db_path)
        row = conn.execute(
            "SELECT ttl_seconds, originating_node_id FROM fleet_blocks "
            "WHERE source_ip = '10.0.0.151' AND status = 'active'"
        ).fetchone()
        orig_ttl = row["ttl_seconds"]
        assert row["originating_node_id"] == "node-1"
        conn.close()

        # Same node reports again — should NOT escalate TTL
        result2 = engine.process_block_report({
            "source_ip": "10.0.0.151",
            "node_id": "node-1",
            "event_type": "SSH_BRUTE",
            "detection_rule": "ssh_brute_medium",
        })
        assert result2["status"] == "accepted"
        assert "TTL renewed" in result2["reason"]

        conn = get_db(db_path)
        row = conn.execute(
            "SELECT ttl_seconds FROM fleet_blocks "
            "WHERE source_ip = '10.0.0.151' AND status = 'active'"
        ).fetchone()
        conn.close()

        assert row is not None
        assert row["ttl_seconds"] == orig_ttl, (
            f"Same-node renewal should not escalate TTL; "
            f"orig={orig_ttl}, got={row['ttl_seconds']}"
        )

    def test_decay_resets_strike_after_clean_period(self, db_path, fleet_sse):
        """Prior blocks older than decay window → strike resets to 0."""
        self._seed_intel_block_count(db_path, "10.0.0.77", 4, last_blocked_offset_days=-40)

        engine = PropagationEngine(db_path, fleet_sse, config=self.RECIDIVE_CONFIG)
        strike = engine._get_fleet_strike("10.0.0.77")
        assert strike == 0  # decayed

    def test_decay_boundary_within_window_keeps_strike(self, db_path, fleet_sse):
        """Prior block within decay window → strike preserved."""
        self._seed_intel_block_count(db_path, "10.0.0.88", 1, last_blocked_offset_days=-10)

        engine = PropagationEngine(db_path, fleet_sse, config=self.RECIDIVE_CONFIG)
        strike = engine._get_fleet_strike("10.0.0.88")
        assert strike == 1  # not decayed — within 30d window

    def test_multiple_priors_oldest_decayed_still_counts_recent(self, db_path, fleet_sse):
        """Only most recent last_blocked_at matters for decay; count stays intact."""
        # Seed intel with 3 blocks, most recent 5 days ago (within decay window)
        self._seed_intel_block_count(db_path, "10.0.0.99", 3, last_blocked_offset_days=-5)

        engine = PropagationEngine(db_path, fleet_sse, config=self.RECIDIVE_CONFIG)
        # Most recent block 5 days ago → within 30d window → strike preserved
        # Seed had count=3 → strike = 3
        strike = engine._get_fleet_strike("10.0.0.99")
        assert strike == 3
