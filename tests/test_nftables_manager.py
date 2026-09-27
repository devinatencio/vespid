"""Tests for NFTablesManager.

Covers:
- block/unblock basics (in-memory shadow mode, no nft binary needed)
- allowlist enforcement
- recidive escalation and decay
- expiry reaper
- bulk defer_persist operations
- persistence round-trip (save/load local blocks, recidive state)
"""

from __future__ import annotations

import json
import time
from unittest.mock import patch

import pytest

# ---------------------------------------------------------------------------
# Fixtures — import vespid modules lazily to avoid /var/lib/vespid permission
# errors from the module-level BUS singleton.
# ---------------------------------------------------------------------------


@pytest.fixture(autouse=True)
def _patch_env(tmp_path, monkeypatch):
    """Set env vars before any vespid module loads."""
    monkeypatch.setenv("VESPID_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("VESPID_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv("VESPID_ID_FILE", str(tmp_path / "node_id"))


@pytest.fixture
def config(tmp_path):
    """Create a ShieldConfig with test-friendly paths and short TTLs."""
    from vespid.config import ShieldConfig

    cfg = ShieldConfig(
        node_id="test-node",
        nft_local_block_ttl=3600,
        allowlist=["127.0.0.1/32", "::1/128", "10.0.0.0/8"],
        recidive_tiers=[100, 300, 600, 1200],  # short tiers for testing
        recidive_decay_seconds=1000,
        fleet_queue_dir=str(tmp_path / "fleet_queue"),
        spool_path=str(tmp_path / "spool.jsonl"),
        subscriptions=[],
    )
    return cfg


@pytest.fixture
def bus(config):
    """Create a DataBus that doesn't start its worker thread."""
    with patch("vespid.fleet_queue.FleetReportQueue.__init__", return_value=None):
        from vespid.databus import DataBus

        b = DataBus(config)
    return b


@pytest.fixture
def nft(config, bus, tmp_path):
    """Create an NFTablesManager in shadow-only mode (no nft binary)."""
    with patch("shutil.which", return_value=None):
        from vespid.nftables_manager import NFTablesManager

        mgr = NFTablesManager(config=config, bus=bus)
    return mgr


# ---------------------------------------------------------------------------
# Block / Unblock Basics
# ---------------------------------------------------------------------------


class TestBlockUnblock:
    def test_block_adds_to_local(self, nft):
        result = nft.block_local("192.168.1.100", reason="test")
        assert result is True
        assert "192.168.1.100" in nft._local
        assert nft.is_locally_blocked("192.168.1.100")

    def test_block_returns_false_for_duplicate(self, nft):
        nft.block_local("1.2.3.4", reason="first")
        result = nft.block_local("1.2.3.4", reason="second")
        assert result is False

    def test_block_records_metadata(self, nft):
        nft.block_local("5.6.7.8", reason="ssh_brute", ttl=7200)
        meta = nft._local["5.6.7.8"]
        assert meta["reason"] == "ssh_brute"
        assert meta["blocked_at"] > 0
        assert meta["expires_at"] == pytest.approx(meta["blocked_at"] + 7200, abs=2)

    def test_unblock_removes_from_local(self, nft):
        nft.block_local("1.1.1.1", reason="test")
        assert nft.is_locally_blocked("1.1.1.1")

        result = nft.unblock_local("1.1.1.1", reason="manual")
        assert result is True
        assert not nft.is_locally_blocked("1.1.1.1")

    def test_unblock_returns_false_if_not_present(self, nft):
        result = nft.unblock_local("9.9.9.9", reason="manual")
        assert result is False

    def test_block_invalid_ip_rejected(self, nft):
        result = nft.block_local("not-an-ip", reason="test")
        assert result is False
        assert "not-an-ip" not in nft._local

    def test_block_publishes_event(self, nft, bus):
        nft.block_local("8.8.8.8", reason="brute")
        event = bus._queue.get_nowait()
        assert event.source_ip == "8.8.8.8"
        assert event.event_type == "NFT_ACTION"
        assert event.action_taken == "BLOCKED"

    def test_unblock_publishes_event(self, nft, bus):
        nft.block_local("8.8.4.4", reason="test")
        bus._queue.get_nowait()  # drain the block event

        nft.unblock_local("8.8.4.4", reason="manual")
        event = bus._queue.get_nowait()
        assert event.source_ip == "8.8.4.4"
        assert event.action_taken == "UNBLOCKED"

    def test_renew_extends_ttl(self, nft):
        nft.block_local("2.2.2.2", reason="test", ttl=100)
        old_expires = nft._local["2.2.2.2"]["expires_at"]

        result = nft.renew_local("2.2.2.2", ttl=5000)
        assert result is True
        new_expires = nft._local["2.2.2.2"]["expires_at"]
        assert new_expires > old_expires

    def test_renew_returns_false_if_not_blocked(self, nft):
        result = nft.renew_local("3.3.3.3", ttl=1000)
        assert result is False


# ---------------------------------------------------------------------------
# Allowlist Enforcement
# ---------------------------------------------------------------------------


class TestAllowlist:
    def test_block_refused_for_allowlisted_ip(self, nft):
        # 10.0.0.0/8 is in the allowlist
        result = nft.block_local("10.1.2.3", reason="test")
        assert result is False
        assert "10.1.2.3" not in nft._local

    def test_localhost_allowlisted(self, nft):
        assert nft.is_allowlisted("127.0.0.1")
        result = nft.block_local("127.0.0.1", reason="test")
        assert result is False

    def test_ipv6_localhost_allowlisted(self, nft):
        assert nft.is_allowlisted("::1")

    def test_non_allowlisted_ip_passes(self, nft):
        assert not nft.is_allowlisted("44.55.66.77")

    def test_allowlist_add_runtime(self, nft):
        result = nft.allowlist_add("172.16.0.0/12")
        assert result["ok"] is True
        assert result["added"] is True
        assert nft.is_allowlisted("172.16.5.5")

    def test_allowlist_add_unblocks_existing(self, nft):
        nft.block_local("192.168.50.1", reason="test")
        assert nft.is_locally_blocked("192.168.50.1")

        result = nft.allowlist_add("192.168.50.0/24")
        assert result["ok"] is True
        assert "192.168.50.1" in result["unblocked"]
        assert not nft.is_locally_blocked("192.168.50.1")

    def test_allowlist_add_duplicate_returns_already(self, nft):
        nft.allowlist_add("172.20.0.0/16")
        result = nft.allowlist_add("172.20.0.0/16")
        assert result["ok"] is True
        assert result["already"] is True

    def test_allowlist_remove_runtime_entry(self, nft):
        nft.allowlist_add("203.0.113.0/24")
        assert nft.is_allowlisted("203.0.113.5")

        result = nft.allowlist_remove("203.0.113.0/24")
        assert result["ok"] is True
        assert result["removed"] is True
        assert not nft.is_allowlisted("203.0.113.5")

    def test_allowlist_remove_config_entry_rejected(self, nft):
        # 10.0.0.0/8 is a config entry, not runtime
        result = nft.allowlist_remove("10.0.0.0/8")
        assert result["ok"] is False
        assert "config" in result["error"]

    def test_allowlist_remove_nonexistent_returns_error(self, nft):
        result = nft.allowlist_remove("198.51.100.0/24")
        assert result["ok"] is False

    def test_allowlist_invalid_entry(self, nft):
        result = nft.allowlist_add("not-a-cidr")
        assert result["ok"] is False
        assert "invalid" in result["error"]

    def test_allowlist_persists_to_disk(self, nft, tmp_path):
        nft.allowlist_add("198.18.0.0/15")
        path = tmp_path / "allowlist.json"
        assert path.exists()
        data = json.loads(path.read_text())
        assert "198.18.0.0/15" in data


# ---------------------------------------------------------------------------
# Recidive Escalation
# ---------------------------------------------------------------------------


class TestRecidive:
    def test_first_offense_gets_tier_0_ttl(self, nft):
        nft.block_local("50.50.50.1", reason="brute")
        meta = nft._local["50.50.50.1"]
        expected_ttl = 100  # tier 0
        actual_ttl = meta["expires_at"] - meta["blocked_at"]
        assert actual_ttl == pytest.approx(expected_ttl, abs=2)
        assert meta["strike"] == 1

    def test_second_offense_gets_tier_1_ttl(self, nft):
        nft.block_local("60.60.60.1", reason="brute")
        nft._local.pop("60.60.60.1")

        nft.block_local("60.60.60.1", reason="brute")
        meta = nft._local["60.60.60.1"]
        expected_ttl = 300  # tier 1
        actual_ttl = meta["expires_at"] - meta["blocked_at"]
        assert actual_ttl == pytest.approx(expected_ttl, abs=2)
        assert meta["strike"] == 2

    def test_third_offense_gets_tier_2_ttl(self, nft):
        ip = "70.70.70.1"
        for i in range(3):
            nft.block_local(ip, reason="brute")
            if i < 2:
                nft._local.pop(ip)

        meta = nft._local[ip]
        expected_ttl = 600  # tier 2
        actual_ttl = meta["expires_at"] - meta["blocked_at"]
        assert actual_ttl == pytest.approx(expected_ttl, abs=2)
        assert meta["strike"] == 3

    def test_fourth_offense_caps_at_last_tier(self, nft):
        ip = "80.80.80.1"
        for i in range(5):
            nft.block_local(ip, reason="brute")
            if i < 4:
                nft._local.pop(ip)

        meta = nft._local[ip]
        expected_ttl = 1200  # tier 3 (last), used for offense 4+
        actual_ttl = meta["expires_at"] - meta["blocked_at"]
        assert actual_ttl == pytest.approx(expected_ttl, abs=2)

    def test_decay_resets_strike_count(self, nft):
        ip = "90.90.90.1"
        for _i in range(3):
            nft.block_local(ip, reason="brute")
            nft._local.pop(ip)

        # Simulate decay by backdating last_seen
        nft._recidive[ip]["last_seen"] = time.time() - 2000  # exceeds decay of 1000s

        nft.block_local(ip, reason="brute")
        meta = nft._local[ip]
        assert meta["strike"] == 1
        expected_ttl = 100  # tier 0 again
        actual_ttl = meta["expires_at"] - meta["blocked_at"]
        assert actual_ttl == pytest.approx(expected_ttl, abs=2)

    def test_fleet_blocks_do_not_escalate_recidive(self, nft):
        ip = "100.100.100.1"
        nft.block_local(ip, reason="fleet:suspicious", ttl=3600)
        assert nft._recidive.get(ip) is None

        nft._local.pop(ip)
        nft.block_local(ip, reason="ssh_brute")
        meta = nft._local[ip]
        assert meta["strike"] == 1

    def test_recidive_persists_to_disk(self, nft, tmp_path):
        nft.block_local("11.11.11.1", reason="test")
        path = tmp_path / "recidive.json"
        assert path.exists()
        data = json.loads(path.read_text())
        assert "11.11.11.1" in data
        assert data["11.11.11.1"]["count"] == 1

    def test_recidive_info(self, nft):
        ip = "22.22.22.1"
        nft.block_local(ip, reason="test")
        nft._local.pop(ip)
        nft.block_local(ip, reason="test")

        info = nft.recidive_info(ip)
        assert info["offenses"] == 2
        assert info["next_ttl"] == 600  # tier 2 for 3rd offense

    def test_prune_recidive_removes_decayed(self, nft):
        ip = "33.33.33.1"
        nft.block_local(ip, reason="test")
        nft._recidive[ip]["last_seen"] = time.time() - 2000

        pruned = nft.prune_recidive()
        assert pruned == 1
        assert ip not in nft._recidive


# ---------------------------------------------------------------------------
# Expiry Reaper
# ---------------------------------------------------------------------------


class TestExpiryReaper:
    def test_reap_removes_expired_entries(self, nft):
        nft.block_local("40.40.40.1", reason="test", ttl=10)
        nft._local["40.40.40.1"]["expires_at"] = time.time() - 1

        reaped = nft.reap_expired()
        assert reaped == 1
        assert "40.40.40.1" not in nft._local

    def test_reap_keeps_non_expired_entries(self, nft):
        nft.block_local("41.41.41.1", reason="test", ttl=9999)

        reaped = nft.reap_expired()
        assert reaped == 0
        assert "41.41.41.1" in nft._local

    def test_reap_mixed_expired_and_active(self, nft):
        nft.block_local("42.42.42.1", reason="test", ttl=10)
        nft.block_local("42.42.42.2", reason="test", ttl=9999)
        nft._local["42.42.42.1"]["expires_at"] = time.time() - 5

        reaped = nft.reap_expired()
        assert reaped == 1
        assert "42.42.42.1" not in nft._local
        assert "42.42.42.2" in nft._local

    def test_is_locally_blocked_excludes_expired(self, nft):
        nft.block_local("43.43.43.1", reason="test", ttl=10)
        nft._local["43.43.43.1"]["expires_at"] = time.time() - 1

        assert not nft.is_locally_blocked("43.43.43.1")


# ---------------------------------------------------------------------------
# Bulk Operations (defer_persist)
# ---------------------------------------------------------------------------


class TestDeferPersist:
    def test_defer_batches_persistence(self, nft, tmp_path):
        persist_path = tmp_path / "local_blocks.json"

        with nft.defer_persist():
            nft.block_local("51.51.51.1", reason="batch")
            nft.block_local("51.51.51.2", reason="batch")
            nft.block_local("51.51.51.3", reason="batch")
            assert nft._persist_needed is True

        assert nft._persist_deferred is False
        assert persist_path.exists()
        data = json.loads(persist_path.read_text())
        assert "51.51.51.1" in data
        assert "51.51.51.2" in data
        assert "51.51.51.3" in data


# ---------------------------------------------------------------------------
# Persistence Round-Trip
# ---------------------------------------------------------------------------


class TestPersistence:
    def test_local_blocks_persist_and_reload(self, nft, config, bus, tmp_path):
        nft.block_local("61.61.61.1", reason="persist_test", ttl=9999)
        nft.block_local("61.61.61.2", reason="persist_test", ttl=9999)

        persist_path = tmp_path / "local_blocks.json"
        assert persist_path.exists()

        with patch("shutil.which", return_value=None):
            from vespid.nftables_manager import NFTablesManager

            nft2 = NFTablesManager(config=config, bus=bus)
        nft2._load_local()

        assert "61.61.61.1" in nft2._local
        assert "61.61.61.2" in nft2._local

    def test_expired_entries_discarded_on_load(self, nft, config, bus, tmp_path):
        nft.block_local("62.62.62.1", reason="test", ttl=10)
        nft._local["62.62.62.1"]["expires_at"] = time.time() - 100
        nft._save_local()

        with patch("shutil.which", return_value=None):
            from vespid.nftables_manager import NFTablesManager

            nft2 = NFTablesManager(config=config, bus=bus)
        nft2._load_local()

        assert "62.62.62.1" not in nft2._local

    def test_allowlisted_entries_discarded_on_load(self, nft, config, bus, tmp_path):
        persist_path = tmp_path / "local_blocks.json"
        persist_path.write_text(
            json.dumps(
                {
                    "10.5.5.5": {
                        "reason": "test",
                        "blocked_at": time.time(),
                        "expires_at": time.time() + 9999,
                        "strike": 1,
                    }
                }
            )
        )

        with patch("shutil.which", return_value=None):
            from vespid.nftables_manager import NFTablesManager

            nft2 = NFTablesManager(config=config, bus=bus)
        nft2._load_local()

        assert "10.5.5.5" not in nft2._local

    def test_recidive_state_survives_restart(self, nft, config, bus, tmp_path):
        ip = "63.63.63.1"
        for _i in range(3):
            nft.block_local(ip, reason="test")
            nft._local.pop(ip)

        assert nft._recidive[ip]["count"] == 3

        with patch("shutil.which", return_value=None):
            from vespid.nftables_manager import NFTablesManager

            nft2 = NFTablesManager(config=config, bus=bus)

        assert ip in nft2._recidive
        assert nft2._recidive[ip]["count"] == 3


# ---------------------------------------------------------------------------
# Status / Inspection
# ---------------------------------------------------------------------------


class TestStatus:
    def test_status_reports_counts(self, nft):
        nft.block_local("71.71.71.1", reason="test")
        nft.block_local("71.71.71.2", reason="fleet:threat")

        status = nft.status()
        assert status["local_count"] == 2
        assert status["fleet_block_count"] == 1
        assert status["nft_available"] is False  # shadow mode

    def test_list_local_excludes_expired(self, nft):
        nft.block_local("72.72.72.1", reason="test", ttl=9999)
        nft.block_local("72.72.72.2", reason="test", ttl=10)
        nft._local["72.72.72.2"]["expires_at"] = time.time() - 1

        listing = nft.list_local()
        ips = [r["ip"] for r in listing]
        assert "72.72.72.1" in ips
        assert "72.72.72.2" not in ips

    def test_local_blocked_set(self, nft):
        nft.block_local("73.73.73.1", reason="test")
        nft.block_local("73.73.73.2", reason="test")

        blocked = nft.local_blocked_set()
        assert "73.73.73.1" in blocked
        assert "73.73.73.2" in blocked
