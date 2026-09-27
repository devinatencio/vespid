"""Tests for get_counter_history function."""

import sqlite3
from datetime import datetime, timedelta, timezone

import pytest

from app.models import (
    _SCHEMA_SQL,
    _friendly_set_name_plain,
    get_counter_history,
    insert_counter_snapshots,
)


@pytest.fixture
def db():
    """Create an in-memory SQLite database with schema."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript(_SCHEMA_SQL)
    yield conn
    conn.close()


def _ts(minutes_ago: int) -> str:
    """Return an ISO-8601 timestamp N minutes ago from now."""
    now = datetime.now(timezone.utc)
    dt = now - timedelta(minutes=minutes_ago)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class TestFriendlySetNamePlain:
    def test_feed_name(self):
        assert _friendly_set_name_plain("shield_feed_firehol_level1") == "Firehol Level1"

    def test_abuse_ch(self):
        assert _friendly_set_name_plain("shield_feed_abuse_ch_feodo") == "Abuse Ch Feodo"

    def test_local_blocks(self):
        assert _friendly_set_name_plain("shield_local_blocks") == "Blocks"

    def test_local_bare(self):
        assert _friendly_set_name_plain("shield_local") == "Local Blocks"

    def test_other_set(self):
        assert _friendly_set_name_plain("some_other_set") == "Some Other Set"


class TestGetCounterHistory:
    def test_empty_database(self, db):
        result = get_counter_history(db, "24h")
        assert result == {"labels": [], "datasets": [], "lifetime_totals": {}}

    def test_invalid_time_range(self, db):
        result = get_counter_history(db, "invalid")
        assert result == {"labels": [], "datasets": [], "lifetime_totals": {}}

    def test_single_node_basic_deltas(self, db):
        ts1 = _ts(30)
        ts2 = _ts(20)
        ts3 = _ts(10)

        counters1 = [{"set": "shield_feed_firehol_level1", "packets": 100, "bytes": 5000}]
        counters2 = [{"set": "shield_feed_firehol_level1", "packets": 150, "bytes": 7500}]
        counters3 = [{"set": "shield_feed_firehol_level1", "packets": 200, "bytes": 10000}]

        insert_counter_snapshots(db, "node-1", ts1, counters1)
        insert_counter_snapshots(db, "node-1", ts2, counters2)
        insert_counter_snapshots(db, "node-1", ts3, counters3)

        result = get_counter_history(db, "1h", node_id="node-1")

        assert len(result["labels"]) == 3
        assert result["labels"] == sorted(result["labels"])
        assert len(result["datasets"]) == 1
        assert result["datasets"][0]["label"] == "Firehol Level1"
        assert result["datasets"][0]["data"] == [0, 50, 50]
        assert result["datasets"][0]["resets"] == [False, False, False]
        assert result["lifetime_totals"]["Firehol Level1"] == 100

    def test_counter_reset_detection(self, db):
        ts1 = _ts(30)
        ts2 = _ts(20)
        ts3 = _ts(10)
        ts4 = _ts(5)

        insert_counter_snapshots(db, "node-1", ts1, [{"set": "shield_feed_abuse_ch_feodo", "packets": 100, "bytes": 5000}])
        insert_counter_snapshots(db, "node-1", ts2, [{"set": "shield_feed_abuse_ch_feodo", "packets": 200, "bytes": 10000}])
        insert_counter_snapshots(db, "node-1", ts3, [{"set": "shield_feed_abuse_ch_feodo", "packets": 50, "bytes": 2500}])
        insert_counter_snapshots(db, "node-1", ts4, [{"set": "shield_feed_abuse_ch_feodo", "packets": 80, "bytes": 4000}])

        result = get_counter_history(db, "1h", node_id="node-1")

        assert result["datasets"][0]["label"] == "Abuse Ch Feodo"
        assert result["datasets"][0]["data"] == [0, 100, 0, 30]
        assert result["datasets"][0]["resets"] == [False, False, True, False]
        assert result["lifetime_totals"]["Abuse Ch Feodo"] == 130

    def test_multi_node_aggregation(self, db):
        ts1 = _ts(30)
        ts2 = _ts(20)
        ts3 = _ts(10)

        # Node 1: 100 -> 150 -> 200 (deltas: 0, 50, 50)
        insert_counter_snapshots(db, "node-1", ts1, [{"set": "shield_feed_firehol_level1", "packets": 100, "bytes": 5000}])
        insert_counter_snapshots(db, "node-1", ts2, [{"set": "shield_feed_firehol_level1", "packets": 150, "bytes": 7500}])
        insert_counter_snapshots(db, "node-1", ts3, [{"set": "shield_feed_firehol_level1", "packets": 200, "bytes": 10000}])

        # Node 2: 50 -> 80 -> 120 (deltas: 0, 30, 40)
        insert_counter_snapshots(db, "node-2", ts1, [{"set": "shield_feed_firehol_level1", "packets": 50, "bytes": 2500}])
        insert_counter_snapshots(db, "node-2", ts2, [{"set": "shield_feed_firehol_level1", "packets": 80, "bytes": 4000}])
        insert_counter_snapshots(db, "node-2", ts3, [{"set": "shield_feed_firehol_level1", "packets": 120, "bytes": 6000}])

        result = get_counter_history(db, "1h", node_id=None)

        # Aggregated: (0+0), (50+30), (50+40) = [0, 80, 90]
        assert result["datasets"][0]["data"] == [0, 80, 90]
        assert result["lifetime_totals"]["Firehol Level1"] == 170

    def test_node_filter_isolation(self, db):
        ts1 = _ts(30)
        ts2 = _ts(20)

        insert_counter_snapshots(db, "node-1", ts1, [{"set": "shield_feed_firehol_level1", "packets": 100, "bytes": 5000}])
        insert_counter_snapshots(db, "node-1", ts2, [{"set": "shield_feed_firehol_level1", "packets": 150, "bytes": 7500}])
        insert_counter_snapshots(db, "node-2", ts1, [{"set": "shield_feed_firehol_level1", "packets": 50, "bytes": 2500}])
        insert_counter_snapshots(db, "node-2", ts2, [{"set": "shield_feed_firehol_level1", "packets": 80, "bytes": 4000}])

        result = get_counter_history(db, "1h", node_id="node-1")

        assert result["datasets"][0]["data"] == [0, 50]
        assert result["lifetime_totals"]["Firehol Level1"] == 50

    def test_time_range_filtering(self, db):
        # Insert data at various times
        ts_recent = _ts(30)  # 30 min ago - within 1h
        ts_old = _ts(120)    # 2 hours ago - outside 1h but within 6h

        insert_counter_snapshots(db, "node-1", ts_old, [{"set": "shield_feed_firehol_level1", "packets": 50, "bytes": 2500}])
        insert_counter_snapshots(db, "node-1", ts_recent, [{"set": "shield_feed_firehol_level1", "packets": 100, "bytes": 5000}])

        # 1h range should only include the recent one
        result_1h = get_counter_history(db, "1h")
        assert len(result_1h["labels"]) == 1

        # 6h range should include both
        result_6h = get_counter_history(db, "6h")
        assert len(result_6h["labels"]) == 2

    def test_multiple_sets(self, db):
        ts1 = _ts(30)
        ts2 = _ts(20)

        insert_counter_snapshots(db, "node-1", ts1, [
            {"set": "shield_feed_firehol_level1", "packets": 100, "bytes": 5000},
            {"set": "shield_feed_abuse_ch_feodo", "packets": 200, "bytes": 10000},
        ])
        insert_counter_snapshots(db, "node-1", ts2, [
            {"set": "shield_feed_firehol_level1", "packets": 150, "bytes": 7500},
            {"set": "shield_feed_abuse_ch_feodo", "packets": 250, "bytes": 12500},
        ])

        result = get_counter_history(db, "1h", node_id="node-1")

        assert len(result["datasets"]) == 2
        labels = [ds["label"] for ds in result["datasets"]]
        assert "Abuse Ch Feodo" in labels
        assert "Firehol Level1" in labels

        # Both sets should have the same labels
        assert len(result["labels"]) == 2

    def test_nonexistent_node_returns_empty(self, db):
        ts1 = _ts(30)
        insert_counter_snapshots(db, "node-1", ts1, [{"set": "shield_feed_firehol_level1", "packets": 100, "bytes": 5000}])

        result = get_counter_history(db, "1h", node_id="nonexistent")
        assert result == {"labels": [], "datasets": [], "lifetime_totals": {}}

    def test_response_structure(self, db):
        ts1 = _ts(30)
        ts2 = _ts(20)

        insert_counter_snapshots(db, "node-1", ts1, [{"set": "shield_feed_firehol_level1", "packets": 100, "bytes": 5000}])
        insert_counter_snapshots(db, "node-1", ts2, [{"set": "shield_feed_firehol_level1", "packets": 150, "bytes": 7500}])

        result = get_counter_history(db, "1h", node_id="node-1")

        # Verify top-level keys
        assert "labels" in result
        assert "datasets" in result
        assert "lifetime_totals" in result

        # Verify labels is a list of strings
        assert isinstance(result["labels"], list)
        assert all(isinstance(l, str) for l in result["labels"])

        # Verify datasets structure
        assert isinstance(result["datasets"], list)
        for ds in result["datasets"]:
            assert "label" in ds
            assert "data" in ds
            assert "resets" in ds
            assert isinstance(ds["label"], str)
            assert isinstance(ds["data"], list)
            assert isinstance(ds["resets"], list)
            assert len(ds["data"]) == len(result["labels"])
            assert len(ds["resets"]) == len(result["labels"])

        # Verify lifetime_totals is a dict
        assert isinstance(result["lifetime_totals"], dict)
