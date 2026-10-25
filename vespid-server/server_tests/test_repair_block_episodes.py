"""Tests for the block episode repair script."""

from datetime import UTC, datetime

from app.intel_models import process_unblock_event, upsert_ip_record
from repair_block_episodes import (
    _compute_expected_episodes,
    _episode_starts,
    repair,
)


def _dt(value: str) -> datetime:
    return datetime.strptime(value, "%Y-%m-%d %H:%M:%S").replace(tzinfo=UTC)


class TestEpisodeComputation:
    def test_blocks_without_unblocks_are_one_episode(self):
        blocks = [_dt("2024-01-01 10:00:00"), _dt("2024-01-02 10:00:00")]
        assert _episode_starts(blocks, []) == [blocks[0]]

    def test_block_after_unblock_starts_new_episode(self):
        blocks = [_dt("2024-01-01 10:00:00"), _dt("2024-01-03 10:00:00")]
        unblocks = [_dt("2024-01-02 10:00:00")]
        assert _episode_starts(blocks, unblocks) == blocks

    def test_consecutive_unblocks_only_start_one_episode(self):
        blocks = [_dt("2024-01-01 10:00:00"), _dt("2024-01-05 10:00:00")]
        unblocks = [_dt("2024-01-02 10:00:00"), _dt("2024-01-03 10:00:00")]
        assert _episode_starts(blocks, unblocks) == blocks

    def test_expected_episodes_without_anchor(self):
        blocks = [_dt("2024-01-01 10:00:00"), _dt("2024-01-03 10:00:00")]
        unblocks = [_dt("2024-01-02 10:00:00")]
        expected, starts = _compute_expected_episodes(blocks, unblocks)
        assert expected == 2
        assert starts == blocks

    def test_expected_episodes_with_anchor_recovers_pruned_unblock(self):
        """repeat_offender_since proves a second episode predates pruned history."""
        blocks = [
            _dt("2024-06-14 21:56:56"),
            _dt("2024-06-16 02:13:20"),
            _dt("2024-06-26 21:34:32"),
            _dt("2024-08-19 06:12:38"),
            _dt("2024-10-25 14:45:01"),
        ]
        # Only the most recent unblock survived retention.
        unblocks = [_dt("2024-09-18 06:13:38")]
        expected, _ = _compute_expected_episodes(
            blocks, unblocks, repeat_offender_since="2024-06-16 02:13:20"
        )
        assert expected == 3

    def test_no_blocks_means_zero_episodes(self):
        assert _compute_expected_episodes([], []) == (0, [])


class TestRepair:
    def _insert_block_event(self, conn, ip, ts):
        conn.execute(
            "INSERT INTO ip_intel_events "
            "(ip_address, node_id, event_type, event_kind, timestamp, detection_rule) "
            "VALUES (?, 'node-1', 'NFT_ACTION', 'block', ?, 'ssh-brute')",
            (ip, ts),
        )
        conn.commit()

    def _corrupt_summary(self, conn, ip, **values):
        assignments = ", ".join(f"{key} = ?" for key in values)
        conn.execute(
            f"UPDATE ip_intel SET {assignments} WHERE ip_address = ?",
            tuple(values.values()) + (ip,),
        )
        conn.commit()

    def _get(self, conn, ip):
        return conn.execute(
            "SELECT block_episode_count, repeat_offender, repeat_offender_since, "
            "last_episode_block_at, last_unblocked_at "
            "FROM ip_intel WHERE ip_address = ?",
            (ip,),
        ).fetchone()

    def test_repairs_suppressed_episode(self, intel_db):
        ip = "203.0.113.9"
        upsert_ip_record(
            intel_db, ip, "node-1", "NFT_ACTION",
            "2024-01-01 10:00:00", True, {"detection_rule": "ssh-brute"},
        )
        process_unblock_event(intel_db, ip, "2024-01-02 10:00:00")
        self._insert_block_event(intel_db, ip, "2024-01-03 10:00:00")
        # Simulate the old bug: the fleet engine advanced last_blocked_at and
        # the re-block never incremented the episode counter.
        self._corrupt_summary(
            intel_db, ip,
            last_blocked_at="2024-01-03 10:00:05",
            block_episode_count=1,
            repeat_offender=0,
            repeat_offender_since=None,
            last_episode_block_at="2024-01-01 10:00:00",
        )

        stats = repair(intel_db)
        assert stats["counts_changed"] == 1
        assert stats["repeat_offenders_set"] == 1

        row = self._get(intel_db, ip)
        assert row["block_episode_count"] == 2
        assert row["repeat_offender"] == 1
        assert row["repeat_offender_since"] == "2024-01-03 10:00:00"
        assert row["last_episode_block_at"] == "2024-01-03 10:00:00"

    def test_repair_uses_anchor_to_recover_older_episode(self, intel_db):
        ip = "203.0.113.10"
        # Build two real episodes through the production code path.
        upsert_ip_record(
            intel_db, ip, "node-1", "NFT_ACTION",
            "2024-06-14 21:56:56", True, {"detection_rule": "ssh-brute"},
        )
        process_unblock_event(intel_db, ip, "2024-06-15 21:56:56")
        upsert_ip_record(
            intel_db, ip, "node-1", "NFT_ACTION",
            "2024-06-16 02:13:20", True, {"detection_rule": "ssh-brute"},
        )
        # Later block events, then a re-block after a real unblock.
        self._insert_block_event(intel_db, ip, "2024-08-19 06:12:38")
        process_unblock_event(intel_db, ip, "2024-09-18 06:13:38")
        self._insert_block_event(intel_db, ip, "2024-10-25 14:45:01")
        # Simulate the suppressed Oct 25 episode.
        self._corrupt_summary(
            intel_db, ip,
            last_blocked_at="2024-10-25 14:45:01",
            block_episode_count=2,
            last_episode_block_at="2024-08-19 06:12:38",
        )

        repair(intel_db)

        row = self._get(intel_db, ip)
        assert row["block_episode_count"] == 3
        assert row["last_episode_block_at"] == "2024-10-25 14:45:01"

    def test_repair_never_decreases_count(self, intel_db):
        ip = "203.0.113.11"
        self._insert_block_event(intel_db, ip, "2024-01-01 10:00:00")
        upsert_ip_record(
            intel_db, ip, "node-1", "NFT_ACTION",
            "2024-01-01 10:00:00", True, {"detection_rule": "ssh-brute"},
        )
        self._corrupt_summary(intel_db, ip, block_episode_count=5)

        repair(intel_db)

        assert self._get(intel_db, ip)["block_episode_count"] == 5

    def test_repair_is_idempotent(self, intel_db):
        ip = "203.0.113.12"
        upsert_ip_record(
            intel_db, ip, "node-1", "NFT_ACTION",
            "2024-01-01 10:00:00", True, {"detection_rule": "ssh-brute"},
        )
        process_unblock_event(intel_db, ip, "2024-01-02 10:00:00")
        self._insert_block_event(intel_db, ip, "2024-01-03 10:00:00")
        self._corrupt_summary(
            intel_db, ip,
            block_episode_count=1,
            repeat_offender=0,
            last_episode_block_at="2024-01-01 10:00:00",
        )

        repair(intel_db)
        second = repair(intel_db)

        assert second["counts_changed"] == 0
        assert second["repeat_offenders_set"] == 0
        assert second["episode_anchor_backfilled"] == 0

    def test_dry_run_does_not_write(self, intel_db):
        ip = "203.0.113.13"
        upsert_ip_record(
            intel_db, ip, "node-1", "NFT_ACTION",
            "2024-01-01 10:00:00", True, {"detection_rule": "ssh-brute"},
        )
        process_unblock_event(intel_db, ip, "2024-01-02 10:00:00")
        self._insert_block_event(intel_db, ip, "2024-01-03 10:00:00")
        self._corrupt_summary(
            intel_db, ip,
            block_episode_count=1,
            repeat_offender=0,
        )

        stats = repair(intel_db, dry_run=True)
        assert stats["counts_changed"] == 1
        assert self._get(intel_db, ip)["block_episode_count"] == 1

        repair(intel_db)
        assert self._get(intel_db, ip)["block_episode_count"] == 2
