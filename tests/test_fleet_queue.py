"""Tests for vespid.fleet_queue.FleetReportQueue.

Covers:
- Enqueue / dequeue FIFO ordering
- Peek without removal
- Size and is_empty
- Max size eviction (oldest evicted)
- Persistence across instances (queue on disk)
- Corrupted file handling
- Async drain (success, partial failure)
"""

from __future__ import annotations

import asyncio

import pytest

from vespid.fleet_queue import FleetReportQueue


@pytest.fixture
def queue(tmp_path):
    """Create a FleetReportQueue in a temp directory."""
    return FleetReportQueue(queue_dir=str(tmp_path / "fleet_queue"), max_size=5)


# ---------------------------------------------------------------------------
# Basic operations
# ---------------------------------------------------------------------------


class TestBasicOperations:
    def test_starts_empty(self, queue):
        assert queue.is_empty()
        assert queue.size() == 0

    def test_enqueue_increases_size(self, queue):
        queue.enqueue({"ip": "1.2.3.4", "reason": "ssh_brute"})
        assert queue.size() == 1
        assert not queue.is_empty()

    def test_dequeue_returns_report(self, queue):
        queue.enqueue({"ip": "1.2.3.4"})
        report = queue.dequeue()
        assert report == {"ip": "1.2.3.4"}
        assert queue.is_empty()

    def test_dequeue_empty_returns_none(self, queue):
        assert queue.dequeue() is None

    def test_peek_returns_without_removing(self, queue):
        queue.enqueue({"ip": "5.6.7.8"})
        report = queue.peek()
        assert report == {"ip": "5.6.7.8"}
        assert queue.size() == 1  # still there

    def test_peek_empty_returns_none(self, queue):
        assert queue.peek() is None


# ---------------------------------------------------------------------------
# FIFO ordering
# ---------------------------------------------------------------------------


class TestFIFO:
    def test_dequeue_returns_oldest_first(self, queue):
        queue.enqueue({"order": 1})
        queue.enqueue({"order": 2})
        queue.enqueue({"order": 3})

        assert queue.dequeue()["order"] == 1
        assert queue.dequeue()["order"] == 2
        assert queue.dequeue()["order"] == 3
        assert queue.is_empty()


# ---------------------------------------------------------------------------
# Max size eviction
# ---------------------------------------------------------------------------


class TestEviction:
    def test_evicts_oldest_when_full(self, queue):
        # max_size is 5
        for i in range(5):
            queue.enqueue({"order": i})
        assert queue.size() == 5

        # This should evict order=0
        queue.enqueue({"order": 5})
        assert queue.size() == 5

        # Oldest remaining should be order=1
        report = queue.dequeue()
        assert report["order"] == 1


# ---------------------------------------------------------------------------
# Persistence
# ---------------------------------------------------------------------------


class TestPersistence:
    def test_survives_new_instance(self, tmp_path):
        q1 = FleetReportQueue(queue_dir=str(tmp_path / "q"), max_size=10)
        q1.enqueue({"ip": "10.0.0.1"})
        q1.enqueue({"ip": "10.0.0.2"})

        # Create a new instance pointing at the same directory
        q2 = FleetReportQueue(queue_dir=str(tmp_path / "q"), max_size=10)
        assert q2.size() == 2
        assert q2.dequeue()["ip"] == "10.0.0.1"


# ---------------------------------------------------------------------------
# Corrupted files
# ---------------------------------------------------------------------------


class TestCorruptedFiles:
    def test_dequeue_skips_corrupted_file(self, queue, tmp_path):
        queue.enqueue({"ip": "good"})

        # Inject a corrupted file that sorts before the valid one
        corrupted_path = queue.queue_dir / "0000000000.000000_corrupted.json"
        corrupted_path.write_text("not valid json{{{")

        # Dequeue should skip the corrupted one and return the good one
        report = queue.dequeue()
        # The corrupted file was removed
        assert not corrupted_path.exists()
        # Next dequeue gets the real report
        report = queue.dequeue()
        assert report == {"ip": "good"}


# ---------------------------------------------------------------------------
# Async drain
# ---------------------------------------------------------------------------


class TestDrain:
    def test_drain_sends_all_in_order(self, queue):
        queue.enqueue({"order": 1})
        queue.enqueue({"order": 2})
        queue.enqueue({"order": 3})

        sent = []

        async def send_fn(report):
            sent.append(report)
            return True

        count = asyncio.run(queue.drain(send_fn))
        assert count == 3
        assert [r["order"] for r in sent] == [1, 2, 3]
        assert queue.is_empty()

    def test_drain_stops_on_failure(self, queue):
        queue.enqueue({"order": 1})
        queue.enqueue({"order": 2})
        queue.enqueue({"order": 3})

        call_count = 0

        async def send_fn(report):
            nonlocal call_count
            call_count += 1
            if report["order"] == 2:
                return False  # fail on second
            return True

        count = asyncio.run(queue.drain(send_fn))
        assert count == 1  # only first succeeded
        assert queue.size() == 2  # 2nd and 3rd remain

    def test_drain_empty_queue(self, queue):
        async def send_fn(report):
            return True

        count = asyncio.run(queue.drain(send_fn))
        assert count == 0


# ---------------------------------------------------------------------------
# Async batched drain
# ---------------------------------------------------------------------------


class TestDrainBatch:
    def test_drain_batch_sends_in_batches_in_order(self, queue):
        # max_size is 5
        for i in range(5):
            queue.enqueue({"order": i})

        batches = []

        async def send_batch(reports):
            batches.append([r["order"] for r in reports])
            return True

        removed = asyncio.run(queue.drain_batch(send_batch, batch_size=2))
        assert removed == 5
        assert batches == [[0, 1], [2, 3], [4]]
        assert queue.is_empty()

    def test_drain_batch_single_request_when_batch_covers_queue(self, queue):
        for i in range(5):
            queue.enqueue({"order": i})

        calls = []

        async def send_batch(reports):
            calls.append(len(reports))
            return True

        removed = asyncio.run(queue.drain_batch(send_batch, batch_size=100))
        assert removed == 5
        # All five reports fit in one request
        assert calls == [5]

    def test_drain_batch_stops_on_failure_and_keeps_remaining(self, queue):
        for i in range(5):
            queue.enqueue({"order": i})

        calls = []

        async def send_batch(reports):
            calls.append([r["order"] for r in reports])
            # Fail on the second batch
            return calls[-1][0] != 2

        removed = asyncio.run(queue.drain_batch(send_batch, batch_size=2))
        assert removed == 2
        assert calls == [[0, 1], [2, 3]]
        # 2, 3, 4 remain queued
        assert queue.size() == 3
        assert queue.peek()["order"] == 2

    def test_drain_batch_empty_queue_does_not_call_sender(self, queue):
        async def send_batch(reports):
            raise AssertionError("sender should not be called for an empty queue")

        removed = asyncio.run(queue.drain_batch(send_batch))
        assert removed == 0

    def test_drain_batch_removes_corrupted_files(self, queue):
        queue.enqueue({"ip": "good"})

        corrupted_path = queue.queue_dir / "0000000000.000000_corrupted.json"
        corrupted_path.write_text("not valid json{{{")

        batches = []

        async def send_batch(reports):
            batches.append(reports)
            return True

        removed = asyncio.run(queue.drain_batch(send_batch, batch_size=10))
        assert removed == 1
        assert not corrupted_path.exists()
        assert batches == [[{"ip": "good"}]]
        assert queue.is_empty()

    def test_drain_batch_clamps_invalid_batch_size(self, queue):
        queue.enqueue({"order": 1})

        async def send_batch(reports):
            return True

        removed = asyncio.run(queue.drain_batch(send_batch, batch_size=0))
        assert removed == 1
        assert queue.is_empty()
