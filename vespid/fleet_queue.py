"""Persistent on-disk queue for block reports when the server is unreachable.

Reports are stored as individual JSON files in a configurable directory.
File names use timestamps to ensure FIFO ordering:
    ``<unix_timestamp_with_microseconds>_<uuid>.json``

The queue survives agent restarts — all state lives on disk with no
in-memory-only data.
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from collections.abc import Awaitable, Callable
from pathlib import Path

log = logging.getLogger("vespid.fleet_queue")


class FleetReportQueue:
    """Persistent FIFO queue for block reports stored as JSON files on disk.

    Parameters
    ----------
    queue_dir:
        Directory where report files are stored.
    max_size:
        Maximum number of reports in the queue. When exceeded, the oldest
        report is evicted and a warning is logged.
    """

    def __init__(
        self, queue_dir: str = "/var/lib/vespid/fleet_queue", max_size: int = 1000
    ) -> None:
        self._queue_dir = Path(queue_dir)
        self._max_size = max_size
        self._queue_dir.mkdir(parents=True, exist_ok=True)

    @property
    def queue_dir(self) -> Path:
        return self._queue_dir

    @property
    def max_size(self) -> int:
        return self._max_size

    def _sorted_files(self) -> list[str]:
        """Return queue filenames sorted in FIFO order (oldest first)."""
        try:
            files = [f for f in os.listdir(self._queue_dir) if f.endswith(".json")]
        except OSError as exc:
            log.error("Failed to list queue directory %s: %s", self._queue_dir, exc)
            return []
        files.sort()
        return files

    def enqueue(self, report: dict) -> None:
        """Persist a block report as a timestamped JSON file.

        If the queue is at max_size, the oldest entry is evicted first
        and a warning is logged.
        """
        # Evict oldest if at capacity
        if self.size() >= self._max_size:
            files = self._sorted_files()
            if files:
                oldest = self._queue_dir / files[0]
                try:
                    oldest.unlink()
                    log.warning(
                        "Fleet report queue at max capacity (%d); evicted oldest report: %s",
                        self._max_size,
                        files[0],
                    )
                except OSError as exc:
                    log.error("Failed to evict oldest queue file %s: %s", oldest, exc)

        # Generate a filename with timestamp for FIFO ordering
        timestamp = f"{time.time():.6f}"
        unique_id = uuid.uuid4().hex[:12]
        filename = f"{timestamp}_{unique_id}.json"
        filepath = self._queue_dir / filename

        try:
            filepath.write_text(
                json.dumps(report, separators=(",", ":"), sort_keys=True),
                encoding="utf-8",
            )
        except OSError as exc:
            log.error("Failed to enqueue report to %s: %s", filepath, exc)

    def dequeue(self) -> dict | None:
        """Pop and delete the oldest report file.

        Returns the parsed dict, or None if the queue is empty.
        """
        files = self._sorted_files()
        if not files:
            return None

        filepath = self._queue_dir / files[0]
        try:
            data = json.loads(filepath.read_text(encoding="utf-8"))
            filepath.unlink()
            return data
        except (OSError, json.JSONDecodeError) as exc:
            log.error("Failed to dequeue report from %s: %s", filepath, exc)
            # Remove corrupted file to avoid blocking the queue
            try:
                filepath.unlink()
            except OSError:
                pass
            return None

    def peek(self) -> dict | None:
        """Read the oldest report without removing it.

        Returns the parsed dict, or None if the queue is empty.
        """
        files = self._sorted_files()
        if not files:
            return None

        filepath = self._queue_dir / files[0]
        try:
            return json.loads(filepath.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            log.error("Failed to peek report from %s: %s", filepath, exc)
            return None

    def size(self) -> int:
        """Return current queue depth."""
        return len(self._sorted_files())

    def is_empty(self) -> bool:
        """Return True if the queue has no reports."""
        return self.size() == 0

    async def drain(self, send_fn: Callable[[dict], Awaitable[bool]]) -> int:
        """Send all queued reports via send_fn in FIFO order.

        For each report, calls ``await send_fn(report)``. If send_fn
        returns True, the report is removed from the queue. On the first
        failure (send_fn returns False), draining stops immediately.

        Returns the count of successfully sent reports.
        """
        sent_count = 0
        files = self._sorted_files()

        for filename in files:
            filepath = self._queue_dir / filename
            try:
                data = json.loads(filepath.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                log.error("Failed to read queued report %s: %s", filepath, exc)
                # Skip corrupted files — remove them to unblock the queue
                try:
                    filepath.unlink()
                except OSError:
                    pass
                continue

            success = await send_fn(data)
            if success:
                try:
                    filepath.unlink()
                except OSError as exc:
                    log.error("Failed to remove sent report %s: %s", filepath, exc)
                sent_count += 1
            else:
                # Stop on first failure
                break

        return sent_count

    def _read_batch(self, limit: int) -> list[tuple[str, dict]]:
        """Read up to *limit* oldest reports in FIFO order.

        Corrupted files are removed and skipped without counting toward the
        limit. Returns a list of ``(filename, report)`` tuples.
        """
        batch: list[tuple[str, dict]] = []
        for filename in self._sorted_files():
            if len(batch) >= limit:
                break
            filepath = self._queue_dir / filename
            try:
                data = json.loads(filepath.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError) as exc:
                log.error("Failed to read queued report %s: %s", filepath, exc)
                # Skip corrupted files — remove them to unblock the queue
                try:
                    filepath.unlink()
                except OSError:
                    pass
                continue
            batch.append((filename, data))
        return batch

    async def drain_batch(
        self,
        send_batch_fn: Callable[[list[dict]], Awaitable[bool]],
        batch_size: int = 100,
    ) -> int:
        """Send queued reports to the server in batches.

        Reads up to ``batch_size`` oldest reports and passes them to
        ``send_batch_fn`` in a single call, allowing them to be shipped in
        one request instead of one request per report. If ``send_batch_fn``
        returns True the batch's reports are removed from the queue and the
        next batch is attempted. On the first failure (returns False),
        draining stops immediately and the remaining reports stay queued.

        Returns the number of reports removed from the queue.
        """
        if batch_size < 1:
            batch_size = 1

        removed = 0
        while True:
            batch = self._read_batch(batch_size)
            if not batch:
                break

            if not await send_batch_fn([report for _, report in batch]):
                # Stop on first failure — keep the whole batch for retry
                break

            for filename, _ in batch:
                filepath = self._queue_dir / filename
                try:
                    filepath.unlink()
                except OSError as exc:
                    log.error("Failed to remove sent report %s: %s", filepath, exc)
                    continue
                removed += 1

        return removed
