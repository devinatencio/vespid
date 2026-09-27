"""Synthetic Check Worker SSE Manager.

Provides a thread-safe fan-out for waking up worker nodes when new jobs
are assigned to them. Workers subscribe to a per-worker SSE stream to
get instant notification instead of waiting for the next poll interval.

Follows the same pattern as FleetSSEManager but with per-worker targeting.
"""

from __future__ import annotations

import logging
import queue
import threading
from collections import deque
from collections.abc import Generator

logger = logging.getLogger(__name__)


class CheckWorkerSSEManager:
    """Notifies workers of newly assigned jobs via SSE.

    - Maintains a dict of worker_id -> set of client queues
    - publish() sends to all clients for a specific worker
    - broadcast() sends to all connected workers
    """

    def __init__(self, history_size: int = 500):
        self.history_size = history_size
        self._lock = threading.Lock()
        self._worker_clients: dict[str, set[queue.Queue[str | None]]] = {}
        self._history: deque[tuple[str, str]] = deque(maxlen=history_size)

    @staticmethod
    def _format_sse(event_id: str, data: str) -> str:
        lines = data.split("\n")
        data_section = "\n".join(f"data: {line}" for line in lines)
        return f"id: {event_id}\nevent: new_jobs\n{data_section}\n\n"

    def notify(self, worker_id: str) -> None:
        """Notify a specific worker that new jobs are available."""
        data = '{"event":"jobs_available"}'
        message = self._format_sse(worker_id, data)

        with self._lock:
            self._history.append((worker_id, message))
            clients = self._worker_clients.get(worker_id, set())
            dead: list[queue.Queue] = []
            for c in clients:
                try:
                    c.put_nowait(message)
                except queue.Full:
                    dead.append(c)
            for d in dead:
                clients.discard(d)

    def broadcast(self, data: str) -> None:
        """Send a message to all connected workers."""
        message = self._format_sse("broadcast", data)
        with self._lock:
            for _worker_id, clients in self._worker_clients.items():
                dead: list[queue.Queue] = []
                for c in clients:
                    try:
                        c.put_nowait(message)
                    except queue.Full:
                        dead.append(c)
                for d in dead:
                    clients.discard(d)

    def create_client(self, worker_id: str) -> queue.Queue[str | None]:
        """Create and register a client queue for a worker.

        Args:
            worker_id: The worker to listen for notifications for.

        Returns:
            A per-client queue that will receive SSE-formatted messages.
        """
        client_queue: queue.Queue[str | None] = queue.Queue(maxsize=1000)
        with self._lock:
            if worker_id not in self._worker_clients:
                self._worker_clients[worker_id] = set()
            self._worker_clients[worker_id].add(client_queue)
        return client_queue

    def remove_client(self, worker_id: str, client_queue: queue.Queue[str | None]) -> None:
        """Unregister a client queue."""
        with self._lock:
            clients = self._worker_clients.get(worker_id, set())
            clients.discard(client_queue)
            if not clients:
                self._worker_clients.pop(worker_id, None)

    def subscribe(self, worker_id: str, timeout: float | None = 60.0) -> Generator[str, None, None]:
        """Yield SSE-formatted strings for a connected worker.

        Creates a per-client queue, streams new job notifications.
        Sends a keepalive comment every *timeout* seconds.

        Args:
            worker_id: The worker to subscribe for.
            timeout: Keepalive interval in seconds. None means no keepalive.

        Yields:
            SSE-formatted message strings.
        """
        client_queue = self.create_client(worker_id)
        try:
            yield _keepalive_comment()
            while True:
                try:
                    message = client_queue.get(timeout=timeout)
                except queue.Empty:
                    yield _keepalive_comment()
                    continue
                if message is None:
                    return
                yield message
        finally:
            self.remove_client(worker_id, client_queue)

    @property
    def client_count(self) -> int:
        with self._lock:
            return sum(len(clients) for clients in self._worker_clients.values())


def _keepalive_comment() -> str:
    return ": heartbeat\n\n"
