"""Fleet SSE (Server-Sent Events) manager.

Provides thread-safe fan-out of fleet block events to connected SSE clients.
Supports Last-Event-ID for reconnection via a configurable history ring buffer.

This is a dedicated SSE manager for fleet block propagation, separate from
the dashboard SSE stream to avoid cross-contamination and allow independent
scaling.

Requirements: 2.1, 2.4, 2.5, 2.6
"""

from __future__ import annotations

import os
import queue
import threading
from collections import deque
from collections.abc import Generator

# Default history size for fleet SSE reconnection replay.
_DEFAULT_FLEET_HISTORY_SIZE = 1000


class FleetSSEManager:
    """Manages Fleet Block Server-Sent Events connections.

    - Maintains a set of connected client queues
    - When a fleet block is approved/removed, pushes an SSE-formatted message
      to all connected subscriber queues
    - Supports Last-Event-ID for reconnection (tracks last N fleet block IDs)
    - Clients that disconnect are cleaned up automatically

    The event type is ``fleet_block`` and the ``id`` field is set to the
    ``fleet_block_id`` for each message.
    """

    def __init__(self, history_size: int | None = None):
        if history_size is None:
            history_size = _DEFAULT_FLEET_HISTORY_SIZE
        self.history_size = history_size

        # Lock protects _clients and _history
        self._lock = threading.Lock()

        # Set of per-client queues
        self._clients: set[queue.Queue[str | None]] = set()

        # Ring buffer of (fleet_block_id, formatted_message) tuples for replay
        self._history: deque[tuple[str, str]] = deque(maxlen=history_size)

        # Optional Redis bridge for cross-worker fan-out
        self._redis_bridge = None
        self._redis_channel: str | None = None

    @staticmethod
    def _format_sse(fleet_block_id: str, data: str) -> str:
        """Format a single SSE message for fleet block events.

        SSE message format:
            id: <fleet_block_id>
            event: fleet_block
            data: <line1>
            data: <line2>
            ...

            (terminated by a blank line)

        Multi-line data is split across multiple ``data:`` fields per the
        SSE spec — the client reassembles them with newline separators.
        """
        lines = data.split("\n")
        data_section = "\n".join(f"data: {line}" for line in lines)
        return f"id: {fleet_block_id}\nevent: fleet_block\n{data_section}\n\n"

    def set_redis(self, bridge, channel: str) -> None:
        """Attach a Redis pub/sub bridge for cross-worker fan-out."""
        self._redis_bridge = bridge
        self._redis_channel = channel
        bridge.register(channel, self._on_redis_message)

    def _on_redis_message(self, data: dict) -> None:
        # Skip if this message originated from the same worker process —
        # publish() already fanned it out locally.  Without this check
        # every event gets delivered twice to the publishing worker's
        # clients (once from _fan_out() in publish(), once from Redis
        # pub/sub loopback).
        if data.get("_origin_pid") == os.getpid():
            return
        message = data.get("message", "")
        if message:
            self._fan_out(message)

    def _fan_out(self, message: str) -> None:
        """Push a pre-formatted SSE message to local client queues."""
        with self._lock:
            dead_clients: list[queue.Queue] = []
            for client_queue in self._clients:
                try:
                    client_queue.put_nowait(message)
                except queue.Full:
                    dead_clients.append(client_queue)
            for dead in dead_clients:
                self._clients.discard(dead)

    def publish(self, fleet_block_id: str, data: str) -> None:
        """Push a new fleet block event to all connected clients.

        Args:
            fleet_block_id: Unique identifier for the fleet block event
                (used as the SSE id field and for Last-Event-ID replay).
            data: The JSON payload to send as the SSE data field.
        """
        message = self._format_sse(fleet_block_id, data)

        with self._lock:
            self._history.append((fleet_block_id, message))

        self._fan_out(message)

        if self._redis_bridge and self._redis_channel:
            self._redis_bridge.publish(
                self._redis_channel,
                {
                    "message": message,
                    "_origin_pid": os.getpid(),
                },
            )

    def create_client(self, last_event_id: str | None = None) -> queue.Queue[str | None]:
        """Create and register a client queue, replaying missed events.

        This gives the caller direct access to the queue so it can
        implement its own get-with-timeout loop (e.g. for keepalive
        comments).  The caller **must** call :meth:`remove_client` when
        done.

        Args:
            last_event_id: If provided, replay events after this ID from
                the history buffer into the queue before returning.

        Returns:
            A per-client queue that will receive SSE-formatted messages.
        """
        client_queue: queue.Queue[str | None] = queue.Queue(maxsize=1000)

        with self._lock:
            if last_event_id is not None:
                found = False
                for eid, message in self._history:
                    if found:
                        client_queue.put_nowait(message)
                    elif eid == last_event_id:
                        found = True

            self._clients.add(client_queue)

        return client_queue

    def remove_client(self, client_queue: queue.Queue[str | None]) -> None:
        """Unregister a client queue created by :meth:`create_client`."""
        with self._lock:
            self._clients.discard(client_queue)

    def subscribe(
        self, last_event_id: str | None = None, timeout: float | None = None
    ) -> Generator[str, None, None]:
        """Yield SSE-formatted strings for a connected fleet block subscriber.

        Creates a per-client queue, optionally replays missed events from
        history if *last_event_id* is provided, then blocks waiting for
        new messages.

        Args:
            last_event_id: If provided, replay events after this ID from
                the history buffer before streaming live events.
            timeout: Optional timeout in seconds for queue.get(). If None,
                blocks indefinitely. Useful for testing.

        Yields:
            SSE-formatted message strings.
        """
        client_queue: queue.Queue[str | None] = queue.Queue(maxsize=1000)

        with self._lock:
            # Replay missed events from history if reconnecting
            if last_event_id is not None:
                found = False
                for eid, message in self._history:
                    if found:
                        client_queue.put_nowait(message)
                    elif eid == last_event_id:
                        found = True
                # If the ID wasn't found in history, we can't replay —
                # the client will just start receiving new events.

            # Register the client queue for live events
            self._clients.add(client_queue)

        try:
            while True:
                try:
                    message = client_queue.get(timeout=timeout)
                except queue.Empty:
                    # Timeout reached — stop the generator (used in tests)
                    return
                if message is None:
                    # Sentinel value — shut down this subscriber
                    return
                yield message
        finally:
            # Clean up: remove the client queue when the generator is closed
            with self._lock:
                self._clients.discard(client_queue)

    def disconnect_all(self) -> None:
        """Send a sentinel to all connected clients to shut them down."""
        with self._lock:
            for client_queue in self._clients:
                try:
                    client_queue.put_nowait(None)
                except queue.Full:
                    pass
            self._clients.clear()

    @property
    def client_count(self) -> int:
        """Return the number of currently connected clients."""
        with self._lock:
            return len(self._clients)
