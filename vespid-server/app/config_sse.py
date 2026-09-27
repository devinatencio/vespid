"""Config SSE (Server-Sent Events) manager.

Provides thread-safe fan-out of configuration update events to connected
SSE clients, keyed by node_id for targeted push to specific agents.
Supports Last-Event-ID for reconnection via a configurable history ring buffer.

This is a dedicated SSE manager for configuration synchronization, modeled
after FleetSSEManager but with per-node targeting for profile-based distribution.

Requirements: 5.1, 5.2, 5.8, 5.13, 16.1, 16.2, 16.11
"""

from __future__ import annotations

import json
import queue
import threading
from collections import deque
from collections.abc import Generator

# Default history size for config SSE reconnection replay.
_DEFAULT_CONFIG_HISTORY_SIZE = 1000

# Keepalive interval in seconds (SSE comment sent on idle connections).
_KEEPALIVE_INTERVAL = 30


class ConfigSSEManager:
    """Manages Config Server-Sent Events connections.

    - Maintains per-node client queues (keyed by node_id for targeted push)
    - When a profile is updated, pushes config_updated events to all
      connected agents assigned to that profile
    - Supports Last-Event-ID for reconnection replay via history ring buffer
    - Respects rollout policies (only pushes to targeted agents)
    - Sends keepalive comments every 30 seconds on idle connections

    The event type is ``config_updated`` and the ``id`` field is set to a
    monotonically increasing event ID for each message.
    """

    def __init__(self, history_size: int | None = None):
        if history_size is None:
            history_size = _DEFAULT_CONFIG_HISTORY_SIZE
        self.history_size = history_size

        # Lock protects _clients, _history, and _event_counter
        self._lock = threading.Lock()

        # Per-node client queues: node_id -> Queue
        self._clients: dict[str, queue.Queue[str | None]] = {}

        # Ring buffer of (event_id, formatted_message) tuples for replay
        self._history: deque[tuple[str, str]] = deque(maxlen=history_size)

        # Monotonically increasing event counter for unique event IDs
        self._event_counter: int = 0

        # Optional Redis bridge for cross-worker fan-out
        self._redis_bridge = None
        self._redis_channel: str | None = None

    def _next_event_id(self) -> str:
        """Generate the next monotonic event ID.

        Must be called while holding self._lock.
        """
        self._event_counter += 1
        return str(self._event_counter)

    @staticmethod
    def _format_sse(event_id: str, data: str) -> str:
        """Format a single SSE message for config_updated events.

        SSE message format:
            id: <event_id>
            event: config_updated
            data: <line1>
            data: <line2>
            ...

            (terminated by a blank line)

        Multi-line data is split across multiple ``data:`` fields per the
        SSE spec — the client reassembles them with newline separators.
        """
        lines = data.split("\n")
        data_section = "\n".join(f"data: {line}" for line in lines)
        return f"id: {event_id}\nevent: config_updated\n{data_section}\n\n"

    def set_redis(self, bridge, channel: str) -> None:
        """Attach a Redis pub/sub bridge for cross-worker fan-out."""
        self._redis_bridge = bridge
        self._redis_channel = channel
        bridge.register(channel, self._on_redis_message)

    def _on_redis_message(self, data: dict) -> None:
        """Handle a message received from Redis (another worker)."""
        message = data.get("message", "")
        target_nodes = data.get("target_nodes")
        if message:
            self._fan_out(message, target_nodes)

    def _fan_out(self, message: str, target_nodes: list[str] | None = None) -> None:
        """Push a pre-formatted SSE message to local client queues."""
        with self._lock:
            if target_nodes is not None:
                target_set = set(target_nodes)
                target_clients = {nid: q for nid, q in self._clients.items() if nid in target_set}
            else:
                target_clients = dict(self._clients)

            dead_clients: list[str] = []
            for node_id, client_queue in target_clients.items():
                try:
                    client_queue.put_nowait(message)
                except queue.Full:
                    dead_clients.append(node_id)

            for node_id in dead_clients:
                self._clients.pop(node_id, None)

    def publish_to_profile(
        self,
        profile_id: int,
        event_data: dict,
        target_nodes: list[str] | None = None,
    ) -> None:
        """Push a config_updated event to agents assigned to a profile.

        If target_nodes is provided (for canary/staged rollouts), only
        those nodes receive the event. Otherwise all connected nodes in
        target_nodes receive it.

        Args:
            profile_id: The profile ID being updated (included in event
                metadata for logging/debugging).
            event_data: The event payload dict (will be JSON-serialized).
                Should contain: profile_name, version, settings,
                updated_at, conflict_strategy.
            target_nodes: If provided, only push to these node_ids.
                If None, push to all currently connected clients.
        """
        data_str = json.dumps(event_data, separators=(",", ":"))

        with self._lock:
            event_id = self._next_event_id()
            message = self._format_sse(event_id, data_str)
            self._history.append((event_id, message))

        self._fan_out(message, target_nodes)

        if self._redis_bridge and self._redis_channel:
            self._redis_bridge.publish(
                self._redis_channel,
                {
                    "message": message,
                    "target_nodes": target_nodes,
                },
            )

    def publish_list_update(
        self,
        action: str,
        key: str,
        entry: str,
    ) -> None:
        """Push a list_update event to all connected agents.

        Lightweight delta event for allowlist/blocklist changes,
        decoupled from config profile versioning.

        Args:
            action: ``"add"`` or ``"remove"``.
            key: ``"allowlist"`` or ``"blocklist"``.
            entry: The IP/CIDR being added or removed.
        """
        event_data = {"action": action, "key": key, "entry": entry}
        data_str = json.dumps(event_data, separators=(",", ":"))

        with self._lock:
            event_id = self._next_event_id()
            message = self._format_list_update_sse(event_id, data_str)
            self._history.append((event_id, message))

        self._fan_out(message, target_nodes=None)

        if self._redis_bridge and self._redis_channel:
            self._redis_bridge.publish(
                self._redis_channel,
                {
                    "message": message,
                    "target_nodes": None,
                },
            )

    @staticmethod
    def _format_list_update_sse(event_id: str, data: str) -> str:
        """Format a single SSE message for list_update events."""
        lines = data.split("\n")
        data_section = "\n".join(f"data: {line}" for line in lines)
        return f"id: {event_id}\nevent: list_update\n{data_section}\n\n"

    def create_client(
        self, node_id: str, last_event_id: str | None = None
    ) -> queue.Queue[str | None]:
        """Register a node's SSE client queue with optional history replay.

        If the node already has a registered client, the old queue is
        replaced (previous connection is considered stale).

        Args:
            node_id: The agent's unique node identifier.
            last_event_id: If provided, replay events after this ID from
                the history buffer into the queue before returning.

        Returns:
            A per-client queue that will receive SSE-formatted messages.
        """
        client_queue: queue.Queue[str | None] = queue.Queue(maxsize=1000)

        with self._lock:
            # If there's an existing client for this node, send sentinel
            # to signal the old connection should close
            old_queue = self._clients.get(node_id)
            if old_queue is not None:
                try:
                    old_queue.put_nowait(None)
                except queue.Full:
                    pass

            # Replay missed events from history if reconnecting
            if last_event_id is not None:
                found = False
                for eid, message in self._history:
                    if found:
                        client_queue.put_nowait(message)
                    elif eid == last_event_id:
                        found = True

            # Register the new client queue
            self._clients[node_id] = client_queue

        return client_queue

    def remove_client(self, node_id: str) -> None:
        """Unregister a node's SSE client queue.

        Args:
            node_id: The agent's unique node identifier.
        """
        with self._lock:
            self._clients.pop(node_id, None)

    def subscribe(
        self, node_id: str, last_event_id: str | None = None
    ) -> Generator[str, None, None]:
        """Yield SSE-formatted strings for a connected config subscriber.

        Creates a per-client queue, optionally replays missed events from
        history if *last_event_id* is provided, then blocks waiting for
        new messages. Sends keepalive comments (`: keepalive\\n\\n`) every
        30 seconds on idle connections.

        Args:
            node_id: The agent's unique node identifier.
            last_event_id: If provided, replay events after this ID from
                the history buffer before streaming live events.

        Yields:
            SSE-formatted message strings (events or keepalive comments).
        """
        client_queue = self.create_client(node_id, last_event_id)

        try:
            while True:
                try:
                    message = client_queue.get(timeout=_KEEPALIVE_INTERVAL)
                except queue.Empty:
                    # Timeout reached — send keepalive comment
                    yield ": keepalive\n\n"
                    continue
                if message is None:
                    # Sentinel value — shut down this subscriber
                    return
                yield message
        finally:
            # Clean up: remove the client queue when the generator is closed
            self.remove_client(node_id)

    def disconnect_all(self) -> None:
        """Send a sentinel to all connected clients to shut them down."""
        with self._lock:
            for client_queue in self._clients.values():
                try:
                    client_queue.put_nowait(None)
                except queue.Full:
                    pass
            self._clients.clear()

    def disconnect_node(self, node_id: str) -> None:
        """Send a sentinel to a specific node's client to shut it down.

        Args:
            node_id: The agent's unique node identifier.
        """
        with self._lock:
            client_queue = self._clients.pop(node_id, None)
            if client_queue is not None:
                try:
                    client_queue.put_nowait(None)
                except queue.Full:
                    pass

    @property
    def client_count(self) -> int:
        """Return the number of currently connected clients."""
        with self._lock:
            return len(self._clients)

    def get_connected_nodes(self) -> list[str]:
        """Return a list of currently connected node IDs."""
        with self._lock:
            return list(self._clients.keys())
