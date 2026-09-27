"""Unit tests for Fleet SSE manager.

Tests publish/subscribe, client cleanup, Last-Event-ID replay, and message format.
Requirements: 2.1, 2.4, 2.5, 2.6
"""

import threading
import time

import pytest

from app.fleet_sse import FleetSSEManager


class TestFleetSSEMessageFormat:
    """Test that Fleet SSE messages follow the required format."""

    def test_format_sse_basic(self):
        """SSE message should use fleet_block event type and fleet_block_id as id."""
        msg = FleetSSEManager._format_sse("fb-001", '{"action":"block","source_ip":"1.2.3.4"}')
        assert msg == (
            'id: fb-001\n'
            'event: fleet_block\n'
            'data: {"action":"block","source_ip":"1.2.3.4"}\n\n'
        )

    def test_format_sse_empty_data(self):
        """SSE message with empty data should still be well-formed."""
        msg = FleetSSEManager._format_sse("fb-002", "")
        assert msg == "id: fb-002\nevent: fleet_block\ndata: \n\n"

    def test_format_sse_multiline_data(self):
        """Multi-line data should be split across multiple data: fields."""
        msg = FleetSSEManager._format_sse("fb-003", "line1\nline2\nline3")
        assert "data: line1\n" in msg
        assert "data: line2\n" in msg
        assert "data: line3\n" in msg
        assert msg.startswith("id: fb-003\n")
        assert "event: fleet_block\n" in msg
        assert msg.endswith("\n\n")

    def test_format_sse_event_type_is_fleet_block(self):
        """Event type must be 'fleet_block', not 'new_event'."""
        msg = FleetSSEManager._format_sse("fb-004", "test")
        assert "event: fleet_block\n" in msg
        assert "event: new_event" not in msg


class TestFleetPublishSubscribe:
    """Test basic publish/subscribe functionality."""

    def test_single_subscriber_receives_message(self):
        """A single subscriber should receive published fleet block messages."""
        mgr = FleetSSEManager(history_size=10)
        messages = []

        def consumer():
            for msg in mgr.subscribe(timeout=0.5):
                messages.append(msg)

        t = threading.Thread(target=consumer)
        t.start()
        time.sleep(0.05)

        mgr.publish("fb-1", '{"action":"block","source_ip":"10.0.0.1"}')
        t.join(timeout=2)

        assert len(messages) == 1
        assert "id: fb-1\n" in messages[0]
        assert "event: fleet_block\n" in messages[0]
        assert 'data: {"action":"block","source_ip":"10.0.0.1"}' in messages[0]

    def test_multiple_subscribers_receive_same_message(self):
        """All connected subscribers should receive the same published message."""
        mgr = FleetSSEManager(history_size=10)
        results = {0: [], 1: [], 2: []}

        def consumer(idx):
            for msg in mgr.subscribe(timeout=0.5):
                results[idx].append(msg)

        threads = [threading.Thread(target=consumer, args=(i,)) for i in range(3)]
        for t in threads:
            t.start()
        time.sleep(0.05)

        mgr.publish("fb-1", "data1")

        for t in threads:
            t.join(timeout=2)

        for idx in range(3):
            assert len(results[idx]) == 1
            assert "id: fb-1\n" in results[idx][0]

    def test_multiple_publishes_received_in_order(self):
        """Subscriber should receive multiple messages in publish order."""
        mgr = FleetSSEManager(history_size=10)
        messages = []

        def consumer():
            for msg in mgr.subscribe(timeout=0.5):
                messages.append(msg)

        t = threading.Thread(target=consumer)
        t.start()
        time.sleep(0.05)

        mgr.publish("fb-1", "first")
        mgr.publish("fb-2", "second")
        mgr.publish("fb-3", "third")

        t.join(timeout=2)

        assert len(messages) == 3
        assert "id: fb-1\n" in messages[0]
        assert "id: fb-2\n" in messages[1]
        assert "id: fb-3\n" in messages[2]


class TestFleetClientManagement:
    """Test create_client/remove_client and client cleanup."""

    def test_create_client_returns_queue(self):
        """create_client should return a queue that receives published messages."""
        mgr = FleetSSEManager(history_size=10)
        client_q = mgr.create_client()

        mgr.publish("fb-1", "test-data")

        msg = client_q.get(timeout=1)
        assert "id: fb-1\n" in msg
        assert "event: fleet_block\n" in msg

    def test_remove_client_stops_receiving(self):
        """After remove_client, the queue should no longer receive messages."""
        mgr = FleetSSEManager(history_size=10)
        client_q = mgr.create_client()

        assert mgr.client_count == 1
        mgr.remove_client(client_q)
        assert mgr.client_count == 0

        mgr.publish("fb-1", "test-data")
        assert client_q.empty()

    def test_create_client_with_last_event_id_replays(self):
        """create_client with last_event_id should replay missed events."""
        mgr = FleetSSEManager(history_size=100)

        mgr.publish("fb-1", "first")
        mgr.publish("fb-2", "second")
        mgr.publish("fb-3", "third")

        client_q = mgr.create_client(last_event_id="fb-1")

        # Should have fb-2 and fb-3 replayed
        msg1 = client_q.get(timeout=1)
        msg2 = client_q.get(timeout=1)
        assert "id: fb-2\n" in msg1
        assert "id: fb-3\n" in msg2
        assert client_q.empty()

    def test_create_client_unknown_last_event_id(self):
        """If last_event_id is not in history, no replay occurs."""
        mgr = FleetSSEManager(history_size=100)

        mgr.publish("fb-1", "first")
        mgr.publish("fb-2", "second")

        client_q = mgr.create_client(last_event_id="unknown-id")

        # No replay — queue should be empty
        assert client_q.empty()

    def test_client_count(self):
        """client_count should track connected clients."""
        mgr = FleetSSEManager(history_size=10)
        assert mgr.client_count == 0

        q1 = mgr.create_client()
        assert mgr.client_count == 1

        q2 = mgr.create_client()
        assert mgr.client_count == 2

        mgr.remove_client(q1)
        assert mgr.client_count == 1

        mgr.remove_client(q2)
        assert mgr.client_count == 0

    def test_disconnect_all_stops_subscribers(self):
        """disconnect_all should send sentinel and clear all clients."""
        mgr = FleetSSEManager(history_size=10)
        messages = []

        def consumer():
            for msg in mgr.subscribe(timeout=2):
                messages.append(msg)

        t = threading.Thread(target=consumer)
        t.start()
        time.sleep(0.05)

        assert mgr.client_count == 1
        mgr.disconnect_all()
        t.join(timeout=2)

        assert mgr.client_count == 0


class TestFleetLastEventIDReplay:
    """Test Last-Event-ID reconnection replay."""

    def test_replay_from_last_event_id(self):
        """Reconnecting with Last-Event-ID should replay missed events."""
        mgr = FleetSSEManager(history_size=100)

        mgr.publish("fb-1", "first")
        mgr.publish("fb-2", "second")
        mgr.publish("fb-3", "third")
        mgr.publish("fb-4", "fourth")

        # Subscribe with last_event_id="fb-2" — should replay fb-3 and fb-4
        messages = []

        def consumer():
            for msg in mgr.subscribe(last_event_id="fb-2", timeout=0.3):
                messages.append(msg)

        t = threading.Thread(target=consumer)
        t.start()
        t.join(timeout=2)

        assert len(messages) == 2
        assert "id: fb-3\n" in messages[0]
        assert "id: fb-4\n" in messages[1]

    def test_replay_plus_live_events(self):
        """Reconnecting should replay missed events then receive live ones."""
        mgr = FleetSSEManager(history_size=100)

        mgr.publish("fb-1", "first")
        mgr.publish("fb-2", "second")

        messages = []

        def consumer():
            for msg in mgr.subscribe(last_event_id="fb-1", timeout=0.5):
                messages.append(msg)

        t = threading.Thread(target=consumer)
        t.start()
        time.sleep(0.05)

        mgr.publish("fb-3", "live")
        t.join(timeout=2)

        # Should have fb-2 (replayed) + fb-3 (live)
        assert len(messages) == 2
        assert "id: fb-2\n" in messages[0]
        assert "id: fb-3\n" in messages[1]

    def test_replay_last_event_in_history(self):
        """If Last-Event-ID is the most recent event, no replay occurs."""
        mgr = FleetSSEManager(history_size=100)

        mgr.publish("fb-1", "first")
        mgr.publish("fb-2", "second")

        messages = []

        def consumer():
            for msg in mgr.subscribe(last_event_id="fb-2", timeout=0.3):
                messages.append(msg)

        t = threading.Thread(target=consumer)
        t.start()
        time.sleep(0.05)

        mgr.publish("fb-3", "live")
        t.join(timeout=2)

        assert len(messages) == 1
        assert "id: fb-3\n" in messages[0]

    def test_history_respects_max_size(self):
        """History ring buffer should not exceed the configured size."""
        mgr = FleetSSEManager(history_size=3)

        mgr.publish("fb-1", "one")
        mgr.publish("fb-2", "two")
        mgr.publish("fb-3", "three")
        mgr.publish("fb-4", "four")
        mgr.publish("fb-5", "five")

        # fb-1 and fb-2 should have been evicted from history
        messages = []

        def consumer():
            for msg in mgr.subscribe(last_event_id="fb-1", timeout=0.3):
                messages.append(msg)

        t = threading.Thread(target=consumer)
        t.start()
        t.join(timeout=2)

        # fb-1 is no longer in history, so no replay
        assert len(messages) == 0

    def test_default_history_size_is_1000(self):
        """Default history size should be 1000."""
        mgr = FleetSSEManager()
        assert mgr.history_size == 1000

    def test_replay_events_in_chronological_order(self):
        """Replayed events must be in chronological (publish) order."""
        mgr = FleetSSEManager(history_size=100)

        for i in range(10):
            mgr.publish(f"fb-{i}", f"event-{i}")

        messages = []

        def consumer():
            for msg in mgr.subscribe(last_event_id="fb-3", timeout=0.3):
                messages.append(msg)

        t = threading.Thread(target=consumer)
        t.start()
        t.join(timeout=2)

        # Should replay fb-4 through fb-9
        assert len(messages) == 6
        for idx, i in enumerate(range(4, 10)):
            assert f"id: fb-{i}\n" in messages[idx]


class TestFleetSSEThreadSafety:
    """Test thread-safety of concurrent publish/subscribe operations."""

    def test_concurrent_publish_and_subscribe(self):
        """Multiple publishers and subscribers should work concurrently."""
        mgr = FleetSSEManager(history_size=100)
        num_publishers = 3
        events_per_publisher = 10
        total_events = num_publishers * events_per_publisher

        subscriber_messages = []

        def subscriber():
            for msg in mgr.subscribe(timeout=1.0):
                subscriber_messages.append(msg)

        def publisher(prefix):
            for i in range(events_per_publisher):
                mgr.publish(f"{prefix}-{i}", f"data-{prefix}-{i}")
                time.sleep(0.01)

        sub_thread = threading.Thread(target=subscriber)
        sub_thread.start()
        time.sleep(0.05)

        pub_threads = [
            threading.Thread(target=publisher, args=(f"pub{j}",))
            for j in range(num_publishers)
        ]
        for t in pub_threads:
            t.start()
        for t in pub_threads:
            t.join(timeout=5)

        sub_thread.join(timeout=3)

        assert len(subscriber_messages) == total_events
