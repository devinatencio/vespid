"""Unit tests for SSE manager.

Tests publish/subscribe, client cleanup, Last-Event-ID replay, and message format.
Requirements: 5.1, 5.2, 5.3
"""

import threading
import time

import pytest

from app.sse import SSEManager


class TestSSEMessageFormat:
    """Test that SSE messages follow the required format."""

    def test_format_sse_basic(self):
        """SSE message should follow id/event/data format with trailing blank line."""
        msg = SSEManager._format_sse("evt-001", "<div>hello</div>")
        assert msg == "id: evt-001\nevent: new_event\ndata: <div>hello</div>\n\n"

    def test_format_sse_empty_data(self):
        """SSE message with empty data should still be well-formed."""
        msg = SSEManager._format_sse("evt-002", "")
        assert msg == "id: evt-002\nevent: new_event\ndata: \n\n"

    def test_format_sse_special_characters(self):
        """SSE message should preserve special characters in data."""
        data = '<tr class="event"><td>&amp;</td></tr>'
        msg = SSEManager._format_sse("evt-003", data)
        assert f"data: {data}" in msg
        assert msg.startswith("id: evt-003\n")
        assert "event: new_event\n" in msg
        assert msg.endswith("\n\n")


class TestPublishSubscribe:
    """Test basic publish/subscribe functionality."""

    def test_single_subscriber_receives_message(self):
        """A single subscriber should receive published messages."""
        mgr = SSEManager(history_size=10)
        messages = []

        def consumer():
            for msg in mgr.subscribe(timeout=0.5):
                messages.append(msg)

        t = threading.Thread(target=consumer)
        t.start()

        # Give the subscriber time to register
        time.sleep(0.05)

        mgr.publish("e1", "<div>event 1</div>")
        t.join(timeout=2)

        assert len(messages) == 1
        assert "id: e1\n" in messages[0]
        assert "data: <div>event 1</div>" in messages[0]

    def test_multiple_subscribers_receive_same_message(self):
        """All connected subscribers should receive the same published message."""
        mgr = SSEManager(history_size=10)
        results = {0: [], 1: [], 2: []}

        def consumer(idx):
            for msg in mgr.subscribe(timeout=0.5):
                results[idx].append(msg)

        threads = [threading.Thread(target=consumer, args=(i,)) for i in range(3)]
        for t in threads:
            t.start()

        time.sleep(0.05)

        mgr.publish("e1", "data1")

        for t in threads:
            t.join(timeout=2)

        for idx in range(3):
            assert len(results[idx]) == 1
            assert "id: e1\n" in results[idx][0]

    def test_multiple_publishes_received_in_order(self):
        """Subscriber should receive multiple messages in publish order."""
        mgr = SSEManager(history_size=10)
        messages = []

        def consumer():
            for msg in mgr.subscribe(timeout=0.5):
                messages.append(msg)

        t = threading.Thread(target=consumer)
        t.start()
        time.sleep(0.05)

        mgr.publish("e1", "first")
        mgr.publish("e2", "second")
        mgr.publish("e3", "third")

        t.join(timeout=2)

        assert len(messages) == 3
        assert "id: e1\n" in messages[0]
        assert "id: e2\n" in messages[1]
        assert "id: e3\n" in messages[2]

    def test_no_messages_before_subscribe(self):
        """Messages published before subscribe should not be received (without Last-Event-ID)."""
        mgr = SSEManager(history_size=10)

        mgr.publish("e1", "before")

        messages = []

        def consumer():
            for msg in mgr.subscribe(timeout=0.3):
                messages.append(msg)

        t = threading.Thread(target=consumer)
        t.start()
        time.sleep(0.05)

        mgr.publish("e2", "after")
        t.join(timeout=2)

        assert len(messages) == 1
        assert "id: e2\n" in messages[0]


class TestClientCleanup:
    """Test automatic cleanup of disconnected clients."""

    def test_client_count_increases_on_subscribe(self):
        """Client count should increase when a subscriber connects."""
        mgr = SSEManager(history_size=10)
        assert mgr.client_count == 0

        messages = []

        def consumer():
            for msg in mgr.subscribe(timeout=0.3):
                messages.append(msg)

        t = threading.Thread(target=consumer)
        t.start()
        time.sleep(0.05)

        assert mgr.client_count == 1
        t.join(timeout=2)

    def test_client_count_decreases_after_disconnect(self):
        """Client count should decrease when a subscriber disconnects."""
        mgr = SSEManager(history_size=10)

        def consumer():
            for msg in mgr.subscribe(timeout=0.2):
                pass

        t = threading.Thread(target=consumer)
        t.start()
        time.sleep(0.05)
        assert mgr.client_count == 1

        t.join(timeout=2)
        # After the generator exits, the client should be cleaned up
        assert mgr.client_count == 0

    def test_disconnect_all_stops_subscribers(self):
        """disconnect_all should send sentinel and clear all clients."""
        mgr = SSEManager(history_size=10)
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


class TestLastEventIDReplay:
    """Test Last-Event-ID reconnection replay."""

    def test_replay_from_last_event_id(self):
        """Reconnecting with Last-Event-ID should replay missed events."""
        mgr = SSEManager(history_size=100)

        # Publish some events (no subscribers yet — they go to history only)
        mgr.publish("e1", "first")
        mgr.publish("e2", "second")
        mgr.publish("e3", "third")
        mgr.publish("e4", "fourth")

        # Subscribe with last_event_id="e2" — should replay e3 and e4
        messages = []

        def consumer():
            for msg in mgr.subscribe(last_event_id="e2", timeout=0.3):
                messages.append(msg)

        t = threading.Thread(target=consumer)
        t.start()
        t.join(timeout=2)

        assert len(messages) == 2
        assert "id: e3\n" in messages[0]
        assert "id: e4\n" in messages[1]

    def test_replay_plus_live_events(self):
        """Reconnecting should replay missed events then receive live ones."""
        mgr = SSEManager(history_size=100)

        mgr.publish("e1", "first")
        mgr.publish("e2", "second")

        messages = []

        def consumer():
            for msg in mgr.subscribe(last_event_id="e1", timeout=0.5):
                messages.append(msg)

        t = threading.Thread(target=consumer)
        t.start()
        time.sleep(0.05)

        # Publish a live event after the subscriber connects
        mgr.publish("e3", "live")

        t.join(timeout=2)

        # Should have e2 (replayed) + e3 (live)
        assert len(messages) == 2
        assert "id: e2\n" in messages[0]
        assert "id: e3\n" in messages[1]

    def test_replay_unknown_last_event_id(self):
        """If Last-Event-ID is not in history, no replay occurs."""
        mgr = SSEManager(history_size=100)

        mgr.publish("e1", "first")
        mgr.publish("e2", "second")

        messages = []

        def consumer():
            for msg in mgr.subscribe(last_event_id="unknown-id", timeout=0.3):
                messages.append(msg)

        t = threading.Thread(target=consumer)
        t.start()
        time.sleep(0.05)

        mgr.publish("e3", "live")
        t.join(timeout=2)

        # Only the live event should be received
        assert len(messages) == 1
        assert "id: e3\n" in messages[0]

    def test_replay_last_event_in_history(self):
        """If Last-Event-ID is the most recent event, no replay occurs."""
        mgr = SSEManager(history_size=100)

        mgr.publish("e1", "first")
        mgr.publish("e2", "second")

        messages = []

        def consumer():
            for msg in mgr.subscribe(last_event_id="e2", timeout=0.3):
                messages.append(msg)

        t = threading.Thread(target=consumer)
        t.start()
        time.sleep(0.05)

        mgr.publish("e3", "live")
        t.join(timeout=2)

        # Only the live event
        assert len(messages) == 1
        assert "id: e3\n" in messages[0]

    def test_history_respects_max_size(self):
        """History ring buffer should not exceed the configured size."""
        mgr = SSEManager(history_size=3)

        mgr.publish("e1", "one")
        mgr.publish("e2", "two")
        mgr.publish("e3", "three")
        mgr.publish("e4", "four")
        mgr.publish("e5", "five")

        # e1 and e2 should have been evicted from history
        messages = []

        def consumer():
            for msg in mgr.subscribe(last_event_id="e1", timeout=0.3):
                messages.append(msg)

        t = threading.Thread(target=consumer)
        t.start()
        t.join(timeout=2)

        # e1 is no longer in history, so no replay
        assert len(messages) == 0

    def test_replay_from_oldest_in_history(self):
        """Replaying from the oldest event in history should replay all subsequent."""
        mgr = SSEManager(history_size=5)

        mgr.publish("e1", "one")
        mgr.publish("e2", "two")
        mgr.publish("e3", "three")

        messages = []

        def consumer():
            for msg in mgr.subscribe(last_event_id="e1", timeout=0.3):
                messages.append(msg)

        t = threading.Thread(target=consumer)
        t.start()
        t.join(timeout=2)

        assert len(messages) == 2
        assert "id: e2\n" in messages[0]
        assert "id: e3\n" in messages[1]

    def test_no_last_event_id_no_replay(self):
        """Without Last-Event-ID, no history replay should occur."""
        mgr = SSEManager(history_size=100)

        mgr.publish("e1", "first")
        mgr.publish("e2", "second")

        messages = []

        def consumer():
            for msg in mgr.subscribe(last_event_id=None, timeout=0.3):
                messages.append(msg)

        t = threading.Thread(target=consumer)
        t.start()
        time.sleep(0.05)

        mgr.publish("e3", "live")
        t.join(timeout=2)

        # Only the live event
        assert len(messages) == 1
        assert "id: e3\n" in messages[0]


class TestThreadSafety:
    """Test thread-safety of concurrent publish/subscribe operations."""

    def test_concurrent_publish_and_subscribe(self):
        """Multiple publishers and subscribers should work concurrently."""
        mgr = SSEManager(history_size=100)
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

        # The subscriber should have received all events
        assert len(subscriber_messages) == total_events
