"""Unit tests for Config SSE manager.

Tests publish/subscribe, per-node targeting, client cleanup, Last-Event-ID
replay, keepalive, and message format.
Requirements: 5.1, 5.2, 5.8, 5.13, 16.1, 16.2, 16.11
"""

import json
import threading
import time

import pytest

from app.config_sse import ConfigSSEManager, _KEEPALIVE_INTERVAL


class TestConfigSSEMessageFormat:
    """Test that Config SSE messages follow the required format."""

    def test_format_sse_basic(self):
        """SSE message should use config_updated event type and event_id as id."""
        msg = ConfigSSEManager._format_sse(
            "1", '{"profile_name":"prod","version":3}'
        )
        assert msg == (
            "id: 1\n"
            "event: config_updated\n"
            'data: {"profile_name":"prod","version":3}\n\n'
        )

    def test_format_sse_empty_data(self):
        """SSE message with empty data should still be well-formed."""
        msg = ConfigSSEManager._format_sse("2", "")
        assert msg == "id: 2\nevent: config_updated\ndata: \n\n"

    def test_format_sse_multiline_data(self):
        """Multi-line data should be split across multiple data: fields."""
        msg = ConfigSSEManager._format_sse("3", "line1\nline2\nline3")
        assert "data: line1\n" in msg
        assert "data: line2\n" in msg
        assert "data: line3\n" in msg
        assert msg.startswith("id: 3\n")
        assert "event: config_updated\n" in msg
        assert msg.endswith("\n\n")

    def test_format_sse_event_type_is_config_updated(self):
        """Event type must be 'config_updated'."""
        msg = ConfigSSEManager._format_sse("4", "test")
        assert "event: config_updated\n" in msg
        assert "event: fleet_block" not in msg


class TestConfigPublishToProfile:
    """Test publish_to_profile with targeted and broadcast delivery."""

    def test_targeted_publish_reaches_only_specified_nodes(self):
        """publish_to_profile with target_nodes should only reach those nodes."""
        mgr = ConfigSSEManager(history_size=10)
        q1 = mgr.create_client("node-1")
        q2 = mgr.create_client("node-2")
        q3 = mgr.create_client("node-3")

        event_data = {"profile_name": "prod", "version": 2, "settings": {}}
        mgr.publish_to_profile(
            profile_id=1, event_data=event_data, target_nodes=["node-1", "node-3"]
        )

        # node-1 and node-3 should receive the message
        msg1 = q1.get(timeout=1)
        msg3 = q3.get(timeout=1)
        assert "config_updated" in msg1
        assert "config_updated" in msg3

        # node-2 should NOT receive the message
        assert q2.empty()

    def test_broadcast_publish_reaches_all_nodes(self):
        """publish_to_profile with target_nodes=None should reach all clients."""
        mgr = ConfigSSEManager(history_size=10)
        q1 = mgr.create_client("node-1")
        q2 = mgr.create_client("node-2")

        event_data = {"profile_name": "dev", "version": 1, "settings": {}}
        mgr.publish_to_profile(profile_id=1, event_data=event_data, target_nodes=None)

        msg1 = q1.get(timeout=1)
        msg2 = q2.get(timeout=1)
        assert "config_updated" in msg1
        assert "config_updated" in msg2

    def test_publish_generates_monotonic_event_ids(self):
        """Each publish should generate a monotonically increasing event ID."""
        mgr = ConfigSSEManager(history_size=10)
        q = mgr.create_client("node-1")

        for i in range(5):
            mgr.publish_to_profile(
                profile_id=1,
                event_data={"version": i},
                target_nodes=["node-1"],
            )

        for i in range(1, 6):
            msg = q.get(timeout=1)
            assert f"id: {i}\n" in msg

    def test_publish_serializes_event_data_as_json(self):
        """Event data should be JSON-serialized in the SSE data field."""
        mgr = ConfigSSEManager(history_size=10)
        q = mgr.create_client("node-1")

        event_data = {
            "profile_name": "test-profile",
            "version": 5,
            "settings": {"allowlist": ["10.0.0.1"]},
            "conflict_strategy": "server-wins",
        }
        mgr.publish_to_profile(
            profile_id=1, event_data=event_data, target_nodes=["node-1"]
        )

        msg = q.get(timeout=1)
        # Extract data line and parse JSON
        for line in msg.split("\n"):
            if line.startswith("data: "):
                data_str = line[len("data: "):]
                parsed = json.loads(data_str)
                assert parsed["profile_name"] == "test-profile"
                assert parsed["version"] == 5
                assert parsed["settings"]["allowlist"] == ["10.0.0.1"]
                break
        else:
            pytest.fail("No data: line found in SSE message")

    def test_publish_to_nonexistent_target_nodes_is_noop(self):
        """Publishing to target_nodes that aren't connected should not error."""
        mgr = ConfigSSEManager(history_size=10)
        q = mgr.create_client("node-1")

        # Publish to nodes that don't exist — should not raise
        mgr.publish_to_profile(
            profile_id=1,
            event_data={"version": 1},
            target_nodes=["node-99", "node-100"],
        )

        # node-1 should not receive anything
        assert q.empty()


class TestConfigClientManagement:
    """Test create_client/remove_client and per-node keying."""

    def test_create_client_returns_queue(self):
        """create_client should return a queue that receives published messages."""
        mgr = ConfigSSEManager(history_size=10)
        client_q = mgr.create_client("node-1")

        mgr.publish_to_profile(
            profile_id=1,
            event_data={"version": 1},
            target_nodes=["node-1"],
        )

        msg = client_q.get(timeout=1)
        assert "config_updated" in msg

    def test_remove_client_stops_receiving(self):
        """After remove_client, the node should no longer receive messages."""
        mgr = ConfigSSEManager(history_size=10)
        mgr.create_client("node-1")

        assert mgr.client_count == 1
        mgr.remove_client("node-1")
        assert mgr.client_count == 0

    def test_replacing_client_sends_sentinel_to_old(self):
        """Creating a new client for the same node_id should close the old one."""
        mgr = ConfigSSEManager(history_size=10)
        q_old = mgr.create_client("node-1")
        q_new = mgr.create_client("node-1")

        # Old queue should receive sentinel (None)
        sentinel = q_old.get(timeout=1)
        assert sentinel is None

        # New queue should be active
        assert mgr.client_count == 1
        mgr.publish_to_profile(
            profile_id=1,
            event_data={"version": 1},
            target_nodes=["node-1"],
        )
        msg = q_new.get(timeout=1)
        assert "config_updated" in msg

    def test_client_count(self):
        """client_count should track connected clients."""
        mgr = ConfigSSEManager(history_size=10)
        assert mgr.client_count == 0

        mgr.create_client("node-1")
        assert mgr.client_count == 1

        mgr.create_client("node-2")
        assert mgr.client_count == 2

        mgr.remove_client("node-1")
        assert mgr.client_count == 1

        mgr.remove_client("node-2")
        assert mgr.client_count == 0

    def test_get_connected_nodes(self):
        """get_connected_nodes should return all connected node IDs."""
        mgr = ConfigSSEManager(history_size=10)
        mgr.create_client("node-a")
        mgr.create_client("node-b")
        mgr.create_client("node-c")

        nodes = mgr.get_connected_nodes()
        assert set(nodes) == {"node-a", "node-b", "node-c"}

    def test_disconnect_all_stops_subscribers(self):
        """disconnect_all should send sentinel and clear all clients."""
        mgr = ConfigSSEManager(history_size=10)
        q1 = mgr.create_client("node-1")
        q2 = mgr.create_client("node-2")

        mgr.disconnect_all()

        assert mgr.client_count == 0
        assert q1.get(timeout=1) is None
        assert q2.get(timeout=1) is None

    def test_disconnect_node(self):
        """disconnect_node should send sentinel to specific node only."""
        mgr = ConfigSSEManager(history_size=10)
        q1 = mgr.create_client("node-1")
        q2 = mgr.create_client("node-2")

        mgr.disconnect_node("node-1")

        assert mgr.client_count == 1
        assert q1.get(timeout=1) is None
        # node-2 should still be connected
        assert q2.empty()


class TestConfigLastEventIDReplay:
    """Test Last-Event-ID reconnection replay."""

    def test_replay_from_last_event_id(self):
        """Reconnecting with Last-Event-ID should replay missed events."""
        mgr = ConfigSSEManager(history_size=100)

        mgr.publish_to_profile(1, {"version": 1}, target_nodes=None)
        mgr.publish_to_profile(1, {"version": 2}, target_nodes=None)
        mgr.publish_to_profile(1, {"version": 3}, target_nodes=None)
        mgr.publish_to_profile(1, {"version": 4}, target_nodes=None)

        # Remove all clients, then reconnect with last_event_id="2"
        mgr.disconnect_all()

        q = mgr.create_client("node-1", last_event_id="2")

        # Should have events 3 and 4 replayed
        msg1 = q.get(timeout=1)
        msg2 = q.get(timeout=1)
        assert "id: 3\n" in msg1
        assert "id: 4\n" in msg2
        assert q.empty()

    def test_replay_unknown_last_event_id(self):
        """If last_event_id is not in history, no replay occurs."""
        mgr = ConfigSSEManager(history_size=100)

        mgr.publish_to_profile(1, {"version": 1}, target_nodes=None)
        mgr.publish_to_profile(1, {"version": 2}, target_nodes=None)

        mgr.disconnect_all()
        q = mgr.create_client("node-1", last_event_id="999")

        # No replay — queue should be empty
        assert q.empty()

    def test_replay_last_event_in_history(self):
        """If Last-Event-ID is the most recent event, no replay occurs."""
        mgr = ConfigSSEManager(history_size=100)

        mgr.publish_to_profile(1, {"version": 1}, target_nodes=None)
        mgr.publish_to_profile(1, {"version": 2}, target_nodes=None)

        mgr.disconnect_all()
        q = mgr.create_client("node-1", last_event_id="2")

        # No events to replay after the last one
        assert q.empty()

    def test_history_respects_max_size(self):
        """History ring buffer should not exceed the configured size."""
        mgr = ConfigSSEManager(history_size=3)

        for i in range(5):
            mgr.publish_to_profile(1, {"version": i + 1}, target_nodes=None)

        mgr.disconnect_all()

        # Events 1 and 2 should have been evicted; only 3, 4, 5 remain
        q = mgr.create_client("node-1", last_event_id="1")
        # Event ID "1" is no longer in history, so no replay
        assert q.empty()

        # But event ID "3" should still be in history
        mgr.remove_client("node-1")
        q = mgr.create_client("node-1", last_event_id="3")
        msg1 = q.get(timeout=1)
        msg2 = q.get(timeout=1)
        assert "id: 4\n" in msg1
        assert "id: 5\n" in msg2
        assert q.empty()

    def test_default_history_size_is_1000(self):
        """Default history size should be 1000."""
        mgr = ConfigSSEManager()
        assert mgr.history_size == 1000

    def test_replay_events_in_chronological_order(self):
        """Replayed events must be in chronological (publish) order."""
        mgr = ConfigSSEManager(history_size=100)

        for i in range(10):
            mgr.publish_to_profile(1, {"version": i + 1}, target_nodes=None)

        mgr.disconnect_all()
        q = mgr.create_client("node-1", last_event_id="4")

        # Should replay events 5 through 10
        for expected_id in range(5, 11):
            msg = q.get(timeout=1)
            assert f"id: {expected_id}\n" in msg


class TestConfigSubscribeGenerator:
    """Test the subscribe() generator with keepalive and sentinel handling."""

    def test_subscribe_receives_published_events(self):
        """subscribe() generator should yield published events."""
        mgr = ConfigSSEManager(history_size=10)
        messages = []

        def consumer():
            for msg in mgr.subscribe("node-1"):
                messages.append(msg)

        t = threading.Thread(target=consumer)
        t.start()
        time.sleep(0.05)

        mgr.publish_to_profile(
            1, {"version": 1}, target_nodes=["node-1"]
        )
        time.sleep(0.05)
        mgr.disconnect_node("node-1")
        t.join(timeout=2)

        assert len(messages) == 1
        assert "config_updated" in messages[0]

    def test_subscribe_with_last_event_id_replays(self):
        """subscribe() with last_event_id should replay then stream live."""
        mgr = ConfigSSEManager(history_size=100)

        # Publish some events (no clients connected, but history records them)
        # Need a dummy client to avoid dead client cleanup
        dummy = mgr.create_client("dummy")
        mgr.publish_to_profile(1, {"version": 1}, target_nodes=["dummy"])
        mgr.publish_to_profile(1, {"version": 2}, target_nodes=["dummy"])
        mgr.remove_client("dummy")

        messages = []

        def consumer():
            for msg in mgr.subscribe("node-1", last_event_id="1"):
                messages.append(msg)

        t = threading.Thread(target=consumer)
        t.start()
        time.sleep(0.05)

        # Should have replayed event 2, then receive live event 3
        mgr.publish_to_profile(1, {"version": 3}, target_nodes=["node-1"])
        time.sleep(0.05)
        mgr.disconnect_node("node-1")
        t.join(timeout=2)

        assert len(messages) == 2
        assert "id: 2\n" in messages[0]
        assert "id: 3\n" in messages[1]

    def test_subscribe_stops_on_sentinel(self):
        """subscribe() generator should stop when sentinel (None) is received."""
        mgr = ConfigSSEManager(history_size=10)
        messages = []

        def consumer():
            for msg in mgr.subscribe("node-1"):
                messages.append(msg)

        t = threading.Thread(target=consumer)
        t.start()
        time.sleep(0.05)

        mgr.disconnect_node("node-1")
        t.join(timeout=2)

        assert len(messages) == 0

    def test_subscribe_cleans_up_on_generator_close(self, monkeypatch):
        """Closing the subscribe generator should remove the client."""
        import app.config_sse as config_sse_module

        monkeypatch.setattr(config_sse_module, "_KEEPALIVE_INTERVAL", 0.05)

        mgr = ConfigSSEManager(history_size=10)

        gen = mgr.subscribe("node-1")
        # Advance the generator to trigger create_client (generators are lazy)
        # The first yield will be a keepalive after the short timeout
        msg = next(gen)
        assert msg == ": keepalive\n\n"
        assert mgr.client_count == 1

        gen.close()
        assert mgr.client_count == 0


class TestConfigSSEKeepalive:
    """Test keepalive comment generation on idle connections."""

    def test_keepalive_sent_on_idle(self, monkeypatch):
        """Keepalive comment should be sent after timeout on idle connection."""
        import app.config_sse as config_sse_module

        monkeypatch.setattr(config_sse_module, "_KEEPALIVE_INTERVAL", 0.1)

        mgr = ConfigSSEManager(history_size=10)
        messages = []

        def consumer():
            count = 0
            for msg in mgr.subscribe("node-1"):
                messages.append(msg)
                count += 1
                if count >= 2:
                    break

        t = threading.Thread(target=consumer)
        t.start()
        t.join(timeout=2)

        # Should have received keepalive comments
        assert len(messages) >= 2
        for msg in messages:
            assert msg == ": keepalive\n\n"

    def test_keepalive_format(self, monkeypatch):
        """Keepalive should be an SSE comment (colon-prefixed line)."""
        import app.config_sse as config_sse_module

        monkeypatch.setattr(config_sse_module, "_KEEPALIVE_INTERVAL", 0.05)

        mgr = ConfigSSEManager(history_size=10)
        gen = mgr.subscribe("node-1")
        msg = next(gen)
        gen.close()

        assert msg == ": keepalive\n\n"


class TestConfigSSEThreadSafety:
    """Test thread-safety of concurrent publish/subscribe operations."""

    def test_concurrent_publish_and_subscribe(self):
        """Multiple publishers and subscribers should work concurrently."""
        mgr = ConfigSSEManager(history_size=100)
        num_nodes = 3
        events_per_publisher = 10

        results = {f"node-{i}": [] for i in range(num_nodes)}

        def subscriber(node_id):
            for msg in mgr.subscribe(node_id):
                results[node_id].append(msg)

        def publisher():
            for i in range(events_per_publisher):
                mgr.publish_to_profile(
                    1, {"version": i}, target_nodes=None
                )
                time.sleep(0.01)

        # Start subscribers
        sub_threads = []
        for i in range(num_nodes):
            t = threading.Thread(target=subscriber, args=(f"node-{i}",))
            t.start()
            sub_threads.append(t)
        time.sleep(0.05)

        # Start publisher
        pub_thread = threading.Thread(target=publisher)
        pub_thread.start()
        pub_thread.join(timeout=5)

        # Give subscribers time to process, then disconnect
        time.sleep(0.1)
        mgr.disconnect_all()

        for t in sub_threads:
            t.join(timeout=2)

        # Each subscriber should have received all events
        for node_id in results:
            assert len(results[node_id]) == events_per_publisher
