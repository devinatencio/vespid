"""Property-based tests for Fleet-Wide Blocklist Sharing.

Uses Hypothesis to verify correctness properties across randomised inputs.
Each test is annotated with the property number and the requirements it validates.
"""

import threading

from hypothesis import given, settings, strategies as st, assume

from app.fleet_sse import FleetSSEManager


# ── Hypothesis strategies ────────────────────────────────────────────────


def st_fleet_block_id():
    """Strategy for generating unique fleet block IDs."""
    return st.uuids().map(lambda u: f"fb-{u}")


def st_fleet_event_data():
    """Strategy for generating fleet block event JSON payloads."""
    return st.fixed_dictionaries({
        "action": st.sampled_from(["block", "unblock"]),
        "source_ip": st.tuples(
            st.integers(min_value=1, max_value=254),
            st.integers(min_value=0, max_value=255),
            st.integers(min_value=0, max_value=255),
            st.integers(min_value=1, max_value=254),
        ).map(lambda t: f"{t[0]}.{t[1]}.{t[2]}.{t[3]}"),
        "reason": st.text(min_size=1, max_size=50),
        "ttl_seconds": st.integers(min_value=60, max_value=86400),
    }).map(
        lambda d: (
            f'{{"action":"{d["action"]}",'
            f'"source_ip":"{d["source_ip"]}",'
            f'"reason":"{d["reason"]}",'
            f'"ttl_seconds":{d["ttl_seconds"]}}}'
        )
    )


# ── Property 12: Fleet SSE reconnection replays missed events ────────────
# Feature: fleet-blocklist-sharing, Property 12: Fleet SSE reconnection replays missed events
# **Validates: Requirements 2.4, 2.6**


class TestFleetSSEReconnectionReplay:
    """Property 12: Fleet SSE reconnection replays missed events.

    For any sequence of fleet block events published to the Fleet SSE Channel
    and any valid Last-Event-ID from that sequence, a new subscriber connecting
    with that Last-Event-ID SHALL receive exactly the events published after
    that ID, in chronological order.
    """

    @given(
        event_data=st.lists(
            st.tuples(st_fleet_block_id(), st_fleet_event_data()),
            min_size=2,
            max_size=20,
            unique_by=lambda x: x[0],
        ),
        split_index=st.integers(min_value=0),
    )
    @settings(max_examples=100, deadline=None)
    def test_reconnection_replays_missed_events(self, event_data, split_index):
        """**Validates: Requirements 2.4, 2.6**

        Publish a sequence of fleet block events, pick a split point, then
        subscribe with the Last-Event-ID at the split point. The subscriber
        should receive exactly the events after the split point in order.
        """
        # Clamp split_index to valid range: [0, len-2] so there's at least
        # one event after the split point
        split_index = split_index % (len(event_data) - 1)

        mgr = FleetSSEManager(history_size=max(len(event_data) + 10, 50))

        # Publish all events (no subscribers yet — goes to history only)
        for fleet_block_id, data in event_data:
            mgr.publish(fleet_block_id, data)

        # The Last-Event-ID is the event at the split point
        last_event_id = event_data[split_index][0]

        # Expected: all events after the split point
        expected_ids = [eid for eid, _ in event_data[split_index + 1:]]

        # Subscribe with Last-Event-ID and collect replayed messages
        replayed = []

        def consumer():
            for msg in mgr.subscribe(last_event_id=last_event_id, timeout=0.3):
                replayed.append(msg)

        t = threading.Thread(target=consumer)
        t.start()
        t.join(timeout=3)

        # Extract event IDs from the replayed SSE messages
        replayed_ids = []
        for msg in replayed:
            for line in msg.split("\n"):
                if line.startswith("id: "):
                    replayed_ids.append(line[4:])

        # Should replay exactly the events after the split point, in order
        assert replayed_ids == expected_ids, (
            f"Expected replay of {len(expected_ids)} events after "
            f"Last-Event-ID={last_event_id}, got {len(replayed_ids)} events.\n"
            f"Expected IDs: {expected_ids}\n"
            f"Got IDs: {replayed_ids}"
        )
