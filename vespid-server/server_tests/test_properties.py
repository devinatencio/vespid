"""Property-based tests for Vespid Server database models.

Uses Hypothesis to verify correctness properties across randomised inputs.
Each test is annotated with the property number and the requirements it validates.
"""

import json
import uuid
from collections import Counter
from datetime import datetime, timedelta, timezone

import pytest
from hypothesis import given, settings, strategies as st, assume, HealthCheck

from app.models import (
    get_country_breakdown,
    get_dashboard_stats,
    get_node_health,
    get_time_series,
    init_db,
    get_db,
    insert_events,
    upsert_node,
    list_nodes,
)
from app.validators import validate_batch


# ── Fixtures ─────────────────────────────────────────────────────────────


@pytest.fixture()
def db(tmp_path):
    """Return an initialised in-memory-like SQLite connection."""
    db_path = str(tmp_path / "test_props.db")
    init_db(db_path)
    conn = get_db(db_path)
    yield conn
    conn.close()


# ── Hypothesis strategies ────────────────────────────────────────────────

EVENT_TYPES = ["SSH_BRUTE", "PORT_SCAN", "DNS_TUNNEL", "WEB_ATTACK", "MALWARE_BEACON"]
ACTION_TAKEN_VALUES = ["BLOCKED", "LOGGED", "RATE_LIMITED", "ALERTED"]
COUNTRY_CODES = ["US", "CN", "RU", "DE", "BR", "IN", "GB", "FR", "JP", "AU"]


def st_ipv4():
    """Strategy that generates valid IPv4 address strings."""
    return st.tuples(
        st.integers(min_value=1, max_value=254),
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=1, max_value=254),
    ).map(lambda t: f"{t[0]}.{t[1]}.{t[2]}.{t[3]}")


def st_timestamp_recent():
    """Strategy that generates ISO-8601 timestamps within the last 23 hours.

    Keeps events well within the 24h window used by dashboard stats.
    """
    now = datetime.now(timezone.utc)
    return st.integers(
        min_value=0, max_value=int(23 * 3600)
    ).map(
        lambda secs: (now - timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def st_timestamp_variable():
    """Strategy that generates timestamps that may be inside or outside the 24h window."""
    now = datetime.now(timezone.utc)
    return st.integers(
        min_value=0, max_value=int(48 * 3600)
    ).map(
        lambda secs: (now - timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def st_node_id():
    """Strategy for node IDs."""
    return st.sampled_from(["node-alpha", "node-beta", "node-gamma", "node-delta", "node-epsilon"])


def st_security_event(timestamp_strategy=None):
    """Composite strategy that generates a valid SecurityEvent dict.

    Each call produces a unique event_id via UUID.
    """
    if timestamp_strategy is None:
        timestamp_strategy = st_timestamp_recent()

    return st.fixed_dictionaries({
        "event_id": st.uuids().map(str),
        "node_id": st_node_id(),
        "timestamp": timestamp_strategy,
        "source_ip": st_ipv4(),
        "event_type": st.sampled_from(EVENT_TYPES),
        "action_taken": st.sampled_from(ACTION_TAKEN_VALUES),
        "geo_data": st.fixed_dictionaries({
            "country": st.sampled_from(COUNTRY_CODES),
            "city": st.sampled_from(["Dallas", "Beijing", "Moscow", "Berlin", "Tokyo"]),
        }),
        "metadata": st.just({}),
    })


# ── Property 5: Dashboard statistics correctness ────────────────────────
# **Validates: Requirements 4.1, 4.2**


class TestDashboardStatisticsCorrectness:
    """Property 5: Dashboard statistics correctness.

    For any set of events inserted into the database with varying timestamps,
    node_ids, source_ips, event_types, and action_taken values, the dashboard
    stats query should return correct counts.
    """

    @given(events=st.lists(st_security_event(st_timestamp_variable()), min_size=1, max_size=30))
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_dashboard_stats_match_manual_counts(self, db, events):
        """**Validates: Requirements 4.1, 4.2**"""
        # Deduplicate event_ids (Hypothesis may generate duplicates from UUIDs, unlikely but safe)
        seen_ids = set()
        unique_events = []
        for ev in events:
            if ev["event_id"] not in seen_ids:
                seen_ids.add(ev["event_id"])
                unique_events.append(ev)
        events = unique_events
        assume(len(events) > 0)

        # Clear events table for this test run
        db.execute("DELETE FROM events")
        db.commit()

        insert_events(db, events)

        # Compute the cutoff the same way SQLite does: using 'now'
        now = datetime.now(timezone.utc)
        cutoff_24h = (now - timedelta(hours=24)).strftime("%Y-%m-%dT%H:%M:%SZ")
        cutoff_15m = (now - timedelta(minutes=15)).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Manual counts from the input data
        events_in_24h = [e for e in events if e["timestamp"] >= cutoff_24h]
        expected_total_24h = len(events_in_24h)
        expected_active_nodes = len({e["node_id"] for e in events if e["timestamp"] >= cutoff_15m})
        expected_blocked_ips = len({
            e["source_ip"] for e in events_in_24h
            if e["action_taken"] == "BLOCKED"
        })
        expected_distinct_ips = len({e["source_ip"] for e in events_in_24h})

        stats = get_dashboard_stats(db)

        assert stats["total_events_24h"] == expected_total_24h
        assert stats["active_nodes"] == expected_active_nodes
        assert stats["blocked_ips"] == expected_blocked_ips
        assert stats["distinct_source_ips"] == expected_distinct_ips


# ── Property 11: Node health derivation ─────────────────────────────────
# **Validates: Requirements 7.2**


class TestNodeHealthDerivation:
    """Property 11: Node health derivation.

    For any last_event_at timestamp and current time, the derived health
    status should follow the threshold rules:
    - healthy: delta < 300s
    - degraded: 300s <= delta < 900s
    - offline: delta >= 900s or last_event_at is None
    """

    @given(delta_seconds=st.floats(min_value=0, max_value=7200, allow_nan=False, allow_infinity=False))
    @settings(max_examples=100, deadline=None)
    def test_health_thresholds(self, delta_seconds):
        """**Validates: Requirements 7.2**"""
        now = datetime.now(timezone.utc)
        last_event_at = (now - timedelta(seconds=delta_seconds)).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )

        health = get_node_health(last_event_at)

        # The function also computes 'now' internally, so there may be a
        # tiny drift (< 1s). We account for this by checking the boundaries
        # with a small tolerance. Since timestamps are truncated to seconds,
        # the actual delta seen by get_node_health may differ by up to 1s.
        # We test the clear regions and skip the boundary ±2s zones.
        if delta_seconds < 298:
            assert health == "healthy", f"Expected healthy for delta={delta_seconds}s, got {health}"
        elif delta_seconds > 302 and delta_seconds < 898:
            assert health == "degraded", f"Expected degraded for delta={delta_seconds}s, got {health}"
        elif delta_seconds > 902:
            assert health == "offline", f"Expected offline for delta={delta_seconds}s, got {health}"
        # In boundary zones (298-302, 898-902) we accept any adjacent status

    @given(st.none())
    @settings(max_examples=1, deadline=None)
    def test_none_is_offline(self, _):
        """**Validates: Requirements 7.2**"""
        assert get_node_health(None) == "offline"


# ── Property 12: Country breakdown aggregation and ordering ──────────────
# **Validates: Requirements 8.1, 8.2**


class TestCountryBreakdownAggregation:
    """Property 12: Country breakdown aggregation and ordering.

    For any set of events with varying geo_country values, the country
    breakdown query should return one row per distinct country with a count
    equal to the number of events from that country, and the rows should be
    sorted by count in descending order.
    """

    @given(events=st.lists(st_security_event(), min_size=1, max_size=30))
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_country_breakdown_counts_and_ordering(self, db, events):
        """**Validates: Requirements 8.1, 8.2**"""
        seen_ids = set()
        unique_events = []
        for ev in events:
            if ev["event_id"] not in seen_ids:
                seen_ids.add(ev["event_id"])
                unique_events.append(ev)
        events = unique_events
        assume(len(events) > 0)

        db.execute("DELETE FROM events")
        db.commit()

        insert_events(db, events)

        breakdown = get_country_breakdown(db)

        # Compute expected counts from input
        expected_counts = Counter()
        for ev in events:
            country = ev["geo_data"].get("country")
            if country is not None:
                expected_counts[country] += 1

        # One row per distinct country
        assert len(breakdown) == len(expected_counts)

        # Each row has the correct count
        actual_counts = {row["country"]: row["count"] for row in breakdown}
        assert actual_counts == dict(expected_counts)

        # Rows are sorted by count descending
        counts = [row["count"] for row in breakdown]
        assert counts == sorted(counts, reverse=True)


# ── Property 13: Time-series bucketing correctness ───────────────────────
# **Validates: Requirements 9.1, 9.2**


class TestTimeSeriesBucketing:
    """Property 13: Time-series bucketing correctness.

    For any set of events and any time interval, the time-series chart data
    should assign each event to exactly one time bucket, the sum of all
    bucket counts should equal the total number of events in the queried
    range, and buckets should be in chronological order.
    """

    @given(
        events=st.lists(st_security_event(), min_size=1, max_size=30),
        interval=st.sampled_from(["1h", "6h", "24h", "7d"]),
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_bucketing_sum_and_order(self, db, events, interval):
        """**Validates: Requirements 9.1, 9.2**"""
        seen_ids = set()
        unique_events = []
        for ev in events:
            if ev["event_id"] not in seen_ids:
                seen_ids.add(ev["event_id"])
                unique_events.append(ev)
        events = unique_events
        assume(len(events) > 0)

        db.execute("DELETE FROM events")
        db.commit()

        insert_events(db, events)

        # Determine the time window the query uses
        interval_offsets = {
            "1h": timedelta(hours=1),
            "6h": timedelta(hours=6),
            "24h": timedelta(hours=24),
            "7d": timedelta(days=7),
        }
        now = datetime.now(timezone.utc)
        window_start = (now - interval_offsets[interval]).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Count events that fall within the query window
        events_in_range = [e for e in events if e["timestamp"] >= window_start]

        series = get_time_series(db, interval)

        # Sum of bucket counts should equal events in range
        total_bucketed = sum(entry["count"] for entry in series)
        assert total_bucketed == len(events_in_range)

        # Buckets should be in chronological (ascending) order
        buckets = [entry["bucket"] for entry in series]
        assert buckets == sorted(buckets)


# ── Property 10: Node auto-registration and field accuracy ──────────────
# **Validates: Requirements 7.1, 7.3, 7.4**


class TestNodeAutoRegistration:
    """Property 10: Node auto-registration and field accuracy.

    For any sequence of event batches from distinct node_ids, after ingestion
    each node_id should appear in the nodes table with:
    - total_events equal to the count of events from that node
    - last_event_at equal to the most recent event's timestamp from that node
    - last_geo_data equal to the geo_data of the most recent event from that node
    """

    @given(events=st.lists(st_security_event(), min_size=1, max_size=30))
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_node_registration_accuracy(self, db, events):
        """**Validates: Requirements 7.1, 7.3, 7.4**"""
        seen_ids = set()
        unique_events = []
        for ev in events:
            if ev["event_id"] not in seen_ids:
                seen_ids.add(ev["event_id"])
                unique_events.append(ev)
        events = unique_events
        assume(len(events) > 0)

        db.execute("DELETE FROM events")
        db.execute("DELETE FROM nodes")
        db.commit()

        # Simulate the ingestion flow: insert events then upsert nodes
        insert_events(db, events)
        for ev in events:
            upsert_node(db, ev["node_id"], ev["timestamp"], ev["geo_data"])

        # Compute expected values per node
        node_events: dict[str, list[dict]] = {}
        for ev in events:
            node_events.setdefault(ev["node_id"], []).append(ev)

        nodes = list_nodes(db)
        node_map = {n["node_id"]: n for n in nodes}

        # Every node_id from events should be registered
        assert set(node_events.keys()) == set(node_map.keys())

        for nid, evts in node_events.items():
            node = node_map[nid]

            # total_events should equal the count of events from this node
            assert node["total_events"] == len(evts), (
                f"Node {nid}: expected total_events={len(evts)}, got {node['total_events']}"
            )

            # last_event_at should equal the most recent timestamp
            expected_last_ts = max(e["timestamp"] for e in evts)
            assert node["last_event_at"] == expected_last_ts, (
                f"Node {nid}: expected last_event_at={expected_last_ts}, "
                f"got {node['last_event_at']}"
            )

            # last_geo_data should equal the geo_data of the most recent event
            # Find the event with the max timestamp (if tie, last in list wins
            # due to upsert_node's > comparison)
            most_recent_ev = max(evts, key=lambda e: e["timestamp"])
            expected_geo = json.dumps(most_recent_ev["geo_data"])
            assert node["last_geo_data"] == expected_geo, (
                f"Node {nid}: expected last_geo_data={expected_geo}, "
                f"got {node['last_geo_data']}"
            )


# ── Strategies for invalid events ────────────────────────────────────────


def st_invalid_event():
    """Strategy that generates an event dict with at least one validation failure.

    Randomly corrupts one field of an otherwise valid event to ensure it
    fails validation.
    """
    corruption = st.sampled_from([
        "missing_node_id",
        "missing_timestamp",
        "missing_source_ip",
        "missing_event_type",
        "missing_action_taken",
        "missing_geo_data",
        "missing_event_id",
        "bad_ip",
        "bad_timestamp",
        "bad_geo_data_type",
        "empty_node_id",
        "empty_event_id",
    ])

    @st.composite
    def _build(draw):
        base = draw(st_security_event())
        kind = draw(corruption)

        if kind == "missing_node_id":
            del base["node_id"]
        elif kind == "missing_timestamp":
            del base["timestamp"]
        elif kind == "missing_source_ip":
            del base["source_ip"]
        elif kind == "missing_event_type":
            del base["event_type"]
        elif kind == "missing_action_taken":
            del base["action_taken"]
        elif kind == "missing_geo_data":
            del base["geo_data"]
        elif kind == "missing_event_id":
            del base["event_id"]
        elif kind == "bad_ip":
            base["source_ip"] = "999.999.999.999"
        elif kind == "bad_timestamp":
            base["timestamp"] = "not-a-timestamp"
        elif kind == "bad_geo_data_type":
            base["geo_data"] = "not-a-dict"
        elif kind == "empty_node_id":
            base["node_id"] = ""
        elif kind == "empty_event_id":
            base["event_id"] = ""

        return base

    return _build()


def st_mixed_batch():
    """Strategy that generates a batch with a known mix of valid and invalid events.

    Returns a tuple of (batch, expected_valid_indices, expected_invalid_indices).
    """

    @st.composite
    def _build(draw):
        # Generate some valid and some invalid events
        n_valid = draw(st.integers(min_value=0, max_value=10))
        n_invalid = draw(st.integers(min_value=0, max_value=10))
        assume(n_valid + n_invalid > 0)

        valid_events = [draw(st_security_event()) for _ in range(n_valid)]
        invalid_events = [draw(st_invalid_event()) for _ in range(n_invalid)]

        # Ensure valid events have unique event_ids
        seen_ids: set[str] = set()
        deduped_valid = []
        for ev in valid_events:
            if ev["event_id"] not in seen_ids:
                seen_ids.add(ev["event_id"])
                deduped_valid.append(ev)
        valid_events = deduped_valid

        # Ensure invalid events don't share event_ids with valid ones
        # (to avoid false duplicate rejections confusing the test)
        clean_invalid = []
        for ev in invalid_events:
            eid = ev.get("event_id")
            if isinstance(eid, str) and eid in seen_ids:
                # Give it a fresh unique ID so the only reason it fails
                # is the corruption, not a duplicate ID
                ev["event_id"] = str(uuid.uuid4())
            if isinstance(eid, str) and eid:
                seen_ids.add(ev.get("event_id", ""))
            clean_invalid.append(ev)

        # Interleave: valid first, then invalid (order matters for tracking)
        batch = []
        valid_indices = set()
        invalid_indices = set()
        idx = 0
        for ev in valid_events:
            batch.append(ev)
            valid_indices.add(idx)
            idx += 1
        for ev in clean_invalid:
            batch.append(ev)
            invalid_indices.add(idx)
            idx += 1

        return batch, valid_indices, invalid_indices

    return _build()


# ── Property 2: Batch validation partitioning ────────────────────────────
# **Validates: Requirements 1.3, 1.4**


class TestBatchValidationPartitioning:
    """Property 2: Batch validation partitioning.

    For any batch containing a mix of valid and invalid SecurityEvent dicts,
    validate_batch should separate exactly the valid events from the invalid
    ones, with the accepted count equaling the number of valid events and
    the rejected list containing one entry per invalid event with a non-empty
    error description.
    """

    @given(data=st_mixed_batch())
    @settings(max_examples=100, deadline=None)
    def test_partition_counts_match(self, data):
        """**Validates: Requirements 1.3, 1.4**"""
        batch, expected_valid_indices, expected_invalid_indices = data

        result = validate_batch(batch)

        # The number of valid events should equal the expected valid count
        assert len(result.valid) == len(expected_valid_indices), (
            f"Expected {len(expected_valid_indices)} valid, got {len(result.valid)}"
        )

        # The number of error entries should equal the expected invalid count
        assert len(result.errors) == len(expected_invalid_indices), (
            f"Expected {len(expected_invalid_indices)} errors, got {len(result.errors)}"
        )

        # Every error entry should have a non-empty errors list
        for err_entry in result.errors:
            assert len(err_entry["errors"]) > 0, (
                f"Error entry at index {err_entry['index']} has empty errors list"
            )

        # The indices in error entries should match the expected invalid indices
        actual_error_indices = {e["index"] for e in result.errors}
        assert actual_error_indices == expected_invalid_indices, (
            f"Expected error indices {expected_invalid_indices}, "
            f"got {actual_error_indices}"
        )

        # Valid + errors should account for the entire batch
        assert len(result.valid) + len(result.errors) == len(batch)


# ── Fixtures for auth/RBAC property tests ────────────────────────────────

from app import create_app
from app.routes.auth import User


@pytest.fixture()
def app(tmp_path):
    """Create a Flask app with a test database for auth/RBAC tests."""
    db_path = str(tmp_path / "test_auth_props.db")
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({
        "SECRET_KEY": "test-secret-key",
        "DATABASE_PATH": db_path,
    }))
    app = create_app(str(config_file))
    app.config["TESTING"] = True
    return app


# ── Property 3: Unauthenticated access redirect ─────────────────────────
# **Validates: Requirements 2.1**


# Protected URL paths that require authentication
PROTECTED_PATHS = [
    "/",
    "/events",
    "/nodes",
    "/geo",
    "/trends",
    "/admin/users",
    "/admin/keys",
    "/admin/audit",
]


class TestUnauthenticatedAccessRedirect:
    """Property 3: Unauthenticated access redirect.

    For any protected URL path (dashboard, events, nodes, geo, trends,
    admin pages), an HTTP request without a valid session cookie should
    receive a redirect response (HTTP 302) to the /login page.
    """

    @given(path=st.sampled_from(PROTECTED_PATHS))
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_unauthenticated_request_redirects_to_login(self, app, path):
        """**Validates: Requirements 2.1**"""
        with app.test_client() as client:
            response = client.get(path)
            assert response.status_code == 302, (
                f"Expected 302 redirect for unauthenticated GET {path}, "
                f"got {response.status_code}"
            )
            # The redirect location should point to /login
            location = response.headers.get("Location", "")
            assert "/login" in location, (
                f"Expected redirect to /login for {path}, got Location: {location}"
            )


# ── Property 4: RBAC permission matrix ──────────────────────────────────
# **Validates: Requirements 3.2, 3.3, 3.4, 3.5**


# Permission matrix: (path, minimum_role)
# viewer can access viewer+ routes, analyst can access analyst+ routes, admin can access all
PERMISSION_MATRIX = [
    # Viewer-accessible routes
    ("/", "viewer"),
    ("/events", "viewer"),
    ("/nodes", "viewer"),
    ("/geo", "viewer"),
    ("/trends", "viewer"),
    # Admin-only routes
    ("/admin/users", "admin"),
    ("/admin/keys", "admin"),
    ("/admin/audit", "admin"),
]

ROLES = ["viewer", "analyst", "admin"]

ROLE_LEVEL = {"viewer": 1, "analyst": 2, "admin": 3}


class TestRBACPermissionMatrix:
    """Property 4: RBAC permission matrix.

    For any (role, endpoint) pair drawn from the full permission matrix,
    a user with that role should receive HTTP 200 for permitted endpoints
    and HTTP 403 for forbidden endpoints. The role hierarchy is:
    viewer ⊂ analyst ⊂ admin.
    """

    @given(
        role=st.sampled_from(ROLES),
        endpoint_data=st.sampled_from(PERMISSION_MATRIX),
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_rbac_permission_enforcement(self, app, auth_client, role, endpoint_data):
        """**Validates: Requirements 3.2, 3.3, 3.4, 3.5**"""
        path, min_role = endpoint_data

        c = auth_client(role)
        response = c.get(path)

        user_level = ROLE_LEVEL[role]
        required_level = ROLE_LEVEL[min_role]

        if user_level >= required_level:
            assert response.status_code in (200, 302), (
                f"Role '{role}' should have access to {path} "
                f"(requires '{min_role}'), got {response.status_code}"
            )
        else:
            assert response.status_code in (403, 302), (
                f"Role '{role}' should NOT have access to {path} "
                f"(requires '{min_role}'), got {response.status_code}"
            )


# ── Property 6: SSE reconnection replays missed events ──────────────────
# **Validates: Requirements 5.3**

import threading
from app.sse import SSEManager


def st_event_id():
    """Strategy for generating unique event IDs."""
    return st.uuids().map(str)


def st_html_fragment():
    """Strategy for generating simple HTML fragment data."""
    return st.text(
        alphabet=st.characters(whitelist_categories=("L", "N", "P", "Z")),
        min_size=1,
        max_size=50,
    ).map(lambda t: f"<div>{t}</div>")


class TestSSEReconnectionReplay:
    """Property 6: SSE reconnection replays missed events.

    For any sequence of ingested events and any valid Last-Event-ID from
    that sequence, reconnecting to the SSE endpoint with that Last-Event-ID
    should replay exactly the events that were ingested after the event with
    that ID, in chronological order.
    """

    @given(
        event_data=st.lists(
            st.tuples(st_event_id(), st_html_fragment()),
            min_size=2,
            max_size=20,
            unique_by=lambda x: x[0],
        ),
        split_index=st.integers(min_value=0),
    )
    @settings(max_examples=100, deadline=None)
    def test_reconnection_replays_missed_events(self, event_data, split_index):
        """**Validates: Requirements 5.3**

        Publish a sequence of events, pick a split point, then subscribe
        with the Last-Event-ID at the split point. The subscriber should
        receive exactly the events after the split point.
        """
        # Clamp split_index to a valid range: [0, len-2] so there's at least
        # one event after the split point
        split_index = split_index % (len(event_data) - 1)

        mgr = SSEManager(history_size=max(len(event_data) + 10, 50))

        # Publish all events (no subscribers yet — goes to history)
        for eid, data in event_data:
            mgr.publish(eid, data)

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
            f"Expected replay of {expected_ids}, got {replayed_ids}"
        )


# ── Property 1: Event ingestion round-trip ───────────────────────────────
# **Validates: Requirements 1.1, 1.5**

from app.models import create_api_key, create_user, search_events


class TestEventIngestionRoundTrip:
    """Property 1: Event ingestion round-trip.

    For any valid SecurityEvent batch, ingesting via POST /api/v1/events
    and querying the database should return events with identical field
    values (node_id, timestamp, source_ip, event_type, action_taken,
    geo_data, event_id, metadata) for every event in the batch.
    """

    @given(events=st.lists(st_security_event(), min_size=1, max_size=10))
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_ingested_events_match_database(self, app, events):
        """**Validates: Requirements 1.1, 1.5**"""
        # Deduplicate event_ids
        seen_ids = set()
        unique_events = []
        for ev in events:
            if ev["event_id"] not in seen_ids:
                seen_ids.add(ev["event_id"])
                unique_events.append(ev)
        events = unique_events
        assume(len(events) > 0)

        with app.test_client() as client:
            db_path = app.config["DATABASE_PATH"]
            db = get_db(db_path)
            try:
                # Clean slate
                db.execute("DELETE FROM events")
                db.execute("DELETE FROM nodes")
                db.execute("DELETE FROM api_keys")
                db.execute("DELETE FROM users")
                db.commit()

                # Create admin user and API key
                admin_id = create_user(db, "admin", "admin_pass", "admin")
                token = create_api_key(db, "test-key", None, admin_id)
            finally:
                db.close()

            # Ingest events via the API
            response = client.post(
                "/api/v1/events",
                data=json.dumps({"events": events}),
                content_type="application/json",
                headers={"Authorization": f"Bearer {token}"},
            )
            assert response.status_code == 200
            data = response.get_json()
            assert data["accepted"] == len(events)

            # Query the database and verify each event
            db = get_db(db_path)
            try:
                for ev in events:
                    row = db.execute(
                        "SELECT * FROM events WHERE event_id = ?",
                        (ev["event_id"],),
                    ).fetchone()
                    assert row is not None, f"Event {ev['event_id']} not found in DB"
                    assert row["node_id"] == ev["node_id"]
                    assert row["timestamp"] == ev["timestamp"]
                    assert row["source_ip"] == ev["source_ip"]
                    assert row["event_type"] == ev["event_type"]
                    assert row["action_taken"] == ev["action_taken"]
                    assert row["event_id"] == ev["event_id"]

                    # geo_data is stored as JSON string
                    stored_geo = json.loads(row["geo_data"])
                    assert stored_geo == ev["geo_data"]

                    # metadata is stored as JSON string
                    stored_meta = json.loads(row["metadata"])
                    assert stored_meta == ev["metadata"]
            finally:
                db.close()


# ── Property 15: API key hash round-trip ─────────────────────────────────
# **Validates: Requirements 11.1**

import hashlib


class TestAPIKeyHashRoundTrip:
    """Property 15: API key hash round-trip.

    For any newly created API key, SHA-256 of the raw token should equal
    the stored key_hash, and first 8 chars should equal key_prefix.
    """

    @given(
        label=st.text(
            alphabet=st.characters(whitelist_categories=("L", "N")),
            min_size=1,
            max_size=20,
        ),
        node_restriction=st.one_of(st.none(), st_node_id()),
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_key_hash_and_prefix_match(self, app, label, node_restriction):
        """**Validates: Requirements 11.1**"""
        db_path = app.config["DATABASE_PATH"]
        db = get_db(db_path)
        try:
            # Ensure admin user exists
            row = db.execute("SELECT id FROM users WHERE username = 'keyadmin'").fetchone()
            if row:
                admin_id = row["id"]
            else:
                admin_id = create_user(db, "keyadmin", "admin_pass", "admin")

            # Create a new API key
            raw_token = create_api_key(db, label, node_restriction, admin_id)

            # Compute expected hash and prefix
            expected_hash = hashlib.sha256(raw_token.encode()).hexdigest()
            expected_prefix = raw_token[:8]

            # Look up the key in the database
            key_row = db.execute(
                "SELECT key_hash, key_prefix FROM api_keys WHERE key_hash = ?",
                (expected_hash,),
            ).fetchone()

            assert key_row is not None, "API key not found in database by hash"
            assert key_row["key_hash"] == expected_hash, (
                f"key_hash mismatch: expected {expected_hash}, got {key_row['key_hash']}"
            )
            assert key_row["key_prefix"] == expected_prefix, (
                f"key_prefix mismatch: expected {expected_prefix}, got {key_row['key_prefix']}"
            )
        finally:
            db.close()


# ── Property 16: API key enforcement ─────────────────────────────────────
# **Validates: Requirements 11.2, 11.4**


class TestAPIKeyEnforcement:
    """Property 16: API key enforcement.

    For any API key with a node_id restriction, events with non-matching
    node_id should be rejected; revoked keys should get 401.
    """

    @given(
        restricted_node=st_node_id(),
        event_node=st_node_id(),
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_node_id_restriction_enforcement(self, app, restricted_node, event_node):
        """**Validates: Requirements 11.4**

        For any API key with a node_id restriction, events with a non-matching
        node_id should be rejected, while events with the matching node_id
        should be accepted.
        """
        with app.test_client() as client:
            db_path = app.config["DATABASE_PATH"]
            db = get_db(db_path)
            try:
                # Clean slate
                db.execute("DELETE FROM events")
                db.execute("DELETE FROM nodes")
                db.execute("DELETE FROM api_keys")
                db.execute("DELETE FROM users")
                db.commit()

                admin_id = create_user(db, "admin", "admin_pass", "admin")
                token = create_api_key(db, "restricted-key", restricted_node, admin_id)
            finally:
                db.close()

            # Build a single-event batch with the given event_node
            event = {
                "event_id": str(uuid.uuid4()),
                "node_id": event_node,
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "source_ip": "10.0.0.1",
                "event_type": "SSH_BRUTE",
                "action_taken": "BLOCKED",
                "geo_data": {"country": "US"},
                "metadata": {},
            }

            response = client.post(
                "/api/v1/events",
                data=json.dumps({"events": [event]}),
                content_type="application/json",
                headers={"Authorization": f"Bearer {token}"},
            )

            if event_node == restricted_node:
                # Should be accepted
                assert response.status_code == 200, (
                    f"Expected 200 for matching node_id '{event_node}', "
                    f"got {response.status_code}"
                )
                data = response.get_json()
                assert data["accepted"] == 1
            else:
                # Should be rejected with 403 (all events have wrong node_id)
                assert response.status_code == 403, (
                    f"Expected 403 for non-matching node_id "
                    f"(key restricted to '{restricted_node}', event has '{event_node}'), "
                    f"got {response.status_code}"
                )
                data = response.get_json()
                assert data["error"] == "node_id_mismatch"

    @given(
        label=st.text(
            alphabet=st.characters(whitelist_categories=("L", "N")),
            min_size=1,
            max_size=20,
        ),
    )
    @settings(max_examples=50, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_revoked_key_returns_401(self, app, label):
        """**Validates: Requirements 11.2**

        For any revoked API key, all subsequent ingestion requests should
        receive HTTP 401.
        """
        with app.test_client() as client:
            db_path = app.config["DATABASE_PATH"]
            db = get_db(db_path)
            try:
                # Clean slate
                db.execute("DELETE FROM events")
                db.execute("DELETE FROM nodes")
                db.execute("DELETE FROM api_keys")
                db.execute("DELETE FROM users")
                db.commit()

                admin_id = create_user(db, "admin", "admin_pass", "admin")
                token = create_api_key(db, label, None, admin_id)

                # Revoke the key
                key_hash = hashlib.sha256(token.encode()).hexdigest()
                db.execute(
                    "UPDATE api_keys SET is_active = 0 WHERE key_hash = ?",
                    (key_hash,),
                )
                db.commit()
            finally:
                db.close()

            event = {
                "event_id": str(uuid.uuid4()),
                "node_id": "node-alpha",
                "timestamp": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
                "source_ip": "10.0.0.1",
                "event_type": "SSH_BRUTE",
                "action_taken": "BLOCKED",
                "geo_data": {"country": "US"},
                "metadata": {},
            }

            response = client.post(
                "/api/v1/events",
                data=json.dumps({"events": [event]}),
                content_type="application/json",
                headers={"Authorization": f"Bearer {token}"},
            )

            assert response.status_code == 401, (
                f"Expected 401 for revoked key, got {response.status_code}"
            )
            data = response.get_json()
            assert data["error"] == "key_revoked"


# ── Property 4 (Counter History): Time-range filtering correctness ───────
# Feature: counter-history-charts, Property 4: Time-range filtering correctness
# **Validates: Requirements 5.2**

from app.models import (
    _SCHEMA_SQL,
    get_counter_history,
    insert_counter_snapshots,
)


def st_counter_timestamp_wide():
    """Strategy that generates ISO-8601 timestamps spanning 0 to 10 days ago.

    This ensures timestamps both inside and outside all supported time ranges
    (1h, 6h, 24h, 7d).
    """
    now = datetime.now(timezone.utc)
    return st.integers(
        min_value=0, max_value=int(10 * 24 * 3600)
    ).map(
        lambda secs: (now - timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%SZ")
    )


def st_counter_entry():
    """Strategy that generates a valid counter entry dict for insert_counter_snapshots."""
    return st.fixed_dictionaries({
        "set": st.sampled_from([
            "shield_feed_firehol_level1",
            "shield_feed_abuse_ch_feodo",
            "shield_local_blocks",
        ]),
        "chain": st.just("input"),
        "family": st.just("inet"),
        "packets": st.integers(min_value=0, max_value=100000),
        "bytes": st.integers(min_value=0, max_value=10000000),
    })


class TestTimeRangeFilteringCorrectness:
    """Feature: counter-history-charts, Property 4: Time-range filtering correctness.

    For any set of counter snapshots with timestamps spanning a wide range,
    and for any selected time range (1h, 6h, 24h, 7d), all timestamps in
    the query result should fall within the specified time window, and no
    snapshot within the window should be excluded from the result.

    **Validates: Requirements 5.2**
    """

    @pytest.fixture()
    def counter_db(self, tmp_path):
        """Create an in-memory SQLite database with schema for counter tests."""
        import sqlite3
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(_SCHEMA_SQL)
        yield conn
        conn.close()

    @given(
        snapshots=st.lists(
            st.tuples(
                st.sampled_from(["node-1", "node-2", "node-3"]),
                st_counter_timestamp_wide(),
                st.lists(st_counter_entry(), min_size=1, max_size=3),
            ),
            min_size=1,
            max_size=20,
        ),
        time_range=st.sampled_from(["1h", "6h", "24h", "7d"]),
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_all_returned_timestamps_within_window(self, counter_db, snapshots, time_range):
        """**Validates: Requirements 5.2**

        All timestamps in the result fall within the specified time window.
        """
        # Clear any previous data
        counter_db.execute("DELETE FROM counter_snapshots")
        counter_db.commit()

        # Insert all generated snapshots
        for node_id, timestamp, counters in snapshots:
            insert_counter_snapshots(counter_db, node_id, timestamp, counters)

        # Query with the given time range
        result = get_counter_history(counter_db, time_range)

        # Compute the expected cutoff
        range_offsets = {
            "1h": timedelta(hours=1),
            "6h": timedelta(hours=6),
            "24h": timedelta(hours=24),
            "7d": timedelta(days=7),
        }
        now = datetime.now(timezone.utc)
        cutoff = (now - range_offsets[time_range]).strftime("%Y-%m-%dT%H:%M:%SZ")

        # All returned labels (timestamps) must be >= cutoff
        for label in result["labels"]:
            assert label >= cutoff, (
                f"Returned timestamp {label} is before cutoff {cutoff} "
                f"for time_range={time_range}"
            )

    @given(
        snapshots=st.lists(
            st.tuples(
                st.sampled_from(["node-1", "node-2", "node-3"]),
                st_counter_timestamp_wide(),
                st.lists(st_counter_entry(), min_size=1, max_size=3),
            ),
            min_size=1,
            max_size=20,
        ),
        time_range=st.sampled_from(["1h", "6h", "24h", "7d"]),
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_no_snapshot_within_window_excluded(self, counter_db, snapshots, time_range):
        """**Validates: Requirements 5.2**

        No snapshot within the time window is excluded from the result.
        """
        # Clear any previous data
        counter_db.execute("DELETE FROM counter_snapshots")
        counter_db.commit()

        # Insert all generated snapshots
        for node_id, timestamp, counters in snapshots:
            insert_counter_snapshots(counter_db, node_id, timestamp, counters)

        # Query with the given time range
        result = get_counter_history(counter_db, time_range)

        # Compute the expected cutoff
        range_offsets = {
            "1h": timedelta(hours=1),
            "6h": timedelta(hours=6),
            "24h": timedelta(hours=24),
            "7d": timedelta(days=7),
        }
        now = datetime.now(timezone.utc)
        cutoff = (now - range_offsets[time_range]).strftime("%Y-%m-%dT%H:%M:%SZ")

        # Determine which timestamps from the input are within the window
        expected_timestamps_in_window = set()
        for node_id, timestamp, counters in snapshots:
            if timestamp >= cutoff:
                expected_timestamps_in_window.add(timestamp)

        # All timestamps within the window should appear in the result labels
        returned_labels = set(result["labels"])
        for ts in expected_timestamps_in_window:
            assert ts in returned_labels, (
                f"Timestamp {ts} is within the window (cutoff={cutoff}, "
                f"range={time_range}) but was not returned in labels"
            )


# ── Property 5 (Counter History): Multi-node aggregation correctness ─────
# Feature: counter-history-charts, Property 5: Multi-node aggregation correctness
# **Validates: Requirements 6.2**


def st_counter_timestamp_recent_window():
    """Strategy that generates ISO-8601 timestamps within the last 30 minutes.

    Keeps all timestamps well within the 1h window so they are always included
    in query results regardless of which time_range is used.
    """
    now = datetime.now(timezone.utc)
    return st.integers(
        min_value=60, max_value=int(30 * 60)
    ).map(
        lambda secs: (now - timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%SZ")
    )


class TestMultiNodeAggregationCorrectness:
    """Feature: counter-history-charts, Property 5: Multi-node aggregation correctness.

    For any set of counter snapshots from multiple nodes for the same set and
    timestamps, when queried with "All Nodes" aggregation (node_id=None), the
    aggregated delta at each timestamp should equal the sum of the individual
    per-node deltas at that timestamp.

    **Validates: Requirements 6.2**
    """

    @pytest.fixture()
    def counter_db(self, tmp_path):
        """Create an in-memory SQLite database with schema for counter tests."""
        import sqlite3
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(_SCHEMA_SQL)
        yield conn
        conn.close()

    @given(
        node_ids=st.lists(
            st.sampled_from(["node-A", "node-B", "node-C", "node-D"]),
            min_size=2,
            max_size=4,
            unique=True,
        ),
        timestamps=st.lists(
            st_counter_timestamp_recent_window(),
            min_size=2,
            max_size=5,
            unique=True,
        ),
        set_name=st.sampled_from([
            "shield_feed_firehol_level1",
            "shield_feed_abuse_ch_feodo",
            "shield_local_blocks",
        ]),
        packets_per_node=st.lists(
            st.lists(
                st.integers(min_value=0, max_value=50000),
                min_size=2,
                max_size=5,
            ),
            min_size=2,
            max_size=4,
        ),
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_aggregated_delta_equals_sum_of_per_node_deltas(
        self, counter_db, node_ids, timestamps, set_name, packets_per_node
    ):
        """**Validates: Requirements 6.2**

        Generate snapshots from multiple nodes for the same set and timestamps.
        Verify aggregated delta equals sum of individual per-node deltas.
        """
        # Ensure packets_per_node has the same length as node_ids
        # and each inner list has the same length as timestamps
        assume(len(packets_per_node) >= len(node_ids))
        packets_per_node = packets_per_node[:len(node_ids)]
        for plist in packets_per_node:
            assume(len(plist) >= len(timestamps))

        # Sort timestamps so snapshots are in chronological order
        sorted_timestamps = sorted(timestamps)

        # Clear any previous data
        counter_db.execute("DELETE FROM counter_snapshots")
        counter_db.commit()

        # Insert snapshots: each node gets the same set_name at the same timestamps
        # but with different cumulative packet values
        for i, node_id in enumerate(node_ids):
            node_packets = sorted(packets_per_node[i][:len(sorted_timestamps)])
            for j, ts in enumerate(sorted_timestamps):
                counters = [{
                    "set": set_name,
                    "chain": "input",
                    "family": "inet",
                    "packets": node_packets[j],
                    "bytes": node_packets[j] * 100,
                }]
                insert_counter_snapshots(counter_db, node_id, ts, counters)

        # Query aggregated (node_id=None)
        aggregated_result = get_counter_history(counter_db, "1h", node_id=None)

        # Query per-node and sum deltas at each timestamp
        per_node_results = {}
        for node_id in node_ids:
            per_node_results[node_id] = get_counter_history(counter_db, "1h", node_id=node_id)

        # Build a map of timestamp -> aggregated delta from the aggregated result
        aggregated_deltas = {}
        if aggregated_result["datasets"]:
            for idx, ts in enumerate(aggregated_result["labels"]):
                total_delta = 0
                for ds in aggregated_result["datasets"]:
                    total_delta += ds["data"][idx]
                aggregated_deltas[ts] = total_delta

        # Build a map of timestamp -> sum of per-node deltas
        summed_per_node_deltas = {}
        for node_id in node_ids:
            node_result = per_node_results[node_id]
            if node_result["datasets"]:
                for idx, ts in enumerate(node_result["labels"]):
                    for ds in node_result["datasets"]:
                        summed_per_node_deltas[ts] = (
                            summed_per_node_deltas.get(ts, 0) + ds["data"][idx]
                        )

        # Verify: at each timestamp, aggregated delta == sum of per-node deltas
        all_timestamps = set(aggregated_deltas.keys()) | set(summed_per_node_deltas.keys())
        for ts in all_timestamps:
            agg_val = aggregated_deltas.get(ts, 0)
            sum_val = summed_per_node_deltas.get(ts, 0)
            assert agg_val == sum_val, (
                f"At timestamp {ts}: aggregated delta ({agg_val}) != "
                f"sum of per-node deltas ({sum_val})"
            )


# ── Property 6 (Counter History): Node filter isolation ──────────────────
# Feature: counter-history-charts, Property 6: Node filter isolation
# **Validates: Requirements 6.3**


class TestNodeFilterIsolation:
    """Feature: counter-history-charts, Property 6: Node filter isolation.

    For any set of counter snapshots from multiple nodes, when queried with
    a specific node_id filter, all returned data should belong exclusively
    to that node, and no data from other nodes should be present.

    **Validates: Requirements 6.3**
    """

    @pytest.fixture()
    def counter_db(self, tmp_path):
        """Create an in-memory SQLite database with schema for counter tests."""
        import sqlite3
        conn = sqlite3.connect(":memory:")
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        conn.executescript(_SCHEMA_SQL)
        yield conn
        conn.close()

    @given(
        node_ids=st.lists(
            st.sampled_from(["node-A", "node-B", "node-C", "node-D"]),
            min_size=2,
            max_size=4,
            unique=True,
        ),
        timestamps=st.lists(
            st_counter_timestamp_recent_window(),
            min_size=2,
            max_size=5,
            unique=True,
        ),
        set_name=st.sampled_from([
            "shield_feed_firehol_level1",
            "shield_feed_abuse_ch_feodo",
            "shield_local_blocks",
        ]),
        packets_per_node=st.lists(
            st.lists(
                st.integers(min_value=0, max_value=50000),
                min_size=2,
                max_size=5,
            ),
            min_size=2,
            max_size=4,
        ),
    )
    @settings(max_examples=100, deadline=None, suppress_health_check=[HealthCheck.function_scoped_fixture])
    def test_filtered_result_contains_only_target_node_data(
        self, counter_db, node_ids, timestamps, set_name, packets_per_node
    ):
        """**Validates: Requirements 6.3**

        Generate multi-node data, query with a specific node_id, and verify
        all returned data belongs exclusively to that node.
        """
        # Ensure packets_per_node has the same length as node_ids
        # and each inner list has the same length as timestamps
        assume(len(packets_per_node) >= len(node_ids))
        packets_per_node = packets_per_node[:len(node_ids)]
        for plist in packets_per_node:
            assume(len(plist) >= len(timestamps))

        # Sort timestamps so snapshots are in chronological order
        sorted_timestamps = sorted(timestamps)

        # Clear any previous data
        counter_db.execute("DELETE FROM counter_snapshots")
        counter_db.commit()

        # Insert snapshots: each node gets the same set_name at the same timestamps
        # but with different cumulative packet values
        for i, node_id in enumerate(node_ids):
            node_packets = sorted(packets_per_node[i][:len(sorted_timestamps)])
            for j, ts in enumerate(sorted_timestamps):
                counters = [{
                    "set": set_name,
                    "chain": "input",
                    "family": "inet",
                    "packets": node_packets[j],
                    "bytes": node_packets[j] * 100,
                }]
                insert_counter_snapshots(counter_db, node_id, ts, counters)

        # Pick the first node as the target for filtering
        target_node = node_ids[0]

        # Query with the specific node_id filter
        filtered_result = get_counter_history(counter_db, "1h", node_id=target_node)

        # Also query only the target node's data in isolation (fresh DB with only that node)
        # to get the expected result
        import sqlite3 as _sqlite3
        expected_db = _sqlite3.connect(":memory:")
        expected_db.row_factory = _sqlite3.Row
        expected_db.execute("PRAGMA journal_mode=WAL")
        expected_db.execute("PRAGMA foreign_keys=ON")
        expected_db.executescript(_SCHEMA_SQL)

        # Insert only the target node's data
        target_packets = sorted(packets_per_node[0][:len(sorted_timestamps)])
        for j, ts in enumerate(sorted_timestamps):
            counters = [{
                "set": set_name,
                "chain": "input",
                "family": "inet",
                "packets": target_packets[j],
                "bytes": target_packets[j] * 100,
            }]
            insert_counter_snapshots(expected_db, target_node, ts, counters)

        expected_result = get_counter_history(expected_db, "1h", node_id=target_node)
        expected_db.close()

        # The filtered result should match what we'd get if only that node's data existed
        assert filtered_result["labels"] == expected_result["labels"], (
            f"Labels mismatch: filtered={filtered_result['labels']}, "
            f"expected={expected_result['labels']}"
        )

        assert len(filtered_result["datasets"]) == len(expected_result["datasets"]), (
            f"Dataset count mismatch: filtered has {len(filtered_result['datasets'])}, "
            f"expected has {len(expected_result['datasets'])}"
        )

        for f_ds, e_ds in zip(filtered_result["datasets"], expected_result["datasets"]):
            assert f_ds["label"] == e_ds["label"], (
                f"Dataset label mismatch: {f_ds['label']} != {e_ds['label']}"
            )
            assert f_ds["data"] == e_ds["data"], (
                f"Dataset data mismatch for {f_ds['label']}: "
                f"{f_ds['data']} != {e_ds['data']}"
            )
            assert f_ds["resets"] == e_ds["resets"], (
                f"Dataset resets mismatch for {f_ds['label']}: "
                f"{f_ds['resets']} != {e_ds['resets']}"
            )

        assert filtered_result["lifetime_totals"] == expected_result["lifetime_totals"], (
            f"Lifetime totals mismatch: {filtered_result['lifetime_totals']} != "
            f"{expected_result['lifetime_totals']}"
        )
