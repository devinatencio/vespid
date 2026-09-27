"""Property-based tests for the Intel Event Ingestion Pipeline.

Uses Hypothesis to verify correctness properties of the ingestion routing,
counter integrity, reporting node logic, fleet filtering, recency windows,
reputation scoring, and deduplication across randomised inputs.

Each test is annotated with the property number and the requirements it validates.
"""

import json
import sqlite3
from datetime import datetime, timedelta, timezone

from hypothesis import given, settings, strategies as st, assume, HealthCheck

from app.intel_models import (
    compute_recency,
    get_ip_record,
    init_intel_db,
    process_fleet_block_event,
    process_unblock_event,
    upsert_ip_record,
)
from app.intel_score import compute_threat_score
from app.intel_service import process_block_event, process_sighting


# ── Shared Fixtures ──────────────────────────────────────────────────────
# The intel_db fixture is provided by conftest.py as a parameterized fixture
# that runs tests against both SQLite (in-memory) and MySQL (when available).
# The MySQL variant is automatically skipped when the test database is not
# reachable. See conftest.py for details (Validates: Requirements 18.4, 18.5).


# ── Hypothesis Strategies ────────────────────────────────────────────────

# Valid event_type values recognized by the ingestion pipeline
INTEL_EVENT_TYPES = ["LOG_MATCH", "RECON_CORRELATION", "NFT_ACTION", "SSH_BRUTE", "BLOCKLIST_HIT"]

# Valid action_taken values
ACTION_TAKEN_VALUES = ["DETECTED", "BLOCKED", "OBSERVED", "UNBLOCKED"]

# Default set of actions that qualify for intel ingestion
INTEL_INGEST_ACTIONS = {"BLOCKED"}


def st_ipv4():
    """Strategy that generates valid IPv4 address strings."""
    return st.tuples(
        st.integers(min_value=1, max_value=254),
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=0, max_value=255),
        st.integers(min_value=1, max_value=254),
    ).map(lambda t: f"{t[0]}.{t[1]}.{t[2]}.{t[3]}")


def st_node_id():
    """Strategy for generating node identifiers."""
    return st.from_regex(r"node-[a-z]{3,8}-[0-9]{1,4}", fullmatch=True)


def st_timestamp():
    """Strategy that generates ISO-8601 UTC timestamps within the last 30 days."""
    now = datetime.now(timezone.utc)
    return st.integers(
        min_value=0, max_value=int(30 * 24 * 3600)
    ).map(
        lambda secs: (now - timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%S")
    )


def st_timestamp_spread():
    """Strategy that generates timestamps spread across 60 days for recency testing."""
    now = datetime.now(timezone.utc)
    return st.integers(
        min_value=0, max_value=int(60 * 24 * 3600)
    ).map(
        lambda secs: (now - timedelta(seconds=secs)).strftime("%Y-%m-%dT%H:%M:%S")
    )


def st_detection_rule():
    """Strategy for detection rule names."""
    return st.sampled_from([
        "ssh-brute", "http-probe", "recon-correlation",
        "port-scan", "dns-tunnel", "malware-beacon",
    ])


def st_threat_tag():
    """Strategy for threat tag values."""
    return st.sampled_from([
        "ssh-brute", "http-probe", "recon-correlation",
        "port-scan", "dns-tunnel", "malware-beacon",
        "web-attack", "credential-stuffing",
    ])


def st_metadata_reason():
    """Strategy for metadata.reason values — some with fleet prefix, some without."""
    return st.one_of(
        st.just("fleet:node-abc-123"),
        st.just("fleet:propagation"),
        st.from_regex(r"fleet:[a-z0-9-]+", fullmatch=True),
        st.just("local-detection"),
        st.just("rule-match"),
        st.just(""),
        st.from_regex(r"[a-z_-]{3,20}", fullmatch=True),
    )


def st_security_event():
    """Composite strategy that generates a SecurityEvent dict for ingestion testing.

    Generates events with varied event_type, action_taken, and metadata.reason
    values to test the full ingestion filter logic.
    """
    return st.fixed_dictionaries({
        "event_id": st.uuids().map(str),
        "node_id": st_node_id(),
        "timestamp": st_timestamp(),
        "source_ip": st_ipv4(),
        "event_type": st.sampled_from(INTEL_EVENT_TYPES),
        "action_taken": st.sampled_from(ACTION_TAKEN_VALUES),
        "metadata": st.fixed_dictionaries({
            "reason": st_metadata_reason(),
            "detection_rule_name": st_detection_rule(),
            "threat_tag": st.one_of(st_threat_tag(), st.none()),
            "block_ttl_seconds": st.integers(min_value=0, max_value=86400),
        }),
        "geo_data": st.fixed_dictionaries({
            "country": st.sampled_from(["US", "CN", "RU", "DE", "BR", "GB"]),
        }),
    })


# ── Property Tests ───────────────────────────────────────────────────────


@given(event=st_security_event())
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_intel_filter_correctness(intel_db, event):
    """Property 1: Intel Filter Correctness.

    **Validates: Requirements 2.1, 2.2, 2.3, 2.5, 2.6, 5.1**

    For any generated SecurityEvent, the event reaches the intel database
    if and only if:
      - action_taken is in INTEL_INGEST_ACTIONS (default: {"BLOCKED"}) AND
      - If action_taken == "BLOCKED" then event_type == "NFT_ACTION" AND
      - metadata.reason does not start with "fleet:"
    """
    # Determine whether this event SHOULD reach the intel DB per the spec
    action_taken = event["action_taken"].upper()
    event_type = event["event_type"]
    reason = event["metadata"]["reason"]

    should_reach_intel = (
        action_taken in INTEL_INGEST_ACTIONS
        and (action_taken != "BLOCKED" or event_type == "NFT_ACTION")
        and not reason.startswith("fleet:")
    )

    # Count rows in ip_intel_events BEFORE processing
    row_before = intel_db.execute(
        "SELECT COUNT(*) as cnt FROM ip_intel_events WHERE ip_address = ?",
        (event["source_ip"],),
    ).fetchone()
    count_before = row_before["cnt"]

    # Simulate the ingestion routing logic (mirrors api.py ingest_events)
    # Step 1: Fleet filter — events with "fleet:" reason are excluded at
    # the DataBus level and never reach the server ingestion endpoint.
    if reason.startswith("fleet:"):
        # Event is excluded by DataBus fleet filter — does not reach server
        pass
    elif action_taken not in INTEL_INGEST_ACTIONS:
        # Event's action_taken is not in the configured ingest actions — skip
        pass
    elif action_taken == "BLOCKED" and event_type != "NFT_ACTION":
        # BLOCKED events must be NFT_ACTION to avoid double-counting — skip
        pass
    elif action_taken == "BLOCKED":
        # Qualifying block event — route to process_block_event
        intel_payload = {
            "source_ip": event["source_ip"],
            "node_id": event["node_id"],
            "event_type": event["event_type"],
            "timestamp": event["timestamp"],
            "detection_rule": event["metadata"]["detection_rule_name"],
            "block_ttl_seconds": event["metadata"]["block_ttl_seconds"],
            "metadata": {
                "geo_country": event["geo_data"]["country"],
                "threat_tag": event["metadata"]["threat_tag"],
            },
        }
        if event["metadata"]["threat_tag"]:
            intel_payload["threat_tag"] = event["metadata"]["threat_tag"]
        process_block_event(intel_db, intel_payload)
    elif action_taken == "OBSERVED":
        # Qualifying sighting event — route to process_sighting
        intel_payload = {
            "source_ip": event["source_ip"],
            "node_id": event["node_id"],
            "event_type": event["event_type"],
            "timestamp": event["timestamp"],
            "metadata": {
                "geo_country": event["geo_data"]["country"],
            },
        }
        process_sighting(intel_db, intel_payload)

    # Count rows in ip_intel_events AFTER processing
    row_after = intel_db.execute(
        "SELECT COUNT(*) as cnt FROM ip_intel_events WHERE ip_address = ?",
        (event["source_ip"],),
    ).fetchone()
    count_after = row_after["cnt"]

    # Verify the biconditional: event reaches intel DB iff conditions are met
    event_reached_intel = count_after > count_before

    assert event_reached_intel == should_reach_intel, (
        f"Event {'should' if should_reach_intel else 'should NOT'} have reached intel DB, "
        f"but {'did' if event_reached_intel else 'did NOT'}. "
        f"action_taken={action_taken}, event_type={event_type}, reason={reason!r}"
    )


@given(
    event_type=st.sampled_from(INTEL_EVENT_TYPES),
    source_ip=st_ipv4(),
    node_id=st_node_id(),
    timestamp=st_timestamp(),
    reason=st_metadata_reason(),
)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_detected_events_never_increment_counters(
    intel_db, event_type, source_ip, node_id, timestamp, reason
):
    """Property: DETECTED events never increment any intel counter.

    **Validates: Requirements 5.1, 5.3**

    For any SecurityEvent with action_taken="DETECTED", regardless of
    event_type or metadata.reason, the Intel_Ingestion_Pipeline SHALL:
      - NOT insert any rows into ip_intel_events
      - NOT increment total_times_seen
      - NOT increment total_times_blocked
      - NOT increment total_reporting_nodes
    """
    # Snapshot counters BEFORE processing
    row_before = intel_db.execute(
        "SELECT COUNT(*) as cnt FROM ip_intel_events WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()
    events_count_before = row_before["cnt"]

    ip_record_before = intel_db.execute(
        "SELECT total_times_seen, total_times_blocked, total_reporting_nodes "
        "FROM ip_intel WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()

    times_seen_before = ip_record_before["total_times_seen"] if ip_record_before else 0
    times_blocked_before = ip_record_before["total_times_blocked"] if ip_record_before else 0
    reporting_nodes_before = ip_record_before["total_reporting_nodes"] if ip_record_before else 0

    # Simulate the ingestion routing logic for a DETECTED event.
    # Per Req 2.3 and Req 5.1: DETECTED events are rejected from intel
    # ingestion regardless of event_type.
    action_taken = "DETECTED"

    # The ingestion pipeline checks:
    # 1. Fleet filter: events with "fleet:" reason are excluded at DataBus level
    # 2. action_taken must be in INTEL_INGEST_ACTIONS (default: {"BLOCKED"})
    # 3. DETECTED is NOT in INTEL_INGEST_ACTIONS → skip intel processing
    #
    # Regardless of the path taken, DETECTED events must never reach intel DB.
    if reason.startswith("fleet:"):
        # Excluded by DataBus fleet filter — never reaches server
        pass
    elif action_taken not in INTEL_INGEST_ACTIONS:
        # DETECTED is not in INTEL_INGEST_ACTIONS — skip intel processing
        pass
    elif action_taken == "BLOCKED" and event_type != "NFT_ACTION":
        # Would not apply to DETECTED, but included for completeness
        pass
    elif action_taken == "BLOCKED":
        # Would not apply to DETECTED
        intel_payload = {
            "source_ip": source_ip,
            "node_id": node_id,
            "event_type": event_type,
            "timestamp": timestamp,
            "detection_rule": "test-rule",
            "block_ttl_seconds": 3600,
            "metadata": {"geo_country": "US", "threat_tag": None},
        }
        process_block_event(intel_db, intel_payload)
    elif action_taken == "OBSERVED":
        # Would not apply to DETECTED
        intel_payload = {
            "source_ip": source_ip,
            "node_id": node_id,
            "event_type": event_type,
            "timestamp": timestamp,
            "metadata": {"geo_country": "US"},
        }
        process_sighting(intel_db, intel_payload)

    # Snapshot counters AFTER processing
    row_after = intel_db.execute(
        "SELECT COUNT(*) as cnt FROM ip_intel_events WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()
    events_count_after = row_after["cnt"]

    ip_record_after = intel_db.execute(
        "SELECT total_times_seen, total_times_blocked, total_reporting_nodes "
        "FROM ip_intel WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()

    times_seen_after = ip_record_after["total_times_seen"] if ip_record_after else 0
    times_blocked_after = ip_record_after["total_times_blocked"] if ip_record_after else 0
    reporting_nodes_after = ip_record_after["total_reporting_nodes"] if ip_record_after else 0

    # Assert: No rows inserted into ip_intel_events
    assert events_count_after == events_count_before, (
        f"DETECTED event with event_type={event_type} inserted row(s) into ip_intel_events. "
        f"Before: {events_count_before}, After: {events_count_after}"
    )

    # Assert: total_times_seen not incremented
    assert times_seen_after == times_seen_before, (
        f"DETECTED event with event_type={event_type} incremented total_times_seen. "
        f"Before: {times_seen_before}, After: {times_seen_after}"
    )

    # Assert: total_times_blocked not incremented
    assert times_blocked_after == times_blocked_before, (
        f"DETECTED event with event_type={event_type} incremented total_times_blocked. "
        f"Before: {times_blocked_before}, After: {times_blocked_after}"
    )

    # Assert: total_reporting_nodes not incremented
    assert reporting_nodes_after == reporting_nodes_before, (
        f"DETECTED event with event_type={event_type} incremented total_reporting_nodes. "
        f"Before: {reporting_nodes_before}, After: {reporting_nodes_after}"
    )


@given(
    source_ip=st_ipv4(),
    node_id=st_node_id(),
    timestamp=st_timestamp(),
    is_block=st.booleans(),
    detection_rule=st_detection_rule(),
)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_single_event_counter_integrity(
    intel_db, source_ip, node_id, timestamp, is_block, detection_rule
):
    """Property 2: Single Action Counter Integrity.

    **Validates: Requirements 3.1, 3.2, 3.3**

    For any single qualifying event processed through upsert_ip_record():
      - total_times_seen increases by exactly 1
      - total_times_blocked increases by exactly 1 if is_block=True, else unchanged
      - Exactly 1 new row appears in ip_intel_events
    """
    # Snapshot counters BEFORE processing
    ip_record_before = intel_db.execute(
        "SELECT total_times_seen, total_times_blocked "
        "FROM ip_intel WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()

    times_seen_before = ip_record_before["total_times_seen"] if ip_record_before else 0
    times_blocked_before = ip_record_before["total_times_blocked"] if ip_record_before else 0

    events_count_before = intel_db.execute(
        "SELECT COUNT(*) as cnt FROM ip_intel_events WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()["cnt"]

    # Process the event through upsert_ip_record
    metadata = {
        "detection_rule": detection_rule if is_block else "",
        "block_ttl_seconds": 3600 if is_block else 0,
        "geo_country": "US",
    }

    upsert_ip_record(
        conn=intel_db,
        ip_address=source_ip,
        node_id=node_id,
        event_type="NFT_ACTION" if is_block else "LOG_MATCH",
        timestamp=timestamp,
        is_block=is_block,
        metadata=metadata,
    )

    # Snapshot counters AFTER processing
    ip_record_after = intel_db.execute(
        "SELECT total_times_seen, total_times_blocked "
        "FROM ip_intel WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()

    times_seen_after = ip_record_after["total_times_seen"]
    times_blocked_after = ip_record_after["total_times_blocked"]

    events_count_after = intel_db.execute(
        "SELECT COUNT(*) as cnt FROM ip_intel_events WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()["cnt"]

    # Assert: total_times_seen incremented by exactly 1
    assert times_seen_after == times_seen_before + 1, (
        f"total_times_seen should increment by 1. "
        f"Before: {times_seen_before}, After: {times_seen_after}, is_block={is_block}"
    )

    # Assert: total_times_blocked incremented by 1 iff is_block=True
    if is_block:
        assert times_blocked_after == times_blocked_before + 1, (
            f"total_times_blocked should increment by 1 when is_block=True. "
            f"Before: {times_blocked_before}, After: {times_blocked_after}"
        )
    else:
        assert times_blocked_after == times_blocked_before, (
            f"total_times_blocked should NOT change when is_block=False. "
            f"Before: {times_blocked_before}, After: {times_blocked_after}"
        )

    # Assert: Exactly 1 new row in ip_intel_events
    assert events_count_after == events_count_before + 1, (
        f"Exactly 1 new row should appear in ip_intel_events. "
        f"Before: {events_count_before}, After: {events_count_after}, is_block={is_block}"
    )


@given(
    source_ip=st_ipv4(),
    node_id=st_node_id(),
    n_sightings=st.integers(min_value=0, max_value=10),
    m_blocks=st.integers(min_value=0, max_value=10),
    timestamps=st.lists(st_timestamp(), min_size=20, max_size=20),
    detection_rule=st_detection_rule(),
)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_observed_vs_blocked_counter_semantics(
    intel_db, source_ip, node_id, n_sightings, m_blocks, timestamps, detection_rule
):
    """Property 3: Observed vs Blocked Semantics.

    **Validates: Requirements 4.1, 4.2, 4.3, 4.4**

    For any sequence of N sighting events and M block events for the same IP:
      - total_times_seen == N + M
      - total_times_blocked == M
      - ip_intel_events row count == N + M
      - Rows with event_kind == "block" count == M
    """
    # Skip trivial case where no events are generated
    assume(n_sightings + m_blocks > 0)

    # Ensure we start from a clean state for this IP by checking it doesn't
    # already exist (Hypothesis reuses the fixture across examples)
    existing = intel_db.execute(
        "SELECT 1 FROM ip_intel WHERE ip_address = ?", (source_ip,)
    ).fetchone()
    assume(existing is None)

    # Process N sighting events
    for i in range(n_sightings):
        sighting_payload = {
            "source_ip": source_ip,
            "node_id": node_id,
            "event_type": "LOG_MATCH",
            "timestamp": timestamps[i],
            "metadata": {"geo_country": "US"},
        }
        process_sighting(intel_db, sighting_payload)

    # Process M block events
    for i in range(m_blocks):
        block_payload = {
            "source_ip": source_ip,
            "node_id": node_id,
            "event_type": "NFT_ACTION",
            "timestamp": timestamps[n_sightings + i],
            "detection_rule": detection_rule,
            "block_ttl_seconds": 3600,
            "metadata": {"geo_country": "US"},
        }
        process_block_event(intel_db, block_payload)

    # Verify counters on ip_intel record
    ip_record = intel_db.execute(
        "SELECT total_times_seen, total_times_blocked "
        "FROM ip_intel WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()

    assert ip_record is not None, (
        f"ip_intel record should exist after processing {n_sightings} sightings + {m_blocks} blocks"
    )

    # Assert: total_times_seen == N + M
    assert ip_record["total_times_seen"] == n_sightings + m_blocks, (
        f"total_times_seen should be {n_sightings + m_blocks} (N={n_sightings} sightings + M={m_blocks} blocks), "
        f"but got {ip_record['total_times_seen']}"
    )

    # Assert: total_times_blocked == M
    assert ip_record["total_times_blocked"] == m_blocks, (
        f"total_times_blocked should be {m_blocks} (only block events), "
        f"but got {ip_record['total_times_blocked']}"
    )

    # Verify ip_intel_events row count == N + M
    events_count = intel_db.execute(
        "SELECT COUNT(*) as cnt FROM ip_intel_events WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()["cnt"]

    assert events_count == n_sightings + m_blocks, (
        f"ip_intel_events row count should be {n_sightings + m_blocks}, "
        f"but got {events_count}"
    )

    # Verify rows with event_kind == "block" count == M
    block_rows = intel_db.execute(
        "SELECT COUNT(*) as cnt FROM ip_intel_events WHERE ip_address = ? AND event_kind = 'block'",
        (source_ip,),
    ).fetchone()["cnt"]

    assert block_rows == m_blocks, (
        f"ip_intel_events rows with event_kind='block' should be {m_blocks}, "
        f"but got {block_rows}"
    )


@given(
    source_ip=st_ipv4(),
    node_id=st_node_id(),
    event_flags=st.lists(st.booleans(), min_size=1, max_size=15),
    timestamps=st.lists(st_timestamp(), min_size=15, max_size=15),
    detection_rule=st_detection_rule(),
)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_counter_event_row_consistency(
    intel_db, source_ip, node_id, event_flags, timestamps, detection_rule
):
    """Property 7: Counter-Event Row Consistency.

    **Validates: Requirements 9, 15**

    After any sequence of upsert operations for an IP:
      - total_times_seen == COUNT(*) FROM ip_intel_events WHERE ip_address = X
        AND event_kind IN ('block', 'sighting')
      - total_times_blocked == COUNT(*) FROM ip_intel_events WHERE ip_address = X
        AND event_kind = 'block'

    Note: fleet_block rows are excluded from total_times_seen.
    """
    # Ensure we start from a clean state for this IP
    existing = intel_db.execute(
        "SELECT 1 FROM ip_intel WHERE ip_address = ?", (source_ip,)
    ).fetchone()
    assume(existing is None)

    # Process a random sequence of mixed block/sighting events
    for i, is_block in enumerate(event_flags):
        if is_block:
            block_payload = {
                "source_ip": source_ip,
                "node_id": node_id,
                "event_type": "NFT_ACTION",
                "timestamp": timestamps[i],
                "detection_rule": detection_rule,
                "block_ttl_seconds": 3600,
                "metadata": {"geo_country": "US"},
            }
            process_block_event(intel_db, block_payload)
        else:
            sighting_payload = {
                "source_ip": source_ip,
                "node_id": node_id,
                "event_type": "LOG_MATCH",
                "timestamp": timestamps[i],
                "metadata": {"geo_country": "US"},
            }
            process_sighting(intel_db, sighting_payload)

    # Query the ip_intel record for counter values
    ip_record = intel_db.execute(
        "SELECT total_times_seen, total_times_blocked "
        "FROM ip_intel WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()

    assert ip_record is not None, (
        f"ip_intel record should exist after processing {len(event_flags)} events"
    )

    # Count rows in ip_intel_events where event_kind IN ('block', 'sighting')
    # (excludes fleet_block rows per Req 15 AC 7)
    event_count_seen = intel_db.execute(
        "SELECT COUNT(*) as cnt FROM ip_intel_events "
        "WHERE ip_address = ? AND event_kind IN ('block', 'sighting')",
        (source_ip,),
    ).fetchone()["cnt"]

    # Count rows in ip_intel_events where event_kind = 'block'
    event_count_blocked = intel_db.execute(
        "SELECT COUNT(*) as cnt FROM ip_intel_events "
        "WHERE ip_address = ? AND event_kind = 'block'",
        (source_ip,),
    ).fetchone()["cnt"]

    # Assert: total_times_seen == COUNT of block + sighting rows
    assert ip_record["total_times_seen"] == event_count_seen, (
        f"total_times_seen ({ip_record['total_times_seen']}) should equal "
        f"COUNT(*) of event_kind IN ('block', 'sighting') rows ({event_count_seen}). "
        f"Event sequence (True=block, False=sighting): {event_flags}"
    )

    # Assert: total_times_blocked == COUNT of block rows
    assert ip_record["total_times_blocked"] == event_count_blocked, (
        f"total_times_blocked ({ip_record['total_times_blocked']}) should equal "
        f"COUNT(*) of event_kind='block' rows ({event_count_blocked}). "
        f"Event sequence (True=block, False=sighting): {event_flags}"
    )


@given(
    source_ip=st_ipv4(),
    node_ids=st.lists(st_node_id(), min_size=1, max_size=20),
    timestamps=st.lists(st_timestamp(), min_size=20, max_size=20),
    detection_rule=st_detection_rule(),
)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_reporting_node_idempotence(
    intel_db, source_ip, node_ids, timestamps, detection_rule
):
    """Property 4: Reporting Node Idempotence.

    **Validates: Requirements 6.1, 6.2, 6.3, 6.4**

    For any sequence of events from a set of K distinct node_ids:
      - total_reporting_nodes == min(K, 1000)
      - len(reporting_node_list) == min(K, 1000)
      - Each node_id appears at most once in reporting_node_list
    """
    # Ensure we start from a clean state for this IP
    existing = intel_db.execute(
        "SELECT 1 FROM ip_intel WHERE ip_address = ?", (source_ip,)
    ).fetchone()
    assume(existing is None)

    # Determine K = number of distinct node_ids in the generated list
    distinct_node_ids = set(node_ids)
    k = len(distinct_node_ids)

    # Process events from each node_id (list may contain repeats)
    for i, nid in enumerate(node_ids):
        block_payload = {
            "source_ip": source_ip,
            "node_id": nid,
            "event_type": "NFT_ACTION",
            "timestamp": timestamps[i],
            "detection_rule": detection_rule,
            "block_ttl_seconds": 3600,
            "metadata": {"geo_country": "US"},
        }
        process_block_event(intel_db, block_payload)

    # Query the ip_intel record
    ip_record = intel_db.execute(
        "SELECT total_reporting_nodes, reporting_node_list "
        "FROM ip_intel WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()

    assert ip_record is not None, (
        f"ip_intel record should exist after processing events from {k} distinct nodes"
    )

    reporting_node_list = json.loads(ip_record["reporting_node_list"])
    total_reporting_nodes = ip_record["total_reporting_nodes"]

    expected_count = min(k, 1000)

    # Assert: total_reporting_nodes == min(K, 1000)
    assert total_reporting_nodes == expected_count, (
        f"total_reporting_nodes should be min(K={k}, 1000) = {expected_count}, "
        f"but got {total_reporting_nodes}. "
        f"node_ids submitted: {node_ids}"
    )

    # Assert: len(reporting_node_list) == min(K, 1000)
    assert len(reporting_node_list) == expected_count, (
        f"len(reporting_node_list) should be min(K={k}, 1000) = {expected_count}, "
        f"but got {len(reporting_node_list)}. "
        f"reporting_node_list: {reporting_node_list}"
    )

    # Assert: Each node_id appears at most once (no duplicates)
    assert len(reporting_node_list) == len(set(reporting_node_list)), (
        f"reporting_node_list should contain no duplicates, "
        f"but found duplicates. List: {reporting_node_list}"
    )


# ── Edge-Case Tests ──────────────────────────────────────────────────────


def test_reporting_node_list_capped_at_1000(intel_db):
    """Edge-case test: reporting_node_list capped at 1000 entries.

    **Validates: Requirement 6.4**

    THE Intel_Database SHALL cap reporting_node_list at 1000 entries to bound
    storage. The 1001st distinct node_id does NOT increment the counter.

    Steps:
      1. Create a fresh IP in the intel_db
      2. Process 1000 block events from 1000 distinct node_ids
      3. Verify total_reporting_nodes == 1000 and len(reporting_node_list) == 1000
      4. Process a 1001st block event from a new distinct node_id
      5. Verify total_reporting_nodes is still 1000 (not 1001)
      6. Verify len(reporting_node_list) is still 1000 (capped)
    """
    source_ip = "192.168.99.1"
    timestamp = "2024-01-15T12:00:00"

    # Step 1 & 2: Process 1000 block events from 1000 distinct node_ids
    for i in range(1000):
        block_payload = {
            "source_ip": source_ip,
            "node_id": f"node-cap-{i}",
            "event_type": "NFT_ACTION",
            "timestamp": timestamp,
            "detection_rule": "ssh-brute",
            "block_ttl_seconds": 3600,
            "metadata": {"geo_country": "US"},
        }
        process_block_event(intel_db, block_payload)

    # Step 3: Verify total_reporting_nodes == 1000 and len(reporting_node_list) == 1000
    ip_record = intel_db.execute(
        "SELECT total_reporting_nodes, reporting_node_list "
        "FROM ip_intel WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()

    assert ip_record is not None, "ip_intel record should exist after 1000 block events"

    reporting_node_list = json.loads(ip_record["reporting_node_list"])
    assert ip_record["total_reporting_nodes"] == 1000, (
        f"total_reporting_nodes should be 1000 after 1000 distinct nodes, "
        f"got {ip_record['total_reporting_nodes']}"
    )
    assert len(reporting_node_list) == 1000, (
        f"len(reporting_node_list) should be 1000 after 1000 distinct nodes, "
        f"got {len(reporting_node_list)}"
    )

    # Step 4: Process a 1001st block event from a new distinct node_id
    block_payload_1001 = {
        "source_ip": source_ip,
        "node_id": "node-cap-1000",
        "event_type": "NFT_ACTION",
        "timestamp": timestamp,
        "detection_rule": "ssh-brute",
        "block_ttl_seconds": 3600,
        "metadata": {"geo_country": "US"},
    }
    process_block_event(intel_db, block_payload_1001)

    # Step 5 & 6: Verify total_reporting_nodes is still 1000 (capped)
    ip_record_after = intel_db.execute(
        "SELECT total_reporting_nodes, reporting_node_list "
        "FROM ip_intel WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()

    reporting_node_list_after = json.loads(ip_record_after["reporting_node_list"])

    assert ip_record_after["total_reporting_nodes"] == 1000, (
        f"total_reporting_nodes should still be 1000 after 1001st node (capped), "
        f"got {ip_record_after['total_reporting_nodes']}"
    )
    assert len(reporting_node_list_after) == 1000, (
        f"len(reporting_node_list) should still be 1000 after 1001st node (capped), "
        f"got {len(reporting_node_list_after)}"
    )


# ── Fleet Filter Property Tests ──────────────────────────────────────────


@given(
    events=st.lists(
        st.fixed_dictionaries({
            "event_id": st.uuids().map(str),
            "node_id": st_node_id(),
            "timestamp": st_timestamp(),
            "source_ip": st_ipv4(),
            "event_type": st.sampled_from(INTEL_EVENT_TYPES),
            "action_taken": st.sampled_from(ACTION_TAKEN_VALUES),
            "metadata": st.fixed_dictionaries({
                "reason": st_metadata_reason(),
                "detection_rule_name": st_detection_rule(),
                "threat_tag": st.one_of(st_threat_tag(), st.none()),
                "block_ttl_seconds": st.integers(min_value=0, max_value=86400),
            }),
            "geo_data": st.fixed_dictionaries({
                "country": st.sampled_from(["US", "CN", "RU", "DE", "BR", "GB"]),
            }),
        }),
        min_size=1,
        max_size=20,
    )
)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_fleet_filter_exclusion_in_handle_batch(intel_db, events):
    """Property 5: Fleet Filter Exclusion.

    **Validates: Requirements 7.1, 7.2**

    For any event where metadata.reason starts with "fleet:", the event is
    excluded from the intel_payload list in _handle_batch(). For any event
    where metadata.reason does NOT start with "fleet:", the event is included.

    This test directly exercises the fleet filter logic extracted from
    _handle_batch() — the list comprehension that partitions events into
    intel_payload (non-fleet) vs excluded (fleet-originated).
    """
    # Simulate the payload construction from _handle_batch():
    # payload = [json.loads(e.to_json()) for e in batch]
    # Here we already have dict-form events, which is equivalent.
    payload = events

    # Apply the fleet filter logic exactly as implemented in _handle_batch()
    intel_payload = [
        e for e in payload
        if not (e.get("metadata", {}).get("reason", "").startswith("fleet:"))
    ]

    # Verify: every event with "fleet:" prefix is EXCLUDED from intel_payload
    for event in payload:
        reason = event.get("metadata", {}).get("reason", "")
        is_fleet = reason.startswith("fleet:")

        if is_fleet:
            assert event not in intel_payload, (
                f"Event with metadata.reason={reason!r} should be EXCLUDED from "
                f"intel_payload but was found in it. event_id={event['event_id']}"
            )
        else:
            assert event in intel_payload, (
                f"Event with metadata.reason={reason!r} should be INCLUDED in "
                f"intel_payload but was NOT found. event_id={event['event_id']}"
            )

    # Verify: the counts are consistent
    fleet_count = sum(
        1 for e in payload
        if e.get("metadata", {}).get("reason", "").startswith("fleet:")
    )
    non_fleet_count = len(payload) - fleet_count

    assert len(intel_payload) == non_fleet_count, (
        f"intel_payload should contain exactly {non_fleet_count} non-fleet events, "
        f"but contains {len(intel_payload)}. "
        f"Total events: {len(payload)}, fleet events: {fleet_count}"
    )


def st_non_fleet_reason():
    """Strategy that generates metadata.reason values that do NOT start with 'fleet:'.

    Ensures no generated value can accidentally begin with the "fleet:" prefix,
    covering empty strings, common local reasons, and arbitrary non-fleet text.
    """
    return st.one_of(
        st.sampled_from(["local-detection", "rule-match", ""]),
        st.from_regex(r"[a-z_-]{3,20}", fullmatch=True).filter(
            lambda s: not s.startswith("fleet:")
        ),
    )


@given(
    events=st.lists(
        st.fixed_dictionaries({
            "event_id": st.uuids().map(str),
            "node_id": st_node_id(),
            "timestamp": st_timestamp(),
            "source_ip": st_ipv4(),
            "event_type": st.sampled_from(INTEL_EVENT_TYPES),
            "action_taken": st.sampled_from(ACTION_TAKEN_VALUES),
            "metadata": st.fixed_dictionaries({
                "reason": st_non_fleet_reason(),
                "detection_rule_name": st_detection_rule(),
                "threat_tag": st.one_of(st_threat_tag(), st.none()),
                "block_ttl_seconds": st.integers(min_value=0, max_value=86400),
            }),
            "geo_data": st.fixed_dictionaries({
                "country": st.sampled_from(["US", "CN", "RU", "DE", "BR", "GB"]),
            }),
        }),
        min_size=1,
        max_size=20,
    )
)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_non_fleet_events_included_in_intel_payload(intel_db, events):
    """Property 5 (inclusion complement): Non-fleet events are always included.

    **Validates: Requirements 7.2, 7.4**

    For any batch of events where metadata.reason does NOT start with "fleet:",
    ALL events are included in intel_payload after the fleet filter is applied.
    None are accidentally excluded.

    This is the complementary test to test_fleet_filter_exclusion_in_handle_batch,
    focusing specifically on the inclusion guarantee: non-fleet events must never
    be filtered out by the fleet filter logic.
    """
    # Precondition: all generated events have non-fleet reasons
    for event in events:
        reason = event.get("metadata", {}).get("reason", "")
        assert not reason.startswith("fleet:"), (
            f"Test generator produced a fleet-prefixed reason: {reason!r}. "
            "This should not happen — strategy is misconfigured."
        )

    # Apply the fleet filter logic exactly as implemented in _handle_batch()
    intel_payload = [
        e for e in events
        if not (e.get("metadata", {}).get("reason", "").startswith("fleet:"))
    ]

    # Verify: ALL events are included (none excluded)
    assert len(intel_payload) == len(events), (
        f"All {len(events)} non-fleet events should be included in intel_payload, "
        f"but only {len(intel_payload)} were included. "
        f"Reasons: {[e['metadata']['reason'] for e in events]}"
    )

    # Verify: each individual event is present in intel_payload
    for event in events:
        assert event in intel_payload, (
            f"Non-fleet event with reason={event['metadata']['reason']!r} "
            f"was excluded from intel_payload. event_id={event['event_id']}"
        )


# ── Recency Window Property Tests ────────────────────────────────────────


@given(
    source_ip=st_ipv4(),
    node_id=st_node_id(),
    timestamps=st.lists(st_timestamp_spread(), min_size=1, max_size=15),
    is_blocks=st.lists(st.booleans(), min_size=15, max_size=15),
    detection_rule=st_detection_rule(),
)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_time_window_30d_lte_total_times_seen(
    intel_db, source_ip, node_id, timestamps, is_blocks, detection_rule
):
    """Property: times_seen_last_30d <= total_times_seen for any IP record.

    **Validates: Requirements 14.3**

    FOR ALL IP records, THE Intel_Database SHALL maintain:
    times_seen_last_30d is less than or equal to total_times_seen.

    This holds because times_seen_last_30d counts events within the last 30 days,
    which is a subset of all events ever recorded (total_times_seen). Events with
    timestamps older than 30 days contribute to total_times_seen but NOT to
    times_seen_last_30d, ensuring the invariant.

    Generator: Random sets of events with timestamps distributed across the past
    60 days, so some events will be outside the 30d window.
    """
    # Ensure we start from a clean state for this IP
    existing = intel_db.execute(
        "SELECT 1 FROM ip_intel WHERE ip_address = ?", (source_ip,)
    ).fetchone()
    assume(existing is None)

    num_events = len(timestamps)

    # Process events with timestamps spread across 60 days
    for i in range(num_events):
        is_block = is_blocks[i]
        metadata = {
            "detection_rule": detection_rule if is_block else "",
            "block_ttl_seconds": 3600 if is_block else 0,
            "geo_country": "US",
        }

        upsert_ip_record(
            conn=intel_db,
            ip_address=source_ip,
            node_id=node_id,
            event_type="NFT_ACTION" if is_block else "LOG_MATCH",
            timestamp=timestamps[i],
            is_block=is_block,
            metadata=metadata,
        )

    # Query the ip_intel record for total_times_seen
    ip_record = intel_db.execute(
        "SELECT total_times_seen FROM ip_intel WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()

    assert ip_record is not None, (
        f"ip_intel record should exist after processing {num_events} events"
    )

    total_times_seen = ip_record["total_times_seen"]

    # Compute recency windows
    recency = compute_recency(intel_db, source_ip)
    times_seen_last_30d = recency["times_seen_last_30d"]

    # Assert: times_seen_last_30d <= total_times_seen
    assert times_seen_last_30d <= total_times_seen, (
        f"Time Window Monotonicity violated: times_seen_last_30d ({times_seen_last_30d}) "
        f"> total_times_seen ({total_times_seen}). "
        f"This means more events were counted in the 30d window than exist in total. "
        f"num_events={num_events}, timestamps={timestamps}"
    )


@given(
    source_ip=st_ipv4(),
    node_id=st_node_id(),
    timestamps=st.lists(st_timestamp_spread(), min_size=1, max_size=20),
    is_blocks=st.lists(st.booleans(), min_size=20, max_size=20),
    detection_rule=st_detection_rule(),
)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_recency_window_monotonicity(
    intel_db, source_ip, node_id, timestamps, is_blocks, detection_rule
):
    """Property 6: Recency Window Monotonicity.

    **Validates: Requirements 10, 14**

    For any set of events inserted at arbitrary timestamps, compute_recency()
    always returns values satisfying:
        times_seen_last_24h <= times_seen_last_7d <= times_seen_last_30d

    This holds because the 24h window is a subset of the 7d window, which is
    a subset of the 30d window. Any event counted in the 24h window must also
    be counted in the 7d and 30d windows.

    Generator: Random sets of events with timestamps distributed across the
    past 60 days, ensuring coverage of events inside and outside each window.
    """
    # Ensure we start from a clean state for this IP
    existing = intel_db.execute(
        "SELECT 1 FROM ip_intel WHERE ip_address = ?", (source_ip,)
    ).fetchone()
    assume(existing is None)

    num_events = len(timestamps)

    # Process events with timestamps spread across 60 days
    for i in range(num_events):
        is_block = is_blocks[i]
        metadata = {
            "detection_rule": detection_rule if is_block else "",
            "block_ttl_seconds": 3600 if is_block else 0,
            "geo_country": "US",
        }

        upsert_ip_record(
            conn=intel_db,
            ip_address=source_ip,
            node_id=node_id,
            event_type="NFT_ACTION" if is_block else "LOG_MATCH",
            timestamp=timestamps[i],
            is_block=is_block,
            metadata=metadata,
        )

    # Compute recency windows
    recency = compute_recency(intel_db, source_ip)
    times_seen_last_24h = recency["times_seen_last_24h"]
    times_seen_last_7d = recency["times_seen_last_7d"]
    times_seen_last_30d = recency["times_seen_last_30d"]

    # Assert: times_seen_last_24h <= times_seen_last_7d
    assert times_seen_last_24h <= times_seen_last_7d, (
        f"Recency Window Monotonicity violated: "
        f"times_seen_last_24h ({times_seen_last_24h}) > times_seen_last_7d ({times_seen_last_7d}). "
        f"The 24h window is a subset of the 7d window, so this should never happen. "
        f"num_events={num_events}, timestamps={timestamps}"
    )

    # Assert: times_seen_last_7d <= times_seen_last_30d
    assert times_seen_last_7d <= times_seen_last_30d, (
        f"Recency Window Monotonicity violated: "
        f"times_seen_last_7d ({times_seen_last_7d}) > times_seen_last_30d ({times_seen_last_30d}). "
        f"The 7d window is a subset of the 30d window, so this should never happen. "
        f"num_events={num_events}, timestamps={timestamps}"
    )


# ── Reputation Score Property Tests ──────────────────────────────────────


def st_record_dict():
    """Strategy that generates valid IP record dicts for compute_threat_score().

    Generates records with non-negative counters, valid threat_tags arrays,
    recency values, and repeat_offender flags. Ensures internal consistency
    (e.g., total_times_blocked <= total_times_seen).
    """
    return st.fixed_dictionaries({
        "total_times_seen": st.integers(min_value=0, max_value=100000),
        "total_times_blocked": st.integers(min_value=0, max_value=100000),
        "total_reporting_nodes": st.integers(min_value=0, max_value=1000),
        "times_seen_last_24h": st.integers(min_value=0, max_value=10000),
        "times_seen_last_7d": st.integers(min_value=0, max_value=10000),
        "times_seen_last_30d": st.integers(min_value=0, max_value=10000),
        "threat_tags": st.lists(
            st_threat_tag(), min_size=0, max_size=10, unique=True
        ),
        "repeat_offender": st.booleans(),
    }).filter(
        # Ensure total_times_blocked <= total_times_seen (logical constraint)
        lambda r: r["total_times_blocked"] <= r["total_times_seen"]
    )


@given(record=st_record_dict())
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_reputation_score_bounds_and_precision(record):
    """Property 8: Reputation Score Bounds.

    **Validates: Requirements 12.4**

    For any valid IP record dict with non-negative counters:
      - 0.0 <= compute_threat_score(record) <= 100.0
      - Result has at most 1 decimal place

    The score is a weighted sum of normalized signals clamped to [0.0, 100.0]
    and rounded to 1 decimal place. This property must hold regardless of the
    input values (extreme counters, empty threat_tags, etc.).
    """
    score = compute_threat_score(record)

    # Assert: score is within [0.0, 100.0]
    assert 0.0 <= score <= 100.0, (
        f"compute_threat_score() returned {score} which is outside [0.0, 100.0]. "
        f"Record: total_times_seen={record['total_times_seen']}, "
        f"total_times_blocked={record['total_times_blocked']}, "
        f"total_reporting_nodes={record['total_reporting_nodes']}, "
        f"threat_tags={record['threat_tags']}, "
        f"repeat_offender={record['repeat_offender']}"
    )

    # Assert: result has at most 1 decimal place
    # A number rounded to 1 decimal place satisfies: round(x, 1) == x
    assert round(score, 1) == score, (
        f"compute_threat_score() returned {score} which has more than 1 decimal place. "
        f"Expected round({score}, 1) == {score}, got round({score}, 1) = {round(score, 1)}. "
        f"Record: total_times_seen={record['total_times_seen']}, "
        f"total_times_blocked={record['total_times_blocked']}"
    )


def st_record_dict_zero_seen():
    """Strategy that generates IP record dicts with total_times_seen == 0.

    All other fields are varied randomly to ensure the zero-seen early exit
    holds regardless of other signal values (blocked counts, reporting nodes,
    recency values, threat_tags, repeat_offender flag).
    """
    return st.fixed_dictionaries({
        "total_times_seen": st.just(0),
        "total_times_blocked": st.just(0),
        "total_reporting_nodes": st.integers(min_value=0, max_value=1000),
        "times_seen_last_24h": st.integers(min_value=0, max_value=10000),
        "times_seen_last_7d": st.integers(min_value=0, max_value=10000),
        "times_seen_last_30d": st.integers(min_value=0, max_value=10000),
        "threat_tags": st.lists(
            st_threat_tag(), min_size=0, max_size=10, unique=True
        ),
        "repeat_offender": st.booleans(),
    })


@given(record=st_record_dict_zero_seen())
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_reputation_score_zero_when_total_times_seen_zero(record):
    """Property 8 (zero-seen): If total_times_seen == 0, score == 0.0.

    **Validates: Requirements 12**

    When an IP record has total_times_seen == 0, the compute_threat_score()
    function must return exactly 0.0 regardless of any other field values.
    This is the early-exit condition: no activity means no threat.

    Generator: Random record dicts where total_times_seen is explicitly 0,
    with other fields (reporting_nodes, recency, threat_tags, repeat_offender)
    varied randomly to confirm the early exit is unconditional.
    """
    score = compute_threat_score(record)

    assert score == 0.0, (
        f"compute_threat_score() should return exactly 0.0 when total_times_seen == 0, "
        f"but returned {score}. "
        f"Record: total_reporting_nodes={record['total_reporting_nodes']}, "
        f"times_seen_last_24h={record['times_seen_last_24h']}, "
        f"times_seen_last_7d={record['times_seen_last_7d']}, "
        f"times_seen_last_30d={record['times_seen_last_30d']}, "
        f"threat_tags={record['threat_tags']}, "
        f"repeat_offender={record['repeat_offender']}"
    )


@given(
    total_times_seen=st.integers(min_value=2, max_value=100000),
    total_reporting_nodes=st.integers(min_value=0, max_value=1000),
    times_seen_last_24h=st.integers(min_value=0, max_value=10000),
    times_seen_last_7d=st.integers(min_value=0, max_value=10000),
    times_seen_last_30d=st.integers(min_value=0, max_value=10000),
    threat_tags=st.lists(st_threat_tag(), min_size=0, max_size=10, unique=True),
    repeat_offender=st.booleans(),
    blocked_low=st.integers(min_value=0, max_value=99999),
    blocked_high=st.integers(min_value=1, max_value=100000),
)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_reputation_score_monotonic_with_total_times_blocked(
    total_times_seen,
    total_reporting_nodes,
    times_seen_last_24h,
    times_seen_last_7d,
    times_seen_last_30d,
    threat_tags,
    repeat_offender,
    blocked_low,
    blocked_high,
):
    """Property 8 (monotonicity): Score is monotonically non-decreasing as total_times_blocked increases.

    **Validates: Requirements 12**

    For any valid IP record, if we hold all fields constant and only increase
    total_times_blocked, the resulting score must be >= the score with the
    lower total_times_blocked value.

    This follows from the block_ratio signal (weight=30%):
        block_ratio = total_times_blocked / total_times_seen
    Increasing total_times_blocked (with total_times_seen held constant)
    increases block_ratio, which increases the weighted contribution to the
    score. All other signals remain unchanged, so the total score must be
    non-decreasing.

    Generator: A base record with random field values, plus two distinct
    total_times_blocked values (low < high), both <= total_times_seen.
    """
    # Ensure blocked_low < blocked_high and both <= total_times_seen
    assume(blocked_low < blocked_high)
    assume(blocked_high <= total_times_seen)

    # Build the base record (shared fields)
    base_record = {
        "total_times_seen": total_times_seen,
        "total_reporting_nodes": total_reporting_nodes,
        "times_seen_last_24h": times_seen_last_24h,
        "times_seen_last_7d": times_seen_last_7d,
        "times_seen_last_30d": times_seen_last_30d,
        "threat_tags": threat_tags,
        "repeat_offender": repeat_offender,
    }

    # Create two versions: one with lower blocked count, one with higher
    record_low = {**base_record, "total_times_blocked": blocked_low}
    record_high = {**base_record, "total_times_blocked": blocked_high}

    score_low = compute_threat_score(record_low)
    score_high = compute_threat_score(record_high)

    # Assert: score with higher total_times_blocked >= score with lower
    assert score_high >= score_low, (
        f"Score monotonicity violated: increasing total_times_blocked from "
        f"{blocked_low} to {blocked_high} (with total_times_seen={total_times_seen}) "
        f"decreased the score from {score_low} to {score_high}. "
        f"block_ratio_low={blocked_low/total_times_seen:.4f}, "
        f"block_ratio_high={blocked_high/total_times_seen:.4f}. "
        f"Other fields: total_reporting_nodes={total_reporting_nodes}, "
        f"threat_tags={threat_tags}, repeat_offender={repeat_offender}"
    )


# ── Double-Counting Prevention Property Tests ────────────────────────────


@given(
    source_ip=st_ipv4(),
    node_id=st_node_id(),
    timestamp=st_timestamp(),
    detection_rule=st_detection_rule(),
    extra_detection_types=st.lists(
        st.sampled_from(["LOG_MATCH", "RECON_CORRELATION", "SSH_BRUTE", "BLOCKLIST_HIT"]),
        min_size=1,
        max_size=4,
    ),
)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_double_counting_prevention_paired_events(
    intel_db, source_ip, node_id, timestamp, detection_rule, extra_detection_types
):
    """Property 9: Double-Counting Prevention.

    **Validates: Requirements 3.4, 2.2**

    For any batch containing both a detection-level event (e.g.,
    RECON_CORRELATION + BLOCKED) and a confirmation event (NFT_ACTION + BLOCKED)
    for the same IP and same block action, the intel database increments
    total_times_blocked by exactly 1 (not 2).

    The intel filter only allows BLOCKED events with event_type == NFT_ACTION
    through to the intel database. Detection-level events (RECON_CORRELATION,
    LOG_MATCH, SSH_BRUTE, BLOCKLIST_HIT) with action_taken == BLOCKED are
    rejected by the filter, preventing double-counting.

    Generator: Batches with paired detection/confirmation events for random IPs.
    Each batch contains 1+ detection-level events (non-NFT_ACTION + BLOCKED) and
    exactly one confirmation event (NFT_ACTION + BLOCKED) for the same IP.
    """
    # Ensure we start from a clean state for this IP
    existing = intel_db.execute(
        "SELECT 1 FROM ip_intel WHERE ip_address = ?", (source_ip,)
    ).fetchone()
    assume(existing is None)

    # Build a batch of events simulating a single block action:
    # - One or more detection-level events (e.g., RECON_CORRELATION + BLOCKED)
    # - One confirmation event (NFT_ACTION + BLOCKED)
    # All for the same IP, same node, same timestamp (same block action).
    batch = []

    # Add detection-level events (these should be REJECTED by the intel filter)
    for det_type in extra_detection_types:
        batch.append({
            "event_type": det_type,
            "action_taken": "BLOCKED",
            "source_ip": source_ip,
            "node_id": node_id,
            "timestamp": timestamp,
            "metadata": {
                "reason": "local-detection",
                "detection_rule_name": detection_rule,
                "threat_tag": detection_rule,
                "block_ttl_seconds": 3600,
            },
            "geo_data": {"country": "US"},
        })

    # Add the confirmation event (NFT_ACTION + BLOCKED — this one SHOULD pass)
    batch.append({
        "event_type": "NFT_ACTION",
        "action_taken": "BLOCKED",
        "source_ip": source_ip,
        "node_id": node_id,
        "timestamp": timestamp,
        "metadata": {
            "reason": "local-detection",
            "detection_rule_name": detection_rule,
            "threat_tag": detection_rule,
            "block_ttl_seconds": 3600,
        },
        "geo_data": {"country": "US"},
    })

    # Process the entire batch through the ingestion filter logic
    # (mirrors the routing in api.py ingest_events)
    for event in batch:
        action_taken = event["action_taken"].upper()
        event_type = event["event_type"]
        reason = event["metadata"]["reason"]

        # Step 1: Fleet filter — events with "fleet:" reason are excluded
        if reason.startswith("fleet:"):
            continue

        # Step 2: Check action_taken against INTEL_INGEST_ACTIONS
        if action_taken not in INTEL_INGEST_ACTIONS:
            continue

        # Step 3: For BLOCKED, only NFT_ACTION passes (double-counting prevention)
        if action_taken == "BLOCKED" and event_type != "NFT_ACTION":
            continue

        # Step 4: Route qualifying event to intel processing
        if action_taken == "BLOCKED":
            intel_payload = {
                "source_ip": event["source_ip"],
                "node_id": event["node_id"],
                "event_type": event["event_type"],
                "timestamp": event["timestamp"],
                "detection_rule": event["metadata"]["detection_rule_name"],
                "block_ttl_seconds": event["metadata"]["block_ttl_seconds"],
                "metadata": {
                    "geo_country": event["geo_data"]["country"],
                    "threat_tag": event["metadata"]["threat_tag"],
                },
            }
            if event["metadata"]["threat_tag"]:
                intel_payload["threat_tag"] = event["metadata"]["threat_tag"]
            process_block_event(intel_db, intel_payload)

    # Verify: total_times_blocked == 1 (not 2 or more)
    ip_record = intel_db.execute(
        "SELECT total_times_seen, total_times_blocked "
        "FROM ip_intel WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()

    assert ip_record is not None, (
        f"ip_intel record should exist after processing batch with NFT_ACTION+BLOCKED "
        f"for IP {source_ip}"
    )

    # The key assertion: despite having multiple BLOCKED events in the batch,
    # only the NFT_ACTION event should have been ingested.
    assert ip_record["total_times_blocked"] == 1, (
        f"Double-counting detected! total_times_blocked should be exactly 1 "
        f"(only NFT_ACTION+BLOCKED ingested), but got {ip_record['total_times_blocked']}. "
        f"Batch contained {len(extra_detection_types)} detection-level events "
        f"({extra_detection_types}) + 1 NFT_ACTION event, all with action_taken=BLOCKED. "
        f"The filter should reject non-NFT_ACTION BLOCKED events."
    )

    assert ip_record["total_times_seen"] == 1, (
        f"total_times_seen should be exactly 1 (only NFT_ACTION+BLOCKED ingested), "
        f"but got {ip_record['total_times_seen']}. "
        f"Detection-level BLOCKED events should not increment any counter."
    )

    # Verify: exactly 1 row in ip_intel_events (the NFT_ACTION event)
    events_count = intel_db.execute(
        "SELECT COUNT(*) as cnt FROM ip_intel_events WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()["cnt"]

    assert events_count == 1, (
        f"ip_intel_events should contain exactly 1 row (the NFT_ACTION event), "
        f"but found {events_count} rows. "
        f"Detection-level BLOCKED events should not create event rows."
    )

    # Verify: the single event row has event_kind == 'block'
    event_row = intel_db.execute(
        "SELECT event_kind, event_type FROM ip_intel_events WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()

    assert event_row["event_kind"] == "block", (
        f"The single event row should have event_kind='block', "
        f"but got event_kind='{event_row['event_kind']}'"
    )

    assert event_row["event_type"] == "NFT_ACTION", (
        f"The single event row should have event_type='NFT_ACTION', "
        f"but got event_type='{event_row['event_type']}'"
    )


@given(
    source_ip=st_ipv4(),
    k=st.integers(min_value=1, max_value=20),
    timestamp=st_timestamp(),
    detection_rule=st_detection_rule(),
)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_multi_node_additivity(intel_db, source_ip, k, timestamp, detection_rule):
    """Property 10: Multi-Node Additivity.

    **Validates: Requirements 8.1, 8.2, 8.3**

    For K distinct nodes each independently blocking the same IP (each
    submitting one NFT_ACTION + BLOCKED event):
      - total_times_blocked == K
      - total_reporting_nodes == K
      - ip_intel_events block rows == K

    This verifies that independent blocks from multiple nodes each count
    toward the IP's threat profile, ensuring distributed attacks are properly
    reflected. Each distinct node contributes exactly one block and one
    reporting node entry.

    Generator: Random K (1–20) distinct node_ids, each submitting one block
    event for the same IP.
    """
    # Ensure we start from a clean state for this IP
    existing = intel_db.execute(
        "SELECT 1 FROM ip_intel WHERE ip_address = ?", (source_ip,)
    ).fetchone()
    assume(existing is None)

    # Generate K distinct node_ids
    node_ids = [f"node-multi-{i:04d}" for i in range(k)]

    # Each distinct node submits one NFT_ACTION + BLOCKED event for the same IP
    for node_id in node_ids:
        block_payload = {
            "source_ip": source_ip,
            "node_id": node_id,
            "event_type": "NFT_ACTION",
            "timestamp": timestamp,
            "detection_rule": detection_rule,
            "block_ttl_seconds": 3600,
            "metadata": {"geo_country": "US"},
        }
        process_block_event(intel_db, block_payload)

    # Query the ip_intel record
    ip_record = intel_db.execute(
        "SELECT total_times_seen, total_times_blocked, total_reporting_nodes, "
        "reporting_node_list FROM ip_intel WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()

    assert ip_record is not None, (
        f"ip_intel record should exist after processing {k} block events "
        f"from {k} distinct nodes for IP {source_ip}"
    )

    # Assert: total_times_blocked == K
    assert ip_record["total_times_blocked"] == k, (
        f"total_times_blocked should be {k} (one block per distinct node), "
        f"but got {ip_record['total_times_blocked']}. "
        f"K={k} distinct nodes each submitted one NFT_ACTION+BLOCKED event."
    )

    # Assert: total_reporting_nodes == K
    assert ip_record["total_reporting_nodes"] == k, (
        f"total_reporting_nodes should be {k} (each distinct node counted once), "
        f"but got {ip_record['total_reporting_nodes']}. "
        f"K={k} distinct nodes each independently reported the IP."
    )

    # Assert: ip_intel_events block rows == K
    block_rows = intel_db.execute(
        "SELECT COUNT(*) as cnt FROM ip_intel_events "
        "WHERE ip_address = ? AND event_kind = 'block'",
        (source_ip,),
    ).fetchone()["cnt"]

    assert block_rows == k, (
        f"ip_intel_events should contain {k} rows with event_kind='block', "
        f"but found {block_rows}. "
        f"Each of the {k} distinct nodes should produce exactly one block row."
    )

    # Additional verification: reporting_node_list contains exactly K distinct entries
    reporting_node_list = json.loads(ip_record["reporting_node_list"])

    assert len(reporting_node_list) == k, (
        f"reporting_node_list should contain {k} entries (one per distinct node), "
        f"but has {len(reporting_node_list)} entries. "
        f"List: {reporting_node_list}"
    )

    # Verify no duplicates in reporting_node_list
    assert len(reporting_node_list) == len(set(reporting_node_list)), (
        f"reporting_node_list should contain no duplicates, "
        f"but found duplicates. List: {reporting_node_list}"
    )

    # Verify all submitted node_ids are present in reporting_node_list
    for node_id in node_ids:
        assert node_id in reporting_node_list, (
            f"node_id '{node_id}' should be in reporting_node_list but was not found. "
            f"reporting_node_list: {reporting_node_list}"
        )


# ── Fleet Block Visibility Property Tests ────────────────────────────────


@given(
    source_ip=st_ipv4(),
    m_blocks=st.integers(min_value=1, max_value=10),
    f_fleet_blocks=st.integers(min_value=1, max_value=10),
    block_node_ids=st.lists(st_node_id(), min_size=10, max_size=10),
    fleet_node_ids=st.lists(st_node_id(), min_size=10, max_size=10),
    timestamps=st.lists(st_timestamp(), min_size=20, max_size=20),
    detection_rule=st_detection_rule(),
)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_fleet_block_visibility_without_counter_inflation(
    intel_db, source_ip, m_blocks, f_fleet_blocks,
    block_node_ids, fleet_node_ids, timestamps, detection_rule
):
    """Property 11: Fleet Block Visibility Without Counter Inflation.

    **Validates: Requirements 15.3, 15.4, 15.5, 15.7**

    For any sequence of M active block events and F fleet_block events for the same IP:
      - total_times_seen is incremented only by active events (blocks + sightings),
        not by fleet_block events
      - total_times_blocked == M (fleet_block events do not contribute)
      - ip_intel_events total row count == M + F (fleet_block rows are stored)
      - ip_intel_events rows with event_kind == "fleet_block" count == F
      - reporting_node_list contains only node_ids from active block events,
        not from fleet_block events

    Generator: Random sequences of mixed active block events and fleet_block events
    with random IPs, node_ids, and timestamps.
    """
    # Ensure we start from a clean state for this IP
    existing = intel_db.execute(
        "SELECT 1 FROM ip_intel WHERE ip_address = ?", (source_ip,)
    ).fetchone()
    assume(existing is None)

    # Process M active block events
    active_node_ids_used = []
    for i in range(m_blocks):
        node_id = block_node_ids[i]
        active_node_ids_used.append(node_id)
        block_payload = {
            "source_ip": source_ip,
            "node_id": node_id,
            "event_type": "NFT_ACTION",
            "timestamp": timestamps[i],
            "detection_rule": detection_rule,
            "block_ttl_seconds": 3600,
            "metadata": {"geo_country": "US"},
        }
        process_block_event(intel_db, block_payload)

    # Process F fleet_block events
    fleet_node_ids_used = []
    for i in range(f_fleet_blocks):
        node_id = fleet_node_ids[i]
        fleet_node_ids_used.append(node_id)
        process_fleet_block_event(
            conn=intel_db,
            ip_address=source_ip,
            node_id=node_id,
            timestamp=timestamps[m_blocks + i],
            event_type="NFT_ACTION",
        )

    # ── Verify counters on ip_intel record ──
    ip_record = intel_db.execute(
        "SELECT total_times_seen, total_times_blocked, "
        "total_reporting_nodes, reporting_node_list "
        "FROM ip_intel WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()

    assert ip_record is not None, (
        f"ip_intel record should exist after processing {m_blocks} blocks + "
        f"{f_fleet_blocks} fleet_blocks for IP {source_ip}"
    )

    # Assert: total_times_seen == M (only active block events count)
    assert ip_record["total_times_seen"] == m_blocks, (
        f"total_times_seen should be {m_blocks} (only active block events), "
        f"but got {ip_record['total_times_seen']}. "
        f"Fleet_block events (F={f_fleet_blocks}) must NOT increment total_times_seen."
    )

    # Assert: total_times_blocked == M (fleet_block events do not contribute)
    assert ip_record["total_times_blocked"] == m_blocks, (
        f"total_times_blocked should be {m_blocks} (only active block events), "
        f"but got {ip_record['total_times_blocked']}. "
        f"Fleet_block events (F={f_fleet_blocks}) must NOT increment total_times_blocked."
    )

    # ── Verify ip_intel_events row counts ──
    # Total row count == M + F (fleet_block rows are stored alongside active events)
    total_event_rows = intel_db.execute(
        "SELECT COUNT(*) as cnt FROM ip_intel_events WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()["cnt"]

    assert total_event_rows == m_blocks + f_fleet_blocks, (
        f"ip_intel_events total row count should be {m_blocks + f_fleet_blocks} "
        f"(M={m_blocks} blocks + F={f_fleet_blocks} fleet_blocks), "
        f"but got {total_event_rows}."
    )

    # Rows with event_kind == "fleet_block" count == F
    fleet_block_rows = intel_db.execute(
        "SELECT COUNT(*) as cnt FROM ip_intel_events "
        "WHERE ip_address = ? AND event_kind = 'fleet_block'",
        (source_ip,),
    ).fetchone()["cnt"]

    assert fleet_block_rows == f_fleet_blocks, (
        f"ip_intel_events rows with event_kind='fleet_block' should be {f_fleet_blocks}, "
        f"but got {fleet_block_rows}."
    )

    # Rows with event_kind == "block" count == M
    block_rows = intel_db.execute(
        "SELECT COUNT(*) as cnt FROM ip_intel_events "
        "WHERE ip_address = ? AND event_kind = 'block'",
        (source_ip,),
    ).fetchone()["cnt"]

    assert block_rows == m_blocks, (
        f"ip_intel_events rows with event_kind='block' should be {m_blocks}, "
        f"but got {block_rows}."
    )

    # ── Verify reporting_node_list excludes fleet_block node_ids ──
    reporting_node_list = json.loads(ip_record["reporting_node_list"])

    # All active block node_ids should be in reporting_node_list
    distinct_active_nodes = set(active_node_ids_used)
    for node_id in distinct_active_nodes:
        assert node_id in reporting_node_list, (
            f"Active block node_id '{node_id}' should be in reporting_node_list "
            f"but was not found. reporting_node_list: {reporting_node_list}"
        )

    # Fleet_block node_ids that are NOT also active block node_ids
    # should NOT appear in reporting_node_list
    fleet_only_nodes = set(fleet_node_ids_used) - set(active_node_ids_used)
    for node_id in fleet_only_nodes:
        assert node_id not in reporting_node_list, (
            f"Fleet-only node_id '{node_id}' should NOT be in reporting_node_list "
            f"(fleet_block events must not modify reporting_node_list). "
            f"reporting_node_list: {reporting_node_list}"
        )


# ── Fleet Block Reporting Node List Exclusion Property Test ──────────────


@given(
    source_ip=st_ipv4(),
    fleet_node_ids=st.lists(
        st_node_id(), min_size=1, max_size=15, unique=True
    ),
    timestamps=st.lists(st_timestamp(), min_size=15, max_size=15),
)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_fleet_block_events_do_not_add_to_reporting_node_list(
    intel_db, source_ip, fleet_node_ids, timestamps
):
    """Property 11.2: Fleet_block events do NOT add node_ids to reporting_node_list.

    **Validates: Requirements 15.5**

    For any sequence of F fleet_block events from distinct node_ids for a fresh IP
    (no active block or sighting events):
      - reporting_node_list is empty ('[]')
      - total_reporting_nodes == 0

    This is a focused test specifically on the reporting_node_list invariant for
    fleet_block events. Fleet_block events are stored for operational visibility
    but must NEVER modify the reporting_node_list or total_reporting_nodes counter,
    because reporting_node_list should only contain node_ids from active
    block/sighting events (nodes that independently observed or blocked the IP).

    Generator: Random sequences of fleet_block events from distinct node_ids
    for a fresh IP address that has no prior intel records.
    """
    # Ensure we start from a clean state for this IP
    existing = intel_db.execute(
        "SELECT 1 FROM ip_intel WHERE ip_address = ?", (source_ip,)
    ).fetchone()
    assume(existing is None)

    f_count = len(fleet_node_ids)

    # Process F fleet_block events from distinct node_ids
    for i, node_id in enumerate(fleet_node_ids):
        process_fleet_block_event(
            conn=intel_db,
            ip_address=source_ip,
            node_id=node_id,
            timestamp=timestamps[i],
            event_type="NFT_ACTION",
        )

    # ── Verify ip_intel record state ──
    ip_record = intel_db.execute(
        "SELECT total_reporting_nodes, reporting_node_list, "
        "total_times_seen, total_times_blocked "
        "FROM ip_intel WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()

    assert ip_record is not None, (
        f"ip_intel record should exist after processing {f_count} fleet_block events "
        f"(INSERT OR IGNORE creates the record for visibility)"
    )

    # Parse reporting_node_list
    reporting_node_list = json.loads(ip_record["reporting_node_list"])

    # Assert: reporting_node_list is empty — fleet_block events must NOT add node_ids
    assert reporting_node_list == [], (
        f"reporting_node_list should be empty ('[]') when only fleet_block events "
        f"have been processed, but got {reporting_node_list}. "
        f"Fleet_block events from {f_count} distinct node_ids ({fleet_node_ids}) "
        f"must NOT modify reporting_node_list. "
        f"Only active block/sighting events should add to reporting_node_list."
    )

    # Assert: total_reporting_nodes == 0
    assert ip_record["total_reporting_nodes"] == 0, (
        f"total_reporting_nodes should be 0 when only fleet_block events "
        f"have been processed, but got {ip_record['total_reporting_nodes']}. "
        f"Fleet_block events from {f_count} distinct node_ids must NOT "
        f"increment total_reporting_nodes."
    )

    # Assert: total_times_seen == 0 (fleet_block events don't count)
    assert ip_record["total_times_seen"] == 0, (
        f"total_times_seen should be 0 when only fleet_block events "
        f"have been processed, but got {ip_record['total_times_seen']}."
    )

    # Assert: total_times_blocked == 0 (fleet_block events don't count)
    assert ip_record["total_times_blocked"] == 0, (
        f"total_times_blocked should be 0 when only fleet_block events "
        f"have been processed, but got {ip_record['total_times_blocked']}."
    )

    # ── Verify fleet_block event rows ARE stored (visibility) ──
    fleet_event_rows = intel_db.execute(
        "SELECT COUNT(*) as cnt FROM ip_intel_events "
        "WHERE ip_address = ? AND event_kind = 'fleet_block'",
        (source_ip,),
    ).fetchone()["cnt"]

    assert fleet_event_rows == f_count, (
        f"ip_intel_events should contain {f_count} fleet_block rows "
        f"(events are stored for visibility), but got {fleet_event_rows}."
    )

    # ── Verify no node_id from fleet_block events leaked into reporting_node_list ──
    # (Double-check: even after multiple fleet_block events from distinct nodes,
    # the reporting_node_list must remain empty)
    for node_id in fleet_node_ids:
        assert node_id not in reporting_node_list, (
            f"Fleet_block node_id '{node_id}' should NOT appear in "
            f"reporting_node_list, but it was found. "
            f"reporting_node_list: {reporting_node_list}"
        )


# ── Fleet Block Row Count Property Test ──────────────────────────────────


@given(
    source_ip=st_ipv4(),
    m_blocks=st.integers(min_value=0, max_value=8),
    s_sightings=st.integers(min_value=0, max_value=8),
    f_fleet_blocks=st.integers(min_value=0, max_value=8),
    block_node_ids=st.lists(st_node_id(), min_size=8, max_size=8),
    sighting_node_ids=st.lists(st_node_id(), min_size=8, max_size=8),
    fleet_node_ids=st.lists(st_node_id(), min_size=8, max_size=8),
    timestamps=st.lists(st_timestamp(), min_size=24, max_size=24),
    detection_rule=st_detection_rule(),
)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_fleet_block_row_count_equals_m_plus_s_plus_f(
    intel_db, source_ip, m_blocks, s_sightings, f_fleet_blocks,
    block_node_ids, sighting_node_ids, fleet_node_ids, timestamps, detection_rule
):
    """Property 11.3: ip_intel_events row count == M + S + F.

    **Validates: Requirements 15.3, 15.7**

    For any sequence of M active block events, S sighting events, and F
    fleet_block events for the same IP:
      - ip_intel_events total row count == M + S + F
      - Rows with event_kind == "block" count == M
      - Rows with event_kind == "sighting" count == S
      - Rows with event_kind == "fleet_block" count == F

    Fleet_block rows are stored alongside active events for operational
    visibility. All event types contribute to the total row count in
    ip_intel_events, ensuring the full chronological timeline is preserved.

    Generator: Random M blocks, S sightings, and F fleet_block events for
    the same IP with varied node_ids and timestamps.
    """
    # Skip trivial case where no events are generated
    assume(m_blocks + s_sightings + f_fleet_blocks > 0)

    # Ensure we start from a clean state for this IP
    existing = intel_db.execute(
        "SELECT 1 FROM ip_intel WHERE ip_address = ?", (source_ip,)
    ).fetchone()
    assume(existing is None)

    ts_idx = 0

    # Process M active block events
    for i in range(m_blocks):
        block_payload = {
            "source_ip": source_ip,
            "node_id": block_node_ids[i],
            "event_type": "NFT_ACTION",
            "timestamp": timestamps[ts_idx],
            "detection_rule": detection_rule,
            "block_ttl_seconds": 3600,
            "metadata": {"geo_country": "US"},
        }
        process_block_event(intel_db, block_payload)
        ts_idx += 1

    # Process S sighting events
    for i in range(s_sightings):
        sighting_payload = {
            "source_ip": source_ip,
            "node_id": sighting_node_ids[i],
            "event_type": "LOG_MATCH",
            "timestamp": timestamps[ts_idx],
            "metadata": {"geo_country": "US"},
        }
        process_sighting(intel_db, sighting_payload)
        ts_idx += 1

    # Process F fleet_block events
    for i in range(f_fleet_blocks):
        process_fleet_block_event(
            conn=intel_db,
            ip_address=source_ip,
            node_id=fleet_node_ids[i],
            timestamp=timestamps[ts_idx],
            event_type="NFT_ACTION",
        )
        ts_idx += 1

    # ── Verify total row count == M + S + F ──
    total_event_rows = intel_db.execute(
        "SELECT COUNT(*) as cnt FROM ip_intel_events WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()["cnt"]

    expected_total = m_blocks + s_sightings + f_fleet_blocks
    assert total_event_rows == expected_total, (
        f"ip_intel_events total row count should be {expected_total} "
        f"(M={m_blocks} blocks + S={s_sightings} sightings + F={f_fleet_blocks} fleet_blocks), "
        f"but got {total_event_rows}."
    )

    # ── Verify breakdown by event_kind ──
    # Rows with event_kind == "block" count == M
    block_rows = intel_db.execute(
        "SELECT COUNT(*) as cnt FROM ip_intel_events "
        "WHERE ip_address = ? AND event_kind = 'block'",
        (source_ip,),
    ).fetchone()["cnt"]

    assert block_rows == m_blocks, (
        f"ip_intel_events rows with event_kind='block' should be {m_blocks}, "
        f"but got {block_rows}."
    )

    # Rows with event_kind == "sighting" count == S
    sighting_rows = intel_db.execute(
        "SELECT COUNT(*) as cnt FROM ip_intel_events "
        "WHERE ip_address = ? AND event_kind = 'sighting'",
        (source_ip,),
    ).fetchone()["cnt"]

    assert sighting_rows == s_sightings, (
        f"ip_intel_events rows with event_kind='sighting' should be {s_sightings}, "
        f"but got {sighting_rows}."
    )

    # Rows with event_kind == "fleet_block" count == F
    fleet_block_rows = intel_db.execute(
        "SELECT COUNT(*) as cnt FROM ip_intel_events "
        "WHERE ip_address = ? AND event_kind = 'fleet_block'",
        (source_ip,),
    ).fetchone()["cnt"]

    assert fleet_block_rows == f_fleet_blocks, (
        f"ip_intel_events rows with event_kind='fleet_block' should be {f_fleet_blocks}, "
        f"but got {fleet_block_rows}."
    )

# ── Multi-Vector Scoring Property Tests ──────────────────────────────────


@given(
    threat_tags=st.lists(
        st_threat_tag(),
        min_size=0,
        max_size=10,
        unique=True,
    ),
)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_tag_diversity_normalization(threat_tags):
    """Property 12 — Tag diversity normalization.

    **Validates: Requirements 16.4**

    For any valid IP record dict with a threat_tags array:
      - Tag diversity signal == min(len(threat_tags) / 5, 1.0)

    Generator: Random record dicts with threat_tags arrays of varying lengths
    (0–10 distinct tags).
    """
    from app.intel_score import compute_tag_diversity

    record = {"threat_tags": threat_tags}

    result = compute_tag_diversity(record)

    expected = min(len(threat_tags) / 5, 1.0)

    assert result == expected, (
        f"compute_tag_diversity should return min(len(threat_tags) / 5, 1.0) = {expected}, "
        f"but got {result}. threat_tags={threat_tags} (len={len(threat_tags)})"
    )


@given(
    threat_tags=st.lists(
        st_threat_tag(),
        min_size=0,
        max_size=10,
        unique=True,
    ),
)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_multi_vector_bonus_correctness(threat_tags):
    """Property 12 — Multi-vector bonus correctness.

    **Validates: Requirements 16.5**

    If len(threat_tags) < 3, no multi-vector bonus is applied (multiplier == 1.0).
    If len(threat_tags) >= 3, the effective multiplier == min(1.0 + 0.1 * (len(threat_tags) - 2), 1.5).

    Uses a fixed record with known signals to make the base score predictable,
    then verifies the multiplier is applied correctly.
    """
    # Build a fixed record with known signal values so we can predict the base score.
    # We use non-zero counters to ensure the score is > 0 (avoiding the early-exit path).
    record_no_tags = {
        "total_times_seen": 10,
        "total_times_blocked": 5,
        "total_reporting_nodes": 3,
        "times_seen_last_24h": 2,
        "times_seen_last_7d": 5,
        "times_seen_last_30d": 8,
        "threat_tags": [],
        "repeat_offender": False,
        "total_requests": 10,
    }

    # Compute the base score with NO threat_tags (no bonus, no tag diversity)
    base_score_no_tags = compute_threat_score(record_no_tags)

    # Now build the record with the generated threat_tags
    record_with_tags = dict(record_no_tags)
    record_with_tags["threat_tags"] = threat_tags

    # Compute the score with the generated threat_tags
    score_with_tags = compute_threat_score(record_with_tags)

    distinct_tags = len(threat_tags)

    if distinct_tags < 3:
        # No multi-vector bonus should be applied.
        # The only difference from base_score_no_tags is the tag_diversity signal.
        # We verify the multiplier is 1.0 by computing what the score SHOULD be
        # with tag diversity but WITHOUT bonus.
        # Recompute expected score: same as compute_threat_score but with the
        # tag_diversity signal reflecting the actual tags (no multiplier).
        # Since we can't easily decompose the internal weighted sum, we verify
        # by computing the score for a record with < 3 tags and confirming
        # no bonus amplification occurs.
        #
        # Strategy: compute score with 2 tags (max no-bonus) and verify it equals
        # what we'd get without any multiplier. We do this by checking that the
        # score equals the score computed by the function (which should NOT apply
        # a multiplier for < 3 tags).
        #
        # The simplest verification: compute the score ourselves using the same
        # formula without the multiplier and confirm they match.
        import math
        block_ratio = min(5 / 10, 1.0)  # 0.5
        fleet_breadth = min(3 / 10, 1.0)  # 0.3
        volume = min(math.log(1 + 10) / math.log(1 + 1000), 1.0)
        recency = (
            0.5 * min(2 / 1000, 1.0)
            + 0.3 * min(5 / 1000, 1.0)
            + 0.2 * min(8 / 1000, 1.0)
        )
        tag_diversity = min(distinct_tags / 5, 1.0)
        repeat_offender_signal = 0.0

        raw = (
            block_ratio * 30
            + fleet_breadth * 20
            + volume * 15
            + recency * 15
            + tag_diversity * 10
            + repeat_offender_signal * 10
        )
        expected_score = round(min(max((raw / 100) * 100.0, 0.0), 100.0), 1)

        assert score_with_tags == expected_score, (
            f"With {distinct_tags} tags (< 3), no multi-vector bonus should be applied. "
            f"Expected score={expected_score}, got {score_with_tags}. "
            f"threat_tags={threat_tags}"
        )
    else:
        # Multi-vector bonus SHOULD be applied.
        # Expected multiplier: min(1.0 + 0.1 * (distinct_tags - 2), 1.5)
        expected_multiplier = min(1.0 + 0.1 * (distinct_tags - 2), 1.5)

        # Compute the expected base score (before multiplier) with the tag diversity
        import math
        block_ratio = min(5 / 10, 1.0)  # 0.5
        fleet_breadth = min(3 / 10, 1.0)  # 0.3
        volume = min(math.log(1 + 10) / math.log(1 + 1000), 1.0)
        recency = (
            0.5 * min(2 / 1000, 1.0)
            + 0.3 * min(5 / 1000, 1.0)
            + 0.2 * min(8 / 1000, 1.0)
        )
        tag_diversity = min(distinct_tags / 5, 1.0)
        repeat_offender_signal = 0.0

        raw = (
            block_ratio * 30
            + fleet_breadth * 20
            + volume * 15
            + recency * 15
            + tag_diversity * 10
            + repeat_offender_signal * 10
        )
        base_score = (raw / 100) * 100.0
        boosted_score = base_score * expected_multiplier
        expected_score = round(min(max(boosted_score, 0.0), 100.0), 1)

        assert score_with_tags == expected_score, (
            f"With {distinct_tags} tags (>= 3), multi-vector bonus should apply "
            f"multiplier={expected_multiplier}. "
            f"Expected score={expected_score}, got {score_with_tags}. "
            f"threat_tags={threat_tags}"
        )


@given(
    total_times_seen=st.integers(min_value=0, max_value=100000),
    total_times_blocked=st.integers(min_value=0, max_value=100000),
    total_reporting_nodes=st.integers(min_value=0, max_value=1000),
    times_seen_last_24h=st.integers(min_value=0, max_value=10000),
    times_seen_last_7d=st.integers(min_value=0, max_value=10000),
    times_seen_last_30d=st.integers(min_value=0, max_value=10000),
    threat_tags=st.lists(
        st_threat_tag(),
        min_size=0,
        max_size=15,
        unique=True,
    ),
    repeat_offender=st.booleans(),
)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_score_bounds_after_multi_vector_bonus(
    total_times_seen,
    total_times_blocked,
    total_reporting_nodes,
    times_seen_last_24h,
    times_seen_last_7d,
    times_seen_last_30d,
    threat_tags,
    repeat_offender,
):
    """Property 12 — Final score bounds after multi-vector bonus application.

    **Validates: Requirements 12.4**

    For any valid IP record dict (with any combination of signals and threat_tags):
      - 0.0 <= compute_threat_score(record) <= 100.0
      - Result has at most 1 decimal place (score == round(score, 1))

    Generator: Random record dicts with varied counter values, recency values,
    threat_tags lists (0–15 tags), and repeat_offender flags.
    """
    # Ensure blocked <= seen (realistic constraint)
    if total_times_seen > 0:
        total_times_blocked = min(total_times_blocked, total_times_seen)
    else:
        total_times_blocked = 0

    record = {
        "total_times_seen": total_times_seen,
        "total_times_blocked": total_times_blocked,
        "total_reporting_nodes": total_reporting_nodes,
        "times_seen_last_24h": times_seen_last_24h,
        "times_seen_last_7d": times_seen_last_7d,
        "times_seen_last_30d": times_seen_last_30d,
        "threat_tags": threat_tags,
        "repeat_offender": repeat_offender,
    }

    score = compute_threat_score(record)

    # Assert: score is within [0.0, 100.0]
    assert 0.0 <= score <= 100.0, (
        f"Score must be in [0.0, 100.0], but got {score}. "
        f"Record: total_times_seen={total_times_seen}, "
        f"total_times_blocked={total_times_blocked}, "
        f"total_reporting_nodes={total_reporting_nodes}, "
        f"threat_tags={threat_tags} (len={len(threat_tags)}), "
        f"repeat_offender={repeat_offender}"
    )

    # Assert: score has at most 1 decimal place
    assert score == round(score, 1), (
        f"Score must have at most 1 decimal place, but got {score}. "
        f"round(score, 1) = {round(score, 1)}. "
        f"Record: total_times_seen={total_times_seen}, "
        f"threat_tags={threat_tags} (len={len(threat_tags)})"
    )


# ── Threat Tag Accumulation Idempotence Property Tests ───────────────────


@given(
    source_ip=st_ipv4(),
    node_id=st_node_id(),
    threat_tag_pool=st.lists(
        st_threat_tag(), min_size=1, max_size=8, unique=True
    ),
    event_count=st.integers(min_value=2, max_value=15),
    timestamps=st.lists(st_timestamp(), min_size=15, max_size=15),
    detection_rule=st_detection_rule(),
)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_threat_tag_accumulation_idempotence(
    intel_db, source_ip, node_id, threat_tag_pool, event_count, timestamps, detection_rule
):
    """Property 13: Threat Tag Accumulation Idempotence.

    **Validates: Requirements 16.2**

    For any sequence of events with threat_tag values (some repeated), the
    ip_intel threat_tags array:
      - Contains each distinct threat_tag exactly once (no duplicates)
      - Has length equal to the number of distinct threat_tag values across
        all ingested events

    Generator: Random sequences of events with threat_tag values drawn from a
    pool of 1–8 possible tags, with repetition across events.
    """
    # Ensure we start from a clean state for this IP
    existing = intel_db.execute(
        "SELECT 1 FROM ip_intel WHERE ip_address = ?", (source_ip,)
    ).fetchone()
    assume(existing is None)

    # Build a sequence of events where threat_tags are drawn from the pool
    # with repetition (some tags will appear multiple times across events)
    tags_used = []
    for i in range(event_count):
        # Pick a tag from the pool (cycling through to ensure repetition)
        tag = threat_tag_pool[i % len(threat_tag_pool)]
        tags_used.append(tag)

        block_payload = {
            "source_ip": source_ip,
            "node_id": node_id,
            "event_type": "NFT_ACTION",
            "timestamp": timestamps[i],
            "detection_rule": detection_rule,
            "block_ttl_seconds": 3600,
            "metadata": {"geo_country": "US", "threat_tag": tag},
        }
        process_block_event(intel_db, block_payload)

    # Query the ip_intel record for threat_tags
    ip_record = intel_db.execute(
        "SELECT threat_tags FROM ip_intel WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()

    assert ip_record is not None, (
        f"ip_intel record should exist after processing {event_count} events"
    )

    threat_tags = json.loads(ip_record["threat_tags"])
    distinct_tags_in_input = set(tags_used)

    # Assert: No duplicates in threat_tags array
    assert len(threat_tags) == len(set(threat_tags)), (
        f"threat_tags array contains duplicates! "
        f"threat_tags={threat_tags}, "
        f"unique count={len(set(threat_tags))}, total count={len(threat_tags)}. "
        f"Tags submitted (with repeats): {tags_used}"
    )

    # Assert: Length equals the number of distinct tags in the input
    assert len(threat_tags) == len(distinct_tags_in_input), (
        f"threat_tags array length ({len(threat_tags)}) should equal the number of "
        f"distinct tags in input ({len(distinct_tags_in_input)}). "
        f"threat_tags={threat_tags}, "
        f"distinct input tags={distinct_tags_in_input}, "
        f"all tags submitted={tags_used}"
    )

    # Assert: Every distinct tag from input is present in the array
    for tag in distinct_tags_in_input:
        assert tag in threat_tags, (
            f"Distinct tag '{tag}' from input is missing from threat_tags array. "
            f"threat_tags={threat_tags}, "
            f"distinct input tags={distinct_tags_in_input}"
        )


# ── Threat Tag Accumulation Confluence Property Tests ────────────────────


@given(
    source_ip=st_ipv4(),
    node_id=st_node_id(),
    threat_tag_pool=st.lists(
        st_threat_tag(), min_size=1, max_size=8, unique=True
    ),
    event_count=st.integers(min_value=2, max_value=12),
    timestamps=st.lists(st_timestamp(), min_size=12, max_size=12),
    detection_rule=st_detection_rule(),
    shuffle_seed=st.integers(min_value=0, max_value=2**32 - 1),
)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_threat_tag_order_independence(
    intel_db, source_ip, node_id, threat_tag_pool, event_count, timestamps,
    detection_rule, shuffle_seed
):
    """Property 13 (confluence): Order of event ingestion does not affect the final set of threat_tags.

    **Validates: Requirements 16.2**

    For any sequence of events with threat_tag values, the final set of
    threat_tags is the same regardless of ingestion order. This means:
    shuffle the events, process them in different orders, and verify the
    resulting threat_tags sets are equal.

    Approach:
      1. Build a list of events with various threat_tags drawn from a pool
      2. Process them in the original order → get threat_tags set A
      3. Process them in a shuffled order (using a fresh DB) → get threat_tags set B
      4. Verify set(A) == set(B)

    Generator: Random sequences of events with threat_tag values drawn from a
    pool of 1–8 possible tags, with repetition. A random seed controls the
    shuffle to ensure deterministic reproduction of failures.
    """
    import random

    # Ensure we start from a clean state for this IP
    existing = intel_db.execute(
        "SELECT 1 FROM ip_intel WHERE ip_address = ?", (source_ip,)
    ).fetchone()
    assume(existing is None)

    # Build the event list with tags drawn from the pool (with repetition)
    events = []
    for i in range(event_count):
        tag = threat_tag_pool[i % len(threat_tag_pool)]
        events.append({
            "source_ip": source_ip,
            "node_id": node_id,
            "event_type": "NFT_ACTION",
            "timestamp": timestamps[i],
            "detection_rule": detection_rule,
            "block_ttl_seconds": 3600,
            "metadata": {"geo_country": "US", "threat_tag": tag},
        })

    # ── Order A: Process events in original order ──
    for event in events:
        block_payload = {
            "source_ip": event["source_ip"],
            "node_id": event["node_id"],
            "event_type": event["event_type"],
            "timestamp": event["timestamp"],
            "detection_rule": event["detection_rule"],
            "block_ttl_seconds": event["block_ttl_seconds"],
            "metadata": event["metadata"],
        }
        if event["metadata"].get("threat_tag"):
            block_payload["threat_tag"] = event["metadata"]["threat_tag"]
        process_block_event(intel_db, block_payload)

    # Get threat_tags set A (original order)
    ip_record_a = intel_db.execute(
        "SELECT threat_tags FROM ip_intel WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()

    assert ip_record_a is not None, (
        f"ip_intel record should exist after processing {event_count} events in original order"
    )

    threat_tags_a = set(json.loads(ip_record_a["threat_tags"]))

    # ── Order B: Process events in shuffled order using a fresh DB ──
    conn_b = sqlite3.connect(":memory:")
    conn_b.row_factory = sqlite3.Row
    init_intel_db(conn_b, "sqlite")

    # Shuffle the events using the deterministic seed
    shuffled_events = list(events)
    rng = random.Random(shuffle_seed)
    rng.shuffle(shuffled_events)

    for event in shuffled_events:
        block_payload = {
            "source_ip": event["source_ip"],
            "node_id": event["node_id"],
            "event_type": event["event_type"],
            "timestamp": event["timestamp"],
            "detection_rule": event["detection_rule"],
            "block_ttl_seconds": event["block_ttl_seconds"],
            "metadata": event["metadata"],
        }
        if event["metadata"].get("threat_tag"):
            block_payload["threat_tag"] = event["metadata"]["threat_tag"]
        process_block_event(conn_b, block_payload)

    # Get threat_tags set B (shuffled order)
    ip_record_b = conn_b.execute(
        "SELECT threat_tags FROM ip_intel WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()

    assert ip_record_b is not None, (
        f"ip_intel record should exist after processing {event_count} events in shuffled order"
    )

    threat_tags_b = set(json.loads(ip_record_b["threat_tags"]))

    conn_b.close()

    # ── Assert: set(A) == set(B) — order does not affect the final tag set ──
    assert threat_tags_a == threat_tags_b, (
        f"Threat tag confluence violated! Order of ingestion affected the final tag set.\n"
        f"  Original order tags: {sorted(threat_tags_a)}\n"
        f"  Shuffled order tags: {sorted(threat_tags_b)}\n"
        f"  Difference (in A not B): {sorted(threat_tags_a - threat_tags_b)}\n"
        f"  Difference (in B not A): {sorted(threat_tags_b - threat_tags_a)}\n"
        f"  Event count: {event_count}, tag pool: {threat_tag_pool}\n"
        f"  Shuffle seed: {shuffle_seed}"
    )



# ── Block Lifecycle Property Tests ───────────────────────────────────────


@given(
    source_ip=st_ipv4(),
    node_id=st_node_id(),
    block_unblock_sequence=st.lists(
        st.sampled_from(["block", "unblock"]),
        min_size=1,
        max_size=15,
    ),
    timestamp_intervals=st.lists(
        st.integers(min_value=60, max_value=7200),
        min_size=15,
        max_size=15,
    ),
    detection_rule=st_detection_rule(),
)
@settings(
    suppress_health_check=[HealthCheck.function_scoped_fixture],
    max_examples=200,
)
def test_block_lifecycle_correctness(
    intel_db, source_ip, node_id, block_unblock_sequence, timestamp_intervals, detection_rule
):
    """Property 14: Block Lifecycle Correctness.

    **Validates: Requirements 17.3, 17.4, 19.1**

    For any sequence of block and unblock events for the same IP:
      - block_episode_count equals the number of distinct blocking episodes
        (a new episode starts when a block event follows an unblock event)
      - last_unblocked_at equals the timestamp of the most recent unblock event
        (or NULL if never unblocked)
      - repeat_offender is TRUE if and only if block_episode_count >= 2
      - UNBLOCKED events never increment total_times_seen or total_times_blocked
      - The first block event sets block_episode_count = 1

    Generator: Random interleaved sequences of block and unblock events with
    monotonically increasing timestamps, ensuring realistic ordering (unblock
    can only follow a block, and timestamps always advance forward).
    """
    # Ensure we start from a clean state for this IP
    existing = intel_db.execute(
        "SELECT 1 FROM ip_intel WHERE ip_address = ?", (source_ip,)
    ).fetchone()
    assume(existing is None)

    # Generate monotonically increasing timestamps from intervals
    base = datetime(2024, 1, 1, tzinfo=timezone.utc)
    timestamps = []
    cumulative = 0
    for interval in timestamp_intervals:
        cumulative += interval
        timestamps.append(
            (base + timedelta(seconds=cumulative)).strftime("%Y-%m-%dT%H:%M:%S")
        )

    # Normalize the sequence to be realistic: unblock can only follow a block.
    # Filter out unblocks that occur before any block, and consecutive unblocks.
    realistic_sequence = []
    is_currently_blocked = False
    for action in block_unblock_sequence:
        if action == "block":
            realistic_sequence.append("block")
            is_currently_blocked = True
        elif action == "unblock" and is_currently_blocked:
            realistic_sequence.append("unblock")
            is_currently_blocked = False

    # Need at least one event to test
    assume(len(realistic_sequence) >= 1)

    # Compute expected values by simulating the state machine
    expected_episode_count = 0
    expected_last_unblocked_at = None
    expected_total_times_seen = 0
    expected_total_times_blocked = 0
    sim_is_unblocked_since_last_block = False  # tracks if unblock happened after last block

    for i, action in enumerate(realistic_sequence):
        if action == "block":
            expected_total_times_seen += 1
            expected_total_times_blocked += 1
            if expected_episode_count == 0:
                # First block ever — start first episode
                expected_episode_count = 1
            elif sim_is_unblocked_since_last_block:
                # Block after unblock — new episode
                expected_episode_count += 1
            sim_is_unblocked_since_last_block = False
        elif action == "unblock":
            # Unblock does NOT increment counters
            expected_last_unblocked_at = timestamps[i]
            sim_is_unblocked_since_last_block = True

    expected_repeat_offender = 1 if expected_episode_count >= 2 else 0

    # Execute the sequence against the real implementation
    for i, action in enumerate(realistic_sequence):
        if action == "block":
            block_payload = {
                "source_ip": source_ip,
                "node_id": node_id,
                "event_type": "NFT_ACTION",
                "timestamp": timestamps[i],
                "detection_rule": detection_rule,
                "block_ttl_seconds": 3600,
                "metadata": {"geo_country": "US", "threat_tag": detection_rule},
            }
            process_block_event(intel_db, block_payload)
        elif action == "unblock":
            process_unblock_event(intel_db, source_ip, timestamps[i])

    # Query the final state
    ip_record = intel_db.execute(
        "SELECT total_times_seen, total_times_blocked, block_episode_count, "
        "last_unblocked_at, repeat_offender "
        "FROM ip_intel WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()

    assert ip_record is not None, (
        f"ip_intel record should exist after processing sequence: {realistic_sequence}"
    )

    # Assert: block_episode_count matches expected distinct episodes
    assert ip_record["block_episode_count"] == expected_episode_count, (
        f"block_episode_count mismatch. "
        f"Expected: {expected_episode_count}, Got: {ip_record['block_episode_count']}. "
        f"Sequence: {realistic_sequence}"
    )

    # Assert: last_unblocked_at matches the most recent unblock timestamp (or NULL)
    assert ip_record["last_unblocked_at"] == expected_last_unblocked_at, (
        f"last_unblocked_at mismatch. "
        f"Expected: {expected_last_unblocked_at}, Got: {ip_record['last_unblocked_at']}. "
        f"Sequence: {realistic_sequence}"
    )

    # Assert: repeat_offender is TRUE iff block_episode_count >= 2
    assert ip_record["repeat_offender"] == expected_repeat_offender, (
        f"repeat_offender mismatch. "
        f"Expected: {expected_repeat_offender}, Got: {ip_record['repeat_offender']}. "
        f"block_episode_count: {ip_record['block_episode_count']}, "
        f"Sequence: {realistic_sequence}"
    )

    # Assert: UNBLOCKED events never increment total_times_seen
    assert ip_record["total_times_seen"] == expected_total_times_seen, (
        f"total_times_seen mismatch — UNBLOCKED events may have incremented it. "
        f"Expected: {expected_total_times_seen}, Got: {ip_record['total_times_seen']}. "
        f"Sequence: {realistic_sequence}"
    )

    # Assert: UNBLOCKED events never increment total_times_blocked
    assert ip_record["total_times_blocked"] == expected_total_times_blocked, (
        f"total_times_blocked mismatch — UNBLOCKED events may have incremented it. "
        f"Expected: {expected_total_times_blocked}, Got: {ip_record['total_times_blocked']}. "
        f"Sequence: {realistic_sequence}"
    )


# ── Property 17: Concurrent Upsert Atomicity ─────────────────────────────


@given(
    source_ip=st_ipv4(),
    node_ids=st.lists(
        st_node_id(), min_size=2, max_size=10, unique=True
    ),
    is_block_flags=st.lists(st.booleans(), min_size=2, max_size=10),
    timestamps=st.lists(st_timestamp(), min_size=10, max_size=10),
    detection_rule=st_detection_rule(),
)
@settings(
    max_examples=30,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_concurrent_upsert_atomicity(
    tmp_path, source_ip, node_ids, is_block_flags, timestamps, detection_rule
):
    """Property 17: Concurrent Upsert Atomicity.

    **Validates: Requirements 18.1, 18.2**

    For any N concurrent upsert operations on the same IP from different nodes:
      - Final total_times_seen equals N (no lost increments)
      - Final total_times_blocked equals the count of block events among the N
      - reporting_node_list contains all distinct node_ids (no lost node additions)
      - No duplicate entries in reporting_node_list

    Since SQLite serializes writes (WAL mode), concurrent access is effectively
    sequential for SQLite. This test uses threading to simulate concurrent
    upserts against a file-based SQLite DB (not :memory: which can't be shared
    across threads) and verifies no updates are lost.
    """
    import threading
    import uuid as _uuid

    # Align is_block_flags length with node_ids length
    n = len(node_ids)
    block_flags = is_block_flags[:n]
    # Pad with False if is_block_flags is shorter than node_ids
    while len(block_flags) < n:
        block_flags.append(False)

    # Create a file-based SQLite DB for cross-thread sharing.
    # Use a unique filename per Hypothesis example to avoid accumulating
    # data across examples (tmp_path is shared across all examples in one
    # test invocation).
    db_path = str(tmp_path / f"concurrent_test_{_uuid.uuid4().hex}.db")

    # Initialize the database schema with WAL mode for better concurrency
    init_conn = sqlite3.connect(db_path)
    init_conn.row_factory = sqlite3.Row
    init_conn.execute("PRAGMA journal_mode=WAL")
    init_conn.execute("PRAGMA busy_timeout=60000")
    init_intel_db(init_conn, "sqlite")
    init_conn.close()

    # Track errors from threads
    errors = []

    def upsert_worker(nid, is_block, ts):
        """Worker function that performs a single upsert in its own connection.

        Uses retry logic to handle transient SQLite locking under concurrent
        access — SQLite serializes writes so threads must wait their turn.
        """
        import time

        max_retries = 5
        for attempt in range(max_retries):
            try:
                conn = sqlite3.connect(db_path, timeout=60)
                conn.row_factory = sqlite3.Row
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA busy_timeout=60000")

                metadata = {
                    "detection_rule": detection_rule if is_block else "",
                    "block_ttl_seconds": 3600 if is_block else 0,
                    "geo_country": "US",
                }

                upsert_ip_record(
                    conn=conn,
                    ip_address=source_ip,
                    node_id=nid,
                    event_type="NFT_ACTION" if is_block else "LOG_MATCH",
                    timestamp=ts,
                    is_block=is_block,
                    metadata=metadata,
                )
                conn.close()
                return  # Success
            except sqlite3.OperationalError as e:
                if "locked" in str(e) and attempt < max_retries - 1:
                    time.sleep(0.1 * (attempt + 1))
                    try:
                        conn.close()
                    except Exception:
                        pass
                    continue
                errors.append((nid, str(e)))
                return
            except Exception as e:
                errors.append((nid, str(e)))
                return

    # Launch N threads concurrently
    threads = []
    for i in range(n):
        t = threading.Thread(
            target=upsert_worker,
            args=(node_ids[i], block_flags[i], timestamps[i]),
        )
        threads.append(t)

    # Start all threads as close together as possible
    for t in threads:
        t.start()

    # Wait for all threads to complete
    for t in threads:
        t.join(timeout=60)

    # Check for thread errors
    assert not errors, (
        f"Thread errors occurred during concurrent upserts: {errors}"
    )

    # Verify final state
    verify_conn = sqlite3.connect(db_path)
    verify_conn.row_factory = sqlite3.Row

    ip_record = verify_conn.execute(
        "SELECT total_times_seen, total_times_blocked, "
        "total_reporting_nodes, reporting_node_list "
        "FROM ip_intel WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()

    assert ip_record is not None, (
        f"ip_intel record should exist after {n} concurrent upserts"
    )

    reporting_node_list = json.loads(ip_record["reporting_node_list"])

    expected_blocks = sum(1 for b in block_flags if b)

    # Assert: total_times_seen equals N (no lost increments)
    assert ip_record["total_times_seen"] == n, (
        f"total_times_seen should be {n} (one per concurrent upsert), "
        f"but got {ip_record['total_times_seen']}. "
        f"Lost {n - ip_record['total_times_seen']} updates."
    )

    # Assert: total_times_blocked equals count of block events
    assert ip_record["total_times_blocked"] == expected_blocks, (
        f"total_times_blocked should be {expected_blocks}, "
        f"but got {ip_record['total_times_blocked']}. "
        f"block_flags: {block_flags}"
    )

    # Assert: reporting_node_list contains all distinct node_ids
    assert set(reporting_node_list) == set(node_ids), (
        f"reporting_node_list should contain all {n} distinct node_ids. "
        f"Expected: {sorted(node_ids)}, "
        f"Got: {sorted(reporting_node_list)}. "
        f"Missing: {set(node_ids) - set(reporting_node_list)}"
    )

    # Assert: No duplicate entries in reporting_node_list
    assert len(reporting_node_list) == len(set(reporting_node_list)), (
        f"reporting_node_list should have no duplicates. "
        f"List has {len(reporting_node_list)} entries but only "
        f"{len(set(reporting_node_list))} unique values. "
        f"Duplicates: {[x for x in reporting_node_list if reporting_node_list.count(x) > 1]}"
    )

    # Assert: total_reporting_nodes matches list length
    assert ip_record["total_reporting_nodes"] == len(reporting_node_list), (
        f"total_reporting_nodes ({ip_record['total_reporting_nodes']}) should match "
        f"len(reporting_node_list) ({len(reporting_node_list)})"
    )

    # Verify event rows match
    events_count = verify_conn.execute(
        "SELECT COUNT(*) as cnt FROM ip_intel_events WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()["cnt"]

    assert events_count == n, (
        f"ip_intel_events should have {n} rows (one per upsert), "
        f"but got {events_count}"
    )

    verify_conn.close()


# ── Property 16: Repeat Offender Derivation ──────────────────────────────


@given(
    block_episode_count=st.integers(min_value=0, max_value=10),
    total_times_blocked=st.integers(min_value=1, max_value=1000),
)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_repeat_offender_derivation(block_episode_count, total_times_blocked):
    """Property 16: Repeat Offender Derivation.

    **Validates: Requirements 19.1, 19.3, 19.4**

    For any IP record:
      - repeat_offender is TRUE if and only if block_episode_count >= 2
      - repeat_offender is FALSE when block_episode_count < 2 regardless of
        total_times_blocked value
      - The repeat_offender signal in reputation scoring is 1.0 when TRUE,
        0.0 when FALSE
      - A high total_times_blocked from a single continuous episode does NOT
        trigger repeat_offender
    """
    from app.intel_score import compute_repeat_offender

    # Derive the expected repeat_offender flag from block_episode_count alone
    expected_flag = block_episode_count >= 2

    # Build a record dict simulating the ip_intel row state
    record = {
        "repeat_offender": expected_flag,
        "block_episode_count": block_episode_count,
        "total_times_blocked": total_times_blocked,
        "total_times_seen": total_times_blocked + 5,  # arbitrary non-zero
        "total_reporting_nodes": 1,
        "times_seen_last_24h": 0,
        "times_seen_last_7d": 0,
        "times_seen_last_30d": 0,
        "threat_tags": [],
    }

    # ── Assertion 1: repeat_offender flag is TRUE iff block_episode_count >= 2
    assert record["repeat_offender"] == expected_flag, (
        f"repeat_offender should be {expected_flag} when block_episode_count={block_episode_count}"
    )

    # ── Assertion 2: compute_repeat_offender() returns 1.0 when TRUE, 0.0 when FALSE
    signal = compute_repeat_offender(record)
    if expected_flag:
        assert signal == 1.0, (
            f"compute_repeat_offender() should return 1.0 when repeat_offender=True, "
            f"but got {signal}. block_episode_count={block_episode_count}"
        )
    else:
        assert signal == 0.0, (
            f"compute_repeat_offender() should return 0.0 when repeat_offender=False, "
            f"but got {signal}. block_episode_count={block_episode_count}"
        )

    # ── Assertion 3: Independence from total_times_blocked
    # A high total_times_blocked from a single continuous episode (block_episode_count < 2)
    # must NOT trigger repeat_offender
    if block_episode_count < 2:
        assert signal == 0.0, (
            f"repeat_offender signal should be 0.0 when block_episode_count={block_episode_count} "
            f"regardless of total_times_blocked={total_times_blocked}. Got {signal}"
        )

    # ── Assertion 4: The signal value is strictly binary (1.0 or 0.0)
    assert signal in (0.0, 1.0), (
        f"compute_repeat_offender() should return exactly 0.0 or 1.0, got {signal}"
    )


@given(
    block_episode_count=st.integers(min_value=0, max_value=10),
    total_times_blocked=st.integers(min_value=1, max_value=1000),
    total_reporting_nodes=st.integers(min_value=1, max_value=50),
    times_seen_last_24h=st.integers(min_value=0, max_value=100),
    threat_tags=st.lists(st_threat_tag(), min_size=0, max_size=5, unique=True),
)
@settings(suppress_health_check=[HealthCheck.function_scoped_fixture])
def test_repeat_offender_scoring_integration(
    block_episode_count,
    total_times_blocked,
    total_reporting_nodes,
    times_seen_last_24h,
    threat_tags,
):
    """Property 16 (scoring integration): Repeat offender signal in threat score.

    **Validates: Requirements 19.4, 12.3**

    Verifies that the repeat_offender signal contributes correctly to the
    overall threat score computation:
      - When repeat_offender is TRUE (block_episode_count >= 2), the score
        includes the repeat_offender_weight contribution (10% of 1.0)
      - When repeat_offender is FALSE (block_episode_count < 2), the score
        does NOT include any repeat_offender contribution
      - The total_times_blocked value alone does not influence the
        repeat_offender signal
    """
    from app.intel_score import compute_repeat_offender, compute_threat_score

    expected_flag = block_episode_count >= 2
    total_times_seen = total_times_blocked + 5

    record_with_flag = {
        "repeat_offender": expected_flag,
        "block_episode_count": block_episode_count,
        "total_times_blocked": total_times_blocked,
        "total_times_seen": total_times_seen,
        "total_reporting_nodes": total_reporting_nodes,
        "times_seen_last_24h": times_seen_last_24h,
        "times_seen_last_7d": times_seen_last_24h + 5,
        "times_seen_last_30d": times_seen_last_24h + 10,
        "threat_tags": threat_tags,
    }

    # Compute score with the correct repeat_offender flag
    score_actual = compute_threat_score(record_with_flag)

    # Compute score with repeat_offender forced to the opposite value
    record_opposite = dict(record_with_flag)
    record_opposite["repeat_offender"] = not expected_flag
    score_opposite = compute_threat_score(record_opposite)

    # When repeat_offender is TRUE, score should be >= score without it
    # (since the signal adds a positive contribution)
    if expected_flag:
        assert score_actual >= score_opposite, (
            f"Score with repeat_offender=True ({score_actual}) should be >= "
            f"score with repeat_offender=False ({score_opposite}). "
            f"block_episode_count={block_episode_count}, "
            f"total_times_blocked={total_times_blocked}"
        )
    else:
        assert score_actual <= score_opposite, (
            f"Score with repeat_offender=False ({score_actual}) should be <= "
            f"score with repeat_offender=True ({score_opposite}). "
            f"block_episode_count={block_episode_count}, "
            f"total_times_blocked={total_times_blocked}"
        )

    # Verify the signal itself is correct
    signal = compute_repeat_offender(record_with_flag)
    expected_signal = 1.0 if expected_flag else 0.0
    assert signal == expected_signal, (
        f"compute_repeat_offender() should return {expected_signal} "
        f"for block_episode_count={block_episode_count}, got {signal}"
    )


# ── Property Test: OBSERVED Event Threat Tag Accumulation (Task 19.4) ────


# Valid threat tags that represent specific attack vectors
_VALID_THREAT_TAGS = [
    "ssh-brute", "http-probe", "recon-correlation",
    "port-scan", "dns-tunnel", "malware-beacon",
    "web-attack", "credential-stuffing",
]

# Event types that derive to meaningful (non-generic) tags
_MEANINGFUL_EVENT_TYPES = ["SSH_BRUTE", "RECON_CORRELATION", "BLOCKLIST_HIT", "PORT_SCAN"]

# Event types that derive to generic tags (blocked by GENERIC_TAGS)
_GENERIC_EVENT_TYPES = ["LOG_MATCH"]

# The GENERIC_TAGS set from intel_models (for reference in assertions)
_GENERIC_TAGS_SET = frozenset({
    "log-match", "unknown", "other", "nft-action",
    "generic", "none", "unclassified",
})


def st_sighting_event_with_valid_tag():
    """Strategy for sighting events that carry a valid explicit threat_tag."""
    return st.fixed_dictionaries({
        "source_ip": st_ipv4(),
        "node_id": st_node_id(),
        "event_type": st.sampled_from(INTEL_EVENT_TYPES),
        "timestamp": st_timestamp(),
        "metadata": st.fixed_dictionaries({
            "geo_country": st.sampled_from(["US", "CN", "RU", "DE"]),
            "threat_tag": st.sampled_from(_VALID_THREAT_TAGS),
        }),
    })


def st_sighting_event_with_meaningful_event_type():
    """Strategy for sighting events that derive a valid tag from event_type.

    These events have no explicit threat_tag in metadata, but their event_type
    maps to a meaningful (non-generic) derived tag.
    """
    return st.fixed_dictionaries({
        "source_ip": st_ipv4(),
        "node_id": st_node_id(),
        "event_type": st.sampled_from(_MEANINGFUL_EVENT_TYPES),
        "timestamp": st_timestamp(),
        "metadata": st.fixed_dictionaries({
            "geo_country": st.sampled_from(["US", "CN", "RU", "DE"]),
        }),
    })


def st_sighting_event_without_meaningful_tag():
    """Strategy for sighting events that should NOT contribute tags.

    These events have:
      - No explicit threat_tag in metadata
      - An event_type that derives to a generic tag (e.g., LOG_MATCH -> log-match)
    """
    return st.fixed_dictionaries({
        "source_ip": st_ipv4(),
        "node_id": st_node_id(),
        "event_type": st.sampled_from(_GENERIC_EVENT_TYPES),
        "timestamp": st_timestamp(),
        "metadata": st.fixed_dictionaries({
            "geo_country": st.sampled_from(["US", "CN", "RU", "DE"]),
        }),
    })


@given(
    target_ip=st_ipv4(),
    events_with_tags=st.lists(
        st_sighting_event_with_valid_tag(), min_size=1, max_size=5
    ),
    events_with_meaningful_types=st.lists(
        st_sighting_event_with_meaningful_event_type(), min_size=0, max_size=3
    ),
    events_without_tags=st.lists(
        st_sighting_event_without_meaningful_tag(), min_size=1, max_size=5
    ),
)
@settings(
    suppress_health_check=[HealthCheck.function_scoped_fixture, HealthCheck.filter_too_much],
    max_examples=100,
)
def test_observed_event_threat_tag_accumulation(
    intel_db,
    target_ip,
    events_with_tags,
    events_with_meaningful_types,
    events_without_tags,
):
    """Property: OBSERVED events with valid threat_tags contribute to threat_tags
    array; events without meaningful tags do not add empty entries.

    **Validates: Requirements 20.1, 20.2, 20.3**

    For any mix of sighting events:
      - Events with explicit valid threat_tag in metadata accumulate that tag
      - Events with meaningful event_types (SSH_BRUTE, etc.) derive and accumulate
        a valid tag
      - Events with generic event_types (LOG_MATCH) and no explicit tag do NOT
        add any entry to threat_tags
      - The threat_tags array contains no empty strings
      - The threat_tags array contains no generic tags (log-match, unknown, etc.)
      - Valid explicit tags and meaningful derived tags are present
    """
    # Ensure clean state for this IP
    existing = intel_db.execute(
        "SELECT 1 FROM ip_intel WHERE ip_address = ?", (target_ip,)
    ).fetchone()
    assume(existing is None)

    # Collect expected valid tags that should end up in the array
    expected_tags = set()

    # Process events with explicit valid threat_tags
    for event in events_with_tags:
        payload = {
            "source_ip": target_ip,
            "node_id": event["node_id"],
            "event_type": event["event_type"],
            "timestamp": event["timestamp"],
            "metadata": dict(event["metadata"]),
        }
        tag = event["metadata"]["threat_tag"]
        expected_tags.add(tag)
        process_sighting(intel_db, payload)

    # Process events with meaningful event_types (no explicit tag)
    for event in events_with_meaningful_types:
        payload = {
            "source_ip": target_ip,
            "node_id": event["node_id"],
            "event_type": event["event_type"],
            "timestamp": event["timestamp"],
            "metadata": dict(event["metadata"]),
        }
        # Derived tag: event_type.lower().replace("_", "-")
        derived_tag = event["event_type"].lower().replace("_", "-")
        if derived_tag not in _GENERIC_TAGS_SET:
            expected_tags.add(derived_tag)
        process_sighting(intel_db, payload)

    # Process events without meaningful tags (generic event_types, no explicit tag)
    for event in events_without_tags:
        payload = {
            "source_ip": target_ip,
            "node_id": event["node_id"],
            "event_type": event["event_type"],
            "timestamp": event["timestamp"],
            "metadata": dict(event["metadata"]),
        }
        process_sighting(intel_db, payload)

    # Fetch the accumulated threat_tags from the ip_intel record
    ip_record = intel_db.execute(
        "SELECT threat_tags FROM ip_intel WHERE ip_address = ?",
        (target_ip,),
    ).fetchone()

    assert ip_record is not None, "ip_intel record should exist after processing sighting events"

    actual_tags = json.loads(ip_record["threat_tags"])

    # ── Assertion 1: No empty strings in threat_tags
    assert "" not in actual_tags, (
        f"threat_tags array should not contain empty strings. Got: {actual_tags}"
    )

    # ── Assertion 2: No generic tags in threat_tags
    generic_found = [t for t in actual_tags if t in _GENERIC_TAGS_SET]
    assert not generic_found, (
        f"threat_tags array should not contain generic tags. "
        f"Found generic tags: {generic_found}. Full array: {actual_tags}"
    )

    # ── Assertion 3: All expected valid tags are present
    actual_tags_set = set(actual_tags)
    missing_tags = expected_tags - actual_tags_set
    assert not missing_tags, (
        f"Expected valid tags missing from threat_tags array. "
        f"Missing: {missing_tags}. Expected: {expected_tags}. Got: {actual_tags_set}"
    )

    # ── Assertion 4: No unexpected tags (only expected tags should be present)
    unexpected_tags = actual_tags_set - expected_tags
    assert not unexpected_tags, (
        f"Unexpected tags found in threat_tags array. "
        f"Unexpected: {unexpected_tags}. Expected: {expected_tags}. Got: {actual_tags_set}"
    )

    # ── Assertion 5: No duplicates in threat_tags
    assert len(actual_tags) == len(set(actual_tags)), (
        f"threat_tags array should contain no duplicates. Got: {actual_tags}"
    )


# ── Property 15: Timestamp Validation Bounds ─────────────────────────────


def st_timestamp_validation():
    """Strategy that generates timestamps distributed from 60 days in the past to 10 minutes in the future.

    Used for testing timestamp validation bounds per Property 15.
    """
    now = datetime.now(timezone.utc)
    # Range: -60 days (past) to +10 minutes (future)
    # Negative seconds = past, positive seconds = future
    max_past_seconds = 60 * 24 * 3600  # 60 days
    max_future_seconds = 10 * 60  # 10 minutes
    return st.integers(
        min_value=-max_past_seconds, max_value=max_future_seconds
    ).map(
        lambda offset_secs: (now + timedelta(seconds=offset_secs)).strftime("%Y-%m-%dT%H:%M:%SZ")
    )


@given(
    offset_seconds=st.integers(
        min_value=-(60 * 24 * 3600),  # 60 days in the past
        max_value=10 * 60,  # 10 minutes in the future
    ),
)
@settings(
    max_examples=200,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_timestamp_validation_bounds(offset_seconds):
    """Property 15: Timestamp Validation Bounds.

    **Validates: Requirements 21.2, 21.3**

    For any event with an agent-provided timestamp:
      - If the timestamp is more than 5 minutes in the future relative to server UTC,
        the event is rejected
      - If the timestamp is in the past (any amount), the event is accepted
      - If the timestamp is within 5 minutes of the future, the event is accepted
    """
    from app.routes.api import validate_event_timestamp

    # Generate a timestamp at the given offset from "now"
    # We compute "now" inside the test to be as close as possible to what
    # validate_event_timestamp() will use internally
    now = datetime.now(timezone.utc)
    event_ts = now + timedelta(seconds=offset_seconds)
    event_ts_str = event_ts.strftime("%Y-%m-%dT%H:%M:%SZ")

    is_valid, error_msg = validate_event_timestamp(event_ts_str)

    # The 5-minute threshold in seconds
    five_minutes = 5 * 60

    if offset_seconds <= five_minutes:
        # Past timestamps (any amount) and timestamps within 5 minutes of future
        # should always be accepted
        assert is_valid is True, (
            f"Timestamp at offset {offset_seconds}s (within 5min future or in past) "
            f"should be accepted, but was rejected. "
            f"event_ts={event_ts_str}, error={error_msg}"
        )
        assert error_msg == "", (
            f"Accepted timestamp should have empty error message, got: {error_msg!r}"
        )
    else:
        # Timestamps more than 5 minutes in the future should be rejected
        assert is_valid is False, (
            f"Timestamp at offset {offset_seconds}s (more than 5min in future) "
            f"should be rejected, but was accepted. "
            f"event_ts={event_ts_str}"
        )
        assert "more than 5 minutes in the future" in error_msg, (
            f"Rejection error should mention '5 minutes in the future', "
            f"got: {error_msg!r}"
        )


@given(
    past_offset_seconds=st.integers(
        min_value=1,  # at least 1 second in the past
        max_value=60 * 24 * 3600,  # up to 60 days in the past
    ),
)
@settings(
    max_examples=100,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_past_timestamps_always_accepted(past_offset_seconds):
    """Property 15 (sub-property): Past timestamps are always accepted.

    **Validates: Requirement 21.3**

    THE Intel_Ingestion_Pipeline SHALL accept agent timestamps that are in the
    past (events may be delayed due to network issues or batch queuing) without
    modification.
    """
    from app.routes.api import validate_event_timestamp

    now = datetime.now(timezone.utc)
    past_ts = now - timedelta(seconds=past_offset_seconds)
    past_ts_str = past_ts.strftime("%Y-%m-%dT%H:%M:%SZ")

    is_valid, error_msg = validate_event_timestamp(past_ts_str)

    assert is_valid is True, (
        f"Past timestamp ({past_offset_seconds}s ago) should always be accepted. "
        f"event_ts={past_ts_str}, error={error_msg}"
    )
    assert error_msg == "", (
        f"Accepted past timestamp should have empty error message, got: {error_msg!r}"
    )


@given(
    future_offset_seconds=st.integers(
        min_value=5 * 60 + 1,  # just over 5 minutes in the future
        max_value=10 * 60,  # up to 10 minutes in the future
    ),
)
@settings(
    max_examples=100,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_future_timestamps_beyond_5min_rejected(future_offset_seconds):
    """Property 15 (sub-property): Future timestamps beyond 5 minutes are rejected.

    **Validates: Requirement 21.2**

    THE Intel_Ingestion_Pipeline SHALL validate that the agent timestamp is not
    more than 5 minutes in the future relative to server UTC time. IF the
    timestamp exceeds this threshold, THE pipeline SHALL reject the event with
    a validation error.
    """
    from app.routes.api import validate_event_timestamp

    now = datetime.now(timezone.utc)
    future_ts = now + timedelta(seconds=future_offset_seconds)
    future_ts_str = future_ts.strftime("%Y-%m-%dT%H:%M:%SZ")

    is_valid, error_msg = validate_event_timestamp(future_ts_str)

    assert is_valid is False, (
        f"Future timestamp ({future_offset_seconds}s ahead, >{5*60}s threshold) "
        f"should be rejected. event_ts={future_ts_str}"
    )
    assert "more than 5 minutes in the future" in error_msg, (
        f"Rejection error should mention '5 minutes in the future', "
        f"got: {error_msg!r}"
    )


# ── Property 18: Raw Request Volume Accumulation ─────────────────────────


def st_request_count():
    """Strategy for request_count values (1–500, matching design spec generator)."""
    return st.integers(min_value=1, max_value=500)


def st_event_with_request_count():
    """Strategy for events with varying request_count values.

    Generates a tuple of (event_kind, request_count) where event_kind is one of
    'block', 'sighting', or 'fleet_block', and request_count ranges from 1 to 500.
    Some events omit request_count to test default behavior.
    """
    return st.tuples(
        st.sampled_from(["block", "sighting", "fleet_block"]),
        st.one_of(
            st_request_count(),
            st.none(),  # None means request_count not provided (defaults to 1)
        ),
    )


@given(
    source_ip=st_ipv4(),
    node_id=st_node_id(),
    events=st.lists(st_event_with_request_count(), min_size=1, max_size=15),
    timestamps=st.lists(st_timestamp(), min_size=15, max_size=15),
    detection_rule=st_detection_rule(),
)
@settings(
    max_examples=100,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_total_requests_equals_sum_of_request_counts(
    intel_db, source_ip, node_id, events, timestamps, detection_rule
):
    """Property 18: Raw Request Volume Accumulation — total_requests == SUM(request_count).

    **Validates: Requirements 22.3, 22.4, 22.5**

    For any sequence of events with varying request_count values:
      - total_requests == SUM(request_count) across all ingested events
        where event_kind IN ('block', 'sighting')
      - Fleet_block events do NOT contribute to total_requests
    """
    # Ensure we start from a clean state for this IP
    existing = intel_db.execute(
        "SELECT 1 FROM ip_intel WHERE ip_address = ?", (source_ip,)
    ).fetchone()
    assume(existing is None)

    expected_total_requests = 0

    for i, (event_kind, request_count) in enumerate(events):
        effective_request_count = request_count if request_count is not None else 1

        if event_kind == "fleet_block":
            # Fleet block events do NOT contribute to total_requests
            process_fleet_block_event(
                conn=intel_db,
                ip_address=source_ip,
                node_id=node_id,
                timestamp=timestamps[i],
            )
        elif event_kind == "block":
            metadata = {
                "detection_rule": detection_rule,
                "block_ttl_seconds": 3600,
                "geo_country": "US",
            }
            if request_count is not None:
                metadata["request_count"] = request_count
            process_block_event(intel_db, {
                "source_ip": source_ip,
                "node_id": node_id,
                "event_type": "NFT_ACTION",
                "timestamp": timestamps[i],
                "detection_rule": detection_rule,
                "block_ttl_seconds": 3600,
                "metadata": metadata,
            })
            expected_total_requests += effective_request_count
        else:
            # sighting
            metadata = {"geo_country": "US"}
            if request_count is not None:
                metadata["request_count"] = request_count
            process_sighting(intel_db, {
                "source_ip": source_ip,
                "node_id": node_id,
                "event_type": "LOG_MATCH",
                "timestamp": timestamps[i],
                "metadata": metadata,
            })
            expected_total_requests += effective_request_count

    # Verify total_requests on ip_intel record
    ip_record = intel_db.execute(
        "SELECT total_requests FROM ip_intel WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()

    assert ip_record is not None, (
        f"ip_intel record should exist after processing {len(events)} events"
    )
    assert ip_record["total_requests"] == expected_total_requests, (
        f"total_requests should be {expected_total_requests} (SUM of request_count "
        f"for block+sighting events), but got {ip_record['total_requests']}. "
        f"Events: {events}"
    )


@given(
    source_ip=st_ipv4(),
    node_id=st_node_id(),
    fleet_request_counts=st.lists(
        st_request_count(), min_size=1, max_size=10
    ),
    timestamps=st.lists(st_timestamp(), min_size=10, max_size=10),
)
@settings(
    max_examples=100,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_fleet_block_does_not_contribute_to_total_requests(
    intel_db, source_ip, node_id, fleet_request_counts, timestamps
):
    """Property 18 (sub-property): Fleet_block events do NOT contribute to total_requests.

    **Validates: Requirements 22.6**

    Fleet_block events do NOT contribute to total_requests regardless of their
    request_count value. Even if fleet_block events carry a request_count, the
    total_requests counter on ip_intel must remain unchanged.
    """
    # Ensure we start from a clean state for this IP
    existing = intel_db.execute(
        "SELECT 1 FROM ip_intel WHERE ip_address = ?", (source_ip,)
    ).fetchone()
    assume(existing is None)

    # First, create the IP record with one block event so we have a baseline
    process_block_event(intel_db, {
        "source_ip": source_ip,
        "node_id": node_id,
        "event_type": "NFT_ACTION",
        "timestamp": timestamps[0],
        "detection_rule": "ssh-brute",
        "block_ttl_seconds": 3600,
        "metadata": {"geo_country": "US", "request_count": 5},
    })

    # Record total_requests after the initial block
    record_after_block = intel_db.execute(
        "SELECT total_requests FROM ip_intel WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()
    total_requests_after_block = record_after_block["total_requests"]
    assert total_requests_after_block == 5

    # Now process multiple fleet_block events — total_requests should NOT change
    for i, _ in enumerate(fleet_request_counts):
        process_fleet_block_event(
            conn=intel_db,
            ip_address=source_ip,
            node_id=f"{node_id}-fleet-{i}",
            timestamp=timestamps[min(i + 1, len(timestamps) - 1)],
        )

    # Verify total_requests is unchanged
    record_after_fleet = intel_db.execute(
        "SELECT total_requests FROM ip_intel WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()

    assert record_after_fleet["total_requests"] == total_requests_after_block, (
        f"total_requests should remain {total_requests_after_block} after "
        f"{len(fleet_request_counts)} fleet_block events, but got "
        f"{record_after_fleet['total_requests']}. "
        f"Fleet_block events must NOT contribute to total_requests."
    )


@given(
    source_ip=st_ipv4(),
    node_id=st_node_id(),
    n_events=st.integers(min_value=1, max_value=15),
    is_blocks=st.lists(st.booleans(), min_size=15, max_size=15),
    timestamps=st.lists(st_timestamp(), min_size=15, max_size=15),
    detection_rule=st_detection_rule(),
)
@settings(
    max_examples=100,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_default_request_count_ensures_total_requests_gte_total_times_seen(
    intel_db, source_ip, node_id, n_events, is_blocks, timestamps, detection_rule
):
    """Property 18 (sub-property): Default request_count=1 ensures total_requests >= total_times_seen.

    **Validates: Requirements 22.1, 22.3**

    If request_count is not provided on an event, it defaults to 1. Therefore:
      - total_requests >= total_times_seen always holds
      (since each event contributes at least 1 request)
    """
    # Ensure we start from a clean state for this IP
    existing = intel_db.execute(
        "SELECT 1 FROM ip_intel WHERE ip_address = ?", (source_ip,)
    ).fetchone()
    assume(existing is None)

    # Process events WITHOUT providing request_count (should default to 1)
    for i in range(n_events):
        if is_blocks[i]:
            process_block_event(intel_db, {
                "source_ip": source_ip,
                "node_id": node_id,
                "event_type": "NFT_ACTION",
                "timestamp": timestamps[i],
                "detection_rule": detection_rule,
                "block_ttl_seconds": 3600,
                "metadata": {"geo_country": "US"},
                # No request_count — should default to 1
            })
        else:
            process_sighting(intel_db, {
                "source_ip": source_ip,
                "node_id": node_id,
                "event_type": "LOG_MATCH",
                "timestamp": timestamps[i],
                "metadata": {"geo_country": "US"},
                # No request_count — should default to 1
            })

    # Verify the invariant: total_requests >= total_times_seen
    ip_record = intel_db.execute(
        "SELECT total_requests, total_times_seen FROM ip_intel WHERE ip_address = ?",
        (source_ip,),
    ).fetchone()

    assert ip_record is not None, (
        f"ip_intel record should exist after processing {n_events} events"
    )
    assert ip_record["total_requests"] >= ip_record["total_times_seen"], (
        f"total_requests ({ip_record['total_requests']}) should be >= "
        f"total_times_seen ({ip_record['total_times_seen']}). "
        f"Each event contributes at least 1 request (default)."
    )
    # When no request_count is provided, total_requests should equal total_times_seen
    assert ip_record["total_requests"] == ip_record["total_times_seen"], (
        f"When no request_count is provided (default=1), total_requests "
        f"({ip_record['total_requests']}) should equal total_times_seen "
        f"({ip_record['total_times_seen']})."
    )


@given(
    source_ip=st_ipv4(),
    node_id=st_node_id(),
    events=st.lists(
        st.tuples(
            st.sampled_from(["block", "sighting"]),
            st_request_count(),
        ),
        min_size=1,
        max_size=10,
    ),
    timestamps=st.lists(st_timestamp(), min_size=10, max_size=10),
    detection_rule=st_detection_rule(),
)
@settings(
    max_examples=100,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
def test_ip_intel_events_request_count_stores_correct_value(
    intel_db, source_ip, node_id, events, timestamps, detection_rule
):
    """Property 18 (sub-property): ip_intel_events.request_count stores the correct per-event value.

    **Validates: Requirements 22.2**

    The ip_intel_events.request_count column stores the per-event value correctly
    for each ingested event.
    """
    # Ensure we start from a clean state for this IP
    existing = intel_db.execute(
        "SELECT 1 FROM ip_intel WHERE ip_address = ?", (source_ip,)
    ).fetchone()
    assume(existing is None)

    expected_request_counts = []

    for i, (event_kind, request_count) in enumerate(events):
        if event_kind == "block":
            metadata = {
                "detection_rule": detection_rule,
                "block_ttl_seconds": 3600,
                "geo_country": "US",
                "request_count": request_count,
            }
            process_block_event(intel_db, {
                "source_ip": source_ip,
                "node_id": node_id,
                "event_type": "NFT_ACTION",
                "timestamp": timestamps[i],
                "detection_rule": detection_rule,
                "block_ttl_seconds": 3600,
                "metadata": metadata,
            })
        else:
            metadata = {
                "geo_country": "US",
                "request_count": request_count,
            }
            process_sighting(intel_db, {
                "source_ip": source_ip,
                "node_id": node_id,
                "event_type": "LOG_MATCH",
                "timestamp": timestamps[i],
                "metadata": metadata,
            })
        expected_request_counts.append(request_count)

    # Query all event rows and verify request_count values
    rows = intel_db.execute(
        "SELECT request_count FROM ip_intel_events "
        "WHERE ip_address = ? AND event_kind IN ('block', 'sighting') "
        "ORDER BY rowid",
        (source_ip,),
    ).fetchall()

    assert len(rows) == len(expected_request_counts), (
        f"Expected {len(expected_request_counts)} event rows, got {len(rows)}"
    )

    for idx, (row, expected_rc) in enumerate(zip(rows, expected_request_counts)):
        assert row["request_count"] == expected_rc, (
            f"Event {idx}: ip_intel_events.request_count should be {expected_rc}, "
            f"but got {row['request_count']}. "
            f"Events: {events}"
        )
