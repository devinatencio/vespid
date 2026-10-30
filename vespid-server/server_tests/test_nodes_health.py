"""Tests for node health using the canonical liveness timestamp."""

from datetime import UTC, datetime, timedelta

from app.models import get_node, touch_node, update_last_seen


def _age(days: int = 0, hours: int = 0, minutes: int = 0) -> str:
    return (datetime.now(UTC) - timedelta(days=days, hours=hours, minutes=minutes)).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _json_nodes(client):
    resp = client.get("/nodes", headers={"Accept": "application/json"})
    assert resp.status_code == 200
    return {node["node_id"]: node for node in resp.get_json()["nodes"]}


def test_health_uses_last_seen_when_event_is_stale(db, auth_client):
    old_event_ts = _age(hours=2)
    touch_node(db, "node-live", old_event_ts)
    update_last_seen(db, "node-live")

    nodes = _json_nodes(auth_client("viewer"))

    assert nodes["node-live"]["health"] == "healthy"
    assert nodes["node-live"]["last_seen_at"]
    assert nodes["node-live"]["last_event_at"] == old_event_ts


def test_health_falls_back_to_last_event_for_legacy_rows(db, auth_client):
    touch_node(db, "node-legacy", _age(hours=2))

    node = get_node(db, "node-legacy")
    assert node is not None
    assert node["last_seen_at"] is None

    nodes = _json_nodes(auth_client("viewer"))

    assert nodes["node-legacy"]["health"] == "offline"


def test_fresh_last_event_still_marks_healthy_without_last_seen(db, auth_client):
    touch_node(db, "node-event-only", datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ"))

    node = get_node(db, "node-event-only")
    assert node is not None
    assert node["last_seen_at"] is None

    nodes = _json_nodes(auth_client("viewer"))

    assert nodes["node-event-only"]["health"] == "healthy"


def test_nodes_page_shows_last_seen_and_last_event(db, auth_client):
    old_event_ts = _age(hours=2)
    touch_node(db, "node-live", old_event_ts)
    update_last_seen(db, "node-live")

    resp = auth_client("viewer").get("/nodes")

    assert resp.status_code == 200
    assert b"Last Seen" in resp.data
    assert b"Last Event" in resp.data
    assert old_event_ts.encode() in resp.data
