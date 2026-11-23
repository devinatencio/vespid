"""Tests for node health using the canonical liveness timestamp."""

import json
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


def test_update_last_seen_tracks_node_origin_separately(db):
    touch_node(db, "node-origin", _age(minutes=1))

    update_last_seen(
        db,
        "node-origin",
        ip="15.204.238.218",
        geo_data={"country": "US", "city": "Dallas"},
    )

    node = get_node(db, "node-origin")
    assert node["last_ip"] == "15.204.238.218"
    assert json.loads(node["last_node_geo_data"]) == {"country": "US", "city": "Dallas"}


def test_nodes_page_shows_node_location_not_event_source(db, auth_client):
    touch_node(
        db,
        "node-geo",
        _age(minutes=1),
        geo_data={"country": "CN", "city": "Guangzhou"},
    )
    update_last_seen(
        db,
        "node-geo",
        ip="15.204.238.218",
        geo_data={"country": "US", "city": "Dallas"},
    )

    resp = auth_client("viewer").get("/nodes")

    assert resp.status_code == 200
    assert b"Dallas, US" in resp.data
    assert b"Guangzhou" not in resp.data


def test_node_detail_shows_node_location_and_event_origin(db, auth_client):
    touch_node(
        db,
        "node-both",
        _age(minutes=1),
        geo_data={"country": "CN", "city": "Guangzhou"},
    )
    update_last_seen(
        db,
        "node-both",
        ip="15.204.238.218",
        geo_data={"country": "US", "city": "Dallas"},
    )

    resp = auth_client("viewer").get("/nodes/node-both")

    assert resp.status_code == 200
    assert b"Node Location" in resp.data
    assert b"Dallas, US" in resp.data
    assert b"Guangzhou, CN" in resp.data
