"""Tests for database initialization and schema (app/models.py).

Validates that init_db creates all tables, indexes, enables WAL mode and
foreign keys, and that the schema matches the design specification.
"""

import sqlite3

import pytest

from app.models import get_db, init_db


@pytest.fixture()
def db_path(tmp_path):
    """Return a temporary database path."""
    return str(tmp_path / "test.db")


@pytest.fixture()
def db(db_path):
    """Return an initialized database connection."""
    init_db(db_path)
    conn = get_db(db_path)
    yield conn
    conn.close()


# ── Table existence ──────────────────────────────────────────────────────

EXPECTED_TABLES = [
    "events",
    "users",
    "api_keys",
    "nodes",
    "audit_log",
    "pending_commands",
]


class TestTablesCreated:
    """All six tables from the design must exist after init_db."""

    @pytest.mark.parametrize("table_name", EXPECTED_TABLES)
    def test_table_exists(self, db, table_name):
        row = db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
            (table_name,),
        ).fetchone()
        assert row is not None, f"Table '{table_name}' was not created"


# ── Index existence ──────────────────────────────────────────────────────

EXPECTED_INDEXES = [
    # events indexes
    "idx_events_timestamp",
    "idx_events_source_ip",
    "idx_events_node_id",
    "idx_events_event_type",
    "idx_events_geo_country",
    "idx_events_ingested",
    # audit_log indexes
    "idx_audit_timestamp",
    "idx_audit_action_type",
    # pending_commands indexes
    "idx_commands_node_id",
    "idx_commands_status",
]


class TestIndexesCreated:
    """All indexes from the design must exist after init_db."""

    @pytest.mark.parametrize("index_name", EXPECTED_INDEXES)
    def test_index_exists(self, db, index_name):
        row = db.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND name=?",
            (index_name,),
        ).fetchone()
        assert row is not None, f"Index '{index_name}' was not created"


# ── WAL mode ─────────────────────────────────────────────────────────────

class TestWALMode:
    """WAL journal mode must be enabled."""

    def test_wal_mode_enabled(self, db):
        mode = db.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "wal"


# ── Foreign keys ─────────────────────────────────────────────────────────

class TestForeignKeys:
    """Foreign key enforcement must be enabled."""

    def test_foreign_keys_enabled(self, db):
        fk = db.execute("PRAGMA foreign_keys").fetchone()[0]
        assert fk == 1


# ── get_db helper ────────────────────────────────────────────────────────

class TestGetDb:
    """get_db must return a properly configured connection."""

    def test_returns_connection(self, db_path):
        init_db(db_path)
        conn = get_db(db_path)
        assert isinstance(conn, sqlite3.Connection)
        conn.close()

    def test_row_factory_is_row(self, db_path):
        init_db(db_path)
        conn = get_db(db_path)
        assert conn.row_factory is sqlite3.Row
        conn.close()

    def test_wal_mode_set(self, db_path):
        init_db(db_path)
        conn = get_db(db_path)
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "wal"
        conn.close()

    def test_foreign_keys_set(self, db_path):
        init_db(db_path)
        conn = get_db(db_path)
        fk = conn.execute("PRAGMA foreign_keys").fetchone()[0]
        assert fk == 1
        conn.close()


# ── Schema column verification ───────────────────────────────────────────

def _get_columns(db, table_name):
    """Return a dict mapping column name -> {type, notnull, dflt_value, pk}."""
    rows = db.execute(f"PRAGMA table_info({table_name})").fetchall()
    return {
        row["name"]: {
            "type": row["type"],
            "notnull": row["notnull"],
            "pk": row["pk"],
            "dflt_value": row["dflt_value"],
        }
        for row in rows
    }


class TestEventsSchema:
    """Verify the events table schema matches the design."""

    def test_column_names(self, db):
        cols = _get_columns(db, "events")
        expected = [
            "id", "event_id", "node_id", "timestamp", "source_ip",
            "event_type", "action_taken", "geo_country", "geo_city",
            "geo_asn", "geo_org", "geo_latitude", "geo_longitude",
            "geo_data", "metadata", "ingested_at",
        ]
        assert set(cols.keys()) == set(expected)

    def test_id_is_primary_key(self, db):
        cols = _get_columns(db, "events")
        assert cols["id"]["pk"] == 1

    def test_event_id_not_null(self, db):
        cols = _get_columns(db, "events")
        assert cols["event_id"]["notnull"] == 1

    def test_geo_country_nullable(self, db):
        cols = _get_columns(db, "events")
        assert cols["geo_country"]["notnull"] == 0

    def test_geo_data_default(self, db):
        cols = _get_columns(db, "events")
        assert cols["geo_data"]["dflt_value"] == "'{}'"

    def test_metadata_default(self, db):
        cols = _get_columns(db, "events")
        assert cols["metadata"]["dflt_value"] == "'{}'"


class TestUsersSchema:
    """Verify the users table schema matches the design."""

    def test_column_names(self, db):
        cols = _get_columns(db, "users")
        expected = ["id", "username", "password_hash", "role", "created_at", "last_login_at", "theme", "display_name", "failed_login_attempts", "locked_until", "onboarding_dismissed", "brand_beam_enabled"]
        assert set(cols.keys()) == set(expected)

    def test_username_not_null(self, db):
        cols = _get_columns(db, "users")
        assert cols["username"]["notnull"] == 1

    def test_role_default(self, db):
        cols = _get_columns(db, "users")
        assert cols["role"]["dflt_value"] == "'viewer'"

    def test_role_check_constraint(self, db):
        """Inserting an invalid role should raise an IntegrityError."""
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                ("testuser", "hash", "superadmin"),
            )

    def test_valid_roles_accepted(self, db):
        for i, role in enumerate(("admin", "analyst", "viewer")):
            db.execute(
                "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
                (f"user{i}", "hash", role),
            )
        db.commit()
        count = db.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        assert count == 3


class TestApiKeysSchema:
    """Verify the api_keys table schema matches the design."""

    def test_column_names(self, db):
        cols = _get_columns(db, "api_keys")
        expected = [
            "id", "key_hash", "key_prefix", "label", "role",
            "node_id_restriction", "is_active", "created_at",
            "last_used_at", "created_by", "host_id",
        ]
        assert set(cols.keys()) == set(expected)

    def test_is_active_default(self, db):
        cols = _get_columns(db, "api_keys")
        assert cols["is_active"]["dflt_value"] == "1"

    def test_node_id_restriction_nullable(self, db):
        cols = _get_columns(db, "api_keys")
        assert cols["node_id_restriction"]["notnull"] == 0

    def test_created_by_foreign_key(self, db):
        """created_by should reference users(id) — inserting a non-existent
        user id should fail when foreign keys are enforced."""
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                "INSERT INTO api_keys (key_hash, key_prefix, label, created_by) "
                "VALUES (?, ?, ?, ?)",
                ("hash1", "prefix", "test", 9999),
            )


class TestNodesSchema:
    """Verify the nodes table schema matches the design."""

    def test_column_names(self, db):
        cols = _get_columns(db, "nodes")
        expected = [
            "id", "node_id", "display_name", "first_seen_at", "last_event_at",
            "total_events", "last_geo_data", "last_whitelist", "last_allowlist",
            "last_feeds", "last_counters", "last_host_info", "asset_id",
            "agent_version", "last_seen_at",
        ]
        assert set(cols.keys()) == set(expected)

    def test_total_events_default(self, db):
        cols = _get_columns(db, "nodes")
        assert cols["total_events"]["dflt_value"] == "0"

    def test_last_geo_data_default(self, db):
        cols = _get_columns(db, "nodes")
        assert cols["last_geo_data"]["dflt_value"] == "'{}'"


class TestAuditLogSchema:
    """Verify the audit_log table schema matches the design."""

    def test_column_names(self, db):
        cols = _get_columns(db, "audit_log")
        expected = [
            "id", "timestamp", "actor", "actor_ip",
            "action_type", "target", "details",
        ]
        assert set(cols.keys()) == set(expected)

    def test_actor_not_null(self, db):
        cols = _get_columns(db, "audit_log")
        assert cols["actor"]["notnull"] == 1

    def test_details_default(self, db):
        cols = _get_columns(db, "audit_log")
        assert cols["details"]["dflt_value"] == "'{}'"


class TestPendingCommandsSchema:
    """Verify the pending_commands table schema matches the design."""

    def test_column_names(self, db):
        cols = _get_columns(db, "pending_commands")
        expected = [
            "id", "command_id", "node_id", "command_type",
            "payload", "status", "created_at", "acknowledged_at", "result",
        ]
        assert set(cols.keys()) == set(expected)

    def test_status_default(self, db):
        cols = _get_columns(db, "pending_commands")
        assert cols["status"]["dflt_value"] == "'pending'"

    def test_payload_default(self, db):
        cols = _get_columns(db, "pending_commands")
        assert cols["payload"]["dflt_value"] == "'{}'"

    def test_status_check_constraint(self, db):
        """Inserting an invalid status should raise an IntegrityError."""
        with pytest.raises(sqlite3.IntegrityError):
            db.execute(
                "INSERT INTO pending_commands (command_id, node_id, command_type, status) "
                "VALUES (?, ?, ?, ?)",
                ("cmd1", "node1", "unblock_ip", "invalid_status"),
            )

    def test_valid_statuses_accepted(self, db):
        valid = ("pending", "acknowledged", "completed", "failed", "expired")
        for i, status in enumerate(valid):
            db.execute(
                "INSERT INTO pending_commands (command_id, node_id, command_type, status) "
                "VALUES (?, ?, ?, ?)",
                (f"cmd{i}", "node1", "unblock_ip", status),
            )
        db.commit()
        count = db.execute("SELECT COUNT(*) FROM pending_commands").fetchone()[0]
        assert count == len(valid)


# ── Idempotency ──────────────────────────────────────────────────────────

class TestInitDbIdempotent:
    """Calling init_db multiple times should not fail or lose data."""

    def test_double_init_does_not_error(self, db_path):
        init_db(db_path)
        init_db(db_path)  # should not raise

    def test_double_init_preserves_data(self, db_path):
        init_db(db_path)
        conn = get_db(db_path)
        conn.execute(
            "INSERT INTO users (username, password_hash, role) VALUES (?, ?, ?)",
            ("admin", "hash", "admin"),
        )
        conn.commit()
        conn.close()

        # Re-init should not drop the existing row
        init_db(db_path)
        conn = get_db(db_path)
        count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
        conn.close()
        assert count == 1


# ── Event query helper tests (Task 2.2) ─────────────────────────────────

from datetime import datetime, timedelta, timezone

from app.models import (
    get_recent_events,
    get_events_after_id,
    insert_events,
    search_events,
    get_dashboard_stats,
)


def _make_event(
    event_id="evt-1",
    node_id="node-a",
    timestamp=None,
    source_ip="10.0.0.1",
    event_type="SSH_BRUTE",
    action_taken="BLOCKED",
    geo_data=None,
    metadata=None,
):
    """Build a minimal valid event dict with sensible defaults."""
    if timestamp is None:
        timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if geo_data is None:
        geo_data = {"country": "US", "city": "Dallas", "asn": "AS1234", "org": "TestOrg"}
    return {
        "event_id": event_id,
        "node_id": node_id,
        "timestamp": timestamp,
        "source_ip": source_ip,
        "event_type": event_type,
        "action_taken": action_taken,
        "geo_data": geo_data,
        "metadata": metadata or {},
    }


class TestInsertEvents:
    """Tests for insert_events()."""

    def test_insert_single_event(self, db):
        ev = _make_event()
        result = insert_events(db, [ev])
        assert len(result) == 1
        assert ev["event_id"] in result
        row = db.execute("SELECT * FROM events WHERE event_id = ?", (ev["event_id"],)).fetchone()
        assert row is not None
        assert row["node_id"] == "node-a"
        assert row["source_ip"] == "10.0.0.1"

    def test_insert_empty_list(self, db):
        result = insert_events(db, [])
        assert len(result) == 0

    def test_insert_multiple_events(self, db):
        events = [_make_event(event_id=f"evt-{i}") for i in range(5)]
        result = insert_events(db, events)
        assert len(result) == 5
        total = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        assert total == 5

    def test_geo_data_flattened(self, db):
        geo = {"country": "CN", "city": "Beijing", "asn": "AS4134", "org": "ChinaNet",
               "latitude": "39.9", "longitude": "116.4"}
        ev = _make_event(geo_data=geo)
        insert_events(db, [ev])
        row = db.execute("SELECT * FROM events WHERE event_id = ?", (ev["event_id"],)).fetchone()
        assert row["geo_country"] == "CN"
        assert row["geo_city"] == "Beijing"
        assert row["geo_asn"] == "AS4134"
        assert row["geo_org"] == "ChinaNet"
        assert row["geo_latitude"] == "39.9"
        assert row["geo_longitude"] == "116.4"

    def test_geo_data_stored_as_json(self, db):
        import json
        geo = {"country": "DE", "city": "Berlin"}
        ev = _make_event(geo_data=geo)
        insert_events(db, [ev])
        row = db.execute("SELECT geo_data FROM events WHERE event_id = ?", (ev["event_id"],)).fetchone()
        assert json.loads(row["geo_data"]) == geo

    def test_metadata_stored_as_json(self, db):
        import json
        meta = {"rule": "ssh_fast_brute", "attempts": 5}
        ev = _make_event(metadata=meta)
        insert_events(db, [ev])
        row = db.execute("SELECT metadata FROM events WHERE event_id = ?", (ev["event_id"],)).fetchone()
        assert json.loads(row["metadata"]) == meta

    def test_missing_geo_fields_stored_as_null(self, db):
        ev = _make_event(geo_data={})
        insert_events(db, [ev])
        row = db.execute("SELECT * FROM events WHERE event_id = ?", (ev["event_id"],)).fetchone()
        assert row["geo_country"] is None
        assert row["geo_city"] is None


class TestSearchEvents:
    """Tests for search_events()."""

    def _seed(self, db):
        """Insert a known set of events for search testing."""
        now = datetime.now(timezone.utc)
        events = [
            _make_event(event_id="s1", node_id="node-a", source_ip="1.1.1.1",
                        event_type="SSH_BRUTE", timestamp=(now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        geo_data={"country": "US"}),
            _make_event(event_id="s2", node_id="node-b", source_ip="2.2.2.2",
                        event_type="PORT_SCAN", timestamp=(now - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        geo_data={"country": "CN"}),
            _make_event(event_id="s3", node_id="node-a", source_ip="1.1.1.1",
                        event_type="SSH_BRUTE", timestamp=(now - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        geo_data={"country": "US"}),
            _make_event(event_id="s4", node_id="node-c", source_ip="3.3.3.3",
                        event_type="DNS_TUNNEL", timestamp=(now - timedelta(hours=4)).strftime("%Y-%m-%dT%H:%M:%SZ"),
                        geo_data={"country": "RU"}),
        ]
        insert_events(db, events)

    def test_no_filters_returns_all(self, db):
        self._seed(db)
        results, total = search_events(db, {})
        assert total == 4
        assert len(results) == 4

    def test_filter_by_source_ip(self, db):
        self._seed(db)
        results, total = search_events(db, {"source_ip": "1.1.1.1"})
        assert total == 2
        assert all(r["source_ip"] == "1.1.1.1" for r in results)

    def test_filter_by_node_id(self, db):
        self._seed(db)
        results, total = search_events(db, {"node_id": "node-b"})
        assert total == 1
        assert results[0]["event_id"] == "s2"

    def test_filter_by_event_type(self, db):
        self._seed(db)
        results, total = search_events(db, {"event_type": "SSH_BRUTE"})
        assert total == 2

    def test_filter_by_geo_country(self, db):
        self._seed(db)
        results, total = search_events(db, {"geo_country": "RU"})
        assert total == 1
        assert results[0]["event_id"] == "s4"

    def test_filter_by_time_range(self, db):
        self._seed(db)
        now = datetime.now(timezone.utc)
        start = (now - timedelta(hours=2, minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        end = (now - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")
        results, total = search_events(db, {"start_time": start, "end_time": end})
        assert total == 2  # s1 (1h ago) and s2 (2h ago)

    def test_intersection_semantics(self, db):
        self._seed(db)
        results, total = search_events(db, {"source_ip": "1.1.1.1", "event_type": "SSH_BRUTE"})
        assert total == 2
        # Now add a filter that narrows further
        results, total = search_events(db, {"source_ip": "1.1.1.1", "node_id": "node-b"})
        assert total == 0

    def test_pagination(self, db):
        self._seed(db)
        page1, total = search_events(db, {}, page=1, per_page=2)
        assert total == 4
        assert len(page1) == 2
        page2, _ = search_events(db, {}, page=2, per_page=2)
        assert len(page2) == 2
        # No overlap
        ids_p1 = {r["event_id"] for r in page1}
        ids_p2 = {r["event_id"] for r in page2}
        assert ids_p1.isdisjoint(ids_p2)

    def test_results_ordered_by_ingested_at_desc(self, db):
        self._seed(db)
        results, _ = search_events(db, {})
        # Events are ordered by timestamp DESC (agent-provided time), with
        # id ASC as tiebreaker for events sharing the same timestamp.
        # s1=1h ago, s2=2h ago, s3=3h ago, s4=4h ago → newest first.
        ids = [r["event_id"] for r in results]
        assert ids == ["s1", "s2", "s3", "s4"]


class TestGetDashboardStats:
    """Tests for get_dashboard_stats()."""

    def test_empty_database(self, db):
        stats = get_dashboard_stats(db)
        assert stats["total_events_24h"] == 0
        assert stats["active_nodes"] == 0
        assert stats["blocked_ips"] == 0
        assert stats["distinct_source_ips"] == 0
        assert stats["event_type_breakdown"] == []

    def test_counts_only_recent_events(self, db):
        now = datetime.now(timezone.utc)
        recent_ts = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        old_ts = (now - timedelta(hours=25)).strftime("%Y-%m-%dT%H:%M:%SZ")
        events = [
            _make_event(event_id="r1", timestamp=recent_ts, source_ip="1.1.1.1"),
            _make_event(event_id="r2", timestamp=recent_ts, source_ip="2.2.2.2",
                        action_taken="LOGGED"),
            _make_event(event_id="old1", timestamp=old_ts, source_ip="3.3.3.3"),
        ]
        insert_events(db, events)
        stats = get_dashboard_stats(db)
        assert stats["total_events_24h"] == 2
        assert stats["distinct_source_ips"] == 2
        # Only r1 has BLOCKED
        assert stats["blocked_ips"] == 1

    def test_active_nodes_within_15_minutes(self, db):
        now = datetime.now(timezone.utc)
        recent_ts = (now - timedelta(minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")
        old_ts = (now - timedelta(minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ")
        events = [
            _make_event(event_id="n1", node_id="active-node", timestamp=recent_ts),
            _make_event(event_id="n2", node_id="stale-node", timestamp=old_ts),
        ]
        insert_events(db, events)
        stats = get_dashboard_stats(db)
        assert stats["active_nodes"] == 1

    def test_event_type_breakdown(self, db):
        now = datetime.now(timezone.utc)
        ts = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        events = [
            _make_event(event_id="b1", event_type="SSH_BRUTE", timestamp=ts),
            _make_event(event_id="b2", event_type="SSH_BRUTE", timestamp=ts),
            _make_event(event_id="b3", event_type="PORT_SCAN", timestamp=ts),
        ]
        insert_events(db, events)
        stats = get_dashboard_stats(db)
        breakdown = stats["event_type_breakdown"]
        assert len(breakdown) == 2
        # Sorted by count DESC
        assert breakdown[0]["event_type"] == "SSH_BRUTE"
        assert breakdown[0]["count"] == 2
        assert breakdown[1]["event_type"] == "PORT_SCAN"
        assert breakdown[1]["count"] == 1


class TestGetRecentEvents:
    """Tests for get_recent_events()."""

    def test_empty_database(self, db):
        assert get_recent_events(db) == []

    def test_returns_limited_results(self, db):
        events = [_make_event(event_id=f"re-{i}") for i in range(15)]
        insert_events(db, events)
        recent = get_recent_events(db, limit=10)
        assert len(recent) == 10

    def test_custom_limit(self, db):
        events = [_make_event(event_id=f"re-{i}") for i in range(5)]
        insert_events(db, events)
        recent = get_recent_events(db, limit=3)
        assert len(recent) == 3

    def test_ordered_by_timestamp_desc_id_desc(self, db):
        events = [_make_event(event_id=f"re-{i}") for i in range(5)]
        insert_events(db, events)
        recent = get_recent_events(db)
        ids = [r["id"] for r in recent]
        # All events share the same timestamp (same batch), so the
        # tiebreaker is id DESC (most recently inserted first).
        assert ids == sorted(ids, reverse=True)


class TestGetEventsAfterId:
    """Tests for get_events_after_id()."""

    def test_returns_events_after_reference(self, db):
        events = [_make_event(event_id=f"aft-{i}") for i in range(5)]
        insert_events(db, events)
        # Get events after the second one
        after = get_events_after_id(db, "aft-1")
        event_ids = [r["event_id"] for r in after]
        assert "aft-0" not in event_ids
        assert "aft-1" not in event_ids
        assert "aft-2" in event_ids
        assert "aft-3" in event_ids
        assert "aft-4" in event_ids

    def test_ordered_by_id_asc(self, db):
        events = [_make_event(event_id=f"aft-{i}") for i in range(5)]
        insert_events(db, events)
        after = get_events_after_id(db, "aft-1")
        ids = [r["id"] for r in after]
        assert ids == sorted(ids)

    def test_unknown_event_id_returns_empty(self, db):
        events = [_make_event(event_id="aft-0")]
        insert_events(db, events)
        assert get_events_after_id(db, "nonexistent") == []

    def test_last_event_returns_empty(self, db):
        events = [_make_event(event_id=f"aft-{i}") for i in range(3)]
        insert_events(db, events)
        after = get_events_after_id(db, "aft-2")
        assert after == []

    def test_empty_database(self, db):
        assert get_events_after_id(db, "anything") == []


# ── User query helper tests (Task 2.3) ──────────────────────────────────

from werkzeug.security import check_password_hash

from app.models import (
    create_user,
    get_user_by_id,
    get_user_by_username,
    list_users,
    update_user_role,
)


class TestCreateUser:
    """Tests for create_user()."""

    def test_creates_user_and_returns_id(self, db):
        user_id = create_user(db, "alice", "secret123", "admin")
        assert isinstance(user_id, int)
        assert user_id > 0

    def test_password_is_hashed(self, db):
        create_user(db, "alice", "secret123", "admin")
        row = db.execute(
            "SELECT password_hash FROM users WHERE username = ?", ("alice",)
        ).fetchone()
        assert row is not None
        # The stored hash should NOT be the plaintext password
        assert row["password_hash"] != "secret123"
        # But it should verify against the original password
        assert check_password_hash(row["password_hash"], "secret123")

    def test_password_hash_does_not_verify_wrong_password(self, db):
        create_user(db, "alice", "secret123", "admin")
        row = db.execute(
            "SELECT password_hash FROM users WHERE username = ?", ("alice",)
        ).fetchone()
        assert not check_password_hash(row["password_hash"], "wrong_password")

    def test_role_is_stored(self, db):
        create_user(db, "bob", "pass", "analyst")
        row = db.execute(
            "SELECT role FROM users WHERE username = ?", ("bob",)
        ).fetchone()
        assert row["role"] == "analyst"

    def test_duplicate_username_raises(self, db):
        create_user(db, "alice", "pass1", "admin")
        with pytest.raises(sqlite3.IntegrityError):
            create_user(db, "alice", "pass2", "viewer")

    def test_invalid_role_raises(self, db):
        with pytest.raises(sqlite3.IntegrityError):
            create_user(db, "alice", "pass", "superadmin")

    def test_all_valid_roles(self, db):
        for i, role in enumerate(("admin", "analyst", "viewer")):
            user_id = create_user(db, f"user{i}", "pass", role)
            assert user_id > 0


class TestGetUserByUsername:
    """Tests for get_user_by_username()."""

    def test_returns_user_dict(self, db):
        create_user(db, "alice", "secret", "admin")
        user = get_user_by_username(db, "alice")
        assert user is not None
        assert isinstance(user, dict)
        assert user["username"] == "alice"
        assert user["role"] == "admin"
        assert "id" in user
        assert "password_hash" in user
        assert "created_at" in user

    def test_returns_none_for_missing_user(self, db):
        assert get_user_by_username(db, "nonexistent") is None

    def test_password_hash_is_included(self, db):
        create_user(db, "alice", "secret", "admin")
        user = get_user_by_username(db, "alice")
        assert check_password_hash(user["password_hash"], "secret")


class TestGetUserById:
    """Tests for get_user_by_id()."""

    def test_returns_user_dict(self, db):
        user_id = create_user(db, "alice", "secret", "admin")
        user = get_user_by_id(db, user_id)
        assert user is not None
        assert user["username"] == "alice"
        assert user["id"] == user_id

    def test_returns_none_for_missing_id(self, db):
        assert get_user_by_id(db, 9999) is None


class TestUpdateUserRole:
    """Tests for update_user_role()."""

    def test_updates_role(self, db):
        user_id = create_user(db, "alice", "secret", "viewer")
        update_user_role(db, user_id, "admin")
        user = get_user_by_id(db, user_id)
        assert user["role"] == "admin"

    def test_invalid_role_raises(self, db):
        user_id = create_user(db, "alice", "secret", "viewer")
        with pytest.raises(sqlite3.IntegrityError):
            update_user_role(db, user_id, "superadmin")

    def test_nonexistent_user_no_error(self, db):
        # Updating a non-existent user should not raise, just affect 0 rows
        update_user_role(db, 9999, "admin")


class TestListUsers:
    """Tests for list_users()."""

    def test_empty_database(self, db):
        assert list_users(db) == []

    def test_returns_all_users(self, db):
        create_user(db, "alice", "pass1", "admin")
        create_user(db, "bob", "pass2", "analyst")
        create_user(db, "carol", "pass3", "viewer")
        users = list_users(db)
        assert len(users) == 3
        usernames = [u["username"] for u in users]
        assert "alice" in usernames
        assert "bob" in usernames
        assert "carol" in usernames

    def test_does_not_include_password_hash(self, db):
        create_user(db, "alice", "pass1", "admin")
        users = list_users(db)
        assert len(users) == 1
        assert "password_hash" not in users[0]

    def test_includes_expected_fields(self, db):
        create_user(db, "alice", "pass1", "admin")
        users = list_users(db)
        user = users[0]
        assert "id" in user
        assert "username" in user
        assert "role" in user
        assert "created_at" in user
        assert "last_login_at" in user

    def test_ordered_by_id(self, db):
        create_user(db, "alice", "pass1", "admin")
        create_user(db, "bob", "pass2", "analyst")
        create_user(db, "carol", "pass3", "viewer")
        users = list_users(db)
        ids = [u["id"] for u in users]
        assert ids == sorted(ids)


# ── API key query helper tests (Task 2.4) ────────────────────────────────

import hashlib

from app.models import (
    create_api_key,
    list_api_keys,
    revoke_api_key,
    update_api_key_last_used,
    verify_api_key,
)


class TestCreateApiKey:
    """Tests for create_api_key()."""

    def test_returns_raw_token_string(self, db):
        admin_id = create_user(db, "admin", "pass", "admin")
        token = create_api_key(db, "test-key", None, admin_id)
        assert isinstance(token, str)
        assert len(token) > 0

    def test_token_is_unique_each_call(self, db):
        admin_id = create_user(db, "admin", "pass", "admin")
        t1 = create_api_key(db, "key-1", None, admin_id)
        t2 = create_api_key(db, "key-2", None, admin_id)
        assert t1 != t2

    def test_stores_sha256_hash(self, db):
        admin_id = create_user(db, "admin", "pass", "admin")
        token = create_api_key(db, "test-key", None, admin_id)
        expected_hash = hashlib.sha256(token.encode()).hexdigest()
        row = db.execute(
            "SELECT key_hash FROM api_keys WHERE key_prefix = ?",
            (token[:8],),
        ).fetchone()
        assert row is not None
        assert row["key_hash"] == expected_hash

    def test_stores_prefix_first_8_chars(self, db):
        admin_id = create_user(db, "admin", "pass", "admin")
        token = create_api_key(db, "test-key", None, admin_id)
        row = db.execute(
            "SELECT key_prefix FROM api_keys WHERE key_hash = ?",
            (hashlib.sha256(token.encode()).hexdigest(),),
        ).fetchone()
        assert row["key_prefix"] == token[:8]

    def test_stores_label(self, db):
        admin_id = create_user(db, "admin", "pass", "admin")
        token = create_api_key(db, "my-node-key", None, admin_id)
        row = db.execute(
            "SELECT label FROM api_keys WHERE key_hash = ?",
            (hashlib.sha256(token.encode()).hexdigest(),),
        ).fetchone()
        assert row["label"] == "my-node-key"

    def test_stores_node_id_restriction(self, db):
        admin_id = create_user(db, "admin", "pass", "admin")
        token = create_api_key(db, "restricted", "node-abc", admin_id)
        row = db.execute(
            "SELECT node_id_restriction FROM api_keys WHERE key_hash = ?",
            (hashlib.sha256(token.encode()).hexdigest(),),
        ).fetchone()
        assert row["node_id_restriction"] == "node-abc"

    def test_null_node_id_restriction(self, db):
        admin_id = create_user(db, "admin", "pass", "admin")
        token = create_api_key(db, "unrestricted", None, admin_id)
        row = db.execute(
            "SELECT node_id_restriction FROM api_keys WHERE key_hash = ?",
            (hashlib.sha256(token.encode()).hexdigest(),),
        ).fetchone()
        assert row["node_id_restriction"] is None

    def test_stores_created_by(self, db):
        admin_id = create_user(db, "admin", "pass", "admin")
        token = create_api_key(db, "test-key", None, admin_id)
        row = db.execute(
            "SELECT created_by FROM api_keys WHERE key_hash = ?",
            (hashlib.sha256(token.encode()).hexdigest(),),
        ).fetchone()
        assert row["created_by"] == admin_id

    def test_key_is_active_by_default(self, db):
        admin_id = create_user(db, "admin", "pass", "admin")
        token = create_api_key(db, "test-key", None, admin_id)
        row = db.execute(
            "SELECT is_active FROM api_keys WHERE key_hash = ?",
            (hashlib.sha256(token.encode()).hexdigest(),),
        ).fetchone()
        assert row["is_active"] == 1


class TestVerifyApiKey:
    """Tests for verify_api_key()."""

    def test_valid_token_returns_dict(self, db):
        admin_id = create_user(db, "admin", "pass", "admin")
        token = create_api_key(db, "test-key", None, admin_id)
        result = verify_api_key(db, token)
        assert result is not None
        assert isinstance(result, dict)
        assert result["label"] == "test-key"
        assert result["is_active"] == 1

    def test_invalid_token_returns_none(self, db):
        assert verify_api_key(db, "totally-bogus-token") is None

    def test_revoked_key_returns_none(self, db):
        admin_id = create_user(db, "admin", "pass", "admin")
        token = create_api_key(db, "test-key", None, admin_id)
        # Revoke directly via SQL to isolate verify logic
        key_hash = hashlib.sha256(token.encode()).hexdigest()
        db.execute("UPDATE api_keys SET is_active = 0 WHERE key_hash = ?", (key_hash,))
        db.commit()
        assert verify_api_key(db, token) is None

    def test_returns_all_key_fields(self, db):
        admin_id = create_user(db, "admin", "pass", "admin")
        token = create_api_key(db, "full-key", "node-x", admin_id)
        result = verify_api_key(db, token)
        assert "id" in result
        assert "key_hash" in result
        assert "key_prefix" in result
        assert "label" in result
        assert "node_id_restriction" in result
        assert result["node_id_restriction"] == "node-x"
        assert "created_at" in result
        assert "created_by" in result


class TestRevokeApiKey:
    """Tests for revoke_api_key()."""

    def test_revoke_makes_key_inactive(self, db):
        admin_id = create_user(db, "admin", "pass", "admin")
        token = create_api_key(db, "test-key", None, admin_id)
        # Get the key id
        key_hash = hashlib.sha256(token.encode()).hexdigest()
        key_id = db.execute(
            "SELECT id FROM api_keys WHERE key_hash = ?", (key_hash,)
        ).fetchone()["id"]
        revoke_api_key(db, key_id)
        row = db.execute(
            "SELECT is_active FROM api_keys WHERE id = ?", (key_id,)
        ).fetchone()
        assert row["is_active"] == 0

    def test_revoked_key_fails_verification(self, db):
        admin_id = create_user(db, "admin", "pass", "admin")
        token = create_api_key(db, "test-key", None, admin_id)
        key_hash = hashlib.sha256(token.encode()).hexdigest()
        key_id = db.execute(
            "SELECT id FROM api_keys WHERE key_hash = ?", (key_hash,)
        ).fetchone()["id"]
        revoke_api_key(db, key_id)
        assert verify_api_key(db, token) is None

    def test_revoke_nonexistent_key_no_error(self, db):
        # Should not raise, just affect 0 rows
        revoke_api_key(db, 9999)


class TestListApiKeys:
    """Tests for list_api_keys()."""

    def test_empty_database(self, db):
        assert list_api_keys(db) == []

    def test_returns_all_keys(self, db):
        admin_id = create_user(db, "admin", "pass", "admin")
        create_api_key(db, "key-1", None, admin_id)
        create_api_key(db, "key-2", "node-a", admin_id)
        create_api_key(db, "key-3", None, admin_id)
        keys = list_api_keys(db)
        assert len(keys) == 3

    def test_does_not_include_key_hash(self, db):
        admin_id = create_user(db, "admin", "pass", "admin")
        create_api_key(db, "test-key", None, admin_id)
        keys = list_api_keys(db)
        assert len(keys) == 1
        assert "key_hash" not in keys[0]

    def test_includes_expected_fields(self, db):
        admin_id = create_user(db, "admin", "pass", "admin")
        create_api_key(db, "test-key", "node-x", admin_id)
        keys = list_api_keys(db)
        key = keys[0]
        assert "id" in key
        assert "key_prefix" in key
        assert "label" in key
        assert key["label"] == "test-key"
        assert "node_id_restriction" in key
        assert key["node_id_restriction"] == "node-x"
        assert "is_active" in key
        assert "created_at" in key
        assert "last_used_at" in key
        assert "created_by" in key

    def test_ordered_by_id(self, db):
        admin_id = create_user(db, "admin", "pass", "admin")
        create_api_key(db, "key-1", None, admin_id)
        create_api_key(db, "key-2", None, admin_id)
        create_api_key(db, "key-3", None, admin_id)
        keys = list_api_keys(db)
        ids = [k["id"] for k in keys]
        assert ids == sorted(ids)

    def test_includes_revoked_keys(self, db):
        admin_id = create_user(db, "admin", "pass", "admin")
        token = create_api_key(db, "active-key", None, admin_id)
        create_api_key(db, "revoked-key", None, admin_id)
        # Revoke the second key
        keys_before = list_api_keys(db)
        revoke_api_key(db, keys_before[1]["id"])
        keys = list_api_keys(db)
        assert len(keys) == 2
        statuses = {k["label"]: k["is_active"] for k in keys}
        assert statuses["active-key"] == 1
        assert statuses["revoked-key"] == 0


class TestUpdateApiKeyLastUsed:
    """Tests for update_api_key_last_used()."""

    def test_sets_last_used_at(self, db):
        admin_id = create_user(db, "admin", "pass", "admin")
        token = create_api_key(db, "test-key", None, admin_id)
        key_hash = hashlib.sha256(token.encode()).hexdigest()
        key_id = db.execute(
            "SELECT id FROM api_keys WHERE key_hash = ?", (key_hash,)
        ).fetchone()["id"]
        # Initially last_used_at should be None
        row = db.execute(
            "SELECT last_used_at FROM api_keys WHERE id = ?", (key_id,)
        ).fetchone()
        assert row["last_used_at"] is None
        # Update last used
        update_api_key_last_used(db, key_id)
        row = db.execute(
            "SELECT last_used_at FROM api_keys WHERE id = ?", (key_id,)
        ).fetchone()
        assert row["last_used_at"] is not None
        # Should be a valid ISO-8601 timestamp
        assert "T" in row["last_used_at"]
        assert row["last_used_at"].endswith("Z")

    def test_updates_timestamp_on_subsequent_calls(self, db):
        import time
        admin_id = create_user(db, "admin", "pass", "admin")
        token = create_api_key(db, "test-key", None, admin_id)
        key_hash = hashlib.sha256(token.encode()).hexdigest()
        key_id = db.execute(
            "SELECT id FROM api_keys WHERE key_hash = ?", (key_hash,)
        ).fetchone()["id"]
        update_api_key_last_used(db, key_id)
        first = db.execute(
            "SELECT last_used_at FROM api_keys WHERE id = ?", (key_id,)
        ).fetchone()["last_used_at"]
        # SQLite strftime has second-level precision, so the value should
        # be at least the same (within the same second) or later
        update_api_key_last_used(db, key_id)
        second = db.execute(
            "SELECT last_used_at FROM api_keys WHERE id = ?", (key_id,)
        ).fetchone()["last_used_at"]
        assert second >= first

    def test_nonexistent_key_no_error(self, db):
        # Should not raise, just affect 0 rows
        update_api_key_last_used(db, 9999)


# ── Node registry helper tests (Task 2.5) ────────────────────────────────

import json
import time

from app.models import (
    get_node_health,
    list_nodes,
    upsert_node,
)


class TestUpsertNode:
    """Tests for upsert_node()."""

    def test_insert_new_node(self, db):
        upsert_node(db, "node-a", "2025-01-15T10:00:00Z", {"country": "US"})
        row = db.execute("SELECT * FROM nodes WHERE node_id = ?", ("node-a",)).fetchone()
        assert row is not None
        assert row["node_id"] == "node-a"
        assert row["total_events"] == 1
        assert row["last_event_at"] == "2025-01-15T10:00:00Z"
        assert json.loads(row["last_geo_data"]) == {"country": "US"}

    def test_update_existing_node_increments_total(self, db):
        upsert_node(db, "node-a", "2025-01-15T10:00:00Z", {"country": "US"})
        upsert_node(db, "node-a", "2025-01-15T10:01:00Z", {"country": "US"})
        row = db.execute("SELECT * FROM nodes WHERE node_id = ?", ("node-a",)).fetchone()
        assert row["total_events"] == 2

    def test_update_with_newer_timestamp_updates_last_event(self, db):
        upsert_node(db, "node-a", "2025-01-15T10:00:00Z", {"country": "US"})
        upsert_node(db, "node-a", "2025-01-15T11:00:00Z", {"country": "DE"})
        row = db.execute("SELECT * FROM nodes WHERE node_id = ?", ("node-a",)).fetchone()
        assert row["last_event_at"] == "2025-01-15T11:00:00Z"
        assert json.loads(row["last_geo_data"]) == {"country": "DE"}

    def test_update_with_older_timestamp_does_not_update_last_event(self, db):
        upsert_node(db, "node-a", "2025-01-15T11:00:00Z", {"country": "DE"})
        upsert_node(db, "node-a", "2025-01-15T10:00:00Z", {"country": "US"})
        row = db.execute("SELECT * FROM nodes WHERE node_id = ?", ("node-a",)).fetchone()
        assert row["total_events"] == 2
        # last_event_at and geo_data should still reflect the newer event
        assert row["last_event_at"] == "2025-01-15T11:00:00Z"
        assert json.loads(row["last_geo_data"]) == {"country": "DE"}

    def test_multiple_distinct_nodes(self, db):
        upsert_node(db, "node-a", "2025-01-15T10:00:00Z", {"country": "US"})
        upsert_node(db, "node-b", "2025-01-15T10:00:00Z", {"country": "CN"})
        count = db.execute("SELECT COUNT(*) FROM nodes").fetchone()[0]
        assert count == 2

    def test_geo_data_stored_as_json(self, db):
        geo = {"country": "JP", "city": "Tokyo", "asn": "AS2497"}
        upsert_node(db, "node-a", "2025-01-15T10:00:00Z", geo)
        row = db.execute("SELECT last_geo_data FROM nodes WHERE node_id = ?", ("node-a",)).fetchone()
        assert json.loads(row["last_geo_data"]) == geo

    def test_empty_geo_data(self, db):
        upsert_node(db, "node-a", "2025-01-15T10:00:00Z", {})
        row = db.execute("SELECT last_geo_data FROM nodes WHERE node_id = ?", ("node-a",)).fetchone()
        assert json.loads(row["last_geo_data"]) == {}

    def test_many_upserts_same_node(self, db):
        for i in range(10):
            ts = f"2025-01-15T10:{i:02d}:00Z"
            upsert_node(db, "node-a", ts, {"country": "US"})
        row = db.execute("SELECT * FROM nodes WHERE node_id = ?", ("node-a",)).fetchone()
        assert row["total_events"] == 10
        assert row["last_event_at"] == "2025-01-15T10:09:00Z"


class TestListNodes:
    """Tests for list_nodes()."""

    def test_empty_database(self, db):
        assert list_nodes(db) == []

    def test_returns_all_nodes(self, db):
        upsert_node(db, "node-a", "2025-01-15T10:00:00Z", {"country": "US"})
        upsert_node(db, "node-b", "2025-01-15T10:00:00Z", {"country": "CN"})
        upsert_node(db, "node-c", "2025-01-15T10:00:00Z", {"country": "DE"})
        nodes = list_nodes(db)
        assert len(nodes) == 3

    def test_ordered_by_node_id(self, db):
        upsert_node(db, "node-c", "2025-01-15T10:00:00Z", {})
        upsert_node(db, "node-a", "2025-01-15T10:00:00Z", {})
        upsert_node(db, "node-b", "2025-01-15T10:00:00Z", {})
        nodes = list_nodes(db)
        node_ids = [n["node_id"] for n in nodes]
        assert node_ids == ["node-a", "node-b", "node-c"]

    def test_includes_expected_fields(self, db):
        upsert_node(db, "node-a", "2025-01-15T10:00:00Z", {"country": "US"})
        nodes = list_nodes(db)
        node = nodes[0]
        assert "id" in node
        assert "node_id" in node
        assert "first_seen_at" in node
        assert "last_event_at" in node
        assert "total_events" in node
        assert "last_geo_data" in node

    def test_returns_dicts(self, db):
        upsert_node(db, "node-a", "2025-01-15T10:00:00Z", {})
        nodes = list_nodes(db)
        assert isinstance(nodes[0], dict)


class TestGetNodeHealth:
    """Tests for get_node_health()."""

    def test_none_returns_offline(self):
        assert get_node_health(None) == "offline"

    def test_recent_timestamp_returns_healthy(self):
        now = datetime.now(timezone.utc)
        ts = now.strftime("%Y-%m-%dT%H:%M:%SZ")
        assert get_node_health(ts) == "healthy"

    def test_slightly_old_returns_healthy(self):
        now = datetime.now(timezone.utc)
        ts = (now - timedelta(seconds=100)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert get_node_health(ts) == "healthy"

    def test_five_minutes_ago_returns_degraded(self):
        now = datetime.now(timezone.utc)
        ts = (now - timedelta(seconds=350)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert get_node_health(ts) == "degraded"

    def test_ten_minutes_ago_returns_degraded(self):
        now = datetime.now(timezone.utc)
        ts = (now - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert get_node_health(ts) == "degraded"

    def test_fifteen_minutes_ago_returns_offline(self):
        now = datetime.now(timezone.utc)
        ts = (now - timedelta(seconds=900)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert get_node_health(ts) == "offline"

    def test_very_old_returns_offline(self):
        assert get_node_health("2020-01-01T00:00:00Z") == "offline"

    def test_custom_thresholds(self):
        now = datetime.now(timezone.utc)
        # 200 seconds ago — healthy with default, but degraded with custom
        ts = (now - timedelta(seconds=200)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert get_node_health(ts, healthy_seconds=100, degraded_seconds=300) == "degraded"

    def test_custom_thresholds_offline(self):
        now = datetime.now(timezone.utc)
        ts = (now - timedelta(seconds=400)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert get_node_health(ts, healthy_seconds=100, degraded_seconds=300) == "offline"

    def test_invalid_timestamp_returns_offline(self):
        assert get_node_health("not-a-timestamp") == "offline"

    def test_boundary_at_healthy_threshold(self):
        """At exactly 300 seconds, should be degraded (not healthy)."""
        now = datetime.now(timezone.utc)
        ts = (now - timedelta(seconds=300)).strftime("%Y-%m-%dT%H:%M:%SZ")
        # 300 seconds is NOT < 300, so it should be degraded
        assert get_node_health(ts) == "degraded"

    def test_boundary_just_under_healthy(self):
        """At 299 seconds, should still be healthy."""
        now = datetime.now(timezone.utc)
        ts = (now - timedelta(seconds=299)).strftime("%Y-%m-%dT%H:%M:%SZ")
        assert get_node_health(ts) == "healthy"

    def test_boundary_at_degraded_threshold(self):
        """At exactly 900 seconds, should be offline."""
        now = datetime.now(timezone.utc)
        ts = (now - timedelta(seconds=900)).strftime("%Y-%m-%dT%H:%M:%SZ")
        # 900 seconds is NOT < 900, so it should be offline
        assert get_node_health(ts) == "offline"


# ── Audit log helper tests (Task 2.6) ────────────────────────────────────

from app.models import record_audit, search_audit_log, VALID_AUDIT_ACTION_TYPES


class TestRecordAudit:
    """Tests for record_audit()."""

    def test_inserts_audit_entry(self, db):
        entry_id = record_audit(
            db, "admin", "10.0.0.1", "login", None, {"outcome": "success"}
        )
        assert isinstance(entry_id, int)
        assert entry_id > 0
        row = db.execute(
            "SELECT * FROM audit_log WHERE id = ?", (entry_id,)
        ).fetchone()
        assert row is not None
        assert row["actor"] == "admin"
        assert row["actor_ip"] == "10.0.0.1"
        assert row["action_type"] == "login"
        assert row["target"] is None
        assert json.loads(row["details"]) == {"outcome": "success"}

    def test_stores_target(self, db):
        entry_id = record_audit(
            db, "admin", "10.0.0.1", "role_change", "bob",
            {"old_role": "viewer", "new_role": "analyst"},
        )
        row = db.execute(
            "SELECT target FROM audit_log WHERE id = ?", (entry_id,)
        ).fetchone()
        assert row["target"] == "bob"

    def test_actor_ip_can_be_none(self, db):
        entry_id = record_audit(
            db, "system", None, "login_failed", "unknown_user", {}
        )
        row = db.execute(
            "SELECT actor_ip FROM audit_log WHERE id = ?", (entry_id,)
        ).fetchone()
        assert row["actor_ip"] is None

    def test_details_stored_as_json(self, db):
        details = {"old_role": "viewer", "new_role": "admin", "reason": "promotion"}
        entry_id = record_audit(
            db, "admin", "10.0.0.1", "role_change", "carol", details
        )
        row = db.execute(
            "SELECT details FROM audit_log WHERE id = ?", (entry_id,)
        ).fetchone()
        assert json.loads(row["details"]) == details

    def test_empty_details_stored_as_empty_json_object(self, db):
        entry_id = record_audit(db, "admin", "10.0.0.1", "logout", None, {})
        row = db.execute(
            "SELECT details FROM audit_log WHERE id = ?", (entry_id,)
        ).fetchone()
        assert json.loads(row["details"]) == {}

    def test_timestamp_is_set_automatically(self, db):
        entry_id = record_audit(db, "admin", "10.0.0.1", "login", None, {})
        row = db.execute(
            "SELECT timestamp FROM audit_log WHERE id = ?", (entry_id,)
        ).fetchone()
        assert row["timestamp"] is not None
        assert "T" in row["timestamp"]
        assert row["timestamp"].endswith("Z")

    def test_all_valid_action_types(self, db):
        for i, action in enumerate(sorted(VALID_AUDIT_ACTION_TYPES)):
            entry_id = record_audit(
                db, f"user{i}", "10.0.0.1", action, None, {}
            )
            assert entry_id > 0

    def test_invalid_action_type_raises_value_error(self, db):
        with pytest.raises(ValueError, match="Invalid action_type"):
            record_audit(db, "admin", "10.0.0.1", "invalid_action", None, {})

    def test_multiple_entries(self, db):
        record_audit(db, "alice", "10.0.0.1", "login", None, {})
        record_audit(db, "bob", "10.0.0.2", "login", None, {})
        record_audit(db, "alice", "10.0.0.1", "logout", None, {})
        count = db.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        assert count == 3


class TestSearchAuditLog:
    """Tests for search_audit_log()."""

    def _seed(self, db):
        """Insert a known set of audit entries for search testing.

        Uses direct SQL to control timestamps precisely.
        """
        entries = [
            ("alice", "10.0.0.1", "login", None, "{}", "2025-01-15T10:00:00Z"),
            ("bob", "10.0.0.2", "login_failed", "bob", '{"reason": "bad password"}', "2025-01-15T11:00:00Z"),
            ("alice", "10.0.0.1", "role_change", "carol", '{"old_role": "viewer", "new_role": "analyst"}', "2025-01-15T12:00:00Z"),
            ("alice", "10.0.0.1", "key_create", "node-key-1", "{}", "2025-01-15T13:00:00Z"),
            ("alice", "10.0.0.1", "logout", None, "{}", "2025-01-15T14:00:00Z"),
        ]
        for actor, ip, action, target, details, ts in entries:
            db.execute(
                "INSERT INTO audit_log (actor, actor_ip, action_type, target, details, timestamp) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (actor, ip, action, target, details, ts),
            )
        db.commit()

    def test_no_filters_returns_all(self, db):
        self._seed(db)
        results, total = search_audit_log(db)
        assert len(results) == 5
        assert total == 5

    def test_ordered_by_timestamp_desc(self, db):
        self._seed(db)
        results, _ = search_audit_log(db)
        timestamps = [r["timestamp"] for r in results]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_filter_by_action_type(self, db):
        self._seed(db)
        results, total = search_audit_log(db, action_type="login")
        assert len(results) == 1
        assert total == 1
        assert results[0]["actor"] == "alice"
        assert results[0]["action_type"] == "login"

    def test_filter_by_action_type_login_failed(self, db):
        self._seed(db)
        results, _ = search_audit_log(db, action_type="login_failed")
        assert len(results) == 1
        assert results[0]["actor"] == "bob"

    def test_filter_by_start_time(self, db):
        self._seed(db)
        results, total = search_audit_log(db, start="2025-01-15T12:00:00Z")
        assert len(results) == 3  # 12:00, 13:00, 14:00
        assert total == 3

    def test_filter_by_end_time(self, db):
        self._seed(db)
        results, total = search_audit_log(db, end="2025-01-15T11:00:00Z")
        assert len(results) == 2  # 10:00, 11:00
        assert total == 2

    def test_filter_by_time_range(self, db):
        self._seed(db)
        results, total = search_audit_log(
            db, start="2025-01-15T11:00:00Z", end="2025-01-15T13:00:00Z"
        )
        assert len(results) == 3  # 11:00, 12:00, 13:00
        assert total == 3

    def test_combined_action_type_and_time_range(self, db):
        self._seed(db)
        results, total = search_audit_log(
            db, action_type="login", start="2025-01-15T09:00:00Z",
            end="2025-01-15T15:00:00Z"
        )
        assert len(results) == 1
        assert total == 1
        assert results[0]["action_type"] == "login"

    def test_no_matching_results(self, db):
        self._seed(db)
        results, total = search_audit_log(db, action_type="block")
        assert results == []
        assert total == 0

    def test_empty_database(self, db):
        results, total = search_audit_log(db)
        assert results == []
        assert total == 0

    def test_returns_dicts(self, db):
        self._seed(db)
        results, _ = search_audit_log(db)
        assert all(isinstance(r, dict) for r in results)

    def test_includes_expected_fields(self, db):
        self._seed(db)
        results, _ = search_audit_log(db)
        entry = results[0]
        assert "id" in entry
        assert "timestamp" in entry
        assert "actor" in entry
        assert "actor_ip" in entry
        assert "action_type" in entry
        assert "target" in entry
        assert "details" in entry

    def test_filter_by_actor(self, db):
        self._seed(db)
        results, total = search_audit_log(db, actor="bob")
        assert len(results) == 1
        assert total == 1
        assert results[0]["actor"] == "bob"

    def test_filter_by_target(self, db):
        self._seed(db)
        results, total = search_audit_log(db, target="carol")
        assert len(results) == 1
        assert total == 1
        assert results[0]["action_type"] == "role_change"

    def test_pagination(self, db):
        self._seed(db)
        results, total = search_audit_log(db, page=1, per_page=2)
        assert len(results) == 2
        assert total == 5
        results2, total2 = search_audit_log(db, page=2, per_page=2)
        assert len(results2) == 2
        assert total2 == 5
        results3, total3 = search_audit_log(db, page=3, per_page=2)
        assert len(results3) == 1
        assert total3 == 5


# ── Geographic and trend query helper tests (Task 2.7) ───────────────────

from app.models import get_country_breakdown, get_events_by_country, get_time_series


class TestGetCountryBreakdown:
    """Tests for get_country_breakdown()."""

    def test_empty_database(self, db):
        assert get_country_breakdown(db) == []

    def test_single_country(self, db):
        events = [
            _make_event(event_id="c1", geo_data={"country": "US"}),
            _make_event(event_id="c2", geo_data={"country": "US"}),
        ]
        insert_events(db, events)
        result = get_country_breakdown(db)
        assert len(result) == 1
        assert result[0] == {"country": "US", "count": 2}

    def test_multiple_countries_sorted_by_count_desc(self, db):
        events = [
            _make_event(event_id="c1", geo_data={"country": "US"}),
            _make_event(event_id="c2", geo_data={"country": "US"}),
            _make_event(event_id="c3", geo_data={"country": "US"}),
            _make_event(event_id="c4", geo_data={"country": "CN"}),
            _make_event(event_id="c5", geo_data={"country": "CN"}),
            _make_event(event_id="c6", geo_data={"country": "RU"}),
        ]
        insert_events(db, events)
        result = get_country_breakdown(db)
        assert len(result) == 3
        assert result[0] == {"country": "US", "count": 3}
        assert result[1] == {"country": "CN", "count": 2}
        assert result[2] == {"country": "RU", "count": 1}

    def test_excludes_null_country(self, db):
        events = [
            _make_event(event_id="c1", geo_data={"country": "US"}),
            _make_event(event_id="c2", geo_data={}),  # no country -> NULL
        ]
        insert_events(db, events)
        result = get_country_breakdown(db)
        assert len(result) == 1
        assert result[0]["country"] == "US"

    def test_returns_dicts(self, db):
        events = [_make_event(event_id="c1", geo_data={"country": "DE"})]
        insert_events(db, events)
        result = get_country_breakdown(db)
        assert isinstance(result[0], dict)
        assert "country" in result[0]
        assert "count" in result[0]


class TestGetEventsByCountry:
    """Tests for get_events_by_country()."""

    def test_empty_database(self, db):
        assert get_events_by_country(db, "US") == []

    def test_returns_matching_events(self, db):
        now = datetime.now(timezone.utc)
        events = [
            _make_event(event_id="e1", geo_data={"country": "US"},
                        timestamp=(now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")),
            _make_event(event_id="e2", geo_data={"country": "CN"},
                        timestamp=(now - timedelta(hours=2)).strftime("%Y-%m-%dT%H:%M:%SZ")),
            _make_event(event_id="e3", geo_data={"country": "US"},
                        timestamp=(now - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")),
        ]
        insert_events(db, events)
        result = get_events_by_country(db, "US")
        assert len(result) == 2
        assert all(r["geo_country"] == "US" for r in result)

    def test_ordered_by_timestamp_desc(self, db):
        now = datetime.now(timezone.utc)
        events = [
            _make_event(event_id="e1", geo_data={"country": "US"},
                        timestamp=(now - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")),
            _make_event(event_id="e2", geo_data={"country": "US"},
                        timestamp=(now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")),
        ]
        insert_events(db, events)
        result = get_events_by_country(db, "US")
        timestamps = [r["timestamp"] for r in result]
        assert timestamps == sorted(timestamps, reverse=True)

    def test_no_matching_country(self, db):
        events = [_make_event(event_id="e1", geo_data={"country": "US"})]
        insert_events(db, events)
        result = get_events_by_country(db, "JP")
        assert result == []

    def test_returns_full_event_dicts(self, db):
        events = [_make_event(event_id="e1", geo_data={"country": "DE"},
                              source_ip="5.5.5.5", event_type="PORT_SCAN")]
        insert_events(db, events)
        result = get_events_by_country(db, "DE")
        assert len(result) == 1
        ev = result[0]
        assert ev["event_id"] == "e1"
        assert ev["source_ip"] == "5.5.5.5"
        assert ev["event_type"] == "PORT_SCAN"
        assert ev["geo_country"] == "DE"


class TestGetTimeSeries:
    """Tests for get_time_series()."""

    def test_empty_database(self, db):
        result = get_time_series(db, "24h")
        assert result == []

    def test_invalid_interval_raises(self, db):
        with pytest.raises(ValueError, match="Invalid interval"):
            get_time_series(db, "2h")

    def test_invalid_group_by_raises(self, db):
        with pytest.raises(ValueError, match="Invalid group_by"):
            get_time_series(db, "24h", group_by="invalid_column")

    def test_24h_buckets_by_hour(self, db):
        now = datetime.now(timezone.utc)
        events = [
            _make_event(event_id="t1",
                        timestamp=(now - timedelta(hours=2, minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")),
            _make_event(event_id="t2",
                        timestamp=(now - timedelta(hours=2, minutes=20)).strftime("%Y-%m-%dT%H:%M:%SZ")),
            _make_event(event_id="t3",
                        timestamp=(now - timedelta(hours=1, minutes=5)).strftime("%Y-%m-%dT%H:%M:%SZ")),
        ]
        insert_events(db, events)
        result = get_time_series(db, "24h")
        # Should have 2 buckets: one for ~2h ago, one for ~1h ago
        assert len(result) == 2
        # First bucket (earlier) should have 2 events
        assert result[0]["count"] == 2
        assert result[1]["count"] == 1
        # Buckets should be in chronological order
        assert result[0]["bucket"] < result[1]["bucket"]
        # No "group" key when group_by is None
        assert "group" not in result[0]

    def test_24h_bucket_format(self, db):
        now = datetime.now(timezone.utc)
        ts = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        events = [_make_event(event_id="t1", timestamp=ts)]
        insert_events(db, events)
        result = get_time_series(db, "24h")
        assert len(result) == 1
        # 24h bucket format should be YYYY-MM-DDTHH:00
        assert result[0]["bucket"].endswith(":00")

    def test_7d_buckets_by_day(self, db):
        now = datetime.now(timezone.utc)
        events = [
            _make_event(event_id="t1",
                        timestamp=(now - timedelta(days=1)).strftime("%Y-%m-%dT%H:%M:%SZ")),
            _make_event(event_id="t2",
                        timestamp=(now - timedelta(days=1, minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")),
            _make_event(event_id="t3",
                        timestamp=(now - timedelta(days=3)).strftime("%Y-%m-%dT%H:%M:%SZ")),
        ]
        insert_events(db, events)
        result = get_time_series(db, "7d")
        assert len(result) == 2
        # 7d bucket format should be YYYY-MM-DD
        for entry in result:
            assert "T" not in entry["bucket"]

    def test_group_by_event_type(self, db):
        now = datetime.now(timezone.utc)
        ts = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        events = [
            _make_event(event_id="t1", event_type="SSH_BRUTE", timestamp=ts),
            _make_event(event_id="t2", event_type="SSH_BRUTE", timestamp=ts),
            _make_event(event_id="t3", event_type="PORT_SCAN", timestamp=ts),
        ]
        insert_events(db, events)
        result = get_time_series(db, "24h", group_by="event_type")
        # Should have entries with "group" key
        assert all("group" in entry for entry in result)
        groups = {entry["group"] for entry in result}
        assert "SSH_BRUTE" in groups
        assert "PORT_SCAN" in groups
        # Total count across groups should be 3
        total = sum(entry["count"] for entry in result)
        assert total == 3

    def test_group_by_node_id(self, db):
        now = datetime.now(timezone.utc)
        ts = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        events = [
            _make_event(event_id="t1", node_id="node-a", timestamp=ts),
            _make_event(event_id="t2", node_id="node-b", timestamp=ts),
        ]
        insert_events(db, events)
        result = get_time_series(db, "24h", group_by="node_id")
        groups = {entry["group"] for entry in result}
        assert "node-a" in groups
        assert "node-b" in groups

    def test_group_by_source_ip(self, db):
        now = datetime.now(timezone.utc)
        ts = (now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        events = [
            _make_event(event_id="t1", source_ip="1.1.1.1", timestamp=ts),
            _make_event(event_id="t2", source_ip="2.2.2.2", timestamp=ts),
        ]
        insert_events(db, events)
        result = get_time_series(db, "24h", group_by="source_ip")
        groups = {entry["group"] for entry in result}
        assert "1.1.1.1" in groups
        assert "2.2.2.2" in groups

    def test_excludes_events_outside_interval(self, db):
        now = datetime.now(timezone.utc)
        events = [
            _make_event(event_id="t1",
                        timestamp=(now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")),
            _make_event(event_id="t2",
                        timestamp=(now - timedelta(hours=25)).strftime("%Y-%m-%dT%H:%M:%SZ")),
        ]
        insert_events(db, events)
        result = get_time_series(db, "24h")
        total = sum(entry["count"] for entry in result)
        assert total == 1  # Only the recent event

    def test_1h_interval(self, db):
        now = datetime.now(timezone.utc)
        events = [
            _make_event(event_id="t1",
                        timestamp=(now - timedelta(minutes=10)).strftime("%Y-%m-%dT%H:%M:%SZ")),
            _make_event(event_id="t2",
                        timestamp=(now - timedelta(minutes=11)).strftime("%Y-%m-%dT%H:%M:%SZ")),
            _make_event(event_id="t3",
                        timestamp=(now - timedelta(minutes=30)).strftime("%Y-%m-%dT%H:%M:%SZ")),
        ]
        insert_events(db, events)
        result = get_time_series(db, "1h")
        # All 3 events should be within the 1h window
        total = sum(entry["count"] for entry in result)
        assert total == 3

    def test_6h_interval(self, db):
        now = datetime.now(timezone.utc)
        events = [
            _make_event(event_id="t1",
                        timestamp=(now - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")),
            _make_event(event_id="t2",
                        timestamp=(now - timedelta(hours=3)).strftime("%Y-%m-%dT%H:%M:%SZ")),
        ]
        insert_events(db, events)
        result = get_time_series(db, "6h")
        total = sum(entry["count"] for entry in result)
        assert total == 2

    def test_buckets_in_chronological_order(self, db):
        now = datetime.now(timezone.utc)
        events = [
            _make_event(event_id=f"t{i}",
                        timestamp=(now - timedelta(hours=i)).strftime("%Y-%m-%dT%H:%M:%SZ"))
            for i in range(1, 6)
        ]
        insert_events(db, events)
        result = get_time_series(db, "24h")
        buckets = [entry["bucket"] for entry in result]
        assert buckets == sorted(buckets)

# ── Counter history delta computation tests (Task 2.1) ───────────────────

from app.models import compute_deltas


class TestComputeDeltas:
    """Tests for compute_deltas() pure function."""

    def test_empty_list_returns_empty(self):
        assert compute_deltas([]) == []

    def test_single_snapshot_returns_zero_delta(self):
        snapshots = [{"timestamp": "2025-01-15T10:00:00Z", "packets": 100, "bytes": 5000}]
        result = compute_deltas(snapshots)
        assert len(result) == 1
        assert result[0] == {
            "timestamp": "2025-01-15T10:00:00Z",
            "delta_packets": 0,
            "delta_bytes": 0,
            "is_reset": False,
        }

    def test_monotonically_increasing_values(self):
        snapshots = [
            {"timestamp": "2025-01-15T10:00:00Z", "packets": 100, "bytes": 5000},
            {"timestamp": "2025-01-15T10:05:00Z", "packets": 150, "bytes": 7500},
            {"timestamp": "2025-01-15T10:10:00Z", "packets": 200, "bytes": 10000},
        ]
        result = compute_deltas(snapshots)
        assert len(result) == 3
        assert result[0] == {
            "timestamp": "2025-01-15T10:00:00Z",
            "delta_packets": 0,
            "delta_bytes": 0,
            "is_reset": False,
        }
        assert result[1] == {
            "timestamp": "2025-01-15T10:05:00Z",
            "delta_packets": 50,
            "delta_bytes": 2500,
            "is_reset": False,
        }
        assert result[2] == {
            "timestamp": "2025-01-15T10:10:00Z",
            "delta_packets": 50,
            "delta_bytes": 2500,
            "is_reset": False,
        }

    def test_counter_reset_detected(self):
        snapshots = [
            {"timestamp": "2025-01-15T10:00:00Z", "packets": 500, "bytes": 25000},
            {"timestamp": "2025-01-15T10:05:00Z", "packets": 10, "bytes": 400},
        ]
        result = compute_deltas(snapshots)
        assert result[1] == {
            "timestamp": "2025-01-15T10:05:00Z",
            "delta_packets": 0,
            "delta_bytes": 0,
            "is_reset": True,
        }

    def test_reset_followed_by_normal_increase(self):
        snapshots = [
            {"timestamp": "2025-01-15T10:00:00Z", "packets": 500, "bytes": 25000},
            {"timestamp": "2025-01-15T10:05:00Z", "packets": 10, "bytes": 400},
            {"timestamp": "2025-01-15T10:10:00Z", "packets": 60, "bytes": 3000},
        ]
        result = compute_deltas(snapshots)
        assert result[1]["is_reset"] is True
        assert result[1]["delta_packets"] == 0
        assert result[2]["is_reset"] is False
        assert result[2]["delta_packets"] == 50
        assert result[2]["delta_bytes"] == 2600

    def test_no_change_between_snapshots(self):
        snapshots = [
            {"timestamp": "2025-01-15T10:00:00Z", "packets": 100, "bytes": 5000},
            {"timestamp": "2025-01-15T10:05:00Z", "packets": 100, "bytes": 5000},
        ]
        result = compute_deltas(snapshots)
        assert result[1] == {
            "timestamp": "2025-01-15T10:05:00Z",
            "delta_packets": 0,
            "delta_bytes": 0,
            "is_reset": False,
        }

    def test_zero_values(self):
        snapshots = [
            {"timestamp": "2025-01-15T10:00:00Z", "packets": 0, "bytes": 0},
            {"timestamp": "2025-01-15T10:05:00Z", "packets": 0, "bytes": 0},
        ]
        result = compute_deltas(snapshots)
        assert result[0]["delta_packets"] == 0
        assert result[1]["delta_packets"] == 0
        assert result[1]["is_reset"] is False

    def test_output_length_matches_input(self):
        snapshots = [
            {"timestamp": f"2025-01-15T10:{i:02d}:00Z", "packets": i * 10, "bytes": i * 100}
            for i in range(10)
        ]
        result = compute_deltas(snapshots)
        assert len(result) == len(snapshots)

    def test_timestamps_preserved(self):
        snapshots = [
            {"timestamp": "2025-01-15T10:00:00Z", "packets": 100, "bytes": 5000},
            {"timestamp": "2025-01-15T10:05:00Z", "packets": 200, "bytes": 10000},
        ]
        result = compute_deltas(snapshots)
        assert result[0]["timestamp"] == "2025-01-15T10:00:00Z"
        assert result[1]["timestamp"] == "2025-01-15T10:05:00Z"
