"""Tests for the pack-template reconcile pass.

Regression cover for the first-upgrade baseline: a pack rule whose shipped
definition changed must be refreshed even though the row predates the
``content_hash`` provenance column, rather than being frozen as
``user_modified`` forever.
"""

import sqlite3

from app.models.detection_rules import _seed_apache_attack_templates
from app.pack_loader import get_pack_rules, load_packs, rule_content_hash

RULE_NAME = "cms_multi_probe_haproxy"


def _pack_rule(name: str = RULE_NAME) -> dict:
    for rule in get_pack_rules(load_packs()):
        if rule["name"] == name:
            return rule
    raise AssertionError(f"pack rule {name!r} not found")


def _make_conn() -> sqlite3.Connection:
    conn = sqlite3.connect(":memory:")
    conn.executescript(
        """
        CREATE TABLE detection_rules_custom (
            id              INTEGER PRIMARY KEY AUTOINCREMENT,
            name            TEXT    NOT NULL UNIQUE,
            event_type      TEXT    NOT NULL,
            regex           TEXT    NOT NULL,
            log_sources     TEXT    NOT NULL DEFAULT '["*"]',
            max_attempts    INTEGER NOT NULL,
            window_seconds  INTEGER NOT NULL,
            enabled         INTEGER NOT NULL DEFAULT 1,
            is_template     INTEGER NOT NULL DEFAULT 0,
            pack_name       TEXT    NOT NULL DEFAULT '',
            tags            TEXT    NOT NULL DEFAULT '[]',
            sigma_id        TEXT    NOT NULL DEFAULT '',
            sigma_status    TEXT    NOT NULL DEFAULT '',
            content_hash    TEXT    NOT NULL DEFAULT '',
            user_modified   INTEGER NOT NULL DEFAULT 0,
            created_at      TEXT    NOT NULL DEFAULT '',
            updated_at      TEXT    NOT NULL DEFAULT '',
            created_by      TEXT    NOT NULL DEFAULT 'system'
        );
        CREATE TABLE detection_rules_revision (
            id          INTEGER PRIMARY KEY CHECK (id = 1),
            revision    INTEGER NOT NULL DEFAULT 0,
            updated_at  TEXT
        );
        INSERT INTO detection_rules_revision (id, revision) VALUES (1, 0);
        """
    )
    return conn


def _insert_pre_provenance(
    conn: sqlite3.Connection,
    rule: dict,
    *,
    regex: str,
    enabled: int = 1,
    user_modified: int = 0,
) -> None:
    """Insert a row as it would look before the content_hash migration."""
    conn.execute(
        "INSERT INTO detection_rules_custom "
        "(name, event_type, regex, log_sources, max_attempts, window_seconds, "
        "enabled, is_template, pack_name, tags, sigma_id, sigma_status, "
        "content_hash, user_modified) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, '', ?)",
        (
            rule["name"],
            rule["event_type"],
            regex,
            rule["log_sources"],
            rule["max_attempts"],
            rule["window_seconds"],
            enabled,
            rule.get("pack_name", ""),
            rule.get("tags", "[]"),
            rule.get("sigma_id", ""),
            rule.get("sigma_status", ""),
            user_modified,
        ),
    )
    conn.commit()


def _fetch(conn: sqlite3.Connection) -> tuple:
    return conn.execute(
        "SELECT regex, content_hash, user_modified, enabled "
        "FROM detection_rules_custom WHERE name = ?",
        (RULE_NAME,),
    ).fetchone()


def test_baseline_diverged_rule_is_refreshed():
    rule = _pack_rule()
    conn = _make_conn()
    _insert_pre_provenance(conn, rule, regex="stale-regex", enabled=1)

    _seed_apache_attack_templates(conn, "sqlite")

    regex, content_hash, user_modified, enabled = _fetch(conn)
    assert regex == rule["regex"]
    assert content_hash == rule["content_hash"]
    assert user_modified == 0
    assert enabled == 1  # user's enabled state preserved


def test_baseline_matching_rule_only_records_provenance():
    rule = _pack_rule()
    conn = _make_conn()
    _insert_pre_provenance(conn, rule, regex=rule["regex"])

    _seed_apache_attack_templates(conn, "sqlite")

    regex, content_hash, user_modified, _ = _fetch(conn)
    assert regex == rule["regex"]
    assert content_hash == rule["content_hash"]
    assert user_modified == 0


def test_user_modified_rule_is_never_touched():
    rule = _pack_rule()
    conn = _make_conn()
    _insert_pre_provenance(conn, rule, regex="my-custom", user_modified=1)

    _seed_apache_attack_templates(conn, "sqlite")

    regex, _, user_modified, _ = _fetch(conn)
    assert regex == "my-custom"
    assert user_modified == 1


def test_mis_marked_user_modified_row_is_repaired():
    rule = _pack_rule()
    conn = _make_conn()
    stale_regex = "stale-regex"
    _insert_pre_provenance(conn, rule, regex=stale_regex)
    # Reproduce the pre-1.0 baseline bug: the row's own definition hash was
    # stored as content_hash while user_modified was set to 1.
    own_hash = rule_content_hash(
        rule["event_type"],
        stale_regex,
        rule["log_sources"],
        rule["max_attempts"],
        rule["window_seconds"],
        rule.get("tags", "[]"),
        rule.get("sigma_id", ""),
        rule.get("sigma_status", ""),
    )
    conn.execute(
        "UPDATE detection_rules_custom SET content_hash = ?, user_modified = 1 WHERE name = ?",
        (own_hash, rule["name"]),
    )
    conn.commit()

    _seed_apache_attack_templates(conn, "sqlite")

    regex, content_hash, user_modified, enabled = _fetch(conn)
    assert regex == rule["regex"]
    assert content_hash == rule["content_hash"]
    assert user_modified == 0
    assert enabled == 1


def test_genuine_user_edit_is_preserved():
    rule = _pack_rule()
    conn = _make_conn()
    # A genuine UI edit keeps the shipped pack hash as the baseline while
    # pointing at the user's own definition.
    _insert_pre_provenance(conn, rule, regex="my-custom", user_modified=1)
    conn.execute(
        "UPDATE detection_rules_custom SET content_hash = ? WHERE name = ?",
        (rule["content_hash"], rule["name"]),
    )
    conn.commit()

    _seed_apache_attack_templates(conn, "sqlite")

    regex, _, user_modified, _ = _fetch(conn)
    assert regex == "my-custom"
    assert user_modified == 1
