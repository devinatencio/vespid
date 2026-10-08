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


SIGMA_RULE_NAME = "sigma_suspicious_openssh_daemon_error"


def _insert_template_row(
    conn: sqlite3.Connection,
    *,
    name: str,
    regex: str,
    pack_name: str,
    sigma_id: str = "",
    enabled: int = 1,
    user_modified: int = 0,
) -> None:
    conn.execute(
        "INSERT INTO detection_rules_custom "
        "(name, event_type, regex, log_sources, max_attempts, window_seconds, "
        "enabled, is_template, pack_name, tags, sigma_id, sigma_status, "
        "content_hash, user_modified) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, '', ?)",
        (
            name,
            "SIGMA_TEST",
            regex,
            '["apache"]',
            3,
            300,
            enabled,
            pack_name,
            "[]",
            sigma_id,
            "test",
            user_modified,
        ),
    )
    conn.commit()


def test_renamed_pack_rule_is_renamed_not_duplicated():
    """A rule renamed upstream (same Sigma UUID, new name) is renamed in place,
    preserving enabled state and leaving no duplicate."""
    rule = _pack_rule(SIGMA_RULE_NAME)
    assert rule.get("sigma_id")
    conn = _make_conn()
    old_name = rule["name"] + "_old"
    _insert_template_row(
        conn,
        name=old_name,
        regex="old-regex",
        pack_name=rule["pack_name"],
        sigma_id=rule["sigma_id"],
        enabled=1,
    )

    _seed_apache_attack_templates(conn, "sqlite")

    rows = conn.execute(
        "SELECT name, regex, enabled FROM detection_rules_custom WHERE sigma_id = ?",
        (rule["sigma_id"],),
    ).fetchall()
    assert len(rows) == 1
    name, regex, enabled = rows[0]
    assert name == rule["name"]
    assert regex == rule["regex"]
    assert enabled == 1
    assert (
        conn.execute(
            "SELECT COUNT(*) FROM detection_rules_custom WHERE name = ?", (old_name,)
        ).fetchone()[0]
        == 0
    )


def test_stale_pristine_pack_rule_is_retired():
    conn = _make_conn()
    _insert_template_row(
        conn,
        name="sigma_no_longer_shipped",
        regex=r"(?P<ip>\S+)",
        pack_name="sigma-web-attacks",
        sigma_id="deadbeef",
        user_modified=0,
    )

    _seed_apache_attack_templates(conn, "sqlite")

    assert (
        conn.execute(
            "SELECT COUNT(*) FROM detection_rules_custom WHERE name = 'sigma_no_longer_shipped'"
        ).fetchone()[0]
        == 0
    )


def test_stale_user_modified_pack_rule_is_kept():
    conn = _make_conn()
    _insert_template_row(
        conn,
        name="sigma_no_longer_shipped_but_edited",
        regex=r"(?P<ip>\S+)",
        pack_name="sigma-web-attacks",
        sigma_id="deadbeef",
        user_modified=1,
    )

    _seed_apache_attack_templates(conn, "sqlite")

    assert (
        conn.execute(
            "SELECT COUNT(*) FROM detection_rules_custom "
            "WHERE name = 'sigma_no_longer_shipped_but_edited'"
        ).fetchone()[0]
        == 1
    )
