"""Tests for the rule pack update utilities (validate / diff / apply)."""

import io
import json
import sqlite3
import tarfile

import pytest
import yaml

from app.pack_loader import rule_content_hash
from app.pack_update import (
    apply_bundle,
    diff_packs,
    export_bundle,
    manifest_sigma_commit,
    read_manifest,
    resolve_bundle,
    validate_packs,
)

IP_REGEX = r"(?P<ip>\S+)"


def _rule(name, regex=IP_REGEX, log_sources=("apache",)):
    log_sources_json = json.dumps(list(log_sources))
    return {
        "name": name,
        "event_type": "SIGMA_TEST",
        "regex": regex,
        "log_sources": log_sources_json,
        "max_attempts": 3,
        "window_seconds": 300,
        "tags": "[]",
        "sigma_id": "",
        "sigma_status": "",
        "content_hash": rule_content_hash(
            "SIGMA_TEST", regex, log_sources_json, 3, 300, "[]", "", ""
        ),
    }


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


# ── validate_packs ───────────────────────────────────────────────────────


def test_validate_accepts_a_well_formed_pack():
    packs = [{"pack_name": "p", "rules": [_rule("r1")]}]
    assert validate_packs(packs) == []


def test_validate_rejects_missing_ip_group():
    packs = [{"pack_name": "p", "rules": [_rule("r1", regex=r"(?:foo)")]}]
    errors = validate_packs(packs)
    assert any("missing (?P<ip>...) group" in e for e in errors)


def test_validate_allows_auditd_without_ip_group():
    packs = [{"pack_name": "p", "rules": [_rule("r1", regex=r"exe=.*nc", log_sources=["auditd"])]}]
    assert validate_packs(packs) == []


def test_validate_rejects_non_compiling_regex():
    packs = [{"pack_name": "p", "rules": [_rule("r1", regex=r"(?P<ip>\S+")]}]
    errors = validate_packs(packs)
    assert any("does not compile" in e for e in errors)


def test_validate_rejects_duplicate_names():
    packs = [{"pack_name": "p", "rules": [_rule("dup"), _rule("dup")]}]
    errors = validate_packs(packs)
    assert any("duplicate rule name 'dup'" in e for e in errors)


# ── diff_packs ───────────────────────────────────────────────────────────


def test_diff_reports_added_removed_changed():
    current = [{"pack_name": "p", "rules": [_rule("a"), _rule("b")]}]
    incoming = [
        {
            "pack_name": "p",
            "rules": [
                _rule("b", regex=r"(?P<ip>\d+\.\d+\.\d+\.\d+)"),
                _rule("c"),
            ],
        }
    ]
    diff = diff_packs(current, incoming)
    assert diff["added"] == ["c"]
    assert diff["removed"] == ["a"]
    assert diff["changed"] == ["b"]
    assert diff["current_rule_count"] == 2
    assert diff["incoming_rule_count"] == 2


# ── read_manifest ────────────────────────────────────────────────────────


def test_read_manifest(tmp_path):
    (tmp_path / "manifest.json").write_text(
        json.dumps({"sigma_commit": "abc123"}), encoding="utf-8"
    )
    assert read_manifest(tmp_path) == {"sigma_commit": "abc123"}


def test_read_manifest_missing_returns_empty(tmp_path):
    assert read_manifest(tmp_path) == {}


# ── apply_bundle ─────────────────────────────────────────────────────────


def _write_pack(directory, pack_name, rules):
    payload = {
        "pack_name": pack_name,
        "display_name": pack_name,
        "icon": "x",
        "description": "test pack",
        "rules": rules,
    }
    (directory / f"{pack_name}.yaml").write_text(
        yaml.safe_dump(payload, sort_keys=False), encoding="utf-8"
    )


def test_apply_bundle_installs_files_backs_up_and_reconciles(tmp_path):
    bundle = tmp_path / "bundle"
    packs = tmp_path / "packs"
    bundle.mkdir()
    packs.mkdir()
    # A pre-existing pack so the backup has something to copy.
    _write_pack(packs, "old-pack", [{"name": "old_rule", "regex": IP_REGEX}])
    _write_pack(bundle, "new-pack", [{"name": "new_rule", "regex": IP_REGEX}])

    conn = _make_conn()
    report = apply_bundle(bundle, packs, conn, "sqlite")

    assert report["applied"] is True
    assert (packs / "new-pack.yaml").exists()
    assert report["backup_dir"] is not None
    assert (tmp_path / "packs" / "new-pack.yaml").exists()
    # new_rule reconciled into the DB
    row = conn.execute(
        "SELECT COUNT(*) FROM detection_rules_custom WHERE name = 'new_rule'"
    ).fetchone()
    assert row[0] == 1


def test_apply_bundle_dry_run_writes_nothing(tmp_path):
    bundle = tmp_path / "bundle"
    packs = tmp_path / "packs"
    bundle.mkdir()
    packs.mkdir()
    _write_pack(bundle, "new-pack", [{"name": "new_rule", "regex": IP_REGEX}])

    conn = _make_conn()
    report = apply_bundle(bundle, packs, conn, "sqlite", dry_run=True)

    assert report["applied"] is False
    assert not (packs / "new-pack.yaml").exists()
    assert conn.execute("SELECT COUNT(*) FROM detection_rules_custom").fetchone()[0] == 0


# ── export_bundle / resolve_bundle ───────────────────────────────────────


def test_export_bundle_to_directory_writes_manifest(tmp_path):
    packs = tmp_path / "packs"
    packs.mkdir()
    _write_pack(packs, "p1", [{"name": "r1", "regex": IP_REGEX}])

    dest = tmp_path / "bundle"
    exported = export_bundle(packs, dest)

    assert exported == ["p1.yaml"]
    assert (dest / "p1.yaml").exists()
    manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["packs"]["p1.yaml"]["rules"] == 1
    assert len(manifest["packs"]["p1.yaml"]["sha256"]) == 64


def test_export_bundle_preserves_manifest_commit(tmp_path):
    packs = tmp_path / "packs"
    packs.mkdir()
    _write_pack(packs, "p1", [{"name": "r1", "regex": IP_REGEX}])
    (packs / "manifest.json").write_text(json.dumps({"sigma_commit": "cafebabe"}), encoding="utf-8")

    dest = tmp_path / "bundle"
    export_bundle(packs, dest)
    manifest = json.loads((dest / "manifest.json").read_text(encoding="utf-8"))
    assert manifest_sigma_commit(manifest) == "cafebabe"


def test_export_bundle_filters_pack_names(tmp_path):
    packs = tmp_path / "packs"
    packs.mkdir()
    _write_pack(packs, "keep", [{"name": "r1", "regex": IP_REGEX}])
    _write_pack(packs, "drop", [{"name": "r2", "regex": IP_REGEX}])

    dest = tmp_path / "bundle"
    exported = export_bundle(packs, dest, ["keep"])
    assert exported == ["keep.yaml"]
    assert (dest / "keep.yaml").exists()
    assert not (dest / "drop.yaml").exists()


def test_resolve_bundle_passes_through_directory(tmp_path):
    packs = tmp_path / "packs"
    packs.mkdir()
    _write_pack(packs, "p1", [{"name": "r1", "regex": IP_REGEX}])
    assert resolve_bundle(packs, tmp_path / "work") == packs


def test_export_and_resolve_targz(tmp_path):
    packs = tmp_path / "packs"
    packs.mkdir()
    _write_pack(packs, "p1", [{"name": "r1", "regex": IP_REGEX}])
    archive = tmp_path / "bundle.tar.gz"
    export_bundle(packs, archive)

    resolved = resolve_bundle(archive, tmp_path / "work")
    assert (resolved / "p1.yaml").exists()
    assert (resolved / "manifest.json").exists()


def test_export_and_resolve_zip(tmp_path):
    packs = tmp_path / "packs"
    packs.mkdir()
    _write_pack(packs, "p1", [{"name": "r1", "regex": IP_REGEX}])
    archive = tmp_path / "bundle.zip"
    export_bundle(packs, archive)

    resolved = resolve_bundle(archive, tmp_path / "work")
    assert (resolved / "p1.yaml").exists()


def test_resolve_bundle_rejects_path_traversal(tmp_path):
    archive = tmp_path / "evil.tar.gz"
    with tarfile.open(archive, "w:gz") as tf:
        data = b"pack_name: evil\nrules: []\n"
        info = tarfile.TarInfo("../evil.yaml")
        info.size = len(data)
        tf.addfile(info, io.BytesIO(data))

    with pytest.raises(ValueError, match="Unsafe path"):
        resolve_bundle(archive, tmp_path / "work")


def test_apply_from_exported_archive_end_to_end(tmp_path):
    src = tmp_path / "src"
    src.mkdir()
    _write_pack(src, "p1", [{"name": "r1", "regex": IP_REGEX}])
    archive = tmp_path / "bundle.tar.gz"
    export_bundle(src, archive)

    resolved = resolve_bundle(archive, tmp_path / "work")
    target = tmp_path / "target"
    target.mkdir()
    conn = _make_conn()

    report = apply_bundle(resolved, target, conn, "sqlite")

    assert report["applied"] is True
    assert (target / "p1.yaml").exists()
    assert (
        conn.execute("SELECT COUNT(*) FROM detection_rules_custom WHERE name = 'r1'").fetchone()[0]
        == 1
    )
