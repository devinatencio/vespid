"""Tests for app.pack_loader — rule pack YAML loading.

Covers skipping of macOS AppleDouble metadata companions (._*.yaml) that
can sneak into the packs directory when the tree is copied through
non-HFS media.
"""

import json
import logging
import re
from pathlib import Path

from app.pack_loader import load_packs

MINIMAL_PACK = """\
pack_name: "test-pack"
display_name: "Test Pack"
icon: "🛡"
description: "A minimal test pack."
rules:
  - event_type: "test"
    regex: "alert"
    log_sources: '["syslog"]'
    max_attempts: 5
    window_seconds: 60
    tags: '["test"]'
"""


def _make_packs_dir(tmp_path) -> Path:
    d = tmp_path / "packs"
    d.mkdir()
    (d / "real-pack.yaml").write_text(MINIMAL_PACK, encoding="utf-8")
    return d


def test_loads_valid_pack(tmp_path):
    d = _make_packs_dir(tmp_path)
    packs = load_packs(str(d))
    assert [p["pack_name"] for p in packs] == ["test-pack"]


def test_skips_apple_double_metadata_files(tmp_path):
    d = _make_packs_dir(tmp_path)
    # macOS AppleDouble companion — binary metadata, not a real pack.
    (d / "._real-pack.yaml").write_bytes(b"\x00\x00\x00\x01AppleDouble\xa3")
    packs = load_packs(str(d))
    assert len(packs) == 1
    assert packs[0]["pack_name"] == "test-pack"


def test_skips_apple_double_without_valid_pack(tmp_path):
    d = tmp_path / "packs"
    d.mkdir()
    (d / "._orphan.yaml").write_bytes(b"\x00\xa3")
    packs = load_packs(str(d))
    assert packs == []


def test_missing_directory_returns_empty(tmp_path):
    assert load_packs(str(tmp_path / "nope")) == []


def test_invalid_yaml_logs_and_continues(tmp_path, caplog):
    d = _make_packs_dir(tmp_path)
    (d / "broken.yaml").write_text(": not: a: valid: yaml\n\t", encoding="utf-8")
    with caplog.at_level(logging.ERROR, logger="app.pack_loader"):
        packs = load_packs(str(d))
    assert len(packs) == 1  # valid pack still loaded
    assert "Failed to load pack file broken.yaml" in caplog.text


# Vespid's own agent -> server control-plane calls must never be treated as
# CMS/scanner reconnaissance. Regression guard for the `api/` token that
# previously matched /api/v1/... in the CMS probe pack.
VESPID_CONTROL_PLANE_LINES = [
    (
        '15.204.59.125:43328 [21/Sep/2026:17:13:23.581] https~ vespid/vespid '
        "0/0/1/14/74 200 105232 - - ---- 6/6/6/6/0 0/0 {python-httpx/0.28.1} "
        '"GET /api/v1/rules/distribution HTTP/1.1"'
    ),
    (
        '15.204.59.125:46424 [21/Sep/2026:17:13:43.288] https~ vespid/vespid '
        '0/0/0/16/16 204 405 - - ---- 6/6/6/6/0 0/0 {} "POST /api/v1/metrics/write HTTP/1.1"'
    ),
    (
        '15.204.59.125:57058 [21/Sep/2026:17:13:54.116] https~ vespid/vespid '
        "0/0/1/7/8 200 172 - - ---- 7/7/6/6/0 0/0 {Vespid/1.0.0 ConfigSubscriber} "
        '"POST /api/v1/config/check-in HTTP/1.1"'
    ),
]


def _haproxy_cms_rules():
    packs = load_packs()
    pack = next(p for p in packs if p["pack_name"] == "cms-probes")
    for rule in pack["rules"]:
        if "haproxy" in json.loads(rule["log_sources"]):
            yield rule


def test_cms_pack_ignores_vespid_control_plane():
    rules = list(_haproxy_cms_rules())
    assert rules, "expected haproxy rules in the cms-probes pack"
    for rule in rules:
        compiled = re.compile(rule["regex"])
        for line in VESPID_CONTROL_PLANE_LINES:
            assert not compiled.search(line), (
                f'{rule["name"]} matched a legitimate Vespid control-plane request: {line}'
            )


def test_cms_pack_still_matches_real_probe():
    line = (
        '203.0.113.9:4444 [21/Sep/2026:17:14:01.000] https~ vespid/vespid '
        '0/0/1/7/8 404 172 - - ---- 7/7/6/6/0 0/0 {nikto} "GET /api/v2/whatever HTTP/1.1"'
    )
    matched = any(re.compile(r["regex"]).search(line) for r in _haproxy_cms_rules())
    assert matched, "expected the cms-probes pack to still catch non-Vespid API probes"
