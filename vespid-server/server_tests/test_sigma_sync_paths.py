"""Regression tests for Sigma sync path resolution.

The server runs from two different layouts:

* source tree:  <root>/vespid-server  +  <root>/vespid/scripts
* installed:    <root>/vespid-server  +  <root>/vespid/vespid/scripts

Both must find ``sigma_import.py`` and write to the server's packs directory.
"""

from pathlib import Path

from app.routes.rules import _resolve_sigma_sync_paths


def _touch_script(path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("# stub\n")


def test_source_tree_layout(tmp_path):
    server_root = tmp_path / "vespid-server"
    script = tmp_path / "vespid" / "scripts" / "sigma_import.py"
    _touch_script(script)

    resolved, packs_dir = _resolve_sigma_sync_paths(server_root)

    assert resolved == script
    assert packs_dir == server_root / "packs"


def test_installed_layout(tmp_path):
    server_root = tmp_path / "vespid-server"
    script = tmp_path / "vespid" / "vespid" / "scripts" / "sigma_import.py"
    _touch_script(script)

    resolved, packs_dir = _resolve_sigma_sync_paths(server_root)

    assert resolved == script
    assert packs_dir == server_root / "packs"


def test_missing_importer(tmp_path):
    server_root = tmp_path / "vespid-server"

    resolved, packs_dir = _resolve_sigma_sync_paths(server_root)

    assert resolved is None
    assert packs_dir == server_root / "packs"
