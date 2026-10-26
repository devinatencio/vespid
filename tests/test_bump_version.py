"""Tests for the packaging/bump_version.py helper."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "packaging" / "bump_version.py"


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT), *args],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )


def test_version_check_passes():
    result = _run("--check")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "All version references match" in result.stdout


def test_invalid_version_rejected():
    result = _run("1.0")

    assert result.returncode != 0
    assert "invalid version" in result.stderr.lower()


def test_dry_run_does_not_modify_version_file():
    version_file = ROOT / "vespid-server" / "VERSION"
    before = version_file.read_text()

    result = _run("--dry-run", "9.9.9")

    assert result.returncode == 0, result.stdout + result.stderr
    assert "9.9.9" in result.stdout
    assert version_file.read_text() == before
