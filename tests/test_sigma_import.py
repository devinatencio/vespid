"""Tests for the Sigma importer's disposable git cache handling."""

from types import SimpleNamespace
from unittest.mock import patch

from vespid.scripts.sigma_import import _git_pull


def _result(returncode=0, stdout="", stderr=""):
    return SimpleNamespace(returncode=returncode, stdout=stdout, stderr=stderr)


def test_git_pull_refreshes_shallow_cache_after_divergence(tmp_path):
    calls = []

    def fake_run(cmd, **kwargs):
        calls.append(cmd)
        if cmd[3] == "pull":
            return _result(1, stderr="fatal: Not possible to fast-forward")
        if cmd[3] == "fetch":
            return _result(0)
        if cmd[3] == "reset":
            return _result(0)
        raise AssertionError(cmd)

    with patch("vespid.scripts.sigma_import.subprocess.run", side_effect=fake_run):
        assert _git_pull(tmp_path) is True

    assert [cmd[3] for cmd in calls] == ["pull", "fetch", "reset"]


def test_git_pull_returns_false_when_refresh_fails(tmp_path):
    def fake_run(cmd, **kwargs):
        if cmd[3] == "pull":
            return _result(1, stderr="fatal: not a git repository")
        if cmd[3] == "fetch":
            return _result(1, stderr="fatal: unable to access remote")
        raise AssertionError(cmd)

    with patch("vespid.scripts.sigma_import.subprocess.run", side_effect=fake_run):
        assert _git_pull(tmp_path) is False


def test_git_pull_up_to_date(tmp_path):
    def fake_run(cmd, **kwargs):
        return _result(0, stdout="Already up to date.\n")

    with patch("vespid.scripts.sigma_import.subprocess.run", side_effect=fake_run):
        assert _git_pull(tmp_path) is False
