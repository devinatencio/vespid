"""Shared pytest fixtures for Vespid agent tests.

Prevents tests from touching production paths by redirecting all state,
config, and identity writes to temporary directories.
"""

import pytest


@pytest.fixture(autouse=True)
def _isolate_runtime_paths(tmp_path, monkeypatch):
    monkeypatch.setenv("VESPID_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("VESPID_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv("VESPID_ID_FILE", str(tmp_path / "node_id"))
    monkeypatch.setenv("VESPID_SOCKET", str(tmp_path / "vespid.sock"))
