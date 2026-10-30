"""Tests for auditd mode reporting in DataBus heartbeats."""

from __future__ import annotations

import json
import sys
from unittest.mock import MagicMock, patch

import pytest


@pytest.fixture
def databus_module(tmp_path, monkeypatch):
    """Import vespid.databus without touching /var/lib/vespid."""
    monkeypatch.setenv("VESPID_STATE_DIR", str(tmp_path))
    monkeypatch.setenv("VESPID_CONFIG_DIR", str(tmp_path))
    monkeypatch.setenv("VESPID_ID_FILE", str(tmp_path / "node_id"))
    with patch("vespid.fleet_queue.FleetReportQueue.__init__", return_value=None):
        for mod_name in list(sys.modules):
            if mod_name == "vespid.databus":
                del sys.modules[mod_name]
        import vespid.databus as module

    return module


def _make_bus(module, tmp_path):
    module.STATE_DIR = tmp_path

    config = MagicMock()
    config.queue_max_size = 10
    config.fleet_queue_dir = str(tmp_path / "fleet_queue")
    config.fleet_queue_max_size = 100
    with patch("vespid.fleet_queue.FleetReportQueue.__init__", return_value=None):
        return module.DataBus(config=config)


def test_heartbeat_auditd_state_prefers_live_mode(databus_module, tmp_path):
    bus = _make_bus(databus_module, tmp_path)
    (tmp_path / "auditd_mode_state.json").write_text(
        json.dumps(
            {
                "mode": "detecting",
                "learning_started_at": 123.0,
                "promoted_at": None,
                "config_mode": "learning",
            }
        ),
        encoding="utf-8",
    )
    auditd_cfg = MagicMock(enabled=True, mode="learning", learning_duration_hours=24)

    bus._get_auditd_mode = lambda: "alerting"
    state = bus._build_auditd_state(auditd_cfg)

    assert state["mode"] == "alerting"
    assert state["learning_started_at"] == 123.0
    assert state["learning_duration_hours"] == 24


def test_heartbeat_auditd_state_falls_back_to_state_file(databus_module, tmp_path):
    bus = _make_bus(databus_module, tmp_path)
    (tmp_path / "auditd_mode_state.json").write_text(
        json.dumps({"mode": "detecting", "learning_started_at": 456.0}),
        encoding="utf-8",
    )
    auditd_cfg = MagicMock(enabled=True, mode="learning", learning_duration_hours=24)

    bus._get_auditd_mode = None
    state = bus._build_auditd_state(auditd_cfg)

    assert state["mode"] == "detecting"
    assert state["learning_started_at"] == 456.0
