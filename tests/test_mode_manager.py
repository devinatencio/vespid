"""Tests for auditd mode persistence across restarts and config changes."""

from __future__ import annotations

import json
import time

from vespid.auditd.mode_manager import ModeManager


def _state(path):
    return json.loads((path / "auditd_mode_state.json").read_text(encoding="utf-8"))


def test_first_start_applies_config_mode(tmp_path):
    manager = ModeManager("detecting", 24, state_dir=tmp_path)

    assert manager.current_mode == "detecting"
    state = _state(tmp_path)
    assert state["mode"] == "detecting"
    assert state["config_mode"] == "detecting"


def test_runtime_mode_survives_restart_when_config_is_unchanged(tmp_path):
    manager = ModeManager("detecting", 24, state_dir=tmp_path)
    manager.set_mode("alerting")

    restarted = ModeManager("detecting", 24, state_dir=tmp_path)

    assert restarted.current_mode == "alerting"
    assert _state(tmp_path)["config_mode"] == "detecting"


def test_changed_config_mode_overrides_runtime_mode(tmp_path):
    manager = ModeManager("detecting", 24, state_dir=tmp_path)
    manager.set_mode("alerting")

    restarted = ModeManager("learning", 24, state_dir=tmp_path)

    assert restarted.current_mode == "learning"
    assert restarted.learning_started_at is not None
    state = _state(tmp_path)
    assert state["mode"] == "learning"
    assert state["config_mode"] == "learning"


def test_auto_promotion_survives_restart_when_config_is_unchanged(tmp_path):
    now = time.time()
    manager = ModeManager("learning", 24, state_dir=tmp_path)
    manager.set_mode("learning", now=now - (25 * 3600))

    assert manager.check_promotion(now=now) == "detecting"

    restarted = ModeManager("learning", 24, state_dir=tmp_path)

    assert restarted.current_mode == "detecting"
    assert _state(tmp_path)["config_mode"] == "learning"


def test_config_change_updates_recorded_config_mode(tmp_path):
    manager = ModeManager("learning", 24, state_dir=tmp_path)
    manager.set_mode("alerting")

    manager.set_mode("detecting", from_config=True)

    restarted = ModeManager("detecting", 24, state_dir=tmp_path)
    assert restarted.current_mode == "detecting"

    changed = ModeManager("alerting", 24, state_dir=tmp_path)
    assert changed.current_mode == "alerting"


def test_legacy_state_without_config_mode_preserves_runtime_mode(tmp_path):
    now = time.time()
    (tmp_path / "auditd_mode_state.json").write_text(
        json.dumps(
            {
                "mode": "alerting",
                "learning_started_at": now - 3600,
                "promoted_at": now - 1800,
            }
        ),
        encoding="utf-8",
    )

    manager = ModeManager("detecting", 24, state_dir=tmp_path)

    assert manager.current_mode == "alerting"
    state = _state(tmp_path)
    assert state["mode"] == "alerting"
    assert state["config_mode"] == "detecting"


def test_first_start_without_state_applies_config_mode(tmp_path):
    manager = ModeManager("detecting", 24, state_dir=tmp_path)

    assert manager.current_mode == "detecting"
    assert _state(tmp_path)["config_mode"] == "detecting"
