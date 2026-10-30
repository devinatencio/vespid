"""Detection mode state persistence and auto-promotion for the auditd pipeline.

Manages the learning → detecting → alerting state machine, persisting
state to STATE_DIR/auditd_mode_state.json so transitions survive daemon
restarts.

The state file records both the effective runtime mode and the config mode
that was in effect when it was written. On startup the persisted runtime
mode wins as long as the config mode has not changed; a config change still
overrides it, so operators can force a mode from the config file.

State file format:
    {
        "mode": "learning",
        "learning_started_at": 1705312200.0,
        "promoted_at": null,
        "config_mode": "learning"
    }
"""

from __future__ import annotations

import json
import logging
import time
from pathlib import Path

from ..config import STATE_DIR

log = logging.getLogger("vespid.auditd.mode_manager")

_STATE_FILENAME = "auditd_mode_state.json"

# Valid modes in promotion order
_VALID_MODES = ("learning", "detecting", "alerting")


class ModeManager:
    """Manages detection mode state persistence and auto-promotion.

    On first startup with mode="learning", persists a start timestamp.
    On each pipeline cycle, checks whether learning_duration_hours has
    elapsed and auto-promotes to "detecting" if so.

    A config-mode change always overrides the persisted runtime mode. If the
    config mode is unchanged, the persisted runtime mode wins, so a mode
    selected from the dashboard survives daemon restarts.
    """

    def __init__(
        self,
        config_mode: str,
        learning_duration_hours: int,
        state_dir: str | Path | None = None,
    ) -> None:
        self._config_mode = config_mode
        # Config mode recorded in the state file. ``None`` means the state
        # file is missing or was written by an older version that did not
        # track it, in which case the config value is applied once.
        self._state_config_mode: str | None = None
        self._learning_duration_hours = learning_duration_hours
        self._state_dir = Path(state_dir) if state_dir else STATE_DIR
        self._state_path = self._state_dir / _STATE_FILENAME
        self._had_state_file = self._state_path.exists()

        # Internal state
        self._mode: str = "learning"
        self._learning_started_at: float | None = None
        self._promoted_at: float | None = None

        # Load persisted state (if any)
        self._load_state()

        # Apply config override and initial mode logic
        self._apply_config_override()

    @property
    def current_mode(self) -> str:
        """Return the current effective mode."""
        return self._mode

    @property
    def learning_started_at(self) -> float | None:
        """Return the timestamp when learning mode started (if applicable)."""
        return self._learning_started_at

    @property
    def promoted_at(self) -> float | None:
        """Return the timestamp when auto-promotion occurred (if applicable)."""
        return self._promoted_at

    def set_mode(
        self,
        mode: str,
        now: float | None = None,
        *,
        from_config: bool = False,
    ) -> str:
        """Programmatically set the mode.

        Persists the new state and resets the learning timer when entering
        'learning' mode.

        Args:
            mode: One of 'learning', 'detecting', 'alerting'.
            now: Current time override (defaults to time.time()).
            from_config: True when applying a config-file/profile value. In
                that case the recorded config mode is updated too, so a later
                restart knows the config has already been applied.

        Returns:
            The new effective mode.

        Raises:
            ValueError: If mode is not a valid mode.
        """
        if mode not in _VALID_MODES:
            raise ValueError(f"Invalid mode {mode!r}. Valid modes: {_VALID_MODES}")

        if now is None:
            now = time.time()

        source = "config" if from_config else "server command"
        log.info(
            "Mode set programmatically: %r -> %r (%s)",
            self._mode,
            mode,
            source,
        )
        self._mode = mode

        if from_config:
            self._config_mode = mode
            self._state_config_mode = mode

        if mode == "learning":
            # Reset the learning timer when going back to learning
            self._learning_started_at = now
            self._promoted_at = None
        elif mode == "detecting" and self._learning_started_at is not None:
            # Track promotion point if coming from learning
            self._promoted_at = now

        self._persist_state()
        return self._mode

    def check_promotion(self, now: float | None = None) -> str:
        """Check if auto-promotion should occur. Returns current mode.

        Called on each pipeline cycle. If mode is "learning" and the
        learning duration has elapsed, promotes to "detecting" and persists.

        Does not promote if:
        - Mode is not "learning"
        - learning_started_at is not set
        - Time appears to go backwards (clock skew protection)
        """
        if now is None:
            now = time.time()

        # Only auto-promote from learning
        if self._mode != "learning":
            return self._mode

        # Need a start timestamp to compute elapsed time
        if self._learning_started_at is None:
            return self._mode

        # Clock skew protection: don't promote if time appears to go backwards
        if now < self._learning_started_at:
            log.warning(
                "Clock skew detected: now=%.1f < learning_started_at=%.1f; "
                "skipping auto-promotion check",
                now,
                self._learning_started_at,
            )
            return self._mode

        elapsed_seconds = now - self._learning_started_at
        threshold_seconds = self._learning_duration_hours * 3600

        if elapsed_seconds >= threshold_seconds:
            log.info(
                "Learning duration elapsed (%.1f hours); auto-promoting from "
                "'learning' to 'detecting'",
                elapsed_seconds / 3600,
            )
            self._mode = "detecting"
            self._promoted_at = now
            self._persist_state()

        return self._mode

    def _apply_config_override(self) -> None:
        """Apply the config mode when it is new or has changed.

        The state file records the config mode that was in effect when the
        runtime mode was last persisted. If the config mode is unchanged, the
        persisted runtime mode wins, so dashboard changes and auto-promotion
        survive restarts. If the config mode changed, the operator's config
        value takes precedence.
        """
        now = time.time()

        if self._config_mode not in _VALID_MODES:
            log.warning("Invalid config mode %r; ignoring override", self._config_mode)
            self._ensure_state(now)
            return

        if self._state_config_mode is None and self._had_state_file:
            # State written by an older daemon version: we cannot tell
            # whether the config mode changed since then, so preserve the
            # persisted runtime mode and start tracking config changes now.
            log.info(
                "Legacy mode state has no config_mode; preserving runtime mode %r "
                "and recording config mode %r",
                self._mode,
                self._config_mode,
            )
            self._state_config_mode = self._config_mode
            self._persist_state()
            return

        config_changed = (
            self._state_config_mode is None or self._state_config_mode != self._config_mode
        )
        if config_changed:
            log.info(
                "Config mode override: %r -> %r (recorded config mode was %r)",
                self._mode,
                self._config_mode,
                self._state_config_mode,
            )
            self._mode = self._config_mode
            self._state_config_mode = self._config_mode
            if self._config_mode == "learning":
                self._learning_started_at = now
                self._promoted_at = None
            elif self._config_mode == "detecting" and self._learning_started_at is not None:
                self._promoted_at = now
            self._persist_state()
            return

        # Config is unchanged. Keep the persisted runtime mode, but make sure
        # the state file is complete.
        self._ensure_state(now)

    def _ensure_state(self, now: float) -> None:
        """Ensure the state file exists and records the current config mode."""
        changed = False
        if self._state_config_mode is None and self._config_mode in _VALID_MODES:
            self._state_config_mode = self._config_mode
            changed = True
        if self._mode == "learning" and self._learning_started_at is None:
            self._learning_started_at = now
            changed = True
        if changed:
            self._persist_state()

    def _load_state(self) -> None:
        """Load persisted mode state from disk.

        Handles:
        - File doesn't exist (first startup)
        - Corrupted JSON (reset to defaults)
        - Permission errors (log warning, use defaults)
        """
        if not self._state_path.exists():
            return

        try:
            text = self._state_path.read_text(encoding="utf-8")
            data = json.loads(text)

            if not isinstance(data, dict):
                log.warning("Mode state file is not a JSON object — using defaults")
                return

            # Extract mode
            mode = data.get("mode", "learning")
            if mode in _VALID_MODES:
                self._mode = mode
            else:
                log.warning(
                    "Persisted mode %r is invalid — defaulting to 'learning'",
                    mode,
                )
                self._mode = "learning"

            # Extract learning_started_at
            started_at = data.get("learning_started_at")
            if isinstance(started_at, (int, float)) and started_at > 0:
                self._learning_started_at = float(started_at)

            # Extract promoted_at
            promoted_at = data.get("promoted_at")
            if isinstance(promoted_at, (int, float)) and promoted_at > 0:
                self._promoted_at = float(promoted_at)

            # Extract the config mode recorded with this state. Missing means
            # an older state file; the config value is applied once.
            state_config_mode = data.get("config_mode")
            if state_config_mode in _VALID_MODES:
                self._state_config_mode = state_config_mode
            elif state_config_mode is not None:
                log.warning(
                    "Persisted config mode %r is invalid — ignoring",
                    state_config_mode,
                )

        except json.JSONDecodeError as exc:
            log.warning(
                "Mode state file contains invalid JSON (%s) — using defaults",
                exc,
            )
        except (OSError, PermissionError) as exc:
            log.warning(
                "Cannot read mode state file %s: %s — using defaults",
                self._state_path,
                exc,
            )

    def _persist_state(self) -> None:
        """Write current mode state to disk.

        Handles permission errors gracefully — logs a warning and
        continues operation without persisted state.
        """
        state_data = {
            "mode": self._mode,
            "learning_started_at": self._learning_started_at,
            "promoted_at": self._promoted_at,
            "config_mode": self._state_config_mode,
        }

        try:
            self._state_dir.mkdir(parents=True, exist_ok=True)
            self._state_path.write_text(json.dumps(state_data, indent=2), encoding="utf-8")
            log.debug("Mode state persisted to %s", self._state_path)
        except (OSError, PermissionError) as exc:
            log.warning(
                "Cannot write mode state file %s: %s — continuing without persistence",
                self._state_path,
                exc,
            )
