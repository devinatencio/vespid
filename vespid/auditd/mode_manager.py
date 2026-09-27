"""Detection mode state persistence and auto-promotion for the auditd pipeline.

Manages the learning → detecting → alerting state machine, persisting
state to STATE_DIR/auditd_mode_state.json so transitions survive daemon
restarts.

State file format:
    {
        "mode": "learning",
        "learning_started_at": 1705312200.0,
        "promoted_at": null
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

    Manual config overrides are always honored — the operator can force
    any mode at any time via the config file.
    """

    def __init__(
        self,
        config_mode: str,
        learning_duration_hours: int,
        state_dir: str | Path | None = None,
    ) -> None:
        self._config_mode = config_mode
        self._learning_duration_hours = learning_duration_hours
        self._state_dir = Path(state_dir) if state_dir else STATE_DIR
        self._state_path = self._state_dir / _STATE_FILENAME

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

    def set_mode(self, mode: str, now: float | None = None) -> str:
        """Programmatically set the mode (e.g. from a server command).

        Persists the new state and resets the learning timer when entering
        'learning' mode.

        Args:
            mode: One of 'learning', 'detecting', 'alerting'.
            now: Current time override (defaults to time.time()).

        Returns:
            The new effective mode.

        Raises:
            ValueError: If mode is not a valid mode.
        """
        if mode not in _VALID_MODES:
            raise ValueError(f"Invalid mode {mode!r}. Valid modes: {_VALID_MODES}")

        if now is None:
            now = time.time()

        log.info(
            "Mode set programmatically: %r -> %r (server command)",
            self._mode,
            mode,
        )
        self._mode = mode

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
        """Honor manual config override.

        If config_mode differs from the persisted mode, the config value
        is used immediately. The operator can force any mode at any time.
        """
        now = time.time()

        if self._config_mode not in _VALID_MODES:
            log.warning("Invalid config mode %r; ignoring override", self._config_mode)
            # Fall through to normal initialization
        else:
            # If config mode differs from persisted mode, honor config
            if self._config_mode != self._mode:
                log.info(
                    "Config override: mode changed from %r to %r",
                    self._mode,
                    self._config_mode,
                )
                self._mode = self._config_mode

        # On first startup with mode="learning" and no persisted state,
        # record the learning start timestamp
        if self._mode == "learning" and self._learning_started_at is None:
            self._learning_started_at = now
            self._persist_state()
        elif self._mode != "learning" and self._learning_started_at is None:
            # Non-learning mode from the start — no learning timestamp needed
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
