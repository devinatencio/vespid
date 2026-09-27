"""Per-host threat scoring with exponential time decay.

Accumulates score contributions from host detections and applies the formula:
    effective_score = sum(weight_i * 2^(-(now - t_i) / half_life))

Each contribution halves in value every ``half_life`` seconds.  When a host's
effective score transitions from below to at-or-above the configured threshold
(and no cooldown is active), an alert is triggered.
"""

from __future__ import annotations

import time
from collections import defaultdict
from dataclasses import dataclass

from vespid.auditd.detector import HostDetection


@dataclass
class ScoreContribution:
    """A single score contribution from a detection event."""

    weight: int
    timestamp: float
    rule_name: str


class HostScorer:
    """Per-host threat scoring with exponential time decay.

    Parameters
    ----------
    half_life : float
        Seconds for a contribution to decay to half its original weight.
        Default 1800 (30 minutes).
    threshold : float
        Effective score at or above which an alert is triggered.
        Default 100.
    cooldown : float
        Seconds after an alert during which no further alerts fire for the
        same host.  Default 900 (15 minutes).
    max_contributions : int
        Maximum number of score contributions retained per host.  Oldest
        contributions are discarded when this limit is exceeded.  Default 1000.
    """

    def __init__(
        self,
        half_life: float = 1800.0,
        threshold: float = 100.0,
        cooldown: float = 900.0,
        max_contributions: int = 1000,
    ) -> None:
        self._half_life = half_life
        self._threshold = threshold
        self._cooldown = cooldown
        self._max_contributions = max_contributions
        self._scores: dict[str, list[ScoreContribution]] = defaultdict(list)
        self._cooldowns: dict[str, float] = {}  # hostname -> cooldown_until

    def record_detection(self, detection: HostDetection, now: float | None = None) -> bool:
        """Record a detection and return True if threshold was just crossed.

        Steps:
        1. Compute score *before* adding the new contribution.
        2. Create a ScoreContribution from the detection.
        3. Append to the host's contribution list.
        4. Enforce max_contributions (discard oldest).
        5. Compute score *after* adding the new contribution.
        6. If score was below threshold before AND is at-or-above threshold
           after AND no cooldown is active → activate cooldown and return True.
        7. Otherwise return False.
        """
        if now is None:
            now = time.time()

        hostname = detection.hostname

        # Score before the new contribution
        score_before = self._compute_score(hostname, now)

        # Create and append the new contribution
        contribution = ScoreContribution(
            weight=detection.severity_weight,
            timestamp=now,
            rule_name=detection.rule_name,
        )
        self._scores[hostname].append(contribution)

        # Enforce max contributions per host (discard oldest by timestamp)
        if len(self._scores[hostname]) > self._max_contributions:
            # Sort by timestamp and keep only the most recent max_contributions
            self._scores[hostname].sort(key=lambda c: c.timestamp)
            self._scores[hostname] = self._scores[hostname][-self._max_contributions :]

        # Score after adding the new contribution
        score_after = self._compute_score(hostname, now)

        # Check threshold crossing
        if score_before < self._threshold <= score_after:
            # Check cooldown — no alert if cooldown is active for this host
            if hostname not in self._cooldowns or now > self._cooldowns[hostname]:
                # Activate cooldown and signal alert needed
                self._cooldowns[hostname] = now + self._cooldown
                return True

        return False

    def effective_score(self, hostname: str, now: float | None = None) -> float:
        """Compute current decayed score for a host.

        Formula: sum(weight_i * 2^(-(now - t_i) / half_life))
        """
        if now is None:
            now = time.time()
        return self._compute_score(hostname, now)

    def contributing_rules(self, hostname: str) -> list[str]:
        """Return rule names contributing to a host's current score."""
        return [c.rule_name for c in self._scores.get(hostname, [])]

    def _compute_score(self, hostname: str, now: float) -> float:
        """Internal helper to compute the decayed score sum for a host."""
        contributions = self._scores.get(hostname, [])
        if not contributions:
            return 0.0

        total = 0.0
        for c in contributions:
            age = now - c.timestamp
            # 2^(-(now - t_i) / half_life)
            decay = 2.0 ** (-(age) / self._half_life)
            total += c.weight * decay
        return total
