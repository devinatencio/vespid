"""Threat score computation engine for IP intelligence records.

This module provides a pure function that computes a 0.0–100.0 threat score
for an IP record based on behavioral signals: block ratio, fleet breadth,
observation volume, recency patterns, tag diversity, and repeat offender status.

The score is computed at read time as a weighted sum of normalized signals.
Each signal is normalized to [0.0, 1.0] before weighting. The final score
is clamped to [0.0, 100.0] and rounded to 1 decimal place.

Usage:
    from app.intel_score import compute_threat_score, DEFAULT_WEIGHTS

    score = compute_threat_score(record)
    score = compute_threat_score(record, weights={"block_ratio_weight": 50})
    score = compute_threat_score(record, normalization={"fleet_breadth_ceiling": 20})
"""

from __future__ import annotations

import math

DEFAULT_WEIGHTS: dict = {
    "block_ratio_weight": 30,
    "fleet_breadth_weight": 20,
    "volume_weight": 15,
    "recency_weight": 15,
    "tag_diversity_weight": 10,
    "repeat_offender_weight": 10,
}

NORMALIZATION_CONFIG: dict = {
    "fleet_breadth_ceiling": 10,
    "volume_saturation_threshold": 1000,
    "tag_diversity_ceiling": 5,
    "recency_saturation_threshold": 1000,
}


def compute_repeat_offender(record: dict) -> float:
    """Compute the repeat offender signal for an IP record.

    Returns 1.0 when repeat_offender is TRUE, 0.0 when FALSE.

    Args:
        record: IP record dict with a "repeat_offender" key (bool or truthy value).

    Returns:
        1.0 if repeat_offender is TRUE, 0.0 if FALSE.
    """
    return 1.0 if bool(record.get("repeat_offender")) else 0.0


def compute_tag_diversity(record: dict, max_diversity_tags: int = 5) -> float:
    """Compute the tag diversity signal for an IP record.

    Normalizes the count of distinct threat_tags against a configurable maximum.
    Default: 5 distinct tags equals maximum diversity score (1.0).

    Args:
        record: IP record dict with a "threat_tags" key (list of strings).
        max_diversity_tags: The number of distinct tags that yields maximum
            diversity score. Default is 5.

    Returns:
        A float in [0.0, 1.0] representing tag diversity.
    """
    distinct_tags = len(record.get("threat_tags", []))
    return min(distinct_tags / max_diversity_tags, 1.0)


def compute_threat_score(
    record: dict,
    weights: dict | None = None,
    normalization: dict | None = None,
) -> float:
    """Compute a 0.0–100.0 threat score for an IP record.

    Args:
        record: IP record dict with activity counters and recency fields.
        weights: Optional weight overrides (merged with DEFAULT_WEIGHTS).
            Only keys matching the six defined weight names are used.
        normalization: Optional normalization config overrides
            (merged with NORMALIZATION_CONFIG).

    Returns:
        A float between 0.0 and 100.0, rounded to 1 decimal place.
    """
    # Extract signals with null-safe defaults
    total_times_seen = int(record.get("total_times_seen") or 0)
    total_times_blocked = int(record.get("total_times_blocked") or 0)
    total_reporting_nodes = int(record.get("total_reporting_nodes") or 0)
    times_seen_last_24h = int(record.get("times_seen_last_24h") or 0)
    times_seen_last_7d = int(record.get("times_seen_last_7d") or 0)
    times_seen_last_30d = int(record.get("times_seen_last_30d") or 0)
    threat_tags = record.get("threat_tags") or []
    # Early exit: no activity means no threat
    if total_times_seen == 0:
        return 0.0

    # Merge weights with defaults, clamp negatives to 0.0
    merged_weights = dict(DEFAULT_WEIGHTS)
    if weights:
        for key in DEFAULT_WEIGHTS:
            if key in weights:
                merged_weights[key] = weights[key]
    for key in merged_weights:
        if merged_weights[key] < 0.0:
            merged_weights[key] = 0.0

    # If all weights are zero, return 0.0
    sum_of_weights = sum(merged_weights.values())
    if sum_of_weights == 0.0:
        return 0.0

    # Merge normalization config with defaults
    norm = dict(NORMALIZATION_CONFIG)
    if normalization:
        for key in NORMALIZATION_CONFIG:
            if key in normalization:
                norm[key] = normalization[key]

    # Normalize signals to [0.0, 1.0]
    block_ratio = min(total_times_blocked / total_times_seen, 1.0)

    fleet_breadth = min(total_reporting_nodes / norm["fleet_breadth_ceiling"], 1.0)

    volume = min(
        math.log(1 + (record.get("total_requests") or total_times_seen))
        / math.log(1 + norm["volume_saturation_threshold"]),
        1.0,
    )

    recency_threshold = norm["recency_saturation_threshold"]
    recency = (
        0.5 * min(times_seen_last_24h / recency_threshold, 1.0)
        + 0.3 * min(times_seen_last_7d / recency_threshold, 1.0)
        + 0.2 * min(times_seen_last_30d / recency_threshold, 1.0)
    )

    tag_diversity = compute_tag_diversity(
        record, max_diversity_tags=int(norm["tag_diversity_ceiling"])
    )

    repeat_offender_signal = compute_repeat_offender(record)

    # Compute weighted sum
    raw = (
        block_ratio * merged_weights["block_ratio_weight"]
        + fleet_breadth * merged_weights["fleet_breadth_weight"]
        + volume * merged_weights["volume_weight"]
        + recency * merged_weights["recency_weight"]
        + tag_diversity * merged_weights["tag_diversity_weight"]
        + repeat_offender_signal * merged_weights["repeat_offender_weight"]
    )

    score = (raw / sum_of_weights) * 100.0

    # Multi-vector bonus: amplify score when IP has 3+ distinct threat tags
    distinct_tags = len(threat_tags)
    if distinct_tags >= 3:
        multiplier = min(1.0 + 0.1 * (distinct_tags - 2), 1.5)
        score *= multiplier

    # Clamp to [0.0, 100.0] and round to 1 decimal place
    score = max(0.0, min(score, 100.0))
    return round(score, 1)
