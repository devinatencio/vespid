"""Unit tests for the threat score computation engine.

Tests cover: zero-activity, all-max signals, monotonicity properties,
null/missing field handling, custom weight overrides, all-zero weights,
negative weight clamping, JSON round-trip, and determinism.

Requirements covered: 1.2, 1.6–1.9, 2.1–2.7, 3.2–3.5, 5.1–5.4, 6.1–6.2
"""

import json

import pytest

from app.intel_score import compute_tag_diversity, compute_threat_score, DEFAULT_WEIGHTS, NORMALIZATION_CONFIG


# ── Helpers ──────────────────────────────────────────────────────────────


def _base_record(**overrides):
    """Build a base IP record with sensible mid-range defaults.

    All numeric fields default to a moderate value so that individual
    monotonicity tests can vary one field at a time.
    """
    record = {
        "total_times_seen": 100,
        "total_times_blocked": 50,
        "total_reporting_nodes": 5,
        "times_seen_last_24h": 10,
        "times_seen_last_7d": 30,
        "times_seen_last_30d": 60,
        "threat_tags": ["ssh_brute", "port_scan"],
        "repeat_offender": False,
    }
    record.update(overrides)
    return record


# ── Test: Zero-activity record ───────────────────────────────────────────


class TestZeroActivity:
    """Validates: Requirement 1.2, 5.2"""

    def test_zero_activity_returns_zero(self):
        """All counters 0, empty tags, repeat_offender=False → returns 0.0."""
        record = {
            "total_times_seen": 0,
            "total_times_blocked": 0,
            "total_reporting_nodes": 0,
            "times_seen_last_24h": 0,
            "times_seen_last_7d": 0,
            "times_seen_last_30d": 0,
            "threat_tags": [],
            "repeat_offender": False,
        }
        assert compute_threat_score(record) == 0.0


# ── Test: All-max signals ────────────────────────────────────────────────


class TestAllMaxSignals:
    """Validates: Requirement 5.3"""

    def test_all_max_signals_returns_100(self):
        """Counters at/above saturation, 5+ tags, repeat_offender=True → 100.0."""
        record = {
            "total_times_seen": 2000,
            "total_times_blocked": 2000,
            "total_reporting_nodes": 20,
            "times_seen_last_24h": 2000,
            "times_seen_last_7d": 2000,
            "times_seen_last_30d": 2000,
            "threat_tags": ["ssh_brute", "port_scan", "dns_tunnel", "web_attack", "malware"],
            "repeat_offender": True,
        }
        assert compute_threat_score(record) == 100.0


# ── Test: Monotonicity – total_times_blocked ─────────────────────────────


class TestMonotonicityBlocked:
    """Validates: Requirement 1.6, 5.1"""

    def test_increasing_blocked_never_decreases_score(self):
        """Increasing total_times_blocked (holding others constant) never decreases score."""
        blocked_values = [0, 10, 25, 50, 75, 100]
        scores = []
        for blocked in blocked_values:
            record = _base_record(total_times_blocked=blocked)
            scores.append(compute_threat_score(record))

        for i in range(1, len(scores)):
            assert scores[i] >= scores[i - 1], (
                f"Score decreased when total_times_blocked went from "
                f"{blocked_values[i-1]} to {blocked_values[i]}: "
                f"{scores[i-1]} -> {scores[i]}"
            )


# ── Test: Monotonicity – total_reporting_nodes ───────────────────────────


class TestMonotonicityReportingNodes:
    """Validates: Requirement 1.7, 5.1"""

    def test_increasing_reporting_nodes_never_decreases_score(self):
        """Increasing total_reporting_nodes (holding others constant) never decreases score."""
        node_values = [0, 1, 3, 5, 8, 10, 15]
        scores = []
        for nodes in node_values:
            record = _base_record(total_reporting_nodes=nodes)
            scores.append(compute_threat_score(record))

        for i in range(1, len(scores)):
            assert scores[i] >= scores[i - 1], (
                f"Score decreased when total_reporting_nodes went from "
                f"{node_values[i-1]} to {node_values[i]}: "
                f"{scores[i-1]} -> {scores[i]}"
            )


# ── Test: Monotonicity – times_seen_last_24h ─────────────────────────────


class TestMonotonicityRecency:
    """Validates: Requirement 5.1"""

    def test_increasing_times_seen_last_24h_never_decreases_score(self):
        """Increasing times_seen_last_24h never decreases score."""
        recency_values = [0, 10, 50, 100, 500, 1000, 2000]
        scores = []
        for val in recency_values:
            record = _base_record(times_seen_last_24h=val)
            scores.append(compute_threat_score(record))

        for i in range(1, len(scores)):
            assert scores[i] >= scores[i - 1], (
                f"Score decreased when times_seen_last_24h went from "
                f"{recency_values[i-1]} to {recency_values[i]}: "
                f"{scores[i-1]} -> {scores[i]}"
            )


# ── Test: Monotonicity – len(threat_tags) ────────────────────────────────


class TestMonotonicityTags:
    """Validates: Requirement 5.1"""

    def test_increasing_tag_count_never_decreases_score(self):
        """Increasing len(threat_tags) never decreases score."""
        all_tags = ["ssh_brute", "port_scan", "dns_tunnel", "web_attack", "malware", "c2_beacon"]
        scores = []
        for count in range(len(all_tags) + 1):
            record = _base_record(threat_tags=all_tags[:count])
            scores.append(compute_threat_score(record))

        for i in range(1, len(scores)):
            assert scores[i] >= scores[i - 1], (
                f"Score decreased when threat_tags count went from "
                f"{i-1} to {i}: {scores[i-1]} -> {scores[i]}"
            )


# ── Test: Monotonicity – repeat_offender ─────────────────────────────────


class TestMonotonicityRepeatOffender:
    """Validates: Requirement 5.1"""

    def test_flipping_repeat_offender_true_never_decreases_score(self):
        """Flipping repeat_offender from False to True never decreases score."""
        record_false = _base_record(repeat_offender=False)
        record_true = _base_record(repeat_offender=True)

        score_false = compute_threat_score(record_false)
        score_true = compute_threat_score(record_true)

        assert score_true >= score_false, (
            f"Score decreased when repeat_offender flipped True: "
            f"{score_false} -> {score_true}"
        )


# ── Test: Null/missing field handling ────────────────────────────────────


class TestNullMissingFields:
    """Validates: Requirement 1.8"""

    def test_missing_keys_does_not_raise(self):
        """Record with missing keys doesn't raise, returns valid score."""
        # Completely empty record (only total_times_seen missing → defaults to 0)
        record = {}
        score = compute_threat_score(record)
        assert isinstance(score, float)
        assert 0.0 <= score <= 100.0

    def test_none_values_does_not_raise(self):
        """Record with None values doesn't raise, returns valid score."""
        record = {
            "total_times_seen": None,
            "total_times_blocked": None,
            "total_reporting_nodes": None,
            "times_seen_last_24h": None,
            "times_seen_last_7d": None,
            "times_seen_last_30d": None,
            "threat_tags": None,
            "repeat_offender": None,
        }
        score = compute_threat_score(record)
        assert isinstance(score, float)
        assert 0.0 <= score <= 100.0

    def test_partial_missing_fields(self):
        """Record with some fields present and some missing returns valid score."""
        record = {
            "total_times_seen": 50,
            "total_times_blocked": 25,
            # other fields missing
        }
        score = compute_threat_score(record)
        assert isinstance(score, float)
        assert 0.0 <= score <= 100.0


# ── Test: Custom weight overrides ────────────────────────────────────────


class TestCustomWeightOverrides:
    """Validates: Requirement 3.2, 3.7"""

    def test_partial_weights_merge_with_defaults(self):
        """Passing partial weights merges with defaults correctly."""
        record = _base_record()
        custom_weights = {"block_ratio_weight": 50}

        # Compute with custom weights
        score_custom = compute_threat_score(record, weights=custom_weights)

        # Manually verify the merge: block_ratio_weight=50, rest from defaults
        expected_merged = dict(DEFAULT_WEIGHTS)
        expected_merged["block_ratio_weight"] = 50

        # Compute what we expect
        score_manual = compute_threat_score(record, weights=expected_merged)
        assert score_custom == score_manual

    def test_unknown_keys_ignored(self):
        """Unknown weight keys are ignored during merge."""
        record = _base_record()
        score_default = compute_threat_score(record)
        score_with_unknown = compute_threat_score(
            record, weights={"unknown_weight": 999}
        )
        assert score_default == score_with_unknown


# ── Test: All-zero weights ───────────────────────────────────────────────


class TestAllZeroWeights:
    """Validates: Requirement 3.5, 5.4"""

    def test_all_zero_weights_returns_zero(self):
        """All-zero weights → returns 0.0."""
        record = _base_record()
        zero_weights = {k: 0 for k in DEFAULT_WEIGHTS}
        assert compute_threat_score(record, weights=zero_weights) == 0.0


# ── Test: Negative weight clamping ───────────────────────────────────────


class TestNegativeWeightClamping:
    """Validates: Requirement 3.4"""

    def test_negative_weight_treated_as_zero(self):
        """Negative weight treated as 0.0."""
        record = _base_record()

        # Set one weight to negative, rest to defaults
        negative_weights = {"block_ratio_weight": -10}
        score = compute_threat_score(record, weights=negative_weights)

        # Should be equivalent to block_ratio_weight=0
        zero_weights = {"block_ratio_weight": 0}
        score_zero = compute_threat_score(record, weights=zero_weights)

        assert score == score_zero

    def test_all_negative_weights_returns_zero(self):
        """All negative weights (all clamped to 0) → returns 0.0."""
        record = _base_record()
        negative_weights = {k: -5 for k in DEFAULT_WEIGHTS}
        assert compute_threat_score(record, weights=negative_weights) == 0.0


# ── Test: JSON round-trip ────────────────────────────────────────────────


class TestJSONRoundTrip:
    """Validates: Requirement 6.1, 6.2"""

    @pytest.mark.parametrize("record", [
        _base_record(),
        _base_record(total_times_seen=1, total_times_blocked=1),
        _base_record(total_times_seen=999, total_times_blocked=500,
                     total_reporting_nodes=10, threat_tags=["a", "b", "c", "d", "e"],
                     repeat_offender=True),
        _base_record(total_times_seen=1, total_times_blocked=0,
                     total_reporting_nodes=0, threat_tags=[]),
    ])
    def test_json_round_trip_preserves_score(self, record):
        """round(score, 1) == round(json.loads(json.dumps(score)), 1)."""
        score = compute_threat_score(record)
        serialized = json.dumps(score)
        deserialized = json.loads(serialized)
        assert round(score, 1) == round(deserialized, 1)


# ── Test: Determinism ────────────────────────────────────────────────────


class TestDeterminism:
    """Validates: Requirement 1.9"""

    def test_same_input_same_output(self):
        """Same input always produces same output across multiple calls."""
        record = _base_record()
        results = [compute_threat_score(record) for _ in range(100)]
        assert all(r == results[0] for r in results), (
            f"Non-deterministic results detected: {set(results)}"
        )

    def test_determinism_with_custom_weights(self):
        """Determinism holds with custom weights too."""
        record = _base_record(total_times_seen=500, repeat_offender=True)
        weights = {"block_ratio_weight": 40, "recency_weight": 25}
        results = [compute_threat_score(record, weights=weights) for _ in range(50)]
        assert all(r == results[0] for r in results)


# ── Test: compute_tag_diversity ──────────────────────────────────────────


class TestComputeTagDiversity:
    """Validates: Requirement 16 AC 4 — tag diversity normalization."""

    def test_zero_tags_returns_zero(self):
        """Empty threat_tags → 0.0."""
        assert compute_tag_diversity({"threat_tags": []}) == 0.0

    def test_missing_threat_tags_returns_zero(self):
        """Missing threat_tags key → 0.0."""
        assert compute_tag_diversity({}) == 0.0

    def test_one_tag_returns_0_2(self):
        """1 tag / 5 max = 0.2."""
        assert compute_tag_diversity({"threat_tags": ["ssh-brute"]}) == 0.2

    def test_two_tags_returns_0_4(self):
        """2 tags / 5 max = 0.4."""
        assert compute_tag_diversity({"threat_tags": ["ssh-brute", "http-probe"]}) == 0.4

    def test_three_tags_returns_0_6(self):
        """3 tags / 5 max = 0.6."""
        assert compute_tag_diversity({"threat_tags": ["a", "b", "c"]}) == 0.6

    def test_five_tags_returns_1_0(self):
        """5 tags / 5 max = 1.0 (maximum)."""
        assert compute_tag_diversity({"threat_tags": ["a", "b", "c", "d", "e"]}) == 1.0

    def test_more_than_five_tags_capped_at_1_0(self):
        """6+ tags still returns 1.0 (capped)."""
        assert compute_tag_diversity({"threat_tags": ["a", "b", "c", "d", "e", "f", "g"]}) == 1.0

    def test_custom_max_diversity_tags(self):
        """Custom max_diversity_tags parameter changes normalization."""
        record = {"threat_tags": ["a", "b"]}
        assert compute_tag_diversity(record, max_diversity_tags=4) == 0.5
        assert compute_tag_diversity(record, max_diversity_tags=2) == 1.0
        assert compute_tag_diversity(record, max_diversity_tags=10) == 0.2

    def test_result_always_in_0_to_1(self):
        """Result is always in [0.0, 1.0] regardless of input."""
        for n in range(0, 20):
            tags = [f"tag_{i}" for i in range(n)]
            result = compute_tag_diversity({"threat_tags": tags})
            assert 0.0 <= result <= 1.0

    def test_integration_with_compute_threat_score(self):
        """compute_tag_diversity is used by compute_threat_score correctly."""
        record = _base_record(threat_tags=["a", "b", "c", "d", "e"])
        # With 5 tags, tag_diversity should be 1.0
        diversity = compute_tag_diversity(record)
        assert diversity == 1.0

        # Score with max tags should be >= score with no tags
        score_max_tags = compute_threat_score(record)
        score_no_tags = compute_threat_score(_base_record(threat_tags=[]))
        assert score_max_tags >= score_no_tags


# ── Test: Clamping after multi-vector bonus ──────────────────────────────


class TestClampingAfterMultiVectorBonus:
    """Validates: Requirement 12 AC 4 — score clamped to [0.0, 100.0] and
    rounded to 1 decimal place after multi-vector bonus application.
    """

    def test_max_signals_with_7_tags_clamped_at_100(self):
        """All signals at maximum + 7 threat_tags (1.5x multiplier) still clamped at 100.0.

        Without clamping, the raw score would be 100.0 * 1.5 = 150.0.
        After clamping, it must be 100.0.
        """
        record = {
            "total_times_seen": 2000,
            "total_times_blocked": 2000,
            "total_reporting_nodes": 20,
            "times_seen_last_24h": 2000,
            "times_seen_last_7d": 2000,
            "times_seen_last_30d": 2000,
            "threat_tags": ["ssh-brute", "http-probe", "dns-tunnel", "web-attack",
                            "malware", "c2-beacon", "port-scan"],
            "repeat_offender": True,
        }
        score = compute_threat_score(record)
        assert score == 100.0

    def test_max_signals_with_10_tags_clamped_at_100(self):
        """All signals at maximum + 10 threat_tags (still 1.5x cap) clamped at 100.0."""
        record = {
            "total_times_seen": 5000,
            "total_times_blocked": 5000,
            "total_reporting_nodes": 50,
            "times_seen_last_24h": 5000,
            "times_seen_last_7d": 5000,
            "times_seen_last_30d": 5000,
            "threat_tags": [f"tag_{i}" for i in range(10)],
            "repeat_offender": True,
        }
        score = compute_threat_score(record)
        assert score == 100.0

    def test_high_score_with_bonus_still_clamped(self):
        """A record that would exceed 100.0 after bonus is clamped correctly.

        Uses signals that produce a raw score near 100, then applies 3-tag bonus (1.1x).
        """
        record = {
            "total_times_seen": 2000,
            "total_times_blocked": 2000,
            "total_reporting_nodes": 20,
            "times_seen_last_24h": 2000,
            "times_seen_last_7d": 2000,
            "times_seen_last_30d": 2000,
            "threat_tags": ["ssh-brute", "http-probe", "dns-tunnel"],
            "repeat_offender": True,
        }
        score = compute_threat_score(record)
        assert score <= 100.0

    def test_score_never_below_zero_after_bonus(self):
        """Score remains >= 0.0 even with minimal signals and bonus logic."""
        record = {
            "total_times_seen": 1,
            "total_times_blocked": 0,
            "total_reporting_nodes": 0,
            "times_seen_last_24h": 0,
            "times_seen_last_7d": 0,
            "times_seen_last_30d": 0,
            "threat_tags": [],
            "repeat_offender": False,
        }
        score = compute_threat_score(record)
        assert score >= 0.0

    def test_result_has_at_most_1_decimal_place_with_bonus(self):
        """After multi-vector bonus, the result is rounded to 1 decimal place.

        Tests multiple records with 3+ tags to ensure rounding is applied
        after the bonus multiplication.
        """
        test_cases = [
            # 3 tags → 1.1x multiplier
            {
                "total_times_seen": 73,
                "total_times_blocked": 37,
                "total_reporting_nodes": 3,
                "times_seen_last_24h": 5,
                "times_seen_last_7d": 20,
                "times_seen_last_30d": 50,
                "threat_tags": ["ssh-brute", "http-probe", "dns-tunnel"],
                "repeat_offender": False,
            },
            # 5 tags → 1.3x multiplier
            {
                "total_times_seen": 150,
                "total_times_blocked": 80,
                "total_reporting_nodes": 7,
                "times_seen_last_24h": 12,
                "times_seen_last_7d": 45,
                "times_seen_last_30d": 100,
                "threat_tags": ["a", "b", "c", "d", "e"],
                "repeat_offender": True,
            },
            # 7 tags → 1.5x multiplier (capped)
            {
                "total_times_seen": 200,
                "total_times_blocked": 100,
                "total_reporting_nodes": 4,
                "times_seen_last_24h": 8,
                "times_seen_last_7d": 30,
                "times_seen_last_30d": 80,
                "threat_tags": ["a", "b", "c", "d", "e", "f", "g"],
                "repeat_offender": False,
            },
        ]
        for record in test_cases:
            score = compute_threat_score(record)
            # Verify at most 1 decimal place: round(score, 1) == score
            assert score == round(score, 1), (
                f"Score {score} has more than 1 decimal place for record with "
                f"{len(record['threat_tags'])} tags"
            )
            # Also verify bounds
            assert 0.0 <= score <= 100.0

    def test_result_has_at_most_1_decimal_place_without_bonus(self):
        """Even without bonus (< 3 tags), result is rounded to 1 decimal place."""
        test_cases = [
            {
                "total_times_seen": 73,
                "total_times_blocked": 37,
                "total_reporting_nodes": 3,
                "times_seen_last_24h": 5,
                "times_seen_last_7d": 20,
                "times_seen_last_30d": 50,
                "threat_tags": ["ssh-brute"],
                "repeat_offender": False,
            },
            {
                "total_times_seen": 150,
                "total_times_blocked": 80,
                "total_reporting_nodes": 7,
                "times_seen_last_24h": 12,
                "times_seen_last_7d": 45,
                "times_seen_last_30d": 100,
                "threat_tags": ["a", "b"],
                "repeat_offender": True,
            },
        ]
        for record in test_cases:
            score = compute_threat_score(record)
            assert score == round(score, 1), (
                f"Score {score} has more than 1 decimal place"
            )
            assert 0.0 <= score <= 100.0
