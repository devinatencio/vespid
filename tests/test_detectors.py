"""Tests for SlidingWindowDetector and CorrelationDetector.

Validates:
- SlidingWindowDetector fires on threshold breach within window
- SlidingWindowDetector respects parser matching (only matching parsers count)
- SlidingWindowDetector does not fire below threshold
- SlidingWindowDetector respects cooldown after firing
- SlidingWindowDetector trims old entries outside the window
- SlidingWindowDetector prune_stale() cleans inactive buckets
- CorrelationDetector fires when distinct categories reach threshold
- CorrelationDetector categorizes parsers via CATEGORY_MAP
- CorrelationDetector respects cooldown after firing
- CorrelationDetector respects rule enabled/disabled flag
- CorrelationDetector prune_stale() cleans inactive IPs
- CorrelationDetector clears observations on detection
"""

from __future__ import annotations

from vespid.config import BruteForceRule, CorrelationRule
from vespid.detectors import (
    CorrelationDetection,
    CorrelationDetector,
    Detection,
    SlidingWindowDetector,
)


class TestSlidingWindowDetector:
    def make_rule(
        self,
        name: str = "test_rule",
        event_type: str = "TEST_EVENT",
        max_attempts: int = 5,
        window_seconds: int = 60,
        parser: str = "secure",
    ) -> BruteForceRule:
        return BruteForceRule(
            name=name,
            event_type=event_type,
            max_attempts=max_attempts,
            window_seconds=window_seconds,
            parser=parser,
        )

    def test_fires_on_threshold_breach(self):
        rule = self.make_rule(max_attempts=3, window_seconds=60)
        det = SlidingWindowDetector([rule])
        base = 1000.0

        results = []
        for i in range(3):
            results = det.record(parser="secure", source_ip="1.2.3.4", timestamp=base + i)

        assert len(results) == 1
        det_event = results[0]
        assert isinstance(det_event, Detection)
        assert det_event.rule.name == "test_rule"
        assert det_event.source_ip == "1.2.3.4"
        assert det_event.attempts == 3

    def test_no_fire_below_threshold(self):
        rule = self.make_rule(max_attempts=5, window_seconds=60)
        det = SlidingWindowDetector([rule])
        base = 1000.0

        results = []
        for i in range(4):
            results = det.record(parser="secure", source_ip="1.2.3.4", timestamp=base + i)

        assert len(results) == 0

    def test_ignores_non_matching_parser(self):
        rule = self.make_rule(parser="apache", max_attempts=3, window_seconds=60)
        det = SlidingWindowDetector([rule])
        base = 1000.0

        results = []
        for i in range(5):
            results = det.record(parser="secure", source_ip="1.2.3.4", timestamp=base + i)

        assert len(results) == 0

    def test_sliding_window_trims_old_entries(self):
        rule = self.make_rule(max_attempts=5, window_seconds=10)
        det = SlidingWindowDetector([rule])
        base = 1000.0

        results = []
        for i in range(3):
            results = det.record(parser="secure", source_ip="1.2.3.4", timestamp=base + i)
        assert len(results) == 0

        for i in range(3):
            results = det.record(parser="secure", source_ip="1.2.3.4", timestamp=base + 20 + i)
        assert len(results) == 0

    def test_cooldown_prevents_immediate_refire(self):
        rule = self.make_rule(max_attempts=3, window_seconds=60)
        det = SlidingWindowDetector([rule])
        det.cooldown_seconds = 300
        base = 1000.0

        for i in range(3):
            det.record(parser="secure", source_ip="1.2.3.4", timestamp=base + i)

        results = det.record(parser="secure", source_ip="1.2.3.4", timestamp=base + 10)
        assert len(results) == 0

    def test_cooldown_expires_allows_refire(self):
        rule = self.make_rule(max_attempts=3, window_seconds=60)
        det = SlidingWindowDetector([rule])
        det.cooldown_seconds = 10
        base = 1000.0

        for i in range(3):
            det.record(parser="secure", source_ip="1.2.3.4", timestamp=base + i)

        results = det.record(parser="secure", source_ip="1.2.3.4", timestamp=base + 20)
        assert len(results) == 0

        det.record(parser="secure", source_ip="1.2.3.4", timestamp=base + 21)
        results = det.record(parser="secure", source_ip="1.2.3.4", timestamp=base + 22)
        assert len(results) == 1

    def test_multiple_rules_per_detector(self):
        rule1 = self.make_rule(name="fast", max_attempts=3, window_seconds=10)
        rule2 = self.make_rule(name="slow", max_attempts=5, window_seconds=100, parser="messages")
        det = SlidingWindowDetector([rule1, rule2])
        base = 1000.0

        for i in range(3):
            det.record(parser="secure", source_ip="1.2.3.4", timestamp=base + i)

        for i in range(5):
            det.record(parser="messages", source_ip="5.6.7.8", timestamp=base + i)

        results_fast = det.record(parser="secure", source_ip="1.2.3.4", timestamp=base + 4)
        results_slow = det.record(parser="messages", source_ip="5.6.7.8", timestamp=base + 6)

        assert len(results_fast) == 0
        assert len(results_slow) == 0
        results_fast = det.record(parser="secure", source_ip="1.2.3.4", timestamp=base + 5)

    def test_prune_stale_removes_inactive_buckets(self):
        rule = self.make_rule(max_attempts=5, window_seconds=60)
        det = SlidingWindowDetector([rule])
        det.cooldown_seconds = 10
        base = 1000.0

        det.record(parser="secure", source_ip="1.2.3.4", timestamp=base)
        det.record(parser="secure", source_ip="5.6.7.8", timestamp=base + 1)

        pruned = det.prune_stale(now=base + 200)
        assert pruned == 2
        assert len(det._buckets) == 0

    def test_prune_stale_keeps_active_buckets(self):
        rule = self.make_rule(max_attempts=5, window_seconds=600)
        det = SlidingWindowDetector([rule])
        base = 1000.0

        det.record(parser="secure", source_ip="1.2.3.4", timestamp=base)

        pruned = det.prune_stale(now=base + 100)
        assert pruned == 0
        assert len(det._buckets) == 1

    def test_empty_rules_returns_empty_list(self):
        det = SlidingWindowDetector([])
        results = det.record(parser="secure", source_ip="1.2.3.4")
        assert results == []

    def test_prune_stale_with_no_rules(self):
        det = SlidingWindowDetector([])
        pruned = det.prune_stale()
        assert pruned == 0

    def test_different_ips_independent_buckets(self):
        rule = self.make_rule(max_attempts=3, window_seconds=60)
        det = SlidingWindowDetector([rule])
        base = 1000.0

        for i in range(3):
            det.record(parser="secure", source_ip="1.1.1.1", timestamp=base + i)

        for i in range(2):
            det.record(parser="secure", source_ip="2.2.2.2", timestamp=base + i)

        results = det.record(parser="secure", source_ip="2.2.2.2", timestamp=base + 10)
        assert len(results) == 1
        assert results[0].source_ip == "2.2.2.2"

    def test_detection_contains_timing_info(self):
        rule = self.make_rule(max_attempts=3, window_seconds=60)
        det = SlidingWindowDetector([rule])
        base = 1000.0

        det.record(parser="secure", source_ip="1.2.3.4", timestamp=base)
        det.record(parser="secure", source_ip="1.2.3.4", timestamp=base + 5)
        results = det.record(parser="secure", source_ip="1.2.3.4", timestamp=base + 10)

        assert len(results) == 1
        d = results[0]
        assert d.first_seen == base
        assert d.last_seen == base + 10
        assert d.attempts == 3


class TestCorrelationDetector:
    def make_rule(
        self,
        name: str = "recon_correlation",
        event_type: str = "RECON_CORRELATION",
        min_categories: int = 3,
        window_seconds: int = 600,
        enabled: bool = True,
    ) -> CorrelationRule:
        return CorrelationRule(
            name=name,
            event_type=event_type,
            min_categories=min_categories,
            window_seconds=window_seconds,
            enabled=enabled,
        )

    def test_fires_when_distinct_categories_reach_threshold(self):
        rule = self.make_rule(min_categories=3, window_seconds=600)
        det = CorrelationDetector([rule])
        base = 1000.0

        det.record(parser="secure", source_ip="1.2.3.4", timestamp=base)
        det.record(parser="apache", source_ip="1.2.3.4", timestamp=base + 1)
        results = det.record(parser="messages", source_ip="1.2.3.4", timestamp=base + 2)

        assert len(results) == 1
        d = results[0]
        assert isinstance(d, CorrelationDetection)
        assert d.rule.name == "recon_correlation"
        assert d.source_ip == "1.2.3.4"
        assert set(d.categories_seen) == {"firewall_deny", "http_auth_fail", "ssh_auth_fail"}

    def test_no_fire_below_min_categories(self):
        rule = self.make_rule(min_categories=3, window_seconds=600)
        det = CorrelationDetector([rule])
        base = 1000.0

        det.record(parser="secure", source_ip="1.2.3.4", timestamp=base)
        results = det.record(parser="apache", source_ip="1.2.3.4", timestamp=base + 1)

        assert len(results) == 0

    def test_duplicate_category_counts_once(self):
        rule = self.make_rule(min_categories=3, window_seconds=600)
        det = CorrelationDetector([rule])
        base = 1000.0

        for _ in range(10):
            det.record(parser="secure", source_ip="1.2.3.4", timestamp=base)
        det.record(parser="apache", source_ip="1.2.3.4", timestamp=base + 1)
        results = det.record(parser="messages", source_ip="1.2.3.4", timestamp=base + 2)

        assert len(results) == 1

    def test_categorize_parsers_via_map(self):
        rule = self.make_rule(min_categories=3, window_seconds=600)
        det = CorrelationDetector([rule])
        base = 1000.0

        det.record(parser="haproxy_bad_request", source_ip="1.2.3.4", timestamp=base)
        det.record(parser="apache_not_found", source_ip="1.2.3.4", timestamp=base + 1)
        results = det.record(
            parser="secure_negotiate_fail", source_ip="1.2.3.4", timestamp=base + 2
        )

        assert len(results) == 1
        assert set(results[0].categories_seen) == {
            "http_bad_request",
            "http_probe",
            "ssh_negotiate",
        }

    def test_custom_parser_preserved_as_category(self):
        rule = self.make_rule(min_categories=2, window_seconds=600)
        det = CorrelationDetector([rule])
        base = 1000.0

        det.record(parser="custom:my_custom_rule", source_ip="1.2.3.4", timestamp=base)
        results = det.record(parser="secure", source_ip="1.2.3.4", timestamp=base + 1)

        assert len(results) == 1
        assert "custom:my_custom_rule" in results[0].categories_seen

    def test_window_boundary_excludes_old_categories(self):
        rule = self.make_rule(min_categories=3, window_seconds=10)
        det = CorrelationDetector([rule])
        base = 1000.0

        det.record(parser="secure", source_ip="1.2.3.4", timestamp=base)
        det.record(parser="apache", source_ip="1.2.3.4", timestamp=base + 20)
        results = det.record(parser="messages", source_ip="1.2.3.4", timestamp=base + 21)

        assert len(results) == 0

    def test_cooldown_after_detection(self):
        rule = self.make_rule(min_categories=3, window_seconds=600)
        det = CorrelationDetector([rule])
        det.cooldown_seconds = 300
        base = 1000.0

        det.record(parser="secure", source_ip="1.2.3.4", timestamp=base)
        det.record(parser="apache", source_ip="1.2.3.4", timestamp=base + 1)
        det.record(parser="messages", source_ip="1.2.3.4", timestamp=base + 2)

        det.record(parser="haproxy_bad_request", source_ip="1.2.3.4", timestamp=base + 5)
        det.record(parser="apache_scanner_ua", source_ip="1.2.3.4", timestamp=base + 6)
        results = det.record(
            parser="secure_negotiate_fail", source_ip="1.2.3.4", timestamp=base + 7
        )

        assert len(results) == 0

    def test_disabled_rule_not_evaluated(self):
        rule = self.make_rule(enabled=False, min_categories=2, window_seconds=600)
        det = CorrelationDetector([rule])
        base = 1000.0

        det.record(parser="secure", source_ip="1.2.3.4", timestamp=base)
        results = det.record(parser="apache", source_ip="1.2.3.4", timestamp=base + 1)

        assert len(results) == 0

    def test_prune_stale_removes_inactive_ips(self):
        rule = self.make_rule(min_categories=3, window_seconds=60)
        det = CorrelationDetector([rule])
        det.cooldown_seconds = 10
        base = 1000.0

        det.record(parser="secure", source_ip="1.2.3.4", timestamp=base)
        det.record(parser="secure", source_ip="5.6.7.8", timestamp=base + 1)

        pruned = det.prune_stale(now=base + 200)
        assert pruned == 2
        assert len(det._observations) == 0

    def test_prune_stale_keeps_active_ips(self):
        rule = self.make_rule(min_categories=3, window_seconds=600)
        det = CorrelationDetector([rule])
        base = 1000.0

        det.record(parser="secure", source_ip="1.2.3.4", timestamp=base)
        pruned = det.prune_stale(now=base + 100)
        assert pruned == 0
        assert "1.2.3.4" in det._observations

    def test_observations_cleared_after_detection(self):
        rule = self.make_rule(min_categories=3, window_seconds=600)
        det = CorrelationDetector([rule])
        base = 1000.0

        det.record(parser="secure", source_ip="1.2.3.4", timestamp=base)
        assert len(det._observations["1.2.3.4"]) == 1

        det.record(parser="apache", source_ip="1.2.3.4", timestamp=base + 1)
        det.record(parser="messages", source_ip="1.2.3.4", timestamp=base + 2)

        assert det._observations["1.2.3.4"] == []

    def test_empty_rules_returns_empty_list(self):
        det = CorrelationDetector([])
        results = det.record(parser="secure", source_ip="1.2.3.4")
        assert results == []

    def test_prune_stale_empty_rules(self):
        det = CorrelationDetector([])
        pruned = det.prune_stale()
        assert pruned == 0

    def test_different_ips_independent_observations(self):
        rule = self.make_rule(min_categories=2, window_seconds=600)
        det = CorrelationDetector([rule])
        base = 1000.0

        det.record(parser="secure", source_ip="1.1.1.1", timestamp=base)
        det.record(parser="secure", source_ip="2.2.2.2", timestamp=base)

        results_ip1 = det.record(parser="apache", source_ip="1.1.1.1", timestamp=base + 1)
        results_ip2 = det.record(parser="apache", source_ip="2.2.2.2", timestamp=base + 1)

        assert len(results_ip1) == 1
        assert results_ip1[0].source_ip == "1.1.1.1"
        assert len(results_ip2) == 1
        assert results_ip2[0].source_ip == "2.2.2.2"

    def test_unknown_parser_uses_parser_as_category(self):
        rule = self.make_rule(min_categories=2, window_seconds=600)
        det = CorrelationDetector([rule])
        base = 1000.0

        det.record(parser="unknown_parser_type", source_ip="1.2.3.4", timestamp=base)
        results = det.record(parser="secure", source_ip="1.2.3.4", timestamp=base + 1)

        assert len(results) == 1
        assert "unknown_parser_type" in results[0].categories_seen

    def test_single_observation_pruned_when_stale(self):
        rule = self.make_rule(min_categories=3, window_seconds=10)
        det = CorrelationDetector([rule])
        det.cooldown_seconds = 5
        base = 1000.0

        det.record(parser="secure", source_ip="1.2.3.4", timestamp=base)
        pruned = det.prune_stale(now=base + 30)
        assert pruned == 1
