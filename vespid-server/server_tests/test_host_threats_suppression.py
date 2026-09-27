"""Unit tests for the _apply_suppression helper function.

Tests cover:
- suppress_rules: complete removal of matching events
- group_rules: collapsing events within 5-minute windows
- threshold_rules: hiding events below minimum firing count
- Edge cases: None profile, malformed settings, non-string list entries
"""

import json

from app.routes.host_threats import _apply_suppression

# ── Helpers ──────────────────────────────────────────────────────────────


def _make_event(rule_name: str, timestamp: str, **kwargs) -> dict:
    """Create a minimal event dict for testing."""
    event = {
        "rule_name": rule_name,
        "timestamp": timestamp,
        "hostname": kwargs.get("hostname", "web-01"),
        "event_type": kwargs.get("event_type", "medium"),
        "exe": kwargs.get("exe", "/usr/bin/test"),
    }
    event.update(kwargs)
    return event


def _make_profile(settings: dict) -> dict:
    """Create a profile dict with JSON-encoded settings."""
    return {"settings": json.dumps(settings)}


# ── Tests: None / empty profile ──────────────────────────────────────────


class TestNoProfile:
    """When profile is None or has no suppression config, all events pass through."""

    def test_none_profile_returns_all_events(self):
        events = [
            _make_event("sigma_whoami", "2025-01-15T10:00:00Z"),
            _make_event("sigma_reverse_shell", "2025-01-15T10:01:00Z"),
        ]
        result = _apply_suppression(events, None)
        assert len(result) == 2

    def test_empty_settings_returns_all_events(self):
        events = [
            _make_event("sigma_whoami", "2025-01-15T10:00:00Z"),
        ]
        profile = _make_profile({})
        result = _apply_suppression(events, profile)
        assert len(result) == 1

    def test_empty_events_returns_empty(self):
        profile = _make_profile({"suppress_rules": ["sigma_whoami"]})
        result = _apply_suppression([], profile)
        assert result == []


# ── Tests: suppress_rules ────────────────────────────────────────────────


class TestSuppressRules:
    """suppress_rules completely removes events with matching rule_name."""

    def test_suppresses_matching_rules(self):
        events = [
            _make_event("sigma_whoami", "2025-01-15T10:00:00Z"),
            _make_event("sigma_id_command", "2025-01-15T10:01:00Z"),
            _make_event("sigma_reverse_shell", "2025-01-15T10:02:00Z"),
        ]
        profile = _make_profile({"suppress_rules": ["sigma_whoami", "sigma_id_command"]})
        result = _apply_suppression(events, profile)
        assert len(result) == 1
        assert result[0]["rule_name"] == "sigma_reverse_shell"

    def test_suppresses_all_instances_of_rule(self):
        events = [
            _make_event("sigma_whoami", "2025-01-15T10:00:00Z"),
            _make_event("sigma_whoami", "2025-01-15T10:01:00Z"),
            _make_event("sigma_whoami", "2025-01-15T10:02:00Z"),
        ]
        profile = _make_profile({"suppress_rules": ["sigma_whoami"]})
        result = _apply_suppression(events, profile)
        assert len(result) == 0

    def test_no_suppression_when_rule_not_in_list(self):
        events = [
            _make_event("sigma_reverse_shell", "2025-01-15T10:00:00Z"),
        ]
        profile = _make_profile({"suppress_rules": ["sigma_whoami"]})
        result = _apply_suppression(events, profile)
        assert len(result) == 1


# ── Tests: group_rules ───────────────────────────────────────────────────


class TestGroupRules:
    """group_rules collapses events from the same rule within 5-minute windows."""

    def test_collapses_events_within_5_minutes(self):
        events = [
            _make_event("sigma_discovery_basic", "2025-01-15T10:00:00Z"),
            _make_event("sigma_discovery_basic", "2025-01-15T10:01:00Z"),
            _make_event("sigma_discovery_basic", "2025-01-15T10:03:00Z"),
        ]
        profile = _make_profile({"group_rules": ["sigma_discovery_basic"]})
        result = _apply_suppression(events, profile)
        # All 3 events are within a 5-minute window → collapsed to 1
        grouped = [e for e in result if e["rule_name"] == "sigma_discovery_basic"]
        assert len(grouped) == 1
        assert grouped[0]["grouped_count"] == 3

    def test_separate_windows_produce_separate_entries(self):
        events = [
            _make_event("sigma_discovery_basic", "2025-01-15T10:00:00Z"),
            _make_event("sigma_discovery_basic", "2025-01-15T10:02:00Z"),
            # Gap > 5 minutes from first event
            _make_event("sigma_discovery_basic", "2025-01-15T10:06:00Z"),
            _make_event("sigma_discovery_basic", "2025-01-15T10:07:00Z"),
        ]
        profile = _make_profile({"group_rules": ["sigma_discovery_basic"]})
        result = _apply_suppression(events, profile)
        grouped = [e for e in result if e["rule_name"] == "sigma_discovery_basic"]
        assert len(grouped) == 2
        assert grouped[0]["grouped_count"] == 2
        assert grouped[1]["grouped_count"] == 2

    def test_non_grouped_rules_unaffected(self):
        events = [
            _make_event("sigma_discovery_basic", "2025-01-15T10:00:00Z"),
            _make_event("sigma_reverse_shell", "2025-01-15T10:00:30Z"),
            _make_event("sigma_discovery_basic", "2025-01-15T10:01:00Z"),
        ]
        profile = _make_profile({"group_rules": ["sigma_discovery_basic"]})
        result = _apply_suppression(events, profile)
        # sigma_reverse_shell should be untouched
        shell_events = [e for e in result if e["rule_name"] == "sigma_reverse_shell"]
        assert len(shell_events) == 1
        assert "grouped_count" not in shell_events[0]

    def test_single_event_gets_grouped_count_of_1(self):
        events = [
            _make_event("sigma_discovery_basic", "2025-01-15T10:00:00Z"),
        ]
        profile = _make_profile({"group_rules": ["sigma_discovery_basic"]})
        result = _apply_suppression(events, profile)
        assert len(result) == 1
        assert result[0]["grouped_count"] == 1


# ── Tests: threshold_rules ───────────────────────────────────────────────


class TestThresholdRules:
    """threshold_rules hides events below the configured minimum firing count."""

    def test_hides_below_threshold(self):
        # Only 2 events in a 10-minute window, threshold requires 5
        events = [
            _make_event("sigma_netstat", "2025-01-15T10:00:00Z"),
            _make_event("sigma_netstat", "2025-01-15T10:01:00Z"),
        ]
        profile = _make_profile({
            "threshold_rules": {
                "sigma_netstat": {"min_count": 5, "window_minutes": 10},
            }
        })
        result = _apply_suppression(events, profile)
        netstat_events = [e for e in result if e["rule_name"] == "sigma_netstat"]
        assert len(netstat_events) == 0

    def test_shows_when_meets_threshold(self):
        # 5 events in a 10-minute window, threshold requires 5
        events = [
            _make_event("sigma_netstat", "2025-01-15T10:00:00Z"),
            _make_event("sigma_netstat", "2025-01-15T10:02:00Z"),
            _make_event("sigma_netstat", "2025-01-15T10:04:00Z"),
            _make_event("sigma_netstat", "2025-01-15T10:06:00Z"),
            _make_event("sigma_netstat", "2025-01-15T10:08:00Z"),
        ]
        profile = _make_profile({
            "threshold_rules": {
                "sigma_netstat": {"min_count": 5, "window_minutes": 10},
            }
        })
        result = _apply_suppression(events, profile)
        netstat_events = [e for e in result if e["rule_name"] == "sigma_netstat"]
        assert len(netstat_events) == 5

    def test_non_threshold_rules_unaffected(self):
        events = [
            _make_event("sigma_netstat", "2025-01-15T10:00:00Z"),
            _make_event("sigma_reverse_shell", "2025-01-15T10:00:30Z"),
        ]
        profile = _make_profile({
            "threshold_rules": {
                "sigma_netstat": {"min_count": 5, "window_minutes": 10},
            }
        })
        result = _apply_suppression(events, profile)
        # sigma_reverse_shell passes through regardless
        shell_events = [e for e in result if e["rule_name"] == "sigma_reverse_shell"]
        assert len(shell_events) == 1

    def test_threshold_only_counts_within_window(self):
        # 3 events total, but only 2 within the last 5-minute window
        events = [
            _make_event("sigma_netstat", "2025-01-15T09:50:00Z"),  # outside window
            _make_event("sigma_netstat", "2025-01-15T10:00:00Z"),
            _make_event("sigma_netstat", "2025-01-15T10:03:00Z"),
        ]
        profile = _make_profile({
            "threshold_rules": {
                "sigma_netstat": {"min_count": 3, "window_minutes": 5},
            }
        })
        result = _apply_suppression(events, profile)
        netstat_events = [e for e in result if e["rule_name"] == "sigma_netstat"]
        # From the perspective of the last event (10:03), events within 5 min:
        # 10:00 and 10:03 = 2 events (< 3). From 10:00: only 10:00 = 1 event.
        # None meet the threshold
        assert len(netstat_events) == 0


# ── Tests: Edge cases ────────────────────────────────────────────────────


class TestEdgeCases:
    """Edge cases: malformed profiles, non-string values, combined rules."""

    def test_malformed_json_settings_skips_suppression(self):
        events = [
            _make_event("sigma_whoami", "2025-01-15T10:00:00Z"),
        ]
        profile = {"settings": "not valid json {{{"}
        result = _apply_suppression(events, profile)
        assert len(result) == 1

    def test_non_string_values_in_suppress_rules_ignored(self):
        events = [
            _make_event("sigma_whoami", "2025-01-15T10:00:00Z"),
            _make_event("sigma_reverse_shell", "2025-01-15T10:01:00Z"),
        ]
        profile = _make_profile({
            "suppress_rules": ["sigma_whoami", 123, None, True],
        })
        result = _apply_suppression(events, profile)
        # Only sigma_whoami should be suppressed (string match)
        assert len(result) == 1
        assert result[0]["rule_name"] == "sigma_reverse_shell"

    def test_settings_as_dict_directly(self):
        """Profile settings may already be parsed as a dict."""
        events = [
            _make_event("sigma_whoami", "2025-01-15T10:00:00Z"),
            _make_event("sigma_reverse_shell", "2025-01-15T10:01:00Z"),
        ]
        profile = {"settings": {"suppress_rules": ["sigma_whoami"]}}
        result = _apply_suppression(events, profile)
        assert len(result) == 1
        assert result[0]["rule_name"] == "sigma_reverse_shell"

    def test_missing_settings_key_returns_all(self):
        events = [
            _make_event("sigma_whoami", "2025-01-15T10:00:00Z"),
        ]
        profile = {"name": "test-profile"}
        result = _apply_suppression(events, profile)
        assert len(result) == 1

    def test_combined_suppress_and_group(self):
        """suppress_rules is applied before group_rules."""
        events = [
            _make_event("sigma_whoami", "2025-01-15T10:00:00Z"),
            _make_event("sigma_discovery_basic", "2025-01-15T10:00:00Z"),
            _make_event("sigma_discovery_basic", "2025-01-15T10:01:00Z"),
            _make_event("sigma_reverse_shell", "2025-01-15T10:02:00Z"),
        ]
        profile = _make_profile({
            "suppress_rules": ["sigma_whoami"],
            "group_rules": ["sigma_discovery_basic"],
        })
        result = _apply_suppression(events, profile)
        # sigma_whoami removed, sigma_discovery_basic collapsed to 1
        assert len(result) == 2
        rule_names = [e["rule_name"] for e in result]
        assert "sigma_whoami" not in rule_names
        discovery = [e for e in result if e["rule_name"] == "sigma_discovery_basic"]
        assert discovery[0]["grouped_count"] == 2

    def test_threshold_rules_with_invalid_config_skipped(self):
        """Invalid threshold_rules entries are skipped gracefully."""
        events = [
            _make_event("sigma_netstat", "2025-01-15T10:00:00Z"),
            _make_event("sigma_other", "2025-01-15T10:00:00Z"),
        ]
        profile = _make_profile({
            "threshold_rules": {
                "sigma_netstat": {"min_count": "not_a_number", "window_minutes": 10},
                "sigma_other": "invalid_config",
            }
        })
        result = _apply_suppression(events, profile)
        # Both events should pass through since configs are invalid
        assert len(result) == 2
