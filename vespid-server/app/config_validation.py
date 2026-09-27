"""Configuration validation for centralized agent management.

Validates configuration profile settings against the defined manageable
setting categories and their type/range constraints.
"""

from __future__ import annotations

from typing import Any


class ConfigValidator:
    """Validates configuration profile settings.

    Ensures all keys belong to the set of manageable settings and that
    values conform to their defined types and constraints.
    """

    MANAGEABLE_KEYS: set[str] = {
        "brute_force_rules",
        "custom_rules",
        "subscriptions",
        "nft_local_block_ttl",
        "flush_interval_seconds",
        "flush_batch_size",
        "heartbeat_interval_seconds",
        "fleet_blocklist_report_enabled",
        "fleet_blocklist_subscribe_enabled",
        "fleet_block_ttl_seconds",
        "fleet_local_allow_list",
        "log_sources",
        "detection_pack_mode",
        "detection_packs",
        "excluded_http_paths",
        "suppress_rules",
        "group_rules",
        "threshold_rules",
        "disabled_host_threat_rules",
        "auditd",
        "allowlist",
    }

    # Numeric settings with their minimum allowed values.
    # Key format: {setting_name: min_value}
    _NUMERIC_RANGES: dict[str, int] = {
        "nft_local_block_ttl": 0,
        "flush_interval_seconds": 1,
        "flush_batch_size": 1,
        "heartbeat_interval_seconds": 1,
        "fleet_block_ttl_seconds": 0,
    }

    # Numeric settings with maximum allowed values.
    _NUMERIC_MAXES: dict[str, int] = {}

    # Boolean settings.
    _BOOLEAN_KEYS: set[str] = {
        "fleet_blocklist_report_enabled",
        "fleet_blocklist_subscribe_enabled",
    }

    # List settings and the expected item type description.
    _LIST_KEYS: dict[str, str] = {
        "subscriptions": "dict",
        "log_sources": "dict",
        "fleet_local_allow_list": "string",
        "excluded_http_paths": "string",
        "allowlist": "string",
    }

    # Valid values for detection_pack_mode.
    _VALID_PACK_MODES: set[str] = {"auto", "explicit"}

    # Required fields for brute_force_rules entries.
    _BRUTE_FORCE_REQUIRED = {"name", "event_type", "max_attempts", "window_seconds", "parser"}

    # Required fields for custom_rules entries.
    _CUSTOM_RULE_REQUIRED = {"name", "event_type", "regex", "max_attempts", "window_seconds"}

    def validate_settings(self, settings: dict) -> list[str]:
        """Validate all settings, return list of error messages.

        Checks:
        - Settings must not be empty.
        - All keys must be in MANAGEABLE_KEYS.
        - Values must satisfy type and constraint requirements.

        Returns an empty list if all settings are valid.
        """
        errors: list[str] = []

        if not settings:
            errors.append("settings must not be empty")
            return errors

        # Check for invalid keys.
        invalid_keys = set(settings.keys()) - self.MANAGEABLE_KEYS
        if invalid_keys:
            for key in sorted(invalid_keys):
                errors.append(f"invalid setting key: {key}")

        # Validate each known key's value.
        for key, value in settings.items():
            if key in invalid_keys:
                continue

            if key in self._NUMERIC_RANGES:
                err = self.validate_numeric_range(key, value)
                if err:
                    errors.append(err)
            elif key in self._BOOLEAN_KEYS:
                if not isinstance(value, bool):
                    errors.append(f"{key} must be a boolean")
            elif key in self._LIST_KEYS:
                errors.extend(self.validate_list_setting(key, value))
            elif key == "brute_force_rules":
                if not isinstance(value, list):
                    errors.append("brute_force_rules must be a list")
                else:
                    errors.extend(self.validate_detection_rules(value, rule_type="brute_force"))
            elif key == "custom_rules":
                if not isinstance(value, list):
                    errors.append("custom_rules must be a list")
                else:
                    errors.extend(self.validate_detection_rules(value, rule_type="custom"))
            elif key == "detection_pack_mode":
                errors.extend(self.validate_detection_pack_mode(value))
            elif key == "detection_packs":
                errors.extend(self.validate_detection_packs(value))
            elif key == "suppress_rules":
                errors.extend(self.validate_suppress_rules(value))
            elif key == "group_rules":
                errors.extend(self.validate_group_rules(value))
            elif key == "threshold_rules":
                errors.extend(self.validate_threshold_rules(value))
            elif key == "disabled_host_threat_rules":
                errors.extend(self.validate_disabled_host_threat_rules(value))
            elif key == "auditd":
                errors.extend(self.validate_auditd(value))

        return errors

    def validate_numeric_range(self, key: str, value: Any) -> str | None:
        """Validate a numeric setting against its defined range.

        Returns an error message string if invalid, or None if valid.
        """
        if not isinstance(value, int) or isinstance(value, bool):
            return f"{key} must be an integer"

        minimum = self._NUMERIC_RANGES.get(key)
        if minimum is not None and value < minimum:
            return f"{key} must be >= {minimum}"

        maximum = self._NUMERIC_MAXES.get(key)
        if maximum is not None and value > maximum:
            return f"{key} must be <= {maximum}"

        return None

    def validate_list_setting(self, key: str, value: Any) -> list[str]:
        """Validate list settings (allowlist, subscriptions, log_sources, fleet_local_allow_list).

        Checks:
        - Value must be a list.
        - Each item must be the appropriate type (string or dict).
        """
        errors: list[str] = []
        expected_type = self._LIST_KEYS.get(key)

        if not isinstance(value, list):
            errors.append(f"{key} must be a list")
            return errors

        for i, item in enumerate(value):
            if expected_type == "string" and not isinstance(item, str):
                errors.append(f"{key}[{i}] must be a string")
            elif expected_type == "dict" and not isinstance(item, dict):
                errors.append(f"{key}[{i}] must be a dict")

        return errors

    def validate_detection_rules(self, rules: list, rule_type: str = "brute_force") -> list[str]:
        """Validate detection rule structure.

        For brute_force rules: each must have name, event_type, max_attempts,
        window_seconds, parser.

        For custom rules: each must have name, event_type, regex,
        max_attempts, window_seconds.
        """
        errors: list[str] = []

        if rule_type == "brute_force":
            required_fields = self._BRUTE_FORCE_REQUIRED
            label = "brute_force_rules"
        else:
            required_fields = self._CUSTOM_RULE_REQUIRED
            label = "custom_rules"

        for i, rule in enumerate(rules):
            if not isinstance(rule, dict):
                errors.append(f"{label}[{i}] must be a dict")
                continue

            missing = required_fields - set(rule.keys())
            if missing:
                for field_name in sorted(missing):
                    errors.append(f"{label}[{i}] missing required field: {field_name}")

        return errors

    def validate_detection_pack_mode(self, value: Any) -> list[str]:
        """Validate detection_pack_mode field.

        Must be a string with value "auto" or "explicit".
        """
        errors: list[str] = []
        if not isinstance(value, str):
            errors.append("detection_pack_mode must be a string")
        elif value not in self._VALID_PACK_MODES:
            errors.append(
                f"detection_pack_mode must be one of: {', '.join(sorted(self._VALID_PACK_MODES))}"
            )
        return errors

    def validate_detection_packs(self, value: Any) -> list[str]:
        """Validate detection_packs field.

        Must be a list where every element is a non-empty string.
        """
        errors: list[str] = []
        if not isinstance(value, list):
            errors.append("detection_packs must be a list")
            return errors

        for i, item in enumerate(value):
            if not isinstance(item, str):
                errors.append(f"detection_packs[{i}] must be a string")
            elif not item:
                errors.append(f"detection_packs[{i}] must be a non-empty string")

        return errors

    def validate_suppress_rules(self, value: Any) -> list[str]:
        """Validate suppress_rules: must be a list of non-empty strings."""
        errors: list[str] = []
        if not isinstance(value, list):
            errors.append("suppress_rules must be a list")
            return errors
        for i, item in enumerate(value):
            if not isinstance(item, str):
                errors.append(f"suppress_rules[{i}] must be a string")
            elif not item:
                errors.append(f"suppress_rules[{i}] must be a non-empty string")
        return errors

    def validate_group_rules(self, value: Any) -> list[str]:
        """Validate group_rules: must be a list of non-empty strings."""
        errors: list[str] = []
        if not isinstance(value, list):
            errors.append("group_rules must be a list")
            return errors
        for i, item in enumerate(value):
            if not isinstance(item, str):
                errors.append(f"group_rules[{i}] must be a string")
            elif not item:
                errors.append(f"group_rules[{i}] must be a non-empty string")
        return errors

    def validate_threshold_rules(self, value: Any) -> list[str]:
        """Validate threshold_rules: must be a dict mapping rule_name → {min_count, window_minutes}."""
        errors: list[str] = []
        if not isinstance(value, dict):
            errors.append("threshold_rules must be a dict")
            return errors
        for rule_name, config in value.items():
            if not isinstance(rule_name, str) or not rule_name:
                errors.append("threshold_rules key must be a non-empty string")
                continue
            if not isinstance(config, dict):
                errors.append(f"threshold_rules['{rule_name}'] must be a dict")
                continue
            min_count = config.get("min_count")
            window_minutes = config.get("window_minutes")
            if not isinstance(min_count, int) or min_count < 1:
                errors.append(
                    f"threshold_rules['{rule_name}'].min_count must be a positive integer"
                )
            if not isinstance(window_minutes, int) or window_minutes < 1:
                errors.append(
                    f"threshold_rules['{rule_name}'].window_minutes must be a positive integer"
                )
        return errors

    def validate_disabled_host_threat_rules(self, value: Any) -> list[str]:
        """Validate disabled_host_threat_rules: must be a list of non-empty strings."""
        errors: list[str] = []
        if not isinstance(value, list):
            errors.append("disabled_host_threat_rules must be a list")
            return errors
        for i, item in enumerate(value):
            if not isinstance(item, str):
                errors.append(f"disabled_host_threat_rules[{i}] must be a string")
            elif not item:
                errors.append(f"disabled_host_threat_rules[{i}] must be a non-empty string")
        return errors

    _VALID_AUDITD_MODES: set[str] = {"learning", "detecting", "alerting"}

    _AUDITD_NUMERIC_RANGES: dict[str, tuple[int, int, int]] = {
        "learning_duration_hours": (1, 720, 24),
        "process_tree_ttl_seconds": (60, 604800, 3600),
        "scorer_half_life_seconds": (60, 86400, 1800),
        "scorer_threshold": (1, 10000, 100),
        "alert_cooldown_seconds": (0, 86400, 900),
    }

    _AUDITD_KNOWN_KEYS: set[str] = {
        "enabled",
        "log_path",
        "mode",
        "learning_duration_hours",
        "process_tree_ttl_seconds",
        "scorer_half_life_seconds",
        "scorer_threshold",
        "alert_cooldown_seconds",
        "exclude_uids",
        "exclude_exe_prefixes",
    }

    def validate_auditd(self, value: Any) -> list[str]:
        """Validate the auditd configuration dict.

        Must be a dict with known keys. ``enabled`` (bool) and ``log_path``
        (non-empty string when enabled) are required.  Numeric tuning
        parameters are range-checked.  ``mode`` must be one of learning,
        detecting, or alerting.
        """
        errors: list[str] = []
        if not isinstance(value, dict):
            errors.append("auditd must be a dict")
            return errors

        unknown = set(value.keys()) - self._AUDITD_KNOWN_KEYS
        if unknown:
            for k in sorted(unknown):
                errors.append(f"auditd: unknown key '{k}'")

        if "enabled" not in value:
            errors.append("auditd: missing required key 'enabled'")
        elif not isinstance(value["enabled"], bool):
            errors.append("auditd.enabled must be a boolean")

        if "log_path" in value:
            if not isinstance(value["log_path"], str) or not value["log_path"]:
                errors.append("auditd.log_path must be a non-empty string")

        if "mode" in value:
            if value["mode"] not in self._VALID_AUDITD_MODES:
                errors.append(
                    f"auditd.mode must be one of: {', '.join(sorted(self._VALID_AUDITD_MODES))}"
                )

        for field_name, (min_val, max_val, _default) in self._AUDITD_NUMERIC_RANGES.items():
            if field_name in value:
                v = value[field_name]
                if not isinstance(v, int) or isinstance(v, bool):
                    errors.append(f"auditd.{field_name} must be an integer")
                elif v < min_val or v > max_val:
                    errors.append(f"auditd.{field_name} must be between {min_val} and {max_val}")

        if "exclude_uids" in value:
            if not isinstance(value["exclude_uids"], list):
                errors.append("auditd.exclude_uids must be a list")
            else:
                for i, item in enumerate(value["exclude_uids"]):
                    if not isinstance(item, int) or isinstance(item, bool):
                        errors.append(f"auditd.exclude_uids[{i}] must be an integer")

        if "exclude_exe_prefixes" in value:
            if not isinstance(value["exclude_exe_prefixes"], list):
                errors.append("auditd.exclude_exe_prefixes must be a list")
            else:
                for i, item in enumerate(value["exclude_exe_prefixes"]):
                    if not isinstance(item, str):
                        errors.append(f"auditd.exclude_exe_prefixes[{i}] must be a string")

        return errors

    def compute_diff(self, old_settings: dict, new_settings: dict) -> dict:
        """Compute Config_Diff between two settings objects.

        Returns a dict with:
        - added: keys in new_settings not in old_settings (with values)
        - removed: keys in old_settings not in new_settings (with values)
        - modified: keys in both with different values (old_value, new_value)
        """
        old_keys = set(old_settings.keys())
        new_keys = set(new_settings.keys())

        added = {k: new_settings[k] for k in sorted(new_keys - old_keys)}
        removed = {k: old_settings[k] for k in sorted(old_keys - new_keys)}
        modified = {}

        for key in sorted(old_keys & new_keys):
            if old_settings[key] != new_settings[key]:
                modified[key] = {
                    "old_value": old_settings[key],
                    "new_value": new_settings[key],
                }

        return {"added": added, "removed": removed, "modified": modified}
