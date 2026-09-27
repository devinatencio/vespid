"""Tests for detection_pack_mode and detection_packs validation in ConfigValidator."""
from app.config_validation import ConfigValidator

import pytest


@pytest.fixture
def validator():
    return ConfigValidator()


class TestDetectionPackMode:
    """Tests for detection_pack_mode validation."""

    def test_auto_mode_valid(self, validator):
        errors = validator.validate_settings({"detection_pack_mode": "auto"})
        assert errors == []

    def test_explicit_mode_valid(self, validator):
        errors = validator.validate_settings({"detection_pack_mode": "explicit"})
        assert errors == []

    def test_invalid_mode_value(self, validator):
        errors = validator.validate_settings({"detection_pack_mode": "manual"})
        assert len(errors) == 1
        assert "must be one of" in errors[0]

    def test_non_string_mode(self, validator):
        errors = validator.validate_settings({"detection_pack_mode": 123})
        assert len(errors) == 1
        assert "detection_pack_mode must be a string" in errors[0]

    def test_boolean_mode(self, validator):
        errors = validator.validate_settings({"detection_pack_mode": True})
        assert len(errors) == 1
        assert "detection_pack_mode must be a string" in errors[0]

    def test_none_mode(self, validator):
        errors = validator.validate_settings({"detection_pack_mode": None})
        assert len(errors) == 1
        assert "detection_pack_mode must be a string" in errors[0]


class TestDetectionPacks:
    """Tests for detection_packs validation."""

    def test_valid_pack_list(self, validator):
        errors = validator.validate_settings({"detection_packs": ["apache-attacks", "openssh-attacks"]})
        assert errors == []

    def test_empty_list_valid(self, validator):
        errors = validator.validate_settings({"detection_packs": []})
        assert errors == []

    def test_not_a_list(self, validator):
        errors = validator.validate_settings({"detection_packs": "apache-attacks"})
        assert len(errors) == 1
        assert "detection_packs must be a list" in errors[0]

    def test_non_string_element(self, validator):
        errors = validator.validate_settings({"detection_packs": ["valid", 123]})
        assert len(errors) == 1
        assert "detection_packs[1] must be a string" in errors[0]

    def test_empty_string_element(self, validator):
        errors = validator.validate_settings({"detection_packs": ["valid", ""]})
        assert len(errors) == 1
        assert "detection_packs[1] must be a non-empty string" in errors[0]

    def test_multiple_invalid_elements(self, validator):
        errors = validator.validate_settings({"detection_packs": ["", 42, "ok", None]})
        assert len(errors) == 3  # index 0 empty, index 1 not string, index 3 not string


class TestDetectionPackFieldsIntegration:
    """Tests for both fields used together and backward compatibility."""

    def test_both_fields_valid(self, validator):
        errors = validator.validate_settings({
            "detection_pack_mode": "explicit",
            "detection_packs": ["apache-attacks"],
        })
        assert errors == []

    def test_existing_profile_without_new_fields(self, validator):
        """Existing profiles without detection_pack fields should still validate."""
        errors = validator.validate_settings({
            "fleet_blocklist_report_enabled": True,
            "allowlist": ["1.2.3.4"],
        })
        assert errors == []

    def test_new_fields_alongside_existing(self, validator):
        errors = validator.validate_settings({
            "fleet_blocklist_report_enabled": True,
            "detection_pack_mode": "auto",
            "detection_packs": ["postfix-attacks"],
            "log_sources": [{"path": "/var/log/mail.log", "parser": "postfix"}],
        })
        assert errors == []
