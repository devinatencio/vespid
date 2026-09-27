"""Tests for per-node detection pack filtering logic.

Unit tests for the helper functions:
- _log_sources_match()
- _get_node_active_parsers()
- _filter_rules_for_node()

Integration tests for the /api/v1/rules/distribution endpoint with
per-node filtering applied.

Validates: Requirements 2.1, 2.2, 2.3, 2.4, 3.3, 3.4, 6.1
"""

import hashlib
import json

import pytest

from app import create_app
from app.models import create_api_key, create_user, get_db, init_db
from app.routes.rules import _filter_rules_for_node, _get_node_active_parsers, _log_sources_match


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture()
def app(tmp_path):
    """Create a Flask app with a test database."""
    db_path = str(tmp_path / "test_rule_filtering.db")
    config_file = tmp_path / "config.json"
    config_file.write_text(json.dumps({
        "SECRET_KEY": "test-secret-key-filtering",
        "DATABASE_PATH": db_path,
    }))
    application = create_app(str(config_file))
    application.config["TESTING"] = True
    return application


@pytest.fixture()
def client(app):
    """Return a Flask test client."""
    return app.test_client()


@pytest.fixture()
def db(app):
    """Return an initialized database connection."""
    conn = get_db(app.config["DATABASE_PATH"])
    yield conn
    conn.close()


# ---------------------------------------------------------------------------
# Unit Tests: _log_sources_match()
# ---------------------------------------------------------------------------


class TestLogSourcesMatch:
    """Unit tests for _log_sources_match() helper."""

    def test_exact_match_single(self):
        """A rule with log_sources matching one active parser returns True."""
        assert _log_sources_match(["secure"], ["secure", "apache"]) is True

    def test_exact_match_multiple(self):
        """A rule with multiple log_sources overlapping active parsers returns True."""
        assert _log_sources_match(["secure", "postfix"], ["secure", "apache"]) is True

    def test_wildcard_always_matches(self):
        """A rule with wildcard log_sources ['*'] always matches."""
        assert _log_sources_match(["*"], ["secure"]) is True
        assert _log_sources_match(["*"], []) is True

    def test_no_match(self):
        """A rule with log_sources not in active parsers returns False."""
        assert _log_sources_match(["apache"], ["secure", "postfix"]) is False

    def test_empty_rule_log_sources(self):
        """A rule with empty log_sources has no overlap."""
        assert _log_sources_match([], ["secure", "apache"]) is False

    def test_empty_active_parsers(self):
        """Empty active parsers means no overlap (unless wildcard)."""
        assert _log_sources_match(["secure"], []) is False

    def test_multiple_sources_partial_overlap(self):
        """Only one source needs to overlap for a match."""
        assert _log_sources_match(["nginx", "apache", "postfix"], ["apache"]) is True

    def test_wildcard_among_others(self):
        """Wildcard in log_sources list still triggers match."""
        assert _log_sources_match(["secure", "*"], ["apache"]) is True


# ---------------------------------------------------------------------------
# Unit Tests: _get_node_active_parsers()
# ---------------------------------------------------------------------------


class TestGetNodeActiveParsers:
    """Unit tests for _get_node_active_parsers() helper."""

    def test_explicit_profile_mode(self, app, db):
        """Node with explicit detection_pack_mode profile returns explicit packs."""
        # Create a profile with explicit mode
        db.execute(
            "INSERT INTO config_profiles (name, name_lower, settings, created_by) "
            "VALUES (?, ?, ?, ?)",
            ("explicit-profile", "explicit-profile", json.dumps({
                "detection_pack_mode": "explicit",
                "detection_packs": ["apache-attacks", "postfix-attacks"],
                "log_sources": [{"path": "/var/log/apache2/access.log", "parser": "apache"}],
            }), "admin"),
        )
        profile_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

        # Create a node
        db.execute(
            "INSERT INTO nodes (node_id, last_host_info) VALUES (?, ?)",
            ("node-explicit", json.dumps({"active_parsers": ["secure"]})),
        )

        # Assign profile to node
        db.execute(
            "INSERT INTO config_assignments (node_id, profile_id, assigned_by) "
            "VALUES (?, ?, ?)",
            ("node-explicit", profile_id, "admin"),
        )
        db.commit()

        parsers, mode = _get_node_active_parsers(db, "node-explicit")
        assert mode == "explicit"
        assert set(parsers) == {"apache-attacks", "postfix-attacks"}

    def test_auto_profile_with_log_sources(self, app, db):
        """Node with auto mode profile derives parsers from profile log_sources."""
        # Create a profile with auto mode and log_sources
        db.execute(
            "INSERT INTO config_profiles (name, name_lower, settings, created_by) "
            "VALUES (?, ?, ?, ?)",
            ("auto-profile", "auto-profile", json.dumps({
                "detection_pack_mode": "auto",
                "log_sources": [
                    {"path": "/var/log/secure", "parser": "secure"},
                    {"path": "/var/log/apache2/access.log", "parser": "apache"},
                ],
            }), "admin"),
        )
        profile_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

        # Create a node
        db.execute(
            "INSERT INTO nodes (node_id, last_host_info) VALUES (?, ?)",
            ("node-auto", json.dumps({"active_parsers": ["postfix"]})),
        )

        # Assign profile to node
        db.execute(
            "INSERT INTO config_assignments (node_id, profile_id, assigned_by) "
            "VALUES (?, ?, ?)",
            ("node-auto", profile_id, "admin"),
        )
        db.commit()

        parsers, mode = _get_node_active_parsers(db, "node-auto")
        assert mode == "auto"
        assert set(parsers) == {"secure", "apache"}

    def test_heartbeat_only_fallback(self, app, db):
        """Node with no profile falls back to heartbeat active_parsers."""
        # Create a node with heartbeat data but no profile assignment
        db.execute(
            "INSERT INTO nodes (node_id, last_host_info) VALUES (?, ?)",
            ("node-heartbeat", json.dumps({"active_parsers": ["secure", "postfix"]})),
        )
        db.commit()

        parsers, mode = _get_node_active_parsers(db, "node-heartbeat")
        assert mode == "auto"
        assert set(parsers) == {"secure", "postfix"}

    def test_no_data_returns_all(self, app, db):
        """Node with no profile and no active_parsers in heartbeat returns all mode."""
        # Create a node with empty host_info
        db.execute(
            "INSERT INTO nodes (node_id, last_host_info) VALUES (?, ?)",
            ("node-legacy", json.dumps({})),
        )
        db.commit()

        parsers, mode = _get_node_active_parsers(db, "node-legacy")
        assert mode == "all"
        assert parsers is None

    def test_unknown_node_returns_all(self, app, db):
        """A node_id that doesn't exist in the database returns all mode."""
        parsers, mode = _get_node_active_parsers(db, "nonexistent-node")
        assert mode == "all"
        assert parsers is None


# ---------------------------------------------------------------------------
# Unit Tests: _filter_rules_for_node()
# ---------------------------------------------------------------------------


class TestFilterRulesForNode:
    """Unit tests for _filter_rules_for_node() helper."""

    def _sample_rules(self):
        """Return a sample rules dict for testing."""
        return {
            "brute_force_rules": [
                {"name": "ssh_brute", "parser": "secure", "event_type": "SSH_BRUTE",
                 "max_attempts": 5, "window_seconds": 60},
                {"name": "http_brute", "parser": "apache", "event_type": "HTTP_BRUTE",
                 "max_attempts": 20, "window_seconds": 600},
                {"name": "postfix_brute", "parser": "postfix", "event_type": "POSTFIX_BRUTE",
                 "max_attempts": 10, "window_seconds": 300},
            ],
            "custom_rules": [
                {"name": "apache_scanner", "log_sources": ["apache"], "pack_name": "apache-attacks",
                 "event_type": "SCAN", "regex": ".*", "max_attempts": 3, "window_seconds": 60},
                {"name": "ssh_tunnel", "log_sources": ["secure"], "pack_name": "openssh-attacks",
                 "event_type": "TUNNEL", "regex": ".*", "max_attempts": 1, "window_seconds": 60},
                {"name": "wildcard_rule", "log_sources": ["*"], "pack_name": "",
                 "event_type": "GENERIC", "regex": ".*", "max_attempts": 5, "window_seconds": 120},
                {"name": "postfix_spam", "log_sources": ["postfix"], "pack_name": "postfix-attacks",
                 "event_type": "SPAM", "regex": ".*", "max_attempts": 10, "window_seconds": 300},
            ],
        }

    def test_auto_mode_filters_by_parser(self):
        """Auto mode filters brute_force by parser and custom by log_sources."""
        rules = self._sample_rules()
        result = _filter_rules_for_node(rules, ["secure"], "auto")

        # Only ssh_brute should remain in brute_force
        assert len(result["brute_force_rules"]) == 1
        assert result["brute_force_rules"][0]["name"] == "ssh_brute"

        # ssh_tunnel (secure) and wildcard_rule (*) should remain
        custom_names = [r["name"] for r in result["custom_rules"]]
        assert "ssh_tunnel" in custom_names
        assert "wildcard_rule" in custom_names
        assert "apache_scanner" not in custom_names
        assert "postfix_spam" not in custom_names

    def test_explicit_mode_filters_by_pack(self):
        """Explicit mode only includes rules from listed packs + non-pack matching rules."""
        rules = self._sample_rules()
        result = _filter_rules_for_node(
            rules, ["secure", "apache"], "explicit",
            explicit_packs=["apache-attacks"],
        )

        # Brute force: secure and apache parsers match
        bf_names = [r["name"] for r in result["brute_force_rules"]]
        assert "ssh_brute" in bf_names
        assert "http_brute" in bf_names
        assert "postfix_brute" not in bf_names

        # Custom: apache-attacks pack + non-pack rules matching parsers
        custom_names = [r["name"] for r in result["custom_rules"]]
        assert "apache_scanner" in custom_names  # in explicit_packs
        assert "wildcard_rule" in custom_names  # non-pack, wildcard matches
        assert "ssh_tunnel" not in custom_names  # not in explicit_packs
        assert "postfix_spam" not in custom_names  # not in explicit_packs

    def test_all_mode_no_filtering(self):
        """All mode returns rules unchanged."""
        rules = self._sample_rules()
        result = _filter_rules_for_node(rules, None, "all")

        assert result is rules  # Same object, no filtering applied

    def test_none_active_parsers_no_filtering(self):
        """When active_parsers is None, no filtering is applied regardless of mode."""
        rules = self._sample_rules()
        result = _filter_rules_for_node(rules, None, "auto")

        assert result is rules

    def test_auto_mode_multiple_parsers(self):
        """Auto mode with multiple parsers includes rules for all of them."""
        rules = self._sample_rules()
        result = _filter_rules_for_node(rules, ["secure", "apache"], "auto")

        bf_names = [r["name"] for r in result["brute_force_rules"]]
        assert "ssh_brute" in bf_names
        assert "http_brute" in bf_names
        assert "postfix_brute" not in bf_names

        custom_names = [r["name"] for r in result["custom_rules"]]
        assert "apache_scanner" in custom_names
        assert "ssh_tunnel" in custom_names
        assert "wildcard_rule" in custom_names
        assert "postfix_spam" not in custom_names


# ---------------------------------------------------------------------------
# Integration Tests: /api/v1/rules/distribution with filtering
# ---------------------------------------------------------------------------


class TestDistributionFiltering:
    """Integration tests for the distribution endpoint with per-node filtering."""

    def _setup_rules(self, db):
        """Seed brute force and custom rules for integration tests.

        Clears any pre-seeded rules first to have a controlled test environment.
        """
        # Clear pre-seeded rules to have a clean slate
        db.execute("DELETE FROM detection_rules_brute_force")
        db.execute("DELETE FROM detection_rules_custom")

        # SSH brute force rules (parser: secure)
        db.execute(
            "INSERT INTO detection_rules_brute_force "
            "(name, event_type, max_attempts, window_seconds, parser, enabled) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("ssh_fast_brute", "SSH_BRUTE", 5, 60, "secure", 1),
        )
        db.execute(
            "INSERT INTO detection_rules_brute_force "
            "(name, event_type, max_attempts, window_seconds, parser, enabled) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("http_auth_brute", "HTTP_AUTH_BRUTE", 20, 600, "apache", 1),
        )

        # Custom rules with pack_name
        db.execute(
            "INSERT INTO detection_rules_custom "
            "(name, event_type, regex, log_sources, max_attempts, window_seconds, "
            "enabled, is_template, pack_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("apache_scanner_detect", "APACHE_SCAN", r"(?P<ip>\d+\.\d+\.\d+\.\d+).*scanner",
             json.dumps(["apache"]), 3, 60, 1, 1, "apache-attacks"),
        )
        db.execute(
            "INSERT INTO detection_rules_custom "
            "(name, event_type, regex, log_sources, max_attempts, window_seconds, "
            "enabled, is_template, pack_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("ssh_tunnel_detect", "SSH_TUNNEL", r"(?P<ip>\d+\.\d+\.\d+\.\d+).*tunnel",
             json.dumps(["secure"]), 1, 60, 1, 1, "openssh-attacks"),
        )
        db.execute(
            "INSERT INTO detection_rules_custom "
            "(name, event_type, regex, log_sources, max_attempts, window_seconds, "
            "enabled, is_template, pack_name) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
            ("generic_wildcard", "GENERIC", r"(?P<ip>\d+\.\d+\.\d+\.\d+).*attack",
             json.dumps(["*"]), 5, 120, 1, 0, ""),
        )

        # Ensure revision row exists
        db.execute(
            "INSERT OR IGNORE INTO detection_rules_revision (id, revision) VALUES (1, 1)"
        )
        db.commit()

    def _create_node_with_key(self, db, node_id, active_parsers=None):
        """Create a node and an API key restricted to it. Returns the raw token."""
        host_info = {}
        if active_parsers is not None:
            host_info["active_parsers"] = active_parsers

        db.execute(
            "INSERT OR REPLACE INTO nodes (node_id, last_host_info) VALUES (?, ?)",
            (node_id, json.dumps(host_info)),
        )

        # Ensure admin user exists for key creation
        row = db.execute("SELECT id FROM users WHERE username = 'admin'").fetchone()
        if row:
            admin_id = row["id"]
        else:
            admin_id = create_user(db, "admin", "admin_pass", "admin")

        token = create_api_key(db, f"key-{node_id}", node_id, admin_id)
        return token

    def test_node_with_secure_parsers_gets_ssh_not_apache(self, app, client, db):
        """Node with only ['secure'] parsers gets SSH rules but not Apache pack rules."""
        self._setup_rules(db)
        token = self._create_node_with_key(db, "node-ssh-only", ["secure"])

        response = client.get(
            "/api/v1/rules/distribution",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.get_json()

        # Should have SSH brute force rule but not HTTP
        bf_names = [r["name"] for r in data["brute_force_rules"]]
        assert "ssh_fast_brute" in bf_names
        assert "http_auth_brute" not in bf_names

        # Should have SSH custom rule and wildcard, but not Apache pack rule
        custom_names = [r["name"] for r in data["custom_rules"]]
        assert "ssh_tunnel_detect" in custom_names
        assert "generic_wildcard" in custom_names
        assert "apache_scanner_detect" not in custom_names

        # Metadata
        assert data["filtered"] is True
        assert data["active_parsers"] == ["secure"]

    def test_managed_node_explicit_pack_assignment(self, app, client, db):
        """Managed node with explicit ['apache-attacks'] assignment gets only that pack.

        In explicit mode, active_parsers holds pack names (not parser names).
        Brute force rules are filtered by parser matching against pack names,
        so they won't match (pack names != parser names). Only custom rules
        from the explicitly listed packs are included.
        """
        self._setup_rules(db)

        # Create profile with explicit mode
        db.execute(
            "INSERT INTO config_profiles (name, name_lower, settings, created_by) "
            "VALUES (?, ?, ?, ?)",
            ("apache-only", "apache-only", json.dumps({
                "detection_pack_mode": "explicit",
                "detection_packs": ["apache-attacks"],
                "log_sources": [
                    {"path": "/var/log/apache2/access.log", "parser": "apache"},
                ],
            }), "admin"),
        )
        profile_id = db.execute("SELECT last_insert_rowid()").fetchone()[0]

        # Create node and assign profile
        token = self._create_node_with_key(db, "node-managed", ["apache"])

        db.execute(
            "INSERT INTO config_assignments (node_id, profile_id, assigned_by) "
            "VALUES (?, ?, ?)",
            ("node-managed", profile_id, "admin"),
        )
        db.commit()

        response = client.get(
            "/api/v1/rules/distribution",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.get_json()

        # In explicit mode, active_parsers = ["apache-attacks"] (pack names).
        # Brute force rules are filtered by parser in active_parsers, so no
        # brute force rules match since "secure"/"apache" != "apache-attacks".
        bf_names = [r["name"] for r in data["brute_force_rules"]]
        assert "http_auth_brute" not in bf_names
        assert "ssh_fast_brute" not in bf_names

        # Custom: only apache-attacks pack rules + non-pack rules matching
        # (wildcard matches since active_parsers has content)
        custom_names = [r["name"] for r in data["custom_rules"]]
        assert "apache_scanner_detect" in custom_names  # in explicit_packs
        assert "generic_wildcard" in custom_names  # non-pack, wildcard matches
        assert "ssh_tunnel_detect" not in custom_names  # not in explicit_packs

        # Metadata
        assert data["filtered"] is True
        assert "apache-attacks" in data["packs"]

    def test_legacy_node_no_active_parsers_gets_all_rules(self, app, client, db):
        """Legacy node with no active_parsers gets all rules (backward compat)."""
        self._setup_rules(db)
        # Create node with no active_parsers in host_info
        token = self._create_node_with_key(db, "node-legacy", None)

        response = client.get(
            "/api/v1/rules/distribution",
            headers={"Authorization": f"Bearer {token}"},
        )
        assert response.status_code == 200
        data = response.get_json()

        # Should get ALL rules unfiltered
        bf_names = [r["name"] for r in data["brute_force_rules"]]
        assert "ssh_fast_brute" in bf_names
        assert "http_auth_brute" in bf_names

        custom_names = [r["name"] for r in data["custom_rules"]]
        assert "apache_scanner_detect" in custom_names
        assert "ssh_tunnel_detect" in custom_names
        assert "generic_wildcard" in custom_names

        # Metadata: not filtered
        assert data["filtered"] is False
        assert data["active_parsers"] is None
