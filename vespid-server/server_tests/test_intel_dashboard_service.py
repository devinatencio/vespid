"""Unit tests for intel_dashboard_service.py — parse_search_query() and execute_search()."""

import json
import sqlite3

import pytest

from app.intel_dashboard_service import execute_search, parse_search_query
from app.intel_models import init_intel_db


@pytest.fixture()
def intel_db():
    """Create an in-memory SQLite database with intel tables initialized."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    init_intel_db(conn, "sqlite")
    yield conn
    conn.close()


def _insert_ip_record(conn, ip_address="192.168.1.1", ip_version="v4", **kwargs):
    """Helper to insert a test IP record with sensible defaults."""
    defaults = {
        "first_seen_at": "2024-01-01T00:00:00",
        "last_seen_at": "2024-01-02T00:00:00",
        "last_blocked_at": None,
        "total_times_seen": 1,
        "total_times_blocked": 0,
        "total_reporting_nodes": 1,
        "total_attack_events": 0,
        "repeat_offender": 0,
        "first_reporting_node": "node-1",
        "most_recent_reporting_node": "node-1",
        "reporting_node_list": '["node-1"]',
        "geo_country": None,
        "asn": None,
        "isp_organization": None,
        "reputation_score": None,
        "threat_tags": "[]",
    }
    defaults.update(kwargs)
    conn.execute(
        "INSERT INTO ip_intel (ip_address, ip_version, first_seen_at, last_seen_at, "
        "last_blocked_at, total_times_seen, total_times_blocked, total_reporting_nodes, "
        "total_attack_events, repeat_offender, first_reporting_node, "
        "most_recent_reporting_node, reporting_node_list, geo_country, asn, "
        "isp_organization, reputation_score, threat_tags) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            ip_address, ip_version,
            defaults["first_seen_at"], defaults["last_seen_at"],
            defaults["last_blocked_at"], defaults["total_times_seen"],
            defaults["total_times_blocked"], defaults["total_reporting_nodes"],
            defaults["total_attack_events"], defaults["repeat_offender"],
            defaults["first_reporting_node"], defaults["most_recent_reporting_node"],
            defaults["reporting_node_list"], defaults["geo_country"],
            defaults["asn"], defaults["isp_organization"],
            defaults["reputation_score"], defaults["threat_tags"],
        ),
    )
    conn.commit()


# ── parse_search_query tests ─────────────────────────────────────────────


class TestParseSearchQuery:
    """Tests for parse_search_query classification logic."""

    def test_exact_ipv4(self):
        result = parse_search_query("192.168.1.1")
        assert result["query_type"] == "exact_ip"
        assert result["value"] == "192.168.1.1"
        assert result["error"] is None

    def test_exact_ipv6(self):
        result = parse_search_query("2001:db8::1")
        assert result["query_type"] == "exact_ip"
        assert result["value"] == "2001:db8::1"
        assert result["error"] is None

    def test_exact_ipv6_full(self):
        result = parse_search_query("2001:0db8:0000:0000:0000:0000:0000:0001")
        assert result["query_type"] == "exact_ip"
        assert result["error"] is None

    def test_cidr_ipv4(self):
        result = parse_search_query("192.168.1.0/24")
        assert result["query_type"] == "cidr"
        assert result["error"] is None
        # value should be an IPv4Network object
        import ipaddress
        assert isinstance(result["value"], ipaddress.IPv4Network)

    def test_cidr_ipv6(self):
        result = parse_search_query("2001:db8::/32")
        assert result["query_type"] == "cidr"
        assert result["error"] is None
        import ipaddress
        assert isinstance(result["value"], ipaddress.IPv6Network)

    def test_cidr_invalid(self):
        result = parse_search_query("192.168.1.0/99")
        assert result["query_type"] == "invalid"
        assert result["error"] is not None

    def test_prefix_with_trailing_dot(self):
        result = parse_search_query("192.168.")
        assert result["query_type"] == "prefix"
        assert result["value"] == "192.168."
        assert result["error"] is None

    def test_prefix_two_octets(self):
        result = parse_search_query("10.0.")
        assert result["query_type"] == "prefix"
        assert result["value"] == "10.0."
        assert result["error"] is None

    def test_prefix_three_octets(self):
        result = parse_search_query("172.16.1.")
        assert result["query_type"] == "prefix"
        assert result["value"] == "172.16.1."
        assert result["error"] is None

    def test_prefix_without_trailing_dot(self):
        result = parse_search_query("192.168")
        assert result["query_type"] == "prefix"
        assert result["value"] == "192.168"
        assert result["error"] is None

    def test_prefix_ipv6_partial(self):
        result = parse_search_query("2001:")
        assert result["query_type"] == "prefix"
        assert result["value"] == "2001:"
        assert result["error"] is None

    def test_prefix_ipv6_two_groups(self):
        result = parse_search_query("2001:db8:")
        assert result["query_type"] == "prefix"
        assert result["value"] == "2001:db8:"
        assert result["error"] is None

    def test_threat_tag_simple(self):
        result = parse_search_query("ssh_bruteforce")
        assert result["query_type"] == "threat_tag"
        assert result["value"] == "ssh_bruteforce"
        assert result["error"] is None

    def test_threat_tag_with_hyphens(self):
        result = parse_search_query("apt-28")
        assert result["query_type"] == "threat_tag"
        assert result["value"] == "apt-28"
        assert result["error"] is None

    def test_threat_tag_max_length(self):
        tag = "a" * 64
        result = parse_search_query(tag)
        assert result["query_type"] == "threat_tag"

    def test_threat_tag_too_long(self):
        tag = "a" * 65
        result = parse_search_query(tag)
        assert result["query_type"] == "invalid"

    def test_invalid_empty(self):
        result = parse_search_query("")
        assert result["query_type"] == "invalid"
        assert result["error"] is not None

    def test_invalid_whitespace_only(self):
        result = parse_search_query("   ")
        assert result["query_type"] == "invalid"
        assert result["error"] is not None

    def test_invalid_special_chars(self):
        result = parse_search_query("hello world!")
        assert result["query_type"] == "invalid"

    def test_strips_whitespace(self):
        result = parse_search_query("  192.168.1.1  ")
        assert result["query_type"] == "exact_ip"
        assert result["value"] == "192.168.1.1"

    def test_invalid_octet_too_large(self):
        result = parse_search_query("999.168.1.1")
        # 999 is > 255, so not a valid IP, not a valid prefix
        # But it matches the threat_tag pattern? No, it has dots.
        # Actually "999.168.1.1" - ipaddress will reject it, _is_partial_ipv4 will reject 999
        # It has dots and special chars so won't match threat_tag
        assert result["query_type"] == "invalid"


# ── execute_search tests ─────────────────────────────────────────────────


class TestExecuteSearch:
    """Tests for execute_search function."""

    def test_exact_ip_found(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1")
        results, total = execute_search(intel_db, "192.168.1.1")
        assert total == 1
        assert len(results) == 1
        assert results[0]["ip_address"] == "192.168.1.1"

    def test_exact_ip_not_found(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1")
        results, total = execute_search(intel_db, "10.0.0.1")
        assert total == 0
        assert results == []

    def test_prefix_search(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1")
        _insert_ip_record(intel_db, "192.168.1.2")
        _insert_ip_record(intel_db, "10.0.0.1")
        results, total = execute_search(intel_db, "192.168.")
        assert total == 2
        assert all(r["ip_address"].startswith("192.168.") for r in results)

    def test_cidr_search(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1")
        _insert_ip_record(intel_db, "192.168.1.100")
        _insert_ip_record(intel_db, "192.168.2.1")
        _insert_ip_record(intel_db, "10.0.0.1")
        results, total = execute_search(intel_db, "192.168.1.0/24")
        assert total == 2
        ips = {r["ip_address"] for r in results}
        assert ips == {"192.168.1.1", "192.168.1.100"}

    def test_threat_tag_search(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1", threat_tags='["ssh_bruteforce", "scanner"]')
        _insert_ip_record(intel_db, "192.168.1.2", threat_tags='["web_exploit"]')
        _insert_ip_record(intel_db, "10.0.0.1", threat_tags='["ssh_bruteforce"]')
        results, total = execute_search(intel_db, "ssh_bruteforce")
        assert total == 2
        ips = {r["ip_address"] for r in results}
        assert ips == {"192.168.1.1", "10.0.0.1"}

    def test_invalid_query_returns_empty(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1")
        results, total = execute_search(intel_db, "hello world!")
        assert total == 0
        assert results == []

    def test_pagination(self, intel_db):
        for i in range(10):
            _insert_ip_record(intel_db, f"192.168.1.{i+1}")
        results, total = execute_search(intel_db, "192.168.", page=1, per_page=3)
        assert total == 10
        assert len(results) == 3

    def test_pagination_page_2(self, intel_db):
        for i in range(10):
            _insert_ip_record(intel_db, f"192.168.1.{i+1}")
        results, total = execute_search(intel_db, "192.168.", page=2, per_page=3)
        assert total == 10
        assert len(results) == 3

    def test_sort_by_total_times_seen(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1", total_times_seen=5)
        _insert_ip_record(intel_db, "192.168.1.2", total_times_seen=10)
        _insert_ip_record(intel_db, "192.168.1.3", total_times_seen=1)
        results, total = execute_search(
            intel_db, "192.168.", sort_by="total_times_seen", sort_order="desc"
        )
        assert results[0]["total_times_seen"] == 10
        assert results[1]["total_times_seen"] == 5
        assert results[2]["total_times_seen"] == 1

    def test_filter_repeat_offender(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1", repeat_offender=1)
        _insert_ip_record(intel_db, "192.168.1.2", repeat_offender=0)
        results, total = execute_search(
            intel_db, "192.168.", filters={"repeat_offender": True}
        )
        assert total == 1
        assert results[0]["ip_address"] == "192.168.1.1"

    def test_filter_geo_country(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1", geo_country="US")
        _insert_ip_record(intel_db, "192.168.1.2", geo_country="CN")
        results, total = execute_search(
            intel_db, "192.168.", filters={"geo_country": "US"}
        )
        assert total == 1
        assert results[0]["ip_address"] == "192.168.1.1"

    def test_filter_min_sighting_count(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1", total_times_seen=5)
        _insert_ip_record(intel_db, "192.168.1.2", total_times_seen=15)
        results, total = execute_search(
            intel_db, "192.168.", filters={"min_sighting_count": 10}
        )
        assert total == 1
        assert results[0]["ip_address"] == "192.168.1.2"

    def test_cidr_with_filters(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1", repeat_offender=1)
        _insert_ip_record(intel_db, "192.168.1.2", repeat_offender=0)
        _insert_ip_record(intel_db, "10.0.0.1", repeat_offender=1)
        results, total = execute_search(
            intel_db, "192.168.1.0/24", filters={"repeat_offender": True}
        )
        assert total == 1
        assert results[0]["ip_address"] == "192.168.1.1"

    def test_per_page_clamped_to_max(self, intel_db):
        for i in range(5):
            _insert_ip_record(intel_db, f"192.168.1.{i+1}")
        # per_page > 200 should be clamped to 200
        results, total = execute_search(intel_db, "192.168.", per_page=500)
        assert total == 5
        assert len(results) == 5

    def test_invalid_sort_column_defaults(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1")
        # Invalid sort_by should default to last_seen_at
        results, total = execute_search(intel_db, "192.168.", sort_by="invalid_col")
        assert total == 1

    def test_json_fields_parsed(self, intel_db):
        _insert_ip_record(
            intel_db, "192.168.1.1",
            threat_tags='["ssh_bruteforce", "scanner"]',
            reporting_node_list='["node-1", "node-2"]',
        )
        results, total = execute_search(intel_db, "192.168.1.1")
        assert results[0]["threat_tags"] == ["ssh_bruteforce", "scanner"]
        assert results[0]["reporting_node_list"] == ["node-1", "node-2"]

    def test_repeat_offender_as_bool(self, intel_db):
        _insert_ip_record(intel_db, "192.168.1.1", repeat_offender=1)
        results, total = execute_search(intel_db, "192.168.1.1")
        assert results[0]["repeat_offender"] is True
