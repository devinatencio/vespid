"""Tests for allowlist/blocklist list-sync normalization."""

from vespid.net_utils import normalize_entry_map as _normalize_entry_map


def test_bare_ip_and_cidr_are_equivalent():
    """A server bare IP and a runtime /32 must compare as the same entry."""
    server = _normalize_entry_map(["72.201.135.201"])
    local = _normalize_entry_map(["72.201.135.201/32"])

    assert set(server) == set(local) == {"72.201.135.201/32"}
    assert not (set(server) - set(local))
    assert not (set(local) - set(server))


def test_duplicate_forms_collapse():
    entries = _normalize_entry_map(["10.0.0.0/24", "10.0.0.1/24", "10.0.0.0/24"])

    assert set(entries) == {"10.0.0.0/24"}


def test_invalid_entries_are_ignored():
    entries = _normalize_entry_map(["not-an-ip", "192.168.1.5"])

    assert set(entries) == {"192.168.1.5/32"}
