"""Tests for shared CLI helpers."""

from vespid.cli._common import ip_sort_key, sort_entries_by_ip


def test_ip_sort_key_handles_mixed_ipv4_and_ipv6():
    entries = [
        {"ip": "2400:6180:10:200::e8e6:f000"},
        {"ip": "121.31.210.125"},
        {"ip": "10.0.0.1"},
        {"ip": "not-an-ip"},
    ]

    ordered = [entry["ip"] for entry in sort_entries_by_ip(entries)]

    assert ordered == [
        "10.0.0.1",
        "121.31.210.125",
        "2400:6180:10:200::e8e6:f000",
        "not-an-ip",
    ]


def test_ip_sort_key_orders_cidrs_numerically():
    entries = [
        {"entry": "192.168.2.0/24"},
        {"entry": "10.0.0.0/8"},
        {"entry": "192.168.1.0/24"},
    ]

    ordered = [entry["entry"] for entry in sort_entries_by_ip(entries, key="entry")]

    assert ordered == ["10.0.0.0/8", "192.168.1.0/24", "192.168.2.0/24"]


def test_sort_entries_by_ip_supports_plain_strings():
    assert sorted(
        ["2001:db8::1", "192.0.2.1", "10.0.0.1"],
        key=ip_sort_key,
    ) == ["10.0.0.1", "192.0.2.1", "2001:db8::1"]
