#!/usr/bin/env python3
"""CLI to look up an IP in bundled db-ip City + ASN MMDBs (and MaxMind if present).

Usage:
    .venv/bin/python lookup_ip.py 8.8.8.8
    .venv/bin/python lookup_ip.py 8.8.8.8 --raw
    VESPID_GEOIP_MAXMIND_DB=/path/to/GeoLite2-City.mmdb \
        VESPID_GEOIP_MAXMIND_ASN_DB=/path/to/GeoLite2-ASN.mmdb \
        .venv/bin/python lookup_ip.py 1.1.1.1
"""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

import maxminddb

# Default MMDBs shipped with this repo.
DBIP_CITY_MMDB = Path(__file__).resolve().parent / "dbip-city-lite-2026-06.mmdb"
DBIP_ASN_MMDB = Path(__file__).resolve().parent / "dbip-asn-lite-2026-06.mmdb"

# MaxMind lookup locations (override via env var).
MAXMIND_CITY_DEFAULT_PATHS = [
    Path("/var/lib/GeoIP/GeoLite2-City.mmdb"),
    Path("/etc/vespid/geoip/GeoLite2-City.mmdb"),
]
MAXMIND_ASN_DEFAULT_PATHS = [
    Path("/var/lib/GeoIP/GeoLite2-ASN.mmdb"),
    Path("/etc/vespid/geoip/GeoLite2-ASN.mmdb"),
]


def _normalize(record: dict | None) -> dict:
    """Normalize a raw MMDB record to a flat comparison dict."""
    result: dict = {}
    if not record:
        return result

    # Country
    country_val = record.get("country")
    if isinstance(country_val, dict):
        result["country"] = country_val.get("iso_code")
        names = country_val.get("names", {})
        if names:
            result["country_name"] = names.get("en")
    elif isinstance(country_val, str):
        result["country"] = country_val

    if not result.get("country"):
        reg = record.get("registered_country")
        if isinstance(reg, dict):
            result["country"] = reg.get("iso_code")
            names = reg.get("names", {})
            if names and not result.get("country_name"):
                result["country_name"] = names.get("en")

    if result.get("country") and not result.get("country_name"):
        cn = record.get("country_name")
        if isinstance(cn, str):
            result["country_name"] = cn

    # City
    city_val = record.get("city")
    if isinstance(city_val, dict):
        names = city_val.get("names", {})
        if names:
            result["city"] = names.get("en")
    elif isinstance(city_val, str):
        result["city"] = city_val

    # Region / subdivision
    subs = record.get("subdivisions")
    if isinstance(subs, list) and subs:
        sub = subs[0]
        if isinstance(sub, dict):
            region = sub.get("iso_code") or sub.get("names", {}).get("en")
            if region:
                result["region"] = region

    region_val = record.get("region")
    if isinstance(region_val, str) and not result.get("region"):
        result["region"] = region_val

    # Location
    loc = record.get("location")
    if isinstance(loc, dict):
        if loc.get("latitude") is not None:
            result["latitude"] = loc["latitude"]
        if loc.get("longitude") is not None:
            result["longitude"] = loc["longitude"]
        if loc.get("accuracy_radius") is not None:
            result["accuracy_radius"] = loc["accuracy_radius"]
        if loc.get("time_zone") is not None:
            result["time_zone"] = loc["time_zone"]

    if record.get("latitude") is not None and not result.get("latitude"):
        result["latitude"] = record["latitude"]
    if record.get("longitude") is not None and not result.get("longitude"):
        result["longitude"] = record["longitude"]

    # ASN / organization
    asn = record.get("autonomous_system_number")
    if asn is not None:
        result["asn"] = f"AS{asn}"
    org = record.get("autonomous_system_organization")
    if org:
        result["org"] = org

    return result


def _open_db(path: Path) -> maxminddb.Reader | None:
    if not path.exists():
        return None
    try:
        return maxminddb.open_database(str(path))
    except Exception as exc:  # pragma: no cover
        print(f"warning: could not open {path}: {exc}", file=sys.stderr)
        return None


def _find_maxmind_city_db() -> Path | None:
    env = os.environ.get("VESPID_GEOIP_MAXMIND_DB")
    if env:
        return Path(env)
    for candidate in MAXMIND_CITY_DEFAULT_PATHS:
        if candidate.exists():
            return candidate
    return None


def _find_maxmind_asn_db() -> Path | None:
    env = os.environ.get("VESPID_GEOIP_MAXMIND_ASN_DB")
    if env:
        return Path(env)
    for candidate in MAXMIND_ASN_DEFAULT_PATHS:
        if candidate.exists():
            return candidate
    return None


def _lookup(reader: maxminddb.Reader | None, ip: str) -> dict | None:
    if reader is None:
        return None
    try:
        return reader.get(ip)
    except Exception as exc:  # pragma: no cover
        print(f"warning: lookup failed for {ip}: {exc}", file=sys.stderr)
        return None


def _full_lookup(city_reader: maxminddb.Reader | None, asn_reader: maxminddb.Reader | None, ip: str) -> tuple[dict | None, dict | None, dict]:
    """Return (city_raw, asn_raw, merged_normalized)."""
    city_raw = _lookup(city_reader, ip)
    asn_raw = _lookup(asn_reader, ip)
    normalized = _normalize(city_raw)
    normalized.update(_normalize(asn_raw))
    return city_raw, asn_raw, normalized


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Look up an IP in db-ip City + ASN MMDBs (and optionally MaxMind)."
    )
    parser.add_argument("ip", help="IP address to look up")
    parser.add_argument(
        "--dbip-db",
        default=str(DBIP_CITY_MMDB),
        help="Path to the db-ip City MMDB",
    )
    parser.add_argument(
        "--dbip-asn-db",
        default=str(DBIP_ASN_MMDB),
        help="Path to the db-ip ASN MMDB",
    )
    parser.add_argument(
        "--maxmind-db",
        default=os.environ.get("VESPID_GEOIP_MAXMIND_DB"),
        help="Path to a MaxMind City MMDB (defaults to env VESPID_GEOIP_MAXMIND_DB)",
    )
    parser.add_argument(
        "--maxmind-asn-db",
        default=os.environ.get("VESPID_GEOIP_MAXMIND_ASN_DB"),
        help="Path to a MaxMind ASN MMDB (defaults to env VESPID_GEOIP_MAXMIND_ASN_DB)",
    )
    parser.add_argument(
        "--raw",
        action="store_true",
        help="Also print the raw MMDB records",
    )
    args = parser.parse_args()

    dbip_city_path = Path(args.dbip_db)
    dbip_asn_path = Path(args.dbip_asn_db)

    if not dbip_city_path.exists():
        print(f"error: db-ip City database not found: {dbip_city_path}", file=sys.stderr)
        return 1

    dbip_city_reader = _open_db(dbip_city_path)
    if dbip_city_reader is None:
        print(f"error: could not open db-ip City database: {dbip_city_path}", file=sys.stderr)
        return 1

    dbip_asn_reader = _open_db(dbip_asn_path) if dbip_asn_path.exists() else None

    maxmind_city_path = Path(args.maxmind_db) if args.maxmind_db else _find_maxmind_city_db()
    maxmind_city_reader = _open_db(maxmind_city_path) if maxmind_city_path else None

    maxmind_asn_path = Path(args.maxmind_asn_db) if args.maxmind_asn_db else _find_maxmind_asn_db()
    maxmind_asn_reader = _open_db(maxmind_asn_path) if maxmind_asn_path else None

    print(f"IP: {args.ip}")
    print(f"db-ip City DB: {dbip_city_path}")
    print(f"db-ip ASN DB:  {dbip_asn_path}{' (not found)' if dbip_asn_reader is None else ''}")

    dbip_city_raw, dbip_asn_raw, dbip_norm = _full_lookup(dbip_city_reader, dbip_asn_reader, args.ip)

    print("\n--- db-ip normalized ---")
    print(json.dumps(dbip_norm, indent=2, default=str))
    if args.raw:
        if dbip_city_raw:
            print("\n--- db-ip City raw record ---")
            print(json.dumps(dbip_city_raw, indent=2, default=str))
        if dbip_asn_raw:
            print("\n--- db-ip ASN raw record ---")
            print(json.dumps(dbip_asn_raw, indent=2, default=str))

    if maxmind_city_reader is not None or maxmind_asn_reader is not None:
        print(f"\nMaxMind City DB: {maxmind_city_path}{' (not found)' if maxmind_city_reader is None else ''}")
        print(f"MaxMind ASN DB:  {maxmind_asn_path}{' (not found)' if maxmind_asn_reader is None else ''}")

        mm_city_raw, mm_asn_raw, mm_norm = _full_lookup(maxmind_city_reader, maxmind_asn_reader, args.ip)

        print("\n--- MaxMind normalized ---")
        print(json.dumps(mm_norm, indent=2, default=str))
        if args.raw:
            if mm_city_raw:
                print("\n--- MaxMind City raw record ---")
                print(json.dumps(mm_city_raw, indent=2, default=str))
            if mm_asn_raw:
                print("\n--- MaxMind ASN raw record ---")
                print(json.dumps(mm_asn_raw, indent=2, default=str))

        print("\n--- side-by-side (normalized) ---")
        all_keys = sorted(set(dbip_norm) | set(mm_norm))
        width = max((len(k) for k in all_keys), default=0)
        print(f"{'key':<{width}}  {'db-ip':<40} {'MaxMind':<40}")
        print("-" * (width + 84))
        for key in all_keys:
            print(f"{key:<{width}}  {str(dbip_norm.get(key, '-')):<40} {str(mm_norm.get(key, '-')):<40}")
    else:
        print("\nMaxMind DBs: not found (set VESPID_GEOIP_MAXMIND_DB / VESPID_GEOIP_MAXMIND_ASN_DB or use --maxmind-db / --maxmind-asn-db)")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
