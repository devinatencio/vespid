"""Lightweight GeoIP lookup helper for the server.

Provides IP-to-country, ASN, and organization lookups using MaxMind GeoLite2
or db-ip MMDB databases. Supports both vendors' record formats transparently.
Degrades gracefully if maxminddb is not installed or databases are not present.

Database search order (first match wins per DB type):
  1. Environment variable override (VESPID_GEOIP_DB, etc.)
  2. /etc/vespid-server/geoip/
  3. /etc/vespid/geoip/
  4. /var/lib/GeoIP/
"""

from __future__ import annotations

import glob
import ipaddress
import logging
import os
import re
from functools import lru_cache

logger = logging.getLogger(__name__)

_SEARCH_DIRS = [
    "/etc/vespid-server/geoip",
    "/etc/vespid/geoip",
    "/var/lib/GeoIP",
]

_DB_NAMES = {
    "country": ["GeoLite2-Country.mmdb", "dbip-country-lite.mmdb", "dbip-country.mmdb"],
    "city": ["GeoLite2-City.mmdb", "dbip-city-lite.mmdb", "dbip-city.mmdb"],
    "asn": ["GeoLite2-ASN.mmdb", "dbip-asn-lite.mmdb", "dbip-asn.mmdb"],
}

_ENV_OVERRIDES = {
    "country": "VESPID_GEOIP_DB",
    "city": "VESPID_GEOIP_CITY_DB",
    "asn": "VESPID_GEOIP_ASN_DB",
}

# Dated db-ip download names (e.g. dbip-city-lite-2026-06.mmdb).
_DATED_PATTERNS = {
    "country": ["dbip-country-lite-*.mmdb", "dbip-country-*.mmdb"],
    "city": ["dbip-city-lite-*.mmdb", "dbip-city-*.mmdb"],
    "asn": ["dbip-asn-lite-*.mmdb", "dbip-asn-*.mmdb"],
}

_DATE_RE = re.compile(r"(\d{4})-(\d{2})")


def _db_sort_key(path: str) -> tuple:
    """Sort key for MMDB candidates.

    Non-dated (user-uploaded) files rank above dated (auto-downloaded) files,
    so a manually-placed GeoLite2 or commercial MaxMind database is always
    preferred over the free auto-downloaded DB-IP Lite databases.  Among
    dated files, newer dates rank above older ones.
    """
    filename = os.path.basename(path)
    m = _DATE_RE.search(filename)
    if m:
        return (0, int(m.group(1)), int(m.group(2)), filename)
    return (1, 0, 0, filename)


def _find_db(db_key: str) -> str | None:
    """Locate a GeoIP database file."""
    env_var = _ENV_OVERRIDES[db_key]
    env_path = os.environ.get(env_var)
    if env_path:
        if os.path.exists(env_path):
            return env_path
        logger.warning("%s set to %s but file not found", env_var, env_path)
        return None

    candidates: list[str] = []
    for directory in _SEARCH_DIRS:
        if not os.path.isdir(directory):
            continue
        for filename in _DB_NAMES[db_key]:
            candidate = os.path.join(directory, filename)
            if os.path.isfile(candidate):
                candidates.append(candidate)
        for pattern in _DATED_PATTERNS[db_key]:
            for candidate in glob.glob(os.path.join(directory, pattern)):
                if os.path.isfile(candidate):
                    candidates.append(candidate)

    if not candidates:
        return None

    candidates.sort(key=_db_sort_key, reverse=True)
    return candidates[0]


try:
    import maxminddb

    _HAS_MAXMINDDB = True
except ImportError:
    _HAS_MAXMINDDB = False


def _open_reader(db_key: str):
    """Open a maxminddb Reader for the given DB type."""
    if not _HAS_MAXMINDDB:
        return None
    path = _find_db(db_key)
    if not path:
        return None
    try:
        logger.info("Using %s DB: %s (pid=%d)", db_key, path, os.getpid())
        return maxminddb.open_database(path)
    except Exception as exc:
        logger.warning("Could not open %s DB %s: %s", db_key, path, exc)
        return None


@lru_cache(maxsize=1)
def _country_reader():
    return _open_reader("country")


@lru_cache(maxsize=1)
def _city_reader():
    return _open_reader("city")


@lru_cache(maxsize=1)
def _asn_reader():
    return _open_reader("asn")


def clear_cache() -> None:
    """Drop all cached MMDB reader instances.

    After calling this, the next call to *lookup()* will re-open the
    database files from disk, picking up any newly-downloaded files.
    """
    _country_reader.cache_clear()
    _city_reader.cache_clear()
    _asn_reader.cache_clear()


def _normalize(record: dict | None) -> dict:
    """Normalize a raw MMDB record to a standard output dict.

    Handles both MaxMind (nested dicts) and db-ip (flat values) formats.
    """
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

    # Fallback to registered_country (MaxMind)
    if not result.get("country"):
        reg = record.get("registered_country")
        if isinstance(reg, dict):
            result["country"] = reg.get("iso_code")
            names = reg.get("names", {})
            if names and not result.get("country_name"):
                result["country_name"] = names.get("en")

    # Country name for db-ip (some versions include it)
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
            result["latitude"] = str(loc["latitude"])
        if loc.get("longitude") is not None:
            result["longitude"] = str(loc["longitude"])

    if record.get("latitude") is not None and not result.get("latitude"):
        result["latitude"] = str(record["latitude"])
    if record.get("longitude") is not None and not result.get("longitude"):
        result["longitude"] = str(record["longitude"])

    # ASN / organization
    asn = record.get("autonomous_system_number")
    if asn is not None:
        result["asn"] = asn
    org = record.get("autonomous_system_organization")
    if org:
        result["org"] = org

    return result


def _is_public(ip: str) -> bool:
    """Return True if the IP is a public (globally routable) address."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_multicast
        or addr.is_reserved
    )


@lru_cache(maxsize=4096)
def lookup(ip: str) -> dict:
    """Return geo metadata for an IP address.

    Returns a dict with only non-None keys from:
        - country: ISO 3166-1 alpha-2 code
        - country_name: Full country name
        - city: City name
        - region: Subdivision/region name
        - latitude: String latitude
        - longitude: String longitude
        - asn: integer ASN
        - org: organization name

    Always returns a dict (possibly empty), never raises.
    """
    result: dict = {}

    if not ip or not _is_public(ip):
        return result

    # Try City DB first (richest data — includes country + city + location),
    # then Country DB as fallback for country-only fields.
    for get_reader in (_city_reader, _country_reader):
        rdr = get_reader()
        if rdr is not None:
            record = rdr.get(ip)
            if record:
                for k, v in _normalize(record).items():
                    result.setdefault(k, v)

    # ASN lookup (independent database)
    rdr = _asn_reader()
    if rdr is not None:
        record = rdr.get(ip)
        if record:
            result.update(_normalize(record))

    return result


def is_available() -> bool:
    """Return True if at least one GeoIP database is usable."""
    if not _HAS_MAXMINDDB:
        return False
    return _country_reader() is not None or _city_reader() is not None or _asn_reader() is not None
