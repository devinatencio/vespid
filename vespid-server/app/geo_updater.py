"""Automatic GeoIP database updater.

Downloads the latest DB-IP Lite databases from db-ip.com on a periodic
schedule.  Runs in-process (no cron/systemd timer needed) and invalidates
the MMDB reader cache so new lookups pick up the new files without a
process restart.

Databases are free under CC BY 4.0 (https://db-ip.com).
"""

from __future__ import annotations

import gzip
import logging
import os
import re
import time
import urllib.request

log = logging.getLogger(__name__)

BASE_URL = "https://download.db-ip.com/free"
DB_NAMES = ["dbip-asn-lite", "dbip-city-lite", "dbip-country-lite"]

STALE_AGE_DAYS = 45

# Regex matching auto-downloaded DB-IP Lite filenames (e.g. dbip-city-lite-2026-06.mmdb)
_AUTO_FNAME_RE = re.compile(r"^dbip-\w+-lite-\d{4}-\d{2}\.mmdb$")


def _month_str(ts: float | None = None) -> str:
    return time.strftime("%Y-%m", time.gmtime(ts))


def _prev_month_str() -> str:
    return _month_str(time.time() - 30 * 86400)


def _download_file(url: str, target: str) -> bool:
    """Download a .gz file from *url*, decompress it, and write to *target*.

    Returns True on success, False on any failure.
    """
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "Vespid-Server/1.0.1",
            "Accept": "*/*",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            data = resp.read()
    except Exception as exc:
        log.warning("Download failed: %s — %s", url, exc)
        return False
    try:
        decompressed = gzip.decompress(data)
        with open(target, "wb") as f:
            f.write(decompressed)
    except Exception as exc:
        log.warning("Write failed: %s — %s", target, exc)
        return False
    log.info("Downloaded %s -> %s (%d bytes)", url, target, len(decompressed))
    return True


def _cleanup_stale(geo_dir: str) -> None:
    """Remove .mmdb files older than *STALE_AGE_DAYS* days."""
    cutoff = time.time() - STALE_AGE_DAYS * 86400
    removed = 0
    for entry in os.listdir(geo_dir):
        if not entry.endswith(".mmdb"):
            continue
        path = os.path.join(geo_dir, entry)
        try:
            if os.path.getmtime(path) < cutoff:
                os.remove(path)
                removed += 1
                log.info("Removed stale GeoIP DB: %s", path)
        except OSError:
            pass
    if removed:
        log.info("Cleaned up %d stale GeoIP database(s)", removed)


def _has_user_managed_dbs(geo_dir: str) -> bool:
    """Return True if *geo_dir* contains any non-auto-downloaded .mmdb file.

    Files like ``GeoLite2-City.mmdb`` or commercial ``dbip-country.mmdb``
    signal that the user is managing their own GeoIP databases — the auto-
    updater should not download DB-IP Lite files in that case.
    """
    if not os.path.isdir(geo_dir):
        return False
    for entry in os.listdir(geo_dir):
        if not entry.endswith(".mmdb"):
            continue
        if not _AUTO_FNAME_RE.match(entry):
            return True
    return False


def update_geoip(geo_dir: str) -> bool:
    """Download the latest GeoIP databases into *geo_dir*.

    Skips if the directory already contains a user-managed database
    (e.g. GeoLite2 or commercial MaxMind).  Otherwise tries the current
    month first, falling back to the previous month if the current
    month's release is not yet available (db-ip publishes around the
    1st).  Existing files are skipped.

    Returns True if at least one new database was downloaded, False otherwise.
    """
    if not os.path.isdir(geo_dir):
        try:
            os.makedirs(geo_dir, exist_ok=True)
        except OSError as exc:
            log.warning("Cannot create geoip directory %s: %s", geo_dir, exc)
            return False

    if _has_user_managed_dbs(geo_dir):
        log.debug(
            "User-managed GeoIP databases found in %s — skipping auto-update",
            geo_dir,
        )
        return False

    downloaded = False

    for attempt_month in (_month_str(), _prev_month_str()):
        for db in DB_NAMES:
            fname = f"{db}-{attempt_month}.mmdb"
            target = os.path.join(geo_dir, fname)
            if os.path.exists(target):
                continue
            url = f"{BASE_URL}/{fname}.gz"
            if _download_file(url, target):
                downloaded = True
            else:
                # If any file in the current month fails, we break out
                # of the DB loop and try the previous month instead.
                break
        else:
            # All DBs for this month succeeded (or already existed)
            if downloaded:
                _cleanup_stale(geo_dir)
            return downloaded

        # Current month had at least one failure — try previous month
        continue

    return downloaded
