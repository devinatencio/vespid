#!/usr/bin/env bash
# download_geoip.sh — Download DB-IP Lite GeoIP databases for packaging
#
# DB-IP Lite databases are freely redistributable under CC BY 4.0
# (Creative Commons Attribution). Attribution is provided at:
#   https://db-ip.com
#
# Usage:
#   ./download_geoip.sh [--month YYYY-MM] /path/to/output/dir
#
# Downloads:  dbip-asn-lite-YYYY-MM.mmdb
#             dbip-city-lite-YYYY-MM.mmdb
#             dbip-country-lite-YYYY-MM.mmdb

set -euo pipefail

MONTH=""
OUTPUT_DIR=""

usage() {
    echo "Usage: $0 [--month YYYY-MM] <output-directory>"
    echo ""
    echo "  --month YYYY-MM   Download a specific month (default: current month,"
    echo "                     falls back to previous months if not yet available)"
    echo ""
    echo "Example:"
    echo "  $0 /tmp/geoip"
    echo "  $0 --month 2026-06 /tmp/geoip"
    exit 1
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --month|-m)
            MONTH="$2"; shift 2 ;;
        --help|-h) usage ;;
        -*) echo "Unknown flag: $1"; usage ;;
        *)  OUTPUT_DIR="$1"; shift ;;
    esac
done

if [[ -z "$OUTPUT_DIR" ]]; then
    echo "ERROR: output directory required"
    usage
fi

mkdir -p "$OUTPUT_DIR"

BASE_URL="https://download.db-ip.com/free"
DBS=("dbip-asn-lite" "dbip-city-lite" "dbip-country-lite")

download_month() {
    local m="$1"
    for db in "${DBS[@]}"; do
        local fname="${db}-${m}.mmdb"
        local target="${OUTPUT_DIR}/${fname}"
        if [[ -f "$target" ]]; then
            echo "  Already have $fname, skipping"
            continue
        fi
        local url="${BASE_URL}/${fname}.gz"
        echo "  Downloading $fname ..."
        if curl -fsSL --retry 2 --connect-timeout 10 "$url" -o "${target}.gz"; then
            gunzip -f "${target}.gz"
            echo "    -> $target"
        else
            rm -f "${target}.gz"
            return 1
        fi
    done
    return 0
}

if [[ -n "$MONTH" ]]; then
    echo "Downloading DB-IP Lite databases for $MONTH to $OUTPUT_DIR/"
    if download_month "$MONTH"; then
        echo "Done."
    else
        echo "ERROR: Failed to download one or more databases for $MONTH"
        exit 1
    fi
else
    # Try current month, then previous month
    CURRENT=$(date +%Y-%m)
    PREVIOUS=$(date -v-1m +%Y-%m 2>/dev/null || date -d "1 month ago" +%Y-%m)
    echo "Downloading DB-IP Lite databases to $OUTPUT_DIR/"

    if download_month "$CURRENT"; then
        echo "Done (${CURRENT})."
    else
        echo "  Current month ($CURRENT) not available, trying $PREVIOUS ..."
        if download_month "$PREVIOUS"; then
            echo "Done (${PREVIOUS})."
        else
            echo "ERROR: Failed to download databases for $CURRENT or $PREVIOUS"
            exit 1
        fi
    fi
fi
