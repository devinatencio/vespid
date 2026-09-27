#!/bin/sh
# Detect the native package format of the host.
#
# Prints exactly one of: rpm | deb | unknown
#
# Detection order:
#   1. /etc/os-release  (ID / ID_LIKE)
#   2. available tooling (dpkg-deb / rpmbuild)
set -eu

id=""
id_like=""
if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    id="${ID:-}"
    id_like="${ID_LIKE:-}"
fi

haystack=" ${id} ${id_like} "
case "${haystack}" in
    *debian*|*ubuntu*|*linuxmint*|*pop*|*raspbian*|*kali*)
        echo deb
        exit 0
        ;;
    *rhel*|*fedora*|*centos*|*almalinux*|*rocky*|*oracle*|*amzn*|*suse*|*opensuse*)
        echo rpm
        exit 0
        ;;
esac

if command -v dpkg-deb >/dev/null 2>&1; then
    echo deb
    exit 0
fi
if command -v rpmbuild >/dev/null 2>&1; then
    echo rpm
    exit 0
fi

echo unknown
