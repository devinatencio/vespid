#!/usr/bin/env bash
# ===========================================================================
# sign-rpms.sh — Sign Vespid RPM packages with a GPG key
#
# Prerequisites:
#   1. Create a signing key:  gpg --gen-key
#   2. Configure rpm:         echo '%_gpg_name Vespid Security' >> ~/.rpmmacros
#   3. Run this script with the key name:
#        ./packaging/sign-rpms.sh "Vespid Security"
#
# This will sign all RPMs found in rpmbuild/RPMS/ and rpmbuild/SRPMS/.
# If the GPG key has a passphrase, rpm will prompt for it (or use gpg-agent).
#
# To verify signing:  rpm -Kv rpmbuild/RPMS/*/*.rpm
# ===========================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
RPM_DIR="${PROJECT_DIR}/rpmbuild"

SIGN_KEY="${1:-}"

if [ -z "$SIGN_KEY" ]; then
    echo "Usage: $0 \"GPG Key Name\""
    echo ""
    echo "Examples:"
    echo "  $0 \"Vespid Security\""
    echo "  $0 \"team@vespid.dev\""
    echo ""
    echo "Set up your signing key first:"
    echo "  gpg --gen-key"
    echo "  echo '%_gpg_name Vespid Security' >> ~/.rpmmacros"
    exit 1
fi

# Check for RPMs to sign
RPMS=$(find "$RPM_DIR/RPMS" "$RPM_DIR/SRPMS" -name '*.rpm' 2>/dev/null || true)

if [ -z "$RPMS" ]; then
    echo "No RPMs found in $RPM_DIR"
    echo "Build them first:  make rpm"
    exit 1
fi

echo "Signing RPMs with key: $SIGN_KEY"
echo ""

for rpm in $RPMS; do
    echo "  Signing: $(basename "$rpm")"
    rpm --addsign --define "_gpg_name $SIGN_KEY" "$rpm"
done

echo ""
echo "Done — all RPMs signed."
echo ""
echo "Verification:"
echo "  rpm -Kv $RPM_DIR/RPMS/*/*.rpm"
