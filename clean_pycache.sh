#!/usr/bin/env bash
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
find "${SCRIPT_DIR}" -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null
find "${SCRIPT_DIR}" -type f -name '*.pyc' -delete 2>/dev/null
find "${SCRIPT_DIR}" -type f -name '*.pyo' -delete 2>/dev/null
echo "Cleaned __pycache__ directories and .pyc/.pyo files from ${SCRIPT_DIR}"
