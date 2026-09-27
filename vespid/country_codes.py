"""ISO 3166-1 alpha-2 country code to name mapping.

Zero dependencies (beyond the bundled JSON data file).
"""

import json
import os

__all__ = ["COUNTRY_NAMES", "country_name"]

_DATA_PATH = os.path.normpath(
    os.path.join(os.path.dirname(__file__), "..", "data", "country_codes.json")
)

# Graceful degradation: if the data file is missing (e.g. a build that did
# not bundle it), fall back to an empty mapping so importing this module
# never crashes. country_name() then returns the raw ISO code unchanged.
COUNTRY_NAMES: dict[str, str] = {}
if os.path.isfile(_DATA_PATH):
    try:
        with open(_DATA_PATH, encoding="utf-8") as _f:
            COUNTRY_NAMES = json.load(_f)
    except (OSError, json.JSONDecodeError):
        pass


def country_name(code: str) -> str:
    """Return "HK (Hong Kong)" for a known code, or the raw code if unknown."""
    if not code or code == "??":
        return "??"
    name = COUNTRY_NAMES.get(code.upper())
    if name:
        return f"{code} ({name})"
    return code
