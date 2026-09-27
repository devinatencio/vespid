"""ISO 3166-1 alpha-2 country code to name mapping.

Zero dependencies (beyond the bundled JSON data file).
"""

import json
import os

__all__ = ["COUNTRY_NAMES", "country_name"]

# In development the data file lives at the repo root; in an RPM
# install it is placed under the install prefix at data/country_codes.json.
_here = os.path.dirname(os.path.abspath(__file__))
_candidates = [
    os.path.join(_here, "..", "data", "country_codes.json"),
    os.path.join(_here, "..", "..", "data", "country_codes.json"),
]
_DATA_PATH = next((p for p in _candidates if os.path.isfile(p)), None)

# Graceful degradation: if the data file is missing (e.g. a build that did
# not bundle it), fall back to an empty mapping so importing this module
# never crashes. country_name() then returns the raw ISO code unchanged.
COUNTRY_NAMES: dict[str, str] = {}
if _DATA_PATH:
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
