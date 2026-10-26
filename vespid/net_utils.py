"""Network entry normalization helpers."""

from __future__ import annotations

import ipaddress
import logging
from collections.abc import Iterable

log = logging.getLogger("vespid.net")


def normalize_entry_map(entries: Iterable[str]) -> dict[str, str]:
    """Map normalized network strings to their original entry strings.

    The server stores bare IPs (``72.201.135.201``) while the runtime
    allowlist normalizes entries to CIDR (``72.201.135.201/32``). Comparing
    raw strings makes every list sync add and remove the same entry. Keying
    by the normalized network avoids that flip-flop.
    """
    result: dict[str, str] = {}
    for raw in entries:
        text = str(raw).strip()
        if not text:
            continue
        try:
            key = str(ipaddress.ip_network(text, strict=False))
        except ValueError:
            log.warning("Ignoring invalid IP/CIDR entry %r", text)
            continue
        result.setdefault(key, text)
    return result
