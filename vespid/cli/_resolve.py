"""Shared identifier resolution helpers for CLI commands."""

import json as _json
import re as _re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ..server_client import ServerClient

_UUID_RE = _re.compile(
    r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$",
    _re.IGNORECASE,
)


def resolve_node(client: "ServerClient", ident: str) -> str | None:
    """Resolve a node ID or hostname to a node UUID.

    Returns the UUID string if found, or None if unresolvable.
    If *ident* is already a UUID, it is returned as-is.
    """
    if _UUID_RE.match(ident):
        return ident
    from ..server_client import ServerClientError

    try:
        result = client.nodes_list()
    except (ServerClientError, Exception):
        return None
    nodes = result if isinstance(result, list) else result.get("nodes", [])
    for n in nodes:
        hi = n.get("last_host_info", {})
        if isinstance(hi, str):
            try:
                hi = _json.loads(hi)
            except (ValueError, TypeError):
                hi = {}
        hostname = (
            n.get("display_name", "")
            or n.get("node_display", "")
            or hi.get("hostname", "")
            or hi.get("host_name", "")
        )
        if ident.lower() == hostname.lower():
            return n.get("node_id")
    return None


def build_node_map(client: "ServerClient") -> dict[str, str]:
    """Build a UUID → hostname mapping from all known nodes."""
    from ..server_client import ServerClientError

    try:
        result = client.nodes_list()
    except (ServerClientError, Exception):
        return {}
    nodes = result if isinstance(result, list) else result.get("nodes", [])
    mapping: dict[str, str] = {}
    for n in nodes:
        nid = n.get("node_id", "")
        hi = n.get("last_host_info", {})
        if isinstance(hi, str):
            try:
                hi = _json.loads(hi)
            except (ValueError, TypeError):
                hi = {}
        hostname = (
            n.get("display_name", "")
            or n.get("node_display", "")
            or hi.get("hostname", "")
            or hi.get("host_name", "")
        )
        if nid and hostname:
            mapping[nid] = hostname
    return mapping
