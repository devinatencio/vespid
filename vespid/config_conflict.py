"""Conflict resolution strategies for centralized agent management.

Provides pure functions for resolving conflicts between server-managed
configuration settings and local agent configuration.

Each resolver takes dict representations of the server profile settings
and the local configuration, and returns a merged dict representing the
resolved configuration to apply.
"""

from __future__ import annotations

import logging
from typing import Any

log = logging.getLogger("vespid.config_conflict")

# Keys whose values are lists — in merge mode these are replaced entirely
# by the server value rather than being merged element-by-element.
LIST_KEYS: set[str] = {
    "fleet_local_allow_list",
}

# Keys whose list values should be UNIONED (profile + local) rather than
# replaced.  Items are deduplicated by a key field for dicts, or by value
# for strings.  Profile entries take precedence on conflicts.
# See _DEDUP_KEY_MAP for which field is used for deduplication per key.
LAYERED_LIST_KEYS: set[str] = {
    "subscriptions",
    "brute_force_rules",
    "custom_rules",
    "fleet_local_allow_list",
    "log_sources",
}

# Subset of LAYERED_LIST_KEYS where LOCAL entries take precedence on
# dedup-field conflicts instead of server entries.  This allows the server
# to push sensible defaults (e.g. auth.log for SSH detection) while nodes
# that explicitly configure log_sources locally retain full control over
# their own paths.  Server entries for paths NOT defined locally are still
# merged in.
LOCAL_WINS_LAYERED_KEYS: set[str] = {
    "log_sources",
}

# Map of config key → dict field used for deduplication during union.
# Keys not listed here default to "name".
_DEDUP_KEY_MAP: dict[str, str] = {
    "log_sources": "path",
}


def _union_named_lists(server_list: list, local_list: list, dedup_field: str = "name") -> list:
    """Union two lists of dicts by a key field.  Server entries win on conflict.

    Args:
        server_list: Items from the server profile (take precedence).
        local_list: Items from the local/auto-detected config.
        dedup_field: The dict field used for deduplication (default: "name").
                     For log_sources this is "path".

    Items without the dedup field are included from both lists (deduplicated
    by value equality for non-dict items like plain strings).
    """
    if not server_list and not local_list:
        return []

    # Index server items by dedup field
    server_by_key: dict[str, Any] = {}
    server_unkeyed: list = []
    for item in server_list or []:
        if isinstance(item, dict) and dedup_field in item:
            server_by_key[item[dedup_field]] = item
        else:
            server_unkeyed.append(item)

    # Start with all server items
    result = list(server_list or [])

    # Add local items that aren't already in server (by dedup field)
    for item in local_list or []:
        if isinstance(item, dict) and dedup_field in item:
            if item[dedup_field] not in server_by_key:
                result.append(item)
        elif item not in server_unkeyed:
            result.append(item)

    return result


def _union_local_wins(server_list: list, local_list: list, dedup_field: str = "name") -> list:
    """Union two lists of dicts by a key field.  Local entries win on conflict.

    Like _union_named_lists but with reversed precedence: local items form
    the baseline and server items are added only for keys not already defined
    locally.  This lets the server push defaults that fill gaps without
    overriding explicit local configuration.

    Args:
        server_list: Items from the server profile (fill gaps only).
        local_list: Items from the local config (take precedence).
        dedup_field: The dict field used for deduplication (default: "name").
                     For log_sources this is "path".
    """
    if not server_list and not local_list:
        return []

    # Index local items by dedup field
    local_by_key: dict[str, Any] = {}
    local_unkeyed: list = []
    for item in local_list or []:
        if isinstance(item, dict) and dedup_field in item:
            local_by_key[item[dedup_field]] = item
        else:
            local_unkeyed.append(item)

    # Start with all local items
    result = list(local_list or [])

    # Add server items that aren't already defined locally (by dedup field)
    for item in server_list or []:
        if isinstance(item, dict) and dedup_field in item:
            if item[dedup_field] not in local_by_key:
                result.append(item)
        elif item not in local_unkeyed:
            result.append(item)

    return result


def resolve_server_wins(
    server_settings: dict[str, Any], local_config: dict[str, Any]
) -> dict[str, Any]:
    """Server-wins conflict resolution with layered list merging.

    Server values for all keys present in the server settings (profile).
    Local values for keys NOT present in the server settings.

    For LAYERED_LIST_KEYS (subscriptions, brute_force_rules, custom_rules,
    log_sources, fleet_local_allow_list):
    the profile provides the baseline and local additions are unioned on top.
    This allows feeds/rules added via the command queue to coexist with
    profile-managed feeds/rules.

    For LOCAL_WINS_LAYERED_KEYS (log_sources): local entries take precedence
    on path conflicts, and server entries fill in any paths not defined locally.
    This lets the server push sensible defaults while nodes that explicitly
    configure log_sources locally retain control over their own paths.

    For other list keys: server replaces local entirely.

    Args:
        server_settings: Settings dict from the server profile.
        local_config: Dict of current local configuration values.

    Returns:
        Resolved settings dict.
    """
    resolved: dict[str, Any] = {}

    # Start with all local keys
    for key, value in local_config.items():
        resolved[key] = value

    # Server values override for every key present in the profile
    for key, value in server_settings.items():
        if key in LAYERED_LIST_KEYS and isinstance(value, list):
            # Layered merge: union profile list with local additions
            local_value = local_config.get(key, [])
            if isinstance(local_value, list):
                dedup_field = _DEDUP_KEY_MAP.get(key, "name")
                if key in LOCAL_WINS_LAYERED_KEYS:
                    # Local entries take precedence; server fills gaps
                    merged = _union_local_wins(value, local_value, dedup_field)
                    if merged != local_value:
                        log.info(
                            "Conflict resolved [server-wins/local-layered] key=%s "
                            "local=%d items + server_defaults=%d items → merged=%d items",
                            key,
                            len(local_value),
                            len(value),
                            len(merged),
                        )
                else:
                    merged = _union_named_lists(value, local_value, dedup_field)
                    if merged != local_value:
                        log.info(
                            "Conflict resolved [server-wins/layered] key=%s "
                            "profile=%d items + local_additions=%d items → merged=%d items",
                            key,
                            len(value),
                            len(local_value),
                            len(merged),
                        )
                resolved[key] = merged
            else:
                resolved[key] = value
        else:
            if key in local_config and local_config[key] != value:
                log.info(
                    "Conflict resolved [server-wins] key=%s server_value=%r local_value=%r",
                    key,
                    value,
                    local_config[key],
                )
            resolved[key] = value

    return resolved


def resolve_local_wins(
    server_settings: dict[str, Any],
    local_config: dict[str, Any],
    defaults: dict[str, Any],
) -> dict[str, Any]:
    """Local-wins conflict resolution.

    For keys present in both server and local where local differs from default:
        use local value (local wins).
    For keys present in server but not in local, or where local equals default:
        use server value.
    Keys present only in local (not in server) retain their local value.

    Args:
        server_settings: Settings dict from the server profile.
        local_config: Dict of current local configuration values.
        defaults: Dict of ShieldConfig default values for comparison.

    Returns:
        Resolved settings dict.
    """
    resolved: dict[str, Any] = {}

    # Start with all local keys
    for key, value in local_config.items():
        resolved[key] = value

    # Apply server settings where local hasn't been customized
    for key, server_value in server_settings.items():
        if key in local_config:
            local_value = local_config[key]
            default_value = defaults.get(key)
            if local_value != default_value:
                # Local has been customized — local wins
                log.info(
                    "Conflict resolved [local-wins] key=%s local_value=%r "
                    "(non-default, wins over server_value=%r)",
                    key,
                    local_value,
                    server_value,
                )
                resolved[key] = local_value
            else:
                # Local is at default — server wins
                if server_value != local_value:
                    log.info(
                        "Conflict resolved [local-wins] key=%s server_value=%r "
                        "(local at default=%r)",
                        key,
                        server_value,
                        local_value,
                    )
                resolved[key] = server_value
        else:
            # Key only in server, not in local — use server value
            resolved[key] = server_value

    return resolved


def resolve_merge(server_settings: dict[str, Any], local_config: dict[str, Any]) -> dict[str, Any]:
    """Merge conflict resolution with layered list merging.

    For scalar keys present in both: server value wins.
    For LAYERED_LIST_KEYS (subscriptions, brute_force_rules, custom_rules,
    log_sources, fleet_local_allow_list):
        union profile list with local additions (profile wins on key conflicts).
    For LOCAL_WINS_LAYERED_KEYS (log_sources): local entries take precedence
        on path conflicts; server entries fill gaps only.
    For other list keys: server list replaces local entirely.
    For keys present only in local (not in server): local value preserved.
    For keys present only in server (not in local): server value used.

    Args:
        server_settings: Settings dict from the server profile.
        local_config: Dict of current local configuration values.

    Returns:
        Resolved settings dict.
    """
    resolved: dict[str, Any] = {}

    # Start with all local keys (preserves local-only keys)
    for key, value in local_config.items():
        resolved[key] = value

    # Server values override for keys present in server settings
    for key, server_value in server_settings.items():
        if key in local_config:
            local_value = local_config[key]
            if key in LAYERED_LIST_KEYS and isinstance(server_value, list):
                # Layered merge: union profile list with local additions
                if isinstance(local_value, list):
                    dedup_field = _DEDUP_KEY_MAP.get(key, "name")
                    if key in LOCAL_WINS_LAYERED_KEYS:
                        # Local entries take precedence; server fills gaps
                        merged = _union_local_wins(server_value, local_value, dedup_field)
                        if merged != local_value:
                            log.info(
                                "Conflict resolved [merge/local-layered] key=%s "
                                "local=%d items + server_defaults=%d items → merged=%d items",
                                key,
                                len(local_value),
                                len(server_value),
                                len(merged),
                            )
                    else:
                        merged = _union_named_lists(server_value, local_value, dedup_field)
                        if merged != local_value:
                            log.info(
                                "Conflict resolved [merge/layered] key=%s "
                                "profile=%d items + local=%d items → merged=%d items",
                                key,
                                len(server_value),
                                len(local_value),
                                len(merged),
                            )
                    resolved[key] = merged
                else:
                    resolved[key] = server_value
            elif key in LIST_KEYS:
                # Non-layered list keys: server replaces entirely
                if local_value != server_value:
                    log.info(
                        "Conflict resolved [merge] key=%s (list) server replaces local entirely",
                        key,
                    )
                resolved[key] = server_value
            else:
                # Scalar keys: server wins
                if local_value != server_value:
                    log.info(
                        "Conflict resolved [merge] key=%s (scalar) "
                        "server_value=%r wins over local_value=%r",
                        key,
                        server_value,
                        local_value,
                    )
                resolved[key] = server_value
        else:
            # Key only in server — use server value
            resolved[key] = server_value

    return resolved
