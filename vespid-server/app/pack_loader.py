"""Rule Pack Loader — loads detection rule packs from YAML files on disk.

Packs are stored as individual YAML files in a configurable directory
(default: ``packs/`` relative to the server root). Each file defines
pack metadata (name, icon, description, prerequisite) and a list of
detection rules.

This module provides:
    - ``load_packs(packs_dir)`` — read all .yaml files and return pack dicts
    - ``get_pack_rules(packs)`` — flatten all rules for database seeding
    - ``get_pack_metadata(packs)`` — return metadata for the admin UI

Adding a new pack is as simple as dropping a .yaml file in the packs
directory. No code changes required.
"""

import hashlib
import json
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# Default packs directory: <server_root>/packs/
_DEFAULT_PACKS_DIR = Path(__file__).parent.parent / "packs"


def _norm_json(value) -> str:
    """Normalize a list/JSON-string into a compact, deterministic JSON string."""
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except (json.JSONDecodeError, TypeError):
            return value
    try:
        return json.dumps(value, separators=(",", ":"))
    except (TypeError, ValueError):
        return str(value)


def rule_content_hash(
    event_type,
    regex,
    log_sources,
    max_attempts,
    window_seconds,
    tags,
    sigma_id="",
    sigma_status="",
) -> str:
    """Stable hash of a rule's pack-owned definition.

    Covers everything the pack *ships* (definition + default policy) but NOT
    user state (``enabled``) or identity (``name``/``pack_name``). Used to
    detect when a pack ships a new version of a rule so reconcile can refresh
    rules the user hasn't modified.
    """
    payload = json.dumps(
        {
            "event_type": (event_type or "").strip(),
            "regex": regex or "",
            "log_sources": _norm_json(log_sources),
            "max_attempts": int(max_attempts),
            "window_seconds": int(window_seconds),
            "tags": _norm_json(tags if tags not in (None, "") else []),
            "sigma_id": (sigma_id or "").strip(),
            "sigma_status": (sigma_status or "").strip(),
        },
        sort_keys=True,
        separators=(",", ":"),
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def load_packs(packs_dir: str | None = None) -> list[dict]:
    """Load all rule pack YAML files from the given directory.

    Args:
        packs_dir: Path to the packs directory. Defaults to ``<server_root>/packs/``.

    Returns:
        A list of pack dicts, each containing:
            - pack_name (str)
            - display_name (str)
            - icon (str)
            - description (str)
            - prerequisite (str)
            - rules (list of rule dicts)
    """
    try:
        import yaml
    except ImportError:
        logger.error("PyYAML is required to load rule packs. Install it with: pip install pyyaml")
        return []

    directory = Path(packs_dir) if packs_dir else _DEFAULT_PACKS_DIR

    if not directory.exists():
        logger.warning("Packs directory does not exist: %s", directory)
        return []

    packs = []
    for filepath in sorted(directory.glob("*.yaml")):
        # Skip macOS AppleDouble metadata companions (._file.yaml) and other
        # junk that can appear when the tree is copied through non-HFS media.
        if filepath.name.startswith("._"):
            continue
        try:
            raw = filepath.read_text(encoding="utf-8")
            data = yaml.safe_load(raw)
        except Exception as exc:
            logger.error("Failed to load pack file %s: %s", filepath.name, exc)
            continue

        if not isinstance(data, dict):
            logger.error("Pack file %s did not produce a mapping, skipping", filepath.name)
            continue

        # Validate required fields
        pack_name = data.get("pack_name", "")
        if not pack_name:
            logger.error("Pack file %s is missing 'pack_name', skipping", filepath.name)
            continue

        rules = data.get("rules", [])
        if not isinstance(rules, list):
            logger.error("Pack file %s has invalid 'rules' field, skipping", filepath.name)
            continue

        # Normalize rules
        normalized_rules = []
        for rule in rules:
            if not isinstance(rule, dict):
                continue
            # Ensure log_sources is a JSON string for DB storage
            log_sources = rule.get("log_sources", ["*"])
            if isinstance(log_sources, list):
                log_sources_str = json.dumps(log_sources)
            else:
                log_sources_str = str(log_sources)

            # Normalize tags to a JSON string for DB storage
            tags = rule.get("tags", [])
            if isinstance(tags, list):
                tags_str = json.dumps(tags)
            elif isinstance(tags, str):
                tags_str = tags  # Already a JSON string
            else:
                tags_str = "[]"

            normalized_rules.append(
                {
                    "name": rule.get("name", ""),
                    "event_type": rule.get("event_type", ""),
                    "regex": rule.get("regex", ""),
                    "log_sources": log_sources_str,
                    "max_attempts": int(rule.get("max_attempts", 3)),
                    "window_seconds": int(rule.get("window_seconds", 3600)),
                    "enabled": 0,
                    "is_template": 1,
                    "pack_name": pack_name,
                    "tags": tags_str,
                    "sigma_id": str(rule.get("sigma_id", "")),
                    "sigma_status": str(rule.get("sigma_status", "")),
                    "content_hash": rule_content_hash(
                        rule.get("event_type", ""),
                        rule.get("regex", ""),
                        log_sources_str,
                        int(rule.get("max_attempts", 3)),
                        int(rule.get("window_seconds", 3600)),
                        tags_str,
                        str(rule.get("sigma_id", "")),
                        str(rule.get("sigma_status", "")),
                    ),
                }
            )

        packs.append(
            {
                "pack_name": pack_name,
                "display_name": data.get("display_name", pack_name),
                "icon": data.get("icon", "📦"),
                "description": data.get("description", "").strip(),
                "prerequisite": data.get("prerequisite", "").strip(),
                "rules": normalized_rules,
            }
        )

    logger.info("Loaded %d rule pack(s) from %s", len(packs), directory)
    return packs


def get_pack_rules(packs: list[dict]) -> list[dict]:
    """Flatten all rules from all packs into a single list for DB seeding.

    Args:
        packs: List of pack dicts as returned by ``load_packs()``.

    Returns:
        A flat list of rule dicts ready for database insertion.
    """
    rules = []
    for pack in packs:
        rules.extend(pack.get("rules", []))
    return rules


def get_pack_metadata(packs: list[dict]) -> list[dict]:
    """Return pack metadata (without rules) for the admin UI registry.

    Args:
        packs: List of pack dicts as returned by ``load_packs()``.

    Returns:
        A list of pack metadata dicts (pack_name, display_name, icon,
        description, prerequisite).
    """
    return [
        {
            "pack_name": p["pack_name"],
            "display_name": p["display_name"],
            "icon": p["icon"],
            "description": p["description"],
            "prerequisite": p["prerequisite"],
            "rule_count": len(p.get("rules", [])),
        }
        for p in packs
    ]


# ---------------------------------------------------------------------------
# Shared, refreshable pack cache
# ---------------------------------------------------------------------------
# Packs are read from disk lazily and cached process-wide so the admin UI and
# API don't re-parse YAML on every request. ``reload_packs()`` re-reads the
# YAML from disk so an admin can pick up edited packs without a server restart.

_pack_cache: dict = {"packs": None, "metadata": None}


def get_cached_packs(force: bool = False) -> list[dict]:
    """Return the cached list of loaded packs, loading from disk if needed.

    Args:
        force: When True, re-read all pack YAML from disk even if cached.
    """
    if force or _pack_cache["packs"] is None:
        packs = load_packs()
        _pack_cache["packs"] = packs
        _pack_cache["metadata"] = get_pack_metadata(packs)
    return _pack_cache["packs"]


def get_cached_pack_metadata(force: bool = False) -> list[dict]:
    """Return cached pack metadata (no rules), loading from disk if needed."""
    get_cached_packs(force=force)
    return _pack_cache["metadata"]


def reload_packs() -> list[dict]:
    """Force a re-read of all pack YAML from disk and refresh the cache.

    Returns the freshly loaded list of packs.
    """
    return get_cached_packs(force=True)
