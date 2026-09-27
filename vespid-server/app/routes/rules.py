"""Rules API blueprint — detection rule management and distribution.

Endpoints:
    GET    /api/v1/rules                    — List all rules (paginated, admin)
    POST   /api/v1/rules/brute-force        — Create brute force rule (admin)
    POST   /api/v1/rules/custom             — Create custom rule (admin)
    PUT    /api/v1/rules/brute-force/<id>   — Update brute force rule (admin)
    PUT    /api/v1/rules/custom/<id>        — Update custom rule (admin)
    DELETE /api/v1/rules/brute-force/<id>   — Soft-delete brute force rule (admin)
    DELETE /api/v1/rules/custom/<id>        — Soft-delete custom rule (admin)
    GET    /api/v1/rules/distribution       — Get enabled rules for nodes (Bearer auth)
"""

import hashlib
import json
import logging
import re

from flask import current_app, jsonify, request
from flask_login import current_user
from flask_openapi3 import APIBlueprint
from flask_openapi3.models import Tag

from app.config_resolution import resolve_effective_profile
from app.decorators import require_role
from app.models import (
    _utcnow_iso,
    get_detection_rules_revision,
    get_enabled_detection_rules,
    get_request_db,
    increment_detection_rules_revision,
    list_detection_rules,
    record_audit,
)
from app.pack_loader import get_cached_pack_metadata, reload_packs
from app.rate_limit import limiter
from app.routes.auth import authenticate_bearer_token

logger = logging.getLogger(__name__)

rules_bp = APIBlueprint(
    "rules",
    __name__,
    url_prefix="/api/v1/rules",
    abp_tags=[Tag(name="Rules", description="Detection rule management")],
    abp_security=[{"BearerAuth": []}, {"SessionAuth": []}],
)


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

# Validation helpers
# ---------------------------------------------------------------------------


def _validate_brute_force_fields(data: dict) -> list:
    """Validate brute force rule fields. Returns list of error strings."""
    errors = []
    name = data.get("name", "")
    if not name or not isinstance(name, str) or len(name.strip()) == 0:
        errors.append("name is required and must be a non-empty string")
    elif len(name) > 64:
        errors.append("name must be at most 64 characters")

    event_type = data.get("event_type", "")
    if not event_type or not isinstance(event_type, str) or len(event_type.strip()) == 0:
        errors.append("event_type is required and must be a non-empty string")
    elif len(event_type) > 64:
        errors.append("event_type must be at most 64 characters")

    max_attempts = data.get("max_attempts")
    if max_attempts is None:
        errors.append("max_attempts is required")
    else:
        try:
            max_attempts = int(max_attempts)
            if max_attempts < 1 or max_attempts > 10000:
                errors.append("max_attempts must be between 1 and 10000")
        except (TypeError, ValueError):
            errors.append("max_attempts must be a positive integer")

    window_seconds = data.get("window_seconds")
    if window_seconds is None:
        errors.append("window_seconds is required")
    else:
        try:
            window_seconds = int(window_seconds)
            if window_seconds < 1 or window_seconds > 604800:
                errors.append("window_seconds must be between 1 and 604800")
        except (TypeError, ValueError):
            errors.append("window_seconds must be a positive integer")

    parser = data.get("parser", "")
    if not parser or not isinstance(parser, str) or len(parser.strip()) == 0:
        errors.append("parser is required and must be a non-empty string")
    elif len(parser) > 64:
        errors.append("parser must be at most 64 characters")

    return errors


def _validate_custom_fields(data: dict) -> list:
    """Validate custom rule fields. Returns list of error strings."""
    errors = []
    name = data.get("name", "")
    if not name or not isinstance(name, str) or len(name.strip()) == 0:
        errors.append("name is required and must be a non-empty string")
    elif len(name) > 64:
        errors.append("name must be at most 64 characters")

    event_type = data.get("event_type", "")
    if not event_type or not isinstance(event_type, str) or len(event_type.strip()) == 0:
        errors.append("event_type is required and must be a non-empty string")
    elif len(event_type) > 64:
        errors.append("event_type must be at most 64 characters")

    max_attempts = data.get("max_attempts")
    if max_attempts is None:
        errors.append("max_attempts is required")
    else:
        try:
            max_attempts = int(max_attempts)
            if max_attempts < 1 or max_attempts > 10000:
                errors.append("max_attempts must be between 1 and 10000")
        except (TypeError, ValueError):
            errors.append("max_attempts must be a positive integer")

    window_seconds = data.get("window_seconds")
    if window_seconds is None:
        errors.append("window_seconds is required")
    else:
        try:
            window_seconds = int(window_seconds)
            if window_seconds < 1 or window_seconds > 604800:
                errors.append("window_seconds must be between 1 and 604800")
        except (TypeError, ValueError):
            errors.append("window_seconds must be a positive integer")

    regex_str = data.get("regex", "")
    if not regex_str or not isinstance(regex_str, str) or len(regex_str.strip()) == 0:
        errors.append("regex is required and must be a non-empty string")
    elif len(regex_str) > 1024:
        errors.append("regex must be at most 1024 characters")
    else:
        try:
            compiled = re.compile(regex_str)
            if "ip" not in compiled.groupindex:
                errors.append("regex must contain a (?P<ip>...) named group")
        except re.error as exc:
            errors.append(f"regex does not compile: {exc}")

    log_sources = data.get("log_sources")
    if log_sources is not None:
        if isinstance(log_sources, str):
            try:
                log_sources = json.loads(log_sources)
            except (json.JSONDecodeError, TypeError):
                errors.append("log_sources must be a JSON array of strings")
                log_sources = None
        if log_sources is not None:
            if not isinstance(log_sources, list):
                errors.append("log_sources must be an array of strings")
            elif len(log_sources) > 20:
                errors.append("log_sources must have at most 20 entries")
            elif not all(isinstance(s, str) for s in log_sources):
                errors.append("log_sources entries must be strings")

    return errors


def _normalize_tags(tags: list | str | None) -> str:
    """Normalize tags to a JSON string for DB storage."""
    if tags is None:
        return "[]"
    if isinstance(tags, str):
        try:
            parsed = json.loads(tags)
            return json.dumps(parsed if isinstance(parsed, list) else [tags])
        except (json.JSONDecodeError, TypeError):
            return "[]"
    if isinstance(tags, list):
        return json.dumps(tags)
    return "[]"


def _deserialize_tags(raw: str | list | None) -> list[str]:
    """Deserialize tags from a JSON string or list to a list of strings."""
    if raw is None:
        return []
    if isinstance(raw, list):
        return raw
    if isinstance(raw, str):
        try:
            parsed = json.loads(raw)
            return parsed if isinstance(parsed, list) else []
        except (json.JSONDecodeError, TypeError):
            return []
    return []


# ---------------------------------------------------------------------------
# Node active parsers resolution
# ---------------------------------------------------------------------------


def _get_node_active_parsers(db, node_id: str) -> tuple[list[str] | None, str]:
    """Resolve active parsers for a node.

    Returns (active_parsers, mode) where mode is "explicit", "auto", or "all".
    - "explicit": only packs in detection_packs list
    - "auto": filter by parser match
    - "all": no filtering (legacy/unknown node)
    """
    # 1. Check config profile for explicit assignment
    profile = resolve_effective_profile(db, node_id)
    if profile:
        settings = (
            json.loads(profile["settings"])
            if isinstance(profile["settings"], str)
            else profile["settings"]
        )
        mode = settings.get("detection_pack_mode", "auto")
        if mode == "explicit":
            return settings.get("detection_packs", []), "explicit"
        # Auto mode on managed node: derive from profile's log_sources
        log_sources = settings.get("log_sources", [])
        if log_sources:
            parsers = list(set(ls.get("parser", "") for ls in log_sources if ls.get("parser")))
            # Merge "auditd" if the profile has auditd enabled — auditd is
            # configured via a separate config block, not log_sources, so it
            # won't appear in the profile's log_sources list.
            auditd_cfg = settings.get("auditd", {})
            if isinstance(auditd_cfg, dict) and auditd_cfg.get("enabled"):
                parsers = list(set(parsers) | {"auditd"})
            else:
                # Fall back to heartbeat-reported active_parsers for auditd
                node = db.execute(
                    "SELECT last_host_info FROM nodes WHERE node_id = ?", (node_id,)
                ).fetchone()
                if node:
                    try:
                        hi = (
                            json.loads(node["last_host_info"])
                            if isinstance(node["last_host_info"], str)
                            else node["last_host_info"]
                        )
                        heartbeat_parsers = hi.get("active_parsers", []) if hi else []
                        if isinstance(heartbeat_parsers, list) and "auditd" in heartbeat_parsers:
                            parsers = list(set(parsers) | {"auditd"})
                    except (json.JSONDecodeError, TypeError):
                        pass
            if parsers:
                return parsers, "auto"

    # 2. Fall back to heartbeat-reported active_parsers
    node = db.execute("SELECT last_host_info FROM nodes WHERE node_id = ?", (node_id,)).fetchone()
    if node:
        host_info = (
            json.loads(node["last_host_info"])
            if isinstance(node["last_host_info"], str)
            else node["last_host_info"]
        )
        active_parsers = host_info.get("active_parsers")
        if active_parsers and isinstance(active_parsers, list) and len(active_parsers) > 0:
            return active_parsers, "auto"

    # 3. No info available — return all
    return None, "all"


def _log_sources_match(rule_log_sources: list[str], active_parsers: list[str]) -> bool:
    """Check if a rule's log_sources overlap with the node's active parsers.

    Returns True if there's any overlap or if the rule has a wildcard ["*"].
    """
    if "*" in rule_log_sources:
        return True
    return bool(set(rule_log_sources) & set(active_parsers))


def _filter_rules_for_node(
    rules: dict,
    active_parsers: list[str] | None,
    mode: str,
    explicit_packs: list[str] | None = None,
) -> dict:
    """Filter rules based on node's active parsers and mode.

    Args:
        rules: Dict with "brute_force_rules" and "custom_rules" lists.
        active_parsers: List of parser names the node monitors, or None.
        mode: One of "all", "auto", or "explicit".
        explicit_packs: List of pack names when mode is "explicit".

    Returns:
        Filtered dict with the same structure as input.
    """
    if mode == "all" or active_parsers is None:
        return rules  # No filtering

    if mode == "explicit" and explicit_packs is not None:
        # Only include rules from explicitly assigned packs + non-pack rules matching parsers
        filtered_bf = [r for r in rules["brute_force_rules"] if r["parser"] in active_parsers]
        filtered_custom = [
            r
            for r in rules["custom_rules"]
            if r.get("pack_name", "") in explicit_packs
            or (
                not r.get("pack_name")
                and _log_sources_match(r.get("log_sources", ["*"]), active_parsers)
            )
        ]
    else:
        # Auto mode: filter by parser/log_sources match
        filtered_bf = [r for r in rules["brute_force_rules"] if r["parser"] in active_parsers]
        filtered_custom = [
            r
            for r in rules["custom_rules"]
            if _log_sources_match(r.get("log_sources", ["*"]), active_parsers)
        ]

    return {"brute_force_rules": filtered_bf, "custom_rules": filtered_custom}


# ---------------------------------------------------------------------------
# Bearer token auth (reused from fleet.py pattern)
# ---------------------------------------------------------------------------


_authenticate_bearer_token = authenticate_bearer_token


# ---------------------------------------------------------------------------
# CRUD Endpoints (admin, session auth)
# ---------------------------------------------------------------------------


@rules_bp.get(
    "",
    summary="List detection rules",
    description="List all detection rules with pagination. Admin only.",
)
@require_role("admin")
def list_rules():
    """List all detection rules with pagination."""
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)

    db = get_request_db()
    result = list_detection_rules(db, page=page, per_page=per_page)
    revision = get_detection_rules_revision(db)

    result["revision"] = revision
    return jsonify(result), 200


@rules_bp.post(
    "/brute-force",
    summary="Create brute force rule",
    description="Create a new brute force detection rule. Admin only.",
)
@require_role("admin")
def create_brute_force_rule():
    """Create a new brute force detection rule."""
    data = request.get_json(silent=True) or {}
    errors = _validate_brute_force_fields(data)
    if errors:
        return jsonify({"error": "validation_error", "errors": errors}), 422

    db = get_request_db()
    # Check uniqueness
    existing = db.execute(
        "SELECT id FROM detection_rules_brute_force WHERE name = ?",
        (data["name"].strip(),),
    ).fetchone()
    if existing:
        return jsonify(
            {"error": "conflict", "message": f"Rule name '{data['name']}' already exists"}
        ), 409

    cursor = db.execute(
        "INSERT INTO detection_rules_brute_force "
        "(name, event_type, max_attempts, window_seconds, parser, enabled, created_by) "
        "VALUES (?, ?, ?, ?, ?, ?, ?)",
        (
            data["name"].strip(),
            data["event_type"].strip(),
            int(data["max_attempts"]),
            int(data["window_seconds"]),
            data["parser"].strip(),
            1 if data.get("enabled", True) else 0,
            current_user.username if current_user.is_authenticated else "system",
        ),
    )
    increment_detection_rules_revision(db)

    rule = db.execute(
        "SELECT * FROM detection_rules_brute_force WHERE id = ?",
        (cursor.lastrowid,),
    ).fetchone()

    record_audit(
        db,
        actor=current_user.username,
        actor_ip=request.remote_addr,
        action_type="rule_created",
        target=data["name"].strip(),
        details={"rule_type": "brute_force", "rule_id": cursor.lastrowid},
    )

    return jsonify(dict(rule)), 201


@rules_bp.post(
    "/custom",
    summary="Create custom rule",
    description="Create a new custom regex detection rule. Admin only.",
)
@require_role("admin")
def create_custom_rule():
    """Create a new custom regex detection rule."""
    data = request.get_json(silent=True) or {}
    errors = _validate_custom_fields(data)
    if errors:
        return jsonify({"error": "validation_error", "errors": errors}), 422

    log_sources = data.get("log_sources", ["*"])
    if isinstance(log_sources, str):
        try:
            log_sources = json.loads(log_sources)
        except (json.JSONDecodeError, TypeError):
            log_sources = ["*"]

    db = get_request_db()
    existing = db.execute(
        "SELECT id FROM detection_rules_custom WHERE name = ?",
        (data["name"].strip(),),
    ).fetchone()
    if existing:
        return jsonify(
            {"error": "conflict", "message": f"Rule name '{data['name']}' already exists"}
        ), 409

    cursor = db.execute(
        "INSERT INTO detection_rules_custom "
        "(name, event_type, regex, log_sources, max_attempts, window_seconds, enabled, created_by, tags, sigma_id, sigma_status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            data["name"].strip(),
            data["event_type"].strip(),
            data["regex"],
            json.dumps(log_sources),
            int(data["max_attempts"]),
            int(data["window_seconds"]),
            1 if data.get("enabled", True) else 0,
            current_user.username if current_user.is_authenticated else "system",
            _normalize_tags(data.get("tags", [])),
            data.get("sigma_id", "").strip(),
            data.get("sigma_status", "").strip(),
        ),
    )
    increment_detection_rules_revision(db)

    rule = db.execute(
        "SELECT * FROM detection_rules_custom WHERE id = ?",
        (cursor.lastrowid,),
    ).fetchone()

    record_audit(
        db,
        actor=current_user.username,
        actor_ip=request.remote_addr,
        action_type="rule_created",
        target=data["name"].strip(),
        details={"rule_type": "custom", "rule_id": cursor.lastrowid},
    )

    return jsonify(dict(rule)), 201


@rules_bp.put(
    "/brute-force/<int:rule_id>",
    summary="Update brute force rule",
    description="Update an existing brute force rule. Admin only.",
)
@require_role("admin")
def update_brute_force_rule(rule_id):
    """Update an existing brute force rule."""
    data = request.get_json(silent=True) or {}

    db = get_request_db()
    existing = db.execute(
        "SELECT * FROM detection_rules_brute_force WHERE id = ?", (rule_id,)
    ).fetchone()
    if not existing:
        return jsonify({"error": "not_found", "message": "Rule not found"}), 404

    # Merge with existing values for partial updates
    merged = {
        "name": data.get("name", existing["name"]),
        "event_type": data.get("event_type", existing["event_type"]),
        "max_attempts": data.get("max_attempts", existing["max_attempts"]),
        "window_seconds": data.get("window_seconds", existing["window_seconds"]),
        "parser": data.get("parser", existing["parser"]),
    }
    errors = _validate_brute_force_fields(merged)
    if errors:
        return jsonify({"error": "validation_error", "errors": errors}), 422

    # Check name uniqueness if changed
    if merged["name"].strip() != existing["name"]:
        dup = db.execute(
            "SELECT id FROM detection_rules_brute_force WHERE name = ? AND id != ?",
            (merged["name"].strip(), rule_id),
        ).fetchone()
        if dup:
            return jsonify(
                {"error": "conflict", "message": f"Rule name '{merged['name']}' already exists"}
            ), 409

    enabled = data.get("enabled", existing["enabled"])
    if isinstance(enabled, bool):
        enabled = 1 if enabled else 0

    db.execute(
        "UPDATE detection_rules_brute_force SET "
        "name = ?, event_type = ?, max_attempts = ?, window_seconds = ?, "
        "parser = ?, enabled = ?, updated_at = ? "
        "WHERE id = ?",
        (
            merged["name"].strip(),
            merged["event_type"].strip(),
            int(merged["max_attempts"]),
            int(merged["window_seconds"]),
            merged["parser"].strip(),
            enabled,
            _utcnow_iso(),
            rule_id,
        ),
    )
    increment_detection_rules_revision(db)

    updated = db.execute(
        "SELECT * FROM detection_rules_brute_force WHERE id = ?", (rule_id,)
    ).fetchone()

    record_audit(
        db,
        actor=current_user.username,
        actor_ip=request.remote_addr,
        action_type="rule_updated",
        target=merged["name"].strip(),
        details={"rule_type": "brute_force", "rule_id": rule_id},
    )

    return jsonify(dict(updated)), 200


@rules_bp.put(
    "/custom/<int:rule_id>",
    summary="Update custom rule",
    description="Update an existing custom regex rule. Admin only.",
)
@require_role("admin")
def update_custom_rule(rule_id):
    """Update an existing custom regex rule."""
    data = request.get_json(silent=True) or {}

    db = get_request_db()
    existing = db.execute(
        "SELECT * FROM detection_rules_custom WHERE id = ?", (rule_id,)
    ).fetchone()
    if not existing:
        return jsonify({"error": "not_found", "message": "Rule not found"}), 404

    # Parse existing log_sources
    existing_log_sources = existing["log_sources"]
    if isinstance(existing_log_sources, str):
        try:
            existing_log_sources = json.loads(existing_log_sources)
        except (json.JSONDecodeError, TypeError):
            existing_log_sources = ["*"]

    merged = {
        "name": data.get("name", existing["name"]),
        "event_type": data.get("event_type", existing["event_type"]),
        "max_attempts": data.get("max_attempts", existing["max_attempts"]),
        "window_seconds": data.get("window_seconds", existing["window_seconds"]),
        "regex": data.get("regex", existing["regex"]),
        "log_sources": data.get("log_sources", existing_log_sources),
    }
    errors = _validate_custom_fields(merged)
    if errors:
        return jsonify({"error": "validation_error", "errors": errors}), 422

    # Check name uniqueness if changed
    if merged["name"].strip() != existing["name"]:
        dup = db.execute(
            "SELECT id FROM detection_rules_custom WHERE name = ? AND id != ?",
            (merged["name"].strip(), rule_id),
        ).fetchone()
        if dup:
            return jsonify(
                {"error": "conflict", "message": f"Rule name '{merged['name']}' already exists"}
            ), 409

    log_sources = merged["log_sources"]
    if isinstance(log_sources, list):
        log_sources = json.dumps(log_sources)

    enabled = data.get("enabled", existing["enabled"])
    if isinstance(enabled, bool):
        enabled = 1 if enabled else 0

    tags = _normalize_tags(data.get("tags", _deserialize_tags(existing.get("tags", "[]"))))
    sigma_id = data.get("sigma_id", existing.get("sigma_id", ""))
    sigma_status = data.get("sigma_status", existing.get("sigma_status", ""))

    db.execute(
        "UPDATE detection_rules_custom SET "
        "name = ?, event_type = ?, regex = ?, log_sources = ?, "
        "max_attempts = ?, window_seconds = ?, enabled = ?, "
        "tags = ?, sigma_id = ?, sigma_status = ?, "
        "user_modified = 1, "
        "updated_at = ? "
        "WHERE id = ?",
        (
            merged["name"].strip(),
            merged["event_type"].strip(),
            merged["regex"],
            log_sources,
            int(merged["max_attempts"]),
            int(merged["window_seconds"]),
            enabled,
            tags,
            sigma_id.strip(),
            sigma_status.strip(),
            _utcnow_iso(),
            rule_id,
        ),
    )
    increment_detection_rules_revision(db)

    updated = db.execute("SELECT * FROM detection_rules_custom WHERE id = ?", (rule_id,)).fetchone()

    record_audit(
        db,
        actor=current_user.username,
        actor_ip=request.remote_addr,
        action_type="rule_updated",
        target=merged["name"].strip(),
        details={"rule_type": "custom", "rule_id": rule_id},
    )

    return jsonify(dict(updated)), 200


@rules_bp.delete(
    "/brute-force/<int:rule_id>",
    summary="Delete brute force rule",
    description="Soft-delete a brute force rule (set enabled=0). Admin only.",
)
@require_role("admin")
def delete_brute_force_rule(rule_id):
    """Soft-delete a brute force rule (set enabled=0)."""
    db = get_request_db()
    existing = db.execute(
        "SELECT * FROM detection_rules_brute_force WHERE id = ?", (rule_id,)
    ).fetchone()
    if not existing:
        return jsonify({"error": "not_found", "message": "Rule not found"}), 404

    db.execute(
        "UPDATE detection_rules_brute_force SET enabled = 0, updated_at = ? WHERE id = ?",
        (_utcnow_iso(), rule_id),
    )
    increment_detection_rules_revision(db)

    record_audit(
        db,
        actor=current_user.username,
        actor_ip=request.remote_addr,
        action_type="rule_deleted",
        target=existing["name"],
        details={"rule_type": "brute_force", "rule_id": rule_id},
    )

    return jsonify({"ok": True, "message": f"Rule '{existing['name']}' disabled"}), 200


@rules_bp.delete(
    "/custom/<int:rule_id>",
    summary="Delete custom rule",
    description="Soft-delete a custom rule (set enabled=0). Admin only.",
)
@require_role("admin")
def delete_custom_rule(rule_id):
    """Soft-delete a custom rule (set enabled=0)."""
    db = get_request_db()
    existing = db.execute(
        "SELECT * FROM detection_rules_custom WHERE id = ?", (rule_id,)
    ).fetchone()
    if not existing:
        return jsonify({"error": "not_found", "message": "Rule not found"}), 404

    db.execute(
        "UPDATE detection_rules_custom SET enabled = 0, updated_at = ? WHERE id = ?",
        (_utcnow_iso(), rule_id),
    )
    increment_detection_rules_revision(db)

    record_audit(
        db,
        actor=current_user.username,
        actor_ip=request.remote_addr,
        action_type="rule_deleted",
        target=existing["name"],
        details={"rule_type": "custom", "rule_id": rule_id},
    )

    return jsonify({"ok": True, "message": f"Rule '{existing['name']}' disabled"}), 200


# ---------------------------------------------------------------------------
# Correlation Rule CRUD Endpoints (admin, session auth)
# ---------------------------------------------------------------------------


def _validate_correlation_fields(data: dict) -> list:
    """Validate correlation rule fields. Returns list of error strings."""
    errors = []
    name = data.get("name", "")
    if not name or not isinstance(name, str) or len(name.strip()) == 0:
        errors.append("name is required and must be a non-empty string")
    elif len(name) > 64:
        errors.append("name must be at most 64 characters")

    event_type = data.get("event_type", "")
    if not event_type or not isinstance(event_type, str) or len(event_type.strip()) == 0:
        errors.append("event_type is required and must be a non-empty string")
    elif len(event_type) > 64:
        errors.append("event_type must be at most 64 characters")

    min_categories = data.get("min_categories")
    if min_categories is None:
        errors.append("min_categories is required")
    else:
        try:
            min_categories = int(min_categories)
            if min_categories < 2 or min_categories > 20:
                errors.append("min_categories must be between 2 and 20")
        except (TypeError, ValueError):
            errors.append("min_categories must be a positive integer")

    window_seconds = data.get("window_seconds")
    if window_seconds is None:
        errors.append("window_seconds is required")
    else:
        try:
            window_seconds = int(window_seconds)
            if window_seconds < 60 or window_seconds > 86400:
                errors.append("window_seconds must be between 60 and 86400")
        except (TypeError, ValueError):
            errors.append("window_seconds must be a positive integer")

    return errors


@rules_bp.post(
    "/correlation",
    summary="Create correlation rule",
    description="Create a new correlation detection rule. Admin only.",
)
@require_role("admin")
def create_correlation_rule():
    """Create a new correlation detection rule."""
    data = request.get_json(silent=True) or {}
    errors = _validate_correlation_fields(data)
    if errors:
        return jsonify({"error": "validation_error", "errors": errors}), 422

    db = get_request_db()
    existing = db.execute(
        "SELECT id FROM detection_rules_correlation WHERE name = ?",
        (data["name"].strip(),),
    ).fetchone()
    if existing:
        return jsonify(
            {"error": "conflict", "message": f"Rule name '{data['name']}' already exists"}
        ), 409

    cursor = db.execute(
        "INSERT INTO detection_rules_correlation "
        "(name, event_type, min_categories, window_seconds, enabled, created_by) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (
            data["name"].strip(),
            data["event_type"].strip(),
            int(data["min_categories"]),
            int(data["window_seconds"]),
            1 if data.get("enabled", True) else 0,
            current_user.username if current_user.is_authenticated else "system",
        ),
    )
    increment_detection_rules_revision(db)

    rule = db.execute(
        "SELECT * FROM detection_rules_correlation WHERE id = ?",
        (cursor.lastrowid,),
    ).fetchone()

    record_audit(
        db,
        actor=current_user.username,
        actor_ip=request.remote_addr,
        action_type="rule_created",
        target=data["name"].strip(),
        details={"rule_type": "correlation", "rule_id": cursor.lastrowid},
    )

    return jsonify(dict(rule)), 201


@rules_bp.put(
    "/correlation/<int:rule_id>",
    summary="Update correlation rule",
    description="Update an existing correlation rule. Admin only.",
)
@require_role("admin")
def update_correlation_rule(rule_id):
    """Update an existing correlation rule."""
    data = request.get_json(silent=True) or {}

    db = get_request_db()
    existing = db.execute(
        "SELECT * FROM detection_rules_correlation WHERE id = ?", (rule_id,)
    ).fetchone()
    if not existing:
        return jsonify({"error": "not_found", "message": "Rule not found"}), 404

    merged = {
        "name": data.get("name", existing["name"]),
        "event_type": data.get("event_type", existing["event_type"]),
        "min_categories": data.get("min_categories", existing["min_categories"]),
        "window_seconds": data.get("window_seconds", existing["window_seconds"]),
    }
    errors = _validate_correlation_fields(merged)
    if errors:
        return jsonify({"error": "validation_error", "errors": errors}), 422

    if merged["name"].strip() != existing["name"]:
        dup = db.execute(
            "SELECT id FROM detection_rules_correlation WHERE name = ? AND id != ?",
            (merged["name"].strip(), rule_id),
        ).fetchone()
        if dup:
            return jsonify(
                {"error": "conflict", "message": f"Rule name '{merged['name']}' already exists"}
            ), 409

    enabled = data.get("enabled", existing["enabled"])
    if isinstance(enabled, bool):
        enabled = 1 if enabled else 0

    db.execute(
        "UPDATE detection_rules_correlation SET "
        "name = ?, event_type = ?, min_categories = ?, window_seconds = ?, "
        "enabled = ?, updated_at = ? "
        "WHERE id = ?",
        (
            merged["name"].strip(),
            merged["event_type"].strip(),
            int(merged["min_categories"]),
            int(merged["window_seconds"]),
            enabled,
            _utcnow_iso(),
            rule_id,
        ),
    )
    increment_detection_rules_revision(db)

    updated = db.execute(
        "SELECT * FROM detection_rules_correlation WHERE id = ?", (rule_id,)
    ).fetchone()

    record_audit(
        db,
        actor=current_user.username,
        actor_ip=request.remote_addr,
        action_type="rule_updated",
        target=merged["name"].strip(),
        details={"rule_type": "correlation", "rule_id": rule_id},
    )

    return jsonify(dict(updated)), 200


@rules_bp.delete(
    "/correlation/<int:rule_id>",
    summary="Delete correlation rule",
    description="Soft-delete a correlation rule (set enabled=0). Admin only.",
)
@require_role("admin")
def delete_correlation_rule(rule_id):
    """Soft-delete a correlation rule (set enabled=0)."""
    db = get_request_db()
    existing = db.execute(
        "SELECT * FROM detection_rules_correlation WHERE id = ?", (rule_id,)
    ).fetchone()
    if not existing:
        return jsonify({"error": "not_found", "message": "Rule not found"}), 404

    db.execute(
        "UPDATE detection_rules_correlation SET enabled = 0, updated_at = ? WHERE id = ?",
        (_utcnow_iso(), rule_id),
    )
    increment_detection_rules_revision(db)

    record_audit(
        db,
        actor=current_user.username,
        actor_ip=request.remote_addr,
        action_type="rule_deleted",
        target=existing["name"],
        details={"rule_type": "correlation", "rule_id": rule_id},
    )

    return jsonify({"ok": True, "message": f"Rule '{existing['name']}' disabled"}), 200


# ---------------------------------------------------------------------------
# Pack listing endpoint
# ---------------------------------------------------------------------------


@rules_bp.get(
    "/packs",
    summary="List rule packs",
    description="List all available rule packs with metadata. Admin only.",
)
@require_role("admin")
def list_packs():
    """List all available rule packs with metadata."""
    return jsonify({"packs": get_cached_pack_metadata()}), 200


@rules_bp.post(
    "/packs/reload",
    summary="Reload rule packs from disk",
    description=(
        "Re-read all rule pack YAML files from disk and reconcile them into the "
        "database without a server restart. New rules are inserted (disabled), "
        "pristine rules whose shipped definition changed are refreshed (enabled "
        "state preserved), and user-modified rules are left untouched. Bumps the "
        "detection rules revision so agents pick up changes on their next poll. "
        "Admin only."
    ),
)
@require_role("admin")
def reload_rule_packs():
    """Reload packs from disk and reconcile into the database (no restart)."""
    from app.models.detection_rules import _seed_apache_attack_templates

    db = get_request_db()
    db_type = current_app.config.get("DATABASE_TYPE", "sqlite")

    rev_before = get_detection_rules_revision(db)
    packs = reload_packs()
    _seed_apache_attack_templates(db, db_type)
    rev_after = get_detection_rules_revision(db)
    changed = rev_after != rev_before

    record_audit(
        db,
        actor=current_user.username,
        actor_ip=request.remote_addr,
        action_type="packs_reloaded",
        target="*",
        details={
            "pack_count": len(packs),
            "revision_before": rev_before,
            "revision_after": rev_after,
            "changed": changed,
        },
    )

    return (
        jsonify(
            {
                "ok": True,
                "changed": changed,
                "pack_count": len(packs),
                "revision": rev_after,
                "message": (
                    "Packs reloaded; rules refreshed and revision bumped."
                    if changed
                    else "Packs reloaded; no rule changes detected."
                ),
            }
        ),
        200,
    )


# ---------------------------------------------------------------------------
# Template Pack Endpoints (admin, session auth)
# ---------------------------------------------------------------------------


@rules_bp.get(
    "/templates/<pack_name>",
    summary="List pack templates",
    description="List all template rules in a given pack with their enabled status. Admin only.",
)
@require_role("admin")
def list_pack_templates(pack_name):
    """List all template rules in a given pack with their enabled status."""
    db = get_request_db()
    rows = db.execute(
        "SELECT * FROM detection_rules_custom WHERE is_template = 1 "
        "AND pack_name = ? ORDER BY name",
        (pack_name,),
    ).fetchall()

    if not rows:
        return jsonify({"error": "not_found", "message": f"No pack named '{pack_name}'"}), 404

    return jsonify({"pack_name": pack_name, "templates": [dict(r) for r in rows]}), 200


@rules_bp.post(
    "/templates/<pack_name>/enable-all",
    summary="Enable all pack templates",
    description="Enable all template rules in a pack at once. Admin only.",
)
@require_role("admin")
def enable_all_pack_templates(pack_name):
    """Enable all template rules in a pack at once."""
    db = get_request_db()
    count = db.execute(
        "SELECT COUNT(*) FROM detection_rules_custom WHERE is_template = 1 AND pack_name = ?",
        (pack_name,),
    ).fetchone()[0]
    if count == 0:
        return jsonify({"error": "not_found", "message": f"No pack named '{pack_name}'"}), 404

    db.execute(
        "UPDATE detection_rules_custom SET enabled = 1, "
        "updated_at = ? "
        "WHERE is_template = 1 AND pack_name = ?",
        (_utcnow_iso(), pack_name),
    )
    increment_detection_rules_revision(db)

    record_audit(
        db,
        actor=current_user.username,
        actor_ip=request.remote_addr,
        action_type="templates_enabled",
        target=pack_name,
        details={"action": "enable_all", "count": count},
    )

    return jsonify({"ok": True, "message": f"All '{pack_name}' templates enabled"}), 200


@rules_bp.post(
    "/templates/<pack_name>/disable-all",
    summary="Disable all pack templates",
    description="Disable all template rules in a pack at once. Admin only.",
)
@require_role("admin")
def disable_all_pack_templates(pack_name):
    """Disable all template rules in a pack at once."""
    db = get_request_db()
    count = db.execute(
        "SELECT COUNT(*) FROM detection_rules_custom WHERE is_template = 1 AND pack_name = ?",
        (pack_name,),
    ).fetchone()[0]
    if count == 0:
        return jsonify({"error": "not_found", "message": f"No pack named '{pack_name}'"}), 404

    db.execute(
        "UPDATE detection_rules_custom SET enabled = 0, "
        "updated_at = ? "
        "WHERE is_template = 1 AND pack_name = ?",
        (_utcnow_iso(), pack_name),
    )
    increment_detection_rules_revision(db)

    record_audit(
        db,
        actor=current_user.username,
        actor_ip=request.remote_addr,
        action_type="templates_disabled",
        target=pack_name,
        details={"action": "disable_all", "count": count},
    )

    return jsonify({"ok": True, "message": f"All '{pack_name}' templates disabled"}), 200


@rules_bp.post(
    "/templates/<pack_name>/<int:rule_id>/toggle",
    summary="Toggle pack template",
    description="Toggle a single template rule on/off within a pack. Admin only.",
)
@require_role("admin")
def toggle_pack_template(pack_name, rule_id):
    """Toggle a single template rule on/off within a pack."""
    db = get_request_db()
    existing = db.execute(
        "SELECT * FROM detection_rules_custom WHERE id = ? AND is_template = 1 AND pack_name = ?",
        (rule_id, pack_name),
    ).fetchone()
    if not existing:
        return jsonify({"error": "not_found", "message": "Template rule not found"}), 404

    new_enabled = 0 if existing["enabled"] else 1
    db.execute(
        "UPDATE detection_rules_custom SET enabled = ?, updated_at = ? WHERE id = ?",
        (new_enabled, _utcnow_iso(), rule_id),
    )
    increment_detection_rules_revision(db)

    record_audit(
        db,
        actor=current_user.username,
        actor_ip=request.remote_addr,
        action_type="template_toggled",
        target=existing["name"],
        details={"rule_id": rule_id, "pack_name": pack_name, "enabled": bool(new_enabled)},
    )

    status = "enabled" if new_enabled else "disabled"
    return jsonify(
        {"ok": True, "enabled": bool(new_enabled), "message": f"Rule '{existing['name']}' {status}"}
    ), 200


# ---------------------------------------------------------------------------
# Distribution Endpoint (Bearer token auth, for nodes)
# ---------------------------------------------------------------------------


@rules_bp.get(
    "/distribution",
    summary="Get enabled rules for node",
    description="Return enabled rules for node consumption with ETag support and per-node filtering. Bearer auth required.",
    security=[{"BearerAuth": []}],
)
@limiter.limit(lambda: current_app.config.get("RATELIMIT_RULES_DISTRIBUTION", "30 per minute"))
def distribution():
    """Return enabled rules for node consumption with ETag support and per-node filtering.

    The ETag incorporates both the global rule revision and the requesting
    node's active parser list.  This ensures that when a node's log sources
    (and therefore active parsers) change — e.g. from ``["apache"]`` to
    ``["haproxy"]`` — the cached response is invalidated and the node
    receives the correctly filtered rule set on the next poll, even when
    the global rule revision has not changed.
    """
    api_key, error_response = _authenticate_bearer_token()
    if error_response is not None:
        return error_response

    db = get_request_db()
    revision = get_detection_rules_revision(db)

    # Resolve the requesting node's identity
    node_id = api_key.get("node_id_restriction") or request.args.get("node_id")

    # Resolve active parsers BEFORE the ETag check so the node's filter
    # state is incorporated into the cache key.
    filter_key: str | None = None
    node_mode: str = "all"
    disabled_rules_hash: str = ""
    if node_id:
        active_parsers, node_mode = _get_node_active_parsers(db, node_id)
        if active_parsers is not None:
            # Stable hash of the parsers for the ETag suffix.
            filter_key = hashlib.md5("|".join(sorted(active_parsers)).encode()).hexdigest()[:12]

        # Include disabled host threat rules in ETag so that
        # enabling/disabling rules invalidates the agent cache.
        profile = resolve_effective_profile(db, node_id)
        if profile:
            settings = (
                json.loads(profile["settings"])
                if isinstance(profile["settings"], str)
                else profile["settings"]
            )
            dr = settings.get("disabled_host_threat_rules", [])
            if isinstance(dr, list) and dr:
                disabled_rules_hash = hashlib.md5("|".join(sorted(dr)).encode()).hexdigest()[:8]

    # Build a node-aware ETag: revision + filter suffix + disabled hash.
    etag_parts = [str(revision)]
    if filter_key and node_mode != "all":
        etag_parts.append(filter_key)
    if disabled_rules_hash:
        etag_parts.append(disabled_rules_hash)
    etag = '"' + "-".join(etag_parts) + '"'

    # Check If-None-Match for conditional response
    if_none_match = request.headers.get("If-None-Match", "").strip('"')
    if if_none_match and if_none_match == etag.strip('"'):
        return "", 304

    rules = get_enabled_detection_rules(db)

    filtered = False
    active_parsers_out = None
    packs = []

    if node_id:
        # Re-resolve — cheap, and avoids passing active_parsers through
        # the no-ETag early-return path above.
        active_parsers, node_mode = _get_node_active_parsers(db, node_id)
        explicit_packs = active_parsers if node_mode == "explicit" else None

        rules = _filter_rules_for_node(rules, active_parsers, node_mode, explicit_packs)
        filtered = node_mode != "all"
        active_parsers_out = active_parsers

        # Filter out rules that are disabled for this node via config profile
        profile = resolve_effective_profile(db, node_id)
        if profile:
            settings = (
                json.loads(profile["settings"])
                if isinstance(profile["settings"], str)
                else profile["settings"]
            )
            disabled_rules = settings.get("disabled_host_threat_rules", [])
            if isinstance(disabled_rules, list) and disabled_rules:
                disabled_set = set(disabled_rules)
                rules["custom_rules"] = [
                    r for r in rules["custom_rules"] if r.get("name", "") not in disabled_set
                ]
                rules["brute_force_rules"] = [
                    r for r in rules["brute_force_rules"] if r.get("name", "") not in disabled_set
                ]
                filtered = True

    # Compute packs metadata: unique pack names present in the filtered rules
    packs = sorted(
        set(r.get("pack_name", "") for r in rules.get("custom_rules", []) if r.get("pack_name"))
    )

    rules["revision"] = revision
    rules["packs"] = packs
    rules["filtered"] = filtered
    rules["active_parsers"] = active_parsers_out

    response = jsonify(rules)
    response.headers["ETag"] = etag
    return response, 200


# ---------------------------------------------------------------------------
# Sigma Sync Endpoint (admin only)
# ---------------------------------------------------------------------------


@rules_bp.post(
    "/sigma/sync",
    summary="Trigger Sigma rule sync",
    description="Trigger a Sigma rule sync: pull latest rules, re-convert, regenerate packs. Returns a diff report. Admin only.",
)
@require_role("admin")
def sigma_sync():
    """Trigger a Sigma rule sync: pull latest rules, re-convert, regenerate packs.

    Returns a diff report showing added/removed/changed rules.
    """
    import subprocess
    import sys
    from pathlib import Path

    # Resolve the sigma_import module path
    project_root = Path(current_app.root_path).parent.parent
    sigma_script = project_root / "vespid" / "scripts" / "sigma_import.py"

    if not sigma_script.exists():
        return jsonify({"error": "sigma_import tool not found"}), 500

    try:
        result = subprocess.run(
            [sys.executable, "-m", "vespid.scripts.sigma_import", "--sync"],
            cwd=str(project_root),
            capture_output=True,
            text=True,
            timeout=300,
        )
    except subprocess.TimeoutExpired:
        return jsonify({"error": "Sigma sync timed out after 300 seconds"}), 504
    except Exception as exc:
        return jsonify({"error": f"Sigma sync failed: {exc}"}), 500

    # Check if packs were updated
    packs_updated = False
    web_pack = project_root / "vespid-server" / "packs" / "sigma-web-attacks.yaml"
    ssh_pack = project_root / "vespid-server" / "packs" / "sigma-ssh-attacks.yaml"
    if web_pack.exists() or ssh_pack.exists():
        packs_updated = True

    # If packs changed, re-seed the database and bump revision
    if packs_updated and result.returncode == 0:
        from app.pack_loader import get_pack_rules, load_packs

        db = get_request_db()
        packs = load_packs()
        pack_rules = get_pack_rules(packs)
        # Only re-insert sigma pack rules
        sigma_rules = [r for r in pack_rules if r.get("pack_name", "").startswith("sigma-")]
        inserted = 0
        updated = 0
        for rule in sigma_rules:
            existing = db.execute(
                "SELECT id FROM detection_rules_custom WHERE name = ?",
                (rule["name"],),
            ).fetchone()
            if existing:
                # Update existing rule's regex and metadata
                db.execute(
                    "UPDATE detection_rules_custom SET "
                    "regex = ?, tags = ?, sigma_id = ?, sigma_status = ?, "
                    "event_type = ?, max_attempts = ?, window_seconds = ?, "
                    "updated_at = ? WHERE id = ?",
                    (
                        rule["regex"],
                        rule.get("tags", "[]"),
                        rule.get("sigma_id", ""),
                        rule.get("sigma_status", ""),
                        rule["event_type"],
                        rule["max_attempts"],
                        rule["window_seconds"],
                        _utcnow_iso(),
                        existing["id"],
                    ),
                )
                updated += 1
            else:
                db.execute(
                    "INSERT OR IGNORE INTO detection_rules_custom "
                    "(name, event_type, regex, log_sources, max_attempts, window_seconds, "
                    "enabled, is_template, pack_name, tags, sigma_id, sigma_status) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        rule["name"],
                        rule["event_type"],
                        rule["regex"],
                        rule["log_sources"],
                        rule["max_attempts"],
                        rule["window_seconds"],
                        rule["enabled"],
                        rule["is_template"],
                        rule["pack_name"],
                        rule.get("tags", "[]"),
                        rule.get("sigma_id", ""),
                        rule.get("sigma_status", ""),
                    ),
                )
                inserted += 1
        if inserted > 0 or updated > 0:
            increment_detection_rules_revision(db)

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="sigma_sync",
            target="sigma_rules",
            details={"inserted": inserted, "updated": updated},
        )

        return jsonify(
            {
                "ok": True,
                "inserted": inserted,
                "updated": updated,
                "output": result.stdout[-2000:],
                "stderr": result.stderr[-1000:] if result.stderr else "",
                "returncode": result.returncode,
            }
        ), 200

    return jsonify(
        {
            "ok": result.returncode == 0,
            "output": result.stdout[-2000:],
            "stderr": result.stderr[-1000:] if result.stderr else "",
            "returncode": result.returncode,
            "message": "No pack changes detected" if not packs_updated else "Sync completed",
        }
    ), 200 if result.returncode == 0 else 500
