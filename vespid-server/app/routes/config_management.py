"""Config Management API blueprint — centralized agent configuration profiles.

Endpoints:
    POST   /api/v1/config/profiles                   — Create a configuration profile (admin)
    GET    /api/v1/config/profiles                   — List configuration profiles (analyst)
    GET    /api/v1/config/profiles/<id>              — Get profile detail (analyst)
    PUT    /api/v1/config/profiles/<id>              — Update a profile (admin)
    DELETE /api/v1/config/profiles/<id>              — Soft-delete a profile (admin)
    POST   /api/v1/config/assignments                — Assign profile to agent/group
    DELETE  /api/v1/config/assignments/<id>           — Unassign profile
    GET    /api/v1/config/profiles/<id>/assignments   — List assigned agents (paginated)
    POST   /api/v1/config/groups                     — Create group
    GET    /api/v1/config/groups                     — List groups (paginated)
    DELETE  /api/v1/config/groups/<id>                — Delete group
    POST   /api/v1/config/groups/<id>/members        — Add agent to group
    DELETE  /api/v1/config/groups/<id>/members/<node_id> — Remove agent from group

Requirements: 2.1, 2.2, 2.3, 2.4, 2.5, 2.6, 2.7, 2.8, 2.9, 3.1, 3.2, 3.3, 3.5, 3.6, 3.7, 3.8, 3.9, 4.1, 4.2, 4.3, 4.4, 4.5, 4.6, 4.7, 4.8, 4.9, 11.1, 11.2
"""

import json
import logging
import sqlite3
from datetime import UTC

from flask import Response, current_app, jsonify, request
from flask_login import current_user
from flask_openapi3 import APIBlueprint
from flask_openapi3.models import Tag

from app.config_resolution import resolve_effective_profile
from app.config_validation import ConfigValidator
from app.decorators import require_role
from app.models import (
    add_group_member,
    create_agent_group,
    create_assignment,
    create_config_profile,
    deactivate_assignment,
    delete_agent_group,
    get_active_rollout,
    get_config_profile,
    get_request_db,
    get_version_settings,
    list_agent_groups,
    list_assignments_for_profile,
    list_config_profiles,
    list_ip_rules,
    list_version_history,
    record_audit,
    remove_group_member,
    soft_delete_config_profile,
    update_config_profile,
    update_last_seen,
    upsert_agent_config_status,
)
from app.rate_limit import _key_func_body_node, limiter
from app.routes.auth import authenticate_bearer_token
from app.routes.config_rollout import rollout_engine

logger = logging.getLogger(__name__)

config_mgmt_bp = APIBlueprint(
    "config_mgmt",
    __name__,
    url_prefix="/api/v1/config",
    abp_tags=[
        Tag(
            name="Config Management",
            description="Centralized agent configuration profiles and groups",
        )
    ],
    abp_security=[{"BearerAuth": []}, {"SessionAuth": []}],
)

_validator = ConfigValidator()


# ---------------------------------------------------------------------------
# SSE publish helper
# ---------------------------------------------------------------------------


def _publish_profile_update_sse(db, profile_id: int, updated_profile: dict) -> None:
    """Push a config_updated SSE event to connected agents after a profile update.

    Respects rollout policy:
    - No active rollout or immediate rollout: push to all assigned agents (target_nodes=None)
    - Canary rollout: push only to canary_nodes
    - Staged rollout: push only to nodes within the current percentage bucket

    Args:
        db: An open SQLite connection.
        profile_id: The profile that was updated.
        updated_profile: The updated profile dict (must have settings parsed as dict).
    """
    import hashlib as _hashlib

    try:
        config_sse = current_app.config_sse_manager
    except AttributeError:
        # SSE manager not initialized (e.g., during testing without full app setup)
        logger.debug("config_sse_manager not available, skipping SSE publish")
        return

    # Determine target_nodes based on active rollout policy
    active_rollout = get_active_rollout(db, profile_id)
    target_nodes = None  # None means push to all connected clients

    if active_rollout is not None:
        policy = active_rollout.get("policy", "immediate")

        if policy == "canary":
            # Only push to canary nodes
            canary_nodes = active_rollout.get("canary_nodes", "[]")
            if isinstance(canary_nodes, str):
                canary_nodes = json.loads(canary_nodes)
            target_nodes = canary_nodes

        elif policy == "staged":
            # Compute which nodes fall within the current percentage
            percentage = active_rollout.get("current_percentage", 100)
            all_assigned = _get_assigned_node_ids(db, profile_id)
            target_nodes = [
                nid
                for nid in all_assigned
                if (int(_hashlib.sha256(nid.encode()).hexdigest(), 16) % 100) < percentage
            ]

        # For immediate policy, target_nodes stays None (all agents)

    # Build event data
    settings = updated_profile.get("settings", {})
    if isinstance(settings, str):
        settings = json.loads(settings)

    updated_at = updated_profile.get("updated_at", "")
    # MySQL returns datetime objects; ensure string for JSON serialization
    if hasattr(updated_at, "strftime"):
        updated_at = updated_at.strftime("%Y-%m-%dT%H:%M:%SZ")

    event_data = {
        "profile_name": updated_profile.get("name", ""),
        "version": updated_profile.get("version", 1),
        "settings": settings,
        "updated_at": updated_at,
        "conflict_strategy": "server-wins",  # Default; agents may override locally
    }

    config_sse.publish_to_profile(profile_id, event_data, target_nodes)
    logger.info(
        "Published config_updated SSE event for profile %d (version %d, targets=%s)",
        profile_id,
        event_data["version"],
        "all" if target_nodes is None else f"{len(target_nodes)} nodes",
    )


def _get_assigned_node_ids(db, profile_id: int) -> list[str]:
    """Get all node_ids assigned to a profile (direct + group-based).

    Args:
        db: An open SQLite connection.
        profile_id: The profile to look up assignments for.

    Returns:
        A list of unique node_id strings.
    """
    # Direct assignments
    direct_rows = db.execute(
        "SELECT node_id FROM config_assignments "
        "WHERE profile_id = ? AND is_active = 1 AND node_id IS NOT NULL",
        (profile_id,),
    ).fetchall()

    # Group-based assignments
    group_rows = db.execute(
        "SELECT DISTINCT agm.node_id FROM agent_group_members agm "
        "JOIN config_assignments ca ON ca.group_id = agm.group_id "
        "WHERE ca.profile_id = ? AND ca.is_active = 1",
        (profile_id,),
    ).fetchall()

    all_nodes = set()
    for row in direct_rows:
        all_nodes.add(row["node_id"])
    for row in group_rows:
        all_nodes.add(row["node_id"])

    return list(all_nodes)


# ---------------------------------------------------------------------------
# Profile CRUD endpoints
# ---------------------------------------------------------------------------


@config_mgmt_bp.post(
    "/profiles",
    summary="Create config profile",
    description="Create a new configuration profile. Admin only.",
)
@limiter.limit(lambda: current_app.config.get("RATELIMIT_CONFIG_ADMIN", "30 per minute"))
@require_role("admin")
def create_profile():
    """Create a new configuration profile.

    Request body (JSON):
        {
            "name": "production-standard",
            "settings": {"flush_interval_seconds": 30, ...},
            "description": "Optional description"
        }

    Returns 201 with the created profile record.

    Requirements: 2.1, 2.6, 2.9, 11.1
    """
    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid_json", "message": "Request body is not valid JSON"}), 400

    if not body or not isinstance(body, dict):
        return jsonify({"error": "invalid_json", "message": "Request body is not valid JSON"}), 400

    # Validate required fields
    errors = []
    name = body.get("name")
    settings = body.get("settings")
    description = body.get("description", "")

    if name is None or (isinstance(name, str) and not name.strip()):
        errors.append("name is required and must not be empty")
    elif not isinstance(name, str):
        errors.append("name must be a string")
    elif len(name) > 128:
        errors.append("name must not exceed 128 characters")

    if settings is None:
        errors.append("settings is required")
    elif not isinstance(settings, dict):
        errors.append("settings must be a JSON object")

    if isinstance(description, str) and len(description) > 512:
        errors.append("description must not exceed 512 characters")
    elif not isinstance(description, str):
        errors.append("description must be a string")

    if errors:
        return jsonify({"error": "validation_error", "errors": errors}), 422

    # Validate settings values
    validation_errors = _validator.validate_settings(settings)
    if validation_errors:
        return jsonify({"error": "validation_error", "errors": validation_errors}), 422

    # Create the profile
    db = get_request_db()
    name = name.strip()
    # Check for duplicate name (case-insensitive)
    existing = db.execute(
        "SELECT id FROM config_profiles WHERE name_lower = ? AND is_active = 1",
        (name.lower(),),
    ).fetchone()
    if existing:
        return jsonify(
            {
                "error": "duplicate_name",
                "message": f"A profile with name '{name}' already exists (case-insensitive)",
            }
        ), 409

    profile = create_config_profile(
        db,
        name=name,
        settings=settings,
        created_by=current_user.username,
        description=description,
    )

    # Record audit log
    record_audit(
        db,
        actor=current_user.username,
        actor_ip=request.remote_addr,
        action_type="config_profile_create",
        target=name,
        details={
            "profile_id": profile["id"],
            "diff": {"added": settings, "removed": {}, "modified": {}},
        },
    )

    # Parse settings JSON string back to dict for response
    if isinstance(profile.get("settings"), str):
        profile["settings"] = json.loads(profile["settings"])

    return jsonify(profile), 201


@config_mgmt_bp.get(
    "/profiles",
    summary="List config profiles",
    description="List active configuration profiles with pagination. Analyst+ required.",
)
@limiter.limit(lambda: current_app.config.get("RATELIMIT_CONFIG_READ", "60 per minute"))
@require_role("analyst")
def list_profiles():
    """List active configuration profiles with pagination.

    Query params:
        page (int): Page number (default: 1)
        per_page (int): Items per page (default: 50, max: 200)

    Returns 200 with {profiles, total, page, per_page}.

    Requirements: 2.2
    """
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)

    # Clamp values
    page = max(1, page)
    per_page = max(1, min(per_page, 200))

    db = get_request_db()
    result = list_config_profiles(db, page=page, per_page=per_page)

    # Parse settings JSON strings back to dicts for response
    for profile in result["profiles"]:
        if isinstance(profile.get("settings"), str):
            profile["settings"] = json.loads(profile["settings"])


@config_mgmt_bp.get(
    "/profiles/<int:profile_id>",
    summary="Get config profile",
    description="Get a configuration profile by ID. Analyst+ required.",
)
@limiter.limit(lambda: current_app.config.get("RATELIMIT_CONFIG_READ", "60 per minute"))
@require_role("analyst")
def get_profile(profile_id):
    """Get a configuration profile by ID.

    Returns 200 with the profile, or 404 if not found/inactive.

    Requirements: 2.5, 2.8
    """
    db = get_request_db()
    profile = get_config_profile(db, profile_id)
    if profile is None:
        return jsonify(
            {
                "error": "not_found",
                "message": f"Profile with id {profile_id} not found",
            }
        ), 404

    # Parse settings JSON string back to dict for response
    if isinstance(profile.get("settings"), str):
        profile["settings"] = json.loads(profile["settings"])


@config_mgmt_bp.put(
    "/profiles/<int:profile_id>",
    summary="Update config profile",
    description="Update a configuration profile. Requires change_reason. Admin only.",
)
@limiter.limit(lambda: current_app.config.get("RATELIMIT_CONFIG_ADMIN", "30 per minute"))
@require_role("admin")
def update_profile(profile_id):
    """Update a configuration profile.

    Request body (JSON):
        {
            "name": "new-name",          (optional)
            "description": "...",        (optional)
            "settings": {...},           (optional)
            "change_reason": "..."       (required)
        }

    Returns 200 with the updated profile, or 404 if not found.

    Requirements: 2.3, 2.6, 2.7, 2.8, 2.9, 11.1
    """
    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid_json", "message": "Request body is not valid JSON"}), 400

    if not body or not isinstance(body, dict):
        return jsonify({"error": "invalid_json", "message": "Request body is not valid JSON"}), 400

    # Check profile exists
    db = get_request_db()
    existing = get_config_profile(db, profile_id)
    if existing is None:
        return jsonify(
            {
                "error": "not_found",
                "message": f"Profile with id {profile_id} not found",
            }
        ), 404

    # Validate fields
    errors = []
    name = body.get("name")
    description = body.get("description")
    settings = body.get("settings")
    change_reason = body.get("change_reason", "")

    if not change_reason or not isinstance(change_reason, str) or not change_reason.strip():
        errors.append("change_reason is required and must not be empty")

    if name is not None:
        if not isinstance(name, str) or not name.strip():
            errors.append("name must be a non-empty string")
        elif len(name) > 128:
            errors.append("name must not exceed 128 characters")
        else:
            # Check for duplicate name (case-insensitive), excluding current profile
            dup = db.execute(
                "SELECT id FROM config_profiles WHERE name_lower = ? AND is_active = 1 AND id != ?",
                (name.strip().lower(), profile_id),
            ).fetchone()
            if dup:
                errors.append(
                    f"A profile with name '{name.strip()}' already exists (case-insensitive)"
                )

    if description is not None:
        if not isinstance(description, str):
            errors.append("description must be a string")
        elif len(description) > 512:
            errors.append("description must not exceed 512 characters")

    if settings is not None:
        if not isinstance(settings, dict):
            errors.append("settings must be a JSON object")
        else:
            validation_errors = _validator.validate_settings(settings)
            if validation_errors:
                errors.extend(validation_errors)

    if errors:
        return jsonify({"error": "validation_error", "errors": errors}), 422

    # Compute diff for audit
    old_settings = existing.get("settings", {})
    if isinstance(old_settings, str):
        old_settings = json.loads(old_settings)
    new_settings = settings if settings is not None else old_settings
    diff = _validator.compute_diff(old_settings, new_settings)

    # Perform update
    updated = update_config_profile(
        db,
        profile_id=profile_id,
        name=name.strip() if name else None,
        description=description,
        settings=settings,
        changed_by=current_user.username,
        change_reason=change_reason.strip(),
    )

    if updated is None:
        return jsonify(
            {
                "error": "not_found",
                "message": f"Profile with id {profile_id} not found",
            }
        ), 404

    # Record audit log
    record_audit(
        db,
        actor=current_user.username,
        actor_ip=request.remote_addr,
        action_type="config_profile_update",
        target=updated.get("name", existing.get("name")),
        details={
            "profile_id": profile_id,
            "diff": diff,
            "change_reason": change_reason.strip(),
        },
    )

    # Parse settings JSON string back to dict for response
    if isinstance(updated.get("settings"), str):
        updated["settings"] = json.loads(updated["settings"])

    # --- SSE push: notify connected agents of the profile update ---
    _publish_profile_update_sse(db, profile_id, updated)

    return jsonify(updated), 200


@config_mgmt_bp.delete(
    "/profiles/<int:profile_id>",
    summary="Delete config profile",
    description="Soft-delete a configuration profile. Admin only.",
)
@limiter.limit(lambda: current_app.config.get("RATELIMIT_CONFIG_ADMIN", "30 per minute"))
@require_role("admin")
def delete_profile(profile_id):
    """Soft-delete a configuration profile.

    Returns 200 on success, or 404 if not found/inactive.

    Requirements: 2.4, 2.7, 2.8, 11.1
    """
    db = get_request_db()
    # Get profile info before deletion for audit
    profile = get_config_profile(db, profile_id)
    if profile is None:
        return jsonify(
            {
                "error": "not_found",
                "message": f"Profile with id {profile_id} not found",
            }
        ), 404

    deleted = soft_delete_config_profile(db, profile_id)
    if not deleted:
        return jsonify(
            {
                "error": "not_found",
                "message": f"Profile with id {profile_id} not found",
            }
        ), 404

    # Record audit log
    record_audit(
        db,
        actor=current_user.username,
        actor_ip=request.remote_addr,
        action_type="config_profile_delete",
        target=profile.get("name"),
        details={
            "profile_id": profile_id,
            "diff": {"added": {}, "removed": {}, "modified": {}},
        },
    )

    return jsonify({"status": "deleted", "profile_id": profile_id}), 200


@config_mgmt_bp.post(
    "/assignments",
    summary="Assign config profile",
    description="Assign a configuration profile to an agent or group. Admin only.",
)
@require_role("admin")
def create_assignment_endpoint():
    """Assign a configuration profile to an agent or group.

    Body: {profile_id, node_id?, group_id?}
    One of node_id or group_id is required.

    Validates:
    - Profile exists and is active
    - If node_id: node is enrolled (exists in nodes table)
    - Assigning new profile deactivates previous assignment for same agent

    Returns HTTP 201 with the created assignment record.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "invalid_json", "message": "Request body must be valid JSON"}), 400

    profile_id = data.get("profile_id")
    node_id = data.get("node_id")
    group_id = data.get("group_id")

    # Validate required fields
    if profile_id is None:
        return jsonify({"error": "missing_fields", "fields": ["profile_id"]}), 400

    if node_id is None and group_id is None:
        return jsonify(
            {
                "error": "missing_fields",
                "message": "One of node_id or group_id is required",
                "fields": ["node_id", "group_id"],
            }
        ), 400

    db = get_request_db()
    # Validate profile exists and is active
    profile = db.execute(
        "SELECT id, name, is_active FROM config_profiles WHERE id = ?",
        (profile_id,),
    ).fetchone()

    if profile is None:
        return jsonify({"error": "not_found", "message": "Profile not found"}), 404

    if not profile["is_active"]:
        return jsonify(
            {
                "error": "validation_error",
                "message": "Profile is inactive",
            }
        ), 422

    # Validate node_id is enrolled if provided
    if node_id is not None:
        node = db.execute(
            "SELECT node_id FROM nodes WHERE node_id = ?",
            (node_id,),
        ).fetchone()
        if node is None:
            return jsonify(
                {
                    "error": "not_found",
                    "message": f"Node '{node_id}' is not enrolled",
                }
            ), 404

    # Validate group_id exists if provided
    if group_id is not None:
        group = db.execute(
            "SELECT id FROM agent_groups WHERE id = ?",
            (group_id,),
        ).fetchone()
        if group is None:
            return jsonify(
                {
                    "error": "not_found",
                    "message": f"Group with id {group_id} not found",
                }
            ), 404

    # Create the assignment (deactivates previous for same node)
    assignment = create_assignment(
        db,
        profile_id=profile_id,
        assigned_by=current_user.username,
        node_id=node_id,
        group_id=group_id,
    )

    # Record audit log
    details = {"profile_id": profile_id}
    if node_id:
        details["node_id"] = node_id
    if group_id:
        details["group_id"] = group_id

    record_audit(
        db,
        actor=current_user.username,
        actor_ip=request.remote_addr,
        action_type="config_assignment_create",
        target=profile["name"],
        details=details,
    )

    return jsonify(assignment), 201


@config_mgmt_bp.delete(
    "/assignments/<int:assignment_id>",
    summary="Unassign config profile",
    description="Unassign a profile (deactivate the assignment). Admin only.",
)
@require_role("admin")
def delete_assignment_endpoint(assignment_id):
    """Unassign a profile (deactivate the assignment).

    Returns HTTP 200 on success, 404 if not found.
    """
    db = get_request_db()
    # Get assignment details for audit before deactivating
    assignment = db.execute(
        "SELECT ca.*, cp.name as profile_name FROM config_assignments ca "
        "JOIN config_profiles cp ON ca.profile_id = cp.id "
        "WHERE ca.id = ? AND ca.is_active = 1",
        (assignment_id,),
    ).fetchone()

    if assignment is None:
        return jsonify({"error": "not_found", "message": "Assignment not found"}), 404

    success = deactivate_assignment(db, assignment_id)
    if not success:
        return jsonify({"error": "not_found", "message": "Assignment not found"}), 404

    # Record audit log
    details = {"assignment_id": assignment_id, "profile_id": assignment["profile_id"]}
    if assignment["node_id"]:
        details["node_id"] = assignment["node_id"]
    if assignment["group_id"]:
        details["group_id"] = assignment["group_id"]

    record_audit(
        db,
        actor=current_user.username,
        actor_ip=request.remote_addr,
        action_type="config_assignment_delete",
        target=assignment["profile_name"],
        details=details,
    )

    return jsonify({"message": "Assignment deactivated", "id": assignment_id}), 200


@config_mgmt_bp.get(
    "/profiles/<int:profile_id>/assignments",
    summary="List profile assignments",
    description="List active assignments for a profile (paginated). Analyst+ required.",
)
@require_role("analyst")
def list_profile_assignments(profile_id):
    """List active assignments for a profile (paginated).

    Query params:
        page (int): Page number (default: 1)
        per_page (int): Items per page (default: 50, clamped 1-200)

    Returns 404 if profile not found.
    """
    db = get_request_db()
    # Validate profile exists
    profile = db.execute(
        "SELECT id, is_active FROM config_profiles WHERE id = ?",
        (profile_id,),
    ).fetchone()

    if profile is None or not profile["is_active"]:
        return jsonify({"error": "not_found", "message": "Profile not found"}), 404

    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)

    result = list_assignments_for_profile(db, profile_id, page=page, per_page=per_page)
    return jsonify(result), 200


# ---------------------------------------------------------------------------
# Group endpoints
# ---------------------------------------------------------------------------


@config_mgmt_bp.post(
    "/groups",
    summary="Create agent group",
    description="Create an agent group. Admin only.",
)
@require_role("admin")
def create_group_endpoint():
    """Create an agent group.

    Body: {name, description?}
    Validates name is unique.

    Returns HTTP 201 with the created group record.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "invalid_json", "message": "Request body must be valid JSON"}), 400

    name = data.get("name")
    description = data.get("description", "")

    if not name or not isinstance(name, str) or not name.strip():
        return jsonify(
            {
                "error": "validation_error",
                "message": "name is required and must be a non-empty string",
            }
        ), 422

    name = name.strip()
    if len(name) > 128:
        return jsonify(
            {
                "error": "validation_error",
                "message": "name must not exceed 128 characters",
            }
        ), 422

    if isinstance(description, str) and len(description) > 512:
        return jsonify(
            {
                "error": "validation_error",
                "message": "description must not exceed 512 characters",
            }
        ), 422

    db = get_request_db()
    try:
        group = create_agent_group(
            db,
            name=name,
            created_by=current_user.username,
            description=description if description else "",
        )

        # Record audit log
        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="config_group_create",
            target=name,
            details={"group_id": group["id"], "name": name, "description": description},
        )

        return jsonify(group), 201

    except sqlite3.IntegrityError:
        return jsonify(
            {
                "error": "validation_error",
                "message": f"Group name '{name}' is already in use",
            }
        ), 409


@config_mgmt_bp.get(
    "/groups",
    summary="List agent groups",
    description="List agent groups (paginated). Analyst+ required.",
)
@require_role("analyst")
def list_groups_endpoint():
    """List agent groups (paginated).

    Query params:
        page (int): Page number (default: 1)
        per_page (int): Items per page (default: 50, clamped 1-200)
    """
    db = get_request_db()
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)

    result = list_agent_groups(db, page=page, per_page=per_page)
    return jsonify(result), 200


@config_mgmt_bp.delete(
    "/groups/<int:group_id>",
    summary="Delete agent group",
    description="Delete an agent group. Cascades: removes memberships and deactivates assignments. Admin only.",
)
@require_role("admin")
def delete_group_endpoint(group_id):
    """Delete an agent group.

    Cascades: removes all memberships and deactivates all assignments
    for this group before deleting.

    Returns 404 if group not found.
    """
    db = get_request_db()
    # Get group details for audit before deleting
    group = db.execute(
        "SELECT * FROM agent_groups WHERE id = ?",
        (group_id,),
    ).fetchone()

    if group is None:
        return jsonify({"error": "not_found", "message": "Group not found"}), 404

    success = delete_agent_group(db, group_id)
    if not success:
        return jsonify({"error": "not_found", "message": "Group not found"}), 404

    # Record audit log
    record_audit(
        db,
        actor=current_user.username,
        actor_ip=request.remote_addr,
        action_type="config_group_delete",
        target=group["name"],
        details={"group_id": group_id, "name": group["name"]},
    )

    return jsonify({"message": "Group deleted", "id": group_id}), 200


@config_mgmt_bp.post(
    "/groups/<int:group_id>/members",
    summary="Add group member",
    description="Add an agent to a group. Admin only.",
)
@require_role("admin")
def add_group_member_endpoint(group_id):
    """Add an agent to a group.

    Body: {node_id}
    Validates node is enrolled and group exists.

    Returns HTTP 201 with the created membership record.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "invalid_json", "message": "Request body must be valid JSON"}), 400

    node_id = data.get("node_id")
    if not node_id or not isinstance(node_id, str) or not node_id.strip():
        return jsonify(
            {
                "error": "missing_fields",
                "message": "node_id is required",
                "fields": ["node_id"],
            }
        ), 400

    node_id = node_id.strip()

    db = get_request_db()
    # Validate group exists
    group = db.execute(
        "SELECT * FROM agent_groups WHERE id = ?",
        (group_id,),
    ).fetchone()

    if group is None:
        return jsonify({"error": "not_found", "message": "Group not found"}), 404

    # Validate node is enrolled
    node = db.execute(
        "SELECT node_id FROM nodes WHERE node_id = ?",
        (node_id,),
    ).fetchone()
    if node is None:
        return jsonify(
            {
                "error": "not_found",
                "message": f"Node '{node_id}' is not enrolled",
            }
        ), 404

    try:
        membership = add_group_member(
            db,
            group_id=group_id,
            node_id=node_id,
            added_by=current_user.username,
        )
    except sqlite3.IntegrityError:
        return jsonify(
            {
                "error": "validation_error",
                "message": f"Node '{node_id}' is already a member of this group",
            }
        ), 409

    # Record audit log
    record_audit(
        db,
        actor=current_user.username,
        actor_ip=request.remote_addr,
        action_type="config_group_member_add",
        target=group["name"],
        details={"group_id": group_id, "node_id": node_id},
    )

    return jsonify(membership), 201


@config_mgmt_bp.delete(
    "/groups/<int:group_id>/members/<node_id>",
    summary="Remove group member",
    description="Remove an agent from a group. Admin only.",
)
@require_role("admin")
def remove_group_member_endpoint(group_id, node_id):
    """Remove an agent from a group.

    Returns 404 if group or membership not found.
    """
    db = get_request_db()
    # Validate group exists
    group = db.execute(
        "SELECT * FROM agent_groups WHERE id = ?",
        (group_id,),
    ).fetchone()

    if group is None:
        return jsonify({"error": "not_found", "message": "Group not found"}), 404

    success = remove_group_member(db, group_id=group_id, node_id=node_id)
    if not success:
        return jsonify(
            {
                "error": "not_found",
                "message": f"Membership not found for node '{node_id}' in group {group_id}",
            }
        ), 404

    # Record audit log
    record_audit(
        db,
        actor=current_user.username,
        actor_ip=request.remote_addr,
        action_type="config_group_member_remove",
        target=group["name"],
        details={"group_id": group_id, "node_id": node_id},
    )

    return jsonify({"message": "Member removed", "group_id": group_id, "node_id": node_id}), 200


# ---------------------------------------------------------------------------
# Version history and rollback endpoints
# ---------------------------------------------------------------------------


@config_mgmt_bp.get(
    "/profiles/<int:profile_id>/history",
    summary="Profile version history",
    description="List version history for a configuration profile (paginated). Analyst+ required.",
)
@limiter.limit(lambda: current_app.config.get("RATELIMIT_CONFIG_READ", "60 per minute"))
@require_role("analyst")
def profile_version_history(profile_id):
    """List version history for a configuration profile (paginated).

    Query params:
        page (int): Page number (default: 1)
        per_page (int): Items per page (default: 50, clamped 1-200)

    Returns 200 with paginated version history, or 404 if profile not found.

    Requirements: 9.1
    """
    db = get_request_db()
    # Validate profile exists and is active
    profile = get_config_profile(db, profile_id)
    if profile is None:
        return jsonify(
            {
                "error": "not_found",
                "message": f"Profile with id {profile_id} not found",
            }
        ), 404

    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)

    page = max(1, page)
    per_page = max(1, min(per_page, 200))

    result = list_version_history(db, profile_id, page=page, per_page=per_page)
    return jsonify(result), 200


@config_mgmt_bp.get(
    "/profiles/<int:profile_id>/history/<int:ver>",
    summary="Profile version detail",
    description="Get the full settings of a historical version of a profile. Analyst+ required.",
)
@limiter.limit(lambda: current_app.config.get("RATELIMIT_CONFIG_READ", "60 per minute"))
@require_role("analyst")
def profile_version_detail(profile_id, ver):
    """Get the full settings of a historical version of a profile.

    Returns 200 with {version, settings}, or 404 if profile or version not found.

    Requirements: 9.2, 9.7
    """
    db = get_request_db()
    # Validate profile exists and is active
    profile = get_config_profile(db, profile_id)
    if profile is None:
        return jsonify(
            {
                "error": "not_found",
                "message": f"Profile with id {profile_id} not found",
            }
        ), 404

    settings = get_version_settings(db, profile_id, ver)
    if settings is None:
        return jsonify(
            {
                "error": "not_found",
                "message": f"Version {ver} not found for profile {profile_id}",
            }
        ), 404

    return jsonify({"version": ver, "settings": settings}), 200


@config_mgmt_bp.get(
    "/profiles/<int:profile_id>/diff",
    summary="Profile version diff",
    description="Compute a diff between two versions of a profile. Analyst+ required.",
)
@limiter.limit(lambda: current_app.config.get("RATELIMIT_CONFIG_READ", "60 per minute"))
@require_role("analyst")
def profile_version_diff(profile_id):
    """Compute a diff between two versions of a profile.

    Query params:
        from_version (int, required): Source version number
        to_version (int, required): Target version number

    Returns 200 with the Config_Diff, or 400/404 on error.

    Requirements: 9.4, 9.8
    """
    from_version = request.args.get("from_version", type=int)
    to_version = request.args.get("to_version", type=int)

    if from_version is None or to_version is None:
        return jsonify(
            {
                "error": "validation_error",
                "message": "Both from_version and to_version query parameters are required",
            }
        ), 400

    db = get_request_db()
    # Validate profile exists and is active
    profile = get_config_profile(db, profile_id)
    if profile is None:
        return jsonify(
            {
                "error": "not_found",
                "message": f"Profile with id {profile_id} not found",
            }
        ), 404

    from_settings = get_version_settings(db, profile_id, from_version)
    if from_settings is None:
        return jsonify(
            {
                "error": "not_found",
                "message": f"Version {from_version} not found for profile {profile_id}",
            }
        ), 404

    to_settings = get_version_settings(db, profile_id, to_version)
    if to_settings is None:
        return jsonify(
            {
                "error": "not_found",
                "message": f"Version {to_version} not found for profile {profile_id}",
            }
        ), 404

    diff = _validator.compute_diff(from_settings, to_settings)
    return jsonify(
        {
            "from_version": from_version,
            "to_version": to_version,
            "diff": diff,
        }
    ), 200


@config_mgmt_bp.post(
    "/profiles/<int:profile_id>/rollback",
    summary="Rollback profile",
    description="Rollback a profile to a previous version. Admin only.",
)
@limiter.limit(lambda: current_app.config.get("RATELIMIT_CONFIG_ADMIN", "30 per minute"))
@require_role("admin")
def profile_rollback(profile_id):
    """Rollback a profile to a previous version.

    Request body (JSON):
        {
            "target_version": 3,
            "reason": "Reverting bad change"
        }

    Creates a new version with the historical settings and records an audit entry.

    Returns 200 with the updated profile, or 404/422 on error.

    Requirements: 9.3, 9.5, 9.6, 11.1
    """
    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid_json", "message": "Request body is not valid JSON"}), 400

    if not body or not isinstance(body, dict):
        return jsonify({"error": "invalid_json", "message": "Request body is not valid JSON"}), 400

    target_version = body.get("target_version")
    reason = body.get("reason")

    # Validate required fields
    errors = []
    if target_version is None or not isinstance(target_version, int):
        errors.append("target_version is required and must be an integer")
    if reason is None or not isinstance(reason, str) or not reason.strip():
        errors.append("reason is required and must be a non-empty string")

    if errors:
        return jsonify({"error": "validation_error", "errors": errors}), 422

    db = get_request_db()
    # Validate profile exists and is active
    profile = get_config_profile(db, profile_id)
    if profile is None:
        return jsonify(
            {
                "error": "not_found",
                "message": f"Profile with id {profile_id} not found",
            }
        ), 404

    # Get historical settings for target version
    historical_settings = get_version_settings(db, profile_id, target_version)
    if historical_settings is None:
        return jsonify(
            {
                "error": "not_found",
                "message": f"Version {target_version} not found for profile {profile_id}",
            }
        ), 404

    # Perform the rollback by updating the profile with historical settings
    source_version = profile["version"]
    change_reason = f"Rollback to version {target_version}: {reason.strip()}"

    updated = update_config_profile(
        db,
        profile_id=profile_id,
        settings=historical_settings,
        changed_by=current_user.username,
        change_reason=change_reason,
    )

    if updated is None:
        return jsonify(
            {
                "error": "not_found",
                "message": f"Profile with id {profile_id} not found",
            }
        ), 404

    # Record audit log for rollback
    record_audit(
        db,
        actor=current_user.username,
        actor_ip=request.remote_addr,
        action_type="config_profile_rollback",
        target=profile.get("name"),
        details={
            "profile_id": profile_id,
            "source_version": source_version,
            "target_version": target_version,
            "reason": reason.strip(),
        },
    )

    # Parse settings JSON string back to dict for response
    if isinstance(updated.get("settings"), str):
        updated["settings"] = json.loads(updated["settings"])

    return jsonify(updated), 200


# ---------------------------------------------------------------------------
# SSE Stream endpoint (Bearer token auth)
# ---------------------------------------------------------------------------


_authenticate_bearer_token = authenticate_bearer_token


@config_mgmt_bp.get(
    "/stream",
    summary="Config SSE stream",
    description="Streams config_updated events to subscribed agents. Supports Last-Event-ID for reconnection replay. Bearer auth required.",
    security=[{"BearerAuth": []}],
)
@limiter.exempt
def config_stream():
    """Config SSE stream endpoint with Bearer token auth.

    Streams config_updated events to subscribed agents. Supports
    Last-Event-ID for reconnection replay and sends keepalive
    comments every 30 seconds on idle connections.

    The agent's node_id is determined from the API key's node_id_restriction
    field, or from the `node_id` query parameter if the key has no restriction.

    Requirements: 16.1, 16.2, 16.6, 16.11, 16.12
    """
    api_key, error_response = _authenticate_bearer_token()
    if error_response is not None:
        return error_response

    # Determine node_id: prefer API key restriction, fall back to query param
    node_id = api_key.get("node_id_restriction") or request.args.get("node_id")
    if not node_id:
        return jsonify(
            {
                "error": "missing_node_id",
                "message": "node_id is required (via API key restriction or query parameter)",
            }
        ), 400

    last_event_id = request.headers.get("Last-Event-ID")
    config_sse = current_app.config_sse_manager

    def generate():
        """Yield SSE messages with periodic keepalive comments.

        Uses a 30-second timeout on queue.get() so we can emit an SSE
        comment as a keepalive. This prevents reverse proxies and load
        balancers from closing idle connections.

        Requirements: 16.11
        """
        client_queue = config_sse.create_client(node_id=node_id, last_event_id=last_event_id)
        try:
            while True:
                try:
                    message = client_queue.get(timeout=30)
                except Exception:
                    # queue.Empty — no events for 30s, send keepalive
                    yield ": keepalive\n\n"
                    continue
                if message is None:
                    # Sentinel value — server is shutting down
                    return
                yield message
        except GeneratorExit:
            # Client disconnected
            pass
        finally:
            config_sse.remove_client(node_id)

    return Response(
        generate(),
        mimetype="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
            "Connection": "keep-alive",
        },
    )


# ---------------------------------------------------------------------------
# Agent check-in endpoint (Bearer token auth)
# ---------------------------------------------------------------------------


@config_mgmt_bp.post(
    "/check-in",
    summary="Agent check-in",
    description="Agent check-in endpoint for initial sync and health reporting. Bearer auth required.",
    security=[{"BearerAuth": []}],
)
@limiter.limit(
    lambda: current_app.config.get("RATELIMIT_CONFIG_CHECKIN", "120 per minute"),
    key_func=_key_func_body_node,
)
def agent_check_in():
    """Agent check-in endpoint for initial sync and health reporting.

    Authenticates via Bearer token. Agents call this on startup (before
    opening the SSE stream) to report their current state and receive any
    pending configuration updates.

    Request body (JSON):
        {
            "node_id": "node-abc",
            "current_config_version": 3,
            "management_mode": "server-managed",
            "agent_version": "1.5.0",
            "health": {
                "uptime": 7200,
                "active_rules": 10,
                "blocked_ips": 42
            }
        }

    Logic:
        1. Authenticate via Bearer token
        2. Parse body
        3. Update config_agent_status with health data
        4. If management_mode == "standalone": return 200 with {config_update: null}
        5. Resolve effective profile for node_id
        6. If no profile assigned: return 200 with {config_update: null}
        7. Check rollout engine: if active rollout exists, call should_distribute()
        8. If current_config_version < profile.version (and rollout allows): return full settings
        9. If current_config_version == profile.version: return {config_update: null}
        10. Record audit log entry for config acknowledgments

    Returns:
        200 with {config_update: {...}} or {config_update: null}
        401 if authentication fails
        400 if request body is invalid

    Requirements: 5.4, 5.5, 5.6, 5.7, 10.2, 10.3, 11.3, 16.3, 16.4, 16.5, 16.6, 16.7, 16.8, 16.9, 16.10
    """
    # 1. Authenticate via Bearer token
    api_key, error_response = _authenticate_bearer_token()
    if error_response is not None:
        return error_response

    # 2. Parse body
    try:
        body = request.get_json(force=True)
    except Exception:
        return jsonify({"error": "invalid_json", "message": "Request body is not valid JSON"}), 400

    if not body or not isinstance(body, dict):
        return jsonify({"error": "invalid_json", "message": "Request body is not valid JSON"}), 400

    node_id = body.get("node_id")
    current_config_version = body.get("current_config_version", 0)
    management_mode = body.get("management_mode", "standalone")
    agent_version = body.get("agent_version")
    health = body.get("health", {})

    if not node_id or not isinstance(node_id, str):
        return jsonify(
            {
                "error": "validation_error",
                "message": "node_id is required and must be a non-empty string",
            }
        ), 400

    # Extract health fields
    health_uptime = health.get("uptime") if isinstance(health, dict) else None
    health_active_rules = health.get("active_rules") if isinstance(health, dict) else None
    health_blocked_ips = health.get("blocked_ips") if isinstance(health, dict) else None

    db = get_request_db()
    # 3. Update config_agent_status with health data
    from datetime import datetime

    now_iso = datetime.now(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")

    status_kwargs = {
        "last_check_in": now_iso,
        "management_mode": management_mode,
    }
    if agent_version is not None:
        status_kwargs["agent_version"] = agent_version
    if health_uptime is not None:
        status_kwargs["health_uptime"] = health_uptime
    if health_active_rules is not None:
        status_kwargs["health_active_rules"] = health_active_rules
    if health_blocked_ips is not None:
        status_kwargs["health_blocked_ips"] = health_blocked_ips

    upsert_agent_config_status(db, node_id, **status_kwargs)

    # Track agent liveness
    update_last_seen(db, node_id)

    # 4. If standalone mode: acknowledge without config data
    if management_mode == "standalone":
        return jsonify({"config_update": None}), 200

    # 5. Resolve effective profile for node_id
    profile = resolve_effective_profile(db, node_id)

    # 6. If no profile assigned: return no update
    if profile is None:
        return jsonify({"config_update": None}), 200

    profile_id = profile["id"]
    profile_version = profile["version"]
    profile_name = profile["name"]

    # Parse settings if stored as JSON string
    settings = profile.get("settings", "{}")
    if isinstance(settings, str):
        settings = json.loads(settings)

    # Determine conflict strategy from profile or default
    conflict_strategy = profile.get("conflict_strategy", "server-wins")

    # 7. Check rollout engine: if active rollout exists, check should_distribute()
    active_rollout = get_active_rollout(db, profile_id)
    rollout_allows = True
    if active_rollout is not None:
        rollout_allows = rollout_engine.should_distribute(active_rollout, node_id)

    # 8. If version differs and rollout allows: return full settings
    if current_config_version != profile_version and rollout_allows:
        # Update agent status to reflect the new version being sent
        upsert_agent_config_status(
            db,
            node_id,
            profile_id=profile_id,
            acknowledged_version=profile_version,
            config_status="up_to_date",
        )

        # 10. Record audit log for config acknowledgment
        record_audit(
            db,
            actor=node_id,
            actor_ip=request.remote_addr,
            action_type="config_ack",
            target=profile_name,
            details={
                "node_id": node_id,
                "version": profile_version,
                "previous_version": current_config_version,
            },
        )

        return jsonify(
            {
                "config_update": {
                    "profile_name": profile_name,
                    "version": profile_version,
                    "settings": settings,
                    "conflict_strategy": conflict_strategy,
                }
            }
        ), 200

    # 9. If version current (or rollout blocks distribution): no update needed
    upsert_agent_config_status(
        db,
        node_id,
        profile_id=profile_id,
        acknowledged_version=current_config_version,
        config_status="up_to_date",
    )

    return jsonify({"config_update": None}), 200


# ---------------------------------------------------------------------------
# Rules Lists endpoint (Bearer token auth) — decoupled from config profiles
# ---------------------------------------------------------------------------


@config_mgmt_bp.get(
    "/rules/lists",
    summary="Rules lists",
    description="Return current allowlist and blocklist from ip_rules table. Used by agents for initial sync. Bearer auth required.",
    security=[{"BearerAuth": []}],
)
@limiter.limit(
    lambda: current_app.config.get("RATELIMIT_CONFIG_CHECKIN", "120 per minute"),
    key_func=_key_func_body_node,
)
def rules_lists():
    """Return current allowlist and blocklist for agent sync."""
    api_key, error_response = _authenticate_bearer_token()
    if error_response is not None:
        return error_response

    db = get_request_db()
    allowlist_rows = list_ip_rules(db, rule_type="allowlist")
    blocklist_rows = list_ip_rules(db, rule_type="blocklist")

    allowlist = [r["entry"] for r in allowlist_rows]
    blocklist = [r["entry"] for r in blocklist_rows]

    updated_at = ""
    for r in allowlist_rows + blocklist_rows:
        ca = str(r["created_at"]) if r["created_at"] else ""
        if ca > updated_at:
            updated_at = ca

    return jsonify(
        {
            "allowlist": allowlist,
            "blocklist": blocklist,
            "updated_at": updated_at,
        }
    ), 200
