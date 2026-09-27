"""Rollout engine and API endpoints for configuration rollouts.

Provides the RolloutEngine class for managing rollout state transitions
and agent targeting, plus Flask blueprint endpoints for creating, promoting,
and cancelling rollouts.

Endpoints:
    POST   /api/v1/config/rollouts              — Create a rollout
    POST   /api/v1/config/rollouts/<id>/promote — Promote rollout stage
    POST   /api/v1/config/rollouts/<id>/cancel  — Cancel rollout

Requirements: 10.1, 10.2, 10.3, 10.4, 10.5, 10.6, 10.7, 10.8, 11.4
"""

import hashlib
import json
import logging

from flask import Blueprint, current_app, jsonify, request
from flask_login import current_user

from app.decorators import require_role
from app.models import (
    create_rollout,
    get_active_rollout,
    get_db,
    record_audit,
    update_rollout_status,
)
from app.rate_limit import limiter

logger = logging.getLogger(__name__)

config_rollout_bp = Blueprint("config_rollout", __name__, url_prefix="/api/v1/config")


# ── Rollout Engine ────────────────────────────────────────────────────────


class RolloutEngine:
    """Manages rollout state transitions and agent targeting.

    Supports three rollout policies:
    - immediate: all assigned agents receive the update
    - canary: only agents in the canary set receive the update
    - staged: percentage-based incremental rollout using deterministic hashing
    """

    def should_distribute(self, rollout: dict, node_id: str) -> bool:
        """Determine if a node should receive the update given rollout policy.

        Args:
            rollout: The rollout record dict (must include policy,
                canary_nodes, current_percentage).
            node_id: The agent's node identifier.

        Returns:
            True if the node should receive the configuration update.
        """
        policy = rollout.get("policy", "immediate")

        if policy == "immediate":
            return True

        if policy == "canary":
            canary_nodes = rollout.get("canary_nodes", "[]")
            if isinstance(canary_nodes, str):
                canary_nodes = json.loads(canary_nodes)
            return node_id in canary_nodes

        if policy == "staged":
            percentage = rollout.get("current_percentage", 100)
            # Use hash of node_id for deterministic selection
            hash_val = int(hashlib.sha256(node_id.encode()).hexdigest(), 16)
            # Map to 0-99 range
            bucket = hash_val % 100
            return bucket < percentage

        # Unknown policy — don't distribute
        return False

    def check_failure_threshold(self, db, rollout_id: int) -> bool:
        """Check if >50% of targeted agents reported failure.

        Args:
            db: An open SQLite connection.
            rollout_id: The rollout to check.

        Returns:
            True if the failure threshold is exceeded (rollout should fail).
        """
        row = db.execute(
            "SELECT failure_count, success_count, total_targeted FROM config_rollouts WHERE id = ?",
            (rollout_id,),
        ).fetchone()

        if row is None:
            return False

        failure_count = row["failure_count"]
        total_targeted = row["total_targeted"]

        # Need at least one targeted agent to evaluate threshold
        if total_targeted <= 0:
            # Fall back to success + failure as total if total_targeted not set
            total = failure_count + row["success_count"]
            if total <= 0:
                return False
            return failure_count > (total / 2)

        return failure_count > (total_targeted / 2)

    def promote(self, db, rollout_id: int, next_percentage: int | None = None) -> dict:
        """Advance a staged rollout or promote canary to full.

        For canary rollouts: sets policy to immediate, status to in_progress.
        For staged rollouts: updates current_percentage to next_percentage.

        Args:
            db: An open SQLite connection.
            rollout_id: The rollout to promote.
            next_percentage: For staged rollouts, the next target percentage.

        Returns:
            The updated rollout record as a dict.

        Raises:
            ValueError: If the rollout cannot be promoted.
        """
        row = db.execute(
            "SELECT * FROM config_rollouts WHERE id = ?",
            (rollout_id,),
        ).fetchone()

        if row is None:
            raise ValueError(f"Rollout {rollout_id} not found")

        rollout = dict(row)
        policy = rollout["policy"]
        status = rollout["status"]

        if status not in ("pending", "in_progress"):
            raise ValueError(f"Cannot promote rollout in '{status}' status")

        if policy == "canary":
            # Promote canary to full distribution
            db.execute(
                "UPDATE config_rollouts SET policy = 'immediate', "
                "status = 'in_progress', current_percentage = 100 "
                "WHERE id = ?",
                (rollout_id,),
            )
            db.commit()

        elif policy == "staged":
            if next_percentage is None:
                next_percentage = 100
            if next_percentage < 1 or next_percentage > 100:
                raise ValueError("next_percentage must be between 1 and 100")
            new_status = "in_progress"
            if next_percentage == 100:
                new_status = "in_progress"  # Will complete when all ack
            db.execute(
                "UPDATE config_rollouts SET current_percentage = ?, status = ? WHERE id = ?",
                (next_percentage, new_status, rollout_id),
            )
            db.commit()

        elif policy == "immediate":
            raise ValueError("Cannot promote an immediate rollout")

        # Return updated record
        updated = db.execute(
            "SELECT * FROM config_rollouts WHERE id = ?",
            (rollout_id,),
        ).fetchone()
        return dict(updated)


# Module-level engine instance
rollout_engine = RolloutEngine()


# ── API Endpoints ─────────────────────────────────────────────────────────


@config_rollout_bp.route("/rollouts", methods=["POST"])
@require_role("admin")
@limiter.limit("30/minute")
def create_rollout_endpoint():
    """Create a new configuration rollout.

    Body:
        profile_id (int, required): The profile to roll out.
        policy (str, optional): 'immediate', 'canary', or 'staged'. Default: 'immediate'.
        canary_nodes (list[str], optional): Node IDs for canary rollout.
        initial_percentage (int, optional): Starting percentage for staged rollout.

    Returns:
        201: The created rollout record.
        400: Invalid request body.
        404: Profile not found.
        409: Active rollout already exists for this profile.
        422: Validation error.
    """
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"error": "invalid_json", "message": "Request body must be valid JSON"}), 400

    profile_id = data.get("profile_id")
    if profile_id is None:
        return jsonify({"error": "missing_fields", "fields": ["profile_id"]}), 400

    try:
        profile_id = int(profile_id)
    except (TypeError, ValueError):
        return jsonify(
            {"error": "validation_error", "message": "profile_id must be an integer"}
        ), 422

    policy = data.get("policy", "immediate")
    if policy not in ("immediate", "canary", "staged"):
        return jsonify(
            {
                "error": "validation_error",
                "message": f"Invalid policy '{policy}'. Must be 'immediate', 'canary', or 'staged'",
            }
        ), 422

    canary_nodes = data.get("canary_nodes", [])
    initial_percentage = data.get("initial_percentage", 100 if policy != "staged" else 25)

    # Validate canary-specific fields
    if policy == "canary":
        if not canary_nodes or not isinstance(canary_nodes, list):
            return jsonify(
                {
                    "error": "validation_error",
                    "message": "canary_nodes must be a non-empty list for canary policy",
                }
            ), 422

    # Validate staged-specific fields
    if policy == "staged":
        try:
            initial_percentage = int(initial_percentage)
        except (TypeError, ValueError):
            return jsonify(
                {
                    "error": "validation_error",
                    "message": "initial_percentage must be an integer",
                }
            ), 422
        if initial_percentage < 1 or initial_percentage > 99:
            return jsonify(
                {
                    "error": "validation_error",
                    "message": "initial_percentage must be between 1 and 99 for staged rollouts",
                }
            ), 422

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        # Verify profile exists and is active
        profile = db.execute(
            "SELECT id, version, name FROM config_profiles WHERE id = ? AND is_active = 1",
            (profile_id,),
        ).fetchone()
        if profile is None:
            return jsonify({"error": "not_found", "message": "Profile not found"}), 404

        # Check for existing active rollout
        active = get_active_rollout(db, profile_id)
        if active is not None:
            return jsonify(
                {
                    "error": "conflict",
                    "message": "An active rollout already exists for this profile",
                }
            ), 409

        # Create the rollout
        target_version = profile["version"]
        rollout = create_rollout(
            db,
            profile_id=profile_id,
            target_version=target_version,
            created_by=current_user.username,
            policy=policy,
            canary_nodes=canary_nodes if policy == "canary" else None,
            current_percentage=initial_percentage if policy == "staged" else 100,
        )

        # For immediate rollouts, set status to in_progress right away
        if policy == "immediate":
            update_rollout_status(db, rollout["id"], "in_progress")
            rollout["status"] = "in_progress"

        # Record audit log
        actor_ip = request.remote_addr
        record_audit(
            db,
            actor=current_user.username,
            actor_ip=actor_ip,
            action_type="config_rollout_create",
            target=profile["name"],
            details={
                "rollout_id": rollout["id"],
                "profile_id": profile_id,
                "policy": policy,
                "target_version": target_version,
                "canary_nodes": canary_nodes if policy == "canary" else [],
                "initial_percentage": initial_percentage if policy == "staged" else 100,
            },
        )

        # Parse canary_nodes JSON string in response
        if isinstance(rollout.get("canary_nodes"), str):
            rollout["canary_nodes"] = json.loads(rollout["canary_nodes"])

        # --- SSE push: for immediate rollouts, push to all assigned agents ---
        if policy == "immediate":
            _publish_rollout_sse(db, profile_id, profile)

        return jsonify(rollout), 201

    finally:
        db.close()


@config_rollout_bp.route("/rollouts/<int:rollout_id>/promote", methods=["POST"])
@require_role("admin")
@limiter.limit("30/minute")
def promote_rollout_endpoint(rollout_id: int):
    """Promote a rollout to the next stage.

    For canary rollouts: promotes to full distribution (immediate).
    For staged rollouts: advances to the next percentage.

    Body:
        next_percentage (int, optional): Target percentage for staged rollouts.

    Returns:
        200: The updated rollout record.
        400: Invalid request.
        404: Rollout not found.
        422: Cannot promote (wrong state or policy).
    """
    data = request.get_json(silent=True) or {}
    next_percentage = data.get("next_percentage")

    if next_percentage is not None:
        try:
            next_percentage = int(next_percentage)
        except (TypeError, ValueError):
            return jsonify(
                {
                    "error": "validation_error",
                    "message": "next_percentage must be an integer",
                }
            ), 422

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        # Get the rollout
        row = db.execute(
            "SELECT * FROM config_rollouts WHERE id = ?",
            (rollout_id,),
        ).fetchone()
        if row is None:
            return jsonify({"error": "not_found", "message": "Rollout not found"}), 404

        rollout = dict(row)
        previous_stage = rollout["policy"]
        previous_percentage = rollout["current_percentage"]

        try:
            updated = rollout_engine.promote(db, rollout_id, next_percentage)
        except ValueError as e:
            logger.error("Rollout promote failed for rollout %s: %s", rollout_id, e)
            return jsonify(
                {"error": "validation_error", "message": "Invalid rollout promotion parameters"}
            ), 422

        # Determine new stage description for audit
        if previous_stage == "canary":
            new_stage = "full"
        else:
            new_stage = f"{updated['current_percentage']}%"

        # Get profile name for audit
        profile = db.execute(
            "SELECT name FROM config_profiles WHERE id = ?",
            (updated["profile_id"],),
        ).fetchone()
        profile_name = profile["name"] if profile else f"profile_{updated['profile_id']}"

        # Count targeted agents in new stage
        targeted_count = _count_targeted_agents(db, updated)

        # Record audit log
        actor_ip = request.remote_addr
        record_audit(
            db,
            actor=current_user.username,
            actor_ip=actor_ip,
            action_type="config_rollout_promote",
            target=profile_name,
            details={
                "rollout_id": rollout_id,
                "previous_stage": f"{previous_percentage}%"
                if previous_stage == "staged"
                else "canary",
                "new_stage": new_stage,
                "agents_targeted": targeted_count,
            },
        )

        # Parse canary_nodes JSON string in response
        if isinstance(updated.get("canary_nodes"), str):
            updated["canary_nodes"] = json.loads(updated["canary_nodes"])

        return jsonify(updated), 200

    finally:
        db.close()


@config_rollout_bp.route("/rollouts/<int:rollout_id>/cancel", methods=["POST"])
@require_role("admin")
@limiter.limit("30/minute")
def cancel_rollout_endpoint(rollout_id: int):
    """Cancel an in-progress rollout.

    Sets the rollout status to 'cancelled'. Agents that already received
    the update retain it.

    Returns:
        200: The updated rollout record.
        404: Rollout not found.
        422: Cannot cancel (already in terminal state).
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        # Get the rollout
        row = db.execute(
            "SELECT * FROM config_rollouts WHERE id = ?",
            (rollout_id,),
        ).fetchone()
        if row is None:
            return jsonify({"error": "not_found", "message": "Rollout not found"}), 404

        rollout = dict(row)
        if rollout["status"] in ("completed", "cancelled", "failed"):
            return jsonify(
                {
                    "error": "validation_error",
                    "message": f"Cannot cancel rollout in '{rollout['status']}' status",
                }
            ), 422

        # Cancel the rollout
        update_rollout_status(db, rollout_id, "cancelled")

        # Get profile name for audit
        profile = db.execute(
            "SELECT name FROM config_profiles WHERE id = ?",
            (rollout["profile_id"],),
        ).fetchone()
        profile_name = profile["name"] if profile else f"profile_{rollout['profile_id']}"

        # Record audit log
        actor_ip = request.remote_addr
        record_audit(
            db,
            actor=current_user.username,
            actor_ip=actor_ip,
            action_type="config_rollout_cancel",
            target=profile_name,
            details={
                "rollout_id": rollout_id,
                "previous_status": rollout["status"],
                "policy": rollout["policy"],
            },
        )

        # Return updated record
        updated = db.execute(
            "SELECT * FROM config_rollouts WHERE id = ?",
            (rollout_id,),
        ).fetchone()
        result = dict(updated)
        if isinstance(result.get("canary_nodes"), str):
            result["canary_nodes"] = json.loads(result["canary_nodes"])

        return jsonify(result), 200

    finally:
        db.close()


# ── Helpers ───────────────────────────────────────────────────────────────


def _count_targeted_agents(db, rollout: dict) -> int:
    """Count the number of agents targeted in the current rollout stage.

    Args:
        db: An open SQLite connection.
        rollout: The rollout record dict.

    Returns:
        The count of targeted agents.
    """
    profile_id = rollout["profile_id"]

    # Get all agents assigned to this profile (direct + group)
    direct_nodes = db.execute(
        "SELECT node_id FROM config_assignments "
        "WHERE profile_id = ? AND is_active = 1 AND node_id IS NOT NULL",
        (profile_id,),
    ).fetchall()

    group_nodes = db.execute(
        "SELECT DISTINCT agm.node_id FROM agent_group_members agm "
        "JOIN config_assignments ca ON ca.group_id = agm.group_id "
        "WHERE ca.profile_id = ? AND ca.is_active = 1",
        (profile_id,),
    ).fetchall()

    all_nodes = set()
    for row in direct_nodes:
        all_nodes.add(row["node_id"])
    for row in group_nodes:
        all_nodes.add(row["node_id"])

    policy = rollout.get("policy", "immediate")

    if policy == "immediate":
        return len(all_nodes)
    elif policy == "canary":
        canary_nodes = rollout.get("canary_nodes", "[]")
        if isinstance(canary_nodes, str):
            canary_nodes = json.loads(canary_nodes)
        return len(set(canary_nodes) & all_nodes)
    elif policy == "staged":
        # For staged, count nodes that fall within the percentage bucket
        percentage = rollout.get("current_percentage", 100)
        count = 0
        for node_id in all_nodes:
            hash_val = int(hashlib.sha256(node_id.encode()).hexdigest(), 16)
            if (hash_val % 100) < percentage:
                count += 1
        return count

    return len(all_nodes)


def _publish_rollout_sse(db, profile_id: int, profile_row) -> None:
    """Push a config_updated SSE event when an immediate rollout is created.

    For immediate rollouts, all assigned agents should receive the update
    immediately (target_nodes=None pushes to all connected clients).

    Args:
        db: An open SQLite connection.
        profile_id: The profile being rolled out.
        profile_row: The profile database row (must have name, version).
    """
    try:
        config_sse = current_app.config_sse_manager
    except AttributeError:
        # SSE manager not initialized (e.g., during testing without full app setup)
        logger.debug("config_sse_manager not available, skipping SSE publish")
        return

    # Get the full profile settings for the event payload
    settings_row = db.execute(
        "SELECT settings FROM config_profiles WHERE id = ? AND is_active = 1",
        (profile_id,),
    ).fetchone()

    if settings_row is None:
        return

    settings = settings_row["settings"]
    if isinstance(settings, str):
        settings = json.loads(settings)

    event_data = {
        "profile_name": profile_row["name"],
        "version": profile_row["version"],
        "settings": settings,
        "updated_at": "",  # Rollout creation doesn't change updated_at
        "conflict_strategy": "server-wins",
    }

    # For immediate rollouts, push to all connected clients (target_nodes=None)
    config_sse.publish_to_profile(profile_id, event_data, target_nodes=None)
    logger.info(
        "Published config_updated SSE event for immediate rollout of profile %d (version %d)",
        profile_id,
        profile_row["version"],
    )
