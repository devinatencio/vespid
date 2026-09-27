"""Config Dashboard blueprint — admin UI for centralized configuration management.

Provides web pages and HTMX fragments for managing configuration profiles,
agent groups, assignments, and rollouts. Reads query the database directly;
mutations are proxied through the Config Management API endpoints.

Endpoints:
    GET  /admin/config                              — Config management page
    GET  /admin/config/fragments/profile-list       — Profile list fragment (HTMX)
    GET  /admin/config/fragments/profile-detail/<id> — Profile detail fragment (HTMX)
    GET  /admin/config/fragments/group-list         — Group list fragment (HTMX)
    GET  /admin/config/fragments/group-detail/<id>  — Group detail fragment (HTMX)
    GET  /admin/config/fragments/assignment-list/<id> — Assignment list fragment (HTMX)
    GET  /admin/config/fragments/history/<id>       — Version history fragment (HTMX)
    GET  /admin/config/fragments/rollout-list/<id>  — Rollout list fragment (HTMX)

    POST /admin/config/profiles                     — Create profile (form)
    POST /admin/config/profiles/<id>/update         — Update profile (form)
    POST /admin/config/profiles/<id>/delete         — Delete profile (form)
    POST /admin/config/assignments                  — Create assignment (form)
    POST /admin/config/assignments/<id>/delete      — Delete assignment (form)
    POST /admin/config/groups                       — Create group (form)
    POST /admin/config/groups/<id>/delete           — Delete group (form)
    POST /admin/config/groups/<id>/members          — Add member (form)
    POST /admin/config/groups/<id>/members/<node_id>/remove — Remove member (form)
    POST /admin/config/rollouts                     — Create rollout (form)
    POST /admin/config/rollouts/<id>/promote        — Promote rollout (form)
    POST /admin/config/rollouts/<id>/cancel         — Cancel rollout (form)

Requirements: 2.1, 3.1, 4.1, 4.5, 9.1, 10.1, 11.1, 11.5
"""

import json
import logging

from flask import (
    Blueprint,
    current_app,
    flash,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import current_user

from app.config_validation import ConfigValidator
from app.decorators import require_role
from app.models import (
    add_group_member,
    create_agent_group,
    create_assignment,
    create_config_profile,
    create_rollout,
    deactivate_assignment,
    delete_agent_group,
    get_config_profile,
    get_db,
    list_agent_groups,
    list_assignments_for_profile,
    list_config_profiles,
    list_feed_catalog,
    list_version_history,
    record_audit,
    remove_group_member,
    soft_delete_config_profile,
    update_config_profile,
)
from app.pack_loader import get_pack_metadata, load_packs
from app.routes.config_rollout import rollout_engine

logger = logging.getLogger(__name__)

config_dashboard_bp = Blueprint(
    "config_dashboard",
    __name__,
    url_prefix="/admin/config",
    template_folder="templates",
)

_validator = ConfigValidator()


# ── Helper functions ─────────────────────────────────────────────────────

# Category labels for managed keys display
_KEY_CATEGORIES = {
    "brute_force_rules": "Detection",
    "custom_rules": "Detection",
    "subscriptions": "Feeds",
    "nft_local_block_ttl": "Network",
    "excluded_http_paths": "Network",
    "flush_interval_seconds": "Telemetry",
    "flush_batch_size": "Telemetry",
    "heartbeat_interval_seconds": "Telemetry",
    "fleet_blocklist_report_enabled": "Fleet",
    "fleet_blocklist_subscribe_enabled": "Fleet",
    "fleet_block_ttl_seconds": "Fleet",
    "fleet_local_allow_list": "Fleet",
    "log_sources": "Log Sources",
    "detection_pack_mode": "Detection Packs",
    "detection_packs": "Detection Packs",
    "auditd": "Auditd Monitoring",
}


def _managed_keys_summary(profile: dict) -> str:
    """Generate a human-readable summary of which categories a profile manages."""
    settings = profile.get("settings", "{}")
    if isinstance(settings, str):
        try:
            settings = json.loads(settings)
        except (json.JSONDecodeError, TypeError):
            return "—"
    if not settings:
        return "—"
    categories = set()
    for key in settings:
        cat = _KEY_CATEGORIES.get(key, key)
        categories.add(cat)
    return ", ".join(sorted(categories))


def _get_assignment_count(db, profile_id: int) -> int:
    """Count active assignments for a profile."""
    row = db.execute(
        "SELECT COUNT(*) FROM config_assignments WHERE profile_id = ? AND is_active = 1",
        (profile_id,),
    ).fetchone()
    return row[0] if row else 0


def _get_group_members(db, group_id: int) -> list:
    """Get members of a group."""
    rows = db.execute(
        "SELECT * FROM agent_group_members WHERE group_id = ? ORDER BY added_at DESC",
        (group_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def _get_group_assignment(db, group_id: int) -> dict | None:
    """Get the active profile assignment for a group."""
    row = db.execute(
        "SELECT ca.*, cp.name as profile_name FROM config_assignments ca "
        "JOIN config_profiles cp ON ca.profile_id = cp.id "
        "WHERE ca.group_id = ? AND ca.is_active = 1 "
        "ORDER BY ca.assigned_at DESC LIMIT 1",
        (group_id,),
    ).fetchone()
    return dict(row) if row else None


def _get_rollouts_for_profile(db, profile_id: int) -> list:
    """Get rollouts for a profile, ordered by most recent first."""
    rows = db.execute(
        "SELECT * FROM config_rollouts WHERE profile_id = ? ORDER BY created_at DESC LIMIT 10",
        (profile_id,),
    ).fetchall()
    return [dict(r) for r in rows]


def _get_enrolled_agents(db, security_only: bool = False) -> list:
    """Get list of enrolled agent node_ids.

    Args:
        security_only: If True, only return security agents (agents present in
            the nodes table). Monitor-only agents handle config check-in and
            cannot be assigned configuration profiles.

    Returns:
        A list of dicts with node_id and hostname keys.
    """
    sql = (
        "SELECT DISTINCT er.node_id, er.hostname FROM enrollment_requests er "
        "WHERE er.status = 'approved'"
    )
    if security_only:
        sql = (
            "SELECT DISTINCT er.node_id, er.hostname FROM enrollment_requests er "
            "JOIN nodes n ON n.node_id = er.node_id "
            "WHERE er.status = 'approved'"
        )
    try:
        rows = db.execute(sql + " ORDER BY er.node_id").fetchall()
        return [dict(r) for r in rows]
    except Exception:
        logger.warning("Could not query enrollment_requests table (test env?)", exc_info=True)
        return []


# ── Main Page ────────────────────────────────────────────────────────────


@config_dashboard_bp.route("/", methods=["GET"])
@require_role("admin")
def config_page():
    """Display the configuration management admin page.

    Requirements: 2.1, 11.5
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        result = list_config_profiles(db, page=1, per_page=100)
        profiles = result["profiles"]

        # Enrich profiles with assignment counts
        for p in profiles:
            p["assignment_count"] = _get_assignment_count(db, p["id"])
            p["managed_keys_summary"] = _managed_keys_summary(p)

        groups_result = list_agent_groups(db, page=1, per_page=100)
        groups = groups_result["groups"]

        # Enrich groups with member counts and assignment info
        for g in groups:
            members = _get_group_members(db, g["id"])
            g["member_count"] = len(members)
            assignment = _get_group_assignment(db, g["id"])
            g["profile_assignment"] = assignment

        enrolled_agents = _get_enrolled_agents(db)
    finally:
        db.close()

    # Load available detection packs for the pack selector
    available_packs = get_pack_metadata(load_packs())

    # Load feed catalog for the feed picker
    db = get_db(db_path)
    try:
        feed_catalog = list_feed_catalog(db)
    finally:
        db.close()

    return render_template(
        "admin/config_management.html",
        profiles=profiles,
        groups=groups,
        enrolled_agents=enrolled_agents,
        available_packs=available_packs,
        feed_catalog=feed_catalog,
    )


# ── HTMX Fragment Endpoints ──────────────────────────────────────────────


@config_dashboard_bp.route("/fragments/profile-list", methods=["GET"])
@require_role("admin")
def fragment_profile_list():
    """Return the profile list table as an HTMX fragment."""
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        result = list_config_profiles(db, page=1, per_page=100)
        profiles = result["profiles"]
        for p in profiles:
            p["assignment_count"] = _get_assignment_count(db, p["id"])
            p["managed_keys_summary"] = _managed_keys_summary(p)
    finally:
        db.close()

    return render_template(
        "admin/_config_profile_list.html",
        profiles=profiles,
    )


@config_dashboard_bp.route("/fragments/profile-detail/<int:profile_id>", methods=["GET"])
@require_role("admin")
def fragment_profile_detail(profile_id):
    """Return profile detail panel as an HTMX fragment."""
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        profile = get_config_profile(db, profile_id)
        if not profile:
            return "<p>Profile not found.</p>", 404

        assignments = list_assignments_for_profile(db, profile_id, page=1, per_page=50)
        history = list_version_history(db, profile_id, page=1, per_page=10)
        rollouts = _get_rollouts_for_profile(db, profile_id)
        enrolled_agents = _get_enrolled_agents(db, security_only=True)
        groups_result = list_agent_groups(db, page=1, per_page=100)

        # Resolve friendly names for assignment targets (hostnames / group names)
        hostname_map = {
            a["node_id"]: a["hostname"]
            for a in _get_enrolled_agents(db)
            if a.get("node_id") and a.get("hostname")
        }
        group_name_map = {g["id"]: g["name"] for g in groups_result["groups"]}
        for a in assignments["assignments"]:
            if a.get("node_id"):
                a["node_display"] = hostname_map.get(a["node_id"], a["node_id"])
            elif a.get("group_id"):
                a["group_name"] = group_name_map.get(a["group_id"])
    finally:
        db.close()

    settings = profile.get("settings", "{}")
    if isinstance(settings, str):
        try:
            settings = json.loads(settings)
        except (json.JSONDecodeError, TypeError):
            settings = {}

    # Load available detection packs for the pack selector
    available_packs = get_pack_metadata(load_packs())

    # Load feed catalog for the feed picker
    db = get_db(db_path)
    try:
        feed_catalog = list_feed_catalog(db)
    finally:
        db.close()

    return render_template(
        "admin/_config_profile_detail.html",
        profile=profile,
        settings=settings,
        assignments=assignments,
        history=history,
        rollouts=rollouts,
        enrolled_agents=enrolled_agents,
        groups=groups_result["groups"],
        available_packs=available_packs,
        feed_catalog=feed_catalog,
    )


@config_dashboard_bp.route("/fragments/group-list", methods=["GET"])
@require_role("admin")
def fragment_group_list():
    """Return the group list as an HTMX fragment."""
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        groups_result = list_agent_groups(db, page=1, per_page=100)
        groups = groups_result["groups"]
        for g in groups:
            members = _get_group_members(db, g["id"])
            g["member_count"] = len(members)
            assignment = _get_group_assignment(db, g["id"])
            g["profile_assignment"] = assignment
    finally:
        db.close()

    return render_template(
        "admin/_config_group_list.html",
        groups=groups,
    )


@config_dashboard_bp.route("/fragments/group-detail/<int:group_id>", methods=["GET"])
@require_role("admin")
def fragment_group_detail(group_id):
    """Return group detail panel as an HTMX fragment."""
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        group = db.execute("SELECT * FROM agent_groups WHERE id = ?", (group_id,)).fetchone()
        if not group:
            return "<p>Group not found.</p>", 404
        group = dict(group)
        members = _get_group_members(db, group_id)
        assignment = _get_group_assignment(db, group_id)
        enrolled_agents = _get_enrolled_agents(db, security_only=True)
    finally:
        db.close()

    return render_template(
        "admin/_config_group_detail.html",
        group=group,
        members=members,
        assignment=assignment,
        enrolled_agents=enrolled_agents,
    )


# ── Profile CRUD (Form Submissions) ─────────────────────────────────────


@config_dashboard_bp.route("/profiles", methods=["POST"])
@require_role("admin")
def create_profile():
    """Create a new configuration profile from form submission.

    Requirements: 2.1
    """
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()
    settings_raw = request.form.get("settings", "{}").strip()

    if not name:
        flash("Profile name is required.", "error")
        return redirect(url_for("config_dashboard.config_page"))

    try:
        settings = json.loads(settings_raw)
    except (json.JSONDecodeError, TypeError):
        flash("Settings must be valid JSON.", "error")
        return redirect(url_for("config_dashboard.config_page"))

    if not isinstance(settings, dict) or not settings:
        flash("Settings must be a non-empty JSON object.", "error")
        return redirect(url_for("config_dashboard.config_page"))

    # Validate settings
    errors = _validator.validate_settings(settings)
    if errors:
        flash(f"Validation errors: {'; '.join(errors)}", "error")
        return redirect(url_for("config_dashboard.config_page"))

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        try:
            profile = create_config_profile(
                db,
                name=name,
                description=description,
                settings=settings,
                created_by=current_user.username,
            )
        except Exception as e:
            logger.exception("Failed to create profile '%s'", name)
            flash(f"Failed to create profile: {e}", "error")
            return redirect(url_for("config_dashboard.config_page"))

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="config_profile_create",
            target=name,
            details={"profile_id": profile["id"], "settings_keys": list(settings.keys())},
        )
    finally:
        db.close()

    flash(f"Profile '{name}' created successfully.", "success")
    return redirect(url_for("config_dashboard.config_page"))


@config_dashboard_bp.route("/profiles/<int:profile_id>/update", methods=["POST"])
@require_role("admin")
def update_profile(profile_id):
    """Update a configuration profile from form submission.

    Requirements: 2.1
    """
    name = request.form.get("name", "").strip() or None
    description = request.form.get("description", "").strip() or None
    settings_raw = request.form.get("settings", "").strip()
    change_reason = request.form.get("change_reason", "").strip()

    if not change_reason:
        flash("Change reason is required.", "error")
        return redirect(url_for("config_dashboard.config_page"))

    settings = None
    if settings_raw:
        try:
            settings = json.loads(settings_raw)
        except (json.JSONDecodeError, TypeError):
            flash("Settings must be valid JSON.", "error")
            return redirect(url_for("config_dashboard.config_page"))

        if not isinstance(settings, dict) or not settings:
            flash("Settings must be a non-empty JSON object.", "error")
            return redirect(url_for("config_dashboard.config_page"))

        errors = _validator.validate_settings(settings)
        if errors:
            flash(f"Validation errors: {'; '.join(errors)}", "error")
            return redirect(url_for("config_dashboard.config_page"))

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        updated = update_config_profile(
            db,
            profile_id,
            name=name,
            description=description,
            settings=settings,
            changed_by=current_user.username,
            change_reason=change_reason,
        )
        if not updated:
            flash("Profile not found.", "error")
            return redirect(url_for("config_dashboard.config_page"))

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="config_profile_update",
            target=updated["name"],
            details={"profile_id": profile_id, "new_version": updated["version"]},
        )

        # Publish SSE update to connected agents
        from app.routes.config_management import _publish_profile_update_sse

        _publish_profile_update_sse(db, profile_id, updated)
    finally:
        db.close()

    flash(f"Profile updated to version {updated['version']}.", "success")
    return redirect(url_for("config_dashboard.config_page"))


@config_dashboard_bp.route("/profiles/<int:profile_id>/delete", methods=["POST"])
@require_role("admin")
def delete_profile(profile_id):
    """Soft-delete a configuration profile.

    Requirements: 2.1
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        profile = get_config_profile(db, profile_id)
        if not profile:
            flash("Profile not found.", "error")
            return redirect(url_for("config_dashboard.config_page"))

        soft_delete_config_profile(db, profile_id)

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="config_profile_delete",
            target=profile["name"],
            details={"profile_id": profile_id},
        )
    finally:
        db.close()

    flash(f"Profile '{profile['name']}' deleted.", "success")
    return redirect(url_for("config_dashboard.config_page"))


# ── Assignment Management ────────────────────────────────────────────────


@config_dashboard_bp.route("/assignments", methods=["POST"])
@require_role("admin")
def create_assignment_form():
    """Create a profile assignment from form submission.

    Requirements: 3.1
    """
    profile_id = request.form.get("profile_id", type=int)
    node_id = request.form.get("node_id", "").strip() or None
    group_id = request.form.get("group_id", type=int) or None

    if not profile_id:
        flash("Profile ID is required.", "error")
        return redirect(url_for("config_dashboard.config_page"))

    if not node_id and not group_id:
        flash("Either a node ID or group ID is required.", "error")
        return redirect(url_for("config_dashboard.config_page"))

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        try:
            assignment = create_assignment(
                db,
                profile_id=profile_id,
                node_id=node_id,
                group_id=group_id,
                assigned_by=current_user.username,
            )
        except Exception as e:
            logger.exception("Failed to create profile assignment")
            flash(f"Failed to create assignment: {e}", "error")
            return redirect(url_for("config_dashboard.config_page"))

        target = node_id or f"group:{group_id}"
        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="config_assignment_create",
            target=target,
            details={"profile_id": profile_id, "assignment_id": assignment["id"]},
        )
    finally:
        db.close()

    flash("Assignment created successfully.", "success")
    return redirect(url_for("config_dashboard.config_page"))


@config_dashboard_bp.route("/assignments/<int:assignment_id>/delete", methods=["POST"])
@require_role("admin")
def delete_assignment_form(assignment_id):
    """Delete (deactivate) a profile assignment.

    Requirements: 3.1
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        deactivate_assignment(db, assignment_id)

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="config_assignment_delete",
            target=str(assignment_id),
            details={"assignment_id": assignment_id},
        )
    finally:
        db.close()

    flash("Assignment removed.", "success")
    return redirect(url_for("config_dashboard.config_page"))


# ── Group Management ─────────────────────────────────────────────────────


@config_dashboard_bp.route("/groups", methods=["POST"])
@require_role("admin")
def create_group():
    """Create a new agent group from form submission.

    Requirements: 4.1
    """
    name = request.form.get("name", "").strip()
    description = request.form.get("description", "").strip()

    if not name:
        flash("Group name is required.", "error")
        return redirect(url_for("config_dashboard.config_page"))

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        try:
            group = create_agent_group(
                db,
                name=name,
                description=description,
                created_by=current_user.username,
            )
        except Exception as e:
            logger.exception("Failed to create group")
            flash(f"Failed to create group: {e}", "error")
            return redirect(url_for("config_dashboard.config_page"))

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="config_group_create",
            target=name,
            details={"group_id": group["id"]},
        )
    finally:
        db.close()

    flash(f"Group '{name}' created.", "success")
    return redirect(url_for("config_dashboard.config_page"))


@config_dashboard_bp.route("/groups/<int:group_id>/delete", methods=["POST"])
@require_role("admin")
def delete_group(group_id):
    """Delete an agent group.

    Requirements: 4.1
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        group = db.execute("SELECT * FROM agent_groups WHERE id = ?", (group_id,)).fetchone()
        if not group:
            flash("Group not found.", "error")
            return redirect(url_for("config_dashboard.config_page"))

        delete_agent_group(db, group_id)

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="config_group_delete",
            target=group["name"],
            details={"group_id": group_id},
        )
    finally:
        db.close()

    flash(f"Group '{group['name']}' deleted.", "success")
    return redirect(url_for("config_dashboard.config_page"))


@config_dashboard_bp.route("/groups/<int:group_id>/members", methods=["POST"])
@require_role("admin")
def add_member(group_id):
    """Add an agent to a group.

    Requirements: 4.5
    """
    node_id = request.form.get("node_id", "").strip()

    if not node_id:
        flash("Node ID is required.", "error")
        return redirect(url_for("config_dashboard.config_page"))

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        try:
            add_group_member(
                db,
                group_id=group_id,
                node_id=node_id,
                added_by=current_user.username,
            )
        except Exception as e:
            logger.exception("Failed to add group member")
            flash(f"Failed to add member: {e}", "error")
            return redirect(url_for("config_dashboard.config_page"))

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="config_group_member_add",
            target=node_id,
            details={"group_id": group_id},
        )
    finally:
        db.close()

    flash(f"Agent '{node_id}' added to group.", "success")
    return redirect(url_for("config_dashboard.config_page"))


@config_dashboard_bp.route("/groups/<int:group_id>/members/<node_id>/remove", methods=["POST"])
@require_role("admin")
def remove_member(group_id, node_id):
    """Remove an agent from a group.

    Requirements: 4.5
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        remove_group_member(db, group_id=group_id, node_id=node_id)

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="config_group_member_remove",
            target=node_id,
            details={"group_id": group_id},
        )
    finally:
        db.close()

    flash(f"Agent '{node_id}' removed from group.", "success")
    return redirect(url_for("config_dashboard.config_page"))


# ── Rollout Management ───────────────────────────────────────────────────


@config_dashboard_bp.route("/rollouts", methods=["POST"])
@require_role("admin")
def create_rollout_form():
    """Create a new rollout from form submission.

    Requirements: 10.1
    """
    profile_id = request.form.get("profile_id", type=int)
    policy = request.form.get("policy", "immediate").strip()
    canary_nodes_raw = request.form.get("canary_nodes", "").strip()

    if not profile_id:
        flash("Profile ID is required.", "error")
        return redirect(url_for("config_dashboard.config_page"))

    if policy not in ("immediate", "canary", "staged"):
        flash("Invalid rollout policy.", "error")
        return redirect(url_for("config_dashboard.config_page"))

    canary_nodes = []
    if canary_nodes_raw and policy == "canary":
        canary_nodes = [n.strip() for n in canary_nodes_raw.split(",") if n.strip()]

    initial_percentage = request.form.get("initial_percentage", type=int) or 100

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        profile = get_config_profile(db, profile_id)
        if not profile:
            flash("Profile not found.", "error")
            return redirect(url_for("config_dashboard.config_page"))

        try:
            rollout = create_rollout(
                db,
                profile_id=profile_id,
                target_version=profile["version"],
                policy=policy,
                canary_nodes=canary_nodes,
                current_percentage=initial_percentage if policy == "staged" else 100,
                created_by=current_user.username,
            )
        except Exception as e:
            logger.exception("Failed to create rollout")
            flash(f"Failed to create rollout: {e}", "error")
            return redirect(url_for("config_dashboard.config_page"))

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="config_rollout_create",
            target=profile["name"],
            details={"rollout_id": rollout["id"], "policy": policy},
        )
    finally:
        db.close()

    flash(f"Rollout created for profile '{profile['name']}' (policy: {policy}).", "success")
    return redirect(url_for("config_dashboard.config_page"))


@config_dashboard_bp.route("/rollouts/<int:rollout_id>/promote", methods=["POST"])
@require_role("admin")
def promote_rollout(rollout_id):
    """Promote a rollout to the next stage.

    Requirements: 10.1
    """
    next_percentage = request.form.get("next_percentage", type=int)

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        try:
            result = rollout_engine.promote(db, rollout_id, next_percentage)
        except (ValueError, Exception) as e:
            flash(f"Failed to promote rollout: {e}", "error")
            return redirect(url_for("config_dashboard.config_page"))

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="config_rollout_promote",
            target=str(rollout_id),
            details={"new_percentage": result.get("current_percentage")},
        )
    finally:
        db.close()

    flash("Rollout promoted.", "success")
    return redirect(url_for("config_dashboard.config_page"))


@config_dashboard_bp.route("/rollouts/<int:rollout_id>/cancel", methods=["POST"])
@require_role("admin")
def cancel_rollout(rollout_id):
    """Cancel an active rollout.

    Requirements: 10.1
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        db.execute(
            "UPDATE config_rollouts SET status = 'cancelled' WHERE id = ? AND status IN ('pending', 'in_progress')",
            (rollout_id,),
        )
        db.commit()

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="config_rollout_cancel",
            target=str(rollout_id),
            details={"rollout_id": rollout_id},
        )
    finally:
        db.close()

    flash("Rollout cancelled.", "success")
    return redirect(url_for("config_dashboard.config_page"))
