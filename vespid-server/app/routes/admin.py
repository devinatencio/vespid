"""Admin blueprint — user management, API key management, audit log, enrollment.

Endpoints:
    GET  /admin/users          — List operators (admin only)
    POST /admin/users          — Create operator (admin only)
    PUT  /admin/users/<id>/role — Change operator role (HTMX, admin only)
    GET  /admin/keys           — List API keys (admin only)
    POST /admin/keys           — Create API key (admin only)
    POST /admin/keys/<id>/revoke — Revoke API key (admin only)
    GET  /admin/audit          — View audit log (admin only)
    GET  /admin/enrollment     — Enrollment management page (admin only)
    POST /admin/enrollment/settings — Update enrollment settings (admin only)
    POST /admin/enrollment/<id>/approve — Approve pending enrollment (admin only)
    POST /admin/enrollment/<id>/reject  — Reject pending enrollment (admin only)
    POST /admin/enrollment/<id>/revoke  — Revoke approved enrollment (admin only)
    POST /admin/enrollment/<id>/rotate  — Rotate enrollment credentials (admin only)

Requirements: 3.1, 3.4, 8.1, 8.2, 8.3, 8.4, 8.5, 8.6, 10.3, 10.4, 10.5, 11.1, 11.2, 11.3, 12.1, 12.2, 12.3
"""

import csv
import io
import json
import logging
import os
from datetime import UTC, datetime

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    send_file,
    url_for,
)
from flask import (
    Response as FlaskResponse,
)
from flask_login import current_user

from app.decorators import require_role
from app.enrollment_models import (
    approve_enrollment,
    delete_enrollment,
    get_enrollment_setting,
    get_enrollment_settings,
    list_enrollment_requests,
    reissue_enrollment,
    reject_enrollment,
    revoke_enrollment,
    rotate_enrollment_credentials,
    update_enrollment_setting,
)
from app.inventory import (
    delete_asset as delete_asset_fn,
)
from app.inventory import (
    find_duplicate_assets,
    find_orphaned_aliases,
    find_stale_assets,
    get_asset,
    list_assets,
    merge_assets,
    purge_stale_assets,
)
from app.models import (
    create_api_key,
    create_assignment,
    create_user,
    get_db,
    get_detection_rules_revision,
    list_api_keys,
    list_config_profiles,
    list_detection_rules,
    list_nodes,
    list_users,
    record_audit,
    reset_user_onboarding,
    revoke_api_key,
    search_audit_log,
    summarize_audit_details,
    update_user_role,
)

logger = logging.getLogger(__name__)

admin_bp = Blueprint("admin", __name__, url_prefix="/admin")


# ── Helper ───────────────────────────────────────────────────────────────


def _wants_json() -> bool:
    """Return True if the client prefers JSON (API/CLI request)."""
    accept = request.headers.get("Accept", "")
    auth = request.headers.get("Authorization", "")
    return "application/json" in accept or auth.startswith("Bearer ")


def _export_audit_csv(entries: list[dict], total: int) -> FlaskResponse:
    """Return filtered audit log entries as a CSV download."""
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Timestamp", "Actor", "Actor IP", "Action Type", "Target", "Details"])

    for e in entries:
        details_raw = e.get("details", {})
        if isinstance(details_raw, dict):
            details_str = json.dumps(details_raw)
        else:
            details_str = str(details_raw)
        writer.writerow(
            [
                e.get("timestamp", ""),
                e.get("actor", ""),
                e.get("actor_ip", ""),
                e.get("action_type", ""),
                e.get("target", ""),
                details_str,
            ]
        )

    output.seek(0)
    return FlaskResponse(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit_log.csv"},
    )


# ── Built-in parser reference ────────────────────────────────────────────

_BUILTIN_PARSERS = [
    {
        "name": "secure",
        "log_source": "/var/log/secure (RHEL) or /var/log/auth.log (Debian)",
        "description": "Failed SSH password attempts, invalid users, and PAM authentication failures.",
        "regex": r"sshd.*?(?:Failed password|Invalid user|authentication failure).*?(?:from\s+|rhost=)(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)",
    },
    {
        "name": "secure_recon_strong",
        "log_source": "/var/log/secure (RHEL) or /var/log/auth.log (Debian)",
        "description": "Strong recon signals: pre-auth disconnects ([preauth]), SSH auth timeouts (LoginGraceTime expired), and banner exchange failures. No legitimate client should trigger these.",
        "regex": r"sshd.*?(?:Received disconnect from|Disconnected from|Connection closed by)\s+(?:authenticating user \S+ |invalid user \S+ )?(?P<ip>...)\s+port\s+\d+.*?\[preauth\]",
    },
    {
        "name": "secure_negotiate_fail",
        "log_source": "/var/log/secure (RHEL) or /var/log/auth.log (Debian)",
        "description": "SSH negotiation failures — client offered only deprecated/weak algorithms (ssh-rsa, ssh-dss, weak DH groups). Almost always scanners or exploit tools.",
        "regex": r"sshd.*?Unable to negotiate with\s+(?P<ip>...)\s+port\s+\d+:\s+no matching (?:host key type|key exchange method) found\..*?\[preauth\]",
    },
    {
        "name": "secure_recon_weak",
        "log_source": "/var/log/secure (RHEL) or /var/log/auth.log (Debian)",
        "description": "Generic connection reset/close by remote host. The 'Read error from remote host' pattern was removed because it was almost pure network noise (idle TCP timeouts, NAT drops) that hits legitimate publickey-authenticated users.",
        "regex": r"sshd.*?Connection (?:reset|closed) by.*?(?P<ip>...)\s+port\s+\d+(?::\s+Connection reset by peer)?",
    },
    {
        "name": "messages",
        "log_source": "/var/log/messages",
        "description": "Kernel firewall DROP/REJECT entries with a source IP.",
        "regex": r"(?:DROP|REJECT|kernel:.*?SRC=)(?P<ip>\d{1,3}(?:\.\d{1,3}){3})",
    },
    {
        "name": "apache",
        "log_source": "Configured per node (default: /var/log/httpd/access_log)",
        "description": "HTTP 401/403 responses indicating authentication failures. Backwards-compatible parser name used by the http_auth_brute rule.",
        "regex": r'^(?P<ip>\d{1,3}(?:\.\d{1,3}){3}|[0-9a-fA-F:]+)\s+\S+\s+\S+\s+\[...\]\s+"..."\s+(?:401|403)\s+...',
    },
    {
        "name": "apache_bad_request",
        "log_source": "Configured per node (default: /var/log/httpd/access_log)",
        "description": "HTTP 400 Bad Request responses. Triggered by malformed requests, TLS-on-HTTP probes, and protocol violations.",
        "regex": r"(same combined log format, status=400)",
    },
    {
        "name": "apache_not_found",
        "log_source": "Configured per node (default: /var/log/httpd/access_log)",
        "description": "HTTP 404 Not Found responses. High volumes from a single IP indicate path scanning or vulnerability probing.",
        "regex": r"(same combined log format, status=404)",
    },
    {
        "name": "apache_other",
        "log_source": "Configured per node (default: /var/log/httpd/access_log)",
        "description": "All other HTTP status codes (200, 301, 500, etc.). Used by custom rules that need to match successful exploit attempts.",
        "regex": r"(same combined log format, other status codes)",
    },
]


# ── Rule Pack Registry ───────────────────────────────────────────────────
# Pack metadata and rules are loaded from YAML files in the packs/ directory.
# To add a new pack: create a .yaml file in packs/ — no code changes needed.

from app.config_resolution import resolve_effective_profile  # noqa: E402
from app.pack_loader import get_cached_pack_metadata, get_cached_packs  # noqa: E402
from app.routes.rules import _log_sources_match  # noqa: E402


def _load_rule_packs(db) -> list:
    """Load rule packs with their templates and counts from the database.

    Returns a list of pack dicts enriched with 'templates', 'total_count',
    and 'enabled_count' from the database. Sorted: fully enabled first,
    then partially enabled, then disabled — alphabetical within each group.
    """
    packs = []
    for pack_meta in get_cached_pack_metadata():
        pack_name = pack_meta["pack_name"]
        rows = db.execute(
            "SELECT * FROM detection_rules_custom WHERE is_template = 1 "
            "AND pack_name = ? ORDER BY name",
            (pack_name,),
        ).fetchall()
        templates = [dict(r) for r in rows]
        enabled_count = sum(1 for t in templates if t["enabled"])

        # Add a human-readable display_name for each template.
        # For Sigma rules (sigma_ prefix), strip prefix and replace
        # underscores with spaces.  For hand-authored rules, use name as-is.
        for tmpl in templates:
            name = tmpl.get("name", "")
            if name.startswith("sigma_"):
                display = name[6:].replace("_-_", " — ").replace("_", " ").replace("-", " ")
                # Title-case: capitalize each word but keep already-capital letters
                display = " ".join(
                    w[0].upper() + w[1:] if w and w[0].islower() else w for w in display.split()
                )
                tmpl["display_name"] = display
            else:
                tmpl["display_name"] = name

        packs.append(
            {
                **pack_meta,
                "templates": templates,
                "total_count": len(templates),
                "enabled_count": enabled_count,
            }
        )

    # Sort: fully enabled first, then partially enabled, then disabled.
    # Within each group, sort alphabetically by display_name.
    def sort_key(p):
        if p["enabled_count"] == p["total_count"] and p["total_count"] > 0:
            group = 0  # fully enabled
        elif p["enabled_count"] > 0:
            group = 1  # partially enabled
        else:
            group = 2  # disabled
        return (group, p["display_name"].lower())

    packs.sort(key=sort_key)
    return packs


# ── User Management ──────────────────────────────────────────────────────


@admin_bp.route("/users", methods=["GET"])
@require_role("admin")
def users():
    """List all operators.

    Requirements: 3.1, 3.4
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        user_list = list_users(db)
    finally:
        db.close()

    if _wants_json():
        return jsonify({"users": user_list})

    return render_template("admin/users.html", users=user_list)


@admin_bp.route("/users", methods=["POST"])
@require_role("admin")
def create_user_endpoint():
    """Create a new operator.

    Requirements: 3.1
    """
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    role = request.form.get("role", "viewer")
    display_name = request.form.get("display_name", "").strip()[:128]

    if not username or not password:
        flash("Username and password are required.", "error")
        return redirect(url_for("admin.users"))

    if role not in ("admin", "analyst", "viewer"):
        flash("Invalid role.", "error")
        return redirect(url_for("admin.users"))

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        try:
            create_user(db, username, password, role, display_name)
        except Exception:
            logger.exception("Failed to create user '%s'", username)
            flash(f"Failed to create user '{username}'. Username may already exist.", "error")
            return redirect(url_for("admin.users"))

        # Record audit log
        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="role_change",
            target=username,
            details={"action": "user_created", "role": role},
        )
    finally:
        db.close()

    flash(f"User '{username}' created with role '{role}'.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/role", methods=["PUT"])
@require_role("admin")
def change_user_role(user_id):
    """Change an operator's role (HTMX endpoint).

    Requirements: 3.4, 10.3
    """
    if _wants_json():
        data = request.get_json(silent=True) or {}
        new_role = data.get("role", "").strip()
    else:
        new_role = request.form.get("role", "").strip()
    if new_role not in ("admin", "analyst", "viewer"):
        if _wants_json():
            return jsonify({"error": "invalid_role", "message": f"Invalid role '{new_role}'"}), 400
        return "Invalid role", 400

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        from app.models import get_user_by_id

        target_user = get_user_by_id(db, user_id)
        if target_user is None:
            if _wants_json():
                return jsonify({"error": "not_found", "message": "User not found"}), 404
            return "User not found", 404

        old_role = target_user["role"]
        update_user_role(db, user_id, new_role)

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="role_change",
            target=target_user["username"],
            details={"old_role": old_role, "new_role": new_role},
        )
    finally:
        db.close()

    if _wants_json():
        return jsonify({"ok": True, "user_id": user_id, "role": new_role})

    return f'<span class="badge badge-{new_role}">{new_role}</span>'


@admin_bp.route("/users/<int:user_id>/display-name", methods=["PUT"])
@require_role("admin")
def change_user_display_name(user_id):
    """Change an operator's display name (HTMX endpoint)."""
    new_name = request.form.get("display_name", "").strip()[:128]

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        from app.models import get_user_by_id, update_user_display_name

        target_user = get_user_by_id(db, user_id)
        if target_user is None:
            return "User not found", 404

        update_user_display_name(db, user_id, new_name)

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="role_change",
            target=target_user["username"],
            details={
                "action": "display_name_changed",
                "old_name": target_user.get("display_name", ""),
                "new_name": new_name,
            },
        )
    finally:
        db.close()

    if new_name:
        return f'<span style="cursor:pointer;user-select:none;" onclick="this.parentElement.style.display=&quot;none&quot;;document.getElementById(&quot;dn-form-{user_id}&quot;).style.display=&quot;flex&quot;;" title="Click to edit">{new_name}&nbsp;✎</span>'
    return f'<span style="cursor:pointer;user-select:none;color:var(--fg-muted);" onclick="this.parentElement.style.display=&quot;none&quot;;document.getElementById(&quot;dn-form-{user_id}&quot;).style.display=&quot;flex&quot;;" title="Click to edit">—&nbsp;✎</span>'


@admin_bp.route("/users/<int:user_id>/theme", methods=["PUT"])
@require_role("admin")
def change_user_theme(user_id):
    """Change an operator's theme preference (HTMX endpoint)."""
    new_theme = request.form.get("theme", "").strip()
    if new_theme not in ("dark", "light", "nord", "vespid"):
        return "Invalid theme", 400

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        from app.models import get_user_by_id, update_user_theme

        target_user = get_user_by_id(db, user_id)
        if target_user is None:
            return "User not found", 404

        update_user_theme(db, user_id, new_theme)

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="role_change",
            target=target_user["username"],
            details={
                "action": "theme_changed",
                "old_theme": target_user.get("theme", "dark"),
                "new_theme": new_theme,
            },
        )
    finally:
        db.close()

    theme_labels = {"dark": "Dark", "light": "Light", "nord": "Nord", "vespid": "Vespid"}
    options_html = ""
    for value, label in theme_labels.items():
        selected = "selected" if value == new_theme else ""
        options_html += f'<option value="{value}" {selected}>{label}</option>\n'

    return f'''<form hx-put="{url_for("admin.change_user_theme", user_id=user_id)}"
          hx-target="#theme-{user_id}"
          hx-swap="innerHTML"
          style="display:inline-flex; gap:0.25rem; align-items:center;">
        <select name="theme" style="padding:0.2rem; font-size:0.75rem;">
{options_html}</select>
        <button type="submit" class="btn btn-sm">Save</button>
    </form>'''


@admin_bp.route("/users/<int:user_id>/password", methods=["POST"])
@require_role("admin")
def change_user_password_endpoint(user_id):
    """Change an operator's password (admin only)."""
    if _wants_json():
        data = request.get_json(silent=True) or {}
        new_password = data.get("new_password", "")
    else:
        new_password = request.form.get("new_password", "")
        confirm_password = request.form.get("confirm_password", "")
        if new_password != confirm_password:
            flash("Passwords do not match.", "error")
            return redirect(url_for("admin.users"))

    if not new_password:
        if _wants_json():
            return jsonify(
                {"error": "missing_password", "message": "New password is required."}
            ), 400
        flash("New password is required.", "error")
        return redirect(url_for("admin.users"))

    if len(new_password) < 8:
        if _wants_json():
            return jsonify(
                {"error": "weak_password", "message": "Password must be at least 8 characters."}
            ), 400
        flash("Password must be at least 8 characters.", "error")
        return redirect(url_for("admin.users"))

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        from app.models import change_user_password, get_user_by_id

        target_user = get_user_by_id(db, user_id)
        if target_user is None:
            if _wants_json():
                return jsonify({"error": "not_found", "message": "User not found."}), 404
            flash("User not found.", "error")
            return redirect(url_for("admin.users"))

        change_user_password(db, user_id, new_password)

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="password_change",
            target=target_user["username"],
            details={"changed_by": "admin"},
        )
    finally:
        db.close()

    if _wants_json():
        return jsonify({"ok": True, "user_id": user_id, "username": target_user["username"]})

    flash(f"Password changed for user '{target_user['username']}'.", "success")
    return redirect(url_for("admin.users"))


@admin_bp.route("/users/<int:user_id>/onboarding-reset", methods=["POST"])
@require_role("admin")
def reset_user_onboarding_endpoint(user_id):
    """Reset the onboarding flag so the welcome dialog appears on next login."""
    db_path = current_app.config.get("DATABASE_PATH")
    db = get_db(db_path)
    try:
        from app.models import get_user_by_id

        target_user = get_user_by_id(db, user_id)
        if target_user is None:
            flash("User not found.", "error")
            return redirect(url_for("admin.users"))

        reset_user_onboarding(db, user_id)
        flash(f"Onboarding dialog re-enabled for '{target_user['username']}'.", "success")
    finally:
        db.close()

    return redirect(url_for("admin.users"))


# ── API Key Management ───────────────────────────────────────────────────


def _resolve_hostname(k: dict, node_to_er: dict, assets: dict) -> str:
    """Best-effort hostname for a key row tuple."""
    nid = (k.get("node_id_restriction") or "").strip()
    er = node_to_er.get(nid)
    if er:
        return er["hostname"]
    hid = (k.get("host_id") or "").strip()
    if hid and hid in node_to_er:
        return node_to_er[hid]["hostname"]
    return nid[:12] + "..." if nid else ""


def _resolve_key_source(k: dict, node_to_er: dict) -> str:
    nid = (k.get("node_id_restriction") or "").strip()
    er = node_to_er.get(nid)
    return (er or {}).get("source", "")


_SERVICE_LABELS = {
    "agent": "Security Agent",
    "monitor": "Monitor Agent",
    "worker": "Synthetic Worker",
}


@admin_bp.route("/keys", methods=["GET"])
@require_role("admin")
def keys():
    """List all API keys in a single flat searchable table.

    Each row resolves the host display name from the inventory system
    via enrollment_request → asset linkage, falling back to host_id
    grouping and finally to unlinked.

    The ``flat`` list is pre-computed in Python so the template is a
    simple loop over annotated rows.
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        key_list = list_api_keys(db)
        nodes = list_nodes(db)
        users = list_users(db)
        enrollment_settings_dict = get_enrollment_settings(db)

        # ── 1. Inventory assets + aliases ──
        asset_rows = db.execute(
            "SELECT asset_id, asset_type, display_name, metadata, labels "
            "FROM assets WHERE asset_type IN ('host', 'vm') "
            "ORDER BY last_seen_at DESC"
        ).fetchall()
        alias_rows = db.execute(
            "SELECT asset_id, alias_type, alias_value FROM asset_aliases "
            "WHERE alias_type IN ('hostname', 'machine_id')"
        ).fetchall()

        assets = {}
        for r in asset_rows:
            meta = r["metadata"]
            lbls = r["labels"]
            if isinstance(meta, str):
                try:
                    meta = json.loads(meta)
                except (json.JSONDecodeError, TypeError):
                    meta = {}
            if isinstance(lbls, str):
                try:
                    lbls = json.loads(lbls)
                except (json.JSONDecodeError, TypeError):
                    lbls = {}
            assets[r["asset_id"]] = {
                "display_name": r["display_name"],
                "asset_type": r["asset_type"],
                "metadata": meta,
                "labels": lbls,
                "hostnames": [],
                "machine_ids": [],
            }
        for r in alias_rows:
            entry = assets.get(r["asset_id"])
            if entry:
                if r["alias_type"] == "hostname":
                    entry["hostnames"].append(r["alias_value"])
                elif r["alias_type"] == "machine_id":
                    entry["machine_ids"].append(r["alias_value"])

        # ── 2. Enrollment requests ──
        er_rows = db.execute(
            "SELECT node_id, hostname, source, host_id, asset_id, status "
            "FROM enrollment_requests WHERE node_id IS NOT NULL"
        ).fetchall()
        node_to_er = {}
        for r in er_rows:
            if r["node_id"]:
                node_to_er[r["node_id"]] = {
                    "source": r["source"] or "agent",
                    "host_id": r["host_id"] or "",
                    "asset_id": r["asset_id"] or "",
                    "hostname": r["hostname"] or r["node_id"],
                }
        user_map = {u["id"]: u["username"] for u in users}

        # ── 3. Build a flat list of annotated key rows ──
        #    For each key we resolve the best host display name, IP,
        #    inventory labels, and service label.  The template just
        #    iterates ``flat``.
        flat = []
        seen = set()

        # Build asset_id → host info for quick lookup
        hostid_to_assets = {}
        for er in node_to_er.values():
            aid = er["asset_id"]
            hid = er["host_id"]
            if aid:
                hostid_to_assets.setdefault(hid, set()).add(aid)

        def _host_info(k, node_to_er, assets, hostid_to_assets):
            """Resolve host display name, IP, and inventory labels."""
            nid = (k.get("node_id_restriction") or "").strip()
            hid = (k.get("host_id") or "").strip()
            er = node_to_er.get(nid)

            if er and er["asset_id"]:
                asset = assets.get(er["asset_id"], {})
                hn = (
                    asset.get("display_name")
                    or (asset.get("hostnames", [None]) or [None])[0]
                    or er["hostname"]
                )
                meta = asset.get("metadata", {})
                ifaces = meta.get("interfaces") or []
                ip = ifaces[0].get("ipv4", [""])[0] if ifaces and ifaces[0].get("ipv4") else ""
                return hn, ip, asset.get("labels", {}), er["source"]
            if hid and hid in hostid_to_assets:
                # Share hostname with any enrolled key on same host
                for aid in hostid_to_assets[hid]:
                    asset = assets.get(aid, {})
                    hn = (
                        asset.get("display_name")
                        or (asset.get("hostnames", [None]) or [None])[0]
                        or hid[:12]
                    )
                    meta = asset.get("metadata", {})
                    ifaces = meta.get("interfaces") or []
                    ip = ifaces[0].get("ipv4", [""])[0] if ifaces and ifaces[0].get("ipv4") else ""
                    return hn, ip, asset.get("labels", {}), er["source"] if er else ""
            if er:
                return er["hostname"], "", {}, er["source"]
            return (
                nid[:12] + "..." if nid else "Unlinked",
                "",
                {},
                "",
            )

        for k in key_list:
            key_id = k["id"]
            nid = (k.get("node_id_restriction") or "").strip()
            source = _SERVICE_LABELS.get((node_to_er.get(nid) or {}).get("source", ""), "Custom")
            hn, ip, labels, _ = _host_info(k, node_to_er, assets, hostid_to_assets)

            is_auto = "auto-enrolled" in (k.get("label") or "").lower()
            cb = (
                "auto-enrolled"
                if is_auto
                else user_map.get(k.get("created_by"), k.get("created_by") or "—")
            )

            flat.append(
                {
                    "key_id": key_id,
                    "prefix": k["key_prefix"][:8],
                    "node_id": nid,
                    "node_id_restriction": nid,
                    "hostname": hn,
                    "host_id": k.get("host_id") or "",
                    "asset_id": (node_to_er.get(nid) or {}).get("asset_id", ""),
                    "ip": ip,
                    "labels": labels,
                    "source": source,
                    "service": source,
                    "created_by": cb,
                    "is_active": k["is_active"],
                    "created_at": k["created_at"],
                    "last_used_at": k.get("last_used_at"),
                }
            )
            seen.add(key_id)

        # Active keys first, then revoked keys; preserve id order within each group.
        flat.sort(key=lambda k: (not k["is_active"], k["key_id"]))

    finally:
        db.close()

    if _wants_json():
        return jsonify({"keys": flat})

    return render_template(
        "admin/api_keys.html",
        flat=flat,
        nodes=nodes,
        users=users,
        enrollment_settings=enrollment_settings_dict,
        node_to_er=node_to_er,
    )


@admin_bp.route("/keys", methods=["POST"])
@require_role("admin")
def create_key_endpoint():
    """Create a new API key. Returns the raw token once.

    Requirements: 11.1, 10.4
    """
    if _wants_json():
        data = request.get_json(silent=True) or {}
        label = data.get("name", data.get("label", "")).strip()
        node_id_restriction = data.get("node_id_restriction", "").strip() or None
    else:
        label = request.form.get("label", "").strip()
        node_id_restriction = request.form.get("node_id_restriction", "").strip() or None

    if not label:
        if _wants_json():
            return jsonify({"error": "Label is required."}), 400
        flash("Label is required.", "error")
        return redirect(url_for("admin.keys"))

    # Enforce the server-wide "allow_unrestricted_api_keys" policy.
    # When the policy is off, every key must be bound to a node.
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        allow_unrestricted = (
            get_enrollment_setting(db, "allow_unrestricted_api_keys", "true") == "true"
        )
        if not allow_unrestricted and not node_id_restriction:
            if _wants_json():
                return jsonify(
                    {
                        "error": "node_id_required",
                        "message": (
                            "Server policy requires every API key to be bound "
                            "to a node. Provide a node_id_restriction or "
                            "enable 'allow_unrestricted_api_keys' in "
                            "enrollment settings."
                        ),
                    }
                ), 400
            flash(
                "Server policy requires every API key to be bound to a node. "
                "Select a node before creating the key.",
                "error",
            )
            return redirect(url_for("admin.keys"))

        raw_token = create_api_key(db, label, node_id_restriction, current_user.id)

        # Record audit log
        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="key_create",
            target=label,
            details={"node_id_restriction": node_id_restriction},
        )
    finally:
        db.close()

    if _wants_json():
        return jsonify({"key": raw_token, "label": label}), 201

    flash(
        f"API key created. Copy this token now — it will not be shown again: {raw_token}", "success"
    )
    return redirect(url_for("admin.keys"))


@admin_bp.route("/keys/<int:key_id>/revoke", methods=["POST"])
@require_role("admin")
def revoke_key_endpoint(key_id):
    """Revoke an API key.

    Requirements: 11.2, 10.4
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        # Get key info for audit log
        key_row = db.execute(
            "SELECT label, key_prefix FROM api_keys WHERE id = ?", (key_id,)
        ).fetchone()

        if key_row is None:
            if _wants_json():
                return jsonify({"error": "API key not found."}), 404
            flash("API key not found.", "error")
            return redirect(url_for("admin.keys"))

        revoke_api_key(db, key_id)

        # Record audit log
        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="key_revoke",
            target=key_row["label"],
            details={"key_prefix": key_row["key_prefix"]},
        )
    finally:
        db.close()

    if _wants_json():
        return jsonify({"ok": True, "revoked": key_row["label"]})

    flash(f"API key '{key_row['label']}' has been revoked.", "success")
    return redirect(url_for("admin.keys"))


@admin_bp.route("/keys/<int:key_id>/delete", methods=["POST"])
@require_role("admin")
def delete_key_endpoint(key_id):
    """Permanently delete an API key.

    Only inactive (revoked) keys can be deleted.
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        key_row = db.execute(
            "SELECT label, key_prefix, is_active FROM api_keys WHERE id = ?", (key_id,)
        ).fetchone()

        if key_row is None:
            if _wants_json():
                return jsonify({"error": "not_found", "message": "API key not found."}), 404
            flash("API key not found.", "error")
            return redirect(url_for("admin.keys"))

        if key_row["is_active"]:
            if _wants_json():
                return jsonify(
                    {
                        "error": "key_active",
                        "message": "Cannot delete an active key. Revoke it first.",
                    }
                ), 400
            flash("Cannot delete an active key. Revoke it first.", "error")
            return redirect(url_for("admin.keys"))

        db.execute(
            "UPDATE enrollment_requests SET api_key_id = NULL WHERE api_key_id = ?",
            (key_id,),
        )
        db.execute("DELETE FROM api_keys WHERE id = ?", (key_id,))
        db.commit()

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="key_delete",
            target=key_row["label"],
            details={"key_prefix": key_row["key_prefix"]},
        )
    finally:
        db.close()

    if _wants_json():
        return jsonify({"ok": True, "deleted": key_row["label"]})

    flash(f"API key '{key_row['label']}' has been deleted.", "success")
    return redirect(url_for("admin.keys"))


@admin_bp.route("/keys/<int:key_id>/node-restriction", methods=["PUT"])
@require_role("admin")
def update_key_node_restriction(key_id):
    """Update the node_id_restriction on an existing API key."""
    if _wants_json():
        data = request.get_json(silent=True) or {}
        node_restriction = data.get("node_id_restriction", "").strip() or None
    else:
        node_restriction = request.form.get("node_id_restriction", "").strip() or None

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        row = db.execute("SELECT id, label FROM api_keys WHERE id = ?", (key_id,)).fetchone()
        if row is None:
            if _wants_json():
                return jsonify({"error": "not_found", "message": "Key not found"}), 404
            return "Key not found", 404

        db.execute(
            "UPDATE api_keys SET node_id_restriction = ? WHERE id = ?",
            (node_restriction, key_id),
        )
        db.commit()

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="key_update",
            target=row["label"],
            details={"node_id_restriction": node_restriction or "any"},
        )

        nodes = list_nodes(db)
    finally:
        db.close()

    if _wants_json():
        return jsonify({"ok": True, "key_id": key_id, "node_id_restriction": node_restriction})

    if node_restriction:
        node_name = ""
        for n in nodes:
            if n["node_id"] == node_restriction:
                node_name = n.get("display_name") or n.get("hostname", "")
                break
        label = node_name or node_restriction
    else:
        label = "Any"

    return f'<span>{label}</span> <button class="btn btn-sm btn-password" style="padding:0.1rem 0.4rem;font-size:0.65rem;" onclick="editNodeRestriction({key_id},\'{node_restriction or ""}\')">Edit</button>'


# ── Audit Log ────────────────────────────────────────────────────────────


@admin_bp.route("/audit", methods=["GET"])
@require_role("admin")
def audit():
    """Display audit log with filtering.

    Requirements: 10.5, 11.5
    """
    action_type = request.args.get("action_type", "").strip() or None
    actor = request.args.get("actor", "").strip() or None
    target = request.args.get("target", "").strip() or None
    start_raw = request.args.get("start", "").strip()
    end_raw = request.args.get("end", "").strip()

    # Normalize datetime-local values to match stored ISO 8601 format
    # (stored as YYYY-MM-DDTHH:MM:SSZ in the audit_log table via
    # strftime('%Y-%m-%dT%H:%M:%SZ', 'now')). Since SQLite compares
    # these as plain strings, we must add seconds and the Z suffix so
    # the range comparison works correctly.
    start = start_raw or None
    end = end_raw or None
    if start is not None and ":" in start and start.count(":") < 2:
        start += ":00Z"
    elif start is not None and not start.endswith("Z"):
        start += "Z"
    if end is not None and ":" in end and end.count(":") < 2:
        end += ":59:59Z"  # inclusive end-of-minute
    elif end is not None and not end.endswith("Z"):
        if ":" in end and end.count(":") >= 2:
            end += "Z"

    search = request.args.get("search", "").strip() or None
    page = request.args.get("page", 1, type=int)
    per_page = request.args.get("per_page", 50, type=int)
    refresh = request.args.get("refresh", "").strip()
    sort_by = request.args.get("sort_by", "timestamp").strip()
    sort_order = request.args.get("sort_order", "DESC").strip().upper()
    export = request.args.get("export", "").strip().lower()

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        entries, total = search_audit_log(
            db,
            action_type=action_type,
            actor=actor,
            target=target,
            start=start,
            end=end,
            page=page,
            per_page=per_page,
            search=search,
            sort_by=sort_by,
            sort_order=sort_order,
        )

        # Parse details JSON and build summary stats
        unique_actors: set[str] = set()
        unique_actions: set[str] = set()
        for entry in entries:
            raw = entry.get("details", "{}")
            if isinstance(raw, str):
                try:
                    entry["details"] = json.loads(raw)
                except (json.JSONDecodeError, TypeError):
                    entry["details"] = {}
            entry["summary"] = summarize_audit_details(entry["action_type"], entry["details"])
            unique_actors.add(entry.get("actor", ""))
            unique_actions.add(entry.get("action_type", ""))

    finally:
        db.close()

    # ── CSV export ────────────────────────────────────────────────────
    if export == "csv":
        return _export_audit_csv(entries, total)

    if _wants_json() and not request.headers.get("HX-Request"):
        return jsonify({"entries": entries, "total": total})

    total_pages = max(1, (total + per_page - 1) // per_page)
    ctx = dict(
        entries=entries,
        total=total,
        page=page,
        total_pages=total_pages,
        per_page=per_page,
        action_type=action_type or "",
        actor=actor or "",
        target=target or "",
        start=start_raw or "",
        end=end_raw or "",
        search=search or "",
        refresh=refresh,
        sort_by=sort_by,
        sort_order=sort_order,
        unique_actors=len(unique_actors),
        unique_actions=len(unique_actions),
    )

    # HTMX fragment — just the table section
    if request.headers.get("HX-Request"):
        return render_template("admin/_audit_table.html", **ctx)

    return render_template("admin/audit.html", **ctx)


# ── Cleanup / Retention ───────────────────────────────────────────────


@admin_bp.route("/cleanup", methods=["GET", "POST"])
@require_role("admin")
def cleanup():
    """Display and manage data retention / cleanup settings."""
    from app.models import get_setting, purge_old_audit_log, purge_old_events, set_setting

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        audit_retention_days = int(get_setting(db, "audit_retention_days", "90"))
        if request.method == "POST":
            if _wants_json():
                data = request.get_json(silent=True) or {}
                action = data.get("action", "")
                if action == "save_retention":
                    days = str(
                        data.get("retention_days", get_setting(db, "event_retention_days", "90"))
                    )
                    set_setting(db, "event_retention_days", days)
                    audit_days = str(
                        data.get(
                            "audit_retention_days", get_setting(db, "audit_retention_days", "90")
                        )
                    )
                    set_setting(db, "audit_retention_days", audit_days)
                    return jsonify(
                        {"ok": True, "retention_days": days, "audit_retention_days": audit_days}
                    )
                elif action == "purge_now":
                    retention_days = int(get_setting(db, "event_retention_days", "90"))
                    result = purge_old_events(db, retention_days)
                    audit_retention_days = int(get_setting(db, "audit_retention_days", "90"))
                    audit_purged = purge_old_audit_log(db, audit_retention_days)
                    return jsonify({"ok": True, "purged": result, "audit_purged": audit_purged})
                return jsonify(
                    {"error": "unknown_action", "message": f"Unknown action '{action}'"}
                ), 400
            else:
                action = request.form.get("action", "")
                if action == "save_retention":
                    days = request.form.get("retention_days") or get_setting(
                        db, "event_retention_days", "90"
                    )
                    set_setting(db, "event_retention_days", days)
                    audit_days = request.form.get("audit_retention_days") or get_setting(
                        db, "audit_retention_days", "90"
                    )
                    set_setting(db, "audit_retention_days", audit_days)
                    flash(
                        f"Event retention set to {days} days; audit retention set to {audit_days} days.",
                        "success",
                    )
                elif action == "purge_now":
                    retention_days = int(get_setting(db, "event_retention_days", "90"))
                    result = purge_old_events(db, retention_days)
                    audit_retention_days = int(get_setting(db, "audit_retention_days", "90"))
                    audit_purged = purge_old_audit_log(db, audit_retention_days)
                    total = sum(result.values()) + audit_purged
                    flash(
                        f"Purged {total} rows (events={result['events']}, "
                        f"context={result['event_context']}, counters={result['counters']}, "
                        f"audit={audit_purged}). Events older than {retention_days}d, "
                        f"audit entries older than {audit_retention_days}d.",
                        "success",
                    )

        retention_days = get_setting(db, "event_retention_days", "90")
        audit_retention_days = get_setting(db, "audit_retention_days", "90")

        total_events = db.execute("SELECT COUNT(*) FROM events").fetchone()[0]
        oldest_event = db.execute("SELECT MIN(timestamp) FROM events").fetchone()[0] or ""
        newest_event = db.execute("SELECT MAX(timestamp) FROM events").fetchone()[0] or ""

        from datetime import datetime, timedelta

        cutoff = (datetime.now(UTC) - timedelta(days=int(retention_days))).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        purgeable = db.execute(
            "SELECT COUNT(*) FROM events WHERE timestamp < ?", (cutoff,)
        ).fetchone()[0]

        total_audit = db.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        oldest_audit = db.execute("SELECT MIN(timestamp) FROM audit_log").fetchone()[0] or ""
        newest_audit = db.execute("SELECT MAX(timestamp) FROM audit_log").fetchone()[0] or ""
        audit_cutoff = (datetime.now(UTC) - timedelta(days=int(audit_retention_days))).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
        audit_purgeable = db.execute(
            "SELECT COUNT(*) FROM audit_log WHERE timestamp < ?", (audit_cutoff,)
        ).fetchone()[0]
    finally:
        db.close()

    if _wants_json() and request.method == "GET":
        return jsonify(
            {
                "retention_days": int(retention_days),
                "audit_retention_days": int(audit_retention_days),
                "total_events": total_events,
                "oldest_event": oldest_event,
                "newest_event": newest_event,
                "purgeable": purgeable,
                "total_audit": total_audit,
                "oldest_audit": oldest_audit,
                "newest_audit": newest_audit,
                "audit_purgeable": audit_purgeable,
            }
        )

    return render_template(
        "admin/cleanup.html",
        retention_days=retention_days,
        audit_retention_days=audit_retention_days,
        total_events=total_events,
        oldest_event=oldest_event,
        newest_event=newest_event,
        purgeable=purgeable,
        total_audit=total_audit,
        oldest_audit=oldest_audit,
        newest_audit=newest_audit,
        audit_purgeable=audit_purgeable,
    )


# ── Command Queue Management ─────────────────────────────────────────────


@admin_bp.route("/commands", methods=["GET", "POST"])
@require_role("admin")
def commands():
    """View and manage the command queue."""
    from app.models import (
        count_commands_by_status,
        delete_command,
        expire_stale_commands,
        get_setting,
        list_commands,
        purge_old_commands,
        set_setting,
    )

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        if request.method == "POST":
            if _wants_json():
                data = request.get_json(silent=True) or {}
                action = data.get("action", "")
                if action == "delete" and data.get("command_id"):
                    cid = data["command_id"]
                    deleted = delete_command(db, cid)
                    return jsonify({"ok": deleted, "command_id": cid})
                elif action == "expire_pending":
                    hours = int(data.get("hours", "24"))
                    expired = expire_stale_commands(db, hours)
                    return jsonify({"ok": True, "expired": expired, "hours": hours})
                elif action == "purge_old":
                    days = int(data.get("days", "30"))
                    purged = purge_old_commands(db, days)
                    return jsonify({"ok": True, "purged": purged, "days": days})
                elif action == "save_settings":
                    set_setting(
                        db, "command_pending_expiry_hours", str(data.get("expiry_hours", "24"))
                    )
                    set_setting(db, "command_retention_days", str(data.get("retention_days", "30")))
                    return jsonify({"ok": True})
                return jsonify(
                    {"error": "unknown_action", "message": f"Unknown action '{action}'"}
                ), 400
            else:
                action = request.form.get("action", "")
                if action == "delete" and request.form.get("command_id"):
                    cid = request.form["command_id"]
                    if delete_command(db, cid):
                        flash(f"Deleted command {cid[:8]}…", "success")
                    else:
                        flash(f"Command {cid[:8]}… not found.", "warning")
                elif action == "expire_pending":
                    hours = int(request.form.get("hours", "24"))
                    expired = expire_stale_commands(db, hours)
                    flash(f"Expired {expired} pending command(s) older than {hours}h.", "success")
                elif action == "purge_old":
                    days = int(request.form.get("days", "30"))
                    purged = purge_old_commands(db, days)
                    flash(f"Purged {purged} old command(s) older than {days}d.", "success")
                elif action == "save_settings":
                    set_setting(
                        db, "command_pending_expiry_hours", request.form.get("expiry_hours", "24")
                    )
                    set_setting(
                        db, "command_retention_days", request.form.get("retention_days", "30")
                    )
                    flash("Command queue settings saved.", "success")
            return redirect(url_for("admin.commands"))

        status_filter = request.args.get("status", "")
        node_filter = request.args.get("node_id", "")
        cmd_list = list_commands(
            db,
            node_id=node_filter or None,
            status=status_filter or None,
            limit=200,
        )
        counts = count_commands_by_status(db)
        expiry_hours = get_setting(db, "command_pending_expiry_hours", "24")
        retention_days = get_setting(db, "command_retention_days", "30")
        total = sum(counts.values())
    finally:
        db.close()

    if _wants_json() and request.method == "GET":
        return jsonify(
            {
                "commands": [
                    {
                        "command_id": c["command_id"],
                        "node_id": c.get("node_id"),
                        "command_type": c.get("command_type"),
                        "status": c.get("status"),
                        "payload": c.get("payload"),
                        "created_at": c.get("created_at"),
                        "completed_at": c.get("completed_at"),
                    }
                    for c in cmd_list
                ],
                "counts": dict(counts),
                "total": total,
                "expiry_hours": int(expiry_hours),
                "retention_days": int(retention_days),
            }
        )

    return render_template(
        "admin/commands.html",
        commands=cmd_list,
        counts=counts,
        total=total,
        status_filter=status_filter,
        node_filter=node_filter,
        expiry_hours=expiry_hours,
        retention_days=retention_days,
    )


# ── Backups ────────────────────────────────────────────────────────────────


@admin_bp.route("/backups", methods=["GET"])
@require_role("admin")
def backups():
    """DB backup management page (admin only)."""
    from app.db_backup import (
        DEFAULT_BACKUP_DIR,
        DEFAULT_INTERVAL_HOURS,
        DEFAULT_RETENTION_DAYS,
        get_backup_list,
    )
    from app.models import get_setting

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        backup_dir = get_setting(db, "backup_directory", DEFAULT_BACKUP_DIR)
        enabled = get_setting(db, "backup_enabled", "false")
        interval_hours = get_setting(db, "backup_interval_hours", str(DEFAULT_INTERVAL_HOURS))
        retention_days = get_setting(db, "backup_retention_days", str(DEFAULT_RETENTION_DAYS))
        last_run = get_setting(db, "backup_last_run", "")
    finally:
        db.close()

    backup_files = get_backup_list(backup_dir)
    for b in backup_files:
        b["ts"] = datetime.utcfromtimestamp(b["mtime"]).strftime("%Y-%m-%d %H:%M:%S")
    total_size = sum(b["size"] for b in backup_files)
    total_size_display = _format_backup_size(total_size)

    next_run = ""
    if enabled in ("true", "1", "yes", True) and last_run:
        try:
            interval_s = int(interval_hours) * 3600
            last_dt = datetime.fromisoformat(last_run)
            next_dt = last_dt.timestamp() + interval_s
            next_run = datetime.fromtimestamp(next_dt).strftime("%Y-%m-%d %H:%M:%S")
        except (ValueError, TypeError):
            pass

    if _wants_json():
        return jsonify(
            {
                "backup_dir": backup_dir,
                "enabled": enabled in ("true", "1", "yes", True),
                "interval_hours": int(interval_hours),
                "retention_days": int(retention_days),
                "last_run": last_run,
                "next_run": next_run,
                "backup_files": backup_files,
                "total_size": total_size,
            }
        )

    return render_template(
        "admin/backups.html",
        backup_dir=backup_dir,
        enabled=enabled,
        interval_hours=interval_hours,
        retention_days=retention_days,
        last_run=last_run,
        next_run=next_run,
        backup_files=backup_files,
        total_size_display=total_size_display,
    )


# ── Enrollment Management ────────────────────────────────────────────────


@admin_bp.route("/enrollment", methods=["GET"])
@require_role("admin")
def enrollment():
    """Display enrollment management page.

    Shows current enrollment settings and records grouped by status.
    Supports an optional ``?host=<host_id>`` query parameter to filter
    the records to a single logical host — useful for seeing all
    security-agent and monitor-agent enrollments on the same machine
    side by side.

    Requirements: 8.1, 8.2, 8.6, 12.1
    """
    host_filter = request.args.get("host", "").strip()

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        settings = get_enrollment_settings(db)
        if host_filter:
            all_records = list_enrollment_requests(db)
            pending = [
                r
                for r in all_records
                if r.get("host_id") == host_filter and r["status"] == "pending"
            ]
            approved = [
                r
                for r in all_records
                if r.get("host_id") == host_filter and r["status"] == "approved"
            ]
            rejected = [
                r
                for r in all_records
                if r.get("host_id") == host_filter and r["status"] == "rejected"
            ]
            revoked = [
                r
                for r in all_records
                if r.get("host_id") == host_filter and r["status"] == "revoked"
            ]
        else:
            pending = list_enrollment_requests(db, status="pending")
            approved = list_enrollment_requests(db, status="approved")
            rejected = list_enrollment_requests(db, status="rejected")
            revoked = list_enrollment_requests(db, status="revoked")
        profiles_result = list_config_profiles(db, page=1, per_page=200)
        profiles = profiles_result.get("profiles", [])
    finally:
        db.close()

    if _wants_json():
        return jsonify(
            {
                "enrollments": pending + approved + rejected + revoked,
                "settings": settings,
                "host_filter": host_filter or None,
            }
        )

    return render_template(
        "admin/enrollment.html",
        settings=settings,
        pending=pending,
        approved=approved,
        rejected=rejected,
        revoked=revoked,
        profiles=profiles,
        records=pending + approved + rejected + revoked,
        host_filter=host_filter,
    )


@admin_bp.route("/enrollment/settings", methods=["POST"])
@require_role("admin")
def enrollment_settings():
    """Update enrollment enabled/mode/token settings.

    Requirements: 12.2, 12.3, 12.4, 12.5
    """
    if _wants_json():
        data = request.get_json(silent=True) or {}
        enrollment_enabled = str(data.get("enrollment_enabled", "false")).lower()
        enrollment_mode = data.get("enrollment_mode", "manual_approval")
        enrollment_token = data.get("enrollment_token", "").strip()
        allow_unrestricted = str(data.get("allow_unrestricted_api_keys", "true")).lower()
    else:
        enrollment_enabled = request.form.get("enrollment_enabled", "false")
        enrollment_mode = request.form.get("enrollment_mode", "manual_approval")
        enrollment_token = request.form.get("enrollment_token", "").strip()
        allow_unrestricted = request.form.get("allow_unrestricted_api_keys", "true")

    if enrollment_mode not in ("open", "manual_approval", "restricted"):
        if _wants_json():
            return jsonify(
                {"error": "invalid_mode", "message": f"Invalid enrollment mode '{enrollment_mode}'"}
            ), 400
        flash("Invalid enrollment mode.", "error")
        return redirect(url_for("admin.enrollment"))

    if enrollment_enabled not in ("true", "false"):
        enrollment_enabled = "false"
    if allow_unrestricted not in ("true", "false"):
        allow_unrestricted = "true"

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        update_enrollment_setting(
            db, "enrollment_enabled", enrollment_enabled, current_user.username
        )
        update_enrollment_setting(db, "enrollment_mode", enrollment_mode, current_user.username)
        update_enrollment_setting(db, "enrollment_token", enrollment_token, current_user.username)
        update_enrollment_setting(
            db, "allow_unrestricted_api_keys", allow_unrestricted, current_user.username
        )
    finally:
        db.close()

    if _wants_json():
        return jsonify(
            {
                "ok": True,
                "enrollment_enabled": enrollment_enabled,
                "enrollment_mode": enrollment_mode,
                "allow_unrestricted_api_keys": allow_unrestricted,
            }
        )

    flash("Enrollment settings updated.", "success")
    return redirect(url_for("admin.enrollment"))


@admin_bp.route("/enrollment/allow-unrestricted", methods=["POST"])
@require_role("admin")
def enrollment_allow_unrestricted():
    """Toggle the ``allow_unrestricted_api_keys`` server setting.

    JSON-only endpoint intended for the API/CLI. When set to ``"false"``,
    the server requires every newly created API key to be bound to a
    specific ``node_id`` — both for admin-created keys
    (``create_key_endpoint``) and for enrollment-issued keys.

    Request body: ``{"allow_unrestricted_api_keys": "true" | "false"}``
    Response: ``{"ok": true, "allow_unrestricted_api_keys": "..."}``
    """
    data = request.get_json(silent=True) or {}
    new_value = str(data.get("allow_unrestricted_api_keys", "true")).lower()
    if new_value not in ("true", "false"):
        return jsonify(
            {
                "error": "invalid_value",
                "message": "allow_unrestricted_api_keys must be 'true' or 'false'",
            }
        ), 400

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        update_enrollment_setting(
            db, "allow_unrestricted_api_keys", new_value, current_user.username
        )
    finally:
        db.close()

    return jsonify({"ok": True, "allow_unrestricted_api_keys": new_value})


@admin_bp.route("/enrollment/<int:record_id>/approve", methods=["POST"])
@require_role("admin")
def enrollment_approve(record_id):
    """Approve a pending enrollment request.

    Requirements: 8.3, 3.2, 3.4
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        # Get node_id before approval (approve_enrollment returns the token)
        row = db.execute(
            "SELECT node_id FROM enrollment_requests WHERE id = ?",
            (record_id,),
        ).fetchone()
        if row is None:
            flash("Enrollment record not found.", "error")
            return redirect(url_for("admin.enrollment"))
        node_id = row["node_id"]

        try:
            approve_enrollment(db, record_id, current_user.username)
        except ValueError as e:
            flash(str(e), "error")
            return redirect(url_for("admin.enrollment"))

        profile_id = request.form.get("profile_id", type=int)
        if profile_id:
            try:
                create_assignment(
                    db,
                    profile_id=profile_id,
                    node_id=node_id,
                    assigned_by=current_user.username,
                )
                record_audit(
                    db,
                    actor=current_user.username,
                    actor_ip=request.remote_addr,
                    action_type="config_assignment_create",
                    target=node_id,
                    details={
                        "profile_id": profile_id,
                        "source": "enrollment_approval",
                    },
                )
            except Exception as e:
                logger.exception("Profile assignment post-approval failed for enrollment")
                flash(f"Profile assigned but note: {e}", "warning")
    finally:
        db.close()

    flash("Enrollment request approved.", "success")
    return redirect(url_for("admin.enrollment"))


@admin_bp.route("/enrollment/<int:record_id>/reject", methods=["POST"])
@require_role("admin")
def enrollment_reject(record_id):
    """Reject a pending enrollment request.

    Requirements: 8.4, 3.3, 3.4
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        try:
            reject_enrollment(db, record_id, current_user.username)
        except ValueError as e:
            flash(str(e), "error")
            return redirect(url_for("admin.enrollment"))
    finally:
        db.close()

    flash("Enrollment request rejected.", "success")
    return redirect(url_for("admin.enrollment"))


@admin_bp.route("/enrollment/<int:record_id>/revoke", methods=["POST"])
@require_role("admin")
def enrollment_revoke(record_id):
    """Revoke an approved enrollment.

    Requirements: 8.5, 9.1, 9.2, 9.3
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        try:
            revoke_enrollment(db, record_id, current_user.username)
        except ValueError as e:
            flash(str(e), "error")
            return redirect(url_for("admin.enrollment"))
    finally:
        db.close()

    flash("Enrollment revoked.", "success")
    return redirect(url_for("admin.enrollment"))


@admin_bp.route("/enrollment/<int:record_id>/rotate", methods=["POST"])
@require_role("admin")
def enrollment_rotate(record_id):
    """Rotate credentials for an approved enrollment.

    Requirements: 10.1, 10.2, 10.3
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        try:
            rotate_enrollment_credentials(db, record_id, current_user.username)
        except ValueError as e:
            if _wants_json():
                return jsonify({"error": "bad_request", "message": str(e)}), 400
            flash(str(e), "error")
            return redirect(url_for("admin.enrollment"))
    finally:
        db.close()

    if _wants_json():
        return jsonify({"ok": True, "record_id": record_id})

    flash("Credentials rotated successfully.", "success")
    return redirect(url_for("admin.enrollment"))


@admin_bp.route("/enrollment/<int:record_id>/delete", methods=["POST"])
@require_role("admin")
def enrollment_delete(record_id):
    """Delete a revoked or rejected enrollment record.

    Permanently removes the record from the database. Only revoked or
    rejected records can be deleted.
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        try:
            delete_enrollment(db, record_id, current_user.username)
        except ValueError as e:
            if _wants_json():
                return jsonify({"error": "bad_request", "message": str(e)}), 400
            flash(str(e), "error")
            return redirect(url_for("admin.enrollment"))
    finally:
        db.close()

    if _wants_json():
        return jsonify({"ok": True, "record_id": record_id})

    flash("Enrollment record deleted.", "success")
    return redirect(url_for("admin.enrollment"))


@admin_bp.route("/enrollment/<int:record_id>/reissue", methods=["POST"])
@require_role("admin")
def enrollment_reissue(record_id):
    """Re-issue credentials for a revoked enrollment.

    Generates a fresh API key and transitions the record back to approved.
    The agent will pick up the new credentials on its next enrollment poll.
    """
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        try:
            reissue_enrollment(db, record_id, current_user.username)
        except ValueError as e:
            if _wants_json():
                return jsonify({"error": "bad_request", "message": str(e)}), 400
            flash(str(e), "error")
            return redirect(url_for("admin.enrollment"))
    finally:
        db.close()

    if _wants_json():
        return jsonify({"ok": True, "record_id": record_id})

    flash("Credentials re-issued. The agent will pick them up on its next poll.", "success")
    return redirect(url_for("admin.enrollment"))


# ── Detection Rules Management ───────────────────────────────────────────


@admin_bp.route("/rules", methods=["GET"])
@require_role("admin")
def rules():
    """Display detection rules management page."""
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        result = list_detection_rules(db)
        revision = get_detection_rules_revision(db)
        # Fetch all rule packs dynamically from the database
        rule_packs = _load_rule_packs(db)

        # ── Compute node counts per pack ──────────────────────────────────
        # For each pack, determine which nodes receive it based on:
        # 1. Explicit profile assignment (detection_pack_mode: "explicit")
        # 2. Auto matching (pack log_sources overlap with node active_parsers)
        all_nodes = db.execute("SELECT node_id, last_host_info FROM nodes").fetchall()

        # Pre-compute each pack's log_sources from its rules
        all_packs_data = get_cached_packs()
        pack_log_sources_map = {}
        for pack_data in all_packs_data:
            pack_name = pack_data["pack_name"]
            pack_sources = set()
            for rule in pack_data.get("rules", []):
                ls = rule.get("log_sources", '["*"]')
                if isinstance(ls, str):
                    try:
                        ls = json.loads(ls)
                    except (json.JSONDecodeError, TypeError):
                        ls = ["*"]
                for s in ls:
                    pack_sources.add(s)
            pack_log_sources_map[pack_name] = list(pack_sources)

        # For each node, determine which packs it receives
        pack_node_ids = {pack["pack_name"]: [] for pack in rule_packs}

        for node_row in all_nodes:
            node_id = node_row["node_id"]

            # Resolve active parsers and mode for this node
            # Check config profile for explicit assignment
            profile = resolve_effective_profile(db, node_id)
            node_active_parsers = None
            node_mode = "all"

            if profile:
                settings = (
                    json.loads(profile["settings"])
                    if isinstance(profile["settings"], str)
                    else profile["settings"]
                )
                mode = settings.get("detection_pack_mode", "auto")
                if mode == "explicit":
                    node_mode = "explicit"
                    node_active_parsers = settings.get("detection_packs", [])
                else:
                    # Auto mode on managed node: derive from profile's log_sources
                    log_sources = settings.get("log_sources", [])
                    if log_sources:
                        parsers = list(
                            set(ls.get("parser", "") for ls in log_sources if ls.get("parser"))
                        )
                        if parsers:
                            node_active_parsers = parsers
                            node_mode = "auto"

            if node_active_parsers is None and node_mode != "explicit":
                # Fall back to heartbeat-reported active_parsers
                raw_hi = node_row["last_host_info"]
                try:
                    host_info = json.loads(raw_hi) if isinstance(raw_hi, str) else raw_hi
                    ap = host_info.get("active_parsers") if host_info else None
                    if ap and isinstance(ap, list) and len(ap) > 0:
                        node_active_parsers = ap
                        node_mode = "auto"
                except (json.JSONDecodeError, TypeError):
                    pass

            # Determine which packs this node receives
            for pack in rule_packs:
                pack_name = pack["pack_name"]
                if node_mode == "explicit":
                    # node_active_parsers holds pack names in explicit mode
                    if pack_name in (node_active_parsers or []):
                        pack_node_ids[pack_name].append(node_id)
                elif node_mode == "auto":
                    # Check log_sources overlap
                    pack_sources = pack_log_sources_map.get(pack_name, ["*"])
                    if _log_sources_match(pack_sources, node_active_parsers):
                        pack_node_ids[pack_name].append(node_id)
                else:
                    # "all" mode — legacy node gets all packs
                    pack_node_ids[pack_name].append(node_id)

        # Enrich each pack with node_count and node_ids
        for pack in rule_packs:
            pack_name = pack["pack_name"]
            if pack.get("enabled", True):
                pack["node_ids"] = pack_node_ids.get(pack_name, [])
                pack["node_count"] = len(pack["node_ids"])
            else:
                pack["node_ids"] = []
                pack["node_count"] = 0
    finally:
        db.close()

    return render_template(
        "admin/rules.html",
        rules=result["rules"],
        total=result["total"],
        revision=revision,
        builtin_parsers=_BUILTIN_PARSERS,
        rule_packs=rule_packs,
    )


@admin_bp.route("/backups/run", methods=["POST"])
@require_role("admin")
def trigger_backup():
    """Run a manual backup now."""
    from app.db_backup import DEFAULT_BACKUP_DIR, perform_backup
    from app.models import get_db, get_setting, set_setting

    db_config = current_app.config["DATABASE_PATH"]
    db_path_for_type = current_app.config["DATABASE_PATH"]
    db_type = current_app.config.get("DATABASE_TYPE", "sqlite")
    if db_type == "mysql":
        db_config = {
            "type": "mysql",
            "DATABASE_HOST": current_app.config.get("DATABASE_HOST", "localhost"),
            "DATABASE_PORT": current_app.config.get("DATABASE_PORT", 3306),
            "DATABASE_USER": current_app.config.get("DATABASE_USER", "vespid"),
            "DATABASE_PASSWORD": current_app.config.get("DATABASE_PASSWORD", ""),
            "DATABASE_NAME": current_app.config.get("DATABASE_NAME", "vespid"),
        }

    db = get_db(db_path_for_type)
    try:
        backup_dir = get_setting(db, "backup_directory", DEFAULT_BACKUP_DIR)
    finally:
        db.close()

    result = perform_backup(db_config, backup_dir)

    if result:
        db2 = get_db(db_path_for_type)
        try:
            set_setting(db2, "backup_last_run", datetime.now().isoformat())
            record_audit(
                db2,
                actor=current_user.username,
                actor_ip=request.remote_addr,
                action_type="rule_created",
                target="database",
                details={"action": "manual_backup", "filename": os.path.basename(result)},
            )
        finally:
            db2.close()

        if _wants_json():
            return jsonify({"ok": True, "filename": os.path.basename(result)})
        flash(f"Backup created: {os.path.basename(result)}", "success")
    else:
        if _wants_json():
            return jsonify(
                {"error": "backup_failed", "message": "Backup failed. Check server logs."}
            ), 500
        flash("Backup failed. Check server logs for details.", "error")

    return redirect(url_for("admin.backups"))


@admin_bp.route("/backups/download/<path:filename>")
@require_role("admin")
def download_backup(filename: str):
    """Download a backup file."""
    from app.db_backup import DEFAULT_BACKUP_DIR
    from app.models import get_setting

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        backup_dir = get_setting(db, "backup_directory", DEFAULT_BACKUP_DIR)
    finally:
        db.close()

    safe_name = os.path.basename(filename)
    filepath = os.path.join(backup_dir, safe_name)
    real_dir = os.path.realpath(backup_dir)
    real_file = os.path.realpath(filepath)

    if not real_file.startswith(real_dir + os.sep) or not os.path.isfile(real_file):
        flash("Backup file not found.", "error")
        return redirect(url_for("admin.backups"))

    return send_file(real_file, as_attachment=True, download_name=safe_name)


@admin_bp.route("/backups/delete/<path:filename>", methods=["POST"])
@require_role("admin")
def delete_backup(filename: str):
    """Delete a backup file."""
    from app.db_backup import DEFAULT_BACKUP_DIR
    from app.models import get_setting

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        backup_dir = get_setting(db, "backup_directory", DEFAULT_BACKUP_DIR)
    finally:
        db.close()

    safe_name = os.path.basename(filename)
    filepath = os.path.join(backup_dir, safe_name)
    real_dir = os.path.realpath(backup_dir)
    real_file = os.path.realpath(filepath)

    if not real_file.startswith(real_dir + os.sep) or not os.path.isfile(real_file):
        if _wants_json():
            return jsonify({"error": "not_found", "message": "Backup file not found."}), 404
        flash("Backup file not found.", "error")
        return redirect(url_for("admin.backups"))

    try:
        os.remove(real_file)
        db2 = get_db(db_path)
        try:
            record_audit(
                db2,
                actor=current_user.username,
                actor_ip=request.remote_addr,
                action_type="rule_deleted",
                target="backup",
                details={"action": "delete_backup", "filename": safe_name},
            )
        finally:
            db2.close()
        if _wants_json():
            return jsonify({"ok": True, "deleted": safe_name})
        flash(f"Deleted {safe_name}", "success")
    except OSError:
        if _wants_json():
            return jsonify(
                {"error": "delete_failed", "message": "Failed to delete backup file."}
            ), 500
        flash("Failed to delete backup file.", "error")

    return redirect(url_for("admin.backups"))


@admin_bp.route("/backups/settings", methods=["POST"])
@require_role("admin")
def update_backup_settings():
    """Update backup schedule settings."""
    from app.models import set_setting

    if _wants_json():
        data = request.get_json(silent=True) or {}
        enabled = data.get("backup_enabled", "false")
        interval = str(data.get("backup_interval_hours", "24"))
        retention = str(data.get("backup_retention_days", "30"))
        backup_dir = data.get("backup_directory", "").strip()
    else:
        enabled = request.form.get("backup_enabled", "false")
        interval = request.form.get("backup_interval_hours", "24")
        retention = request.form.get("backup_retention_days", "30")
        backup_dir = request.form.get("backup_directory", "").strip()

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        set_setting(db, "backup_enabled", "true" if enabled in ("true", "on", True) else "false")

        try:
            interval_int = int(interval)
            if interval_int < 1:
                interval_int = 1
        except (ValueError, TypeError):
            interval_int = 24
        set_setting(db, "backup_interval_hours", str(interval_int))

        try:
            retention_int = int(retention)
            if retention_int < 1:
                retention_int = 1
        except (ValueError, TypeError):
            retention_int = 30
        set_setting(db, "backup_retention_days", str(retention_int))

        if backup_dir:
            set_setting(db, "backup_directory", backup_dir)

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="rule_updated",
            target="backup_settings",
            details={
                "action": "update_backup_settings",
                "enabled": enabled in ("true", "on", True),
                "interval_hours": interval_int,
                "retention_days": retention_int,
                "backup_directory": backup_dir or None,
            },
        )
    finally:
        db.close()

    if _wants_json():
        return jsonify({"ok": True})

    flash("Backup settings updated.", "success")
    return redirect(url_for("admin.backups"))


def _format_backup_size(size_bytes: int) -> str:
    if size_bytes < 1024:
        return f"{size_bytes} B"
    if size_bytes < 1048576:
        return f"{size_bytes / 1024:.1f} KB"
    if size_bytes < 1073741824:
        return f"{size_bytes / 1048576:.1f} MB"
    return f"{size_bytes / 1073741824:.2f} GB"


@admin_bp.route("/logs", methods=["GET"])
@require_role("admin")
def logs():
    """Display server log files (admin only)."""
    import os

    log_dir = current_app.config.get("LOG_DIR", "/var/log/vespid-server")
    log_files = {}
    lines = request.args.get("lines", 200, type=int)
    lines = max(50, min(lines, 2000))

    for name in ["vespid-server.log", "access.log", "error.log", "vespid-reaper.log"]:
        path = os.path.join(log_dir, name)
        if os.path.isfile(path):
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    content = fh.readlines()
                total = len(content)
                tail = content[-lines:]
                log_files[name] = {"lines": tail, "total": total}
            except OSError:
                log_files[name] = {"lines": [], "total": 0, "error": str(OSError)}
        else:
            log_files[name] = {"lines": [], "total": 0, "missing": True}

    if _wants_json():
        return jsonify(
            {
                "log_dir": log_dir,
                "lines_requested": lines,
                "log_files": {
                    name: {
                        "total": info["total"],
                        "lines": info.get("lines", []),
                        "missing": info.get("missing", False),
                    }
                    for name, info in log_files.items()
                },
            }
        )

    return render_template(
        "admin/logs.html",
        log_files=log_files,
        lines=lines,
    )


@admin_bp.route("/changelog", methods=["GET"])
@require_role("admin")
def changelog():
    """Render the server CHANGELOG as a 'What's New' page (admin only)."""
    from pathlib import Path

    from app import __version__

    changelog_path = Path(current_app.root_path).parent / "CHANGELOG.md"
    try:
        raw = changelog_path.read_text(encoding="utf-8")
    except OSError:
        raw = ""

    if _wants_json():
        return jsonify({"version": __version__, "changelog": raw})

    html = ""
    if raw:
        try:
            from markdown_it import MarkdownIt

            html = MarkdownIt("commonmark").render(raw)
        except Exception:
            from markupsafe import escape

            html = f"<pre>{escape(raw)}</pre>"

    return render_template(
        "admin/changelog.html",
        changelog_html=html,
        version=__version__,
        missing=not raw,
    )


# ── Inventory admin ──────────────────────────────────────────────────────


@admin_bp.route("/inventory", methods=["GET"])
@require_role("admin")
def inventory_admin():
    """Inventory admin page — cleanup stale assets, duplicates, orphans."""
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        stale = find_stale_assets(db)
        duplicates = find_duplicate_assets(db)
        orphans = find_orphaned_aliases(db)
        all_assets = list_assets(db, limit=500)
    finally:
        db.close()

    if _wants_json():
        return jsonify(
            {
                "stale_assets": stale,
                "duplicates": duplicates,
                "orphans": orphans,
                "all_assets": [
                    {
                        "asset_id": a["asset_id"],
                        "display_name": a.get("display_name", ""),
                        "asset_type": a.get("asset_type", ""),
                    }
                    for a in all_assets
                ],
            }
        )

    return render_template(
        "admin/inventory.html",
        stale_assets=stale,
        duplicates=duplicates,
        orphans=orphans,
        all_assets=all_assets,
    )


@admin_bp.route("/inventory/purge-stale", methods=["POST"])
@require_role("admin")
def inventory_purge_stale():
    """Delete all stale/gone assets older than 24 hours."""
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        count = purge_stale_assets(db)
        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="asset_deleted",
            target="purge_stale",
            details={"count": count},
        )
    finally:
        db.close()

    if _wants_json():
        return jsonify({"ok": True, "purged": count})

    return redirect(url_for("admin.inventory_admin"))


@admin_bp.route("/inventory/merge", methods=["POST"])
@require_role("admin")
def inventory_merge():
    """Merge two duplicate assets (keep the older one, discard the newer)."""
    if _wants_json():
        data = request.get_json(silent=True) or {}
        keep_id = (data.get("keep_id") or "").strip()
        discard_id = (data.get("discard_id") or "").strip()
    else:
        keep_id = (request.form.get("keep_id") or "").strip()
        discard_id = (request.form.get("discard_id") or "").strip()

    if not keep_id or not discard_id:
        if _wants_json():
            return jsonify(
                {"error": "missing_ids", "message": "Both keep_id and discard_id are required."}
            ), 400
        return redirect(url_for("admin.inventory_admin"))

    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        merged = merge_assets(db, keep_id, discard_id)
        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="asset_merged",
            target="merge_assets",
            details={"keep_id": keep_id, "discard_id": discard_id, "aliases_moved": merged},
        )
    finally:
        db.close()

    if _wants_json():
        return jsonify(
            {"ok": True, "keep_id": keep_id, "discard_id": discard_id, "aliases_moved": merged}
        )

    return redirect(url_for("admin.inventory_admin"))


@admin_bp.route("/inventory/<asset_id>/delete", methods=["POST"])
@require_role("admin")
def inventory_delete_asset(asset_id: str):
    """Delete a single asset (from the admin page)."""
    db_path = current_app.config["DATABASE_PATH"]
    db = get_db(db_path)
    try:
        asset = get_asset(db, asset_id)
        name = asset["display_name"] if asset else asset_id
        delete_asset_fn(db, asset_id)
        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="asset_deleted",
            target=name,
            details={"asset_id": asset_id},
        )
    finally:
        db.close()

    if _wants_json():
        return jsonify({"ok": True, "deleted": asset_id})

    return redirect(url_for("admin.inventory_admin"))
