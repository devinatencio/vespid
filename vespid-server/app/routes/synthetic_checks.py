"""Synthetic Monitoring Checks blueprint — HTML pages only.

API endpoints moved to app/synth_api.py.

Endpoints:
    GET  /alerts/synthetic-checks                  — Checks list page
    GET  /alerts/synthetic-checks/new              — Create check form
    GET  /alerts/synthetic-checks/<check_id>       — Check detail page
    GET  /alerts/synthetic-checks/<check_id>/edit  — Edit check form
    GET  /alerts/synthetic-alerts                  — Redirect to checks page
    GET  /alerts/synthetic-alerts/new              — Create alert form
    GET  /alerts/synthetic-alerts/<rule_id>/edit   — Edit alert form
"""

import logging

from flask import Blueprint, redirect, render_template, url_for

from app.decorators import require_role

synth_bp = Blueprint("synthetic_checks", __name__)
logger = logging.getLogger(__name__)


# ── HTML Pages ─────────────────────────────────────────────────────────────


@synth_bp.route("/alerts/synthetic-checks", strict_slashes=False)
@require_role("viewer")
def list_page():
    """Synthetic checks list page."""
    return render_template("synthetic_checks/list.html")


@synth_bp.route("/alerts/synthetic-checks/new", strict_slashes=False)
@require_role("admin")
def new_page():
    """Create synthetic check form."""
    return render_template("synthetic_checks/form.html", check=None, edit=False)


@synth_bp.route("/alerts/synthetic-checks/<int:check_id>", strict_slashes=False)
@require_role("viewer")
def detail_page(check_id: int):
    """Synthetic check detail page."""
    return render_template("synthetic_checks/detail.html", check_id=check_id)


@synth_bp.route("/alerts/synthetic-checks/<int:check_id>/edit", strict_slashes=False)
@require_role("admin")
def edit_page(check_id: int):
    """Edit synthetic check form."""
    return render_template("synthetic_checks/form.html", check_id=check_id, edit=True)


# ── Alert Rule HTML Pages ─────────────────────────────────────────────


@synth_bp.route("/alerts/synthetic-alerts")
@require_role("viewer")
def alerts_page():
    """Redirect to synthetic checks page (alert rules now shown inline)."""
    return redirect(url_for("synthetic_checks.list_page"))


@synth_bp.route("/alerts/synthetic-alerts/new")
@require_role("admin")
def alert_new_page():
    """Create alert rule form."""
    return render_template("synthetic_alerts/form.html", rule=None, edit=False)


@synth_bp.route("/alerts/synthetic-alerts/<int:rule_id>/edit")
@require_role("admin")
def alert_edit_page(rule_id: int):
    """Edit alert rule form."""
    return render_template("synthetic_alerts/form.html", rule_id=rule_id, edit=True)
