"""Authentication blueprint.

Handles login, logout, session management via Flask-Login,
and audit log recording for authentication events.
"""

from datetime import UTC, datetime, timedelta

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    url_for,
)
from flask_login import UserMixin, current_user, login_user, logout_user
from werkzeug.security import check_password_hash

from app.models import (
    change_user_password,
    get_db,
    get_user_by_id,
    get_user_by_username,
    record_audit,
    update_brand_beam_enabled,
    update_user_display_name,
    update_user_theme,
)
from app.rate_limit import limiter
from app.themes import get_all_themes

auth_bp = Blueprint("auth", __name__)

_LOGIN_RATE_LIMIT = "10 per minute"
_MAX_FAILED_ATTEMPTS = 5
_FAILED_WINDOW_MINUTES = 15
_LOCKOUT_DURATION_MINUTES = 15


class User(UserMixin):
    """Flask-Login compatible user class.

    Wraps a user dict from the database and exposes the attributes
    required by Flask-Login (is_authenticated, is_active, is_anonymous,
    get_id) via the UserMixin base class.
    """

    def __init__(self, user_dict: dict):
        self._data = user_dict
        self.id = user_dict["id"]
        self.username = user_dict["username"]
        self.role = user_dict["role"]
        self.password_hash = user_dict["password_hash"]
        self.display_name = user_dict.get("display_name", "") or ""
        self.theme = user_dict.get("theme", "dark") or "dark"
        self.onboarding_dismissed = bool(user_dict.get("onboarding_dismissed", 0))
        self.brand_beam_enabled = bool(user_dict.get("brand_beam_enabled", 1))

    def get_id(self) -> str:
        """Return the user id as a string for Flask-Login."""
        return str(self.id)


def init_login_manager(app):
    """Configure the Flask-Login user_loader callback on the app.

    This should be called during app factory setup so that Flask-Login
    can reload users from the session cookie.

    Args:
        app: The Flask application instance.
    """

    @app.login_manager.user_loader
    def load_user(user_id):
        """Load a user by ID for Flask-Login session management."""
        db_path = app.config.get("DATABASE_PATH")
        if not db_path:
            return None
        db = get_db(db_path)
        try:
            user_dict = get_user_by_id(db, int(user_id))
            if user_dict is None:
                return None
            return User(user_dict)
        finally:
            db.close()


def _is_account_locked(user_dict: dict) -> bool:
    """Check whether an account is currently locked out.

    Accounts auto-unlock after the lockout duration expires.
    """
    locked_until = user_dict.get("locked_until")
    if not locked_until:
        return False
    try:
        lock_dt = datetime.fromisoformat(locked_until.replace("Z", "+00:00"))
        if lock_dt.tzinfo is None:
            lock_dt = lock_dt.replace(tzinfo=UTC)
    except (ValueError, TypeError):
        return False
    return datetime.now(UTC) < lock_dt


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit(_LOGIN_RATE_LIMIT)
def login():
    """Handle login: render form on GET, authenticate on POST."""
    if request.method == "GET":
        if current_user.is_authenticated:
            return redirect(url_for("dashboard.index"))
        return render_template("login.html")

    # POST: authenticate credentials
    username = request.form.get("username", "").strip()
    password = request.form.get("password", "")
    actor_ip = request.remote_addr

    db_path = current_app.config.get("DATABASE_PATH")
    db = get_db(db_path)
    try:
        user_dict = get_user_by_username(db, username)
        now_utc = datetime.now(UTC)
        now_str = now_utc.strftime("%Y-%m-%dT%H:%M:%SZ")

        # Check if account exists and is locked
        if user_dict is not None and _is_account_locked(user_dict):
            record_audit(
                db,
                actor=username or "unknown",
                actor_ip=actor_ip,
                action_type="login_failed",
                target=None,
                details={"reason": "account_locked"},
            )
            flash(
                "Account is temporarily locked due to too many failed attempts. Please try again later.",
                "error",
            )
            return render_template("login.html"), 401

        if user_dict is None or not check_password_hash(user_dict["password_hash"], password):
            # Failed login attempt — increment counter and potentially lock
            if user_dict is not None:
                attempts = (user_dict.get("failed_login_attempts", 0) or 0) + 1
                if attempts >= _MAX_FAILED_ATTEMPTS:
                    lock_until = (now_utc + timedelta(minutes=_LOCKOUT_DURATION_MINUTES)).strftime(
                        "%Y-%m-%dT%H:%M:%SZ"
                    )
                    db.execute(
                        "UPDATE users SET failed_login_attempts = ?, locked_until = ? WHERE id = ?",
                        (attempts, lock_until, user_dict["id"]),
                    )
                    record_audit(
                        db,
                        actor=username,
                        actor_ip=actor_ip,
                        action_type="user_locked_out",
                        target=username,
                        details={"failed_attempts": attempts, "locked_until": lock_until},
                    )
                else:
                    db.execute(
                        "UPDATE users SET failed_login_attempts = ? WHERE id = ?",
                        (attempts, user_dict["id"]),
                    )
                db.commit()
            record_audit(
                db,
                actor=username or "unknown",
                actor_ip=actor_ip,
                action_type="login_failed",
                target=None,
                details={"reason": "invalid_credentials"},
            )
            flash("Invalid username or password", "error")
            return render_template("login.html"), 401

        # Successful login — reset lockout counters
        user = User(user_dict)
        login_user(user)

        db.execute(
            "UPDATE users SET last_login_at = ?, failed_login_attempts = 0, locked_until = NULL WHERE id = ?",
            (now_str, user.id),
        )
        db.commit()

        record_audit(
            db,
            actor=username,
            actor_ip=actor_ip,
            action_type="login",
            target=None,
            details={},
        )

        return redirect(url_for("dashboard.index"))
    finally:
        db.close()


@auth_bp.route("/logout", methods=["POST"])
def logout():
    """Destroy session, record audit log entry, redirect to login."""
    if current_user.is_authenticated:
        username = current_user.username
        actor_ip = request.remote_addr

        db_path = current_app.config.get("DATABASE_PATH")
        db = get_db(db_path)
        try:
            record_audit(
                db,
                actor=username,
                actor_ip=actor_ip,
                action_type="logout",
                target=None,
                details={},
            )
        finally:
            db.close()

    logout_user()
    return redirect(url_for("auth.login"))


@auth_bp.route("/onboarding/dismiss", methods=["POST"])
def dismiss_onboarding():
    """Mark the onboarding dialog as dismissed for the current user."""
    if not current_user.is_authenticated:
        return {"status": "error", "reason": "not_authenticated"}, 401

    db_path = current_app.config.get("DATABASE_PATH")
    db = get_db(db_path)
    try:
        db.execute(
            "UPDATE users SET onboarding_dismissed = 1 WHERE id = ?",
            (current_user.id,),
        )
        db.commit()
        current_user.onboarding_dismissed = True
        return {"status": "ok"}, 200
    finally:
        db.close()


@auth_bp.route("/account")
def account():
    """Show the current user's account settings page."""
    return render_template("account.html")


@auth_bp.route("/account/password", methods=["POST"])
def change_password():
    """Change the current user's password (self-service).

    Requires the user to provide their current password for verification,
    then validates the new password and updates it.
    """
    if not current_user.is_authenticated:
        return redirect(url_for("auth.login"))

    current_password = request.form.get("current_password", "")
    new_password = request.form.get("new_password", "")
    confirm_password = request.form.get("confirm_password", "")

    # Validate current password
    if not check_password_hash(current_user.password_hash, current_password):
        flash("Current password is incorrect.", "error")
        return redirect(url_for("auth.account"))

    # Validate new password
    if not new_password:
        flash("New password is required.", "error")
        return redirect(url_for("auth.account"))

    if len(new_password) < 8:
        flash("New password must be at least 8 characters.", "error")
        return redirect(url_for("auth.account"))

    if new_password != confirm_password:
        flash("New passwords do not match.", "error")
        return redirect(url_for("auth.account"))

    if current_password == new_password:
        flash("New password must be different from current password.", "error")
        return redirect(url_for("auth.account"))

    db_path = current_app.config.get("DATABASE_PATH")
    db = get_db(db_path)
    try:
        change_user_password(db, current_user.id, new_password)

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="password_change",
            target=current_user.username,
            details={"changed_by": "self"},
        )
    finally:
        db.close()

    flash("Password changed successfully.", "success")
    return redirect(url_for("auth.account"))


@auth_bp.route("/account/display-name", methods=["POST"])
def update_account_display_name():
    """Update the current user's display name."""
    if not current_user.is_authenticated:
        return redirect(url_for("auth.login"))

    display_name = request.form.get("display_name", "").strip()[:128]

    db_path = current_app.config.get("DATABASE_PATH")
    db = get_db(db_path)
    try:
        update_user_display_name(db, current_user.id, display_name)

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="profile_update",
            target=current_user.username,
            details={"field": "display_name"},
        )
    finally:
        db.close()

    flash("Display name updated.", "success")
    return redirect(url_for("auth.account"))


def _valid_themes():
    """Return the set of all valid theme names (built-in + custom)."""
    theme_dir = current_app.config.get("CUSTOM_THEME_DIR")
    return frozenset(get_all_themes(theme_dir))


@auth_bp.route("/account/theme", methods=["POST"])
def update_account_theme():
    """Update the current user's theme preference."""
    if not current_user.is_authenticated:
        return redirect(url_for("auth.login"))

    theme = request.form.get("theme", "").strip()

    if theme not in _valid_themes():
        flash(f"Invalid theme '{theme}'.", "error")
        return redirect(url_for("auth.account"))

    db_path = current_app.config.get("DATABASE_PATH")
    db = get_db(db_path)
    try:
        update_user_theme(db, current_user.id, theme)

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="profile_update",
            target=current_user.username,
            details={"field": "theme", "value": theme},
        )
    finally:
        db.close()

    flash(f"Theme set to '{theme}'.", "success")
    return redirect(url_for("auth.account"))


@auth_bp.route("/account/brand-beam", methods=["POST"])
def update_brand_beam():
    """Toggle the brand sweep beam animation on/off for the current user."""
    if not current_user.is_authenticated:
        return redirect(url_for("auth.login"))

    enabled = request.form.get("enabled", "1") == "1"

    db_path = current_app.config.get("DATABASE_PATH")
    db = get_db(db_path)
    try:
        update_brand_beam_enabled(db, current_user.id, enabled)
        current_user.brand_beam_enabled = enabled

        record_audit(
            db,
            actor=current_user.username,
            actor_ip=request.remote_addr,
            action_type="profile_update",
            target=current_user.username,
            details={"field": "brand_beam", "value": "enabled" if enabled else "disabled"},
        )
    finally:
        db.close()

    flash("Brand beam " + ("enabled." if enabled else "disabled."), "success")
    return redirect(url_for("auth.account"))


# ---------------------------------------------------------------------------
# Bearer token auth (for API/agent-facing endpoints)
# ---------------------------------------------------------------------------


import hashlib  # noqa: E402

from app.models import get_request_db  # noqa: E402


def authenticate_bearer_token():
    """Authenticate the request using a Bearer token against the api_keys table.

    Returns:
        A tuple of ``(api_key_dict, error_response)``. On success
        ``error_response`` is ``None``. On failure ``api_key_dict`` is
        ``None`` and ``error_response`` is a Flask ``(response, status)``
        tuple.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        return None, (
            jsonify({"error": "unauthorized", "message": "Missing or invalid Bearer token"}),
            401,
        )

    token = auth_header[7:]
    if not token.strip():
        return None, (
            jsonify({"error": "unauthorized", "message": "Missing or invalid Bearer token"}),
            401,
        )

    db = get_request_db()
    key_hash = hashlib.sha256(token.encode()).hexdigest()
    row = db.execute("SELECT * FROM api_keys WHERE key_hash = ?", (key_hash,)).fetchone()

    if row is None:
        return None, (
            jsonify({"error": "unauthorized", "message": "Invalid API key"}),
            401,
        )

    if not row["is_active"]:
        return None, (
            jsonify({"error": "key_revoked", "message": "API key has been revoked"}),
            401,
        )

    return dict(row), None
