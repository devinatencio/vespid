"""Role-based access control decorators.

Provides @require_auth and @require_role decorators for protecting
Flask routes with authentication and role-based authorization.

Supports both session-based auth (Flask-Login) and Bearer token auth
(API keys). Bearer tokens are checked when the user is not already
authenticated via session.
"""

from functools import wraps

from flask import abort, jsonify, redirect, request, url_for
from flask_login import current_user, login_user

# Role hierarchy: admin > analyst > viewer
# 'agent' keys are treated as admin-level (they are server-trusted API keys
# used by nodes and the CLI for full operational access).
ROLE_HIERARCHY = {
    "admin": 3,
    "agent": 3,
    "analyst": 2,
    "viewer": 1,
}


def _try_bearer_auth():
    """Attempt to authenticate via Bearer token if no session is active.

    Returns True if authentication succeeded, False otherwise.
    Does not abort — the caller decides what to do on failure.
    """
    if current_user.is_authenticated:
        return True

    from app.routes.auth import authenticate_bearer_token

    api_key, error_response = authenticate_bearer_token()
    if api_key is None:
        return False

    # Determine role — column may not exist on older databases
    try:
        role = api_key.get("role") or "agent"
    except (IndexError, KeyError):
        role = "agent"

    # Create a minimal user-like object for role checking
    from app.routes.auth import User

    user = User(
        {
            "id": api_key["id"],
            "username": api_key.get("label", f"apikey-{api_key['id']}"),
            "role": role,
            "password_hash": "",
        }
    )
    login_user(user, remember=False)
    return True


def _is_api_request() -> bool:
    """Determine if this is an API/CLI request vs a browser request."""
    accept = request.headers.get("Accept", "")
    content_type = request.headers.get("Content-Type", "")
    auth = request.headers.get("Authorization", "")
    return (
        "application/json" in accept
        or "application/json" in content_type
        or auth.startswith("Bearer ")
    )


def require_auth(f):
    """Redirect to /login if the current user is not authenticated.

    Use this decorator on routes that require any authenticated user,
    regardless of role. Supports Bearer token auth for API clients.
    """

    @wraps(f)
    def decorated_function(*args, **kwargs):
        _try_bearer_auth()
        if not current_user.is_authenticated:
            if _is_api_request():
                return jsonify({"error": "unauthorized", "message": "Authentication required"}), 401
            return redirect(url_for("auth.login"))
        return f(*args, **kwargs)

    return decorated_function


def require_role(*roles: str):
    """Deny access if the user's role is not in the allowed set.

    Respects the role hierarchy: admin > analyst > viewer.
    If a route requires 'viewer', then analyst and admin can also access it.
    If a route requires 'analyst', then admin can also access it.

    Supports Bearer token auth for API/CLI clients. Returns JSON errors
    for API requests instead of HTML redirects.

    Args:
        *roles: One or more role names that are allowed to access the route.

    Returns:
        A decorator that checks authentication and role authorization.
    """

    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            _try_bearer_auth()

            if not current_user.is_authenticated:
                if _is_api_request():
                    return jsonify(
                        {"error": "unauthorized", "message": "Authentication required"}
                    ), 401
                return redirect(url_for("auth.login"))

            # Determine the minimum required level from the allowed roles
            min_required_level = min(ROLE_HIERARCHY.get(r, 0) for r in roles)

            # Get the user's level from the hierarchy
            user_level = ROLE_HIERARCHY.get(current_user.role, 0)

            if user_level < min_required_level:
                if _is_api_request():
                    return jsonify(
                        {"error": "forbidden", "message": f"Requires role: {', '.join(roles)}"}
                    ), 403
                abort(403)

            return f(*args, **kwargs)

        return decorated_function

    return decorator
