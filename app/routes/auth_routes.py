from flask import Blueprint, jsonify, request, session

from ..db import get_db
from ..security import (ApiError, authenticate, current_user, login_rate_ok, login_required, public_user,
                        start_session, write_audit)

bp = Blueprint("auth", __name__, url_prefix="/api/auth")


@bp.post("/login")
def login():
    if not login_rate_ok(request.remote_addr or "unknown"):
        raise ApiError(429, "RATE_LIMITED", "Too many login attempts. Try again shortly.")
    data = request.get_json(silent=True) or {}
    username, password = str(data.get("username", "")).strip(), str(data.get("password", ""))
    if not username or not password or len(username) > 64 or len(password) > 256:
        raise ApiError(422, "VALIDATION_ERROR", "Username and password are required.")
    user = authenticate(username, password)
    csrf = start_session(user)
    write_audit("LOGIN", "user", user["id"], {}, actor=user["username"])
    return jsonify({"user": public_user(user), "csrf": csrf})


@bp.post("/logout")
@login_required
def logout():
    write_audit("LOGOUT")
    session.clear()
    return jsonify({"ok": True})


@bp.get("/me")
def me():
    u = current_user()
    if not u:
        raise ApiError(401, "UNAUTHENTICATED", "Please sign in.")
    if "csrf" not in session:
        session["csrf"] = __import__("secrets").token_urlsafe(24)
    return jsonify({"user": public_user(u), "csrf": session["csrf"]})


@bp.get("/session")
def session_info():
    """Always 200: lets the UI check for an existing session without a failing (401) request."""
    u = current_user()
    if not u:
        return jsonify({"authenticated": False})
    if "csrf" not in session:
        session["csrf"] = __import__("secrets").token_urlsafe(24)
    return jsonify({"authenticated": True, "user": public_user(u), "csrf": session["csrf"]})
