"""Authentication, RBAC, CSRF, hash-chained audit log and API error handling."""
import hashlib
import hmac
import json
import secrets
import sqlite3
import threading
import time
from collections import defaultdict, deque
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import current_app, g, jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from .db import connect_standalone, get_db, now_iso

ROLES = ("admin", "analyst", "auditor", "viewer")
ROLE_LABELS = {"admin": "CISO / Security lead", "analyst": "Security analyst", "auditor": "Audit lead",
               "viewer": "Executive viewer (read-only)"}
PERMISSIONS = {
    "admin": {"*"},
    "analyst": {"threats.write", "incidents.write", "policy.write", "awareness.write", "vulns.write"},
    "auditor": {"auditplan.write", "auditlog.read"},
    "viewer": set(),
}
# permissions granted to every signed-in user
COMMON = {"quiz.submit", "data.read", "reports.read"}


class ApiError(Exception):
    def __init__(self, status, code, message, details=None):
        super().__init__(message)
        self.status, self.code, self.message, self.details = status, code, message, details


def has_perm(role, perm):
    perms = PERMISSIONS.get(role, set())
    return perm in COMMON or "*" in perms or perm in perms


def permissions_for(role):
    if role == "admin":
        return sorted(COMMON | {"threats.write", "incidents.write", "policy.write", "awareness.write", "vulns.write",
                                "auditplan.write", "auditlog.read", "users.manage"})
    return sorted(COMMON | PERMISSIONS.get(role, set()))


# ---------------------------------------------------------------- audit log
_audit_lock = threading.Lock()


def _entry_hash(prev, ts, actor, action, entity, entity_id, details):
    payload = json.dumps([ts, actor, action, entity, entity_id, details], sort_keys=True, separators=(",", ":"))
    return hashlib.sha256((prev + payload).encode()).hexdigest()


def write_audit(action, entity=None, entity_id=None, details=None, actor=None):
    """Append-only, hash-chained audit entry (own transaction so denials/failures are kept)."""
    if actor is None:
        u = getattr(g, "user", None)
        actor = u["username"] if u else None
    details_s = json.dumps(details or {}, sort_keys=True, default=str)
    with _audit_lock:
        conn = connect_standalone(current_app.config["DATABASE"])
        try:
            last = conn.execute("SELECT entry_hash FROM audit_log ORDER BY id DESC LIMIT 1").fetchone()
            prev = last[0] if last else "GENESIS"
            ts = now_iso()
            h = _entry_hash(prev, ts, actor, action, entity, str(entity_id) if entity_id is not None else None, details_s)
            conn.execute("INSERT INTO audit_log(ts,actor,action,entity,entity_id,details,prev_hash,entry_hash) VALUES(?,?,?,?,?,?,?,?)",
                         (ts, actor, action, entity, str(entity_id) if entity_id is not None else None, details_s, prev, h))
            conn.commit()
        finally:
            conn.close()


def verify_audit_chain():
    conn = connect_standalone(current_app.config["DATABASE"])
    try:
        prev, n = "GENESIS", 0
        for r in conn.execute("SELECT * FROM audit_log ORDER BY id"):
            n += 1
            if r["prev_hash"] != prev or _entry_hash(prev, r["ts"], r["actor"], r["action"], r["entity"], r["entity_id"], r["details"]) != r["entry_hash"]:
                return {"valid": False, "entries_checked": n, "first_invalid_id": r["id"]}
            prev = r["entry_hash"]
        return {"valid": True, "entries_checked": n, "first_invalid_id": None}
    finally:
        conn.close()


# ---------------------------------------------------------------- users / sessions
def current_user():
    if "user" in g:
        return g.user
    uid = session.get("uid")
    user = None
    if uid:
        row = get_db().execute("SELECT id,username,full_name,role,active FROM users WHERE id=?", (uid,)).fetchone()
        if row and row["active"]:
            user = dict(row)
    g.user = user
    return user


def public_user(u):
    return {"id": u["id"], "username": u["username"], "full_name": u["full_name"], "role": u["role"],
            "role_label": ROLE_LABELS.get(u["role"], u["role"]), "permissions": permissions_for(u["role"])}


def login_required(fn):
    @wraps(fn)
    def wrapper(*a, **kw):
        if not current_user():
            raise ApiError(401, "UNAUTHENTICATED", "Please sign in.")
        return fn(*a, **kw)
    return wrapper


def require(perm):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            u = current_user()
            if not u:
                raise ApiError(401, "UNAUTHENTICATED", "Please sign in.")
            if not has_perm(u["role"], perm):
                write_audit("AUTHZ_DENIED", details={"permission": perm, "path": request.path, "method": request.method})
                raise ApiError(403, "FORBIDDEN", "Your role does not allow this action.")
            return fn(*a, **kw)
        return wrapper
    return deco


def authenticate(username, password):
    cfg = current_app.config
    db = get_db()
    row = db.execute("SELECT * FROM users WHERE username=?", (username,)).fetchone()
    now = datetime.now(timezone.utc)
    if row is None:
        check_password_hash(_DUMMY, password)  # equalise timing
        write_audit("LOGIN_FAILED", details={"reason": "unknown_user"}, actor=username[:64])
        raise ApiError(401, "INVALID_CREDENTIALS", "Invalid username or password.")
    if row["locked_until"] and datetime.fromisoformat(row["locked_until"].replace("Z", "+00:00")) > now:
        write_audit("LOGIN_FAILED", details={"reason": "locked"}, actor=username)
        raise ApiError(423, "ACCOUNT_LOCKED", "Account temporarily locked. Try again later.")
    if not row["active"] or not check_password_hash(row["password_hash"], password):
        attempts = row["failed_attempts"] + 1
        locked = None
        if attempts >= cfg["MAX_FAILED_LOGINS"]:
            locked = (now + timedelta(minutes=cfg["LOCKOUT_MINUTES"])).strftime("%Y-%m-%dT%H:%M:%SZ")
            attempts = 0
        db.execute("UPDATE users SET failed_attempts=?, locked_until=? WHERE id=?", (attempts, locked, row["id"]))
        db.commit()
        write_audit("LOGIN_FAILED", details={"reason": "bad_credentials"}, actor=username)
        raise ApiError(401, "INVALID_CREDENTIALS", "Invalid username or password.")
    db.execute("UPDATE users SET failed_attempts=0, locked_until=NULL WHERE id=?", (row["id"],))
    db.commit()
    return dict(row)


_DUMMY = generate_password_hash("dummy-password-for-timing")
_login_hits = defaultdict(deque)
_rl_lock = threading.Lock()


def login_rate_ok(key):
    limit = current_app.config["LOGIN_RATE_PER_MIN"]
    now = time.monotonic()
    with _rl_lock:
        q = _login_hits[key]
        while q and now - q[0] > 60:
            q.popleft()
        if len(q) >= limit:
            return False
        q.append(now)
        return True


def start_session(user):
    session.clear()
    session["uid"] = user["id"]
    session["csrf"] = secrets.token_urlsafe(24)
    session.permanent = True
    return session["csrf"]


def check_csrf():
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    if request.endpoint == "auth.login":
        return
    token = request.headers.get("X-CSRF-Token", "")
    expected = session.get("csrf", "")
    if not expected or not hmac.compare_digest(token, expected):
        raise ApiError(403, "CSRF", "Missing or invalid CSRF token. Reload the page and sign in again.")


def create_user(username, password, role, full_name=""):
    db = get_db()
    db.execute("INSERT INTO users(username,full_name,password_hash,role,active,created_at) VALUES(?,?,?,?,1,?)",
               (username, full_name or username, generate_password_hash(password), role, now_iso()))
    db.commit()


def password_problem(pw):
    if len(pw) < 10:
        return "Password must be at least 10 characters."
    if not any(c.isalpha() for c in pw) or not any(c.isdigit() for c in pw):
        return "Password must contain letters and digits."
    return None


def register_error_handlers(app):
    @app.errorhandler(ApiError)
    def _api(e):
        return jsonify({"error": {"code": e.code, "message": e.message, "details": e.details}}), e.status

    @app.errorhandler(404)
    def _404(_e):
        if request.path.startswith("/api/"):
            return jsonify({"error": {"code": "NOT_FOUND", "message": "Resource not found.", "details": None}}), 404
        return ("Not found", 404)

    @app.errorhandler(405)
    def _405(_e):
        return jsonify({"error": {"code": "METHOD_NOT_ALLOWED", "message": "Method not allowed.", "details": None}}), 405

    @app.errorhandler(413)
    def _413(_e):
        return jsonify({"error": {"code": "TOO_LARGE", "message": "Upload is too large.", "details": None}}), 413

    @app.errorhandler(sqlite3.IntegrityError)
    def _integrity(e):
        app.logger.warning("integrity error: %s", e)
        return jsonify({"error": {"code": "CONFLICT", "message": "The change conflicts with existing data (duplicate or referenced record).", "details": None}}), 409

    @app.errorhandler(Exception)
    def _500(e):
        app.logger.exception("unhandled error")
        return jsonify({"error": {"code": "INTERNAL_ERROR", "message": "Unexpected server error.", "details": None}}), 500
