"""User administration and the tamper-evident platform audit log."""
from flask import Blueprint, jsonify, request
from werkzeug.security import generate_password_hash

from ..crud import F, norm_datetime, validate
from ..db import get_db, now_iso, one, rows, scalar
from ..security import (ROLES, ROLE_LABELS, ApiError, create_user, current_user, password_problem, require, verify_audit_chain,
                        write_audit)

bp = Blueprint("admin", __name__, url_prefix="/api")


def _user(u):
    return {"id": u["id"], "username": u["username"], "full_name": u["full_name"], "role": u["role"],
            "role_label": ROLE_LABELS.get(u["role"]), "active": bool(u["active"]), "created_at": u["created_at"]}


@bp.get("/users")
@require("users.manage")
def list_users():
    return jsonify({"items": [_user(u) for u in rows("SELECT * FROM users ORDER BY username")]})


@bp.post("/users")
@require("users.manage")
def add_user():
    c = validate([F("username", required=True, maxlen=64), F("full_name", maxlen=128), F("password", required=True, maxlen=256),
                  F("role", "choice", True, choices=list(ROLES))], request.get_json(silent=True), partial=False)
    if not all(ch.isalnum() or ch in "._-" for ch in c["username"]) or len(c["username"]) < 3:
        raise ApiError(422, "VALIDATION_ERROR", "Invalid username.", [{"field": "username", "message": "3+ characters: letters, digits, . _ -"}])
    problem = password_problem(c["password"])
    if problem:
        raise ApiError(422, "WEAK_PASSWORD", problem, [{"field": "password", "message": problem}])
    if scalar("SELECT 1 FROM users WHERE username=?", (c["username"],)):
        raise ApiError(409, "USERNAME_TAKEN", "Username already exists.")
    create_user(c["username"], c["password"], c["role"], c.get("full_name") or "")
    write_audit("CREATE", "user", None, {"username": c["username"], "role": c["role"]})
    return jsonify(_user(one("SELECT * FROM users WHERE username=?", (c["username"],)))), 201


@bp.patch("/users/<int:uid>")
@require("users.manage")
def edit_user(uid):
    target = one("SELECT * FROM users WHERE id=?", (uid,))
    if not target:
        raise ApiError(404, "NOT_FOUND", "User not found.")
    c = validate([F("full_name", maxlen=128), F("role", "choice", choices=list(ROLES)), F("active", "bool"),
                  F("password", maxlen=256)], request.get_json(silent=True), partial=True)
    me = current_user()
    if target["id"] == me["id"] and (c.get("active") == 0 or (c.get("role") and c["role"] != target["role"])):
        raise ApiError(409, "SELF_CHANGE_FORBIDDEN", "You cannot deactivate yourself or change your own role.")
    sets, args, changed = [], [], []
    if c.get("full_name") is not None:
        sets.append("full_name=?"); args.append(c["full_name"]); changed.append("full_name")
    if c.get("role"):
        sets.append("role=?"); args.append(c["role"]); changed.append("role")
    if c.get("active") is not None:
        sets.append("active=?"); args.append(c["active"]); changed.append("active")
    if c.get("password"):
        problem = password_problem(c["password"])
        if problem:
            raise ApiError(422, "WEAK_PASSWORD", problem, [{"field": "password", "message": problem}])
        sets += ["password_hash=?", "failed_attempts=0", "locked_until=NULL"]
        args.append(generate_password_hash(c["password"])); changed.append("password_reset")
    if sets:
        get_db().execute(f"UPDATE users SET {','.join(sets)} WHERE id=?", args + [uid])
        get_db().commit()
        write_audit("UPDATE", "user", uid, {"changed": changed})
    return jsonify(_user(one("SELECT * FROM users WHERE id=?", (uid,))))


@bp.get("/audit-log")
@require("auditlog.read")
def audit_log():
    try:
        limit = max(1, min(int(request.args.get("limit", 50)), 200))
        offset = max(0, int(request.args.get("offset", 0)))
    except ValueError:
        raise ApiError(422, "VALIDATION_ERROR", "limit/offset must be integers.")
    where, args = [], []
    for col, key in (("actor", "actor"), ("action", "action"), ("entity", "entity")):
        v = request.args.get(key)
        if v:
            where.append(f"{col}=?"); args.append(v)
    sql = "FROM audit_log" + (" WHERE " + " AND ".join(where) if where else "")
    total = scalar("SELECT COUNT(*) " + sql, args)
    items = rows("SELECT id,ts,actor,action,entity,entity_id,details,entry_hash " + sql + " ORDER BY id DESC LIMIT ? OFFSET ?", args + [limit, offset])
    return jsonify({"items": items, "total": total, "limit": limit, "offset": offset})


@bp.get("/audit-log/verify")
@require("auditlog.read")
def audit_verify():
    return jsonify(verify_audit_chain())
