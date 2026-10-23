"""Week 2 - Incident response: register, timeline, evidence (SHA-256), decisions, actions, metrics."""
import hashlib
import json
import os
import re
import secrets
from datetime import datetime, timedelta, timezone

from flask import Blueprint, current_app, jsonify, request, send_file

from .. import reference as R
from ..crud import F, Resource, clean_value, validate
from ..db import get_db, jload, now_iso, one, rows, scalar
from ..security import ApiError, current_user, login_required, require, write_audit

bp = Blueprint("incidents", __name__, url_prefix="/api")

SEV = {s["level"]: s for s in R.SEVERITY_MODEL}
STATUS_IDX = {s: i for i, s in enumerate(R.INCIDENT_STATUSES)}
OPEN_STATES = [s for s in R.INCIDENT_STATUSES if s != "Closed"]
STAMPS = {"Declared": "declared_at", "Contained": "contained_at", "Recovered": "recovered_at", "Closed": "closed_at"}


def parse_dt(s):
    return datetime.fromisoformat(s.replace("Z", "+00:00")) if s else None


def iso(dt):
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def add_business_days(dt, n):
    while n > 0:
        dt += timedelta(days=1)
        if dt.weekday() < 5:
            n -= 1
    return dt


def minutes(a, b):
    if not a or not b:
        return None
    return round((parse_dt(b) - parse_dt(a)).total_seconds() / 60, 1)


def decorate(d):
    d["checklist15"] = jload(d.get("checklist15"), []) if isinstance(d.get("checklist15"), str) else d.get("checklist15", [])
    d["checklist24"] = jload(d.get("checklist24"), []) if isinstance(d.get("checklist24"), str) else d.get("checklist24", [])
    d["closure_checks"] = jload(d.get("closure_checks"), []) if isinstance(d.get("closure_checks"), str) else d.get("closure_checks", [])
    d["is_open"] = d["status"] != "Closed"
    rep = parse_dt(d["reported_at"])
    sev = SEV[d["severity"]]
    due = add_business_days(rep, 1) if d["severity"] == "SEV-4" else rep + timedelta(minutes=sev["ack_minutes"])
    d["ack_target"] = sev["ack_text"]
    d["ack_due"] = iso(due)
    now = datetime.now(timezone.utc)
    if d.get("acknowledged_at"):
        d["ack_breached"] = parse_dt(d["acknowledged_at"]) > due
    else:
        d["ack_breached"] = d["is_open"] and now > due
    d["ack_pending"] = d["is_open"] and not d.get("acknowledged_at")
    start = d.get("started_at") or d["reported_at"]
    d["metrics"] = {"time_to_acknowledge_min": minutes(d["reported_at"], d.get("acknowledged_at")),
                    "time_to_declare_min": minutes(d["reported_at"], d.get("declared_at")),
                    "time_to_contain_min": minutes(start, d.get("contained_at")),
                    "time_to_recover_min": minutes(start, d.get("recovered_at"))}
    d["checklist15_done"], d["checklist15_total"] = len(d["checklist15"]), len(R.CHECKLIST_15)
    d["checklist24_done"], d["checklist24_total"] = len(d["checklist24"]), len(R.CHECKLIST_24)
    d["closure_done"], d["closure_total"] = len(d["closure_checks"]), len(R.CLOSURE_CRITERIA)
    d["management_involvement"] = sev["management"]
    d["update_cadence"] = sev["cadence"]
    if d["cert_in_assessment"] == "Required":
        dl = rep + timedelta(hours=6)
        d["cert_in_deadline"] = iso(dl)
        if d.get("cert_in_reported_at"):
            d["cert_in_state"] = "Reported within 6h" if parse_dt(d["cert_in_reported_at"]) <= dl else "Reported late"
        else:
            hrs = (dl - now).total_seconds() / 3600
            d["cert_in_state"] = "OVERDUE" if hrs < 0 else f"Due in {hrs:.1f} h"
        d["cert_in_hours_left"] = None if d.get("cert_in_reported_at") else round((dl - now).total_seconds() / 3600, 2)
    else:
        d["cert_in_deadline"], d["cert_in_state"], d["cert_in_hours_left"] = None, None, None
    return d


def before_save(clean, existing, user):
    merged = {**(existing or {}), **clean}
    rep = merged.get("reported_at")
    for k in ("acknowledged_at", "declared_at", "contained_at", "recovered_at", "closed_at"):
        if merged.get(k) and rep and merged[k] < rep:
            raise ApiError(422, "VALIDATION_ERROR", "Timestamp order is invalid.",
                           [{"field": k, "message": "cannot be earlier than the report time"}])
    for key, size in (("checklist15", len(R.CHECKLIST_15)), ("checklist24", len(R.CHECKLIST_24)), ("closure_checks", len(R.CLOSURE_CRITERIA))):
        if key in clean:
            items = json.loads(clean[key]) if isinstance(clean[key], str) else clean[key]
            if not all(isinstance(i, int) and not isinstance(i, bool) and 0 <= i < size for i in items):
                raise ApiError(422, "VALIDATION_ERROR", "Invalid checklist items.", [{"field": key, "message": f"items must be integers 0-{size - 1}"}])
            clean[key] = json.dumps(sorted(set(items)))
    new_status = clean.get("status")
    if new_status and (existing is None or new_status != existing["status"]):
        for st, col in STAMPS.items():
            if STATUS_IDX[new_status] >= STATUS_IDX[st] and not merged.get(col):
                clean[col] = now_iso()
        merged = {**(existing or {}), **clean}
    if merged.get("status") == "Closed":
        checks = merged.get("closure_checks")
        checks = jload(checks, []) if isinstance(checks, str) else (checks or [])
        problems = []
        if not (merged.get("closure_summary") or "").strip():
            problems.append({"field": "closure_summary", "message": "required to close an incident"})
        if len(set(checks)) != len(R.CLOSURE_CRITERIA):
            problems.append({"field": "closure_checks", "message": "all seven closure criteria must be confirmed"})
        if problems:
            raise ApiError(422, "CLOSURE_CRITERIA_NOT_MET", "The incident cannot be closed until the closure criteria are met.", problems)
    if existing is None:
        year = (merged["reported_at"] or now_iso())[:4]
        n = scalar("SELECT COUNT(*) FROM incidents WHERE ref LIKE ?", (f"IR-{year}-%",)) + 1
        while scalar("SELECT 1 FROM incidents WHERE ref=?", (f"IR-{year}-{n:03d}",)):
            n += 1
        clean["ref"] = f"IR-{year}-{n:03d}"
        clean["created_by"] = user["username"]
    return clean


INC_FIELDS = [
    F("title", required=True), F("category", "choice", True, choices=R.INCIDENT_CATEGORIES),
    F("severity", "choice", True, choices=list(SEV)), F("status", "choice", choices=R.INCIDENT_STATUSES, default="Reported"),
    F("started_at", "datetime"), F("reported_at", "datetime", True), F("acknowledged_at", "datetime"), F("declared_at", "datetime"),
    F("contained_at", "datetime"), F("recovered_at", "datetime"), F("closed_at", "datetime"),
    F("reporter"), F("triage_owner"), F("incident_commander"), F("affected_assets", "text"), F("observed_activity", "text"),
    F("business_impact", "text"), F("data_impact", "choice", choices=["Unknown", "None", "Suspected", "Confirmed"], default="Unknown"),
    F("cert_in_assessment", "choice", choices=["Not assessed", "Not required", "Required"], default="Not assessed"),
    F("cert_in_reported_at", "datetime"), F("root_cause", "text"), F("closure_summary", "text"),
    F("checklist15", "json", default="[]"), F("checklist24", "json", default="[]"), F("closure_checks", "json", default="[]"),
]
Resource("incidents", "incidents", INC_FIELDS, write="incidents.write", search=("ref", "title", "affected_assets", "observed_activity"),
         filters=("severity", "status", "category"), sorts=("id", "reported_at", "severity", "status", "ref"), default_sort="-reported_at",
         before_save=before_save, decorate=decorate, timestamps=True, deletable=False).register(bp)


@bp.post("/incidents/<int:rid>/acknowledge")
@require("incidents.write")
def acknowledge(rid):
    inc = one("SELECT * FROM incidents WHERE id=?", (rid,))
    if not inc:
        raise ApiError(404, "NOT_FOUND", "Incident not found.")
    if inc["acknowledged_at"]:
        raise ApiError(409, "ALREADY_ACKNOWLEDGED", "This incident is already acknowledged.")
    db = get_db()
    status = "Triage" if inc["status"] == "Reported" else inc["status"]
    db.execute("UPDATE incidents SET acknowledged_at=?, status=?, updated_at=? WHERE id=?", (now_iso(), status, now_iso(), rid))
    db.commit()
    write_audit("ACKNOWLEDGE", "incidents", rid, {})
    return jsonify(decorate(_row(rid)))


def _row(rid):
    r = one("SELECT * FROM incidents WHERE id=?", (rid,))
    return r


def _incident_exists(clean, existing, user):
    iid = clean.get("incident_id") if "incident_id" in clean else (existing or {}).get("incident_id")
    if existing is None or "incident_id" in clean:
        if not scalar("SELECT 1 FROM incidents WHERE id=?", (iid,)):
            raise ApiError(422, "VALIDATION_ERROR", "Unknown incident.", [{"field": "incident_id", "message": "incident does not exist"}])
    return clean


CONF = ["High", "Medium", "Low"]
Resource("incident-timeline", "incident_timeline", [
    F("incident_id", "int", True, lo=1), F("event_time", "datetime", True), F("event", "text", True), F("source"),
    F("confidence", "choice", choices=CONF), F("interpretation", "text")], write="incidents.write",
    filters=("incident_id",), sorts=("id", "event_time"), default_sort="event_time", before_save=_incident_exists).register(bp)
Resource("incident-decisions", "incident_decisions", [
    F("incident_id", "int", True, lo=1), F("decided_at", "datetime", True), F("decision", "text", True), F("rationale", "text"),
    F("approver"), F("outcome", "text")], write="incidents.write", filters=("incident_id",), sorts=("id", "decided_at"),
    default_sort="decided_at", before_save=_incident_exists).register(bp)
Resource("incident-actions", "incident_actions", [
    F("incident_id", "int", True, lo=1), F("title", "text", True), F("priority", "choice", choices=["Critical", "High", "Medium", "Low"], default="Medium"),
    F("owner"), F("due_date", "date"), F("status", "choice", choices=R.FINDING_STATUSES, default="Open"), F("evidence", "text")],
    write="incidents.write", filters=("incident_id", "status"), sorts=("id", "due_date"), default_sort="due_date",
    before_save=lambda c, e, u: _action_rules(_incident_exists(c, e, u), e, u)).register(bp)


def _action_rules(clean, existing, user):
    merged = {**(existing or {}), **clean}
    if merged.get("status") == "Closed" and not (merged.get("evidence") or "").strip():
        raise ApiError(422, "EVIDENCE_REQUIRED", "Closing an action requires verification evidence.",
                       [{"field": "evidence", "message": "required to close"}])
    return clean


# ------------------------------------------------------------------ evidence register (SHA-256, optional file)
EV = Resource("incident-evidence", "incident_evidence", [
    F("incident_id", "int", True, lo=1), F("description", "text", True), F("collected_by"), F("collected_at", "datetime"),
    F("storage_location"), F("sha256", maxlen=64)], write="incidents.write", filters=("incident_id",),
    sorts=("id", "collected_at"), default_sort="id", before_save=_incident_exists)


def _strip(d):
    d.pop("stored_name", None)
    d["has_file"] = bool(d.get("filename"))
    return d


EV.decorate = _strip
EV.register(bp, skip=("create",))


@bp.post("/incident-evidence")
@require("incidents.write")
def create_evidence():
    user = current_user()
    form = request.form if request.files or request.form else (request.get_json(silent=True) or {})
    payload = {k: form.get(k) for k in ("incident_id", "description", "collected_by", "collected_at", "storage_location", "sha256")
               if form.get(k) not in (None, "")}
    clean = validate(EV.fields, payload, partial=False)
    _incident_exists(clean, None, user)
    sha = clean.get("sha256")
    if sha and not re.fullmatch(r"[0-9a-fA-F]{64}", sha):
        raise ApiError(422, "VALIDATION_ERROR", "Invalid SHA-256.", [{"field": "sha256", "message": "must be 64 hexadecimal characters"}])
    filename = size = stored = None
    f = request.files.get("file")
    if f and f.filename:
        data = f.read()
        digest = hashlib.sha256(data).hexdigest()
        if sha and sha.lower() != digest:
            raise ApiError(422, "HASH_MISMATCH", "The supplied SHA-256 does not match the uploaded file.", [{"field": "sha256", "message": f"file hash is {digest}"}])
        sha = digest
        filename = re.sub(r"[^A-Za-z0-9._-]", "_", os.path.basename(f.filename))[:100] or "evidence"
        stored = secrets.token_hex(16)
        path = os.path.join(current_app.config["UPLOAD_DIR"], stored)
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "wb") as out:
            out.write(data)
        size = len(data)
    db = get_db()
    n = scalar("SELECT COUNT(*) FROM incident_evidence WHERE incident_id=?", (clean["incident_id"],)) + 1
    cur = db.execute("""INSERT INTO incident_evidence(incident_id,evid,description,collected_by,collected_at,sha256,storage_location,filename,size_bytes,stored_name)
                        VALUES(?,?,?,?,?,?,?,?,?,?)""",
                     (clean["incident_id"], f"EV-{n:03d}", clean["description"], clean.get("collected_by") or user["username"],
                      clean.get("collected_at") or now_iso(), sha.lower() if sha else None, clean.get("storage_location"), filename, size, stored))
    db.commit()
    write_audit("CREATE", "incident-evidence", cur.lastrowid, {"has_file": bool(filename), "sha256": sha})
    return jsonify(_strip(dict(one("SELECT * FROM incident_evidence WHERE id=?", (cur.lastrowid,))))), 201


@bp.get("/incident-evidence/<int:rid>/download")
@login_required
def download_evidence(rid):
    r = one("SELECT * FROM incident_evidence WHERE id=?", (rid,))
    if not r or not r["stored_name"]:
        raise ApiError(404, "NOT_FOUND", "No file stored for this evidence item.")
    path = os.path.join(current_app.config["UPLOAD_DIR"], r["stored_name"])
    if not os.path.isfile(path):
        raise ApiError(404, "NOT_FOUND", "Evidence file is missing on disk.")
    write_audit("EVIDENCE_DOWNLOAD", "incident-evidence", rid, {})
    return send_file(path, as_attachment=True, download_name=r["filename"] or "evidence", mimetype="application/octet-stream")


@bp.post("/incident-evidence/<int:rid>/verify")
@login_required
def verify_evidence(rid):
    r = one("SELECT * FROM incident_evidence WHERE id=?", (rid,))
    if not r or not r["stored_name"]:
        raise ApiError(404, "NOT_FOUND", "No file stored for this evidence item.")
    path = os.path.join(current_app.config["UPLOAD_DIR"], r["stored_name"])
    with open(path, "rb") as fh:
        digest = hashlib.sha256(fh.read()).hexdigest()
    return jsonify({"intact": digest == r["sha256"], "recorded": r["sha256"], "current": digest})


@bp.delete("/incident-evidence/<int:rid>")
@require("incidents.write")
def delete_evidence(rid):
    r = one("SELECT * FROM incident_evidence WHERE id=?", (rid,))
    if not r:
        raise ApiError(404, "NOT_FOUND", "Record not found.")
    if r["stored_name"]:
        try:
            os.remove(os.path.join(current_app.config["UPLOAD_DIR"], r["stored_name"]))
        except OSError:
            pass
    get_db().execute("DELETE FROM incident_evidence WHERE id=?", (rid,))
    get_db().commit()
    write_audit("DELETE", "incident-evidence", rid, {})
    return jsonify({"deleted": True})


@bp.get("/incidents-summary")
@login_required
def summary():
    items = [decorate(r) for r in rows("SELECT * FROM incidents")]
    open_items = [i for i in items if i["is_open"]]

    def avg(key):
        vals = [i["metrics"][key] for i in items if i["metrics"][key] is not None]
        return round(sum(vals) / len(vals), 1) if vals else None
    by_sev = {s: sum(1 for i in open_items if i["severity"] == s) for s in SEV}
    by_status = {s: sum(1 for i in items if i["status"] == s) for s in R.INCIDENT_STATUSES}
    return jsonify({"total": len(items), "open": len(open_items), "open_by_severity": by_sev, "by_status": by_status,
                    "ack_breaches": sum(1 for i in items if i["ack_breached"]),
                    "ack_pending": sum(1 for i in items if i["ack_pending"]),
                    "cert_in_attention": sum(1 for i in open_items if i["cert_in_assessment"] == "Required" and not i.get("cert_in_reported_at")),
                    "cert_in_unassessed": sum(1 for i in open_items if i["cert_in_assessment"] == "Not assessed"),
                    "avg_minutes": {k: avg(k) for k in ("time_to_acknowledge_min", "time_to_declare_min", "time_to_contain_min", "time_to_recover_min")},
                    "open_actions": scalar("SELECT COUNT(*) FROM incident_actions WHERE status NOT IN ('Closed','Risk Accepted')")})
