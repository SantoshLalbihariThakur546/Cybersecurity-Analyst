"""Week 3 - Security policy review: control assessment, risk register, roadmap, exceptions, metrics, checklist."""
from flask import Blueprint, jsonify

from .. import reference as R
from ..crud import F, Resource, today
from ..db import jload, rows, scalar
from ..security import ApiError, login_required

bp = Blueprint("policy", __name__, url_prefix="/api")

RATINGS = [d["rating"] for d in R.POLICY_RATING_DEFS]
PRIORITIES = ["Critical", "High", "Medium", "Low"]
PHASES = ["First 30 days", "Days 31-60", "Days 61-90", "3-6 months"]
ACTION_STATUS = ["Not started", "In progress", "Completed", "Blocked"]


def band(score):
    return "Critical" if score >= 20 else "High" if score >= 12 else "Medium" if score >= 6 else "Low"


Resource("policy-controls", "policy_controls", [
    F("area", required=True), F("rating", "choice", True, choices=RATINGS), F("main_gap"), F("priority", "choice", True, choices=PRIORITIES),
    F("critique", "text"), F("recommendation", "text"), F("evidence", "text"), F("sort_order", "int", default=0, lo=0, hi=999)],
    write="policy.write", search=("area", "main_gap", "critique", "recommendation"), filters=("rating", "priority"),
    sorts=("id", "sort_order", "area", "rating", "priority"), default_sort="sort_order").register(bp)


def risk_before(clean, existing, user):
    merged = {**(existing or {}), **clean}
    clean["score"] = int(merged["likelihood"]) * int(merged["impact"])
    clean["band"] = band(clean["score"])
    if existing is None and not clean.get("ref"):
        n = (scalar("SELECT COUNT(*) FROM policy_risks") or 0) + 1
        while scalar("SELECT 1 FROM policy_risks WHERE ref=?", (f"R{n}",)):
            n += 1
        clean["ref"] = f"R{n}"
    return clean


Resource("policy-risks", "policy_risks", [
    F("ref", maxlen=20), F("title", "text", True), F("likelihood", "int", True, lo=1, hi=5), F("impact", "int", True, lo=1, hi=5),
    F("owner"), F("treatment", "choice", choices=["Mitigate", "Accept", "Transfer", "Avoid"], default="Mitigate"),
    F("status", "choice", choices=["Open", "Mitigating", "Accepted", "Closed"], default="Open"), F("review_date", "date")],
    write="policy.write", search=("ref", "title", "owner"), filters=("band", "status", "treatment"),
    sorts=("id", "score", "ref", "likelihood", "impact", "review_date"), default_sort="-score", before_save=risk_before,
    timestamps=True).register(bp)

Resource("policy-actions", "policy_actions", [
    F("phase", "choice", True, choices=PHASES), F("action", "text", True), F("owner"), F("deliverable", "text"),
    F("success_measure", "text"), F("status", "choice", choices=ACTION_STATUS, default="Not started"), F("due_date", "date")],
    write="policy.write", search=("action", "owner", "deliverable"), filters=("phase", "status"), sorts=("id", "phase", "status", "due_date"),
    decorate=lambda d: {**d, "overdue": bool(d.get("due_date") and d["due_date"] < today() and d["status"] != "Completed")}).register(bp)


def exc_before(clean, existing, user):
    m = {**(existing or {}), **clean}
    problems = []
    if m.get("status") == "Approved":
        for k, label in (("approver", "an approver"), ("approved_on", "an approval date"), ("expiry_date", "an expiry date")):
            if not m.get(k):
                problems.append({"field": k, "message": f"required: an approved exception needs {label}"})
        if m.get("expiry_date") and m.get("approved_on") and m["expiry_date"] < m["approved_on"]:
            problems.append({"field": "expiry_date", "message": "cannot be before the approval date"})
    if m.get("status") == "Closed" and not (m.get("closure_evidence") or "").strip():
        problems.append({"field": "closure_evidence", "message": "required to close an exception"})
    if problems:
        raise ApiError(422, "VALIDATION_ERROR", "Exception record is incomplete.", problems)
    if existing is None:
        year = today()[:4]
        n = (scalar("SELECT COUNT(*) FROM policy_exceptions WHERE ref LIKE ?", (f"EX-{year}-%",)) or 0) + 1
        while scalar("SELECT 1 FROM policy_exceptions WHERE ref=?", (f"EX-{year}-{n:03d}",)):
            n += 1
        clean["ref"] = f"EX-{year}-{n:03d}"
    return clean


def exc_decorate(d):
    t = today()
    d["expired"] = bool(d["status"] == "Approved" and d.get("expiry_date") and d["expiry_date"] < t)
    d["review_overdue"] = bool(d["status"] == "Approved" and d.get("review_date") and d["review_date"] < t)
    d["effective_status"] = "Expired" if d["expired"] else d["status"]
    return d


Resource("policy-exceptions", "policy_exceptions", [
    F("requester", required=True), F("control", "text", True), F("assets", "text"), F("justification", "text"),
    F("risk_assessment", "text"), F("compensating_controls", "text"), F("approver"), F("approved_on", "date"),
    F("expiry_date", "date"), F("review_date", "date"),
    F("status", "choice", choices=["Pending", "Approved", "Rejected", "Closed"], default="Pending"), F("closure_evidence", "text")],
    write="policy.write", search=("ref", "requester", "control", "assets"), filters=("status",),
    sorts=("id", "expiry_date", "status", "ref"), default_sort="-id", before_save=exc_before, decorate=exc_decorate,
    timestamps=True).register(bp)


def metric_decorate(d):
    cur, tgt = d.get("current_value"), d.get("target_value")
    if cur is None:
        d["state"] = "No data"
    elif tgt is None:
        d["state"] = "Tracked"
    else:
        ok = cur >= tgt if d["direction"] == "higher" else cur <= tgt
        d["state"] = "Target met" if ok else "Below target" if d["direction"] == "higher" else "Above target"
    return d


Resource("policy-metrics", "policy_metrics", [
    F("name", required=True), F("definition", "text"), F("target_text", "text"), F("target_value", "float"),
    F("current_value", "float"), F("unit", maxlen=20), F("direction", "choice", choices=["higher", "lower"], default="higher"),
    F("cadence"), F("owner")], write="policy.write", search=("name", "definition"), sorts=("id", "name"),
    decorate=metric_decorate, timestamps=True).register(bp)

ANSWERS = ["Unanswered", "Yes", "Partially", "No", "N/A"]
Resource("policy-checklist", "policy_checklist", [F("question", "text", True), F("answer", "choice", choices=ANSWERS, default="Unanswered"),
         F("evidence", "text")], write="policy.write", search=("question",), filters=("answer",)).register(bp)
Resource("evidence-requests", "evidence_requests", [F("item", "text", True),
         F("status", "choice", choices=["Not requested", "Requested", "Received", "Not available"], default="Not requested"),
         F("notes", "text")], write="policy.write", search=("item",), filters=("status",)).register(bp)
Resource("policy-statements", "policy_statements", [F("topic", required=True), F("language", "text", True)],
         write="policy.write", search=("topic", "language")).register(bp)


@bp.get("/policy-summary")
@login_required
def summary():
    t = today()
    controls = rows("SELECT rating, priority FROM policy_controls")
    risks = rows("SELECT likelihood, impact, band, score, ref, title FROM policy_risks WHERE status != 'Closed'")
    matrix = {}
    for r in risks:
        matrix.setdefault(f"{r['likelihood']}-{r['impact']}", []).append(r["ref"])
    actions = rows("SELECT phase, status, due_date FROM policy_actions")
    phases = {p: {"total": 0, "completed": 0} for p in PHASES}
    for a in actions:
        phases[a["phase"]]["total"] += 1
        phases[a["phase"]]["completed"] += a["status"] == "Completed"
    chk = rows("SELECT answer FROM policy_checklist")
    return jsonify({
        "ratings": {r: sum(1 for c in controls if c["rating"] == r) for r in RATINGS},
        "priorities": {p: sum(1 for c in controls if c["priority"] == p) for p in PRIORITIES},
        "risk_bands": {b: sum(1 for r in risks if r["band"] == b) for b in PRIORITIES},
        "risk_matrix": matrix, "open_risks": len(risks),
        "phases": phases, "actions_total": len(actions), "actions_completed": sum(1 for a in actions if a["status"] == "Completed"),
        "actions_overdue": sum(1 for a in actions if a["due_date"] and a["due_date"] < t and a["status"] != "Completed"),
        "exceptions_open": scalar("SELECT COUNT(*) FROM policy_exceptions WHERE status IN ('Pending','Approved')"),
        "exceptions_expired": scalar("SELECT COUNT(*) FROM policy_exceptions WHERE status='Approved' AND expiry_date < ?", (t,)),
        "checklist": {"total": len(chk), "answered": sum(1 for c in chk if c["answer"] != "Unanswered"),
                      "yes": sum(1 for c in chk if c["answer"] == "Yes"), "no": sum(1 for c in chk if c["answer"] == "No")},
        "evidence": {"total": scalar("SELECT COUNT(*) FROM evidence_requests"),
                     "received": scalar("SELECT COUNT(*) FROM evidence_requests WHERE status='Received'")},
    })
