"""Week 6 - Cybersecurity audit plan: calendar, workpapers, findings, follow-up, KPIs."""
import statistics
from datetime import date

from flask import Blueprint, jsonify

from .. import reference as R
from ..crud import F, Resource, add_days, today
from ..db import rows, scalar
from ..security import ApiError, login_required

bp = Blueprint("audits", __name__, url_prefix="/api")

SEVS = [s["rating"] for s in R.AUDIT_SEVERITY]
SEV_DAYS = {s["rating"]: s["target_days"] for s in R.AUDIT_SEVERITY}
STATUS = R.FINDING_STATUSES
OPEN = ("Open", "In Progress", "Pending Verification")
AUDIT_STATUS = ["Planned", "In Progress", "Completed", "Rescheduled"]
MONTHS = ["", "January", "February", "March", "April", "May", "June", "July", "August", "September", "October", "November", "December"]


def cal_before(clean, existing, user):
    m = {**(existing or {}), **clean}
    if m["status"] == "Rescheduled" and not (m.get("reschedule_rationale") or "").strip():
        raise ApiError(422, "VALIDATION_ERROR", "A reschedule needs a documented rationale.", [{"field": "reschedule_rationale", "message": "required when rescheduled"}])
    if m["status"] == "Completed" and not m.get("completed_on"):
        clean["completed_on"] = today()
    return clean


Resource("audit-calendar", "audit_calendar", [
    F("month", "int", True, lo=1, hi=12), F("focus", required=True), F("activities", "text"),
    F("tier", "choice", choices=[t["tier"] for t in R.AUDIT_TIERS]), F("status", "choice", choices=AUDIT_STATUS, default="Planned"),
    F("completed_on", "date"), F("reschedule_rationale", "text"), F("notes", "text")], write="auditplan.write",
    sorts=("id", "month", "status"), default_sort="month", before_save=cal_before,
    decorate=lambda d: {**d, "month_name": MONTHS[d["month"]]}).register(bp)


def audit_before(clean, existing, user):
    m = {**(existing or {}), **clean}
    if existing is None and not m.get("ref"):
        year = today()[:4]
        n = (scalar("SELECT COUNT(*) FROM audits WHERE ref LIKE ?", (f"AUD-{year}-%",)) or 0) + 1
        while scalar("SELECT 1 FROM audits WHERE ref=?", (f"AUD-{year}-{n:03d}",)):
            n += 1
        clean["ref"] = f"AUD-{year}-{n:03d}"
    if m.get("status") == "Completed":
        missing = [k for k in ("criteria", "population", "evidence_source", "evidence_date", "auditor", "test_procedure") if not (m.get(k) or "").strip()]
        if m.get("result") == "Not tested":
            missing.append("result")
        if missing:
            raise ApiError(422, "WORKPAPER_INCOMPLETE", "A completed audit needs a complete workpaper (criteria, population, evidence, auditor, procedure, result).",
                           [{"field": k, "message": "required to complete the audit"} for k in missing])
    return clean


Resource("audits", "audits", [
    F("ref", maxlen=30), F("month", "int", lo=1, hi=12), F("domain", "choice", True, choices=R.AUDIT_DOMAINS), F("control_objective", "text"),
    F("criteria", "text"), F("population", "text"), F("sample_size"), F("period_covered"), F("evidence_source", "text"),
    F("evidence_date", "date"), F("auditor"), F("test_procedure", "text"),
    F("result", "choice", choices=["Pass", "Partial", "Fail", "Not tested"], default="Not tested"), F("risk_impact", "text"),
    F("limitations", "text"), F("status", "choice", choices=AUDIT_STATUS, default="Planned"), F("planned_date", "date")],
    write="auditplan.write", search=("ref", "domain", "control_objective", "auditor"), filters=("status", "domain", "result"),
    sorts=("id", "ref", "month", "planned_date", "status"), default_sort="month", before_save=audit_before, timestamps=True).register(bp)


def finding_before(clean, existing, user):
    m = {**(existing or {}), **clean}
    t = today()
    if existing is None:
        if not m.get("identified_on"):
            clean["identified_on"] = m["identified_on"] = t
        if not m.get("ref"):
            n = (scalar("SELECT COUNT(*) FROM audit_findings") or 0) + 1
            while scalar("SELECT 1 FROM audit_findings WHERE ref=?", (f"AF-{n:03d}",)):
                n += 1
            clean["ref"] = f"AF-{n:03d}"
    if m.get("audit_id") and not scalar("SELECT 1 FROM audits WHERE id=?", (m["audit_id"],)):
        raise ApiError(422, "VALIDATION_ERROR", "Unknown audit.", [{"field": "audit_id", "message": "audit does not exist"}])
    if "identified_on" in clean and not clean["identified_on"]:
        clean["identified_on"] = m["identified_on"] = (existing or {}).get("identified_on") or t
    if "target_days" in clean and not clean["target_days"] and m["severity"] != "Observation":
        clean["target_days"] = m["target_days"] = SEV_DAYS[m["severity"]]
    sev_changed = existing is not None and "severity" in clean and clean["severity"] != existing["severity"]
    if (existing is None and not m.get("target_days") and SEV_DAYS[m["severity"]]) or (sev_changed and "target_days" not in clean):
        clean["target_days"] = m["target_days"] = SEV_DAYS[m["severity"]]
    if m["severity"] == "Observation" and (existing is None or sev_changed):
        clean["target_days"] = m["target_days"] = None
    if existing is None or any(k in clean for k in ("identified_on", "target_days")) or sev_changed:
        clean["due_date"] = add_days(m["identified_on"], int(m["target_days"])) if m.get("target_days") else None
    problems = []
    if m.get("status") == "Closed":
        if not (m.get("closure_evidence") or "").strip():
            problems.append({"field": "closure_evidence", "message": "required to close a finding"})
        if m["severity"] in ("Critical", "High") and m.get("retest_result") != "Pass":
            problems.append({"field": "retest_result", "message": "Critical/High findings must pass a retest before closure"})
        if not m.get("closed_on"):
            clean["closed_on"] = t
    elif existing and existing["status"] == "Closed" and "status" in clean:
        clean["closed_on"] = None
    if m.get("status") == "Risk Accepted":
        for k in ("accept_rationale", "accept_approver", "accept_expiry"):
            if not (m.get(k) or "").strip():
                problems.append({"field": k, "message": "required for formal risk acceptance"})
        if m.get("accept_expiry") and m["accept_expiry"] < t and "accept_expiry" in clean:
            problems.append({"field": "accept_expiry", "message": "must not be in the past"})
    if problems:
        raise ApiError(422, "VALIDATION_ERROR", "The finding cannot be saved in this state.", problems)
    return clean


def finding_decorate(d):
    t = today()
    d["overdue"] = bool(d["status"] in OPEN and d.get("due_date") and d["due_date"] < t)
    d["escalation"] = bool(d["overdue"] and d["severity"] in ("Critical", "High"))
    d["acceptance_expired"] = bool(d["status"] == "Risk Accepted" and d.get("accept_expiry") and d["accept_expiry"] < t)
    d["days_to_close"] = (date.fromisoformat(d["closed_on"]) - date.fromisoformat(d["identified_on"])).days if d.get("closed_on") else None
    d["retest_required"] = d["severity"] in ("Critical", "High")
    d["audit_ref"] = scalar("SELECT ref FROM audits WHERE id=?", (d["audit_id"],)) if d.get("audit_id") else None
    return d


Resource("audit-findings", "audit_findings", [
    F("ref", maxlen=20), F("audit_id", "int", lo=1), F("title", "text", True), F("severity", "choice", True, choices=SEVS),
    F("description", "text"), F("evidence_ref", maxlen=500), F("recommendation", "text"), F("owner"), F("identified_on", "date"),
    F("target_days", "int", lo=1, hi=730), F("status", "choice", choices=STATUS, default="Open"), F("mgmt_response", "text"),
    F("closure_evidence", "text"), F("closed_on", "date"), F("retest_result", "choice", choices=["Not retested", "Pass", "Fail"], default="Not retested"),
    F("accept_rationale", "text"), F("accept_approver"), F("accept_expiry", "date"), F("is_repeat", "bool", default=0)],
    write="auditplan.write", search=("ref", "title", "owner", "description"), filters=("severity", "status", "audit_id"),
    sorts=("id", "ref", "severity", "due_date", "status", "identified_on"), default_sort="due_date", before_save=finding_before,
    decorate=finding_decorate, timestamps=True).register(bp)

ANSWERS = ["Unanswered", "Yes", "Partially", "No", "N/A"]
Resource("audit-checklist", "audit_checklist", [F("item", "text", True), F("answer", "choice", choices=ANSWERS, default="Unanswered"),
         F("evidence", "text")], write="auditplan.write", filters=("answer",)).register(bp)
Resource("audit-kpis", "audit_kpis", [F("name", required=True), F("target_text", "text"), F("review"), F("current_text", "text")],
         write="auditplan.write", timestamps=True).register(bp)


@bp.get("/audit-summary")
@login_required
def summary():
    cal = rows("SELECT status, reschedule_rationale FROM audit_calendar")
    done = sum(1 for c in cal if c["status"] == "Completed")
    resched = sum(1 for c in cal if c["status"] == "Rescheduled" and (c["reschedule_rationale"] or "").strip())
    plan_pct = round(100 * (done + resched) / len(cal), 1) if cal else None
    items = [finding_decorate(r) for r in rows("SELECT * FROM audit_findings")]
    median = {}
    for s in SEVS:
        days = [i["days_to_close"] for i in items if i["severity"] == s and i["days_to_close"] is not None]
        median[s] = statistics.median(days) if days else None
    complete = [i for i in items if i.get("evidence_ref") and i.get("owner") and i.get("recommendation") and
                (i.get("due_date") or i["severity"] == "Observation")]
    chk = rows("SELECT answer FROM audit_checklist")
    return jsonify({
        "calendar": {s: sum(1 for c in cal if c["status"] == s) for s in AUDIT_STATUS}, "plan_completion_pct": plan_pct,
        "audits": {s: scalar("SELECT COUNT(*) FROM audits WHERE status=?", (s,)) for s in AUDIT_STATUS},
        "findings_total": len(items), "findings_open": sum(1 for i in items if i["status"] in OPEN),
        "by_severity": {s: sum(1 for i in items if i["severity"] == s) for s in SEVS},
        "by_status": {s: sum(1 for i in items if i["status"] == s) for s in STATUS},
        "overdue": sum(1 for i in items if i["overdue"]), "overdue_critical_high": sum(1 for i in items if i["escalation"]),
        "acceptance_expired": sum(1 for i in items if i["acceptance_expired"]),
        "median_days_to_close": median,
        "evidence_quality_pct": round(100 * len(complete) / len(items), 1) if items else None,
        "repeat_findings": sum(1 for i in items if i["is_repeat"]),
        "checklist": {"total": len(chk), "answered": sum(1 for c in chk if c["answer"] != "Unanswered"),
                      "yes": sum(1 for c in chk if c["answer"] == "Yes")},
    })
