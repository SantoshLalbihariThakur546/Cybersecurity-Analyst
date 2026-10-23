"""Week 5 - Vulnerability assessment: assets, findings with SLA due dates, closure evidence rules, roadmap, metrics."""
from flask import Blueprint, jsonify, request

from ..crud import F, Resource, add_days, today
from ..db import one, rows, scalar
from ..security import ApiError, login_required

bp = Blueprint("vulns", __name__, url_prefix="/api")

SEVERITY = ["Critical", "High", "Medium", "Low"]
LEVEL = ["Low", "Medium", "Medium-High", "High", "Very High"]
STATUS = ["Open", "In Progress", "Pending Verification", "Closed", "Risk Accepted"]
OPEN = ("Open", "In Progress", "Pending Verification")
SLA_DAYS = {"Critical": 7, "High": 14, "Medium": 30, "Low": 90}
EXPLOITED_DAYS = 3


def default_days(severity, exploited):
    return EXPLOITED_DAYS if exploited else SLA_DAYS[severity]


Resource("assets", "assets", [
    F("name", required=True), F("type", "choice", True, choices=["Endpoint", "Server", "Network", "Cloud", "Application", "Other"]),
    F("owner"), F("criticality", "choice", choices=["Critical", "High", "Medium", "Low"], default="Medium"),
    F("exposure", "choice", choices=["Internal", "Internet-facing"], default="Internal"), F("platform"),
    F("support_status", "choice", choices=["Supported", "Unsupported", "Unknown"], default="Supported"), F("notes", "text")],
    write="vulns.write", search=("name", "owner", "platform"), filters=("type", "criticality", "exposure"),
    sorts=("id", "name", "criticality"), before_delete=lambda r: None).register(bp)


def finding_before(clean, existing, user):
    m = {**(existing or {}), **clean}
    t = today()
    if existing is None:
        clean.setdefault("identified_on", None)
        if not m.get("identified_on"):
            clean["identified_on"] = m["identified_on"] = t
        if not m.get("ref"):
            n = (scalar("SELECT COUNT(*) FROM vuln_findings") or 0) + 1
            while scalar("SELECT 1 FROM vuln_findings WHERE ref=?", (f"VA-{n:02d}",)):
                n += 1
            clean["ref"] = f"VA-{n:02d}"
    if "identified_on" in clean and not clean["identified_on"]:
        clean["identified_on"] = m["identified_on"] = (existing or {}).get("identified_on") or t
    if "target_days" in clean and not clean["target_days"]:
        clean["target_days"] = m["target_days"] = default_days(m["severity"], m.get("actively_exploited"))
    sev_changed = existing is not None and (("severity" in clean and clean["severity"] != existing["severity"]) or
                                            ("actively_exploited" in clean and clean["actively_exploited"] != existing["actively_exploited"]))
    if (existing is None and not m.get("target_days")) or (sev_changed and "target_days" not in clean):
        clean["target_days"] = m["target_days"] = default_days(m["severity"], m.get("actively_exploited"))
    if existing is None or any(k in clean for k in ("identified_on", "target_days")) or sev_changed:
        clean["due_date"] = add_days(m["identified_on"], int(m["target_days"]))
    problems = []
    status = m.get("status")
    if status == "Closed":
        if not (m.get("closure_evidence") or "").strip():
            problems.append({"field": "closure_evidence", "message": "required: attach verification evidence (e.g. follow-up scan) to close"})
        if not m.get("closed_on"):
            clean["closed_on"] = t
    elif "status" in clean and existing and existing["status"] == "Closed":
        clean["closed_on"] = None  # re-opened
    if status == "Risk Accepted":
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
    d["overdue"] = d["status"] in OPEN and d["due_date"] < t
    d["days_remaining"] = (__import__("datetime").date.fromisoformat(d["due_date"]) - __import__("datetime").date.today()).days
    d["acceptance_expired"] = bool(d["status"] == "Risk Accepted" and d.get("accept_expiry") and d["accept_expiry"] < t)
    d["closed_on_time"] = bool(d["status"] == "Closed" and d.get("closed_on") and d["closed_on"] <= d["due_date"])
    d["asset_name"] = scalar("SELECT name FROM assets WHERE id=?", (d["asset_id"],)) if d.get("asset_id") else None
    return d


Resource("vuln-findings", "vuln_findings", [
    F("ref", maxlen=20), F("title", "text", True), F("severity", "choice", True, choices=SEVERITY), F("likelihood", "choice", choices=LEVEL),
    F("impact", "choice", choices=LEVEL), F("priority", "choice", choices=LEVEL), F("owner"),
    F("target_days", "int", lo=1, hi=730), F("identified_on", "date"), F("status", "choice", choices=STATUS, default="Open"),
    F("observation", "text"), F("potential_impact", "text"), F("recommendations", "text"), F("verification_required", "text"),
    F("closure_evidence", "text"), F("closed_on", "date"), F("asset_id", "int", lo=1), F("actively_exploited", "bool", default=0),
    F("accept_rationale", "text"), F("accept_approver"), F("accept_expiry", "date")],
    write="vulns.write", search=("ref", "title", "owner", "observation"), filters=("severity", "status", "asset_id"),
    sorts=("id", "ref", "severity", "due_date", "status", "identified_on"), default_sort="due_date", before_save=finding_before,
    decorate=finding_decorate, timestamps=True).register(bp)

Resource("vuln-roadmap", "vuln_roadmap", [F("timeframe", required=True), F("actions", "text", True), F("success_measure", "text"),
         F("status", "choice", choices=["Not started", "In progress", "Completed", "Blocked"], default="Not started"),
         F("sort_order", "int", default=0, lo=0, hi=999)], write="vulns.write", sorts=("id", "sort_order"), default_sort="sort_order").register(bp)


def vm_decorate(d):
    cur, tgt = d.get("current_value"), d.get("target_value")
    if cur is None:
        d["state"] = "No data"
    elif tgt is None:
        d["state"] = "Tracked"
    else:
        d["state"] = "Target met" if (cur >= tgt if d["direction"] == "higher" else cur <= tgt) else "Below target"
    return d


Resource("vuln-metrics", "vuln_metrics", [F("name", required=True), F("target_text", "text"), F("target_value", "float"),
         F("current_value", "float"), F("unit", maxlen=20), F("direction", "choice", choices=["higher", "lower"], default="higher"),
         F("cadence")], write="vulns.write", decorate=vm_decorate, timestamps=True).register(bp)


@bp.get("/sla")
@login_required
def sla_calculator():
    sev = request.args.get("severity", "")
    if sev not in SLA_DAYS:
        raise ApiError(422, "VALIDATION_ERROR", "severity must be one of Critical, High, Medium, Low.", [{"field": "severity", "message": "invalid"}])
    exploited = request.args.get("exploited", "0") in ("1", "true", "True")
    start = request.args.get("identified_on") or today()
    try:
        days = default_days(sev, exploited)
        due = add_days(start, days)
    except ValueError:
        raise ApiError(422, "VALIDATION_ERROR", "identified_on must be YYYY-MM-DD.", [{"field": "identified_on", "message": "invalid date"}])
    return jsonify({"severity": sev, "actively_exploited": exploited, "target_days": days, "due_date": due})


@bp.get("/vuln-summary")
@login_required
def summary():
    items = [finding_decorate(r) for r in rows("SELECT * FROM vuln_findings")]
    considered = [i for i in items if i["status"] != "Risk Accepted"]
    within = [i for i in considered if (i["status"] == "Closed" and i["closed_on_time"]) or (i["status"] in OPEN and not i["overdue"])]
    ch = [i for i in items if i["severity"] in ("Critical", "High")]
    ch_done = [i for i in ch if i["status"] in ("Closed", "Risk Accepted")]
    assets = rows("SELECT type, exposure, support_status FROM assets")
    return jsonify({
        "total": len(items), "open": sum(1 for i in items if i["status"] in OPEN),
        "by_severity": {s: sum(1 for i in items if i["severity"] == s) for s in SEVERITY},
        "open_by_severity": {s: sum(1 for i in items if i["severity"] == s and i["status"] in OPEN) for s in SEVERITY},
        "by_status": {s: sum(1 for i in items if i["status"] == s) for s in STATUS},
        "overdue": sum(1 for i in items if i["overdue"]), "acceptance_expired": sum(1 for i in items if i["acceptance_expired"]),
        "sla_compliance_pct": round(100 * len(within) / len(considered), 1) if considered else None,
        "critical_high_resolved_pct": round(100 * len(ch_done) / len(ch), 1) if ch else None,
        "assets": {"total": len(assets), "internet_facing": sum(1 for a in assets if a["exposure"] == "Internet-facing"),
                   "unsupported": sum(1 for a in assets if a["support_status"] == "Unsupported")},
        "roadmap": {"total": scalar("SELECT COUNT(*) FROM vuln_roadmap"), "completed": scalar("SELECT COUNT(*) FROM vuln_roadmap WHERE status='Completed'")},
    })
