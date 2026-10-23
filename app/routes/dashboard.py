"""Executive dashboard: aggregates every module and builds the 'needs attention' queue."""
from flask import Blueprint, jsonify

from .. import reference as R
from ..crud import today
from ..db import rows, scalar
from ..security import login_required
from . import audits, awareness, incidents, policy, vulns
from .threats import threat_decorate

bp = Blueprint("dashboard", __name__, url_prefix="/api")


def attention_items():
    t = today()
    items = []

    def add(kind, severity, label, page, ref=None):
        items.append({"kind": kind, "severity": severity, "label": label, "page": page, "ref": ref})
    for i in [incidents.decorate(r) for r in rows("SELECT * FROM incidents WHERE status != 'Closed'")]:
        if i["ack_breached"]:
            add("Incident", "Critical" if i["severity"] in ("SEV-1", "SEV-2") else "High",
                f"{i['ref']} acknowledgement target missed ({i['severity']}, target {i['ack_target']})", "incidents", i["ref"])
        elif i["ack_pending"]:
            add("Incident", "High", f"{i['ref']} awaiting acknowledgement (due {i['ack_due'][11:16]}Z)", "incidents", i["ref"])
        if i["cert_in_state"] == "OVERDUE":
            add("Incident", "Critical", f"{i['ref']} CERT-In six-hour reporting window has passed - verify obligations with legal/privacy", "incidents", i["ref"])
        elif i["cert_in_state"] and i["cert_in_state"].startswith("Due"):
            add("Incident", "High", f"{i['ref']} CERT-In report {i['cert_in_state'].lower()}", "incidents", i["ref"])
        if i["cert_in_assessment"] == "Not assessed" and i["severity"] in ("SEV-1", "SEV-2"):
            add("Incident", "Medium", f"{i['ref']} reporting obligations not yet assessed", "incidents", i["ref"])
    for f in [vulns.finding_decorate(r) for r in rows("SELECT * FROM vuln_findings")]:
        if f["overdue"]:
            add("Vulnerability", f["severity"], f"{f['ref']} overdue since {f['due_date']}: {f['title']}", "vulns", f["ref"])
        if f["acceptance_expired"]:
            add("Vulnerability", "High", f"{f['ref']} risk acceptance expired {f['accept_expiry']}", "vulns", f["ref"])
    for f in [audits.finding_decorate(r) for r in rows("SELECT * FROM audit_findings")]:
        if f["overdue"]:
            add("Audit", f["severity"] if f["severity"] != "Observation" else "Low",
                f"{f['ref']} overdue since {f['due_date']}" + (" - escalate" if f["escalation"] else "") + f": {f['title']}", "audits", f["ref"])
        if f["acceptance_expired"]:
            add("Audit", "High", f"{f['ref']} risk acceptance expired {f['accept_expiry']}", "audits", f["ref"])
    for e in rows("SELECT ref, control, expiry_date FROM policy_exceptions WHERE status='Approved' AND expiry_date < ?", (t,)):
        add("Policy", "High", f"Exception {e['ref']} expired {e['expiry_date']} - reapprove or close", "policy", e["ref"])
    for a in rows("SELECT action, due_date FROM policy_actions WHERE status != 'Completed' AND due_date IS NOT NULL AND due_date < ?", (t,)):
        add("Policy", "Medium", f"Roadmap action overdue ({a['due_date']}): {a['action'][:80]}", "policy")
    for th in rows("SELECT name, review_date FROM threats WHERE status != 'Accepted' AND review_date IS NOT NULL AND review_date < ?", (t,)):
        add("Threat", "Medium", f"Threat review overdue ({th['review_date']}): {th['name']}", "threats")
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3}
    items.sort(key=lambda x: order.get(x["severity"], 4))
    return items


@bp.get("/dashboard")
@login_required
def dashboard():
    threats = [threat_decorate(dict(r)) for r in rows("SELECT * FROM threats")]
    threats_sorted = sorted(threats, key=lambda x: (-x["score"], x["name"]))
    att = attention_items()
    return jsonify({
        "organization": R.ORGANIZATION, "today": today(),
        "threats": {"total": len(threats),
                    "by_rating": {r: sum(1 for x in threats if x["indicative_rating"] == r) for r in ("Critical", "High", "Medium", "Low")},
                    "top": [{"id": x["id"], "name": x["name"], "score": x["score"], "rating": x["indicative_rating"]} for x in threats_sorted[:5]],
                    "points": [{"id": x["id"], "name": x["name"], "likelihood": x["likelihood"], "impact": x["impact"], "rating": x["indicative_rating"]} for x in threats]},
        "incidents": incidents.summary().get_json(),
        "policy": policy.summary().get_json(),
        "awareness": awareness.summary().get_json(),
        "vulns": vulns.summary().get_json(),
        "audit": audits.summary().get_json(),
        "attention": att[:25], "attention_total": len(att),
    })
