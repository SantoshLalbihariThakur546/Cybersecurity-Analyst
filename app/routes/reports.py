"""Printable HTML reports and CSV exports (every export is audited; CSV cells are formula-injection safe)."""
import csv
import html
import io

from flask import Blueprint, Response, make_response

from .. import reference as R
from ..crud import today
from ..db import one, rows
from ..security import ApiError, require, write_audit
from . import audits, awareness, incidents, policy, vulns
from .dashboard import attention_items

bp = Blueprint("reports", __name__, url_prefix="/api")
E = html.escape
CSS = ("body{font-family:Segoe UI,Arial,sans-serif;max-width:1000px;margin:2rem auto;padding:0 1rem;color:#14213d;line-height:1.45}"
       "h1{color:#0b2a4a}h2{color:#1f5fa8;border-bottom:1px solid #d5dce6;padding-bottom:4px;margin-top:2rem}"
       "table{border-collapse:collapse;width:100%;font-size:.88rem;margin:.6rem 0}th,td{border:1px solid #c9d3df;padding:5px 8px;text-align:left;vertical-align:top}"
       "th{background:#eaf0f8}.muted{color:#5b6b7c}.note{background:#fff7e6;border-left:4px solid #e0a100;padding:8px 12px;margin:1rem 0}"
       "@media print{body{margin:0}}")


def _page(title, body):
    resp = make_response(f"<!doctype html><html lang='en'><head><meta charset='utf-8'><title>{E(title)}</title><style>{CSS}</style></head><body>{body}</body></html>")
    resp.headers["Content-Type"] = "text/html; charset=utf-8"
    resp.headers["Content-Security-Policy"] = "default-src 'none'; style-src 'unsafe-inline'"
    return resp


def _table(headers, data):
    head = "".join(f"<th>{E(h)}</th>" for h in headers)
    body = "".join("<tr>" + "".join(f"<td>{E('' if c is None else str(c))}</td>" for c in r) + "</tr>" for r in data)
    return f"<table><thead><tr>{head}</tr></thead><tbody>{body or '<tr><td colspan=%d>None</td></tr>' % len(headers)}</tbody></table>"


@bp.get("/reports/executive")
@require("reports.read")
def executive():
    inc, pol, awr = incidents.summary().get_json(), policy.summary().get_json(), awareness.summary().get_json()
    vul, aud = vulns.summary().get_json(), audits.summary().get_json()
    att = attention_items()
    write_audit("REPORT", "executive", None, {})
    org = R.ORGANIZATION
    b = [f"<h1>Cybersecurity Program - Executive Summary</h1><p class='muted'>{E(org['name'])} - generated {E(today())}</p>",
         f"<div class='note'>{E(org['note'])}</div>",
         "<h2>Needs attention</h2>", _table(["Severity", "Area", "Item"], [(a["severity"], a["kind"], a["label"]) for a in att[:20]]),
         "<h2>Week 1 - Threat landscape (top scenarios)</h2>",
         _table(["Threat", "Likelihood", "Impact", "Score", "Indicative rating"],
                [(t["name"], t["likelihood"], t["impact"], t["score"], t["indicative_rating"]) for t in
                 sorted([__import__('app.routes.threats', fromlist=['x']).threat_decorate(dict(r)) for r in rows("SELECT * FROM threats")],
                        key=lambda x: -x["score"])[:6]]),
         "<h2>Week 2 - Incident response</h2>",
         f"<p>Open incidents: <b>{inc['open']}</b> (SEV-1: {inc['open_by_severity']['SEV-1']}, SEV-2: {inc['open_by_severity']['SEV-2']}, SEV-3: {inc['open_by_severity']['SEV-3']}, SEV-4: {inc['open_by_severity']['SEV-4']}). "
         f"Acknowledgement target breaches: <b>{inc['ack_breaches']}</b>. Average minutes to acknowledge: {inc['avg_minutes']['time_to_acknowledge_min']}.</p>",
         "<h2>Week 3 - Security policy review</h2>",
         f"<p>Open policy risks by band: {E(str(pol['risk_bands']))}. Roadmap actions completed: {pol['actions_completed']}/{pol['actions_total']}. Expired exceptions: {pol['exceptions_expired']}.</p>",
         _table(["Control area", "Rating", "Priority"], [(c["area"], c["rating"], c["priority"]) for c in rows("SELECT * FROM policy_controls ORDER BY sort_order")]),
         "<h2>Week 4 - Awareness campaign</h2>",
         _table(["Objective", "Target", "Current", "Met"], [(m["name"], f"{m['target']}{m['unit']}", "no data" if m["current"] is None else f"{m['current']}{m['unit']}", "-" if m["met"] is None else ("yes" if m["met"] else "not yet")) for m in awr["metrics"]]),
         "<h2>Week 5 - Vulnerability assessment</h2>",
         f"<p>Open findings: <b>{vul['open']}</b>; overdue: <b>{vul['overdue']}</b>; SLA compliance: {vul['sla_compliance_pct']}%; Critical/High resolved: {vul['critical_high_resolved_pct']}%.</p>",
         _table(["Ref", "Finding", "Severity", "Owner", "Due", "Status"], [(f["ref"], f["title"], f["severity"], f["owner"], f["due_date"], f["status"]) for f in rows("SELECT * FROM vuln_findings ORDER BY due_date")]),
         "<h2>Week 6 - Audit plan</h2>",
         f"<p>Plan completion: {aud['plan_completion_pct']}% (completed or formally rescheduled). Open findings: {aud['findings_open']}; overdue Critical/High: {aud['overdue_critical_high']}.</p>",
         _table(["Month", "Focus", "Status"], [(r["month"], r["focus"], r["status"]) for r in rows("SELECT * FROM audit_calendar ORDER BY month")]),
         "<p class='muted'>Illustrative scenario data unless replaced. Generated figures are planning aids, not evidence of compliance.</p>"]
    return _page("Executive summary", "".join(b))


@bp.get("/incidents/<int:rid>/report")
@require("reports.read")
def incident_report(rid):
    r = one("SELECT * FROM incidents WHERE id=?", (rid,))
    if not r:
        raise ApiError(404, "NOT_FOUND", "Incident not found.")
    i = incidents.decorate(dict(r))
    tl = rows("SELECT * FROM incident_timeline WHERE incident_id=? ORDER BY event_time", (rid,))
    ev = rows("SELECT * FROM incident_evidence WHERE incident_id=? ORDER BY id", (rid,))
    dec = rows("SELECT * FROM incident_decisions WHERE incident_id=? ORDER BY decided_at", (rid,))
    act = rows("SELECT * FROM incident_actions WHERE incident_id=? ORDER BY id", (rid,))
    m = i["metrics"]
    write_audit("REPORT", "incident", rid, {})
    sections = [
        ("Executive summary", f"<p><b>{E(i['ref'])}</b> - {E(i['title'])}<br>Severity {E(i['severity'])}; status {E(i['status'])}; category {E(i['category'])}; reported {E(i['reported_at'])}.<br>Business impact: {E(i.get('business_impact') or 'not recorded')}</p>"),
        ("Detection", f"<p>Time to acknowledge: {m['time_to_acknowledge_min']} min (target {E(i['ack_target'])}; {'MISSED' if i['ack_breached'] else 'met or pending'}). Time to declare: {m['time_to_declare_min']} min.</p>"),
        ("Scope", f"<p>Affected assets: {E(i.get('affected_assets') or 'not recorded')}<br>Observed activity: {E(i.get('observed_activity') or 'not recorded')}<br>Data impact (confirmed vs suspected): <b>{E(i['data_impact'])}</b></p>"),
        ("Timeline", _table(["Time", "Event", "Source", "Confidence", "Interpretation / action"], [(t["event_time"], t["event"], t["source"], t["confidence"], t["interpretation"]) for t in tl])),
        ("Root cause", f"<p>{E(i.get('root_cause') or 'Not yet determined')}</p>"),
        ("Response actions", f"<p>Time to contain: {m['time_to_contain_min']} min; time to recover: {m['time_to_recover_min']} min.</p>" + _table(["ID", "Evidence", "Collected by", "Collected (UTC)", "SHA-256", "Location"], [(e["evid"], e["description"], e["collected_by"], e["collected_at"], e["sha256"], e["storage_location"]) for e in ev]) + _table(["Decision", "Rationale", "Approver", "Outcome", "Time"], [(d["decision"], d["rationale"], d["approver"], d["outcome"], d["decided_at"]) for d in dec])),
        ("Notifications", f"<p>CERT-In assessment: {E(i['cert_in_assessment'])}; state: {E(str(i['cert_in_state'] or 'n/a'))}. {E(R.CERT_IN_NOTE)}</p>"),
        ("Impact and cost", "<p class='muted'>Record downtime, recovery effort, data impact and estimated cost here if approved.</p>"),
        ("What worked / did not", "<p class='muted'>Add evidence-based observations during the post-incident review.</p>"),
        ("Corrective action plan", _table(["Action", "Priority", "Owner", "Due", "Status"], [(a["title"], a["priority"], a["owner"], a["due_date"], a["status"]) for a in act])),
        ("Approval", "<p>Incident commander: ________ &nbsp; Business owner: ________ &nbsp; Security lead: ________ &nbsp; Executive reviewer: ________</p>"),
    ]
    body = f"<h1>Post-incident report - {E(i['ref'])}</h1>" + ("<div class='note'>Illustrative demo incident - fictional timeline for demonstration only.</div>" if i["is_demo"] else "")
    body += "".join(f"<h2>{n}. {E(h)}</h2>{c}" for n, (h, c) in enumerate(sections, 1))
    return _page(f"Post-incident report {i['ref']}", body)


EXPORTS = {"threats": "threats", "vuln-findings": "vuln_findings", "audit-findings": "audit_findings", "policy-risks": "policy_risks",
           "policy-exceptions": "policy_exceptions", "policy-actions": "policy_actions", "incidents": "incidents",
           "policy-controls": "policy_controls", "campaign-tasks": "campaign_tasks", "audit-calendar": "audit_calendar"}


def _safe(v):
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v
    return v


@bp.get("/export/<name>.csv")
@require("reports.read")
def export_csv(name):
    table = EXPORTS.get(name)
    if not table:
        raise ApiError(404, "NOT_FOUND", "Unknown export.")
    data = rows(f"SELECT * FROM {table} ORDER BY id")
    buf = io.StringIO()
    if data:
        cols = [c for c in data[0] if c not in ("password_hash",)]
        w = csv.writer(buf)
        w.writerow(cols)
        for r in data:
            w.writerow([_safe(r[c]) for c in cols])
    write_audit("EXPORT", name, None, {"rows": len(data)})
    resp = Response(buf.getvalue(), mimetype="text/csv")
    resp.headers["Content-Disposition"] = f'attachment; filename="{name}-{today()}.csv"'
    return resp
