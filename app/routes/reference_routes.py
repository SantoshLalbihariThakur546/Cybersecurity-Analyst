from flask import Blueprint, jsonify

from .. import reference as R
from ..security import ApiError, login_required

bp = Blueprint("reference", __name__, url_prefix="/api/reference")

_SETS = {
    "organization": R.ORGANIZATION, "weeks": R.WEEKS, "scale": R.LIKELIHOOD_IMPACT_SCALE, "attack_stages": R.ATTACK_STAGES,
    "impact_dimensions": R.IMPACT_DIMENSIONS, "defensive_priorities": R.DEFENSIVE_PRIORITIES,
    "severity_model": R.SEVERITY_MODEL, "incident_categories": R.INCIDENT_CATEGORIES, "incident_statuses": R.INCIDENT_STATUSES,
    "checklist15": R.CHECKLIST_15, "checklist24": R.CHECKLIST_24, "closure_criteria": R.CLOSURE_CRITERIA,
    "playbooks": R.PLAYBOOKS, "ir_roles": R.IR_ROLES, "post_incident_template": R.POST_INCIDENT_TEMPLATE,
    "cert_in_note": R.CERT_IN_NOTE, "patch_sla": R.PATCH_SLA, "policy_rating_defs": R.POLICY_RATING_DEFS,
    "policy_baseline": R.POLICY_BASELINE, "policy_roles": R.POLICY_GOVERNANCE_ROLES, "exception_process": R.EXCEPTION_PROCESS,
    "campaign_messages": R.CAMPAIGN_MESSAGES, "campaign_risks": R.CAMPAIGN_RISKS, "campaign_guardrails": R.CAMPAIGN_GUARDRAILS,
    "audit_domains": R.AUDIT_DOMAINS, "audit_tiers": R.AUDIT_TIERS, "audit_severity": R.AUDIT_SEVERITY,
    "audit_workflow": R.AUDIT_WORKFLOW, "audit_roles": R.AUDIT_ROLES, "audit_program_risks": R.AUDIT_PROGRAM_RISKS,
    "workpaper_template": R.WORKPAPER_TEMPLATE, "finding_statuses": R.FINDING_STATUSES,
}


@bp.get("/<name>")
@login_required
def get_set(name):
    if name not in _SETS:
        raise ApiError(404, "NOT_FOUND", "Unknown reference set.")
    return jsonify(_SETS[name])
