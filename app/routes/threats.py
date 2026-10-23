"""Week 1 - Threat landscape analysis."""
from flask import Blueprint

from ..crud import F, Resource, today

bp = Blueprint("threats", __name__, url_prefix="/api")

SCALE = [1, 1.5, 2, 2.5, 3, 3.5, 4]
STATUS = ["Open", "Mitigating", "Monitoring", "Accepted"]


def _band(score):
    # documented qualitative ratings are expert judgment (Week 1 s9.1); this band is only a prioritisation aid on the 1-16 product
    return "Critical" if score >= 9 else "High" if score >= 6 else "Medium" if score >= 3 else "Low"


def threat_decorate(d):
    d["score"] = round(d["likelihood"] * d["impact"], 2)
    d["score_band"] = _band(d["score"])
    d["review_overdue"] = bool(d.get("review_date") and d["review_date"] < today() and d["status"] != "Accepted")
    return d


Resource("threats", "threats", [
    F("name", required=True), F("category"), F("likelihood", "float", True, lo=1, hi=4), F("impact", "float", True, lo=1, hi=4),
    F("indicative_rating", "choice", True, choices=["Low", "Medium", "High", "Critical"]),
    F("reasoning", "text"), F("controls", "text"), F("owner"), F("status", "choice", choices=STATUS, default="Open"),
    F("review_date", "date")], write="threats.write", search=("name", "category", "reasoning"),
    filters=("status", "indicative_rating"), sorts=("id", "name", "likelihood", "impact", "indicative_rating", "review_date"),
    decorate=threat_decorate, timestamps=True).register(bp)

Resource("threat-categories", "threat_categories", [F("name", required=True), F("description", "text"),
         F("potential_impact", "text"), F("priority_controls", "text")], write="threats.write",
         search=("name", "description")).register(bp)
Resource("threat-actors", "threat_actors", [F("category", required=True), F("goals", "text"), F("approaches", "text"),
         F("indicators", "text")], write="threats.write", search=("category", "goals")).register(bp)
Resource("intel-sources", "intel_sources", [F("title", required=True), F("publisher"), F("period"), F("finding", "text"),
         F("caution", "text"), F("url", maxlen=500)], write="threats.write", search=("title", "publisher", "finding")).register(bp)
Resource("research-log", "research_log", [F("logged_at", "datetime"), F("question", "text", True), F("source", maxlen=500),
         F("evidence", "text"), F("reliability", "text"), F("report_section")], write="threats.write",
         search=("question", "source", "evidence"), sorts=("id", "logged_at"), default_sort="-id", timestamps=True).register(bp)
