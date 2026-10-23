"""Week 4 - Security awareness campaign: tasks, anonymous quiz, simulations, feedback, objective tracking."""
from flask import Blueprint, jsonify, request

from ..crud import F, Resource, today, validate
from ..db import get_db, jload, now_iso, one, rows, scalar
from ..security import ApiError, login_required, require, write_audit

bp = Blueprint("awareness", __name__, url_prefix="/api")
TASK_STATUS = ["Not started", "In progress", "Completed", "Blocked"]


def campaign_before(clean, existing, user):
    m = {**(existing or {}), **clean}
    elig = m.get("eligible_employees") or 0
    for k in ("reached_count", "completed_count"):
        if (m.get(k) or 0) > elig:
            raise ApiError(422, "VALIDATION_ERROR", "Counts cannot exceed eligible employees.", [{"field": k, "message": "exceeds eligible employees"}])
    if (m.get("completed_count") or 0) > (m.get("reached_count") or 0):
        raise ApiError(422, "VALIDATION_ERROR", "Completed cannot exceed reached.", [{"field": "completed_count", "message": "exceeds reached employees"}])
    return clean


Resource("campaigns", "campaigns", [
    F("name", required=True), F("tagline"), F("start_date", "date"), F("eligible_employees", "int", True, lo=1, hi=1000000),
    F("reached_count", "int", default=0, lo=0), F("completed_count", "int", default=0, lo=0),
    F("status", "choice", choices=["Planned", "Active", "Completed"], default="Planned"), F("sponsor"), F("owner")],
    write="awareness.write", before_save=campaign_before).register(bp)
Resource("campaign-tasks", "campaign_tasks", [
    F("campaign_id", "int", True, lo=1), F("week", "int", True, lo=1, hi=8), F("theme", required=True), F("activity", "text"),
    F("deliverable", "text"), F("evidence", "text"), F("owner"), F("status", "choice", choices=TASK_STATUS, default="Not started"),
    F("due_date", "date")], write="awareness.write", filters=("campaign_id", "status", "week"), sorts=("id", "week", "status"),
    default_sort="week").register(bp)
Resource("campaign-segments", "campaign_segments", [F("name", required=True), F("headcount", "int", lo=0), F("risk", "text"),
         F("response", "text")], write="awareness.write").register(bp)
Resource("campaign-topics", "campaign_topics", [F("topic", required=True), F("takeaway", "text"), F("activity", "text")],
         write="awareness.write").register(bp)
Resource("campaign-channels", "campaign_channels", [F("channel", required=True), F("cadence", "text"), F("owner"),
         F("accessibility", "text")], write="awareness.write").register(bp)


def sim_before(clean, existing, user):
    m = {**(existing or {}), **clean}
    if m["clicked"] > m["sent"] or m["reported"] > m["sent"]:
        raise ApiError(422, "VALIDATION_ERROR", "Clicked/reported cannot exceed sent.", [{"field": "sent", "message": "clicked and reported must not exceed sent"}])
    return clean


def sim_decorate(d):
    d["click_rate"] = round(100 * d["clicked"] / d["sent"], 1) if d["sent"] else None
    d["report_rate"] = round(100 * d["reported"] / d["sent"], 1) if d["sent"] else None
    return d


Resource("simulations", "simulations", [
    F("phase", "choice", True, choices=["baseline", "follow_up"]), F("run_date", "date"), F("sent", "int", True, lo=1),
    F("clicked", "int", True, lo=0), F("reported", "int", True, lo=0), F("notes", "text")], write="awareness.write",
    sorts=("id", "run_date", "phase"), default_sort="run_date", before_save=sim_before, decorate=sim_decorate).register(bp)

Resource("quiz-questions", "quiz_questions", [F("position", "int", True, lo=1, hi=100), F("question", "text", True),
         F("options", "json", True), F("correct_index", "int", True, lo=0, hi=9), F("explanation", "text")],
         write="awareness.write", read="awareness.write", sorts=("id", "position"), default_sort="position",
         before_save=lambda c, e, u: _quiz_check(c, e)).register(bp)


def _quiz_check(clean, existing):
    m = {**(existing or {}), **clean}
    opts = m["options"] if isinstance(m["options"], list) else jload(m["options"], [])
    if not (2 <= len(opts) <= 6) or not all(isinstance(o, str) and o.strip() for o in opts):
        raise ApiError(422, "VALIDATION_ERROR", "Provide 2-6 non-empty answer options.", [{"field": "options", "message": "2-6 text options required"}])
    if m["correct_index"] >= len(opts):
        raise ApiError(422, "VALIDATION_ERROR", "Correct answer index is out of range.", [{"field": "correct_index", "message": "out of range"}])
    return clean


@bp.get("/quiz")
@login_required
def quiz():
    """Questions WITHOUT the answer key (the key is checked server-side on submit)."""
    qs = rows("SELECT id, position, question, options FROM quiz_questions ORDER BY position")
    for q in qs:
        q["options"] = jload(q["options"], [])
    return jsonify({"questions": qs})


@bp.post("/quiz/submit")
@require("quiz.submit")
def quiz_submit():
    data = request.get_json(silent=True) or {}
    phase = data.get("phase")
    if phase not in ("baseline", "post"):
        raise ApiError(422, "VALIDATION_ERROR", "phase must be 'baseline' or 'post'.", [{"field": "phase", "message": "invalid"}])
    segment = str(data.get("segment") or "All employees")[:80]
    answers = data.get("answers")
    questions = rows("SELECT * FROM quiz_questions ORDER BY position")
    if not isinstance(answers, dict) or not questions:
        raise ApiError(422, "VALIDATION_ERROR", "answers must map question id to chosen option index.", [{"field": "answers", "message": "invalid"}])
    score, review = 0, []
    for q in questions:
        opts = jload(q["options"], [])
        a = answers.get(str(q["id"]))
        if not isinstance(a, int) or isinstance(a, bool) or not (0 <= a < len(opts)):
            raise ApiError(422, "VALIDATION_ERROR", "Please answer every question.", [{"field": f"answers.{q['id']}", "message": "missing or invalid"}])
        correct = a == q["correct_index"]
        score += correct
        review.append({"id": q["id"], "correct": correct, "correct_index": q["correct_index"], "explanation": q["explanation"]})
    get_db().execute("INSERT INTO quiz_attempts(phase,segment,score,total,submitted_at) VALUES(?,?,?,?,?)",
                     (phase, segment, score, len(questions), now_iso()))
    get_db().commit()
    write_audit("QUIZ_SUBMIT", "quiz", None, {"phase": phase})  # no score/identity linkage beyond the actor of the request
    return jsonify({"score": score, "total": len(questions), "percent": round(100 * score / len(questions), 1), "review": review})


@bp.post("/feedback")
@require("quiz.submit")
def feedback_submit():
    data = request.get_json(silent=True) or {}
    clean = validate([F("relevance", "int", True, lo=1, hi=5), F("confidence", "int", True, lo=1, hi=5),
                      F("knows_reporting", "bool", True), F("comment", "text", maxlen=1000)], data, partial=False)
    get_db().execute("INSERT INTO feedback(relevance,confidence,knows_reporting,comment,submitted_at) VALUES(?,?,?,?,?)",
                     (clean["relevance"], clean["confidence"], clean["knows_reporting"], clean.get("comment"), now_iso()))
    get_db().commit()
    write_audit("FEEDBACK_SUBMIT", "feedback", None, {})
    return jsonify({"ok": True}), 201


@bp.get("/awareness-summary")
@login_required
def summary():
    c = one("SELECT * FROM campaigns ORDER BY id LIMIT 1")
    elig = c["eligible_employees"] if c else 0
    reach = round(100 * c["reached_count"] / elig, 1) if elig else None
    completion = round(100 * c["completed_count"] / elig, 1) if elig else None

    def avg_pct(phase):
        r = one("SELECT COUNT(*) n, SUM(score) s, SUM(total) t FROM quiz_attempts WHERE phase=?", (phase,))
        return (round(100 * r["s"] / r["t"], 1), r["n"]) if r["n"] else (None, 0)
    base, nb = avg_pct("baseline")
    post, np_ = avg_pct("post")
    improvement = round(post - base, 1) if base is not None and post is not None else None
    fb = one("SELECT COUNT(*) n, AVG(relevance) rel, AVG(confidence) conf, SUM(knows_reporting) kr FROM feedback")
    sims = {s["phase"]: sim_decorate(s) for s in rows("SELECT * FROM simulations ORDER BY run_date")}
    tasks = rows("SELECT status FROM campaign_tasks")

    def metric(name, target, current, unit, goal, note=""):
        met = None if current is None else current >= target
        return {"name": name, "target": target, "current": current, "unit": unit, "goal": goal, "met": met, "note": note}
    kr = round(100 * fb["kr"] / fb["n"], 1) if fb["n"] else None
    return jsonify({
        "campaign": c,
        "metrics": [
            metric("Reach", 90, reach, "%", "At least 90% of employees reached by core campaign content"),
            metric("Training completion", 85, completion, "%", "At least 85% complete the microlearning within the campaign window"),
            metric("Knowledge improvement", 20, improvement, "pp", "Average post-campaign quiz score at least 20 percentage points above baseline",
                   f"baseline {base}% (n={nb}) -> post {post}% (n={np_})" if improvement is not None else "Needs baseline and post-campaign attempts"),
            metric("Reporting awareness", 90, kr, "%", "At least 90% know how to report a suspicious message", f"n={fb['n']}" if fb["n"] else "No feedback yet"),
        ],
        "quiz": {"baseline_pct": base, "baseline_n": nb, "post_pct": post, "post_n": np_, "improvement_pp": improvement},
        "simulations": sims,
        "simulation_trend": ({"click_rate_change_pp": round(sims["follow_up"]["click_rate"] - sims["baseline"]["click_rate"], 1),
                              "report_rate_change_pp": round(sims["follow_up"]["report_rate"] - sims["baseline"]["report_rate"], 1)}
                             if "baseline" in sims and "follow_up" in sims else None),
        "feedback": {"n": fb["n"], "avg_relevance": round(fb["rel"], 2) if fb["n"] else None,
                     "avg_confidence": round(fb["conf"], 2) if fb["n"] else None, "knows_reporting_pct": kr},
        "tasks": {"total": len(tasks), "completed": sum(1 for t in tasks if t["status"] == "Completed"),
                  "in_progress": sum(1 for t in tasks if t["status"] == "In progress")},
    })
