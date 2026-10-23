"""SQLite access + schema. One connection per request; WAL mode; foreign keys enforced."""
import json
import sqlite3
from datetime import datetime, timezone

from flask import current_app, g

SCHEMA = """
CREATE TABLE IF NOT EXISTS users(
  id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, full_name TEXT NOT NULL DEFAULT '',
  password_hash TEXT NOT NULL, role TEXT NOT NULL, active INTEGER NOT NULL DEFAULT 1,
  failed_attempts INTEGER NOT NULL DEFAULT 0, locked_until TEXT, created_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT, action TEXT NOT NULL, entity TEXT,
  entity_id TEXT, details TEXT, prev_hash TEXT NOT NULL, entry_hash TEXT NOT NULL);

-- Week 1: threat landscape
CREATE TABLE IF NOT EXISTS threats(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, category TEXT, likelihood REAL NOT NULL, impact REAL NOT NULL,
  indicative_rating TEXT NOT NULL, reasoning TEXT, controls TEXT, owner TEXT, status TEXT NOT NULL DEFAULT 'Open',
  review_date TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS threat_categories(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, description TEXT, potential_impact TEXT, priority_controls TEXT);
CREATE TABLE IF NOT EXISTS threat_actors(
  id INTEGER PRIMARY KEY AUTOINCREMENT, category TEXT NOT NULL, goals TEXT, approaches TEXT, indicators TEXT);
CREATE TABLE IF NOT EXISTS intel_sources(
  id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT NOT NULL, publisher TEXT, period TEXT, finding TEXT, caution TEXT, url TEXT);
CREATE TABLE IF NOT EXISTS research_log(
  id INTEGER PRIMARY KEY AUTOINCREMENT, logged_at TEXT, question TEXT NOT NULL, source TEXT, evidence TEXT,
  reliability TEXT, report_section TEXT, created_at TEXT);

-- Week 2: incident response
CREATE TABLE IF NOT EXISTS incidents(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ref TEXT UNIQUE, title TEXT NOT NULL, category TEXT NOT NULL,
  severity TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Reported',
  started_at TEXT, reported_at TEXT NOT NULL, acknowledged_at TEXT, declared_at TEXT, contained_at TEXT,
  recovered_at TEXT, closed_at TEXT, reporter TEXT, triage_owner TEXT, incident_commander TEXT,
  affected_assets TEXT, observed_activity TEXT, business_impact TEXT, data_impact TEXT NOT NULL DEFAULT 'Unknown',
  cert_in_assessment TEXT NOT NULL DEFAULT 'Not assessed', cert_in_reported_at TEXT, root_cause TEXT,
  closure_summary TEXT, checklist15 TEXT NOT NULL DEFAULT '[]', checklist24 TEXT NOT NULL DEFAULT '[]',
  closure_checks TEXT NOT NULL DEFAULT '[]', is_demo INTEGER NOT NULL DEFAULT 0, created_by TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS incident_timeline(
  id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  event_time TEXT NOT NULL, event TEXT NOT NULL, source TEXT, confidence TEXT, interpretation TEXT);
CREATE TABLE IF NOT EXISTS incident_evidence(
  id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  evid TEXT, description TEXT NOT NULL, collected_by TEXT, collected_at TEXT, sha256 TEXT, storage_location TEXT,
  filename TEXT, size_bytes INTEGER, stored_name TEXT);
CREATE TABLE IF NOT EXISTS incident_decisions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  decided_at TEXT NOT NULL, decision TEXT NOT NULL, rationale TEXT, approver TEXT, outcome TEXT);
CREATE TABLE IF NOT EXISTS incident_actions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, incident_id INTEGER NOT NULL REFERENCES incidents(id) ON DELETE CASCADE,
  title TEXT NOT NULL, priority TEXT NOT NULL DEFAULT 'Medium', owner TEXT, due_date TEXT,
  status TEXT NOT NULL DEFAULT 'Open', evidence TEXT);

-- Week 3: policy review
CREATE TABLE IF NOT EXISTS policy_controls(
  id INTEGER PRIMARY KEY AUTOINCREMENT, area TEXT NOT NULL, rating TEXT NOT NULL, main_gap TEXT, priority TEXT NOT NULL,
  critique TEXT, recommendation TEXT, evidence TEXT, sort_order INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS policy_risks(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ref TEXT UNIQUE, title TEXT NOT NULL, likelihood INTEGER NOT NULL,
  impact INTEGER NOT NULL, score INTEGER NOT NULL, band TEXT NOT NULL, owner TEXT, treatment TEXT NOT NULL DEFAULT 'Mitigate',
  status TEXT NOT NULL DEFAULT 'Open', review_date TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS policy_actions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, phase TEXT NOT NULL, action TEXT NOT NULL, owner TEXT, deliverable TEXT,
  success_measure TEXT, status TEXT NOT NULL DEFAULT 'Not started', due_date TEXT);
CREATE TABLE IF NOT EXISTS policy_exceptions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ref TEXT UNIQUE, requester TEXT NOT NULL, control TEXT NOT NULL, assets TEXT,
  justification TEXT, risk_assessment TEXT, compensating_controls TEXT, approver TEXT, approved_on TEXT,
  expiry_date TEXT, review_date TEXT, status TEXT NOT NULL DEFAULT 'Pending', closure_evidence TEXT,
  created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS policy_metrics(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, definition TEXT, target_text TEXT, target_value REAL,
  current_value REAL, unit TEXT, direction TEXT NOT NULL DEFAULT 'higher', cadence TEXT, owner TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS policy_checklist(
  id INTEGER PRIMARY KEY AUTOINCREMENT, question TEXT NOT NULL, answer TEXT NOT NULL DEFAULT 'Unanswered', evidence TEXT);
CREATE TABLE IF NOT EXISTS evidence_requests(
  id INTEGER PRIMARY KEY AUTOINCREMENT, item TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'Not requested', notes TEXT);
CREATE TABLE IF NOT EXISTS policy_statements(
  id INTEGER PRIMARY KEY AUTOINCREMENT, topic TEXT NOT NULL, language TEXT NOT NULL);

-- Week 4: awareness campaign
CREATE TABLE IF NOT EXISTS campaigns(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, tagline TEXT, start_date TEXT, eligible_employees INTEGER NOT NULL,
  reached_count INTEGER NOT NULL DEFAULT 0, completed_count INTEGER NOT NULL DEFAULT 0, status TEXT NOT NULL DEFAULT 'Planned',
  sponsor TEXT, owner TEXT);
CREATE TABLE IF NOT EXISTS campaign_tasks(
  id INTEGER PRIMARY KEY AUTOINCREMENT, campaign_id INTEGER NOT NULL REFERENCES campaigns(id) ON DELETE CASCADE,
  week INTEGER NOT NULL, theme TEXT NOT NULL, activity TEXT, deliverable TEXT, evidence TEXT, owner TEXT,
  status TEXT NOT NULL DEFAULT 'Not started', due_date TEXT);
CREATE TABLE IF NOT EXISTS campaign_segments(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, headcount INTEGER, risk TEXT, response TEXT);
CREATE TABLE IF NOT EXISTS campaign_topics(
  id INTEGER PRIMARY KEY AUTOINCREMENT, topic TEXT NOT NULL, takeaway TEXT, activity TEXT);
CREATE TABLE IF NOT EXISTS campaign_channels(
  id INTEGER PRIMARY KEY AUTOINCREMENT, channel TEXT NOT NULL, cadence TEXT, owner TEXT, accessibility TEXT);
CREATE TABLE IF NOT EXISTS quiz_questions(
  id INTEGER PRIMARY KEY AUTOINCREMENT, position INTEGER NOT NULL, question TEXT NOT NULL, options TEXT NOT NULL,
  correct_index INTEGER NOT NULL, explanation TEXT);
CREATE TABLE IF NOT EXISTS quiz_attempts(
  id INTEGER PRIMARY KEY AUTOINCREMENT, phase TEXT NOT NULL, segment TEXT, score INTEGER NOT NULL, total INTEGER NOT NULL,
  submitted_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS simulations(
  id INTEGER PRIMARY KEY AUTOINCREMENT, phase TEXT NOT NULL, run_date TEXT, sent INTEGER NOT NULL, clicked INTEGER NOT NULL,
  reported INTEGER NOT NULL, notes TEXT);
CREATE TABLE IF NOT EXISTS feedback(
  id INTEGER PRIMARY KEY AUTOINCREMENT, relevance INTEGER NOT NULL, confidence INTEGER NOT NULL,
  knows_reporting INTEGER NOT NULL, comment TEXT, submitted_at TEXT NOT NULL);

-- Week 5: vulnerability assessment
CREATE TABLE IF NOT EXISTS assets(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, type TEXT NOT NULL, owner TEXT, criticality TEXT NOT NULL DEFAULT 'Medium',
  exposure TEXT NOT NULL DEFAULT 'Internal', platform TEXT, support_status TEXT NOT NULL DEFAULT 'Supported', notes TEXT);
CREATE TABLE IF NOT EXISTS vuln_findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ref TEXT UNIQUE, title TEXT NOT NULL, severity TEXT NOT NULL, likelihood TEXT, impact TEXT,
  priority TEXT, owner TEXT, target_days INTEGER NOT NULL, identified_on TEXT NOT NULL, due_date TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Open', observation TEXT, potential_impact TEXT, recommendations TEXT, verification_required TEXT,
  closure_evidence TEXT, closed_on TEXT, asset_id INTEGER REFERENCES assets(id) ON DELETE SET NULL,
  actively_exploited INTEGER NOT NULL DEFAULT 0, accept_rationale TEXT, accept_approver TEXT, accept_expiry TEXT,
  created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS vuln_roadmap(
  id INTEGER PRIMARY KEY AUTOINCREMENT, timeframe TEXT NOT NULL, actions TEXT NOT NULL, success_measure TEXT,
  status TEXT NOT NULL DEFAULT 'Not started', sort_order INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS vuln_metrics(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, target_text TEXT, target_value REAL, current_value REAL,
  unit TEXT, direction TEXT NOT NULL DEFAULT 'higher', cadence TEXT, updated_at TEXT);

-- Week 6: audit plan
CREATE TABLE IF NOT EXISTS audit_calendar(
  id INTEGER PRIMARY KEY AUTOINCREMENT, month INTEGER UNIQUE NOT NULL, focus TEXT NOT NULL, activities TEXT, tier TEXT,
  status TEXT NOT NULL DEFAULT 'Planned', completed_on TEXT, reschedule_rationale TEXT, notes TEXT);
CREATE TABLE IF NOT EXISTS audits(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ref TEXT UNIQUE, month INTEGER, domain TEXT NOT NULL, control_objective TEXT, criteria TEXT,
  population TEXT, sample_size TEXT, period_covered TEXT, evidence_source TEXT, evidence_date TEXT, auditor TEXT,
  test_procedure TEXT, result TEXT NOT NULL DEFAULT 'Not tested', risk_impact TEXT, limitations TEXT,
  status TEXT NOT NULL DEFAULT 'Planned', planned_date TEXT, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS audit_findings(
  id INTEGER PRIMARY KEY AUTOINCREMENT, ref TEXT UNIQUE, audit_id INTEGER REFERENCES audits(id) ON DELETE SET NULL,
  title TEXT NOT NULL, severity TEXT NOT NULL, description TEXT, evidence_ref TEXT, recommendation TEXT, owner TEXT,
  identified_on TEXT NOT NULL, target_days INTEGER, due_date TEXT, status TEXT NOT NULL DEFAULT 'Open', mgmt_response TEXT,
  closure_evidence TEXT, closed_on TEXT, retest_result TEXT NOT NULL DEFAULT 'Not retested', accept_rationale TEXT,
  accept_approver TEXT, accept_expiry TEXT, is_repeat INTEGER NOT NULL DEFAULT 0, created_at TEXT, updated_at TEXT);
CREATE TABLE IF NOT EXISTS audit_checklist(
  id INTEGER PRIMARY KEY AUTOINCREMENT, item TEXT NOT NULL, answer TEXT NOT NULL DEFAULT 'Unanswered', evidence TEXT);
CREATE TABLE IF NOT EXISTS audit_kpis(
  id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, target_text TEXT, review TEXT, current_text TEXT, updated_at TEXT);
"""


def now_iso():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def get_db():
    if "db" not in g:
        conn = sqlite3.connect(current_app.config["DATABASE"], timeout=30)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA foreign_keys=ON")
        g.db = conn
    return g.db


def close_db(_exc=None):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def connect_standalone(path):
    conn = sqlite3.connect(path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_schema(path):
    conn = connect_standalone(path)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.executescript(SCHEMA)
    conn.commit()
    conn.close()


def rows(sql, args=()):
    return [dict(r) for r in get_db().execute(sql, args).fetchall()]


def one(sql, args=()):
    r = get_db().execute(sql, args).fetchone()
    return dict(r) if r else None


def scalar(sql, args=()):
    r = get_db().execute(sql, args).fetchone()
    return r[0] if r else None


def run(sql, args=()):
    cur = get_db().execute(sql, args)
    get_db().commit()
    return cur


def jload(text, default):
    try:
        return json.loads(text) if text else default
    except (TypeError, ValueError):
        return default
