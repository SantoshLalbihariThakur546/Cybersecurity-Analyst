"""API tests (unittest; also runnable with pytest). Each class gets a fresh temp database."""
import hashlib
import io
import os
import sqlite3
import sys
import tempfile
import unittest
from datetime import date, datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from app import create_app  # noqa: E402

PW = "Northstar!2026"


class Base(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="northstar-test-")
        cls.app = create_app({"DATA_DIR": cls.tmp, "DATABASE": cls.tmp + "/t.db", "UPLOAD_DIR": cls.tmp + "/ev",
                              "LOGIN_RATE_PER_MIN": 10000})
        cls._sessions = {}

    def client(self, role):
        """(client, csrf-headers) signed in as a seeded demo user of that role."""
        if role not in self._sessions:
            c = self.app.test_client()
            r = c.post("/api/auth/login", json={"username": role, "password": PW})
            self.assertEqual(r.status_code, 200, r.get_json())
            self._sessions[role] = (c, {"X-CSRF-Token": r.get_json()["csrf"]})
        return self._sessions[role]

    def call(self, role, method, path, **kw):
        c, h = self.client(role)
        return getattr(c, method)(path, headers=h, **kw)


class TestAuthAndRbac(Base):
    def test_unauthenticated_and_csrf(self):
        c = self.app.test_client()
        self.assertEqual(c.get("/api/threats").status_code, 401)
        self.assertEqual(c.get("/api/dashboard").get_json()["error"]["code"], "UNAUTHENTICATED")
        cc, _ = self.client("analyst")
        r = cc.post("/api/threats", json={"name": "x"})  # no CSRF header
        self.assertEqual(r.status_code, 403)
        self.assertEqual(r.get_json()["error"]["code"], "CSRF")

    def test_login_failures_and_lockout(self):
        c = self.app.test_client()
        r = c.post("/api/auth/login", json={"username": "viewer", "password": "wrong"})
        self.assertEqual(r.status_code, 401)
        self.assertEqual(c.post("/api/auth/login", json={"username": "ghost", "password": "x"}).get_json()["error"]["message"],
                         "Invalid username or password.")
        self.assertEqual(c.post("/api/auth/login", json={}).status_code, 422)
        for _ in range(5):
            c.post("/api/auth/login", json={"username": "viewer", "password": "bad"})
        r = c.post("/api/auth/login", json={"username": "viewer", "password": PW})
        self.assertEqual(r.status_code, 423)
        # unlock for other tests in this class
        con = sqlite3.connect(self.tmp + "/t.db")
        con.execute("UPDATE users SET locked_until=NULL, failed_attempts=0 WHERE username='viewer'")
        con.commit(); con.close()

    def test_role_matrix(self):
        payload = {"name": "RBAC threat", "likelihood": 2, "impact": 2, "indicative_rating": "Medium"}
        self.assertEqual(self.call("viewer", "post", "/api/threats", json=payload).status_code, 403)
        self.assertEqual(self.call("auditor", "post", "/api/threats", json=payload).status_code, 403)
        self.assertEqual(self.call("analyst", "post", "/api/threats", json=payload).status_code, 201)
        self.assertEqual(self.call("admin", "post", "/api/threats", json=payload).status_code, 201)
        self.assertEqual(self.call("analyst", "get", "/api/users").status_code, 403)
        self.assertEqual(self.call("analyst", "get", "/api/audit-log").status_code, 403)
        self.assertEqual(self.call("auditor", "get", "/api/audit-log").status_code, 200)
        cal = {"focus": "x", "month": 1}
        self.assertEqual(self.call("analyst", "post", "/api/audits", json={"domain": "Incident response"}).status_code, 403)
        self.assertEqual(self.call("auditor", "post", "/api/audits", json={"domain": "Incident response"}).status_code, 201)
        self.assertEqual(self.call("auditor", "post", "/api/incidents", json={}).status_code, 403)

    def test_me_and_logout(self):
        c = self.app.test_client()
        r = c.post("/api/auth/login", json={"username": "auditor", "password": PW})
        self.assertIn("auditlog.read", r.get_json()["user"]["permissions"])
        self.assertNotIn("threats.write", r.get_json()["user"]["permissions"])
        h = {"X-CSRF-Token": r.get_json()["csrf"]}
        self.assertEqual(c.get("/api/auth/me").status_code, 200)
        self.assertEqual(c.post("/api/auth/logout", headers=h).status_code, 200)
        self.assertEqual(c.get("/api/auth/me").status_code, 401)

    def test_user_admin(self):
        r = self.call("admin", "post", "/api/users", json={"username": "newuser", "password": "short", "role": "analyst"})
        self.assertEqual(r.status_code, 422)
        r = self.call("admin", "post", "/api/users", json={"username": "newuser", "password": "Str0ngPass99", "role": "analyst"})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(self.call("admin", "post", "/api/users", json={"username": "newuser", "password": "Str0ngPass99", "role": "analyst"}).status_code, 409)
        me = self.call("admin", "get", "/api/auth/me").get_json()["user"]["id"]
        self.assertEqual(self.call("admin", "patch", f"/api/users/{me}", json={"active": False}).status_code, 409)
        self.assertEqual(self.call("admin", "patch", f"/api/users/{me}", json={"role": "viewer"}).status_code, 409)
        self.assertNotIn("password_hash", self.call("admin", "get", "/api/users").get_data(as_text=True))

    def test_static_and_headers(self):
        c = self.app.test_client()
        r = c.get("/health")
        self.assertEqual(r.headers["X-Content-Type-Options"], "nosniff")
        self.assertIn("script-src 'self'", r.headers["Content-Security-Policy"])
        self.assertEqual(c.get("/api/nope").status_code, 404)


class TestValidation(Base):
    def test_threat_validation(self):
        r = self.call("analyst", "post", "/api/threats", json={"name": "t", "likelihood": 5, "impact": 2, "indicative_rating": "Medium"})
        self.assertEqual(r.status_code, 422)
        fields = {d["field"] for d in r.get_json()["error"]["details"]}
        self.assertIn("likelihood", fields)
        r = self.call("analyst", "post", "/api/threats", json={"likelihood": 2, "impact": 2, "indicative_rating": "Bogus"})
        self.assertEqual({d["field"] for d in r.get_json()["error"]["details"]}, {"name", "indicative_rating"})
        r = self.call("analyst", "post", "/api/threats", json={"name": "ok", "likelihood": 2.5, "impact": 4, "indicative_rating": "High", "owner": "x"})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.get_json()["score"], 10.0)

    def test_mass_assignment_ignored_and_sort_whitelist(self):
        r = self.call("analyst", "post", "/api/threats", json={"name": "m", "likelihood": 1, "impact": 1, "indicative_rating": "Low",
                                                                "id": 9999, "created_at": "x"})
        self.assertEqual(r.status_code, 201)
        self.assertNotEqual(r.get_json()["id"], 9999)
        self.assertEqual(self.call("analyst", "get", "/api/threats?sort=name;DROP TABLE threats").status_code, 422)
        self.assertEqual(self.call("analyst", "get", "/api/threats?q=%27%20OR%201=1").get_json()["total"], 0)

    def test_search_filter_and_missing(self):
        r = self.call("viewer", "get", "/api/threats?q=ransomware").get_json()
        self.assertGreaterEqual(r["total"], 1)
        self.assertEqual(self.call("viewer", "get", "/api/threats?indicative_rating=Critical").get_json()["total"], 4)
        self.assertEqual(self.call("viewer", "get", "/api/threats/99999").status_code, 404)

    def test_seeded_reference_matches_documents(self):
        self.assertEqual(self.call("viewer", "get", "/api/threats").get_json()["total"] >= 10, True)
        self.assertEqual(self.call("viewer", "get", "/api/policy-controls").get_json()["total"], 13)
        self.assertEqual(self.call("viewer", "get", "/api/policy-risks").get_json()["total"], 10)
        self.assertEqual(self.call("viewer", "get", "/api/vuln-findings").get_json()["total"], 6)
        self.assertEqual(self.call("viewer", "get", "/api/audit-calendar").get_json()["total"], 12)
        self.assertEqual(len(self.call("viewer", "get", "/api/reference/playbooks").get_json()), 5)
        self.assertEqual(len(self.call("viewer", "get", "/api/reference/severity_model").get_json()), 4)


class TestIncidents(Base):
    def new(self, **kw):
        body = {"title": "Test incident", "category": "Ransomware / destructive malware", "severity": "SEV-3",
                "reported_at": "2026-10-21T10:00:00Z"}
        body.update(kw)
        return self.call("analyst", "post", "/api/incidents", json=body)

    def test_create_ack_targets_and_refs(self):
        r = self.new(severity="SEV-1")
        self.assertEqual(r.status_code, 201)
        d = r.get_json()
        self.assertTrue(d["ref"].startswith("IR-2026-"))
        self.assertEqual(d["ack_due"], "2026-10-21T10:15:00Z")
        self.assertTrue(d["ack_pending"])
        r2 = self.new(severity="SEV-4", reported_at="2026-10-23T10:00:00Z")  # Friday -> next business day Monday
        self.assertEqual(r2.get_json()["ack_due"], "2026-10-26T10:00:00Z")
        self.assertEqual(self.new(severity="SEV-3").get_json()["ack_due"], "2026-10-21T11:00:00Z")
        self.assertNotEqual(d["ref"], self.new().get_json()["ref"])

    def test_acknowledge_and_breach_flags(self):
        d = self.new(severity="SEV-2", reported_at="2026-01-01T10:00:00Z").get_json()
        self.assertTrue(d["ack_breached"])  # far in the past and unacknowledged
        r = self.call("analyst", "post", f"/api/incidents/{d['id']}/acknowledge")
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["ack_breached"])  # acknowledged late
        self.assertEqual(r.get_json()["status"], "Triage")
        self.assertEqual(self.call("analyst", "post", f"/api/incidents/{d['id']}/acknowledge").status_code, 409)

    def test_closure_requires_criteria(self):
        d = self.new().get_json()
        r = self.call("analyst", "patch", f"/api/incidents/{d['id']}", json={"status": "Closed"})
        self.assertEqual(r.status_code, 422)
        self.assertEqual(r.get_json()["error"]["code"], "CLOSURE_CRITERIA_NOT_MET")
        r = self.call("analyst", "patch", f"/api/incidents/{d['id']}", json={"status": "Closed", "closure_summary": "Done", "closure_checks": [0, 1, 2, 3, 4, 5, 6]})
        self.assertEqual(r.status_code, 200)
        self.assertTrue(r.get_json()["closed_at"])
        self.assertFalse(r.get_json()["is_open"])

    def test_status_stamps_and_order_validation(self):
        d = self.new().get_json()
        r = self.call("analyst", "patch", f"/api/incidents/{d['id']}", json={"status": "Contained"})
        j = r.get_json()
        self.assertTrue(j["declared_at"] and j["contained_at"])
        self.assertIsNotNone(j["metrics"]["time_to_contain_min"])
        r = self.call("analyst", "patch", f"/api/incidents/{d['id']}", json={"acknowledged_at": "2026-10-21T09:00:00Z"})
        self.assertEqual(r.status_code, 422)

    def test_cert_in_clock(self):
        recent = (datetime.now(timezone.utc) - timedelta(hours=1)).strftime("%Y-%m-%dT%H:%M:%SZ")
        d = self.new(reported_at=recent, cert_in_assessment="Required").get_json()
        self.assertTrue(d["cert_in_state"].startswith("Due in"))
        self.assertTrue(4.5 < d["cert_in_hours_left"] < 5.1)
        old = self.new(reported_at="2026-01-01T00:00:00Z", cert_in_assessment="Required").get_json()
        self.assertEqual(old["cert_in_state"], "OVERDUE")
        done = self.new(reported_at="2026-01-01T00:00:00Z", cert_in_assessment="Required", cert_in_reported_at="2026-01-01T05:00:00Z").get_json()
        self.assertEqual(done["cert_in_state"], "Reported within 6h")

    def test_checklist_validation(self):
        d = self.new().get_json()
        self.assertEqual(self.call("analyst", "patch", f"/api/incidents/{d['id']}", json={"checklist15": [0, 99]}).status_code, 422)
        r = self.call("analyst", "patch", f"/api/incidents/{d['id']}", json={"checklist15": [3, 1, 1]})
        self.assertEqual(r.get_json()["checklist15"], [1, 3])
        self.assertEqual(r.get_json()["checklist15_done"], 2)

    def test_timeline_decisions_actions(self):
        d = self.new().get_json()
        iid = d["id"]
        r = self.call("analyst", "post", "/api/incident-timeline", json={"incident_id": iid, "event_time": "2026-10-21T10:05", "event": "Alert fired", "confidence": "High"})
        self.assertEqual(r.status_code, 201)
        self.assertEqual(r.get_json()["event_time"], "2026-10-21T10:05:00Z")
        self.assertEqual(self.call("analyst", "post", "/api/incident-timeline", json={"incident_id": 99999, "event_time": "2026-10-21T10:05", "event": "x"}).status_code, 422)
        self.assertEqual(self.call("analyst", "get", f"/api/incident-timeline?incident_id={iid}").get_json()["total"], 1)
        a = self.call("analyst", "post", "/api/incident-actions", json={"incident_id": iid, "title": "Fix", "priority": "High"}).get_json()
        r = self.call("analyst", "patch", f"/api/incident-actions/{a['id']}", json={"status": "Closed"})
        self.assertEqual(r.status_code, 422)
        r = self.call("analyst", "patch", f"/api/incident-actions/{a['id']}", json={"status": "Closed", "evidence": "Retest passed"})
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.call("analyst", "post", "/api/incident-decisions", json={"incident_id": iid, "decided_at": "2026-10-21T10:10:00Z", "decision": "Isolate host"}).status_code, 201)

    def test_evidence_hash_and_download(self):
        iid = self.new().get_json()["id"]
        content = b"suspicious-email-headers"
        digest = hashlib.sha256(content).hexdigest()
        r = self.call("analyst", "post", "/api/incident-evidence", data={"incident_id": str(iid), "description": "Original email", "file": (io.BytesIO(content), "mail.eml")},
                      content_type="multipart/form-data")
        self.assertEqual(r.status_code, 201, r.get_json())
        ev = r.get_json()
        self.assertEqual(ev["sha256"], digest)
        self.assertEqual(ev["evid"], "EV-001")
        self.assertNotIn("stored_name", ev)
        dl = self.call("viewer", "get", f"/api/incident-evidence/{ev['id']}/download")
        self.assertEqual(dl.data, content)
        dl.close()
        self.assertTrue(self.call("viewer", "post", f"/api/incident-evidence/{ev['id']}/verify").get_json()["intact"])
        bad = self.call("analyst", "post", "/api/incident-evidence", data={"incident_id": str(iid), "description": "x", "sha256": "0" * 64, "file": (io.BytesIO(b"abc"), "a.txt")},
                        content_type="multipart/form-data")
        self.assertEqual(bad.status_code, 422)
        self.assertEqual(bad.get_json()["error"]["code"], "HASH_MISMATCH")
        manual = self.call("analyst", "post", "/api/incident-evidence", json={"incident_id": iid, "description": "Hash only", "sha256": digest})
        self.assertEqual(manual.get_json()["evid"], "EV-002")
        self.assertEqual(self.call("analyst", "post", "/api/incident-evidence", json={"incident_id": iid, "description": "bad", "sha256": "xyz"}).status_code, 422)
        # tampering with the stored file is detected
        stored = [f for f in os.listdir(self.tmp + "/ev")]
        with open(os.path.join(self.tmp, "ev", stored[0]), "ab") as fh:
            fh.write(b"tampered")
        self.assertFalse(self.call("viewer", "post", f"/api/incident-evidence/{ev['id']}/verify").get_json()["intact"])
        self.assertEqual(self.call("viewer", "delete", f"/api/incident-evidence/{ev['id']}").status_code, 403)
        self.assertEqual(self.call("analyst", "delete", f"/api/incident-evidence/{ev['id']}").status_code, 200)

    def test_summary_and_report(self):
        s = self.call("viewer", "get", "/api/incidents-summary").get_json()
        self.assertGreaterEqual(s["total"], 1)
        self.assertIn("SEV-1", s["open_by_severity"])
        r = self.call("viewer", "get", "/api/incidents/1/report")
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        self.assertIn("Post-incident report", html)
        self.assertIn("Illustrative demo incident", html)
        self.assertEqual(r.headers["Content-Security-Policy"], "default-src 'none'; style-src 'unsafe-inline'")


class TestPolicy(Base):
    def test_risk_scoring_bands(self):
        self.assertEqual(self.call("viewer", "get", "/api/policy-risks?ref=R1").get_json()["items"][0]["score"], 20)
        cases = {(5, 5): ("Critical", 25), (4, 3): ("High", 12), (2, 3): ("Medium", 6), (1, 5): ("Low", 5)}
        for (l, i), (band, score) in cases.items():
            r = self.call("analyst", "post", "/api/policy-risks", json={"title": f"t{l}{i}", "likelihood": l, "impact": i}).get_json()
            self.assertEqual((r["band"], r["score"]), (band, score))
        r = self.call("analyst", "post", "/api/policy-risks", json={"title": "t", "likelihood": 6, "impact": 1})
        self.assertEqual(r.status_code, 422)
        rid = self.call("analyst", "get", "/api/policy-risks?sort=-id").get_json()["items"][0]["id"]
        r = self.call("analyst", "patch", f"/api/policy-risks/{rid}", json={"impact": 5})
        self.assertEqual(r.get_json()["score"], r.get_json()["likelihood"] * 5)

    def test_duplicate_ref_conflict(self):
        r = self.call("analyst", "post", "/api/policy-risks", json={"ref": "R1", "title": "dup", "likelihood": 1, "impact": 1})
        self.assertEqual(r.status_code, 409)

    def test_exception_rules(self):
        base = {"requester": "IT", "control": "MFA for legacy VPN"}
        r = self.call("analyst", "post", "/api/policy-exceptions", json={**base, "status": "Approved"})
        self.assertEqual(r.status_code, 422)
        self.assertEqual({d["field"] for d in r.get_json()["error"]["details"]}, {"approver", "approved_on", "expiry_date"})
        ok = self.call("analyst", "post", "/api/policy-exceptions", json={**base, "status": "Approved", "approver": "CISO", "approved_on": "2026-01-01", "expiry_date": "2026-02-01"})
        self.assertEqual(ok.status_code, 201)
        j = ok.get_json()
        self.assertTrue(j["ref"].startswith("EX-"))
        self.assertTrue(j["expired"])
        self.assertEqual(j["effective_status"], "Expired")
        r = self.call("analyst", "patch", f"/api/policy-exceptions/{j['id']}", json={"status": "Closed"})
        self.assertEqual(r.status_code, 422)
        r = self.call("analyst", "patch", f"/api/policy-exceptions/{j['id']}", json={"status": "Closed", "closure_evidence": "Control now enforced"})
        self.assertEqual(r.status_code, 200)
        bad = self.call("analyst", "post", "/api/policy-exceptions", json={**base, "status": "Approved", "approver": "x", "approved_on": "2026-05-01", "expiry_date": "2026-04-01"})
        self.assertEqual(bad.status_code, 422)

    def test_metrics_state_and_summary(self):
        mid = self.call("analyst", "get", "/api/policy-metrics?q=MFA").get_json()["items"][0]
        self.assertEqual(mid["state"], "No data")
        self.assertEqual(self.call("analyst", "patch", f"/api/policy-metrics/{mid['id']}", json={"current_value": 80}).get_json()["state"], "Below target")
        self.assertEqual(self.call("analyst", "patch", f"/api/policy-metrics/{mid['id']}", json={"current_value": 100}).get_json()["state"], "Target met")
        lower = self.call("analyst", "get", "/api/policy-metrics?q=Overdue").get_json()["items"][0]
        self.assertEqual(self.call("analyst", "patch", f"/api/policy-metrics/{lower['id']}", json={"current_value": 2}).get_json()["state"], "Above target")
        s = self.call("viewer", "get", "/api/policy-summary").get_json()
        self.assertEqual(s["ratings"]["Weak"], 6)  # Governance, IAM, Data, Vulnerability, Logging, Incident response
        self.assertEqual(s["risk_bands"]["Critical"], self.call("viewer", "get", "/api/policy-risks?band=Critical").get_json()["total"])
        self.assertGreaterEqual(s["risk_bands"]["Critical"], 3)  # R1-R3 (score 20)
        self.assertEqual(s["actions_total"], 21)

    def test_checklist_and_actions(self):
        cid = self.call("analyst", "get", "/api/policy-checklist").get_json()["items"][0]["id"]
        self.assertEqual(self.call("analyst", "patch", f"/api/policy-checklist/{cid}", json={"answer": "Maybe"}).status_code, 422)
        self.assertEqual(self.call("analyst", "patch", f"/api/policy-checklist/{cid}", json={"answer": "Yes", "evidence": "Policy v2"}).status_code, 200)
        aid = self.call("analyst", "get", "/api/policy-actions").get_json()["items"][0]["id"]
        r = self.call("analyst", "patch", f"/api/policy-actions/{aid}", json={"status": "In progress", "due_date": "2020-01-01"})
        self.assertTrue(r.get_json()["overdue"])


class TestAwareness(Base):
    def test_quiz_never_leaks_answers_and_scores(self):
        q = self.call("viewer", "get", "/api/quiz").get_json()["questions"]
        self.assertEqual(len(q), 5)
        self.assertNotIn("correct_index", q[0])
        self.assertEqual(self.call("viewer", "get", "/api/quiz-questions").status_code, 403)
        self.assertEqual(self.call("analyst", "get", "/api/quiz-questions").status_code, 200)
        key = {1: 1, 2: 2, 3: 0, 4: 1, 5: 2}
        ids = [x["id"] for x in q]
        r = self.call("viewer", "post", "/api/quiz/submit", json={"phase": "post", "answers": {str(i): key[n + 1] for n, i in enumerate(ids)}})
        self.assertEqual(r.get_json()["score"], 5)
        wrong = {str(i): 9 for i in ids}
        self.assertEqual(self.call("viewer", "post", "/api/quiz/submit", json={"phase": "post", "answers": wrong}).status_code, 422)
        partial = {str(ids[0]): 0}
        self.assertEqual(self.call("viewer", "post", "/api/quiz/submit", json={"phase": "baseline", "answers": partial}).status_code, 422)
        self.assertEqual(self.call("viewer", "post", "/api/quiz/submit", json={"phase": "bogus", "answers": {}}).status_code, 422)

    def test_summary_metrics_improvement(self):
        s = self.call("viewer", "get", "/api/awareness-summary").get_json()
        by = {m["name"]: m for m in s["metrics"]}
        self.assertEqual(by["Reach"]["current"], 92.8)
        self.assertEqual(by["Training completion"]["current"], 85.6)
        self.assertTrue(by["Training completion"]["met"])
        self.assertEqual(s["quiz"]["improvement_pp"], round(s["quiz"]["post_pct"] - s["quiz"]["baseline_pct"], 1))
        self.assertTrue(by["Knowledge improvement"]["met"])  # seeded demo: well above the 20 pp target
        self.assertEqual(s["simulation_trend"]["click_rate_change_pp"], -12.4)
        self.assertEqual(s["simulations"]["baseline"]["click_rate"], 20.8)

    def test_feedback_and_simulation_rules(self):
        self.assertEqual(self.call("viewer", "post", "/api/feedback", json={"relevance": 5, "confidence": 4, "knows_reporting": True}).status_code, 201)
        self.assertEqual(self.call("viewer", "post", "/api/feedback", json={"relevance": 7, "confidence": 4, "knows_reporting": True}).status_code, 422)
        self.assertEqual(self.call("analyst", "post", "/api/simulations", json={"phase": "baseline", "sent": 10, "clicked": 11, "reported": 1}).status_code, 422)
        self.assertEqual(self.call("viewer", "post", "/api/simulations", json={"phase": "baseline", "sent": 10, "clicked": 1, "reported": 1}).status_code, 403)

    def test_campaign_counts(self):
        r = self.call("analyst", "patch", "/api/campaigns/1", json={"reached_count": 999})
        self.assertEqual(r.status_code, 422)
        r = self.call("analyst", "patch", "/api/campaigns/1", json={"reached_count": 200, "completed_count": 210})
        self.assertEqual(r.status_code, 422)
        self.assertEqual(self.call("analyst", "patch", "/api/campaigns/1", json={"reached_count": 240, "completed_count": 230}).status_code, 200)
        # restore the seeded demo values so other tests are order-independent
        self.call("analyst", "patch", "/api/campaigns/1", json={"reached_count": 232, "completed_count": 214})


class TestVulns(Base):
    def test_sla_due_dates_seeded(self):
        items = {f["ref"]: f for f in self.call("viewer", "get", "/api/vuln-findings").get_json()["items"]}
        self.assertEqual(items["VA-02"]["due_date"], "2026-10-27")
        self.assertEqual(items["VA-01"]["due_date"], "2026-11-03")
        self.assertEqual(items["VA-04"]["due_date"], "2026-11-19")
        self.assertEqual(items["VA-02"]["severity"], "Critical")

    def test_create_defaults_and_sla_endpoint(self):
        r = self.call("analyst", "post", "/api/vuln-findings", json={"title": "New", "severity": "High", "identified_on": "2026-11-01"}).get_json()
        self.assertEqual((r["target_days"], r["due_date"]), (14, "2026-11-15"))
        r = self.call("analyst", "post", "/api/vuln-findings", json={"title": "Exploited", "severity": "Medium", "identified_on": "2026-11-01", "actively_exploited": True}).get_json()
        self.assertEqual(r["target_days"], 3)
        s = self.call("viewer", "get", "/api/sla?severity=Critical&identified_on=2026-12-01").get_json()
        self.assertEqual((s["target_days"], s["due_date"]), (7, "2026-12-08"))
        self.assertEqual(self.call("viewer", "get", "/api/sla?severity=Nope").status_code, 422)
        self.assertEqual(self.call("viewer", "get", "/api/sla?severity=Low&identified_on=bad").status_code, 422)
        up = self.call("analyst", "patch", f"/api/vuln-findings/{r['id']}", json={"severity": "Low", "actively_exploited": False}).get_json()
        self.assertEqual(up["target_days"], 90)

    def test_closure_and_acceptance_rules(self):
        r = self.call("analyst", "patch", "/api/vuln-findings/1", json={"status": "Closed"})
        self.assertEqual(r.status_code, 422)
        self.assertEqual(r.get_json()["error"]["details"][0]["field"], "closure_evidence")
        ok = self.call("analyst", "patch", "/api/vuln-findings/1", json={"status": "Closed", "closure_evidence": "Follow-up scan 2026-10-30 clean"})
        self.assertEqual(ok.status_code, 200)
        self.assertTrue(ok.get_json()["closed_on"])
        reopened = self.call("analyst", "patch", "/api/vuln-findings/1", json={"status": "In Progress"}).get_json()
        self.assertIsNone(reopened["closed_on"])
        r = self.call("analyst", "patch", "/api/vuln-findings/2", json={"status": "Risk Accepted"})
        self.assertEqual({d["field"] for d in r.get_json()["error"]["details"]}, {"accept_rationale", "accept_approver", "accept_expiry"})
        ok = self.call("analyst", "patch", "/api/vuln-findings/2", json={"status": "Risk Accepted", "accept_rationale": "Compensating control in place",
                                                                         "accept_approver": "CISO", "accept_expiry": (date.today() + timedelta(days=30)).isoformat()})
        self.assertEqual(ok.status_code, 200)
        past = self.call("analyst", "patch", "/api/vuln-findings/3", json={"status": "Risk Accepted", "accept_rationale": "x", "accept_approver": "y", "accept_expiry": "2020-01-01"})
        self.assertEqual(past.status_code, 422)

    def test_overdue_and_summary(self):
        r = self.call("analyst", "post", "/api/vuln-findings", json={"title": "Old one", "severity": "Critical", "identified_on": "2020-01-01"}).get_json()
        self.assertTrue(r["overdue"])
        self.assertLess(r["days_remaining"], 0)
        s = self.call("viewer", "get", "/api/vuln-summary").get_json()
        self.assertGreaterEqual(s["overdue"], 1)
        self.assertEqual(s["assets"]["total"], self.call("viewer", "get", "/api/assets").get_json()["total"])
        att = self.call("viewer", "get", "/api/dashboard").get_json()["attention"]
        self.assertTrue(any("Old one" in a["label"] for a in att))
        self.assertEqual(att[0]["severity"], "Critical")

    def test_asset_link_and_delete(self):
        r = self.call("analyst", "post", "/api/vuln-findings", json={"title": "Linked", "severity": "Low", "asset_id": 3}).get_json()
        self.assertEqual(r["asset_name"], "Remote-access gateway")
        self.assertEqual(self.call("analyst", "delete", "/api/assets/3").status_code, 200)  # FK SET NULL, no crash
        self.assertIsNone(self.call("analyst", "get", f"/api/vuln-findings/{r['id']}").get_json()["asset_name"])


class TestAudit(Base):
    def test_finding_due_dates_and_observation(self):
        sev = {"Critical": 7, "High": 30, "Medium": 60, "Low": 180}
        for s, days in sev.items():
            r = self.call("auditor", "post", "/api/audit-findings", json={"title": s, "severity": s, "identified_on": "2026-03-01"}).get_json()
            self.assertEqual(r["target_days"], days)
            self.assertEqual(r["due_date"], (date(2026, 3, 1) + timedelta(days=days)).isoformat())
        o = self.call("auditor", "post", "/api/audit-findings", json={"title": "obs", "severity": "Observation"}).get_json()
        self.assertIsNone(o["due_date"])

    def test_critical_high_need_retest_to_close(self):
        f = self.call("auditor", "post", "/api/audit-findings", json={"title": "Crit", "severity": "Critical", "identified_on": "2026-03-01"}).get_json()
        r = self.call("auditor", "patch", f"/api/audit-findings/{f['id']}", json={"status": "Closed", "closure_evidence": "Config export"})
        self.assertEqual(r.status_code, 422)
        self.assertEqual([d["field"] for d in r.get_json()["error"]["details"]], ["retest_result"])
        ok = self.call("auditor", "patch", f"/api/audit-findings/{f['id']}", json={"status": "Closed", "closure_evidence": "Config export", "retest_result": "Pass"})
        self.assertEqual(ok.status_code, 200)
        m = self.call("auditor", "post", "/api/audit-findings", json={"title": "Med", "severity": "Medium", "identified_on": "2026-03-01"}).get_json()
        self.assertEqual(self.call("auditor", "patch", f"/api/audit-findings/{m['id']}", json={"status": "Closed", "closure_evidence": "Ticket 42"}).status_code, 200)

    def test_escalation_flag(self):
        f = self.call("auditor", "post", "/api/audit-findings", json={"title": "Late", "severity": "High", "identified_on": "2020-01-01"}).get_json()
        self.assertTrue(f["overdue"] and f["escalation"])
        self.assertGreaterEqual(self.call("viewer", "get", "/api/audit-summary").get_json()["overdue_critical_high"], 1)

    def test_calendar_and_workpaper_rules(self):
        r = self.call("auditor", "patch", "/api/audit-calendar/3", json={"status": "Rescheduled"})
        self.assertEqual(r.status_code, 422)
        self.assertEqual(self.call("auditor", "patch", "/api/audit-calendar/3", json={"status": "Rescheduled", "reschedule_rationale": "Auditor unavailable"}).status_code, 200)
        done = self.call("auditor", "patch", "/api/audit-calendar/2", json={"status": "Completed"}).get_json()
        self.assertEqual(done["completed_on"], date.today().isoformat())
        s = self.call("viewer", "get", "/api/audit-summary").get_json()
        self.assertAlmostEqual(s["plan_completion_pct"], round(100 * 2 / 12, 1))
        a = self.call("auditor", "post", "/api/audits", json={"domain": "Backup and continuity", "status": "Completed"})
        self.assertEqual(a.status_code, 422)
        self.assertEqual(a.get_json()["error"]["code"], "WORKPAPER_INCOMPLETE")
        full = {"domain": "Backup and continuity", "status": "Completed", "criteria": "Policy 7.9", "population": "All critical backups", "evidence_source": "Backup console export",
                "evidence_date": "2026-09-01", "auditor": "A. Auditor", "test_procedure": "Inspect permissions and restore test", "result": "Pass"}
        self.assertEqual(self.call("auditor", "post", "/api/audits", json=full).status_code, 201)
        self.assertEqual(len(self.call("viewer", "get", "/api/reference/workpaper_template").get_json()), 9)

    def test_evidence_quality_metric(self):
        s = self.call("viewer", "get", "/api/audit-summary").get_json()
        self.assertIsNotNone(s["evidence_quality_pct"])
        self.assertIn("Critical", s["median_days_to_close"])


class TestReportsAndAudit(Base):
    def test_executive_report_and_exports(self):
        r = self.call("viewer", "get", "/api/reports/executive")
        self.assertEqual(r.status_code, 200)
        html = r.get_data(as_text=True)
        for needle in ("Executive Summary", "Week 1", "Week 6", "Northstar Services Ltd."):
            self.assertIn(needle, html)
        self.call("analyst", "post", "/api/threats", json={"name": "=HYPERLINK(\"http://evil\")", "likelihood": 1, "impact": 1, "indicative_rating": "Low"})
        csv_text = self.call("viewer", "get", "/api/export/threats.csv").get_data(as_text=True)
        self.assertIn("'=HYPERLINK", csv_text)
        self.assertNotIn(",=HYPERLINK", csv_text)
        self.assertEqual(self.call("viewer", "get", "/api/export/users.csv").status_code, 404)

    def test_html_escaping_in_reports(self):
        self.call("analyst", "post", "/api/threats", json={"name": "<script>alert(1)</script>", "likelihood": 4, "impact": 4, "indicative_rating": "Critical"})
        html = self.call("viewer", "get", "/api/reports/executive").get_data(as_text=True)
        self.assertNotIn("<script>alert(1)</script>", html)

    def test_audit_chain_and_tamper_detection(self):
        self.call("analyst", "post", "/api/threats", json={"name": "chain", "likelihood": 1, "impact": 1, "indicative_rating": "Low"})
        self.assertEqual(self.call("viewer", "post", "/api/threats", json={"name": "denied"}).status_code, 403)
        v = self.call("auditor", "get", "/api/audit-log/verify").get_json()
        self.assertTrue(v["valid"])
        self.assertGreaterEqual(v["entries_checked"], 3)
        actions = {i["action"] for i in self.call("auditor", "get", "/api/audit-log?limit=200").get_json()["items"]}
        for a in ("LOGIN", "CREATE", "AUTHZ_DENIED"):
            self.assertIn(a, actions)
        con = sqlite3.connect(self.tmp + "/t.db")
        con.execute("UPDATE audit_log SET actor='mallory' WHERE id=2")
        con.commit(); con.close()
        v = self.call("auditor", "get", "/api/audit-log/verify").get_json()
        self.assertFalse(v["valid"])
        self.assertEqual(v["first_invalid_id"], 2)

    def test_dashboard_shape(self):
        d = self.call("viewer", "get", "/api/dashboard").get_json()
        for k in ("threats", "incidents", "policy", "awareness", "vulns", "audit", "attention", "organization"):
            self.assertIn(k, d)
        self.assertEqual(len(d["threats"]["points"]), d["threats"]["total"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
