"""Browser tests (Playwright + headless Chromium) against a live in-process server.
Run:  pip install playwright && playwright install chromium && python -m unittest tests.test_ui
Skipped automatically when Playwright or a browser is not available."""
import os
import sys
import tempfile
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
try:
    from playwright.sync_api import sync_playwright
    HAVE = True
except ImportError:  # pragma: no cover
    HAVE = False

from werkzeug.serving import make_server  # noqa: E402
from app import create_app  # noqa: E402

PW = "Northstar!2026"
PORT = 5077
URL = f"http://127.0.0.1:{PORT}"


@unittest.skipUnless(HAVE, "playwright not installed")
class TestUI(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp(prefix="northstar-ui-")
        app = create_app({"DATA_DIR": cls.tmp, "DATABASE": cls.tmp + "/t.db", "UPLOAD_DIR": cls.tmp + "/ev", "LOGIN_RATE_PER_MIN": 10000})
        cls.srv = make_server("127.0.0.1", PORT, app, threaded=True)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.pw = sync_playwright().start()
        try:
            cls.browser = cls.pw.chromium.launch()
        except Exception as exc:  # no browser installed
            cls.pw.stop()
            cls.srv.shutdown()
            raise unittest.SkipTest(f"Chromium unavailable: {exc}")

    @classmethod
    def tearDownClass(cls):
        cls.browser.close(); cls.pw.stop(); cls.srv.shutdown()

    def page(self, user=None):
        ctx = self.browser.new_context(viewport={"width": 1440, "height": 900})
        pg = ctx.new_page()
        pg.problems = []
        pg.on("console", lambda m: pg.problems.append(m.text) if m.type in ("error", "warning") and "status of 4" not in m.text else None)
        pg.on("pageerror", lambda e: pg.problems.append(str(e)))
        pg.goto(URL + "/")
        pg.wait_for_selector("#login-form")
        if user:
            pg.fill("[name=username]", user); pg.fill("[name=password]", PW); pg.click("button[type=submit]")
            pg.wait_for_selector("#nav a")
        return pg

    def go(self, pg, route, wait=".page-head"):
        pg.goto(f"{URL}/#/{route}")
        pg.wait_for_selector(wait)
        pg.wait_for_timeout(250)

    def test_login_errors_and_logout(self):
        pg = self.page()
        pg.fill("[name=username]", "admin"); pg.fill("[name=password]", "wrong"); pg.click("button[type=submit]")
        pg.wait_for_selector("#login-error:not(:empty)")
        self.assertIn("Invalid username or password", pg.inner_text("#login-error"))
        pg.fill("[name=password]", PW); pg.click("button[type=submit]")
        pg.wait_for_selector("#nav a")
        self.assertIn("Priya Sharma", pg.inner_text("#whoami"))
        pg.click("#logout")
        pg.wait_for_selector("#login-form")
        pg.reload(); pg.wait_for_selector("#login-form")  # session really ended
        self.assertFalse([p for p in pg.problems if "Content Security" in p or "TypeError" in p or "ReferenceError" in p], pg.problems)

    def test_every_page_renders_without_errors(self):
        pg = self.page("admin")
        for route in ("overview", "threats", "incidents", "policy", "awareness", "vulns", "audits", "reports", "auditlog", "users"):
            self.go(pg, route)
            self.assertNotIn("Something went wrong", pg.inner_text("#main"), route)
            self.assertNotIn("Page not available", pg.inner_text("#main"), route)
        # every tab on the tabbed pages
        for route in ("threats", "incidents", "policy", "awareness", "vulns", "audits"):
            self.go(pg, route)
            for i in range(pg.locator(".tabs button").count()):
                pg.locator(".tabs button").nth(i).click()
                pg.wait_for_timeout(250)
                self.assertNotIn("Something went wrong", pg.inner_text("#main"))
                self.assertEqual(pg.locator(".tab-pane .note.bad").count(), 0, f"{route} tab {i}")
        self.assertEqual(pg.problems, [])

    def test_overview_content(self):
        pg = self.page("viewer")
        self.go(pg, "overview")
        text = pg.inner_text("#main")
        for needle in ("Needs attention", "Threat scenario map", "Policy risk matrix", "Awareness objectives", "Vulnerability assessment"):
            self.assertIn(needle, text)
        self.assertEqual(pg.locator(".stream").count(), 6)
        self.assertEqual(pg.locator("#nav a").count(), 8)  # viewer: overview, 6 workstreams, reports
        self.assertEqual(pg.problems, [])

    def test_viewer_is_read_only(self):
        pg = self.page("viewer")
        self.go(pg, "threats")
        self.assertEqual(pg.locator("[data-add]").count(), 0)
        pg.locator("tr.clickable").first.click()
        pg.wait_for_selector(".modal")
        self.assertTrue(pg.locator(".modal input[name=name]").is_disabled())
        self.assertEqual(pg.locator(".modal-foot button", has_text="Save changes").count(), 0)
        pg.keyboard.press("Escape")
        self.go(pg, "users", ".panel")
        self.assertIn("Page not available", pg.inner_text("#main"))

    def test_create_threat_with_validation(self):
        pg = self.page("analyst")
        self.go(pg, "threats")
        pg.click("[data-add]"); pg.wait_for_selector(".modal")
        pg.click(".modal-foot button.primary")
        pg.wait_for_selector(".modal .field-error:not(:empty)")
        self.assertIn("required", pg.locator("[data-err=name]").inner_text())
        pg.fill(".modal input[name=name]", "UI-created scenario")
        pg.select_option(".modal select[name=likelihood]", "3"); pg.select_option(".modal select[name=impact]", "4")
        pg.select_option(".modal select[name=indicative_rating]", "Critical")
        pg.click(".modal-foot button.primary")
        pg.wait_for_selector(".modal", state="detached")
        pg.fill("[data-q]", "UI-created"); pg.wait_for_timeout(600)
        self.assertIn("UI-created scenario", pg.inner_text("[data-table]"))
        self.assertEqual(pg.problems, [])

    def test_incident_lifecycle(self):
        pg = self.page("analyst")
        self.go(pg, "incidents")
        pg.click("[data-new]"); pg.wait_for_selector(".modal")
        pg.fill(".modal input[name=title]", "UI test ransomware")
        pg.select_option(".modal select[name=category]", "Ransomware / destructive malware")
        pg.select_option(".modal select[name=severity]", "SEV-1")
        pg.select_option(".modal select[name=cert_in_assessment]", "Required")
        pg.click(".modal-foot button.primary")
        pg.wait_for_selector(".modal", state="detached")
        pg.wait_for_selector("tr.clickable")
        pg.locator("tr.clickable", has_text="UI test ransomware").click()
        pg.wait_for_selector("[data-ack]")
        self.assertIn("CERT-In", pg.inner_text("#main"))
        pg.click("[data-ack]")
        pg.wait_for_selector("[data-ack]", state="detached")
        # closing without criteria is refused with a clear message
        pg.select_option("[data-status]", "Closed")
        pg.wait_for_selector(".modal")
        pg.click(".modal-foot button.primary")
        pg.wait_for_selector(".modal [data-err]:not(:empty)")
        self.assertIn("closure criteria", pg.locator(".modal [data-err]").inner_text().lower())
        for cb in pg.locator(".modal [data-c]").all():
            cb.check()
        pg.fill(".modal [data-sum]", "Contained, recovered and reviewed.")
        pg.click(".modal-foot button.primary")
        pg.wait_for_selector(".modal", state="detached")
        pg.wait_for_selector(".chip:text-is('Closed')")
        # evidence upload with a real file
        pg.locator(".tabs button", has_text="Evidence").click()
        pg.click("[data-add]"); pg.wait_for_selector(".modal")
        pg.fill(".modal textarea[name=description]", "Mail headers")
        path = os.path.join(self.tmp, "headers.txt")
        with open(path, "w") as fh:
            fh.write("Received: from example")
        pg.set_input_files(".modal input[name=file]", path)
        pg.click(".modal-foot button.primary")
        pg.wait_for_selector(".modal", state="detached")
        pg.wait_for_selector(".hash")
        self.assertEqual(len(pg.locator(".hash").first.inner_text()), 64)
        self.assertEqual(pg.problems, [])

    def test_vulnerability_closure_needs_evidence(self):
        pg = self.page("analyst")
        self.go(pg, "vulns")
        pg.locator("tr.clickable", has_text="VA-06").click()
        pg.wait_for_selector(".modal")
        pg.select_option(".modal select[name=status]", "Closed")
        pg.click(".modal-foot button.primary")
        pg.wait_for_selector("[data-err=closure_evidence]:not(:empty)")
        self.assertIn("required", pg.locator("[data-err=closure_evidence]").inner_text())
        pg.fill(".modal textarea[name=closure_evidence]", "Follow-up scan clean")
        pg.click(".modal-foot button.primary")
        pg.wait_for_selector(".modal", state="detached")
        pg.wait_for_selector("tr:has-text('VA-06') .chip:text-is('Closed')")  # list refreshes after the save
        self.assertIn("Closed", pg.locator("tr", has_text="VA-06").inner_text())

    def test_quiz_flow_is_anonymous_and_scored(self):
        pg = self.page("viewer")
        self.go(pg, "awareness")
        pg.locator(".tabs button", has_text="Take the knowledge check").click()
        pg.wait_for_selector("[data-quiz]")
        for q, a in ((1, 1), (2, 2), (3, 0), (4, 1), (5, 2)):
            pg.locator(".q").nth(q - 1).locator("input[type=radio]").nth(a).check()
        pg.click("[data-quiz] button[type=submit]")
        pg.wait_for_selector(".q.right")
        self.assertEqual(pg.locator(".q.right").count(), 5)
        self.assertIn("5/5", pg.locator("#toast").inner_text())

    def test_audit_log_verify_and_report_buttons(self):
        pg = self.page("auditor")
        self.go(pg, "auditlog")
        pg.click("[data-verify]")
        pg.wait_for_selector("[data-result] .chip:has-text('Chain valid')")
        self.go(pg, "audits")
        self.assertIn("Annual calendar", pg.inner_text("#main"))
        self.assertEqual(pg.locator(".cal-m").count(), 12)

    def test_keyboard_modal_escape_and_responsive_menu(self):
        pg = self.page("analyst")
        self.go(pg, "threats")
        pg.click("[data-add]"); pg.wait_for_selector(".modal")
        pg.keyboard.press("Escape")
        pg.wait_for_selector(".modal", state="detached")
        pg.set_viewport_size({"width": 600, "height": 800})
        self.assertTrue(pg.locator(".menu-btn").is_visible())
        pg.click(".menu-btn")
        self.assertIn("open", pg.locator(".rail").get_attribute("class"))


if __name__ == "__main__":
    unittest.main(verbosity=2)
