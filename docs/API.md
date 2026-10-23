# API reference

All endpoints are under `/api`, return JSON, and need a signed-in session (cookie) unless noted. State-changing requests (`POST`, `PUT`, `PATCH`, `DELETE`) must send the header `X-CSRF-Token: <csrf>` returned by `POST /api/auth/login` (or `GET /api/auth/session`). Errors always look like
`{"error": {"code": "...", "message": "...", "details": [{"field": "...", "message": "..."}]}}`  (401 sign in, 403 role/CSRF, 404, 409 conflict, 422 validation, 423 locked, 429 rate limit).

List endpoints accept `q` (search), `sort` (`field` or `-field`, whitelisted) and the filters shown in the UI.

| Area | Endpoints | Write permission |
|---|---|---|
| Auth | `POST /auth/login`, `POST /auth/logout`, `GET /auth/me`, `GET /auth/session` (always 200) | - |
| Overview | `GET /dashboard`, `GET /reference/<set>` | - |
| Week 1 | `/threats`, `/threat-categories`, `/threat-actors`, `/intel-sources`, `/research-log` (CRUD) | `threats.write` |
| Week 2 | `/incidents` (CRUD without delete), `POST /incidents/<id>/acknowledge`, `/incident-timeline`, `/incident-decisions`, `/incident-actions`, `/incident-evidence` (+ `/download`, `POST /<id>/verify`), `GET /incidents-summary`, `GET /incidents/<id>/report` | `incidents.write` |
| Week 3 | `/policy-controls`, `/policy-risks`, `/policy-actions`, `/policy-exceptions`, `/policy-metrics`, `/policy-checklist`, `/evidence-requests`, `/policy-statements`, `GET /policy-summary` | `policy.write` |
| Week 4 | `/campaigns`, `/campaign-tasks`, `/campaign-segments`, `/campaign-topics`, `/campaign-channels`, `/simulations`, `/quiz-questions` (answer key: staff only), `GET /quiz`, `POST /quiz/submit`, `POST /feedback`, `GET /awareness-summary` | `awareness.write` (quiz and feedback: any signed-in user) |
| Week 5 | `/assets`, `/vuln-findings`, `/vuln-roadmap`, `/vuln-metrics`, `GET /sla`, `GET /vuln-summary` | `vulns.write` |
| Week 6 | `/audit-calendar`, `/audits`, `/audit-findings`, `/audit-checklist`, `/audit-kpis`, `GET /audit-summary` | `auditplan.write` |
| Reports | `GET /reports/executive` (HTML), `GET /export/<name>.csv` | - |
| Platform | `GET /audit-log`, `GET /audit-log/verify` (`auditlog.read`); `/users` (`users.manage`) | |

## Business rules enforced by the server

* **Incidents:** acknowledgement targets by severity (15 min / 15 min / 1 h / next business day); six-hour CERT-In clock when assessed "Required"; status timestamps auto-filled; **closing needs all 7 closure criteria plus a summary**; timestamp order validated; evidence hashed with SHA-256 and re-verifiable.
* **Policy risks:** score = likelihood x impact (1-5); band 20-25 Critical, 12-19 High, 6-11 Medium, 1-5 Low. **Exceptions:** approval needs approver, approval date and expiry; closing needs evidence; expired approvals are flagged.
* **Vulnerability findings:** due date = identified date + target days (exploited 3, Critical 7, High 14, Medium 30, Low 90 by default); **closing needs verification evidence**; risk acceptance needs rationale, approver and a future expiry.
* **Audit findings:** targets Critical 7 / High 30 / Medium 60 / Low 180 days / Observation none; **Critical and High need a passed retest to close**; overdue Critical/High are flagged for escalation; completed audits need a complete workpaper; a reschedule needs a rationale.
* **Awareness:** quiz answers are checked on the server and stored without identity; simulation counts cannot exceed messages sent.
