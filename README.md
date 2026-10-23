# Northstar - Cybersecurity Program Platform

One working application that turns your six weekly deliverables into a connected, usable security program:

| Week | Deliverable | Module in the dashboard |
|---|---|---|
| 1 | Threat Landscape Analysis | **Threat landscape** - scored scenario register with map, actors, categories, attack chain, priorities, sources, research log |
| 2 | Cybersecurity Incident Response Plan | **Incident response** - live incident register with acknowledgement clock, timeline, SHA-256 evidence, decisions, actions, checklists, playbooks, CERT-In clock, post-incident report |
| 3 | Security Policy Review Report | **Policy review** - control ratings, 5x5 risk matrix, 90-day roadmap, exceptions, metrics, review checklist |
| 4 | Security Awareness Campaign Plan | **Awareness campaign** - four-week schedule, anonymous quiz, simulations, feedback, objectives measured from real data |
| 5 | Vulnerability Assessment Report | **Vulnerability assessment** - findings with automatic due dates and closure-evidence rules, assets, roadmap, metrics |
| 6 | Cybersecurity Audit Plan | **Audit plan** - 12-month calendar, workpapers, findings with retest and escalation rules, KPIs |

The **Overview** page combines everything into a "Needs attention" queue (missed acknowledgements, overdue findings, expired exceptions...) plus charts. Content is transcribed from your six documents; see `docs/WEEK_MAPPING.md`.

> The organization (Northstar Services Ltd.) and its findings are the hypothetical scenario from your documents. Demo records are labelled "(Demo)". Replace them with real data before relying on any figure; metrics are planning aids, not compliance evidence.

---

## 1. What has been tested

| Check | Result |
|---|---|
| 42 API tests (login, lockout, CSRF, role matrix, validation, every business rule, evidence hashing and tamper detection, CSV formula-injection guard, report HTML escaping, audit-log hash chain) | pass |
| 10 browser tests in headless Chromium (login, every page and every tab with zero console/CSP errors, form validation, full incident lifecycle with real file upload, closure rules, vulnerability closure rule, anonymous quiz, read-only viewer, keyboard/Escape, mobile menu) | pass |
| Real server process smoke test with `curl` (static files, login, CSRF refusal, create, reports, 403 for wrong role) | pass |
| Full suite repeated 5 times in a row | 5 of 5 green |

Not tested here: the Docker image build, Windows, and browsers other than Chromium. The code uses only the Python standard library plus Flask, so those are low risk.

---

## 2. Folder structure

```
northstar/
|-- run.py                  start the app
|-- requirements.txt        Flask only
|-- Dockerfile, docker-compose.yml, .env.example
|-- app/
|   |-- __init__.py         application factory, security headers
|   |-- config.py db.py security.py crud.py
|   |-- reference.py        models, checklists, playbooks transcribed from the documents
|   |-- seed.py             register data from the documents + labelled demo records
|   `-- routes/             threats incidents policy awareness vulns audits dashboard reports admin
|-- static/                 the dashboard (index.html, css/app.css, js/*.js) - no build step
|-- tests/                  test_api.py (42), test_ui.py (10, browser)
`-- docs/                   API.md, WEEK_MAPPING.md
```

---

## 3. Run it - step by step

You need **Python 3.10 or newer** (check: `python --version` on Windows, `python3 --version` on macOS/Linux). No Node.js, no database server, no internet after installing Flask.

**Step 1 - open a terminal in the project folder**
```bash
cd northstar
```

**Step 2 - create a virtual environment and activate it**
```bash
python -m venv .venv
source .venv/bin/activate            # Windows PowerShell: .venv\Scripts\Activate.ps1   (cmd: .venv\Scripts\activate.bat)
```

**Step 3 - install**
```bash
python -m pip install -r requirements.txt
```

**Step 4 - start the server**
```bash
python run.py
```
The first start creates `data/northstar.db`, loads the reference data from your documents, and creates the demo users.

**Step 5 - open** http://127.0.0.1:5000

**Step 6 - sign in** (password for every demo account: `Northstar!2026`)

| Username | Role | Can do |
|---|---|---|
| `admin` | CISO / security lead | everything, including users |
| `analyst` | Security analyst | edit threats, incidents, policy, awareness, vulnerabilities |
| `auditor` | Audit lead | edit the audit plan; read everything; audit log |
| `viewer` | Executive (read-only) | read everything, reports, take the quiz |

**Step 7 (optional) - run the tests**
```bash
python -m unittest tests.test_api -v          # 42 API tests, about 6 seconds
pip install playwright && playwright install chromium
python -m unittest tests.test_ui -v           # 10 browser tests, about 30 seconds (skipped if Playwright is missing)
```

---

## 4. Guided tour (about 10 minutes)

1. **Overview** - read the "Needs attention" queue; click a workstream tile.
2. **Threat landscape** - open a scenario, change its likelihood; the map updates. Try the *Attack chain and scale* and *Defensive priorities* tabs.
3. **Incident response** (as `analyst`) - *Report incident*: choose SEV-1 and CERT-In "Required". Open it: the **acknowledgement clock** and the **six-hour CERT-In deadline** are live. Click *Acknowledge*. Try to set status **Closed**: it is refused until all seven closure criteria and a summary exist. On *Evidence*, upload a file: its SHA-256 is computed and *Verify hash* proves it is unchanged. Open *Post-incident report*.
4. **Policy review** - on *Risk register* add a risk with L=5, I=5: it becomes **Critical (25)** and appears in the matrix. On *Exceptions* try to approve one without an expiry: refused.
5. **Awareness campaign** - *Take the knowledge check* (anonymous; answer key stays on the server). Watch *Objectives and results* update.
6. **Vulnerability assessment** - open VA-06 and set it to **Closed** without evidence: refused. Add evidence and it saves. Use *Remediation targets* to compute a due date.
7. **Audit plan** - on *Annual calendar* mark a month **Rescheduled** (needs a rationale). In *Findings* create a **Critical** finding and try to close it without a passed retest: refused.
8. **Reports and exports** - executive summary, CSV exports (every export is audited).
9. Sign in as `auditor` -> **Audit log** -> *Verify chain integrity*.

---

## 5. Using the API directly

```bash
B=http://127.0.0.1:5000
curl -s -c jar -X POST $B/api/auth/login -H 'Content-Type: application/json' \
     -d '{"username":"analyst","password":"Northstar!2026"}' > login.json
CSRF=$(python3 -c "import json;print(json.load(open('login.json'))['csrf'])")

curl -s -b jar $B/api/dashboard                                   # reads need only the session cookie
curl -s -b jar -X POST $B/api/threats -H "X-CSRF-Token: $CSRF" -H 'Content-Type: application/json' \
     -d '{"name":"My scenario","likelihood":3,"impact":3,"indicative_rating":"High"}'
```
Writes without the `X-CSRF-Token` header are refused (403). The full endpoint list and the business rules are in `docs/API.md`.

---

## 6. Configuration (environment variables, all optional)

| Variable | Default | Meaning |
|---|---|---|
| `PORT`, `HOST` | `5000`, `127.0.0.1` | where the server listens |
| `DATA_DIR` | `./data` | database, secret key, uploaded evidence |
| `SEED_DEMO_USERS` | `true` | create the four demo accounts on a fresh database |
| `SEED_DEMO_DATA` | `true` | include the labelled "(Demo)" incident, quiz attempts, simulations and audit finding |
| `DEMO_PASSWORD` | `Northstar!2026` | password for demo accounts |
| `SECRET_KEY` | generated in `data/secret.key` | signs session cookies |
| `APP_ENV` | `development` | `production` refuses demo users and sets secure cookies |
| `MAX_UPLOAD_MB`, `SESSION_HOURS`, `MAX_FAILED_LOGINS`, `LOCKOUT_MINUTES` | 5, 8, 5, 15 | limits |

**Start with an empty program (no demo records):** delete the `data` folder, then `SEED_DEMO_DATA=false python run.py`. The reference content from your documents remains; only the demo records are skipped.

**Docker:** `docker compose up --build`, then open http://localhost:5000 (data persists in a volume).

---

## 7. How it is built to be safe

* Server-side authorization on every endpoint (roles above); the UI only hides buttons for convenience.
* Sessions in HttpOnly SameSite cookies plus a CSRF token on every write; passwords hashed with scrypt; account lockout after 5 failures; login rate limit.
* Parameterised SQL only, whitelisted fields and sort columns, strict input validation with field-level errors.
* Strict Content-Security-Policy (no inline scripts or styles), escaped output everywhere, CSV formula-injection neutralised.
* Evidence files stored privately with SHA-256 integrity checks; every sign-in, change, denial, export and download goes into a **hash-chained audit log** that detects tampering.
* Quiz and feedback are anonymous; the quiz answer key never leaves the server.

---

## 8. Troubleshooting

| Symptom | Fix |
|---|---|
| `ModuleNotFoundError: flask` | activate the virtual environment, then `pip install -r requirements.txt` |
| `Address already in use` | `PORT=5001 python run.py` |
| PowerShell blocks activation | `Set-ExecutionPolicy -Scope Process -ExecutionPolicy RemoteSigned` |
| Account locked | wait 15 minutes, or delete the `data` folder to reset everything |
| Page shows old data | hard refresh (Ctrl+Shift+R) |
| UI tests skipped | `pip install playwright && playwright install chromium` |
| Reset everything | stop the server, delete `data/`, start again |

## 9. Limitations (by design for this assignment)

Single-process server (the audit-log chain and rate limiter are process-local), SQLite storage, no email notifications, no single sign-on or multi-factor authentication, and no multi-tenant separation. Before real use: replace demo accounts, serve behind HTTPS, back up `data/`, and have legal/privacy confirm CERT-In and other reporting obligations (the platform's clock is a planning aid, not legal advice).
