"""Static reference content transcribed from the Week 1-6 documents (models, templates, checklists, playbooks).
Served read-only at /api/reference/*. Operational data (registers) lives in the database."""

ORGANIZATION = {
    "name": "Northstar Services Ltd.",
    "note": "Hypothetical organization used across the Week 3-6 case studies (approximately 250 employees; head office "
            "and remote working; cloud email/collaboration, CRM, finance software, laptops, a small on-premises network "
            "and external service providers). All data in this platform is illustrative unless you replace it.",
    "employees": 250,
}

WEEKS = [
    {"week": 1, "key": "threats", "title": "Threat Landscape Analysis", "hours": "31 (plan: 30-35)",
     "blocks": [["Define scope and questions", 2], ["Review authoritative reports", 6], ["Research threat actors and campaigns", 4],
                ["Map attack vectors", 4], ["Analyze impacts and sector context", 4], ["Build risk assessment", 3],
                ["Develop control recommendations", 4], ["Draft and quality-check report", 4]]},
    {"week": 2, "key": "incidents", "title": "Incident Response Plan", "hours": "31 (plan: 30-35)",
     "blocks": [["Research and requirements", 4], ["Organization assumptions and scope", 3], ["Governance and severity model", 4],
                ["Lifecycle procedures", 7], ["Scenario playbooks", 4], ["Communications and compliance", 3],
                ["Diagrams, templates, and metrics", 3], ["Review and quality assurance", 3]]},
    {"week": 3, "key": "policy", "title": "Security Policy Review", "hours": "33 (plan: 30-35)",
     "blocks": [["Define scope and context", 3], ["Establish assessment criteria", 3], ["Review policy baseline", 5],
                ["Identify weaknesses", 5], ["Risk assessment", 4], ["Develop recommendations", 5], ["Roadmap and metrics", 3],
                ["Report writing and quality review", 5]]},
    {"week": 4, "key": "awareness", "title": "Security Awareness Campaign Plan", "hours": "32 (plan: 30-35)",
     "blocks": [["Discovery and scoping", 3], ["Risk and topic prioritization", 4], ["Objectives and measurement", 3],
                ["Campaign design", 4], ["Communication planning", 4], ["Schedule and resources", 4],
                ["Content and assessment outline", 5], ["Review and risk controls", 2], ["Final document and quality check", 3]]},
    {"week": 5, "key": "vulns", "title": "Vulnerability Assessment", "hours": "32 (plan: 30-35)",
     "blocks": [["Scope, assumptions, and asset inventory", 4], ["Review of vulnerability/configuration evidence", 8],
                ["Risk analysis and prioritization", 5], ["Mitigation design and remediation roadmap", 6],
                ["Report drafting and quality review", 6], ["Stakeholder summary and finalization", 3]]},
    {"week": 6, "key": "audit", "title": "Cybersecurity Audit Plan", "hours": "32 (plan: 30-35)",
     "blocks": [["Understand organization and define objectives", 4], ["Define scope and audit domains", 5],
                ["Choose criteria and risk-based frequencies", 4], ["Build annual schedule and workflow", 6],
                ["Design roles, reporting, and follow-up", 4], ["Define metrics, resources, and program risks", 4],
                ["Draft, review, and finalize report", 5]]},
]

# ---------------------------------------------------------------- Week 1
LIKELIHOOD_IMPACT_SCALE = [
    {"score": 1, "label": "Low", "likelihood": "Uncommon in the relevant environment; strong controls and limited exposure.",
     "impact": "Minor inconvenience; limited data or service effect; readily recoverable."},
    {"score": 2, "label": "Medium", "likelihood": "Plausible and seen in the sector; some exposed paths remain.",
     "impact": "Noticeable disruption or limited sensitive-data impact; manageable recovery."},
    {"score": 3, "label": "High", "likelihood": "Likely or frequently observed; exposure or control gaps exist.",
     "impact": "Major operational, financial, privacy, safety or reputational consequences."},
    {"score": 4, "label": "Very High", "likelihood": "Highly plausible under current exposure or an active targeted campaign.",
     "impact": "Critical services fail, extensive sensitive data is affected, or safety/legal/strategic harm is severe."},
]

ATTACK_STAGES = [
    {"stage": "Initial access", "detection": "New geographies/devices, suspicious email clicks, unusual VPN or web-app activity.",
     "response": "Block malicious source or message; disable/restrict affected identity; preserve logs."},
    {"stage": "Execution / persistence", "detection": "Unexpected scripts, remote tools, new services, startup changes or OAuth grants.",
     "response": "Isolate endpoint; remove unauthorized persistence after evidence capture; rotate exposed secrets."},
    {"stage": "Privilege / credential access", "detection": "Role changes, admin tool use, token anomalies, password vault access.",
     "response": "Revoke sessions; reset credentials; review privileged identities and service principals."},
    {"stage": "Lateral movement / discovery", "detection": "Unusual authentication fan-out, admin shares, remote execution and directory queries.",
     "response": "Segment/isolate affected hosts; restrict administrative protocols; scope impacted systems."},
    {"stage": "Collection / exfiltration", "detection": "Large downloads, unusual cloud API calls, outbound transfer spikes or archive creation.",
     "response": "Contain egress; preserve evidence; identify data classes and affected parties."},
    {"stage": "Impact / recovery", "detection": "Mass file changes, backup deletion, service failure or ransom note.",
     "response": "Activate incident command; protect backups; restore from validated clean copies."},
]

IMPACT_DIMENSIONS = [
    {"dimension": "Confidentiality", "examples": "Customer records, student records, employee data, intellectual property, credentials or contracts disclosed."},
    {"dimension": "Integrity", "examples": "Altered payment instructions, modified grades, manipulated records, tampered software or corrupted data."},
    {"dimension": "Availability", "examples": "Ransomware, DDoS, cloud outage, destructive attack or loss of a key supplier."},
    {"dimension": "Financial", "examples": "Fraudulent payments, incident response, restoration, legal fees, lost sales and higher insurance costs."},
    {"dimension": "Legal / regulatory", "examples": "Privacy notification, contractual reporting, evidence preservation, sector rules and litigation."},
    {"dimension": "Operational / safety", "examples": "Delayed care, disrupted manufacturing, unavailable education or citizen services."},
    {"dimension": "Reputation / trust", "examples": "Customer churn, public criticism, loss of partner confidence and employee concern."},
    {"dimension": "Strategic / intellectual property", "examples": "Loss of designs, research, bids, source code, credentials or competitive plans."},
]

DEFENSIVE_PRIORITIES = [
    {"horizon": "First 30 days", "items": [
        "Build a verified inventory of internet-facing assets, domains, cloud tenants, critical applications, privileged accounts and third-party remote connections.",
        "Enforce MFA for email, remote access, administrator accounts and cloud consoles; prioritize phishing-resistant methods for high-risk roles.",
        "Review exposure to actively exploited vulnerabilities (CISA KEV and vendor bulletins).",
        "Verify backups are isolated or immutable, protected from normal administrator credentials, and restorable.",
        "Enable endpoint protection and central logging on critical endpoints and servers; route alerts to a monitored owner.",
        "Reduce standing administrator privileges and review dormant, shared, service and vendor accounts.",
        "Implement out-of-band verification for changes to bank details, payroll, invoices and payment approvals.",
        "Publish a one-page incident reporting guide with clear contacts."]},
    {"horizon": "30-90 days", "items": [
        "Adopt asset-based vulnerability management using severity, exploit evidence, exposure and business criticality.",
        "Centralize identity, endpoint, email, network and cloud logs; synchronize time and protect log integrity.",
        "Segment high-value systems and backups from ordinary user networks; restrict administrative protocols.",
        "Establish cloud security baselines for storage, IAM, keys, audit logging, API exposure and OAuth consent.",
        "Create a third-party risk register (critical suppliers, access, data, recovery dependencies, exit options).",
        "Run phishing and payment-fraud exercises focused on learning and reporting, not blame.",
        "Document data classification, retention, secure sharing, secrets handling and approved AI use.",
        "Test incident-response playbooks through a tabletop exercise and track actions to closure."]},
    {"horizon": "3-12 months", "items": [
        "Align the program to NIST CSF 2.0 or ISO/IEC 27001 where appropriate.",
        "Implement continuous access reviews, privileged access management and joiner-mover-leaver automation.",
        "Develop secure software delivery practices (code review, dependency and secret scanning, protected CI/CD).",
        "Use threat modelling for critical applications, APIs, AI integrations and major architecture changes.",
        "Measure recovery through realistic restore tests, not backup-job success alone.",
        "Establish risk ownership, budget governance, independent assurance and executive reporting."]},
]

# ---------------------------------------------------------------- Week 2
SEVERITY_MODEL = [
    {"level": "SEV-1", "name": "Critical", "ack_minutes": 15, "ack_text": "Immediate / 15 minutes",
     "criteria": "Widespread ransomware, confirmed sensitive data exfiltration, critical service outage, domain/cloud admin compromise",
     "management": "Executive sponsor and crisis team immediately", "cadence": "Every 30-60 minutes, or on material change"},
    {"level": "SEV-2", "name": "High", "ack_minutes": 15, "ack_text": "15 minutes",
     "criteria": "Privileged account compromise, multiple endpoints, credible breach indicators, major business unit impact",
     "management": "Security leader and relevant business owner", "cadence": "Every 1-2 hours, or on material change"},
    {"level": "SEV-3", "name": "Medium", "ack_minutes": 60, "ack_text": "1 hour",
     "criteria": "Single compromised endpoint, contained malware, limited service impact",
     "management": "Security lead and system owner", "cadence": "At key milestones and at least daily while active"},
    {"level": "SEV-4", "name": "Low", "ack_minutes": 1440, "ack_text": "1 business day",
     "criteria": "Suspicious event with no confirmed compromise, low-impact policy issue",
     "management": "Routine security queue; elevate if facts change", "cadence": "At triage and closure, unless escalated"},
]

INCIDENT_CATEGORIES = [
    "Phishing / BEC / account takeover", "Ransomware / destructive malware", "Credential theft / privileged misuse / IdP compromise",
    "Data loss / unauthorized access / exfiltration", "Web application / API / database compromise",
    "Denial of service / service disruption", "Lost or stolen device / insider misuse / policy violation",
    "Cloud / SaaS compromise / exposed keys / third-party breach"]

INCIDENT_STATUSES = ["Reported", "Triage", "Declared", "Contained", "Eradicated", "Recovered", "Closed"]

CHECKLIST_15 = [
    "Ensure immediate human safety and operational safety.",
    "Acknowledge report and open an incident record.",
    "Record detection/report time, timezone, source, and initial evidence.",
    "Assign a triage owner; identify the IC or on-call backup.",
    "Determine whether activity is ongoing and whether impact could be critical.",
    "Assign provisional severity and escalate credible high-impact indicators.",
    "Use a secure channel; switch out of band if corporate identity or messaging may be compromised.",
    "Preserve high-value evidence where feasible and record any destructive action.",
    "Choose a proportionate containment action and obtain required approval.",
    "Identify business owner, legal/privacy contact, and affected dependencies.",
    "Set the next update time and communicate only confirmed facts.",
    "Record decisions, owners, due times, and outstanding unknowns."]

CHECKLIST_24 = [
    "Confirm incident declaration, severity, command structure, and response objectives.",
    "Build an initial affected-asset, account, service, and data inventory.",
    "Establish a timestamped incident timeline and evidence register.",
    "Contain ongoing access/spread; verify containment with telemetry.",
    "Identify initial access, persistence, exposed secrets, and likely root cause.",
    "Preserve relevant identity, endpoint, network, cloud, email, application, and backup logs.",
    "Involve legal/privacy and determine whether reporting or notification deadlines apply.",
    "Engage critical vendors, insurer, and external specialists where appropriate.",
    "Protect clean recovery paths, backup systems, and trusted administrative access.",
    "Provide regular executive updates with facts, uncertainty, impact, decisions, and next steps.",
    "Document recovery priorities, RTO/RPO implications, and service dependencies.",
    "Record all containment changes and approvals; maintain rollback options.",
    "Assign a scribe/evidence custodian and ensure records are backed up securely."]

CLOSURE_CRITERIA = [
    "The incident scope is understood to a level approved by the IC; unknowns are documented.",
    "Active threat access and spread are contained; eradication actions are verified or residual risks accepted.",
    "Affected services are restored and validated by their owners, or formally handed to a tracked recovery programme.",
    "Required legal, regulatory, contractual, insurer, and stakeholder notifications have been assessed and completed as applicable.",
    "Evidence and incident records are secured, access-controlled, and retained according to policy and law.",
    "Corrective actions have owners, priorities, due dates, and verification criteria.",
    "Lessons learned are documented and the appropriate leadership group has reviewed major incidents."]

PLAYBOOKS = [
    {"key": "phishing", "title": "Phishing and business email compromise", "steps": [
        "Open an incident record; preserve the original email, headers, URL, attachment hash, and recipient list.",
        "Determine whether a user clicked, executed a file, entered credentials, approved an MFA prompt, or initiated a payment/change request.",
        "If credentials or sessions may be compromised, revoke sessions/tokens, reset credentials through a trusted channel, and verify MFA/recovery settings.",
        "Search mailboxes and gateway logs for related messages; remove malicious messages where supported and authorized.",
        "Review mailbox forwarding rules, OAuth/app grants, delegated access, sign-in history, and suspicious inbox rules.",
        "If financial fraud is suspected, notify finance and the relevant bank/payment provider immediately using a verified contact method.",
        "Notify impacted users with approved guidance; hunt for related indicators across the organization.",
        "Close only after scope is understood, access is secured, and preventive actions are assigned."]},
    {"key": "ransomware", "title": "Ransomware", "steps": [
        "Declare severity based on spread, criticality, and evidence of data theft or destructive activity.",
        "Activate incident command; move to out-of-band communications if identity/email may be compromised.",
        "Isolate affected endpoints and network segments using approved controls; protect backup and management planes.",
        "Preserve key evidence and logs when feasible; do not delete ransom notes or wipe systems before evidence decisions are made.",
        "Determine whether encryption is still spreading, whether data exfiltration is suspected, and which critical services are affected.",
        "Engage legal/privacy, executive leadership, insurer, recovery specialists, and authorities where appropriate.",
        "Rebuild from trusted sources, rotate credentials, patch initial access, and validate backup integrity.",
        "Restore in business-priority order with enhanced monitoring and documented sign-off.",
        "Do not promise that payment will restore data or prevent disclosure; any extortion decision belongs to authorized leadership and counsel."]},
    {"key": "breach", "title": "Suspected data breach", "steps": [
        "Restrict the exposed access path or sharing mechanism while preserving relevant audit logs.",
        "Identify data categories, approximate volume, systems, time range, and whether access/exfiltration is confirmed or only suspected.",
        "Determine whether data was encrypted, pseudonymized, publicly accessible, downloaded, or shared externally; avoid unsupported conclusions.",
        "Engage privacy/legal and data owners immediately to assess applicable obligations and harm-reduction steps.",
        "Preserve access logs, object versions, sharing settings, queries, exports, and relevant communications.",
        "Consider token revocation, key rotation, access reviews, user/customer protections, and monitoring for misuse.",
        "Make notification decisions through the approved legal workflow and track deadlines.",
        "Complete a root-cause review and verify that the exposure path is closed."]},
    {"key": "cloud", "title": "Cloud account or API-key compromise", "steps": [
        "Use a trusted administrative device and identity to investigate; do not rely on a potentially compromised session.",
        "Disable or rotate exposed keys/tokens; revoke sessions and remove unauthorized identity federation or application grants.",
        "Review cloud audit logs, role assumptions, new users, policy changes, network changes, snapshots, object access, and billing anomalies.",
        "Preserve logs and snapshots in a separate restricted account or repository where feasible.",
        "Restrict compromised roles and apply temporary guardrails; protect root/break-glass access.",
        "Determine affected workloads and data; rebuild resources if integrity cannot be trusted.",
        "Rotate dependent secrets, review CI/CD and secret stores, and validate monitoring before restoring normal permissions."]},
    {"key": "dos", "title": "Denial-of-service or critical outage", "steps": [
        "Confirm the affected service, start time, geographic/customer scope, and whether availability or security is the primary issue.",
        "Engage network, hosting, CDN, cloud, and ISP contacts through prearranged escalation paths.",
        "Apply approved rate limits, filtering, scaling, traffic scrubbing, or failover while monitoring collateral impact.",
        "Preserve traffic metrics, firewall/WAF logs, provider tickets, and configuration changes.",
        "Communicate service status through the approved status page and customer support channels.",
        "After stabilization, review capacity, filtering, architecture, dependencies, and failover readiness."]},
]

IR_ROLES = [
    {"role": "Executive sponsor", "responsibility": "Sets risk tolerance, approves extraordinary business disruption, funds remediation.", "authority": "Accepts residual business risk; approves major crisis decisions."},
    {"role": "Incident commander", "responsibility": "Coordinates the response, maintains situation report, assigns actions, tracks decisions and dependencies.", "authority": "Declares/coordinates incident within delegated authority; escalates high-impact choices."},
    {"role": "SOC/security lead", "responsibility": "Triage alerts, investigate telemetry, recommend containment, maintain technical timeline.", "authority": "Low-risk reversible actions under runbook; recommends higher-impact actions."},
    {"role": "IT/infrastructure lead", "responsibility": "Isolates systems, manages identity/network/cloud changes, restores infrastructure.", "authority": "Executes approved technical changes and records changes."},
    {"role": "Application/data owner", "responsibility": "Explains business impact, validates data integrity, approves functional tests.", "authority": "Confirms business service readiness with IC."},
    {"role": "Legal/privacy lead", "responsibility": "Assesses legal privilege, notification duties, contracts, evidence preservation, and counsel engagement.", "authority": "Approves legal statements and required notifications with accountable management."},
    {"role": "Communications/PR", "responsibility": "Prepares staff, customer, media, and stakeholder messages.", "authority": "Publishes only approved messages through designated spokesperson."},
    {"role": "HR", "responsibility": "Supports employee matters, insider-risk processes, and staff communications.", "authority": "Handles personnel actions under policy and law."},
    {"role": "Vendor/third-party manager", "responsibility": "Contacts service providers, invokes contract response, tracks external dependencies.", "authority": "Coordinates vendor commitments and escalations."},
    {"role": "Scribe/evidence custodian", "responsibility": "Logs decisions, timestamps, evidence identifiers, access, and chain of custody.", "authority": "Maintains incident record and evidence register."}]

POST_INCIDENT_TEMPLATE = [
    ["Executive summary", "Incident type, severity, dates, business impact, current status."],
    ["Detection", "How discovered, time to acknowledge, time to declare, visibility gaps."],
    ["Scope", "Affected assets, accounts, data categories, service impact; confirmed vs suspected."],
    ["Timeline", "Key events with timestamps, source, action, owner, and result."],
    ["Root cause", "Initial access path, exploited weaknesses, contributing factors, confidence."],
    ["Response actions", "Containment, eradication, recovery, evidence, and decision records."],
    ["Notifications", "Legal assessment, required notifications, dates, approvals, and follow-up."],
    ["Impact and cost", "Downtime, recovery effort, data impact, customer effects, estimated cost if approved."],
    ["What worked / did not", "Evidence-based observations and process bottlenecks."],
    ["Corrective action plan", "Action, priority, owner, due date, measure of success, retest date."],
    ["Approval", "IC, business owner, security lead, and executive reviewer as required."]]

CERT_IN_NOTE = ("Planning aid only: the Week 2 plan notes that the CERT-In Directions of 28 April 2022 include reporting "
                "requirements for specified cyber incidents with a six-hour reporting window from noticing such incidents "
                "for entities within scope. The legal/privacy lead must verify the current official directions, "
                "applicability and reportable categories at the time of an actual incident. This is not legal advice.")

# ---------------------------------------------------------------- Week 3 / 5 / 6 shared tables
PATCH_SLA = [
    {"condition": "Actively exploited or critical exposure", "target_days": 3,
     "target": "Mitigate immediately; target 24-72 hours where feasible", "action": "Emergency change, compensating controls, management visibility"},
    {"condition": "Critical", "target_days": 7, "target": "Target 7 calendar days", "action": "Patch or document approved risk treatment"},
    {"condition": "High", "target_days": 14, "target": "Target 14 calendar days", "action": "Prioritized remediation and tracked exception if overdue"},
    {"condition": "Medium", "target_days": 30, "target": "Target 30 calendar days", "action": "Remediate in planned cycle"},
    {"condition": "Low", "target_days": 90, "target": "Target 90 calendar days or approved maintenance window", "action": "Track and resolve proportionately"}]

POLICY_RATING_DEFS = [
    {"rating": "Effective", "meaning": "Requirement is clear, assigned and supported by evidence", "interpretation": "Maintain and periodically test"},
    {"rating": "Partially effective", "meaning": "Topic is addressed but detail, ownership or assurance is incomplete", "interpretation": "Clarify and implement targeted improvements"},
    {"rating": "Weak", "meaning": "Requirement is vague, inconsistent or difficult to enforce", "interpretation": "Prioritize remediation"},
    {"rating": "Missing / not evidenced", "meaning": "No adequate requirement or supporting evidence is available in the assumed baseline", "interpretation": "Create a control and verify operation"},
    {"rating": "Not assessed", "meaning": "Evidence or access is insufficient for a defensible rating", "interpretation": "Collect evidence before concluding"}]

POLICY_BASELINE = [
    "Employees must use company systems responsibly and protect their passwords.",
    "Access is granted to staff who need it for their work.",
    "Sensitive information should not be shared with unauthorized people.",
    "Devices should have antivirus protection and should be updated regularly.",
    "Employees should report suspicious activity to IT.",
    "Important information should be backed up.",
    "Employees should complete security awareness training."]

POLICY_GOVERNANCE_ROLES = [
    {"role": "Executive sponsor", "responsibility": "Approve risk appetite, resources and material risk acceptance", "evidence": "Approval records and periodic risk review"},
    {"role": "Policy owner / Security Lead", "responsibility": "Maintain policy, coordinate review, track exceptions and metrics", "evidence": "Version history, exception register, review minutes"},
    {"role": "IT Operations", "responsibility": "Implement technical controls, patch, back up and maintain systems", "evidence": "Configuration reports, patch reports, restore results"},
    {"role": "System and data owners", "responsibility": "Classify information, approve access and define business recovery needs", "evidence": "Data inventory, access approvals, RTO/RPO decisions"},
    {"role": "Human Resources", "responsibility": "Notify IT of employment changes and coordinate training", "evidence": "Joiner/mover/leaver records, training completion"},
    {"role": "Procurement / Legal / Privacy", "responsibility": "Assess supplier and contractual risks; advise on obligations", "evidence": "Due diligence, contract clauses, legal review records"},
    {"role": "All employees and contractors", "responsibility": "Follow policy, protect credentials and report concerns promptly", "evidence": "Acknowledgement and incident reports"},
    {"role": "Internal audit / independent reviewer", "responsibility": "Test design and operation of controls independently where feasible", "evidence": "Review plan, findings and follow-up actions"}]

EXCEPTION_PROCESS = [
    "Requester documents the control that cannot be met, business reason, affected assets and duration.",
    "System or data owner assesses business impact and proposes compensating controls.",
    "Security Lead evaluates residual risk and recommends approval, rejection or alternative treatment.",
    "Authorized management approves exceptions according to risk level; critical controls require senior approval.",
    "Record an expiry date, responsible owner and review date. Exceptions must not become permanent by default.",
    "Reassess when the system, threat, business need or applicable requirements change."]

# ---------------------------------------------------------------- Week 4
CAMPAIGN_MESSAGES = [
    {"title": "Launch message", "body": "Subject: Pause. Check. Protect. - our four-week security awareness campaign\n\nCybersecurity is part of everyone's work. Over the next four weeks, we'll share short, practical ways to recognize suspicious requests, protect accounts and data, and report concerns quickly. You do not need to know every technical detail. If a message or request feels unusual, pause, verify it using a trusted channel, and report it through our approved process. If you make a mistake, report it promptly - early reporting helps us respond. Start with the campaign hub: [insert approved internal link]."},
    {"title": "Weekly tip", "body": "A familiar logo or display name does not prove a message is genuine. Check the full sender address, be cautious with unexpected links or attachments, and verify unusual requests through a separate trusted channel. When unsure, report it rather than replying."},
    {"title": "Manager huddle prompt", "body": "Ask the team: \"You receive an urgent request to change a supplier's bank details. What would you do before acting?\" Reinforce the answer: stop, independently verify using a known contact method, and report suspicious requests. Do not use phone numbers or links supplied only in the unexpected message."}]

CAMPAIGN_RISKS = [
    ["Low participation due to workload", "Keep activities short, schedule time with managers and provide shift-friendly alternatives."],
    ["Employees feel blamed or monitored", "Use a supportive tone, protect individual results and explain that the aim is learning."],
    ["Simulation causes confusion or distress", "Obtain approval, limit scope, avoid collecting credentials, provide prompt debriefing and support."],
    ["Reporting route is unclear or not functioning", "Validate the report button/help-desk process before launch; include a tested fallback route."],
    ["Inaccessible or overly technical content", "Use plain language, captions, readable contrast, keyboard-accessible materials and realistic examples."],
    ["Conflicting advice across teams", "Have Security and IT review content; publish the intranet hub as the single source of truth."],
    ["Baseline data is unavailable", "Use a short pre-campaign quiz and pulse survey; label targets provisional until results are known."],
    ["A real incident occurs during the campaign", "Pause any confusing exercise if needed and follow the incident-response procedure immediately."]]

CAMPAIGN_GUARDRAILS = ("Simulations must be approved, limited in scope, and designed for learning. Do not collect real passwords, "
                       "expose personal results publicly, or punish employees for clicking. Use aggregate trends; quiz attempts "
                       "and survey answers in this platform are anonymous and never linked to a person.")

# ---------------------------------------------------------------- Week 6
AUDIT_DOMAINS = [
    "Governance and risk", "Identity and access", "Asset and vulnerability management", "Endpoint and server security",
    "Network and remote access", "Cloud and applications", "Data protection and privacy", "Incident response",
    "Backup and continuity", "Third-party risk", "People and awareness"]

AUDIT_TIERS = [
    {"tier": "Tier 1 - Critical", "example": "Identity administration, critical customer-data systems, backups, remote access, security logging",
     "frequency": "Quarterly focused review; continuous or monthly monitoring where feasible"},
    {"tier": "Tier 2 - High", "example": "Endpoints, core business applications, network configuration, cloud sharing, critical suppliers",
     "frequency": "At least twice per year"},
    {"tier": "Tier 3 - Standard", "example": "General policies, awareness records, routine asset processes, non-critical applications",
     "frequency": "At least annually"},
    {"tier": "Event-driven", "example": "Major system change, acquisition, serious incident, new critical supplier, material control failure",
     "frequency": "Targeted review after the event or before go-live where appropriate"}]

AUDIT_SEVERITY = [
    {"rating": "Critical", "target_days": 7, "definition": "A control gap creates a credible path to severe business-wide compromise or interruption.",
     "response": "Escalate immediately; implement containment or compensating controls; agree an urgent fix, normally within 7 days where feasible."},
    {"rating": "High", "target_days": 30, "definition": "A weakness could materially affect sensitive data, key systems, or continuity.",
     "response": "Assign an owner and plan promptly; target remediation within 30 days unless an approved exception applies."},
    {"rating": "Medium", "target_days": 60, "definition": "Meaningful risk with more limited likelihood, scope, or impact.",
     "response": "Plan remediation, generally within 60-90 days, and monitor interim controls."},
    {"rating": "Low", "target_days": 180, "definition": "Limited risk or a control improvement with low immediate impact.",
     "response": "Address through routine improvement, generally within 180 days or the approved maintenance cycle."},
    {"rating": "Observation", "target_days": None, "definition": "Improvement opportunity without a substantiated material control failure.",
     "response": "Assign an appropriate owner and decide whether to implement."}]

AUDIT_WORKFLOW = [
    "Initiation: issue an audit notice, confirm sponsor and scope, identify system owners, and agree evidence-handling requirements.",
    "Planning: review prior findings, risk registers, asset inventories, policies, architecture, and contracts; prepare a test plan and sample selection.",
    "Evidence collection: inspect approved configuration exports, reports, tickets, access records, logs, training records, and recovery-test results.",
    "Interviews and walkthroughs: ask process owners to demonstrate how controls operate in practice and compare practice with documented policy.",
    "Sampling and validation: select representative users, systems, changes, and suppliers based on risk; validate safely without unnecessary production changes.",
    "Analysis: compare evidence with approved criteria, record gaps, evaluate compensating controls, and determine root causes where possible.",
    "Reporting: validate factual accuracy with the owner, assign severity, and present practical remediation options to management.",
    "Follow-up: track actions, review closure evidence, retest where appropriate, and formally record any accepted residual risk."]

AUDIT_ROLES = [
    {"role": "Executive sponsor / risk committee", "responsibility": "Approve the plan, review material risks, resolve resource conflicts, and authorize significant risk acceptance."},
    {"role": "Audit lead", "responsibility": "Maintain independence, define audit procedures, supervise evidence collection, rate findings, and issue reports."},
    {"role": "Information security lead", "responsibility": "Provide security context, coordinate technical evidence, advise on mitigations, and track security-related actions."},
    {"role": "IT and system owners", "responsibility": "Provide access to evidence, explain control operation, remediate findings, and supply closure evidence."},
    {"role": "Data and business owners", "responsibility": "Confirm information sensitivity, business impact, access needs, and acceptable downtime."},
    {"role": "Legal/privacy contact", "responsibility": "Advise on privacy, contractual, regulatory, and evidence-retention obligations where applicable."},
    {"role": "External assessor (if used)", "responsibility": "Perform agreed independent reviews under a written scope, confidentiality terms, and rules of engagement."}]

AUDIT_PROGRAM_RISKS = [
    ["Limited staff availability", "Delays or shallow testing", "Agree calendar early, identify deputies, prioritize critical controls, and escalate resource conflicts."],
    ["Incomplete or inaccurate asset inventory", "Audit misses important systems", "Reconcile endpoint, cloud, procurement, and network inventories; document coverage gaps."],
    ["Auditor conflict of interest", "Reduced independence or missed issues", "Use independent review for controls owned by the auditor and disclose conflicts."],
    ["Disruption from testing", "Service outage or data loss", "Use read-only methods, approved test windows, change control, and rollback plans."],
    ["Poor remediation ownership", "Findings remain open", "Name one accountable owner per action, set due dates, and escalate overdue items."],
    ["Sensitive evidence exposure", "Privacy or security incident", "Minimize collection, restrict access, encrypt storage, and apply retention/disposal rules."]]

WORKPAPER_TEMPLATE = [
    ["Audit ID / control", "Unique identifier and control objective"], ["Criteria", "Policy, contract, framework control, or requirement used"],
    ["Population / sample", "Items in scope, selection rationale, sample size, and period"],
    ["Evidence", "Source, collection date, secure location, and evidence reference"],
    ["Test procedure", "Steps performed, including any limitations"],
    ["Result", "Pass, partial, fail, or not tested; factual observations"],
    ["Risk and impact", "Likelihood, business impact, severity, and affected assets"],
    ["Action / owner / date", "Recommended mitigation, accountable owner, target date"],
    ["Retest / closure", "Verification method, results, closure approval, or risk acceptance"]]

FINDING_STATUSES = ["Open", "In Progress", "Pending Verification", "Closed", "Risk Accepted"]
