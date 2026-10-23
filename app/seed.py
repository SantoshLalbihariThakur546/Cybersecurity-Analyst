"""Seed the database. Reference/register content is transcribed from the Week 1-6 documents.
Operational demo records (incident, quiz attempts, ...) are flagged "(Demo)" and can be disabled with SEED_DEMO_DATA=false."""
import json
from datetime import date, timedelta

from .db import connect_standalone, init_schema, now_iso

ASSESS_DATE = "2026-10-20"  # reporting date used in the Week 3-6 documents


def _many(conn, sql, rows):
    conn.executemany(sql, rows)


def seed_reference(conn):
    if conn.execute("SELECT COUNT(*) FROM threats").fetchone()[0]:
        return
    now = now_iso()

    # ---------------- Week 1 -------------------------------------------------
    threats = [  # name, likelihood, impact, indicative rating, reasoning, category, owner
        ("Phishing leads to account takeover", 3, 3, "Critical", "Common, scalable and capable of reaching email, SaaS and financial workflows.", "Phishing, smishing, vishing and collaboration-channel deception", "Identity owner"),
        ("Ransomware disrupts critical systems", 3, 4, "Critical", "Can interrupt operations and may include data theft and extortion.", "Ransomware and multi-extortion", "IT Operations"),
        ("Internet-facing known vulnerability exploited", 3, 3, "Critical", "Risk rises sharply where vulnerable assets are exposed and patching is delayed.", "Vulnerability exploitation and zero-days", "IT Operations"),
        ("Cloud/SaaS misconfiguration exposes data", 2.5, 3, "High", "Misconfiguration and broad permissions can expose large datasets quickly.", "Cloud, SaaS and API security failures", "Cloud / IT"),
        ("Supplier compromise affects operations", 2, 4, "High", "Likelihood varies by supplier footprint; impact can spread across customers and dependencies.", "Supply-chain and third-party compromise", "Procurement / IT"),
        ("Business email compromise / payment fraud", 3, 3, "Critical", "May bypass technical controls by exploiting approval processes and trust.", "Phishing, smishing, vishing and collaboration-channel deception", "Finance / Security"),
        ("DDoS takes down a public service", 2, 2.5, "High", "Impact depends on service criticality, protection and upstream resilience.", "DDoS and availability attacks", "Network team"),
        ("Insider intentionally exfiltrates data", 1.5, 3, "High", "Lower frequency in many organizations but potentially significant data and trust impact.", "Insider risk and accidental exposure", "HR / Security"),
        ("AI integration leaks sensitive data or executes unsafe action", 2, 3, "High", "Exposure depends on tool permissions, data access, testing and governance maturity.", "AI-enabled attacks and AI application risks", "Security Lead"),
        ("State-linked espionage / long-term access", 1.5, 4, "High", "Likelihood is sector-dependent; stealth and strategic consequences may be substantial.", "Threat actors: state-linked / espionage", "Security Lead"),
    ]
    _many(conn, "INSERT INTO threats(name,category,likelihood,impact,indicative_rating,reasoning,owner,status,review_date,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'Open',?,?,?)",
          [(n, c, l, i, r, why, o, "2027-01-20", now, now) for n, l, i, r, why, c, o in threats])

    cats = [
        ("Ransomware and multi-extortion", "Intrusion and extortion pattern, not just file encryption: data theft first, recovery options disabled, public-release threats.", "Business interruption; recovery costs; data disclosure; contractual and regulatory exposure; customer harm; safety impact where operations are affected.", "MFA for remote access; patch exposed systems; EDR; segmentation; restrict admin tools; monitor bulk file access and exfiltration; offline/immutable backups; test full restoration."),
        ("Phishing, smishing, vishing and collaboration-channel deception", "Impersonation of executives, HR, IT support, banks or suppliers, increasingly with synthetic voice/video; fake login pages and malicious OAuth grants.", "Account takeover; payment diversion; malware execution; payroll fraud; exposure of cloud files; reputational damage.", "Phishing-resistant MFA; mail authentication and filtering; out-of-band verification for payment or credential changes; user reporting; disable legacy authentication; monitor inbox rules and OAuth grants."),
        ("Credential theft and session hijacking", "Passwords stolen by infostealers, reuse, password spraying or adversary-in-the-middle phishing; session cookies and refresh tokens may outlive a password change.", "Unauthorized access to email, cloud data, VPN, source code, finance systems and administrator consoles.", "Unique passwords and password manager; MFA; conditional access; protected short-lived sessions; revoke sessions and tokens during response; monitor atypical sign-ins."),
        ("Vulnerability exploitation and zero-days", "Known flaws in internet-facing appliances, web applications, remote management and file transfer can remain dangerous long after patches exist.", "Remote code execution; data theft; persistence; ransomware deployment; service interruption; downstream customer compromise.", "Inventory assets and software; external attack-surface monitoring; CISA KEV and vendor advisories; patch by exposure, exploit evidence and criticality; isolate unsupported systems; validate fixes."),
        ("Cloud, SaaS and API security failures", "Public storage, excessive permissions, exposed API keys, insecure OAuth apps, missing audit logs and broad service principals.", "Large-scale data exposure; cloud resource abuse; account takeover; malicious changes; loss of availability; unexpected costs.", "Secure configuration baselines; least-privilege roles; secrets management; private storage by default; logging and alerting; API inventory; periodic access reviews."),
        ("Supply-chain and third-party compromise", "Compromised software package, update mechanism, contractor, MSP, identity integration or vendor support account.", "Multiple organizations affected; hidden persistence; integrity compromise; delayed detection; contractual and regulatory issues.", "Tier suppliers by criticality; due diligence; limit vendor access; time-bound privileged access; monitor third-party accounts; verify software provenance; exit and outage plans."),
        ("Malware, information stealers and botnets", "Commodity malware steals browser credentials, session data, wallets and files; botnets support DDoS and spam.", "Credential exposure; fraud; endpoint compromise; lateral movement; disruption; onward infection.", "Application control; EDR; patch browsers and OS; restrict scripting and macros; block known malicious infrastructure; educate users not to run unknown commands or installers."),
        ("DDoS and availability attacks", "Network, application or upstream services overwhelmed by traffic or expensive requests; used for extortion, ideology or distraction.", "Unavailable websites, portals, APIs and customer services; lost revenue; support overload; reputational harm.", "DDoS protection and CDN; rate limiting; upstream provider coordination; tested traffic scrubbing; resilient DNS; separate availability and intrusion runbooks."),
        ("Insider risk and accidental exposure", "Legitimate access misused deliberately or accidentally (wrong recipient, exposed repository, excessive export, access kept after a role change).", "Data loss; privacy harm; fraud; intellectual-property loss; compliance findings; reduced trust.", "Least privilege; joiner-mover-leaver controls; data classification; proportionate DLP; audit trails; manager-approved exceptions; fair investigation and separation of duties."),
        ("AI-enabled attacks and AI application risks", "Generative AI speeds social engineering and reconnaissance; AI applications face prompt injection, data leakage, unsafe tool use and excessive agent permissions.", "Fraud; leakage of confidential information; unauthorized actions by connected agents; unreliable decisions; exposure of training or retrieval data.", "Approved-use policy; data minimization; isolate secrets; least privilege for agents and tools; human approval for high-impact actions; prompt-injection testing; logging; supplier review."),
    ]
    _many(conn, "INSERT INTO threat_categories(name,description,potential_impact,priority_controls) VALUES(?,?,?,?)", cats)

    actors = [
        ("Cybercriminal groups", "Extortion, fraud, theft, resale of data or access.", "Phishing, stolen credentials, infostealers, exposed services, ransomware and data theft.", "Unexpected logins, unusual data staging, endpoint alerts, ransom or leak-site claims."),
        ("Initial-access brokers", "Sell access to organizations or compromised accounts.", "Credential theft, exploitation of edge devices, compromised remote access.", "Old or dormant accounts suddenly used; access sold or reused by another actor."),
        ("State-linked / espionage actors", "Intelligence collection, strategic access, influence or disruption.", "Spear phishing, zero-day or known vulnerability exploitation, stealthy persistence, supplier compromise.", "Long-lived access, targeted collection, unusual authentication and covert command/control."),
        ("Hacktivists", "Political or ideological messaging, disruption, publicity.", "DDoS, website defacement, data leaks, doxxing or opportunistic exploitation.", "Traffic spikes, public claims, defacement, exposed data or disruption around high-profile events."),
        ("Insiders", "Personal gain, grievance, coercion or careless misuse.", "Unauthorized downloads, privilege misuse, data transfer to personal services, policy bypass.", "Abnormal access patterns; context and due process are essential before drawing conclusions."),
        ("Fraudsters / BEC operators", "Payment diversion, payroll fraud, invoice manipulation, identity theft.", "Mailbox takeover, impersonation, fake vendor changes, social engineering and deepfake voice/video.", "Urgent payment requests, changed bank details, suspicious mailbox rules and unusual forwarding."),
        ("Opportunistic actors / automated scanning", "Find vulnerable or misconfigured systems at scale.", "Internet scanning, exploitation of known flaws, password spraying and commodity malware.", "Repeated probes, exposure of outdated services and broad attack attempts."),
    ]
    _many(conn, "INSERT INTO threat_actors(category,goals,approaches,indicators) VALUES(?,?,?,?)", actors)

    sources = [
        ("ENISA Threat Landscape 2025", "ENISA", "Incidents 1 Jul 2024 - 30 Jun 2025", "Analyses 4,875 incidents; discusses ransomware, information stealers, hacktivism and state-linked activity.", "EU-focused synthesis; does not represent every global incident.", "https://www.enisa.europa.eu/publications/enisa-threat-landscape-2025"),
        ("2025 Data Breach Investigations Report", "Verizon", "2025", "Highlights third-party involvement, vulnerability exploitation as an initial-access path, and ransomware in breaches.", "Directional evidence, not a universal probability for every organization.", "https://www.verizon.com/business/resources/reports/dbir.5/"),
        ("Quarterly Threat Landscape Report - Q2 2026", "Rapid7", "Q2 2026", "High/critical CVE disclosures rising from 4,268 (Q2 2025) to 8,539 (Q2 2026) in its analysis; pressure on conventional patching cycles.", "Vendor visibility and definitions; prioritize exploitable exposure, not every CVE equally.", "https://www.rapid7.com/research/report/quarterly-threat-landscape-report/"),
        ("Digital Defense Report 2026", "Microsoft", "Published October 2026", "Emphasizes identity compromise, phishing, faster weaponization and AI changing attacker speed.", "Vendor telemetry; use alongside independent sources.", "https://news.microsoft.com/source/asia/2026/10/13/microsoft-digital-defense-2026-report-highlights-new-cybersecurity-challenges-amid-rapid-ai-adoption/"),
        ("Cloud and Threat Report 2026", "Netskope Threat Labs", "2026", "Cloud phishing, counterfeit login pages, malicious OAuth applications and session-cookie theft.", "Cloud identity and sessions should be monitored as security-critical assets.", "https://threatlabs.netskope.com/reports/2026/cloud-and-threat-report-2026"),
        ("Known Exploited Vulnerabilities Catalog", "CISA", "Live catalog", "Helps prioritize remediation of vulnerabilities known to be exploited in the wild.", "Check the live catalog for current entries.", "https://www.cisa.gov/known-exploited-vulnerabilities-catalog"),
        ("MITRE ATT&CK", "MITRE", "Knowledge base", "Describes adversary tactics and techniques; maps defensive coverage.", "A mapping and detection aid, not a checklist that guarantees coverage.", "https://attack.mitre.org/"),
        ("Cybersecurity Framework 2.0", "NIST", "2024", "Govern, Identify, Protect, Detect, Respond and Recover.", "Reference framework, not proof of compliance.", "https://www.nist.gov/cyberframework"),
        ("CERT-In directions and advisories", "CERT-In", "Current", "Official advisories, directions and reporting information for India.", "Verify current requirements and applicability; not legal advice.", "https://www.cert-in.org.in/"),
        ("Ministry of Electronics and IT (MeitY)", "Government of India", "Current", "Official policy and legal materials including data protection updates.", "Confirm with qualified counsel before compliance conclusions.", "https://www.meity.gov.in/"),
        ("NCIIPC", "NCIIPC", "Current", "Official information for critical information infrastructure protection.", "Check whether CII obligations apply.", "https://nciipc.gov.in/"),
        ("Four critical threats requiring urgent improvements", "Gartner", "2 June 2026", "Highlights deepfakes, AI application compromise, prompt injection and software supply chains.", "Analyst commentary; validate against your own exposure.", "https://www.gartner.com/en/newsroom/press-releases/2026-06-02-gartner-identifies-four-critical-threats-requiring-urgent-improvements-from-cybersecurity-leaders"),
    ]
    _many(conn, "INSERT INTO intel_sources(title,publisher,period,finding,caution,url) VALUES(?,?,?,?,?,?)", sources)

    # ---------------- Week 3 -------------------------------------------------
    controls = [  # area, rating, main gap, priority, critique, recommendation, evidence
        ("Governance and policy lifecycle", "Weak", "No clear owner, approval cycle or exception process", "High",
         "General policy language is not sufficient unless staff know who approves the policy, who maintains it, who monitors compliance and how exceptions are authorized.",
         "Assign an executive sponsor and policy owner; require management approval, version control, annual and out-of-cycle review; maintain a register of standards and procedures; define a documented exception process with expiry.",
         "Approved policy version, change history, named owner, annual review calendar and exception register."),
        ("Identity and access management", "Weak", "MFA, privileged access and access review requirements unclear", "Critical",
         "\"Access is granted to staff who need it\" does not define how need is established, who approves access, how roles are reviewed or how access is removed. Password-only authentication exposes the organization to phishing, credential stuffing and reuse.",
         "MFA for all remote, privileged, cloud-admin and business-critical access; unique accounts; least privilege and separate admin accounts; HR-integrated joiner/mover/leaver; privileged access review quarterly, ordinary access every six months; password manager; monitored emergency access.",
         "MFA coverage report, access approval tickets, quarterly privileged-access review, termination checklist and list of service accounts."),
        ("Data protection and privacy", "Weak", "Classification and handling rules insufficiently specific", "High",
         "A broad instruction to protect sensitive information does not tell employees how to identify it or which safeguards apply.",
         "Adopt Public / Internal / Confidential / Restricted classes with owners; define storage, sharing, transfer, printing and disposal rules; encrypt laptops and portable media; approved external sharing with expiry; retention and secure deletion schedules; data inventory.",
         "Classification standard, data inventory, approved sharing settings, encryption compliance report and disposal records."),
        ("Endpoint and mobile security", "Partially effective", "Baseline configuration, encryption and device response unclear", "High",
         "A general antivirus requirement does not cover hardening, disk encryption, patch status, EDR, screen locking, mobile access or lost-device handling.",
         "Maintain endpoint inventory; apply a secure baseline (screen lock, full-disk encryption, host firewall, endpoint protection); central management; restrict local admin; lost/stolen device route with session revocation and remote wipe; BYOD conditions.",
         "Endpoint management reports, encryption status, EDR/antivirus coverage and device inventory."),
        ("Network and remote access", "Partially effective", "Remote-access safeguards and segmentation not defined", "High",
         "If network and remote access requirements are not explicit, remote connections may be exposed to weak authentication, unmanaged devices or broad network access.",
         "MFA and managed-device checks for remote access; separate guest, corporate, server and management zones; restrict inbound admin access; change-controlled firewall rules with periodic review; secure Wi-Fi; remote-work guidance.",
         "Network diagrams, remote-access configuration, firewall review records and cloud security baselines."),
        ("Vulnerability and patch management", "Weak", "No severity-based deadlines or verification", "Critical",
         "\"Update regularly\" is not measurable: no asset ownership, discovery methods, remediation deadlines, exceptions or verification.",
         "Severity-based service levels (exploited/critical exposure 24-72 h; Critical 7 days; High 14; Medium 30; Low 90), asset inventory, authenticated scanning, advisory monitoring, proportionate testing, verification and time-limited exceptions.",
         "Vulnerability scan summaries, patch compliance reports, remediation tickets and approved exceptions."),
        ("Logging and monitoring", "Weak", "Log sources, retention and alert ownership unspecified", "High",
         "Logging requirements without sources, retention, access protection and alert ownership can leave the organization unable to reconstruct incidents or detect suspicious activity.",
         "Collect identity, endpoint, email, firewall, VPN, cloud and critical-application logs; synchronize clocks; protect logs; define retention; alert on suspicious sign-ins, privileged changes, mass downloads and disabled controls; assign alert owner and escalation route; test alert quality.",
         "Logging source list, retention settings, alert queue records and incident triage samples."),
        ("Incident response", "Weak", "No severity model, response roles or exercise schedule", "Critical",
         "Telling employees to report suspicious activity is not enough if they do not know how, what to provide or whether they will be blamed.",
         "One obvious reporting channel plus emergency alternative; severity model; named roles (incident commander, technical lead, communications, legal/privacy, business owner); evidence preservation; playbooks; annual tabletop; review CERT-In obligations with qualified personnel.",
         "Incident register, response playbooks, exercise reports, post-incident reviews and communications templates."),
        ("Backup and recovery", "Partially effective", "Backup testing and recovery objectives unspecified", "Critical",
         "\"Important information should be backed up\" does not define scope, frequency, retention, isolation, recovery objectives or restoration testing. A backup that cannot be restored is not a recovery control.",
         "Business-approved RTO/RPO for critical services; protected isolated or immutable copies with separate administration; encrypted backups; scheduled restore tests with recorded results; documented recovery order; ransomware recovery scenarios.",
         "Backup schedules, backup access controls, restoration test records and continuity plans."),
        ("Security awareness", "Partially effective", "Training frequency and effectiveness measures unclear", "Medium",
         "A statement requiring training is incomplete without onboarding coverage, refresher frequency, role-based content or a way to assess behaviour change.",
         "Onboarding plus at least annual refreshers; role-specific training; respectful simulations; measure reporting rates and time to report rather than only quiz scores.",
         "Security awareness curriculum, completion reports and phishing-reporting metrics."),
        ("Third-party risk", "Missing / not evidenced", "No supplier due diligence or access review requirements", "High",
         "External providers may process sensitive information or have privileged access; without due diligence and oversight the organization inherits their weaknesses.",
         "Classify suppliers; assess high-risk suppliers before onboarding; security, breach-notification, audit and termination clauses; named least-privilege vendor accounts with MFA; periodic review; exit plan.",
         "Supplier register, security assessments, contract security clauses and vendor access reviews."),
        ("Physical security and media", "Partially effective", "Visitor, equipment and media disposal controls unclear", "Medium",
         "Physical access, visitor handling and removable media can bypass digital controls.",
         "Visitor registration and escorting; secure unattended devices and clean-desk practices; restrict removable storage; secure destruction of paper and media; prompt reporting of lost access cards, keys or devices.",
         "Visitor logs, media disposal records, access-card reports."),
        ("Secure change management and application security", "Not assessed", "Not rated in the Week 3 overall table (section 7.13 only)", "Medium",
         "Changes to infrastructure, cloud configuration or applications can introduce vulnerabilities if there is no approval, testing or rollback process.",
         "Change records for material production changes; separate dev/test/prod; secrets in approved secret management; secure development practices; review of cloud permission changes; retrospective approval of emergency changes.",
         "Change records, cloud permission change reviews, emergency change log."),
    ]
    _many(conn, "INSERT INTO policy_controls(area,rating,main_gap,priority,critique,recommendation,evidence,sort_order) VALUES(?,?,?,?,?,?,?,?)",
          [c + (i,) for i, c in enumerate(controls, 1)])

    def band(score):
        return "Critical" if score >= 20 else "High" if score >= 12 else "Medium" if score >= 6 else "Low"
    risks = [
        ("R1", "Weak authentication or excessive privileges enable account compromise", 4, 5, "IT / Identity owner"),
        ("R2", "Known vulnerabilities remain unpatched on exposed systems", 4, 5, "IT Operations"),
        ("R3", "Incident response delays containment or evidence preservation", 4, 5, "Security Lead"),
        ("R4", "Backups fail or are compromised during a disruptive incident", 3, 5, "IT Operations / Business owners"),
        ("R5", "Sensitive data is shared or retained inappropriately", 4, 4, "Data owners / Privacy"),
        ("R6", "Insufficient logging prevents timely detection or investigation", 3, 4, "Security / IT"),
        ("R7", "Supplier weakness or access creates a path into company systems", 3, 4, "Procurement / IT / Legal"),
        ("R8", "Unmanaged endpoints increase malware and data-loss exposure", 3, 4, "Endpoint owner"),
        ("R9", "Staff do not recognize or promptly report suspicious activity", 3, 3, "HR / Security"),
        ("R10", "Uncontrolled exceptions cause inconsistent enforcement", 3, 3, "Policy owner"),
    ]
    _many(conn, "INSERT INTO policy_risks(ref,title,likelihood,impact,score,band,owner,treatment,status,review_date,created_at,updated_at) VALUES(?,?,?,?,?,?,?,'Mitigate','Open','2027-01-20',?,?)",
          [(r, t, l, i, l * i, band(l * i), o, now, now) for r, t, l, i, o in risks])

    actions = [
        ("First 30 days", "Name policy owner and executive sponsor", "Executive management", "Approved responsibility record", "Owner and review date published"),
        ("First 30 days", "Review MFA for privileged, remote and critical access", "IT / Identity owner", "Coverage report and remediation list", "All in-scope privileged and remote access protected or exception approved"),
        ("First 30 days", "Publish incident reporting route and escalation tree", "Security Lead", "Contact sheet and short response procedure", "Staff can identify reporting route; contacts tested"),
        ("First 30 days", "Inventory critical systems and backup coverage", "IT Operations / Business owners", "Critical asset and backup register", "All identified critical services have named owners and backup status"),
        ("First 30 days", "Triage exposed critical vulnerabilities", "IT Operations", "Prioritized remediation tracker", "Critical exposures mitigated or formally risk-accepted"),
        ("Days 31-60", "Publish data classification and handling standard", "Data owners / Privacy", "Approved classification matrix", "High-value repositories assigned a class and owner"),
        ("Days 31-60", "Implement joiner-mover-leaver workflow", "HR / IT", "Process and ticket evidence", "Access removal tracked and completed within defined target"),
        ("Days 31-60", "Define patch service levels and exception rules", "IT Operations / Security", "Vulnerability standard", "Overdue critical/high items visible and assigned"),
        ("Days 31-60", "Establish endpoint baseline and compliance reporting", "Endpoint owner", "Configuration standard and dashboard", "Coverage and non-compliance trend measured"),
        ("Days 31-60", "Assess critical suppliers", "Procurement / IT / Legal", "Supplier risk register", "Critical suppliers risk-rated and contract gaps tracked"),
        ("Days 61-90", "Centralize priority security logs and alert handling", "Security / IT", "Log-source register and response procedure", "Critical log sources reporting and alerts assigned"),
        ("Days 61-90", "Perform access recertification", "System owners", "Signed access review records", "High-risk access reviewed and removals tracked"),
        ("Days 61-90", "Test restoration of critical data/services", "IT Operations / Business owners", "Restore-test report", "Results meet approved recovery objectives or gaps have plans"),
        ("Days 61-90", "Run incident tabletop exercise", "Security Lead / Management", "Scenario, attendance and lessons learned", "Actions assigned with due dates"),
        ("Days 61-90", "Approve updated policy and communicate changes", "Policy owner / HR", "Versioned policy and acknowledgement", "Relevant staff notified and acknowledgement tracked"),
        ("3-6 months", "Extend automated asset, vulnerability and endpoint compliance reporting", "IT Operations", "Automated reports", "Coverage trend reported monthly"),
        ("3-6 months", "Introduce risk-based supplier reassessments and vendor-access reviews", "Procurement", "Reassessment schedule", "Critical suppliers reassessed on schedule"),
        ("3-6 months", "Improve detection coverage for identity, email, endpoints and critical cloud services", "Security / IT", "Detection coverage report", "Coverage gaps closed"),
        ("3-6 months", "Run a ransomware or business-disruption recovery exercise", "Security Lead", "Exercise report", "Dependencies validated"),
        ("3-6 months", "Review privacy, retention and incident reporting requirements with qualified advisers", "Legal / Privacy", "Advice record", "Obligations register updated"),
        ("3-6 months", "Use metrics and internal assurance to revise controls", "Policy owner", "Quarterly review minutes", "Controls revised from observed performance"),
    ]
    _many(conn, "INSERT INTO policy_actions(phase,action,owner,deliverable,success_measure,status) VALUES(?,?,?,?,?,'Not started')", actions)

    metrics = [  # name, definition, target text, target value, unit, direction, cadence, owner
        ("MFA coverage", "Percentage of in-scope accounts protected by MFA", "100% of privileged and remote accounts; monthly", 100, "%", "higher", "Monthly", "Identity owner"),
        ("Privileged access review", "Percentage of privileged accounts reviewed on schedule", "100% quarterly", 100, "%", "higher", "Quarterly", "System owners"),
        ("Critical patch compliance", "Critical findings remediated within approved target", "At least 95%; all exceptions visible", 95, "%", "higher", "Monthly", "IT Operations"),
        ("Endpoint management coverage", "Managed endpoints reporting current security status", "At least 95% of eligible endpoints", 95, "%", "higher", "Monthly", "Endpoint owner"),
        ("Backup restore success", "Successful tests against scheduled restoration tests", "100% of critical restore tests or corrective plan", 100, "%", "higher", "Quarterly", "IT Operations"),
        ("Incident acknowledgement", "Time from report receipt to initial triage", "Defined by severity (see Week 2 model); reviewed monthly", None, "", "lower", "Monthly", "Security Lead"),
        ("Security training completion", "Completion among required personnel", "At least 98% by due date", 98, "%", "higher", "Quarterly", "HR / Security"),
        ("Supplier assessment coverage", "Critical suppliers with current risk assessment", "100% of critical suppliers", 100, "%", "higher", "Quarterly", "Procurement"),
        ("Overdue policy exceptions", "Open exceptions past expiry or review date", "Zero overdue without reapproval", 0, "count", "lower", "Monthly", "Policy owner"),
        ("Incident exercise actions closed on time", "Lessons-learned actions closed by target date", "At least 90% on time", 90, "%", "higher", "After each exercise", "Security Lead"),
    ]
    _many(conn, "INSERT INTO policy_metrics(name,definition,target_text,target_value,current_value,unit,direction,cadence,owner,updated_at) VALUES(?,?,?,?,NULL,?,?,?,?,?)",
          [(n, d, t, tv, u, di, c, o, now) for n, d, t, tv, u, di, c, o in metrics])

    checklist = ["Is a policy owner and approving authority named?", "Is the review date and version history controlled?",
                 "Are scope, audience and responsibilities clear?", "Are MFA and privileged-access requirements explicit?",
                 "Are access approval, review and removal processes defined?", "Are information classes and handling rules defined?",
                 "Are encryption, retention and secure disposal addressed?", "Are endpoint and mobile security requirements measurable?",
                 "Are remote access and network security requirements defined?",
                 "Are vulnerability discovery, remediation deadlines and exceptions defined?",
                 "Are critical logs protected and monitored by assigned roles?",
                 "Are incident reporting, severity, escalation and evidence handling defined?",
                 "Are backups protected and restoration tests scheduled?", "Are RTOs/RPOs defined for critical services?",
                 "Are supplier onboarding, review and exit controls defined?", "Are awareness training and completion monitoring defined?",
                 "Is there a documented exception process with expiry dates?", "Are metrics and periodic assurance activities defined?"]
    _many(conn, "INSERT INTO policy_checklist(question) VALUES(?)", [(q,) for q in checklist])

    evidence = ["Current approved security policy, supporting standards, procedures and prior versions.",
                "Asset inventory, system owners, data inventory and critical service dependencies.",
                "Identity provider configuration and MFA coverage, privileged account list and access review records.",
                "Joiner-mover-leaver tickets, account disablement records and service-account register.",
                "Endpoint management reports, encryption status, EDR/antivirus coverage and device inventory.",
                "Vulnerability scan summaries, patch compliance reports, remediation tickets and approved exceptions.",
                "Network diagrams, remote-access configuration, firewall review records and cloud security baselines.",
                "Logging source list, retention settings, alert queue records and incident triage samples.",
                "Incident register, response playbooks, exercise reports, post-incident reviews and communications templates.",
                "Backup schedules, backup access controls, restoration test records and continuity plans.",
                "Security awareness curriculum, completion reports and phishing-reporting metrics.",
                "Supplier register, security assessments, contract security clauses and vendor access reviews.",
                "Policy exception register, risk register, internal audit reports and management review minutes."]
    _many(conn, "INSERT INTO evidence_requests(item) VALUES(?)", [(e,) for e in evidence])

    statements = [
        ("Access control", "Access to information and systems shall be approved by the relevant owner, limited to business need and reviewed periodically. Access shall be removed or adjusted promptly when a person changes role or no longer requires it."),
        ("Authentication", "MFA shall be required for privileged access, remote access and critical services, and for other systems where supported and proportionate. Credentials must not be shared; approved password-management methods shall be used."),
        ("Data handling", "Information shall be classified and handled according to its sensitivity. Sensitive information may be stored or shared only through approved services and protected using controls appropriate to its classification."),
        ("Endpoint security", "Company-managed endpoints shall use supported software, approved security protection, encryption where appropriate, screen locking and centrally managed configuration. Security controls must not be disabled without authorization."),
        ("Vulnerability management", "Assets shall be assessed for vulnerabilities on a risk-based schedule. Remediation deadlines shall reflect severity, exploitability and business criticality. Exceptions must be approved, documented and time-limited."),
        ("Incident reporting", "Employees and contractors shall promptly report suspected security incidents through the approved channel. Reports made in good faith shall be handled promptly and confidentially to the extent practicable."),
        ("Logging", "Security-relevant logs for critical systems shall be protected, retained according to an approved schedule and reviewed or alerted on by assigned personnel."),
        ("Backup and recovery", "Critical information and systems shall be backed up according to approved business recovery requirements. Restoration shall be tested periodically and corrective actions tracked."),
        ("Third parties", "Suppliers with access to company systems or information shall be risk-assessed before access is granted and periodically thereafter. Access shall be limited, monitored and revoked when no longer required."),
        ("Training", "Personnel shall complete security awareness training at onboarding and periodically thereafter. Personnel in higher-risk roles shall receive role-specific instruction."),
        ("Exceptions", "Exceptions to this policy require documented business justification, risk assessment, compensating controls, authorized approval and an expiry date."),
        ("Review", "The policy shall be reviewed at least annually and following material incidents, significant business or technology changes, or changes to applicable requirements."),
    ]
    _many(conn, "INSERT INTO policy_statements(topic,language) VALUES(?,?)", statements)

    # ---------------- Week 4 -------------------------------------------------
    conn.execute("INSERT INTO campaigns(name,tagline,start_date,eligible_employees,reached_count,completed_count,status,sponsor,owner) VALUES(?,?,?,?,0,0,'Planned',?,?)",
                 ("Pause. Check. Protect.", "Four-week security awareness campaign for Northstar Services Ltd.", None, 250, "Executive sponsor", "IT/Security Awareness Lead"))
    tasks = [
        (1, "Recognize", "Confirm stakeholders; take a baseline pulse and knowledge check; run an approved baseline simulation if available; launch the campaign.", "Launch email, campaign hub, \"spot the red flags\" visual.", "Baseline results, reach report, approved audience list."),
        (2, "Verify", "Deliver microlearning on phishing, social engineering, passwords and MFA; run the red-flag challenge; discuss invoice fraud in finance/procurement.", "Microlearning link, myth-buster card, manager talking points.", "Completion rate, quiz results, questions received."),
        (3, "Protect", "Cover data handling, devices, remote work, safe software and approved AI use; run a choose-your-response scenario.", "Data-sharing decision card, remote-work checklist, short scenario.", "Scenario response summary and common knowledge gaps."),
        (4, "Report and reinforce", "Demonstrate incident reporting; run a follow-up knowledge check and, if approved, a comparable simulation; gather feedback; recognize participation.", "Reporting demo, final reminder, survey and thank-you message.", "Post-campaign metrics, feedback summary and improvement actions."),
        (5, "30-day follow-up", "Review incident-reporting trends and outstanding actions; share a brief summary with leadership; plan quarterly refreshers.", "One-page results summary and next-step reminder.", "Action owner, due date and follow-up review date."),
    ]
    _many(conn, "INSERT INTO campaign_tasks(campaign_id,week,theme,activity,deliverable,evidence,owner,status) VALUES(1,?,?,?,?,?,'Security Awareness Lead','Not started')", tasks)
    segments = [
        ("All employees", 250, "Phishing, password reuse, MFA fatigue, unsafe links or attachments", "Short core module, practical examples, reporting instructions"),
        ("Finance and procurement", None, "Invoice fraud, fake supplier details, urgent payment requests", "Out-of-band verification checklist and scenario discussion"),
        ("HR and people managers", None, "Sensitive employee data, payroll scams, impersonation", "Data-handling reminders and identity verification practice"),
        ("Remote and mobile workers (70 employees)", 70, "Lost devices, public Wi-Fi risks, shoulder surfing, insecure home networks", "Device-lock, update, VPN/approved-access and travel reminders"),
        ("Customer-facing teams (30 employees)", 30, "Social engineering, disclosure of customer information", "Caller verification, minimum-necessary disclosure and escalation steps"),
        ("Office / hybrid staff (150 employees)", 150, "Phishing and everyday data handling", "Core module and weekly huddles"),
        ("Managers and champions", None, "Inconsistent messages or delayed escalation", "Briefing pack, talking points and clear incident pathway"),
    ]
    _many(conn, "INSERT INTO campaign_segments(name,headcount,risk,response) VALUES(?,?,?,?)", segments)
    topics = [
        ("Phishing and social engineering", "Pause when a message is unexpected, urgent, unusual or asks for secrets/money. Check the sender and destination carefully.", "Spot-the-red-flags email challenge"),
        ("Passwords and MFA", "Use a unique password or passphrase for each service, use an approved password manager, enable MFA, and never share codes or approve unexpected prompts.", "Password/MFA myth-versus-fact card"),
        ("Payment and account-change fraud", "Verify bank-detail, payroll and supplier changes using a known, separate contact method - not the details in the request.", "Two-minute invoice-fraud scenario"),
        ("Data classification and privacy", "Share only what is needed, with authorized recipients, using approved storage and sharing settings.", "\"Where should this file go?\" decision exercise"),
        ("Devices and remote work", "Lock screens, install approved updates promptly, protect devices physically, and use approved secure access.", "Desk-side or remote-work checklist"),
        ("Safe browsing and software", "Use approved applications; do not bypass security warnings or install unapproved tools/extensions.", "Choose-the-safe-action quiz"),
        ("Incident reporting", "Report quickly - even if you clicked, sent data to the wrong person, or approved a suspicious prompt. Early reporting helps limit harm.", "Practice using the real report button or help-desk route"),
        ("AI and information sharing", "Do not paste confidential, personal or customer data into unapproved AI tools; verify AI-generated content and follow organizational policy.", "Data-sharing do/don't examples"),
    ]
    _many(conn, "INSERT INTO campaign_topics(topic,takeaway,activity) VALUES(?,?,?)", topics)
    channels = [
        ("Launch email", "One concise email with campaign purpose, dates and reporting route", "Communications + Security", "Plain language, mobile-readable, links described clearly"),
        ("Intranet campaign hub", "Central page with materials, FAQ, reporting instructions and module link", "IT + Communications", "Single source of truth; accessible headings and captions"),
        ("Microlearning", "One 8-12 minute module plus a short quiz", "Security Awareness Lead", "Captions/transcript; allow completion during work time"),
        ("Team huddles", "5-minute discussion once per week", "People managers / champions", "Written talking points for shift and remote teams"),
        ("Posters / digital signage", "One visual reminder per week in common spaces and collaboration channels", "Communications", "High contrast, minimal text, digital alternative"),
        ("Collaboration messages", "Weekly short tip with one action", "Security champions", "Avoid excessive notifications; repeat the reporting route"),
        ("Safe phishing simulation", "One baseline and one follow-up simulation, if approved", "Security / IT", "No credential collection; private aggregate reporting"),
        ("Feedback pulse", "Three-question anonymous survey at campaign end", "HR + Security", "Optional comment field and non-retaliation statement"),
    ]
    _many(conn, "INSERT INTO campaign_channels(channel,cadence,owner,accessibility) VALUES(?,?,?,?)", channels)
    quiz = [
        ("An email asks you to sign in urgently through a link. What is the safest first action?",
         ["Click because the message is urgent", "Check the sender and destination, then use a trusted route to verify", "Forward it to colleagues"], 1,
         "Urgency is a classic red flag. Verify through a trusted route before acting."),
        ("A colleague asks you to share your MFA code to fix an access problem. What should you do?",
         ["Share it once", "Send it in chat", "Never share the code; verify and report the request"], 2,
         "MFA codes must never be shared. Report the request."),
        ("A supplier emails new bank details. What should you do before payment?",
         ["Verify via a known, separate contact method", "Reply to the email only", "Pay quickly to avoid delay"], 0,
         "Use a known, separate contact method - not details supplied in the request."),
        ("You accidentally send a file to the wrong recipient. What is the best response?",
         ["Wait to see if anyone notices", "Promptly report it through the approved incident route", "Delete your sent message and say nothing"], 1,
         "Early reporting limits harm; mistakes are handled without blame."),
        ("You are unsure whether an AI tool is approved for customer data. What should you do?",
         ["Paste a small sample", "Remove the customer name only and proceed", "Check policy or ask Security before sharing data"], 2,
         "Do not share confidential or customer data with unapproved tools; check policy or ask Security."),
    ]
    _many(conn, "INSERT INTO quiz_questions(position,question,options,correct_index,explanation) VALUES(?,?,?,?,?)",
          [(i, q, json.dumps(o), c, e) for i, (q, o, c, e) in enumerate(quiz, 1)])

    # ---------------- Week 5 -------------------------------------------------
    assets = [
        ("Employee laptops and desktops (Windows)", "Endpoint", "IT Operations", "High", "Internal", "Windows 10/11", "Supported"),
        ("Business application servers", "Server", "Infrastructure Team", "High", "Internal", "On-premises", "Supported"),
        ("Remote-access gateway", "Network", "Network team", "Critical", "Internet-facing", "VPN / remote access", "Supported"),
        ("Cloud email and collaboration", "Cloud", "Messaging Administrator", "Critical", "Internet-facing", "SaaS", "Supported"),
        ("Shared drives and file collaboration spaces", "Cloud", "Data Owners / IT", "High", "Internet-facing", "SaaS", "Supported"),
        ("Backup repository and console", "Server", "Infrastructure Team", "Critical", "Internal", "Backup platform", "Supported"),
        ("Identity provider / directory", "Cloud", "Identity Administrator", "Critical", "Internet-facing", "SaaS", "Supported"),
        ("Office firewall and switching", "Network", "Network team", "High", "Internet-facing", "Network equipment", "Supported"),
    ]
    _many(conn, "INSERT INTO assets(name,type,owner,criticality,exposure,platform,support_status,notes) VALUES(?,?,?,?,?,?,?,'Illustrative asset from the Week 5 training scenario')", assets)

    def due(days):
        return (date.fromisoformat(ASSESS_DATE) + timedelta(days=days)).isoformat()
    vulns = [
        ("VA-01", "Inconsistent security patching", "High", "High", "High", "High", "IT Operations", 14, 1,
         "The hypothetical environment has no consistently enforced patch service-level agreement, and a subset of endpoints or servers may lag behind approved security updates. Older software can expose known weaknesses that attackers may use to gain a foothold or escalate access.",
         "Malware infection, unauthorized access, service disruption, data exposure, and increased recovery costs. Unsupported software may be especially difficult to secure.",
         "Create a complete inventory of operating systems, applications, versions, owners and support status. Deploy centralized patch management with emergency handling for actively exploited vulnerabilities. Risk-based targets: critical exploited issues within 72 hours where feasible; other critical within 7 days; high within 14 days; routine within 30 days. Test on a pilot group with rollback plans; report exceptions to the IT manager. Replace or isolate unsupported systems.",
         "Patch-compliance dashboard, exception register, and a follow-up scan showing identified versions are remediated."),
        ("VA-02", "MFA not enforced for all remote and privileged access", "Critical", "High", "High", "High", "Identity Administrator", 7, 3,
         "MFA is assumed to be enabled for most users but not consistently required for every remote-access path or privileged account. Password-only access is more vulnerable to credential theft, reuse and phishing.",
         "Account takeover, unauthorized remote access, privilege abuse, access to confidential files, and ransomware deployment.",
         "Enforce MFA for all remote access, cloud applications, administrators and sensitive workflows; prioritize phishing-resistant methods for privileged users. Remove legacy authentication paths; restrict administrator accounts to managed devices. Review privileged roles and service accounts; store secrets in an approved vault. Alert on suspicious sign-ins, repeated failures, new device registrations and authentication-method changes. Document an account-recovery process without help-desk shortcuts that bypass MFA.",
         "Identity-policy export, test sign-ins for representative accounts, and confirmation that privileged accounts cannot access in-scope services without MFA."),
        ("VA-03", "Overly broad permissions on shared folders", "High", "Medium-High", "High", "High", "Data Owners / IT", 14, 5,
         "Some shared folders or cloud collaboration spaces may grant broad groups read or edit access beyond their business need. External sharing links may remain active longer than necessary.",
         "Accidental disclosure, unauthorized alteration or deletion of business records, privacy incidents, and loss of customer trust.",
         "Apply least privilege using role- or group-based access and assign a business owner to each sensitive repository. Review public links, external guests, inherited permissions and stale accounts. Separate highly sensitive data into restricted locations and enable audit logging for sharing and permission changes. Schedule quarterly access reviews with owner certification.",
         "Approved access-review records, a sample of permission reports, and confirmation that anonymous links are disabled or explicitly justified."),
        ("VA-04", "Incomplete endpoint detection and centralized logging", "High", "Medium", "High", "Medium-High", "Security Operations", 30, 1,
         "Endpoint protection coverage and security-event collection may be inconsistent across laptops and servers, delaying detection and making investigation difficult.",
         "A compromised device may remain unnoticed, spread malware, or allow an intruder to maintain access for longer.",
         "Enroll all supported endpoints and servers in centrally managed endpoint protection with tamper protection. Collect identity, endpoint, email, firewall, VPN and cloud audit events centrally. Define alerting for malware detections, privilege changes, disabled security tools, unusual sign-ins and large data transfers. Document triage responsibilities and retention. Test alert delivery with a tabletop exercise.",
         "Asset-to-agent coverage report, recent log-ingestion checks, and a recorded test alert that reaches the assigned responder."),
        ("VA-05", "Backup isolation and restore-testing gaps", "High", "Medium", "High", "High", "Infrastructure Team", 14, 6,
         "Backups may exist but could share administrative credentials or network access with production systems, and restoration may not be tested on a reliable schedule.",
         "Ransomware or administrator compromise could affect both production data and backups, extending downtime and increasing the risk of permanent data loss.",
         "Maintain protected, immutable or offline copies of critical backups with separate administrative credentials. Apply MFA and least privilege to backup consoles and monitor deletion, retention and configuration changes. Define RTO/RPO with business owners. Test restoration at least quarterly and after major architecture changes. Keep recovery procedures and emergency contacts where they are accessible during an outage.",
         "Successful restore-test record, protected-backup configuration, and approved RTO/RPO documentation."),
        ("VA-06", "Email authentication and phishing controls need improvement", "Medium", "Medium-High", "Medium-High", "Medium-High", "Messaging Administrator", 30, 4,
         "Email authentication settings and anti-phishing controls may not be fully tuned. Employees may also lack a simple, well-publicized way to report suspicious messages.",
         "Business email compromise, credential theft, fraudulent payments, malware delivery, and reputational harm.",
         "Inventory legitimate sending services and configure SPF and DKIM; move DMARC toward enforcement after monitoring. Enable anti-phishing, malicious-link, attachment and impersonation protections. Provide a one-step phishing-reporting mechanism. Use short, role-relevant awareness exercises and measure reporting rates without shaming individuals. Require independent verification for payment-instruction changes.",
         "Email-authentication reports, policy configuration, and a test confirming a reported message reaches the security mailbox or ticket queue."),
    ]
    for ref, title, sev, lik, imp, prio, owner, tdays, aid, obs, pot, rec, ver in vulns:
        conn.execute("""INSERT INTO vuln_findings(ref,title,severity,likelihood,impact,priority,owner,target_days,identified_on,due_date,status,
                        observation,potential_impact,recommendations,verification_required,asset_id,actively_exploited,created_at,updated_at)
                        VALUES(?,?,?,?,?,?,?,?,?,?,'Open',?,?,?,?,?,0,?,?)""",
                     (ref, title, sev, lik, imp, prio, owner, tdays, ASSESS_DATE, due(tdays), obs, pot, rec, ver, aid, now, now))
    roadmap = [
        ("First 7 days", "Enforce MFA for privileged and remote access; review emergency access; confirm protected backups; identify actively exploited patch gaps.", "MFA coverage confirmed; critical exceptions assigned; backup controls reviewed."),
        ("Days 8-14", "Patch priority systems; remove excessive shared-folder access; validate backup restoration; remediate unsupported software where possible.", "Critical/high-risk patch backlog reduced; access review signed off; restore test completed."),
        ("Days 15-30", "Improve endpoint agent coverage and log collection; tune alerts; strengthen email authentication and phishing reporting.", "Coverage dashboards meet agreed targets; test alerts and email controls verified."),
        ("Days 31-60", "Complete broader configuration review, document exceptions, train owners, and conduct retesting.", "Findings closed or formally accepted; evidence attached to each closure."),
        ("Quarterly", "Repeat access reviews, restore tests, patch reporting, and risk review.", "Metrics reviewed by IT leadership and tracked over time."),
    ]
    _many(conn, "INSERT INTO vuln_roadmap(timeframe,actions,success_measure,sort_order) VALUES(?,?,?,?)", [r + (i,) for i, r in enumerate(roadmap, 1)])
    vmetrics = [
        ("MFA coverage for privileged and remote access", "100% except documented, time-limited exceptions", 100, "%", "higher", "Weekly until complete"),
        ("Critical security updates within emergency SLA", "Within approved emergency SLA; 72 hours for actively exploited issues where feasible", 100, "%", "higher", "Weekly"),
        ("High-risk patch compliance", "At least 95% within the agreed 14-day target", 95, "%", "higher", "Weekly"),
        ("Managed endpoint protection coverage", "At least 98% of supported in-scope endpoints", 98, "%", "higher", "Weekly"),
        ("Sensitive repository access reviews", "100% of designated repositories reviewed quarterly", 100, "%", "higher", "Quarterly"),
        ("Successful backup restore tests", "All critical services tested to approved RTO/RPO", 100, "%", "higher", "Quarterly"),
        ("Critical/High findings closed or formally risk-accepted", "All Critical/High findings closed or formally risk-accepted with compensating controls", 100, "%", "higher", "Monthly"),
    ]
    _many(conn, "INSERT INTO vuln_metrics(name,target_text,target_value,current_value,unit,direction,cadence,updated_at) VALUES(?,?,?,NULL,?,?,?,?)",
          [(n, t, tv, u, d, c, now) for n, t, tv, u, d, c in vmetrics])

    # ---------------- Week 6 -------------------------------------------------
    cal = [
        (1, "Program planning and governance", "Confirm scope, risks, criteria, owners, prior findings, and audit calendar; approve annual plan.", "Tier 3 - Standard"),
        (2, "Identity and access", "Sample user lifecycle records, MFA coverage, privileged roles, service accounts, and access reviews.", "Tier 1 - Critical"),
        (3, "Vulnerability and patch management", "Review asset inventory, scan coverage, patch compliance, exceptions, and remediation evidence.", "Tier 1 - Critical"),
        (4, "Endpoint and server security", "Sample hardening, encryption, endpoint agent coverage, local admin rights, and logging.", "Tier 2 - High"),
        (5, "Network and remote access", "Review firewall change approvals, segmentation, VPN settings, and management access.", "Tier 1 - Critical"),
        (6, "Cloud and application security", "Review cloud configuration, external sharing, application access, and change management.", "Tier 2 - High"),
        (7, "Data protection and privacy", "Check classification, encryption, retention, data sharing, and access to sensitive repositories.", "Tier 1 - Critical"),
        (8, "Incident response", "Review incident playbooks, escalation lists, evidence handling, tabletop exercise, and lessons learned.", "Tier 2 - High"),
        (9, "Backup and business continuity", "Inspect backup permissions and protection; witness or review restore tests and recovery objectives.", "Tier 1 - Critical"),
        (10, "Supplier and third-party risk", "Review critical supplier inventory, due diligence, contract clauses, and vendor access.", "Tier 2 - High"),
        (11, "Awareness and policy effectiveness", "Review training coverage, phishing reporting, policy exceptions, and awareness outcomes.", "Tier 3 - Standard"),
        (12, "Annual closure and follow-up", "Retest high-priority findings, report risk trends, document accepted risks, and draft next year's plan.", "Event-driven"),
    ]
    _many(conn, "INSERT INTO audit_calendar(month,focus,activities,tier) VALUES(?,?,?,?)", cal)
    ac = ["A current inventory of hardware, software, cloud services, and system owners exists.",
          "Privileged and remote access require MFA, with exceptions documented and approved.",
          "User access is removed promptly when employment or business need ends.",
          "Critical vulnerabilities and patch exceptions are tracked to closure.",
          "Endpoint protection, device encryption, and centralized logging cover in-scope assets.",
          "Firewall and remote-access changes are approved and periodically reviewed.",
          "Sensitive repositories use least-privilege access and appropriate sharing controls.",
          "Backup copies are protected and critical restoration procedures are tested.",
          "Incident response roles and escalation contacts are current and exercised.",
          "Critical suppliers are assessed and vendor access is reviewed.",
          "Employees receive relevant security training and can report suspicious messages.",
          "Previous audit findings have verified closure or documented risk acceptance."]
    _many(conn, "INSERT INTO audit_checklist(item) VALUES(?)", [(x,) for x in ac])
    kpis = [("Audit plan completion", "At least 90% of planned audits completed or formally rescheduled with rationale", "Quarterly"),
            ("Critical/High actions overdue", "Zero without documented escalation and approved exception", "Monthly"),
            ("Finding remediation time", "Median days to closure by severity; trend compared quarter to quarter", "Quarterly"),
            ("Evidence quality", "100% of findings have evidence references, owner, rating, due date, and closure criteria", "Each audit"),
            ("Privileged access review", "All privileged accounts reviewed at least quarterly", "Quarterly"),
            ("Backup recovery validation", "Critical services tested against approved RTO/RPO at least annually; more often for high-risk services", "Quarterly/annual"),
            ("Repeat findings", "Track recurring issues and root causes; reduce repeat High/Critical findings year over year", "Quarterly"),
            ("Audit stakeholder feedback", "Collect concise feedback on clarity, feasibility, and value of recommendations", "After audit")]
    _many(conn, "INSERT INTO audit_kpis(name,target_text,review,updated_at) VALUES(?,?,?,?)", [k + (now,) for k in kpis])
    conn.commit()


def seed_demo(conn):
    """Clearly labelled illustrative operational data so charts and workflows are populated on first run."""
    if conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]:
        return
    now = now_iso()
    # Appendix A fictional timeline of the Week 2 plan (demonstration only)
    base = "2026-10-20T"
    conn.execute("""INSERT INTO incidents(ref,title,category,severity,status,started_at,reported_at,acknowledged_at,declared_at,contained_at,
                    reporter,triage_owner,incident_commander,affected_assets,observed_activity,business_impact,data_impact,cert_in_assessment,
                    is_demo,created_by,created_at,updated_at)
                    VALUES('IR-2026-001','(Demo) Phishing / BEC - suspicious invoice request','Phishing / BEC / account takeover','SEV-2','Contained',?,?,?,?,?,
                    'Service desk (SD-220)','Security on-call','Incident commander (demo)','One employee mailbox; pending supplier bank-detail change (F-33)',
                    'Email gateway flagged a suspicious invoice email (E-104); employee reported clicking a link and entering credentials; unusual sign-in and a new inbox rule observed.',
                    'Potential payment diversion; one mailbox affected so far.','Suspected','Not assessed',1,'system',?,?)""",
                 (base + "09:05:00Z", base + "09:05:00Z", base + "09:12:00Z", base + "09:18:00Z", base + "09:25:00Z", now, now))
    timeline = [
        ("09:05", "Email gateway flags suspicious invoice email", "Gateway alert E-104", "High", "Open case; assign triage owner"),
        ("09:12", "Employee reports clicking link and entering credentials", "Service desk ticket SD-220", "High", "Escalate to security; preserve message"),
        ("09:18", "Unusual sign-in and new inbox rule observed", "Identity and mail audit logs", "Medium", "Provisional SEV-2; notify IC"),
        ("09:25", "Sessions revoked and credentials reset through trusted process", "Identity admin audit", "High", "Verify no attacker-controlled recovery method"),
        ("09:40", "Finance confirms pending bank-detail change", "Finance ticket F-33", "High", "Stop change using verified contact method"),
        ("10:15", "Mailbox audit review finds no confirmed bulk export so far", "Mail audit query", "Medium", "Continue investigation; do not claim no data access"),
        ("13:00", "Search completed across similar indicators", "SIEM query reference Q-81", "Medium", "Scope updated; actions assigned"),
    ]
    _many(conn, "INSERT INTO incident_timeline(incident_id,event_time,event,source,confidence,interpretation) VALUES(1,?,?,?,?,?)",
          [(base + t + ":00Z", e, s, c, i) for t, e, s, c, i in timeline])
    _many(conn, "INSERT INTO incident_decisions(incident_id,decided_at,decision,rationale,approver,outcome) VALUES(1,?,?,?,?,?)",
          [(base + "09:18:00Z", "Classify as provisional SEV-2", "Credentials entered on a phishing page plus a new inbox rule indicates account compromise", "Security lead", "IC notified"),
           (base + "09:40:00Z", "Stop pending supplier bank-detail change", "Possible payment diversion; verified through known contact", "Finance lead", "Change blocked")])
    _many(conn, "INSERT INTO incident_actions(incident_id,title,priority,owner,due_date,status) VALUES(1,?,?,?,?,?)",
          [("Enforce MFA and review app-consent grants", "High", "Identity Administrator", "2026-10-27", "Open"),
           ("Add payment-change out-of-band verification step", "High", "Finance lead", "2026-11-03", "In Progress")])
    conn.execute("UPDATE incidents SET checklist15=? WHERE id=1", (json.dumps([0, 1, 2, 3, 5, 7, 8, 11]),))

    # anonymous awareness data (aggregate only)
    nowz = now
    for phase, scores in (("baseline", [2, 3, 2, 3, 1, 3, 2, 3, 2, 2]), ("post", [4, 5, 4, 3, 5, 4, 5, 4, 4, 5])):
        _many(conn, "INSERT INTO quiz_attempts(phase,segment,score,total,submitted_at) VALUES(?,?,?,5,?)", [(phase, "All employees", s, nowz) for s in scores])
    _many(conn, "INSERT INTO simulations(phase,run_date,sent,clicked,reported,notes) VALUES(?,?,?,?,?,?)",
          [("baseline", "2026-10-20", 250, 52, 38, "(Demo) Approved baseline simulation, no credentials collected"),
           ("follow_up", "2026-11-17", 250, 21, 91, "(Demo) Comparable follow-up simulation")])
    _many(conn, "INSERT INTO feedback(relevance,confidence,knows_reporting,comment,submitted_at) VALUES(?,?,?,?,?)",
          [(5, 4, 1, "(Demo) Short and practical.", nowz), (4, 4, 1, "", nowz), (4, 3, 1, "(Demo) More examples for finance, please.", nowz), (5, 5, 1, "", nowz), (3, 3, 0, "", nowz)])
    conn.execute("UPDATE campaigns SET reached_count=232, completed_count=214, status='Active', start_date='2026-10-20' WHERE id=1")
    conn.execute("UPDATE campaign_tasks SET status='Completed' WHERE week IN (1,2)")
    conn.execute("UPDATE campaign_tasks SET status='In progress' WHERE week=3")

    # audit module demo: January + February performed (illustrative)
    conn.execute("""INSERT INTO audits(ref,month,domain,control_objective,criteria,population,sample_size,period_covered,evidence_source,evidence_date,auditor,
                    test_procedure,result,risk_impact,limitations,status,planned_date,created_at,updated_at)
                    VALUES('AUD-2027-02-IAM',2,'Identity and access','Access is authorized, least-privileged and periodically reviewed',
                    'Security policy access-control statement; NIST CSF 2.0 PR.AA','All privileged accounts (illustrative) plus a risk-based sample of standard users','All privileged + 25 standard users',
                    'Q4 2026','Identity provider export; access review tickets','2026-10-20','Audit lead (demo)',
                    'Compared MFA policy export and access recertification records with the approved criteria','Partial','Privileged accounts without MFA enforcement increase account-takeover impact',
                    'Sampling does not prove every account complies. (Demo workpaper)','In Progress','2027-02-10',?,?)""", (now, now))
    conn.execute("""INSERT INTO audit_findings(ref,audit_id,title,severity,description,evidence_ref,recommendation,owner,identified_on,target_days,due_date,status,mgmt_response,
                    retest_result,is_repeat,created_at,updated_at)
                    VALUES('AF-001',1,'(Demo) Two privileged accounts lack MFA enforcement','High','Illustrative finding: two privileged accounts were not covered by the MFA policy.',
                    'EV-IAM-001 (policy export)','Enforce MFA for all privileged accounts and document any time-limited exception.','Identity Administrator','2026-10-20',30,'2026-11-19','Open',
                    'Accepted; fix scheduled','Not retested',0,?,?)""", (now, now))
    conn.commit()


def seed_all(path, with_demo=True):
    init_schema(path)
    conn = connect_standalone(path)
    try:
        seed_reference(conn)
        if with_demo:
            seed_demo(conn)
    finally:
        conn.close()
