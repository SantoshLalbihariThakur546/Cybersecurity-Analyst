# How each weekly assignment is implemented

| Week | Document deliverable | Where it lives in the platform |
|---|---|---|
| 1 Threat Landscape Analysis | Threat actors, 10 threat categories, attack chain, likelihood x impact scale, 10 scored scenarios, defensive priorities (30 days / 30-90 days / 3-12 months), evidence sources and research log | **Threat landscape**: register with scenario map, actors, categories, attack chain and scale, defensive priorities, evidence sources, research log |
| 2 Incident Response Plan | Severity model, roles, lifecycle, first-15-minute and first-24-hour checklists, five playbooks, evidence register, decision log, timeline, CERT-In planning note, closure criteria, post-incident report template, metrics | **Incident response**: live register with acknowledgement clock, incident workspace (overview, timeline, evidence with SHA-256, decisions, corrective actions, checklists, playbook), plan reference tab, generated post-incident report |
| 3 Security Policy Review | 13 control areas with ratings, 10-risk register (L x I), 30/60/90-day roadmap, exception process and register, 10 metrics, review checklist, evidence requests, suggested policy statements | **Policy review**: control assessment, risk register with matrix, roadmap with phase progress, exceptions, metrics, checklist and evidence requests, reference |
| 4 Awareness Campaign Plan | "Pause. Check. Protect." four-week schedule, audience segments, topics, channels, messages, 4 objectives, 5-question knowledge check with answer key, simulation and feedback measures, risks and guardrails | **Awareness campaign**: objectives dashboard computed from real data, schedule, anonymous quiz, simulations and feedback pulse, audience and content, quiz management |
| 5 Vulnerability Assessment | 6 findings VA-01 to VA-06 with severity, owner, target, evidence; asset inventory; remediation roadmap; 7 metrics; patch service levels | **Vulnerability assessment**: findings with automatic due dates and overdue flags, assets, roadmap, metrics, remediation-target calculator |
| 6 Cybersecurity Audit Plan | 12-month calendar, risk tiers, workflow, workpaper template, severity and follow-up rules, 8 KPIs, 12-point readiness checklist, program risks | **Audit plan**: annual calendar, workpapers, findings with retest and escalation rules, KPIs (computed and manual), readiness checklist, program reference |

Content is transcribed from the six uploaded documents. The Week 3-6 organization (Northstar Services Ltd.) and its findings are the documents' hypothetical scenario. Demo records are labelled "(Demo)" and can be removed with `SEED_DEMO_DATA=false`.

Two judgement calls worth knowing about:

* Week 3 lists 12 control areas in its overall table but describes a 13th topic (secure change management and application security) in section 7.13 without rating it. It is included as **Not assessed**.
* Week 1's likelihood/impact ratings are documented expert judgments. The platform stores the document's indicative rating and also shows a computed score (likelihood x impact) purely as a prioritisation aid.
