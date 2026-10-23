'use strict';
/* Week 6 - Cybersecurity audit plan */
NS.pages.audits = async (root) => {
  const w = 'auditplan.write';
  const [domains, sevDefs, s] = await Promise.all([NS.getRef('audit_domains'), NS.getRef('audit_severity'), NS.api('/audit-summary')]);
  const SEV = sevDefs.map((x) => x.rating);
  const STATUS = ['Open', 'In Progress', 'Pending Verification', 'Closed', 'Risk Accepted'];
  const AST = ['Planned', 'In Progress', 'Completed', 'Rescheduled'];
  root.innerHTML = NS.head('Audit plan', 'A risk-based twelve-month audit calendar, evidence-backed workpapers, and findings tracked to verified closure.', '', 'Week 6') +
    `<div class="stat-row"><div class="stat"><div class="n">${s.plan_completion_pct ?? 0}%</div><div class="l">plan completed or rescheduled with rationale (target 90%)</div></div>
      <div class="stat"><div class="n">${s.findings_open}</div><div class="l">open findings</div></div>
      <div class="stat ${s.overdue_critical_high ? 'bad' : 'good'}"><div class="n">${s.overdue_critical_high}</div><div class="l">Critical/High overdue (escalate)</div></div>
      <div class="stat"><div class="n">${s.evidence_quality_pct ?? '-'}${s.evidence_quality_pct === null ? '' : '%'}</div><div class="l">findings with complete evidence fields</div></div>
      <div class="stat"><div class="n">${s.repeat_findings}</div><div class="l">repeat findings</div></div></div>`;
  NS.tabs(root, [
    { key: 'calendar', label: 'Annual calendar', render: async (el) => {
      const cal = (await NS.api('/audit-calendar')).items;
      el.innerHTML = `<p class="muted">Select a month to update its status. Rescheduling needs a documented rationale; completion is counted toward the 90% plan target.</p><div class="cal">${cal.map((c) => `<button class="cal-m ${NS.esc(c.status.replace(/ /g, '-'))}" data-id="${c.id}" type="button"><small>${NS.esc(c.month_name)}</small><b>${NS.esc(c.focus)}</b>${NS.chip(c.status)} <small>${NS.esc(c.tier || '')}</small></button>`).join('')}</div>`;
      $$('.cal-m', el).forEach((b) => b.addEventListener('click', () => {
        const c = cal.find((x) => String(x.id) === b.dataset.id);
        NS.editModal({ title: `${c.month_name}: ${c.focus}`, endpoint: 'audit-calendar', id: c.id, canWrite: NS.can(w), values: c, onSaved: () => NS.route(), intro: `<p class="muted">${NS.esc(c.activities || '')}</p>`,
          fields: [{ name: 'status', label: 'Status', type: 'select', options: AST, required: true }, { name: 'completed_on', label: 'Completed on', type: 'date' }, { name: 'reschedule_rationale', label: 'Reschedule rationale', type: 'textarea', full: true, hint: 'Required when rescheduled' }, { name: 'notes', label: 'Notes', type: 'textarea', full: true }] });
      }));
    } },
    { key: 'workpapers', label: 'Audits and workpapers', render: async (el) => {
      const tpl = await NS.getRef('workpaper_template');
      el.innerHTML = `<details class="pb"><summary><b>Workpaper template</b></summary>${NS.simpleTable(['Element', 'What to record'], tpl.map((t) => [`<b>${NS.esc(t[0])}</b>`, NS.esc(t[1])]), { wrap: [1] })}</details><div data-table></div>`;
      await NS.crudTable($('[data-table]', el), { endpoint: 'audits', noun: 'audit', write: w, canDelete: true, sort: 'month', wide: true,
        filters: [{ key: 'status', label: 'Status', options: AST }, { key: 'result', label: 'Result', options: ['Pass', 'Partial', 'Fail', 'Not tested'] }],
        columns: [{ label: 'Ref', render: (r) => `<b>${NS.esc(r.ref)}</b>` }, { label: 'Domain', key: 'domain', wrap: true }, { label: 'Control objective', key: 'control_objective', wrap: true }, { label: 'Auditor', key: 'auditor' },
          { label: 'Planned', render: (r) => NS.fmtD(r.planned_date) }, { label: 'Result', render: (r) => NS.chip(r.result) }, { label: 'Status', render: (r) => NS.chip(r.status) }],
        fields: [{ name: 'ref', label: 'Reference', hint: 'Blank = auto' }, { name: 'domain', label: 'Audit domain', type: 'select', options: domains, required: true }, { name: 'control_objective', label: 'Control objective', type: 'textarea', full: true },
          { name: 'criteria', label: 'Criteria (policy, framework, contract)', type: 'textarea', full: true }, { name: 'population', label: 'Population', type: 'textarea', full: true }, { name: 'sample_size', label: 'Sample size' }, { name: 'period_covered', label: 'Period covered' },
          { name: 'evidence_source', label: 'Evidence source', type: 'textarea', full: true }, { name: 'evidence_date', label: 'Evidence collected on', type: 'date' }, { name: 'auditor', label: 'Auditor' },
          { name: 'test_procedure', label: 'Test procedure', type: 'textarea', full: true }, { name: 'result', label: 'Result', type: 'select', options: ['Pass', 'Partial', 'Fail', 'Not tested'], required: true, default: 'Not tested' },
          { name: 'status', label: 'Status', type: 'select', options: AST, required: true, default: 'Planned' }, { name: 'risk_impact', label: 'Risk and impact', type: 'textarea', full: true }, { name: 'limitations', label: 'Limitations', type: 'textarea', full: true },
          { name: 'month', label: 'Calendar month (1-12)', type: 'number', step: 1, min: 1, max: 12 }, { name: 'planned_date', label: 'Planned date', type: 'date' }] });
    } },
    { key: 'findings', label: 'Findings and follow-up', render: async (el) => {
      const audits = (await NS.api('/audits')).items;
      const aopts = [{ v: '', l: 'Not linked' }, ...audits.map((a) => ({ v: a.id, l: `${a.ref} - ${a.domain}` }))];
      el.innerHTML = `<details class="pb"><summary><b>Severity ratings and remediation targets</b></summary>${NS.simpleTable(['Rating', 'Definition', 'Response'], sevDefs.map((x) => [NS.chip(x.rating), NS.esc(x.definition), NS.esc(x.response)]), { wrap: [1, 2] })}</details><div data-table></div>`;
      await NS.crudTable($('[data-table]', el), { endpoint: 'audit-findings', noun: 'finding', write: w, canDelete: true, sort: 'due_date', exportName: 'audit-findings', wide: true,
        filters: [{ key: 'severity', label: 'Severity', options: SEV }, { key: 'status', label: 'Status', options: STATUS }],
        columns: [{ label: 'Ref', render: (r) => `<b>${NS.esc(r.ref)}</b>${r.is_repeat ? '<div>' + NS.chip('Repeat', 'warn') + '</div>' : ''}` }, { label: 'Finding', key: 'title', wrap: true }, { label: 'Severity', render: (r) => NS.chip(r.severity) }, { label: 'Owner', key: 'owner' },
          { label: 'Due', render: (r) => NS.fmtD(r.due_date) + (r.escalation ? '<div>' + NS.chip('ESCALATE', 'danger') + '</div>' : r.overdue ? '<div>' + NS.chip('OVERDUE', 'danger') + '</div>' : '') },
          { label: 'Retest', render: (r) => (r.retest_required ? NS.chip(r.retest_result) : '<span class="muted">n/a</span>') }, { label: 'Status', render: (r) => NS.chip(r.status) }],
        fields: [{ name: 'ref', label: 'Reference', hint: 'Blank = auto' }, { name: 'severity', label: 'Severity', type: 'select', options: SEV, required: true, default: 'Medium' }, { name: 'title', label: 'Finding', required: true, full: true },
          { name: 'audit_id', label: 'Related audit', type: 'select', options: aopts }, { name: 'owner', label: 'Accountable owner' }, { name: 'identified_on', label: 'Identified on', type: 'date' },
          { name: 'target_days', label: 'Target days', type: 'number', step: 1, min: 1, hint: 'Blank = default for severity (7 / 30 / 60 / 180)' },
          { name: 'description', label: 'Description (facts)', type: 'textarea', full: true }, { name: 'evidence_ref', label: 'Evidence reference', full: true }, { name: 'recommendation', label: 'Recommendation and closure criteria', type: 'textarea', full: true },
          { name: 'mgmt_response', label: 'Management response', type: 'textarea', full: true }, { name: 'status', label: 'Status', type: 'select', options: STATUS, required: true, default: 'Open' },
          { name: 'retest_result', label: 'Retest result', type: 'select', options: ['Not retested', 'Pass', 'Fail'], required: true, default: 'Not retested', hint: 'Critical/High must pass before closure' },
          { name: 'closure_evidence', label: 'Closure evidence', type: 'textarea', full: true }, { name: 'accept_rationale', label: 'Risk acceptance: rationale', type: 'textarea', full: true }, { name: 'accept_approver', label: 'Risk acceptance: approver' },
          { name: 'accept_expiry', label: 'Risk acceptance: expires', type: 'date' }, { name: 'is_repeat', label: 'Repeat of an earlier finding', type: 'checkbox', full: true }] });
    } },
    { key: 'kpis', label: 'KPIs', render: async (el) => {
      const med = s.median_days_to_close;
      el.innerHTML = `<section class="panel"><h2>Computed from the data</h2>${NS.simpleTable(['Measure', 'Value', 'Target'], [
        ['Audit plan completion', `<b>${s.plan_completion_pct ?? 0}%</b>`, 'At least 90% completed or formally rescheduled with rationale'],
        ['Critical/High findings overdue', `<b>${s.overdue_critical_high}</b>`, 'Zero without documented escalation and approved exception'],
        ['Median days to closure', SEV.filter((x) => x !== 'Observation').map((x) => `${x}: ${med[x] === null ? '-' : med[x]}`).join(' &nbsp; '), 'Trend by severity, quarter over quarter'],
        ['Evidence quality', `<b>${s.evidence_quality_pct ?? '-'}${s.evidence_quality_pct === null ? '' : '%'}</b>`, '100% of findings have evidence reference, owner, rating, due date and closure criteria'],
        ['Repeat findings', `<b>${s.repeat_findings}</b>`, 'Reduce repeat High/Critical findings year over year']], { wrap: [2] })}</section>
        <section class="panel"><h2>Tracked manually</h2><div data-k></div></section>`;
      await NS.crudTable($('[data-k]', el), { endpoint: 'audit-kpis', noun: 'KPI', write: w, canDelete: true, search: false, wide: true,
        columns: [{ label: 'KPI', render: (r) => `<b>${NS.esc(r.name)}</b>` }, { label: 'Target', key: 'target_text', wrap: true }, { label: 'Review', key: 'review' }, { label: 'Current', key: 'current_text', wrap: true }],
        fields: [{ name: 'name', label: 'KPI', required: true, full: true }, { name: 'target_text', label: 'Target', type: 'textarea', full: true }, { name: 'review', label: 'Review frequency' }, { name: 'current_text', label: 'Current value / notes', type: 'textarea', full: true }] });
    } },
    { key: 'checklist', label: 'Readiness checklist', render: (el) => NS.crudTable(el, { endpoint: 'audit-checklist', noun: 'checklist item', write: w, canDelete: true, wide: true, filters: [{ key: 'answer', label: 'Answer', options: ['Unanswered', 'Yes', 'Partially', 'No', 'N/A'] }],
      columns: [{ label: 'Control to confirm', key: 'item', wrap: true }, { label: 'Answer', render: (r) => NS.chip(r.answer) }, { label: 'Evidence', key: 'evidence', wrap: true }],
      fields: [{ name: 'item', label: 'Control to confirm', type: 'textarea', required: true, full: true }, { name: 'answer', label: 'Answer', type: 'select', options: ['Unanswered', 'Yes', 'Partially', 'No', 'N/A'], required: true, default: 'Unanswered' }, { name: 'evidence', label: 'Evidence / notes', type: 'textarea', full: true }] }) },
    { key: 'reference', label: 'Program reference', render: async (el) => {
      const [tiers, wf, roles, risks] = await Promise.all([NS.getRef('audit_tiers'), NS.getRef('audit_workflow'), NS.getRef('audit_roles'), NS.getRef('audit_program_risks')]);
      el.innerHTML = `<section class="panel"><h2>Risk tiers and audit frequency</h2>${NS.simpleTable(['Tier', 'Examples', 'Frequency'], tiers.map((t) => [`<b>${NS.esc(t.tier)}</b>`, NS.esc(t.example), NS.esc(t.frequency)]), { wrap: [1, 2] })}</section>
        <section class="panel"><h2>Audit workflow</h2><ol class="clean">${wf.map((x) => `<li>${NS.esc(x)}</li>`).join('')}</ol></section>
        <section class="panel"><h2>Roles</h2>${NS.simpleTable(['Role', 'Responsibility'], roles.map((r) => [`<b>${NS.esc(r.role)}</b>`, NS.esc(r.responsibility)]), { wrap: [1] })}</section>
        <section class="panel"><h2>Program risks</h2>${NS.simpleTable(['Risk', 'Impact', 'Mitigation'], risks.map((r) => [NS.esc(r[0]), NS.esc(r[1]), NS.esc(r[2])]), { wrap: [0, 1, 2] })}</section>`;
    } },
  ]);
};
