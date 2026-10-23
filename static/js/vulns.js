'use strict';
/* Week 5 - Vulnerability assessment */
NS.pages.vulns = async (root) => {
  const w = 'vulns.write';
  const s = await NS.api('/vuln-summary');
  const SEV = ['Critical', 'High', 'Medium', 'Low'];
  const LEVEL = ['Low', 'Medium', 'Medium-High', 'High', 'Very High'];
  const STATUS = ['Open', 'In Progress', 'Pending Verification', 'Closed', 'Risk Accepted'];
  const assets = (await NS.api('/assets')).items;
  root.innerHTML = NS.head('Vulnerability assessment', 'Track findings from discovery to verified closure against severity-based remediation targets.', '', 'Week 5') +
    `<div class="stat-row"><div class="stat"><div class="n">${s.open}</div><div class="l">open findings</div></div>
      <div class="stat ${s.overdue ? 'bad' : 'good'}"><div class="n">${s.overdue}</div><div class="l">overdue</div></div>
      <div class="stat"><div class="n">${s.sla_compliance_pct ?? '-'}${s.sla_compliance_pct === null ? '' : '%'}</div><div class="l">within remediation target</div></div>
      <div class="stat"><div class="n">${s.critical_high_resolved_pct ?? '-'}${s.critical_high_resolved_pct === null ? '' : '%'}</div><div class="l">Critical/High closed or accepted</div></div>
      <div class="stat"><div class="n">${s.assets.internet_facing}</div><div class="l">internet-facing assets of ${s.assets.total}</div></div></div>`;
  const assetOpts = [{ v: '', l: 'Not linked' }, ...assets.map((a) => ({ v: a.id, l: a.name }))];
  const findingFields = [
    { name: 'ref', label: 'Reference', hint: 'Blank = auto' }, { name: 'severity', label: 'Severity', type: 'select', options: SEV, required: true, default: 'High' },
    { name: 'title', label: 'Finding', required: true, full: true }, { name: 'likelihood', label: 'Likelihood', type: 'select', options: LEVEL }, { name: 'impact', label: 'Impact', type: 'select', options: LEVEL },
    { name: 'priority', label: 'Priority', type: 'select', options: LEVEL }, { name: 'owner', label: 'Owner' }, { name: 'identified_on', label: 'Identified on', type: 'date' },
    { name: 'target_days', label: 'Target days', type: 'number', step: 1, min: 1, hint: 'Blank = default for severity (exploited 3, Critical 7, High 14, Medium 30, Low 90)' },
    { name: 'asset_id', label: 'Affected asset', type: 'select', options: assetOpts }, { name: 'actively_exploited', label: 'Actively exploited in the wild (72-hour target)', type: 'checkbox', full: true },
    { name: 'status', label: 'Status', type: 'select', options: STATUS, required: true, default: 'Open' },
    { name: 'observation', label: 'Observation', type: 'textarea', full: true }, { name: 'potential_impact', label: 'Potential impact', type: 'textarea', full: true }, { name: 'recommendations', label: 'Recommended mitigation', type: 'textarea', full: true },
    { name: 'verification_required', label: 'Verification evidence required', type: 'textarea', full: true },
    { name: 'closure_evidence', label: 'Closure evidence', type: 'textarea', full: true, hint: 'Required to close, e.g. a follow-up scan or configuration export' },
    { name: 'accept_rationale', label: 'Risk acceptance: rationale', type: 'textarea', full: true }, { name: 'accept_approver', label: 'Risk acceptance: approver' }, { name: 'accept_expiry', label: 'Risk acceptance: expires', type: 'date' }];
  NS.tabs(root, [
    { key: 'findings', label: 'Findings', render: (el) => NS.crudTable(el, { endpoint: 'vuln-findings', noun: 'finding', write: w, canDelete: true, sort: 'due_date', exportName: 'vuln-findings', wide: true,
      prepare: (p) => { if (p.asset_id === '') p.asset_id = ''; return p; },
      filters: [{ key: 'severity', label: 'Severity', options: SEV }, { key: 'status', label: 'Status', options: STATUS }],
      columns: [{ label: 'Ref', render: (r) => `<b>${NS.esc(r.ref)}</b>` }, { label: 'Finding', wrap: true, render: (r) => `${NS.esc(r.title)}<div class="muted">${NS.esc(r.asset_name || '')}${r.actively_exploited ? ' ' + NS.chip('Actively exploited', 'danger') : ''}</div>` },
        { label: 'Severity', render: (r) => NS.chip(r.severity) }, { label: 'Owner', key: 'owner', wrap: true },
        { label: 'Due', render: (r) => `${NS.fmtD(r.due_date)}<div class="muted">${r.status === 'Closed' || r.status === 'Risk Accepted' ? '' : (r.overdue ? NS.chip(Math.abs(r.days_remaining) + ' d overdue', 'danger') : r.days_remaining + ' d left')}</div>` },
        { label: 'Status', render: (r) => NS.chip(r.status) + (r.acceptance_expired ? ' ' + NS.chip('Acceptance expired', 'danger') : '') }],
      fields: findingFields, rowIntro: (r) => `<div class="note info">Remediation target: ${r.target_days} days from ${NS.esc(r.identified_on)}, due ${NS.esc(r.due_date)}.</div>` }) },
    { key: 'assets', label: 'Assets', render: (el) => NS.crudTable(el, { endpoint: 'assets', noun: 'asset', write: w, canDelete: true, wide: true,
      filters: [{ key: 'exposure', label: 'Exposure', options: ['Internal', 'Internet-facing'] }, { key: 'criticality', label: 'Criticality', options: ['Critical', 'High', 'Medium', 'Low'] }],
      columns: [{ label: 'Asset', render: (r) => `<b>${NS.esc(r.name)}</b>`, wrap: true }, { label: 'Type', key: 'type' }, { label: 'Owner', key: 'owner' }, { label: 'Criticality', render: (r) => NS.chip(r.criticality) }, { label: 'Exposure', render: (r) => NS.chip(r.exposure) }, { label: 'Platform', key: 'platform' }, { label: 'Support', render: (r) => NS.chip(r.support_status) }],
      fields: [{ name: 'name', label: 'Asset', required: true, full: true }, { name: 'type', label: 'Type', type: 'select', options: ['Endpoint', 'Server', 'Network', 'Cloud', 'Application', 'Other'], required: true }, { name: 'owner', label: 'Owner' },
        { name: 'criticality', label: 'Criticality', type: 'select', options: ['Critical', 'High', 'Medium', 'Low'], required: true, default: 'Medium' }, { name: 'exposure', label: 'Exposure', type: 'select', options: ['Internal', 'Internet-facing'], required: true, default: 'Internal' },
        { name: 'platform', label: 'Platform / version' }, { name: 'support_status', label: 'Support status', type: 'select', options: ['Supported', 'Unsupported', 'Unknown'], required: true, default: 'Supported' }, { name: 'notes', label: 'Notes', type: 'textarea', full: true }] }) },
    { key: 'roadmap', label: 'Remediation roadmap', render: (el) => NS.crudTable(el, { endpoint: 'vuln-roadmap', noun: 'roadmap phase', write: w, canDelete: true, search: false, sort: 'sort_order', wide: true,
      columns: [{ label: 'Timeframe', render: (r) => `<b>${NS.esc(r.timeframe)}</b>` }, { label: 'Actions', key: 'actions', wrap: true }, { label: 'Success measure', key: 'success_measure', wrap: true }, { label: 'Status', render: (r) => NS.chip(r.status) }],
      fields: [{ name: 'timeframe', label: 'Timeframe', required: true }, { name: 'status', label: 'Status', type: 'select', options: ['Not started', 'In progress', 'Completed', 'Blocked'], required: true, default: 'Not started' },
        { name: 'actions', label: 'Actions', type: 'textarea', required: true, full: true }, { name: 'success_measure', label: 'Success measure', type: 'textarea', full: true }, { name: 'sort_order', label: 'Order', type: 'number', step: 1, min: 0 }] }) },
    { key: 'metrics', label: 'Metrics', render: (el) => NS.crudTable(el, { endpoint: 'vuln-metrics', noun: 'metric', write: w, canDelete: true, search: false, wide: true,
      columns: [{ label: 'Metric', key: 'name', wrap: true }, { label: 'Target', key: 'target_text', wrap: true }, { label: 'Current', render: (r) => NS.num(r.current_value, r.unit) }, { label: 'State', render: (r) => NS.chip(r.state) }, { label: 'Cadence', key: 'cadence' }],
      fields: [{ name: 'name', label: 'Metric', required: true, full: true }, { name: 'target_text', label: 'Target (description)', full: true }, { name: 'target_value', label: 'Target value', type: 'number' }, { name: 'current_value', label: 'Current value', type: 'number' }, { name: 'unit', label: 'Unit' },
        { name: 'direction', label: 'Better when', type: 'select', options: [{ v: 'higher', l: 'Higher is better' }, { v: 'lower', l: 'Lower is better' }], required: true, default: 'higher' }, { name: 'cadence', label: 'Cadence' }] }) },
    { key: 'sla', label: 'Remediation targets', render: async (el) => {
      const sla = await NS.getRef('patch_sla');
      el.innerHTML = `<div class="grid g-main"><section class="panel"><h2>Remediation target calculator</h2><form class="form-grid" data-calc novalidate><label>Severity<select name="severity">${SEV.map((x) => `<option>${x}</option>`).join('')}</select></label>
        <label>Identified on<input type="date" name="identified_on"></label><label class="inline full"><input type="checkbox" name="exploited"> Actively exploited or critical exposure</label>
        <div class="full"><button class="btn primary" type="submit">Calculate</button></div></form><div data-out class="note info">Choose a severity to see the due date.</div></section>
        <section class="panel"><h2>Service levels</h2>${NS.simpleTable(['Condition', 'Target', 'Action'], sla.map((x) => [`<b>${NS.esc(x.condition)}</b>`, NS.esc(x.target), NS.esc(x.action)]), { wrap: [1, 2] })}</section></div>`;
      $('[data-calc]', el).addEventListener('submit', NS.guard(async (ev) => {
        ev.preventDefault();
        const f = ev.target;
        const r = await NS.api('/sla?' + NS.qs({ severity: f.severity.value, identified_on: f.identified_on.value, exploited: f.exploited.checked ? 1 : 0 }));
        $('[data-out]', el).innerHTML = `<b>${r.target_days} days</b> - due <b>${NS.esc(r.due_date)}</b>${r.actively_exploited ? ' (actively exploited: mitigate within 72 hours where feasible)' : ''}`;
      }));
    } },
  ]);
};
