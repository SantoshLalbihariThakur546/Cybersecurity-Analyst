'use strict';
/* Week 3 - Security policy review */
NS.pages.policy = async (root) => {
  const w = 'policy.write';
  const [defs, summary] = await Promise.all([NS.getRef('policy_rating_defs'), NS.api('/policy-summary')]);
  const ratings = defs.map((d) => d.rating);
  root.innerHTML = NS.head('Security policy review', 'Assess each control area against the policy baseline, rate the risks, and track the 90-day roadmap, exceptions and metrics.', '', 'Week 3') +
    `<div class="stat-row">
      <div class="stat ${summary.ratings.Weak ? 'bad' : ''}"><div class="n">${summary.ratings.Weak}</div><div class="l">weak control areas</div></div>
      <div class="stat"><div class="n">${(summary.risk_bands.Critical || 0) + (summary.risk_bands.High || 0)}</div><div class="l">critical or high risks open</div></div>
      <div class="stat"><div class="n">${summary.actions_completed}/${summary.actions_total}</div><div class="l">roadmap actions completed</div></div>
      <div class="stat ${summary.exceptions_expired ? 'bad' : ''}"><div class="n">${summary.exceptions_open}</div><div class="l">open exceptions (${summary.exceptions_expired} expired)</div></div>
      <div class="stat"><div class="n">${summary.checklist.answered}/${summary.checklist.total}</div><div class="l">review checklist answered</div></div></div>`;
  const ratingFilter = [{ key: 'rating', label: 'Rating', options: ratings }, { key: 'priority', label: 'Priority', options: ['Critical', 'High', 'Medium', 'Low'] }];
  const tabs = NS.tabs(root, [
    { key: 'controls', label: 'Control assessment', render: (el) => NS.crudTable(el, { endpoint: 'policy-controls', noun: 'control area', write: w, canDelete: true, wide: true, sort: 'sort_order', filters: ratingFilter,
      columns: [{ label: 'Control area', render: (r) => `<b>${NS.esc(r.area)}</b>`, wrap: true }, { label: 'Rating', render: (r) => NS.chip(r.rating) }, { label: 'Main gap', key: 'main_gap', wrap: true }, { label: 'Priority', render: (r) => NS.chip(r.priority) }],
      fields: [{ name: 'area', label: 'Control area', required: true, full: true }, { name: 'rating', label: 'Rating', type: 'select', options: ratings, required: true }, { name: 'priority', label: 'Priority', type: 'select', options: ['Critical', 'High', 'Medium', 'Low'], required: true },
        { name: 'main_gap', label: 'Main gap', full: true }, { name: 'critique', label: 'Critical review', type: 'textarea', full: true }, { name: 'recommendation', label: 'Recommended improvement', type: 'textarea', full: true },
        { name: 'evidence', label: 'Evidence to request / verify', type: 'textarea', full: true }, { name: 'sort_order', label: 'Display order', type: 'number', step: 1, min: 0 }],
      rowIntro: (r) => `<p>${NS.chip(r.rating)} ${NS.chip(r.priority)}</p>`, onChange: () => 0 }) },
    { key: 'risks', label: 'Risk register', render: async (el) => {
      el.innerHTML = '<section class="panel"><h2>Risk matrix (likelihood x impact, 1-5)</h2><div class="matrix-box" data-matrix></div><p class="field-note">Bands: 20-25 Critical, 12-19 High, 6-11 Medium, 1-5 Low. Closed risks are hidden.</p></section><div data-table></div>';
      const drawMatrix = async () => { const s = await NS.api('/policy-summary'); NS.setHtml($('[data-matrix]', el), NS.charts.riskMatrix5(s.risk_matrix)); };
      await drawMatrix();
      await NS.crudTable($('[data-table]', el), { endpoint: 'policy-risks', noun: 'risk', write: w, canDelete: true, sort: '-score', exportName: 'policy-risks', wide: true, onChange: drawMatrix,
        filters: [{ key: 'band', label: 'Band', options: ['Critical', 'High', 'Medium', 'Low'] }, { key: 'status', label: 'Status', options: ['Open', 'Mitigating', 'Accepted', 'Closed'] }],
        columns: [{ label: 'Ref', render: (r) => `<b>${NS.esc(r.ref)}</b>` }, { label: 'Risk', key: 'title', wrap: true }, { label: 'L x I', render: (r) => `${r.likelihood} x ${r.impact}` }, { label: 'Score', render: (r) => `${r.score} ${NS.chip(r.band)}` },
          { label: 'Owner', key: 'owner', wrap: true }, { label: 'Treatment', key: 'treatment' }, { label: 'Status', render: (r) => NS.chip(r.status) }],
        fields: [{ name: 'ref', label: 'Reference', hint: 'Leave blank to auto-number' }, { name: 'title', label: 'Risk', type: 'textarea', required: true, full: true },
          { name: 'likelihood', label: 'Likelihood (1-5)', type: 'number', step: 1, min: 1, max: 5, required: true }, { name: 'impact', label: 'Impact (1-5)', type: 'number', step: 1, min: 1, max: 5, required: true },
          { name: 'owner', label: 'Risk owner' }, { name: 'treatment', label: 'Treatment', type: 'select', options: ['Mitigate', 'Accept', 'Transfer', 'Avoid'], required: true, default: 'Mitigate' },
          { name: 'status', label: 'Status', type: 'select', options: ['Open', 'Mitigating', 'Accepted', 'Closed'], required: true, default: 'Open' }, { name: 'review_date', label: 'Next review', type: 'date' }] });
    } },
    { key: 'roadmap', label: '90-day roadmap', render: async (el) => {
      const s = await NS.api('/policy-summary');
      el.innerHTML = `<div class="grid g4">${Object.entries(s.phases).map(([p, v]) => `<section class="panel"><b>${NS.esc(p)}</b><div class="muted">${v.completed} of ${v.total} complete</div>${NS.meter(v.total ? (100 * v.completed) / v.total : 0, v.completed === v.total && v.total ? 'good' : '')}</section>`).join('')}</div><div data-table></div>`;
      await NS.crudTable($('[data-table]', el), { endpoint: 'policy-actions', noun: 'roadmap action', write: w, canDelete: true, sort: 'phase', wide: true, exportName: 'policy-actions',
        filters: [{ key: 'phase', label: 'Phase', options: ['First 30 days', 'Days 31-60', 'Days 61-90', '3-6 months'] }, { key: 'status', label: 'Status', options: ['Not started', 'In progress', 'Completed', 'Blocked'] }],
        columns: [{ label: 'Phase', key: 'phase' }, { label: 'Action', key: 'action', wrap: true }, { label: 'Owner', key: 'owner', wrap: true }, { label: 'Success measure', key: 'success_measure', wrap: true },
          { label: 'Due', render: (r) => NS.fmtD(r.due_date) + (r.overdue ? ' ' + NS.chip('OVERDUE', 'danger') : '') }, { label: 'Status', render: (r) => NS.chip(r.status) }],
        fields: [{ name: 'phase', label: 'Phase', type: 'select', options: ['First 30 days', 'Days 31-60', 'Days 61-90', '3-6 months'], required: true }, { name: 'status', label: 'Status', type: 'select', options: ['Not started', 'In progress', 'Completed', 'Blocked'], required: true, default: 'Not started' },
          { name: 'action', label: 'Action', type: 'textarea', required: true, full: true }, { name: 'owner', label: 'Owner' }, { name: 'due_date', label: 'Due date', type: 'date' },
          { name: 'deliverable', label: 'Deliverable', type: 'textarea', full: true }, { name: 'success_measure', label: 'Success measure', type: 'textarea', full: true }], onChange: () => 0 });
    } },
    { key: 'exceptions', label: 'Exceptions', render: async (el) => {
      const proc = await NS.getRef('exception_process');
      el.innerHTML = `<details class="pb"><summary><b>Exception process</b></summary><ol class="clean">${proc.map((p) => `<li>${NS.esc(p)}</li>`).join('')}</ol></details><div data-table></div>`;
      await NS.crudTable($('[data-table]', el), { endpoint: 'policy-exceptions', noun: 'exception', write: w, sort: '-id', exportName: 'policy-exceptions', wide: true,
        filters: [{ key: 'status', label: 'Status', options: ['Pending', 'Approved', 'Rejected', 'Closed'] }],
        columns: [{ label: 'Ref', render: (r) => `<b>${NS.esc(r.ref)}</b>` }, { label: 'Control', key: 'control', wrap: true }, { label: 'Requester', key: 'requester' }, { label: 'Approver', key: 'approver' },
          { label: 'Expires', render: (r) => NS.fmtD(r.expiry_date) }, { label: 'Status', render: (r) => NS.chip(r.effective_status) }],
        fields: [{ name: 'requester', label: 'Requester', required: true }, { name: 'status', label: 'Status', type: 'select', options: ['Pending', 'Approved', 'Rejected', 'Closed'], required: true, default: 'Pending' },
          { name: 'control', label: 'Control that cannot be met', type: 'textarea', required: true, full: true }, { name: 'assets', label: 'Affected assets', type: 'textarea', full: true },
          { name: 'justification', label: 'Business justification', type: 'textarea', full: true }, { name: 'risk_assessment', label: 'Residual risk assessment', type: 'textarea', full: true },
          { name: 'compensating_controls', label: 'Compensating controls', type: 'textarea', full: true }, { name: 'approver', label: 'Approver', hint: 'Required when approved' },
          { name: 'approved_on', label: 'Approved on', type: 'date' }, { name: 'expiry_date', label: 'Expiry date', type: 'date', hint: 'Exceptions must not become permanent' }, { name: 'review_date', label: 'Review date', type: 'date' },
          { name: 'closure_evidence', label: 'Closure evidence', type: 'textarea', full: true, hint: 'Required to close' }] });
    } },
    { key: 'metrics', label: 'Metrics', render: (el) => NS.crudTable(el, { endpoint: 'policy-metrics', noun: 'metric', write: w, canDelete: true, wide: true,
      columns: [{ label: 'Metric', wrap: true, render: (r) => `<b>${NS.esc(r.name)}</b><div class="muted">${NS.esc(r.definition || '')}</div>` }, { label: 'Target', key: 'target_text', wrap: true }, { label: 'Current', render: (r) => NS.num(r.current_value, r.unit) },
        { label: 'State', render: (r) => NS.chip(r.state) }, { label: 'Cadence', key: 'cadence' }, { label: 'Owner', key: 'owner' }],
      fields: [{ name: 'name', label: 'Metric', required: true, full: true }, { name: 'definition', label: 'Definition', type: 'textarea', full: true }, { name: 'target_text', label: 'Target (description)', full: true },
        { name: 'target_value', label: 'Target value', type: 'number' }, { name: 'current_value', label: 'Current value', type: 'number' }, { name: 'unit', label: 'Unit (e.g. %)' },
        { name: 'direction', label: 'Better when', type: 'select', options: [{ v: 'higher', l: 'Higher is better' }, { v: 'lower', l: 'Lower is better' }], required: true, default: 'higher' }, { name: 'cadence', label: 'Cadence' }, { name: 'owner', label: 'Owner' }] }) },
    { key: 'checklist', label: 'Review checklist', render: async (el) => {
      const ans = ['Unanswered', 'Yes', 'Partially', 'No', 'N/A'];
      el.innerHTML = '<section class="panel"><h2>Policy review checklist</h2><div data-a></div></section><section class="panel"><h2>Evidence requests</h2><div data-b></div></section>';
      await NS.crudTable($('[data-a]', el), { endpoint: 'policy-checklist', noun: 'question', write: w, canDelete: true, filters: [{ key: 'answer', label: 'Answer', options: ans }], wide: true,
        columns: [{ label: 'Question', key: 'question', wrap: true }, { label: 'Answer', render: (r) => NS.chip(r.answer) }, { label: 'Evidence', key: 'evidence', wrap: true }],
        fields: [{ name: 'question', label: 'Question', type: 'textarea', required: true, full: true }, { name: 'answer', label: 'Answer', type: 'select', options: ans, required: true, default: 'Unanswered' }, { name: 'evidence', label: 'Evidence / notes', type: 'textarea', full: true }] });
      await NS.crudTable($('[data-b]', el), { endpoint: 'evidence-requests', noun: 'evidence request', write: w, canDelete: true, filters: [{ key: 'status', label: 'Status', options: ['Not requested', 'Requested', 'Received', 'Not available'] }], wide: true,
        columns: [{ label: 'Evidence item', key: 'item', wrap: true }, { label: 'Status', render: (r) => NS.chip(r.status) }, { label: 'Notes', key: 'notes', wrap: true }],
        fields: [{ name: 'item', label: 'Evidence item', type: 'textarea', required: true, full: true }, { name: 'status', label: 'Status', type: 'select', options: ['Not requested', 'Requested', 'Received', 'Not available'], required: true, default: 'Not requested' }, { name: 'notes', label: 'Notes', type: 'textarea', full: true }] });
    } },
    { key: 'reference', label: 'Reference', render: async (el) => {
      const [dfs, base, roles] = await Promise.all([NS.getRef('policy_rating_defs'), NS.getRef('policy_baseline'), NS.getRef('policy_roles')]);
      el.innerHTML = `<section class="panel"><h2>Assumed baseline policy (reviewed)</h2>${NS.list(base)}</section>
        <section class="panel"><h2>Rating definitions</h2>${NS.simpleTable(['Rating', 'Meaning', 'Interpretation'], dfs.map((d) => [NS.chip(d.rating), NS.esc(d.meaning), NS.esc(d.interpretation)]), { wrap: [1, 2] })}</section>
        <section class="panel"><h2>Governance roles</h2>${NS.simpleTable(['Role', 'Responsibility', 'Evidence'], roles.map((r) => [`<b>${NS.esc(r.role)}</b>`, NS.esc(r.responsibility), NS.esc(r.evidence)]), { wrap: [1, 2] })}</section>
        <section class="panel"><h2>Suggested policy statements</h2><div data-s></div></section>`;
      await NS.crudTable($('[data-s]', el), { endpoint: 'policy-statements', noun: 'policy statement', write: w, canDelete: true, wide: true,
        columns: [{ label: 'Topic', render: (r) => `<b>${NS.esc(r.topic)}</b>` }, { label: 'Control statement', key: 'language', wrap: true }],
        fields: [{ name: 'topic', label: 'Topic', required: true }, { name: 'language', label: 'Statement', type: 'textarea', required: true, full: true }] });
    } },
  ]);
};
