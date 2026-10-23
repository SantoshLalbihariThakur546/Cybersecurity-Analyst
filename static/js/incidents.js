'use strict';
/* Week 2 - Incident response */
const IR = {
  statuses: ['Reported', 'Triage', 'Declared', 'Contained', 'Eradicated', 'Recovered', 'Closed'],
  sev: ['SEV-1', 'SEV-2', 'SEV-3', 'SEV-4'],
  playbookFor: { 'Phishing / BEC / account takeover': 'phishing', 'Ransomware / destructive malware': 'ransomware', 'Data loss / unauthorized access / exfiltration': 'breach',
    'Cloud / SaaS compromise / exposed keys / third-party breach': 'cloud', 'Denial of service / service disruption': 'dos' },
};
const nowUtc = () => new Date().toISOString().slice(0, 16);

NS.pages.incidents = async (root, args) => {
  if (args[0]) return incidentDetail(root, Number(args[0]));
  const w = 'incidents.write';
  const cats = await NS.getRef('incident_categories');
  root.innerHTML = NS.head('Incident response', 'Report, triage, contain and learn from incidents against the severity model and response lifecycle.',
    NS.can(w) ? '<button class="btn primary" data-new type="button">Report incident</button>' : '', 'Week 2');
  NS.tabs(root, [
    { key: 'register', label: 'Incidents', render: async (el) => {
      const s = await NS.api('/incidents-summary');
      el.innerHTML = `<div class="stat-row">
        <div class="stat ${s.open ? 'bad' : 'good'}"><div class="n">${s.open}</div><div class="l">open incidents</div></div>
        <div class="stat ${s.ack_breaches ? 'bad' : 'good'}"><div class="n">${s.ack_breaches}</div><div class="l">acknowledgement target missed</div></div>
        <div class="stat ${s.ack_pending ? 'bad' : ''}"><div class="n">${s.ack_pending}</div><div class="l">awaiting acknowledgement</div></div>
        <div class="stat"><div class="n">${NS.minutes(s.avg_minutes.time_to_acknowledge_min)}</div><div class="l">average time to acknowledge</div></div>
        <div class="stat"><div class="n">${NS.minutes(s.avg_minutes.time_to_contain_min)}</div><div class="l">average time to contain</div></div>
        <div class="stat ${s.cert_in_attention ? 'bad' : ''}"><div class="n">${s.cert_in_attention}</div><div class="l">CERT-In reports outstanding</div></div></div><div data-table></div>`;
      await NS.crudTable($('[data-table]', el), {
        endpoint: 'incidents', noun: 'incident', sort: '-reported_at', exportName: 'incidents', rowClick: (r) => { location.hash = '#/incidents/' + r.id; },
        filters: [{ key: 'severity', label: 'Severity', options: IR.sev }, { key: 'status', label: 'Status', options: IR.statuses }],
        columns: [{ label: 'Ref', render: (r) => `<b>${NS.esc(r.ref)}</b>` }, { label: 'Incident', wrap: true, render: (r) => `${NS.esc(r.title)}<div class="muted">${NS.esc(r.category)}</div>` },
          { label: 'Severity', render: (r) => NS.chip(r.severity) }, { label: 'Status', render: (r) => NS.chip(r.status) }, { label: 'Reported', render: (r) => NS.fmtDT(r.reported_at) },
          { label: 'Acknowledgement', render: (r) => (r.ack_breached ? NS.chip(r.acknowledged_at ? 'Late' : 'MISSED', 'danger') : r.acknowledged_at ? NS.chip('On time', 'ok') : NS.chip('Due ' + r.ack_due.slice(11, 16) + 'Z', 'warn')) },
          { label: 'CERT-In', render: (r) => (r.cert_in_state ? NS.chip(r.cert_in_state, r.cert_in_state === 'OVERDUE' ? 'danger' : r.cert_in_state.startsWith('Reported') ? 'ok' : 'warn') : '<span class="muted">-</span>') }] });
    } },
    { key: 'playbooks', label: 'Plan and playbooks', render: async (el) => {
      const [sev, pbs, rolesR, c15, c24, closure, tpl, cert] = await Promise.all(['severity_model', 'playbooks', 'ir_roles', 'checklist15', 'checklist24', 'closure_criteria', 'post_incident_template', 'cert_in_note'].map(NS.getRef));
      el.innerHTML = `<section class="panel"><h2>Severity model</h2>${NS.simpleTable(['Level', 'Name', 'Typical criteria', 'Acknowledge within', 'Management involvement', 'Update cadence'],
        sev.map((s) => [NS.chip(s.level), NS.esc(s.name), NS.esc(s.criteria), NS.esc(s.ack_text), NS.esc(s.management), NS.esc(s.cadence)]), { wrap: [2, 4] })}</section>
        <section class="panel"><h2>Scenario playbooks</h2>${pbs.map((p) => `<details class="pb"><summary><b>${NS.esc(p.title)}</b></summary><ol class="clean">${p.steps.map((s) => `<li>${NS.esc(s)}</li>`).join('')}</ol></details>`).join('')}</section>
        <div class="grid g2"><section class="panel"><h2>First 15 minutes</h2><ol class="clean">${c15.map((x) => `<li>${NS.esc(x)}</li>`).join('')}</ol></section>
        <section class="panel"><h2>First 24 hours</h2><ol class="clean">${c24.map((x) => `<li>${NS.esc(x)}</li>`).join('')}</ol></section></div>
        <section class="panel"><h2>Roles and authority</h2>${NS.simpleTable(['Role', 'Responsibility', 'Authority'], rolesR.map((r) => [`<b>${NS.esc(r.role)}</b>`, NS.esc(r.responsibility), NS.esc(r.authority)]), { wrap: [1, 2] })}</section>
        <div class="grid g2"><section class="panel"><h2>Closure criteria</h2><ul class="clean">${closure.map((x) => `<li>${NS.esc(x)}</li>`).join('')}</ul></section>
        <section class="panel"><h2>Post-incident report template</h2>${NS.simpleTable(['Section', 'Contents'], tpl.map((t) => [`<b>${NS.esc(t[0])}</b>`, NS.esc(t[1])]), { wrap: [1] })}<div class="note">${NS.esc(cert)}</div></section></div>`;
    } },
  ]);
  const nb = $('[data-new]', root);
  if (nb) nb.addEventListener('click', () => NS.editModal({
    title: 'Report an incident', createLabel: 'Report incident', endpoint: 'incidents', canWrite: true, wide: true,
    values: { reported_at: nowUtc(), severity: 'SEV-3', data_impact: 'Unknown', cert_in_assessment: 'Not assessed' },
    fields: incidentFields(cats), onSaved: () => NS.route(), createdMessage: 'Incident recorded',
  }));
};

function incidentFields(cats) {
  return [
    { name: 'title', label: 'Title', required: true, full: true }, { name: 'category', label: 'Category', type: 'select', options: cats, required: true, full: true },
    { name: 'severity', label: 'Provisional severity', type: 'select', options: IR.sev, required: true, hint: 'SEV-1 and SEV-2: acknowledge within 15 minutes' },
    { name: 'reported_at', label: 'Reported / detected (UTC)', type: 'datetime', required: true }, { name: 'started_at', label: 'Estimated start (UTC)', type: 'datetime', hint: 'Used for time-to-contain and recover' },
    { name: 'reporter', label: 'Reported by' }, { name: 'triage_owner', label: 'Triage owner' }, { name: 'incident_commander', label: 'Incident commander' },
    { name: 'data_impact', label: 'Data impact', type: 'select', options: ['Unknown', 'None', 'Suspected', 'Confirmed'], required: true, hint: 'Do not state confirmed unless evidence supports it' },
    { name: 'cert_in_assessment', label: 'CERT-In reporting assessment', type: 'select', options: ['Not assessed', 'Not required', 'Required'], required: true },
    { name: 'affected_assets', label: 'Affected assets, accounts, services', type: 'textarea', full: true }, { name: 'observed_activity', label: 'Observed activity', type: 'textarea', full: true },
    { name: 'business_impact', label: 'Business impact', type: 'textarea', full: true },
  ];
}

async function incidentDetail(root, id) {
  const [cats, cert, c15, c24, closure, pbs] = await Promise.all([NS.getRef('incident_categories'), NS.getRef('cert_in_note'), NS.getRef('checklist15'), NS.getRef('checklist24'), NS.getRef('closure_criteria'), NS.getRef('playbooks')]);
  const w = 'incidents.write', canW = NS.can(w);
  let inc = await NS.api('/incidents/' + id);
  const header = document.createElement('div');
  const body = document.createElement('div');
  root.appendChild(header); root.appendChild(body);

  const reload = async () => { inc = await NS.api('/incidents/' + id); NS.refreshBadge(); drawHeader(); if (tabsApi) tabsApi.show(currentTab); };
  const patch = async (payload, ok) => {
    try { inc = await NS.api('/incidents/' + id, { method: 'PATCH', body: payload }); NS.toast(ok || 'Saved'); NS.refreshBadge(); drawHeader(); return true; }
    catch (e) { NS.toast(e.message + (e.details.length ? ': ' + e.details.map((d) => d.message).join('; ') : ''), true); return false; }
  };
  function drawHeader() {
    const ackChip = inc.ack_breached ? NS.chip(inc.acknowledged_at ? 'Acknowledged late' : 'Acknowledgement MISSED', 'danger') : inc.acknowledged_at ? NS.chip('Acknowledged', 'ok') : NS.chip('Acknowledge by ' + inc.ack_due.slice(11, 16) + ' UTC', 'warn');
    header.innerHTML = `<p><a href="#/incidents">&larr; All incidents</a></p>` + NS.head(`${inc.ref}: ${inc.title}`, '', `
      ${canW && !inc.acknowledged_at ? '<button class="btn primary" data-ack type="button">Acknowledge</button>' : ''}
      ${canW && inc.is_open ? `<label class="inline">Status <select data-status>${IR.statuses.map((s) => `<option ${s === inc.status ? 'selected' : ''}>${s}</option>`).join('')}</select></label>` : ''}
      ${canW ? '<button class="btn" data-edit type="button">Edit details</button>' : ''}
      <button class="btn" data-report type="button">Post-incident report</button>`, 'Week 2') +
      `<p>${NS.chip(inc.severity)} ${NS.chip(inc.status)} ${ackChip} ${inc.cert_in_state ? NS.chip('CERT-In: ' + inc.cert_in_state, inc.cert_in_state === 'OVERDUE' ? 'danger' : inc.cert_in_state.startsWith('Reported') ? 'ok' : 'warn') : ''} ${inc.is_demo ? NS.chip('Illustrative demo', 'info') : ''}</p>`;
    const ack = $('[data-ack]', header);
    if (ack) ack.addEventListener('click', NS.guard(async () => { await NS.api(`/incidents/${id}/acknowledge`, { method: 'POST' }); NS.toast('Incident acknowledged'); await reload(); }));
    const st = $('[data-status]', header);
    if (st) st.addEventListener('change', async () => {
      const target = st.value;
      if (target === 'Closed') { openClosure(); st.value = inc.status; return; }
      if (!(await patch({ status: target }, `Status set to ${target}`))) st.value = inc.status; else if (tabsApi) tabsApi.show(currentTab);
    });
    const ed = $('[data-edit]', header);
    if (ed) ed.addEventListener('click', () => NS.editModal({ title: 'Edit incident', endpoint: 'incidents', id, canWrite: true, wide: true, values: inc,
      fields: [...incidentFields(cats), { name: 'acknowledged_at', label: 'Acknowledged (UTC)', type: 'datetime' }, { name: 'declared_at', label: 'Declared (UTC)', type: 'datetime' },
        { name: 'contained_at', label: 'Containment verified (UTC)', type: 'datetime' }, { name: 'recovered_at', label: 'Service recovered (UTC)', type: 'datetime' },
        { name: 'cert_in_reported_at', label: 'CERT-In report submitted (UTC)', type: 'datetime' }, { name: 'root_cause', label: 'Root cause', type: 'textarea', full: true }],
      onSaved: reload }));
    $('[data-report]', header).addEventListener('click', NS.guard(() => NS.openHtml(`/incidents/${id}/report`)));
  }
  function openClosure() {
    const box = document.createElement('div');
    box.innerHTML = `<p class="muted">An incident can only be closed when every closure criterion is confirmed and a closure summary is recorded.</p>
      ${closure.map((c, i) => `<label class="check"><input type="checkbox" data-c="${i}" ${inc.closure_checks.includes(i) ? 'checked' : ''}><span>${NS.esc(c)}</span></label>`).join('')}
      <label>Closure summary<textarea data-sum>${NS.esc(inc.closure_summary || '')}</textarea></label><p class="form-error" data-err></p>`;
    NS.modal({ title: `Close ${inc.ref}`, body: box, foot: [{ label: 'Cancel', onClick: (m) => m.close() }, { label: 'Close incident', cls: 'primary', onClick: async (m) => {
      const checks = $$('[data-c]', box).filter((c) => c.checked).map((c) => Number(c.dataset.c));
      try { inc = await NS.api('/incidents/' + id, { method: 'PATCH', body: { closure_checks: checks, closure_summary: $('[data-sum]', box).value, status: 'Closed' } }); }
      catch (e) { $('[data-err]', box).textContent = e.message + (e.details.length ? ' - ' + e.details.map((d) => d.message).join('; ') : ''); return; }
      NS.toast('Incident closed'); m.close(); await reload();
    } }] });
  }

  let tabsApi = null, currentTab = 'overview';
  drawHeader();
  const child = (endpoint, cfg) => NS.crudTable(cfg.holder, { endpoint, baseParams: { incident_id: id }, write: w, canDelete: true, prepare: (p) => ({ ...p, incident_id: id }), wide: true, ...cfg.cfg });
  const defs = [
    { key: 'overview', label: 'Overview', render: (el) => {
      const m = inc.metrics;
      el.innerHTML = `<div class="grid g2"><section class="panel"><h2>Facts</h2>${NS.kv([
        ['Category', NS.esc(inc.category)], ['Reported', NS.fmtDT(inc.reported_at)], ['Estimated start', NS.fmtDT(inc.started_at)], ['Reporter', NS.esc(inc.reporter || '')], ['Triage owner', NS.esc(inc.triage_owner || '')],
        ['Incident commander', NS.esc(inc.incident_commander || '')], ['Affected assets', NS.esc(inc.affected_assets || '')], ['Observed activity', NS.esc(inc.observed_activity || '')],
        ['Business impact', NS.esc(inc.business_impact || '')], ['Data impact', NS.chip(inc.data_impact)], ['Root cause', NS.esc(inc.root_cause || 'Not yet determined')],
        ['Management involvement', NS.esc(inc.management_involvement)], ['Update cadence', NS.esc(inc.update_cadence)]])}</section>
        <div><section class="panel"><h2>Response clock</h2>${NS.kv([['Acknowledgement target', NS.esc(inc.ack_target) + ' (due ' + NS.fmtDT(inc.ack_due) + ')'], ['Acknowledged', NS.fmtDT(inc.acknowledged_at)], ['Declared', NS.fmtDT(inc.declared_at)],
          ['Containment verified', NS.fmtDT(inc.contained_at)], ['Service recovered', NS.fmtDT(inc.recovered_at)], ['Closed', NS.fmtDT(inc.closed_at)],
          ['Time to acknowledge', NS.minutes(m.time_to_acknowledge_min)], ['Time to declare', NS.minutes(m.time_to_declare_min)], ['Time to contain', NS.minutes(m.time_to_contain_min)], ['Time to recover', NS.minutes(m.time_to_recover_min)]])}</section>
        <section class="panel"><h2>Reporting obligations</h2>${NS.kv([['CERT-In assessment', NS.chip(inc.cert_in_assessment)], ['Six-hour deadline', inc.cert_in_deadline ? NS.fmtDT(inc.cert_in_deadline) : '-'],
          ['State', inc.cert_in_state ? NS.chip(inc.cert_in_state, inc.cert_in_state === 'OVERDUE' ? 'danger' : inc.cert_in_state.startsWith('Reported') ? 'ok' : 'warn') : '-'], ['Report submitted', NS.fmtDT(inc.cert_in_reported_at)]])}
          <div class="note">${NS.esc(cert)}</div></section></div></div>`;
    } },
    { key: 'timeline', label: 'Timeline', render: (el) => child('incident-timeline', { holder: el, cfg: { noun: 'timeline event', sort: 'event_time', defaults: { event_time: nowUtc(), confidence: 'Medium' },
      columns: [{ label: 'Time (UTC)', render: (r) => NS.fmtDT(r.event_time) }, { label: 'Event', key: 'event', wrap: true }, { label: 'Source', key: 'source', wrap: true }, { label: 'Confidence', render: (r) => NS.esc(r.confidence || '') }, { label: 'Interpretation / action', key: 'interpretation', wrap: true }],
      fields: [{ name: 'event_time', label: 'Time (UTC)', type: 'datetime', required: true }, { name: 'confidence', label: 'Confidence', type: 'select', options: ['High', 'Medium', 'Low'] },
        { name: 'event', label: 'What happened (fact)', type: 'textarea', required: true, full: true }, { name: 'source', label: 'Source', full: true }, { name: 'interpretation', label: 'Interpretation or next action', type: 'textarea', full: true }] } }) },
    { key: 'evidence', label: 'Evidence', render: (el) => evidenceTab(el, id, canW) },
    { key: 'decisions', label: 'Decisions', render: (el) => child('incident-decisions', { holder: el, cfg: { noun: 'decision', sort: 'decided_at', defaults: { decided_at: nowUtc() },
      columns: [{ label: 'Time (UTC)', render: (r) => NS.fmtDT(r.decided_at) }, { label: 'Decision', key: 'decision', wrap: true }, { label: 'Rationale', key: 'rationale', wrap: true }, { label: 'Approver', key: 'approver' }, { label: 'Outcome', key: 'outcome', wrap: true }],
      fields: [{ name: 'decided_at', label: 'Time (UTC)', type: 'datetime', required: true }, { name: 'approver', label: 'Approver' }, { name: 'decision', label: 'Decision', type: 'textarea', required: true, full: true }, { name: 'rationale', label: 'Rationale', type: 'textarea', full: true }, { name: 'outcome', label: 'Outcome', type: 'textarea', full: true }] } }) },
    { key: 'actions', label: 'Corrective actions', render: (el) => child('incident-actions', { holder: el, cfg: { noun: 'corrective action', sort: 'due_date',
      columns: [{ label: 'Action', key: 'title', wrap: true }, { label: 'Priority', render: (r) => NS.chip(r.priority) }, { label: 'Owner', key: 'owner' }, { label: 'Due', render: (r) => NS.fmtD(r.due_date) }, { label: 'Status', render: (r) => NS.chip(r.status) }, { label: 'Closure evidence', key: 'evidence', wrap: true }],
      fields: [{ name: 'title', label: 'Action', type: 'textarea', required: true, full: true }, { name: 'priority', label: 'Priority', type: 'select', options: ['Critical', 'High', 'Medium', 'Low'], required: true, default: 'Medium' },
        { name: 'owner', label: 'Owner' }, { name: 'due_date', label: 'Due date', type: 'date' }, { name: 'status', label: 'Status', type: 'select', options: ['Open', 'In Progress', 'Pending Verification', 'Closed', 'Risk Accepted'], required: true, default: 'Open' },
        { name: 'evidence', label: 'Verification evidence', type: 'textarea', full: true, hint: 'Required before an action can be closed' }] } }) },
    { key: 'checklists', label: 'Checklists', render: (el) => {
      const block = (title, items, key) => `<section class="panel"><h2>${NS.esc(title)} <span class="muted">${inc[key].length}/${items.length}</span></h2>${items.map((t, i) => `<label class="check"><input type="checkbox" data-k="${key}" data-i="${i}" ${inc[key].includes(i) ? 'checked' : ''} ${canW ? '' : 'disabled'}><span>${NS.esc(t)}</span></label>`).join('')}</section>`;
      el.innerHTML = `<div class="grid g3">${block('First 15 minutes', c15, 'checklist15')}${block('First 24 hours', c24, 'checklist24')}${block('Closure criteria', closure, 'closure_checks')}</div>`;
      $$('input[data-k]', el).forEach((cb) => cb.addEventListener('change', NS.guard(async () => {
        const key = cb.dataset.k;
        const set = new Set(inc[key]);
        if (cb.checked) set.add(Number(cb.dataset.i)); else set.delete(Number(cb.dataset.i));
        const ok = await patch({ [key]: [...set] }, 'Checklist updated');
        if (!ok) cb.checked = !cb.checked;
      })));
    } },
    { key: 'playbook', label: 'Playbook', render: (el) => {
      const key = IR.playbookFor[inc.category];
      const pb = pbs.find((p) => p.key === key);
      el.innerHTML = pb ? `<section class="panel"><h2>${NS.esc(pb.title)}</h2><ol class="clean">${pb.steps.map((s) => `<li>${NS.esc(s)}</li>`).join('')}</ol></section>`
        : '<div class="note info">No scenario playbook matches this category. Use the first-15-minutes and first-24-hours checklists and the general lifecycle.</div>';
    } },
  ];
  tabsApi = NS.tabs(body, defs.map((d) => ({ ...d, render: (el) => { currentTab = d.key; return d.render(el); } })), 'overview');
}

async function evidenceTab(el, id, canW) {
  const load = async () => {
    const data = await NS.api('/incident-evidence?incident_id=' + id);
    NS.setHtml(list, NS.simpleTable(['ID', 'Description', 'Collected by', 'Collected (UTC)', 'SHA-256', 'Location', 'File'], data.items.map((e) => [
      `<b>${NS.esc(e.evid)}</b>`, NS.esc(e.description), NS.esc(e.collected_by || ''), NS.fmtDT(e.collected_at), `<span class="hash">${NS.esc(e.sha256 || '')}</span>`, NS.esc(e.storage_location || ''),
      e.has_file ? `<button class="btn sm" data-dl="${e.id}" data-name="${NS.esc(e.filename)}">Download</button> <button class="btn sm" data-vf="${e.id}">Verify hash</button>` + (canW ? ` <button class="btn sm danger" data-del="${e.id}">Delete</button>` : '')
        : '<span class="muted">hash only</span>' + (canW ? ` <button class="btn sm danger" data-del="${e.id}">Delete</button>` : '')]), { wrap: [1, 5], empty: 'No evidence recorded. Add each item with a hash so integrity can be checked later.' }));
    $$('[data-dl]', list).forEach((b) => b.addEventListener('click', NS.guard(() => NS.download(`/incident-evidence/${b.dataset.dl}/download`, b.dataset.name))));
    $$('[data-vf]', list).forEach((b) => b.addEventListener('click', NS.guard(async () => {
      const r = await NS.api(`/incident-evidence/${b.dataset.vf}/verify`, { method: 'POST' });
      NS.toast(r.intact ? 'Hash verified: the file is unchanged since collection.' : 'WARNING: the stored file no longer matches its recorded hash.', !r.intact);
    })));
    $$('[data-del]', list).forEach((b) => b.addEventListener('click', NS.guard(async () => {
      if (!(await NS.confirm('Delete evidence', 'Delete this evidence record and any stored file?', 'Delete', true))) return;
      await NS.api(`/incident-evidence/${b.dataset.del}`, { method: 'DELETE' }); NS.toast('Deleted'); load();
    })));
  };
  el.innerHTML = `<div class="toolbar">${canW ? '<button class="btn primary" data-add type="button">Add evidence</button>' : ''}<span class="muted">Files are hashed with SHA-256 on upload and stored privately. Record the original source and handling in the description.</span></div><div data-list></div>`;
  const list = $('[data-list]', el);
  const add = $('[data-add]', el);
  if (add) add.addEventListener('click', () => {
    const form = document.createElement('div');
    form.innerHTML = `<form class="form-grid" novalidate>
      <label class="full">Description<textarea name="description" required></textarea><span class="field-error" data-err="description"></span></label>
      <label>Collected by<input name="collected_by" maxlength="100"></label><label>Collected (UTC)<input name="collected_at" type="datetime-local" value="${nowUtc()}"></label>
      <label class="full">Storage location<input name="storage_location" maxlength="200" placeholder="e.g. evidence vault, restricted folder"></label>
      <label class="full">File (optional, max 5 MB)<input name="file" type="file"></label>
      <label class="full">SHA-256 (only if there is no file)<input name="sha256" maxlength="64" class="mono"><span class="field-error" data-err="sha256"></span></label></form>`;
    NS.modal({ title: 'Add evidence item', body: form, foot: [{ label: 'Cancel', onClick: (m) => m.close() }, { label: 'Save evidence', cls: 'primary', onClick: async (m) => {
      const fd = new FormData();
      fd.append('incident_id', String(id));
      ['description', 'collected_by', 'storage_location', 'sha256'].forEach((k) => { const v = $(`[name=${k}]`, form).value.trim(); if (v) fd.append(k, v); });
      const ca = $('[name=collected_at]', form).value; if (ca) fd.append('collected_at', ca + ':00Z');
      const file = $('[name=file]', form).files[0]; if (file) fd.append('file', file);
      try { await NS.api('/incident-evidence', { method: 'POST', form: fd }); } catch (e) { NS.showErrors(form, e); NS.toast(e.message, true); return; }
      NS.toast('Evidence recorded'); m.close(); load();
    } }] });
  });
  await load();
}
