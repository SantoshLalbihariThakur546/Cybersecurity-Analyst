'use strict';
/* Reports and exports, audit log, user administration */
NS.pages.reports = async (root) => {
  root.innerHTML = NS.head('Reports and exports', 'Printable summaries and CSV exports. Every export is recorded in the audit log.') + `
    <div class="grid g2"><section class="panel"><h2>Executive summary</h2><p>One printable page covering all six workstreams, the needs-attention queue and key tables.</p><button class="btn primary" data-exec type="button">Open executive summary</button></section>
    <section class="panel"><h2>Post-incident reports</h2><p>Open an incident and choose "Post-incident report" to generate the eleven-section report with its timeline, evidence hashes and corrective actions.</p><a class="btn" href="#/incidents">Go to incidents</a></section></div>
    <section class="panel"><h2>CSV exports</h2><p class="muted">Cells that start with a formula character are neutralised so spreadsheets cannot run them.</p>
    <div class="toolbar">${[['threats', 'Threat register'], ['incidents', 'Incidents'], ['policy-controls', 'Policy controls'], ['policy-risks', 'Policy risks'], ['policy-actions', 'Roadmap actions'], ['policy-exceptions', 'Policy exceptions'],
      ['campaign-tasks', 'Campaign tasks'], ['vuln-findings', 'Vulnerability findings'], ['audit-calendar', 'Audit calendar'], ['audit-findings', 'Audit findings']].map(([k, l]) => `<button class="btn" data-x="${k}" type="button">${l}</button>`).join('')}</div></section>`;
  $('[data-exec]', root).addEventListener('click', NS.guard(() => NS.openHtml('/reports/executive')));
  $$('[data-x]', root).forEach((b) => b.addEventListener('click', NS.guard(() => NS.download(`/export/${b.dataset.x}.csv`, `${b.dataset.x}.csv`))));
};

NS.pages.auditlog = async (root) => {
  root.innerHTML = NS.head('Audit log', 'Append-only record of sign-ins, changes, denials, exports and evidence access. Entries are hash-chained so tampering is detectable.') +
    '<div class="toolbar"><button class="btn primary" data-verify type="button">Verify chain integrity</button><span data-result class="muted"></span></div><div data-table></div>';
  $('[data-verify]', root).addEventListener('click', NS.guard(async () => {
    const v = await NS.api('/audit-log/verify');
    $('[data-result]', root).innerHTML = v.valid ? NS.chip(`Chain valid - ${v.entries_checked} entries`, 'ok') : NS.chip(`CHAIN BROKEN at entry ${v.first_invalid_id}`, 'danger');
  }));
  let offset = 0;
  const holder = $('[data-table]', root);
  const load = async () => {
    const d = await NS.api('/audit-log?' + NS.qs({ limit: 40, offset }));
    NS.setHtml(holder, NS.simpleTable(['#', 'Time (UTC)', 'Actor', 'Action', 'Object', 'Details'], d.items.map((e) => [e.id, NS.fmtDT(e.ts), NS.esc(e.actor || ''), NS.chip(e.action, /DENIED|FAILED/.test(e.action) ? 'danger' : ''),
      NS.esc((e.entity || '') + (e.entity_id ? ' #' + e.entity_id : '')), `<code>${NS.esc((e.details || '').slice(0, 120))}</code>`]), { wrap: [5] }) +
      `<div class="toolbar"><button class="btn" data-prev ${offset <= 0 ? 'disabled' : ''}>Newer</button><span class="muted">${d.total ? offset + 1 : 0}-${Math.min(offset + d.limit, d.total)} of ${d.total}</span><button class="btn" data-next ${offset + d.limit >= d.total ? 'disabled' : ''}>Older</button></div>`);
    $('[data-prev]', holder).onclick = () => { offset = Math.max(0, offset - d.limit); NS.guard(load)(); };
    $('[data-next]', holder).onclick = () => { offset += d.limit; NS.guard(load)(); };
  };
  await load();
};

NS.pages.users = async (root) => {
  root.innerHTML = NS.head('Users and roles', 'Access follows the role: analysts run the program, auditors own the audit plan, viewers have read-only access.', '<button class="btn primary" data-add type="button">Add user</button>') + '<div data-table></div>';
  const ROLES = [{ v: 'admin', l: 'Administrator (CISO / security lead)' }, { v: 'analyst', l: 'Security analyst' }, { v: 'auditor', l: 'Audit lead' }, { v: 'viewer', l: 'Executive viewer (read-only)' }];
  const holder = $('[data-table]', root);
  const load = async () => {
    const d = await NS.api('/users');
    NS.setHtml(holder, NS.simpleTable(['Username', 'Name', 'Role', 'Status', 'Actions'], d.items.map((u) => [`<b>${NS.esc(u.username)}</b>`, NS.esc(u.full_name), NS.esc(u.role_label), u.active ? NS.chip('Active', 'ok') : NS.chip('Disabled', 'danger'),
      `<button class="btn sm" data-edit="${u.id}">Edit</button> <button class="btn sm" data-pw="${u.id}">Reset password</button>`])));
    $$('[data-edit]', holder).forEach((b) => b.addEventListener('click', () => {
      const u = d.items.find((x) => String(x.id) === b.dataset.edit);
      NS.editModal({ title: `Edit ${u.username}`, endpoint: 'users', id: u.id, canWrite: true, values: { ...u, active: u.active }, onSaved: load,
        fields: [{ name: 'full_name', label: 'Full name', full: true }, { name: 'role', label: 'Role', type: 'select', options: ROLES, required: true }, { name: 'active', label: 'Account is active', type: 'checkbox', full: true }] });
    }));
    $$('[data-pw]', holder).forEach((b) => b.addEventListener('click', () => {
      const u = d.items.find((x) => String(x.id) === b.dataset.pw);
      NS.editModal({ title: `Reset password for ${u.username}`, endpoint: 'users', id: u.id, canWrite: true, values: {}, onSaved: load,
        fields: [{ name: 'password', label: 'New password', required: true, hint: 'At least 10 characters with letters and digits', full: true }] });
    }));
  };
  $('[data-add]', root).addEventListener('click', () => NS.editModal({ title: 'Add user', endpoint: 'users', canWrite: true, values: { role: 'analyst' }, onSaved: load, createLabel: 'Create user',
    fields: [{ name: 'username', label: 'Username', required: true }, { name: 'full_name', label: 'Full name' }, { name: 'role', label: 'Role', type: 'select', options: ROLES, required: true }, { name: 'password', label: 'Initial password', required: true, hint: 'At least 10 characters with letters and digits' }] }));
  await load();
};
