'use strict';
/* Generic form + register-table builder used by every module. */

/* field: {name,label,type,options,required,hint,full,placeholder,readonlyOnEdit,default}
   types: text textarea number date datetime select checkbox */
NS.fieldHtml = (f, value) => {
  const id = 'f_' + f.name;
  const v = value === null || value === undefined ? (f.default ?? '') : value;
  const req = f.required ? ' <span class="muted" aria-hidden="true">(required)</span>' : '';
  const hint = f.hint ? `<span class="hint">${NS.esc(f.hint)}</span>` : '';
  let ctl;
  if (f.type === 'textarea') ctl = `<textarea id="${id}" name="${f.name}" ${f.required ? 'required' : ''} placeholder="${NS.esc(f.placeholder || '')}">${NS.esc(v)}</textarea>`;
  else if (f.type === 'select') {
    const opts = (f.options || []).map((o) => (typeof o === 'object' ? o : { v: o, l: o }));
    ctl = `<select id="${id}" name="${f.name}" ${f.required ? 'required' : ''}>${f.required ? '' : '<option value=""></option>'}${opts.map((o) => `<option value="${NS.esc(o.v)}" ${String(o.v) === String(v) ? 'selected' : ''}>${NS.esc(o.l)}</option>`).join('')}</select>`;
  } else if (f.type === 'checkbox') {
    return `<label class="inline ${f.full ? 'full' : ''}"><input type="checkbox" id="${id}" name="${f.name}" ${v ? 'checked' : ''}> ${NS.esc(f.label)}</label>`;
  } else if (f.type === 'datetime') ctl = `<input id="${id}" name="${f.name}" type="datetime-local" value="${NS.esc(String(v).slice(0, 16))}">`;
  else if (f.type === 'number') ctl = `<input id="${id}" name="${f.name}" type="number" step="${f.step || 'any'}" ${f.min !== undefined ? `min="${f.min}"` : ''} ${f.max !== undefined ? `max="${f.max}"` : ''} value="${NS.esc(v)}" ${f.required ? 'required' : ''}>`;
  else ctl = `<input id="${id}" name="${f.name}" type="${f.type === 'date' ? 'date' : 'text'}" value="${NS.esc(v)}" ${f.required ? 'required' : ''} placeholder="${NS.esc(f.placeholder || '')}" maxlength="${f.maxlength || 300}">`;
  return `<label class="${f.full ? 'full' : ''}" for="${id}">${NS.esc(f.label)}${req}${ctl}${hint}<span class="field-error" data-err="${f.name}" role="alert"></span></label>`;
};
NS.formHtml = (fields, values = {}) => `<form class="form-grid" novalidate>${fields.map((f) => NS.fieldHtml(f, values[f.name])).join('')}</form>`;

NS.readForm = (root, fields) => {
  const out = {};
  fields.forEach((f) => {
    const el = $(`[name="${f.name}"]`, root);
    if (!el) return;
    if (f.type === 'checkbox') { out[f.name] = el.checked; return; }
    let v = el.value;
    if (v === '') { out[f.name] = ''; return; }
    if (f.type === 'number') out[f.name] = Number(v);
    else if (f.type === 'datetime') out[f.name] = v.length === 16 ? v + ':00Z' : v;
    else out[f.name] = v;
  });
  return out;
};

NS.showErrors = (root, err) => {
  $$('[data-err]', root).forEach((e) => { e.textContent = ''; });
  $$('.invalid', root).forEach((e) => e.classList.remove('invalid'));
  let shown = 0;
  (err.details || []).forEach((d) => {
    const slot = $(`[data-err="${d.field}"]`, root);
    if (slot) { slot.textContent = d.message; shown++; const inp = $(`[name="${d.field}"]`, root); if (inp) inp.classList.add('invalid'); }
  });
  return shown;
};

/* Opens a create/edit modal. cfg: {title, fields, values, endpoint, id, canWrite, canDelete, onSaved, extraFoot, prepare(payload)} */
NS.editModal = (cfg) => {
  const editing = cfg.id !== undefined && cfg.id !== null;
  const fields = cfg.fields;
  const form = document.createElement('div');
  form.innerHTML = (cfg.intro || '') + NS.formHtml(fields, cfg.values || {});
  if (!cfg.canWrite) $$('input,select,textarea', form).forEach((x) => { x.disabled = true; });
  const foot = [];
  if (editing && cfg.canDelete && cfg.canWrite) foot.push({ label: 'Delete', cls: 'danger', onClick: async (m) => {
    if (!(await NS.confirm('Delete record', 'This cannot be undone. Delete this record?', 'Delete', true))) return;
    await NS.api(`/${cfg.endpoint}/${cfg.id}`, { method: 'DELETE' });
    NS.toast('Deleted'); m.close(); if (cfg.onSaved) cfg.onSaved();
  } });
  (cfg.extraFoot || []).forEach((f) => foot.push(f));
  if (cfg.canWrite) foot.push({ label: editing ? 'Save changes' : (cfg.createLabel || 'Create'), cls: 'primary', onClick: async (m) => {
    let payload = NS.readForm(form, fields);
    if (cfg.prepare) payload = cfg.prepare(payload);
    try {
      if (editing) await NS.api(`/${cfg.endpoint}/${cfg.id}`, { method: 'PATCH', body: payload });
      else await NS.api(`/${cfg.endpoint}`, { method: 'POST', body: payload });
    } catch (e) {
      if (!NS.showErrors(form, e)) NS.toast(e.message, true);
      else NS.toast(e.message, true);
      return;
    }
    NS.toast(editing ? 'Changes saved' : (cfg.createdMessage || 'Created'));
    m.close(); if (cfg.onSaved) cfg.onSaved();
  } });
  else foot.push({ label: 'Close', onClick: (m) => m.close() });
  return NS.modal({ title: cfg.title, body: form, foot, wide: cfg.wide });
};

/* Register table. cfg: {endpoint, columns, fields, write, noun, search, filters, sort, canDelete, empty, rowClick, createLabel, defaults, toolbarExtra, onLoaded} */
NS.crudTable = async (root, cfg) => {
  const canWrite = cfg.write ? NS.can(cfg.write) : false;
  const wrap = document.createElement('div');
  root.appendChild(wrap);
  const filters = cfg.filters || [];
  let rows = [];
  const state = { q: '', f: {} };
  wrap.innerHTML = `<div class="toolbar">
    ${cfg.search === false ? '' : '<label class="grow">Search<input type="search" data-q placeholder="Search ' + NS.esc(cfg.noun || 'records') + '"></label>'}
    ${filters.map((f) => `<label>${NS.esc(f.label)}<select data-f="${f.key}"><option value="">All</option>${f.options.map((o) => `<option>${NS.esc(o)}</option>`).join('')}</select></label>`).join('')}
    ${cfg.toolbarExtra || ''}
    ${canWrite && cfg.fields ? `<button class="btn primary" type="button" data-add>Add ${NS.esc(cfg.noun || 'record')}</button>` : ''}
    ${cfg.exportName ? `<button class="btn" type="button" data-export>Export CSV</button>` : ''}
  </div><div data-table></div>`;
  const tableEl = $('[data-table]', wrap);
  const render = () => {
    const head = cfg.columns.map((c) => `<th>${NS.esc(c.label)}</th>`).join('');
    const body = rows.map((r, i) => `<tr class="${cfg.fields || cfg.rowClick ? 'clickable' : ''}" data-i="${i}" tabindex="${cfg.fields || cfg.rowClick ? 0 : -1}">${cfg.columns.map((c) => `<td class="${c.wrap ? 'wrap' : ''}">${c.render ? c.render(r) : NS.esc(r[c.key] ?? '')}</td>`).join('')}</tr>`).join('');
    NS.setHtml(tableEl, `<div class="table-wrap"><table><thead><tr>${head}</tr></thead><tbody>${body || `<tr><td colspan="${cfg.columns.length}"><div class="empty"><b>${NS.esc(cfg.empty || 'No records found')}</b>${canWrite && cfg.fields ? 'Use "Add" to create the first one.' : 'Adjust the search or filters.'}</div></td></tr>`}</tbody></table></div>
      <p class="muted count" data-count></p>`);
    $('[data-count]', tableEl).textContent = `${rows.length} ${rows.length === 1 ? 'record' : 'records'}`;
    $$('tr[data-i]', tableEl).forEach((tr) => {
      const open = () => openRow(rows[Number(tr.dataset.i)]);
      tr.addEventListener('click', open);
      tr.addEventListener('keydown', (e) => { if (e.key === 'Enter') open(); });
    });
  };
  const load = async () => {
    const params = { ...(cfg.baseParams || {}), ...state.f, q: state.q, sort: cfg.sort };
    const data = await NS.api(`/${cfg.endpoint}?` + NS.qs(params));
    rows = data.items;
    render();
    if (cfg.onLoaded) cfg.onLoaded(rows);
  };
  const openRow = (row) => {
    if (cfg.rowClick) return cfg.rowClick(row, load);
    if (!cfg.fields) return;
    NS.editModal({ title: `${cfg.noun ? cfg.noun[0].toUpperCase() + cfg.noun.slice(1) : 'Record'}${row.ref ? ' ' + row.ref : ''}`, fields: cfg.fields, values: row,
      endpoint: cfg.endpoint, id: row.id, canWrite, canDelete: cfg.canDelete, prepare: cfg.prepare, onSaved: () => { load(); if (cfg.onChange) cfg.onChange(); },
      intro: cfg.rowIntro ? cfg.rowIntro(row) : '', wide: cfg.wide });
  };
  const add = $('[data-add]', wrap);
  if (add) add.addEventListener('click', () => NS.editModal({ title: `Add ${cfg.noun || 'record'}`, fields: cfg.fields, values: cfg.defaults || {}, endpoint: cfg.endpoint,
    canWrite, createLabel: cfg.createLabel, prepare: cfg.prepare, onSaved: () => { load(); if (cfg.onChange) cfg.onChange(); }, wide: cfg.wide }));
  const q = $('[data-q]', wrap);
  if (q) { let t; q.addEventListener('input', () => { clearTimeout(t); t = setTimeout(() => { state.q = q.value; NS.guard(load)(); }, 250); }); }
  $$('[data-f]', wrap).forEach((s) => s.addEventListener('change', () => { state.f[s.dataset.f] = s.value; NS.guard(load)(); }));
  const ex = $('[data-export]', wrap);
  if (ex) ex.addEventListener('click', NS.guard(async () => NS.download(`/export/${cfg.exportName}.csv`, `${cfg.exportName}.csv`)));
  await load();
  return { reload: load, wrap };
};

NS.download = async (path, filename) => {
  const res = await NS.api(path, { raw: true });
  const blob = await res.blob();
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob); a.download = filename; document.body.appendChild(a); a.click(); a.remove();
  setTimeout(() => URL.revokeObjectURL(a.href), 3000);
};
NS.openHtml = async (path) => {
  const res = await NS.api(path, { raw: true });
  const blob = new Blob([await res.text()], { type: 'text/html' });
  window.open(URL.createObjectURL(blob), '_blank', 'noopener');
};
