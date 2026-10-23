'use strict';
/* Northstar core: state, API client, helpers, modal, toast. All dynamic text goes through NS.esc(). */
const NS = { state: { user: null, csrf: null, perms: new Set(), badge: 0 }, pages: {} };
const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

NS.esc = (v) => String(v ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));
NS.can = (p) => NS.state.perms.has(p);
NS.fmtDT = (iso) => (iso ? NS.esc(String(iso).replace('T', ' ').slice(0, 16) + ' UTC') : '<span class="muted">-</span>');
NS.fmtD = (d) => (d ? NS.esc(d) : '<span class="muted">-</span>');
NS.num = (v, unit = '') => (v === null || v === undefined ? '<span class="muted">no data</span>' : NS.esc(v) + NS.esc(unit));
NS.minutes = (m) => {
  if (m === null || m === undefined) return '-';
  if (m < 60) return `${Math.round(m)} min`;
  const h = m / 60;
  return h < 48 ? `${h.toFixed(1)} h` : `${(h / 24).toFixed(1)} d`;
};
NS.qs = (o) => Object.entries(o).filter(([, v]) => v !== '' && v != null).map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`).join('&');

const CHIP = {
  'In Progress': 'info', 'In progress': 'info', 'Pending Verification': 'warn', 'Risk Accepted': 'warn', 'Not started': '', 'Planned': '',
  'Rescheduled': 'warn', 'Triage': 'info', 'Declared': 'warn', 'Contained': 'info', 'Eradicated': 'info', 'Recovered': 'ok', 'Mitigating': 'info',
  'Monitoring': 'info', 'Accepted': 'warn', 'Pending': 'warn', 'Approved': 'ok', 'Rejected': 'danger', 'Expired': 'danger', 'Partially effective': 'Medium',
  'Missing / not evidenced': 'Critical', 'Not assessed': '', 'Unanswered': '', 'No': 'Critical', 'N/A': '', 'Fail': 'Critical', 'Partial': 'Medium',
  'Not tested': '', 'Target met': 'ok', 'Below target': 'danger', 'Above target': 'danger', 'No data': '', 'Tracked': 'info', 'Active': 'info',
  'Not requested': '', 'Requested': 'info', 'Not available': 'danger', 'Not retested': '', 'Unknown': 'warn', 'Suspected': 'warn', 'Confirmed': 'danger',
  'Internet-facing': 'warn', 'Internal': '', 'Unsupported': 'danger', 'Supported': 'ok', 'Required': 'warn', 'Not required': ''};
NS.chip = (v, cls) => `<span class="chip ${NS.esc(cls !== undefined ? cls : (v in CHIP ? CHIP[v] : v))}">${NS.esc(v)}</span>`;
NS.bool = (b, yes = 'Yes', no = 'No') => (b ? NS.chip(yes, 'warn') : '<span class="muted">' + no + '</span>');

NS.toast = (msg, isErr) => {
  const t = $('#toast');
  t.textContent = msg;
  t.className = 'toast' + (isErr ? ' err' : '');
  clearTimeout(NS.toast.timer);
  NS.toast.timer = setTimeout(() => t.classList.add('hidden'), isErr ? 8000 : 4500);
};

NS.api = async (path, opts = {}) => {
  const method = opts.method || 'GET';
  const headers = { Accept: 'application/json' };
  let body;
  if (opts.form) body = opts.form;
  else if (opts.body !== undefined) { headers['Content-Type'] = 'application/json'; body = JSON.stringify(opts.body); }
  if (method !== 'GET' && NS.state.csrf) headers['X-CSRF-Token'] = NS.state.csrf;
  const res = await fetch('/api' + path, { method, headers, body, credentials: 'same-origin' });
  if (opts.raw) {
    if (!res.ok) throw await NS.toError(res);
    return res;
  }
  const data = await res.json().catch(() => ({}));
  if (!res.ok) {
    if (res.status === 401 && path !== '/auth/login' && NS.state.user) NS.signedOut();
    throw NS.fromData(res, data);
  }
  return data;
};
NS.toError = async (res) => NS.fromData(res, await res.json().catch(() => ({})));
NS.fromData = (res, data) => {
  const e = data.error || {};
  const err = new Error(e.message || `Request failed (${res.status})`);
  err.status = res.status; err.code = e.code; err.details = Array.isArray(e.details) ? e.details : [];
  return err;
};
NS.guard = (fn) => async (...a) => { try { return await fn(...a); } catch (e) { NS.toast(e.message, true); } };

NS.applyStyles = (root) => {
  $$('[data-w]', root).forEach((el) => { el.style.width = Math.max(0, Math.min(100, Number(el.dataset.w) || 0)) + '%'; });
};
NS.setHtml = (el, html) => { el.innerHTML = html; NS.applyStyles(el); };

NS.ref = {};
NS.getRef = async (name) => (NS.ref[name] = NS.ref[name] || await NS.api('/reference/' + name));

/* ---------------------------------------------------------------- modal */
NS.modal = ({ title, body, wide = false, foot = [], onClose }) => {
  const root = $('#modal-root');
  const prevFocus = document.activeElement;
  const overlay = document.createElement('div');
  overlay.className = 'overlay';
  overlay.innerHTML = `<div class="modal ${wide ? 'wide' : ''}" role="dialog" aria-modal="true" aria-labelledby="modal-title">
    <div class="modal-head"><h2 id="modal-title">${NS.esc(title)}</h2><span class="spacer"></span><button class="btn sm" data-close type="button" aria-label="Close dialog">Close</button></div>
    <div class="modal-body"></div><div class="modal-foot"></div></div>`;
  const bodyEl = $('.modal-body', overlay);
  if (typeof body === 'string') NS.setHtml(bodyEl, body); else bodyEl.appendChild(body);
  const footEl = $('.modal-foot', overlay);
  if (!foot.length) footEl.remove();
  const api = {
    root: overlay, body: bodyEl,
    close() { overlay.remove(); document.removeEventListener('keydown', onKey); if (prevFocus && prevFocus.focus) prevFocus.focus(); if (onClose) onClose(); },
  };
  foot.forEach((f) => {
    const b = document.createElement('button');
    b.type = 'button'; b.className = 'btn ' + (f.cls || ''); b.textContent = f.label;
    b.addEventListener('click', async () => {
      if (b.disabled) return;
      b.disabled = true;
      try { await f.onClick(api); } catch (e) { NS.toast(e.message, true); } finally { b.disabled = false; }
    });
    footEl.appendChild(b);
  });
  const onKey = (e) => {
    if (e.key === 'Escape') api.close();
    if (e.key === 'Tab') {
      const f = $$('button,input,select,textarea,a[href]', overlay).filter((x) => !x.disabled && x.offsetParent !== null);
      if (!f.length) return;
      const first = f[0], last = f[f.length - 1];
      if (e.shiftKey && document.activeElement === first) { e.preventDefault(); last.focus(); }
      else if (!e.shiftKey && document.activeElement === last) { e.preventDefault(); first.focus(); }
    }
  };
  document.addEventListener('keydown', onKey);
  $('[data-close]', overlay).addEventListener('click', () => api.close());
  overlay.addEventListener('mousedown', (e) => { if (e.target === overlay) api.close(); });
  root.appendChild(overlay);
  const first = $('input:not([type=hidden]),select,textarea', bodyEl) || $('[data-close]', overlay);
  if (first) first.focus();
  return api;
};

NS.confirm = (title, message, okLabel = 'Confirm', danger = false) => new Promise((resolve) => {
  let done = false;
  const m = NS.modal({ title, body: `<p>${NS.esc(message)}</p>`, onClose: () => { if (!done) resolve(false); },
    foot: [{ label: 'Cancel', onClick: (a) => a.close() }, { label: okLabel, cls: danger ? 'danger' : 'primary', onClick: (a) => { done = true; resolve(true); a.close(); } }] });
  return m;
});

/* ---------------------------------------------------------------- small UI helpers */
NS.head = (title, subtitle, actionsHtml = '', weekTag = '') => `<div class="page-head"><div><h1>${NS.esc(title)}</h1>
  ${subtitle || weekTag ? `<p>${weekTag ? `<span class="source-tag">${NS.esc(weekTag)}</span>` : ''}${NS.esc(subtitle || '')}</p>` : ''}</div>
  <div class="actions">${actionsHtml}</div></div>`;

NS.tabs = (root, defs, initial) => {
  const bar = document.createElement('div');
  bar.className = 'tabs'; bar.setAttribute('role', 'tablist');
  const pane = document.createElement('div');
  pane.className = 'tab-pane';
  root.appendChild(bar); root.appendChild(pane);
  let current = null;
  const show = async (key) => {
    current = key;
    $$('button', bar).forEach((b) => b.setAttribute('aria-selected', String(b.dataset.key === key)));
    pane.innerHTML = '<p class="muted">Loading...</p>';
    const def = defs.find((d) => d.key === key);
    const holder = document.createElement('div');
    try { await def.render(holder); } catch (e) { holder.innerHTML = `<div class="note bad">${NS.esc(e.message)}</div>`; }
    if (current === key) { pane.innerHTML = ''; pane.appendChild(holder); NS.applyStyles(holder); }
  };
  defs.forEach((d) => {
    const b = document.createElement('button');
    b.type = 'button'; b.dataset.key = d.key; b.textContent = d.label; b.setAttribute('role', 'tab');
    b.addEventListener('click', () => show(d.key));
    bar.appendChild(b);
  });
  show(initial || defs[0].key);
  return { show };
};

NS.kv = (pairs) => `<dl class="kv">${pairs.map(([k, v]) => `<dt>${NS.esc(k)}</dt><dd>${v === null || v === undefined || v === '' ? '<span class="muted">-</span>' : v}</dd>`).join('')}</dl>`;
NS.list = (items) => `<ul class="clean">${items.map((i) => `<li>${NS.esc(i)}</li>`).join('')}</ul>`;
NS.simpleTable = (headers, rows, opts = {}) => `<div class="table-wrap"><table><thead><tr>${headers.map((h) => `<th>${NS.esc(h)}</th>`).join('')}</tr></thead><tbody>${
  rows.length ? rows.map((r) => `<tr>${r.map((c, i) => `<td class="${opts.wrap && opts.wrap.includes(i) ? 'wrap' : ''}">${c ?? ''}</td>`).join('')}</tr>`).join('')
    : `<tr><td colspan="${headers.length}"><div class="empty">${NS.esc(opts.empty || 'Nothing here yet.')}</div></td></tr>`}</tbody></table></div>`;
NS.meter = (pct, cls = '') => `<div class="meter ${cls}" role="progressbar" aria-valuenow="${pct === null ? 0 : pct}" aria-valuemin="0" aria-valuemax="100"><i data-w="${pct === null ? 0 : pct}"></i></div>`;
