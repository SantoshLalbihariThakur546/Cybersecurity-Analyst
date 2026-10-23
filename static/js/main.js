'use strict';
/* App shell: authentication, navigation, hash router. */
const NAV = [
  { group: 'Program' },
  { key: 'overview', label: 'Overview', perm: 'data.read' },
  { group: 'Workstreams' },
  { key: 'threats', label: 'Threat landscape', wk: 1, perm: 'data.read' },
  { key: 'incidents', label: 'Incident response', wk: 2, perm: 'data.read', badge: true },
  { key: 'policy', label: 'Policy review', wk: 3, perm: 'data.read' },
  { key: 'awareness', label: 'Awareness campaign', wk: 4, perm: 'data.read' },
  { key: 'vulns', label: 'Vulnerability assessment', wk: 5, perm: 'data.read' },
  { key: 'audits', label: 'Audit plan', wk: 6, perm: 'data.read' },
  { group: 'Platform' },
  { key: 'reports', label: 'Reports and exports', perm: 'reports.read' },
  { key: 'auditlog', label: 'Audit log', perm: 'auditlog.read' },
  { key: 'users', label: 'Users and roles', perm: 'users.manage' },
];
const TITLES = Object.fromEntries(NAV.filter((n) => n.key).map((n) => [n.key, n.label]));

function showLogin() {
  $('#app').classList.add('hidden');
  $('#login-screen').classList.remove('hidden');
  $('#login-form [name=username]').focus();
}
NS.signedOut = () => {
  NS.state = { user: null, csrf: null, perms: new Set(), badge: 0 };
  NS.ref = {};
  showLogin();
};

function buildNav() {
  $('#nav').innerHTML = NAV.filter((n) => n.group || NS.can(n.perm)).map((n) => n.group
    ? `<div class="nav-group">${NS.esc(n.group)}</div>`
    : `<a href="#/${n.key}" data-page="${n.key}">${n.wk ? `<span class="wk">${n.wk}</span>` : '<span class="wk">&#9733;</span>'}<span>${NS.esc(n.label)}</span>${n.badge ? '<span class="badge-count hidden" id="nav-badge"></span>' : ''}</a>`).join('');
  $$('#nav a').forEach((a) => a.addEventListener('click', () => $('.rail').classList.remove('open')));
}

NS.refreshBadge = async () => {
  try {
    const s = await NS.api('/incidents-summary');
    const n = s.ack_breaches + s.ack_pending;
    const el = $('#nav-badge');
    if (el) { el.textContent = String(n); el.classList.toggle('hidden', n === 0); el.title = `${n} incident(s) awaiting acknowledgement or past target`; }
  } catch (e) { /* non-critical */ }
};

async function startApp(info) {
  NS.state.user = info.user;
  NS.state.csrf = info.csrf;
  NS.state.perms = new Set(info.user.permissions);
  $('#login-screen').classList.add('hidden');
  $('#app').classList.remove('hidden');
  $('#whoami').innerHTML = `<b>${NS.esc(info.user.full_name)}</b> &middot; ${NS.esc(info.user.role_label)}`;
  buildNav();
  try { const org = await NS.getRef('organization'); $('#org-name').textContent = org.name; } catch (e) { /* ignore */ }
  NS.refreshBadge();
  route();
}

let routeSeq = 0;
async function route() {
  if (!NS.state.user) return;
  const mySeq = ++routeSeq; // a slower, older navigation must never overwrite a newer one
  const parts = (location.hash.replace(/^#\//, '') || 'overview').split('/');
  const page = parts[0];
  const main = $('#main');
  $$('#nav a').forEach((a) => a.classList.toggle('active', a.dataset.page === page));
  const entry = NAV.find((n) => n.key === page);
  if (!entry || !NS.pages[page] || !NS.can(entry.perm)) {
    main.innerHTML = '<div class="panel"><h2>Page not available</h2><p>This page does not exist or your role cannot open it.</p><a class="btn" href="#/overview">Back to overview</a></div>';
    return;
  }
  $('#crumb').innerHTML = `Northstar <span>/</span> ${NS.esc(TITLES[page])}`;
  document.title = `${TITLES[page]} - Northstar`;
  main.innerHTML = '<p class="muted">Loading...</p>';
  const holder = document.createElement('div');
  try {
    await NS.pages[page](holder, parts.slice(1));
    if (mySeq !== routeSeq) return;
    main.innerHTML = '';
    main.appendChild(holder);
    NS.applyStyles(holder);
    main.focus({ preventScroll: true });
    window.scrollTo(0, 0);
  } catch (e) {
    if (mySeq !== routeSeq) return;
    main.innerHTML = `<div class="panel"><h2>Something went wrong</h2><p class="form-error">${NS.esc(e.message)}</p><button class="btn" onclick="location.reload()">Reload</button></div>`;
  }
}
NS.route = route;
window.addEventListener('hashchange', route);

$('#login-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const f = new FormData(ev.target);
  const err = $('#login-error');
  err.textContent = '';
  const btn = $('button[type=submit]', ev.target);
  btn.disabled = true;
  try {
    const data = await NS.api('/auth/login', { method: 'POST', body: { username: f.get('username'), password: f.get('password') } });
    ev.target.reset();
    await startApp(data);
  } catch (e) { err.textContent = e.message; } finally { btn.disabled = false; }
});
$('#logout').addEventListener('click', async () => {
  try { await NS.api('/auth/logout', { method: 'POST' }); } catch (e) { /* ignore */ }
  NS.signedOut();
});
$('#menu-btn').addEventListener('click', () => $('.rail').classList.toggle('open'));

(async function boot() {
  try { const me = await NS.api('/auth/session'); if (me.authenticated) await startApp(me); else showLogin(); } catch (e) { showLogin(); }
})();
