'use strict';
NS.pages.overview = async (root) => {
  const d = await NS.api('/dashboard');
  const t = d.threats, inc = d.incidents, pol = d.policy, awr = d.awareness, vul = d.vulns, aud = d.audit;
  const att = d.attention;
  const pageOf = { Incident: 'incidents', Vulnerability: 'vulns', Audit: 'audits', Policy: 'policy', Threat: 'threats' };
  const metric = (n) => awr.metrics.find((m) => m.name === n) || {};

  root.innerHTML = NS.head('Program overview', `${d.organization.name} - ${d.today}. Everything below comes from the six workstreams.`,
    `<button class="btn" data-report type="button">Executive report</button>`);
  const hero = document.createElement('section');
  hero.className = 'attention' + (att.length ? '' : ' clear');
  hero.setAttribute('aria-labelledby', 'att-h');
  hero.innerHTML = `<div class="attention-head"><h2 id="att-h">${att.length ? 'Needs attention' : 'Nothing is overdue'}</h2>
    <span class="muted">${att.length ? `${d.attention_total} item${d.attention_total === 1 ? '' : 's'} ordered by severity` : 'No missed acknowledgements, overdue findings or expired exceptions.'}</span></div>
    ${att.length ? `<ul>${att.slice(0, 8).map((a) => `<li><span>${NS.chip(a.severity)}</span><span class="muted">${NS.esc(a.kind)}</span><span>${NS.esc(a.label)}</span>
      <a href="#/${pageOf[a.kind] || 'overview'}">Open</a></li>`).join('')}</ul>` : ''}`;
  root.appendChild(hero);

  const sr = document.createElement('div');
  sr.className = 'stat-row';
  sr.innerHTML = `
    <div class="stat ${inc.open ? 'bad' : 'good'}"><div class="n">${inc.open}</div><div class="l">open incidents</div></div>
    <div class="stat ${vul.overdue ? 'bad' : ''}"><div class="n">${vul.open}</div><div class="l">open vulnerability findings${vul.overdue ? ` (${vul.overdue} overdue)` : ''}</div></div>
    <div class="stat ${aud.overdue_critical_high ? 'bad' : ''}"><div class="n">${aud.findings_open}</div><div class="l">open audit findings</div></div>
    <div class="stat"><div class="n">${(pol.risk_bands.Critical || 0) + (pol.risk_bands.High || 0)}</div><div class="l">critical or high policy risks</div></div>
    <div class="stat ${metric('Knowledge improvement').met ? 'good' : ''}"><div class="n">${awr.quiz.improvement_pp === null ? '-' : (awr.quiz.improvement_pp > 0 ? '+' : '') + awr.quiz.improvement_pp}</div><div class="l">quiz change, percentage points</div></div>`;
  root.appendChild(sr);

  const topThreat = t.top[0];
  const streams = [
    { wk: 1, page: 'threats', title: 'Threat landscape', big: `${t.by_rating.Critical} critical`, sub: topThreat ? `Top scenario: ${topThreat.name}` : 'No scenarios yet' },
    { wk: 2, page: 'incidents', title: 'Incident response', big: `${inc.open} open`, sub: `${inc.ack_breaches} past acknowledgement target; avg ack ${NS.minutes(inc.avg_minutes.time_to_acknowledge_min)}` },
    { wk: 3, page: 'policy', title: 'Policy review', big: `${pol.actions_completed}/${pol.actions_total} actions`, sub: `${pol.ratings.Weak} weak controls; ${pol.exceptions_expired} expired exceptions` },
    { wk: 4, page: 'awareness', title: 'Awareness campaign', big: awr.campaign ? `${metric('Training completion').current ?? 0}% complete` : 'Not set up', sub: `Reach ${metric('Reach').current ?? 0}% (target 90%); tasks ${awr.tasks.completed}/${awr.tasks.total} done` },
    { wk: 5, page: 'vulns', title: 'Vulnerability assessment', big: `${vul.open} open`, sub: `SLA compliance ${vul.sla_compliance_pct ?? '-'}%; Critical/High resolved ${vul.critical_high_resolved_pct ?? '-'}%` },
    { wk: 6, page: 'audits', title: 'Audit plan', big: `${aud.plan_completion_pct ?? 0}% of plan`, sub: `${aud.findings_open} open findings; ${aud.overdue_critical_high} Critical/High overdue` },
  ];
  const sg = document.createElement('div');
  sg.className = 'streams';
  sg.innerHTML = streams.map((s) => `<a class="stream" href="#/${s.page}"><div class="k"><span class="wk">${s.wk}</span>${NS.esc(s.title)}</div><div class="big">${NS.esc(s.big)}</div><div class="sub">${NS.esc(s.sub)}</div></a>`).join('');
  root.appendChild(sg);

  const grid = document.createElement('div');
  grid.className = 'grid g2';
  const pts = [...t.points].sort((a, b) => b.likelihood * b.impact - a.likelihood * a.impact || a.name.localeCompare(b.name)).map((p, i) => ({ ...p, n: i + 1 }));
  grid.innerHTML = `
    <section class="panel"><div class="panel-head"><h2>Threat scenario map</h2><span class="spacer"></span><a href="#/threats">Open register</a></div>
      <div class="grid g-main">${NS.charts.threatMap(pts)}<ol class="clean small-list">${pts.map((p) => `<li>${NS.esc(p.name)} ${NS.chip(p.rating)}</li>`).join('')}</ol></div></section>
    <section class="panel"><div class="panel-head"><h2>Open vulnerabilities by severity</h2><span class="spacer"></span><a href="#/vulns">Open findings</a></div>
      ${NS.charts.donut([{ label: 'Critical', value: vul.open_by_severity.Critical, cls: 'c-crit', bg: 'bg-crit' }, { label: 'High', value: vul.open_by_severity.High, cls: 'c-high', bg: 'bg-high' },
        { label: 'Medium', value: vul.open_by_severity.Medium, cls: 'c-med', bg: 'bg-med' }, { label: 'Low', value: vul.open_by_severity.Low, cls: 'c-low', bg: 'bg-low' }], 'open')}
      <p class="muted">Remediation targets: exploited 72 h, Critical 7 d, High 14 d, Medium 30 d, Low 90 d.</p></section>
    <section class="panel"><div class="panel-head"><h2>Policy risk matrix</h2><span class="spacer"></span><a href="#/policy">Open register</a></div>
      ${NS.charts.riskMatrix5(pol.risk_matrix)}</section>
    <section class="panel"><div class="panel-head"><h2>Awareness objectives</h2><span class="spacer"></span><a href="#/awareness">Open campaign</a></div>
      ${awr.metrics.map((m) => `<div class="objective"><div><b>${NS.esc(m.name)}</b><div class="muted">${NS.esc(m.goal)}</div></div>
        <div>${m.current === null ? '<span class="muted">no data</span>' : NS.esc(m.current) + NS.esc(m.unit)} <span class="muted">/ ${m.target}${NS.esc(m.unit)}</span></div>
        ${NS.meter(m.current === null ? 0 : Math.min(100, (m.current / m.target) * 100), m.met ? 'good' : 'warn')}</div>`).join('')}</section>`;
  root.appendChild(grid);
  $('[data-report]', root).addEventListener('click', NS.guard(() => NS.openHtml('/reports/executive')));
};
