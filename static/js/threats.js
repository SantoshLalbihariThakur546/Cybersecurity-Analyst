'use strict';
/* Week 1 - Threat landscape analysis */
NS.pages.threats = async (root) => {
  root.innerHTML = NS.head('Threat landscape', 'Which threats matter most for the organization, how they work, and which controls answer them.',
    '', 'Week 1');
  const SCALE = [{ v: 1, l: '1 - Low' }, { v: 1.5, l: '1.5 - Low to medium' }, { v: 2, l: '2 - Medium' }, { v: 2.5, l: '2.5 - Medium to high' }, { v: 3, l: '3 - High' }, { v: 3.5, l: '3.5' }, { v: 4, l: '4 - Very high' }];
  const w = 'threats.write';
  NS.tabs(root, [
    { key: 'register', label: 'Threat register', render: async (el) => {
      el.innerHTML = `<div class="grid g-main"><section class="panel"><h2>Scenario map</h2><div data-map></div></section>
        <section class="panel"><h2>Scenarios by score</h2><ol class="clean small-list" data-list></ol>
        <div class="note info">Ratings are documented expert judgments, not measurements. Score = likelihood x impact on the 1-4 scale and is only a prioritisation aid.</div></section></div><div data-table></div>`;
      await NS.crudTable($('[data-table]', el), {
        endpoint: 'threats', noun: 'threat scenario', write: w, canDelete: true, exportName: 'threats', sort: '-id', wide: true,
        filters: [{ key: 'indicative_rating', label: 'Rating', options: ['Critical', 'High', 'Medium', 'Low'] }, { key: 'status', label: 'Status', options: ['Open', 'Mitigating', 'Monitoring', 'Accepted'] }],
        columns: [
          { label: 'Scenario', wrap: true, render: (r) => `<b>${NS.esc(r.name)}</b><div class="muted">${NS.esc(r.category || '')}</div>` },
          { label: 'L', render: (r) => NS.esc(r.likelihood) }, { label: 'I', render: (r) => NS.esc(r.impact) },
          { label: 'Score', render: (r) => `${r.score} ${NS.chip(r.score_band)}` },
          { label: 'Indicative rating', render: (r) => NS.chip(r.indicative_rating) }, { label: 'Status', render: (r) => NS.chip(r.status) },
          { label: 'Owner', key: 'owner' }, { label: 'Next review', render: (r) => NS.fmtD(r.review_date) + (r.review_overdue ? ' ' + NS.chip('OVERDUE', 'danger') : '') }],
        fields: [
          { name: 'name', label: 'Scenario', required: true, full: true }, { name: 'category', label: 'Category', full: true },
          { name: 'likelihood', label: 'Likelihood', type: 'select', options: SCALE, required: true, default: 2 }, { name: 'impact', label: 'Impact', type: 'select', options: SCALE, required: true, default: 2 },
          { name: 'indicative_rating', label: 'Indicative rating', type: 'select', options: ['Critical', 'High', 'Medium', 'Low'], required: true, default: 'Medium' },
          { name: 'status', label: 'Status', type: 'select', options: ['Open', 'Mitigating', 'Monitoring', 'Accepted'], required: true, default: 'Open' },
          { name: 'owner', label: 'Owner' }, { name: 'review_date', label: 'Next review date', type: 'date' },
          { name: 'reasoning', label: 'Reasoning', type: 'textarea', full: true }, { name: 'controls', label: 'Priority controls', type: 'textarea', full: true }],
        onLoaded: (rows) => {
          const pts = rows.map((r) => ({ ...r, rating: r.indicative_rating })).sort((a, b) => b.score - a.score || a.name.localeCompare(b.name)).map((r, i) => ({ ...r, n: i + 1 }));
          NS.setHtml($('[data-map]', el), NS.charts.threatMap(pts));
          NS.setHtml($('[data-list]', el), pts.map((p) => `<li>${NS.esc(p.name)} ${NS.chip(p.rating)}</li>`).join(''));
        } });
    } },
    { key: 'actors', label: 'Threat actors', render: (el) => NS.crudTable(el, { endpoint: 'threat-actors', noun: 'actor group', write: w, canDelete: true, wide: true,
      columns: [{ label: 'Actor', key: 'category' }, { label: 'Goals', key: 'goals', wrap: true }, { label: 'Typical approaches', key: 'approaches', wrap: true }, { label: 'Indicators', key: 'indicators', wrap: true }],
      fields: [{ name: 'category', label: 'Actor category', required: true, full: true }, { name: 'goals', label: 'Goals', type: 'textarea', full: true }, { name: 'approaches', label: 'Typical approaches', type: 'textarea', full: true }, { name: 'indicators', label: 'Observable indicators', type: 'textarea', full: true }] }) },
    { key: 'categories', label: 'Threat categories', render: (el) => NS.crudTable(el, { endpoint: 'threat-categories', noun: 'threat category', write: w, canDelete: true, wide: true,
      columns: [{ label: 'Category', render: (r) => `<b>${NS.esc(r.name)}</b>`, wrap: true }, { label: 'What it is', key: 'description', wrap: true }, { label: 'Potential impact', key: 'potential_impact', wrap: true }, { label: 'Priority controls', key: 'priority_controls', wrap: true }],
      fields: [{ name: 'name', label: 'Category', required: true, full: true }, { name: 'description', label: 'Description', type: 'textarea', full: true }, { name: 'potential_impact', label: 'Potential impact', type: 'textarea', full: true }, { name: 'priority_controls', label: 'Priority controls', type: 'textarea', full: true }] }) },
    { key: 'chain', label: 'Attack chain and scale', render: async (el) => {
      const [stages, scale, dims] = await Promise.all([NS.getRef('attack_stages'), NS.getRef('scale'), NS.getRef('impact_dimensions')]);
      el.innerHTML = `<section class="panel"><h2>Attack chain: detect and respond at each stage</h2>${NS.simpleTable(['Stage', 'Detection opportunities', 'Response actions'], stages.map((s) => [`<b>${NS.esc(s.stage)}</b>`, NS.esc(s.detection), NS.esc(s.response)]), { wrap: [1, 2] })}</section>
        <section class="panel"><h2>Likelihood and impact scale (1-4)</h2>${NS.simpleTable(['Score', 'Level', 'Likelihood meaning', 'Impact meaning'], scale.map((s) => [s.score, `<b>${NS.esc(s.label)}</b>`, NS.esc(s.likelihood), NS.esc(s.impact)]), { wrap: [2, 3] })}</section>
        <section class="panel"><h2>Impact dimensions</h2>${NS.simpleTable(['Dimension', 'Examples'], dims.map((d) => [`<b>${NS.esc(d.dimension)}</b>`, NS.esc(d.examples)]), { wrap: [1] })}</section>`;
    } },
    { key: 'priorities', label: 'Defensive priorities', render: async (el) => {
      const p = await NS.getRef('defensive_priorities');
      el.innerHTML = `<div class="grid g3">${p.map((h) => `<section class="panel"><h2>${NS.esc(h.horizon)}</h2>${NS.list(h.items)}</section>`).join('')}</div>`;
    } },
    { key: 'sources', label: 'Evidence sources', render: (el) => NS.crudTable(el, { endpoint: 'intel-sources', noun: 'source', write: w, canDelete: true, wide: true,
      columns: [{ label: 'Source', wrap: true, render: (r) => `<b>${NS.esc(r.title)}</b><div class="muted">${NS.esc(r.publisher || '')} - ${NS.esc(r.period || '')}</div>` }, { label: 'Use in analysis', key: 'finding', wrap: true }, { label: 'Caution', key: 'caution', wrap: true },
        { label: 'Link', render: (r) => (r.url ? `<a href="${NS.esc(r.url)}" target="_blank" rel="noopener noreferrer">Open</a>` : '') }],
      fields: [{ name: 'title', label: 'Title', required: true, full: true }, { name: 'publisher', label: 'Publisher' }, { name: 'period', label: 'Period covered' }, { name: 'finding', label: 'What it tells us', type: 'textarea', full: true }, { name: 'caution', label: 'Limitations', type: 'textarea', full: true }, { name: 'url', label: 'URL', full: true }] }) },
    { key: 'log', label: 'Research log', render: (el) => NS.crudTable(el, { endpoint: 'research-log', noun: 'research entry', write: w, canDelete: true, sort: '-id', wide: true, defaults: { logged_at: new Date().toISOString().slice(0, 16) },
      columns: [{ label: 'Logged', render: (r) => NS.fmtDT(r.logged_at) }, { label: 'Question', key: 'question', wrap: true }, { label: 'Source', key: 'source', wrap: true }, { label: 'Evidence', key: 'evidence', wrap: true }, { label: 'Reliability', key: 'reliability', wrap: true }, { label: 'Report section', key: 'report_section' }],
      fields: [{ name: 'logged_at', label: 'Logged (UTC)', type: 'datetime' }, { name: 'report_section', label: 'Report section' }, { name: 'question', label: 'Research question', type: 'textarea', required: true, full: true }, { name: 'source', label: 'Source / URL', full: true }, { name: 'evidence', label: 'Evidence found', type: 'textarea', full: true }, { name: 'reliability', label: 'Reliability notes', type: 'textarea', full: true }] }) },
  ]);
};
