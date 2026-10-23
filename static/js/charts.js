'use strict';
/* Dependency-free SVG/HTML charts. Colours come from CSS classes (CSP-safe: no inline style attributes). */
NS.charts = {};

NS.charts.donut = (items, label = '') => {
  const total = items.reduce((s, i) => s + i.value, 0);
  const R = 52, C = 2 * Math.PI * R;
  let offset = 0;
  const arcs = total ? items.filter((i) => i.value > 0).map((i) => {
    const len = (i.value / total) * C;
    const el = `<circle class="arc ${NS.esc(i.cls)}" cx="70" cy="70" r="${R}" fill="none" stroke-width="22" stroke-dasharray="${len.toFixed(2)} ${(C - len).toFixed(2)}" stroke-dashoffset="${(-offset).toFixed(2)}" transform="rotate(-90 70 70)"><title>${NS.esc(i.label)}: ${i.value}</title></circle>`;
    offset += len;
    return el;
  }).join('') : '<circle cx="70" cy="70" r="52" fill="none" stroke="#e4e9ef" stroke-width="22"/>';
  return `<div class="donut-wrap"><svg class="chart donut" viewBox="0 0 140 140" role="img" aria-label="${NS.esc(label)}: ${items.map((i) => i.label + ' ' + i.value).join(', ')}">${arcs}
    <text x="70" y="68" text-anchor="middle" class="donut-n">${total}</text><text x="70" y="86" text-anchor="middle" class="donut-l">${NS.esc(label)}</text></svg>
    <div class="legend">${items.map((i) => `<span><i class="${NS.esc(i.bg)}"></i>${NS.esc(i.label)} ${i.value}</span>`).join('')}</div></div>`;
};

NS.charts.bars = (items) => {
  const max = Math.max(1, ...items.map((i) => i.value));
  return `<div class="bars">${items.map((i) => `<div class="bar-row"><span class="bar-label">${NS.esc(i.label)}</span>
    <span class="bar-track"><i class="${NS.esc(i.bg)}" data-w="${(i.value / max) * 100}"></i></span><span class="bar-val">${NS.esc(i.display ?? i.value)}</span></div>`).join('')}</div>`;
};

/* 5x5 likelihood x impact matrix; cells: {"L-I": ["R1","R2"]} */
NS.charts.riskMatrix5 = (cells) => {
  const W = 340, H = 300, ox = 44, oy = 10, cw = 56, ch = 52;
  let svg = '';
  for (let l = 1; l <= 5; l++) for (let i = 1; i <= 5; i++) {
    const s = l * i;
    const cls = s >= 20 ? 'cell-crit' : s >= 12 ? 'cell-high' : s >= 6 ? 'cell-med' : 'cell-low';
    const x = ox + (i - 1) * cw, y = oy + (5 - l) * ch;
    const refs = cells[`${l}-${i}`] || [];
    svg += `<rect class="${cls}" x="${x}" y="${y}" width="${cw - 2}" height="${ch - 2}" rx="3"><title>Likelihood ${l} x Impact ${i} = ${s}${refs.length ? ': ' + refs.join(', ') : ''}</title></rect>`;
    if (refs.length) svg += `<text x="${x + cw / 2 - 1}" y="${y + ch / 2 + 4}" text-anchor="middle" font-weight="700">${NS.esc(refs.length > 2 ? refs.length + ' risks' : refs.join(' '))}</text>`;
  }
  for (let k = 1; k <= 5; k++) {
    svg += `<text x="${ox - 10}" y="${oy + (5 - k) * ch + ch / 2 + 4}" text-anchor="end">${k}</text><text x="${ox + (k - 1) * cw + cw / 2}" y="${oy + 5 * ch + 16}" text-anchor="middle">${k}</text>`;
  }
  svg += `<text x="${ox + 2.5 * cw}" y="${H - 6}" text-anchor="middle">Impact</text><text transform="rotate(-90)" x="${-(oy + 2.5 * ch)}" y="12" text-anchor="middle">Likelihood</text>`;
  return `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Risk matrix: likelihood by impact, 5 by 5">${svg}</svg>`;
};

/* 4x4 threat scenario map using fractional coordinates (1-4) */
NS.charts.threatMap = (points) => {
  const W = 470, H = 360, ox = 76, oy = 12, cw = 96, ch = 78;
  let svg = '';
  for (let l = 1; l <= 4; l++) for (let i = 1; i <= 4; i++) {
    const s = l * i;
    const cls = s >= 9 ? 'cell-crit' : s >= 6 ? 'cell-high' : s >= 3 ? 'cell-med' : 'cell-low';
    svg += `<rect class="${cls}" x="${ox + (i - 1) * cw}" y="${oy + (4 - l) * ch}" width="${cw - 2}" height="${ch - 2}" rx="3"/>`;
  }
  ['Low', 'Medium', 'High', 'Very high'].forEach((t, k) => {
    svg += `<text x="${ox - 8}" y="${oy + (3 - k) * ch + ch / 2 + 4}" text-anchor="end">${t}</text><text x="${ox + k * cw + cw / 2}" y="${oy + 4 * ch + 16}" text-anchor="middle">${t}</text>`;
  });
  points.forEach((p, idx) => {
    const x = ox + (p.impact - 0.5) * cw - 1, y = oy + (4 - p.likelihood + 0.5) * ch - 1;
    const cls = p.rating === 'Critical' ? 'c-crit' : p.rating === 'High' ? 'c-high' : p.rating === 'Medium' ? 'c-med' : 'c-low';
    svg += `<g><circle class="${cls}" cx="${x}" cy="${y}" r="11" stroke="#fff" stroke-width="2"><title>${NS.esc(p.name)} (likelihood ${p.likelihood}, impact ${p.impact}, ${p.rating})</title></circle>
      <text x="${x}" y="${y + 4}" text-anchor="middle" font-weight="700" fill="#fff" class="pt">${p.n || idx + 1}</text></g>`;
  });
  svg += `<text x="${ox + 2 * cw}" y="${H - 6}" text-anchor="middle">Impact</text><text transform="rotate(-90)" x="${-(oy + 2 * ch)}" y="12" text-anchor="middle">Likelihood</text>`;
  return `<svg class="chart" viewBox="0 0 ${W} ${H}" role="img" aria-label="Threat scenario map, likelihood against impact">${svg}</svg>`;
};

NS.charts.compare = (rows) => rows.map((r) => `<div class="cmp"><div class="cmp-h"><span>${NS.esc(r.label)}</span></div>
  ${r.bars.map((b) => `<div class="bar-row"><span class="bar-label">${NS.esc(b.label)}</span><span class="bar-track"><i class="${NS.esc(b.bg)}" data-w="${b.value ?? 0}"></i></span><span class="bar-val">${b.value === null ? 'no data' : b.value + '%'}</span></div>`).join('')}</div>`).join('');
