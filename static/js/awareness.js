'use strict';
/* Week 4 - Security awareness campaign */
NS.pages.awareness = async (root) => {
  const w = 'awareness.write';
  root.innerHTML = NS.head('Awareness campaign', 'Pause. Check. Protect. - plan, run and measure the four-week campaign. Quiz and survey answers are anonymous.', '', 'Week 4');
  const STATUS = ['Not started', 'In progress', 'Completed', 'Blocked'];
  NS.tabs(root, [
    { key: 'objectives', label: 'Objectives and results', render: async (el) => {
      const s = await NS.api('/awareness-summary');
      const c = s.campaign;
      el.innerHTML = `<div class="grid g-main"><section class="panel"><div class="panel-head"><h2>${NS.esc(c.name)}</h2><span class="spacer"></span>${NS.chip(c.status)}${NS.can(w) ? ' <button class="btn sm" data-edit type="button">Update numbers</button>' : ''}</div>
        <p class="muted">${NS.esc(c.tagline || '')}</p>
        ${NS.kv([['Eligible employees', NS.esc(c.eligible_employees)], ['Reached', NS.esc(c.reached_count)], ['Completed training', NS.esc(c.completed_count)], ['Start date', NS.fmtD(c.start_date)], ['Sponsor', NS.esc(c.sponsor || '')], ['Owner', NS.esc(c.owner || '')]])}
        <h2 class="mt">Objectives</h2>
        ${s.metrics.map((m) => `<div class="objective"><div><b>${NS.esc(m.name)}</b><div class="muted">${NS.esc(m.goal)}${m.note ? ' - ' + NS.esc(m.note) : ''}</div></div>
          <div>${m.current === null ? '<span class="muted">no data</span>' : '<b>' + NS.esc(m.current) + NS.esc(m.unit) + '</b>'} <span class="muted">/ target ${m.target}${NS.esc(m.unit)}</span> ${m.met === null ? '' : NS.chip(m.met ? 'Target met' : 'Below target')}</div>
          ${NS.meter(m.current === null ? 0 : Math.max(0, Math.min(100, (m.current / m.target) * 100)), m.met ? 'good' : 'warn')}</div>`).join('')}</section>
        <div><section class="panel"><h2>Knowledge check</h2>${NS.charts.compare([{ label: 'Average quiz score', bars: [{ label: `Baseline (n=${s.quiz.baseline_n})`, value: s.quiz.baseline_pct, bg: 'bg-muted' }, { label: `After (n=${s.quiz.post_n})`, value: s.quiz.post_pct, bg: 'bg-signal' }] }])}
          <p class="muted">${s.quiz.improvement_pp === null ? 'Collect baseline and post-campaign attempts to measure improvement.' : `Change: ${s.quiz.improvement_pp > 0 ? '+' : ''}${s.quiz.improvement_pp} percentage points.`}</p></section>
        <section class="panel"><h2>Phishing simulation</h2>${['baseline', 'follow_up'].map((p) => s.simulations[p] ? NS.charts.compare([{ label: p === 'baseline' ? 'Baseline' : 'Follow-up', bars: [{ label: 'Clicked', value: s.simulations[p].click_rate, bg: 'bg-high' }, { label: 'Reported', value: s.simulations[p].report_rate, bg: 'bg-low' }] }]) : '').join('') || '<p class="muted">No simulation results recorded.</p>'}
          ${s.simulation_trend ? `<p class="muted">Click rate ${s.simulation_trend.click_rate_change_pp > 0 ? '+' : ''}${s.simulation_trend.click_rate_change_pp} pp; report rate ${s.simulation_trend.report_rate_change_pp > 0 ? '+' : ''}${s.simulation_trend.report_rate_change_pp} pp. Reporting matters more than avoiding clicks.</p>` : ''}</section>
        <section class="panel"><h2>Feedback pulse</h2>${s.feedback.n ? NS.kv([['Responses', s.feedback.n], ['Relevance (1-5)', s.feedback.avg_relevance], ['Confidence to report (1-5)', s.feedback.avg_confidence], ['Know how to report', s.feedback.knows_reporting_pct + '%']]) : '<p class="muted">No responses yet.</p>'}</section></div></div>`;
      const ed = $('[data-edit]', el);
      if (ed) ed.addEventListener('click', () => NS.editModal({ title: 'Update campaign numbers', endpoint: 'campaigns', id: c.id, canWrite: true, values: c, onSaved: () => NS.route(),
        fields: [{ name: 'name', label: 'Campaign name', required: true, full: true }, { name: 'eligible_employees', label: 'Eligible employees', type: 'number', step: 1, min: 1, required: true },
          { name: 'start_date', label: 'Start date', type: 'date' }, { name: 'reached_count', label: 'Employees reached', type: 'number', step: 1, min: 0 }, { name: 'completed_count', label: 'Completed training', type: 'number', step: 1, min: 0 },
          { name: 'status', label: 'Status', type: 'select', options: ['Planned', 'Active', 'Completed'], required: true }, { name: 'sponsor', label: 'Sponsor' }, { name: 'owner', label: 'Owner' }] }));
    } },
    { key: 'schedule', label: 'Four-week schedule', render: (el) => NS.crudTable(el, { endpoint: 'campaign-tasks', noun: 'campaign task', write: w, canDelete: true, sort: 'week', wide: true, defaults: { campaign_id: 1 }, prepare: (p) => ({ ...p, campaign_id: 1 }),
      filters: [{ key: 'status', label: 'Status', options: STATUS }],
      columns: [{ label: 'Week', render: (r) => (r.week >= 5 ? '30-day follow-up' : 'Week ' + r.week) }, { label: 'Theme', render: (r) => `<b>${NS.esc(r.theme)}</b>` }, { label: 'Activities', key: 'activity', wrap: true }, { label: 'Deliverables', key: 'deliverable', wrap: true },
        { label: 'Evidence of success', key: 'evidence', wrap: true }, { label: 'Status', render: (r) => NS.chip(r.status) }],
      fields: [{ name: 'week', label: 'Week (5 = follow-up)', type: 'number', step: 1, min: 1, max: 8, required: true }, { name: 'theme', label: 'Theme', required: true }, { name: 'status', label: 'Status', type: 'select', options: STATUS, required: true, default: 'Not started' },
        { name: 'owner', label: 'Owner' }, { name: 'due_date', label: 'Due date', type: 'date' }, { name: 'activity', label: 'Activities', type: 'textarea', full: true }, { name: 'deliverable', label: 'Deliverables', type: 'textarea', full: true }, { name: 'evidence', label: 'Evidence of success', type: 'textarea', full: true }] }) },
    { key: 'quiz', label: 'Take the knowledge check', render: async (el) => {
      const data = await NS.api('/quiz');
      el.innerHTML = `<section class="panel"><h2>Anonymous knowledge check</h2><p class="muted">Five questions. Results are stored without your name and only used for campaign totals. Choose the stage to count it toward.</p>
        <div class="toolbar"><label>This attempt counts as<select data-phase><option value="baseline">Baseline (before campaign)</option><option value="post">After the campaign</option></select></label>
        <label>Group<select data-seg>${['All employees', 'Finance and procurement', 'HR and people managers', 'Remote and mobile workers', 'Customer-facing teams', 'Managers and champions'].map((x) => `<option>${x}</option>`).join('')}</select></label></div>
        <form data-quiz>${data.questions.map((q) => `<div class="q" data-q="${q.id}"><fieldset><legend>${q.position}. ${NS.esc(q.question)}</legend>${q.options.map((o, i) => `<label><input type="radio" name="q${q.id}" value="${i}"> ${NS.esc(o)}</label>`).join('')}</fieldset><div class="res"></div></div>`).join('')}
        <p class="form-error" data-err></p><button class="btn primary" type="submit">Submit answers</button></form></section>`;
      $('[data-quiz]', el).addEventListener('submit', NS.guard(async (ev) => {
        ev.preventDefault();
        const answers = {};
        data.questions.forEach((q) => { const c = $(`input[name=q${q.id}]:checked`, el); if (c) answers[q.id] = Number(c.value); });
        const err = $('[data-err]', el);
        if (Object.keys(answers).length < data.questions.length) { err.textContent = 'Please answer every question.'; return; }
        err.textContent = '';
        const r = await NS.api('/quiz/submit', { method: 'POST', body: { phase: $('[data-phase]', el).value, segment: $('[data-seg]', el).value, answers } });
        r.review.forEach((x) => { const box = $(`[data-q="${x.id}"]`, el); box.classList.add(x.correct ? 'right' : 'wrong'); $('.res', box).textContent = (x.correct ? 'Correct. ' : 'Not quite. ') + x.explanation; });
        $$('input', el).forEach((i) => { if (i.type === 'radio') i.disabled = true; });
        $('button[type=submit]', el).disabled = true;
        NS.toast(`Score: ${r.score}/${r.total} (${r.percent}%) - recorded anonymously`);
      }));
    } },
    { key: 'simulations', label: 'Simulations and feedback', render: async (el) => {
      el.innerHTML = `<section class="panel"><h2>Phishing simulation results</h2><div class="note info">Use only approved simulations. Do not collect credentials or publish individual results. Record aggregate counts only.</div><div data-sim></div></section>
        <section class="panel"><h2>Feedback pulse</h2><p class="muted">Three anonymous questions.</p>
        <form data-fb class="form-grid"><label>The campaign was relevant to my role (1-5)<select name="relevance">${[5, 4, 3, 2, 1].map((n) => `<option>${n}</option>`).join('')}</select></label>
        <label>I feel confident reporting a mistake or suspicious message (1-5)<select name="confidence">${[5, 4, 3, 2, 1].map((n) => `<option>${n}</option>`).join('')}</select></label>
        <label>I know how to report a suspicious message<select name="knows"><option value="1">Yes</option><option value="0">No</option></select></label>
        <label class="full">Comment (optional)<textarea name="comment" maxlength="1000"></textarea></label><div class="full"><button class="btn primary" type="submit">Send feedback</button></div></form></section>`;
      await NS.crudTable($('[data-sim]', el), { endpoint: 'simulations', noun: 'simulation result', write: w, canDelete: true, search: false, sort: 'run_date',
        columns: [{ label: 'Stage', render: (r) => NS.esc(r.phase === 'baseline' ? 'Baseline' : 'Follow-up') }, { label: 'Date', render: (r) => NS.fmtD(r.run_date) }, { label: 'Sent', key: 'sent' }, { label: 'Clicked', render: (r) => `${r.clicked} (${r.click_rate}%)` },
          { label: 'Reported', render: (r) => `${r.reported} (${r.report_rate}%)` }, { label: 'Notes', key: 'notes', wrap: true }],
        fields: [{ name: 'phase', label: 'Stage', type: 'select', options: [{ v: 'baseline', l: 'Baseline' }, { v: 'follow_up', l: 'Follow-up' }], required: true }, { name: 'run_date', label: 'Date', type: 'date' },
          { name: 'sent', label: 'Messages sent', type: 'number', step: 1, min: 1, required: true }, { name: 'clicked', label: 'Clicked', type: 'number', step: 1, min: 0, required: true }, { name: 'reported', label: 'Reported', type: 'number', step: 1, min: 0, required: true },
          { name: 'notes', label: 'Notes', type: 'textarea', full: true }] });
      $('[data-fb]', el).addEventListener('submit', NS.guard(async (ev) => {
        ev.preventDefault();
        const f = ev.target;
        await NS.api('/feedback', { method: 'POST', body: { relevance: Number(f.relevance.value), confidence: Number(f.confidence.value), knows_reporting: f.knows.value === '1', comment: f.comment.value } });
        NS.toast('Thank you - feedback recorded anonymously'); f.reset();
      }));
    } },
    { key: 'content', label: 'Audience and content', render: async (el) => {
      const [msgs, risks, guard] = await Promise.all([NS.getRef('campaign_messages'), NS.getRef('campaign_risks'), NS.getRef('campaign_guardrails')]);
      el.innerHTML = `<div class="note">${NS.esc(guard)}</div><section class="panel"><h2>Audience segments</h2><div data-seg></div></section><section class="panel"><h2>Topics</h2><div data-top></div></section>
        <section class="panel"><h2>Channels</h2><div data-ch></div></section><section class="panel"><h2>Message templates</h2>${msgs.map((m) => `<details class="pb"><summary><b>${NS.esc(m.title)}</b></summary><p class="pre">${NS.esc(m.body)}</p></details>`).join('')}</section>
        <section class="panel"><h2>Campaign risks and controls</h2>${NS.simpleTable(['Risk', 'Control'], risks.map((r) => [NS.esc(r[0]), NS.esc(r[1])]), { wrap: [0, 1] })}</section>`;
      await NS.crudTable($('[data-seg]', el), { endpoint: 'campaign-segments', noun: 'segment', write: w, canDelete: true, search: false, wide: true,
        columns: [{ label: 'Group', key: 'name', wrap: true }, { label: 'Headcount', render: (r) => NS.esc(r.headcount ?? '') }, { label: 'Main risk', key: 'risk', wrap: true }, { label: 'Campaign response', key: 'response', wrap: true }],
        fields: [{ name: 'name', label: 'Group', required: true, full: true }, { name: 'headcount', label: 'Headcount', type: 'number', step: 1, min: 0 }, { name: 'risk', label: 'Main risk', type: 'textarea', full: true }, { name: 'response', label: 'Campaign response', type: 'textarea', full: true }] });
      await NS.crudTable($('[data-top]', el), { endpoint: 'campaign-topics', noun: 'topic', write: w, canDelete: true, search: false, wide: true,
        columns: [{ label: 'Topic', render: (r) => `<b>${NS.esc(r.topic)}</b>`, wrap: true }, { label: 'Key message', key: 'takeaway', wrap: true }, { label: 'Activity', key: 'activity', wrap: true }],
        fields: [{ name: 'topic', label: 'Topic', required: true, full: true }, { name: 'takeaway', label: 'Key message', type: 'textarea', full: true }, { name: 'activity', label: 'Activity', type: 'textarea', full: true }] });
      await NS.crudTable($('[data-ch]', el), { endpoint: 'campaign-channels', noun: 'channel', write: w, canDelete: true, search: false, wide: true,
        columns: [{ label: 'Channel', render: (r) => `<b>${NS.esc(r.channel)}</b>` }, { label: 'Cadence', key: 'cadence', wrap: true }, { label: 'Owner', key: 'owner', wrap: true }, { label: 'Accessibility', key: 'accessibility', wrap: true }],
        fields: [{ name: 'channel', label: 'Channel', required: true }, { name: 'owner', label: 'Owner' }, { name: 'cadence', label: 'Cadence', type: 'textarea', full: true }, { name: 'accessibility', label: 'Accessibility notes', type: 'textarea', full: true }] });
    } },
    { key: 'manage-quiz', label: 'Manage quiz', render: async (el) => {
      if (!NS.can(w)) { el.innerHTML = '<div class="note info">Only security analysts and administrators can manage quiz questions. The answer key is hidden from quiz takers.</div>'; return; }
      await NS.crudTable(el, { endpoint: 'quiz-questions', noun: 'quiz question', write: w, canDelete: true, search: false, sort: 'position', wide: true,
        columns: [{ label: '#', key: 'position' }, { label: 'Question', key: 'question', wrap: true }, { label: 'Options', wrap: true, render: (r) => r.options.map((o, i) => `${i === r.correct_index ? '<b>' : ''}${NS.esc(o)}${i === r.correct_index ? ' (correct)</b>' : ''}`).join('<br>') }],
        rowClick: (row, reload) => {
          const form = document.createElement('div');
          form.innerHTML = `<form class="form-grid" novalidate><label>Position<input name="position" type="number" min="1" value="${row.position}"></label>
            <label>Correct option (number)<input name="correct" type="number" min="1" max="6" value="${row.correct_index + 1}"></label><label class="full">Question<textarea name="question">${NS.esc(row.question)}</textarea></label>
            <label class="full">Options (one per line)<textarea name="options" rows="4">${NS.esc(row.options.join('\n'))}</textarea></label><label class="full">Explanation<textarea name="explanation">${NS.esc(row.explanation || '')}</textarea></label></form>`;
          NS.modal({ title: 'Edit quiz question', body: form, wide: true, foot: [{ label: 'Cancel', onClick: (m) => m.close() }, { label: 'Save question', cls: 'primary', onClick: async (m) => {
            const opts = $('[name=options]', form).value.split('\n').map((x) => x.trim()).filter(Boolean);
            await NS.api('/quiz-questions/' + row.id, { method: 'PATCH', body: { position: Number($('[name=position]', form).value), question: $('[name=question]', form).value, options: opts, correct_index: Number($('[name=correct]', form).value) - 1, explanation: $('[name=explanation]', form).value } });
            NS.toast('Question saved'); m.close(); reload();
          } }] });
        } });
    } },
  ]);
};
