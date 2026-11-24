/* NAT-Lab Notify (N2) — PI-only communication centre.
 * Compose · Templates · History · Automation. All data comes from /api/notify
 * (PI only on the server). Recipients are resolved by the server; this page
 * never supplies e-mail addresses. */
(function () {
    'use strict';
    const API = '/api/notify';
    const esc = (v) => String(v === undefined || v === null ? '' : v).replace(/[&<>"'`]/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' }[c]));
    const fmt = (d) => d ? new Date(d).toLocaleString('en-GB', { dateStyle: 'medium', timeStyle: 'short' }) : '';
    async function api(path, method, body) {
        const r = await fetch(API + path, { method: method || 'GET', credentials: 'same-origin',
            headers: body ? { 'Content-Type': 'application/json' } : {}, body: body ? JSON.stringify(body) : undefined });
        let j = null; try { j = await r.json(); } catch (_) { j = null; }
        if (!r.ok) { const e = new Error((j && j.error) || ('Request failed (' + r.status + ')')); e.code = j && j.code; e.status = r.status; throw e; }
        return j;
    }
    const S = { root: null, view: 'compose', status: null, aud: null, tpl: null, compose: { groups: [], affiliation: '', individuals: [], subject: '', body: '', template_id: '', template_name: '', category: 'general' }, poll: null };

    const STATUS_LABEL = { ACCEPTED: 'Accepted by Resend', DELIVERED: 'Delivered (confirmed)', FAILED: 'Failed', UNCERTAIN: 'Uncertain', SKIPPED: 'Skipped', QUEUED: 'Queued', SENDING: 'Sending', BOUNCED: 'Bounced' };
    const pill = (st) => `<span class="nt-pill nt-${esc(String(st).toLowerCase())}">${esc(STATUS_LABEL[st] || st)}</span>`;

    function msg(text, kind) {
        const el = S.root.querySelector('#ntMsg');
        if (!el) return;
        el.className = 'message show ' + (kind || 'info'); el.textContent = text;
        if (kind !== 'error') setTimeout(() => { if (el.textContent === text) el.className = 'message'; }, 6000);
    }

    // ------------------------------------------------------------- shell
    async function mount(root) {
        if (!root) return;
        if (!S.root) {
            S.root = root;
            root.innerHTML = `<div class="nt">
              <div id="ntStatus" class="nt-status"></div>
              <div class="nt-subnav">
                <button data-v="compose" class="active">Compose</button><button data-v="templates">Templates</button>
                <button data-v="history">History</button><button data-v="automation">Automation</button>
              </div>
              <div id="ntMsg" class="message"></div>
              <div id="ntView"></div></div>`;
            root.querySelectorAll('.nt-subnav button').forEach(b => b.addEventListener('click', () => show(b.dataset.v)));
        }
        await refreshStatus();
        await show(S.view);
    }
    async function refreshStatus() {
        try { S.status = await api('/status'); } catch (e) { S.root.querySelector('#ntStatus').innerHTML = `<div class="message error show">${esc(e.message)}</div>`; return; }
        const e = S.status.email, st = S.status.settings;
        const item = (ok, label, detail) => `<div class="nt-st ${ok ? 'on' : 'off'}"><b>${esc(label)}</b><span>${esc(detail)}</span></div>`;
        S.root.querySelector('#ntStatus').innerHTML =
            item(e.configured, 'E-mail service', e.configured ? 'Configured' : 'Not configured' + (e.missing.length ? ' — missing: ' + e.missing.join(', ') : '')) +
            item(e.sending_switch, 'Global sending switch', e.sending_switch ? 'ON (NOTIFY_SENDING_ENABLED)' : 'OFF — nothing can be sent') +
            item(st.manual_enabled, 'Manual sending', st.manual_enabled ? 'Enabled' : 'Disabled') +
            item(!st.paused, 'Emergency pause', st.paused ? 'PAUSED — all sending stopped' + (S.status.pending && S.status.pending.recipients ? ` · ${S.status.pending.recipients} pending e-mail(s) in ${S.status.pending.messages} message(s) — see History` : ' · nothing pending') : 'Not paused') +
            `<div class="nt-st meta"><b>Sender</b><span>${esc(e.from || '—')}</span></div>` +
            `<div class="nt-st meta"><b>Reply-To</b><span>${esc(e.reply_to || '—')}</span></div>` +
            `<div class="nt-st meta"><b>Test recipient</b><span>${esc(e.test_recipient || '—')}</span></div>`;
    }
    async function show(v) {
        S.view = v;
        if (S.poll) { clearInterval(S.poll); S.poll = null; }
        S.root.querySelectorAll('.nt-subnav button').forEach(b => b.classList.toggle('active', b.dataset.v === v));
        const view = S.root.querySelector('#ntView');
        view.innerHTML = '<div class="nt-loading">Loading…</div>';
        try {
            if (v === 'compose') await renderCompose(view);
            else if (v === 'templates') await renderTemplates(view);
            else if (v === 'history') await renderHistory(view);
            else await renderAutomation(view);
        } catch (e) { view.innerHTML = `<div class="message error show">${esc(e.message)}</div>`; }
    }

    // ------------------------------------------------------------ compose
    async function renderCompose(view) {
        [S.aud, S.tpl] = await Promise.all([api('/audiences'), api('/templates')]);
        const c = S.compose, cnt = S.aud.counts;
        const box = (key, label) => `<label class="nt-check"><input type="checkbox" data-g="${key}" ${c.groups.includes(key) ? 'checked' : ''}> ${esc(label)} <span class="nt-count">${cnt[key] !== undefined ? cnt[key] : 0}</span></label>`;
        const gname = (code) => { const g = S.aud.groups.find(x => x.code === code); return g ? g.name : code; };
        const tpls = S.tpl.system.map(t => `<option value="${esc(t.id)}">${esc(t.name)} (built-in)</option>`).join('') +
            S.tpl.templates.filter(t => !t.archived_at).map(t => `<option value="${esc(t.id)}">${esc(t.name)}</option>`).join('');
        view.innerHTML = `<div class="nt-compose">
          <div class="panel"><div class="panel-header"><h2>Recipients</h2></div><div class="panel-content">
            <div class="nt-aud">
              ${box('all', 'All eligible NAT-Lab members')}${box('researchers', 'Researchers')}${box('supervisors', 'Supervisors')}
              ${box('gm:LIU', gname('LIU') + ' (Group Meetings)')}${box('gm:UNAV', gname('UNAV') + ' (Group Meetings)')}${box('gm:JOINT', gname('JOINT') + ' (Group Meetings)')}
            </div>
            <div class="form-group"><label>Institution filter (applies to the groups above)</label>
              <select id="ntAff"><option value="">Any institution</option>${['LiU', 'UNAV', 'EXTERNAL'].map(a => `<option ${c.affiliation === a ? 'selected' : ''}>${a}</option>`).join('')}</select></div>
            <div class="form-group"><label>Individual recipients</label>
              <input id="ntFind" placeholder="Search name…">
              <div class="nt-people" id="ntPeople">${S.aud.people.map(p => `<label class="nt-person" data-name="${esc(p.name.toLowerCase())}"><input type="checkbox" data-id="${esc(p.id)}" ${c.individuals.includes(p.id) ? 'checked' : ''}>
                ${esc(p.name)} <small>${esc(p.role)} · ${esc(p.affiliation || '')}${p.groups.length ? ' · ' + esc(p.groups.join('/')) : ''}${p.pi_alternate ? ' · not in group audiences' : ''}</small></label>`).join('')}</div></div>
            <p class="nt-hint">Eligible: active accounts with an active NAT-Lab membership (researchers and supervisors). Inactive, company, investor and AI accounts are never included. Each person receives an individual e-mail; addresses are never shared.</p>
          </div></div>
          <div class="panel"><div class="panel-header"><h2>Message</h2></div><div class="panel-content">
            <div class="form-group"><label>Template</label><select id="ntTpl"><option value="">— none —</option>${tpls}</select></div>
            <div class="form-group"><label>Subject</label><input id="ntSubject" maxlength="200" value="${esc(c.subject)}"></div>
            <div class="form-group"><label>Message (plain text; links starting with https:// become clickable)</label><textarea id="ntBody" rows="12">${esc(c.body)}</textarea></div>
            <div class="nt-vars">Variables: ${Object.keys(S.status.variables).map(v => `<button type="button" class="nt-var" title="${esc(S.status.variables[v])}" data-var="${v}">{{${v}}}</button>`).join(' ')}</div>
            <div class="nt-actions">
              <button class="btn btn-secondary" id="ntPreview">Preview</button>
              <button class="btn btn-warning" id="ntTest">Send test to PI</button>
              <button class="btn btn-primary" id="ntPrepare">Prepare to send…</button>
            </div>
          </div></div>
          <div class="panel nt-preview-panel"><div class="panel-header"><h2>Preview</h2></div><div class="panel-content" id="ntPrev"><p class="nt-hint">Select recipients and press Preview.</p></div></div>
        </div>`;
        const sync = () => {
            c.groups = [...view.querySelectorAll('[data-g]:checked')].map(x => x.dataset.g);
            c.individuals = [...view.querySelectorAll('[data-id]:checked')].map(x => x.dataset.id);
            c.affiliation = view.querySelector('#ntAff').value;
            c.subject = view.querySelector('#ntSubject').value; c.body = view.querySelector('#ntBody').value;
        };
        view.querySelectorAll('input, select, textarea').forEach(x => x.addEventListener('change', sync));
        view.querySelector('#ntSubject').addEventListener('input', sync); view.querySelector('#ntBody').addEventListener('input', sync);
        view.querySelector('#ntFind').addEventListener('input', (e) => { const q = e.target.value.toLowerCase(); view.querySelectorAll('.nt-person').forEach(p => { p.style.display = p.dataset.name.includes(q) ? '' : 'none'; }); });
        view.querySelector('#ntTpl').addEventListener('change', (e) => {
            const id = e.target.value; if (!id) return;
            const t = S.tpl.system.concat(S.tpl.templates).find(x => x.id === id); if (!t) return;
            if ((c.subject || c.body) && !confirm('Replace the current subject and message with this template?')) { e.target.value = ''; return; }
            c.subject = t.subject; c.body = t.body; c.template_id = t.id; c.template_name = t.name; c.category = t.category || 'general';
            view.querySelector('#ntSubject').value = t.subject; view.querySelector('#ntBody').value = t.body;
        });
        view.querySelectorAll('.nt-var').forEach(b => b.addEventListener('click', () => {
            const ta = view.querySelector('#ntBody'); const ins = '{{' + b.dataset.var + '}}';
            const s = ta.selectionStart || ta.value.length; ta.value = ta.value.slice(0, s) + ins + ta.value.slice(ta.selectionEnd || s); ta.focus(); sync();
        }));
        const payload = () => { sync(); return { audience: { groups: c.groups, affiliation: c.affiliation || null, individuals: c.individuals }, subject: c.subject, body: c.body,
            template_id: c.template_id || null, template_name: c.template_name || null, category: c.category }; };
        view.querySelector('#ntPreview').addEventListener('click', () => preview(payload()));
        view.querySelector('#ntTest').addEventListener('click', async (e) => {
            e.target.disabled = true;
            try { const r = await api('/test', 'POST', payload()); msg(r.status === 'ACCEPTED' ? 'Test e-mail accepted by Resend for delivery to the PI test address.' : 'Test e-mail not accepted: ' + (r.error || r.status), r.status === 'ACCEPTED' ? 'success' : 'error'); }
            catch (err) { msg(err.message, 'error'); } finally { e.target.disabled = false; }
        });
        view.querySelector('#ntPrepare').addEventListener('click', () => prepareSend(payload()));
    }
    async function preview(p) {
        const box = S.root.querySelector('#ntPrev');
        box.innerHTML = '<div class="nt-loading">Resolving recipients…</div>';
        try {
            const r = await api('/preview', 'POST', p);
            box.innerHTML = `<div class="nt-count-big">${r.count} recipient${r.count === 1 ? '' : 's'}</div>
              ${r.problems.length ? `<div class="message error show">${r.problems.map(esc).join('<br>')}</div>` : ''}
              <details ${r.count <= 15 ? 'open' : ''}><summary>Recipients</summary><table class="data-table"><tr><th>Name</th><th>Address</th><th>Institution</th><th>Included as</th></tr>
                ${r.recipients.map(x => `<tr><td>${esc(x.name)}</td><td>${esc(x.email)}</td><td>${esc(x.affiliation || '')}</td><td>${esc(x.reason)}</td></tr>`).join('')}</table></details>
              ${r.excluded.length ? `<details><summary>Not included (${r.excluded.length})</summary><ul>${r.excluded.map(x => `<li>${esc(x.name)} — ${esc(x.reason)}</li>`).join('')}</ul></details>` : ''}
              ${r.sample ? `<p class="nt-hint">Rendered for ${esc(r.sample.for)} — subject: <b>${esc(r.sample.subject)}</b></p><iframe class="nt-frame" sandbox="" referrerpolicy="no-referrer"></iframe>` : ''}`;
            if (r.sample) box.querySelector('iframe').srcdoc = r.sample.html;
        } catch (e) { box.innerHTML = `<div class="message error show">${esc(e.message)}</div>`; }
    }
    async function prepareSend(p) {
        let d;
        try { d = await api('/drafts', 'POST', p); } catch (e) { msg(e.message, 'error'); return; }
        const n = d.recipient_count;
        const ov = document.createElement('div'); ov.className = 'nt-modal-bg';
        ov.innerHTML = `<div class="nt-modal"><h3>Send ${n} individual e-mail${n === 1 ? '' : 's'}?</h3>
            <p><b>Subject:</b> ${esc(p.subject)}</p>
            <div class="nt-modal-list">${d.recipients.map(x => esc(x.name) + ' &lt;' + esc(x.email) + '&gt;').join('<br>')}</div>
            ${n > 10 ? `<div class="form-group"><label>Type the number of recipients (${n}) to confirm</label><input id="ntTyped" inputmode="numeric"></div>` : ''}
            <p class="nt-hint">Each recipient gets a separate e-mail. Recipients are checked again before each e-mail is sent.</p>
            <div class="nt-actions"><button class="btn btn-secondary" id="ntCancel">Cancel</button><button class="btn btn-primary" id="ntGo">Confirm and send</button></div></div>`;
        document.body.appendChild(ov);
        const close = () => ov.remove();
        ov.querySelector('#ntCancel').addEventListener('click', async () => { close(); try { await api('/messages/' + d.id + '/discard', 'POST', {}); } catch (_) {} msg('Not sent (draft discarded).', 'info'); });
        ov.querySelector('#ntGo').addEventListener('click', async (e) => {
            if (n > 10 && String((ov.querySelector('#ntTyped') || {}).value || '').trim() !== String(n)) { alert('Please type ' + n + ' to confirm.'); return; }
            e.target.disabled = true;
            try { await api('/messages/' + d.id + '/confirm', 'POST', { recipient_count: n }); close(); msg('Confirmed. Sending…', 'info'); await show('history'); openDetail(d.id); }
            catch (err) { close(); msg(err.message, 'error'); try { await api('/messages/' + d.id + '/discard', 'POST', {}); } catch (_) {} }
        });
    }

    // ------------------------------------------------------------ history
    async function renderHistory(view) {
        const r = await api('/messages?limit=200');
        const c = (m, k) => (m.counts && m.counts[k]) || 0;
        view.innerHTML = `<div class="panel"><div class="panel-header"><h2>Sending history</h2><button class="btn btn-sm btn-secondary" id="ntRefresh">Refresh</button></div><div class="panel-content">
          <p class="nt-hint">"Accepted" means Resend accepted the e-mail for delivery. Delivery itself is not confirmed by NAT-Lab. "Uncertain" means the outcome is unknown (for example a timeout); such e-mails are never re-sent automatically.</p>
          <table class="data-table"><tr><th>Date</th><th>Type</th><th>Subject</th><th>Sent by</th><th>Recipients</th><th>Status</th></tr>
          ${r.messages.map(m => `<tr class="nt-row" data-id="${esc(m.id)}"><td>${fmt(m.confirmed_at || m.created_at)}</td><td>${esc(m.kind)}${m.kind === 'manual' ? '' : ' · ' + esc(m.category)}</td>
            <td>${esc(m.subject)}</td><td>${esc(m.created_by === 'system' ? 'System (' + (m.trigger_event || '') + ')' : m.created_by_name)}</td>
            <td>${m.recipient_count} <small>(${c(m, 'ACCEPTED') + c(m, 'DELIVERED')} accepted${c(m, 'FAILED') ? ', ' + c(m, 'FAILED') + ' failed' : ''}${c(m, 'UNCERTAIN') ? ', ' + c(m, 'UNCERTAIN') + ' uncertain' : ''}${c(m, 'SKIPPED') ? ', ' + c(m, 'SKIPPED') + ' skipped' : ''})</small></td>
            <td>${esc(m.status)}</td></tr>`).join('') || '<tr><td colspan="6">No messages yet.</td></tr>'}</table>
          <div id="ntDetail"></div></div></div>`;
        view.querySelector('#ntRefresh').addEventListener('click', () => show('history'));
        view.querySelectorAll('.nt-row').forEach(tr => tr.addEventListener('click', () => openDetail(tr.dataset.id)));
    }
    async function openDetail(id) {
        const box = S.root.querySelector('#ntDetail'); if (!box) return;
        if (S.poll) { clearInterval(S.poll); S.poll = null; }
        const load = async () => {
            let d; try { d = await api('/messages/' + id); } catch (e) { box.innerHTML = `<div class="message error show">${esc(e.message)}</div>`; return; }
            const m = d.message, rs = d.recipients;
            const done = rs.filter(x => !['QUEUED', 'SENDING'].includes(x.status)).length;
            const canResend = m.kind !== 'test' && rs.some(x => x.status === 'FAILED' || x.status === 'UNCERTAIN') && !d.sending;
            box.innerHTML = `<div class="nt-detail"><h3>${esc(m.subject)}</h3>
              <p class="nt-hint">${esc(m.kind)} · ${esc(m.category)} · status ${esc(m.status)} · by ${esc(m.created_by === 'system' ? 'System' : m.created_by_name)} · confirmed ${fmt(m.confirmed_at)}${m.completed_at ? ' · finished ' + fmt(m.completed_at) : ''}</p>
              <div class="nt-progress"><div style="width:${rs.length ? Math.round(100 * done / rs.length) : 0}%"></div></div>
              ${m.status === 'QUEUED' && !d.sending ? '<div class="message info show">Queued — sending is held (global switch, manual sending or pause). It continues when sending is allowed again.</div>' : ''}
              <table class="data-table"><tr><th>Recipient</th><th>To / CC</th><th>Address</th><th>Status</th><th>Resend ID</th><th>Error / reason</th><th>Attempts</th><th>Last attempt</th></tr>
              ${rs.map(x => `<tr><td>${esc(x.name)}</td><td>${x.recipient_role === 'cc' ? 'CC (copy)' : 'To'}</td><td>${esc(x.email)}</td><td>${pill(x.status)}</td><td><code>${esc(x.provider_id || '')}</code></td>
                <td>${esc(x.error || x.skip_reason || '')}</td><td>${x.attempts}</td><td>${fmt(x.last_attempt_at)}</td></tr>`).join('')}</table>
              ${canResend ? `<div class="nt-actions"><label class="nt-check"><input type="checkbox" id="ntUnc"> also re-send UNCERTAIN e-mails (may duplicate if they were in fact delivered)</label>
                 <button class="btn btn-warning" id="ntResend">Re-send failed</button></div>` : ''}
              ${d.sample ? `<details><summary>Message as sent (first recipient)</summary><pre class="nt-pre">${esc(d.sample.sent_text)}</pre></details>` : ''}</div>`;
            const b = box.querySelector('#ntResend');
            if (b) b.addEventListener('click', async () => {
                const inc = box.querySelector('#ntUnc').checked;
                try { await api('/messages/' + id + '/resend', 'POST', { include_uncertain: inc }); }
                catch (e) {
                    if (e.code === 'duplicate_risk' && confirm(e.message + '\n\nRe-send anyway?')) { try { await api('/messages/' + id + '/resend', 'POST', { include_uncertain: inc, acknowledge_duplicate_risk: true }); } catch (e2) { msg(e2.message, 'error'); return; } }
                    else { msg(e.message, 'error'); return; }
                }
                msg('Re-sending…', 'info'); openDetail(id);
            });
            if (!d.sending && !rs.some(x => x.status === 'SENDING') && S.poll && m.status !== 'QUEUED') { clearInterval(S.poll); S.poll = null; }
        };
        await load();
        S.poll = setInterval(load, 2000);
        setTimeout(() => { if (S.poll) { clearInterval(S.poll); S.poll = null; } }, 5 * 60000);
    }

    // ---------------------------------------------------------- templates
    async function renderTemplates(view) {
        S.tpl = await api('/templates');
        const row = (t, sys) => `<tr><td>${esc(t.name)}${t.archived_at ? ' <small>(archived)</small>' : ''}</td><td>${esc(t.category)}</td><td>${esc(t.subject)}</td><td class="nt-tactions">
            <button class="btn btn-sm btn-secondary" data-a="use" data-id="${esc(t.id)}">Use</button>
            ${sys ? '' : `<button class="btn btn-sm btn-secondary" data-a="edit" data-id="${esc(t.id)}">Edit</button>`}
            <button class="btn btn-sm btn-secondary" data-a="dup" data-id="${esc(t.id)}">Duplicate</button>
            ${sys ? '<small>built-in</small>' : `<button class="btn btn-sm btn-secondary" data-a="${t.archived_at ? 'unarchive' : 'archive'}" data-id="${esc(t.id)}">${t.archived_at ? 'Restore' : 'Archive'}</button>`}</td></tr>`;
        view.innerHTML = `<div class="panel"><div class="panel-header"><h2>Templates</h2><button class="btn btn-sm btn-primary" id="ntNewT">New template</button></div><div class="panel-content">
          <table class="data-table"><tr><th>Name</th><th>Category</th><th>Subject</th><th></th></tr>${S.tpl.system.map(t => row(t, true)).join('')}${S.tpl.templates.map(t => row(t, false)).join('')}</table>
          <div id="ntTEdit"></div></div></div>`;
        view.querySelector('#ntNewT').addEventListener('click', () => editTemplate(null));
        view.querySelectorAll('[data-a]').forEach(b => b.addEventListener('click', async () => {
            const id = b.dataset.id, a = b.dataset.a;
            const t = S.tpl.system.concat(S.tpl.templates).find(x => x.id === id);
            try {
                if (a === 'use') { Object.assign(S.compose, { subject: t.subject, body: t.body, template_id: t.id, template_name: t.name, category: t.category || 'general' }); await show('compose'); return; }
                if (a === 'edit') return editTemplate(t);
                if (a === 'dup') { await api('/templates/' + encodeURIComponent(id) + '/duplicate', 'POST', {}); msg('Template duplicated.', 'success'); }
                if (a === 'archive' || a === 'unarchive') await api('/templates/' + id + '/archive', 'POST', { archived: a === 'archive' });
                await show('templates');
            } catch (e) { msg(e.message, 'error'); }
        }));
    }
    function editTemplate(t) {
        const box = S.root.querySelector('#ntTEdit');
        const cats = ['general', 'reminder', 'submission', 'review', 'group_meetings', 'supervisor'];
        box.innerHTML = `<div class="nt-detail"><h3>${t ? 'Edit template' : 'New template'}</h3>
          <div class="form-group"><label>Name</label><input id="ntTN" maxlength="120" value="${esc(t ? t.name : '')}"></div>
          <div class="form-group"><label>Category</label><select id="ntTC">${cats.map(c => `<option ${t && t.category === c ? 'selected' : ''}>${c}</option>`).join('')}</select></div>
          <div class="form-group"><label>Subject</label><input id="ntTS" maxlength="200" value="${esc(t ? t.subject : '')}"></div>
          <div class="form-group"><label>Message</label><textarea id="ntTB" rows="10">${esc(t ? t.body : '')}</textarea></div>
          <div class="nt-actions"><button class="btn btn-secondary" id="ntTX">Cancel</button><button class="btn btn-primary" id="ntTSave">Save</button></div></div>`;
        box.querySelector('#ntTX').addEventListener('click', () => { box.innerHTML = ''; });
        box.querySelector('#ntTSave').addEventListener('click', async () => {
            const body = { name: box.querySelector('#ntTN').value, category: box.querySelector('#ntTC').value, subject: box.querySelector('#ntTS').value, body: box.querySelector('#ntTB').value };
            try { if (t) await api('/templates/' + t.id, 'PUT', body); else await api('/templates', 'POST', body); msg('Template saved.', 'success'); await show('templates'); }
            catch (e) { msg(e.message, 'error'); }
        });
    }

    // --------------------------------------------------------- automation
    async function renderAutomation(view) {
        await refreshStatus();
        const st = S.status.settings, e = S.status.email;
        view.innerHTML = `<div class="panel"><div class="panel-header"><h2>Sending controls</h2></div><div class="panel-content">
            <p><b>Global sending switch:</b> ${e.sending_switch ? 'ON' : 'OFF'} <small>(Railway variable NOTIFY_SENDING_ENABLED — changing it requires a restart)</small></p>
            <label class="nt-check"><input type="checkbox" id="ntManual" ${st.manual_enabled ? 'checked' : ''}> Manual sending from Compose enabled</label>
            <label class="nt-check nt-danger"><input type="checkbox" id="ntPause" ${st.paused ? 'checked' : ''}> Emergency pause — stop ALL sending immediately</label>
          </div></div>
          <div class="panel"><div class="panel-header"><h2>Automatic notifications</h2></div><div class="panel-content">
            <p class="nt-hint">Every category and option is off by default and is switched on individually. Once on, notifications are sent automatically after the operation has succeeded. Supervisor copies go only to supervisors currently assigned to the researcher; they never grant access to documents. E-mails contain no documents, filenames, approval comments, discard reasons or notes.</p>
            ${[...new Set(S.status.categories.map(c => c.group))].map(g => `<h3 class="nt-group">${esc(g)}</h3><table class="data-table"><tr><th>Notification</th><th>State</th></tr>
            ${S.status.categories.filter(c => c.group === g).map(c => `<tr><td>${esc(c.label)}</td><td>${c.implemented && !c.locked
                ? `<label class="nt-check"><input type="checkbox" data-cat="${esc(c.key)}" ${c.enabled ? 'checked' : ''}> ${c.enabled ? 'On' : 'Off'}</label>`
                : `<span class="nt-pill nt-skipped">${c.locked ? 'Not available' : 'Planned'}</span>`}</td></tr>`).join('')}</table>`).join('')}
            <h3 class="nt-group">Options</h3><table class="data-table"><tr><th>Option</th><th>State</th></tr>
            ${(S.status.options || []).map(o => `<tr><td>${esc(o.label)}</td><td><label class="nt-check"><input type="checkbox" data-opt="${esc(o.key)}" ${o.enabled ? 'checked' : ''}> ${o.enabled ? 'On' : 'Off'}</label></td></tr>`).join('')}</table>
          </div></div>`;
        const put = async (body, what) => {
            try { await api('/settings', 'PUT', body); msg(what + ' saved.', 'success'); } catch (err) { msg(err.message, 'error'); }
            await refreshStatus(); await show('automation');
        };
        view.querySelector('#ntManual').addEventListener('change', (ev) => put({ manual_enabled: ev.target.checked }, 'Manual sending'));
        view.querySelector('#ntPause').addEventListener('change', (ev) => {
            if (!ev.target.checked) {
                const p = S.status.pending || { messages: 0, recipients: 0 };
                const txt = p.recipients
                    ? `Resume sending?\n\n${p.recipients} pending e-mail(s) in ${p.messages} message(s) are listed in History with status "Queued".\nBefore each one is sent, its category setting and the recipient's eligibility (account, NAT-Lab membership, supervisor assignment) are checked again; anything no longer allowed is skipped.`
                    : 'Resume sending? Nothing is pending.';
                if (!confirm(txt)) { ev.target.checked = true; return; }
            }
            put({ paused: ev.target.checked }, 'Pause');
        });
        view.querySelectorAll('[data-opt]').forEach(x => x.addEventListener('change', (ev) => {
            if (ev.target.checked && !confirm('Switch on: "' + x.closest('tr').firstChild.textContent + '"?')) { ev.target.checked = false; return; }
            put({ options: { [x.dataset.opt]: ev.target.checked } }, 'Option');
        }));
        view.querySelectorAll('[data-cat]').forEach(x => x.addEventListener('change', (ev) => {
            if (ev.target.checked && !confirm('Switch on automatic e-mails for "' + x.closest('tr').firstChild.textContent + '"?')) { ev.target.checked = false; return; }
            put({ categories: { [x.dataset.cat]: ev.target.checked } }, 'Category');
        }));
    }

    window.NotifyPI = { mount };
})();
