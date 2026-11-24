'use strict';
// ============================================================================
// NAT-Lab Notify N3 — automatic notifications for scientific submissions,
// scientific decisions and training / certification.
// ----------------------------------------------------------------------------
// * Triggered only AFTER a successful operation (the route has done its work);
//   runs after the response, never throws, never affects the operation.
// * Every category and every option (supervisor copies, researcher-facing
//   messages) is OFF until the PI switches it on in Notify → Automation.
// * Recipients are resolved from existing data only:
//     PI            NOTIFY_PI_EMAIL
//     researcher    the document / training owner (active account)
//     supervisors   CURRENT rows of di_supervisor_researchers whose supervisor is
//                   an active account with role 'supervisor' and an active NAT-Lab
//                   membership (the same relationship document access uses);
//                   alternate PI accounts (NOTIFY_BULK_EXCLUDED_ACCOUNTS) never.
//     certifier     the supervisor named on a training entry (existing workflow)
//   Each row stores WHY the person may receive it ("basis"); this is re-checked
//   just before the e-mail is sent, so a revoked assignment stops a queued copy.
// * "CC" copies are separate individual e-mails (role 'cc' in the history): no
//   recipient ever sees another recipient's address.
// * Content: metadata only (who, what type, when) and a sign-in link to
//   https://glp.hernandezlab.com. Never filenames, documents, certificates,
//   approval comments, discard reasons or notes. The only free text ever
//   included is what the researcher already sees in their own portal (revision
//   comment, training rejection / revision comment), only to that researcher and
//   only when "Include researcher-facing messages" is on.
// ============================================================================
const notify = require('./notify');

const TYPE_LABELS = { SOP: 'SOP', DATA: 'DATA', PRESENTATION: 'Presentation', REPORT: 'Report' };

function createNotifyEvents({ pool, getSettings, enqueueEvent, bulkExcludedIds, log }) {
    const portal = () => notify.config().portal;
    const one = (v, n) => notify.oneLine(v, n || 120);
    const date = (d) => d ? notify.dateOnly(d instanceof Date ? d : new Date(d)) : '';

    // ------------------------------------------------------------ people
    async function account(id) {
        if (!id) return null;
        const r = await pool.query(`SELECT researcher_id, name, institution_email AS email, role, active FROM di_allowlist WHERE researcher_id = $1`, [id]);
        return r.rows[0] || null;
    }
    const LAB_MEMBER_SQL = `EXISTS (SELECT 1 FROM workspace_users wu JOIN workspaces w ON w.id = wu.workspace_id AND w.workspace_type = 'LAB'
                             WHERE wu.user_id = %s AND wu.is_active = TRUE AND COALESCE(to_jsonb(wu)->>'status', 'active') = 'active')`;
    async function supervisorsOf(researcherId) {
        const r = await pool.query(`
            SELECT s.researcher_id, s.name, s.institution_email AS email
              FROM di_supervisor_researchers x
              JOIN di_allowlist s ON s.researcher_id = x.supervisor_id AND s.active = TRUE AND s.role = 'supervisor'
              JOIN di_allowlist r ON r.researcher_id = x.researcher_id AND r.active = TRUE
             WHERE x.researcher_id = $1 AND ${LAB_MEMBER_SQL.replace('%s', 's.researcher_id')}
             ORDER BY s.name`, [researcherId]);
        const ex = new Set(bulkExcludedIds());
        return r.rows.filter(x => notify.validEmail(x.email) && !ex.has(x.researcher_id));
    }
    async function eligibleCertifier(supervisorId) {
        const r = await pool.query(`SELECT researcher_id, name, institution_email AS email FROM di_allowlist s
             WHERE s.researcher_id = $1 AND s.active = TRUE AND s.role = 'supervisor' AND ${LAB_MEMBER_SQL.replace('%s', 's.researcher_id')}`, [supervisorId]);
        const x = r.rows[0];
        return x && notify.validEmail(x.email) && !bulkExcludedIds().includes(x.researcher_id) ? x : null;
    }
    // Re-check at send time (called by the outbox worker for automatic rows).
    async function recheck(basis, email) {
        if (!basis || !basis.kind) return 'No recipient basis';
        const st = await getSettings();
        if (basis.option && st.options[basis.option] !== true) return 'Supervisor copies switched off';
        if (basis.kind === 'pi') { const pi = notify.piAddress(); return pi && pi.toLowerCase() === String(email).toLowerCase() ? null : 'PI address changed'; }
        if (basis.kind === 'researcher') {
            const a = await account(basis.researcher_id);
            return a && a.active && String(a.email || '').toLowerCase() === String(email).toLowerCase() ? null : 'Recipient account inactive or address changed';
        }
        if (basis.kind === 'supervisor') {
            const s = (await supervisorsOf(basis.researcher_id)).find(x => x.researcher_id === basis.supervisor_id);
            return s && s.email.toLowerCase() === String(email).toLowerCase() ? null : 'Supervision assignment no longer valid';
        }
        if (basis.kind === 'certifier') {
            const e = await pool.query(`SELECT supervisor_id FROM di_training_entries WHERE id = $1`, [basis.entry_id]);
            if (!e.rows[0] || e.rows[0].supervisor_id !== basis.supervisor_id) return 'Training entry certifier changed';
            const c = await eligibleCertifier(basis.supervisor_id);
            return c && c.email.toLowerCase() === String(email).toLowerCase() ? null : 'Certifier no longer eligible';
        }
        return 'Unknown recipient basis';
    }

    // ---------------------------------------------------------- content
    function compose({ to, title, color, lead, rows, link, linkLabel, note, freeText, freeTextLabel }) {
        const body = `<p>${notify.esc(lead)}</p>${notify.table(rows.map(([k, v]) => notify.row(k, v)))}` +
            (freeText ? `<p><strong>${notify.esc(freeTextLabel)}</strong><br>${notify.esc(freeText).replace(/\n/g, '<br>')}</p>` : '') +
            (note ? `<p style="font-size:13px;color:#555;">${notify.esc(note)}</p>` : '') +
            notify.button(link, linkLabel) + `<p style="font-size:12px;color:#666;">Sign-in is required. No documents are attached to this e-mail.</p>`;
        const text = `${lead}\n` + rows.map(([k, v]) => `${k}: ${v}`).join('\n') + '\n' +
            (freeText ? `${freeTextLabel}\n${freeText}\n` : '') + (note ? note + '\n' : '') + `${linkLabel} (sign-in required): ${link}\n`;
        return { html: notify.wrap(title, color, body), text };
    }
    function recipientsWithCopies(primary, copies, eventKey) {
        const seen = new Set(); const out = [];
        for (const r of primary.concat(copies)) {
            if (!r || !notify.validEmail(r.to)) continue;
            const k = r.to.toLowerCase();
            if (seen.has(k)) continue;
            seen.add(k);
            // fixed length: one key per (event, role, address); a repeated event can never e-mail twice
            out.push({ ...r, dedupeKey: 'ev-' + notify.hashKey(eventKey, r.role, r.to.toLowerCase()) });
        }
        return out;
    }
    async function supervisorCopies(researcherId, option, st, exclude) {
        if (st.options[option] !== true) return [];
        return (await supervisorsOf(researcherId)).filter(s => !(exclude || []).includes(s.researcher_id))
            .map(s => ({ to: s.email, name: s.name, researcherId: s.researcher_id, role: 'cc', basis: { kind: 'supervisor', supervisor_id: s.researcher_id, researcher_id: researcherId, option } }));
    }
    const piRecipient = () => { const pi = notify.piAddress(); return pi ? { to: pi, name: 'PI', researcherId: null, role: 'to', basis: { kind: 'pi' } } : null; };
    const researcherRecipient = (a) => a && a.active && notify.validEmail(a.email) ? { to: a.email, name: a.name, researcherId: a.researcher_id, role: 'to', basis: { kind: 'researcher', researcher_id: a.researcher_id } } : null;

    async function deliverAll({ category, event, eventKey, recipients, render }) {
        if (!recipients.length) { log(event, 'skipped', 'reason=no-eligible-recipient'); return; }
        const list = recipients.map(r => ({ ...r, ...render(r) }));
        await enqueueEvent({ category, event, list });
    }

    // ------------------------------------------------------- submissions
    async function onSubmission({ submissionId, researcherId, fileType, resubmission }) {
        const t = String(fileType || '').toUpperCase();
        const category = resubmission ? 'submission_resubmission' : ({ SOP: 'submission_sop', DATA: 'submission_data', PRESENTATION: 'submission_presentation' }[t] || 'submission_report');
        const event = 'submission.' + (resubmission ? 'resubmitted' : 'received');
        const st = await getSettings();
        if (!st.categories[category]) { log(event, 'skipped', 'reason=category-disabled'); return; }
        const s = (await pool.query(`SELECT s.submission_id, s.researcher_id, s.file_type, s.created_at, w.workspace_type
            FROM di_submissions s LEFT JOIN workspaces w ON w.id = s.workspace_id WHERE s.submission_id = $1`, [submissionId])).rows[0];
        if (!s || s.workspace_type !== 'LAB') { log(event, 'skipped', 'reason=not-a-nat-lab-submission'); return; }
        const owner = await account(s.researcher_id || researcherId);
        const who = one(owner && owner.name || s.researcher_id);
        const typeLabel = TYPE_LABELS[String(s.file_type || '').toUpperCase()] || 'Document';
        const copies = await supervisorCopies(s.researcher_id, 'cc_submissions', st, []);
        const recipients = recipientsWithCopies([piRecipient()], copies, `sub-${resubmission ? 'resub' : 'new'}-${s.submission_id}`);
        const rows = [['Researcher', who], ['Type', typeLabel + (resubmission ? ' (revised version)' : '')], ['Submitted', date(s.created_at)]];
        await deliverAll({ category, event, recipients, render: (r) => {
            const pi = r.role === 'to';
            const c = compose({ title: resubmission ? 'Revised submission received' : 'New submission received', color: '#1a365d',
                lead: resubmission ? `${who} has submitted a revised version of a ${typeLabel}.` : `${who} has submitted a new ${typeLabel}.`,
                rows, link: portal() + (pi ? '/pi-dashboard.html' : '/upload.html'), linkLabel: pi ? 'Open the PI dashboard' : 'Open the NAT-Lab portal',
                note: pi ? null : `You receive this copy as an assigned supervisor of ${who}.` });
            return { subject: `NAT-Lab: ${resubmission ? 'revised' : 'new'} ${typeLabel} submission from ${who}`, ...c };
        } });
    }

    // --------------------------------------------------------- decisions
    async function onDecision({ submissionId, decision }) {
        const d = String(decision || '').toUpperCase();
        const category = { APPROVED: 'decision_approved', REVISION_NEEDED: 'decision_revision', DISCARDED: 'decision_discarded' }[d];
        if (!category) return;
        const event = 'decision.' + category.slice(9);
        const st = await getSettings();
        if (!st.categories[category]) { log(event, 'skipped', 'reason=category-disabled'); return; }
        const s = (await pool.query(`SELECT s.submission_id, s.researcher_id, s.file_type, s.created_at, w.workspace_type
            FROM di_submissions s LEFT JOIN workspaces w ON w.id = s.workspace_id WHERE s.submission_id = $1`, [submissionId])).rows[0];
        if (!s || s.workspace_type !== 'LAB') { log(event, 'skipped', 'reason=not-a-nat-lab-submission'); return; }
        const owner = await account(s.researcher_id);
        const who = one(owner && owner.name || s.researcher_id);
        const typeLabel = TYPE_LABELS[String(s.file_type || '').toUpperCase()] || 'Document';
        let eventKey = `dec-${d}-${s.submission_id}`, revisionComment = null;
        if (d === 'REVISION_NEEDED') {
            const rr = (await pool.query(`SELECT id, created_at, pi_comment FROM di_revision_requests WHERE file_id = $1 ORDER BY created_at DESC LIMIT 1`, [s.submission_id]).catch(() => ({ rows: [] }))).rows[0];
            if (rr) { eventKey += '-' + notify.hashKey(rr.id, rr.created_at && new Date(rr.created_at).toISOString()); revisionComment = rr.pi_comment || null; }
        }
        const copies = await supervisorCopies(s.researcher_id, 'cc_decisions', st, []);
        const recipients = recipientsWithCopies([researcherRecipient(owner)], copies, eventKey);
        const words = { APPROVED: ['Submission approved', '#1e7e34', 'approved and signed by the PI'], REVISION_NEEDED: ['Revision requested', '#b45309', 'returned by the PI for revision'], DISCARDED: ['Submission discarded', '#6c757d', 'discarded by the PI'] }[d];
        const rows = [['Researcher', who], ['Document', typeLabel], ['Submitted', date(s.created_at)]];
        await deliverAll({ category, event, recipients, render: (r) => {
            const own = r.role === 'to';
            const freeText = own && d === 'REVISION_NEEDED' && st.options.include_researcher_messages === true && revisionComment ? String(revisionComment).slice(0, 4000) : null;
            const c = compose({ title: words[0], color: words[1],
                lead: own ? `Your ${typeLabel} submitted on ${date(s.created_at)} has been ${words[2]}.` : `A ${typeLabel} submitted by ${who} has been ${words[2]}.`,
                rows, link: portal() + '/upload.html', linkLabel: 'Open the NAT-Lab portal', freeText, freeTextLabel: 'Revision request from the PI:',
                note: own ? (d === 'REVISION_NEEDED' && !freeText ? 'The details of the requested revision are in the portal.' : null) : `You receive this copy as an assigned supervisor of ${who}.` });
            return { subject: `GLP ${words[0]}: ${typeLabel}${own ? '' : ' by ' + who} (${date(s.created_at)})`, ...c };
        } });
    }

    // ---------------------------------------------------------- training
    async function entryInfo(entryId) {
        return (await pool.query(`SELECT e.id, e.training_type, e.supervisor_id, e.certification_route, e.status, e.rejection_comment, e.certified_by,
                p.id AS pack_id, p.researcher_id FROM di_training_entries e JOIN di_training_packs p ON p.id = e.pack_id WHERE e.id = $1`, [entryId]).catch(() => ({ rows: [] }))).rows[0];
    }
    async function packInfo(packId) {
        return (await pool.query(`SELECT p.id, p.researcher_id, p.status, p.version, p.updated_at, p.revision_comments, p.sealed_at FROM di_training_packs p WHERE p.id = $1`, [packId]).catch(() => ({ rows: [] }))).rows[0];
    }
    async function training(kind, payload) {
        const map = {
            entry_created: 'training_initiated', pack_submitted: 'training_submitted', entry_certified_supervisor: 'training_supervisor_accepted',
            entry_certified_pi: 'training_pi_accepted', pack_revision: 'training_revision', entry_rejected: 'training_rejected', pack_sealed: 'training_certified',
        };
        const k = kind === 'entry_certified' ? 'entry_certified_' + (payload.by === 'pi' ? 'pi' : 'supervisor') : kind;
        const category = map[k];
        if (!category) return;
        const event = 'training.' + k;
        const st = await getSettings();
        if (!st.categories[category]) { log(event, 'skipped', 'reason=category-disabled'); return; }
        const entry = payload.entryId ? await entryInfo(payload.entryId) : null;
        const pack = payload.packId ? await packInfo(payload.packId) : (entry ? await packInfo(entry.pack_id) : null);
        if (!pack) { log(event, 'skipped', 'reason=not-found'); return; }
        const owner = await account(pack.researcher_id);
        const who = one(owner && owner.name || pack.researcher_id);
        const trainingType = entry ? one(entry.training_type, 80) : null;
        const actor = entry && entry.certified_by ? [entry.certified_by] : (entry && k === 'entry_rejected' ? [entry.supervisor_id] : []);
        const copies = await supervisorCopies(pack.researcher_id, 'cc_training', st, actor);
        let primary, eventKey, title, lead, ownLead, freeText = null, freeTextLabel = '';
        const verPart = notify.hashKey(pack.version, pack.updated_at && new Date(pack.updated_at).toISOString());
        switch (k) {
            case 'entry_created': {
                let to = null;
                if (entry.certification_route === 'SUPERVISOR' && entry.supervisor_id) {
                    const c = await eligibleCertifier(entry.supervisor_id);
                    if (c) to = { to: c.email, name: c.name, researcherId: c.researcher_id, role: 'to', basis: { kind: 'certifier', supervisor_id: c.researcher_id, entry_id: entry.id } };
                } else if (entry.certification_route === 'PI') to = piRecipient();
                primary = [to]; eventKey = 'tr-init-' + entry.id;
                title = 'Training entry awaiting certification'; lead = `${who} has recorded a training entry that awaits certification.`;
                break;
            }
            case 'pack_submitted': primary = [piRecipient()]; eventKey = 'tr-sub-' + pack.id + '-' + verPart;
                title = 'Training pack submitted for validation'; lead = `${who} has submitted a training pack for validation.`; break;
            case 'entry_certified_supervisor': primary = [researcherRecipient(owner)]; eventKey = 'tr-cert-' + entry.id;
                title = 'Training certified by supervisor'; ownLead = 'Your training entry has been certified by your supervisor.'; lead = `A training entry of ${who} has been certified by the supervisor.`; break;
            case 'entry_certified_pi': primary = [researcherRecipient(owner)]; eventKey = 'tr-picert-' + entry.id;
                title = 'Training accepted by the PI'; ownLead = 'Your training entry has been accepted by the PI.'; lead = `A training entry of ${who} has been accepted by the PI.`; break;
            case 'entry_rejected': primary = [researcherRecipient(owner)]; eventKey = 'tr-rej-' + entry.id + '-' + notify.hashKey(entry.rejection_comment);
                title = 'Training entry not accepted'; ownLead = 'A training entry was not accepted and needs your attention.'; lead = `A training entry of ${who} was not accepted.`;
                freeText = entry.rejection_comment; freeTextLabel = 'Comment:'; break;
            case 'pack_revision': primary = [researcherRecipient(owner)]; eventKey = 'tr-rev-' + pack.id + '-' + verPart;
                title = 'Training revision requested'; ownLead = 'The PI has requested additional training or a revision of your training pack.'; lead = `The PI has requested a revision of the training pack of ${who}.`;
                freeText = pack.revision_comments; freeTextLabel = 'Revision request from the PI:'; break;
            case 'pack_sealed': primary = [researcherRecipient(owner)]; eventKey = 'tr-seal-' + pack.id;
                title = 'Training certification issued'; ownLead = 'Your training has been certified and your certificate has been issued.'; lead = `The training certification of ${who} has been issued.`; break;
        }
        const recipients = recipientsWithCopies(primary, copies, eventKey);
        const rows = [['Researcher', who], ...(trainingType ? [['Training', trainingType]] : []), ['Date', date(new Date())]];
        await deliverAll({ category, event, recipients, render: (r) => {
            const own = r.basis.kind === 'researcher';
            const piTo = r.basis.kind === 'pi';
            const text = own && st.options.include_researcher_messages === true && freeText ? String(freeText).slice(0, 4000) : null;
            const c = compose({ title, color: '#0f766e', lead: own && ownLead ? ownLead : lead, rows,
                link: portal() + (piTo ? '/pi-dashboard.html' : '/upload.html'), linkLabel: piTo ? 'Open the PI dashboard' : 'Open the NAT-Lab portal',
                freeText: text, freeTextLabel,
                note: r.role === 'cc' ? `You receive this copy as an assigned supervisor of ${who}.` : (k === 'pack_sealed' && own ? 'The certificate is available in the portal; it is not attached.' : null) });
            return { subject: `NAT-Lab training: ${title.toLowerCase()}${own ? '' : ' — ' + who}`, ...c };
        } });
    }

    const handlers = {
        'submission.received': onSubmission,
        'decision': onDecision,
        'training.entry_created': (p) => training('entry_created', p),
        'training.pack_submitted': (p) => training('pack_submitted', p),
        'training.entry_certified': (p) => training('entry_certified', p),
        'training.entry_rejected': (p) => training('entry_rejected', p),
        'training.pack_revision': (p) => training('pack_revision', p),
        'training.pack_sealed': (p) => training('pack_sealed', p),
    };
    // Fire-and-forget: after the current response, never throws.
    function emit(type, payload) {
        const h = handlers[type];
        if (!h) return;
        try {
            setImmediate(() => { Promise.resolve().then(() => h(payload || {})).catch(e => log(type, 'failed', `reason=${(e && e.code) || 'internal'}`)); });
        } catch (_) { /* never propagate */ }
    }
    return { emit, recheck, supervisorsOf };
}

module.exports = { createNotifyEvents };
