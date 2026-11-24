'use strict';
// ============================================================================
// Optional e-mail notifications (replaces the former n8n webhooks)
// ----------------------------------------------------------------------------
// - Uses Node's built-in fetch and Resend's HTTPS API. No extra packages,
//   services, queues or tables.
// - N1: sending requires THREE things: RESEND_API_KEY and NOTIFY_FROM configured
//   AND the explicit global switch NOTIFY_SENDING_ENABLED=true. Installing the
//   credentials alone never sends anything. (NOTIFY_ENABLED=false still forces
//   everything off.) Every automatic category is additionally opt-in, off by
//   default, through the Notify settings (server/notifyCenter.js).
// - Every request has a bounded timeout. Functions here never throw.
// - Core operations never wait for e-mail: they call dispatch(), which runs the
//   send after the current request has been answered.
// - Logs contain only the event name and the outcome: never recipient
//   addresses, filenames, document contents, keys or credentials.
// - Every e-mail carries an Idempotency-Key so that the one automatic retry
//   (or an accidental repeat of the same event) cannot produce a duplicate.
// - No filenames, document contents or attachments are ever sent to the
//   provider. E-mails identify a submission only by document type and date.
//
// Delivery reliability (best effort, by design):
// - There is no persistent queue. A notification that is waiting to be sent or
//   is in flight is LOST if the application restarts or redeploys at that
//   moment; the underlying operation (upload, decision, booking) is unaffected.
// - A failed send is retried once; after that it is only logged
//   (outcome=failed). Nothing re-sends it later.
// - Duplicates are suppressed by the provider's Idempotency-Key for 24 hours.
// - Group-meeting e-mails are the exception: the PI waits for the result, sees
//   a failure, and the meeting is marked as notified only after success.
// ============================================================================
const crypto = require('crypto');

const DEFAULT_ENDPOINT = 'https://api.resend.com/emails';
const DEFAULT_PORTAL = 'https://glp.hernandezlab.com'; // primary address; the Railway fallback stays served

const SENDER_RE = /^([^<>"\r\n]{1,100}) <([^<>\s]+)>$/;
function validSender(v) { const m = SENDER_RE.exec(v || ''); return m ? validEmail(m[2]) : validEmail(v); }

function config() {
    const env = process.env;
    const off = /^(0|false|off|no)$/i.test(String(env.NOTIFY_ENABLED || '').trim());
    const sendingSwitch = String(env.NOTIFY_SENDING_ENABLED || '').trim().toLowerCase() === 'true';
    const apiKey = String(env.RESEND_API_KEY || '').trim();
    const from = String(env.NOTIFY_FROM || '').trim();
    const replyTo = String(env.NOTIFY_REPLY_TO || '').trim();
    const configured = !!apiKey && !/\s/.test(apiKey) && validSender(from);
    let timeoutMs = parseInt(env.NOTIFY_TIMEOUT_MS || '8000', 10);
    if (!Number.isFinite(timeoutMs)) timeoutMs = 8000;
    timeoutMs = Math.min(15000, Math.max(1000, timeoutMs));
    const endpoint = String(env.RESEND_API_URL || DEFAULT_ENDPOINT).trim().replace(/\/+$/, '');
    return {
        configured, sendingSwitch, off,
        enabled: !off && configured && sendingSwitch,
        apiKey, from, timeoutMs, endpoint,
        replyTo: validEmail(replyTo) ? replyTo : '',
        piEmail: String(env.NOTIFY_PI_EMAIL || '').trim(),
        theraliaTeam: [env.INVESTOR_MEETING_CEO_EMAIL, env.INVESTOR_MEETING_CSO_EMAIL]
            .map(x => String(x || '').trim()).filter(Boolean),
        portal: String(env.NOTIFY_PORTAL_URL || DEFAULT_PORTAL).trim().replace(/\/+$/, '')
    };
}

function isEnabled() { return config().enabled; }
// What the PI's Notify page may learn: booleans, variable NAMES and the (non-secret)
// addresses. Never the key or anything derived from it.
function status() {
    const c = config();
    const missing = [];
    if (!c.apiKey) missing.push('RESEND_API_KEY');
    if (!validSender(c.from)) missing.push('NOTIFY_FROM');
    if (!c.replyTo) missing.push('NOTIFY_REPLY_TO');
    if (!validEmail(c.piEmail)) missing.push('NOTIFY_PI_EMAIL');
    return { configured: c.configured, sending_switch: c.sendingSwitch && !c.off, sending_possible: c.enabled,
             missing, from: validSender(c.from) ? c.from : null, reply_to: c.replyTo || null,
             test_recipient: validEmail(c.piEmail) ? c.piEmail : null, portal: c.portal };
}
// The configured PI address (used as the only recipient in meeting test mode).
function piAddress() { const a = config().piEmail; return validEmail(a) ? a : ''; }

const EMAIL_RE = /^[^\s@<>,;"]+@[^\s@<>,;"]+\.[^\s@<>,;"]+$/;
function validEmail(x) { return typeof x === 'string' && EMAIL_RE.test(x.trim()); }

function esc(value) {
    return String(value === undefined || value === null ? '' : value).replace(/[&<>"'`]/g, ch => ({
        '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;'
    }[ch]));
}
function oneLine(value, max) {
    return String(value === undefined || value === null ? '' : value).replace(/[\r\n\t]+/g, ' ').trim().slice(0, max || 200);
}
function hashKey(...parts) {
    return crypto.createHash('sha256').update(parts.map(p => String(p === undefined || p === null ? '' : p)).join('\u0000')).digest('hex').slice(0, 40);
}

function log(event, outcome, extra) {
    console.log(`[NOTIFY] event=${event} outcome=${outcome}${extra ? ' ' + extra : ''}`);
}

// One POST with a bounded timeout; one immediate retry on network error, timeout,
// 429 or 5xx — always with the SAME Idempotency-Key, so the provider cannot
// deliver twice (Resend keeps the key for 24 h). Returns { ok, outcome, http, id,
// ambiguous }. `ambiguous` = it is unknown whether the provider accepted it.
// Never throws.
async function post(path, body, idempotencyKey, event) {
    const cfg = config();
    if (!cfg.enabled) { log(event, 'skipped', 'reason=not-configured'); return { ok: false, outcome: 'skipped' }; }
    const url = cfg.endpoint + path;
    let last = { ok: false, outcome: 'failed' };
    for (let attempt = 1; attempt <= 2; attempt++) {
        const started = Date.now();
        try {
            const r = await fetch(url, {
                method: 'POST',
                headers: {
                    'Authorization': 'Bearer ' + cfg.apiKey,
                    'Content-Type': 'application/json',
                    'Idempotency-Key': idempotencyKey
                },
                body: JSON.stringify(body),
                redirect: 'error',
                signal: AbortSignal.timeout(cfg.timeoutMs)
            });
            let id = null;
            try { const j = JSON.parse(Buffer.from(await r.arrayBuffer()).toString('utf8') || 'null'); id = j && typeof j.id === 'string' ? j.id.slice(0, 100) : null; } catch (_) { /* body not needed */ }
            const ms = Date.now() - started;
            if (r.ok) { log(event, 'sent', `http=${r.status} attempt=${attempt} ms=${ms}`); return { ok: true, outcome: 'sent', http: r.status, id }; }
            // 5xx and 409 (concurrent request with the same key) leave it UNKNOWN whether the
            // provider accepted the e-mail; other 4xx (incl. 429) mean it was not accepted.
            last = { ok: false, outcome: 'failed', http: r.status, ambiguous: r.status >= 500 || r.status === 409 };
            log(event, 'failed', `http=${r.status} attempt=${attempt} ms=${ms}`);
            if (!(r.status === 429 || r.status >= 500)) break;
        } catch (e) {
            const reason = e && (e.name === 'TimeoutError' || e.name === 'AbortError') ? 'timeout' : 'network';
            last = { ok: false, outcome: 'failed', reason, ambiguous: true };
            log(event, 'failed', `reason=${reason} attempt=${attempt} ms=${Date.now() - started}`);
        }
        if (attempt === 1) await new Promise(res => setTimeout(res, 500));
    }
    return last;
}

async function sendEmail({ event, to, subject, html, text, idempotencyKey }) {
    try {
        const cfg = config();
        if (!cfg.enabled) { log(event, 'skipped', 'reason=not-configured'); return { ok: false, outcome: 'skipped' }; }
        const recipients = (Array.isArray(to) ? to : [to]).filter(validEmail);
        if (recipients.length === 0) { log(event, 'skipped', 'reason=no-recipient'); return { ok: false, outcome: 'skipped' }; }
        const body = { from: cfg.from, to: recipients, subject: oneLine(subject, 250), html, text };
        if (cfg.replyTo) body.reply_to = cfg.replyTo;
        return await post('', body, idempotencyKey, event);
    } catch (_) {
        log(event, 'failed', 'reason=internal');
        return { ok: false, outcome: 'failed' };
    }
}

// One e-mail to ONE address (never CC/BCC) for the Notify outbox. Returns
// { status: 'accepted' | 'failed' | 'uncertain' | 'disabled', id, code }.
// 'accepted' = Resend accepted the request (NOT proof of delivery).
async function deliver({ event, to, subject, html, text, idempotencyKey }) {
    if (!config().enabled) return { status: 'disabled', code: 'sending_disabled' };
    if (!validEmail(to)) return { status: 'failed', code: 'invalid_address' };
    const r = await sendEmail({ event, to: String(to).trim(), subject, html, text, idempotencyKey });
    if (r.ok) return { status: 'accepted', id: r.id || null };
    if (r.outcome === 'skipped') return { status: 'disabled', code: 'sending_disabled' };
    const code = r.http ? 'http_' + r.http : (r.reason || 'internal');
    return { status: r.ambiguous ? 'uncertain' : 'failed', code };
}

// Several separate e-mails in ONE request (Resend batch endpoint): the request
// is accepted or rejected as a whole. Used for group-meeting notifications.
async function sendBatch({ event, messages, idempotencyKey }) {
    try {
        const cfg = config();
        if (!cfg.enabled) { log(event, 'skipped', 'reason=not-configured'); return { ok: false, outcome: 'skipped' }; }
        const list = messages.filter(m => validEmail(m.to)).map(m => ({ from: cfg.from, to: [m.to.trim()], subject: oneLine(m.subject, 250), html: m.html, text: m.text }));
        if (list.length === 0 || list.length !== messages.length) { log(event, 'skipped', 'reason=invalid-recipient'); return { ok: false, outcome: 'skipped' }; }
        if (list.length > 100) { log(event, 'skipped', 'reason=too-many-recipients'); return { ok: false, outcome: 'skipped' }; }
        return await post('/batch', list, idempotencyKey, event);
    } catch (_) {
        log(event, 'failed', 'reason=internal');
        return { ok: false, outcome: 'failed' };
    }
}

// ------------------------------------------------------------- automation
// Automatic categories are opt-in (default OFF). server/notifyCenter.js installs
// the category check and the durable delivery sink; without it nothing automatic
// is ever sent.
let automation = { isCategoryEnabled: async () => false, deliver: null, onEvent: null };
function setAutomation(a) { automation = Object.assign({ isCategoryEnabled: async () => false, deliver: null, onEvent: null }, a || {}); }
// N3: when the Notify centre is installed, scientific events are handed to it
// (it decides categories, recipients incl. supervisor copies, content and delivery).
function handOver(type, payload) {
    if (typeof automation.onEvent !== 'function') return false;
    try { automation.onEvent(type, payload); } catch (_) { log(type, 'failed', 'reason=internal'); }
    return true;
}
async function automaticAllowed(category, event) {
    try {
        if (!config().enabled) { log(event, 'skipped', 'reason=sending-disabled'); return false; }
        if (!(await automation.isCategoryEnabled(category))) { log(event, 'skipped', 'reason=category-disabled'); return false; }
        return true;
    } catch (_) { log(event, 'skipped', 'reason=category-check-failed'); return false; }
}
async function deliverAutomatic(m) {
    if (typeof automation.deliver === 'function') return automation.deliver(m);
    return sendEmail({ event: m.event, to: m.to, subject: m.subject, html: m.html, text: m.text, idempotencyKey: m.dedupeKey });
}

// Run fn after the current request has been answered. Never throws, never blocks.
function dispatch(event, fn) {
    try {
        setImmediate(() => {
            Promise.resolve().then(fn).catch(() => log(event, 'failed', 'reason=internal'));
        });
    } catch (_) { /* never propagate */ }
}

// ---------------------------------------------------------------- templates
function wrap(title, color, bodyHtml) {
    return `<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;max-width:600px;margin:0 auto;color:#1f2937;">
<div style="background:${color};color:#fff;padding:16px 20px;border-radius:8px 8px 0 0;"><h1 style="margin:0;font-size:19px;">${esc(title)}</h1></div>
<div style="padding:20px 24px;background:#f8f9fa;line-height:1.5;">${bodyHtml}</div>
<div style="padding:12px;text-align:center;font-size:12px;color:#888;">NAT-Lab GLP System &middot; automated notification</div>
</body></html>`;
}
function row(label, value) {
    return `<tr><td style="padding:6px 10px;color:#555;width:38%;">${esc(label)}</td><td style="padding:6px 10px;">${esc(value)}</td></tr>`;
}
function table(rows) { return `<table style="width:100%;border-collapse:collapse;background:#fff;border-radius:6px;margin:12px 0;">${rows.join('')}</table>`; }
function button(href, label) {
    return `<p style="margin:16px 0;"><a href="${esc(href)}" style="background:#1a365d;color:#fff;padding:10px 18px;border-radius:6px;text-decoration:none;display:inline-block;">${esc(label)}</a></p>`;
}

const TYPE_LABELS = { SOP: 'SOP', DATA: 'Data', PRESENTATION: 'Presentation', REPORT: 'Report' };

// New submission -> configured PI address. Minimal metadata, no filename, no content.
function notifySubmissionReceived({ submissionId, researcherId, researcherName, fileType, reportSubcategory, uploadedByAutomation, resubmission }) {
    if (handOver('submission.received', { submissionId, researcherId, fileType, resubmission: !!resubmission })) return;
    const event = 'submission.received';
    dispatch(event, async () => {
        const cfg = config();
        if (!(await automaticAllowed('submission_received', event))) return;
        if (!validEmail(cfg.piEmail)) { log(event, 'skipped', 'reason=no-pi-address'); return; }
        const typeLabel = TYPE_LABELS[String(fileType || '').toUpperCase()] || oneLine(fileType, 40) || 'Document';
        const who = oneLine(researcherName, 120) || 'a researcher';
        const rows = [row('Researcher', who), row('Type', typeLabel + (reportSubcategory ? ' (' + oneLine(reportSubcategory, 60).replace(/_/g, ' ').toLowerCase() + ')' : ''))];
        if (uploadedByAutomation) rows.push(row('Uploaded by', 'automation account on behalf of the researcher'));
        const dash = cfg.portal + '/pi-dashboard.html';
        const html = wrap('New submission waiting for review', '#1a365d',
            `<p>A new document has been submitted to NAT-Lab.</p>${table(rows)}${button(dash, 'Open the PI dashboard')}<p style="font-size:12px;color:#666;">Sign-in is required. The document itself is not attached to this e-mail.</p>`);
        const text = `New NAT-Lab submission\nResearcher: ${who}\nType: ${typeLabel}\nOpen the PI dashboard (sign-in required): ${dash}\n`;
        await deliverAutomatic({ category: 'submission_received', event, to: cfg.piEmail, recipientId: null, name: 'PI',
            subject: `New NAT-Lab submission: ${typeLabel} from ${who}`, html, text,
            dedupeKey: 'submission-received-' + hashKey(submissionId) });
    });
}

// PI decision -> researcher. Per category opt-in (decision_approved /
// decision_revision / decision_discarded), all OFF by default.
// The e-mail carries NO filename, NO PI comment, NO discard reason or note and
// NO verification code: only the document type, the submission date and a link
// to the portal, where sign-in and the document-access rules apply. (Payload
// fields such as approval_comment, pi_comments, discard_reason, discard_note,
// file_name, view_url and verification_code are deliberately ignored.)
// The optional async `describe()` returns { fileType, submittedAt }; it runs after
// the response and its failure is harmless. Each decision event has its own key,
// so a later revision request on the same submission is never suppressed.
const DECISION_CATEGORY = { APPROVED: 'decision_approved', REVISION_NEEDED: 'decision_revision', DISCARDED: 'decision_discarded' };
function notifyResearcherDecision(payload, describe) {
    const p = payload || {};
    const decision = String(p.decision || '').toUpperCase();
    if (handOver('decision', { submissionId: p.submission_id, decision })) return;
    const event = 'decision.' + (decision === 'APPROVED' ? 'approved' : decision === 'DISCARDED' ? 'discarded' : decision === 'REVISION_NEEDED' ? 'revision' : 'unknown');
    const eventId = crypto.randomUUID();
    dispatch(event, async () => {
        const cfg = config();
        if (event === 'decision.unknown') { log(event, 'skipped', 'reason=unknown-decision'); return; }
        if (!(await automaticAllowed(DECISION_CATEGORY[decision], event))) return;
        let info = {};
        if (typeof describe === 'function') { try { info = (await describe()) || {}; } catch (_) { info = {}; } }
        const typeLabel = TYPE_LABELS[String(info.fileType || '').toUpperCase()] || 'Document';
        const submitted = info.submittedAt ? dateOnly(info.submittedAt) : '';
        const what = typeLabel + (submitted ? ' submitted on ' + submitted : '');
        const rows = [row('Document', typeLabel), ...(submitted ? [row('Submitted', submitted)] : [])];
        const portalUrl = cfg.portal + '/upload.html';
        let subject, title, color, lead;
        if (decision === 'APPROVED') {
            subject = `GLP Submission Approved: ${what}`; title = 'Submission Approved'; color = '#1e7e34';
            lead = 'Your submission has been approved and signed by the PI.';
        } else if (decision === 'DISCARDED') {
            subject = `GLP Submission Discarded: ${what}`; title = 'Submission Discarded'; color = '#6c757d';
            lead = 'Your submission has been discarded by the PI.';
        } else {
            subject = `GLP Submission Requires Revision: ${what}`; title = 'Revision Requested'; color = '#b45309';
            lead = 'The PI has requested a revision of your submission.';
        }
        const html = wrap(title, color, `<p>${esc(lead)}</p>${table(rows)}<p>Details are available in the NAT-Lab portal.</p>` +
            button(portalUrl, 'Open the NAT-Lab portal') + `<p style="font-size:12px;color:#666;">Sign-in is required.</p>`);
        const text = `${lead}\nDocument: ${what}\nDetails are available in the NAT-Lab portal (sign-in required): ${portalUrl}\n`;
        await deliverAutomatic({ category: DECISION_CATEGORY[decision], event, to: p.researcher_email, recipientId: p.researcher_id || null,
            name: oneLine(p.researcher_name, 120) || 'Researcher', subject, html, text,
            dedupeKey: 'decision-' + hashKey(p.submission_id, decision, eventId) });
    });
}

// New investor booking -> the configured Theralia team addresses only.
function notifyInvestorBookingTeam({ bookingId, teamText }) {
    const event = 'investor.booking.team';
    dispatch(event, async () => {
        const cfg = config();
        if (!(await automaticAllowed('theralia_investor_booking', event))) return;
        const team = cfg.theraliaTeam.filter(validEmail);
        if (team.length === 0) { log(event, 'skipped', 'reason=no-team-address'); return; }
        const t = String(teamText || '').slice(0, 4000);
        const html = wrap('New investor meeting booking', '#0f4c5c', `<pre style="white-space:pre-wrap;font-family:inherit;margin:0;">${esc(t)}</pre>`);
        await sendEmail({ event, to: team, subject: 'Theralia: new investor meeting booking', html, text: t,
            idempotencyKey: 'investor-booking-' + hashKey(bookingId || crypto.randomUUID()) });
    });
}

// ------------------------------------------------------------ group meetings
const SLOT_LABELS = { DATA_DEEP: 'DATA Deep (30 min)', DATA_FOCUS: 'DATA Focus (10 min)', DATA_FLASH: 'DATA Flash (2 min)' };

// node-postgres returns a DATE column as a Date at local midnight of the server,
// so its LOCAL calendar fields are the stored date (independent of server TZ).
function dateOnly(d) {
    if (d instanceof Date && !Number.isNaN(d.getTime())) {
        return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
    }
    return String(d || '').slice(0, 10);
}
function formatMeetingDate(d) {
    if (!d) return '';
    const date = new Date(dateOnly(d) + 'T12:00:00Z');
    if (Number.isNaN(date.getTime())) return oneLine(d, 40);
    return date.toLocaleDateString('en-GB', { weekday: 'long', day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' });
}

// Builds one message per participant. participants: [{ name, email, slot_type }]
// in agenda order. Returns [{ to, subject, html, text }].
function buildMeetingMessages(meeting, participants) {
    const dateStr = formatMeetingDate(meeting.meeting_date);
    const timeStr = oneLine(meeting.meeting_time, 5) || '09:00';
    const location = oneLine(meeting.location_text, 200) || 'To be announced';
    const agendaRows = participants.map((p, i) => row(`${i + 1}. ${oneLine(p.name, 120)}`, SLOT_LABELS[p.slot_type] || oneLine(p.slot_type, 30)));
    const agendaText = participants.map((p, i) => `${i + 1}. ${oneLine(p.name, 120)} - ${SLOT_LABELS[p.slot_type] || oneLine(p.slot_type, 30)}`).join('\n');
    return participants.map(p => {
        const slot = SLOT_LABELS[p.slot_type] || oneLine(p.slot_type, 30);
        const html = wrap('NAT-Lab Group Meeting', '#6d28d9',
            `<p>Dear ${esc(oneLine(p.name, 120))},</p><p>You are scheduled to present at the next NAT-Lab group meeting.</p>` +
            table([row('Date', dateStr), row('Time', timeStr), row('Location', location), row('Your slot', slot)]) +
            `<p><strong>Agenda</strong></p>${table(agendaRows)}`);
        const text = `Dear ${oneLine(p.name, 120)},\n\nYou are scheduled to present at the next NAT-Lab group meeting.\nDate: ${dateStr}\nTime: ${timeStr}\nLocation: ${location}\nYour slot: ${slot}\n\nAgenda:\n${agendaText}\n`;
        return { to: p.email, subject: `NAT-Lab Group Meeting - ${dateStr}, ${timeStr}`, html, text };
    });
}

module.exports = {
    isEnabled, status, config, piAddress, dateOnly, sendEmail, sendBatch, deliver, dispatch, esc, oneLine, hashKey, validEmail, validSender,
    setAutomation, wrap, row, table, button,
    notifySubmissionReceived, notifyResearcherDecision, notifyInvestorBookingTeam, buildMeetingMessages
};
