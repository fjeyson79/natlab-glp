'use strict';
// ============================================================================
// Optional e-mail notifications (replaces the former n8n webhooks)
// ----------------------------------------------------------------------------
// - Uses Node's built-in fetch and Resend's HTTPS API. No extra packages,
//   services, queues or tables.
// - DISABLED unless RESEND_API_KEY and NOTIFY_FROM are set, and can be switched
//   off with NOTIFY_ENABLED=false. When disabled nothing is sent and nothing fails.
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
const DEFAULT_PORTAL = 'https://natlab-glp-production.up.railway.app';

function config() {
    const env = process.env;
    const off = /^(0|false|off|no)$/i.test(String(env.NOTIFY_ENABLED || '').trim());
    const apiKey = String(env.RESEND_API_KEY || '').trim();
    const from = String(env.NOTIFY_FROM || '').trim();
    let timeoutMs = parseInt(env.NOTIFY_TIMEOUT_MS || '8000', 10);
    if (!Number.isFinite(timeoutMs)) timeoutMs = 8000;
    timeoutMs = Math.min(15000, Math.max(1000, timeoutMs));
    const endpoint = String(env.RESEND_API_URL || DEFAULT_ENDPOINT).trim().replace(/\/+$/, '');
    return {
        enabled: !off && !!apiKey && !!from,
        apiKey, from, timeoutMs, endpoint,
        piEmail: String(env.NOTIFY_PI_EMAIL || '').trim(),
        theraliaTeam: [env.INVESTOR_MEETING_CEO_EMAIL, env.INVESTOR_MEETING_CSO_EMAIL]
            .map(x => String(x || '').trim()).filter(Boolean),
        portal: String(env.NOTIFY_PORTAL_URL || DEFAULT_PORTAL).trim().replace(/\/+$/, '')
    };
}

function isEnabled() { return config().enabled; }
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

// One POST with a bounded timeout; one retry (same Idempotency-Key) on network
// error, timeout, 429 or 5xx. Returns { ok, outcome, http }. Never throws.
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
            try { await r.arrayBuffer(); } catch (_) { /* response body is not used */ }
            const ms = Date.now() - started;
            if (r.ok) { log(event, 'sent', `http=${r.status} attempt=${attempt} ms=${ms}`); return { ok: true, outcome: 'sent', http: r.status }; }
            last = { ok: false, outcome: 'failed', http: r.status };
            log(event, 'failed', `http=${r.status} attempt=${attempt} ms=${ms}`);
            if (!(r.status === 429 || r.status >= 500)) break;
        } catch (e) {
            const reason = e && (e.name === 'TimeoutError' || e.name === 'AbortError') ? 'timeout' : 'network';
            last = { ok: false, outcome: 'failed', reason };
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
        return await post('', { from: cfg.from, to: recipients, subject: oneLine(subject, 250), html, text }, idempotencyKey, event);
    } catch (_) {
        log(event, 'failed', 'reason=internal');
        return { ok: false, outcome: 'failed' };
    }
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
function notifySubmissionReceived({ submissionId, researcherName, fileType, reportSubcategory, uploadedByAutomation }) {
    const event = 'submission.received';
    dispatch(event, async () => {
        const cfg = config();
        if (!cfg.enabled) { log(event, 'skipped', 'reason=not-configured'); return; }
        if (!validEmail(cfg.piEmail)) { log(event, 'skipped', 'reason=no-pi-address'); return; }
        const typeLabel = TYPE_LABELS[String(fileType || '').toUpperCase()] || oneLine(fileType, 40) || 'Document';
        const who = oneLine(researcherName, 120) || 'a researcher';
        const rows = [row('Researcher', who), row('Type', typeLabel + (reportSubcategory ? ' (' + oneLine(reportSubcategory, 60).replace(/_/g, ' ').toLowerCase() + ')' : ''))];
        if (uploadedByAutomation) rows.push(row('Uploaded by', 'automation account on behalf of the researcher'));
        const dash = cfg.portal + '/pi-dashboard.html';
        const html = wrap('New submission waiting for review', '#1a365d',
            `<p>A new document has been submitted to NAT-Lab.</p>${table(rows)}${button(dash, 'Open the PI dashboard')}<p style="font-size:12px;color:#666;">Sign-in is required. The document itself is not attached to this e-mail.</p>`);
        const text = `New NAT-Lab submission\nResearcher: ${who}\nType: ${typeLabel}\nOpen the PI dashboard (sign-in required): ${dash}\n`;
        await sendEmail({ event, to: cfg.piEmail, subject: `New NAT-Lab submission: ${typeLabel} from ${who}`, html, text,
            idempotencyKey: 'submission-received-' + hashKey(submissionId) });
    });
}

// PI decision -> researcher. Same payload shape that notifyResearcher() always
// received (file_name is ignored: no filenames in e-mails). The optional async
// `describe()` returns { fileType, submittedAt } so the researcher can tell which
// submission is meant; it runs after the response and its failure is harmless.
// Each decision event gets its own key, so a later revision request on the same
// submission is never suppressed by an earlier one.
function notifyResearcherDecision(payload, describe) {
    const p = payload || {};
    const decision = String(p.decision || '').toUpperCase();
    const event = 'decision.' + (decision === 'APPROVED' ? 'approved' : decision === 'DISCARDED' ? 'discarded' : decision === 'REVISION_NEEDED' ? 'revision' : 'unknown');
    const eventId = crypto.randomUUID();
    dispatch(event, async () => {
        const cfg = config();
        if (!cfg.enabled) { log(event, 'skipped', 'reason=not-configured'); return; }
        if (event === 'decision.unknown') { log(event, 'skipped', 'reason=unknown-decision'); return; }
        let info = {};
        if (typeof describe === 'function') { try { info = (await describe()) || {}; } catch (_) { info = {}; } }
        const typeLabel = TYPE_LABELS[String(info.fileType || '').toUpperCase()] || 'Document';
        const submitted = info.submittedAt ? dateOnly(info.submittedAt) : '';
        const what = typeLabel + (submitted ? ' submitted on ' + submitted : '');
        const idRows = () => [row('Document', typeLabel), ...(submitted ? [row('Submitted', submitted)] : [])];
        let subject, title, color, body, text;
        if (decision === 'APPROVED') {
            subject = `GLP Submission Approved: ${what}`; title = 'Submission Approved'; color = '#1e7e34';
            const rows = idRows();
            if (p.verification_code) rows.push(row('Verification code', p.verification_code));
            body = `<p>Your submission has been approved and signed by the PI.</p>${table(rows)}` +
                (p.approval_comment ? `<p><strong>PI comment:</strong><br>${esc(p.approval_comment)}</p>` : '') +
                (p.view_url ? button(p.view_url, 'View approved document') : '') +
                `<p style="font-size:12px;color:#666;">Sign-in is required to open the document.</p>`;
            text = `Your submission (${what}) has been approved.\n` + (p.verification_code ? `Verification code: ${p.verification_code}\n` : '') +
                (p.approval_comment ? `PI comment: ${p.approval_comment}\n` : '') + (p.view_url ? `View (sign-in required): ${p.view_url}\n` : '');
        } else if (decision === 'DISCARDED') {
            subject = `GLP Submission Discarded: ${what}`; title = 'Submission Discarded'; color = '#6c757d';
            const rows = idRows();
            if (p.discard_reason) rows.push(row('Reason', p.discard_reason));
            body = `<p>Your submission has been discarded by the PI.</p>${table(rows)}` +
                (p.discard_note ? `<p><strong>Note:</strong><br>${esc(p.discard_note)}</p>` : '');
            text = `Your submission (${what}) has been discarded.\n` + (p.discard_reason ? `Reason: ${p.discard_reason}\n` : '') + (p.discard_note ? `Note: ${p.discard_note}\n` : '');
        } else {
            subject = `GLP Submission Requires Revision: ${what}`; title = 'Revision Requested'; color = '#b45309';
            const uploadUrl = cfg.portal + '/upload.html';
            body = `<p>The PI has requested a revision of your submission.</p>${table(idRows())}` +
                (p.pi_comments ? `<p><strong>PI comments:</strong><br>${esc(p.pi_comments)}</p>` : '') +
                button(uploadUrl, 'Upload a revised version') + `<p style="font-size:12px;color:#666;">Sign-in is required.</p>`;
            text = `The PI has requested a revision of your submission (${what}).\n` + (p.pi_comments ? `PI comments: ${p.pi_comments}\n` : '') + `Upload a revised version (sign-in required): ${uploadUrl}\n`;
        }
        await sendEmail({ event, to: p.researcher_email, subject, html: wrap(title, color, body), text,
            idempotencyKey: 'decision-' + hashKey(p.submission_id, decision, eventId) });
    });
}

// New investor booking -> the configured Theralia team addresses only.
function notifyInvestorBookingTeam({ bookingId, teamText }) {
    const event = 'investor.booking.team';
    dispatch(event, async () => {
        const cfg = config();
        if (!cfg.enabled) { log(event, 'skipped', 'reason=not-configured'); return; }
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
    isEnabled, piAddress, dateOnly, sendEmail, sendBatch, dispatch, esc, hashKey, validEmail,
    notifySubmissionReceived, notifyResearcherDecision, notifyInvestorBookingTeam, buildMeetingMessages
};
