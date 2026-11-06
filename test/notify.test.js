'use strict';
// Unit tests for server/notify.js against a localhost provider stand-in.
// Never contacts the real Resend API: RESEND_API_URL always points to 127.0.0.1.
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');

const ENV_KEYS = ['NOTIFY_ENABLED', 'RESEND_API_KEY', 'NOTIFY_FROM', 'NOTIFY_PI_EMAIL', 'RESEND_API_URL', 'NOTIFY_TIMEOUT_MS',
    'INVESTOR_MEETING_CEO_EMAIL', 'INVESTOR_MEETING_CSO_EMAIL', 'NOTIFY_PORTAL_URL'];
const saved = {}; for (const k of ENV_KEYS) saved[k] = process.env[k];
test.after(() => { for (const k of ENV_KEYS) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; } });

// Stand-in provider: behaviour per request is taken from `mode`.
let mode = 'ok'; const seen = [];
const server = http.createServer((req, res) => {
    let body = ''; req.on('data', c => { body += c; });
    req.on('end', () => {
        seen.push({ path: req.url, auth: req.headers.authorization, key: req.headers['idempotency-key'], body: JSON.parse(body || 'null') });
        const m = typeof mode === 'function' ? mode(seen.length) : mode;
        if (m === 'hang') return; // never answers
        if (m === 'slow') return setTimeout(() => { res.writeHead(200); res.end('{"id":"x"}'); }, 300);
        res.writeHead(m === 'ok' ? 200 : Number(m)); res.end('{}');
    });
});
let base;
test.before(async () => { await new Promise(r => server.listen(0, '127.0.0.1', r)); base = `http://127.0.0.1:${server.address().port}/emails`; });
test.after(() => { server.closeAllConnections(); server.close(); });

function configure(extra) {
    for (const k of ENV_KEYS) delete process.env[k];
    Object.assign(process.env, { RESEND_API_KEY: 'test-key-not-real', NOTIFY_FROM: 'NAT-Lab <noreply@example.test>', RESEND_API_URL: base,
        NOTIFY_PI_EMAIL: 'pi@example.test', NOTIFY_TIMEOUT_MS: '1000' }, extra || {});
}
const notify = require('../server/notify');
function captureLogs() {
    const lines = []; const orig = { log: console.log, warn: console.warn, error: console.error };
    for (const k of Object.keys(orig)) console[k] = (...a) => lines.push(a.join(' '));
    return { lines, restore: () => Object.assign(console, orig) };
}
const settle = ms => new Promise(r => setTimeout(r, ms));

test('disabled without configuration or with NOTIFY_ENABLED=false: nothing is sent, no throw', async () => {
    seen.length = 0;
    for (const k of ENV_KEYS) delete process.env[k];
    assert.strictEqual(notify.isEnabled(), false);
    const r = await notify.sendEmail({ event: 't', to: 'a@example.test', subject: 's', html: 'h', text: 't', idempotencyKey: 'k' });
    assert.strictEqual(r.outcome, 'skipped');
    configure({ NOTIFY_ENABLED: 'false' });
    assert.strictEqual(notify.isEnabled(), false);
    assert.strictEqual((await notify.sendEmail({ event: 't', to: 'a@example.test', subject: 's', idempotencyKey: 'k' })).outcome, 'skipped');
    assert.strictEqual(seen.length, 0);
});

test('success: one request with bearer key and Idempotency-Key', async () => {
    configure(); mode = 'ok'; seen.length = 0;
    const r = await notify.sendEmail({ event: 't', to: 'a@example.test', subject: 'Hello', html: '<p>x</p>', text: 'x', idempotencyKey: 'key-1' });
    assert.deepStrictEqual([r.ok, r.outcome, seen.length], [true, 'sent', 1]);
    assert.strictEqual(seen[0].auth, 'Bearer test-key-not-real');
    assert.strictEqual(seen[0].key, 'key-1');
    assert.deepStrictEqual(seen[0].body.to, ['a@example.test']);
});

test('5xx and 429 are retried once with the SAME Idempotency-Key; 4xx is not retried', async () => {
    configure(); seen.length = 0; mode = n => (n === 1 ? '503' : 'ok');
    const r = await notify.sendEmail({ event: 't', to: 'a@example.test', subject: 's', idempotencyKey: 'key-r' });
    assert.strictEqual(r.ok, true); assert.strictEqual(seen.length, 2); assert.strictEqual(seen[0].key, seen[1].key);
    seen.length = 0; mode = '422';
    const r2 = await notify.sendEmail({ event: 't', to: 'a@example.test', subject: 's', idempotencyKey: 'key-4' });
    assert.strictEqual(r2.ok, false); assert.strictEqual(seen.length, 1);
    seen.length = 0; mode = '500';
    const r3 = await notify.sendEmail({ event: 't', to: 'a@example.test', subject: 's', idempotencyKey: 'key-5' });
    assert.strictEqual(r3.ok, false); assert.strictEqual(seen.length, 2);
});

test('unresponsive provider: bounded by the timeout (2 attempts), never throws', async () => {
    configure({ NOTIFY_TIMEOUT_MS: '1000' }); mode = 'hang'; seen.length = 0;
    const t0 = Date.now();
    const r = await notify.sendEmail({ event: 't', to: 'a@example.test', subject: 's', idempotencyKey: 'key-h' });
    const ms = Date.now() - t0;
    assert.strictEqual(r.ok, false); assert.strictEqual(r.reason, 'timeout');
    assert.ok(ms >= 2000 && ms < 4500, 'elapsed ' + ms);
    server.closeAllConnections();
});

test('unreachable provider: fails cleanly', async () => {
    configure({ RESEND_API_URL: 'http://127.0.0.1:9/emails' });
    const r = await notify.sendEmail({ event: 't', to: 'a@example.test', subject: 's', idempotencyKey: 'k' });
    assert.strictEqual(r.ok, false); assert.strictEqual(r.reason, 'network');
});

test('dispatch-based notifications return immediately even when the provider hangs', async () => {
    configure(); mode = 'hang'; seen.length = 0;
    const t0 = Date.now();
    notify.notifyResearcherDecision({ submission_id: 's1', decision: 'APPROVED', researcher_email: 'r@example.test', file_name: 'f.pdf' });
    notify.notifySubmissionReceived({ submissionId: 's1', researcherName: 'R', fileType: 'SOP' });
    assert.ok(Date.now() - t0 < 50);
    await settle(3000); server.closeAllConnections();
});

test('HTML escaping in decision and meeting e-mails; no attachment, no document content', async () => {
    configure(); mode = 'ok'; seen.length = 0;
    notify.notifyResearcherDecision({ submission_id: 's2', decision: 'REVISION_NEEDED', researcher_email: 'r@example.test',
        file_name: '<img src=x onerror=alert(1)>.pdf', pi_comments: '<script>alert("x")</script> & more' });
    await settle(300);
    const b = seen[0].body;
    assert.ok(!b.html.includes('<script>') && !b.html.includes('<img'));
    assert.ok(b.html.includes('&lt;script&gt;') && b.html.includes('&amp; more'));
    assert.strictEqual(b.attachments, undefined);
    const msgs = notify.buildMeetingMessages({ meeting_date: '2026-11-12', meeting_time: '09:00:00', location_text: '<b>Room</b>' },
        [{ name: '<i>A</i>', email: 'a@example.test', slot_type: 'DATA_DEEP' }]);
    assert.ok(!msgs[0].html.includes('<b>Room') && !msgs[0].html.includes('<i>A'));
    assert.ok(msgs[0].html.includes('&lt;b&gt;Room'));
});

test('submission e-mail: PI address only, minimal metadata (no filename), stable key per submission', async () => {
    configure(); mode = 'ok'; seen.length = 0;
    notify.notifySubmissionReceived({ submissionId: 'sub-A', researcherName: 'Researcher A', fileType: 'SOP' });
    notify.notifySubmissionReceived({ submissionId: 'sub-A', researcherName: 'Researcher A', fileType: 'SOP' });
    notify.notifySubmissionReceived({ submissionId: 'sub-B', researcherName: 'Researcher A', fileType: 'REPORT', reportSubcategory: 'PHD_REPORT' });
    await settle(300);
    assert.strictEqual(seen.length, 3);
    assert.ok(seen.every(s => s.body.to.length === 1 && s.body.to[0] === 'pi@example.test'));
    assert.strictEqual(seen[0].key, seen[1].key); assert.notStrictEqual(seen[0].key, seen[2].key);
    assert.ok(!JSON.stringify(seen.map(s => s.body)).includes('.pdf'));
});

test('decision e-mails: every decision event has its own key (repeated revisions are not suppressed)', async () => {
    configure(); mode = 'ok'; seen.length = 0;
    const p = { submission_id: 'sub-R', decision: 'REVISION_NEEDED', researcher_email: 'r@example.test', file_name: 'f.pdf', pi_comments: 'same' };
    notify.notifyResearcherDecision(p); notify.notifyResearcherDecision(p);
    notify.notifyResearcherDecision({ ...p, decision: 'APPROVED' });
    await settle(300);
    assert.strictEqual(seen.length, 3);
    assert.strictEqual(new Set(seen.map(s => s.key)).size, 3);
    assert.ok(seen[0].body.subject.startsWith('GLP Submission Requires Revision:'));
    assert.ok(seen[2].body.subject.startsWith('GLP Submission Approved:'));
});

test('investor booking: only the configured Theralia team, never the investor', async () => {
    configure({ INVESTOR_MEETING_CEO_EMAIL: 'ceo@example.test', INVESTOR_MEETING_CSO_EMAIL: 'cso@example.test' }); mode = 'ok'; seen.length = 0;
    notify.notifyInvestorBookingTeam({ bookingId: 7, teamText: 'Investor: X\nEmail: investor@example.test' });
    await settle(300);
    assert.strictEqual(seen.length, 1); assert.deepStrictEqual(seen[0].body.to, ['ceo@example.test', 'cso@example.test']);
    configure(); seen.length = 0;
    notify.notifyInvestorBookingTeam({ bookingId: 8, teamText: 'x' });
    await settle(200);
    assert.strictEqual(seen.length, 0);
});

test('batch: all-or-nothing single request; rejects invalid recipients', async () => {
    configure(); mode = 'ok'; seen.length = 0;
    const msgs = notify.buildMeetingMessages({ meeting_date: '2026-11-12', meeting_time: '09:00' },
        [{ name: 'A', email: 'a@example.test', slot_type: 'DATA_FLASH' }, { name: 'B', email: 'b@example.test', slot_type: 'DATA_FOCUS' }]);
    const r = await notify.sendBatch({ event: 'm', messages: msgs, idempotencyKey: 'mk' });
    assert.strictEqual(r.ok, true); assert.strictEqual(seen.length, 1); assert.strictEqual(seen[0].path, '/emails/batch');
    assert.strictEqual(seen[0].body.length, 2);
    const bad = await notify.sendBatch({ event: 'm', messages: [...msgs, { to: 'not-an-address', subject: 's', html: '', text: '' }], idempotencyKey: 'mk2' });
    assert.strictEqual(bad.ok, false); assert.strictEqual(seen.length, 1);
});

test('logs never contain addresses, filenames, comments, keys or the API key', async () => {
    configure(); seen.length = 0;
    const cap = captureLogs();
    try {
        mode = 'ok';
        notify.notifyResearcherDecision({ submission_id: 'sub-L', decision: 'DISCARDED', researcher_email: 'secret.person@example.test', file_name: 'Secret_Project.pdf', discard_reason: 'Duplicate', discard_note: 'confidential note' });
        notify.notifySubmissionReceived({ submissionId: 'sub-L', researcherName: 'Secret Person', fileType: 'DATA' });
        await settle(300);
        mode = '500';
        await notify.sendEmail({ event: 't', to: 'secret.person@example.test', subject: 'Secret_Project.pdf', idempotencyKey: 'idem-secret' });
    } finally { cap.restore(); }
    const all = cap.lines.join('\n');
    assert.ok(cap.lines.length >= 3);
    for (const s of ['@', 'Secret', '.pdf', 'confidential', 'idem-secret', 'test-key-not-real', 'sub-L']) assert.ok(!all.includes(s), 'log contains ' + s);
    assert.ok(cap.lines.every(l => l.startsWith('[NOTIFY] event=')));
});

test('meeting date is the stored calendar date regardless of server time zone', () => {
    const local = new Date(2027, 4, 3); // how node-postgres returns DATE 2027-05-03
    assert.strictEqual(notify.dateOnly(local), '2027-05-03');
    assert.strictEqual(notify.dateOnly('2027-05-03'), '2027-05-03');
    const [m] = notify.buildMeetingMessages({ meeting_date: local, meeting_time: '10:00:00', location_text: 'R' }, [{ name: 'A', email: 'a@example.test', slot_type: 'DATA_FLASH' }]);
    assert.ok(m.text.includes('Monday') && m.text.includes('3 May 2027'), m.text.split('\n')[3]);
});

test('decision e-mails never contain the filename; they name document type and submission date', async () => {
    configure(); mode = 'ok'; seen.length = 0;
    for (const decision of ['APPROVED', 'REVISION_NEEDED', 'DISCARDED']) {
        notify.notifyResearcherDecision({ submission_id: 'sub-F-' + decision, decision, researcher_email: 'r@example.test', file_name: '2026-11-06_AB_SecretProject_Assay.pdf', verification_code: 'NATLAB-x', pi_comments: 'c', discard_reason: 'Duplicate' },
            async () => ({ fileType: 'DATA', submittedAt: new Date(2026, 10, 5, 14, 30) }));
    }
    await settle(300);
    assert.strictEqual(seen.length, 3);
    for (const s of seen) {
        const all = JSON.stringify(s.body);
        assert.ok(!all.includes('SecretProject') && !all.includes('.pdf'), 'filename leaked: ' + s.body.subject);
        assert.ok(s.body.subject.includes('Data submitted on 2026-11-05'), s.body.subject);
        assert.strictEqual(s.body.attachments, undefined);
    }
});

test('decision e-mail still sent (generic wording) when the type/date lookup fails', async () => {
    configure(); mode = 'ok'; seen.length = 0;
    notify.notifyResearcherDecision({ submission_id: 'sub-G', decision: 'APPROVED', researcher_email: 'r@example.test', file_name: 'x.pdf' },
        async () => { throw new Error('db down'); });
    await settle(300);
    assert.strictEqual(seen.length, 1);
    assert.strictEqual(seen[0].body.subject, 'GLP Submission Approved: Document');
});
