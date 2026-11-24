// Group Meetings R3.3 — session UI (pure rendering; no DOM, no network).
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const gm = require('../public/js/group-meetings.js');

const SID = 'aaaaaaaa-0000-4000-8000-000000000001';
const doc = (over) => ({ submission_id: SID, title: 'x.pdf', file_type: 'DATA', status: 'APPROVED', submitted_at: '2026-11-20T10:00:00Z', legacy: false, can_open: true, meeting_status: null, ...over });
const controls = (html) => html.match(/<(button|a|input|select|textarea|form)\b[^>]*>/g) || [];
const ADMIN_WORDS = /approve|discard|archive|delete|reject|upload/i;

// ------------------------------------------------------------ document rows
test('without session options the document rows are exactly R2 (View only)', () => {
    const a = gm.renderDocumentRows([doc()]);
    const b = gm.renderDocumentRows([doc()], null);
    assert.strictEqual(a, b);
    assert.strictEqual(controls(a).length, 1);
    assert.doesNotMatch(a, /data-gm-mark|gm-activity/);
});

test('meeting activity is read-only text (meeting date, presenter), never a control or a time', () => {
    const html = gm.renderDocumentRows([doc({ can_open: false, meeting_status: { presented_in_session: true, discussed_in_session: true, last_presented_on: '2026-11-24T10:54:00Z', last_presenter_name: 'Ana <b>' } })]);
    assert.strictEqual(controls(html).length, 0);
    assert.match(html, /Presented \d{1,2} [A-Z][a-z]+ by Ana &lt;b&gt;/);
    assert.match(html, /Discussed in this meeting/);
    assert.doesNotMatch(html.replace(/<[^>]+>/g, ''), /\d{1,2}:\d{2}/, 'no presentation time');
});

test('PI attached: one Presented + one Discussed control per row; recorded = pressed; pending = disabled', () => {
    const marks = { [SID]: { PRESENTED: { id: 'e1', presenter_name: 'Bo' } } };
    const html = gm.renderDocumentRows([doc()], { canMark: true, marks, pending: { [SID + ':DISCUSSED']: true } });
    assert.match(html, /data-gm-mark="PRESENTED" data-sid="[^"]+" aria-pressed="true"/);
    assert.match(html, /data-gm-mark="DISCUSSED" data-sid="[^"]+" aria-pressed="false" disabled/);
    assert.strictEqual((html.match(/data-gm-mark=/g) || []).length, 2);
    // no time fields, no administration controls
    assert.doesNotMatch(html, /type="(time|datetime-local)"|duration/i);
    assert.ok(controls(html).every(c => !ADMIN_WORDS.test(c)));
    const labels = (html.match(/<button\b[^>]*>[\s\S]*?<\/button>/g) || []).map(b => b.replace(/<[^>]+>/g, '').trim());
    assert.deepStrictEqual(labels, ['&#10003; Presented', 'Discussed', 'View']);
});

// ------------------------------------------------------------ session controls
const active = { id: 'o1', origin: 'SCHEDULED', started_at: '2026-11-24T08:00:00Z', stale: false, reopened: false, attendance: { present: 4, absent: 1, unmarked: 8, total: 13 } };
const actions = (html) => (html.match(/data-gm-action="([a-z-]+)"/g) || []).map(s => s.slice(16, -1));

test('PI without a meeting: Start meeting + History', () => {
    assert.deepStrictEqual(actions(gm.renderSessionControls({ role: 'pi', active: null })), ['start-meeting', 'history']);
});

test('PI attached to the active meeting: Attendance, Notes, End meeting, History + indicator with present/total', () => {
    const html = gm.renderSessionControls({ role: 'pi', active, attached: true, now: new Date('2026-11-24T09:00:00Z') });
    assert.deepStrictEqual(actions(html), ['attendance', 'notes', 'end-meeting', 'history']);
    assert.match(html, /In progress/);
    assert.match(html, />4\/13<\/span>/);
});

test('PI in another window / after logout: Resume, End, Abandon (never automatic)', () => {
    assert.deepStrictEqual(actions(gm.renderSessionControls({ role: 'pi', active, attached: false })), ['resume-meeting', 'end-meeting', 'abandon-meeting', 'history']);
    // a reopened meeting cannot be abandoned
    const re = gm.renderSessionControls({ role: 'pi', active: { ...active, reopened: true }, attached: false });
    assert.ok(!actions(re).includes('abandon-meeting'));
    assert.match(re, /Reopened/);
});

test('>12 h: warning style and explanation, still no automatic action', () => {
    const html = gm.renderSessionControls({ role: 'pi', active: { ...active, stale: true }, attached: true, now: new Date('2026-11-24T21:30:00Z') });
    assert.match(html, /gm-live-stale/);
    assert.match(html, /more than 12 hours/);
    assert.match(html, /13 h 30 min ago/);
});

test('members: read-only indicator + History only; never attendance, even if present in data', () => {
    const html = gm.renderSessionControls({ role: 'member', active, attached: true });
    assert.deepStrictEqual(actions(html), ['history']);
    assert.match(html, /In progress/);
    assert.doesNotMatch(html, /present|absent|unmarked|4\/13/i);
    assert.deepStrictEqual(actions(gm.renderSessionControls({ role: 'member', active: null })), ['history']);
});

// ------------------------------------------------------------ attendance
test('attendance rows: three states, escaped names, Added marker', () => {
    const html = gm.renderAttendanceRows([
        { researcher_id: 'L1', display_name: '<i>Ana</i>', affiliation: 'LiU', source: 'ROSTER', status: 'PRESENT' },
        { researcher_id: 'U1', display_name: 'Uxue', affiliation: 'UNAV', source: 'ADDED', status: 'UNMARKED' },
    ]);
    assert.ok(!html.includes('<i>'));
    assert.strictEqual((html.match(/data-gm-do="att-set"/g) || []).length, 6);
    assert.match(html, /data-rid="L1" data-st="PRESENT" aria-checked="true"/);
    assert.match(html, /data-rid="U1" data-st="UNMARKED" aria-checked="true"/);
    assert.match(html, />Added</);
});

// ------------------------------------------------------------ history
const detail = {
    meeting: { id: 'o1', date: '2026-11-24T08:00:00Z', duration_minutes: 75, origin: 'ADHOC' },
    presentations: [{ type: 'PRESENTED', presenter_name: 'Bo', owner_name: 'Ana', document: { submission_id: SID, title: 'slides.pdf', file_type: 'PRESENTATION', can_open: true } },
                    { type: 'PRESENTED', presenter_name: 'Cy', owner_name: null, document: null }],
    discussions: [{ type: 'DISCUSSED', presenter_name: null, owner_name: 'Ana', document: { submission_id: SID, title: 'data.pdf', file_type: 'DATA', can_open: false } }],
    shared_conclusions: 'Shared <script>',
};

test('history list: date, duration, counts, unscheduled marker', () => {
    const html = gm.renderHistoryList([{ id: 'o1', date: '2026-11-24T08:00:00Z', duration_minutes: 75, origin: 'ADHOC', presented: 2, discussed: 1 }]);
    assert.match(html, /1 h 15 min/);
    assert.match(html, /2 presented · 1 discussed/);
    assert.match(html, /Unscheduled/);
    assert.match(gm.renderHistoryList([]), /No completed meetings/);
});

test('member history detail: presenters, discussed, shared conclusions; View only when can_open; no PI content', () => {
    const html = gm.renderHistoryDetail(detail, false, {});
    assert.match(html, /Presented by Bo · owner Ana/);
    assert.match(html, /Document no longer available/);
    assert.match(html, /Shared &lt;script&gt;/);
    assert.match(html, /Visible to group members/);
    assert.strictEqual((html.match(/data-gm-do="hist-view"/g) || []).length, 1, 'only the openable document');
    assert.doesNotMatch(html, /Private|PI only|Attendance|Correction history|data-gm-do="hist-rec-edit"/);
    // even if private fields were (wrongly) present, a member render never shows them
    const leaky = { ...detail, private_notes: 'SECRET', attendance: [{ display_name: 'Ana', status: 'PRESENT' }], correction_log: [{ what: 'reopen' }],
        presentations: [{ ...detail.presentations[0], event_id: 'e1', comment: 'SECRET-COMMENT', voided: false }] };
    assert.doesNotMatch(gm.renderHistoryDetail(leaky, false, {}), /SECRET|Attendance|Correction history|Correct</);
});

test('PI history detail: private notes, comments, invalidated records, attendance, correction history, correction actions', () => {
    const pi = { ...detail, private_notes: 'Private <note>', attendance: [{ researcher_id: 'L1', display_name: 'Ana', status: 'PRESENT' }, { researcher_id: 'L2', display_name: 'Bo', status: 'UNMARKED' }],
        correction_log: [{ at: '2026-11-24T10:00:00Z', by: 'PI', what: 'attendance', target: 'L2', from: 'UNMARKED', to: 'ABSENT' }, { at: '2026-11-24T10:05:00Z', by: 'PI', what: 'presentation_void', target: 'e2', reason: 'wrong doc' }],
        presentations: [{ ...detail.presentations[0], event_id: 'e1', comment: 'Good data', voided: false }, { ...detail.presentations[1], event_id: 'e2', voided: true, void_reason: 'wrong doc' }] };
    const html = gm.renderHistoryDetail(pi, true, { L2: 'Bo', PI: 'PI' });
    assert.match(html, /Private &lt;note&gt;/);
    assert.match(html, /Good data/);
    assert.match(html, /gm-voided/);
    assert.match(html, /Invalidated<\/span> wrong doc/);
    assert.match(html, /1 present · 0 absent · 1 unmarked/);
    assert.match(html, /Attendance of Bo: Unmarked → Absent/);
    assert.strictEqual((html.match(/data-gm-do="hist-rec-edit"/g) || []).length, 1, 'no correction on an invalidated record');
});

test('correction-log descriptions never expose raw ids for unknown people', () => {
    assert.strictEqual(gm.describeLogEntry({ what: 'presenter', from: 'X9', to: 'Y7' }, {}), 'Presenter changed: participant → participant');
    assert.match(gm.describeLogEntry({ what: 'private_notes' }, {}), /Private notes edited/);
    assert.match(gm.describeLogEntry({ what: 'times', from: { started_at: '2026-11-24T08:00:00Z', ended_at: '2026-11-24T09:00:00Z' }, to: { started_at: '2026-11-24T07:30:00Z', ended_at: '2026-11-24T09:00:00Z' }, reason: 'late' }, {}), /Start\/end corrected.*\(late\)/);
});

test('durations', () => {
    assert.strictEqual(gm.fmtDuration(0), '0 min');
    assert.strictEqual(gm.fmtDuration(45), '45 min');
    assert.strictEqual(gm.fmtDuration(60), '1 h');
    assert.strictEqual(gm.fmtDuration(65), '1 h 05 min');
    assert.strictEqual(gm.fmtDuration(null), '');
});

// ------------------------------------------------------------ static guards
test('R3 UI requests only when /me reports sessions; component still has no timers or polling', () => {
    const js = fs.readFileSync(path.join(__dirname, '..', 'public', 'js', 'group-meetings.js'), 'utf8');
    assert.match(js, /if \(sessionsOn\(\)\) reqs\.push\(loadSession\(code\)\);/);
    assert.match(js, /function sessionsOn\(\) \{ return !!\(me && me\.sessions\); \}/);
    assert.doesNotMatch(js, /setInterval|setTimeout|EventSource|WebSocket/);
    // every session/history request path is reached only through sessionsOn()-gated code
    assert.match(js, /if \(sessionsOn\(\)\) switch \(el\.getAttribute\('data-gm-action'\)\)/);
    // destructive session actions require an explicit confirmation flag
    assert.match(js, /\/end', \{ method: 'POST', body: \{ confirm: true/);
    assert.match(js, /\/abandon', \{ method: 'POST', body: \{ confirm: true/);
    assert.match(js, /\/reopen', \{ method: 'POST', body: \{ confirm: true/);
});

test('new toolbar layout rules are scoped to sessions-on (R2.2 CSS unchanged when off)', () => {
    const css = fs.readFileSync(path.join(__dirname, '..', 'public', 'css', 'group-meetings.css'), 'utf8');
    const r3 = css.slice(css.indexOf('R3.3 — meeting sessions'));
    for (const rule of r3.match(/[^{}]*\.gm-toolbar[^{}]*\{/g) || []) assert.match(rule, /\.gm-has-session/, rule.trim());
});
