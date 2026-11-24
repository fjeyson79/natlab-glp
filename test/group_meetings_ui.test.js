// Group Meetings R2 — UI component (pure rendering) and portal integration.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const vm = require('vm');
const gm = require('../public/js/group-meetings.js');

const pub = (f) => fs.readFileSync(path.join(__dirname, '..', 'public', f), 'utf8');
const doc = (over) => ({ submission_id: 'aaaaaaaa-0000-4000-8000-000000000001', title: 'x.pdf', file_type: 'DATA', status: 'APPROVED', submitted_at: '2026-11-20T10:00:00Z', legacy: false, meeting_status: null, ...over });

// ----------------------------------------------------- document panel
test('View option rendered ONLY when the server says can_open === true', () => {
    assert.match(gm.renderDocumentRows([doc({ can_open: true })]), /data-gm-view=/);
    for (const v of [false, undefined, null, 'true', 1]) {
        assert.doesNotMatch(gm.renderDocumentRows([doc({ can_open: v })]), /data-gm-view=|>View</, String(v));
    }
});

test('document rows show no administration controls', () => {
    const html = gm.renderDocumentRows([doc({ can_open: true }), doc({ status: 'PENDING', can_open: false })]);
    // the only interactive control is the View button
    const controls = html.match(/<(button|a|input|select|form)\b[^>]*>/g) || [];
    assert.strictEqual(controls.length, 1);
    assert.match(controls[0], /^<button [^>]*data-gm-view=/);
    assert.doesNotMatch(html, /data-gm-(?!view)[a-z-]+=/, 'no other actions');
    // status is displayed as metadata only
    assert.match(html, /gm-status-APPROVED[^>]*>Approved</);
    assert.match(html, /gm-status-PENDING[^>]*>Pending</);
});

test('all rendered text is escaped', () => {
    const evil = '<img src=x onerror=alert(1)>"\'`';
    const d = gm.renderDocumentRows([doc({ title: evil, can_open: true, submission_id: '"><script>' })]);
    assert.ok(!d.includes('<img') && !d.includes('<script>'));
    const o = gm.renderOverviewRows([{ researcher_id: '"x', name: evil, last_upload: null, last_presented: null, new_count: 0, total_count: 0 }], null);
    assert.ok(!o.includes('<img'));
});

test('two-line document rows: type tile, title, "TYPE · date · status"; LEGACY marker; no R3 placeholder column', () => {
    const html = gm.renderDocumentRows([doc({ file_type: 'PRESENTATION', legacy: true })]);
    assert.match(html, /gm-ficon gm-ficon-PRESENTATION" aria-hidden="true">PRES</);
    assert.match(html, /class="gm-doc-title" title="x\.pdf">x\.pdf</);
    assert.match(html, /class="gm-doc-sub">PRES · <span title="[^"]+">[^<]+<\/span> · <span class="gm-status gm-status-APPROVED">Approved</);
    assert.match(html, /LEGACY/);
    assert.doesNotMatch(html, /gm-col-meeting/, 'no non-functional R3 column');
});

test('dates: short within the current year, with year otherwise', () => {
    const y = new Date().getFullYear();
    assert.doesNotMatch(gm.fmtDate(`${y}-03-05T12:00:00Z`), /\d{4}/);
    assert.match(gm.fmtDate('2019-03-05T12:00:00Z'), /2019/);
});

test('Load more row: shown only while more pages exist', () => {
    assert.strictEqual(gm.renderMoreRow(100, 100, false), '');
    assert.match(gm.renderMoreRow(100, 260, true), /data-gm-action="more"[^>]*>Load more · 100 of 260 shown</);
    assert.strictEqual(gm.PAGE_SIZE, 100);
});

test('empty states', () => {
    assert.match(gm.renderDocumentRows([]), /No documents in this period/);
    assert.match(gm.renderOverviewRows([], null), /No researchers/);
});

// --------------------------------------------------------- overview panel
test('overview rows: neutral dash for missing dates, selection, YOU marker, New badge', () => {
    const rows = [
        { researcher_id: 'A', name: 'Anna', is_self: true, last_upload: '2026-11-20T10:00:00Z', last_presented: null, new_count: 2, total_count: 14 },
        { researcher_id: 'B', name: 'Bo', is_self: false, last_upload: null, last_presented: null, new_count: 0, total_count: 0 },
    ];
    const html = gm.renderOverviewRows(rows, 'B');
    assert.strictEqual((html.match(/<tr /g) || []).length, 2, 'researchers with no submissions stay visible');
    assert.match(html, /data-rid="B" tabindex="0" aria-selected="true"/);
    assert.match(html, /data-rid="A" tabindex="0" aria-selected="false"/);
    assert.match(html, /YOU/);
    assert.match(html, /class="gm-new">2</);
    assert.strictEqual((html.match(/gm-dash/g) || []).length, 3); // A: last presented; B: last upload + last presented
});

test('labels: since-last fallback is explicit', () => {
    assert.match(gm.windowLabel({ fallback: true, basis: 'previous_7_days', since: '2026-11-17T00:00:00Z' }), /Last 7 days \(no completed meeting yet\)/);
    assert.match(gm.windowLabel({ fallback: false, basis: 'last_completed_meeting', since: '2026-11-05T09:00:00Z' }), /Since last meeting/);
    assert.match(gm.windowLabel({ basis: 'current_calendar_week', since: '2026-11-23T00:00:00Z' }), /This week/);
});

// ------------------------------------------------------------ viewer / zoom
test('viewer uses the existing PDF.js viewer over the meeting-scoped file endpoint', () => {
    const url = gm.fileUrl('LIU', 'aaaaaaaa-0000-4000-8000-000000000001', false);
    assert.strictEqual(url, '/api/group-meetings/groups/LIU/documents/aaaaaaaa-0000-4000-8000-000000000001/file');
    assert.strictEqual(gm.viewerSrc(url), '/pdfjs/web/viewer.html?file=' + encodeURIComponent(url) + '#pagemode=none&zoom=page-width');
    assert.match(gm.fileUrl('LIU', 'id', true), /\?download=1$/);
});

test('Zoom button only links to https Zoom URLs', () => {
    assert.strictEqual(gm.isSafeZoomHref('https://liu-se.zoom.us/j/1?pwd=a'), true);
    for (const u of ['javascript:alert(1)', 'http://zoom.us/j/1', 'https://evil.com/zoom.us/', null]) assert.strictEqual(gm.isSafeZoomHref(u), false, String(u));
});

// ------------------------------------------------------------- layout
test('compact layout: ~38px rows so at least eight researchers fit', () => {
    const css = pub('css/group-meetings.css');
    const row = Number((css.match(/--gm-row:\s*(\d+)px/) || [])[1]);
    assert.ok(row >= 36 && row <= 40, `row height ${row}px`);
    const minH = Number((css.match(/\.gm-root \{[^}]*min-height:\s*(\d+)px/) || [])[1]);
    // toolbar with two-line heading(~58) + gap(10) + panel head(40) + table head(34) + 8 rows must fit the minimum height
    assert.ok(58 + 10 + 40 + 34 + 8 * row <= minH, `min-height ${minH}px fits 8 rows`);
    assert.match(css, /\.gm-table th \{[^}]*position: sticky/);
    assert.match(css, /\.gm-scroll \{[^}]*overflow: auto/);
});

// ------------------------------------------------------- portal wiring
test('PI portal: new tab and legacy toggle both follow the feature flag', () => {
    const html = pub('pi-dashboard.html');
    assert.match(html, /<button class="tab-btn" data-tab="group-meetings" id="gmTabBtn" style="display:none;">Group Meetings<\/button>/);
    assert.match(html, /<div class="tab-content" id="tab-group-meetings">/);
    // legacy toggle preserved for rollback, hidden by default, revealed only when the flag is off
    assert.match(html, /<label class="gd-toggle" id="gdToggleMeetingRow" style="margin-top:10px;display:none;">\s*<input type="checkbox" id="gdToggleMeeting">/);
    assert.match(html, /GroupMeetings\.featureEnabled\(\)/);
    assert.match(html, /if \(on\) \{\s*if \(legacyRow\) legacyRow\.style\.display = 'none';\s*GroupMeetings\.enableTab\('#gmTabBtn'\);\s*\} else if \(legacyRow\) \{\s*legacyRow\.style\.display = '';/);
    assert.match(html, /<div class="tab-content" id="tab-group-meeting">/, 'legacy interface kept for rollback');
    assert.match(html, /<script src="\/js\/group-meetings\.js"><\/script>/);
    assert.match(html, /href="\/css\/group-meetings\.css"/);
    // other top-level tabs are all still present
    for (const t of ['dashboard', 'lab-files', 'group-docs', 'user-mgmt', 'training', 'purchases-inventory', 'backup', 'oligo-id']) {
        assert.match(html, new RegExp(`data-tab="${t}"`), t);
    }
});

test('Researcher portal: main Group Meetings section (hidden until authorized)', () => {
    const html = pub('upload.html');
    assert.match(html, /id="groupMeetingsTabBtn" class="section-btn" data-section="groupMeetings"[^>]*style="display:none;"/);
    assert.match(html, /<div id="section-groupMeetings" class="section-content" style="display:none;">/);
    assert.match(html, /gmSection\.style\.display = section === 'groupMeetings'/);
    assert.match(html, /<script src="\/js\/presentation-mode\.js"><\/script>\s*<script src="\/js\/group-meetings\.js"><\/script>/);
    for (const s of ['files', 'inventory', 'training', 'glpVision', 'supervision']) assert.match(html, new RegExp(`data-section="${s}"`), s);
});

test('GLP Vision: legacy next-meeting announcement follows the flag; everything else intact', () => {
    const html = pub('glp-vision.html');
    assert.match(html, /^\s*gvLoadNextMeeting\(\);/m, 'still called (flag off => unchanged behaviour)');
    assert.match(html, /async function gvLoadNextMeeting\(\) \{\s*try \{[\s\S]{0,300}fetch\('\/api\/group-meetings\/status'[\s\S]{0,120}if \(gm && gm\.ok\) return;/);
    assert.match(html, /await gvLoadFiles\(\);/);
    assert.match(html, /function gvEnterPresentation/);
});

test('inline scripts of the modified portal pages still compile', () => {
    for (const f of ['pi-dashboard.html', 'upload.html', 'glp-vision.html']) {
        const html = pub(f);
        const re = /<script(?![^>]*\bsrc=)[^>]*>([\s\S]*?)<\/script>/gi;
        let m, n = 0;
        while ((m = re.exec(html))) { new vm.Script(m[1], { filename: `${f}#script${++n}` }); }
        assert.ok(n > 0, f);
    }
    new vm.Script(pub('js/group-meetings.js'), { filename: 'group-meetings.js' });
});

test('component contains no polling, timers or external calls', () => {
    const js = pub('js/group-meetings.js');
    assert.doesNotMatch(js, /setInterval|setTimeout|EventSource|WebSocket/);
    const urls = (js.match(/https?:\/\/[^\s'"]+/g) || []).filter(u => !u.includes('…')); // ignore input placeholder text
    assert.deepStrictEqual(urls, [], 'no hard-coded external URLs');
    assert.doesNotMatch(js, /\bfetch\(\s*['"]https?:/);
    assert.doesNotMatch(js, /\/api\/(?!group-meetings)/, 'only the Group Meetings API is used');
});
