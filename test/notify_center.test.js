'use strict';
// Unit tests for server/notifyCenter.js rendering and validation (no database, no network).
const test = require('node:test');
const assert = require('node:assert');
const nc = require('../server/notifyCenter');

test('variables: known ones are accepted, unknown and malformed ones are reported', () => {
    assert.deepStrictEqual(nc.variablesIn('Hi {{first_name}} {{ portal_link }}'), { used: ['first_name', 'portal_link'], unknown: [], malformed: false });
    assert.deepStrictEqual(nc.variablesIn('{{password}}').unknown, ['password']);
    assert.strictEqual(nc.variablesIn('Hi {{first_name}').malformed, true);
    assert.strictEqual(nc.variablesIn('{{ constructor }}').unknown.length, 1);
});

test('rendering: values and text are escaped; only https links become links; no script, no attributes injected', () => {
    const r = nc.renderFor({ name: '<img src=x onerror=alert(1)> Eve', affiliation: 'LiU' },
        'Hello {{first_name}} <b>', 'Dear {{full_name}},\n\n<script>alert(1)</script> see https://glp.hernandezlab.com/di/access.html. and javascript:alert(1) and http://plain.example "q" \' `\n\n{{portal_link}}', {});
    assert.ok(!r.html.includes('<script') && !r.html.includes('<img') && !r.html.includes('onerror=alert(1)>'));
    assert.ok(r.html.includes('&lt;script&gt;'));
    assert.ok(r.html.includes('<a href="https://glp.hernandezlab.com/di/access.html"'), 'https link (trailing dot excluded)');
    assert.ok(!/href="javascript:|href="http:\/\//.test(r.html), 'no javascript: or plain http links');
    assert.strictEqual(r.subject.includes('\n'), false);
    assert.ok(r.text.includes('https://glp.hernandezlab.com/di/access.html'), 'portal link uses the primary domain');
    assert.ok(!r.html.includes('railway.app'));
});

test('rendering: values are single-line (no header injection) and meeting variables come only from the server context', () => {
    const r = nc.renderFor({ name: 'A\r\nBcc: x@evil.example', affiliation: '' }, '{{first_name}}\r\nX', 'Zoom {{zoom_link}} {{meeting_group}}',
        { meetingGroup: { name: 'LiU group', zoom: 'https://liu-se.zoom.us/j/1' } });
    assert.ok(!/[\r\n]/.test(r.subject));
    assert.ok(r.text.includes('https://liu-se.zoom.us/j/1') && r.text.includes('LiU group'));
});

test('categories (N3): submissions, decisions and training are switchable; summaries and Group Meetings stay planned; investor bookings locked; 4 options', () => {
    const keys = nc.CATEGORIES.map(c => c.key);
    assert.strictEqual(new Set(keys).size, keys.length);
    assert.deepStrictEqual(nc.CATEGORIES.filter(c => c.implemented).map(c => c.key), ['submission_sop', 'submission_data', 'submission_presentation', 'submission_report', 'submission_resubmission',
        'decision_approved', 'decision_revision', 'decision_discarded', 'training_initiated', 'training_submitted', 'training_supervisor_accepted', 'training_pi_accepted',
        'training_revision', 'training_rejected', 'training_certified']);
    assert.deepStrictEqual(nc.CATEGORIES.filter(c => !c.implemented).map(c => c.key), ['research_summary', 'supervisor_summary', 'gm_invitation', 'gm_reminder', 'theralia_investor_booking']);
    assert.deepStrictEqual(nc.OPTIONS.map(o => o.key), ['cc_submissions', 'cc_decisions', 'cc_training', 'include_researcher_messages']);
    assert.ok(nc.CATEGORIES.find(c => c.key === 'theralia_investor_booking').locked);
    assert.ok(nc.SYSTEM_TEMPLATES.length >= 7 && nc.SYSTEM_TEMPLATES.every(t => nc.variablesIn(t.subject + t.body).unknown.length === 0));
    assert.strictEqual(nc.MAX_RECIPIENTS, 60);
});
