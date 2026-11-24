const test = require('node:test');
const assert = require('node:assert');
const p = require('../server/meetings/policy');

const acct = (id, role, active = true) => ({ researcher_id: id, role, active });

// ------------------------------------------------------------------ actors
test('actor: no session is 401', () => {
    assert.strictEqual(p.classifyActor(null, null).status, 401);
    assert.strictEqual(p.classifyActor({}, null).status, 401);
});

test('actor: PI requires PI in BOTH session and current allowlist', () => {
    assert.strictEqual(p.classifyActor({ researcher_id: 'PI1', role: 'pi' }, acct('PI1', 'pi')).actor.isPi, true);
    // session says pi, allowlist demoted -> treated as researcher, not PI
    const demoted = p.classifyActor({ researcher_id: 'PI1', role: 'pi' }, acct('PI1', 'researcher'));
    assert.strictEqual(demoted.ok, true);
    assert.strictEqual(demoted.actor.isPi, false);
    // allowlist says pi but session does not -> not PI
    assert.strictEqual(p.classifyActor({ researcher_id: 'PI1', role: 'researcher' }, acct('PI1', 'pi')).ok, false);
});

test('actor: ai_bot never gets access (session or allowlist)', () => {
    assert.strictEqual(p.classifyActor({ researcher_id: 'B', role: 'ai_bot' }, acct('B', 'ai_bot')).reason, 'ai_bot_not_permitted');
    assert.strictEqual(p.classifyActor({ researcher_id: 'B', role: 'researcher' }, acct('B', 'ai_bot')).reason, 'ai_bot_not_permitted');
    assert.strictEqual(p.classifyActor({ researcher_id: 'B', role: 'ai_bot' }, acct('B', 'researcher')).reason, 'ai_bot_not_permitted');
});

test('actor: inactive accounts and unknown accounts are rejected', () => {
    assert.strictEqual(p.classifyActor({ researcher_id: 'R1', role: 'researcher' }, acct('R1', 'researcher', false)).reason, 'inactive_account');
    assert.strictEqual(p.classifyActor({ researcher_id: 'R1', role: 'researcher' }, null).reason, 'unknown_account');
    // account row for a different id (e.g. impersonation mix-up) is rejected
    assert.strictEqual(p.classifyActor({ researcher_id: 'R1', role: 'researcher' }, acct('R2', 'researcher')).reason, 'unknown_account');
});

test('actor: researcher and supervisor are ordinary members; other roles rejected', () => {
    assert.deepStrictEqual(p.classifyActor({ researcher_id: 'S', role: 'supervisor' }, acct('S', 'supervisor')).actor, { id: 'S', isPi: false, role: 'supervisor' });
    assert.strictEqual(p.classifyActor({ researcher_id: 'I', role: 'investor' }, acct('I', 'investor')).reason, 'role_not_permitted');
});

test('membership eligibility: active researcher/supervisor only', () => {
    assert.strictEqual(p.isMembershipEligibleAccount(acct('a', 'researcher')), true);
    assert.strictEqual(p.isMembershipEligibleAccount(acct('a', 'supervisor')), true);
    assert.strictEqual(p.isMembershipEligibleAccount(acct('a', 'researcher', false)), false);
    for (const r of ['pi', 'ai_bot', 'investor']) assert.strictEqual(p.isMembershipEligibleAccount(acct('a', r)), false);
});

// --------------------------------------------------------------- documents
const R1 = { id: 'R1', isPi: false };
const PI = { id: 'PI', isPi: true };
const ctx = { ownerIsMember: true, actorCanAccessGroup: true };
const doc = (over) => ({ researcher_id: 'R2', file_type: 'DATA', status: 'APPROVED', in_natlab_workspace: true, ...over });

test('eligibility: SOP, DATA, PRESENTATION (and PRES shorthand) only', () => {
    for (const t of ['SOP', 'DATA', 'PRESENTATION', 'PRES', 'data']) assert.strictEqual(p.isEligibleFileType(t), true, t);
    for (const t of ['REPORT', 'DOCS', 'INVENTORY', 'PAPER', '', null]) assert.strictEqual(p.isEligibleFileType(t), false, String(t));
    for (const t of ['REPORT', 'DOCS', 'INVENTORY']) {
        assert.strictEqual(p.isListableDocument(doc({ file_type: t }), ctx), false, t);
        assert.strictEqual(p.canOpenDocument(PI, doc({ file_type: t }), ctx), false, t);
    }
    assert.strictEqual(p.displayFileType('PRES'), 'PRESENTATION');
});

test('listing: APPROVED, PENDING, SUBMITTED, REVISION_NEEDED (and missing = PENDING) are listed for all members', () => {
    for (const s of ['APPROVED', 'PENDING', 'SUBMITTED', 'REVISION_NEEDED', null, 'pending']) {
        assert.strictEqual(p.isListableDocument(doc({ status: s }), ctx), true, String(s));
    }
});

test('listing excludes discarded, archived and any other status', () => {
    for (const s of ['DISCARDED', 'ARCHIVED', 'REVISION', 'DELETED']) assert.strictEqual(p.isListableDocument(doc({ status: s }), ctx), false, s);
});

test('opening: owner and PI only, regardless of approval status', () => {
    for (const s of ['APPROVED', 'PENDING', 'SUBMITTED', 'REVISION_NEEDED']) {
        assert.strictEqual(p.canOpenDocument(R1, doc({ status: s }), ctx), false, `co-member ${s}`);
        assert.strictEqual(p.canOpenDocument(PI, doc({ status: s }), ctx), true, `pi ${s}`);
        assert.strictEqual(p.canOpenDocument(R1, doc({ status: s, researcher_id: 'R1' }), ctx), true, `owner ${s}`);
    }
    // approval never grants other members the right to open
    assert.strictEqual(p.canOpenDocument(R1, doc({ status: 'APPROVED' }), ctx), false);
    // excluded documents cannot be opened even by the PI or the owner here
    assert.strictEqual(p.canOpenDocument(PI, doc({ status: 'DISCARDED' }), ctx), false);
    assert.strictEqual(p.canOpenDocument(R1, doc({ status: 'ARCHIVED', researcher_id: 'R1' }), ctx), false);
    assert.strictEqual(p.isOwnerOrPi(null, 'R1'), false);
});

test('non-member owner, non-member actor and non-NAT-Lab workspace are excluded', () => {
    assert.strictEqual(p.isListableDocument(doc(), { ownerIsMember: false, actorCanAccessGroup: true }), false);
    assert.strictEqual(p.isListableDocument(doc(), { ownerIsMember: true, actorCanAccessGroup: false }), false);
    assert.strictEqual(p.isListableDocument(doc({ in_natlab_workspace: false }), ctx), false);
    assert.strictEqual(p.canOpenDocument(PI, doc({ in_natlab_workspace: false }), ctx), false);
});

test('legacy imports: submitted pack items listed, unsubmitted drafts never', () => {
    const legacyApproved = doc({ record_origin: 'legacy_pre2026', legacy_pack_id: 'pk', status: 'APPROVED' });
    assert.strictEqual(p.isListableDocument(legacyApproved, ctx), true);
    const draft = doc({ record_origin: 'legacy_pre2026', legacy_pack_id: null, status: 'SUBMITTED', researcher_id: 'R1' });
    assert.strictEqual(p.isListableDocument(draft, ctx), false);
    assert.strictEqual(p.canOpenDocument(R1, draft, ctx), false);
    assert.strictEqual(p.canOpenDocument(PI, draft, ctx), false);
});

// ------------------------------------------------------------- windows
test('new window: last completed meeting, else 7-day labelled fallback', () => {
    const now = new Date('2026-11-24T12:00:00Z');
    const w1 = p.newSubmissionWindow(null, now);
    assert.strictEqual(w1.fallback, true);
    assert.strictEqual(w1.basis, 'previous_7_days');
    assert.strictEqual(w1.since.toISOString(), '2026-11-17T12:00:00.000Z');
    const w2 = p.newSubmissionWindow('2026-10-01T09:00:00Z', now);
    assert.strictEqual(w2.fallback, false);
    assert.strictEqual(w2.since.toISOString(), '2026-10-01T09:00:00.000Z'); // weeks without meetings stay in the window
});

test('filters: week, since_last, all; anything else rejected', () => {
    assert.strictEqual(p.normalizeFilter(undefined), 'all');
    assert.strictEqual(p.normalizeFilter('WEEK'), 'week');
    assert.strictEqual(p.normalizeFilter('since_last'), 'since_last');
    assert.strictEqual(p.normalizeFilter('month'), null);
});

// ---------------------------------------------------------------- zoom
test('zoom URL: accepts https zoom.us / zoom.com meeting links', () => {
    for (const u of [
        'https://zoom.us/j/1234567890',
        'https://liu-se.zoom.us/j/1234567890?pwd=abcDEF123',
        'https://us02web.zoom.us/j/1234567890',
        'https://unav.zoom.us/my/natlab',
        'https://zoom.com/j/1234567890',
    ]) assert.strictEqual(p.validateZoomJoinUrl(u).ok, true, u);
});

test('zoom URL: rejects arbitrary or unsafe URLs', () => {
    const cases = {
        'http://zoom.us/j/123': 'https_required',
        'https://evil.com/j/123': 'host_not_approved',
        'https://zoom.us.evil.com/j/123': 'host_not_approved',
        'https://evilzoom.us/j/123': 'host_not_approved',
        'https://user:pw@zoom.us/j/123': 'credentials_not_allowed',
        'https://zoom.us:8443/j/123': 'port_not_allowed',
        'https://zoom.us/j/123#x': 'fragment_not_allowed',
        'https://zoom.us/signin': 'path_not_a_meeting_link',
        'https://zoom.us/j/123/../../profile': 'path_not_a_meeting_link',
        'javascript:alert(1)': 'https_required',
        'https://zoom.us/j/1 23': 'invalid_characters',
        'not a url': 'invalid_characters',
    };
    for (const [u, reason] of Object.entries(cases)) {
        const r = p.validateZoomJoinUrl(u);
        assert.strictEqual(r.ok, false, u);
        assert.strictEqual(r.reason, reason, u);
    }
    assert.strictEqual(p.validateZoomJoinUrl(123).ok, false);
    assert.strictEqual(p.validateZoomJoinUrl('https://zoom.us/j/' + '1'.repeat(600)).reason, 'too_long');
});

test('zoom URL: null or empty removes the link', () => {
    assert.deepStrictEqual(p.validateZoomJoinUrl(null), { ok: true, value: null });
    assert.deepStrictEqual(p.validateZoomJoinUrl('  '), { ok: true, value: null });
});

// --------------------------------------------------------- occurrences
test('occurrence actions: allowed transitions only; start/end reserved for R3', () => {
    assert.deepStrictEqual(p.planOccurrenceAction('SCHEDULED', 'cancel'), { ok: true, to: 'CANCELLED', event: 'meeting.cancelled' });
    assert.strictEqual(p.planOccurrenceAction('POSTPONED', 'reschedule').to, 'SCHEDULED');
    assert.strictEqual(p.planOccurrenceAction('CANCELLED', 'reschedule').ok, false);
    assert.strictEqual(p.planOccurrenceAction('COMPLETED', 'cancel').ok, false);
    assert.strictEqual(p.planOccurrenceAction('SCHEDULED', 'complete').reason, 'unknown_action');
});

test('input parsing: codes, ids, dates, durations', () => {
    assert.strictEqual(p.normalizeGroupCode('liu'), 'LIU');
    assert.strictEqual(p.normalizeGroupCode('OTHER'), null);
    assert.strictEqual(p.isValidResearcherId("R1'; DROP"), false);
    assert.strictEqual(p.parseScheduledStart('2026-12-03T09:00:00+01:00').toISOString(), '2026-12-03T08:00:00.000Z');
    assert.strictEqual(p.parseScheduledStart('2026-12-03 09:00'), null); // no offset -> ambiguous
    assert.strictEqual(p.parseDuration(3).ok, false);
    assert.strictEqual(p.parseDuration(60).value, 60);
});
