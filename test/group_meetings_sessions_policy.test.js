// Group Meetings R3.1 — pure session policy.
const test = require('node:test');
const assert = require('node:assert');
const p = require('../server/meetings/policy');
const { isFeatureEnabled } = require('../server/meetings');

test('sessions flag: off by default; sessions need BOTH flags', () => {
    assert.strictEqual(p.isSessionsFlagOn({}), false);
    assert.strictEqual(p.isSessionsFlagOn({ GROUP_MEETINGS_SESSIONS_ENABLED: 'false' }), false);
    assert.strictEqual(p.isSessionsFlagOn({ GROUP_MEETINGS_SESSIONS_ENABLED: 'true' }), true);
    const both = (env) => isFeatureEnabled(env) && p.isSessionsFlagOn(env);
    assert.strictEqual(both({ GROUP_MEETINGS_SESSIONS_ENABLED: 'true' }), false, 'sessions flag alone is not enough');
    assert.strictEqual(both({ GROUP_MEETINGS_ENABLED: 'true' }), false);
    assert.strictEqual(both({ GROUP_MEETINGS_ENABLED: 'true', GROUP_MEETINGS_SESSIONS_ENABLED: 'true' }), true);
});

test('unfinished-session warning: informational, strictly after 12 h', () => {
    const start = new Date('2026-12-01T09:00:00Z');
    assert.strictEqual(p.isStaleSession(start, new Date('2026-12-01T21:00:00Z')), false, 'exactly 12 h');
    assert.strictEqual(p.isStaleSession(start, new Date('2026-12-01T21:00:01Z')), true);
    assert.strictEqual(p.isStaleSession(null, new Date()), false);
});

test('attendance: exactly UNMARKED, PRESENT, ABSENT', () => {
    assert.deepStrictEqual(p.ATTENDANCE_STATUSES, ['UNMARKED', 'PRESENT', 'ABSENT']);
    assert.strictEqual(p.normalizeAttendanceStatus('present'), 'PRESENT');
    assert.strictEqual(p.normalizeAttendanceStatus('unmarked'), 'UNMARKED');
    for (const v of ['EXCUSED', 'late', '', null]) assert.strictEqual(p.normalizeAttendanceStatus(v), null, String(v));
    assert.deepStrictEqual(p.BULK_ATTENDANCE_ACTIONS, ['all_present', 'remaining_absent']);
});

test('reopened detection from the correction log', () => {
    assert.strictEqual(p.isReopenedSession([]), false);
    assert.strictEqual(p.isReopenedSession([{ what: 'reopen' }]), true);
    assert.strictEqual(p.isReopenedSession([{ what: 'reopen' }, { what: 'attendance' }]), true);
    assert.strictEqual(p.isReopenedSession([{ what: 'reopen' }, { what: 'complete' }]), false);
    assert.strictEqual(p.isReopenedSession([{ what: 'reopen' }, { what: 'complete' }, { what: 'reopen' }]), true);
});

test('reopen: only the most recent completed meeting, and only with nothing else in progress', () => {
    const A = { id: 'A', status: 'COMPLETED', started_at: '2026-11-05T08:00:00Z' };
    const B = { id: 'B', status: 'COMPLETED', started_at: '2026-11-12T08:00:00Z' };
    const X = { id: 'X', status: 'CANCELLED', started_at: '2026-11-19T08:00:00Z' }; // abandoned later: does not count
    assert.deepStrictEqual(p.planReopen(B, [A, B, X]), { ok: true });
    assert.strictEqual(p.planReopen(A, [A, B]).reason, 'not_most_recent');
    assert.strictEqual(p.planReopen(B, [A, B, { id: 'C', status: 'IN_PROGRESS', started_at: '2026-11-19T08:00:00Z' }]).reason, 'another_meeting_in_progress');
    assert.strictEqual(p.planReopen({ ...B, status: 'IN_PROGRESS' }, [A, B]).reason, 'not_completed');
    assert.strictEqual(p.planReopen({ ...B, status: 'CANCELLED' }, [A, B]).reason, 'not_completed');
});

test('timestamp correction: reason required, ordered, not future, no overlap', () => {
    const current = { started_at: '2026-11-12T08:00:00Z', ended_at: '2026-11-12T09:30:00Z' };
    const now = new Date('2026-11-24T12:00:00Z');
    const others = [{ id: 'A', status: 'COMPLETED', started_at: '2026-11-05T08:00:00Z', ended_at: '2026-11-05T09:00:00Z' }];
    const v = (o) => p.validateTimeCorrection({ current, now, others, reason: 'Started late', ...o });
    assert.strictEqual(v({ reason: '' }).reason, 'reason_required');
    assert.strictEqual(v({ reason: 'x'.repeat(501) }).reason, 'reason_required');
    assert.strictEqual(v({}).reason, 'nothing_to_correct');
    assert.strictEqual(v({ startedAt: 'yesterday' }).reason, 'invalid_timestamp');
    assert.strictEqual(v({ startedAt: '2026-11-12T10:00:00Z' }).reason, 'start_not_before_end');
    assert.strictEqual(v({ endedAt: '2026-11-30T09:00:00Z' }).reason, 'in_the_future');
    assert.strictEqual(v({ startedAt: '2026-11-05T08:30:00Z' }).reason, 'overlaps_another_meeting');
    const ok = v({ startedAt: '2026-11-12T08:10:00Z' });
    assert.strictEqual(ok.ok, true);
    assert.strictEqual(ok.startedAt.toISOString(), '2026-11-12T08:10:00.000Z');
    assert.strictEqual(ok.endedAt.toISOString(), '2026-11-12T09:30:00.000Z');
    // an IN_PROGRESS meeting without end is treated as open-ended
    assert.strictEqual(p.validateTimeCorrection({ current, now, reason: 'r', startedAt: '2026-11-12T08:10:00Z',
        others: [{ id: 'C', status: 'IN_PROGRESS', started_at: '2026-11-12T09:00:00Z', ended_at: null }] }).reason, 'overlaps_another_meeting');
});

test('optional text: absent / null clears / length limit', () => {
    assert.deepStrictEqual(p.parseOptionalText(undefined), { ok: true, present: false });
    assert.deepStrictEqual(p.parseOptionalText(null), { ok: true, present: true, value: null });
    assert.deepStrictEqual(p.parseOptionalText('  '), { ok: true, present: true, value: null });
    assert.strictEqual(p.parseOptionalText('x'.repeat(p.TEXT_MAX + 1)).ok, false);
    assert.strictEqual(p.parseOptionalText(42).ok, false);
});
