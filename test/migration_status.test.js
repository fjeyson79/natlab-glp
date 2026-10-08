const test = require('node:test');
const assert = require('node:assert');
const { assessMigrationState } = require('../server/migration_status');

test('no state row is not ok', () => {
    assert.strictEqual(assessMigrationState(undefined).ok, false);
});

test('success with no later error is ok', () => {
    const s = assessMigrationState({ last_success_at: '2026-10-08T10:00:00Z', last_error_at: null });
    assert.strictEqual(s.ok, true);
});

test('error after last success is not ok (production state since May 2026)', () => {
    const s = assessMigrationState({
        last_success_at: '2026-05-16T09:17:26Z',
        last_error_at: '2026-06-23T20:42:57Z',
        last_error_text: 'check constraint "di_submissions_file_type_check" of relation "di_submissions" is violated by some row',
    });
    assert.strictEqual(s.ok, false);
    assert.match(s.reason, /di_submissions_file_type_check/);
});

test('success after an older error is ok', () => {
    const s = assessMigrationState({ last_success_at: '2026-10-09T10:00:00Z', last_error_at: '2026-06-23T20:42:57Z' });
    assert.strictEqual(s.ok, true);
});

test('never succeeded is not ok', () => {
    assert.strictEqual(assessMigrationState({ last_success_at: null, last_error_at: null }).ok, false);
});
