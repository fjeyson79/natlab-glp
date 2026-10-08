const test = require('node:test');
const assert = require('node:assert');
const {
    normalizeEmail,
    isEmailAllowedForAffiliation,
    affiliationDomainError,
} = require('../server/institution_email');

test('LiU accepts @liu.se addresses', () => {
    assert.ok(isEmailAllowedForAffiliation('frank.hernandez@liu.se', 'LiU'));
});

test('LiU accepts @student.liu.se addresses', () => {
    assert.ok(isEmailAllowedForAffiliation('mathe078@student.liu.se', 'LiU'));
});

test('LiU matching is case-insensitive and ignores surrounding whitespace', () => {
    assert.ok(isEmailAllowedForAffiliation('  MATHE078@Student.LIU.SE ', 'LiU'));
    assert.ok(isEmailAllowedForAffiliation('Frank.Hernandez@LIU.SE', 'LiU'));
});

test('LiU rejects lookalike and non-LiU domains', () => {
    const bad = [
        'user@notliu.se',
        'user@fakeliu.se',
        'user@liu.se.evil.com',
        'user@evil-liu.se',
        'user@liu.se.com',
        'user@student.liu.se.example.org',
        'user@xstudent.liu.se',
        'user@other.liu.se',
        'user@liu.com',
        'user@gmail.com',
        'user@unav.es',
        'liu.se@gmail.com',
        'user@liu.se@gmail.com',
        '@liu.se',
        'liu.se',
        '',
        null,
        undefined,
    ];
    for (const email of bad) {
        assert.strictEqual(isEmailAllowedForAffiliation(email, 'LiU'), false, `expected reject: ${email}`);
    }
});

test('UNAV rules are preserved', () => {
    assert.ok(isEmailAllowedForAffiliation('fjhernandezh@unav.es', 'UNAV'));
    assert.ok(isEmailAllowedForAffiliation('someone@alumni.unav.es', 'UNAV'));
    assert.strictEqual(isEmailAllowedForAffiliation('someone@notunav.es', 'UNAV'), false);
    assert.strictEqual(isEmailAllowedForAffiliation('someone@unav.es.evil.com', 'UNAV'), false);
    assert.strictEqual(isEmailAllowedForAffiliation('someone@student.liu.se', 'UNAV'), false);
});

test('EXTERNAL has no domain restriction', () => {
    assert.ok(isEmailAllowedForAffiliation('someone@gmail.com', 'EXTERNAL'));
    assert.ok(isEmailAllowedForAffiliation('someone@liu.se', 'EXTERNAL'));
});

test('existing seeded LiU accounts remain valid', () => {
    const seeded = [
        'frank.hernandez@liu.se',
        'baris.ata.borsa@liu.se',
        'march354@student.liu.se',
        'matla239@student.liu.se',
        'penku788@student.liu.se',
    ];
    for (const email of seeded) {
        assert.ok(isEmailAllowedForAffiliation(email, 'LiU'), email);
    }
});

test('normalizeEmail trims and lowercases', () => {
    assert.strictEqual(normalizeEmail('  A.B@Student.LiU.se '), 'a.b@student.liu.se');
});

test('error messages list exact permitted domains', () => {
    assert.strictEqual(affiliationDomainError('LiU'), 'LiU affiliation requires @liu.se or @student.liu.se email');
    assert.strictEqual(affiliationDomainError('UNAV'), 'UNAV affiliation requires @unav.es or @alumni.unav.es email');
});
