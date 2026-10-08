const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { DI_SUBMISSIONS_FILE_TYPES, DI_SUBMISSIONS_FILE_TYPE_CHECK_SQL } = require('../server/di_submission_types');

const root = path.join(__dirname, '..');
const migrate = fs.readFileSync(path.join(root, 'db/migrate.js'), 'utf8');
const server = fs.readFileSync(path.join(root, 'server.js'), 'utf8');

const EXPECTED = ['SOP', 'DATA', 'INVENTORY', 'PRESENTATION', 'REPORT', 'DOCS', 'PRES'];

function parseList(src) {
    return src.match(/'([A-Z_]+)'/g).map(s => s.slice(1, -1));
}

test('shared module defines the full di_submissions file_type list', () => {
    assert.deepStrictEqual(DI_SUBMISSIONS_FILE_TYPES, EXPECTED);
});

test('shared constraint SQL is a single atomic DROP + ADD with the full list', () => {
    const sql = DI_SUBMISSIONS_FILE_TYPE_CHECK_SQL.replace(/\s+/g, ' ');
    assert.match(sql, /^ALTER TABLE di_submissions DROP CONSTRAINT IF EXISTS di_submissions_file_type_check, ADD CONSTRAINT di_submissions_file_type_check CHECK \(file_type IN \(/);
    assert.deepStrictEqual(parseList(sql.slice(sql.indexOf('CHECK'))), EXPECTED);
});

test('migrate.js uses the shared SQL and has no inline file_type check left', () => {
    assert.match(migrate, /require\('\.\.\/server\/di_submission_types'\)/);
    assert.strictEqual((migrate.match(/^\s*DI_SUBMISSIONS_FILE_TYPE_CHECK_SQL,$/gm) || []).length, 2);
    assert.doesNotMatch(migrate, /di_submissions_file_type_check\s+CHECK/);
    assert.doesNotMatch(migrate, /`ALTER TABLE di_submissions DROP CONSTRAINT IF EXISTS di_submissions_file_type_check`/);
});

test('server.js runtime widener uses the shared SQL and no separate drops', () => {
    assert.match(server, /await pool\.query\(DI_SUBMISSIONS_FILE_TYPE_CHECK_SQL\)/);
    assert.doesNotMatch(server, /`ALTER TABLE di_submissions DROP CONSTRAINT IF EXISTS di_submissions_(file_type|affiliation)_check`/);
    assert.doesNotMatch(server, /di_submissions_file_type_check CHECK/);
});

test('upload validation lists only use allowed file types', () => {
    const lists = [...server.matchAll(/!\[((?:'[A-Z]+',?\s*)+)\]\.includes\((?:normalizedType|fileType|docType)\)/g)];
    assert.ok(lists.length >= 4, 'expected upload validation lists');
    for (const l of lists) {
        for (const t of parseList(l[1])) assert.ok(EXPECTED.includes(t), `${t} not allowed by constraint`);
    }
});
