// Group Meetings R1 — static guarantees checked against the source code.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const dir = path.join(__dirname, '..', 'server', 'meetings');
const files = fs.readdirSync(dir).filter(f => f.endsWith('.js'));
const src = Object.fromEntries(files.map(f => [f, fs.readFileSync(path.join(dir, f), 'utf8')]));
const all = Object.values(src).join('\n');
const server = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');

test('never writes scientific submissions', () => {
    assert.doesNotMatch(all, /(INSERT\s+INTO|UPDATE|DELETE\s+FROM|ALTER\s+TABLE|TRUNCATE|DROP\s+TABLE)\s+di_submissions/i);
});

test('no constraint or foreign key references di_submissions', () => {
    assert.doesNotMatch(src['schema.js'], /REFERENCES\s+di_submissions/i);
});

test('schema is additive: no DROP / DELETE / TRUNCATE / RENAME statements are executed', () => {
    const { STATEMENTS } = require('../server/meetings/schema');
    // ('ON DELETE CASCADE' inside the unchanged migration-033 table definition is a FK rule, not a deletion)
    for (const s of STATEMENTS) {
        const stmt = s.replace(/ON DELETE CASCADE/gi, '');
        assert.doesNotMatch(stmt, /\b(DROP|DELETE|TRUNCATE|RENAME)\b/i, s.slice(0, 80));
    }
    // legacy publication / speaker-slot tables are not touched
    for (const s of STATEMENTS) assert.doesNotMatch(s, /meeting_schedule|meeting_participation|meeting_speaker_pool/i);
});

test('no Zoom API, e-mail, n8n, scheduler or outbound network code', () => {
    assert.doesNotMatch(all, /\bfetch\s*\(|require\(['"](node-fetch|axios|https?|node:https?)['"]\)/);
    assert.doesNotMatch(all, /api\.zoom\.us|zoom\.us\/oauth|ZOOM_(CLIENT|ACCOUNT|SECRET)/i);
    assert.doesNotMatch(all, /require\(['"]\.\.\/notify['"]\)|resend|n8n|webhook/i);
    assert.doesNotMatch(all, /setInterval|setTimeout|cron/i);
});

test('no direct storage client: retrieval only through the injected existing helper', () => {
    assert.doesNotMatch(all, /@aws-sdk|S3Client|GetObjectCommand|R2_(ENDPOINT|BUCKET|ACCESS)/);
});

test('logs never include Zoom links, filenames or storage keys', () => {
    const logLines = all.split('\n').filter(l => /console\.(log|warn|error)/.test(l));
    for (const l of logLines) assert.doesNotMatch(l, /zoom_join_url|original_filename|r2_object_key|\bkey\b|url/i, l.trim());
});

test('server.js: legacy meeting announcements retired only while the flag is on', () => {
    const next = server.slice(server.indexOf("app.get('/api/meetings/next'"), server.indexOf("app.get('/api/meetings/by-date/:date'"));
    assert.match(next, /isAvailableFor\(req\.session\.user\)\) return res\.json\(\{ meeting: null, retired: true \}\);/);
    const byId = server.slice(server.indexOf("app.get('/api/meetings/:id', requireAuth"), server.indexOf("app.get('/api/meetings/:id', requireAuth") + 700);
    assert.match(byId, /req\.session\.user\.role !== 'pi' && require\('\.\/server\/meetings'\)\.isAvailableFor\(req\.session\.user\)\) \{\s*return res\.status\(404\)/);
});

test('server.js: mounted once, flag-gated, existing download route unchanged', () => {
    assert.strictEqual((server.match(/app\.use\('\/api\/group-meetings'/g) || []).length, 1);
    assert.match(server, /groupMeetings\.ensureSchemaIfEnabled\(pool\)/);
    assert.match(server, /app\.get\('\/api\/di\/download\/:id', r1bRequireDownloadAuth, docGuards\.submission,/);
    // docAccess remains in shadow mode and unchanged by this feature
    assert.strictEqual(require('../server/docAccess').ENFORCE, false);
    assert.doesNotMatch(fs.readFileSync(path.join(__dirname, '..', 'server', 'docAccess.js'), 'utf8'), /group.?meeting|meeting_group/i);
});
