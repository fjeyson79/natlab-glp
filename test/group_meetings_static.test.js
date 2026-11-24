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

test('R2.2: all 22 legacy meeting routes are permanently retired (410) for every role', () => {
    const mount = "app.use(['/api/meetings', '/api/meeting-groups'], legacyMeetingsRetiredHandler);";
    const mountAt = server.indexOf(mount);
    assert.ok(mountAt > 0, 'retirement handler mounted on both legacy prefixes');
    assert.strictEqual(server.split(mount).length - 1, 1, 'mounted exactly once');
    assert.match(server, /function legacyMeetingsRetiredHandler\(req, res\) \{\s*return res\.status\(410\)\.json\(/);
    // Express matches in registration order: every legacy route is defined AFTER the 410 mount.
    const routeRe = /app\.(get|post|put|patch|delete)\('(\/api\/(?:meetings|meeting-groups)[^']*)'/g;
    const routes = [];
    let m;
    while ((m = routeRe.exec(server))) routes.push({ route: `${m[1].toUpperCase()} ${m[2]}`, at: m.index });
    assert.strictEqual(routes.length, 22, 'inventory of legacy routes: ' + routes.map(r => r.route).join(', '));
    for (const r of routes) assert.ok(r.at > mountAt, `${r.route} is shadowed by the 410 handler`);
    // the retirement does not touch the new Group Meetings API (different prefix)
    assert.ok(!'/api/group-meetings/status'.startsWith('/api/meetings/') && !'/api/group-meetings'.startsWith('/api/meeting-groups'));
    // no handler for these prefixes is registered before the retirement mount
    assert.doesNotMatch(server.slice(0, mountAt), /'\/api\/meetings|'\/api\/meeting-groups/);
});

test('server.js: mounted once, flag-gated, existing download route unchanged', () => {
    assert.strictEqual((server.match(/app\.use\('\/api\/group-meetings'/g) || []).length, 1);
    assert.match(server, /groupMeetings\.ensureSchemaIfEnabled\(pool\)/);
    assert.match(server, /app\.get\('\/api\/di\/download\/:id', r1bRequireDownloadAuth, docGuards\.submission,/);
    // Group Meetings does not depend on, or modify, core document authorization
    // (S1.2a staged enforcement lives in docAccess; meetings keep their own owner-or-PI check)
    assert.doesNotMatch(fs.readFileSync(path.join(__dirname, '..', 'server', 'docAccess.js'), 'utf8'), /group.?meeting|meeting_group/i);
});
