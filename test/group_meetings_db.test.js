// Group Meetings R1 — database tests against an ISOLATED LOCAL PostgreSQL.
//
// Runs only when GM_TEST_PGHOST points to a local Unix-socket directory
// (e.g. GM_TEST_PGHOST=/tmp/gmpg). It never reads DATABASE_URL or .env and
// refuses any TCP host, so it cannot reach a production or staging database.
// Each scenario creates and drops its own throwaway database.
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const express = require('express');
const { Pool } = require('pg');
const policy = require('../server/meetings/policy');
const schema = require('../server/meetings/schema');
const { makeRepo } = require('../server/meetings/repo');
const { createGroupMeetingsRouter } = require('../server/meetings');

const HOST = process.env.GM_TEST_PGHOST || '';
const LOCAL = HOST.startsWith('/');
const skip = LOCAL ? false : 'set GM_TEST_PGHOST to a local Unix-socket directory to run database tests';

const NATLAB_WS = '43a32f1d-8ff1-465b-9231-c366fafcec70';
const OTHER_WS = '99999999-9999-4999-8999-999999999999';

function poolFor(database) {
    if (!LOCAL) throw new Error('refusing non-local database');
    return new Pool({ host: HOST, user: 'postgres', database, port: Number(process.env.GM_TEST_PGPORT || 5432), max: 4 });
}

async function freshDb(name) {
    const admin = poolFor('postgres');
    await admin.query(`DROP DATABASE IF EXISTS ${name}`);
    await admin.query(`CREATE DATABASE ${name}`);
    await admin.end();
    return poolFor(name);
}

// Minimal shapes of the existing production tables the module reads.
async function baseFixture(pool, { legacyColumns = true } = {}) {
    await pool.query(`
        CREATE TABLE di_allowlist (researcher_id VARCHAR(50) PRIMARY KEY, name VARCHAR(255) NOT NULL,
            institution_email VARCHAR(255), affiliation VARCHAR(20), role VARCHAR(20), active BOOLEAN DEFAULT TRUE);
        CREATE TABLE workspaces (id UUID PRIMARY KEY, slug TEXT UNIQUE, is_active BOOLEAN DEFAULT TRUE, workspace_type TEXT);
        CREATE TABLE workspace_users (id SERIAL PRIMARY KEY, workspace_id UUID, user_id TEXT, membership_class TEXT DEFAULT 'core', is_active BOOLEAN DEFAULT TRUE);
        CREATE TABLE di_submissions (submission_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), researcher_id VARCHAR(50) NOT NULL,
            affiliation VARCHAR(20), file_type VARCHAR(20) NOT NULL, original_filename VARCHAR(500) NOT NULL,
            status VARCHAR(20) DEFAULT 'PENDING', ai_review JSONB, signed_at TIMESTAMP, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            r2_object_key TEXT, workspace_id UUID);
        CREATE INDEX idx_di_submissions_researcher ON di_submissions(researcher_id);
        INSERT INTO workspaces VALUES ('${NATLAB_WS}', 'natlab', TRUE, 'LAB'), ('${OTHER_WS}', 'theralia', TRUE, 'COMPANY');
        INSERT INTO di_allowlist VALUES
            ('PI', 'Principal', 'pi@x', 'LiU', 'pi', TRUE),
            ('BOT', 'Bot', 'b@x', 'LiU', 'ai_bot', TRUE),
            ('L1', 'Anna Liu', 'l1@x', 'LiU', 'researcher', TRUE),
            ('L2', 'Bo Liu', 'l2@x', 'LiU', 'supervisor', TRUE),
            ('U1', 'Carla Unav', 'u1@x', 'UNAV', 'researcher', TRUE),
            ('COL', 'Dan Collab', 'c@x', 'LiU', 'researcher', TRUE),
            ('OFF', 'Eve Gone', 'o@x', 'LiU', 'researcher', FALSE);
        INSERT INTO workspace_users (workspace_id, user_id, membership_class) VALUES ('${NATLAB_WS}', 'COL', 'collaborator');
    `);
    if (legacyColumns) {
        await pool.query(`ALTER TABLE di_submissions ADD COLUMN record_origin TEXT, ADD COLUMN legacy_pack_id UUID, ADD COLUMN original_created_at TIMESTAMPTZ`);
    }
}

// The migration-033 state, as it may exist in production.
async function migration033(pool) {
    await pool.query(`
        CREATE TABLE meeting_schedule (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), meeting_date DATE NOT NULL,
            status VARCHAR(10) NOT NULL DEFAULT 'DRAFT', created_by VARCHAR(100) NOT NULL);
        CREATE TABLE meeting_groups (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name VARCHAR(200) NOT NULL, site VARCHAR(100),
            default_day INTEGER CHECK (default_day BETWEEN 0 AND 6), default_time TIME DEFAULT '09:00', location TEXT,
            is_active BOOLEAN NOT NULL DEFAULT true, created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
        CREATE UNIQUE INDEX uq_meeting_groups_name ON meeting_groups(name);
        INSERT INTO meeting_groups (name, site, default_day, default_time) VALUES
            ('LiU Weekly Meeting', 'LiU', 4, '09:00'), ('UNAV Weekly Meeting', 'UNAV', 5, '09:00'), ('LiU-UNAV Meeting', 'LiU-UNAV', 3, '10:00');
        CREATE TABLE meeting_group_members (id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
            meeting_group_id UUID NOT NULL REFERENCES meeting_groups(id) ON DELETE CASCADE, researcher_id VARCHAR(100) NOT NULL,
            can_deep BOOLEAN NOT NULL DEFAULT false, can_focus BOOLEAN NOT NULL DEFAULT true, can_flash BOOLEAN NOT NULL DEFAULT true,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now());
        CREATE UNIQUE INDEX uq_meeting_group_members ON meeting_group_members(meeting_group_id, researcher_id);
        INSERT INTO meeting_group_members (meeting_group_id, researcher_id, can_deep)
            SELECT id, r, true FROM meeting_groups, (VALUES ('L1'), ('L2'), ('OFF')) v(r) WHERE name = 'LiU Weekly Meeting';
        INSERT INTO meeting_group_members (meeting_group_id, researcher_id)
            SELECT id, 'U1' FROM meeting_groups WHERE name = 'UNAV Weekly Meeting';
        INSERT INTO meeting_group_members (meeting_group_id, researcher_id)
            SELECT id, r FROM meeting_groups, (VALUES ('L1'), ('U1')) v(r) WHERE name = 'LiU-UNAV Meeting';
        INSERT INTO meeting_schedule (meeting_date, status, created_by) VALUES ('2026-02-26', 'LOCKED', 'PI');
    `);
}

const snapshot = async (pool, sql) => JSON.stringify((await pool.query(sql)).rows);

// --------------------------------------------------------------- schema
test('schema: existing 033 state — codes mapped, memberships and legacy rows untouched, idempotent', { skip }, async () => {
    const pool = await freshDb('gm_existing');
    try {
        await baseFixture(pool);
        await migration033(pool);
        const membersBefore = await snapshot(pool, 'SELECT * FROM meeting_group_members ORDER BY id');
        const scheduleBefore = await snapshot(pool, 'SELECT * FROM meeting_schedule ORDER BY id');
        assert.strictEqual(await schema.isSchemaReady(pool), false);
        for (let i = 0; i < 2; i++) assert.deepStrictEqual(await schema.ensureSchema(pool), { ok: true });
        assert.strictEqual(await schema.isSchemaReady(pool), true);
        const groups = (await pool.query('SELECT name, code FROM meeting_groups ORDER BY name')).rows;
        assert.deepStrictEqual(groups, [
            { name: 'LiU Weekly Meeting', code: 'LIU' },
            { name: 'LiU-UNAV Meeting', code: 'JOINT' },
            { name: 'UNAV Weekly Meeting', code: 'UNAV' },
        ]);
        assert.strictEqual(await snapshot(pool, 'SELECT * FROM meeting_group_members ORDER BY id'), membersBefore);
        assert.strictEqual(await snapshot(pool, 'SELECT * FROM meeting_schedule ORDER BY id'), scheduleBefore);
    } finally { await pool.end(); }
});

test('schema: renamed 033 group is not guessed; no group is ever duplicated', { skip }, async () => {
    const pool = await freshDb('gm_renamed');
    try {
        await baseFixture(pool);
        await migration033(pool);
        await pool.query(`UPDATE meeting_groups SET name = 'LiU Group Meeting' WHERE name = 'LiU Weekly Meeting'`);
        assert.deepStrictEqual(await schema.ensureSchema(pool), { ok: true });
        const rows = (await pool.query('SELECT name, code FROM meeting_groups ORDER BY name')).rows;
        assert.strictEqual(rows.length, 3);
        assert.strictEqual(rows.find(r => r.name === 'LiU Group Meeting').code, null); // PI assigns via /admin/groups/:id/code
        const repo = makeRepo(pool);
        const id = (await pool.query(`SELECT id FROM meeting_groups WHERE name = 'LiU Group Meeting'`)).rows[0].id;
        assert.strictEqual((await repo.assignCode(id, 'LIU')).code, 'LIU');
        // a group that already has a code is never re-coded
        assert.strictEqual(await repo.assignCode((await pool.query(`SELECT id FROM meeting_groups WHERE code='UNAV'`)).rows[0].id, 'JOINT'), null);
        const unavId = (await pool.query(`SELECT id FROM meeting_groups WHERE code='UNAV'`)).rows[0].id;
        await pool.query(`UPDATE meeting_groups SET code = NULL WHERE id = $1`, [unavId]);
        await assert.rejects(repo.assignCode(unavId, 'LIU'), e => e.code === '23505');
    } finally { await pool.end(); }
});

test('schema: fresh database without 033 tables — creates and seeds exactly once', { skip }, async () => {
    const pool = await freshDb('gm_fresh');
    try {
        await baseFixture(pool, { legacyColumns: false });
        for (let i = 0; i < 2; i++) assert.deepStrictEqual(await schema.ensureSchema(pool), { ok: true });
        assert.deepStrictEqual((await pool.query('SELECT code FROM meeting_groups ORDER BY code')).rows.map(r => r.code), ['JOINT', 'LIU', 'UNAV']);
        assert.strictEqual((await pool.query('SELECT COUNT(*)::int n FROM meeting_group_members')).rows[0].n, 0);
    } finally { await pool.end(); }
});

test('schema: a failing statement rolls back everything (transactional)', { skip }, async () => {
    const pool = await freshDb('gm_rollback');
    try {
        await baseFixture(pool);
        await migration033(pool);
        // Incompatible pre-existing column: the CHECK constraint statement fails.
        await pool.query(`ALTER TABLE meeting_groups ADD COLUMN code INTEGER`);
        const r = await schema.ensureSchema(pool);
        assert.strictEqual(r.ok, false);
        assert.strictEqual((await pool.query(`SELECT to_regclass('public.meeting_occurrences') AS t`)).rows[0].t, null);
        assert.strictEqual((await pool.query(`SELECT COUNT(*)::int n FROM information_schema.columns WHERE table_name='meeting_groups' AND column_name='zoom_join_url'`)).rows[0].n, 0);
        assert.strictEqual(await schema.isSchemaReady(pool), false);
    } finally { await pool.end(); }
});

// ----------------------------------------------------- query correctness
async function docsFixture(pool) {
    // Every combination of eligible/ineligible type × status × workspace × legacy.
    const types = ['SOP', 'DATA', 'PRESENTATION', 'PRES', 'REPORT', 'DOCS', 'INVENTORY'];
    const statuses = ['APPROVED', 'PENDING', 'SUBMITTED', 'REVISION_NEEDED', 'DISCARDED', 'ARCHIVED'];
    const owners = ['L1', 'L2', 'U1', 'OFF', 'COL'];
    let i = 0;
    for (const owner of owners) for (const t of types) for (const s of statuses) {
        i++;
        const ws = i % 11 === 0 ? OTHER_WS : NATLAB_WS;
        const legacy = i % 5 === 0;
        const pack = legacy && i % 2 === 0 ? 'b0000000-0000-4000-8000-000000000001' : null;
        const ageDays = (i % 40);
        await pool.query(
            `INSERT INTO di_submissions (researcher_id, file_type, original_filename, status, created_at, r2_object_key, workspace_id, record_origin, legacy_pack_id)
             VALUES ($1, $2, $3, $4, now() - make_interval(days => $5), $6, $7, $8, $9)`,
            [owner, t, `${owner}-${t}-${s}-${i}.pdf`, s, ageDays, `key-${i}`, ws, legacy ? 'legacy_pre2026' : null, pack]);
    }
}

test('SQL listing agrees with policy.isListableDocument for every group, owner and document', { skip }, async () => {
    const pool = await freshDb('gm_matrix');
    try {
        await baseFixture(pool);
        await migration033(pool);
        assert.ok((await schema.ensureSchema(pool)).ok);
        await docsFixture(pool);
        const repo = makeRepo(pool);
        const all = (await pool.query(`SELECT s.*, (s.workspace_id = '${NATLAB_WS}') AS in_natlab_workspace FROM di_submissions s`)).rows;
        const groups = (await pool.query(`SELECT id, code FROM meeting_groups`)).rows;
        const win = policy.newSubmissionWindow(null, new Date());
        let comparisons = 0;
        for (const g of groups) {
            const overview = await repo.overview(g.id, win.since);
            for (const owner of ['L1', 'L2', 'U1', 'OFF', 'COL']) {
                const ownerIsMember = await repo.isMember(g.id, owner);
                const expected = all.filter(d => d.researcher_id === owner &&
                    policy.isListableDocument(d, { ownerIsMember, actorCanAccessGroup: true }));
                const got = await repo.listDocuments(g.id, owner, null, 10000);
                assert.deepStrictEqual(got.map(d => d.submission_id).sort(), expected.map(d => d.submission_id).sort(), `${g.code} owner=${owner}`);
                const row = overview.find(r => r.researcher_id === owner);
                if (!ownerIsMember) { assert.strictEqual(row, undefined); continue; }
                assert.strictEqual(row.total_count, expected.length);
                assert.strictEqual(row.new_count, expected.filter(d => d.created_at > win.since).length);
                const maxCreated = expected.length ? Math.max(...expected.map(d => +d.created_at)) : null;
                assert.strictEqual(row.last_upload ? +row.last_upload : null, maxCreated);
                // file lookup returns exactly the listed documents, with their true owner
                for (const d of all.filter(x => x.researcher_id === owner)) {
                    const f = await repo.getListedDocument(g.id, d.submission_id);
                    assert.strictEqual(!!f, expected.some(e => e.submission_id === d.submission_id));
                    if (f) assert.strictEqual(f.researcher_id, owner);
                    comparisons++;
                }
            }
        }
        assert.ok(comparisons >= 200, `compared ${comparisons} document decisions`);
        // spot check: all four listable statuses appear; excluded statuses/types never
        const co = await repo.listDocuments(groups.find(g => g.code === 'LIU').id, 'L2', null, 10000);
        assert.deepStrictEqual([...new Set(co.map(d => d.status))].sort(), ['APPROVED', 'PENDING', 'REVISION_NEEDED', 'SUBMITTED']);
        assert.ok(co.every(d => ['SOP', 'DATA', 'PRESENTATION', 'PRES'].includes(d.file_type)));
    } finally { await pool.end(); }
});

test('works when optional legacy columns are absent (to_jsonb reads)', { skip }, async () => {
    const pool = await freshDb('gm_nolegacy');
    try {
        await baseFixture(pool, { legacyColumns: false });
        await migration033(pool);
        assert.ok((await schema.ensureSchema(pool)).ok);
        await pool.query(`INSERT INTO di_submissions (researcher_id, file_type, original_filename, status, workspace_id) VALUES ('L2', 'DATA', 'a.pdf', 'APPROVED', '${NATLAB_WS}')`);
        const repo = makeRepo(pool);
        const liu = (await pool.query(`SELECT id FROM meeting_groups WHERE code='LIU'`)).rows[0].id;
        const docs = await repo.listDocuments(liu, 'L2', null, 10);
        assert.strictEqual(docs.length, 1);
        assert.strictEqual(docs[0].record_origin, null);
    } finally { await pool.end(); }
});

test('windows: week start, completed meeting resets, cancelled/postponed do not', { skip }, async () => {
    const pool = await freshDb('gm_windows');
    try {
        await baseFixture(pool);
        await migration033(pool);
        assert.ok((await schema.ensureSchema(pool)).ok);
        const repo = makeRepo(pool);
        const liu = (await pool.query(`SELECT id FROM meeting_groups WHERE code='LIU'`)).rows[0].id;
        const ws = await repo.weekStart('Europe/Stockholm');
        const local = (await pool.query(`SELECT to_char($1::timestamptz AT TIME ZONE 'Europe/Stockholm', 'ID HH24:MI') AS t`, [ws])).rows[0].t;
        assert.strictEqual(local, '1 00:00'); // Monday 00:00 local time
        assert.strictEqual(await repo.lastCompletedAt(liu), null);
        const a = await repo.insertOccurrence({ groupId: liu, scheduledStart: '2026-11-05T08:00:00Z', durationMinutes: 60, note: null, actorId: 'PI' });
        await pool.query(`UPDATE meeting_occurrences SET status='COMPLETED', started_at='2026-11-05T08:00:00Z', ended_at='2026-11-05T09:10:00Z' WHERE id=$1`, [a.id]);
        const b = await repo.insertOccurrence({ groupId: liu, scheduledStart: '2026-11-12T08:00:00Z', durationMinutes: 60, note: null, actorId: 'PI' });
        await pool.query(`UPDATE meeting_occurrences SET status='CANCELLED', ended_at='2026-11-12T09:00:00Z' WHERE id=$1`, [b.id]);
        await repo.insertOccurrence({ groupId: liu, scheduledStart: '2026-11-19T08:00:00Z', durationMinutes: 60, note: null, actorId: 'PI' })
            .then(o => pool.query(`UPDATE meeting_occurrences SET status='POSTPONED' WHERE id=$1`, [o.id]));
        // R3.1: the reference is the ACTUAL START of the most recent completed meeting (not its end)
        assert.strictEqual(new Date(await repo.lastCompletedAt(liu)).toISOString(), '2026-11-05T08:00:00.000Z');
        // unique slot per group (except cancelled); optimistic transitions
        await assert.rejects(repo.insertOccurrence({ groupId: liu, scheduledStart: '2026-11-19T08:00:00Z', durationMinutes: 60, note: null, actorId: 'PI' }), e => e.code === '23505');
        assert.ok(await repo.insertOccurrence({ groupId: liu, scheduledStart: '2026-11-12T08:00:00Z', durationMinutes: 60, note: null, actorId: 'PI' }));
        assert.strictEqual(await repo.transitionOccurrence({ id: a.id, fromStatus: 'SCHEDULED', toStatus: 'CANCELLED', scheduledStart: null, note: null, actorId: 'PI' }), null);
        assert.strictEqual(await repo.isValidTimezone('Europe/Madrid'), true);
        assert.strictEqual(await repo.isValidTimezone('Mars/Base'), false);
    } finally { await pool.end(); }
});

test('complete history: keyset pages return every eligible document exactly once (ties, microseconds, NULL dates)', { skip }, async () => {
    const pool = await freshDb('gm_paging');
    try {
        await baseFixture(pool);
        await migration033(pool);
        assert.ok((await schema.ensureSchema(pool)).ok);
        // 260 eligible docs for L2: many share the exact same timestamp, some differ by microseconds, two have NULL created_at.
        await pool.query(`
            INSERT INTO di_submissions (researcher_id, file_type, original_filename, status, created_at, workspace_id)
            SELECT 'L2', (ARRAY['SOP','DATA','PRESENTATION','PRES'])[1 + g % 4], 'doc-' || g || '.pdf',
                   (ARRAY['APPROVED','PENDING','SUBMITTED','REVISION_NEEDED'])[1 + g % 4],
                   CASE WHEN g <= 2 THEN NULL
                        WHEN g <= 80 THEN TIMESTAMP '2026-11-20 10:00:00'                      -- 78-way tie
                        ELSE TIMESTAMP '2018-01-01 00:00:00' + (g * interval '1 microsecond') + (g * interval '3 days') END,
                   '${NATLAB_WS}'
              FROM generate_series(1, 260) g;
            -- noise that must never appear
            INSERT INTO di_submissions (researcher_id, file_type, original_filename, status, workspace_id)
            SELECT 'L2', 'REPORT', 'r' || g, 'APPROVED', '${NATLAB_WS}' FROM generate_series(1, 30) g;
            INSERT INTO di_submissions (researcher_id, file_type, original_filename, status, workspace_id)
            SELECT 'L2', 'DATA', 'd' || g, 'DISCARDED', '${NATLAB_WS}' FROM generate_series(1, 30) g;`);
        const repo = makeRepo(pool);
        const liu = (await pool.query(`SELECT id FROM meeting_groups WHERE code='LIU'`)).rows[0].id;
        const expected = (await pool.query(`SELECT submission_id FROM di_submissions WHERE original_filename LIKE 'doc-%'`)).rows.map(r => r.submission_id);
        assert.strictEqual(await repo.countDocuments(liu, 'L2', null), 260);
        for (const pageSize of [1, 7, 100]) {
            const seen = [];
            let cursor = null;
            let pages = 0;
            do {
                const rows = await repo.listDocuments(liu, 'L2', null, pageSize + 1, cursor);
                const page = rows.slice(0, pageSize);
                seen.push(...page.map(r => r.submission_id));
                cursor = rows.length > pageSize ? { t: page[page.length - 1].sort_ts, id: page[page.length - 1].submission_id } : null;
                pages++;
                assert.ok(pages < 400, 'terminates');
            } while (cursor);
            assert.strictEqual(seen.length, 260, `page size ${pageSize}`);
            assert.strictEqual(new Set(seen).size, 260, `no duplicates at page size ${pageSize}`);
            assert.deepStrictEqual([...seen].sort(), [...expected].sort());
        }
        // newest first; NULL dates last; overview total equals the paged total
        const first = await repo.listDocuments(liu, 'L2', null, 1000, null);
        assert.strictEqual(first.length, 260);
        assert.strictEqual(first[first.length - 1].created_at, null);
        const ov = await repo.overview(liu, new Date());
        assert.strictEqual(ov.find(r => r.researcher_id === 'L2').total_count, 260);
    } finally { await pool.end(); }
});

test('lifecycle: meeting data never blocks deleting or discarding submissions', { skip }, async () => {
    const pool = await freshDb('gm_lifecycle');
    try {
        await baseFixture(pool);
        await migration033(pool);
        assert.ok((await schema.ensureSchema(pool)).ok);
        const fks = (await pool.query(`
            SELECT conname FROM pg_constraint WHERE contype = 'f' AND confrelid = 'di_submissions'::regclass`)).rows;
        assert.deepStrictEqual(fks, []);
        const id = (await pool.query(`INSERT INTO di_submissions (researcher_id, file_type, original_filename, status, workspace_id) VALUES ('L2','DATA','x.pdf','APPROVED','${NATLAB_WS}') RETURNING submission_id`)).rows[0].submission_id;
        await pool.query(`UPDATE di_submissions SET status='DISCARDED' WHERE submission_id=$1`, [id]);
        await pool.query(`DELETE FROM di_submissions WHERE submission_id=$1`, [id]);
    } finally { await pool.end(); }
});

test('membership SQL: candidates, add/remove, ineligible rows flagged, can_* flags preserved', { skip }, async () => {
    const pool = await freshDb('gm_members');
    try {
        await baseFixture(pool);
        await migration033(pool);
        assert.ok((await schema.ensureSchema(pool)).ok);
        const repo = makeRepo(pool);
        const liu = (await pool.query(`SELECT id FROM meeting_groups WHERE code='LIU'`)).rows[0].id;
        const c = await repo.membershipCandidates(liu);
        const by = Object.fromEntries(c.map(r => [r.researcher_id, r]));
        assert.strictEqual(by.L1.in_group, true);
        assert.strictEqual(by.COL.membership_class, 'collaborator');
        assert.strictEqual(by.OFF.in_group, true);
        assert.strictEqual(by.OFF.eligible, false); // inactive: listed so the PI can remove it, but grants nothing
        assert.strictEqual(by.PI, undefined);
        assert.strictEqual(by.BOT, undefined);
        assert.strictEqual(await repo.isMember(liu, 'OFF'), false);
        assert.strictEqual(await repo.addMember(liu, 'COL'), true);
        assert.strictEqual(await repo.addMember(liu, 'COL'), false);
        const deepBefore = (await pool.query(`SELECT can_deep FROM meeting_group_members WHERE meeting_group_id=$1 AND researcher_id='L1'`, [liu])).rows[0].can_deep;
        assert.strictEqual(deepBefore, true);
        assert.strictEqual(await repo.removeMember(liu, 'COL'), true);
        assert.strictEqual(await repo.isMember(liu, 'COL'), false);
        const s = await repo.updateSettings(liu, { zoom_join_url: 'https://liu-se.zoom.us/j/1', duration_minutes: 60, default_time: '10:30' });
        assert.strictEqual(s.zoom_join_url, 'https://liu-se.zoom.us/j/1');
        assert.strictEqual(String(s.default_time).slice(0, 5), '10:30');
    } finally { await pool.end(); }
});

test('end-to-end HTTP over the real repository with mocked storage', { skip }, async () => {
    const pool = await freshDb('gm_http');
    let server;
    try {
        await baseFixture(pool);
        await migration033(pool);
        assert.ok((await schema.ensureSchema(pool)).ok);
        const ins = async (owner, type, status, name) => (await pool.query(
            `INSERT INTO di_submissions (researcher_id, file_type, original_filename, status, r2_object_key, workspace_id)
             VALUES ($1,$2,$3::text,$4,'r2:key/' || $3::text,'${NATLAB_WS}') RETURNING submission_id`, [owner, type, name, status])).rows[0].submission_id;
        const approved = await ins('L2', 'DATA', 'APPROVED', 'ok.pdf');
        const pending = await ins('L2', 'SOP', 'PENDING', 'pending.pdf');
        const report = await ins('L2', 'REPORT', 'APPROVED', 'secret-report.pdf');
        const storage = [];
        const app = express();
        app.use(express.json());
        app.use((req, res, next) => { req.session = { user: JSON.parse(req.headers['x-test-user']) }; next(); });
        app.use('/api/group-meetings', createGroupMeetingsRouter({
            pool, isEnabled: () => true, audience: () => ({ mode: 'members' }),
            normalizeR2Key: (k) => k.replace(/^r2:/, ''), r2Enabled: () => true,
            downloadFromR2: async (key) => { storage.push(key); return { ContentType: 'application/pdf', Body: Buffer.from('%PDF') }; },
        }));
        server = http.createServer(app);
        await new Promise(r => server.listen(0, '127.0.0.1', r));
        const base = `http://127.0.0.1:${server.address().port}/api/group-meetings`;
        const get = (path, user) => fetch(base + path, { headers: { 'x-test-user': JSON.stringify(user) } });
        const L1 = { researcher_id: 'L1', role: 'researcher' };
        const L2 = { researcher_id: 'L2', role: 'supervisor' };
        const PI = { researcher_id: 'PI', role: 'pi' };
        const ov = await (await get('/groups/LIU/overview', L1)).json();
        assert.strictEqual(ov.researchers.find(r => r.researcher_id === 'L2').total_count, 2);
        const listRes = await (await get('/groups/LIU/members/L2/documents?filter=all', L1)).json();
        const ids = listRes.documents.map(d => d.submission_id).sort();
        assert.deepStrictEqual(ids, [approved, pending].sort());
        assert.ok(listRes.documents.every(d => d.can_open === false));
        assert.ok(!JSON.stringify(listRes).includes(report) && !JSON.stringify(listRes).includes('secret'));
        // listed APPROVED co-member document: visible in the list, NOT retrievable
        assert.strictEqual((await get(`/groups/LIU/documents/${approved}/file`, L1)).status, 403);
        assert.strictEqual((await get(`/groups/LIU/documents/${approved}/file?download=1`, L1)).status, 403);
        assert.strictEqual((await get(`/groups/LIU/documents/${pending}/file`, L1)).status, 403);
        assert.strictEqual((await get(`/groups/LIU/documents/${report}/file`, PI)).status, 404);
        assert.strictEqual(storage.length, 0);
        assert.strictEqual((await get(`/groups/LIU/documents/${approved}/file`, L2)).status, 200);
        assert.strictEqual((await get(`/groups/LIU/documents/${pending}/file`, PI)).status, 200);
        assert.strictEqual((await get('/groups/UNAV/overview', L1)).status, 403);
        assert.strictEqual((await get('/me', { researcher_id: 'BOT', role: 'ai_bot' })).status, 403);
        assert.deepStrictEqual(storage, ['key/ok.pdf', 'key/pending.pdf']);
    } finally {
        if (server) await new Promise(r => server.close(r));
        await pool.end();
    }
});
