// Group Meetings R3.1 — scientific meeting sessions against an ISOLATED LOCAL
// PostgreSQL (GM_TEST_PGHOST = local Unix-socket directory; skipped otherwise).
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const express = require('express');
const { Pool } = require('pg');
const schema = require('../server/meetings/schema');
const { makeRepo } = require('../server/meetings/repo');
const { makeSessionService } = require('../server/meetings/sessions');
const { createGroupMeetingsRouter, ensureSchemaIfEnabled } = require('../server/meetings');

const HOST = process.env.GM_TEST_PGHOST || '';
const LOCAL = HOST.startsWith('/');
const skip = LOCAL ? false : 'set GM_TEST_PGHOST to a local Unix-socket directory to run database tests';
const NATLAB_WS = '43a32f1d-8ff1-465b-9231-c366fafcec70';
const PORT = Number(process.env.GM_TEST_PGPORT || 5432);
const BOTH = { GROUP_MEETINGS_ENABLED: 'true', GROUP_MEETINGS_SESSIONS_ENABLED: 'true' };
const PI = { id: 'PI', isPi: true };

function poolFor(database) {
    if (!LOCAL) throw new Error('refusing non-local database');
    return new Pool({ host: HOST, user: 'postgres', database, port: PORT, max: 10 });
}
async function freshDb(name) {
    const admin = poolFor('postgres');
    await admin.query(`DROP DATABASE IF EXISTS ${name}`);
    await admin.query(`CREATE DATABASE ${name}`);
    await admin.end();
    return poolFor(name);
}
async function fixture(pool) {
    await pool.query(`
        CREATE TABLE di_allowlist (researcher_id VARCHAR(50) PRIMARY KEY, name VARCHAR(255) NOT NULL, institution_email VARCHAR(255),
            affiliation VARCHAR(20), role VARCHAR(20), active BOOLEAN DEFAULT TRUE);
        CREATE TABLE workspaces (id UUID PRIMARY KEY, slug TEXT UNIQUE, is_active BOOLEAN DEFAULT TRUE, workspace_type TEXT);
        CREATE TABLE workspace_users (id SERIAL PRIMARY KEY, workspace_id UUID, user_id TEXT, membership_class TEXT DEFAULT 'core', is_active BOOLEAN DEFAULT TRUE);
        CREATE TABLE di_submissions (submission_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), researcher_id VARCHAR(50) NOT NULL,
            affiliation VARCHAR(20), file_type VARCHAR(20) NOT NULL, original_filename VARCHAR(500) NOT NULL,
            status VARCHAR(20) DEFAULT 'PENDING', signed_at TIMESTAMP, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            r2_object_key TEXT, workspace_id UUID);
        INSERT INTO workspaces VALUES ('${NATLAB_WS}', 'natlab', TRUE, 'LAB');
        INSERT INTO di_allowlist VALUES
            ('PI', 'Principal', 'pi@x', 'LiU', 'pi', TRUE), ('BOT', 'Bot', 'b@x', 'LiU', 'ai_bot', TRUE),
            ('L1', 'Anna Liu', 'l1@x', 'LiU', 'researcher', TRUE), ('L2', 'Bo Liu', 'l2@x', 'LiU', 'supervisor', TRUE),
            ('L3', 'Cai Liu', 'l3@x', 'LiU', 'researcher', TRUE), ('U1', 'Carla Unav', 'u1@x', 'UNAV', 'researcher', TRUE),
            ('U2', 'Dani Unav', 'u2@x', 'UNAV', 'researcher', TRUE), ('OFF', 'Eve Gone', 'o@x', 'LiU', 'researcher', FALSE);
        CREATE TABLE meeting_groups (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name VARCHAR(200) NOT NULL, site VARCHAR(100),
            default_day INTEGER, default_time TIME DEFAULT '09:00', location TEXT, is_active BOOLEAN NOT NULL DEFAULT true,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
        CREATE UNIQUE INDEX uq_meeting_groups_name ON meeting_groups(name);
        INSERT INTO meeting_groups (name, site) VALUES ('LiU Weekly Meeting','LiU'), ('UNAV Weekly Meeting','UNAV'), ('LiU-UNAV Meeting','LiU-UNAV');
        CREATE TABLE meeting_group_members (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), meeting_group_id UUID NOT NULL REFERENCES meeting_groups(id) ON DELETE CASCADE,
            researcher_id VARCHAR(100) NOT NULL, can_deep BOOLEAN NOT NULL DEFAULT false, can_focus BOOLEAN NOT NULL DEFAULT true,
            can_flash BOOLEAN NOT NULL DEFAULT true, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
        CREATE UNIQUE INDEX uq_meeting_group_members ON meeting_group_members(meeting_group_id, researcher_id);
        INSERT INTO meeting_group_members (meeting_group_id, researcher_id) SELECT id, r FROM meeting_groups, (VALUES ('L1'),('L2'),('OFF')) v(r) WHERE name='LiU Weekly Meeting';
        INSERT INTO meeting_group_members (meeting_group_id, researcher_id) SELECT id, r FROM meeting_groups, (VALUES ('U1'),('U2')) v(r) WHERE name='UNAV Weekly Meeting';
        INSERT INTO meeting_group_members (meeting_group_id, researcher_id) SELECT id, r FROM meeting_groups, (VALUES ('L1'),('U1')) v(r) WHERE name='LiU-UNAV Meeting';
    `);
}
const groupOf = async (pool, code) => (await pool.query(`SELECT * FROM meeting_groups WHERE code = $1`, [code])).rows[0];
const status = async (pool, id) => (await pool.query(`SELECT status FROM meeting_occurrences WHERE id = $1`, [id])).rows[0].status;
const roster = async (pool, id) => (await pool.query(
    `SELECT researcher_id, source, status FROM meeting_attendance WHERE occurrence_id = $1 ORDER BY researcher_id`, [id])).rows;
const iso = (t) => (t ? new Date(t).toISOString() : null);

// ------------------------------------------------------------- schema
test('schema: session statements run only when BOTH flags are on; idempotent', { skip }, async () => {
    const pool = await freshDb('gm_s_schema');
    try {
        await fixture(pool);
        assert.deepStrictEqual(await ensureSchemaIfEnabled(pool, {}), { ok: true, skipped: true });
        assert.strictEqual((await pool.query(`SELECT to_regclass('public.meeting_occurrences') AS t`)).rows[0].t, null);
        assert.strictEqual((await ensureSchemaIfEnabled(pool, { GROUP_MEETINGS_ENABLED: 'true' })).sessions, 'skipped');
        assert.strictEqual(await schema.isSessionSchemaReady(pool), false);
        assert.strictEqual((await pool.query(`SELECT to_regclass('public.meeting_attendance') AS t`)).rows[0].t, null);
        for (let i = 0; i < 2; i++) assert.strictEqual((await ensureSchemaIfEnabled(pool, BOTH)).sessions, 'ensured');
        assert.strictEqual(await schema.isSessionSchemaReady(pool), true);
        // no foreign key / constraint on the scientific submissions table
        assert.deepStrictEqual((await pool.query(`SELECT conname FROM pg_constraint WHERE confrelid = 'di_submissions'::regclass`)).rows, []);
    } finally { await pool.end(); }
});

test('schema: a failing session statement rolls back all session additions; R2 schema intact', { skip }, async () => {
    const pool = await freshDb('gm_s_fail');
    try {
        await fixture(pool);
        assert.ok((await schema.ensureSchema(pool)).ok);
        await pool.query(`ALTER TABLE meeting_occurrences ADD COLUMN origin INTEGER`); // incompatible: CHECK on text values fails
        const r = await schema.ensureSessionSchema(pool);
        assert.strictEqual(r.ok, false);
        assert.strictEqual((await pool.query(`SELECT to_regclass('public.meeting_attendance') AS t`)).rows[0].t, null);
        assert.strictEqual((await pool.query(`SELECT COUNT(*)::int n FROM information_schema.columns WHERE table_name='meeting_occurrences' AND column_name='chair_researcher_id'`)).rows[0].n, 0);
        assert.strictEqual(await schema.isSchemaReady(pool), true, 'R2 schema unaffected');
        assert.strictEqual(await schema.isSessionSchemaReady(pool), false);
    } finally { await pool.end(); }
});

// ---------------------------------------------------------- lifecycle
test('lifecycle, attendance, reference, reopen, corrections and recovery', { skip }, async () => {
    const pool = await freshDb('gm_s_life');
    try {
        await fixture(pool);
        assert.strictEqual((await ensureSchemaIfEnabled(pool, BOTH)).sessions, 'ensured');
        const repo = makeRepo(pool);
        const events = [];
        let clock = new Date();
        const svc = makeSessionService(pool, { onEvent: e => events.push(e.event), now: () => clock });
        const LIU = await groupOf(pool, 'LIU'), UNAV = await groupOf(pool, 'UNAV'), JOINT = await groupOf(pool, 'JOINT');

        // --- start a SCHEDULED meeting; roster snapshot of current eligible members (OFF excluded)
        const sched = await repo.insertOccurrence({ groupId: LIU.id, scheduledStart: new Date(Date.now() + 3600e3).toISOString(), durationMinutes: 60, note: null, actorId: 'PI' });
        const a = await svc.start(LIU, PI, { occurrenceId: sched.id });
        assert.strictEqual(a.resumed, false);
        assert.strictEqual(a.occurrence.status, 'IN_PROGRESS');
        assert.strictEqual(a.occurrence.origin, 'SCHEDULED');
        assert.strictEqual(a.occurrence.chair_researcher_id, 'PI');
        assert.deepStrictEqual(await roster(pool, sched.id), [
            { researcher_id: 'L1', source: 'ROSTER', status: 'UNMARKED' }, { researcher_id: 'L2', source: 'ROSTER', status: 'UNMARKED' }]);
        // retry = idempotent resume, no duplicate roster or meeting
        const retry = await svc.start(LIU, PI, { occurrenceId: sched.id });
        assert.strictEqual(retry.resumed, true);
        assert.strictEqual((await roster(pool, sched.id)).length, 2);
        // a second meeting in the same group is refused
        await assert.rejects(svc.start(LIU, PI, { adhoc: true }), e => e.httpStatus === 409 && e.code === 'already_active');
        // reference not advanced by starting
        assert.strictEqual(await repo.lastCompletedAt(LIU.id), null);

        // --- independent groups; concurrent starts produce exactly one meeting
        const j = await svc.start(JOINT, PI, { adhoc: true });
        assert.strictEqual(j.occurrence.origin, 'ADHOC');
        assert.strictEqual(j.occurrence.scheduled_start, null);
        const race = await Promise.allSettled(Array.from({ length: 8 }, () => svc.start(UNAV, PI, { adhoc: true })));
        assert.strictEqual(race.filter(r => r.status === 'fulfilled').length, 1);
        assert.ok(race.filter(r => r.status === 'rejected').every(r => r.reason.httpStatus === 409));
        assert.strictEqual((await pool.query(`SELECT COUNT(*)::int n FROM meeting_occurrences WHERE meeting_group_id=$1 AND status='IN_PROGRESS'`, [UNAV.id])).rows[0].n, 1);
        const unavSession = (await svc.getActive(UNAV.id)).id;

        // --- membership changes during the meeting never rewrite the roster
        await pool.query(`INSERT INTO meeting_group_members (meeting_group_id, researcher_id) VALUES ($1, 'L3')`, [LIU.id]);
        await pool.query(`DELETE FROM meeting_group_members WHERE meeting_group_id=$1 AND researcher_id='L2'`, [LIU.id]);
        assert.deepStrictEqual((await roster(pool, sched.id)).map(r => r.researcher_id), ['L1', 'L2']);
        // explicit addition of a CURRENT eligible member (source ADDED); others refused
        assert.deepStrictEqual(await svc.addParticipant(sched.id, 'L3', PI), { added: true });
        await assert.rejects(svc.addParticipant(sched.id, 'L3', PI), e => e.code === 'already_in_roster');
        await assert.rejects(svc.addParticipant(sched.id, 'U1', PI), e => e.code === 'not_eligible_member');
        await assert.rejects(svc.addParticipant(sched.id, 'OFF', PI), e => e.code === 'not_eligible_member');
        assert.strictEqual((await roster(pool, sched.id)).find(r => r.researcher_id === 'L3').source, 'ADDED');

        // --- attendance: three states, restore to UNMARKED, bulk never overwrites explicit marks
        assert.strictEqual((await svc.setAttendance(sched.id, 'L1', 'present', PI)).status, 'PRESENT');
        assert.strictEqual((await svc.setAttendance(sched.id, 'L1', 'UNMARKED', PI)).status, 'UNMARKED');
        await svc.setAttendance(sched.id, 'L1', 'PRESENT', PI);
        assert.strictEqual((await svc.setAttendance(sched.id, 'L1', 'PRESENT', PI)).changed, false);
        await assert.rejects(svc.setAttendance(sched.id, 'L1', 'EXCUSED', PI), e => e.code === 'invalid_status');
        await assert.rejects(svc.setAttendance(sched.id, 'U1', 'PRESENT', PI), e => e.code === 'not_in_roster');
        await svc.setAttendance(sched.id, 'L3', 'ABSENT', PI);
        const bulk = await svc.bulkAttendance(sched.id, 'remaining_absent', PI);
        assert.strictEqual(bulk.changed, 1); // only L2 was UNMARKED
        assert.deepStrictEqual((await roster(pool, sched.id)).map(r => r.status), ['PRESENT', 'ABSENT', 'ABSENT']);
        // edits during the meeting are normal work, not corrections
        assert.deepStrictEqual((await pool.query(`SELECT correction_log FROM meeting_occurrences WHERE id=$1`, [sched.id])).rows[0].correction_log, []);

        // --- a document uploaded DURING the meeting stays "new" for the next meeting
        const startedA = new Date((await pool.query(`SELECT started_at FROM meeting_occurrences WHERE id=$1`, [sched.id])).rows[0].started_at);
        await pool.query(`INSERT INTO di_submissions (researcher_id, file_type, original_filename, status, created_at, workspace_id)
                          VALUES ('L1', 'DATA', 'during.pdf', 'APPROVED', now(), '${NATLAB_WS}')`);
        await pool.query(`INSERT INTO di_submissions (researcher_id, file_type, original_filename, status, created_at, workspace_id)
                          VALUES ('L1', 'DATA', 'before.pdf', 'APPROVED', now() - interval '2 days', '${NATLAB_WS}')`);

        // --- complete with notes; summary reports unmarked count
        await svc.updateNotes(sched.id, { sharedConclusions: { present: true, value: 'Shared: aptamer stable.' }, privateNotes: { present: true, value: 'PRIVATE-NOTE-TEXT' } }, PI);
        const endA = await svc.end(sched.id, PI);
        assert.strictEqual(endA.occurrence.status, 'COMPLETED');
        assert.deepStrictEqual(endA.attendance, { present: 1, absent: 2, unmarked: 0, total: 3 });
        await assert.rejects(svc.end(sched.id, PI), e => e.code === 'already_completed');
        const refA = await repo.lastCompletedAt(LIU.id);
        assert.strictEqual(iso(refA), startedA.toISOString(), 'reference = actual START of the completed meeting');
        const ov = await repo.overview(LIU.id, refA);
        assert.strictEqual(ov.find(r => r.researcher_id === 'L1').new_count, 1, 'the document uploaded during the meeting is new');

        // --- complete leaving attendance unmarked (JOINT): nothing silently changed
        const endJ = await svc.end(j.occurrence.id, PI);
        assert.strictEqual(endJ.attendance.unmarked, 2);
        assert.ok((await roster(pool, j.occurrence.id)).every(r => r.status === 'UNMARKED'));

        // --- historical corrections on the completed meeting: logged, reference unchanged
        await svc.setAttendance(sched.id, 'L3', 'PRESENT', PI);
        await svc.updateNotes(sched.id, { sharedConclusions: { present: true, value: 'Shared v2' }, privateNotes: { present: false } }, PI);
        const logA = (await pool.query(`SELECT correction_log, updated_at FROM meeting_occurrences WHERE id=$1`, [sched.id])).rows[0];
        assert.deepStrictEqual(logA.correction_log.map(e => [e.what, e.target, e.from, e.to, e.by]),
            [['attendance', 'L3', 'ABSENT', 'PRESENT', 'PI'], ['shared_conclusions', undefined, undefined, undefined, 'PI']]);
        assert.ok(!JSON.stringify(logA.correction_log).includes('Shared v2'), 'no text copies in the log');
        assert.strictEqual(iso(await repo.lastCompletedAt(LIU.id)), iso(refA));
        // lost-update protection
        await assert.rejects(svc.updateNotes(sched.id, { privateNotes: { present: true, value: 'x' }, sharedConclusions: { present: false }, expectedUpdatedAt: '2000-01-01T00:00:00Z' }, PI),
            e => e.code === 'stale_write');
        // concurrent corrections never lose log entries
        await Promise.all(['ABSENT', 'PRESENT', 'UNMARKED'].map((s, i) => svc.setAttendance(sched.id, ['L1', 'L2', 'L3'][i], s, PI)));
        assert.strictEqual((await pool.query(`SELECT jsonb_array_length(correction_log) n FROM meeting_occurrences WHERE id=$1`, [sched.id])).rows[0].n, 5);

        // --- second LIU meeting B; reopen rules
        clock = new Date(Date.now() + 1000);
        const b = await svc.start(LIU, PI, { adhoc: true });
        const startedB = new Date(b.occurrence.started_at);
        assert.deepStrictEqual((await roster(pool, b.occurrence.id)).map(r => r.researcher_id), ['L1', 'L3'], 'roster reflects membership at B start');
        await svc.end(b.occurrence.id, PI);
        assert.strictEqual(iso(await repo.lastCompletedAt(LIU.id)), startedB.toISOString());
        await assert.rejects(svc.reopen(sched.id, PI), e => e.code === 'not_most_recent');
        const re = await svc.reopen(b.occurrence.id, PI);
        assert.strictEqual(re.occurrence.status, 'IN_PROGRESS');
        assert.strictEqual(iso(re.occurrence.started_at), startedB.toISOString(), 'start preserved');
        assert.strictEqual(re.occurrence.ended_at, null);
        // R3.3 refinement: reopening must NOT reset the reference to the previous meeting
        assert.strictEqual(iso(await repo.lastCompletedAt(LIU.id)), startedB.toISOString(), 'while reopened: reference unchanged (still B start)');
        const ovReopened = await repo.overview(LIU.id, await repo.lastCompletedAt(LIU.id));
        const ovBefore = await repo.overview(LIU.id, startedB);
        assert.deepStrictEqual(ovReopened.map(r => [r.researcher_id, r.new_count]), ovBefore.map(r => [r.researcher_id, r.new_count]), 'New counters unchanged while reopened');
        // a freshly started (never completed) meeting still does NOT count: UNAV has only an active, never-completed meeting
        assert.strictEqual(await repo.lastCompletedAt(UNAV.id), null);
        await assert.rejects(svc.start(LIU, PI, { adhoc: true }), e => e.code === 'already_active');
        await assert.rejects(svc.abandon(b.occurrence.id, PI, {}), e => e.code === 'reopened_cannot_be_abandoned');
        await svc.end(b.occurrence.id, PI);
        assert.strictEqual(iso(await repo.lastCompletedAt(LIU.id)), startedB.toISOString(), 'same reference as before reopening');
        assert.deepStrictEqual((await pool.query(`SELECT correction_log FROM meeting_occurrences WHERE id=$1`, [b.occurrence.id])).rows[0].correction_log.map(e => e.what), ['reopen', 'complete']);
        assert.strictEqual(events.filter(e => e === 'meeting.reopened').length, 1);

        // --- abandoned meeting C never moves the reference; reopen blocked while C active
        const c = await svc.start(LIU, PI, { adhoc: true });
        await assert.rejects(svc.reopen(b.occurrence.id, PI), e => e.code === 'another_meeting_in_progress');
        const ab = await svc.abandon(c.occurrence.id, PI, { reason: 'Fire alarm' });
        assert.strictEqual(ab.occurrence.status, 'CANCELLED');
        assert.strictEqual(ab.occurrence.status_note, 'Abandoned session', 'member-visible note is generic');
        assert.ok(ab.occurrence.correction_log.some(e => e.what === 'abandon' && e.reason === 'Fire alarm'), 'reason only in the PI-only log');
        assert.strictEqual(iso(await repo.lastCompletedAt(LIU.id)), startedB.toISOString());
        await assert.rejects(svc.end(c.occurrence.id, PI), e => e.code === 'not_in_progress');
        await assert.rejects(svc.setAttendance(c.occurrence.id, 'L1', 'PRESENT', PI), e => e.code === 'not_editable');

        // --- explicit timestamp correction (reason required, no overlap); logged; only explicit change moves the reference
        await assert.rejects(svc.correctTimes(b.occurrence.id, { startedAt: new Date(startedB - 60000).toISOString() }, PI), e => e.code === 'reason_required');
        await assert.rejects(svc.correctTimes(b.occurrence.id, { startedAt: new Date(startedA.getTime() - 3600e3).toISOString(), reason: 'x' }, PI),
            e => e.code === 'overlaps_another_meeting');
        // (in this test all meetings happen within milliseconds; give them realistic, non-overlapping times)
        const aStart = new Date(Date.now() - 3 * 3600e3), aEnd = new Date(Date.now() - 2 * 3600e3);
        await svc.correctTimes(sched.id, { startedAt: aStart.toISOString(), endedAt: aEnd.toISOString(), reason: 'Recorded late' }, PI);
        assert.strictEqual(iso(await repo.lastCompletedAt(LIU.id)), startedB.toISOString(), 'correcting an older meeting does not move the reference');
        const corrected = new Date(Date.now() - 3600e3);
        await svc.correctTimes(b.occurrence.id, { startedAt: corrected.toISOString(), endedAt: new Date(Date.now() - 1800e3).toISOString(), reason: 'Started a minute earlier' }, PI);
        assert.strictEqual(iso(await repo.lastCompletedAt(LIU.id)), corrected.toISOString(), 'explicit correction of the latest meeting moves it');
        const tlog = (await pool.query(`SELECT correction_log FROM meeting_occurrences WHERE id=$1`, [b.occurrence.id])).rows[0].correction_log.pop();
        assert.strictEqual(tlog.what, 'times');
        assert.strictEqual(tlog.reason, 'Started a minute earlier');
        assert.strictEqual(iso(tlog.from.started_at), startedB.toISOString());

        // --- stale warning is derived only; nothing changes
        await pool.query(`UPDATE meeting_occurrences SET started_at = now() - interval '13 hours' WHERE id=$1`, [unavSession]);
        const sum = await svc.activeSummary(UNAV.id, true);
        assert.strictEqual(sum.stale, true);
        assert.strictEqual(await status(pool, unavSession), 'IN_PROGRESS');

        // --- "restart": a brand-new service instance (and pool) sees the same active meeting
        const pool2 = poolFor('gm_s_life');
        try {
            const svc2 = makeSessionService(pool2);
            assert.strictEqual((await svc2.getActive(UNAV.id)).id, unavSession);
        } finally { await pool2.end(); }

        // --- membership/submission tables untouched by sessions; no FK to submissions
        assert.deepStrictEqual((await pool.query(`SELECT conname FROM pg_constraint WHERE confrelid = 'di_submissions'::regclass`)).rows, []);
        await pool.query(`DELETE FROM di_submissions WHERE original_filename = 'during.pdf'`); // document lifecycle unaffected
        assert.deepStrictEqual(events.filter(e => e === 'meeting.started').length, 5);
    } finally { await pool.end(); }
});

// ------------------------------------------- R3.4 review findings
test('reopened meeting: every change is in the correction log; abandon reason PI-only; lock order', { skip }, async () => {
    const pool = await freshDb('gm_s_audit');
    try {
        await fixture(pool);
        await ensureSchemaIfEnabled(pool, BOTH);
        const svc = makeSessionService(pool);
        const LIU = await groupOf(pool, 'LIU');
        const doc = (await pool.query(`INSERT INTO di_submissions (researcher_id, file_type, original_filename, status, workspace_id)
            VALUES ('L1', 'DATA', 'audit.pdf', 'APPROVED', '${NATLAB_WS}') RETURNING submission_id`)).rows[0].submission_id;
        const m = (await svc.start(LIU, PI, { adhoc: true })).occurrence;
        const pres = await svc.recordEvent(m.id, { submissionId: doc, eventType: 'PRESENTED' }, PI);
        await svc.end(m.id, PI);
        const logOf = async () => (await pool.query(`SELECT correction_log FROM meeting_occurrences WHERE id=$1`, [m.id])).rows[0].correction_log;
        assert.deepStrictEqual(await logOf(), [], 'live meeting changes are not corrections');

        await svc.reopen(m.id, PI);
        await svc.setAttendance(m.id, 'L1', 'PRESENT', PI);
        await svc.updateNotes(m.id, { sharedConclusions: { present: true, value: 'rewritten' } }, PI);
        await svc.voidEvent(m.id, pres.event.id, { reason: 'wrong' }, PI);
        await svc.recordEvent(m.id, { submissionId: doc, eventType: 'DISCUSSED' }, PI);
        await svc.end(m.id, PI, { markRemainingAbsent: true });
        const whats = (await logOf()).map(e => e.what);
        assert.deepStrictEqual(whats, ['reopen', 'attendance', 'shared_conclusions', 'presentation_void', 'presentation_add', 'attendance_bulk', 'complete'],
            'changes made while reopened are logged like historical corrections');
        assert.strictEqual(policyReopened(await logOf()), false, 'ended again');

        // abandon: the free-text reason never reaches the member-visible status note
        const c = (await svc.start(LIU, PI, { adhoc: true })).occurrence;
        const ab = await svc.abandon(c.id, PI, { reason: 'PRIVATE REASON' });
        assert.strictEqual(ab.occurrence.status_note, 'Abandoned session');
        assert.ok(!JSON.stringify((await pool.query(`SELECT status_note FROM meeting_occurrences`)).rows).includes('PRIVATE REASON'));

        // the group lock used by start/reopen/correction never blocks membership changes
        const c1 = await pool.connect(), c2 = await pool.connect();
        try {
            await c1.query('BEGIN');
            await c1.query('SELECT id FROM meeting_groups WHERE id = $1 FOR NO KEY UPDATE', [LIU.id]);
            await c2.query(`SET lock_timeout = '1s'`);
            await c2.query(`INSERT INTO meeting_group_members (meeting_group_id, researcher_id) VALUES ($1, 'L3')`, [LIU.id]);
            await c2.query(`DELETE FROM meeting_group_members WHERE meeting_group_id = $1 AND researcher_id = 'L3'`, [LIU.id]);
        } finally { await c1.query('ROLLBACK'); c1.release(); c2.release(); }
    } finally { await pool.end(); }
});
const policyReopened = (log) => require('../server/meetings/policy').isReopenedSession(log);

// ------------------------------------------------------- HTTP authz
test('HTTP: flags, authorization matrix, private notes never reach members', { skip }, async () => {
    const pool = await freshDb('gm_s_http');
    let server;
    try {
        await fixture(pool);
        assert.strictEqual((await ensureSchemaIfEnabled(pool, BOTH)).sessions, 'ensured');
        let sessionsOn = false;
        const app = express();
        app.use(express.json());
        app.use((req, res, next) => { req.session = { user: req.headers['x-test-user'] ? JSON.parse(req.headers['x-test-user']) : undefined }; next(); });
        app.use('/api/group-meetings', createGroupMeetingsRouter({
            pool, isEnabled: () => true, audience: () => ({ mode: 'members' }), sessionsEnabled: () => sessionsOn,
        }));
        server = http.createServer(app);
        await new Promise(r => server.listen(0, '127.0.0.1', r));
        const base = `http://127.0.0.1:${server.address().port}/api/group-meetings`;
        const U = { PI: { researcher_id: 'PI', role: 'pi' }, L1: { researcher_id: 'L1', role: 'researcher' }, U1: { researcher_id: 'U1', role: 'researcher' },
                    BOT: { researcher_id: 'BOT', role: 'ai_bot' }, OFF: { researcher_id: 'OFF', role: 'researcher' } };
        const call = async (method, p, user, body) => {
            const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json', ...(user ? { 'x-test-user': JSON.stringify(user) } : {}) },
                body: body === undefined ? undefined : JSON.stringify(body) });
            const text = await r.text(); let json = null; try { json = JSON.parse(text); } catch (_) {}
            return { status: r.status, json, text };
        };

        // sessions flag off: R3 endpoints 404, R2 fully operational
        assert.strictEqual((await call('GET', '/groups/LIU/session', U.PI)).status, 404);
        assert.strictEqual((await call('POST', '/admin/groups/LIU/sessions', U.PI, { adhoc: true })).status, 404);
        assert.strictEqual((await call('GET', '/groups/LIU/overview', U.L1)).status, 200);

        sessionsOn = true;
        // start: PI only
        assert.strictEqual((await call('POST', '/admin/groups/LIU/sessions', U.L1, { adhoc: true })).status, 403);
        assert.strictEqual((await call('POST', '/admin/groups/LIU/sessions', U.BOT, { adhoc: true })).status, 403);
        assert.strictEqual((await call('POST', '/admin/groups/LIU/sessions', U.PI, {})).status, 400);
        const st = await call('POST', '/admin/groups/LIU/sessions', U.PI, { adhoc: true });
        assert.strictEqual(st.status, 201);
        const sid = st.json.session.id;
        assert.strictEqual((await call('POST', '/admin/groups/LIU/sessions', U.PI, { adhoc: true })).json.code, 'already_active');

        // notes: private + shared
        assert.strictEqual((await call('PATCH', `/admin/sessions/${sid}/notes`, U.PI, { private_notes: 'TOP-SECRET-PI-NOTE', shared_conclusions: 'Shared conclusion' })).status, 200);

        // member view: active indicator only — no attendance, no notes
        const mem = await call('GET', '/groups/LIU/session', U.L1);
        assert.strictEqual(mem.status, 200);
        assert.strictEqual(mem.json.active.id, sid);
        assert.strictEqual(mem.json.active.attendance, undefined);
        for (const p of ['/groups/LIU/session', '/groups/LIU', '/groups/LIU/overview', '/groups/LIU/occurrences', '/groups/LIU/members/L1/documents', '/me']) {
            const r = await call('GET', p, U.L1);
            assert.ok(!r.text.includes('TOP-SECRET-PI-NOTE') && !r.text.includes('correction_log'), p);
        }
        // PI view includes attendance counts
        assert.deepStrictEqual((await call('GET', '/groups/LIU/session', U.PI)).json.active.attendance, { present: 0, absent: 0, unmarked: 2, total: 2 });
        // non-members, inactive, ai_bot: refused
        assert.strictEqual((await call('GET', '/groups/LIU/session', U.U1)).status, 403);
        assert.strictEqual((await call('GET', '/groups/LIU/session', U.OFF)).status, 403);
        assert.strictEqual((await call('GET', '/groups/LIU/session', U.BOT)).status, 403);
        // every PI session mutation refused for members
        for (const [m, p, body] of [['GET', `/admin/sessions/${sid}`], ['POST', `/admin/sessions/${sid}/end`, { confirm: true }],
            ['POST', `/admin/sessions/${sid}/abandon`, { confirm: true }], ['POST', `/admin/sessions/${sid}/reopen`, { confirm: true }],
            ['PUT', `/admin/sessions/${sid}/attendance/L1`, { status: 'PRESENT' }], ['POST', `/admin/sessions/${sid}/attendance/bulk`, { action: 'all_present' }],
            ['POST', `/admin/sessions/${sid}/attendance`, { researcher_id: 'L1' }], ['PATCH', `/admin/sessions/${sid}/notes`, { private_notes: 'x' }],
            ['PATCH', `/admin/sessions/${sid}/times`, { reason: 'x' }]]) {
            assert.strictEqual((await call(m, p, U.L1, body)).status, 403, `${m} ${p}`);
        }
        // attendance + explicit confirmation required
        assert.strictEqual((await call('PUT', `/admin/sessions/${sid}/attendance/L1`, U.PI, { status: 'PRESENT' })).json.status, 'PRESENT');
        assert.strictEqual((await call('POST', `/admin/sessions/${sid}/end`, U.PI, {})).status, 400);
        // flag disabled mid-meeting: endpoints 404, meeting untouched; re-enabled: resumes
        sessionsOn = false;
        assert.strictEqual((await call('GET', '/groups/LIU/session', U.PI)).status, 404);
        assert.strictEqual(await status(pool, sid), 'IN_PROGRESS');
        sessionsOn = true;
        assert.strictEqual((await call('GET', '/groups/LIU/session', U.PI)).json.active.id, sid);
        // end: summary with unmarked count
        const end = await call('POST', `/admin/sessions/${sid}/end`, U.PI, { confirm: true });
        assert.strictEqual(end.status, 200);
        assert.strictEqual(end.json.unmarked, 1);
        assert.strictEqual((await call('GET', '/groups/LIU/session', U.L1)).json.active, null);
        // PI detail has roster + log; invalid ids 404
        const det = await call('GET', `/admin/sessions/${sid}`, U.PI);
        assert.deepStrictEqual(det.json.roster.map(r => [r.researcher_id, r.status]), [['L1', 'PRESENT'], ['L2', 'UNMARKED']]);
        assert.strictEqual(det.json.session.private_notes, 'TOP-SECRET-PI-NOTE');
        assert.strictEqual((await call('GET', `/admin/sessions/not-a-uuid`, U.PI)).status, 404);
        // R2 still works with sessions on: "since last meeting" now uses the completed meeting's start
        const ov = await call('GET', '/groups/LIU/overview', U.L1);
        assert.strictEqual(ov.json.new_window.fallback, false);
        assert.strictEqual(ov.json.new_window.since, st.json.session.started_at);
    } finally {
        if (server) await new Promise(r => server.close(r));
        await pool.end();
    }
});
