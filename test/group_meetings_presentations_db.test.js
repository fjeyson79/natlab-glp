// Group Meetings R3.2 — presented / discussed records, Last presented and
// meeting history, against an ISOLATED LOCAL PostgreSQL (skipped otherwise).
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const express = require('express');
const { Pool } = require('pg');
const { makeRepo } = require('../server/meetings/repo');
const { makeSessionService } = require('../server/meetings/sessions');
const { createGroupMeetingsRouter, ensureSchemaIfEnabled } = require('../server/meetings');

const HOST = process.env.GM_TEST_PGHOST || '';
const LOCAL = HOST.startsWith('/');
const skip = LOCAL ? false : 'set GM_TEST_PGHOST to a local Unix-socket directory to run database tests';
const PORT = Number(process.env.GM_TEST_PGPORT || 5432);
const NATLAB_WS = '43a32f1d-8ff1-465b-9231-c366fafcec70';
const BOTH = { GROUP_MEETINGS_ENABLED: 'true', GROUP_MEETINGS_SESSIONS_ENABLED: 'true' };
const PI = { id: 'PI', isPi: true };

async function freshDb(name) {
    if (!LOCAL) throw new Error('refusing non-local database');
    const admin = new Pool({ host: HOST, user: 'postgres', database: 'postgres', port: PORT });
    await admin.query(`DROP DATABASE IF EXISTS ${name}`); await admin.query(`CREATE DATABASE ${name}`); await admin.end();
    return new Pool({ host: HOST, user: 'postgres', database: name, port: PORT, max: 10 });
}
async function fixture(pool) {
    await pool.query(`
        CREATE TABLE di_allowlist (researcher_id VARCHAR(50) PRIMARY KEY, name VARCHAR(255) NOT NULL, institution_email VARCHAR(255),
            affiliation VARCHAR(20), role VARCHAR(20), active BOOLEAN DEFAULT TRUE);
        CREATE TABLE workspaces (id UUID PRIMARY KEY, slug TEXT UNIQUE, is_active BOOLEAN DEFAULT TRUE, workspace_type TEXT);
        CREATE TABLE workspace_users (id SERIAL PRIMARY KEY, workspace_id UUID, user_id TEXT, membership_class TEXT DEFAULT 'core', is_active BOOLEAN DEFAULT TRUE);
        CREATE TABLE di_submissions (submission_id UUID PRIMARY KEY DEFAULT gen_random_uuid(), researcher_id VARCHAR(50) NOT NULL,
            affiliation VARCHAR(20), file_type VARCHAR(20) NOT NULL, original_filename VARCHAR(500) NOT NULL, status VARCHAR(20) DEFAULT 'PENDING',
            signed_at TIMESTAMP, created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP, r2_object_key TEXT, workspace_id UUID);
        INSERT INTO workspaces VALUES ('${NATLAB_WS}', 'natlab', TRUE, 'LAB');
        INSERT INTO di_allowlist VALUES ('PI','Principal','pi@x','LiU','pi',TRUE), ('BOT','Bot','b@x','LiU','ai_bot',TRUE),
            ('L1','Anna Liu','l1@x','LiU','researcher',TRUE), ('L2','Bo Liu','l2@x','LiU','supervisor',TRUE),
            ('L3','Cai Liu','l3@x','LiU','researcher',TRUE), ('U1','Carla Unav','u1@x','UNAV','researcher',TRUE);
        CREATE TABLE meeting_groups (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), name VARCHAR(200) NOT NULL, site VARCHAR(100),
            default_day INTEGER, default_time TIME DEFAULT '09:00', location TEXT, is_active BOOLEAN NOT NULL DEFAULT true,
            created_at TIMESTAMPTZ NOT NULL DEFAULT now(), updated_at TIMESTAMPTZ NOT NULL DEFAULT now());
        CREATE UNIQUE INDEX uq_meeting_groups_name ON meeting_groups(name);
        INSERT INTO meeting_groups (name, site) VALUES ('LiU Weekly Meeting','LiU'), ('UNAV Weekly Meeting','UNAV'), ('LiU-UNAV Meeting','LiU-UNAV');
        CREATE TABLE meeting_group_members (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), meeting_group_id UUID NOT NULL REFERENCES meeting_groups(id) ON DELETE CASCADE,
            researcher_id VARCHAR(100) NOT NULL, can_deep BOOLEAN NOT NULL DEFAULT false, can_focus BOOLEAN NOT NULL DEFAULT true,
            can_flash BOOLEAN NOT NULL DEFAULT true, created_at TIMESTAMPTZ NOT NULL DEFAULT now());
        CREATE UNIQUE INDEX uq_meeting_group_members ON meeting_group_members(meeting_group_id, researcher_id);
        INSERT INTO meeting_group_members (meeting_group_id, researcher_id) SELECT id, r FROM meeting_groups, (VALUES ('L1'),('L2')) v(r) WHERE name='LiU Weekly Meeting';
        INSERT INTO meeting_group_members (meeting_group_id, researcher_id) SELECT id, r FROM meeting_groups, (VALUES ('L1'),('U1')) v(r) WHERE name='LiU-UNAV Meeting';
    `);
    const ins = async (owner, type, status, name) => (await pool.query(
        `INSERT INTO di_submissions (researcher_id, file_type, original_filename, status, workspace_id) VALUES ($1,$2,$3,$4,'${NATLAB_WS}') RETURNING submission_id`,
        [owner, type, name, status])).rows[0].submission_id;
    return {
        l1Data: await ins('L1', 'DATA', 'APPROVED', 'L1-data.pdf'),
        l1Pres: await ins('L1', 'PRESENTATION', 'PENDING', 'L1-slides.pdf'),
        l2Sop: await ins('L2', 'SOP', 'APPROVED', 'L2-sop.pdf'),
        l1Report: await ins('L1', 'REPORT', 'APPROVED', 'L1-report.pdf'),
        u1Data: await ins('U1', 'DATA', 'APPROVED', 'U1-data.pdf'),
    };
}
const g = async (pool, code) => (await pool.query(`SELECT * FROM meeting_groups WHERE code=$1`, [code])).rows[0];
const iso = (t) => (t ? new Date(t).toISOString() : null);

test('presentations: one click, idempotency, presenter rules, Last presented by meeting date, corrections, history', { skip }, async () => {
    const pool = await freshDb('gm_p_core');
    try {
        const D = await fixture(pool);
        assert.strictEqual((await ensureSchemaIfEnabled(pool, BOTH)).sessions, 'ensured');
        const repo = makeRepo(pool);
        const svc = makeSessionService(pool);
        const LIU = await g(pool, 'LIU'), JOINT = await g(pool, 'JOINT');

        // no time fields of any kind for presentations
        const cols = (await pool.query(`SELECT column_name FROM information_schema.columns WHERE table_name='meeting_document_events' ORDER BY ordinal_position`)).rows.map(r => r.column_name);
        assert.deepStrictEqual(cols, ['id', 'occurrence_id', 'submission_id', 'owner_researcher_id', 'event_type', 'presenter_researcher_id', 'comment',
            'created_by', 'created_at', 'updated_by', 'updated_at', 'voided_by', 'voided_at', 'void_reason']);
        assert.deepStrictEqual((await pool.query(`SELECT conname FROM pg_constraint WHERE confrelid = 'di_submissions'::regclass`)).rows, []);

        // --- meeting A (LIU)
        const A = (await svc.start(LIU, PI, { adhoc: true })).occurrence;
        // one click: presenter defaults to the owner
        const p1 = await svc.recordEvent(A.id, { submissionId: D.l1Data, eventType: 'PRESENTED' }, PI);
        assert.strictEqual(p1.created, true);
        assert.strictEqual(p1.event.presenter_researcher_id, 'L1');
        // repeated click / retry: same record
        const again = await svc.recordEvent(A.id, { submissionId: D.l1Data, eventType: 'PRESENTED' }, PI);
        assert.strictEqual(again.created, false);
        assert.strictEqual(again.event.id, p1.event.id);
        // concurrent clicks on another document: exactly one record
        await Promise.all(Array.from({ length: 6 }, () => svc.recordEvent(A.id, { submissionId: D.l1Pres, eventType: 'PRESENTED' }, PI)));
        assert.strictEqual((await pool.query(`SELECT COUNT(*)::int n FROM meeting_document_events WHERE submission_id=$1`, [D.l1Pres])).rows[0].n, 1);
        // presenter may differ from the owner (L2 presents L1's work); must be in the roster
        await assert.rejects(svc.recordEvent(A.id, { submissionId: D.l2Sop, eventType: 'PRESENTED', presenterId: 'U1' }, PI), e => e.code === 'presenter_not_in_roster');
        const p3 = await svc.recordEvent(A.id, { submissionId: D.l2Sop, eventType: 'PRESENTED', presenterId: 'L1', comment: 'PI-PRIVATE-COMMENT' }, PI);
        assert.strictEqual(p3.event.owner_researcher_id, 'L2');
        assert.strictEqual(p3.event.presenter_researcher_id, 'L1');
        // Discussed is independent; may have no presenter
        const d1 = await svc.recordEvent(A.id, { submissionId: D.l1Data, eventType: 'DISCUSSED' }, PI);
        assert.strictEqual(d1.created, true);
        assert.strictEqual(d1.event.presenter_researcher_id, null);
        // only documents currently listed in this group
        await assert.rejects(svc.recordEvent(A.id, { submissionId: D.l1Report, eventType: 'PRESENTED' }, PI), e => e.code === 'document_not_listed');
        await assert.rejects(svc.recordEvent(A.id, { submissionId: D.u1Data, eventType: 'PRESENTED' }, PI), e => e.code === 'document_not_listed');
        await assert.rejects(svc.recordEvent(A.id, { submissionId: D.l1Data, eventType: 'VIEWED' }, PI), e => e.code === 'invalid_event_type');

        // Last presented = MEETING DATE, live during the meeting; several documents -> same date
        const lpA = await repo.lastPresentedByResearcher(LIU.id);
        assert.strictEqual(iso(lpA.get('L1')), iso(A.started_at));
        assert.strictEqual(lpA.has('L2'), false, 'owner of a document presented by someone else did not present');
        // per group: nothing in JOINT
        assert.strictEqual((await repo.lastPresentedByResearcher(JOINT.id)).size, 0);
        // meeting status of documents
        const ms = await repo.documentMeetingStatus(LIU.id, [D.l1Data, D.l2Sop]);
        assert.strictEqual(ms.get(D.l1Data).presented_in_session, true);
        assert.strictEqual(ms.get(D.l1Data).discussed_in_session, true);
        assert.strictEqual(ms.get(D.l2Sop).last_presenter_name, 'Anna Liu');
        await svc.updateNotes(A.id, { sharedConclusions: { present: true, value: 'Shared conclusion A' }, privateNotes: { present: true, value: 'PI-PRIVATE-NOTE' } }, PI);
        await svc.end(A.id, PI);

        // --- abandoned meeting C: its presentations never count
        const C = (await svc.start(LIU, PI, { adhoc: true })).occurrence;
        await svc.recordEvent(C.id, { submissionId: D.l2Sop, eventType: 'PRESENTED' }, PI); // L2 presents
        assert.strictEqual(iso((await repo.lastPresentedByResearcher(LIU.id)).get('L2')), iso(C.started_at), 'live during the meeting');
        await svc.abandon(C.id, PI, {});
        assert.strictEqual((await repo.lastPresentedByResearcher(LIU.id)).has('L2'), false, 'abandoned meeting excluded');

        // --- meeting B later; then a RETROSPECTIVE record on completed A keeps A's date
        const B = (await svc.start(LIU, PI, { adhoc: true })).occurrence;
        await svc.end(B.id, PI);
        const retro = await svc.recordEvent(A.id, { submissionId: D.l2Sop, eventType: 'DISCUSSED' }, PI);
        assert.strictEqual(retro.created, true);
        const retroP = await svc.recordEvent(A.id, { submissionId: D.l2Sop, eventType: 'PRESENTED', presenterId: 'L2' }, PI)
            .catch(e => e); // l2Sop already PRESENTED in A (by L1) -> idempotent existing record
        assert.strictEqual(retroP.created, false);
        // correct the presenter of that record (L1 -> L2) retrospectively; Last presented follows
        await svc.updateEvent(A.id, p3.event.id, { presenterId: 'L2' }, PI);
        assert.strictEqual(iso((await repo.lastPresentedByResearcher(LIU.id)).get('L2')), iso(A.started_at), 'retrospective = original meeting date');
        // invalidate L1's records in A -> L1 never presented
        await svc.voidEvent(A.id, p1.event.id, { reason: 'Recorded by mistake' }, PI);
        const l1Pres = (await pool.query(`SELECT id FROM meeting_document_events WHERE submission_id=$1 AND event_type='PRESENTED'`, [D.l1Pres])).rows[0].id;
        await svc.voidEvent(A.id, l1Pres, {}, PI);
        assert.strictEqual((await svc.voidEvent(A.id, l1Pres, {}, PI)).changed, false, 'void is idempotent');
        assert.strictEqual((await repo.lastPresentedByResearcher(LIU.id)).has('L1'), false);
        // a voided record can be re-confirmed (new valid record)
        assert.strictEqual((await svc.recordEvent(A.id, { submissionId: D.l1Data, eventType: 'PRESENTED' }, PI)).created, true);
        // corrections on completed A are logged (no text copies)
        const log = (await pool.query(`SELECT correction_log FROM meeting_occurrences WHERE id=$1`, [A.id])).rows[0].correction_log.map(e => e.what);
        assert.deepStrictEqual(log, ['presentation_add', 'presenter', 'presentation_void', 'presentation_void', 'presentation_add']);
        // corrections never move "since last meeting"
        assert.strictEqual(iso(await repo.lastCompletedAt(LIU.id)), iso(B.started_at));

        // --- history: completed only, newest first
        const h = await svc.history(LIU.id, { limit: 10 });
        assert.deepStrictEqual(h.rows.map(r => r.id), [B.id, A.id]);
        // A: valid PRESENTED = l1Data (re-confirmed) + l2Sop; voided ones excluded. DISCUSSED = l1Data + l2Sop.
        assert.deepStrictEqual([h.rows[1].presented, h.rows[1].discussed], [2, 2]);
        // member view vs PI view
        const member = await svc.historyDetail(LIU.id, A.id, { id: 'L2', isPi: false });
        const memberText = JSON.stringify(member);
        assert.ok(!memberText.includes('PI-PRIVATE-NOTE') && !memberText.includes('PI-PRIVATE-COMMENT'));
        assert.strictEqual(member.attendance, undefined);
        assert.strictEqual(member.correction_log, undefined);
        assert.strictEqual(member.shared_conclusions, 'Shared conclusion A');
        assert.ok(member.presentations.every(p => p.event_id === undefined && p.comment === undefined));
        assert.strictEqual(member.presentations.length, 2, 'voided records hidden from members');
        const sop = member.presentations.find(p => p.document && p.document.title === 'L2-sop.pdf');
        assert.strictEqual(sop.presenter_name, 'Bo Liu');
        assert.strictEqual(sop.document.can_open, true, 'L2 owns it');
        assert.strictEqual(member.presentations.find(p => p.document && p.document.title === 'L1-data.pdf').document.can_open, false, 'not the owner');
        const pi = await svc.historyDetail(LIU.id, A.id, PI);
        assert.strictEqual(pi.private_notes, 'PI-PRIVATE-NOTE');
        assert.ok(pi.presentations.some(p => p.voided));
        assert.ok(pi.presentations.some(p => p.comment === 'PI-PRIVATE-COMMENT'));
        assert.ok(Array.isArray(pi.attendance) && pi.attendance.length === 2);
        // document deleted later: event preserved, "no longer available", no id/metadata for members
        await pool.query(`DELETE FROM di_submissions WHERE submission_id=$1`, [D.l2Sop]);
        const after = await svc.historyDetail(LIU.id, A.id, { id: 'L1', isPi: false });
        const gone = after.presentations.find(p => p.presenter_name === 'Bo Liu');
        assert.strictEqual(gone.document, null);
        assert.strictEqual(gone.owner_name, null, 'no owner metadata for an unlisted document (members)');
        assert.ok(!JSON.stringify(after).includes(D.l2Sop));
        assert.strictEqual((await svc.historyDetail(LIU.id, A.id, PI)).presentations.find(p => p.submission_id === D.l2Sop).document, null);
        // cancelled/abandoned meetings are not history; unknown/other-group ids 404
        await assert.rejects(svc.historyDetail(LIU.id, C.id, PI), e => e.httpStatus === 404);
        await assert.rejects(svc.historyDetail(JOINT.id, A.id, PI), e => e.httpStatus === 404);
    } finally { await pool.end(); }
});

test('HTTP: Last presented / meeting_status only with sessions; event routes PI-only; history uses current membership', { skip }, async () => {
    const pool = await freshDb('gm_p_http');
    let server;
    try {
        const D = await fixture(pool);
        assert.strictEqual((await ensureSchemaIfEnabled(pool, BOTH)).sessions, 'ensured');
        let sessionsOn = true;
        const app = express();
        app.use(express.json());
        app.use((req, res, next) => { req.session = { user: req.headers['x-test-user'] ? JSON.parse(req.headers['x-test-user']) : undefined }; next(); });
        app.use('/api/group-meetings', createGroupMeetingsRouter({ pool, isEnabled: () => true, audience: () => ({ mode: 'members' }), sessionsEnabled: () => sessionsOn }));
        server = http.createServer(app);
        await new Promise(r => server.listen(0, '127.0.0.1', r));
        const base = `http://127.0.0.1:${server.address().port}/api/group-meetings`;
        const U = { PI: { researcher_id: 'PI', role: 'pi' }, L1: { researcher_id: 'L1', role: 'researcher' }, L2: { researcher_id: 'L2', role: 'supervisor' },
                    U1: { researcher_id: 'U1', role: 'researcher' }, BOT: { researcher_id: 'BOT', role: 'ai_bot' } };
        const call = async (method, p, user, body) => {
            const r = await fetch(base + p, { method, headers: { 'content-type': 'application/json', ...(user ? { 'x-test-user': JSON.stringify(user) } : {}) },
                body: body === undefined ? undefined : JSON.stringify(body) });
            const t = await r.text(); let j = null; try { j = JSON.parse(t); } catch (_) {}
            return { status: r.status, json: j, text: t };
        };
        const sid = (await call('POST', '/admin/groups/LIU/sessions', U.PI, { adhoc: true })).json.session.id;
        // one-click confirm (PI); members/ai_bot refused
        const ev = await call('POST', `/admin/sessions/${sid}/events`, U.PI, { submission_id: D.l1Data, event_type: 'PRESENTED', comment: 'SECRET-COMMENT' });
        assert.strictEqual(ev.status, 201);
        assert.strictEqual((await call('POST', `/admin/sessions/${sid}/events`, U.PI, { submission_id: D.l1Data, event_type: 'PRESENTED' })).status, 200, 'retry = existing');
        for (const u of [U.L1, U.L2, U.BOT]) {
            assert.strictEqual((await call('POST', `/admin/sessions/${sid}/events`, u, { submission_id: D.l1Data, event_type: 'DISCUSSED' })).status, 403);
            assert.strictEqual((await call('PATCH', `/admin/sessions/${sid}/events/${ev.json.event.id}`, u, { presenter_researcher_id: 'L2' })).status, 403);
            assert.strictEqual((await call('DELETE', `/admin/sessions/${sid}/events/${ev.json.event.id}`, u, {})).status, 403);
        }
        // overview Last presented + documents meeting_status (members see facts, never comments)
        const ov = await call('GET', '/groups/LIU/overview', U.L2);
        assert.strictEqual(ov.json.last_presented_available, true);
        assert.ok(ov.json.researchers.find(r => r.researcher_id === 'L1').last_presented);
        assert.strictEqual(ov.json.researchers.find(r => r.researcher_id === 'L2').last_presented, null);
        const docs = await call('GET', '/groups/LIU/members/L1/documents?filter=all', U.L2);
        assert.strictEqual(docs.json.documents.find(d => d.submission_id === D.l1Data).meeting_status.presented_in_session, true);
        assert.ok(!docs.text.includes('SECRET-COMMENT'));
        await call('POST', `/admin/sessions/${sid}/end`, U.PI, { confirm: true });
        // history: member list + detail, no private data
        const hist = await call('GET', '/groups/LIU/history', U.L2);
        assert.strictEqual(hist.status, 200);
        assert.strictEqual(hist.json.meetings.length, 1);
        assert.strictEqual(hist.json.meetings[0].presented, 1);
        const det = await call('GET', `/groups/LIU/history/${sid}`, U.L2);
        assert.ok(!det.text.includes('SECRET-COMMENT') && !det.text.includes('correction_log') && det.json.attendance === undefined);
        assert.strictEqual(det.json.presentations[0].presenter_name, 'Anna Liu');
        assert.ok((await call('GET', `/groups/LIU/history/${sid}`, U.PI)).text.includes('SECRET-COMMENT'));
        // non-members and ai_bot refused; a researcher REMOVED from the group loses history access
        assert.strictEqual((await call('GET', '/groups/LIU/history', U.U1)).status, 403);
        assert.strictEqual((await call('GET', '/groups/LIU/history', U.BOT)).status, 403);
        await pool.query(`DELETE FROM meeting_group_members WHERE researcher_id='L2' AND meeting_group_id=(SELECT id FROM meeting_groups WHERE code='LIU')`);
        assert.strictEqual((await call('GET', `/groups/LIU/history/${sid}`, U.L2)).status, 403);
        assert.strictEqual((await call('GET', '/groups/LIU/history', U.PI, undefined)).status, 200);
        assert.strictEqual((await call('GET', '/groups/LIU/history?cursor=bad', U.PI)).status, 400);
        // sessions flag off: R2 unchanged (no Last presented, meeting_status null), R3 routes 404
        sessionsOn = false;
        const ov2 = await call('GET', '/groups/LIU/overview', U.L1);
        assert.strictEqual(ov2.json.last_presented_available, false);
        assert.ok(ov2.json.researchers.every(r => r.last_presented === null));
        assert.ok((await call('GET', '/groups/LIU/members/L1/documents', U.L1)).json.documents.every(d => d.meeting_status === null));
        assert.strictEqual((await call('GET', '/groups/LIU/history', U.PI)).status, 404);
    } finally {
        if (server) await new Promise(r => server.close(r));
        await pool.end();
    }
});
