// Group Meetings R1 — HTTP-level tests of the real router with an in-memory
// repository (same policy rules), a fake session layer and MOCKED storage.
// No database, no Cloudflare R2, no network.
const test = require('node:test');
const assert = require('node:assert');
const http = require('node:http');
const express = require('express');
const policy = require('../server/meetings/policy');
const { createGroupMeetingsRouter, isFeatureEnabled } = require('../server/meetings');

// ----------------------------------------------------------- fixture data
function makeData() {
    const accounts = {
        PI:  { role: 'pi', active: true, name: 'PI', affiliation: 'LiU' },
        BOT: { role: 'ai_bot', active: true, name: 'Bot', affiliation: 'LiU' },
        L1:  { role: 'researcher', active: true, name: 'Liu One', affiliation: 'LiU' },
        L2:  { role: 'supervisor', active: true, name: 'Liu Two', affiliation: 'LiU' },
        U1:  { role: 'researcher', active: true, name: 'Unav One', affiliation: 'UNAV' },
        J1:  { role: 'researcher', active: true, name: 'Joint One', affiliation: 'UNAV' },
        COL: { role: 'researcher', active: true, name: 'Collab', affiliation: 'LiU', membership_class: 'collaborator' },
        OFF: { role: 'researcher', active: false, name: 'Inactive', affiliation: 'LiU' },
        EXT: { role: 'researcher', active: true, name: 'External', affiliation: 'EXTERNAL' },
    };
    const groups = [
        { id: '11111111-1111-4111-8111-111111111111', code: 'LIU', name: 'LiU Weekly Meeting', site: 'LiU', is_active: true, timezone: 'Europe/Stockholm', zoom_join_url: 'https://liu-se.zoom.us/j/111' },
        { id: '22222222-2222-4222-8222-222222222222', code: 'UNAV', name: 'UNAV Weekly Meeting', site: 'UNAV', is_active: true, timezone: 'Europe/Stockholm', zoom_join_url: null },
        { id: '33333333-3333-4333-8333-333333333333', code: 'JOINT', name: 'LiU-UNAV Meeting', site: 'LiU-UNAV', is_active: true, timezone: 'Europe/Stockholm', zoom_join_url: 'https://zoom.us/j/333' },
        { id: '44444444-4444-4444-8444-444444444444', code: null, name: 'Old group', site: null, is_active: true, timezone: 'Europe/Stockholm', zoom_join_url: null },
    ];
    const members = new Set([
        `${groups[0].id}:L1`, `${groups[0].id}:L2`, `${groups[0].id}:OFF`,
        `${groups[1].id}:U1`,
        `${groups[2].id}:L1`, `${groups[2].id}:J1`,
    ]);
    let n = 0;
    const id = () => `aaaaaaaa-0000-4000-8000-${String(++n).padStart(12, '0')}`;
    const recent = new Date(Date.now() - 2 * 86400000);
    const old = new Date('2024-03-01T10:00:00Z');
    const docs = [
        { submission_id: id(), researcher_id: 'L2', file_type: 'DATA', status: 'APPROVED', original_filename: 'L2-approved-data.pdf', created_at: recent, r2_object_key: 'k1' },
        { submission_id: id(), researcher_id: 'L2', file_type: 'SOP', status: 'PENDING', original_filename: 'L2-pending-sop.pdf', created_at: recent, r2_object_key: 'k2' },
        { submission_id: id(), researcher_id: 'L2', file_type: 'REPORT', status: 'APPROVED', original_filename: 'L2-SECRET-report.pdf', created_at: recent, r2_object_key: 'k3' },
        { submission_id: id(), researcher_id: 'L2', file_type: 'PRESENTATION', status: 'DISCARDED', original_filename: 'L2-SECRET-discarded.pdf', created_at: recent, r2_object_key: 'k4' },
        { submission_id: id(), researcher_id: 'L2', file_type: 'PRES', status: 'APPROVED', original_filename: 'L2-old-pres.pdf', created_at: old, r2_object_key: 'k5', record_origin: 'legacy_pre2026', legacy_pack_id: 'p1' },
        { submission_id: id(), researcher_id: 'L1', file_type: 'DATA', status: 'PENDING', original_filename: 'L1-own-pending.pdf', created_at: recent, r2_object_key: 'k6' },
        { submission_id: id(), researcher_id: 'U1', file_type: 'DATA', status: 'APPROVED', original_filename: 'U1-SECRET-unav.pdf', created_at: recent, r2_object_key: 'k7' },
        { submission_id: id(), researcher_id: 'OFF', file_type: 'DATA', status: 'APPROVED', original_filename: 'OFF-SECRET-inactive.pdf', created_at: recent, r2_object_key: 'k8' },
        { submission_id: id(), researcher_id: 'L2', file_type: 'DATA', status: 'APPROVED', original_filename: 'L2-SECRET-otherws.pdf', created_at: recent, r2_object_key: 'k9', workspace: 'theralia' },
    ];
    return { accounts, groups, members, docs, occurrences: [], ids: id };
}

function makeFakeRepo(d) {
    const acc = (rid) => d.accounts[rid];
    const isMember = (gid, rid) => d.members.has(`${gid}:${rid}`) && policy.isMembershipEligibleAccount(acc(rid) && { ...acc(rid), researcher_id: rid });
    const listed = (gid, doc) => policy.isListableDocument({ ...doc, in_natlab_workspace: (doc.workspace || 'natlab') === 'natlab' },
        { ownerIsMember: isMember(gid, doc.researcher_id), actorCanAccessGroup: true });
    const calls = [];
    const repo = {
        async getAccount(rid) { const a = acc(rid); return a ? { researcher_id: rid, role: a.role, active: a.active } : null; },
        async getGroupByCode(code, { includeInactive } = {}) { return d.groups.find(g => g.code === code && (includeInactive || g.is_active)) || null; },
        async listGroupsForActor(actor) {
            return d.groups.filter(g => g.code && g.is_active && (actor.isPi || isMember(g.id, actor.id)));
        },
        async isMember(gid, rid) { return isMember(gid, rid); },
        async lastCompletedAt(gid) {
            const c = d.occurrences.filter(o => o.meeting_group_id === gid && o.status === 'COMPLETED').map(o => o.ended_at);
            return c.length ? new Date(Math.max(...c.map(x => +x))) : null;
        },
        async weekStart() { return new Date(Date.now() - 3 * 86400000); },
        async isValidTimezone(tz) { return ['Europe/Stockholm', 'Europe/Madrid'].includes(tz); },
        async overview(gid, since) {
            return Object.keys(d.accounts).filter(rid => isMember(gid, rid)).map(rid => {
                const mine = d.docs.filter(x => x.researcher_id === rid && listed(gid, x));
                return {
                    researcher_id: rid, name: acc(rid).name,
                    last_upload: mine.length ? new Date(Math.max(...mine.map(x => +x.created_at))) : null,
                    new_count: mine.filter(x => x.created_at > since).length, total_count: mine.length,
                };
            });
        },
        async listDocuments(gid, owner, since, limit, cursor) {
            const all = d.docs.filter(x => x.researcher_id === owner && listed(gid, x) && (!since || x.created_at >= since))
                .map(x => ({ ...x, sort_ts: x.created_at.toISOString().slice(0, 23) }))
                .sort((a, b) => (b.sort_ts.localeCompare(a.sort_ts)) || b.submission_id.localeCompare(a.submission_id));
            const after = cursor ? all.filter(x => x.sort_ts < cursor.t || (x.sort_ts === cursor.t && x.submission_id < cursor.id)) : all;
            return after.slice(0, limit);
        },
        async countDocuments(gid, owner, since) {
            return d.docs.filter(x => x.researcher_id === owner && listed(gid, x) && (!since || x.created_at >= since)).length;
        },
        async getListedDocument(gid, sid) {
            const x = d.docs.find(y => y.submission_id === sid);
            return x && listed(gid, x) ? x : null;
        },
        async listAllGroups() { return d.groups.map(g => ({ ...g, member_count: 0 })); },
        async getGroupById(gid) { return d.groups.find(g => g.id === gid) || null; },
        async assignCode(gid, code) {
            if (d.groups.some(g => g.code === code)) { const e = new Error('dup'); e.code = '23505'; throw e; }
            const g = d.groups.find(x => x.id === gid && !x.code); if (!g) return null; g.code = code; return g;
        },
        async updateSettings(gid, fields) { const g = d.groups.find(x => x.id === gid); Object.assign(g, fields); return g; },
        async membershipCandidates() { return []; },
        async addMember(gid, rid) { const k = `${gid}:${rid}`; const had = d.members.has(k); d.members.add(k); return !had; },
        async removeMember(gid, rid) { return d.members.delete(`${gid}:${rid}`); },
        async membershipClass(rid) { return (acc(rid) && acc(rid).membership_class) || 'core'; },
        async getAffiliation(rid) { return acc(rid) ? acc(rid).affiliation : null; },
        async listOccurrences(gid) { return d.occurrences.filter(o => o.meeting_group_id === gid); },
        async nextScheduled() { return null; },
        async getOccurrence(oid) {
            const o = d.occurrences.find(x => x.id === oid); if (!o) return null;
            return { ...o, group_code: d.groups.find(g => g.id === o.meeting_group_id).code };
        },
        async insertOccurrence({ groupId, scheduledStart, durationMinutes, note, actorId }) {
            if (d.occurrences.some(o => o.meeting_group_id === groupId && +new Date(o.scheduled_start) === +new Date(scheduledStart) && o.status !== 'CANCELLED')) {
                const e = new Error('dup'); e.code = '23505'; throw e;
            }
            const o = { id: d.ids(), meeting_group_id: groupId, scheduled_start: scheduledStart, duration_minutes: durationMinutes, status: 'SCHEDULED', status_note: note, created_by: actorId };
            d.occurrences.push(o); return o;
        },
        async transitionOccurrence({ id: oid, fromStatus, toStatus, scheduledStart, note }) {
            const o = d.occurrences.find(x => x.id === oid && x.status === fromStatus); if (!o) return null;
            o.status = toStatus; if (scheduledStart) o.scheduled_start = scheduledStart; o.status_note = note; return o;
        },
    };
    // record every call so tests can assert "no data access" when disabled
    for (const k of Object.keys(repo)) { const f = repo[k]; repo[k] = (...a) => { calls.push(k); return f(...a); }; }
    return { repo, calls };
}

// --------------------------------------------------------------- harness
async function startApp({ enabled = true, ready = true, data = makeData(), events = [], audience = { mode: 'members' } } = {}) {
    const { repo, calls } = makeFakeRepo(data);
    const storage = { calls: [] };
    const app = express();
    app.use(express.json());
    // Fake session: tests choose the authenticated session user via header.
    app.use((req, res, next) => {
        const h = req.headers['x-test-user'];
        req.session = h ? { user: JSON.parse(h) } : {};
        next();
    });
    // Stand-in for server.js requireSameOrigin: blocks writes without the marker.
    const requireSameOrigin = (req, res, next) =>
        (req.method === 'GET' || req.headers['x-test-same-origin'] === '1') ? next() : res.status(403).json({ error: 'Cross-site request blocked' });
    app.use('/api/group-meetings', createGroupMeetingsRouter({
        pool: null, repo,
        isEnabled: () => enabled,
        audience: () => audience,
        schemaReady: async () => ready,
        requireSameOrigin,
        normalizeR2Key: (k) => k,
        r2Enabled: () => true,
        downloadFromR2: async (key) => { storage.calls.push(key); return { ContentType: 'application/pdf', Body: Buffer.from('%PDF-mock ' + key) }; },
        onOccurrenceEvent: (e) => events.push(e),
    }));
    const server = http.createServer(app);
    await new Promise(r => server.listen(0, '127.0.0.1', r));
    const base = `http://127.0.0.1:${server.address().port}/api/group-meetings`;
    const call = async (method, path, { user, body, sameOrigin = true } = {}) => {
        const headers = { 'content-type': 'application/json' };
        if (user) headers['x-test-user'] = JSON.stringify(user);
        if (sameOrigin) headers['x-test-same-origin'] = '1';
        const r = await realFetch(base + path, { method, headers, body: body === undefined ? undefined : JSON.stringify(body) });
        const text = await r.text();
        let json = null; try { json = JSON.parse(text); } catch (_) {}
        return { status: r.status, json, text, headers: r.headers };
    };
    return { call, data, calls, storage, events, close: () => new Promise(r => server.close(r)) };
}

const U = {
    PI: { researcher_id: 'PI', role: 'pi' }, BOT: { researcher_id: 'BOT', role: 'ai_bot' },
    L1: { researcher_id: 'L1', role: 'researcher' }, L2: { researcher_id: 'L2', role: 'supervisor' },
    U1: { researcher_id: 'U1', role: 'researcher' }, J1: { researcher_id: 'J1', role: 'researcher' },
    COL: { researcher_id: 'COL', role: 'researcher' }, OFF: { researcher_id: 'OFF', role: 'researcher' },
};

// Any outbound call (Zoom, Resend, anything) fails the test run.
const realFetch = globalThis.fetch;
let outbound = [];
test.before(() => {
    globalThis.fetch = (url, ...rest) => {
        if (String(url).startsWith('http://127.0.0.1:')) return realFetch(url, ...rest);
        outbound.push(String(url));
        throw new Error('outbound network call attempted');
    };
});
test.after(() => { globalThis.fetch = realFetch; assert.deepStrictEqual(outbound, [], 'no outbound calls'); });

// ------------------------------------------------------- feature isolation
test('feature flag is disabled by default', () => {
    assert.strictEqual(isFeatureEnabled({}), false);
    assert.strictEqual(isFeatureEnabled({ GROUP_MEETINGS_ENABLED: 'false' }), false);
    assert.strictEqual(isFeatureEnabled({ GROUP_MEETINGS_ENABLED: 'true' }), true);
});

test('controlled rollout: default audience is PI only; members wait; existing memberships untouched', async () => {
    const policy = require('../server/meetings/policy');
    assert.deepStrictEqual(policy.parseAudience({}), { mode: 'pi' });
    const t = await startApp({ audience: policy.parseAudience({}) });
    try {
        assert.strictEqual((await t.call('GET', '/me', { user: U.PI })).status, 200);
        assert.strictEqual((await t.call('GET', '/status', { user: U.PI })).status, 200);
        for (const u of [U.L1, U.L2, U.U1, U.J1]) {
            assert.strictEqual((await t.call('GET', '/me', { user: u })).status, 403, u.researcher_id);
            assert.strictEqual((await t.call('GET', '/groups/LIU/overview', { user: u })).status, 403, u.researcher_id);
            assert.strictEqual((await t.call('GET', '/status', { user: u })).status, 404, 'legacy UI stays for ' + u.researcher_id);
        }
        // PI can review and edit memberships and see every member in the overview
        const ov = await t.call('GET', '/groups/LIU/overview', { user: U.PI });
        assert.deepStrictEqual(ov.json.researchers.map(r => r.researcher_id).sort(), ['L1', 'L2']);
        assert.ok(t.data.members.has(`${t.data.groups[0].id}:L1`), 'memberships not modified');
    } finally { await t.close(); }
});

test('controlled rollout: pilot list admits only the listed researchers (still membership-scoped)', async () => {
    const policy = require('../server/meetings/policy');
    const t = await startApp({ audience: policy.parseAudience({ GROUP_MEETINGS_AUDIENCE: 'L1' }) });
    try {
        assert.deepStrictEqual((await t.call('GET', '/me', { user: U.L1 })).json.groups.map(g => g.code), ['LIU', 'JOINT']);
        assert.strictEqual((await t.call('GET', '/groups/UNAV/overview', { user: U.L1 })).status, 403, 'pilot does not bypass membership');
        assert.strictEqual((await t.call('GET', '/me', { user: U.L2 })).status, 403);
        assert.strictEqual((await t.call('GET', '/me', { user: U.U1 })).status, 403);
    } finally { await t.close(); }
});

test('isAvailableFor: flag AND audience; PI always when flag on', () => {
    const { isAvailableFor } = require('../server/meetings');
    const pi = { researcher_id: 'PI', role: 'pi' }, r = { researcher_id: 'R7', role: 'researcher' };
    assert.strictEqual(isAvailableFor(pi, {}), false);
    assert.strictEqual(isAvailableFor(pi, { GROUP_MEETINGS_ENABLED: 'true' }), true);
    assert.strictEqual(isAvailableFor(r, { GROUP_MEETINGS_ENABLED: 'true' }), false);
    assert.strictEqual(isAvailableFor(r, { GROUP_MEETINGS_ENABLED: 'true', GROUP_MEETINGS_AUDIENCE: 'R1, R7' }), true);
    assert.strictEqual(isAvailableFor(r, { GROUP_MEETINGS_ENABLED: 'true', GROUP_MEETINGS_AUDIENCE: 'members' }), true);
    assert.strictEqual(isAvailableFor(r, { GROUP_MEETINGS_AUDIENCE: 'members' }), false);
    assert.strictEqual(isAvailableFor(null, { GROUP_MEETINGS_ENABLED: 'true' }), false);
});

test('disabled: every endpoint is 404 and touches no data or storage', async () => {
    const t = await startApp({ enabled: false });
    try {
        for (const [m, p] of [['GET', '/me'], ['GET', '/groups/LIU/overview'], ['GET', `/groups/LIU/documents/${t.data.docs[0].submission_id}/file`],
            ['GET', '/admin/groups'], ['PATCH', '/admin/groups/LIU/settings'], ['PUT', '/admin/groups/LIU/members/L1']]) {
            const r = await t.call(m, p, { user: U.PI, body: m === 'GET' ? undefined : {} });
            assert.strictEqual(r.status, 404, `${m} ${p}`);
        }
        assert.deepStrictEqual(t.calls, []);
        assert.deepStrictEqual(t.storage.calls, []);
    } finally { await t.close(); }
});

test('schema not ready: 503, no data access (failure isolation)', async () => {
    const t = await startApp({ ready: false });
    try {
        const r = await t.call('GET', '/me', { user: U.PI });
        assert.strictEqual(r.status, 503);
        assert.deepStrictEqual(t.calls, []);
    } finally { await t.close(); }
});

// ----------------------------------------------------- authn / authz
test('unauthenticated 401; ai_bot, inactive and unknown accounts 403', async () => {
    const t = await startApp();
    try {
        assert.strictEqual((await t.call('GET', '/me')).status, 401);
        assert.strictEqual((await t.call('GET', '/me', { user: U.BOT })).status, 403);
        assert.strictEqual((await t.call('GET', '/groups/LIU/overview', { user: U.BOT })).status, 403);
        assert.strictEqual((await t.call('GET', '/me', { user: U.OFF })).status, 403);
        assert.strictEqual((await t.call('GET', '/me', { user: { researcher_id: 'NOPE', role: 'researcher' } })).status, 403);
    } finally { await t.close(); }
});

test('/me: PI sees the three coded groups; members only their own; collaborators none', async () => {
    const t = await startApp();
    try {
        const pi = await t.call('GET', '/me', { user: U.PI });
        assert.deepStrictEqual(pi.json.groups.map(g => g.code), ['LIU', 'UNAV', 'JOINT']);
        assert.strictEqual(pi.json.role, 'pi');
        assert.deepStrictEqual((await t.call('GET', '/me', { user: U.L1 })).json.groups.map(g => g.code), ['LIU', 'JOINT']);
        assert.deepStrictEqual((await t.call('GET', '/me', { user: U.U1 })).json.groups.map(g => g.code), ['UNAV']);
        assert.deepStrictEqual((await t.call('GET', '/me', { user: U.COL })).json.groups, []);
    } finally { await t.close(); }
});

test('LiU / UNAV isolation and Joint authorization', async () => {
    const t = await startApp();
    try {
        assert.strictEqual((await t.call('GET', '/groups/UNAV/overview', { user: U.L1 })).status, 403);
        assert.strictEqual((await t.call('GET', '/groups/LIU/overview', { user: U.U1 })).status, 403);
        assert.strictEqual((await t.call('GET', '/groups/JOINT/overview', { user: U.U1 })).status, 403);
        const j = await t.call('GET', '/groups/JOINT/overview', { user: U.J1 });
        assert.strictEqual(j.status, 200);
        assert.deepStrictEqual(j.json.researchers.map(r => r.researcher_id).sort(), ['J1', 'L1']);
        // a UNAV researcher's documents are not reachable from LiU or Joint
        const u1doc = t.data.docs.find(d => d.researcher_id === 'U1').submission_id;
        assert.strictEqual((await t.call('GET', `/groups/LIU/documents/${u1doc}/file`, { user: U.PI })).status, 404);
        assert.strictEqual((await t.call('GET', '/groups/JOINT/members/U1/documents', { user: U.J1 })).status, 404);
    } finally { await t.close(); }
});

test('session identity only: ?user= impersonation and body ids are ignored', async () => {
    const t = await startApp();
    try {
        const r = await t.call('GET', '/me?user=U1', { user: U.L1 });
        assert.strictEqual(r.json.researcher_id, 'L1');
        assert.deepStrictEqual(r.json.groups.map(g => g.code), ['LIU', 'JOINT']);
        assert.strictEqual((await t.call('GET', '/groups/UNAV/overview?user=U1', { user: U.L1 })).status, 403);
        const pi = await t.call('GET', '/me?user=L1', { user: U.PI });
        assert.strictEqual(pi.json.role, 'pi');
        assert.strictEqual(pi.json.researcher_id, 'PI');
    } finally { await t.close(); }
});

test('removed member immediately loses workspace and Zoom link', async () => {
    const t = await startApp();
    try {
        const before = await t.call('GET', '/groups/LIU', { user: U.L1 });
        assert.strictEqual(before.json.group.zoom_join_url, 'https://liu-se.zoom.us/j/111');
        assert.strictEqual((await t.call('DELETE', '/admin/groups/LIU/members/L1', { user: U.PI })).json.removed, true);
        const after = await t.call('GET', '/groups/LIU', { user: U.L1 });
        assert.strictEqual(after.status, 403);
        assert.ok(!after.text.includes('zoom.us'));
        assert.strictEqual((await t.call('GET', '/groups/LIU/overview', { user: U.L1 })).status, 403);
    } finally { await t.close(); }
});

test('Zoom link: members of that group and PI only; independent per group; absent link is fine', async () => {
    const t = await startApp();
    try {
        assert.strictEqual((await t.call('GET', '/groups/JOINT', { user: U.J1 })).json.group.zoom_join_url, 'https://zoom.us/j/333');
        const unav = await t.call('GET', '/groups/UNAV', { user: U.U1 });
        assert.strictEqual(unav.json.group.zoom_join_url, null);
        assert.strictEqual(unav.json.group.zoom_configured, false);
        assert.strictEqual((await t.call('GET', '/groups/UNAV/overview', { user: U.U1 })).status, 200);
        const non = await t.call('GET', '/groups/JOINT', { user: U.U1 });
        assert.strictEqual(non.status, 403);
        assert.ok(!non.text.includes('zoom'));
        // /me never carries the URL itself
        assert.ok(!(await t.call('GET', '/me', { user: U.L1 })).text.includes('zoom.us'));
    } finally { await t.close(); }
});

// ---------------------------------------------------------- documents
test('overview counters include every listed submission, identically for all members', async () => {
    const t = await startApp();
    try {
        const row = (r, id) => r.json.researchers.find(x => x.researcher_id === id);
        // L2: approved DATA + pending SOP + legacy PRES (REPORT, discarded, other workspace excluded)
        const asL1 = await t.call('GET', '/groups/LIU/overview', { user: U.L1 });
        assert.strictEqual(row(asL1, 'L2').total_count, 3);
        assert.strictEqual(row(asL1, 'L2').new_count, 2);
        assert.strictEqual(row(asL1, 'L1').total_count, 1);
        assert.strictEqual(row(asL1, 'L1').is_self, true);
        const asPi = await t.call('GET', '/groups/LIU/overview', { user: U.PI });
        const asL2 = await t.call('GET', '/groups/LIU/overview', { user: U.L2 });
        for (const other of [asPi, asL2]) {
            assert.deepStrictEqual(other.json.researchers.map(r => [r.researcher_id, r.total_count, r.new_count, r.last_upload]),
                asL1.json.researchers.map(r => [r.researcher_id, r.total_count, r.new_count, r.last_upload]));
        }
        // inactive account is not listed even though a membership row exists
        assert.strictEqual(row(asL1, 'OFF'), undefined);
        // Last presented is a neutral null until R3
        assert.strictEqual(row(asL1, 'L2').last_presented, null);
        assert.strictEqual(asL1.json.last_presented_available, false);
        assert.strictEqual(asL1.json.new_window.fallback, true);
        assert.strictEqual(asL1.json.new_window.basis, 'previous_7_days');
    } finally { await t.close(); }
});

test('listing: members see all eligible submissions of co-members; excluded ones never appear', async () => {
    const t = await startApp();
    try {
        const r = await t.call('GET', '/groups/LIU/members/L2/documents?filter=all', { user: U.L1 });
        assert.strictEqual(r.status, 200);
        assert.deepStrictEqual(r.json.documents.map(d => d.title).sort(), ['L2-approved-data.pdf', 'L2-old-pres.pdf', 'L2-pending-sop.pdf']);
        assert.deepStrictEqual(r.json.documents.map(d => d.status).sort(), ['APPROVED', 'APPROVED', 'PENDING']);
        // REPORT, discarded and other-workspace documents: no title, no id
        assert.ok(!r.text.includes('SECRET'));
        for (const d of t.data.docs.filter(x => x.original_filename.includes('SECRET'))) assert.ok(!r.text.includes(d.submission_id));
        const legacy = r.json.documents.find(d => d.title === 'L2-old-pres.pdf');
        assert.strictEqual(legacy.file_type, 'PRESENTATION');
        assert.strictEqual(legacy.legacy, true);
        // no administration affordances in the payload
        assert.deepStrictEqual(Object.keys(r.json.documents[0]).sort(), [
            'approved_at', 'can_open', 'file_type', 'legacy', 'meeting_status', 'original_date', 'status', 'submission_id', 'submitted_at', 'title',
        ]);
    } finally { await t.close(); }
});

test('can_open: true only for the owner and the PI, whatever the status', async () => {
    const t = await startApp();
    try {
        const list = async (user) => (await t.call('GET', '/groups/LIU/members/L2/documents?filter=all', { user })).json.documents;
        assert.ok((await list(U.L1)).every(d => d.can_open === false), 'co-member never');
        assert.ok((await list(U.L2)).every(d => d.can_open === true), 'owner always');
        assert.ok((await list(U.PI)).every(d => d.can_open === true), 'PI always');
    } finally { await t.close(); }
});

test('status probe: 404 when disabled, 401 without session, 200 for any logged-in user when enabled', async () => {
    const off = await startApp({ enabled: false });
    try { assert.strictEqual((await off.call('GET', '/status', { user: U.L1 })).status, 404); } finally { await off.close(); }
    const notReady = await startApp({ ready: false });
    try { assert.strictEqual((await notReady.call('GET', '/status', { user: U.L1 })).status, 503); } finally { await notReady.close(); }
    const t = await startApp();
    try {
        assert.strictEqual((await t.call('GET', '/status')).status, 401);
        assert.deepStrictEqual((await t.call('GET', '/status', { user: U.COL })).json, { enabled: true });
        assert.strictEqual((await t.call('GET', '/status', { user: U.BOT })).status, 200); // reveals only the flag
    } finally { await t.close(); }
});

test('documents: paging metadata, page size and cursor validation', async () => {
    const t = await startApp();
    try {
        const p1 = await t.call('GET', '/groups/LIU/members/L2/documents?filter=all&limit=2', { user: U.L1 });
        assert.strictEqual(p1.json.total, 3);
        assert.strictEqual(p1.json.documents.length, 2);
        assert.ok(p1.json.next_cursor);
        const p2 = await t.call('GET', `/groups/LIU/members/L2/documents?filter=all&limit=2&cursor=${encodeURIComponent(p1.json.next_cursor)}`, { user: U.L1 });
        assert.strictEqual(p2.json.documents.length, 1);
        assert.strictEqual(p2.json.next_cursor, null);
        const ids = [...p1.json.documents, ...p2.json.documents].map(d => d.submission_id);
        assert.strictEqual(new Set(ids).size, 3);
        assert.ok([...p1.json.documents, ...p2.json.documents].every(d => d.can_open === false), 'same policy on every page');
        for (const q of ['limit=0', 'limit=1001', 'limit=abc', 'cursor=bad', 'cursor=' + Buffer.from('{"t":"x","id":"y"}').toString('base64url')]) {
            assert.strictEqual((await t.call('GET', `/groups/LIU/members/L2/documents?${q}`, { user: U.L1 })).status, 400, q);
        }
    } finally { await t.close(); }
});

test('filters: week / since_last / all; invalid filter 400; non-member owner 404', async () => {
    const t = await startApp();
    try {
        const week = await t.call('GET', '/groups/LIU/members/L2/documents?filter=week', { user: U.L1 });
        assert.deepStrictEqual(week.json.documents.map(d => d.title).sort(), ['L2-approved-data.pdf', 'L2-pending-sop.pdf']);
        assert.strictEqual(week.json.window.basis, 'current_calendar_week');
        const since = await t.call('GET', '/groups/LIU/members/L2/documents?filter=since_last', { user: U.L1 });
        assert.strictEqual(since.json.window.fallback, true);
        assert.strictEqual((await t.call('GET', '/groups/LIU/members/L2/documents?filter=year', { user: U.L1 })).status, 400);
        assert.strictEqual((await t.call('GET', '/groups/LIU/members/U1/documents', { user: U.PI })).status, 404);
        assert.strictEqual((await t.call('GET', '/groups/LIU/members/OFF/documents', { user: U.PI })).status, 404);
    } finally { await t.close(); }
});

test('since-last window: completed meeting resets it; cancelled/postponed do not', async () => {
    const data = makeData();
    const liu = data.groups[0].id;
    const completedAt = new Date(Date.now() - 1 * 86400000);
    data.occurrences.push({ id: data.ids(), meeting_group_id: liu, status: 'CANCELLED', ended_at: new Date() });
    data.occurrences.push({ id: data.ids(), meeting_group_id: liu, status: 'POSTPONED', ended_at: new Date() });
    const t0 = await startApp({ data });
    try {
        assert.strictEqual((await t0.call('GET', '/groups/LIU/overview', { user: U.PI })).json.new_window.fallback, true);
    } finally { await t0.close(); }
    data.occurrences.push({ id: data.ids(), meeting_group_id: liu, status: 'COMPLETED', ended_at: completedAt });
    const t = await startApp({ data });
    try {
        const o = await t.call('GET', '/groups/LIU/overview', { user: U.PI });
        assert.strictEqual(o.json.new_window.fallback, false);
        assert.strictEqual(new Date(o.json.new_window.since).getTime(), completedAt.getTime());
        assert.strictEqual(o.json.researchers.find(r => r.researcher_id === 'L2').new_count, 0); // uploads were 2 days ago
    } finally { await t.close(); }
});

test('REQUIRED: a member sees a co-member\'s APPROVED document in the listing but cannot open or download it', async () => {
    const t = await startApp();
    try {
        const approved = t.data.docs.find(d => d.original_filename === 'L2-approved-data.pdf').submission_id;
        const listing = await t.call('GET', '/groups/LIU/members/L2/documents?filter=all', { user: U.L1 });
        const entry = listing.json.documents.find(d => d.submission_id === approved);
        assert.ok(entry, 'listed');
        assert.strictEqual(entry.status, 'APPROVED');
        assert.strictEqual(entry.can_open, false);
        for (const q of ['', '?download=1', '?download=true']) {
            const r = await t.call('GET', `/groups/LIU/documents/${approved}/file${q}`, { user: U.L1 });
            assert.strictEqual(r.status, 403, q);
            assert.ok(!r.text.includes('%PDF'));
        }
        // also in the Joint group, where L1 and J1 are co-members
        const l1doc = t.data.docs.find(d => d.original_filename === 'L1-own-pending.pdf').submission_id;
        assert.strictEqual((await t.call('GET', `/groups/JOINT/documents/${l1doc}/file`, { user: U.J1 })).status, 403);
        assert.deepStrictEqual(t.storage.calls, [], 'storage never contacted for refused requests');
    } finally { await t.close(); }
});

test('viewer file: owner and PI only for every status; storage only reached when allowed', async () => {
    const t = await startApp();
    try {
        const by = (name) => t.data.docs.find(d => d.original_filename === name).submission_id;
        const approved = by('L2-approved-data.pdf');
        const pending = by('L2-pending-sop.pdf');
        const report = by('L2-SECRET-report.pdf');
        const discarded = by('L2-SECRET-discarded.pdf');
        const otherWs = by('L2-SECRET-otherws.pdf');
        const ok = await t.call('GET', `/groups/LIU/documents/${approved}/file`, { user: U.L2 });
        assert.strictEqual(ok.status, 200);
        assert.match(ok.headers.get('content-disposition'), /^inline; filename="L2-approved-data.pdf"/);
        assert.strictEqual(ok.headers.get('x-content-type-options'), 'nosniff');
        assert.strictEqual(t.storage.calls.length, 1);
        assert.strictEqual((await t.call('GET', `/groups/LIU/documents/${pending}/file`, { user: U.L2 })).status, 200);
        assert.strictEqual((await t.call('GET', `/groups/LIU/documents/${pending}/file`, { user: U.PI })).status, 200);
        assert.strictEqual((await t.call('GET', `/groups/LIU/documents/${approved}/file`, { user: U.PI })).status, 200);
        assert.match((await t.call('GET', `/groups/LIU/documents/${approved}/file?download=1`, { user: U.PI })).headers.get('content-disposition'), /^attachment;/);
        assert.strictEqual(t.storage.calls.length, 5);
        for (const [sid, who] of [[report, U.PI], [discarded, U.PI], [otherWs, U.PI], [report, U.L2], ['not-a-uuid', U.PI]]) {
            assert.strictEqual((await t.call('GET', `/groups/LIU/documents/${sid}/file`, { user: who })).status, 404, sid);
        }
        assert.strictEqual((await t.call('GET', `/groups/LIU/documents/${pending}/file`, { user: U.L1 })).status, 403);
        assert.strictEqual((await t.call('GET', `/groups/LIU/documents/${approved}/file`, { user: U.U1 })).status, 403);
        assert.strictEqual(t.storage.calls.length, 5, 'no storage access for refused requests');
    } finally { await t.close(); }
});

// -------------------------------------------------------------- admin
test('admin endpoints are PI-only; members get 403', async () => {
    const t = await startApp();
    try {
        for (const [m, p] of [['GET', '/admin/groups'], ['GET', '/admin/groups/LIU/members'], ['PATCH', '/admin/groups/LIU/settings'],
            ['PUT', '/admin/groups/LIU/members/J1'], ['DELETE', '/admin/groups/LIU/members/L2'], ['POST', '/admin/groups/LIU/occurrences']]) {
            assert.strictEqual((await t.call(m, p, { user: U.L2, body: m === 'GET' ? undefined : {} })).status, 403, `${m} ${p}`);
        }
        assert.strictEqual((await t.call('GET', '/admin/groups', { user: U.PI })).status, 200);
    } finally { await t.close(); }
});

test('writes require the same-origin guard', async () => {
    const t = await startApp();
    try {
        const r = await t.call('PUT', '/admin/groups/LIU/members/J1', { user: U.PI, body: {}, sameOrigin: false });
        assert.strictEqual(r.status, 403);
        assert.ok(!t.data.members.has(`${t.data.groups[0].id}:J1`));
    } finally { await t.close(); }
});

test('Zoom settings: validated, removable, never echoed in errors; unknown fields rejected', async () => {
    const t = await startApp();
    try {
        const bad = await t.call('PATCH', '/admin/groups/UNAV/settings', { user: U.PI, body: { zoom_join_url: 'https://evil.example/j/1' } });
        assert.strictEqual(bad.status, 400);
        assert.ok(!bad.text.includes('evil.example'));
        assert.strictEqual(bad.json.reason, 'host_not_approved');
        const good = await t.call('PATCH', '/admin/groups/UNAV/settings', { user: U.PI, body: { zoom_join_url: 'https://unav.zoom.us/j/222?pwd=x' } });
        assert.strictEqual(good.json.group.zoom_join_url, 'https://unav.zoom.us/j/222?pwd=x');
        assert.strictEqual(t.data.groups[0].zoom_join_url, 'https://liu-se.zoom.us/j/111', 'other groups unchanged');
        const cleared = await t.call('PATCH', '/admin/groups/UNAV/settings', { user: U.PI, body: { zoom_join_url: null } });
        assert.strictEqual(cleared.json.group.zoom_join_url, null);
        for (const body of [{ code: 'JOINT' }, { name: 'x' }, { is_active: false }, { zoom_meeting_id: '1' }]) {
            assert.strictEqual((await t.call('PATCH', '/admin/groups/UNAV/settings', { user: U.PI, body })).status, 400, JSON.stringify(body));
        }
        assert.strictEqual((await t.call('PATCH', '/admin/groups/UNAV/settings', { user: U.PI, body: { timezone: 'Mars/Base' } })).status, 400);
        assert.strictEqual((await t.call('PATCH', '/admin/groups/UNAV/settings', { user: U.PI, body: { default_time: '25:00' } })).status, 400);
    } finally { await t.close(); }
});

test('membership: PI adds/removes explicitly; ineligible accounts refused; warnings for collaborators/external', async () => {
    const t = await startApp();
    try {
        const add = await t.call('PUT', '/admin/groups/UNAV/members/COL', { user: U.PI });
        assert.deepStrictEqual(add.json, { success: true, added: true, warnings: ['collaborator'] });
        assert.deepStrictEqual((await t.call('PUT', '/admin/groups/UNAV/members/COL', { user: U.PI })).json.added, false);
        assert.deepStrictEqual((await t.call('PUT', '/admin/groups/UNAV/members/EXT', { user: U.PI })).json.warnings, ['external_affiliation']);
        for (const rid of ['OFF', 'BOT', 'PI']) assert.strictEqual((await t.call('PUT', `/admin/groups/UNAV/members/${rid}`, { user: U.PI })).status, 422, rid);
        assert.strictEqual((await t.call('PUT', '/admin/groups/UNAV/members/NOBODY', { user: U.PI })).status, 404);
        // adding to UNAV does not change LiU membership
        assert.strictEqual((await t.call('GET', '/groups/LIU/overview', { user: U.COL })).status, 403);
        assert.strictEqual((await t.call('GET', '/groups/UNAV/overview', { user: U.COL })).status, 200);
    } finally { await t.close(); }
});

test('assign code: fills an empty code only; never duplicates', async () => {
    const t = await startApp();
    try {
        const old = t.data.groups[3].id;
        assert.strictEqual((await t.call('PUT', `/admin/groups/${old}/code`, { user: U.PI, body: { code: 'LIU' } })).status, 409);
        assert.strictEqual((await t.call('PUT', `/admin/groups/${t.data.groups[0].id}/code`, { user: U.PI, body: { code: 'JOINT' } })).status, 409);
        assert.strictEqual((await t.call('PUT', `/admin/groups/${old}/code`, { user: U.PI, body: { code: 'OTHER' } })).status, 400);
    } finally { await t.close(); }
});

test('occurrences: central service, events emitted to hook, invalid transitions 409', async () => {
    const events = [];
    const t = await startApp({ events });
    try {
        const c = await t.call('POST', '/admin/groups/LIU/occurrences', { user: U.PI, body: { scheduled_start: '2026-12-03T09:00:00+01:00', duration_minutes: 60 } });
        assert.strictEqual(c.status, 201);
        assert.strictEqual(c.json.occurrence.status, 'SCHEDULED');
        assert.strictEqual((await t.call('POST', '/admin/groups/LIU/occurrences', { user: U.PI, body: { scheduled_start: '2026-12-03T09:00:00+01:00' } })).status, 409);
        assert.strictEqual((await t.call('POST', '/admin/groups/LIU/occurrences', { user: U.PI, body: { scheduled_start: '2026-12-03 09:00' } })).status, 400);
        const oid = c.json.occurrence.id;
        assert.strictEqual((await t.call('POST', `/admin/occurrences/${oid}/postpone`, { user: U.PI, body: {} })).json.occurrence.status, 'POSTPONED');
        assert.strictEqual((await t.call('POST', `/admin/occurrences/${oid}/reschedule`, { user: U.PI, body: { scheduled_start: '2026-12-10T09:00:00+01:00' } })).json.occurrence.status, 'SCHEDULED');
        assert.strictEqual((await t.call('POST', `/admin/occurrences/${oid}/cancel`, { user: U.PI, body: { note: 'Holiday' } })).json.occurrence.status, 'CANCELLED');
        assert.strictEqual((await t.call('POST', `/admin/occurrences/${oid}/cancel`, { user: U.PI, body: {} })).status, 409);
        assert.strictEqual((await t.call('POST', `/admin/occurrences/${oid}/complete`, { user: U.PI, body: {} })).status, 404);
        assert.deepStrictEqual(events.map(e => e.event), ['meeting.scheduled', 'meeting.postponed', 'meeting.rescheduled', 'meeting.cancelled']);
        assert.ok(events.every(e => e.group_code === 'LIU'));
        // members can read the schedule but never change it
        assert.strictEqual((await t.call('GET', '/groups/LIU/occurrences', { user: U.L1 })).json.occurrences.length, 1);
        assert.strictEqual((await t.call('POST', `/admin/occurrences/${oid}/reschedule`, { user: U.L1, body: {} })).status, 403);
    } finally { await t.close(); }
});

// ------------------------------------------- no document administration
test('route inventory: no document administration endpoints exist', () => {
    const router = createGroupMeetingsRouter({ pool: null, repo: {}, isEnabled: () => true });
    const routes = router.stack.filter(l => l.route).flatMap(l =>
        Object.keys(l.route.methods).map(m => `${m.toUpperCase()} ${l.route.path}`));
    assert.deepStrictEqual(routes.sort(), [
        'DELETE /admin/groups/:code/members/:researcherId',
        'GET /admin/groups',
        'GET /admin/groups/:code/members',
        'GET /groups/:code',
        'GET /groups/:code/documents/:submissionId/file',
        'GET /groups/:code/members/:researcherId/documents',
        'GET /groups/:code/occurrences',
        'GET /groups/:code/overview',
        'GET /me',
        'GET /status',
        'PATCH /admin/groups/:code/settings',
        'POST /admin/groups/:code/occurrences',
        'POST /admin/occurrences/:id/:action',
        'PUT /admin/groups/:code/members/:researcherId',
        'PUT /admin/groups/:groupId/code',
    ].sort());
    // every route that can modify anything is under /admin (PI-only) and
    // none of them addresses a document
    for (const r of routes.filter(x => !x.startsWith('GET '))) {
        assert.ok(r.includes('/admin/'), r);
        assert.ok(!/document|submission|file/i.test(r), r);
    }
});
