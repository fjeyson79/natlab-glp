// S1.4 / R1c — workspace authorization boundary (unit tests, no database).
const test = require('node:test');
const assert = require('node:assert');
const { makeWorkspaceAccess, COMPANY_PREFIXES } = require('../server/workspaceAccess');

// Same shape as server.js GOVERNANCE_DEFAULTS (subset of modules used here).
const GOV = {
    cso: { dashboard: 'edit', company: 'edit', rnd: 'edit', glp: 'edit', inventory: 'edit', investors: 'edit', investroom: 'edit', user_control: 'full', audit: 'view' },
    ceo: { dashboard: 'edit', company: 'edit', rnd: 'view', glp: 'view', inventory: 'view', investors: 'edit', investroom: 'view', user_control: 'investors_only', audit: 'hidden' },
    cto: { dashboard: 'edit', company: 'view', rnd: 'edit', glp: 'view', inventory: 'view', investors: 'hidden', investroom: 'view', user_control: 'investors_only', audit: 'hidden' },
    coo: { dashboard: 'edit', company: 'view', rnd: 'edit', glp: 'edit', inventory: 'view', investors: 'view', investroom: 'view', user_control: 'investors_only', audit: 'hidden' },
    advisor: { dashboard: 'view', company: 'view', rnd: 'view', glp: 'view', inventory: 'hidden', investors: 'hidden', investroom: 'view', user_control: 'hidden', audit: 'hidden' },
    r_and_d: { dashboard: 'edit', company: 'hidden', rnd: 'edit', glp: 'view', inventory: 'view', investors: 'hidden', investroom: 'hidden', user_control: 'hidden', audit: 'hidden' },
};
const mkRes = () => ({ code: 200, body: null, status(c) { this.code = c; return this; }, json(b) { this.body = b; return this; } });
const run = async (mw, req) => { const res = mkRes(); let nexted = false; await mw(req, res, () => { nexted = true; }); return { res, nexted }; };
const hdr = (h) => (name) => h[name.toLowerCase()];

// ------------------------------------------------------------------ CSRF
test('CSRF: same-origin writes pass on each domain; cross-site, cross-domain and header-less writes are refused', async () => {
    const { csrfGuard } = makeWorkspaceAccess(null, { trustedOrigins: [] });
    const r = (method, h) => run(csrfGuard, { method, get: hdr(h), originalUrl: '/api/x' });
    for (const host of ['glp.hernandezlab.com', 'natlab-glp-production.up.railway.app']) {
        assert.ok((await r('POST', { host, origin: `https://${host}`, 'sec-fetch-site': 'same-origin' })).nexted, host);
        assert.ok((await r('DELETE', { host, origin: `https://${host}` })).nexted, 'older browser without Sec-Fetch-Site');
        assert.ok((await r('PATCH', { host, 'sec-fetch-site': 'same-origin' })).nexted, 'same-origin without Origin');
    }
    const blocked = [
        { host: 'glp.hernandezlab.com', origin: 'https://evil.example' },
        { host: 'glp.hernandezlab.com', origin: 'https://natlab-glp-production.up.railway.app' }, // no cross-domain trust
        { host: 'natlab-glp-production.up.railway.app', origin: 'https://glp.hernandezlab.com' },
        { host: 'glp.hernandezlab.com', origin: 'null' },
        { host: 'glp.hernandezlab.com', origin: 'https://glp.hernandezlab.com', 'sec-fetch-site': 'cross-site' },
        { host: 'glp.hernandezlab.com' }, // neither Origin nor Sec-Fetch-Site
        { host: 'glp.hernandezlab.com', 'sec-fetch-site': 'cross-site' },
    ];
    for (const h of blocked) {
        const out = await r('PUT', h);
        assert.ok(!out.nexted && out.res.code === 403 && out.res.body.code === 'cross_site_blocked', JSON.stringify(h));
    }
    assert.ok((await r('GET', { host: 'x' })).nexted, 'reads are not CSRF-checked');
});

// ----------------------------------------------------------- storage keys
test('storage keys are removed from every JSON response and replaced by has_file', () => {
    const { scrub } = makeWorkspaceAccess(null);
    assert.strictEqual(scrub({ id: 'x', r2ObjectKey: 'di/y.pdf', viewUrl: '/api/di/download/x' }, 0).r2ObjectKey, undefined, 'camelCase variant too');
    const out = scrub({ files: [{ submission_id: 'a', r2_object_key: 'di/x.pdf', original_filename: 'x.pdf' }, { submission_id: 'b', r2_object_key: null }],
        cert: { certificate_r2_key: 'c', nested: { r2_key: 'k', signed_pdf_path: 'r2:p' } } }, 0);
    const s = JSON.stringify(out);
    assert.doesNotMatch(s, /r2_object_key|r2_key|certificate_r2_key|signed_pdf_path|di\/x\.pdf|r2:p/);
    assert.strictEqual(out.files[0].has_file, true); assert.strictEqual(out.files[1].has_file, false);
    assert.strictEqual(out.cert.has_file, true); assert.strictEqual(out.cert.nested.has_file, true);
    assert.strictEqual(out.files[0].original_filename, 'x.pdf');
});

// -------------------------------------------------- clearance / permissions
test('company module clearance: position defaults merged with per-user overrides', () => {
    const { clearanceOf } = makeWorkspaceAccess(null, { getGovernanceDefaults: () => GOV });
    assert.strictEqual(clearanceOf({ position: 'ceo', clearance_config: {} }).company, 'edit');
    assert.strictEqual(clearanceOf({ position: 'cto', clearance_config: {} }).company, 'view');
    assert.strictEqual(clearanceOf({ position: 'cto', clearance_config: { company: 'edit' } }).company, 'edit');
    assert.strictEqual(clearanceOf({ position: 'cso', clearance_config: { inventory: 'view' } }).inventory, 'edit', 'CSO always has the full CSO template (same rule as /api/di/me)');
    assert.strictEqual(clearanceOf({ position: '', clearance_config: {} }).company, undefined);
});

// ------------------------------------------------------- company boundary
function fakePool(resourceWs) {
    const ws = { theralia: { id: 'T', slug: 'theralia', workspace_type: 'COMPANY' }, skinotek: { id: 'K', slug: 'skinotek', workspace_type: 'COMPANY' }, natlab: { id: 'L', slug: 'natlab', workspace_type: 'LAB' } };
    return { query: async (sql, p) => (/FROM workspaces WHERE slug/.test(sql) ? { rows: ws[p[0]] ? [ws[p[0]]] : [] } : { rows: resourceWs === undefined ? [] : [{ id: resourceWs }] }) };
}
const member = (slug, extra = {}) => [slug, { workspace_id: slug === 'theralia' ? 'T' : 'K', slug, workspace_type: 'COMPANY', role: 'founder', position: 'cso', is_master: false, clearance_config: {}, ...extra }];
async function boundary(path, { method = 'GET', user = { role: 'founder', researcher_id: 'F' }, memberships = [], isPi = false, query = {}, headers = {}, workspace_slug = 'natlab', resourceWs, explicit = true } = {}) {
    const { companyBoundary } = makeWorkspaceAccess(fakePool(resourceWs), { getGovernanceDefaults: () => GOV });
    const prefix = COMPANY_PREFIXES.find(p => path.startsWith(p));
    const req = { method, baseUrl: prefix, path: path.slice(prefix.length) || '/', query, headers, workspace_slug, workspaceExplicit: explicit,
        session: { user }, workspaceAccess: { isPi, memberships: new Map(memberships) } };
    return run(companyBoundary, req);
}

test('company modules: membership of the acted-on COMPANY workspace; PI exception; LAB workspace refused even for the PI', async () => {
    assert.ok((await boundary('/api/rd/projects', { workspace_slug: 'theralia', memberships: [member('theralia')] })).nexted);
    const other = await boundary('/api/rd/projects', { workspace_slug: 'skinotek', memberships: [member('theralia')] });
    assert.deepStrictEqual([other.nexted, other.res.code, other.res.body.code], [false, 403, 'workspace_access_denied']);
    const lab = await boundary('/api/rd/glp/files', { workspace_slug: 'natlab', isPi: true, user: { role: 'pi' } });
    assert.deepStrictEqual([lab.res.code, lab.res.body.code], [403, 'company_module_only']);
    assert.ok((await boundary('/api/company/sections', { isPi: true, user: { role: 'pi' }, query: { ws: 'skinotek' } })).nexted, 'PI administrative exception');
    const labUser = await boundary('/api/theralia/board-meetings', { user: { role: 'researcher', researcher_id: 'R' } });
    assert.strictEqual(labUser.res.code, 403);
});

test('company writes need the module edit clearance (or workspace master); others keep their own guards', async () => {
    const w = (pos, extra = {}) => boundary('/api/company/statements/vision', { method: 'POST', memberships: [member('theralia', { position: pos, ...extra })] });
    assert.ok((await w('ceo')).nexted);
    assert.strictEqual((await w('cto')).res.body.code, 'module_write_denied');
    assert.ok((await w('cto', { clearance_config: { company: 'edit' } })).nexted, 'explicit per-user override');
    assert.ok((await w('advisor', { is_master: true })).nexted, 'workspace master');
    const inv = (pos) => boundary('/api/theralia/inventory/purchases', { method: 'POST', workspace_slug: 'theralia', memberships: [member('theralia', { position: pos })] });
    assert.ok((await inv('cso')).nexted);
    assert.strictEqual((await inv('ceo')).res.body.code, 'module_write_denied');
    // R&D / GLP: position in the ACTED-ON workspace (a Theralia CSO who is only an advisor at Skinotek cannot write Skinotek R&D)
    const rd = (path, pos, extra = {}) => boundary(path, { method: 'POST', workspace_slug: 'skinotek', memberships: [member('theralia', { position: 'cso' }), member('skinotek', { position: pos, ...extra })] });
    assert.strictEqual((await rd('/api/rd/projects', 'advisor')).res.body.code, 'module_write_denied');
    assert.ok((await rd('/api/rd/projects', 'cto')).nexted);
    assert.ok((await rd('/api/rd/projects', 'r_and_d', { role: 'r_and_d' })).nexted);
    assert.strictEqual((await rd('/api/rd/glp/approve/aaaaaaaa-0000-4000-8000-000000000009', 'cto')).res.body.code, 'module_write_denied');
    assert.ok((await rd('/api/rd/glp/approve/aaaaaaaa-0000-4000-8000-000000000009', 'coo')).nexted);
});

test('investors: read-only, own activity tracking allowed, no board or inventory', async () => {
    const investor = { user: { role: 'investor', researcher_id: 'I' }, memberships: [member('theralia', { role: 'investor', position: 'investor' })] };
    assert.strictEqual((await boundary('/api/company/statements/vision', { method: 'POST', ...investor })).res.body.code, 'investor_read_only');
    assert.ok((await boundary('/api/investor/session-heartbeat', { method: 'POST', ...investor })).nexted);
    // the session-end beacon stays public; the meeting request needs a session (investors allowed)
    assert.ok((await boundary('/api/investor/session-end', { method: 'POST', ...investor })).nexted);
    assert.ok((await boundary('/api/investor/session-end', { method: 'POST', user: null })).nexted, 'beacon without cookie');
    assert.ok((await boundary('/api/investor/request-meeting', { method: 'POST', ...investor })).nexted, 'investor books a meeting');
    assert.strictEqual((await boundary('/api/investor/request-meeting', { method: 'POST', user: null })).res.code, 401, 'anonymous booking refused');
    assert.strictEqual((await boundary('/api/investor/kpis', { user: null })).res.code, 401, 'nothing else is public');
    assert.strictEqual((await boundary('/api/investroom/boxes', investor)).res.body.code, 'investor_tab_required', 'A3: no investor InvestRoom');
    assert.strictEqual((await boundary('/api/theralia/board-meetings', investor)).res.body.code, 'investor_tab_required');
    assert.strictEqual((await boundary('/api/theralia/board-meeting-files/7/view', investor)).res.body.code, 'investor_tab_required', 'board files too');
});

test('bridges are PI-only; conflicting or mismatched workspace selections are refused', async () => {
    assert.strictEqual((await boundary('/api/theralia/bridge/oligo-explorer', { memberships: [member('theralia')] })).res.body.code, 'pi_only');
    assert.ok((await boundary('/api/theralia/bridge/oligo-explorer', { isPi: true, user: { role: 'pi' } })).nexted);
    assert.strictEqual((await boundary('/api/company/sections', { memberships: [member('theralia')], headers: { 'x-workspace-slug': 'skinotek' } })).res.body.code, 'workspace_conflict');
    assert.strictEqual((await boundary('/api/theralia/inventory/purchases', { memberships: [member('theralia')], workspace_slug: 'natlab' })).res.body.code, 'workspace_mismatch');
    assert.strictEqual((await boundary('/api/investor/kpis', { memberships: [member('theralia')], query: { workspace: 'skinotek' } })).res.body.code, 'workspace_conflict', 'legacy ?workspace= selector');
    assert.ok((await boundary('/api/investor/kpis', { memberships: [member('theralia')], query: { workspace: 'theralia' } })).nexted);
});

test('object-level: a record belonging to another workspace is answered as not found', async () => {
    const del = await boundary('/api/company/documents/aaaaaaaa-0000-4000-8000-000000000001', { method: 'DELETE', memberships: [member('theralia')], resourceWs: 'K' });
    assert.deepStrictEqual([del.nexted, del.res.code], [false, 404]);
    const glp = await boundary('/api/rd/glp/approve/aaaaaaaa-0000-4000-8000-000000000002', { method: 'POST', workspace_slug: 'theralia', memberships: [member('theralia')], resourceWs: 'L' });
    assert.deepStrictEqual([glp.nexted, glp.res.code], [false, 404], 'a company cannot approve a NAT-Lab submission');
    assert.ok((await boundary('/api/company/documents/aaaaaaaa-0000-4000-8000-000000000001', { method: 'DELETE', memberships: [member('theralia')], resourceWs: 'T' })).nexted);
    // a link without ?ws= acts on the record's own workspace: a NAT-Lab record is refused (company module only)
    const noWs = await boundary('/api/rd/glp/approve/aaaaaaaa-0000-4000-8000-000000000002', { method: 'POST', explicit: false, memberships: [member('theralia')], resourceWs: 'L' });
    assert.deepStrictEqual([noWs.nexted, noWs.res.code], [false, 403]);
});

// ------------------------------------------------------- A2: module clearance
test('A2: Hidden = no read/write, View = read only, Edit = read+write; unset = Hidden; CSO full; master exempt', async () => {
    const as = (pos, path, extra = {}, method = 'GET') => boundary(path, { method, workspace_slug: 'theralia', memberships: [member('theralia', { position: pos, ...extra })] });
    // Hidden
    assert.strictEqual((await as('r_and_d', '/api/company/sections')).res.body.code, 'module_hidden');
    assert.strictEqual((await as('advisor', '/api/theralia/inventory/purchases')).res.body.code, 'module_hidden');
    assert.strictEqual((await as('cto', '/api/company/sections', { clearance_config: { company: 'hidden' } })).res.body.code, 'module_hidden', 'User Control override');
    assert.strictEqual((await as('', '/api/rd/projects')).res.body.code, 'module_hidden', 'no position, nothing set = Hidden');
    // View
    assert.ok((await as('cto', '/api/company/sections')).nexted);
    assert.strictEqual((await as('cto', '/api/company/sections', {}, 'POST')).res.body.code, 'module_write_denied');
    assert.strictEqual((await as('advisor', '/api/theralia/board-meetings/1/content', {}, 'PUT')).res.body.code, 'module_write_denied', 'dashboard View: no board edits');
    assert.ok((await as('advisor', '/api/theralia/board-meetings')).nexted, 'dashboard View: board readable');
    // Edit
    assert.ok((await as('ceo', '/api/company/sections', {}, 'POST')).nexted);
    assert.ok((await as('cto', '/api/company/sections', { clearance_config: { company: 'edit' } }, 'POST')).nexted, 'per-user Edit');
    // Edit never overrides the position rules (GLP decisions stay CSO/COO)
    assert.strictEqual((await as('cto', '/api/rd/glp/approve/aaaaaaaa-0000-4000-8000-000000000009', { clearance_config: { glp: 'edit' } }, 'POST')).res.body.code, 'module_write_denied');
    // GLP vs R&D are separate modules
    assert.strictEqual((await as('cto', '/api/rd/glp/files', { clearance_config: { glp: 'hidden' } })).res.body.code, 'module_hidden');
    assert.ok((await as('cto', '/api/rd/projects', { clearance_config: { glp: 'hidden' } })).nexted);
    // shared endpoint (investor intelligence): needs InvestRoom AND Investors
    assert.strictEqual((await as('cto', '/api/investor/kpis')).res.body.code, 'module_hidden', 'investors Hidden');
    assert.ok((await as('cto', '/api/investor/kpis', { clearance_config: { investors: 'view' } })).nexted);
    assert.strictEqual((await as('ceo', '/api/investor/kpis', { clearance_config: { investroom: 'hidden' } })).res.body.code, 'module_hidden', 'InvestRoom Hidden');
    // self-service investor endpoints carry no module
    assert.ok((await as('cto', '/api/investor/request-meeting', {}, 'POST')).nexted);
    // CSO full regardless of stored settings; workspace master exempt
    assert.ok((await as('cso', '/api/company/sections', { clearance_config: { company: 'hidden' } }, 'POST')).nexted);
    assert.ok((await as('advisor', '/api/theralia/inventory/purchases', { is_master: true })).nexted);
    // User Control levels
    assert.strictEqual((await as('advisor', '/api/theralia/users')).res.body.code, 'module_hidden');
    assert.strictEqual((await as('ceo', '/api/theralia/users/X', {}, 'PUT')).res.body.code, 'module_write_denied');
    assert.ok((await as('ceo', '/api/theralia/users/X/reset-code', {}, 'POST')).nexted, 'investors_only may manage investor codes (requireCSO still applies)');
});

test('A2: clearance is evaluated in the acted-on company only', async () => {
    const both = [member('theralia', { position: 'cto' }), member('skinotek', { position: 'r_and_d' })];
    assert.ok((await boundary('/api/company/sections', { memberships: both, query: { ws: 'theralia' } })).nexted, 'Theralia CTO: company View');
    assert.strictEqual((await boundary('/api/company/sections', { memberships: both, query: { ws: 'skinotek' } })).res.body.code, 'module_hidden', 'Skinotek R&D: company Hidden');
    const k = [member('theralia', { position: 'cso' }), member('skinotek', { position: 'advisor' })];
    assert.strictEqual((await boundary('/api/company/sections', { method: 'POST', memberships: k, query: { ws: 'skinotek' } })).res.body.code, 'module_write_denied', 'Theralia CSO rights do not carry to Skinotek');
});
