'use strict';
// ============================================================================
// S1.4 / R1c — workspace authorization boundary
// ----------------------------------------------------------------------------
// One shared server-side boundary, built on the existing workspace_users
// membership model (no schema change):
//   1. authorizeWorkspace   — for every authenticated API request, loads the
//      caller's ACTIVE workspace memberships once and refuses an explicitly
//      requested workspace (x-workspace-slug / ?ws=) the caller is not a member
//      of. The PI is the only administrative exception (D1).
//   2. companyBoundary      — the company modules (/api/rd, /api/company,
//      /api/theralia, /api/investroom, /api/investor) require active membership
//      of the COMPANY workspace they act on, investors are read-only (except
//      their own activity tracking) and only see their authorised tabs, company
//      writes need the module's 'edit' clearance, and every mutation or read of
//      a specific record is checked against that record's real workspace.
//   3. requireLabMember     — NAT-Lab-only resources (training, inventory).
//   4. csrfGuard            — same-origin check for every state-changing API
//      request (POST/PUT/PATCH/DELETE), on both domains, no cross-domain trust.
//   5. stripStorageKeys     — removes internal storage keys from every JSON API
//      response (replaced by has_file).
// Document contents stay governed independently by server/docAccess.js.
// Group Meetings (/api/group-meetings) is outside the company boundary and
// keeps its own explicit membership policy.
// Lookup failures fail closed.
// ============================================================================

const STORAGE_KEY_FIELDS = new Set(['r2_object_key', 'r2_key', 'certificate_r2_key', 'signed_pdf_path', 'r2_snapshot_key', 'r2_harmony_key', 'r2ObjectKey']);
const STATE_CHANGING = new Set(['POST', 'PUT', 'PATCH', 'DELETE']);
const COMPANY_PREFIXES = ['/api/rd', '/api/company', '/api/theralia', '/api/investroom', '/api/investor'];
// Investors may write only their own portal-activity records (existing tracking).
const INVESTOR_WRITE_ALLOW = [
    /^\/api\/investor\/(log-tab-access|record-visit|record-activity|session-start|session-heartbeat|request-meeting)$/,
];

// The only PUBLIC endpoint under the company prefixes: the sendBeacon session
// finaliser (beacons may arrive without the cookie; its unguessable session id is
// the token and it can only close that open tracking session). Still CSRF-checked.
// (The meeting-request form is used only inside the logged-in portal and now
// requires a session: investors may submit it — see INVESTOR_WRITE_ALLOW.)
const PUBLIC_COMPANY_PATHS = new Set(['/api/investor/session-end']);

const isPi = (user) => String((user && user.role) || '').toLowerCase() === 'pi';

function deny(res, status, code, message) {
    return res.status(status).json({ error: message, code });
}

// ---------------------------------------------------------------- memberships
async function loadMemberships(pool, researcherId) {
    const r = await pool.query(
        // Optional columns are read through to_jsonb so older schemas still work.
        `SELECT w.id AS workspace_id, w.slug, w.workspace_type, to_jsonb(wu)->>'role' AS role,
                LOWER(COALESCE(to_jsonb(wu)->>'workspace_position', '')) AS position,
                to_jsonb(wu)->>'membership_class' AS membership_class,
                COALESCE((to_jsonb(wu)->>'is_workspace_master')::boolean, FALSE) AS is_master,
                COALESCE(to_jsonb(wu)->'investor_tab_permissions', '{}'::jsonb) AS investor_tabs,
                COALESCE(to_jsonb(wu)->'clearance_config', '{}'::jsonb) AS clearance_config
           FROM workspace_users wu JOIN workspaces w ON w.id = wu.workspace_id
          WHERE wu.user_id = $1 AND wu.is_active = TRUE AND COALESCE(to_jsonb(wu)->>'status', 'active') = 'active'
            AND COALESCE((to_jsonb(w)->>'is_active')::boolean, TRUE)`,
        [researcherId]);
    return new Map(r.rows.map(row => [row.slug, row]));
}

function makeWorkspaceAccess(pool, { getGovernanceDefaults = () => ({}), trustedOrigins = [] } = {}) {
    // ------------------------------------------------------------ 1. boundary
    async function authorizeWorkspace(req, res, next) {
        const user = req.session && req.session.user;
        if (!user) return next();
        try {
            const memberships = await loadMemberships(pool, user.researcher_id);
            const labMember = [...memberships.values()].some(m => m.workspace_type === 'LAB');
            req.workspaceAccess = { isPi: isPi(user), memberships, labMember };
        } catch (err) {
            console.error('[WS-AUTH] membership lookup failed (fail closed):', err && err.message);
            return deny(res, 503, 'workspace_check_unavailable', 'Workspace authorization temporarily unavailable. Please try again.');
        }
        if (req.workspaceExplicit && !req.workspaceAccess.isPi && !req.workspaceAccess.memberships.has(req.workspace_slug)) {
            return deny(res, 403, 'workspace_access_denied', 'You are not a member of this workspace.');
        }
        return next();
    }

    function allowedWorkspaceIds(req) {
        const a = req.workspaceAccess;
        if (!a) return [];
        return [...a.memberships.values()].map(m => m.workspace_id);
    }

    // NAT-Lab-only resources: active LAB membership (or the PI).
    function requireLabMember(req, res, next) {
        if (!req.session || !req.session.user) return deny(res, 401, 'not_authenticated', 'Not authenticated');
        const a = req.workspaceAccess;
        if (a && (a.isPi || a.labMember)) return next();
        return deny(res, 403, 'lab_membership_required', 'NAT-Lab workspace membership required.');
    }

    // ------------------------------------------------------- 2. company modules
    // Effective module clearance — identical to what /api/di/me gives the portal:
    // position defaults merged with the per-user User Control settings; the CSO
    // position always has the full CSO template (existing rule).
    function clearanceOf(m) {
        const all = getGovernanceDefaults() || {};
        if (m.position === 'cso' && all.cso) return { ...all.cso };
        const defaults = all[m.position] || {};
        const stored = (m.clearance_config && typeof m.clearance_config === 'object') ? m.clearance_config : {};
        return { ...defaults, ...stored };
    }

    // ---------------------------------------------- A2: module clearance
    // Hidden = no read/write; View = read only; Edit = read + write. A level that
    // is not set at all counts as Hidden (User Control displays it as Hidden).
    // Module clearance is a NECESSARY condition only: every existing guard
    // (membership, role, position, board, executive, investor, document rules)
    // still applies afterwards, so Edit never widens anything.
    // Endpoints shared by several modules need clearance in ALL of them.
    const MODULE_ROUTES = [
        { re: /^\/api\/company\//, modules: ['company'] },
        { re: /^\/api\/rd\/glp\//, modules: ['glp'] },
        { re: /^\/api\/rd\//, modules: ['rnd'] },
        { re: /^\/api\/theralia\/inventory\//, modules: ['inventory'] },
        { re: /^\/api\/theralia\/board-meeting/, modules: ['dashboard'] },   // board panel lives on the Dashboard
        { re: /^\/api\/investroom\//, modules: ['investroom'] },
        { re: /^\/api\/investor\/(visitors|kpis|activity)$/, modules: ['investroom', 'investors'] }, // investor intelligence (InvestRoom tab)
        { re: /^\/api\/theralia\/(users|investor-optional-tabs|governance-defaults)(\/|$)/, modules: ['user_control'] },
        { re: /^\/api\/theralia\/audit-log$/, modules: ['audit'] },
    ];
    // User Control levels: hidden / investors_only / full.
    const UC_INVESTOR_WRITES = /^\/api\/theralia\/users\/[^/]+\/(reset-code|investor-permissions|upgrade-to-password)$/;
    function moduleDecision(member, method, path) {
        const route = MODULE_ROUTES.find(r => r.re.test(path));
        if (!route) return null; // self-service investor tracking / meeting request: no module
        const cl = clearanceOf(member);
        const writing = STATE_CHANGING.has(method);
        for (const mod of route.modules) {
            const level = cl[mod] || 'hidden';
            if (mod === 'user_control') {
                if (level === 'hidden') return { mod, code: 'module_hidden' };
                if (writing && level !== 'full' && !(level === 'investors_only' && UC_INVESTOR_WRITES.test(path))) return { mod, code: 'module_write_denied' };
                continue;
            }
            if (level === 'hidden' || (level !== 'view' && level !== 'edit')) return { mod, code: 'module_hidden' };
            if (writing && level !== 'edit') return { mod, code: 'module_write_denied' };
        }
        return null;
    }
    const isInvestorMember = (user, m) =>
        String(user.role || '').toLowerCase() === 'investor' || String(m.role || '').toLowerCase() === 'investor' || m.position === 'investor';

    // Effective workspace exactly as the route handlers determine it.
    function effectiveWorkspace(req, path) {
        if (path.startsWith('/api/rd')) return { slug: req.workspace_slug, source: 'resolver' };
        if (path.startsWith('/api/company')) return { slug: req.query.ws || 'theralia', source: 'company' };
        return { slug: 'theralia', source: 'fixed' }; // /api/theralia, /api/investroom, /api/investor
    }

    // Write permission per endpoint (D3). Routes not listed keep their own
    // existing position guards (requireRDWrite, canDecideGLP, requireCSO,
    // requireCeoOrCso, requireBmFounder, inline checks).
    // (Module read/write clearance — company, inventory, … — is handled by moduleDecision.)
    function writeRequirement(method, path) {
        // The existing R&D / GLP guards read the caller's position in Theralia only;
        // this re-checks the SAME rule against the position held in the workspace
        // actually acted on. It runs in addition to them, so it can only narrow.
        if (path.startsWith('/api/rd/glp/')) return { label: 'GLP decision', positions: ['cso', 'coo'] };
        if (path.startsWith('/api/rd/')) return { label: 'R&D write', positions: ['cso', 'cto', 'coo'], roles: ['r_and_d'] };
        return null;
    }
    function meetsRequirement(member, reqmt) {
        if (member.is_master) return true;
        return reqmt.positions.includes(member.position) || (reqmt.roles || []).includes(String(member.role || '').toLowerCase());
    }

    // Object-level checks: the target record's real workspace (D/§4).
    const RESOURCE_CHECKS = [
        { re: /^\/api\/company\/documents\/([0-9a-f-]{36})$/i, methods: ['DELETE'],
          sql: `SELECT w.id FROM company_documents d LEFT JOIN workspaces w ON w.slug = d.workspace_slug WHERE d.id = $1` },
        { re: /^\/api\/rd\/documents\/([0-9a-f-]{36})(\/download)?$/i, methods: ['GET', 'DELETE'], sql: `SELECT workspace_id AS id FROM rd_documents WHERE id = $1` },
        { re: /^\/api\/rd\/projects\/([0-9a-f-]{36})(\/documents)?$/i, methods: ['GET', 'POST', 'PATCH'], sql: `SELECT workspace_id AS id FROM rd_projects WHERE id = $1` },
        { re: /^\/api\/rd\/(programs|partners|grants)\/([0-9a-f-]{36})$/i, methods: ['PATCH'], group: 2,
          sqlByTable: { programs: 'rd_programs', partners: 'rd_partners', grants: 'rd_grants' } },
        { re: /^\/api\/rd\/glp\/(approve|revise|discard|seal|coo-review)\/([0-9a-f-]{36})$/i, methods: ['POST'], group: 2,
          sql: `SELECT workspace_id AS id FROM di_submissions WHERE submission_id = $1` },
        { re: /^\/api\/theralia\/board-meetings\/(\d{1,12})(\/.*)?$/, methods: ['GET', 'PUT', 'PATCH', 'POST'],
          sql: `SELECT w.id FROM theralia_board_meetings m LEFT JOIN workspaces w ON w.slug = m.workspace_id OR w.id::text = m.workspace_id WHERE m.id = $1` },
        { re: /^\/api\/investroom\/boxes\/([0-9a-f-]{36})(\/(files|move))?$/i, methods: ['PUT', 'DELETE', 'POST'],
          sql: `SELECT workspace_id AS id FROM investroom_phase_boxes WHERE id = $1` },
        { re: /^\/api\/investroom\/files\/([0-9a-f-]{36})(\/review)?$/i, methods: ['PATCH', 'DELETE'],
          sql: `SELECT b.workspace_id AS id FROM investroom_phase_box_files f JOIN investroom_phase_boxes b ON b.id = f.box_id WHERE f.id = $1` },
        { re: /^\/api\/theralia\/inventory\/(purchases|strategic-assets)\/([0-9a-f-]{36})(\/files)?$/i, methods: ['GET', 'PUT', 'POST'], group: 2,
          sqlByTable: { purchases: 'theralia_purchases', 'strategic-assets': 'theralia_strategic_assets' }, tableGroup: 1 },
        { re: /^\/api\/theralia\/inventory\/asset-files\/([0-9a-f-]{36})$/i, methods: ['DELETE'], sql: `SELECT workspace_id AS id FROM theralia_strategic_asset_files WHERE id = $1` },
    ];

    async function resourceWorkspace(method, path) {
        for (const c of RESOURCE_CHECKS) {
            const m = path.match(c.re);
            if (!m || !c.methods.includes(method)) continue;
            const id = m[c.group || 1];
            const sql = c.sql || `SELECT workspace_id AS id FROM ${c.sqlByTable[m[c.tableGroup || 1]]} WHERE id = $1`;
            const r = await pool.query(sql, [id]);
            return { checked: true, found: r.rows.length > 0, workspaceId: r.rows[0] ? r.rows[0].id : null };
        }
        return { checked: false };
    }

    async function companyBoundary(req, res, next) {
        const user = req.session && req.session.user;
        const path = req.baseUrl + req.path; // mounted prefix + remainder
        if (req.method === 'POST' && PUBLIC_COMPANY_PATHS.has(path)) return next();
        if (!user) return deny(res, 401, 'not_authenticated', 'Not authenticated');
        const access = req.workspaceAccess;
        if (!access) return deny(res, 503, 'workspace_check_unavailable', 'Workspace authorization temporarily unavailable. Please try again.');
        // D4: academic inventory / oligo bridges are PI-only for now.
        if (path.startsWith('/api/theralia/bridge/')) {
            return access.isPi ? next() : deny(res, 403, 'pi_only', 'Restricted to the PI.');
        }
        const eff = effectiveWorkspace(req, path);
        const header = req.headers['x-workspace-slug'];
        if (header && eff.source !== 'resolver' && header !== eff.slug) {
            return deny(res, 400, 'workspace_conflict', 'Conflicting workspace selection.');
        }
        if (path.startsWith('/api/theralia/inventory/') && req.workspace_slug !== 'theralia') {
            return deny(res, 400, 'workspace_mismatch', 'This module requires ws=theralia.');
        }
        let ws;
        try {
            // R&D links that name no workspace (e.g. a document download link) act
            // on the TARGET RECORD's own workspace — never on the default 'natlab'.
            if (eff.source === 'resolver' && !req.workspaceExplicit) {
                const rw0 = await resourceWorkspace(req.method, path);
                if (rw0.checked && rw0.found && rw0.workspaceId) {
                    ws = (await pool.query(`SELECT id, slug, workspace_type FROM workspaces WHERE id = $1 AND is_active = TRUE`, [rw0.workspaceId])).rows[0];
                }
            }
            if (!ws) ws = (await pool.query(`SELECT id, slug, workspace_type FROM workspaces WHERE slug = $1 AND is_active = TRUE`, [eff.slug])).rows[0];
        } catch (err) {
            console.error('[WS-AUTH] workspace lookup failed (fail closed):', err && err.message);
            return deny(res, 503, 'workspace_check_unavailable', 'Workspace authorization temporarily unavailable. Please try again.');
        }
        if (!ws) return deny(res, 400, 'invalid_workspace', 'Invalid workspace');
        // Some handlers also read ?workspace= (legacy selector): it may only repeat the authorised workspace.
        if (req.query.workspace !== undefined && String(req.query.workspace) !== ws.slug) {
            return deny(res, 400, 'workspace_conflict', 'Conflicting workspace selection.');
        }
        // D2: company modules never serve an academic (LAB) workspace — not even to the PI.
        if (ws.workspace_type !== 'COMPANY') return deny(res, 403, 'company_module_only', 'This module is available for company workspaces only.');
        const member = access.memberships.get(ws.slug);
        if (!access.isPi && !member) return deny(res, 403, 'workspace_access_denied', 'You are not a member of this workspace.');
        const writing = STATE_CHANGING.has(req.method);
        if (!access.isPi) {
            const investor = isInvestorMember(user, member);
            if (investor) {
                if (writing && !INVESTOR_WRITE_ALLOW.some(re => re.test(path))) {
                    return deny(res, 403, 'investor_read_only', 'Investor access is read-only.');
                }
                // Investors only see resources their tabs authorise (company / R&D / GLP Vision are
                // enforced by the tab guards, per acted-on workspace); board, inventory and InvestRoom
                // have no investor tab.
                // A3: InvestRoom is the founders' data room (the portal opens it only for CEO/CSO/founders/master).
                if (path.startsWith('/api/theralia/board-meeting') || path.startsWith('/api/theralia/inventory/') || path.startsWith('/api/investroom/')
                    || /^\/api\/investor\/(visitors|kpis|activity)$/.test(path)) { // founders' investor intelligence
                    return deny(res, 403, 'investor_tab_required', 'Not available for investor accounts.');
                }
            } else {
                // A2: module clearance of THIS workspace (the workspace master — the company's
                // administrative owner — is not subject to module clearance, as before).
                if (!member.is_master) {
                    const md = moduleDecision(member, req.method, path);
                    if (md) {
                        return md.code === 'module_hidden'
                            ? deny(res, 403, 'module_hidden', `You do not have access to the ${md.mod} module.`)
                            : deny(res, 403, 'module_write_denied', `Edit permission for the ${md.mod} module is required.`);
                    }
                }
                if (writing) {
                    const reqmt = writeRequirement(req.method, path);
                    if (reqmt && !meetsRequirement(member, reqmt)) {
                        return deny(res, 403, 'module_write_denied', `Your position in this workspace does not allow this action (${reqmt.label}).`);
                    }
                }
            }
        }
        // Object-level: the target's real workspace must be the authorised one.
        try {
            const rw = await resourceWorkspace(req.method, path);
            if (rw.checked && rw.found && String(rw.workspaceId) !== String(ws.id)) {
                return deny(res, 404, 'not_found', 'Not found'); // never confirm another workspace's records
            }
        } catch (err) {
            console.error('[WS-AUTH] resource lookup failed (fail closed):', err && err.message);
            return deny(res, 503, 'workspace_check_unavailable', 'Workspace authorization temporarily unavailable. Please try again.');
        }
        req.companyWorkspace = ws;
        return next();
    }

    // --------------------------------------------------------------- 4. CSRF
    // Same-origin for every state-changing API request. A browser always sends
    // Origin on cross-site and same-origin POST/PUT/PATCH/DELETE; requests with
    // neither Origin nor a same-origin Sec-Fetch-Site are refused (no legitimate
    // non-browser writer remains: API-key automation was retired in S1.2a).
    function csrfGuard(req, res, next) {
        if (!STATE_CHANGING.has(req.method)) return next();
        const host = String(req.get('host') || '').toLowerCase();
        const origin = req.get('origin');
        const fetchSite = String(req.get('sec-fetch-site') || '').toLowerCase();
        let ok = false;
        if (origin !== undefined) {
            let originHost = null;
            try { originHost = new URL(origin).host.toLowerCase(); } catch (_) { originHost = null; }
            ok = !!originHost && (originHost === host || trustedOrigins.includes(originHost)) && (!fetchSite || fetchSite === 'same-origin' || fetchSite === 'none');
        } else {
            ok = fetchSite === 'same-origin';
        }
        if (ok) return next();
        console.warn(`[CSRF] blocked ${req.method} ${req.originalUrl.split('?')[0]} origin=${origin === undefined ? '-' : String(origin).slice(0, 100)} fetch-site=${fetchSite || '-'}`);
        return deny(res, 403, 'cross_site_blocked', 'Cross-site request blocked');
    }

    // ------------------------------------------------------ 5. storage keys
    function scrub(value, depth) {
        if (depth > 8 || value === null || typeof value !== 'object') return value;
        if (Array.isArray(value)) return value.map(v => scrub(v, depth + 1));
        if (value instanceof Date || Buffer.isBuffer(value)) return value;
        const out = {};
        let hadKey = false, keyPresent = false;
        for (const [k, v] of Object.entries(value)) {
            if (STORAGE_KEY_FIELDS.has(k)) { hadKey = true; if (v) keyPresent = true; continue; }
            out[k] = scrub(v, depth + 1);
        }
        if (hadKey && !('has_file' in out)) out.has_file = keyPresent;
        return out;
    }
    function stripStorageKeys(req, res, next) {
        const json = res.json.bind(res);
        res.json = (body) => json(scrub(body, 0));
        next();
    }

    return { moduleDecision, authorizeWorkspace, companyBoundary, requireLabMember, csrfGuard, stripStorageKeys, allowedWorkspaceIds, clearanceOf, scrub };
}

module.exports = { makeWorkspaceAccess, COMPANY_PREFIXES, PUBLIC_COMPANY_PATHS, STORAGE_KEY_FIELDS, INVESTOR_WRITE_ALLOW, loadMemberships };
