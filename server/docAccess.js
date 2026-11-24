'use strict';
// ============================================================================
// Document access authorization (R1b, S1.2a)
// ----------------------------------------------------------------------------
// Decides whether the logged-in user may open a stored document, using only
// server-side database records (document owner, explicit shares, supervisor
// assignments, report-thread ownership, file associations, and membership of
// the DOCUMENT'S OWN workspace). User-supplied workspace hints (x-workspace-slug,
// ?ws=) are never used as proof of membership.
//
// Staged enforcement (S1.2a), environment variable DOC_ACCESS_ENFORCE:
//   cross_workspace  (default when unset) deny every decision whose scope is
//                    'workspace': lab documents for accounts without an active
//                    NAT-Lab (LAB) membership, company/board/InvestRoom/asset
//                    documents for non-members of the document's workspace,
//                    and the retired AI-assistant account. Relationship-level
//                    denials between lab members are logged as would-deny.
//   all              deny every negative decision (full R1b-2 policy).
//   off              shadow only: log, never block. Temporary transition /
//                    emergency recovery mode; logged as a warning at startup.
//   any other value  configuration error: the STRICTEST mode ('all') is
//                    applied and an error is logged at startup; the policy is
//                    never silently weakened. The portal itself keeps running.
//
// Denials happen before the route handler runs, so no storage request or
// signed URL is ever made for a denied request. Evaluation errors fail closed
// (500) unless the mode is 'off'.
//
// Logs never contain filenames, document contents, emails, credentials or
// tokens. The actor is a short keyed hash, not the researcher id.
// ============================================================================
const crypto = require('crypto');

const MODES = ['off', 'cross_workspace', 'all'];
const DEFAULT_MODE = 'cross_workspace';

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const INT_RE = /^[0-9]{1,12}$/;

// --------------------------------------------------------- configuration
// Returns { mode, source: 'default'|'env'|'invalid', ok, diagnostic }.
function parseEnforceMode(raw) {
    if (raw === undefined || raw === null || String(raw).trim() === '') {
        return { mode: DEFAULT_MODE, source: 'default', ok: true, diagnostic: null };
    }
    const v = String(raw).trim().toLowerCase();
    if (MODES.includes(v)) return { mode: v, source: 'env', ok: true, diagnostic: null };
    const shown = JSON.stringify(String(raw).slice(0, 32));
    return {
        mode: 'all', source: 'invalid', ok: false,
        diagnostic: `DOC_ACCESS_ENFORCE=${shown} is not one of ${MODES.join('|')}; enforcing the strictest mode (all) until it is corrected`,
    };
}

// ---------------------------------------------------------------- pure rules
function roleOf(user) { return String((user && user.role) || '').toLowerCase(); }
function isPi(user) { return roleOf(user) === 'pi'; }
// The previous AI assistant was retired (S1.2a, D4): an ai_bot account has no
// document rights at all. A future assistant will get its own, separately
// designed scope; this keeps the role recognisable without privileges.
function isRetiredAiBot(user) { return roleOf(user) === 'ai_bot'; }
function isInvestor(user) {
    return roleOf(user) === 'investor' || String((user && user.workspace_position) || '').toLowerCase() === 'investor';
}
const allow = (rule) => ({ allow: true, rule, scope: null });
// scope 'workspace': crossing a lab/company boundary (or a retired account);
// scope 'relationship': same workspace, but no owner/share/supervision/etc.
const deny = (rule, scope) => ({ allow: false, rule, scope });
const AI_RETIRED = deny('ai_bot_access_retired', 'workspace');

// facts: { isOwner, isShareRecipient, isAssignedSupervisor, ownsThread, isAssociatedWithOwnFile,
//          isApprovedSop, natlabMember, workspaceType, workspaceMember, investorTabs }
function decideSubmission(user, facts) {
    if (isRetiredAiBot(user)) return AI_RETIRED;
    if (isPi(user)) return allow('pi');
    if (facts.isOwner) return allow('owner');
    if (facts.workspaceType === 'COMPANY') {
        // Company documents: members of the DOCUMENT'S workspace only. NAT-Lab
        // membership, shares, supervision or associations never open them.
        if (facts.workspaceMember && (!isInvestor(user) || facts.investorTabs.rnd === true || facts.investorTabs.glp_vision === true)) {
            return allow('company_workspace_member');
        }
        if (facts.workspaceMember) return deny('investor_tab_missing', 'relationship');
        return deny('not_member_of_document_workspace', 'workspace');
    }
    // Lab documents: an explicit, active NAT-Lab (LAB) membership is required
    // first; company membership never grants access.
    if (!facts.natlabMember) return deny('not_lab_member', 'workspace');
    if (facts.isShareRecipient) return allow('explicit_share');
    if (facts.isAssignedSupervisor) return allow('assigned_supervisor');
    if (facts.ownsThread) return allow('report_thread_owner');
    if (facts.isAssociatedWithOwnFile) return allow('association_of_own_file');
    if (facts.isApprovedSop) return allow('approved_sop_natlab_member');
    return deny('no_matching_rule', 'relationship');
}

// Workspace documents (company / Theralia / InvestRoom / board / assets).
// tab: required investor tab for investor accounts, or null (membership only).
function decideWorkspaceDoc(user, facts, tab) {
    if (isRetiredAiBot(user)) return AI_RETIRED;
    if (isPi(user)) return allow('pi');
    if (!facts.workspaceId) return deny('document_workspace_unknown', 'workspace');
    if (!facts.workspaceMember) return deny('not_member_of_document_workspace', 'workspace');
    if (tab && isInvestor(user) && facts.investorTabs[tab] !== true) return deny(`investor_tab_${tab}_missing`, 'relationship');
    return allow('document_workspace_member');
}

function decideNatlabDoc(user, facts) {
    if (isRetiredAiBot(user)) return AI_RETIRED;
    if (isPi(user)) return allow('pi');
    if (facts.natlabMember) return allow('natlab_member');
    return deny('not_lab_member', 'workspace');
}

function decideTrainingCertificate(user, facts) {
    if (isRetiredAiBot(user)) return AI_RETIRED;
    if (isPi(user)) return allow('pi');
    if (facts.isOwner) return allow('owner');
    if (facts.natlabMember === false) return deny('not_lab_member', 'workspace');
    if (facts.isAssignedSupervisor) return allow('assigned_supervisor');
    return deny('not_owner_or_supervisor', 'relationship');
}

function decidePiOnly(user, facts) {
    if (isRetiredAiBot(user)) return AI_RETIRED;
    if (isPi(user)) return allow('pi');
    if (facts && facts.natlabMember === false) return deny('not_lab_member', 'workspace');
    return deny('pi_required', 'relationship');
}

function isEnforced(decision, mode) {
    if (decision.allow) return false;
    if (mode === 'all') return true;
    if (mode === 'cross_workspace') return decision.scope === 'workspace';
    return false;
}

// ------------------------------------------------------------ DB lookups
function makeLookups(pool) {
    const q = async (sql, params) => (await pool.query(sql, params)).rows;
    async function workspaceType(wsId) {
        if (!wsId) return null;
        const r = await q('SELECT workspace_type FROM workspaces WHERE id = $1', [wsId]);
        return r[0] ? r[0].workspace_type : null;
    }
    async function membership(userId, wsId) {
        if (!userId || !wsId) return { member: false, tabs: {} };
        const r = await q(
            `SELECT investor_tab_permissions FROM workspace_users
              WHERE user_id = $1 AND workspace_id = $2 AND is_active = TRUE
                AND COALESCE(status, 'active') = 'active'`, [userId, wsId]);
        return { member: r.length > 0, tabs: (r[0] && r[0].investor_tab_permissions) || {} };
    }
    // NAT-Lab member (S1.2a, D3): the PI, or an account with an ACTIVE membership
    // of a LAB workspace. No role (supervisor, founder, investor) and no absence
    // of workspace rows implies NAT-Lab membership. Collaborators are LAB members
    // (membership_class 'collaborator') and keep NAT-Lab-member resources only.
    async function natlabMember(user) {
        if (isPi(user)) return true;
        if (!user || !user.researcher_id) return false;
        const rows = await q(
            `SELECT 1 FROM workspace_users wu JOIN workspaces w ON w.id = wu.workspace_id
              WHERE wu.user_id = $1 AND wu.is_active = TRUE AND COALESCE(wu.status, 'active') = 'active'
                AND w.workspace_type = 'LAB' LIMIT 1`, [user.researcher_id]);
        return rows.length > 0;
    }
    // Supervision requires the supervisor role AND a formal assignment (D8).
    async function assignedSupervisor(user, researcherId) {
        if (roleOf(user) !== 'supervisor' || !researcherId) return false;
        const r = await q('SELECT 1 FROM di_supervisor_researchers WHERE supervisor_id = $1 AND researcher_id = $2', [user.researcher_id, researcherId]);
        return r.length > 0;
    }
    async function tableExists(name) {
        const r = await q(`SELECT to_regclass($1) AS t`, ['public.' + name]);
        return !!(r[0] && r[0].t);
    }
    return { q, workspaceType, membership, natlabMember, assignedSupervisor, tableExists };
}

async function submissionFacts(pool, user, submissionId) {
    const L = makeLookups(pool);
    const rows = await L.q(
        `SELECT submission_id, researcher_id, file_type, status, workspace_id, report_thread_root_id
           FROM di_submissions WHERE submission_id = $1`, [submissionId]);
    if (!rows.length) return null;
    const s = rows[0];
    const uid = user.researcher_id;
    const facts = {
        isOwner: s.researcher_id === uid,
        isShareRecipient: false, isAssignedSupervisor: false, ownsThread: false, isAssociatedWithOwnFile: false,
        isApprovedSop: String(s.file_type || '').toUpperCase() === 'SOP' && String(s.status || '').toUpperCase() === 'APPROVED',
        natlabMember: false, workspaceType: await L.workspaceType(s.workspace_id), workspaceMember: false, investorTabs: {}
    };
    if (facts.isOwner || isPi(user) || isRetiredAiBot(user)) return facts;
    if (facts.workspaceType === 'COMPANY') {
        const m = await L.membership(uid, s.workspace_id); facts.workspaceMember = m.member; facts.investorTabs = m.tabs;
        return facts;
    }
    facts.natlabMember = await L.natlabMember(user);
    if (!facts.natlabMember) return facts;
    if (await L.tableExists('di_file_shares')) {
        facts.isShareRecipient = (await L.q(
            'SELECT 1 FROM di_file_shares WHERE submission_id = $1 AND recipient_researcher_id = $2 AND is_active = TRUE', [submissionId, uid])).length > 0;
    }
    facts.isAssignedSupervisor = await L.assignedSupervisor(user, s.researcher_id);
    if (s.report_thread_root_id) {
        facts.ownsThread = (await L.q('SELECT 1 FROM di_submissions WHERE submission_id = $1 AND researcher_id = $2', [s.report_thread_root_id, uid])).length > 0;
    }
    if (await L.tableExists('di_file_associations')) {
        facts.isAssociatedWithOwnFile = (await L.q(
            `SELECT 1 FROM di_file_associations fa JOIN di_submissions src ON src.submission_id::text = fa.source_id::text
              WHERE fa.target_id::text = $1 AND fa.deleted_at IS NULL AND src.researcher_id = $2 LIMIT 1`, [submissionId, uid])).length > 0;
    }
    return facts;
}

// --------------------------------------------------------- logging helpers
function actorHash(user) {
    const secret = process.env.SESSION_SECRET || 'r1b';
    return 'h:' + crypto.createHmac('sha256', secret).update(String((user && user.researcher_id) || '-')).digest('hex').slice(0, 10);
}
function logDecision(route, user, docId, decision, outcome, mode) {
    console.log(`[R1B-ACCESS] route=${route} decision=${outcome} rule=${decision.rule} role=${roleOf(user) || 'api'} actor=${user ? actorHash(user) : 'api-key'} doc=${String(docId).slice(0, 40)} scope=${decision.scope || '-'} mode=${mode}`);
}

// Access-denied response: a readable page for browser navigation, JSON otherwise.
function sendDenied(req, res) {
    const accept = String((req.headers && req.headers.accept) || '');
    if (accept.includes('text/html')) {
        return res.status(403).type('html').send(
            '<!DOCTYPE html><html><head><meta charset="utf-8"><title>Access denied - NATLAB GLP</title></head>' +
            '<body style="font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;background:#f0f0f0;margin:0;">' +
            '<div style="background:white;padding:40px;border-radius:10px;max-width:500px;box-shadow:0 4px 20px rgba(0,0,0,0.1);">' +
            '<h1 style="color:#1a365d;">Access denied</h1>' +
            '<p>You do not have permission to open this document.</p>' +
            '<p>If you need it for your work, ask the document owner or the PI to share it with you.</p>' +
            '<p style="margin-top:30px;"><a href="/di/access.html" style="color:#007bff;">Return to Portal</a></p>' +
            '</div></body></html>');
    }
    return res.status(403).json({ error: 'Access denied', code: 'document_access_denied' });
}

// ------------------------------------------------------------- middleware
// Wraps a decision function into Express middleware. Runs BEFORE the route
// handler: a denial never reaches storage or signed-URL generation.
function guard(pool, route, idParam, idKind, evaluate, getMode) {
    return async function docAccessGuard(req, res, next) {
        const user = req.session && req.session.user;
        const id = String(req.params[idParam] || '');
        const mode = getMode();
        if (!user) return next(); // the route's own login check (registered before this guard) answers 401
        if ((idKind === 'uuid' && !UUID_RE.test(id)) || (idKind === 'int' && !INT_RE.test(id))) return next(); // handler answers 404/400 as before
        try {
            const decision = await evaluate(pool, user, id);
            if (!decision) return next(); // document not found: existing handler answers 404
            const enforced = isEnforced(decision, mode);
            logDecision(route, user, id, decision, decision.allow ? 'allow' : (enforced ? 'deny' : 'would-deny'), mode);
            if (enforced) return sendDenied(req, res);
            return next();
        } catch (err) {
            console.error(`[R1B-ACCESS] route=${route} evaluation error mode=${mode}: ${err && err.message}`);
            if (mode === 'off') return next();
            return res.status(500).json({ error: 'Authorization check failed' }); // fail closed
        }
    };
}

// Evaluators: return a decision, or null when the document does not exist.
const evaluators = {
    async submission(pool, user, id) {
        const f = await submissionFacts(pool, user, id);
        return f ? decideSubmission(user, f) : null;
    },
    async groupDocument(pool, user, id) {
        const L = makeLookups(pool);
        const r = await L.q('SELECT workspace_id FROM di_group_documents WHERE id = $1', [id]);
        if (!r.length) return null;
        const t = await L.workspaceType(r[0].workspace_id);
        if (t === 'COMPANY') {
            const m = await L.membership(user.researcher_id, r[0].workspace_id);
            return decideWorkspaceDoc(user, { workspaceId: r[0].workspace_id, workspaceMember: m.member, investorTabs: m.tabs }, null);
        }
        return decideNatlabDoc(user, { natlabMember: await L.natlabMember(user) });
    },
    async trainingDocumentVersion(pool, user, id) {
        const L = makeLookups(pool);
        if (!(await L.q('SELECT 1 FROM di_training_document_versions WHERE id = $1', [id])).length) return null;
        return decideNatlabDoc(user, { natlabMember: await L.natlabMember(user) });
    },
    async trainingCertificate(pool, user, id) {
        const L = makeLookups(pool);
        const r = await L.q('SELECT researcher_id FROM di_training_packs WHERE id = $1', [id]);
        if (!r.length) return null;
        return decideTrainingCertificate(user, {
            isOwner: r[0].researcher_id === user.researcher_id,
            natlabMember: await L.natlabMember(user),
            isAssignedSupervisor: await L.assignedSupervisor(user, r[0].researcher_id),
        });
    },
    async systemVersion(pool, user, id) {
        const L = makeLookups(pool);
        if (!(await L.q('SELECT 1 FROM system_versions WHERE id = $1', [id])).length) return null;
        return decidePiOnly(user, { natlabMember: await L.natlabMember(user) });
    },
    workspaceDocBy(sql, tab) {
        return async (pool, user, id) => {
            const L = makeLookups(pool);
            const r = await L.q(sql, [id]);
            if (!r.length) return null;
            const wsId = r[0].workspace_id;
            const m = await L.membership(user.researcher_id, wsId);
            return decideWorkspaceDoc(user, { workspaceId: wsId, workspaceMember: m.member, investorTabs: m.tabs }, tab);
        };
    }
};

// opts.mode / opts.env allow tests to choose the configuration explicitly.
function makeGuards(pool, opts = {}) {
    const cfg = opts.mode ? parseEnforceMode(opts.mode) : parseEnforceMode((opts.env || process.env).DOC_ACCESS_ENFORCE);
    if (!cfg.ok) console.error(`[DOC-ACCESS] CONFIGURATION ERROR: ${cfg.diagnostic}`);
    else if (cfg.mode === 'off') console.warn('[DOC-ACCESS] WARNING: document-access enforcement is OFF (shadow only). Temporary transition / emergency recovery mode.');
    else console.log(`[DOC-ACCESS] document-access enforcement mode=${cfg.mode} (${cfg.source === 'default' ? 'default' : 'DOC_ACCESS_ENFORCE'})`);
    const getMode = () => cfg.mode;
    const g = (route, idParam, idKind, ev) => guard(pool, route, idParam, idKind, ev, getMode);
    const ws = (sql, tab) => evaluators.workspaceDocBy(sql, tab);
    return {
        config: cfg,
        submission: g('di-download', 'id', 'uuid', evaluators.submission),
        groupDocument: g('group-document', 'id', 'uuid', evaluators.groupDocument),
        trainingDocumentVersion: g('training-document', 'versionId', 'uuid', evaluators.trainingDocumentVersion),
        trainingCertificate: g('training-certificate', 'packId', 'uuid', evaluators.trainingCertificate),
        systemVersion: g('system-version', 'id', 'uuid', evaluators.systemVersion),
        // theralia_board_meetings.workspace_id is TEXT and holds the workspace
        // slug (e.g. 'theralia') or an id: resolve it to the real workspace id.
        boardMeetingFile: g('board-meeting-file', 'fileId', 'int', ws(
            `SELECT w.id AS workspace_id FROM theralia_board_meeting_files f
               JOIN theralia_board_meetings m ON m.id = f.meeting_id
               LEFT JOIN workspaces w ON w.slug = m.workspace_id OR w.id::text = m.workspace_id
              WHERE f.id = $1`, null)),
        investroomFile: g('investroom-file', 'fileId', 'uuid', ws(
            'SELECT b.workspace_id FROM investroom_phase_box_files f JOIN investroom_phase_boxes b ON b.id = f.box_id WHERE f.id = $1', null)),
        assetFile: g('asset-file', 'fileId', 'uuid', ws(
            'SELECT workspace_id FROM theralia_strategic_asset_files WHERE id = $1', null)),
        companyDocument: g('company-document', 'id', 'uuid', ws(
            'SELECT w.id AS workspace_id FROM company_documents d LEFT JOIN workspaces w ON w.slug = d.workspace_slug WHERE d.id = $1', 'company')),
        rdDocument: g('rd-document', 'id', 'uuid', ws(
            'SELECT workspace_id FROM rd_documents WHERE id = $1', 'rnd')),
    };
}

module.exports = {
    MODES, DEFAULT_MODE, UUID_RE, parseEnforceMode, isEnforced,
    decideSubmission, decideWorkspaceDoc, decideNatlabDoc, decideTrainingCertificate, decidePiOnly,
    isPi, isRetiredAiBot, isInvestor, actorHash, makeGuards, submissionFacts, sendDenied,
};
