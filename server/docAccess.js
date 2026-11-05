'use strict';
// ============================================================================
// R1b document access authorization
// ----------------------------------------------------------------------------
// Decides whether the logged-in user may open a stored document, using only
// server-side database records (document owner, explicit shares, supervisor
// assignments, report-thread ownership, file associations, and membership of
// the DOCUMENT'S OWN workspace). User-supplied workspace hints (x-workspace-slug,
// ?ws=) are never used as proof of membership.
//
// R1b-1: ENFORCE = false -> "shadow mode". Decisions are evaluated and logged as
//        allow / would-deny, but requests are NOT blocked by these rules.
//        (Only the separate login requirement on /api/di/download and the
//        internal-docs PI/AI-bot requirement are enforced in R1b-1.)
// R1b-2: flip ENFORCE to true in a separately approved release.
//
// Logs never contain filenames, document contents, emails, credentials or
// tokens. The actor is a short keyed hash, not the researcher id.
// ============================================================================
const crypto = require('crypto');

const ENFORCE = false;

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
const INT_RE = /^[0-9]{1,12}$/;

// ---------------------------------------------------------------- pure rules
function roleOf(user) { return String((user && user.role) || '').toLowerCase(); }
function isPiOrBot(user) { const r = roleOf(user); return r === 'pi' || r === 'ai_bot'; }
function isInvestor(user) {
    return roleOf(user) === 'investor' || String((user && user.workspace_position) || '').toLowerCase() === 'investor';
}

// facts: { isOwner, isShareRecipient, isAssignedSupervisor, ownsThread, isAssociatedWithOwnFile,
//          isApprovedSop, natlabMember, workspaceType, workspaceMember, investorTabs }
function decideSubmission(user, facts) {
    if (isPiOrBot(user)) return { allow: true, rule: 'pi_or_ai_bot' };
    if (facts.isOwner) return { allow: true, rule: 'owner' };
    if (facts.isShareRecipient) return { allow: true, rule: 'explicit_share' };
    if (facts.isAssignedSupervisor) return { allow: true, rule: 'assigned_supervisor' };
    if (facts.ownsThread) return { allow: true, rule: 'report_thread_owner' };
    if (facts.isAssociatedWithOwnFile) return { allow: true, rule: 'association_of_own_file' };
    if (facts.isApprovedSop && facts.natlabMember) return { allow: true, rule: 'approved_sop_natlab_member' };
    if (facts.workspaceType === 'COMPANY' && facts.workspaceMember &&
        (!isInvestor(user) || facts.investorTabs.rnd === true || facts.investorTabs.glp_vision === true)) {
        return { allow: true, rule: 'company_workspace_member' };
    }
    if (facts.isApprovedSop) return { allow: false, rule: 'approved_sop_not_natlab_member' };
    return { allow: false, rule: 'no_matching_rule' };
}

// Workspace documents (company / Theralia / InvestRoom / board / assets).
// tab: required investor tab for investor accounts, or null (membership only).
function decideWorkspaceDoc(user, facts, tab) {
    if (isPiOrBot(user)) return { allow: true, rule: 'pi_or_ai_bot' };
    if (!facts.workspaceId) return { allow: false, rule: 'document_workspace_unknown' };
    if (!facts.workspaceMember) return { allow: false, rule: 'not_member_of_document_workspace' };
    if (tab && isInvestor(user) && facts.investorTabs[tab] !== true) return { allow: false, rule: `investor_tab_${tab}_missing` };
    return { allow: true, rule: 'document_workspace_member' };
}

function decideNatlabDoc(user, facts) {
    if (isPiOrBot(user)) return { allow: true, rule: 'pi_or_ai_bot' };
    if (facts.natlabMember) return { allow: true, rule: 'natlab_member' };
    return { allow: false, rule: 'not_natlab_member' };
}

function decideTrainingCertificate(user, facts) {
    if (isPiOrBot(user)) return { allow: true, rule: 'pi_or_ai_bot' };
    if (facts.isOwner) return { allow: true, rule: 'owner' };
    if (facts.isAssignedSupervisor) return { allow: true, rule: 'assigned_supervisor' };
    return { allow: false, rule: 'not_owner_or_supervisor' };
}

function decidePiOnly(user) {
    return isPiOrBot(user) ? { allow: true, rule: 'pi_or_ai_bot' } : { allow: false, rule: 'pi_or_ai_bot_required' };
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
    // NAT-Lab member: privileged role, OR active member of a LAB workspace, OR a
    // legacy account with no active COMPANY-only membership (keeps users who have
    // no workspace_users row at all).
    async function natlabMember(user) {
        const r = roleOf(user);
        if (r === 'pi' || r === 'ai_bot' || r === 'supervisor') return true;
        const rows = await q(
            `SELECT w.workspace_type FROM workspace_users wu JOIN workspaces w ON w.id = wu.workspace_id
              WHERE wu.user_id = $1 AND wu.is_active = TRUE AND COALESCE(wu.status, 'active') = 'active'`, [user.researcher_id]);
        if (rows.some(x => x.workspace_type === 'LAB')) return true;
        return !rows.some(x => x.workspace_type === 'COMPANY');
    }
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
        isApprovedSop: s.file_type === 'SOP' && s.status === 'APPROVED',
        natlabMember: false, workspaceType: await L.workspaceType(s.workspace_id), workspaceMember: false, investorTabs: {}
    };
    if (facts.isOwner || isPiOrBot(user)) return facts;
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
    facts.natlabMember = await L.natlabMember(user);
    if (facts.workspaceType === 'COMPANY') {
        const m = await L.membership(uid, s.workspace_id); facts.workspaceMember = m.member; facts.investorTabs = m.tabs;
    }
    return facts;
}

// --------------------------------------------------------- logging helpers
function actorHash(user) {
    const secret = process.env.SESSION_SECRET || 'r1b';
    return 'h:' + crypto.createHmac('sha256', secret).update(String((user && user.researcher_id) || '-')).digest('hex').slice(0, 10);
}
function logDecision(route, user, docId, decision, mode) {
    const outcome = decision.allow ? 'allow' : (mode === 'enforce' ? 'deny' : 'would-deny');
    console.log(`[R1B-ACCESS] route=${route} decision=${outcome} rule=${decision.rule} role=${roleOf(user) || 'api'} actor=${user ? actorHash(user) : 'api-key'} doc=${String(docId).slice(0, 40)}`);
}

// ------------------------------------------------------------- middleware
// Wraps a decision function into Express middleware. In shadow mode the
// request always continues; in enforce mode a deny returns 403.
// Errors inside the check never break the request in shadow mode.
function guard(pool, route, idParam, idKind, evaluate) {
    return async function r1bGuard(req, res, next) {
        const user = req.session && req.session.user;
        const id = String(req.params[idParam] || '');
        const mode = ENFORCE ? 'enforce' : 'shadow';
        if (!user) return next(); // login requirement is handled by the route's existing guard
        if ((idKind === 'uuid' && !UUID_RE.test(id)) || (idKind === 'int' && !INT_RE.test(id))) return next(); // handler answers 404/400 as before
        try {
            const decision = await evaluate(pool, user, id);
            if (!decision) return next(); // document not found: existing handler answers 404
            logDecision(route, user, id, decision, mode);
            if (!decision.allow && ENFORCE) return res.status(403).json({ error: 'Access denied' });
            return next();
        } catch (err) {
            console.error(`[R1B-ACCESS] route=${route} evaluation error: ${err && err.message}`);
            if (ENFORCE) return res.status(500).json({ error: 'Authorization check failed' });
            return next();
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
        return decideTrainingCertificate(user, { isOwner: r[0].researcher_id === user.researcher_id, isAssignedSupervisor: await L.assignedSupervisor(user, r[0].researcher_id) });
    },
    async systemVersion(pool, user, id) {
        const L = makeLookups(pool);
        if (!(await L.q('SELECT 1 FROM system_versions WHERE id = $1', [id])).length) return null;
        return decidePiOnly(user);
    },
    async workspaceDocBy(sql, tab) {
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

function makeGuards(pool) {
    const ws = (sql, tab) => async (p, u, id) => (await evaluators.workspaceDocBy(sql, tab))(p, u, id);
    return {
        submission: guard(pool, 'di-download', 'id', 'uuid', evaluators.submission),
        groupDocument: guard(pool, 'group-document', 'id', 'uuid', evaluators.groupDocument),
        trainingDocumentVersion: guard(pool, 'training-document', 'versionId', 'uuid', evaluators.trainingDocumentVersion),
        trainingCertificate: guard(pool, 'training-certificate', 'packId', 'uuid', evaluators.trainingCertificate),
        systemVersion: guard(pool, 'system-version', 'id', 'uuid', evaluators.systemVersion),
        boardMeetingFile: guard(pool, 'board-meeting-file', 'fileId', 'int', ws(
            'SELECT m.workspace_id FROM theralia_board_meeting_files f JOIN theralia_board_meetings m ON m.id = f.meeting_id WHERE f.id = $1', null)),
        investroomFile: guard(pool, 'investroom-file', 'fileId', 'uuid', ws(
            'SELECT b.workspace_id FROM investroom_phase_box_files f JOIN investroom_phase_boxes b ON b.id = f.box_id WHERE f.id = $1', null)),
        assetFile: guard(pool, 'asset-file', 'fileId', 'uuid', ws(
            'SELECT workspace_id FROM theralia_strategic_asset_files WHERE id = $1', null)),
        companyDocument: guard(pool, 'company-document', 'id', 'uuid', ws(
            'SELECT w.id AS workspace_id FROM company_documents d LEFT JOIN workspaces w ON w.slug = d.workspace_slug WHERE d.id = $1', 'company')),
        rdDocument: guard(pool, 'rd-document', 'id', 'uuid', ws(
            'SELECT workspace_id FROM rd_documents WHERE id = $1', 'rnd')),
    };
}

module.exports = {
    ENFORCE, UUID_RE,
    decideSubmission, decideWorkspaceDoc, decideNatlabDoc, decideTrainingCertificate, decidePiOnly,
    isPiOrBot, isInvestor, actorHash, makeGuards, submissionFacts,
};
