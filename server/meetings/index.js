'use strict';
// ============================================================================
// Group Meetings — R1 API (mounted at /api/group-meetings).
//
// A presentation/coordination layer over existing NAT-Lab submissions:
//   - reads di_submissions (SOP / DATA / PRESENTATION only), never writes it;
//   - no upload, approval, discard, archive, delete or metadata-edit actions;
//   - documents are streamed through the existing storage helper injected by
//     server.js (no new storage integration), after an ACTIVELY ENFORCED,
//     meeting-scoped authorization check (independent of docAccess shadow mode);
//   - membership is PI-controlled (meeting_group_members), checked on every
//     request against the authenticated session identity and the current
//     allowlist row. ?user= impersonation, headers and bodies are ignored;
//   - recurring Zoom links are plain, validated https URLs entered by the PI.
//     There is no Zoom API, SDK, credential or outbound call;
//   - disabled unless GROUP_MEETINGS_ENABLED is on: every route answers 404.
// ============================================================================
const express = require('express');
const policy = require('./policy');
const schema = require('./schema');
const { makeRepo } = require('./repo');
const { makeOccurrenceService } = require('./occurrences');
const { makeSessionService, SessionError } = require('./sessions');
const { actorHash } = require('../docAccess');

const DOC_PAGE_DEFAULT = 100;
const DOC_PAGE_MAX = 1000;
const OCCURRENCE_LIST_LIMIT = 50;
const SETTINGS_FIELDS = ['zoom_join_url', 'timezone', 'duration_minutes', 'default_day', 'default_time', 'location'];
const TIME_RE = /^([01]\d|2[0-3]):[0-5]\d$/;

function isFeatureEnabled(env = process.env) {
    return ['1', 'true', 'yes', 'on'].includes(String(env.GROUP_MEETINGS_ENABLED || '').trim().toLowerCase());
}

// Group Meetings is available to this session user: flag on AND the user is
// in the rollout audience (PI always). Also used by server.js to retire the
// legacy meeting announcements ONLY for users who have the new utility.
function isAvailableFor(sessionUser, env = process.env) {
    if (!sessionUser || !isFeatureEnabled(env)) return false;
    return policy.audienceIncludes(policy.parseAudience(env), {
        id: String(sessionUser.researcher_id || ''), isPi: String(sessionUser.role || '').toLowerCase() === 'pi',
    });
}

function log(route, outcome, req) {
    const u = req && req.session && req.session.user;
    console.log(`[GROUP-MEETINGS] route=${route} outcome=${outcome} actor=${u ? actorHash(u) : '-'}`);
}

function groupView(g) {
    return {
        code: g.code, name: g.name, site: g.site,
        timezone: g.timezone, duration_minutes: g.duration_minutes,
        default_day: g.default_day, default_time: g.default_time ? String(g.default_time).slice(0, 5) : null,
        location: g.location,
        zoom_configured: !!g.zoom_join_url,
        zoom_join_url: g.zoom_join_url || null, // only ever returned to the PI or a current member
    };
}

function adminGroupView(g) {
    return { id: g.id, is_active: g.is_active, member_count: g.member_count, ...groupView(g) };
}

function documentView(d, actor) {
    return {
        submission_id: d.submission_id,
        // Owner or PI only; other members see the listing but cannot open.
        can_open: policy.isOwnerOrPi(actor, d.researcher_id),
        title: d.original_filename,
        file_type: policy.displayFileType(d.file_type),
        status: String(d.status || 'PENDING').toUpperCase(),
        submitted_at: d.created_at,
        approved_at: d.signed_at || null,
        legacy: d.record_origin === 'legacy_pre2026',
        original_date: d.original_created_at || null,
        meeting_status: null, // presented / discussed: R3
    };
}

function occurrenceView(o) {
    return {
        id: o.id, scheduled_start: o.scheduled_start, duration_minutes: o.duration_minutes,
        status: o.status, status_note: o.status_note, started_at: o.started_at, ended_at: o.ended_at,
    };
}

// Opaque keyset cursor: (sort timestamp with microseconds as text, submission id).
function encodeCursor(row) {
    return Buffer.from(JSON.stringify({ t: row.sort_ts, id: row.submission_id })).toString('base64url');
}
function decodeCursor(value) {
    if (value === undefined || value === null || value === '') return { ok: true, cursor: null };
    try {
        const c = JSON.parse(Buffer.from(String(value), 'base64url').toString('utf8'));
        if (c && typeof c.t === 'string' && /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d{1,6})?$/.test(c.t) && policy.isUuid(c.id)) {
            return { ok: true, cursor: c };
        }
    } catch (_) { /* fall through */ }
    return { ok: false };
}
function parsePageSize(value) {
    if (value === undefined || value === '') return DOC_PAGE_DEFAULT;
    const n = Number(value);
    return Number.isInteger(n) && n >= 1 && n <= DOC_PAGE_MAX ? n : null;
}

function safeFilenameHeader(name, disposition) {
    const n = String(name || 'document.pdf');
    const ascii = n.replace(/[^A-Za-z0-9._ -]/g, '_').slice(0, 150) || 'document.pdf';
    return `${disposition}; filename="${ascii}"; filename*=UTF-8''${encodeURIComponent(n)}`;
}

function createGroupMeetingsRouter(deps) {
    const {
        pool,
        repo = makeRepo(pool),
        isEnabled = () => isFeatureEnabled(),
        audience = () => policy.parseAudience(process.env),
        schemaReady = () => schema.isSchemaReady(pool),
        requireSameOrigin = (req, res, next) => next(),
        downloadFromR2,
        normalizeR2Key,
        r2Enabled,
        onOccurrenceEvent = null,
        now = () => new Date(),
        // R3.1 sessions: require BOTH flags; separate schema readiness.
        sessionsEnabled = () => isFeatureEnabled() && policy.isSessionsFlagOn(process.env),
        sessionSchemaReady = () => schema.isSessionSchemaReady(pool),
        sessions = pool ? makeSessionService(pool, { onEvent: onOccurrenceEvent, now }) : null,
    } = deps;
    const occurrences = makeOccurrenceService(repo, { onEvent: onOccurrenceEvent });
    const router = express.Router();

    // R3.2: fill meeting_status on listed documents (presented / discussed in the
    // active meeting; last meeting date at which presented). Unchanged (null)
    // when sessions are not active. Never includes private comments.
    async function withMeetingStatus(groupId, docs) {
        if (!docs.length || !(await sessionsReadyNow())) return docs;
        let m;
        try { m = await repo.documentMeetingStatus(groupId, docs.map(d => d.submission_id)); }
        catch (e) { // R2 listing unaffected; diagnostic = SQLSTATE only (no values, names or ids)
            console.warn(`[GROUP-MEETINGS] meeting status unavailable code=${(e && e.code) || 'n/a'}`); return docs;
        }
        return docs.map(d => {
            const s = m.get(d.submission_id);
            return {
                ...d,
                meeting_status: s ? {
                    presented_in_session: !!s.presented_in_session,
                    discussed_in_session: !!s.discussed_in_session,
                    last_presented_on: s.last_presented_on || null,
                    last_presenter_name: s.last_presenter_name || null,
                } : null,
            };
        });
    }

    // R3: sessions usable = both flags on AND session schema ready (cached).
    let sessionReadyCache = { value: false, at: 0 };
    async function sessionsReadyNow() {
        if (!sessions || !sessionsEnabled()) return false;
        const t = Date.now();
        const ttl = sessionReadyCache.value ? 300000 : 15000;
        if (t - sessionReadyCache.at > ttl) {
            try { sessionReadyCache = { value: await sessionSchemaReady(), at: t }; }
            catch (_) { sessionReadyCache = { value: false, at: t }; }
        }
        return sessionReadyCache.value;
    }

    // 1. Feature flag: everything is 404 while disabled.
    router.use((req, res, next) => {
        if (!isEnabled()) return res.status(404).json({ error: 'Not found' });
        res.set('Cache-Control', 'no-store');
        next();
    });

    // 2. Schema readiness (cached). Missing tables => 503, nothing else breaks.
    let readyCache = { value: false, at: 0 };
    router.use(async (req, res, next) => {
        const t = Date.now();
        const ttl = readyCache.value ? 300000 : 15000;
        if (t - readyCache.at > ttl) {
            try { readyCache = { value: await schemaReady(), at: t }; }
            catch (_) { readyCache = { value: false, at: t }; }
        }
        if (!readyCache.value) return res.status(503).json({ error: 'Group Meetings is not available.' });
        next();
    });

    // Feature status for the portals. 200 means: flag on, schema ready AND this
    // user is in the rollout audience — the portals then hide the legacy
    // meeting entry points for this user. Otherwise 404 => legacy UI unchanged.
    router.get('/status', (req, res) => {
        const u = req.session && req.session.user;
        if (!u) return res.status(401).json({ error: 'Not authenticated' });
        const inAudience = policy.audienceIncludes(audience(), { id: String(u.researcher_id || ''), isPi: String(u.role || '').toLowerCase() === 'pi' });
        if (!inAudience) return res.status(404).json({ error: 'Not found' });
        res.json({ enabled: true });
    });

    // 3. CSRF for writes (existing same-origin guard), then actor resolution.
    router.use(requireSameOrigin);
    router.use(async (req, res, next) => {
        const sessionUser = req.session && req.session.user;
        if (!sessionUser) return res.status(401).json({ error: 'Not authenticated' });
        const account = await repo.getAccount(String(sessionUser.researcher_id || ''));
        const c = policy.classifyActor(sessionUser, account);
        if (!c.ok) {
            log('actor', `deny:${c.reason}`, req);
            return res.status(c.status).json({ error: c.status === 401 ? 'Not authenticated' : 'Group Meetings is not available for this account.' });
        }
        if (!policy.audienceIncludes(audience(), c.actor)) {
            log('actor', 'deny:not_in_rollout_audience', req);
            return res.status(403).json({ error: 'Group Meetings is not yet available for your account.' });
        }
        req.gmActor = c.actor;
        next();
    });

    const requirePiActor = (req, res, next) => {
        if (!req.gmActor || !req.gmActor.isPi) return res.status(403).json({ error: 'PI role required.' });
        next();
    };

    // Loads an active coded group the actor may access (PI: any; member: own).
    async function loadAccessibleGroup(req, res) {
        const code = policy.normalizeGroupCode(req.params.code);
        if (!code) { res.status(404).json({ error: 'Meeting group not found' }); return null; }
        const group = await repo.getGroupByCode(code);
        if (!group) { res.status(404).json({ error: 'Meeting group not found' }); return null; }
        if (!req.gmActor.isPi && !(await repo.isMember(group.id, req.gmActor.id))) {
            log('group', 'deny:not_member', req);
            res.status(403).json({ error: 'You are not a member of this meeting group.' });
            return null;
        }
        return group;
    }

    async function loadAdminGroup(req, res) {
        const code = policy.normalizeGroupCode(req.params.code);
        const group = code ? await repo.getGroupByCode(code, { includeInactive: true }) : null;
        if (!group) { res.status(404).json({ error: 'Meeting group not found' }); return null; }
        return group;
    }

    // ------------------------------------------------------------ member API
    router.get('/me', async (req, res) => {
        const groups = await repo.listGroupsForActor(req.gmActor);
        res.json({
            enabled: true,
            // R3: lets the interface show session features only when BOTH flags
            // are on and the session schema is ready (no extra R3 requests otherwise).
            sessions: await sessionsReadyNow(),
            role: req.gmActor.isPi ? 'pi' : 'member',
            researcher_id: req.gmActor.id,
            groups: groups.map(g => ({ code: g.code, name: g.name, site: g.site, zoom_configured: !!g.zoom_join_url })),
        });
    });

    router.get('/groups/:code', async (req, res) => {
        const group = await loadAccessibleGroup(req, res);
        if (!group) return;
        const [lastCompleted, next] = await Promise.all([repo.lastCompletedAt(group.id), repo.nextScheduled(group.id)]);
        res.json({
            group: groupView(group),
            role: req.gmActor.isPi ? 'pi' : 'member',
            last_completed_at: lastCompleted || null,
            next_occurrence: next ? occurrenceView(next) : null,
        });
    });

    router.get('/groups/:code/overview', async (req, res) => {
        const group = await loadAccessibleGroup(req, res);
        if (!group) return;
        const win = policy.newSubmissionWindow(await repo.lastCompletedAt(group.id), now());
        const rows = await repo.overview(group.id, win.since);
        // R3.2: Last presented (meeting date) only when sessions are active.
        let lastPresented = null;
        if (await sessionsReadyNow()) {
            try { lastPresented = await repo.lastPresentedByResearcher(group.id); }
            catch (e) { console.warn(`[GROUP-MEETINGS] last presented unavailable code=${(e && e.code) || 'n/a'}`); } // R2 overview unaffected
        }
        res.json({
            group: { code: group.code, name: group.name },
            new_window: { since: win.since, fallback: win.fallback, basis: win.basis },
            last_presented_available: !!lastPresented,
            researchers: rows.map(r => ({
                researcher_id: r.researcher_id,
                name: r.name,
                is_self: r.researcher_id === req.gmActor.id,
                last_upload: r.last_upload || null,
                last_presented: lastPresented ? (lastPresented.get(r.researcher_id) || null) : null,
                new_count: r.new_count,
                total_count: r.total_count,
            })),
        });
    });

    router.get('/groups/:code/members/:researcherId/documents', async (req, res) => {
        const group = await loadAccessibleGroup(req, res);
        if (!group) return;
        const ownerId = String(req.params.researcherId || '');
        const filter = policy.normalizeFilter(req.query.filter);
        if (!filter) return res.status(400).json({ error: 'filter must be week, since_last or all' });
        if (!policy.isValidResearcherId(ownerId) || !(await repo.isMember(group.id, ownerId))) {
            return res.status(404).json({ error: 'Researcher not found in this meeting group' });
        }
        let since = null;
        let window = null;
        if (filter === 'week') {
            since = await repo.weekStart(group.timezone);
            window = { since, fallback: false, basis: 'current_calendar_week' };
        } else if (filter === 'since_last') {
            const w = policy.newSubmissionWindow(await repo.lastCompletedAt(group.id), now());
            since = w.since;
            window = { since, fallback: w.fallback, basis: w.basis };
        }
        const limit = parsePageSize(req.query.limit);
        if (!limit) return res.status(400).json({ error: `limit must be an integer between 1 and ${DOC_PAGE_MAX}` });
        const cur = decodeCursor(req.query.cursor);
        if (!cur.ok) return res.status(400).json({ error: 'Invalid cursor' });
        // Same eligibility rule for the count and for every page.
        const [rows, total] = await Promise.all([
            repo.listDocuments(group.id, ownerId, since, limit + 1, cur.cursor),
            repo.countDocuments(group.id, ownerId, since),
        ]);
        const page = rows.slice(0, limit);
        res.json({
            group: { code: group.code },
            researcher_id: ownerId,
            filter,
            window,
            total,
            page_size: limit,
            next_cursor: rows.length > limit ? encodeCursor(page[page.length - 1]) : null,
            documents: await withMeetingStatus(group.id, page.map(d => documentView(d, req.gmActor))),
        });
    });

    // Viewer source for GLP Vision (PDF.js / presentation mode), and the
    // download fallback. Read-only. ACTIVELY ENFORCED: owner or PI only,
    // whatever the approval status; checked before storage is contacted.
    router.get('/groups/:code/documents/:submissionId/file', async (req, res) => {
        const group = await loadAccessibleGroup(req, res);
        if (!group) return;
        const sid = String(req.params.submissionId || '');
        const row = policy.isUuid(sid) ? await repo.getListedDocument(group.id, sid) : null;
        if (!row) {
            log('document-file', 'deny:not_listed', req);
            return res.status(404).json({ error: 'Document not found' });
        }
        if (!policy.isOwnerOrPi(req.gmActor, row.researcher_id)) {
            log('document-file', 'deny:not_owner_or_pi', req);
            return res.status(403).json({ error: 'Only the document owner and the PI can open this document in Group Meetings.' });
        }
        const key = normalizeR2Key ? normalizeR2Key(row.r2_object_key) : null;
        if (!key) return res.status(409).json({ error: 'FILE_NOT_READY', message: 'File not available.' });
        if (!r2Enabled || !r2Enabled() || typeof downloadFromR2 !== 'function') {
            return res.status(503).json({ error: 'STORAGE_NOT_CONFIGURED', message: 'Document storage is not configured.' });
        }
        let obj;
        try {
            obj = await downloadFromR2(key);
        } catch (_) {
            log('document-file', 'storage_error', req);
            return res.status(502).json({ error: 'DOCUMENT_RETRIEVAL_FAILED', message: 'The document could not be retrieved.' });
        }
        log('document-file', 'allow', req);
        const disposition = req.query.download === '1' || req.query.download === 'true' ? 'attachment' : 'inline';
        res.setHeader('Content-Type', obj.ContentType || 'application/pdf');
        res.setHeader('Content-Disposition', safeFilenameHeader(row.original_filename, disposition));
        res.setHeader('X-Content-Type-Options', 'nosniff');
        res.setHeader('Cache-Control', 'private, no-store');
        if (obj.ContentLength) res.setHeader('Content-Length', String(obj.ContentLength));
        if (obj.Body && typeof obj.Body.pipe === 'function') {
            obj.Body.on('error', () => res.destroy());
            return obj.Body.pipe(res);
        }
        return res.end(obj.Body);
    });

    router.get('/groups/:code/occurrences', async (req, res) => {
        const group = await loadAccessibleGroup(req, res);
        if (!group) return;
        const rows = await repo.listOccurrences(group.id, OCCURRENCE_LIST_LIMIT);
        res.json({ group: { code: group.code }, occurrences: rows.map(occurrenceView) });
    });

    // ------------------------------------------------------------- PI admin
    // ------------------------------------------------ R3.1 sessions (gate)
    // Requires GROUP_MEETINGS_ENABLED AND GROUP_MEETINGS_SESSIONS_ENABLED;
    // otherwise 404 (the R2 workspace is unaffected). Session schema missing
    // -> 503 for session routes only.
    async function sessionGate(req, res, next) {
        if (!sessions || !sessionsEnabled()) return res.status(404).json({ error: 'Not found' });
        if (!(await sessionsReadyNow())) return res.status(503).json({ error: 'Meeting sessions are not available.' });
        next();
    }

    // Member-safe: is a meeting in progress in this group? (PI also gets
    // attendance counts.) Never returns notes, attendance rows or the log.
    router.get('/groups/:code/session', sessionGate, async (req, res) => {
        const group = await loadAccessibleGroup(req, res);
        if (!group) return;
        res.json({ group: { code: group.code }, active: await sessions.activeSummary(group.id, req.gmActor.isPi) });
    });

    // R3.2 meeting history (CURRENT membership required; documents shown only
    // if currently listed; owner-and-PI-only opening unchanged).
    router.get('/groups/:code/history', sessionGate, async (req, res) => {
        const group = await loadAccessibleGroup(req, res);
        if (!group) return;
        const limit = parsePageSize(req.query.limit === undefined ? '20' : req.query.limit);
        if (!limit || limit > 100) return res.status(400).json({ error: 'limit must be an integer between 1 and 100' });
        let cursor = null;
        if (req.query.cursor) {
            try {
                const c = JSON.parse(Buffer.from(String(req.query.cursor), 'base64url').toString('utf8'));
                if (!c || !policy.isUuid(c.id) || Number.isNaN(new Date(c.t).getTime())) throw new Error('bad');
                cursor = c;
            } catch (_) { return res.status(400).json({ error: 'Invalid cursor' }); }
        }
        const h = await sessions.history(group.id, { limit, cursor });
        const last = h.rows[h.rows.length - 1];
        res.json({
            group: { code: group.code },
            meetings: h.rows.map(o => ({
                id: o.id, date: o.started_at, started_at: o.started_at, ended_at: o.ended_at, origin: o.origin,
                duration_minutes: o.started_at && o.ended_at ? Math.round((new Date(o.ended_at) - new Date(o.started_at)) / 60000) : null,
                presented: o.presented, discussed: o.discussed,
            })),
            next_cursor: h.more && last ? Buffer.from(JSON.stringify({ t: new Date(last.started_at).toISOString(), id: last.id })).toString('base64url') : null,
        });
    });

    router.get('/groups/:code/history/:occurrenceId', sessionGate, async (req, res) => {
        const group = await loadAccessibleGroup(req, res);
        if (!group) return;
        const oid = String(req.params.occurrenceId || '');
        if (!policy.isUuid(oid)) return res.status(404).json({ error: 'Meeting not found' });
        res.json(await sessions.historyDetail(group.id, oid, req.gmActor));
    });

    router.use('/admin', requirePiActor);

    router.get('/admin/groups', async (req, res) => {
        const rows = await repo.listAllGroups();
        res.json({ groups: rows.map(adminGroupView) });
    });

    // Assign a stable code to an existing group whose code is still empty
    // (e.g. a migration-033 group renamed before R1). Never creates groups.
    router.put('/admin/groups/:groupId/code', async (req, res) => {
        const groupId = String(req.params.groupId || '');
        const code = policy.normalizeGroupCode(req.body && req.body.code);
        if (!policy.isUuid(groupId)) return res.status(404).json({ error: 'Meeting group not found' });
        if (!code) return res.status(400).json({ error: 'code must be LIU, UNAV or JOINT' });
        const g = await repo.getGroupById(groupId);
        if (!g) return res.status(404).json({ error: 'Meeting group not found' });
        if (g.code) return res.status(409).json({ error: 'This meeting group already has a code.' });
        try {
            const updated = await repo.assignCode(groupId, code);
            if (!updated) return res.status(409).json({ error: 'This meeting group already has a code.' });
            log('admin.assign-code', 'ok', req);
            res.json({ success: true, group: adminGroupView(updated) });
        } catch (err) {
            if (err && err.code === '23505') return res.status(409).json({ error: 'This code is already assigned to another meeting group.' });
            throw err;
        }
    });

    router.patch('/admin/groups/:code/settings', async (req, res) => {
        const group = await loadAdminGroup(req, res);
        if (!group) return;
        const body = req.body && typeof req.body === 'object' && !Array.isArray(req.body) ? req.body : null;
        if (!body) return res.status(400).json({ error: 'JSON object body required' });
        const unknown = Object.keys(body).filter(k => !SETTINGS_FIELDS.includes(k));
        if (unknown.length) return res.status(400).json({ error: 'Unsupported setting(s).', fields: unknown });
        const fields = {};
        if ('zoom_join_url' in body) {
            const v = policy.validateZoomJoinUrl(body.zoom_join_url);
            if (!v.ok) return res.status(400).json({ error: 'The Zoom link must be an https meeting link on zoom.us or zoom.com.', reason: v.reason });
            fields.zoom_join_url = v.value;
        }
        if ('timezone' in body) {
            const tz = body.timezone;
            if (typeof tz !== 'string' || tz.length > 64 || !(await repo.isValidTimezone(tz))) return res.status(400).json({ error: 'Invalid timezone' });
            fields.timezone = tz;
        }
        if ('duration_minutes' in body) {
            const d = policy.parseDuration(body.duration_minutes);
            if (!d.ok) return res.status(400).json({ error: 'duration_minutes must be an integer between 5 and 480' });
            fields.duration_minutes = d.value;
        }
        if ('default_day' in body) {
            const v = body.default_day;
            if (!(v === null || (Number.isInteger(v) && v >= 0 && v <= 6))) return res.status(400).json({ error: 'default_day must be 0–6 or null' });
            fields.default_day = v;
        }
        if ('default_time' in body) {
            const v = body.default_time;
            if (!(v === null || (typeof v === 'string' && TIME_RE.test(v)))) return res.status(400).json({ error: 'default_time must be HH:MM or null' });
            fields.default_time = v;
        }
        if ('location' in body) {
            const v = policy.parseNote(body.location, 200);
            if (!v.ok) return res.status(400).json({ error: 'location must be text up to 200 characters' });
            fields.location = v.value;
        }
        const updated = await repo.updateSettings(group.id, fields);
        if (!updated) return res.status(400).json({ error: 'No settings provided' });
        log('admin.settings', 'ok', req); // never logs the Zoom link or other values
        res.json({ success: true, group: groupView(updated) });
    });

    router.get('/admin/groups/:code/members', async (req, res) => {
        const group = await loadAdminGroup(req, res);
        if (!group) return;
        const rows = await repo.membershipCandidates(group.id);
        res.json({
            group: { code: group.code, name: group.name },
            candidates: rows.map(r => ({
                researcher_id: r.researcher_id, name: r.name, affiliation: r.affiliation, role: r.role,
                membership_class: r.membership_class, in_group: r.in_group, eligible: r.eligible,
            })),
        });
    });

    router.put('/admin/groups/:code/members/:researcherId', async (req, res) => {
        const group = await loadAdminGroup(req, res);
        if (!group) return;
        const rid = String(req.params.researcherId || '');
        if (!policy.isValidResearcherId(rid)) return res.status(404).json({ error: 'Researcher not found' });
        const account = await repo.getAccount(rid);
        if (!account) return res.status(404).json({ error: 'Researcher not found' });
        if (!policy.isMembershipEligibleAccount(account)) {
            return res.status(422).json({ error: 'Only active researcher or supervisor accounts can be meeting members.' });
        }
        const added = await repo.addMember(group.id, rid);
        const warnings = [];
        if ((await repo.membershipClass(rid)) === 'collaborator') warnings.push('collaborator');
        const aff = String((await repo.getAffiliation(rid)) || '').toUpperCase();
        if (aff && aff !== 'LIU' && aff !== 'UNAV') warnings.push('external_affiliation');
        log('admin.member-add', added ? 'added' : 'unchanged', req);
        res.json({ success: true, added, warnings });
    });

    router.delete('/admin/groups/:code/members/:researcherId', async (req, res) => {
        const group = await loadAdminGroup(req, res);
        if (!group) return;
        const rid = String(req.params.researcherId || '');
        if (!policy.isValidResearcherId(rid)) return res.status(404).json({ error: 'Researcher not found' });
        const removed = await repo.removeMember(group.id, rid);
        log('admin.member-remove', removed ? 'removed' : 'unchanged', req);
        res.json({ success: true, removed });
    });

    router.post('/admin/groups/:code/occurrences', async (req, res) => {
        const group = await loadAdminGroup(req, res);
        if (!group) return;
        const b = req.body || {};
        const start = policy.parseScheduledStart(b.scheduled_start);
        if (!start) return res.status(400).json({ error: 'scheduled_start must be an ISO date-time with a timezone offset' });
        const d = policy.parseDuration(b.duration_minutes);
        if (!d.ok) return res.status(400).json({ error: 'duration_minutes must be an integer between 5 and 480' });
        const note = policy.parseNote(b.note);
        if (!note.ok) return res.status(400).json({ error: 'note must be text up to 1000 characters' });
        try {
            const r = await occurrences.schedule(group, {
                scheduledStart: start.toISOString(), durationMinutes: d.value ?? group.duration_minutes ?? null, note: note.value,
            }, req.gmActor);
            log('admin.occurrence-schedule', 'ok', req);
            res.status(201).json({ success: true, occurrence: occurrenceView(r.occurrence) });
        } catch (err) {
            if (err && err.code === '23505') return res.status(409).json({ error: 'A meeting is already scheduled at this time for this group.' });
            throw err;
        }
    });

    router.post('/admin/occurrences/:id/:action', async (req, res) => {
        const id = String(req.params.id || '');
        const action = String(req.params.action || '');
        if (!['reschedule', 'postpone', 'cancel'].includes(action)) return res.status(404).json({ error: 'Not found' });
        const occ = policy.isUuid(id) ? await repo.getOccurrence(id) : null;
        if (!occ) return res.status(404).json({ error: 'Meeting not found' });
        const b = req.body || {};
        const note = policy.parseNote(b.note);
        if (!note.ok) return res.status(400).json({ error: 'note must be text up to 1000 characters' });
        let start = null;
        if (action === 'reschedule') {
            const s = policy.parseScheduledStart(b.scheduled_start);
            if (!s) return res.status(400).json({ error: 'scheduled_start must be an ISO date-time with a timezone offset' });
            start = s.toISOString();
        }
        try {
            const r = await occurrences.apply(occ, action, { scheduledStart: start, note: note.value }, req.gmActor);
            if (!r.ok) return res.status(r.status).json({ error: r.error });
            log(`admin.occurrence-${action}`, 'ok', req);
            res.json({ success: true, occurrence: occurrenceView(r.occurrence) });
        } catch (err) {
            if (err && err.code === '23505') return res.status(409).json({ error: 'A meeting is already scheduled at this time for this group.' });
            throw err;
        }
    });

    // ------------------------------------------- R3.1 sessions (PI only)
    const sessionId = (req, res) => {
        const id = String(req.params.id || '');
        if (!policy.isUuid(id)) { res.status(404).json({ error: 'Meeting not found' }); return null; }
        return id;
    };
    const requireConfirm = (req, res) => {
        if (!req.body || req.body.confirm !== true) { res.status(400).json({ error: 'Explicit confirmation required (confirm: true).', code: 'confirm_required' }); return false; }
        return true;
    };
    function sessionView(o) {
        if (!o) return null;
        return {
            id: o.id, group_code: o.group_code, status: o.status, origin: o.origin, status_note: o.status_note,
            scheduled_start: o.scheduled_start, duration_minutes: o.duration_minutes,
            started_at: o.started_at, ended_at: o.ended_at, started_by: o.started_by, ended_by: o.ended_by,
            chair_researcher_id: o.chair_researcher_id,
            shared_conclusions: o.shared_conclusions, private_notes: o.private_notes,
            correction_log: o.correction_log || [], updated_at: o.updated_at,
        };
    }

    router.post('/admin/groups/:code/sessions', sessionGate, async (req, res) => {
        const group = await loadAdminGroup(req, res);
        if (!group) return;
        if (!group.is_active) return res.status(409).json({ error: 'This meeting group is not active.' });
        const b = req.body || {};
        const occurrenceId = b.occurrence_id === undefined || b.occurrence_id === null ? null : String(b.occurrence_id);
        if (occurrenceId && !policy.isUuid(occurrenceId)) return res.status(400).json({ error: 'Invalid occurrence_id' });
        if (occurrenceId && b.adhoc) return res.status(400).json({ error: 'Give either occurrence_id or adhoc, not both.' });
        const r = await sessions.start(group, req.gmActor, { occurrenceId, adhoc: b.adhoc === true });
        log('admin.session-start', r.resumed ? 'resumed' : 'started', req);
        res.status(r.resumed ? 200 : 201).json({ success: true, resumed: r.resumed, session: sessionView(r.occurrence) });
    });

    router.get('/admin/sessions/:id', sessionGate, async (req, res) => {
        const id = sessionId(req, res); if (!id) return;
        const d = await sessions.detail(id);
        res.json({ session: sessionView(d.occurrence), roster: d.roster, events: d.events, attendance: d.attendance, stale: d.stale, reopened: d.reopened });
    });

    // R3.2: confirm PRESENTED / DISCUSSED (single click: presenter defaults to
    // the owner), correct presenter/comment, invalidate. During the meeting or
    // retrospectively on a completed meeting (logged). No time fields.
    router.post('/admin/sessions/:id/events', sessionGate, async (req, res) => {
        const id = sessionId(req, res); if (!id) return;
        const b = req.body || {};
        const r = await sessions.recordEvent(id, {
            submissionId: b.submission_id, eventType: b.event_type,
            presenterId: b.presenter_researcher_id === undefined || b.presenter_researcher_id === null ? null : String(b.presenter_researcher_id),
            comment: b.comment === undefined ? null : b.comment,
        }, req.gmActor);
        res.status(r.created ? 201 : 200).json({ success: true, created: r.created, event: r.event });
    });

    router.patch('/admin/sessions/:id/events/:eventId', sessionGate, async (req, res) => {
        const id = sessionId(req, res); if (!id) return;
        const b = req.body || {};
        const r = await sessions.updateEvent(id, String(req.params.eventId || ''), {
            presenterId: b.presenter_researcher_id, comment: b.comment,
        }, req.gmActor);
        res.json({ success: true, ...r });
    });

    router.delete('/admin/sessions/:id/events/:eventId', sessionGate, async (req, res) => {
        const id = sessionId(req, res); if (!id) return;
        const reason = policy.parseNote(req.body && req.body.reason, policy.REASON_MAX);
        if (!reason.ok) return res.status(400).json({ error: 'reason must be text up to 500 characters' });
        const r = await sessions.voidEvent(id, String(req.params.eventId || ''), { reason: reason.value }, req.gmActor);
        res.json({ success: true, ...r });
    });

    router.post('/admin/sessions/:id/end', sessionGate, async (req, res) => {
        const id = sessionId(req, res); if (!id) return;
        if (!requireConfirm(req, res)) return;
        const r = await sessions.end(id, req.gmActor, { markRemainingAbsent: req.body.mark_remaining_absent === true });
        log('admin.session-end', 'ok', req);
        res.json({ success: true, session: sessionView(r.occurrence), attendance: r.attendance, unmarked: r.attendance.unmarked });
    });

    router.post('/admin/sessions/:id/abandon', sessionGate, async (req, res) => {
        const id = sessionId(req, res); if (!id) return;
        if (!requireConfirm(req, res)) return;
        const reason = policy.parseNote(req.body.reason, policy.REASON_MAX);
        if (!reason.ok) return res.status(400).json({ error: 'reason must be text up to 500 characters' });
        const r = await sessions.abandon(id, req.gmActor, { reason: reason.value });
        log('admin.session-abandon', 'ok', req);
        res.json({ success: true, session: sessionView(r.occurrence) });
    });

    router.post('/admin/sessions/:id/reopen', sessionGate, async (req, res) => {
        const id = sessionId(req, res); if (!id) return;
        if (!requireConfirm(req, res)) return;
        const r = await sessions.reopen(id, req.gmActor);
        log('admin.session-reopen', 'ok', req);
        res.json({ success: true, session: sessionView(r.occurrence) });
    });

    router.put('/admin/sessions/:id/attendance/:researcherId', sessionGate, async (req, res) => {
        const id = sessionId(req, res); if (!id) return;
        const rid = String(req.params.researcherId || '');
        if (!policy.isValidResearcherId(rid)) return res.status(404).json({ error: 'Not in the meeting roster' });
        const r = await sessions.setAttendance(id, rid, req.body && req.body.status, req.gmActor);
        res.json({ success: true, ...r });
    });

    router.post('/admin/sessions/:id/attendance/bulk', sessionGate, async (req, res) => {
        const id = sessionId(req, res); if (!id) return;
        const r = await sessions.bulkAttendance(id, String((req.body && req.body.action) || ''), req.gmActor);
        res.json({ success: true, ...r });
    });

    router.post('/admin/sessions/:id/attendance', sessionGate, async (req, res) => {
        const id = sessionId(req, res); if (!id) return;
        const rid = String((req.body && req.body.researcher_id) || '');
        if (!policy.isValidResearcherId(rid)) return res.status(400).json({ error: 'researcher_id required' });
        const r = await sessions.addParticipant(id, rid, req.gmActor);
        res.status(201).json({ success: true, ...r });
    });

    router.patch('/admin/sessions/:id/notes', sessionGate, async (req, res) => {
        const id = sessionId(req, res); if (!id) return;
        const b = req.body || {};
        const shared = policy.parseOptionalText(b.shared_conclusions);
        const priv = policy.parseOptionalText(b.private_notes);
        if (!shared.ok || !priv.ok) return res.status(400).json({ error: `Notes and conclusions must be text up to ${policy.TEXT_MAX} characters.` });
        if (!shared.present && !priv.present) return res.status(400).json({ error: 'Nothing to update' });
        const r = await sessions.updateNotes(id, { sharedConclusions: shared, privateNotes: priv, expectedUpdatedAt: b.expected_updated_at }, req.gmActor);
        res.json({ success: true, ...r });
    });

    router.patch('/admin/sessions/:id/times', sessionGate, async (req, res) => {
        const id = sessionId(req, res); if (!id) return;
        const b = req.body || {};
        const r = await sessions.correctTimes(id, { startedAt: b.started_at, endedAt: b.ended_at, reason: b.reason }, req.gmActor);
        log('admin.session-times', 'corrected', req);
        res.json({ success: true, ...r });
    });

    // Errors: generic JSON, no stack traces, no request data in logs.
    // eslint-disable-next-line no-unused-vars
    router.use((err, req, res, next) => {
        if (err instanceof SessionError) {
            return res.status(err.httpStatus).json({ error: err.message, code: err.code, ...err.extra });
        }
        console.error(`[GROUP-MEETINGS] error path=${req.route ? req.route.path : '-'} code=${(err && err.code) || '-'}`);
        if (res.headersSent) return res.destroy();
        res.status(500).json({ error: 'Server error' });
    });

    return router;
}

// Called once at startup by server.js, ONLY when the feature flag is on.
async function ensureSchemaIfEnabled(pool, env = process.env) {
    if (!isFeatureEnabled(env)) return { ok: true, skipped: true };
    const r = await schema.ensureSchema(pool);
    if (!r.ok) {
        console.error('[GROUP-MEETINGS] schema ensure failed; feature answers 503 until fixed');
        return r;
    }
    console.log('[GROUP-MEETINGS] schema ensured');
    // R3.1: session schema ONLY when GROUP_MEETINGS_SESSIONS_ENABLED is also on.
    if (!policy.isSessionsFlagOn(env)) return { ...r, sessions: 'skipped' };
    const s = await schema.ensureSessionSchema(pool);
    if (!s.ok) console.error('[GROUP-MEETINGS] session schema ensure failed; session routes answer 503 until fixed');
    else console.log('[GROUP-MEETINGS] session schema ensured');
    return { ...r, sessions: s.ok ? 'ensured' : 'failed' };
}

module.exports = { createGroupMeetingsRouter, ensureSchemaIfEnabled, isFeatureEnabled, isAvailableFor };
