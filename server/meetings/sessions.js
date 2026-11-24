'use strict';
// ============================================================================
// Group Meetings — R3.1 scientific meeting sessions (lifecycle + attendance).
//
// Authoritative state lives in PostgreSQL (meeting_occurrences +
// meeting_attendance). Every transition runs in ONE transaction, locks the
// affected rows and validates the current state, so browser refreshes,
// logouts, network errors and application restarts never complete, cancel or
// duplicate a meeting. There are no timers or background jobs.
//
// Concurrency:
//   - starts are serialized per group (row lock on meeting_groups) and the
//     partial unique index uq_meeting_occurrences_one_active guarantees at
//     most one IN_PROGRESS meeting per group even under races;
//   - correction-log entries are appended with `correction_log || $json`
//     in a single UPDATE (no read-modify-write, no lost entries).
//
// Never touches di_submissions, memberships, Zoom links or legacy tables.
// Attendance is never inferred: only explicit PI actions change it.
// ============================================================================
const policy = require('./policy');
const { makeRepo } = require('./repo');

const EVENT_TYPES = ['PRESENTED', 'DISCUSSED'];
const COMMENT_MAX = 2000;
const EVENT_COLS = `e.id, e.occurrence_id, e.submission_id, e.owner_researcher_id, e.event_type, e.presenter_researcher_id,
    e.comment, e.created_by, e.created_at, e.updated_by, e.updated_at, e.voided_by, e.voided_at, e.void_reason`;

const OCC_COLS = `o.id, o.meeting_group_id, o.scheduled_start, o.duration_minutes, o.status, o.status_note,
    o.started_at, o.ended_at, o.origin, o.chair_researcher_id, o.started_by, o.ended_by,
    o.shared_conclusions, o.private_notes, o.correction_log, o.created_at, o.updated_at`;

class SessionError extends Error {
    constructor(status, code, message, extra) {
        super(message);
        this.httpStatus = status;
        this.code = code;
        this.extra = extra || {};
    }
}
const fail = (status, code, message, extra) => { throw new SessionError(status, code, message, extra); };

function makeSessionService(pool, { onEvent, now = () => new Date() } = {}) {
    const emit = (event, occ) => {
        if (typeof onEvent !== 'function') return;
        try {
            Promise.resolve(onEvent({ event, occurrence_id: occ.id, group_code: occ.group_code }))
                .catch(() => console.warn(`[GROUP-MEETINGS] event hook failed event=${event}`));
        } catch (_) { console.warn(`[GROUP-MEETINGS] event hook failed event=${event}`); }
    };

    async function tx(fn) {
        const c = await pool.connect();
        try {
            await c.query('BEGIN');
            const r = await fn(c);
            await c.query('COMMIT');
            return r;
        } catch (e) {
            try { await c.query('ROLLBACK'); } catch (_) { /* ignore */ }
            if (e && (e.code === '40P01' || e.code === '40001')) {
                throw new SessionError(409, 'concurrent_change', 'Another change to this meeting was being saved at the same time. Please try again.');
            }
            if (e && e.code === '23505' && /uq_meeting_occurrences_one_active/.test(e.constraint || e.message || '')) {
                throw new SessionError(409, 'already_active', 'A meeting is already in progress for this group.');
            }
            throw e;
        } finally {
            c.release();
        }
    }

    const entry = (actor, what, extra) => ({ at: now().toISOString(), by: actor.id, what, ...(extra || {}) });

    async function appendLog(c, occId, entries) {
        if (!entries.length) return;
        await c.query(
            `UPDATE meeting_occurrences SET correction_log = correction_log || $2::jsonb, updated_at = now() WHERE id = $1`,
            [occId, JSON.stringify(entries)]);
    }

    // Changes are logged once a meeting has been completed: while COMPLETED
    // (historical correction) and while REOPENED (it was completed before).
    const auditable = (occ) => occ.status === 'COMPLETED' || policy.isReopenedSession(occ.correction_log);

    // Lock order everywhere: group row first, then occurrence rows (no deadlock
    // between start / reopen / time correction). NO KEY UPDATE does not block
    // membership inserts (their FK check only needs KEY SHARE).
    async function lockGroupOf(c, occId) {
        const g = (await c.query('SELECT meeting_group_id FROM meeting_occurrences WHERE id = $1', [occId])).rows[0];
        if (!g) fail(404, 'not_found', 'Meeting not found');
        await c.query('SELECT id FROM meeting_groups WHERE id = $1 FOR NO KEY UPDATE', [g.meeting_group_id]);
    }

    async function lockOccurrence(c, occId) {
        const r = await c.query(
            `SELECT ${OCC_COLS}, g.code AS group_code
               FROM meeting_occurrences o JOIN meeting_groups g ON g.id = o.meeting_group_id
              WHERE o.id = $1 FOR UPDATE OF o`, [occId]);
        if (!r.rows[0]) fail(404, 'not_found', 'Meeting not found');
        return r.rows[0];
    }

    function requireEditable(occ) {
        if (!['IN_PROGRESS', 'COMPLETED'].includes(occ.status)) {
            fail(409, 'not_editable', 'Only meetings in progress or completed can be edited.');
        }
    }

    // Current eligible members of the group (same rule as the R2 workspace).
    const ELIGIBLE_MEMBERS_SQL = `
        SELECT m.researcher_id, a.name, a.affiliation, LOWER(COALESCE(a.role, 'researcher')) AS role
          FROM meeting_group_members m
          JOIN di_allowlist a ON a.researcher_id = m.researcher_id
         WHERE m.meeting_group_id = $1 AND a.active = TRUE
           AND LOWER(COALESCE(a.role, 'researcher')) IN ('researcher', 'supervisor')`;

    async function snapshotRoster(c, occId, groupId) {
        await c.query(
            `INSERT INTO meeting_attendance (occurrence_id, researcher_id, display_name, affiliation, role_snapshot, source)
             SELECT $1::uuid, e.researcher_id, e.name, e.affiliation, e.role, 'ROSTER'
               FROM (${ELIGIBLE_MEMBERS_SQL.replace('$1', '$2')}) e
             ON CONFLICT (occurrence_id, researcher_id) DO NOTHING`, [occId, groupId]);
    }

    async function attendanceSummary(q, occId) {
        const r = await q.query(
            `SELECT status, COUNT(*)::int AS n FROM meeting_attendance WHERE occurrence_id = $1 GROUP BY status`, [occId]);
        const s = { present: 0, absent: 0, unmarked: 0, total: 0 };
        for (const row of r.rows) { s[row.status.toLowerCase()] = row.n; s.total += row.n; }
        return s;
    }

    async function withGroupCode(c, occ) {
        if (occ.group_code) return occ;
        const g = await c.query('SELECT code FROM meeting_groups WHERE id = $1', [occ.meeting_group_id]);
        return { ...occ, group_code: g.rows[0] && g.rows[0].code };
    }

    return {
        SessionError,

        async getActive(groupId) {
            const r = await pool.query(
                `SELECT ${OCC_COLS} FROM meeting_occurrences o WHERE o.meeting_group_id = $1 AND o.status = 'IN_PROGRESS'`, [groupId]);
            return r.rows[0] || null;
        },

        // Member-safe summary; attendance counts only for the PI. Never notes.
        async activeSummary(groupId, isPi) {
            const occ = await this.getActive(groupId);
            if (!occ) return null;
            const t = now();
            const out = {
                id: occ.id, origin: occ.origin, scheduled_start: occ.scheduled_start, started_at: occ.started_at,
                elapsed_seconds: occ.started_at ? Math.max(0, Math.floor((t - new Date(occ.started_at)) / 1000)) : null,
                stale: policy.isStaleSession(occ.started_at, t),
                reopened: policy.isReopenedSession(occ.correction_log),
            };
            if (isPi) out.attendance = await attendanceSummary(pool, occ.id);
            return out;
        },

        // Start a SCHEDULED occurrence, or an unscheduled (ADHOC) meeting.
        async start(group, actor, { occurrenceId = null, adhoc = false } = {}) {
            const result = await tx(async (c) => {
                await c.query('SELECT id FROM meeting_groups WHERE id = $1 FOR NO KEY UPDATE', [group.id]); // serialize starts per group
                const active = (await c.query(
                    `SELECT ${OCC_COLS} FROM meeting_occurrences o WHERE o.meeting_group_id = $1 AND o.status = 'IN_PROGRESS'`, [group.id])).rows[0];
                let occ;
                if (occurrenceId) {
                    const cur = (await c.query(
                        `SELECT ${OCC_COLS} FROM meeting_occurrences o WHERE o.id = $1 AND o.meeting_group_id = $2 FOR UPDATE`,
                        [occurrenceId, group.id])).rows[0];
                    if (!cur) fail(404, 'not_found', 'Scheduled meeting not found in this group.');
                    if (cur.status === 'IN_PROGRESS') return { occurrence: cur, resumed: true }; // idempotent retry
                    if (active) fail(409, 'already_active', 'A meeting is already in progress for this group.', { active_id: active.id });
                    if (cur.status !== 'SCHEDULED') fail(409, 'invalid_state', 'Only a scheduled meeting can be started.');
                    occ = (await c.query(
                        `UPDATE meeting_occurrences o
                            SET status = 'IN_PROGRESS', started_at = now(), started_by = $2, chair_researcher_id = $2,
                                updated_by = $2, updated_at = now()
                          WHERE o.id = $1 AND o.status = 'SCHEDULED' RETURNING ${OCC_COLS}`, [cur.id, actor.id])).rows[0];
                } else {
                    if (!adhoc) fail(400, 'occurrence_required', 'Give occurrence_id, or adhoc: true for an unscheduled meeting.');
                    if (active) fail(409, 'already_active', 'A meeting is already in progress for this group.', { active_id: active.id });
                    occ = (await c.query(
                        `INSERT INTO meeting_occurrences AS o (meeting_group_id, scheduled_start, duration_minutes, status, origin,
                                                          started_at, started_by, chair_researcher_id, created_by, updated_by)
                         VALUES ($1, NULL, $2, 'IN_PROGRESS', 'ADHOC', now(), $3, $3, $3, $3) RETURNING ${OCC_COLS}`,
                        [group.id, group.duration_minutes || null, actor.id])).rows[0];
                }
                await snapshotRoster(c, occ.id, group.id);
                return { occurrence: { ...occ, group_code: group.code }, resumed: false };
            });
            if (!result.resumed) emit('meeting.started', result.occurrence);
            return result;
        },

        async end(occId, actor, { markRemainingAbsent = false } = {}) {
            const out = await tx(async (c) => {
                const occ = await lockOccurrence(c, occId);
                if (occ.status === 'COMPLETED') fail(409, 'already_completed', 'This meeting is already completed.');
                if (occ.status !== 'IN_PROGRESS') fail(409, 'not_in_progress', 'Only a meeting in progress can be ended.');
                if (markRemainingAbsent) {
                    const marked = (await c.query(
                        `UPDATE meeting_attendance SET status = 'ABSENT', marked_by = $2, marked_at = now()
                          WHERE occurrence_id = $1 AND status = 'UNMARKED' RETURNING researcher_id`, [occ.id, actor.id])).rows;
                    if (marked.length && auditable(occ)) {
                        await appendLog(c, occ.id, [entry(actor, 'attendance_bulk', {
                            action: 'remaining_absent', changes: marked.map(r => ({ target: r.researcher_id, from: 'UNMARKED', to: 'ABSENT' })) })]);
                    }
                }
                const done = (await c.query(
                    `UPDATE meeting_occurrences o SET status = 'COMPLETED', ended_at = now(), ended_by = $2, updated_by = $2, updated_at = now()
                      WHERE o.id = $1 AND o.status = 'IN_PROGRESS' RETURNING ${OCC_COLS}`, [occ.id, actor.id])).rows[0];
                if (policy.isReopenedSession(occ.correction_log)) await appendLog(c, occ.id, [entry(actor, 'complete')]);
                return { occurrence: { ...done, group_code: occ.group_code }, attendance: await attendanceSummary(c, occ.id) };
            });
            emit('meeting.completed', out.occurrence);
            return out;
        },

        async abandon(occId, actor, { reason = null } = {}) {
            const out = await tx(async (c) => {
                const occ = await lockOccurrence(c, occId);
                if (occ.status !== 'IN_PROGRESS') fail(409, 'not_in_progress', 'Only a meeting in progress can be abandoned.');
                if (policy.isReopenedSession(occ.correction_log)) {
                    fail(409, 'reopened_cannot_be_abandoned', 'A reopened meeting cannot be abandoned; end it again to keep its record.');
                }
                // status_note is visible to members (R2 occurrences list): generic text only.
                // The PI's free-text reason goes to the PI-only correction log.
                await c.query(
                    `UPDATE meeting_occurrences o SET status = 'CANCELLED', status_note = 'Abandoned session', ended_by = $2, updated_by = $2, updated_at = now()
                      WHERE o.id = $1 AND o.status = 'IN_PROGRESS'`, [occ.id, actor.id]);
                await appendLog(c, occ.id, [entry(actor, 'abandon', reason ? { reason: String(reason).slice(0, policy.REASON_MAX) } : {})]);
                const row = (await c.query(`SELECT ${OCC_COLS} FROM meeting_occurrences o WHERE o.id = $1`, [occ.id])).rows[0];
                return { occurrence: { ...row, group_code: occ.group_code } };
            });
            emit('meeting.abandoned', out.occurrence);
            return out;
        },

        // Reopen ONLY the most recent started meeting of the group, if completed
        // and nothing else is in progress. Keeps started_at; ended_at is logged
        // and cleared, then set again when the meeting is ended.
        async reopen(occId, actor) {
            const out = await tx(async (c) => {
                await lockGroupOf(c, occId);
                const occ = await lockOccurrence(c, occId);
                const rows = (await c.query(
                    `SELECT id, status, started_at FROM meeting_occurrences WHERE meeting_group_id = $1 FOR UPDATE`,
                    [occ.meeting_group_id])).rows;
                const plan = policy.planReopen(occ, rows);
                if (!plan.ok) {
                    const msg = { not_completed: 'Only a completed meeting can be reopened.',
                                  another_meeting_in_progress: 'Another meeting of this group is in progress.',
                                  not_most_recent: 'Only the most recent meeting of the group can be reopened. Use a correction instead.' }[plan.reason];
                    fail(409, plan.reason, msg);
                }
                const row = (await c.query(
                    `UPDATE meeting_occurrences o SET status = 'IN_PROGRESS', ended_at = NULL, ended_by = NULL, updated_by = $2, updated_at = now()
                      WHERE o.id = $1 AND o.status = 'COMPLETED' RETURNING ${OCC_COLS}`, [occ.id, actor.id])).rows[0];
                await appendLog(c, occ.id, [entry(actor, 'reopen', { from: { ended_at: occ.ended_at, ended_by: occ.ended_by } })]);
                return { occurrence: { ...row, group_code: occ.group_code } };
            });
            emit('meeting.reopened', out.occurrence);
            return out;
        },

        async setAttendance(occId, researcherId, status, actor) {
            const st = policy.normalizeAttendanceStatus(status);
            if (!st) fail(400, 'invalid_status', 'status must be UNMARKED, PRESENT or ABSENT');
            return tx(async (c) => {
                const occ = await lockOccurrence(c, occId);
                requireEditable(occ);
                const row = (await c.query(
                    `SELECT researcher_id, status FROM meeting_attendance WHERE occurrence_id = $1 AND researcher_id = $2 FOR UPDATE`,
                    [occ.id, researcherId])).rows[0];
                if (!row) fail(404, 'not_in_roster', 'This person is not in the meeting roster.');
                if (row.status === st) return { changed: false, status: st };
                await c.query(
                    `UPDATE meeting_attendance SET status = $3, marked_by = $4, marked_at = now() WHERE occurrence_id = $1 AND researcher_id = $2`,
                    [occ.id, researcherId, st, actor.id]);
                if (auditable(occ)) {
                    await appendLog(c, occ.id, [entry(actor, 'attendance', { target: researcherId, from: row.status, to: st })]);
                }
                return { changed: true, status: st };
            });
        },

        // all_present: every roster row -> PRESENT. remaining_absent: ONLY
        // UNMARKED rows -> ABSENT (explicit marks are never overwritten).
        async bulkAttendance(occId, action, actor) {
            if (!policy.BULK_ATTENDANCE_ACTIONS.includes(action)) fail(400, 'invalid_action', 'action must be all_present or remaining_absent');
            return tx(async (c) => {
                const occ = await lockOccurrence(c, occId);
                requireEditable(occ);
                const where = action === 'all_present' ? `status <> 'PRESENT'` : `status = 'UNMARKED'`;
                const to = action === 'all_present' ? 'PRESENT' : 'ABSENT';
                const rows = (await c.query(
                    `SELECT researcher_id, status FROM meeting_attendance WHERE occurrence_id = $1 AND ${where} FOR UPDATE`, [occ.id])).rows;
                if (rows.length) {
                    await c.query(
                        `UPDATE meeting_attendance SET status = $2, marked_by = $3, marked_at = now() WHERE occurrence_id = $1 AND ${where}`,
                        [occ.id, to, actor.id]);
                    if (auditable(occ)) {
                        await appendLog(c, occ.id, [entry(actor, 'attendance_bulk', {
                            action, changes: rows.map(r => ({ target: r.researcher_id, from: r.status, to })) })]);
                    }
                }
                return { changed: rows.length, attendance: await attendanceSummary(c, occ.id) };
            });
        },

        // Explicitly add a CURRENT eligible member (e.g. joined the group after
        // the meeting started). The original roster rows are never rewritten.
        async addParticipant(occId, researcherId, actor) {
            return tx(async (c) => {
                const occ = await lockOccurrence(c, occId);
                requireEditable(occ);
                const m = (await c.query(`${ELIGIBLE_MEMBERS_SQL} AND m.researcher_id = $2`, [occ.meeting_group_id, researcherId])).rows[0];
                if (!m) fail(422, 'not_eligible_member', 'Only a current eligible member of this group can be added.');
                const ins = await c.query(
                    `INSERT INTO meeting_attendance (occurrence_id, researcher_id, display_name, affiliation, role_snapshot, source)
                     VALUES ($1, $2, $3, $4, $5, 'ADDED') ON CONFLICT (occurrence_id, researcher_id) DO NOTHING RETURNING id`,
                    [occ.id, m.researcher_id, m.name, m.affiliation, m.role]);
                if (!ins.rows.length) fail(409, 'already_in_roster', 'This person is already in the meeting roster.');
                if (auditable(occ)) await appendLog(c, occ.id, [entry(actor, 'attendance_add', { target: researcherId })]);
                return { added: true };
            });
        },

        // Shared conclusions (researcher-visible later) and private notes
        // (PI-only). Optional optimistic check against lost updates.
        async updateNotes(occId, { sharedConclusions, privateNotes, expectedUpdatedAt }, actor) {
            return tx(async (c) => {
                const occ = await lockOccurrence(c, occId);
                requireEditable(occ);
                if (expectedUpdatedAt && new Date(expectedUpdatedAt).getTime() !== new Date(occ.updated_at).getTime()) {
                    fail(409, 'stale_write', 'The meeting was changed meanwhile. Reload and try again.', { updated_at: occ.updated_at });
                }
                const sets = [];
                const vals = [occ.id, actor.id];
                const changed = [];
                if (sharedConclusions && sharedConclusions.present && sharedConclusions.value !== occ.shared_conclusions) {
                    vals.push(sharedConclusions.value); sets.push(`shared_conclusions = $${vals.length}`); changed.push('shared_conclusions');
                }
                if (privateNotes && privateNotes.present && privateNotes.value !== occ.private_notes) {
                    vals.push(privateNotes.value); sets.push(`private_notes = $${vals.length}`); changed.push('private_notes');
                }
                if (!sets.length) return { changed: [], updated_at: occ.updated_at };
                const row = (await c.query(
                    `UPDATE meeting_occurrences SET ${sets.join(', ')}, updated_by = $2, updated_at = now() WHERE id = $1 RETURNING updated_at`,
                    vals)).rows[0];
                let updatedAt = row.updated_at;
                if (auditable(occ)) {
                    await appendLog(c, occ.id, changed.map(f => entry(actor, f))); // field, who, when — never the text
                    updatedAt = (await c.query('SELECT updated_at FROM meeting_occurrences WHERE id = $1', [occ.id])).rows[0].updated_at;
                }
                return { changed, updated_at: updatedAt };
            });
        },

        // Explicit start/end correction of a COMPLETED meeting, with a reason.
        // The only operation (besides Start) that can move "Since last meeting".
        async correctTimes(occId, { startedAt, endedAt, reason }, actor) {
            return tx(async (c) => {
                await lockGroupOf(c, occId);
                const occ = await lockOccurrence(c, occId);
                if (occ.status !== 'COMPLETED') fail(409, 'not_completed', 'Timestamps can only be corrected on a completed meeting.');
                const others = (await c.query(
                    `SELECT id, status, started_at, ended_at FROM meeting_occurrences
                      WHERE meeting_group_id = $1 AND id <> $2 AND status IN ('COMPLETED', 'IN_PROGRESS')`,
                    [occ.meeting_group_id, occ.id])).rows;
                const v = policy.validateTimeCorrection({ current: occ, startedAt, endedAt, reason, now: now(), others });
                if (!v.ok) fail(400, v.reason, 'Invalid timestamp correction: ' + v.reason.replace(/_/g, ' '));
                await c.query(
                    `UPDATE meeting_occurrences SET started_at = $2, ended_at = $3, updated_by = $4, updated_at = now() WHERE id = $1`,
                    [occ.id, v.startedAt.toISOString(), v.endedAt.toISOString(), actor.id]);
                await appendLog(c, occ.id, [entry(actor, 'times', {
                    from: { started_at: occ.started_at, ended_at: occ.ended_at },
                    to: { started_at: v.startedAt.toISOString(), ended_at: v.endedAt.toISOString() },
                    reason: String(reason).trim().slice(0, policy.REASON_MAX),
                })]);
                return { started_at: v.startedAt, ended_at: v.endedAt };
            });
        },

        // ---------------------------------------- R3.2 presented / discussed
        // One explicit PI action records that a document was PRESENTED or
        // DISCUSSED in this meeting. No time is recorded: the meeting's date is
        // the scientific date. Idempotent (repeated clicks/retries return the
        // existing record). Allowed during the meeting, and retrospectively on a
        // COMPLETED meeting (logged correction). Never touches the submission.
        async recordEvent(occId, { submissionId, eventType, presenterId = null, comment = null }, actor) {
            const type = String(eventType || '').toUpperCase();
            if (!EVENT_TYPES.includes(type)) fail(400, 'invalid_event_type', 'event_type must be PRESENTED or DISCUSSED');
            if (!policy.isUuid(String(submissionId || ''))) fail(400, 'invalid_submission', 'submission_id required');
            if (comment !== null && (typeof comment !== 'string' || comment.length > COMMENT_MAX)) fail(400, 'invalid_comment', 'comment must be text up to 2000 characters');
            const out = await tx(async (c) => {
                const occ = await lockOccurrence(c, occId);
                requireEditable(occ);
                const doc = await makeRepo(c).getListedDocument(occ.meeting_group_id, submissionId);
                if (!doc) fail(422, 'document_not_listed', 'This document is not currently listed in this meeting group.');
                const roster = new Set((await c.query(
                    `SELECT researcher_id FROM meeting_attendance WHERE occurrence_id = $1`, [occ.id])).rows.map(r => r.researcher_id));
                let presenter = presenterId ? String(presenterId) : null;
                if (presenter && !roster.has(presenter)) fail(422, 'presenter_not_in_roster', 'The presenter must be a participant of this meeting.');
                if (type === 'PRESENTED' && !presenter) {
                    if (roster.has(doc.researcher_id)) presenter = doc.researcher_id; // common case: the owner, one click
                    else fail(422, 'presenter_required', 'The document owner is not in this meeting: choose the presenter.');
                }
                const ins = await c.query(
                    `INSERT INTO meeting_document_events (occurrence_id, submission_id, owner_researcher_id, event_type,
                                                          presenter_researcher_id, comment, created_by, updated_by)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $7)
                     ON CONFLICT (occurrence_id, submission_id, event_type) WHERE voided_at IS NULL DO NOTHING
                     RETURNING id`,
                    [occ.id, submissionId, doc.researcher_id, type, presenter, comment, actor.id]);
                let created = ins.rows.length > 0;
                const event = (await c.query(
                    `SELECT ${EVENT_COLS} FROM meeting_document_events e
                      WHERE e.occurrence_id = $1 AND e.submission_id = $2 AND e.event_type = $3 AND e.voided_at IS NULL`,
                    [occ.id, submissionId, type])).rows[0];
                if (created && auditable(occ)) {
                    await appendLog(c, occ.id, [entry(actor, 'presentation_add', { target: event.id, event_type: type, submission_id: submissionId, presenter })]);
                }
                return { created, event };
            });
            return out;
        },

        // Correct the actual presenter and/or the private comment.
        async updateEvent(occId, eventId, { presenterId, comment }, actor) {
            if (!policy.isUuid(String(eventId || ''))) fail(404, 'event_not_found', 'Record not found');
            if (comment !== undefined && comment !== null && (typeof comment !== 'string' || comment.length > COMMENT_MAX)) {
                fail(400, 'invalid_comment', 'comment must be text up to 2000 characters');
            }
            return tx(async (c) => {
                const occ = await lockOccurrence(c, occId);
                requireEditable(occ);
                const ev = (await c.query(
                    `SELECT ${EVENT_COLS} FROM meeting_document_events e WHERE e.id = $1 AND e.occurrence_id = $2 AND e.voided_at IS NULL FOR UPDATE`,
                    [eventId, occ.id])).rows[0];
                if (!ev) fail(404, 'event_not_found', 'Record not found');
                const sets = [], vals = [ev.id, actor.id], log = [];
                if (presenterId !== undefined) {
                    const p = presenterId === null ? null : String(presenterId);
                    if (ev.event_type === 'PRESENTED' && !p) fail(422, 'presenter_required', 'A presentation needs a presenter.');
                    if (p) {
                        const inRoster = (await c.query(`SELECT 1 FROM meeting_attendance WHERE occurrence_id = $1 AND researcher_id = $2`, [occ.id, p])).rows.length;
                        if (!inRoster) fail(422, 'presenter_not_in_roster', 'The presenter must be a participant of this meeting.');
                    }
                    if (p !== ev.presenter_researcher_id) {
                        vals.push(p); sets.push(`presenter_researcher_id = $${vals.length}`);
                        log.push(entry(actor, 'presenter', { target: ev.id, from: ev.presenter_researcher_id, to: p }));
                    }
                }
                if (comment !== undefined) {
                    const v = comment === null || comment.trim() === '' ? null : comment;
                    if (v !== ev.comment) { vals.push(v); sets.push(`comment = $${vals.length}`); log.push(entry(actor, 'presentation_comment', { target: ev.id })); }
                }
                if (!sets.length) return { changed: false, event: ev };
                const row = (await c.query(
                    `UPDATE meeting_document_events e SET ${sets.join(', ')}, updated_by = $2, updated_at = now() WHERE e.id = $1 RETURNING ${EVENT_COLS}`, vals)).rows[0];
                if (auditable(occ)) await appendLog(c, occ.id, log);
                return { changed: true, event: row };
            });
        },

        // Invalidate (never delete) a record; Last presented updates automatically.
        async voidEvent(occId, eventId, { reason = null } = {}, actor) {
            if (!policy.isUuid(String(eventId || ''))) fail(404, 'event_not_found', 'Record not found');
            return tx(async (c) => {
                const occ = await lockOccurrence(c, occId);
                requireEditable(occ);
                const ev = (await c.query(
                    `SELECT ${EVENT_COLS} FROM meeting_document_events e WHERE e.id = $1 AND e.occurrence_id = $2 FOR UPDATE`, [eventId, occ.id])).rows[0];
                if (!ev) fail(404, 'event_not_found', 'Record not found');
                if (ev.voided_at) return { changed: false };
                const r = reason ? String(reason).slice(0, policy.REASON_MAX) : null;
                await c.query(
                    `UPDATE meeting_document_events SET voided_at = now(), voided_by = $2, void_reason = $3, updated_by = $2, updated_at = now() WHERE id = $1`,
                    [ev.id, actor.id, r]);
                if (auditable(occ)) await appendLog(c, occ.id, [entry(actor, 'presentation_void', { target: ev.id, reason: r })]);
                return { changed: true };
            });
        },

        // ------------------------------------------------------- history
        // Completed meetings of a group, newest first (keyset on started_at, id).
        async history(groupId, { limit = 50, cursor = null } = {}) {
            const rows = (await pool.query(
                `SELECT o.id, o.started_at, o.ended_at, o.origin, o.scheduled_start,
                        (SELECT COUNT(*) FROM meeting_document_events e WHERE e.occurrence_id = o.id AND e.voided_at IS NULL AND e.event_type = 'PRESENTED')::int AS presented,
                        (SELECT COUNT(*) FROM meeting_document_events e WHERE e.occurrence_id = o.id AND e.voided_at IS NULL AND e.event_type = 'DISCUSSED')::int AS discussed
                   FROM meeting_occurrences o
                  WHERE o.meeting_group_id = $1 AND o.status = 'COMPLETED'
                    AND ($2::timestamptz IS NULL OR (o.started_at, o.id) < ($2::timestamptz, $3::uuid))
                  ORDER BY o.started_at DESC, o.id DESC LIMIT $4`,
                [groupId, cursor ? cursor.t : null, cursor ? cursor.id : null, limit + 1])).rows;
            return { rows: rows.slice(0, limit), more: rows.length > limit };
        },

        // One completed meeting. Members: date, duration, presented/discussed
        // documents with actual presenters, shared conclusions. PI additionally:
        // attendance, private notes, private comments, voided records, log.
        // Document details only if the document is CURRENTLY listed in the group.
        async historyDetail(groupId, occId, actor) {
            const occ = (await pool.query(
                `SELECT ${OCC_COLS} FROM meeting_occurrences o WHERE o.id = $1 AND o.meeting_group_id = $2 AND o.status = 'COMPLETED'`,
                [occId, groupId])).rows[0];
            if (!occ) fail(404, 'not_found', 'Meeting not found');
            const events = (await pool.query(
                `SELECT ${EVENT_COLS}, pa.name AS presenter_name_now, oa.name AS owner_name_now,
                        att.display_name AS presenter_name_snapshot
                   FROM meeting_document_events e
                   LEFT JOIN di_allowlist pa ON pa.researcher_id = e.presenter_researcher_id
                   LEFT JOIN di_allowlist oa ON oa.researcher_id = e.owner_researcher_id
                   LEFT JOIN meeting_attendance att ON att.occurrence_id = e.occurrence_id AND att.researcher_id = e.presenter_researcher_id
                  WHERE e.occurrence_id = $1 ${actor.isPi ? '' : 'AND e.voided_at IS NULL'}
                  ORDER BY e.event_type DESC, e.created_at`, [occ.id])).rows;
            const listed = new Map((await makeRepo(pool).getListedDocumentsByIds(groupId, [...new Set(events.map(e => e.submission_id))]))
                .map(d => [d.submission_id, d]));
            const view = (e) => {
                const d = listed.get(e.submission_id);
                const base = {
                    type: e.event_type,
                    presenter_name: e.presenter_researcher_id ? (e.presenter_name_snapshot || e.presenter_name_now || e.presenter_researcher_id) : null,
                    // Members: no owner metadata for a document that is no longer listed.
                    owner_name: d || actor.isPi ? (e.owner_name_now || e.owner_researcher_id) : null,
                    document: d ? {
                        submission_id: d.submission_id, title: d.original_filename, file_type: policy.displayFileType(d.file_type),
                        status: String(d.status || 'PENDING').toUpperCase(), submitted_at: d.created_at,
                        can_open: policy.isOwnerOrPi(actor, d.researcher_id),
                    } : null, // null => "Document no longer available" (no id or metadata exposed to members)
                };
                if (actor.isPi) {
                    Object.assign(base, {
                        event_id: e.id, submission_id: e.submission_id, presenter_researcher_id: e.presenter_researcher_id,
                        comment: e.comment, voided: !!e.voided_at, void_reason: e.void_reason,
                    });
                }
                return base;
            };
            const duration = occ.started_at && occ.ended_at ? Math.round((new Date(occ.ended_at) - new Date(occ.started_at)) / 60000) : null;
            const out = {
                meeting: { id: occ.id, date: occ.started_at, started_at: occ.started_at, ended_at: occ.ended_at, duration_minutes: duration, origin: occ.origin },
                presentations: events.filter(e => e.event_type === 'PRESENTED').map(view),
                discussions: events.filter(e => e.event_type === 'DISCUSSED').map(view),
                shared_conclusions: occ.shared_conclusions,
            };
            if (actor.isPi) {
                out.private_notes = occ.private_notes;
                out.correction_log = occ.correction_log || [];
                out.attendance = (await pool.query(
                    `SELECT researcher_id, display_name, source, status FROM meeting_attendance WHERE occurrence_id = $1
                      ORDER BY LOWER(display_name), researcher_id`, [occ.id])).rows;
            }
            return out;
        },

        // Full PI detail (roster, attendance, notes, correction log).
        async detail(occId) {
            const r = await pool.query(
                `SELECT ${OCC_COLS}, g.code AS group_code FROM meeting_occurrences o
                   JOIN meeting_groups g ON g.id = o.meeting_group_id WHERE o.id = $1`, [occId]);
            const occ = r.rows[0];
            if (!occ) fail(404, 'not_found', 'Meeting not found');
            const roster = (await pool.query(
                `SELECT researcher_id, display_name, affiliation, role_snapshot, source, status, marked_by, marked_at
                   FROM meeting_attendance WHERE occurrence_id = $1 ORDER BY LOWER(display_name), researcher_id`, [occ.id])).rows;
            const events = (await pool.query(
                `SELECT ${EVENT_COLS} FROM meeting_document_events e WHERE e.occurrence_id = $1 ORDER BY e.created_at`, [occ.id])).rows;
            return {
                occurrence: occ,
                roster,
                events,
                attendance: await attendanceSummary(pool, occ.id),
                stale: occ.status === 'IN_PROGRESS' && policy.isStaleSession(occ.started_at, now()),
                reopened: occ.status === 'IN_PROGRESS' && policy.isReopenedSession(occ.correction_log),
            };
        },
    };
}

module.exports = { makeSessionService, SessionError };
