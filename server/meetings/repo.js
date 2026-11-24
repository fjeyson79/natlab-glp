'use strict';
// ============================================================================
// Group Meetings — data access (read-mostly). All document queries read the
// existing di_submissions rows directly: no copies, no caches, no new storage.
//
// LISTING: every document-derived value (counters, last upload, titles, ids,
// metadata) is computed from ONE row set filtered by ELIGIBLE_SQL, which
// mirrors policy.isListableDocument(). Listing is the same for every member.
// OPENING: getListedDocument() returns the owner so the router can enforce the
// owner-or-PI rule (policy.canOpenDocument) BEFORE storage is touched.
//
// Only writes: meeting_groups settings/code, meeting_group_members rows and
// meeting_occurrences rows. di_submissions is never written.
// ============================================================================

// Eligible = NAT-Lab workspace, SOP/DATA/PRESENTATION(PRES), status APPROVED /
// PENDING / SUBMITTED / REVISION_NEEDED, not an unsubmitted legacy draft. `x.j` is to_jsonb(s), so the
// optional legacy columns (migration 020) are read without hard dependencies.
const ELIGIBLE_SQL = `
      s.workspace_id = (SELECT w.id FROM workspaces w WHERE w.slug = 'natlab' LIMIT 1)
  AND UPPER(s.file_type) IN ('SOP', 'DATA', 'PRESENTATION', 'PRES')
  AND UPPER(COALESCE(s.status, 'PENDING')) IN ('APPROVED', 'PENDING', 'SUBMITTED', 'REVISION_NEEDED')
  AND NOT (COALESCE(x.j->>'record_origin', '') = 'legacy_pre2026'
           AND (x.j->>'legacy_pack_id') IS NULL
           AND UPPER(COALESCE(s.status, '')) = 'SUBMITTED')`;

// Current, eligible members of a group (active allowlist row, researcher or
// supervisor role). Inactive accounts and other roles are never members.
function membersCte(groupParam) {
    return `members AS (
        SELECT m.researcher_id, a.name, a.affiliation
          FROM meeting_group_members m
          JOIN di_allowlist a ON a.researcher_id = m.researcher_id
         WHERE m.meeting_group_id = $${groupParam}::uuid
           AND a.active = TRUE
           AND LOWER(COALESCE(a.role, 'researcher')) IN ('researcher', 'supervisor'))`;
}

// Display order of the three series: LiU, UNAV, Joint.
const GROUP_ORDER_SQL = (col) => `array_position(ARRAY['LIU', 'UNAV', 'JOINT']::text[], ${col})`;

const GROUP_COLS = `id, code, name, site, is_active, default_day, default_time, location,
                    timezone, duration_minutes, zoom_join_url`;

function makeRepo(pool) {
    const q = async (sql, params) => (await pool.query(sql, params)).rows;

    return {
        async getAccount(researcherId) {
            const r = await q(
                `SELECT researcher_id, LOWER(COALESCE(role, 'researcher')) AS role, (active = TRUE) AS active
                   FROM di_allowlist WHERE researcher_id = $1`, [researcherId]);
            return r[0] || null;
        },

        // ---------------------------------------------------------- groups
        async getGroupByCode(code, { includeInactive = false } = {}) {
            const r = await q(
                `SELECT ${GROUP_COLS} FROM meeting_groups
                  WHERE code = $1 ${includeInactive ? '' : 'AND is_active = TRUE'}`, [code]);
            return r[0] || null;
        },

        async listGroupsForActor(actor) {
            if (actor.isPi) {
                return q(`SELECT ${GROUP_COLS} FROM meeting_groups
                           WHERE code IS NOT NULL AND is_active = TRUE ORDER BY ${GROUP_ORDER_SQL('code')}`);
            }
            return q(
                `SELECT g.id, g.code, g.name, g.site, g.is_active, g.default_day, g.default_time, g.location,
                        g.timezone, g.duration_minutes, g.zoom_join_url
                   FROM meeting_groups g
                   JOIN meeting_group_members m ON m.meeting_group_id = g.id AND m.researcher_id = $1
                   JOIN di_allowlist a ON a.researcher_id = m.researcher_id
                  WHERE g.code IS NOT NULL AND g.is_active = TRUE
                    AND a.active = TRUE AND LOWER(COALESCE(a.role, 'researcher')) IN ('researcher', 'supervisor')
                  ORDER BY ${GROUP_ORDER_SQL('g.code')}`, [actor.id]);
        },

        async isMember(groupId, researcherId) {
            const r = await q(
                `WITH ${membersCte(1)} SELECT 1 FROM members WHERE researcher_id = $2`, [groupId, researcherId]);
            return r.length > 0;
        },

        async lastCompletedAt(groupId) {
            const r = await q(
                `SELECT MAX(COALESCE(ended_at, scheduled_start)) AS t
                   FROM meeting_occurrences WHERE meeting_group_id = $1 AND status = 'COMPLETED'`, [groupId]);
            return r[0] ? r[0].t : null;
        },

        async weekStart(timezone) {
            const r = await q(`SELECT (date_trunc('week', now() AT TIME ZONE $1) AT TIME ZONE $1) AS t`, [timezone]);
            return r[0].t;
        },

        async isValidTimezone(tz) {
            const r = await q(`SELECT 1 FROM pg_timezone_names WHERE name = $1`, [tz]);
            return r.length > 0;
        },

        // -------------------------------------------------------- overview
        async overview(groupId, since) {
            return q(
                `WITH ${membersCte(1)},
                 docs AS (
                    SELECT s.researcher_id, s.submission_id, s.created_at
                      FROM di_submissions s
                      JOIN members mm ON mm.researcher_id = s.researcher_id
                      CROSS JOIN LATERAL (SELECT to_jsonb(s) AS j) x
                     WHERE ${ELIGIBLE_SQL})
                 SELECT mm.researcher_id, mm.name, mm.affiliation,
                        MAX(d.created_at) AS last_upload,
                        (COUNT(d.submission_id) FILTER (WHERE d.created_at > $2::timestamptz))::int AS new_count,
                        COUNT(d.submission_id)::int AS total_count
                   FROM members mm
                   LEFT JOIN docs d ON d.researcher_id = mm.researcher_id
                  GROUP BY mm.researcher_id, mm.name, mm.affiliation
                  ORDER BY LOWER(mm.name), mm.researcher_id`,
                [groupId, since]);
        },

        // ------------------------------------------------------- documents
        // Keyset-paginated, newest first. `cursor` = { t, id } from the last
        // row of the previous page (t keeps microseconds, so no row is skipped
        // or repeated). NULL created_at sorts as the oldest possible value.
        async listDocuments(groupId, ownerId, since, limit, cursor) {
            return q(
                `WITH ${membersCte(1)}
                 SELECT s.submission_id, s.researcher_id, s.original_filename, s.file_type, s.status,
                        s.created_at, s.signed_at,
                        x.j->>'record_origin' AS record_origin,
                        x.j->>'original_created_at' AS original_created_at,
                        to_char(COALESCE(s.created_at, TIMESTAMP 'epoch'), 'YYYY-MM-DD"T"HH24:MI:SS.US') AS sort_ts
                   FROM di_submissions s
                   JOIN members mm ON mm.researcher_id = s.researcher_id
                   CROSS JOIN LATERAL (SELECT to_jsonb(s) AS j) x
                  WHERE s.researcher_id = $2
                    AND ${ELIGIBLE_SQL}
                    AND ($3::timestamptz IS NULL OR s.created_at >= $3::timestamptz)
                    AND ($5::timestamp IS NULL
                         OR (COALESCE(s.created_at, TIMESTAMP 'epoch'), s.submission_id) < ($5::timestamp, $6::uuid))
                  ORDER BY COALESCE(s.created_at, TIMESTAMP 'epoch') DESC, s.submission_id DESC
                  LIMIT $4`,
                [groupId, ownerId, since, limit, cursor ? cursor.t : null, cursor ? cursor.id : null]);
        },

        async countDocuments(groupId, ownerId, since) {
            const r = await q(
                `WITH ${membersCte(1)}
                 SELECT COUNT(*)::int AS n
                   FROM di_submissions s
                   JOIN members mm ON mm.researcher_id = s.researcher_id
                   CROSS JOIN LATERAL (SELECT to_jsonb(s) AS j) x
                  WHERE s.researcher_id = $2
                    AND ${ELIGIBLE_SQL}
                    AND ($3::timestamptz IS NULL OR s.created_at >= $3::timestamptz)`,
                [groupId, ownerId, since]);
            return r[0].n;
        },

        // A document LISTED in this group (eligible, owner is a current member),
        // or null. The caller must still apply the owner-or-PI rule
        // (policy.canOpenDocument) before using r2_object_key.
        async getListedDocument(groupId, submissionId) {
            const r = await q(
                `WITH ${membersCte(1)}
                 SELECT s.submission_id, s.researcher_id, s.r2_object_key, s.original_filename
                   FROM di_submissions s
                   JOIN members mm ON mm.researcher_id = s.researcher_id
                   CROSS JOIN LATERAL (SELECT to_jsonb(s) AS j) x
                  WHERE s.submission_id = $2::uuid
                    AND ${ELIGIBLE_SQL}`,
                [groupId, submissionId]);
            return r[0] || null;
        },

        // ----------------------------------------------------------- admin
        async listAllGroups() {
            return q(
                `SELECT g.id, g.code, g.name, g.site, g.is_active, g.default_day, g.default_time, g.location,
                        g.timezone, g.duration_minutes, g.zoom_join_url,
                        (SELECT COUNT(*)::int FROM meeting_group_members m
                           JOIN di_allowlist a ON a.researcher_id = m.researcher_id
                          WHERE m.meeting_group_id = g.id AND a.active = TRUE
                            AND LOWER(COALESCE(a.role, 'researcher')) IN ('researcher', 'supervisor')) AS member_count
                   FROM meeting_groups g
                  ORDER BY ${GROUP_ORDER_SQL('g.code')} NULLS LAST, g.name`);
        },

        async getGroupById(groupId) {
            const r = await q(`SELECT ${GROUP_COLS} FROM meeting_groups WHERE id = $1::uuid`, [groupId]);
            return r[0] || null;
        },

        // Fills a NULL code only; the unique index rejects a code already in use.
        async assignCode(groupId, code) {
            const r = await q(
                `UPDATE meeting_groups SET code = $2, updated_at = now()
                  WHERE id = $1::uuid AND code IS NULL RETURNING ${GROUP_COLS}`, [groupId, code]);
            return r[0] || null;
        },

        async updateSettings(groupId, fields) {
            const allowed = ['zoom_join_url', 'timezone', 'duration_minutes', 'default_day', 'default_time', 'location'];
            const sets = [];
            const vals = [groupId];
            for (const k of allowed) {
                if (Object.prototype.hasOwnProperty.call(fields, k)) {
                    vals.push(fields[k]);
                    sets.push(`${k} = $${vals.length}`);
                }
            }
            if (sets.length === 0) return null;
            const r = await q(
                `UPDATE meeting_groups SET ${sets.join(', ')}, updated_at = now()
                  WHERE id = $1::uuid RETURNING ${GROUP_COLS}`, vals);
            return r[0] || null;
        },

        // All active researcher/supervisor accounts with their membership state,
        // plus current member rows that are no longer eligible (so the PI can
        // see and remove them; they already have no access).
        async membershipCandidates(groupId) {
            return q(
                `SELECT a.researcher_id, a.name, a.affiliation,
                        LOWER(COALESCE(a.role, 'researcher')) AS role,
                        (a.active = TRUE) AS active,
                        COALESCE(to_jsonb(wu)->>'membership_class', 'core') AS membership_class,
                        (m.id IS NOT NULL) AS in_group,
                        (a.active = TRUE AND LOWER(COALESCE(a.role, 'researcher')) IN ('researcher', 'supervisor')) AS eligible
                   FROM di_allowlist a
                   LEFT JOIN meeting_group_members m
                          ON m.researcher_id = a.researcher_id AND m.meeting_group_id = $1::uuid
                   LEFT JOIN workspaces w ON w.slug = 'natlab'
                   LEFT JOIN workspace_users wu ON wu.user_id = a.researcher_id AND wu.workspace_id = w.id
                  WHERE (a.active = TRUE AND LOWER(COALESCE(a.role, 'researcher')) IN ('researcher', 'supervisor'))
                     OR m.id IS NOT NULL
                  ORDER BY LOWER(a.name), a.researcher_id`, [groupId]);
        },

        async addMember(groupId, researcherId) {
            const r = await q(
                `INSERT INTO meeting_group_members (meeting_group_id, researcher_id)
                 VALUES ($1::uuid, $2)
                 ON CONFLICT (meeting_group_id, researcher_id) DO NOTHING RETURNING id`, [groupId, researcherId]);
            return r.length > 0;
        },

        async removeMember(groupId, researcherId) {
            const r = await q(
                `DELETE FROM meeting_group_members WHERE meeting_group_id = $1::uuid AND researcher_id = $2 RETURNING id`,
                [groupId, researcherId]);
            return r.length > 0;
        },

        async membershipClass(researcherId) {
            const r = await q(
                `SELECT COALESCE(to_jsonb(wu)->>'membership_class', 'core') AS membership_class
                   FROM workspace_users wu JOIN workspaces w ON w.id = wu.workspace_id
                  WHERE w.slug = 'natlab' AND wu.user_id = $1`, [researcherId]);
            return r[0] ? r[0].membership_class : 'core';
        },

        async getAffiliation(researcherId) {
            const r = await q(`SELECT affiliation FROM di_allowlist WHERE researcher_id = $1`, [researcherId]);
            return r[0] ? r[0].affiliation : null;
        },

        // ----------------------------------------------------- occurrences
        async listOccurrences(groupId, limit) {
            return q(
                `SELECT id, scheduled_start, duration_minutes, status, status_note, started_at, ended_at, created_at, updated_at
                   FROM meeting_occurrences WHERE meeting_group_id = $1::uuid
                  ORDER BY COALESCE(scheduled_start, created_at) DESC LIMIT $2`, [groupId, limit]);
        },

        async nextScheduled(groupId) {
            const r = await q(
                `SELECT id, scheduled_start, duration_minutes, status
                   FROM meeting_occurrences
                  WHERE meeting_group_id = $1::uuid AND status = 'SCHEDULED' AND scheduled_start >= now() - interval '12 hours'
                  ORDER BY scheduled_start ASC LIMIT 1`, [groupId]);
            return r[0] || null;
        },

        async getOccurrence(id) {
            const r = await q(
                `SELECT o.*, g.code AS group_code FROM meeting_occurrences o
                   JOIN meeting_groups g ON g.id = o.meeting_group_id WHERE o.id = $1::uuid`, [id]);
            return r[0] || null;
        },

        async insertOccurrence({ groupId, scheduledStart, durationMinutes, note, actorId }) {
            const r = await q(
                `INSERT INTO meeting_occurrences (meeting_group_id, scheduled_start, duration_minutes, status_note, created_by, updated_by)
                 VALUES ($1::uuid, $2::timestamptz, $3, $4, $5, $5) RETURNING *`,
                [groupId, scheduledStart, durationMinutes, note, actorId]);
            return r[0];
        },

        // Optimistic transition: only applies if the status is still `fromStatus`.
        async transitionOccurrence({ id, fromStatus, toStatus, scheduledStart, note, actorId }) {
            const r = await q(
                `UPDATE meeting_occurrences
                    SET status = $3,
                        scheduled_start = COALESCE($4::timestamptz, scheduled_start),
                        status_note = $5, updated_by = $6, updated_at = now()
                  WHERE id = $1::uuid AND status = $2 RETURNING *`,
                [id, fromStatus, toStatus, scheduledStart, note, actorId]);
            return r[0] || null;
        },
    };
}

module.exports = { makeRepo, ELIGIBLE_SQL };
