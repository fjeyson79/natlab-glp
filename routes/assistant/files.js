// Portal Assistant API — Zoe
// GET /api/assistant/files/search
//
// Ranked file search against di_submissions (NAT-Lab's canonical upload
// table), enriched with optional title / project metadata from rd_documents
// when the file was also ingested via the R&D path.
//
// Why di_submissions is primary:
//   NAT-Lab's main DI upload flow writes di_submissions ONLY. rd_documents
//   is populated only by the R&D path (one INSERT site in server.js). A
//   search that queries rd_documents as its primary table cannot see the
//   bulk of NAT-Lab files. We query di_submissions first and LEFT JOIN
//   rd_documents for enrichment.
//
// Additive: no auth layer, no caching, no embeddings, no full-text index.
// Response contract is preserved (best_match / alternatives; all existing
// item fields retained). New field: submission_id — carries the DI id for
// files that have no rd_documents row, so Zoe can still reference them.
//
// Exported as a factory so we reuse the existing pg Pool from server.js.

'use strict';

const express = require('express');

module.exports = function assistantFilesRouter(pool) {
    const router = express.Router();

    router.get('/search', async (req, res) => {
        const wsSlug = (req.query.ws || '').toString().trim();
        const q = (req.query.q || '').toString().trim();
        if (!wsSlug) return res.status(400).json({ error: 'ws query parameter is required' });
        if (!q)      return res.status(400).json({ error: 'q query parameter is required' });

        const researcher = (req.query.researcher || '').toString().trim() || null;
        const projectId  = (req.query.project_id || '').toString().trim() || null;
        const fileType   = (req.query.file_type || '').toString().trim().toUpperCase() || null;
        const status     = (req.query.status || '').toString().trim().toUpperCase() || null;

        let limit = parseInt(req.query.limit, 10);
        if (!Number.isFinite(limit) || limit < 1) limit = 3;
        if (limit > 5) limit = 5;

        try {
            // Resolve workspace slug -> id (same pattern as /api/assistant/status).
            const wsRow = await pool.query(
                `SELECT id, slug FROM workspaces WHERE slug = $1 AND is_active = TRUE LIMIT 1`,
                [wsSlug]
            );
            if (wsRow.rows.length === 0) {
                return res.status(404).json({ error: 'Workspace not found' });
            }
            const workspaceId = wsRow.rows[0].id;
            const workspaceSlug = wsRow.rows[0].slug;

            // Build parametrized SQL. Keep it simple and transparent.
            const params = [];
            const push = (v) => { params.push(v); return '$' + params.length; };

            const pWs      = push(workspaceId);      // $1
            const pExact   = push(q);                // $2 — for exact-match bonuses (case-insensitive)
            const pExactUp = push(q.toUpperCase());  // $3 — for file_type exact match ('SOP', 'DATA', ...)
            const pWrap    = push('%' + q + '%');    // $4 — for ILIKE wrapped match

            // Primary source: di_submissions (the canonical NAT-Lab upload table).
            // rd_documents is LEFT JOIN'd (via r2_key or filename+timestamp fallback)
            // only to enrich title / rd_documents.id / project_id when they exist.
            // The filename+timestamp fallback handles the case where a revision or
            // discard nulled di_submissions.r2_object_key — rd_documents.r2_key is
            // still set, and rd_documents + its initial di_submissions row were
            // written in the same transaction, so their created_at timestamps match
            // within ms.
            //
            // di_allowlist join provides a trustworthy submitted_by_name (the
            // researcher's canonical name), not the free-text uploaded_by field.
            let sql = `
                SELECT s.submission_id,
                       s.original_filename,
                       s.file_type         AS submission_file_type,
                       s.r2_object_key,
                       s.status            AS glp_status,
                       s.created_at        AS submission_created_at,
                       s.signed_at         AS submission_signed_at,
                       s.discarded_at      AS submission_discarded_at,
                       s.researcher_id     AS submission_researcher_id,
                       s.affiliation       AS submission_affiliation,
                       s.revision_comments AS submission_revision_comments,
                       s.discard_reason    AS submission_discard_reason,
                       a.name              AS submitter_name,
                       d.id                AS rd_id,
                       d.title             AS rd_title,
                       d.filename          AS rd_filename,
                       d.document_type     AS rd_document_type,
                       d.project_id        AS rd_project_id,
                       d.uploaded_by       AS rd_uploaded_by,
                       d.created_at        AS rd_created_at,
                       (
                           -- file_type exact match (e.g. "sop" → type SOP) is the
                           -- strongest signal for NAT-Lab intent queries
                           (CASE WHEN UPPER(COALESCE(s.file_type,'')) = ${pExactUp} THEN 12 ELSE 0 END)
                         -- title/filename exact/substring matches
                         + (CASE WHEN LOWER(COALESCE(d.title,'')) = LOWER(${pExact}) THEN 10 ELSE 0 END)
                         + (CASE WHEN LOWER(COALESCE(s.original_filename,'')) = LOWER(${pExact}) THEN 8 ELSE 0 END)
                         + (CASE WHEN COALESCE(d.title,'')             ILIKE ${pWrap} THEN 6 ELSE 0 END)
                         + (CASE WHEN COALESCE(s.original_filename,'') ILIKE ${pWrap} THEN 5 ELSE 0 END)
                         -- state & recency bonuses
                         + (CASE WHEN s.status = 'APPROVED' THEN 2 ELSE 0 END)
                         + (CASE WHEN s.created_at >= NOW() - INTERVAL '30 days' THEN 1 ELSE 0 END)
                       ) AS score
                  FROM di_submissions s
                  LEFT JOIN di_allowlist a ON a.researcher_id = s.researcher_id
                  LEFT JOIN LATERAL (
                      SELECT d2.id, d2.title, d2.filename, d2.document_type,
                             d2.project_id, d2.uploaded_by, d2.created_at
                        FROM rd_documents d2
                       WHERE d2.workspace_id = s.workspace_id
                         AND (
                               d2.r2_key = s.r2_object_key
                               OR (
                                   s.r2_object_key IS NULL
                                   AND d2.filename = s.original_filename
                                   AND d2.created_at BETWEEN s.created_at - INTERVAL '5 seconds'
                                                         AND s.created_at + INTERVAL '5 seconds'
                               )
                         )
                       ORDER BY
                           CASE WHEN d2.r2_key = s.r2_object_key THEN 0 ELSE 1 END ASC,
                           d2.created_at DESC
                       LIMIT 1
                  ) d ON TRUE
                 WHERE s.workspace_id = ${pWs}
                   AND (
                         COALESCE(s.original_filename,'') ILIKE ${pWrap}
                         OR COALESCE(d.title,'')          ILIKE ${pWrap}
                         OR UPPER(COALESCE(s.file_type,'')) = ${pExactUp}
                   )`;

            // Exclude discarded material by default; only include it if status explicitly asks.
            if (status === 'DISCARDED') {
                sql += ` AND s.status = 'DISCARDED'`;
            } else {
                sql += ` AND (s.status IS NULL OR s.status <> 'DISCARDED')`;
                if (status) {
                    sql += ` AND s.status = ${push(status)}`;
                }
            }

            // Researcher filter: match either the researcher_id (authoritative code
            // e.g. "HJM") or the di_allowlist display name via substring ILIKE.
            if (researcher) {
                const pRes = push(researcher);
                const pResWrap = push('%' + researcher + '%');
                sql += ` AND (s.researcher_id = ${pRes}
                           OR COALESCE(a.name,'') ILIKE ${pResWrap})`;
            }
            if (projectId) {
                // project_id is optional metadata in NAT-Lab — enforce only when
                // rd_documents row exists (otherwise filter excludes by NULL semantics).
                sql += ` AND d.project_id = ${push(projectId)}`;
            }
            if (fileType) {
                sql += ` AND UPPER(COALESCE(s.file_type,'')) = ${push(fileType)}`;
            }

            sql += ` ORDER BY score DESC, s.created_at DESC NULLS LAST
                     LIMIT ${push(limit)}`;

            const r = await pool.query(sql, params);
            const rows = r.rows || [];

            const toItem = (row) => {
                const matchReason = buildReason(row, q);
                // Canonical timestamps: use the submission row as the time authority
                // (it's the primary table). rd_documents.created_at is a secondary
                // fallback if present.
                const createdAt = row.submission_created_at || row.rd_created_at || null;
                const updatedAt = row.submission_discarded_at
                               || row.submission_signed_at
                               || createdAt;

                const ageMs = createdAt ? Date.now() - new Date(createdAt).getTime() : null;
                let reviewState;
                if      (!row.glp_status)                      reviewState = 'not_submitted';
                else if (row.glp_status === 'DISCARDED')       reviewState = 'discarded';
                else if (row.glp_status === 'APPROVED')        reviewState = 'approved';
                else if (row.glp_status === 'REVISION_NEEDED') reviewState = (ageMs && ageMs > 14 * 24 * 3600 * 1000) ? 'blocked' : 'needs_revision';
                else if (row.glp_status === 'PENDING')         reviewState = (ageMs && ageMs > 7  * 24 * 3600 * 1000) ? 'stalled' : 'awaiting_review';
                else                                           reviewState = String(row.glp_status).toLowerCase();

                let revisionReason = null;
                if (row.glp_status === 'REVISION_NEEDED')      revisionReason = row.submission_revision_comments || null;
                else if (row.glp_status === 'DISCARDED')       revisionReason = row.submission_discard_reason    || null;

                // file_id remains the rd_documents.id when that row exists (so
                // open_file_in_portal keeps working). When the file was ingested
                // via the DI-only path, file_id is null and callers should use
                // submission_id for reference.
                const fileId   = row.rd_id || null;
                const title    = row.rd_title || row.original_filename || null;
                const filename = row.original_filename || row.rd_filename || null;
                const fileType = row.submission_file_type || row.rd_document_type || null;

                return {
                    // --- existing contract (kept verbatim for backward compat) ---
                    file_id:   fileId,
                    title,
                    file_type: fileType,
                    status:    row.glp_status || null,
                    reason:    matchReason,
                    // --- enrichment (Priority 3) ---
                    id:                fileId,
                    filename,
                    review_state:      reviewState,
                    revision_reason:   revisionReason,
                    created_at:        createdAt ? new Date(createdAt).toISOString() : null,
                    updated_at:        updatedAt ? new Date(updatedAt).toISOString() : null,
                    submitted_by_name: row.submitter_name || row.rd_uploaded_by || null,
                    researcher_id:     row.submission_researcher_id || null,
                    affiliation:       row.submission_affiliation   || null,
                    r2_object_key:     row.r2_object_key || null,
                    project_id:        row.rd_project_id || null,
                    match_reason:      matchReason,
                    // --- new: always-available DI reference for files without an
                    //     rd_documents row. Lets Zoe reference DI-only uploads
                    //     without inventing a file_id.
                    submission_id:     row.submission_id || null
                };
            };

            if (rows.length === 0) {
                return res.json({
                    workspace: workspaceSlug,
                    query: q,
                    best_match: null,
                    alternatives: []
                });
            }

            const [best, ...rest] = rows;
            res.json({
                workspace: workspaceSlug,
                query: q,
                best_match: toItem(best),
                alternatives: rest.map(toItem)
            });
        } catch (err) {
            console.error('[ASSISTANT] files/search error:', err.message);
            res.status(500).json({ error: 'Failed to search files' });
        }
    });

    // GET /api/assistant/files/:id?ws=natlab
    // Deep detail for one rd_documents row, with a grounded status history.
    // Route ordering matters: '/search' is defined above so '/:id' only matches
    // UUID-shaped ids; we additionally constrain the path param to a UUID regex
    // to be defensive against accidental matches on future sibling routes.
    router.get('/:id', async (req, res) => {
        const fileId = (req.params.id || '').toString().trim();
        const wsSlug = (req.query.ws || '').toString().trim();
        if (!wsSlug) return res.status(400).json({ error: 'ws query parameter is required' });
        if (!fileId) return res.status(400).json({ error: 'file id is required' });
        if (!/^[0-9a-fA-F-]{36}$/.test(fileId)) return res.status(404).json({ error: 'File not found in workspace' });

        try {
            // Resolve workspace slug -> id (same pattern as /search)
            const wsRow = await pool.query(
                `SELECT id, slug FROM workspaces WHERE slug = $1 AND is_active = TRUE LIMIT 1`,
                [wsSlug]
            );
            if (wsRow.rows.length === 0) {
                return res.status(404).json({ error: 'Workspace not found' });
            }
            const workspaceId   = wsRow.rows[0].id;
            const workspaceSlug = wsRow.rows[0].slug;

            // Fetch rd_documents row joined to its latest di_submissions row.
            //
            // rd_documents.r2_key is persistent; di_submissions.r2_object_key is
            // nulled when status transitions to REVISION_NEEDED or DISCARDED (see
            // server.js). To still find the submission in those states, the
            // LATERAL falls back to (workspace_id + original_filename + created_at
            // proximity), since rd_documents and its initial di_submissions row
            // are written in the same transaction and share filename and ~ms
            // timestamp. The r2_key match is preferred when valid.
            const detail = await pool.query(
                `SELECT d.id, d.title, d.filename, d.document_type, d.file_type,
                        d.r2_key, d.uploaded_by, d.created_at, d.project_id,
                        d.file_size,
                        s.submission_id        AS submission_id,
                        s.status               AS glp_status,
                        s.created_at           AS submission_created_at,
                        s.researcher_id        AS submission_researcher_id,
                        s.affiliation          AS submission_affiliation,
                        s.revision_comments    AS submission_revision_comments,
                        s.approval_comment     AS submission_approval_comment,
                        s.signed_at            AS submission_signed_at,
                        s.signer_name          AS submission_signer_name,
                        s.discarded_at         AS submission_discarded_at,
                        s.discarded_by         AS submission_discarded_by,
                        s.discard_reason       AS submission_discard_reason,
                        s.discard_note         AS submission_discard_note
                   FROM rd_documents d
                   LEFT JOIN LATERAL (
                       SELECT s2.*
                         FROM di_submissions s2
                        WHERE s2.workspace_id = d.workspace_id
                          AND (
                              s2.r2_object_key = d.r2_key
                              OR (
                                  s2.r2_object_key IS NULL
                                  AND s2.original_filename = d.filename
                                  AND s2.created_at BETWEEN d.created_at - INTERVAL '5 seconds'
                                                        AND d.created_at + INTERVAL '5 seconds'
                              )
                          )
                        ORDER BY
                            CASE WHEN s2.r2_object_key = d.r2_key THEN 0 ELSE 1 END ASC,
                            s2.created_at DESC
                        LIMIT 1
                   ) s ON TRUE
                  WHERE d.workspace_id = $1
                    AND d.id = $2
                  LIMIT 1`,
                [workspaceId, fileId]
            );

            if (detail.rows.length === 0) {
                return res.status(404).json({ error: 'File not found in workspace' });
            }
            const row = detail.rows[0];

            // Derive review_state (same rules as /search for consistency)
            const ageMs = row.created_at ? Date.now() - new Date(row.created_at).getTime() : null;
            let reviewState;
            if      (!row.glp_status)                      reviewState = 'not_submitted';
            else if (row.glp_status === 'DISCARDED')       reviewState = 'discarded';
            else if (row.glp_status === 'APPROVED')        reviewState = 'approved';
            else if (row.glp_status === 'REVISION_NEEDED') reviewState = (ageMs && ageMs > 14 * 24 * 3600 * 1000) ? 'blocked' : 'needs_revision';
            else if (row.glp_status === 'PENDING')         reviewState = (ageMs && ageMs > 7  * 24 * 3600 * 1000) ? 'stalled' : 'awaiting_review';
            else                                           reviewState = String(row.glp_status).toLowerCase();

            // revision_reason: REVISION_NEEDED -> revision_comments; DISCARDED -> discard_reason
            let revisionReason = null;
            if (row.glp_status === 'REVISION_NEEDED')      revisionReason = row.submission_revision_comments || null;
            else if (row.glp_status === 'DISCARDED')       revisionReason = row.submission_discard_reason    || null;

            // History: derive a timeline from the submission row + any revision
            // requests. We only include events with a real timestamp — no
            // invented audit rows. di_revision_requests may not exist on older
            // databases; treat a query error as "no revision history available".
            const history = [];

            // 1. Upload event — always present when we found a submission.
            if (row.submission_created_at || row.created_at) {
                history.push({
                    at:    (row.submission_created_at || row.created_at).toISOString(),
                    state: 'UPLOADED',
                    by:    row.submission_researcher_id || null,
                    note:  null
                });
            }

            // 2. Revision requests — pull from di_revision_requests for this
            //    submission. Each open or closed row represents a PI asking for a
            //    revision, with the pi_comment as the note.
            let revisionRequests = [];
            if (row.submission_id) {
                try {
                    const revReq = await pool.query(
                        `SELECT created_at, closed_at, pi_comment, status
                           FROM di_revision_requests
                          WHERE file_id = $1
                          ORDER BY created_at ASC`,
                        [row.submission_id]
                    );
                    revisionRequests = revReq.rows || [];
                } catch (e) {
                    // Table missing on older DBs — silently skip.
                    revisionRequests = [];
                }
            }
            for (const rr of revisionRequests) {
                if (rr.created_at) {
                    history.push({
                        at:    new Date(rr.created_at).toISOString(),
                        state: 'REVISION_REQUESTED',
                        by:    null, // di_revision_requests does not store the PI id
                        note:  rr.pi_comment || null
                    });
                }
                if (rr.closed_at && rr.status === 'closed') {
                    history.push({
                        at:    new Date(rr.closed_at).toISOString(),
                        state: 'REVISION_CLOSED',
                        by:    null,
                        note:  null
                    });
                }
            }

            // 3. Approval event — signed_at is the authoritative approval time.
            if (row.submission_signed_at) {
                history.push({
                    at:    new Date(row.submission_signed_at).toISOString(),
                    state: 'APPROVED',
                    by:    row.submission_signer_name || null,
                    note:  row.submission_approval_comment || null
                });
            }

            // 4. Discard event
            if (row.submission_discarded_at) {
                const note = [row.submission_discard_reason, row.submission_discard_note]
                    .filter(Boolean).join(' — ') || null;
                history.push({
                    at:    new Date(row.submission_discarded_at).toISOString(),
                    state: 'DISCARDED',
                    by:    row.submission_discarded_by || null,
                    note
                });
            }

            // Sort chronologically (oldest -> newest) for a readable timeline.
            history.sort((a, b) => new Date(a.at).getTime() - new Date(b.at).getTime());

            res.json({
                workspace:         workspaceSlug,
                id:                row.id,
                file_id:           row.id, // convenience alias matching /search
                filename:          row.filename || null,
                title:             row.title || null,
                file_type:         row.document_type || row.file_type || null,
                file_size:         row.file_size || null,
                status:            row.glp_status || null,
                review_state:      reviewState,
                revision_reason:   revisionReason,
                created_at:        row.created_at ? new Date(row.created_at).toISOString() : null,
                updated_at:        (row.submission_created_at || row.created_at)
                                      ? new Date(row.submission_created_at || row.created_at).toISOString()
                                      : null,
                submitted_by_name: row.uploaded_by || null,
                researcher_id:     row.submission_researcher_id || null,
                affiliation:       row.submission_affiliation   || null,
                r2_object_key:     row.r2_key || null,
                project_id:        row.project_id || null,
                // approver_id is not stored as an ID in di_submissions — only
                // signer_name (a TEXT display name). Expose both: approver_id
                // stays null until the schema carries an id, approver_name
                // carries the best we have.
                approver_id:       null,
                approver_name:     row.submission_signer_name || null,
                approved_at:       row.submission_signed_at
                                      ? new Date(row.submission_signed_at).toISOString()
                                      : null,
                history
            });
        } catch (err) {
            console.error('[ASSISTANT] files/:id error:', err.message);
            res.status(500).json({ error: 'Failed to load file detail' });
        }
    });

    return router;
};

// Short human-readable reason string for why this row ranked where it did.
// Reads from the di_submissions-primary column set (with rd_documents title
// as optional enrichment). Falls back gracefully when fields are missing.
function buildReason(row, q) {
    const parts = [];
    const needle = q.toLowerCase();
    const title    = (row.rd_title || '').toLowerCase();
    const filename = (row.original_filename || row.rd_filename || '').toLowerCase();
    const fileType = (row.submission_file_type || row.rd_document_type || '').toUpperCase();
    const qUp = q.toUpperCase();

    if (fileType && fileType === qUp)            parts.push(`file_type = ${fileType}`);
    if (title && title === needle)               parts.push('exact title match');
    else if (title.includes(needle))             parts.push('title contains query');
    else if (filename.includes(needle))          parts.push('filename contains query');
    if (row.glp_status === 'APPROVED')           parts.push('APPROVED');
    const createdAt = row.submission_created_at || row.rd_created_at;
    if (createdAt && (Date.now() - new Date(createdAt).getTime()) < 30 * 24 * 3600 * 1000) {
        parts.push('recent upload');
    }
    return parts.length ? parts.join('; ') : 'matched search term';
}
