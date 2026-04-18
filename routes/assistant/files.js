// Portal Assistant API — Zoe
// GET /api/assistant/files/search
//
// Simple ranked file search against rd_documents, optionally enriched with
// GLP status from di_submissions (linked via r2_key == r2_object_key).
// Additive: no auth layer, no caching, no embeddings, no full-text index.
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

            const pWs      = push(workspaceId);   // $1
            const pExact   = push(q);             // $2 — for title = q (case-insensitive)
            const pWrap    = push('%' + q + '%'); // $3 — for ILIKE wrapped match

            // di_submissions has no UNIQUE(workspace_id, r2_object_key): revisions and
            // resubmissions can produce multiple rows for the same R2 key. We use a
            // LATERAL subquery with LIMIT 1 to pick the most recent submission per
            // document so rd_documents rows are not duplicated in the result set.
            let sql = `
                SELECT d.id, d.title, d.filename, d.document_type, d.file_type,
                       d.r2_key, d.uploaded_by, d.created_at, d.project_id,
                       s.status AS glp_status,
                       (
                           (CASE WHEN LOWER(COALESCE(d.title,'')) = LOWER(${pExact}) THEN 10 ELSE 0 END)
                         + (CASE WHEN COALESCE(d.title,'')    ILIKE ${pWrap} THEN 6 ELSE 0 END)
                         + (CASE WHEN COALESCE(d.filename,'') ILIKE ${pWrap} THEN 4 ELSE 0 END)
                         + (CASE WHEN s.status = 'APPROVED' THEN 2 ELSE 0 END)
                         + (CASE WHEN d.created_at >= NOW() - INTERVAL '30 days' THEN 1 ELSE 0 END)
                       ) AS score
                  FROM rd_documents d
                  LEFT JOIN LATERAL (
                      SELECT s2.status, s2.created_at
                        FROM di_submissions s2
                       WHERE s2.workspace_id  = d.workspace_id
                         AND s2.r2_object_key = d.r2_key
                       ORDER BY s2.created_at DESC
                       LIMIT 1
                  ) s ON TRUE
                 WHERE d.workspace_id = ${pWs}
                   AND (COALESCE(d.title,'') ILIKE ${pWrap}
                        OR COALESCE(d.filename,'') ILIKE ${pWrap})`;

            // Exclude discarded material by default; only include it if status explicitly asks.
            // Note: when an explicit status is supplied (e.g. ?status=APPROVED), rows whose
            // latest submission is NULL (no di_submissions row for this rd_document) are
            // excluded — `NULL = 'APPROVED'` evaluates to NULL and is filtered out. That is
            // the intended behavior: "filter by GLP status" means "must have that status".
            if (status === 'DISCARDED') {
                sql += ` AND s.status = 'DISCARDED'`;
            } else {
                sql += ` AND (s.status IS NULL OR s.status <> 'DISCARDED')`;
                if (status) {
                    sql += ` AND s.status = ${push(status)}`;
                }
            }

            // rd_documents.uploaded_by is a TEXT display name (e.g. "Jane Doe"), not a
            // researcher ID or FK — see the INSERT path in server.js which writes
            // req.session.user.name. Substring ILIKE matches that free-text label.
            if (researcher) {
                sql += ` AND COALESCE(d.uploaded_by,'') ILIKE ${push('%' + researcher + '%')}`;
            }
            if (projectId) {
                sql += ` AND d.project_id = ${push(projectId)}`;
            }
            if (fileType) {
                sql += ` AND (UPPER(COALESCE(d.file_type,'')) = ${push(fileType)}
                           OR UPPER(COALESCE(d.document_type,'')) = $${params.length})`;
            }

            sql += ` ORDER BY score DESC, d.created_at DESC NULLS LAST
                     LIMIT ${push(limit)}`;

            const r = await pool.query(sql, params);
            const rows = r.rows || [];

            const toItem = (row) => ({
                file_id: row.id,
                title: row.title || row.filename,
                file_type: row.document_type || row.file_type || null,
                status: row.glp_status || null,
                reason: buildReason(row, q)
            });

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

    return router;
};

// Short human-readable reason string for why this row ranked where it did.
function buildReason(row, q) {
    const parts = [];
    const title = (row.title || '').toLowerCase();
    const fname = (row.filename || '').toLowerCase();
    const needle = q.toLowerCase();
    if (title && title === needle)         parts.push('exact title match');
    else if (title.includes(needle))       parts.push('title contains query');
    else if (fname.includes(needle))       parts.push('filename contains query');
    if (row.glp_status === 'APPROVED')     parts.push('APPROVED');
    if (row.created_at && (Date.now() - new Date(row.created_at).getTime()) < 30 * 24 * 3600 * 1000) {
        parts.push('recent upload');
    }
    return parts.length ? parts.join('; ') : 'matched search term';
}
