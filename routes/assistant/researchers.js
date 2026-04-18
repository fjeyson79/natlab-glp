// Portal Assistant API — Zoe
// GET /api/assistant/researchers/:id/report
//
// First-pass GLP-oriented report for one researcher in one workspace.
// Simple rule-based heuristics; NOT a final audit tool.
// Additive: no auth layer, no caching, no schema changes.
//
// Path param `:id` is the internal researcher identifier stored in
//   di_allowlist.researcher_id (VARCHAR(50) PRIMARY KEY)
// and referenced by
//   workspace_users.user_id (FK to di_allowlist.researcher_id)
// and
//   di_submissions.researcher_id.
// These are short codes assigned at onboarding (e.g. "HJM", "PMK", "HMMU"),
// NOT a numeric DB id and NOT a display name. Example:
//   GET /api/assistant/researchers/HJM/report?ws=natlab
//
// Exported as a factory so we reuse the existing pg Pool from server.js.

'use strict';

const express = require('express');

module.exports = function assistantResearchersRouter(pool) {
    const router = express.Router();

    router.get('/:id/report', async (req, res) => {
        const researcherId = (req.params.id || '').toString().trim();
        const wsSlug = (req.query.ws || '').toString().trim();
        if (!wsSlug)       return res.status(400).json({ error: 'ws query parameter is required' });
        if (!researcherId) return res.status(400).json({ error: 'researcher id is required' });

        // Parse `window` — accept "30d", "7d", "90d", or a plain integer as days.
        // Default: 30 days. Clamp to [1, 365] to keep the query bounded.
        const windowRaw = (req.query.window || '30d').toString().trim().toLowerCase();
        let windowDays = 30;
        const m = windowRaw.match(/^(\d+)\s*d?$/);
        if (m) windowDays = parseInt(m[1], 10);
        if (!Number.isFinite(windowDays) || windowDays < 1) windowDays = 30;
        if (windowDays > 365) windowDays = 365;
        const interval = `${windowDays} days`;

        try {
            // 1. Resolve workspace + verify researcher membership in one shot
            //    (same pattern used by requireCSO and others in server.js).
            //    The di_allowlist join is intentional: workspace_users.user_id is a
            //    foreign key to di_allowlist.researcher_id, so every valid workspace
            //    researcher has exactly one allowlist row. We join it here to pull
            //    the display name for the response — not as an extra gate. This
            //    endpoint therefore only reports on researchers who have an
            //    allowlist-linked identity in the workspace (which, by the FK, is
            //    every workspace researcher).
            const who = await pool.query(
                `SELECT w.id AS workspace_id, w.slug AS workspace_slug,
                        a.researcher_id, a.name
                   FROM workspaces w
                   JOIN workspace_users wu ON wu.workspace_id = w.id
                   JOIN di_allowlist a     ON a.researcher_id = wu.user_id
                  WHERE w.slug = $1
                    AND w.is_active = TRUE
                    AND wu.user_id = $2
                    AND wu.is_active = TRUE
                  LIMIT 1`,
                [wsSlug, researcherId]
            );
            if (who.rows.length === 0) {
                // Check whether the workspace itself exists so we can give an accurate 404
                const wsCheck = await pool.query(
                    `SELECT 1 FROM workspaces WHERE slug = $1 AND is_active = TRUE LIMIT 1`,
                    [wsSlug]
                );
                if (wsCheck.rows.length === 0) {
                    return res.status(404).json({ error: 'Workspace not found' });
                }
                return res.status(404).json({ error: 'Researcher not found in workspace' });
            }
            const { workspace_id: workspaceId, workspace_slug: workspaceSlug,
                    researcher_id: rid, name: researcherName } = who.rows[0];

            // 2. Pull researcher-linked rd_documents with their LATEST di_submissions
            //    status (same LATERAL LIMIT 1 pattern as files/search — di_submissions
            //    has no UNIQUE(workspace_id, r2_object_key), so revisions can produce
            //    multiple rows per R2 key).
            //
            //    Real researcher linkage: rd_documents has no researcher FK; the
            //    authoritative link is di_submissions.researcher_id, which is written
            //    in the same transaction as the rd_documents row (see server.js
            //    rd upload flow). We include a document if ANY of its di_submissions
            //    rows belong to this researcher.
            const docsSql = `
                SELECT d.id, d.title, d.filename, d.document_type, d.file_type,
                       d.project_id, d.created_at,
                       s.status AS glp_status
                  FROM rd_documents d
                  LEFT JOIN LATERAL (
                      SELECT s2.status, s2.created_at
                        FROM di_submissions s2
                       WHERE s2.workspace_id  = d.workspace_id
                         AND s2.r2_object_key = d.r2_key
                       ORDER BY s2.created_at DESC
                       LIMIT 1
                  ) s ON TRUE
                 WHERE d.workspace_id = $1
                   AND d.created_at >= NOW() - $2::interval
                   AND EXISTS (
                       SELECT 1 FROM di_submissions s3
                        WHERE s3.workspace_id  = d.workspace_id
                          AND s3.r2_object_key = d.r2_key
                          AND s3.researcher_id = $3
                   )
                 ORDER BY d.created_at DESC`;
            const docsRes = await pool.query(docsSql, [workspaceId, interval, rid]);
            const docs = docsRes.rows;

            // 3. Metrics (latest status per document)
            const metrics = {
                uploads:         docs.length,
                approved:        docs.filter(d => d.glp_status === 'APPROVED').length,
                pending:         docs.filter(d => d.glp_status === 'PENDING').length,
                revision_needed: docs.filter(d => d.glp_status === 'REVISION_NEEDED').length
            };

            // 4. Flags — simple, transparent thresholds
            const flags = [];
            const missingProjectCount = docs.filter(d => !d.project_id).length;
            const revisionRatio = metrics.uploads > 0 ? metrics.revision_needed / metrics.uploads : 0;
            const approvalRatio = metrics.uploads > 0 ? metrics.approved         / metrics.uploads : 0;

            if (metrics.uploads === 0) {
                flags.push('No uploads in selected period');
            } else {
                if (revisionRatio >= 0.30)   flags.push('High revision-needed ratio');
                if (missingProjectCount > 0) flags.push('Uploads missing project linkage');
                if (approvalRatio < 0.50)    flags.push('Low approval conversion');
            }

            // 5. Priority review — up to 3 files that most need attention
            //    Simple scoring: REVISION_NEEDED first, then missing project linkage,
            //    then stale PENDING (>7 days old inside the window).
            const nowMs = Date.now();
            const staleMs = 7 * 24 * 3600 * 1000;
            const priority = [];
            const seen = new Set();
            const push = (d, reason) => {
                if (priority.length >= 3 || seen.has(d.id)) return;
                seen.add(d.id);
                priority.push({ file_id: d.id, reason });
            };
            docs.filter(d => d.glp_status === 'REVISION_NEEDED')
                .forEach(d => push(d, 'GLP status REVISION_NEEDED'));
            docs.filter(d => !d.project_id)
                .forEach(d => push(d, 'Missing project linkage'));
            docs.filter(d => d.glp_status === 'PENDING'
                          && d.created_at
                          && (nowMs - new Date(d.created_at).getTime()) > staleMs)
                .forEach(d => push(d, 'Pending review for more than 7 days'));

            // 6. Compliance signal — simple, explainable rule-based scoring
            //    strong   : approval >= 70% AND no revisions
            //    moderate : approval >= 40% AND revision_needed < 30%
            //               ALSO: uploads === 0 (safer v1 default — "no data" is
            //               not evidence of good compliance, it is inconclusive;
            //               the "No uploads in selected period" flag surfaces this)
            //    weak     : everything else (high revisions, or very low approval)
            let compliance_signal;
            if (metrics.uploads === 0) {
                compliance_signal = 'moderate';
            } else if (approvalRatio >= 0.70 && metrics.revision_needed === 0) {
                compliance_signal = 'strong';
            } else if (approvalRatio >= 0.40 && revisionRatio < 0.30) {
                compliance_signal = 'moderate';
            } else {
                compliance_signal = 'weak';
            }

            // 7. Human-readable summary
            const summary = buildSummary({
                name: researcherName, windowDays, metrics, compliance_signal, flags
            });

            res.json({
                researcher: { id: rid, name: researcherName },
                workspace: workspaceSlug,
                compliance_signal,
                metrics,
                flags,
                priority_review: priority,
                summary
            });
        } catch (err) {
            console.error('[ASSISTANT] researchers/:id/report error:', err.message);
            res.status(500).json({ error: 'Failed to build researcher report' });
        }
    });

    return router;
};

function buildSummary({ name, windowDays, metrics, compliance_signal, flags }) {
    const who = name || 'Researcher';
    if (metrics.uploads === 0) {
        return `${who} has no uploads in the last ${windowDays} days.`;
    }
    const bits = [
        `${metrics.uploads} upload${metrics.uploads === 1 ? '' : 's'} in the last ${windowDays} days`,
        `${metrics.approved} approved, ${metrics.pending} pending, ${metrics.revision_needed} revision-needed`
    ];
    let line = `${who}: ${bits.join('; ')}. Compliance signal: ${compliance_signal}.`;
    if (flags.length) line += ` Flags: ${flags.join('; ')}.`;
    return line;
}
