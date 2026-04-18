// Portal Assistant API — Zoe
// GET /api/assistant/attention
//
// Short prioritized list of attention items for a workspace.
// Simple, transparent, rule-based — not a full alert engine.
// Additive: no auth layer, no caching, no background jobs, no schema changes.
//
// Exported as a factory so we reuse the existing pg Pool from server.js.

'use strict';

const express = require('express');

module.exports = function assistantAttentionRouter(pool) {
    const router = express.Router();

    router.get('/', async (req, res) => {
        const wsSlug = (req.query.ws || '').toString().trim();
        if (!wsSlug) return res.status(400).json({ error: 'ws query parameter is required' });

        let limit = parseInt(req.query.limit, 10);
        if (!Number.isFinite(limit) || limit < 1) limit = 5;
        if (limit > 10) limit = 10;

        try {
            // Resolve workspace slug -> id.
            const wsRow = await pool.query(
                `SELECT id, slug FROM workspaces WHERE slug = $1 AND is_active = TRUE LIMIT 1`,
                [wsSlug]
            );
            if (wsRow.rows.length === 0) {
                return res.status(404).json({ error: 'Workspace not found' });
            }
            const workspaceId = wsRow.rows[0].id;
            const workspaceSlug = wsRow.rows[0].slug;

            // Run all count probes in parallel. Each one is a simple, bounded query.
            const [pending, revision, stalePending, inactiveProjects, recentUploads] = await Promise.all([
                // High: items awaiting GLP review
                pool.query(
                    `SELECT COUNT(*)::int AS c
                       FROM di_submissions
                      WHERE workspace_id = $1 AND status = 'PENDING'`,
                    [workspaceId]
                ),
                // High: items already flagged for revision
                pool.query(
                    `SELECT COUNT(*)::int AS c
                       FROM di_submissions
                      WHERE workspace_id = $1 AND status = 'REVISION_NEEDED'`,
                    [workspaceId]
                ),
                // Medium: pending items waiting more than 7 days
                pool.query(
                    `SELECT COUNT(*)::int AS c
                       FROM di_submissions
                      WHERE workspace_id = $1
                        AND status = 'PENDING'
                        AND created_at < NOW() - INTERVAL '7 days'`,
                    [workspaceId]
                ),
                // Medium: projects with no activity in 45 days.
                // Activity = most recent rd_documents upload on the project; if the
                // project has zero documents we fall back to the project's own
                // created_at (same "last_activity" logic already used in
                // server.js /api/rd/projects). We ignore archived/completed projects.
                pool.query(
                    `SELECT COUNT(*)::int AS c
                       FROM rd_projects p
                      WHERE p.workspace_id = $1
                        AND p.status NOT IN ('archived','completed')
                        AND COALESCE(
                            (SELECT MAX(d.created_at) FROM rd_documents d
                              WHERE d.project_id = p.id),
                            p.created_at
                        ) < NOW() - INTERVAL '45 days'`,
                    [workspaceId]
                ),
                // Low: recent upload activity probe (0 uploads in last 30 days)
                pool.query(
                    `SELECT COUNT(*)::int AS c
                       FROM rd_documents
                      WHERE workspace_id = $1
                        AND created_at >= NOW() - INTERVAL '30 days'`,
                    [workspaceId]
                )
            ]);

            // Build items in descending priority / practical-importance order.
            // The final sort is stable, so insertion order decides the tie-break
            // within the same priority bucket.
            const items = [];
            const nPending   = pending.rows[0].c;
            const nRevision  = revision.rows[0].c;
            const nStale     = stalePending.rows[0].c;
            const nInactive  = inactiveProjects.rows[0].c;
            const nRecent    = recentUploads.rows[0].c;

            if (nPending > 0) {
                items.push({
                    type: 'glp_pending',
                    priority: 'high',
                    message: `${nPending} ${nPending === 1 ? 'item requires' : 'items require'} GLP review`
                });
            }
            if (nRevision > 0) {
                items.push({
                    type: 'glp_revision_needed',
                    priority: 'high',
                    message: `${nRevision} ${nRevision === 1 ? 'item requires' : 'items require'} revision`
                });
            }
            if (nStale > 0) {
                items.push({
                    type: 'glp_pending_stale',
                    priority: 'medium',
                    message: `${nStale} pending ${nStale === 1 ? 'item has' : 'items have'} been waiting more than 7 days`
                });
            }
            if (nInactive > 0) {
                items.push({
                    type: 'project_inactive',
                    priority: 'medium',
                    message: `${nInactive} ${nInactive === 1 ? 'project shows' : 'projects show'} no activity in the last 45 days`
                });
            }
            if (nRecent === 0) {
                items.push({
                    type: 'low_upload_activity',
                    priority: 'low',
                    message: 'Low recent upload activity in workspace'
                });
            }

            // Sort: high > medium > low, keeping insertion order within a bucket.
            const rank = { high: 0, medium: 1, low: 2 };
            items.sort((a, b) => rank[a.priority] - rank[b.priority]);

            res.json({
                workspace: workspaceSlug,
                items: items.slice(0, limit),
                updated_at: new Date().toISOString()
            });
        } catch (err) {
            console.error('[ASSISTANT] attention error:', err.message);
            res.status(500).json({ error: 'Failed to build attention list' });
        }
    });

    return router;
};
