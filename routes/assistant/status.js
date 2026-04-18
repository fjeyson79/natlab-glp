// Portal Assistant API — Zoe
// GET /api/assistant/status
//
// Returns a concise operational summary for a workspace.
// Additive: no auth layer yet, no caching, no joins beyond what is required.
//
// Exported as a factory so we reuse the existing pg Pool from server.js
// instead of opening a second DB connection.

'use strict';

const express = require('express');

module.exports = function assistantStatusRouter(pool) {
    const router = express.Router();

    router.get('/', async (req, res) => {
        const wsSlug = (req.query.ws || '').toString().trim();
        if (!wsSlug) {
            return res.status(400).json({ error: 'ws query parameter is required' });
        }

        try {
            // Resolve the workspace slug -> id. The global resolveWorkspace middleware
            // already does this, but we repeat it locally so this route is self-contained.
            const wsRow = await pool.query(
                `SELECT id, slug FROM workspaces WHERE slug = $1 AND is_active = TRUE LIMIT 1`,
                [wsSlug]
            );
            if (wsRow.rows.length === 0) {
                return res.status(404).json({ error: 'Workspace not found' });
            }
            const workspaceId = wsRow.rows[0].id;
            const workspaceSlug = wsRow.rows[0].slug;

            const [activeProjects, pending, revision, recent, last30] = await Promise.all([
                pool.query(
                    `SELECT COUNT(*)::int AS c
                       FROM rd_projects
                      WHERE workspace_id = $1
                        AND status NOT IN ('archived','completed')`,
                    [workspaceId]
                ),
                pool.query(
                    `SELECT COUNT(*)::int AS c
                       FROM di_submissions
                      WHERE workspace_id = $1
                        AND status = 'PENDING'`,
                    [workspaceId]
                ),
                pool.query(
                    `SELECT COUNT(*)::int AS c
                       FROM di_submissions
                      WHERE workspace_id = $1
                        AND status = 'REVISION_NEEDED'`,
                    [workspaceId]
                ),
                pool.query(
                    `SELECT COUNT(*)::int AS c
                       FROM rd_documents
                      WHERE workspace_id = $1
                        AND created_at >= NOW() - INTERVAL '7 days'`,
                    [workspaceId]
                ),
                pool.query(
                    `SELECT COUNT(*)::int AS c
                       FROM rd_documents
                      WHERE workspace_id = $1
                        AND created_at >= NOW() - INTERVAL '30 days'`,
                    [workspaceId]
                )
            ]);

            const summary = {
                active_projects: activeProjects.rows[0].c,
                pending_glp_items: pending.rows[0].c,
                revision_needed: revision.rows[0].c,
                recent_uploads: recent.rows[0].c
            };

            const attention = [];
            if (summary.pending_glp_items > 0) {
                const n = summary.pending_glp_items;
                attention.push(`${n} ${n === 1 ? 'item requires' : 'items require'} GLP review`);
            }
            if (summary.revision_needed > 0) {
                const n = summary.revision_needed;
                attention.push(`${n} ${n === 1 ? 'item requires' : 'items require'} revision`);
            }
            if (last30.rows[0].c === 0) {
                attention.push('Low recent activity in workspace');
            }

            res.json({
                workspace: workspaceSlug,
                summary,
                attention: attention.slice(0, 3),
                updated_at: new Date().toISOString()
            });
        } catch (err) {
            console.error('[ASSISTANT] status error:', err.message);
            res.status(500).json({ error: 'Failed to build status' });
        }
    });

    return router;
};
