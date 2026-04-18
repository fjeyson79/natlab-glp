// Portal Assistant API — Zoe
// POST /api/assistant/viewer/open
//
// Queues one pending "open this file" command for a previously registered
// Zoe control session. v1: write-only. No websockets, no polling endpoint,
// no consumption endpoint, no full command queue processing — those are
// future phases.
//
// Persistence: zoe_viewer_commands (migration 064). Inserts a single
// PENDING row per request; nothing reads it back yet.
//
// Additive: no auth layer, no schema changes beyond the new table.
// Exported as a factory so we reuse the existing pg Pool from server.js.

'use strict';

const express = require('express');

const ALLOWED_MODES = new Set(['viewer']);  // future: 'navigator', 'upload', …

// Cached existence check for the new queue table (same pattern as
// checkRdTables in server.js). If the migration is not yet applied, the
// endpoint fails closed with 503.
let _tableReady = null;
async function ensureTable(pool) {
    if (_tableReady !== null) return _tableReady;
    try {
        const r = await pool.query(`SELECT to_regclass('public.zoe_viewer_commands') AS t`);
        _tableReady = r.rows[0].t !== null;
    } catch {
        _tableReady = false;
    }
    return _tableReady;
}

module.exports = function assistantViewerRouter(pool) {
    const router = express.Router();

    router.post('/open', async (req, res) => {
        const body = req.body || {};
        const wsSlug = (body.ws || '').toString().trim();
        const controlSessionId = (body.control_session_id || '').toString().trim();
        const fileId = (body.file_id || '').toString().trim();
        let mode = (body.mode || 'viewer').toString().trim().toLowerCase();

        if (!wsSlug)           return res.status(400).json({ error: 'ws is required' });
        if (!controlSessionId) return res.status(400).json({ error: 'control_session_id is required' });
        if (!fileId)           return res.status(400).json({ error: 'file_id is required' });
        if (!ALLOWED_MODES.has(mode)) mode = 'viewer';

        try {
            if (!(await ensureTable(pool))) {
                return res.status(503).json({ error: 'Viewer command queue not ready (migration 064 pending)' });
            }

            // 1. Workspace must resolve.
            const wsRow = await pool.query(
                `SELECT id FROM workspaces WHERE slug = $1 AND is_active = TRUE LIMIT 1`,
                [wsSlug]
            );
            if (wsRow.rows.length === 0) {
                return res.status(404).json({ error: 'Workspace not found' });
            }
            const workspaceId = wsRow.rows[0].id;

            // 2. Control session must exist, belong to this workspace, be active,
            //    and not expired. One query covers all four checks.
            const cs = await pool.query(
                `SELECT id FROM zoe_control_sessions
                  WHERE id = $1
                    AND workspace_id = $2
                    AND is_active = TRUE
                    AND expires_at > NOW()
                  LIMIT 1`,
                [controlSessionId, workspaceId]
            );
            if (cs.rows.length === 0) {
                return res.status(404).json({ error: 'Control session not found, expired, or inactive for this workspace' });
            }

            // 3. file_id must exist in rd_documents within this workspace.
            const doc = await pool.query(
                `SELECT id FROM rd_documents
                  WHERE id = $1 AND workspace_id = $2
                  LIMIT 1`,
                [fileId, workspaceId]
            );
            if (doc.rows.length === 0) {
                return res.status(404).json({ error: 'File not found in workspace' });
            }

            // 4. Enqueue the command (always a fresh PENDING row).
            const ins = await pool.query(
                `INSERT INTO zoe_viewer_commands
                     (workspace_id, control_session_id, file_id, mode, status)
                 VALUES ($1, $2, $3, $4, 'PENDING')
                 RETURNING id`,
                [workspaceId, controlSessionId, fileId, mode]
            );
            console.log('[ZOE] open queued: ' + ins.rows[0].id);

            res.json({ ok: true, message: 'Opening file in portal viewer' });
        } catch (err) {
            console.error('[ASSISTANT] viewer/open error:', err.message);
            res.status(500).json({ error: 'Failed to queue viewer open command' });
        }
    });

    // ------------------------------------------------------------------
    // GET /api/assistant/viewer/next
    // Returns the oldest PENDING command for a control session, or null.
    // No mutation — the browser calls /consume after it has opened the file.
    // ------------------------------------------------------------------
    router.get('/next', async (req, res) => {
        const wsSlug = (req.query.ws || '').toString().trim();
        const controlSessionId = (req.query.control_session_id || '').toString().trim();
        if (!wsSlug)           return res.status(400).json({ error: 'ws is required' });
        if (!controlSessionId) return res.status(400).json({ error: 'control_session_id is required' });

        try {
            if (!(await ensureTable(pool))) {
                return res.status(503).json({ error: 'Viewer command queue not ready (migration 064 pending)' });
            }

            const wsRow = await pool.query(
                `SELECT id FROM workspaces WHERE slug = $1 AND is_active = TRUE LIMIT 1`,
                [wsSlug]
            );
            if (wsRow.rows.length === 0) {
                return res.status(404).json({ error: 'Workspace not found' });
            }
            const workspaceId = wsRow.rows[0].id;

            const cs = await pool.query(
                `SELECT id FROM zoe_control_sessions
                  WHERE id = $1 AND workspace_id = $2
                    AND is_active = TRUE AND expires_at > NOW()
                  LIMIT 1`,
                [controlSessionId, workspaceId]
            );
            if (cs.rows.length === 0) {
                return res.status(404).json({ error: 'Control session not found, expired, or inactive for this workspace' });
            }

            const cmd = await pool.query(
                `SELECT id, file_id, mode
                   FROM zoe_viewer_commands
                  WHERE control_session_id = $1
                    AND workspace_id = $2
                    AND status = 'PENDING'
                  ORDER BY created_at ASC
                  LIMIT 1`,
                [controlSessionId, workspaceId]
            );
            if (cmd.rows.length === 0) {
                return res.json({ ok: true, command: null });
            }
            const row = cmd.rows[0];
            console.log('[ZOE] command served: ' + row.id);
            res.json({
                ok: true,
                command: { id: row.id, file_id: row.file_id, mode: row.mode }
            });
        } catch (err) {
            console.error('[ASSISTANT] viewer/next error:', err.message);
            res.status(500).json({ error: 'Failed to fetch next viewer command' });
        }
    });

    // ------------------------------------------------------------------
    // POST /api/assistant/viewer/consume
    // Marks a command CONSUMED. The UPDATE itself enforces all validation
    // (workspace + control session + command ownership + still PENDING) in
    // a single round trip; affected-row count tells us the outcome.
    // ------------------------------------------------------------------
    router.post('/consume', async (req, res) => {
        const body = req.body || {};
        const wsSlug = (body.ws || '').toString().trim();
        const controlSessionId = (body.control_session_id || '').toString().trim();
        const commandId = (body.command_id || '').toString().trim();
        if (!wsSlug)           return res.status(400).json({ error: 'ws is required' });
        if (!controlSessionId) return res.status(400).json({ error: 'control_session_id is required' });
        if (!commandId)        return res.status(400).json({ error: 'command_id is required' });

        try {
            if (!(await ensureTable(pool))) {
                return res.status(503).json({ error: 'Viewer command queue not ready (migration 064 pending)' });
            }

            const wsRow = await pool.query(
                `SELECT id FROM workspaces WHERE slug = $1 AND is_active = TRUE LIMIT 1`,
                [wsSlug]
            );
            if (wsRow.rows.length === 0) {
                return res.status(404).json({ error: 'Workspace not found' });
            }
            const workspaceId = wsRow.rows[0].id;

            const cs = await pool.query(
                `SELECT id FROM zoe_control_sessions
                  WHERE id = $1 AND workspace_id = $2
                    AND is_active = TRUE AND expires_at > NOW()
                  LIMIT 1`,
                [controlSessionId, workspaceId]
            );
            if (cs.rows.length === 0) {
                return res.status(404).json({ error: 'Control session not found, expired, or inactive for this workspace' });
            }

            const upd = await pool.query(
                `UPDATE zoe_viewer_commands
                    SET status = 'CONSUMED', consumed_at = NOW()
                  WHERE id = $1
                    AND control_session_id = $2
                    AND workspace_id = $3
                    AND status = 'PENDING'`,
                [commandId, controlSessionId, workspaceId]
            );
            if (upd.rowCount === 0) {
                return res.status(404).json({ error: 'Command not found, already consumed, or outside this session' });
            }
            console.log('[ZOE] command consumed: ' + commandId);
            res.json({ ok: true });
        } catch (err) {
            console.error('[ASSISTANT] viewer/consume error:', err.message);
            res.status(500).json({ error: 'Failed to consume viewer command' });
        }
    });

    // ------------------------------------------------------------------
    // GET /api/assistant/viewer/debug?ws=...
    // Last 10 commands for a workspace. No auth, workspace filter only.
    // Intended as a light observability aid; remove or gate later if needed.
    // ------------------------------------------------------------------
    router.get('/debug', async (req, res) => {
        const wsSlug = (req.query.ws || '').toString().trim();
        if (!wsSlug) return res.status(400).json({ error: 'ws is required' });

        try {
            if (!(await ensureTable(pool))) {
                return res.status(503).json({ error: 'Viewer command queue not ready (migration 064 pending)' });
            }
            const wsRow = await pool.query(
                `SELECT id FROM workspaces WHERE slug = $1 AND is_active = TRUE LIMIT 1`,
                [wsSlug]
            );
            if (wsRow.rows.length === 0) {
                return res.status(404).json({ error: 'Workspace not found' });
            }
            const r = await pool.query(
                `SELECT id, control_session_id, file_id, status, created_at, consumed_at
                   FROM zoe_viewer_commands
                  WHERE workspace_id = $1
                  ORDER BY created_at DESC
                  LIMIT 10`,
                [wsRow.rows[0].id]
            );
            res.json({ ok: true, commands: r.rows });
        } catch (err) {
            console.error('[ASSISTANT] viewer/debug error:', err.message);
            res.status(500).json({ error: 'Failed to load viewer debug' });
        }
    });

    return router;
};
