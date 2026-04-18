// Portal Assistant API — Zoe
// POST /api/assistant/sessions/register
//
// Registers one ephemeral browser session so Zoe can later open a file on
// that screen. v1: registration only. No websockets, no command queue, no
// polling — those are future phases.
//
// Persistence: zoe_control_sessions (migration 063). Default TTL 30 min.
// A UNIQUE(workspace_id, session_token) index lets a repeat registration
// refresh the existing row via ON CONFLICT instead of creating a duplicate.
//
// Additive: no auth layer, no schema changes beyond the new table.
// Exported as a factory so we reuse the existing pg Pool from server.js.

'use strict';

const express = require('express');

const DEFAULT_TTL_MINUTES = 30;
const ALLOWED_MODES = new Set(['viewer']);  // future: 'navigator', 'upload', …

// Cached existence check (same pattern as checkRdTables / checkStudioTables
// in server.js). Routes fail closed with 503 if the migration is not applied.
let _tableReady = null;
async function ensureTable(pool) {
    if (_tableReady !== null) return _tableReady;
    try {
        const r = await pool.query(`SELECT to_regclass('public.zoe_control_sessions') AS t`);
        _tableReady = r.rows[0].t !== null;
    } catch {
        _tableReady = false;
    }
    return _tableReady;
}

module.exports = function assistantSessionsRouter(pool) {
    const router = express.Router();

    router.post('/register', async (req, res) => {
        const body = req.body || {};
        const wsSlug = (body.ws || '').toString().trim();
        const sessionToken = (body.session_token || '').toString().trim();
        let mode = (body.mode || 'viewer').toString().trim().toLowerCase();

        if (!wsSlug)       return res.status(400).json({ error: 'ws is required' });
        if (!sessionToken) return res.status(400).json({ error: 'session_token is required' });
        if (!ALLOWED_MODES.has(mode)) mode = 'viewer';

        try {
            if (!(await ensureTable(pool))) {
                return res.status(503).json({ error: 'Control sessions table not ready (migration 063 pending)' });
            }

            // Resolve workspace slug -> id.
            const wsRow = await pool.query(
                `SELECT id FROM workspaces WHERE slug = $1 AND is_active = TRUE LIMIT 1`,
                [wsSlug]
            );
            if (wsRow.rows.length === 0) {
                return res.status(404).json({ error: 'Workspace not found' });
            }
            const workspaceId = wsRow.rows[0].id;

            // Upsert: refresh if (workspace_id, session_token) already exists.
            const upsert = await pool.query(
                `INSERT INTO zoe_control_sessions
                     (workspace_id, session_token, mode, expires_at, is_active)
                 VALUES
                     ($1, $2, $3, NOW() + ($4 || ' minutes')::interval, TRUE)
                 ON CONFLICT (workspace_id, session_token) DO UPDATE SET
                     mode       = EXCLUDED.mode,
                     expires_at = EXCLUDED.expires_at,
                     is_active  = TRUE
                 RETURNING id, expires_at`,
                [workspaceId, sessionToken, mode, String(DEFAULT_TTL_MINUTES)]
            );

            const row = upsert.rows[0];
            res.json({
                ok: true,
                control_session_id: row.id,
                expires_at: row.expires_at.toISOString()
            });
        } catch (err) {
            console.error('[ASSISTANT] sessions/register error:', err.message);
            res.status(500).json({ error: 'Failed to register control session' });
        }
    });

    return router;
};
