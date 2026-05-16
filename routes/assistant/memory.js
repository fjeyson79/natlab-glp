// routes/assistant/memory.js
//
// Zoe memory read/admin endpoints. Mounted at /api/assistant/memory.
//
//   GET  /workspace?ws=natlab               — workspace-level memory
//   GET  /researcher/:code?ws=natlab        — one researcher
//   GET  /project/:project?ws=natlab        — one project (URL-encoded)
//   GET  /file/:id?ws=natlab                — one file
//   GET  /status?ws=natlab                  — row counts + recent jobs
//   POST /weekly-update?ws=natlab           — kick incremental update
//   POST /rebuild?ws=natlab                 — full rebuild (admin only)
//
// All routes 503 cleanly until the memory tables exist (migration 071
// or the runtime ensureSchema fallback).

'use strict';

const express = require('express');

module.exports = function assistantMemoryRouter(pool, deps) {
    const router = express.Router();
    const requirePI = (deps && deps.requirePI) || ((req, res, next) => next());
    const zoeMemory = (deps && deps.zoeMemory) || require('../../services/zoeMemory');

    let _schemaPromise = null;
    function ensureSchemaOnce() {
        if (!_schemaPromise) _schemaPromise = zoeMemory.ensureSchema(pool);
        return _schemaPromise;
    }
    // Kick the schema-ensure at mount so the first request doesn't pay it.
    ensureSchemaOnce().catch(() => {});

    function wsParam(req) {
        return (req.query.ws || '').toString().trim() || 'natlab';
    }

    // ---------------------------------------------------------------
    // GET /workspace
    router.get('/workspace', async (req, res) => {
        try {
            await ensureSchemaOnce();
            const ws = wsParam(req);
            const r = await pool.query(
                `SELECT * FROM assistant_workspace_memory WHERE workspace_slug = $1 LIMIT 1`,
                [ws]);
            if (r.rows.length === 0) {
                return res.json({ workspace_slug: ws, memory: null, hint: 'No workspace memory yet — call POST /api/assistant/memory/rebuild' });
            }
            res.json(shapeMemoryRow(r.rows[0]));
        } catch (err) {
            console.error('[ZOE-MEMORY] GET /workspace error:', err && err.message);
            res.status(500).json({ error: 'Failed to read workspace memory' });
        }
    });

    // GET /researcher/:code
    router.get('/researcher/:code', async (req, res) => {
        try {
            await ensureSchemaOnce();
            const ws = wsParam(req);
            const code = String(req.params.code || '').trim().toUpperCase();
            const r = await pool.query(
                `SELECT * FROM assistant_researcher_memory
                  WHERE workspace_slug = $1 AND researcher_code = $2 LIMIT 1`,
                [ws, code]);
            if (r.rows.length === 0) {
                return res.json({ workspace_slug: ws, researcher_code: code, memory: null });
            }
            res.json(shapeMemoryRow(r.rows[0]));
        } catch (err) {
            console.error('[ZOE-MEMORY] GET /researcher error:', err && err.message);
            res.status(500).json({ error: 'Failed to read researcher memory' });
        }
    });

    // GET /project/:project — project name in URL path, URL-encoded.
    router.get('/project/:project', async (req, res) => {
        try {
            await ensureSchemaOnce();
            const ws = wsParam(req);
            const name = String(req.params.project || '').trim();
            const r = await pool.query(
                `SELECT * FROM assistant_project_memory
                  WHERE workspace_slug = $1 AND project_name = $2 LIMIT 1`,
                [ws, name]);
            if (r.rows.length === 0) {
                return res.json({ workspace_slug: ws, project_name: name, memory: null });
            }
            res.json(shapeMemoryRow(r.rows[0]));
        } catch (err) {
            console.error('[ZOE-MEMORY] GET /project error:', err && err.message);
            res.status(500).json({ error: 'Failed to read project memory' });
        }
    });

    // GET /file/:id — file_id is a UUID from assistant_file_index.
    router.get('/file/:id', async (req, res) => {
        try {
            await ensureSchemaOnce();
            const id = String(req.params.id || '').trim();
            if (!/^[0-9a-fA-F-]{36}$/.test(id)) {
                return res.status(404).json({ error: 'File memory not found' });
            }
            const r = await pool.query(
                `SELECT * FROM assistant_file_memory WHERE file_id = $1 LIMIT 1`,
                [id]);
            if (r.rows.length === 0) {
                return res.json({ file_id: id, memory: null });
            }
            res.json(shapeMemoryRow(r.rows[0]));
        } catch (err) {
            console.error('[ZOE-MEMORY] GET /file error:', err && err.message);
            res.status(500).json({ error: 'Failed to read file memory' });
        }
    });

    // GET /status — counts + recent jobs.
    router.get('/status', async (req, res) => {
        try {
            await ensureSchemaOnce();
            const status = await zoeMemory.getStatus({ pool }, wsParam(req));
            res.json(status);
        } catch (err) {
            console.error('[ZOE-MEMORY] GET /status error:', err && err.message);
            res.status(500).json({ error: 'Failed to read status' });
        }
    });

    // POST /weekly-update — admin/cron-callable. Incremental.
    // Locked to requirePI; callable from n8n via a service-PI session
    // or from the dashboard. Limited to `limit` files per call so we
    // don't melt the box on first run.
    router.post('/weekly-update', requirePI, async (req, res) => {
        try {
            await ensureSchemaOnce();
            const ws = wsParam(req);
            const limit = parseInt((req.body && req.body.limit) || req.query.limit, 10) || 200;
            const out = await zoeMemory.runWeeklyUpdate({ pool }, ws, { limit });
            res.json(out);
        } catch (err) {
            console.error('[ZOE-MEMORY] POST /weekly-update error:', err && err.message);
            res.status(500).json({ error: 'Failed to run weekly update' });
        }
    });

    // POST /rebuild — full rebuild. requirePI only.
    router.post('/rebuild', requirePI, async (req, res) => {
        try {
            await ensureSchemaOnce();
            const ws = wsParam(req);
            const limit = parseInt((req.body && req.body.limit) || req.query.limit, 10) || 500;
            const out = await zoeMemory.rebuildAll({ pool }, ws, { limit });
            res.json(out);
        } catch (err) {
            console.error('[ZOE-MEMORY] POST /rebuild error:', err && err.message);
            res.status(500).json({ error: 'Failed to rebuild memory' });
        }
    });

    return router;
};

function shapeMemoryRow(row) {
    return {
        id:                 row.id,
        workspace_slug:     row.workspace_slug || null,
        file_id:            row.file_id || null,
        researcher_code:    row.researcher_code || null,
        project_name:       row.project_name || null,
        memory_json:        row.memory_json || {},
        summary_text:       row.summary_text || null,
        evidence_file_ids:  row.evidence_file_ids || [],
        confidence:         row.confidence == null ? null : Number(row.confidence),
        source_updated_at:  row.source_updated_at ? new Date(row.source_updated_at).toISOString() : null,
        memory_updated_at:  row.memory_updated_at ? new Date(row.memory_updated_at).toISOString() : null,
        created_at:         row.created_at ? new Date(row.created_at).toISOString() : null
    };
}
