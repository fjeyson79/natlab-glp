// routes/assistant/reports.js
//
// Read-only endpoints over assistant_report_intelligence (migration 068).
// The intelligence rows are written by services/reportIntelligence.js when
// a REPORT is uploaded through /api/di/upload-report; this router exposes
// them to Zoe and the portal.
//
//   GET /api/assistant/reports/intelligence/:submission_id?ws=natlab
//   GET /api/assistant/reports/researcher/:code?ws=natlab
//
// Both routes 503 cleanly when migration 068 is still pending — no 500s
// just because a deploy hasn't picked up the table yet.

'use strict';

const express = require('express');

module.exports = function assistantReportsRouter(pool) {
    const router = express.Router();

    // Cached existence check for assistant_report_intelligence (mig 068).
    let _tableReady = null;
    let _tableChecked = 0;
    const TTL_MS = 60_000;
    async function ensureTable() {
        const now = Date.now();
        if (_tableReady === true && (now - _tableChecked) < TTL_MS) return true;
        try {
            const r = await pool.query(`SELECT to_regclass('public.assistant_report_intelligence') AS t`);
            _tableReady = (r.rows[0].t !== null);
        } catch { _tableReady = false; }
        _tableChecked = now;
        return _tableReady;
    }

    // Shared row -> JSON shape so /intelligence/:id and /researcher/:code
    // return uniform structures. Joins to di_submissions surface the
    // canonical filename / status / r2_object_key alongside the
    // intelligence fields.
    function shapeRow(row) {
        return {
            id:                         row.id,
            submission_id:              row.submission_id,
            workspace_id:               row.workspace_id || null,
            researcher_id:              row.researcher_id || null,
            researcher_name:            row.researcher_name || null,
            affiliation:                row.affiliation || null,
            // submission metadata (joined from di_submissions)
            filename:                   row.original_filename || null,
            file_type:                  row.di_file_type || null,
            di_status:                  row.di_status || null,
            r2_object_key:              row.r2_object_key || null,
            created_at:                 row.submission_created_at ? new Date(row.submission_created_at).toISOString() : null,
            // intelligence fields
            report_subcategory:         row.report_subcategory || null,
            report_status:              row.report_status || null,
            project:                    row.project || null,
            reporting_period_start:     row.reporting_period_start ? new Date(row.reporting_period_start).toISOString().slice(0,10) : null,
            reporting_period_end:       row.reporting_period_end   ? new Date(row.reporting_period_end).toISOString().slice(0,10)   : null,
            supervisor:                 row.supervisor || null,
            title:                      row.title || null,
            short_summary:              row.short_summary || null,
            key_conclusions:            row.key_conclusions || [],
            limitations:                row.limitations || [],
            future_work:                row.future_work || [],
            related_methods:            row.related_methods || [],
            related_assays:             row.related_assays || [],
            related_sops:               row.related_sops || [],
            related_data_files:         row.related_data_files || [],
            detected_project_themes:    row.detected_project_themes || [],
            detected_keywords:          row.detected_keywords || [],
            scientific_maturity_signal: row.scientific_maturity_signal || null,
            glp_relevance_signal:       row.glp_relevance_signal || null,
            source_text_chars:          row.source_text_chars == null ? null : Number(row.source_text_chars),
            extraction_status:          row.extraction_status || null,
            extraction_error:           row.extraction_error || null,
            intelligence_created_at:    row.intel_created_at ? new Date(row.intel_created_at).toISOString() : null,
            intelligence_updated_at:    row.intel_updated_at ? new Date(row.intel_updated_at).toISOString() : null
        };
    }

    // GET /api/assistant/reports/intelligence/:submission_id?ws=natlab
    router.get('/intelligence/:submission_id', async (req, res) => {
        if (!(await ensureTable())) {
            return res.status(503).json({ error: 'assistant_report_intelligence not ready (migration 068 pending)' });
        }
        const submissionId = String(req.params.submission_id || '').trim();
        const wsSlug = (req.query.ws || '').toString().trim();
        if (!submissionId) return res.status(400).json({ error: 'submission_id is required' });
        if (!/^[0-9a-fA-F-]{36}$/.test(submissionId)) {
            return res.status(404).json({ error: 'Intelligence row not found' });
        }

        try {
            // Workspace scope is enforced via the di_submissions join: an
            // intelligence row matches only when its submission lives in the
            // requested workspace. Avoids a separate workspace lookup query.
            const r = await pool.query(
                `SELECT ari.*,
                        ari.created_at AS intel_created_at,
                        ari.updated_at AS intel_updated_at,
                        s.original_filename,
                        s.file_type AS di_file_type,
                        s.status    AS di_status,
                        s.r2_object_key,
                        s.created_at AS submission_created_at,
                        s.affiliation,
                        a.name AS researcher_name
                   FROM assistant_report_intelligence ari
                   JOIN di_submissions s ON s.submission_id = ari.submission_id
                   LEFT JOIN di_allowlist a ON a.researcher_id = s.researcher_id
                   LEFT JOIN workspaces w ON w.id = s.workspace_id
                  WHERE ari.submission_id = $1
                    AND ($2::text IS NULL OR w.slug = $2)
                  LIMIT 1`,
                [submissionId, wsSlug || null]
            );
            if (r.rows.length === 0) {
                return res.status(404).json({ error: 'Intelligence row not found' });
            }
            res.json(shapeRow(r.rows[0]));
        } catch (err) {
            console.error('[ASSISTANT] reports/intelligence error:', err && err.message);
            res.status(500).json({ error: 'Failed to load report intelligence' });
        }
    });

    // GET /api/assistant/reports/researcher/:code?ws=natlab
    //
    // Lists every intelligence row owned by one researcher. Sort newest-first
    // by intelligence updated_at (so a re-uploaded REPORT bubbles up). Always
    // 200 — empty array for "researcher exists but has no REPORTs yet".
    router.get('/researcher/:code', async (req, res) => {
        if (!(await ensureTable())) {
            return res.status(503).json({ error: 'assistant_report_intelligence not ready (migration 068 pending)' });
        }
        const code = String(req.params.code || '').trim().toUpperCase();
        const wsSlug = (req.query.ws || '').toString().trim();
        if (!code) return res.status(400).json({ error: 'researcher code is required' });

        try {
            const r = await pool.query(
                `SELECT ari.*,
                        ari.created_at AS intel_created_at,
                        ari.updated_at AS intel_updated_at,
                        s.original_filename,
                        s.file_type AS di_file_type,
                        s.status    AS di_status,
                        s.r2_object_key,
                        s.created_at AS submission_created_at,
                        s.affiliation,
                        a.name AS researcher_name
                   FROM assistant_report_intelligence ari
                   JOIN di_submissions s ON s.submission_id = ari.submission_id
                   LEFT JOIN di_allowlist a ON a.researcher_id = s.researcher_id
                   LEFT JOIN workspaces w ON w.id = s.workspace_id
                  WHERE ari.researcher_id = $1
                    AND ($2::text IS NULL OR w.slug = $2)
                    AND s.status <> 'DISCARDED'
                  ORDER BY ari.updated_at DESC NULLS LAST`,
                [code, wsSlug || null]
            );
            const rows = r.rows.map(shapeRow);
            res.json({
                researcher_id: code,
                workspace:     wsSlug || null,
                total:         rows.length,
                reports:       rows
            });
        } catch (err) {
            console.error('[ASSISTANT] reports/researcher error:', err && err.message);
            res.status(500).json({ error: 'Failed to load researcher reports' });
        }
    });

    return router;
};
