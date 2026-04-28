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

// Soft cap on extracted PDF text returned by /:submission_id/text. Picked to
// keep responses well under typical upstream LLM payload limits while still
// giving Zoe enough material for ALCOA / SOP-anatomy review on long files.
const DEFAULT_TEXT_MAX = 30000;

// `deps` (originally named `r2`, kept that way for backward compat with the
// /text route added earlier) carries the server.js-scoped helpers this router
// can't reach on its own. Phase 1 additions: requirePI middleware, r2Client +
// r2Bucket for the reindex route, and the indexer module. Each is optional;
// routes that need a missing dep fail closed with 503.
module.exports = function assistantFilesRouter(pool, deps) {
    const router = express.Router();
    const r2 = deps || {};
    const fetchR2ObjectAsBuffer = r2.fetchR2ObjectAsBuffer;
    const normalizeR2Key        = r2.normalizeR2Key;
    // Phase 1 additions:
    const r2Client              = r2.r2Client;
    const r2Bucket               = r2.r2Bucket;
    const requirePI             = r2.requirePI || ((req, res, next) => next()); // soft no-op if absent
    const indexer               = r2.indexer;

    // Cached existence check for the assistant_file_index / assistant_file_text
    // tables (migration 065). Same pattern as checkRoleColumn / checkOligo* in
    // server.js — cheap, refreshed periodically. Endpoints that depend on the
    // index fail fast with 503 when the migration hasn't been applied yet
    // instead of throwing a confusing relation-not-found error.
    let _idxTablesReady = null;
    let _idxTablesChecked = 0;
    const IDX_TABLE_TTL_MS = 60 * 1000;
    async function ensureIndexTables() {
        const now = Date.now();
        if (_idxTablesReady === true && (now - _idxTablesChecked) < IDX_TABLE_TTL_MS) return true;
        try {
            const r = await pool.query(`
                SELECT
                    to_regclass('public.assistant_file_index') AS i,
                    to_regclass('public.assistant_file_text')  AS t
            `);
            _idxTablesReady = (r.rows[0].i !== null && r.rows[0].t !== null);
        } catch {
            _idxTablesReady = false;
        }
        _idxTablesChecked = now;
        return _idxTablesReady;
    }

    router.get('/search', async (req, res) => {
        const wsSlug = (req.query.ws || '').toString().trim();
        const q = (req.query.q || '').toString().trim();

        // Phase 1 search extension. Routing contract:
        //   LEGACY (di_submissions, returns best_match + alternatives):
        //     fires only when ws + q are the ONLY meaningful query params.
        //     This is what the original search_files Zoe tool sends.
        //   INDEXED (assistant_file_index + assistant_file_text):
        //     fires when ANY of these are present in the request:
        //       search_scope, researcher, affiliation, year, file_type,
        //       status, workspace, indexed
        //     `ws` is mapped to `workspace` inside the indexed handler, so
        //     callers may send either or both.
        // Be liberal about "present": treat a non-empty value or even a bare
        // `?indexed` (empty string) as enough to opt in. We check for the
        // KEY's presence on req.query rather than just its value, so the new
        // flow triggers reliably even with empty values.
        const NEW_PARAM_KEYS = [
            'search_scope',
            'researcher',
            'affiliation',
            'year',
            'file_type',
            'status',
            'workspace',
            'indexed',
        ];
        const hasNewParams = NEW_PARAM_KEYS.some(k => Object.prototype.hasOwnProperty.call(req.query, k));
        if (hasNewParams) {
            return handleIndexedSearch(req, res);
        }

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

    // ---------------------------------------------------------------------
    // Phase 1 — Zoe file map / advanced search / researcher view / detail.
    // All routes are read-only and rely on assistant_file_index +
    // assistant_file_text (migration 065). They fail fast with 503 when the
    // tables aren't there, so deployments missing the migration get a clean
    // signal rather than a 500.
    //
    // Defined before /:submission_id/text and /:id so the parameterised
    // routes don't shadow them. (`/map`, `/reindex`, `/researcher/...`,
    // `/indexed/...` are all non-UUID and would already fail the UUID guard
    // on /:id, but explicit ordering is friendlier to future maintainers.)
    // ---------------------------------------------------------------------

    // -- helpers shared by the new routes ----------------------------------
    function parseFiltersFromQuery(q) {
        const trim = (v) => (v == null ? null : String(v).trim() || null);
        const upper = (v) => { const t = trim(v); return t ? t.toUpperCase() : null; };
        const yr = parseInt(q.year, 10);
        return {
            workspace_slug:  trim(q.workspace) || trim(q.ws),
            affiliation:     trim(q.affiliation),
            researcher_code: q.researcher ? String(q.researcher).trim().toUpperCase() : null,
            year:            Number.isFinite(yr) && yr >= 1990 && yr <= 2100 ? yr : null,
            file_type:       upper(q.file_type),
            status:          upper(q.status),
        };
    }

    // GET /api/assistant/files/map
    //
    // Grouped counts + representative filenames. Workspace and affiliation
    // filters supported; everything else is left wide so callers see the
    // whole shape on first call.
    router.get('/map', async (req, res) => {
        if (!(await ensureIndexTables())) {
            return res.status(503).json({ error: 'assistant_file_index not ready (migration 065 pending)' });
        }
        const filters = parseFiltersFromQuery(req.query || {});

        // Build a single base WHERE so the four aggregates stay consistent.
        const where = [];
        const params = [];
        const push = (v) => { params.push(v); return '$' + params.length; };
        if (filters.workspace_slug)  where.push(`workspace_slug  = ${push(filters.workspace_slug)}`);
        if (filters.affiliation)     where.push(`affiliation     = ${push(filters.affiliation)}`);
        if (filters.researcher_code) where.push(`researcher_code = ${push(filters.researcher_code)}`);
        if (filters.year !== null)   where.push(`year            = ${push(filters.year)}`);
        if (filters.file_type)       where.push(`file_type       = ${push(filters.file_type)}`);
        if (filters.status)          where.push(`status          = ${push(filters.status)}`);
        const whereSql = where.length ? `WHERE ${where.join(' AND ')}` : '';

        try {
            // Total count + per-axis grouped counts. We materialise rep filenames
            // via a window function over each group so the result is one query
            // per axis rather than N+1 lookups.
            const groupQ = (col) => `
                SELECT ${col} AS key, COUNT(*)::int AS count,
                       (ARRAY_AGG(filename ORDER BY indexed_at DESC NULLS LAST))[1:3] AS samples
                  FROM assistant_file_index
                  ${whereSql}
                 GROUP BY ${col}
                 ORDER BY count DESC, key ASC NULLS LAST
            `;
            const [total, byWs, byAff, byRes, byYear, byType] = await Promise.all([
                pool.query(`SELECT COUNT(*)::int AS n FROM assistant_file_index ${whereSql}`, params),
                pool.query(groupQ('workspace_slug'),  params),
                pool.query(groupQ('affiliation'),     params),
                pool.query(groupQ('researcher_code'), params),
                pool.query(groupQ('year'),            params),
                pool.query(groupQ('file_type'),       params),
            ]);

            const fmt = (rows) => rows.map(r => ({
                key:      r.key,
                count:    r.count,
                samples:  Array.isArray(r.samples) ? r.samples.filter(Boolean) : []
            }));

            res.json({
                filters,
                total_files: total.rows[0].n,
                by_workspace:  fmt(byWs.rows),
                by_affiliation: fmt(byAff.rows),
                by_researcher: fmt(byRes.rows),
                by_year:       fmt(byYear.rows),
                by_file_type:  fmt(byType.rows),
                generated_at:  new Date().toISOString()
            });
        } catch (err) {
            console.error('[ASSISTANT] files/map error:', err.message);
            res.status(500).json({ error: 'Failed to build file map' });
        }
    });

    // POST /api/assistant/files/reindex
    //
    // Kicks the indexer in the background and returns immediately. Subsequent
    // calls while a run is active return 409 with the live job status. Body
    // (JSON, all optional):
    //   { "metadata_only": bool, "text_only": bool, "concurrency": int, "limit": int }
    //
    // Auth: requirePI — same model as the DI backup-download endpoints. PI
    // session is the only role allowed to trigger an R2 scan from the API.
    router.post('/reindex', requirePI, async (req, res) => {
        if (!indexer || typeof indexer.runJob !== 'function') {
            return res.status(503).json({ error: 'Indexer module not wired into assistant files router' });
        }
        if (!r2Client || !r2Bucket) {
            return res.status(503).json({ error: 'R2 client not available' });
        }
        if (!(await ensureIndexTables())) {
            return res.status(503).json({ error: 'assistant_file_index not ready (migration 065 pending)' });
        }
        const current = indexer.getJobStatus();
        if (current.state === 'running') {
            return res.status(409).json({ error: 'Indexer already running', job: current });
        }
        const body = req.body || {};
        const opts = {
            metadataOnly: !!body.metadata_only,
            textOnly:     !!body.text_only,
            concurrency:  Number.isFinite(parseInt(body.concurrency, 10)) ? parseInt(body.concurrency, 10) : 4,
            limit:        Number.isFinite(parseInt(body.limit, 10))       ? parseInt(body.limit, 10)       : 0
        };
        // Run in the background. Errors flow into job.state = 'failed' so
        // the operator can poll /reindex/status — we don't need to await.
        indexer.runJob({ pool, r2Client, r2Bucket, log: console }, opts).catch((e) => {
            console.error('[ASSISTANT] reindex job threw:', e && e.message || e);
        });
        res.status(202).json({
            ok: true,
            message: 'Reindex started',
            job: indexer.getJobStatus(),
            poll: '/api/assistant/files/reindex/status'
        });
    });

    // GET /api/assistant/files/reindex/status
    // Read-only probe of the in-process job state. Useful while a long
    // first-run is in flight.
    router.get('/reindex/status', async (req, res) => {
        if (!indexer || typeof indexer.getJobStatus !== 'function') {
            return res.status(503).json({ error: 'Indexer module not wired into assistant files router' });
        }
        res.json({ job: indexer.getJobStatus() });
    });

    // GET /api/assistant/files/researcher/:code
    //
    // All indexed files for one researcher_code, grouped by year + file_type.
    // The path param is the di_allowlist short code (e.g. 'MC', 'HJM') —
    // case-insensitive on the way in, normalised to upper.
    router.get('/researcher/:code', async (req, res) => {
        if (!(await ensureIndexTables())) {
            return res.status(503).json({ error: 'assistant_file_index not ready (migration 065 pending)' });
        }
        const code = String(req.params.code || '').trim().toUpperCase();
        if (!code) return res.status(400).json({ error: 'researcher code is required' });

        try {
            // LATERAL join exposes rd_documents.id (when the file is also in
            // the R&D path), so callers can hand it to open_file_in_portal.
            const r = await pool.query(
                `SELECT i.id, i.r2_key, i.filename, i.file_ext, i.file_type, i.workspace_slug,
                        i.researcher_code, i.researcher_name, i.affiliation,
                        i.year, i.date_detected, i.status, i.source_area, i.topic,
                        i.text_status, i.text_preview, i.text_char_count,
                        i.indexed_at,
                        d.id AS portal_file_id
                   FROM assistant_file_index i
                   LEFT JOIN LATERAL (
                       SELECT id
                         FROM rd_documents
                        WHERE r2_key = i.r2_key
                        ORDER BY created_at DESC
                        LIMIT 1
                   ) d ON TRUE
                  WHERE i.researcher_code = $1
                  ORDER BY i.year DESC NULLS LAST, i.indexed_at DESC`,
                [code]
            );
            // Zero hits is a valid answer (researcher exists but no files yet),
            // so we still return 200 with an empty listing rather than 404.
            const rows = r.rows;
            // Group: year → file_type → [files]
            const byYearType = {};
            for (const row of rows) {
                const y = row.year == null ? 'unknown' : String(row.year);
                const t = row.file_type || 'UNTYPED';
                byYearType[y] = byYearType[y] || {};
                byYearType[y][t] = byYearType[y][t] || [];
                byYearType[y][t].push({
                    id:                 row.id,
                    filename:           row.filename,
                    r2_key:             row.r2_key,
                    workspace_slug:     row.workspace_slug,
                    affiliation:        row.affiliation,
                    status:             row.status,
                    text_status:        row.text_status,
                    portal_file_id:     row.portal_file_id || null,
                    can_open_in_portal: !!row.portal_file_id,
                    indexed_at:         row.indexed_at ? new Date(row.indexed_at).toISOString() : null
                });
            }
            res.json({
                researcher_code: code,
                researcher_name: rows[0] ? rows[0].researcher_name : null,
                affiliation:     rows[0] ? rows[0].affiliation : null,
                total: rows.length,
                grouped: byYearType
            });
        } catch (err) {
            console.error('[ASSISTANT] files/researcher error:', err.message);
            res.status(500).json({ error: 'Failed to load researcher files' });
        }
    });

    // GET /api/assistant/files/indexed/:id/text?max_chars=12000
    //
    // Phase 1.2 — read the extracted text Zoe already has on file. Returns
    // the full assistant_file_index metadata plus the extracted text from
    // assistant_file_text, truncated to `max_chars` (default 12000, hard
    // cap 200000 so a paranoid caller can't OOM us).
    //
    // Designed to fail soft on every "no usable text" path:
    //   text_status='pending'     → has_full_text=false, full_text=null
    //   text_status='failed'      → has_full_text=false, full_text=null
    //   text_status='empty'       → has_full_text=false, full_text=null
    //   text_status='unsupported' → has_full_text=false, full_text=null
    //   no assistant_file_text row → has_full_text=false, full_text=null
    // The text_status field tells the caller WHY there's no text; we don't
    // 4xx — the file genuinely exists in the index, just hasn't been (or
    // can't be) extracted yet.
    //
    // Defined BEFORE /indexed/:id so the more-specific 3-segment route is
    // registered first. (Express segment-counts the routes anyway, so the
    // 2-segment /indexed/:id can't shadow this; the ordering is for human
    // readers.)
    router.get('/indexed/:id/text', async (req, res) => {
        if (!(await ensureIndexTables())) {
            return res.status(503).json({ error: 'assistant_file_index not ready (migration 065 pending)' });
        }
        const id = String(req.params.id || '').trim();
        if (!/^[0-9a-fA-F-]{36}$/.test(id)) {
            return res.status(404).json({ error: 'Indexed file not found' });
        }
        let maxChars = parseInt(req.query.max_chars, 10);
        if (!Number.isFinite(maxChars) || maxChars < 1) maxChars = 12000;
        if (maxChars > 200000) maxChars = 200000;

        try {
            const r = await pool.query(
                `SELECT i.id, i.r2_key, i.filename, i.workspace_slug,
                        i.researcher_code, i.researcher_name, i.affiliation,
                        i.file_type, i.year, i.status,
                        i.text_status, i.text_preview, i.text_char_count,
                        t.full_text
                   FROM assistant_file_index i
                   LEFT JOIN assistant_file_text t ON t.file_id = i.id
                  WHERE i.id = $1
                  LIMIT 1`,
                [id]
            );
            if (r.rows.length === 0) {
                return res.status(404).json({ error: 'Indexed file not found' });
            }
            const row = r.rows[0];
            const stored = row.full_text || null;
            const hasFullText = !!(stored && stored.length > 0);
            const truncated = hasFullText && stored.length > maxChars;
            const fullText = hasFullText
                ? (truncated ? stored.slice(0, maxChars) : stored)
                : null;

            res.json({
                id:               row.id,
                filename:         row.filename,
                r2_key:           row.r2_key,
                workspace_slug:   row.workspace_slug,
                researcher_code:  row.researcher_code,
                researcher_name:  row.researcher_name,
                affiliation:      row.affiliation,
                file_type:        row.file_type,
                year:             row.year,
                status:           row.status,
                text_status:      row.text_status,
                text_char_count:  row.text_char_count,
                text_preview:     row.text_preview,
                has_full_text:    hasFullText,
                full_text:        fullText,
                truncated:        truncated,
                max_chars:        maxChars
            });
        } catch (err) {
            console.error('[ASSISTANT] files/indexed/:id/text error:', err.message);
            res.status(500).json({ error: 'Failed to load indexed file text' });
        }
    });

    // GET /api/assistant/files/indexed/:id
    //
    // Full metadata for one assistant_file_index row. Separate path from the
    // existing /:id (which serves rd_documents.id-shaped detail) so neither
    // contract clobbers the other.
    router.get('/indexed/:id', async (req, res) => {
        if (!(await ensureIndexTables())) {
            return res.status(503).json({ error: 'assistant_file_index not ready (migration 065 pending)' });
        }
        const id = String(req.params.id || '').trim();
        if (!/^[0-9a-fA-F-]{36}$/.test(id)) {
            return res.status(404).json({ error: 'Indexed file not found' });
        }
        try {
            // LATERAL join surfaces rd_documents.id when the file is also
            // ingested via the R&D path. Same shape used by /search and
            // /researcher so callers see consistent fields everywhere.
            const r = await pool.query(
                `SELECT i.*,
                        (t.full_text IS NOT NULL) AS has_full_text,
                        d.id AS portal_file_id
                   FROM assistant_file_index i
                   LEFT JOIN assistant_file_text t ON t.file_id = i.id
                   LEFT JOIN LATERAL (
                       SELECT id
                         FROM rd_documents
                        WHERE r2_key = i.r2_key
                        ORDER BY created_at DESC
                        LIMIT 1
                   ) d ON TRUE
                  WHERE i.id = $1
                  LIMIT 1`,
                [id]
            );
            if (r.rows.length === 0) {
                return res.status(404).json({ error: 'Indexed file not found' });
            }
            const row = r.rows[0];
            res.json({
                id:                 row.id,
                r2_key:             row.r2_key,
                filename:           row.filename,
                file_ext:           row.file_ext,
                file_type:          row.file_type,
                workspace_slug:     row.workspace_slug,
                researcher_code:    row.researcher_code,
                researcher_name:    row.researcher_name,
                affiliation:        row.affiliation,
                year:               row.year,
                date_detected:      row.date_detected,
                status:             row.status,
                source_area:        row.source_area,
                topic:              row.topic,
                tags:               row.tags || [],
                mime_type:          row.mime_type,
                size_bytes:         row.size_bytes,
                text_status:        row.text_status,
                text_preview:       row.text_preview,
                text_char_count:    row.text_char_count,
                text_extracted_at:  row.text_extracted_at ? new Date(row.text_extracted_at).toISOString() : null,
                has_full_text:      !!row.has_full_text,
                portal_file_id:     row.portal_file_id || null,
                can_open_in_portal: !!row.portal_file_id,
                created_at:         row.created_at ? new Date(row.created_at).toISOString() : null,
                updated_at:         row.updated_at ? new Date(row.updated_at).toISOString() : null,
                indexed_at:         row.indexed_at ? new Date(row.indexed_at).toISOString() : null
            });
        } catch (err) {
            console.error('[ASSISTANT] files/indexed/:id error:', err.message);
            res.status(500).json({ error: 'Failed to load indexed file' });
        }
    });

    // ---------------------------------------------------------------------
    // The new search flow used when /search is called with new-mode params.
    // Lives below the route definitions so /search can hand off to it. The
    // ranking is deterministic and reads:
    //   +12  exact researcher_code match
    //   +10  exact filename match (case-insensitive)
    //   + 8  exact file_type match
    //   + 6  exact year match
    //   + 5  filename ILIKE %q%
    //   + 4  topic ILIKE %q% OR text_preview ILIKE %q%
    //   + 3  full_text ILIKE %q%      (only when scope ∈ {content, all})
    //   + 2  filename ILIKE % q's first token %  (cheap phrase prefix)
    //   + 1  indexed within last 14 days
    // Plus a strong-phrase bonus when the literal q appears in filename or
    // full_text — separately, so callers can see it in match_reasons.
    // ---------------------------------------------------------------------
    async function handleIndexedSearch(req, res) {
        if (!(await ensureIndexTables())) {
            return res.status(503).json({ error: 'assistant_file_index not ready (migration 065 pending)' });
        }
        const filters = parseFiltersFromQuery(req.query || {});
        const q = (req.query.q || '').toString().trim();
        let scope = (req.query.search_scope || 'all').toString().trim().toLowerCase();
        if (!['metadata', 'content', 'all'].includes(scope)) scope = 'all';

        let limit = parseInt(req.query.limit, 10);
        if (!Number.isFinite(limit) || limit < 1) limit = 10;
        if (limit > 50) limit = 50;

        // Allow filter-only listing (no q). If neither q nor any filter is
        // present, refuse — otherwise we'd dump the whole index.
        const anyFilter = Object.values(filters).some(v => v !== null);
        if (!q && !anyFilter) {
            return res.status(400).json({
                error: 'At least one of q, workspace, affiliation, researcher, year, file_type, or status is required'
            });
        }

        const params = [];
        const push = (v) => { params.push(v); return '$' + params.length; };

        // q-derived placeholders. Only push when the corresponding clause
        // will actually reference the placeholder — Postgres validates the
        // Bind parameter count against the SQL's max $N reference and 500s
        // the request when they disagree.
        //
        // Specifically: pQFirst is ONLY referenced inside the optional
        // first-token boost score clause, which runs only for multi-token
        // queries (`qFirst !== q`). For single-token queries the boost
        // would be redundant with the full-q ILIKE match anyway, so we skip
        // the push entirely. Earlier versions pushed it unconditionally,
        // which produced an unreferenced $3 and a "bind message supplies N
        // parameters, but prepared statement requires M" error on every
        // single-token search (e.g. an exact-filename lookup with no spaces).
        const qWrap   = q ? '%' + q + '%' : null;
        const qLower  = q ? q.toLowerCase() : null;
        const qFirst  = q ? q.split(/\s+/)[0] : null;
        const useFirstTokenBoost = !!(qFirst && qFirst !== q);

        const pQ      = qWrap   ? push(qWrap)   : null;
        const pQLower = qLower  ? push(qLower)  : null;
        const pQFirst = useFirstTokenBoost ? push('%' + qFirst + '%') : null;

        const where = [];
        if (filters.workspace_slug)  where.push(`i.workspace_slug  = ${push(filters.workspace_slug)}`);
        if (filters.affiliation)     where.push(`i.affiliation     = ${push(filters.affiliation)}`);
        if (filters.researcher_code) where.push(`i.researcher_code = ${push(filters.researcher_code)}`);
        if (filters.year !== null)   where.push(`i.year            = ${push(filters.year)}`);
        if (filters.file_type)       where.push(`i.file_type       = ${push(filters.file_type)}`);
        if (filters.status)          where.push(`i.status          = ${push(filters.status)}`);

        // Match clause (only when q is present). We OR across the haystacks
        // permitted by `scope`. With no q, `where` already narrows results
        // via filters and we skip the match clause entirely.
        if (q) {
            const matchOr = [];
            if (scope !== 'content') {
                matchOr.push(`i.filename     ILIKE ${pQ}`);
                matchOr.push(`i.r2_key       ILIKE ${pQ}`);
                matchOr.push(`COALESCE(i.topic,'')        ILIKE ${pQ}`);
                matchOr.push(`COALESCE(i.text_preview,'') ILIKE ${pQ}`);
                // Tags JSONB substring match — cast text and ILIKE.
                matchOr.push(`COALESCE(i.tags::text,'')   ILIKE ${pQ}`);
            }
            if (scope !== 'metadata') {
                matchOr.push(`COALESCE(t.full_text,'') ILIKE ${pQ}`);
            }
            where.push('(' + matchOr.join(' OR ') + ')');
        }

        const whereSql = where.length ? 'WHERE ' + where.join(' AND ') : '';

        // Score expression. Each component contributes only when the
        // corresponding parameter is present, so the same query template
        // works whether or not q / specific filters were passed.
        const scoreParts = [];
        if (filters.researcher_code) scoreParts.push(`(CASE WHEN i.researcher_code = ${push(filters.researcher_code)} THEN 12 ELSE 0 END)`);
        if (filters.file_type)       scoreParts.push(`(CASE WHEN i.file_type       = ${push(filters.file_type)} THEN 8 ELSE 0 END)`);
        if (filters.year !== null)   scoreParts.push(`(CASE WHEN i.year            = ${push(filters.year)} THEN 6 ELSE 0 END)`);
        if (q) {
            scoreParts.push(`(CASE WHEN LOWER(COALESCE(i.filename,'')) = ${pQLower} THEN 10 ELSE 0 END)`);
            scoreParts.push(`(CASE WHEN COALESCE(i.filename,'')        ILIKE ${pQ} THEN 5 ELSE 0 END)`);
            scoreParts.push(`(CASE WHEN COALESCE(i.topic,'')           ILIKE ${pQ} THEN 4 ELSE 0 END)`);
            scoreParts.push(`(CASE WHEN COALESCE(i.text_preview,'')    ILIKE ${pQ} THEN 4 ELSE 0 END)`);
            if (scope !== 'metadata') {
                scoreParts.push(`(CASE WHEN COALESCE(t.full_text,'')   ILIKE ${pQ} THEN 3 ELSE 0 END)`);
            }
            if (useFirstTokenBoost) {
                scoreParts.push(`(CASE WHEN COALESCE(i.filename,'')    ILIKE ${pQFirst} THEN 2 ELSE 0 END)`);
            }
        }
        scoreParts.push(`(CASE WHEN i.indexed_at >= NOW() - INTERVAL '14 days' THEN 1 ELSE 0 END)`);
        const scoreSql = scoreParts.join(' + ');

        // LATERAL join to rd_documents lets us surface a portal-openable id
        // when the file was also ingested via the R&D path. r2_key is the
        // bridge — it's globally unique per object in the bucket. ORDER BY
        // created_at DESC + LIMIT 1 picks the most recent rd_documents row
        // when there are duplicates (revisions).
        const sql = `
            SELECT i.id, i.r2_key, i.filename, i.file_ext, i.file_type,
                   i.workspace_slug, i.researcher_code, i.researcher_name,
                   i.affiliation, i.year, i.date_detected, i.status,
                   i.source_area, i.topic, i.text_status, i.text_preview,
                   i.indexed_at,
                   d.id AS portal_file_id,
                   (${scoreSql}) AS score,
                   (t.file_id IS NOT NULL) AS has_full_text,
                   (CASE WHEN ${q ? `LOWER(COALESCE(i.filename,''))    LIKE '%' || ${pQLower} || '%'` : 'FALSE'} THEN 1 ELSE 0 END) AS match_filename,
                   (CASE WHEN ${q && scope !== 'metadata' ? `LOWER(COALESCE(t.full_text,''))   LIKE '%' || ${pQLower} || '%'` : 'FALSE'} THEN 1 ELSE 0 END) AS match_content
              FROM assistant_file_index i
              LEFT JOIN assistant_file_text t ON t.file_id = i.id
              LEFT JOIN LATERAL (
                  SELECT id
                    FROM rd_documents
                   WHERE r2_key = i.r2_key
                   ORDER BY created_at DESC
                   LIMIT 1
              ) d ON TRUE
              ${whereSql}
              ORDER BY score DESC, i.indexed_at DESC
              LIMIT ${push(limit)}
        `;

        try {
            const r = await pool.query(sql, params);
            const results = r.rows.map(row => {
                const reasons = [];
                if (filters.researcher_code && row.researcher_code === filters.researcher_code) reasons.push('researcher exact match');
                if (filters.file_type && row.file_type === filters.file_type) reasons.push('file_type exact match');
                if (filters.year !== null && row.year === filters.year) reasons.push('year exact match');
                if (row.match_filename) reasons.push('filename contains query');
                if (row.match_content)  reasons.push('content match');
                if (!reasons.length) reasons.push('matched filter');
                return {
                    id:                 row.id,
                    r2_key:             row.r2_key,
                    filename:           row.filename,
                    file_type:          row.file_type,
                    workspace_slug:     row.workspace_slug,
                    researcher_code:    row.researcher_code,
                    researcher_name:    row.researcher_name,
                    affiliation:        row.affiliation,
                    year:               row.year,
                    status:             row.status,
                    topic:              row.topic,
                    text_status:        row.text_status,
                    text_preview:       row.text_preview,
                    has_full_text:      !!row.has_full_text,
                    // Portal openability: rd_documents.id when the file was
                    // also ingested via the R&D path. Null otherwise (e.g.
                    // pure DI uploads). open_file_in_portal needs this id —
                    // not assistant_file_index.id — to succeed.
                    portal_file_id:     row.portal_file_id || null,
                    can_open_in_portal: !!row.portal_file_id,
                    indexed_at:         row.indexed_at ? new Date(row.indexed_at).toISOString() : null,
                    score:              Number(row.score) || 0,
                    match_reasons:      reasons
                };
            });
            res.json({
                workspace_slug: filters.workspace_slug,
                query:          q || null,
                search_scope:   scope,
                filters,
                count:          results.length,
                results
            });
        } catch (err) {
            // Surface the FULL pg error context so prod logs let us
            // diagnose without redeploying. node-pg attaches `code`,
            // `position`, `detail`, `hint`, `where` on `DatabaseError`.
            // We include the raw query + params (no secrets — this index
            // table holds metadata only) so any future 500 here is
            // self-explanatory.
            console.error('[ASSISTANT] indexed-search error:',
                          err && err.message);
            if (err && err.code) {
                console.error('[ASSISTANT] indexed-search PG code=' + err.code,
                              'detail=' + (err.detail || '-'),
                              'hint=' + (err.hint || '-'),
                              'position=' + (err.position || '-'));
            }
            console.error('[ASSISTANT] indexed-search SQL:', sql);
            console.error('[ASSISTANT] indexed-search params:', JSON.stringify(params));
            if (err && err.stack) console.error('[ASSISTANT] indexed-search stack:', err.stack);
            res.status(500).json({ error: 'Failed to run indexed search' });
        }
    }

    // GET /api/assistant/files/:submission_id/text?ws=natlab
    //
    // Read-only text extraction for one DI submission. Zoe needs PDF text for
    // DATA ALCOA review and SOP Anatomy review without ever touching R2
    // credentials directly — the portal backend owns R2 and exposes only the
    // metadata + extracted text here.
    //
    // Behaviour:
    //   - Looks up di_submissions by submission_id (canonical NAT-Lab id).
    //   - Returns 404 if not found in this workspace.
    //   - Pulls the PDF bytes from R2 via the server.js-scoped helper, runs
    //     pdf-parse, returns text capped at DEFAULT_TEXT_MAX chars.
    //   - On scanned/image-only PDFs (pdf-parse error or empty text) returns
    //     text_available=false with extraction.error="scanned_pdf_or_unreadable".
    //   - No signed URLs, no R2 keys/credentials leaked beyond r2_object_key
    //     (which is already exposed by /search and /:id).
    //
    // Defined before /:id so Express route ordering stays explicit, even
    // though the two paths differ by segment count.
    router.get('/:submission_id/text', async (req, res) => {
        const submissionId = (req.params.submission_id || '').toString().trim();
        const wsSlug       = (req.query.ws || '').toString().trim();
        if (!wsSlug)       return res.status(400).json({ error: 'ws query parameter is required' });
        if (!submissionId) return res.status(400).json({ error: 'submission_id is required' });
        // Defensive: the submission_id column is a UUID. Reject other shapes
        // up front rather than scanning di_submissions.
        if (!/^[0-9a-fA-F-]{36}$/.test(submissionId)) {
            return res.status(404).json({ error: 'Submission not found in workspace' });
        }
        if (typeof fetchR2ObjectAsBuffer !== 'function' || typeof normalizeR2Key !== 'function') {
            return res.status(503).json({ error: 'R2 helpers not wired into assistant files router' });
        }

        try {
            const wsRow = await pool.query(
                `SELECT id, slug FROM workspaces WHERE slug = $1 AND is_active = TRUE LIMIT 1`,
                [wsSlug]
            );
            if (wsRow.rows.length === 0) {
                return res.status(404).json({ error: 'Workspace not found' });
            }
            const workspaceId   = wsRow.rows[0].id;
            const workspaceSlug = wsRow.rows[0].slug;

            // di_submissions is the source of truth for NAT-Lab uploads. We
            // join di_allowlist for a trustworthy submitter display name (same
            // pattern as /search and /review-queue).
            const r = await pool.query(
                `SELECT s.submission_id,
                        s.original_filename,
                        s.file_type,
                        s.r2_object_key,
                        s.status,
                        s.created_at,
                        s.signed_at,
                        s.discarded_at,
                        s.researcher_id,
                        s.affiliation,
                        a.name AS submitter_name
                   FROM di_submissions s
                   LEFT JOIN di_allowlist a ON a.researcher_id = s.researcher_id
                  WHERE s.workspace_id = $1
                    AND s.submission_id = $2
                  LIMIT 1`,
                [workspaceId, submissionId]
            );
            if (r.rows.length === 0) {
                return res.status(404).json({ error: 'Submission not found in workspace' });
            }
            const row = r.rows[0];

            // Review state + updated_at — same rules as /search and /:id so
            // Zoe sees consistent values across endpoints. di_submissions has
            // no updated_at column in production, so fall back to
            // discarded_at -> signed_at -> created_at.
            const ageMs = row.created_at ? Date.now() - new Date(row.created_at).getTime() : null;
            let reviewState;
            if      (!row.status)                      reviewState = 'not_submitted';
            else if (row.status === 'DISCARDED')       reviewState = 'discarded';
            else if (row.status === 'APPROVED')        reviewState = 'approved';
            else if (row.status === 'REVISION_NEEDED') reviewState = (ageMs && ageMs > 14 * 24 * 3600 * 1000) ? 'blocked' : 'needs_revision';
            else if (row.status === 'PENDING')         reviewState = (ageMs && ageMs > 7  * 24 * 3600 * 1000) ? 'stalled' : 'awaiting_review';
            else                                       reviewState = String(row.status).toLowerCase();
            const updatedAt = row.discarded_at || row.signed_at || row.created_at;

            const meta = {
                workspace:         workspaceSlug,
                submission_id:     row.submission_id,
                filename:          row.original_filename || null,
                file_type:         row.file_type || null,
                researcher_id:     row.researcher_id || null,
                submitted_by_name: row.submitter_name || null,
                affiliation:       row.affiliation || null,
                status:            row.status || null,
                review_state:      reviewState,
                created_at:        row.created_at ? new Date(row.created_at).toISOString() : null,
                updated_at:        updatedAt ? new Date(updatedAt).toISOString() : null,
                r2_object_key:     row.r2_object_key || null
            };

            // r2_object_key is nulled when di_submissions transitions to
            // REVISION_NEEDED or DISCARDED — there's nothing to extract in
            // that case. Return metadata + a clean failure shape.
            const r2Key = normalizeR2Key(row.r2_object_key);
            if (!r2Key) {
                return res.json({
                    ...meta,
                    text_available: false,
                    extracted_text: '',
                    extraction: { method: 'pdf-parse', error: 'no_r2_object_key' }
                });
            }

            // Only attempt PDF text extraction for files that look like PDFs.
            // Other file types (xlsx, images, etc.) return a clean failure;
            // OCR / non-PDF parsing is intentionally out of scope for this
            // endpoint per the patch brief.
            const filenameLower = (row.original_filename || '').toLowerCase();
            if (!filenameLower.endsWith('.pdf')) {
                return res.json({
                    ...meta,
                    text_available: false,
                    extracted_text: '',
                    extraction: { method: 'pdf-parse', error: 'unsupported_file_type' }
                });
            }

            let buffer;
            try {
                buffer = await fetchR2ObjectAsBuffer(r2Key);
            } catch (e) {
                console.error('[ASSISTANT] files/:submission_id/text R2 fetch failed:', e.message);
                return res.json({
                    ...meta,
                    text_available: false,
                    extracted_text: '',
                    extraction: { method: 'pdf-parse', error: 'r2_fetch_failed' }
                });
            }

            let parsed;
            try {
                const pdfParse = require('pdf-parse');
                parsed = await pdfParse(buffer);
            } catch (e) {
                console.error('[ASSISTANT] files/:submission_id/text pdf-parse failed:', e.message);
                return res.json({
                    ...meta,
                    text_available: false,
                    extracted_text: '',
                    extraction: { method: 'pdf-parse', error: 'scanned_pdf_or_unreadable' }
                });
            }

            const rawText = (parsed.text || '').replace(/\s+\n/g, '\n').trim();
            // pdf-parse on a scanned/image-only PDF parses fine but yields an
            // empty string. Surface that as the documented failure shape.
            if (!rawText) {
                return res.json({
                    ...meta,
                    text_available: false,
                    extracted_text: '',
                    extraction: {
                        method: 'pdf-parse',
                        pages:  parsed.numpages || null,
                        error:  'scanned_pdf_or_unreadable'
                    }
                });
            }

            const charsTotal = rawText.length;
            const truncated  = charsTotal > DEFAULT_TEXT_MAX;
            const out        = truncated ? rawText.slice(0, DEFAULT_TEXT_MAX) : rawText;

            res.json({
                ...meta,
                text_available: true,
                extracted_text: out,
                extraction: {
                    method:         'pdf-parse',
                    pages:          parsed.numpages || null,
                    chars_total:    charsTotal,
                    chars_returned: out.length,
                    truncated
                }
            });
        } catch (err) {
            console.error('[ASSISTANT] files/:submission_id/text error:', err.message);
            res.status(500).json({ error: 'Failed to extract submission text' });
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
