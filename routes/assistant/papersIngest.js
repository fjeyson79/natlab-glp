// routes/assistant/papersIngest.js
//
// POST /api/assistant/papers/ingest
//
// Single-shot PAPER ingestion endpoint. Auth-gated with a static bearer
// token from process.env.NATLAB_PI_TOKEN — separate from the cookie/session
// PI gate because this is called by an out-of-portal VPS runner script
// (scripts/ingest-frank-papers.mjs), not by a logged-in human session.
//
// Pipeline (single multipart POST):
//   1. Token gate (constant-time compare, 401 on miss).
//   2. Multer parses one PDF (file_type forced to PAPER).
//   3. Upload PDF buffer to R2 under a deterministic key:
//        papers/<workspace>/<researcher_code>/<year>/<sanitized_filename>
//   4. INSERT one row into assistant_file_index — workspace_slug, file_type,
//      researcher_code, researcher_name (resolved from di_allowlist), year,
//      pmid/doi/title from form fields, text_status='pending'.
//   5. Trigger the existing extractor (indexer.extractPendingPdfText with
//      limit:1) to run pdf-parse + the PMID/DOI/title detector inline.
//      This reuses the full extraction pipeline — no parallel paper logic.
//   6. Re-fetch and return the row's post-extraction state.
//
// Strictly additive — no edits to upload paths, approval flow, or any
// existing endpoint. Papers never enter di_submissions (the CHECK
// constraint excludes PAPER); they live only in assistant_file_index.

'use strict';

const express = require('express');
const multer  = require('multer');
const crypto  = require('crypto');

// 50 MB is generous for scientific PDFs; the same cap used by report uploads
// is 20 MB but papers can be larger (figures, supplemental matter).
const MAX_BYTES = 50 * 1024 * 1024;

module.exports = function papersIngestRouter(pool, deps) {
    const router  = express.Router();
    const uploadToR2 = deps && deps.uploadToR2;
    const r2Client   = deps && deps.r2Client;
    const r2Bucket   = deps && deps.r2Bucket;
    const indexer    = deps && deps.indexer;

    if (typeof uploadToR2 !== 'function') {
        throw new Error('papersIngestRouter: missing deps.uploadToR2');
    }

    // Column-presence cache. pmid/doi/paper_title are added by migration 072
    // (inlined in db/migrate.js). If the deploy ran before the migration we
    // gracefully omit those columns from INSERT/SELECT so ingest still works
    // — pmid/doi/paper_title come back NULL in the response on that path.
    let _paperColsReady = null;
    async function paperColsReady() {
        if (_paperColsReady !== null) return _paperColsReady;
        try {
            const r = await pool.query(`
                SELECT COUNT(*)::int AS n
                  FROM information_schema.columns
                 WHERE table_name='assistant_file_index'
                   AND column_name IN ('pmid','doi','paper_title')`);
            _paperColsReady = (r.rows[0].n >= 3);
        } catch { _paperColsReady = false; }
        return _paperColsReady;
    }

    const upload = multer({
        storage: multer.memoryStorage(),
        limits:  { fileSize: MAX_BYTES },
        fileFilter: (req, file, cb) => {
            // Accept only PDF — anything else is rejected before reaching the
            // handler. Mimetype + extension to catch both shapes.
            const name = (file.originalname || '').toLowerCase();
            const ok = file.mimetype === 'application/pdf' || name.endsWith('.pdf');
            cb(ok ? null : new Error('only_pdf_supported'), ok);
        }
    });

    // Bearer-token gate. Constant-time compare; rejects clearly when the env
    // var isn't set (503) so a misconfigured deploy is loud rather than
    // silently open.
    function requirePiToken(req, res, next) {
        const expected = process.env.NATLAB_PI_TOKEN;
        if (!expected) {
            return res.status(503).json({ error: 'NATLAB_PI_TOKEN not configured on server' });
        }
        const auth = String(req.headers.authorization || '');
        const m = auth.match(/^Bearer\s+(.+)$/i);
        if (!m) return res.status(401).json({ error: 'Bearer token required' });
        const got = m[1];
        // timingSafeEqual requires equal-length buffers — pad to the max
        // length so the compare itself is constant-time regardless of how
        // long the supplied token is.
        const a = Buffer.from(got, 'utf8');
        const b = Buffer.from(expected, 'utf8');
        const len = Math.max(a.length, b.length);
        const aPad = Buffer.alloc(len); a.copy(aPad);
        const bPad = Buffer.alloc(len); b.copy(bPad);
        const eq = (a.length === b.length) && crypto.timingSafeEqual(aPad, bPad);
        if (!eq) return res.status(401).json({ error: 'Invalid bearer token' });
        next();
    }

    // -----------------------------------------------------------------
    // POST /ingest
    // -----------------------------------------------------------------
    router.post('/ingest', requirePiToken, upload.single('file'), async (req, res) => {
        try {
            const file = req.file;
            if (!file) return res.status(400).json({ error: 'PDF file is required (multipart field: file)' });
            if (!file.buffer || !file.buffer.length) {
                return res.status(400).json({ error: 'Empty PDF buffer' });
            }

            // Required + optional form fields. researcher_code is the only
            // hard requirement — title/year/doi/pmid are best-effort, the
            // indexer's detector will try to fill them from the PDF text.
            const researcherCode = String((req.body.researcher_code || '')).trim().toUpperCase();
            if (!researcherCode) return res.status(400).json({ error: 'researcher_code is required' });

            const title = strOrNull(req.body.title);
            const year  = parseYearOrNull(req.body.year);
            const doi   = strOrNull(req.body.doi);
            const pmid  = pmidOrNull(req.body.pmid);

            // Workspace + researcher resolution. Frank's papers are NAT-Lab;
            // hard-coding here would be brittle, so we resolve from
            // di_allowlist (the canonical researcher table) like the rest
            // of the assistant routes.
            const rosterR = await pool.query(
                `SELECT researcher_id, name, affiliation
                   FROM di_allowlist WHERE researcher_id = $1 LIMIT 1`,
                [researcherCode]
            );
            if (rosterR.rows.length === 0) {
                return res.status(404).json({ error: 'researcher_code not found in di_allowlist' });
            }
            const roster = rosterR.rows[0];

            // Workspace_slug — papers always land in 'natlab' for this
            // endpoint. If a multi-workspace ingest is ever needed, take
            // workspace_slug as a form field; today every paper is NAT-Lab.
            const workspaceSlug = 'natlab';

            // R2 key. The path-segment `papers/` is recognised by
            // services/zoeRetrieval.js parseR2Path() as PAPER, so even a
            // future full-bucket reindex would re-classify this row
            // correctly. Filename is preserved verbatim except for unsafe
            // characters.
            const safeName = sanitizeFilename(file.originalname || 'paper.pdf');
            const yearSeg  = year != null ? String(year) : 'unknown';
            const r2Key    = `papers/${workspaceSlug}/${researcherCode}/${yearSeg}/${safeName}`;

            // R2 upload. Reuses the existing helper — no parallel R2 path.
            try {
                await uploadToR2(file.buffer, r2Key, 'application/pdf');
            } catch (e) {
                return res.status(502).json({ error: 'R2 upload failed', detail: e.message });
            }

            // Insert / upsert the index row. ON CONFLICT (r2_key) DO UPDATE
            // makes re-ingesting the same file idempotent — useful for the
            // VPS runner if it retries a partial batch.
            //
            // text_status is forced to 'pending' so the next extractor pass
            // (run inline below) picks it up. pmid/doi/paper_title are set
            // from the form fields when migration 072 columns exist; the
            // inline extractor's COALESCE-UPDATE will only fill them if
            // they're still NULL, so user-supplied values always win.
            const hasPaperCols = await paperColsReady();
            const baseCols   = `workspace_slug, r2_key, filename, file_ext, file_type,
                                researcher_code, researcher_name, affiliation, year,
                                source_area, topic, mime_type, size_bytes,
                                text_status`;
            const baseVals   = `$1, $2, $3, 'pdf', 'PAPER',
                                $4, $5, $6, $7,
                                'papers', $8, 'application/pdf', $9,
                                'pending'`;
            const baseUpdate = `workspace_slug   = EXCLUDED.workspace_slug,
                                filename         = EXCLUDED.filename,
                                file_type        = 'PAPER',
                                researcher_code  = EXCLUDED.researcher_code,
                                researcher_name  = EXCLUDED.researcher_name,
                                affiliation      = EXCLUDED.affiliation,
                                year             = EXCLUDED.year,
                                source_area      = 'papers',
                                topic            = EXCLUDED.topic,
                                mime_type        = 'application/pdf',
                                size_bytes       = EXCLUDED.size_bytes,
                                text_status      = 'pending',
                                indexed_at       = NOW()`;
            const paperColsSql   = hasPaperCols ? `, pmid, doi, paper_title` : '';
            const paperValsSql   = hasPaperCols ? `, $10, $11, $12`         : '';
            const paperUpdateSql = hasPaperCols
                ? `,
                                pmid             = COALESCE(EXCLUDED.pmid, assistant_file_index.pmid),
                                doi              = COALESCE(EXCLUDED.doi,  assistant_file_index.doi),
                                paper_title      = COALESCE(EXCLUDED.paper_title, assistant_file_index.paper_title)`
                : '';
            const insertParams = hasPaperCols
                ? [workspaceSlug, r2Key, safeName,
                   researcherCode, roster.name || null, roster.affiliation || null, year,
                   title, file.buffer.length,
                   pmid, doi, title]
                : [workspaceSlug, r2Key, safeName,
                   researcherCode, roster.name || null, roster.affiliation || null, year,
                   title, file.buffer.length];

            const ins = await pool.query(
                `INSERT INTO assistant_file_index (${baseCols}${paperColsSql})
                 VALUES (${baseVals}${paperValsSql})
                 ON CONFLICT (r2_key) DO UPDATE SET
                     ${baseUpdate}${paperUpdateSql}
                 RETURNING id`,
                insertParams
            );
            const fileId = ins.rows[0].id;

            // Trigger inline extraction. extractPendingPdfText pulls the
            // newest 'pending' row first, which is the one we just inserted
            // (its indexed_at = NOW()), so limit:1 processes exactly this
            // file. Reuses the existing pipeline: pdf-parse → sanitize →
            // assistant_file_text write → text_status flip → PMID/DOI/title
            // COALESCE-UPDATE.
            let extractionRan = false;
            if (indexer && typeof indexer.extractPendingPdfText === 'function'
                && r2Client && r2Bucket) {
                try {
                    await indexer.extractPendingPdfText(
                        { pool, r2Client, r2Bucket },
                        { limit: 1 }
                    );
                    extractionRan = true;
                } catch (e) {
                    // Extraction failure is recoverable — the row stays
                    // 'pending' (or gets stamped 'failed' by the extractor's
                    // own _markFailed) and the periodic reindex job will
                    // retry. Don't fail the ingest response.
                    console.warn('[PAPER-INGEST] inline extraction failed for', r2Key, '—', e.message);
                }
            }

            // Re-fetch the row so the response reflects post-extraction
            // state (text_status, text_char_count, and any newly detected
            // pmid/doi/paper_title). pmid/doi/paper_title columns are
            // conditional on migration 072.
            const paperSelectCols = hasPaperCols
                ? `, pmid, doi, paper_title`
                : `, NULL::text AS pmid, NULL::text AS doi, NULL::text AS paper_title`;
            const finalR = await pool.query(
                `SELECT id, r2_key, filename, file_type, workspace_slug,
                        researcher_code, researcher_name, affiliation, year,
                        text_status, text_char_count, text_extracted_at,
                        size_bytes, indexed_at
                        ${paperSelectCols}
                   FROM assistant_file_index WHERE id = $1`,
                [fileId]
            );
            const row = finalR.rows[0];

            res.json({
                ok: true,
                extraction_attempted: extractionRan,
                file: {
                    id:               row.id,
                    r2_key:           row.r2_key,
                    filename:         row.filename,
                    file_type:        row.file_type,
                    workspace_slug:   row.workspace_slug,
                    researcher_code:  row.researcher_code,
                    researcher_name:  row.researcher_name,
                    affiliation:      row.affiliation,
                    year:             row.year,
                    text_status:      row.text_status,
                    text_char_count:  row.text_char_count == null ? null : Number(row.text_char_count),
                    text_extracted_at: row.text_extracted_at
                        ? new Date(row.text_extracted_at).toISOString() : null,
                    pmid:             row.pmid        || null,
                    doi:              row.doi         || null,
                    paper_title:      row.paper_title || null,
                    size_bytes:       row.size_bytes == null ? null : Number(row.size_bytes),
                    indexed_at:       row.indexed_at  ? new Date(row.indexed_at).toISOString() : null,
                    indexed_text_endpoint: `/api/assistant/files/indexed/${row.id}/text`
                }
            });
        } catch (err) {
            // Multer file-size rejections surface as MulterError. Map to 413
            // so the runner can distinguish "too big" from other failures.
            if (err && err.code === 'LIMIT_FILE_SIZE') {
                return res.status(413).json({ error: 'PDF exceeds 50 MB limit' });
            }
            if (err && err.message === 'only_pdf_supported') {
                return res.status(415).json({ error: 'Only PDF files are supported' });
            }
            console.error('[PAPER-INGEST] error:', err && err.message);
            if (err && err.code) console.error('[PAPER-INGEST] PG code=' + err.code, 'detail=' + (err.detail || '-'));
            return res.status(500).json({ error: 'Paper ingest failed' });
        }
    });

    return router;
};

// ---------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------

function strOrNull(v) {
    if (v == null) return null;
    const s = String(v).trim();
    return s.length ? s : null;
}

function parseYearOrNull(v) {
    if (v == null || v === '') return null;
    const n = parseInt(String(v).trim(), 10);
    if (!Number.isFinite(n)) return null;
    if (n < 1900 || n > 2100) return null;
    return n;
}

function pmidOrNull(v) {
    const s = strOrNull(v);
    if (!s) return null;
    // PMIDs are pure digits, 1–9 characters in practice. Accept anything
    // that parses cleanly — the column itself is TEXT for flexibility.
    return /^\d{1,9}$/.test(s) ? s : null;
}

// Defensive — the runner builds filenames, but R2 keys must be path-safe.
function sanitizeFilename(name) {
    const base = String(name || 'paper.pdf').split(/[\\\/]/).pop();
    const cleaned = base.replace(/[^\w.\-]+/g, '_');
    return cleaned || 'paper.pdf';
}
