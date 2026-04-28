// services/assistantFileIndexer.js
//
// Zoe Phase 1 — File visibility + keyword search index builder.
//
// Responsibilities:
//   1. Scan the R2 bucket (paginated ListObjectsV2) and, for every key NOT in
//      the existing zoeRetrieval ignore list, upsert a row into
//      assistant_file_index with metadata inferred via parseR2Path() +
//      a small workspace_slug / affiliation / source_area mapper that lives
//      here (not in zoeRetrieval, which is shape-only).
//   2. After the metadata pass completes, walk all rows where
//      text_status = 'pending' AND file_ext = 'pdf', download the bytes
//      from R2, run pdf-parse, and write the result to assistant_file_text +
//      update text_status / text_preview / text_char_count on the index row.
//
// Design constraints (from the brief):
//   - Reuse parseR2Path() and shouldIgnoreR2Path() from zoeRetrieval.
//   - Do NOT duplicate metadata inference logic.
//   - Idempotent (UPSERT keyed on r2_key) and resumable: if the job dies
//     during text extraction, re-running picks up the still-pending rows.
//   - PDF extraction is best-effort. One failed PDF does NOT abort the job.
//   - Non-PDF files get text_status = 'unsupported' (no extraction attempt).
//   - No R2 credentials leak through this module's public API; the caller
//     (server.js mount or CLI) injects an S3 client + bucket name.
//
// Exports (public):
//   runJob(deps, opts)
//   getJobStatus()
//   indexAllFromR2(deps, opts)
//   extractPendingPdfText(deps, opts)
//
// `deps` shape:
//   { pool, r2Client, r2Bucket, log? }
//
// `pool` is a node-postgres Pool. `r2Client` is an @aws-sdk/client-s3 S3Client
// already configured for the R2 endpoint. `r2Bucket` is the bucket name.

'use strict';

const { ListObjectsV2Command, GetObjectCommand } = require('@aws-sdk/client-s3');
const { parseR2Path, shouldIgnoreR2Path } = require('./zoeRetrieval');

// Char cap for text_preview (kept short — this is the snippet shown in
// /map and /search hit summaries, NOT the full document).
const PREVIEW_CHARS = 600;

// Char cap on what we store in assistant_file_text.full_text. PDFs in this
// portal range from 1-100 pages; 500K characters comfortably covers a 100-page
// scientific PDF and keeps the table footprint bounded.
const FULL_TEXT_CHARS = 500000;

// pdf-parse can return strings containing NUL bytes (0x00) or other ASCII
// control characters that are valid in JS strings but not valid in Postgres
// TEXT values under UTF-8 encoding. Inserting them throws:
//   invalid byte sequence for encoding "UTF8": 0x00
// which (before this guard) aborted the whole text-extract pass.
//
// Apply this BEFORE every DB write of extracted text — full_text, text_preview,
// and any future per-page text in pages_json. Strips NUL entirely (no useful
// rendering); replaces other low control chars with a space so word boundaries
// survive; trims surrounding whitespace.
function sanitizeExtractedText(value) {
    if (value == null) return '';
    return String(value)
        .replace(/\u0000/g, '')
        .replace(/[\u0001-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ' ')
        .trim();
}

// ------------------------------------------------------------------------
// Workspace + source-area mapping
// ------------------------------------------------------------------------
// parseR2Path() returns the raw first segment as `organization`. For
// indexing we want a workspace slug that matches the workspaces.slug column
// (used by every existing /api/assistant/* endpoint). The mapping is
// path-prefix-based and intentionally narrow — anything we cannot confidently
// classify stays NULL.
//
// di/...               → natlab     (NAT-Lab DI uploads, training, inventory)
// oligo/...            → natlab     (oligo registry — NAT-Lab only)
// theralia/...         → theralia
// rd/{ws}/...          → {ws}       (per-workspace R&D documents)
// company/{ws}/...     → {ws}       (per-workspace InvestRoom company docs)
// group-docs/...       → null       (cross-workspace shared)
// anything else        → null
function inferWorkspaceSlug(parsed) {
    if (!parsed || !parsed.segments || parsed.segments.length === 0) return null;
    const top = parsed.segments[0];
    if (top === 'di')        return 'natlab';
    if (top === 'oligo')     return 'natlab';
    if (top === 'theralia')  return 'theralia';
    if (top === 'rd' && parsed.segments.length >= 2)      return parsed.segments[1];
    if (top === 'company' && parsed.segments.length >= 2) return parsed.segments[1];
    return null;
}

// di/{aff}/... is the only path layout that puts affiliation in the path.
// Other top-levels (rd, theralia, company) are workspace-scoped, not
// affiliation-scoped, so affiliation stays NULL there.
const _AFFILIATIONS = new Set(['LiU', 'UNAV', 'EXTERNAL', 'THERALIA']);
function inferAffiliation(parsed) {
    if (!parsed || !parsed.segments || parsed.segments.length < 2) return null;
    if (parsed.segments[0] !== 'di') return null;
    const seg = parsed.segments[1];
    return _AFFILIATIONS.has(seg) ? seg : null;
}

// "source_area" is the literal top-level prefix — it is more granular than
// workspace_slug (e.g. di/ vs oligo/ both → workspace 'natlab', but they are
// different operational areas, so /map and /search filter on it separately).
function inferSourceArea(parsed) {
    if (!parsed || !parsed.segments || parsed.segments.length === 0) return null;
    return parsed.segments[0] || null;
}

// Year inference: prefer the iso_date from the filename (most reliable on
// NAT-Lab uploads), then fall back to a 4-digit year segment in the path.
function inferYear(parsed) {
    if (!parsed) return null;
    if (parsed.iso_date) {
        const yr = parseInt(parsed.iso_date.slice(0, 4), 10);
        if (Number.isFinite(yr) && yr >= 1990 && yr <= 2100) return yr;
    }
    for (const seg of (parsed.chrono_segments || [])) {
        if (/^\d{4}$/.test(seg)) {
            const yr = parseInt(seg, 10);
            if (yr >= 1990 && yr <= 2100) return yr;
        }
        if (/^\d{4}-\d{2}/.test(seg)) {
            const yr = parseInt(seg.slice(0, 4), 10);
            if (yr >= 1990 && yr <= 2100) return yr;
        }
    }
    return null;
}

function inferDateDetected(parsed) {
    if (!parsed || !parsed.iso_date) return null;
    return parsed.iso_date;
}

// File type: parseR2Path returns both type_from_path and type_from_filename.
// Path beats filename when both fire (path is the curator's intent).
function inferFileType(parsed) {
    if (!parsed) return null;
    return parsed.type_from_path || parsed.type_from_filename || null;
}

function inferStatus(parsed) {
    if (!parsed) return null;
    return parsed.status_from_path || null;
}

function fileExtOf(filename) {
    if (!filename) return null;
    const m = String(filename).match(/\.([a-z0-9]{1,8})$/i);
    return m ? m[1].toLowerCase() : null;
}

// ------------------------------------------------------------------------
// Researcher resolution
// ------------------------------------------------------------------------
// One-shot fetch of the di_allowlist roster keyed by researcher_id (which is
// the same uppercase initials token parseR2Path puts in `researcher_code`).
// We resolve names + affiliations in JS so the metadata-pass UPSERT stays a
// simple INSERT … ON CONFLICT … DO UPDATE without a per-row JOIN.
async function loadResearcherRoster(pool) {
    const map = new Map();
    try {
        const r = await pool.query(
            `SELECT researcher_id, name, affiliation FROM di_allowlist`
        );
        for (const row of r.rows) {
            if (!row.researcher_id) continue;
            map.set(String(row.researcher_id).toUpperCase(), {
                researcher_id: row.researcher_id,
                name: row.name || null,
                affiliation: row.affiliation || null
            });
        }
    } catch (e) {
        // Allowlist missing or schema drift — keep the roster empty rather
        // than failing the whole indexing job. Researcher_name will be null.
        // eslint-disable-next-line no-console
        console.warn('[INDEXER] di_allowlist not readable:', e.message);
    }
    return map;
}

// ------------------------------------------------------------------------
// R2 helpers (self-contained — no dependency on server.js scope)
// ------------------------------------------------------------------------
async function r2BodyToBuffer(body) {
    if (body == null) throw new Error('empty R2 body');
    if (Buffer.isBuffer(body)) return body;
    if (typeof body === 'string') return Buffer.from(body, 'utf8');
    if (body instanceof Uint8Array) return Buffer.from(body);
    if (typeof ArrayBuffer !== 'undefined' && body instanceof ArrayBuffer) {
        return Buffer.from(new Uint8Array(body));
    }
    if (typeof body.transformToByteArray === 'function') {
        const arr = await body.transformToByteArray();
        return Buffer.from(arr);
    }
    if (typeof body.pipe === 'function' || typeof body[Symbol.asyncIterator] === 'function') {
        const chunks = [];
        for await (const chunk of body) {
            chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
        }
        return Buffer.concat(chunks);
    }
    throw new Error('Unsupported R2 body type: ' + (body && body.constructor && body.constructor.name || typeof body));
}

async function downloadObject(r2Client, r2Bucket, key) {
    const out = await r2Client.send(new GetObjectCommand({ Bucket: r2Bucket, Key: key }));
    return await r2BodyToBuffer(out.Body);
}

// ------------------------------------------------------------------------
// In-memory job status (single-process). Enough for Phase 1 — the reindex
// route returns this. If we move to multi-instance Railway later, push to
// a real table.
// ------------------------------------------------------------------------
let _job = {
    state: 'idle',          // idle | running | done | failed
    started_at: null,
    finished_at: null,
    phase: null,            // 'metadata' | 'pdf_text' | null
    counts: {
        scanned:  0,        // R2 objects seen
        ignored:  0,        // skipped via shouldIgnoreR2Path
        upserted: 0,        // metadata rows touched
        text_processed: 0,  // PDFs we attempted to extract
        text_ready:     0,
        text_failed:    0,
        text_empty:     0,
        text_unsupported: 0
    },
    error: null
};

function getJobStatus() {
    // Return a copy so callers can't mutate internal state.
    return JSON.parse(JSON.stringify(_job));
}

function _resetJob() {
    _job = {
        state: 'running',
        started_at: new Date().toISOString(),
        finished_at: null,
        phase: 'metadata',
        counts: {
            scanned: 0, ignored: 0, upserted: 0,
            text_processed: 0, text_ready: 0, text_failed: 0, text_empty: 0, text_unsupported: 0
        },
        error: null
    };
}

// ------------------------------------------------------------------------
// Pass 1: metadata indexing
// ------------------------------------------------------------------------
// Walks the bucket via ListObjectsV2 (no Prefix — full bucket scan), filters
// out ignored paths, and UPSERTs one row per remaining key. Does NOT download
// any objects — list-only, so a full pass is cheap.
async function indexAllFromR2(deps, opts) {
    const { pool, r2Client, r2Bucket, log = console } = deps;
    const { batchSize = 500 } = opts || {};
    if (!pool || !r2Client || !r2Bucket) {
        throw new Error('indexAllFromR2 requires { pool, r2Client, r2Bucket }');
    }

    _job.phase = 'metadata';
    const roster = await loadResearcherRoster(pool);

    // Gather then flush per batch — keeps memory bounded on large buckets.
    const buffer = [];

    let token;
    do {
        const resp = await r2Client.send(new ListObjectsV2Command({
            Bucket: r2Bucket,
            ContinuationToken: token,
            MaxKeys: 1000
        }));
        const contents = resp.Contents || [];
        for (const obj of contents) {
            _job.counts.scanned += 1;
            if (!obj.Key) continue;
            if (shouldIgnoreR2Path(obj.Key)) {
                _job.counts.ignored += 1;
                continue;
            }
            const parsed = parseR2Path(obj.Key) || {};
            const filename = parsed.filename || obj.Key.split('/').pop();
            const ext = fileExtOf(filename);

            // Resolve researcher_name + affiliation-from-roster when the
            // filename gave us a code. Roster affiliation only fills in if
            // the path didn't already supply one (path is more authoritative
            // for di/{aff}/ uploads).
            const code = parsed.researcher_code ? String(parsed.researcher_code).toUpperCase() : null;
            const rosterEntry = code ? roster.get(code) : null;
            const affPath = inferAffiliation(parsed);
            const affiliation = affPath || (rosterEntry && rosterEntry.affiliation) || null;
            const researcher_name = (rosterEntry && rosterEntry.name) || null;

            buffer.push({
                r2_key:          obj.Key,
                workspace_slug:  inferWorkspaceSlug(parsed),
                filename,
                file_ext:        ext,
                file_type:       inferFileType(parsed),
                researcher_code: code,
                researcher_name,
                affiliation,
                year:            inferYear(parsed),
                date_detected:   inferDateDetected(parsed),
                status:          inferStatus(parsed),
                source_area:     inferSourceArea(parsed),
                topic:           parsed.topic || null,
                size_bytes:      typeof obj.Size === 'number' ? obj.Size : null,
                // text_status: 'pending' for PDFs, 'unsupported' for everything else.
                // Set here so the pdf-text pass has a clean WHERE clause.
                text_status:     ext === 'pdf' ? 'pending' : 'unsupported'
            });

            if (buffer.length >= batchSize) {
                await _flushBatch(pool, buffer);
                _job.counts.upserted += buffer.length;
                buffer.length = 0;
            }
        }
        token = resp.IsTruncated ? resp.NextContinuationToken : undefined;
    } while (token);

    if (buffer.length) {
        await _flushBatch(pool, buffer);
        _job.counts.upserted += buffer.length;
        buffer.length = 0;
    }

    log.info && log.info('[INDEXER] Metadata pass complete:', JSON.stringify(_job.counts));
}

async function _flushBatch(pool, rows) {
    if (!rows.length) return;
    // Single multi-row INSERT … ON CONFLICT (r2_key) DO UPDATE.
    // We let the trigger maintain updated_at; indexed_at is bumped on every
    // touch so callers can see when the row was last re-validated.
    const cols = [
        'r2_key', 'workspace_slug', 'filename', 'file_ext', 'file_type',
        'researcher_code', 'researcher_name', 'affiliation', 'year',
        'date_detected', 'status', 'source_area', 'topic',
        'size_bytes', 'text_status'
    ];
    const placeholders = [];
    const params = [];
    rows.forEach((r, i) => {
        const base = i * cols.length;
        const ph = cols.map((_, j) => '$' + (base + j + 1));
        placeholders.push('(' + ph.join(',') + ')');
        params.push(
            r.r2_key, r.workspace_slug, r.filename, r.file_ext, r.file_type,
            r.researcher_code, r.researcher_name, r.affiliation, r.year,
            r.date_detected, r.status, r.source_area, r.topic,
            r.size_bytes, r.text_status
        );
    });

    // text_status is intentionally NOT updated on conflict: if a previous
    // text pass already set it to 'ready' or 'failed', we keep that signal
    // unless the file_ext changed (rare).
    const sql = `
        INSERT INTO assistant_file_index
            (r2_key, workspace_slug, filename, file_ext, file_type,
             researcher_code, researcher_name, affiliation, year,
             date_detected, status, source_area, topic,
             size_bytes, text_status)
        VALUES ${placeholders.join(',')}
        ON CONFLICT (r2_key) DO UPDATE SET
            workspace_slug   = EXCLUDED.workspace_slug,
            filename         = EXCLUDED.filename,
            file_ext         = EXCLUDED.file_ext,
            file_type        = EXCLUDED.file_type,
            researcher_code  = EXCLUDED.researcher_code,
            researcher_name  = EXCLUDED.researcher_name,
            affiliation      = EXCLUDED.affiliation,
            year             = EXCLUDED.year,
            date_detected    = EXCLUDED.date_detected,
            status           = EXCLUDED.status,
            source_area      = EXCLUDED.source_area,
            topic            = EXCLUDED.topic,
            size_bytes       = EXCLUDED.size_bytes,
            indexed_at       = NOW()
    `;
    await pool.query(sql, params);
}

// ------------------------------------------------------------------------
// Pass 2: PDF text extraction
// ------------------------------------------------------------------------
// Selects rows where text_status='pending' AND file_ext='pdf', downloads the
// object, runs pdf-parse, and updates both tables. Per-file failures are
// caught and recorded — they never abort the loop.
//
// Resumability: a row stays 'pending' until we mark it 'ready' / 'failed' /
// 'empty', so a crashed run can re-enter and pick up where it stopped.
async function extractPendingPdfText(deps, opts) {
    const { pool, r2Client, r2Bucket, log = console } = deps;
    const { limit = 0, concurrency = 4 } = opts || {};
    if (!pool || !r2Client || !r2Bucket) {
        throw new Error('extractPendingPdfText requires { pool, r2Client, r2Bucket }');
    }

    _job.phase = 'pdf_text';

    // Stream rows in pages so we don't hold millions of UUIDs in memory.
    const pageSize = 200;
    let offset = 0;
    let processed = 0;

    // pdf-parse loaded lazily so the metadata pass can run without it loaded
    // (helpful when a future deployment wants a metadata-only quick reindex).
    const pdfParse = require('pdf-parse');

    while (true) {
        if (limit && processed >= limit) break;

        const r = await pool.query(
            `SELECT id, r2_key, filename
               FROM assistant_file_index
              WHERE text_status = 'pending'
                AND file_ext = 'pdf'
              ORDER BY indexed_at DESC
              LIMIT $1`,
            [pageSize]
        );
        const rows = r.rows;
        if (!rows.length) break;

        // Concurrency-limited fan-out. Plain Promise.all on `concurrency`
        // slices avoids pulling in p-limit just for this.
        for (let i = 0; i < rows.length; i += concurrency) {
            const slice = rows.slice(i, i + concurrency);
            await Promise.all(slice.map(row => _processOnePdf(pool, r2Client, r2Bucket, row, pdfParse, log)));
            processed += slice.length;
            if (limit && processed >= limit) break;
        }

        // If the page came back full, we're not done — loop again. The
        // WHERE clause naturally advances since each row leaves 'pending',
        // so we don't need to track an offset.
        offset += rows.length;
        if (rows.length < pageSize) break;
    }

    log.info && log.info('[INDEXER] PDF text pass complete:', JSON.stringify(_job.counts));
}

async function _processOnePdf(pool, r2Client, r2Bucket, row, pdfParse, log) {
    _job.counts.text_processed += 1;

    // Outer guard: NO single PDF can ever bubble an error out of this
    // function. Anything we don't explicitly handle below lands in the
    // bottom catch and gets recorded as a failed row, so the text pass
    // continues and remains resumable. The earlier UTF-8 NUL crash
    // (text_processed=24, then aborted) was caused by an uncaught DB
    // write — that path is now covered.
    try {
        let buffer;
        try {
            buffer = await downloadObject(r2Client, r2Bucket, row.r2_key);
        } catch (e) {
            await _markFailed(pool, row, 'r2_download_failed', e, log);
            return;
        }

        let parsed;
        try {
            parsed = await pdfParse(buffer);
        } catch (e) {
            await _markFailed(pool, row, 'pdf_parse_failed', e, log);
            return;
        }

        const raw = (parsed.text || '').replace(/\s+\n/g, '\n');
        // Sanitize before ANY DB write — strips NUL (which Postgres rejects
        // under UTF-8) and replaces other ASCII control chars with spaces so
        // word boundaries survive. If the result is empty we mark the file
        // 'empty', not 'ready', per the brief.
        const sanitized = sanitizeExtractedText(raw);
        if (!sanitized) {
            await _safeMark(pool, row, {
                status: 'empty',
                preview: null,
                charCount: 0,
                full: null
            }, log);
            _job.counts.text_empty += 1;
            return;
        }

        const fullClipped = sanitized.length > FULL_TEXT_CHARS
            ? sanitized.slice(0, FULL_TEXT_CHARS)
            : sanitized;
        const preview = sanitized.slice(0, PREVIEW_CHARS);

        // pages_json is intentionally not populated in Phase 1 (pdf-parse
        // returns whole-doc text only). When per-page extraction is added in
        // a later phase, sanitize each page's text the same way before
        // packing it into the JSONB payload.

        try {
            await _markText(pool, row.id, row.r2_key, {
                status: 'ready',
                preview,
                charCount: sanitized.length,
                full: fullClipped
            });
            _job.counts.text_ready += 1;
        } catch (e) {
            // Sanitization should have prevented this, but if a DB write
            // still fails (constraint violation, transient pool error,
            // etc.), demote the file to 'failed' so the run keeps moving.
            await _markFailed(pool, row, 'db_write_failed', e, log);
        }
    } catch (e) {
        // Any path we didn't explicitly catch — keep the job alive.
        await _markFailed(pool, row, 'unexpected', e, log);
    }
}

// _markFailed flips text_status to 'failed' on the index row WITHOUT writing
// any text columns, so it can recover even when the original failure was a
// text-encoding issue. Best-effort: if even this DB write fails (extremely
// unlikely — no text columns are touched), we log and let the row stay
// 'pending'. The next reindex run will retry it cleanly.
async function _markFailed(pool, row, kind, err, log) {
    log.warn && log.warn('[INDEXER] ' + kind + ' for', row.r2_key, '—', err && err.message);
    try {
        await _markText(pool, row.id, row.r2_key, {
            status: 'failed',
            preview: null,
            charCount: 0,
            full: null
        });
    } catch (e) {
        log.error && log.error('[INDEXER] could not stamp failed for', row.r2_key, '—', e && e.message);
    }
    _job.counts.text_failed += 1;
}

// Same idea for non-failure paths (empty / ready) where we still want
// per-file resilience: if the marker DB write itself throws, log and move on
// rather than letting it abort the page.
async function _safeMark(pool, row, payload, log) {
    try {
        await _markText(pool, row.id, row.r2_key, payload);
    } catch (e) {
        log.error && log.error('[INDEXER] could not stamp ' + payload.status + ' for', row.r2_key, '—', e && e.message);
    }
}

// Atomic update: write assistant_file_text + flip text_status on the index
// row in one transaction so they never disagree.
async function _markText(pool, fileId, r2Key, payload) {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        if (payload.status === 'ready') {
            await client.query(
                `INSERT INTO assistant_file_text (file_id, r2_key, full_text, indexed_at)
                 VALUES ($1, $2, $3, NOW())
                 ON CONFLICT (file_id) DO UPDATE
                   SET full_text  = EXCLUDED.full_text,
                       r2_key     = EXCLUDED.r2_key,
                       indexed_at = NOW()`,
                [fileId, r2Key, payload.full]
            );
        } else {
            // For failed/empty we still drop any stale text row so /search
            // doesn't return outdated content for this file.
            await client.query(
                `DELETE FROM assistant_file_text WHERE file_id = $1`,
                [fileId]
            );
        }
        await client.query(
            `UPDATE assistant_file_index
                SET text_status = $1,
                    text_preview = $2,
                    text_char_count = $3,
                    text_extracted_at = NOW()
              WHERE id = $4`,
            [payload.status, payload.preview, payload.charCount, fileId]
        );
        await client.query('COMMIT');
    } catch (e) {
        try { await client.query('ROLLBACK'); } catch (_) {}
        throw e;
    } finally {
        client.release();
    }
}

// ------------------------------------------------------------------------
// Top-level orchestrator. Used by the API reindex endpoint and the CLI.
// ------------------------------------------------------------------------
async function runJob(deps, opts) {
    const log = (deps && deps.log) || console;
    if (_job.state === 'running') {
        return { ok: false, error: 'already_running', job: getJobStatus() };
    }
    _resetJob();
    try {
        if (opts && opts.metadataOnly) {
            await indexAllFromR2(deps, opts);
        } else if (opts && opts.textOnly) {
            await extractPendingPdfText(deps, opts);
        } else {
            await indexAllFromR2(deps, opts);
            await extractPendingPdfText(deps, opts);
        }
        _job.state = 'done';
        _job.phase = null;
        _job.finished_at = new Date().toISOString();
        log.info && log.info('[INDEXER] Job complete:', JSON.stringify(_job.counts));
    } catch (e) {
        _job.state = 'failed';
        _job.error = String(e && e.message || e);
        _job.finished_at = new Date().toISOString();
        log.error && log.error('[INDEXER] Job failed:', _job.error);
    }
    return { ok: _job.state === 'done', job: getJobStatus() };
}

module.exports = {
    runJob,
    getJobStatus,
    indexAllFromR2,
    extractPendingPdfText,
    // Exposed for unit-style ad-hoc testing only:
    inferWorkspaceSlug,
    inferAffiliation,
    inferSourceArea,
    inferYear,
    inferFileType,
    inferStatus,
    fileExtOf,
};
