// services/assistantFileExtractor.js
//
// Zoe Phase 2 — file reading layer.
//
// Pipeline for one file in assistant_file_index:
//   1. Look up r2_key + filename + last file_hash + summary_ready.
//   2. Download bytes from R2 (deps.r2Client).
//   3. SHA-256 the buffer. If unchanged AND summary_ready=true, skip
//      (idempotent fast-path) unless caller passed { force: true }.
//   4. pdf-parse with a custom pagerender callback to capture per-page text.
//   5. Sanitise each page via the same helper Phase 1 uses (NUL-strip etc.).
//   6. Build chunks (~2200 chars each, page tracking).
//   7. Build a deterministic rule-based summary (no LLM).
//   8. In one transaction: DELETE old pages/chunks/summary for this file_id,
//      INSERT new rows, UPSERT assistant_file_summaries, UPDATE the index
//      (text_status='ready', text_extracted_at, summary_ready, file_hash,
//      extraction_error=NULL, text_preview, text_char_count), and UPSERT
//      assistant_file_text.full_text so Phase 1 content search keeps
//      finding the file.
//
// Failure paths stamp text_status='failed' + extraction_error so the row
// leaves 'pending' and the reindex job won't keep retrying it indefinitely.
// "empty" / "unsupported" use the same status vocabulary Phase 1 introduced.
//
// Deps shape (matches assistantFileIndexer.js for consistency):
//   { pool, r2Client, r2Bucket, log? }

'use strict';

const crypto = require('crypto');
const { GetObjectCommand } = require('@aws-sdk/client-s3');
const { sanitizeExtractedText } = require('./assistantFileIndexer');

// ---------------------------------------------------------------------------
// Tunables
// ---------------------------------------------------------------------------
// Target characters per chunk. Picked so an average chunk fits in ~500 tokens
// (rule of thumb 4 chars ≈ 1 token), small enough for downstream
// retrieval/ranking but large enough to retain context across paragraphs.
const CHUNK_TARGET_CHARS = 2200;
// Whole-document text cap when writing into assistant_file_text.full_text.
// Same value Phase 1 indexer uses; keeps one source-of-truth for that table.
const FULL_TEXT_CHARS = 500000;
// Preview cap on assistant_file_index.text_preview. Same as Phase 1 indexer.
const PREVIEW_CHARS = 600;

// ---------------------------------------------------------------------------
// R2 download (self-contained — assistantFileIndexer keeps its own copy too,
// matching the precedent rather than introducing a shared util module)
// ---------------------------------------------------------------------------
async function r2BodyToBuffer(body) {
    if (body == null) throw new Error('empty R2 body');
    if (Buffer.isBuffer(body)) return body;
    if (typeof body === 'string') return Buffer.from(body, 'utf8');
    if (body instanceof Uint8Array) return Buffer.from(body);
    if (typeof ArrayBuffer !== 'undefined' && body instanceof ArrayBuffer) {
        return Buffer.from(new Uint8Array(body));
    }
    if (typeof body.transformToByteArray === 'function') {
        return Buffer.from(await body.transformToByteArray());
    }
    if (typeof body.pipe === 'function' || typeof body[Symbol.asyncIterator] === 'function') {
        const chunks = [];
        for await (const chunk of body) {
            chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
        }
        return Buffer.concat(chunks);
    }
    throw new Error('Unsupported R2 body type');
}

async function downloadObject(r2Client, r2Bucket, key) {
    const out = await r2Client.send(new GetObjectCommand({ Bucket: r2Bucket, Key: key }));
    return r2BodyToBuffer(out.Body);
}

function sha256Hex(buffer) {
    return crypto.createHash('sha256').update(buffer).digest('hex');
}

// ---------------------------------------------------------------------------
// PDF per-page extraction
// ---------------------------------------------------------------------------
// pdf-parse accepts a `pagerender` callback that's invoked once per page in
// document order. We use it to capture each page's text into an array while
// still letting pdf-parse compose its overall .text field. Same approach as
// the official pdf-parse docs but adapted to keep page text available.
async function extractPagesFromPdf(buffer) {
    const pdfParse = require('pdf-parse');
    const pages = [];
    const pagerender = async (pageData) => {
        const tc = await pageData.getTextContent({
            normalizeWhitespace: false,
            disableCombineTextItems: false
        });
        let text = '';
        let lastY;
        for (const item of tc.items) {
            if (lastY === item.transform[5] || !lastY) {
                text += item.str;
            } else {
                text += '\n' + item.str;
            }
            lastY = item.transform[5];
        }
        pages.push(text);
        return text;
    };
    const parsed = await pdfParse(buffer, { pagerender });
    return { pages, numpages: parsed && parsed.numpages || pages.length };
}

// ---------------------------------------------------------------------------
// Chunking — accumulate per-page text into ~CHUNK_TARGET_CHARS slices,
// tracking page_start / page_end per chunk. Pages bigger than the target
// get split into fixed-size pieces all attributed to the same page.
// ---------------------------------------------------------------------------
function chunkPages(pageRows, target) {
    target = target || CHUNK_TARGET_CHARS;
    const chunks = [];
    let buf = '';
    let pageStart = null;
    let pageEnd = null;

    function flush() {
        if (!buf) return;
        chunks.push({
            chunk_index: chunks.length,
            page_start: pageStart,
            page_end: pageEnd,
            chunk_text: buf,
            token_estimate: Math.ceil(buf.length / 4),
        });
        buf = '';
        pageStart = null;
        pageEnd = null;
    }

    for (const row of pageRows) {
        const text = row.text || '';
        if (!text) continue;
        const pn = row.page_number;

        // If a single page on its own is bigger than target, flush whatever's
        // in the buffer and emit fixed-size chunks for the long page itself.
        if (text.length > target) {
            flush();
            let pos = 0;
            while (pos < text.length) {
                const end = Math.min(pos + target, text.length);
                chunks.push({
                    chunk_index: chunks.length,
                    page_start: pn,
                    page_end: pn,
                    chunk_text: text.slice(pos, end),
                    token_estimate: Math.ceil((end - pos) / 4),
                });
                pos = end;
            }
            continue;
        }

        // Would adding this page overflow the target? Flush first.
        if (buf && (buf.length + 2 + text.length) > target) {
            flush();
        }
        if (!buf) {
            buf = text;
            pageStart = pn;
            pageEnd = pn;
        } else {
            buf += '\n\n' + text;
            pageEnd = pn;
        }
    }
    flush();
    return chunks;
}

// ---------------------------------------------------------------------------
// Rule-based summarisation — deterministic, no LLM.
// ---------------------------------------------------------------------------
const METHOD_KEYWORDS = [
    'incubated', 'incubation', 'measured', 'plate reader', 'cfu',
    'fluorescence', 'gfp', 'sonication', 'sonicated', 'centrifugation',
    'centrifuged', 'inoculation', 'inoculated', 'assay', 'protocol',
    'aliquot', 'aliquoted', 'pcr', 'qpcr', 'elisa', 'flow cytometry',
    'spectrometry', 'spectrophotometer', 'absorbance', 'od600', 'od 600',
    'plated', 'plating', 'colony forming', 'staining', 'fixed',
];
const RESULT_KEYWORDS = [
    'result', 'observed', 'observation', 'increase', 'decrease',
    'fold change', 'fold-change', 'fold increase', 'fold decrease',
    'cfu', 'fluorescence', 'signal', 'significant', 'p-value', 'p<',
    'control', 'showed', 'demonstrated', 'reduced', 'reduction',
    'compared to', 'higher', 'lower', 'detected', 'positive', 'negative',
];
// Order matters — multi-word phrases first so they aren't shadowed by their
// constituent single words.
const DATA_TYPE_KEYWORDS = [
    'gfp fluorescence', 'plate reader', 'flow cytometry', 'colony forming units',
    'cfu', 'gfp', 'od600', 'od 600', 'qpcr', 'rt-pcr', 'pcr',
    'microscopy', 'absorbance', 'turbidity', 'survival', 'toxicity',
    'imaging', 'fluorescence', 'staining', 'viability',
];

function splitSentences(text) {
    if (!text) return [];
    // Naive split on sentence-final punctuation followed by whitespace. Then
    // trim and keep sentences in a sensible length window (drop one-word
    // fragments and runaway captions).
    return text
        .split(/(?<=[.!?])\s+/)
        .map(s => s.trim())
        .filter(s => s.length >= 25 && s.length <= 600);
}

function pickMatching(sentences, keywords, limit) {
    const lower = keywords.map(k => k.toLowerCase());
    const hits = [];
    const seen = new Set();
    for (const s of sentences) {
        if (hits.length >= limit) break;
        const sLower = s.toLowerCase();
        if (lower.some(k => sLower.includes(k))) {
            const key = sLower.slice(0, 60);
            if (seen.has(key)) continue;
            seen.add(key);
            hits.push(s);
        }
    }
    return hits;
}

function detectDataTypes(text) {
    if (!text) return [];
    const lower = text.toLowerCase();
    const out = [];
    for (const k of DATA_TYPE_KEYWORDS) {
        if (lower.includes(k.toLowerCase()) && !out.includes(k)) out.push(k);
    }
    return out;
}

function summarize(fullText, filename) {
    if (!fullText) return null;
    const sentences = splitSentences(fullText);
    const methodSentences = pickMatching(sentences, METHOD_KEYWORDS, 5);
    const resultSentences = pickMatching(sentences, RESULT_KEYWORDS, 5);
    const dataTypes = detectDataTypes(fullText);

    // summary_short — 3 to 5 short sentences pulled from filename + first
    // meaningful sentences + the strongest method/result hit. Capped to keep
    // /indexed/:id responses bounded.
    const shortParts = [];
    if (filename) shortParts.push('File: ' + filename + '.');
    if (sentences.length > 0) shortParts.push(sentences.slice(0, 2).join(' '));
    if (methodSentences.length > 0) shortParts.push('Methods: ' + methodSentences[0]);
    if (resultSentences.length > 0) shortParts.push('Result: ' + resultSentences[0]);
    if (dataTypes.length > 0) shortParts.push('Data types: ' + dataTypes.slice(0, 4).join(', ') + '.');
    const summary_short = shortParts.join(' ').slice(0, 1500);

    // summary_detailed — first ~30 sentences of the document, joined.
    const summary_detailed = sentences.slice(0, 30).join(' ').slice(0, 5000);

    return {
        summary_short,
        summary_detailed,
        key_methods:    methodSentences.join(' — ').slice(0, 4000),
        key_results:    resultSentences.join(' — ').slice(0, 4000),
        key_data_types: dataTypes.join(', '),
        detected_entities: {},
        detected_assays:   dataTypes,
        detected_controls: [],
        detected_gaps:     [],
    };
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------
async function persistExtraction(pool, fileId, payload) {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');

        // Drop old extracted artefacts for this file_id so re-running is
        // idempotent. ON DELETE CASCADE on the FKs would kick in if we
        // deleted the index row, but we want to KEEP the index row and only
        // refresh the dependent tables.
        await client.query('DELETE FROM assistant_file_pages    WHERE file_id = $1', [fileId]);
        await client.query('DELETE FROM assistant_file_chunks   WHERE file_id = $1', [fileId]);
        await client.query('DELETE FROM assistant_file_summaries WHERE file_id = $1', [fileId]);

        // Insert pages — multi-row VALUES.
        if (payload.pages.length > 0) {
            const placeholders = [];
            const params = [];
            payload.pages.forEach((p, i) => {
                const base = i * 3;
                placeholders.push(`($${base + 1}, $${base + 2}, $${base + 3})`);
                params.push(fileId, p.page_number, p.text);
            });
            await client.query(
                `INSERT INTO assistant_file_pages (file_id, page_number, text)
                 VALUES ${placeholders.join(',')}`,
                params
            );
        }

        // Insert chunks — multi-row VALUES.
        if (payload.chunks.length > 0) {
            const placeholders = [];
            const params = [];
            payload.chunks.forEach((c, i) => {
                const base = i * 6;
                placeholders.push(`($${base + 1}, $${base + 2}, $${base + 3}, $${base + 4}, $${base + 5}, $${base + 6})`);
                params.push(fileId, c.chunk_index, c.page_start, c.page_end, c.chunk_text, c.token_estimate);
            });
            await client.query(
                `INSERT INTO assistant_file_chunks
                    (file_id, chunk_index, page_start, page_end, chunk_text, token_estimate)
                 VALUES ${placeholders.join(',')}`,
                params
            );
        }

        // UPSERT summary. The DELETE above means INSERT alone would suffice,
        // but ON CONFLICT keeps the path safe under concurrent re-extracts.
        const s = payload.summary || {};
        await client.query(
            `INSERT INTO assistant_file_summaries
                (file_id, summary_short, summary_detailed, key_methods, key_results,
                 key_data_types, detected_entities, detected_assays,
                 detected_controls, detected_gaps, updated_at)
             VALUES ($1, $2, $3, $4, $5, $6, $7::jsonb, $8::jsonb, $9::jsonb, $10::jsonb, NOW())
             ON CONFLICT (file_id) DO UPDATE SET
                summary_short     = EXCLUDED.summary_short,
                summary_detailed  = EXCLUDED.summary_detailed,
                key_methods       = EXCLUDED.key_methods,
                key_results       = EXCLUDED.key_results,
                key_data_types    = EXCLUDED.key_data_types,
                detected_entities = EXCLUDED.detected_entities,
                detected_assays   = EXCLUDED.detected_assays,
                detected_controls = EXCLUDED.detected_controls,
                detected_gaps     = EXCLUDED.detected_gaps,
                updated_at        = NOW()`,
            [
                fileId,
                s.summary_short || null,
                s.summary_detailed || null,
                s.key_methods || null,
                s.key_results || null,
                s.key_data_types || null,
                JSON.stringify(s.detected_entities || {}),
                JSON.stringify(s.detected_assays   || []),
                JSON.stringify(s.detected_controls || []),
                JSON.stringify(s.detected_gaps     || []),
            ]
        );

        // Refresh assistant_file_text.full_text so Phase 1 content search
        // (which reads t.full_text ILIKE …) keeps working post-extraction.
        // Same upsert pattern Phase 1 uses.
        await client.query(
            `INSERT INTO assistant_file_text (file_id, r2_key, full_text, indexed_at)
             VALUES ($1, $2, $3, NOW())
             ON CONFLICT (file_id) DO UPDATE SET
                r2_key     = EXCLUDED.r2_key,
                full_text  = EXCLUDED.full_text,
                indexed_at = NOW()`,
            [fileId, payload.r2_key, payload.full_text]
        );

        // Final UPDATE on the index row. Reusing text_status='ready' and
        // text_extracted_at instead of duplicating their semantics with
        // text_extracted/extracted_at columns we agreed to skip.
        await client.query(
            `UPDATE assistant_file_index SET
                text_status       = 'ready',
                text_extracted_at = NOW(),
                summary_ready     = TRUE,
                file_hash         = $2,
                extraction_error  = NULL,
                text_preview      = $3,
                text_char_count   = $4
              WHERE id = $1`,
            [fileId, payload.file_hash, payload.text_preview, payload.text_char_count]
        );

        await client.query('COMMIT');
    } catch (e) {
        try { await client.query('ROLLBACK'); } catch (_) {}
        throw e;
    } finally {
        client.release();
    }
}

// Stamp a soft-fail status on the index without touching the dependent
// tables. Used when we couldn't even extract text (R2 download failed,
// pdf-parse threw, etc.). Best-effort: if even this query fails, we log
// and bail — the row stays however it was, and the next extract attempt
// will retry from scratch.
async function markFailure(pool, fileId, status, errMsg, log) {
    try {
        await pool.query(
            `UPDATE assistant_file_index SET
                text_status      = $2,
                summary_ready    = FALSE,
                extraction_error = $3
              WHERE id = $1`,
            [fileId, status, (errMsg || '').slice(0, 1000)]
        );
    } catch (e) {
        if (log && log.error) log.error('[EXTRACTOR] could not mark', status, 'for', fileId, e.message);
    }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------
async function extractOne(deps, fileId, opts) {
    opts = opts || {};
    const { pool, r2Client, r2Bucket, log = console } = deps;
    if (!pool || !r2Client || !r2Bucket) {
        throw new Error('extractOne requires { pool, r2Client, r2Bucket }');
    }
    const force = !!opts.force;

    // 1. Look up the file. We need r2_key + filename + the prior file_hash
    //    so we can short-circuit when nothing has changed.
    const r = await pool.query(
        `SELECT id, r2_key, filename, file_ext, file_hash, summary_ready
           FROM assistant_file_index
          WHERE id = $1
          LIMIT 1`,
        [fileId]
    );
    if (r.rows.length === 0) {
        const err = new Error('File not found in index');
        err.status = 404;
        throw err;
    }
    const row = r.rows[0];

    // 2. Non-PDFs are intentionally out of scope for Phase 2. Mark
    //    'unsupported' (matches the indexer's vocabulary) and bail. The
    //    front end can show "no extracted text" and move on.
    if ((row.file_ext || '').toLowerCase() !== 'pdf') {
        await markFailure(pool, fileId, 'unsupported',
                          'file_ext=' + (row.file_ext || 'unknown'), log);
        return {
            ok: false,
            file_id: fileId,
            filename: row.filename,
            text_status: 'unsupported',
            page_count: 0,
            chunk_count: 0,
            summary_ready: false,
            reason: 'unsupported_file_type',
        };
    }

    // 3. Download from R2.
    let buffer;
    try {
        buffer = await downloadObject(r2Client, r2Bucket, row.r2_key);
    } catch (e) {
        await markFailure(pool, fileId, 'failed', 'r2_download: ' + e.message, log);
        const err = new Error('R2 download failed: ' + e.message);
        err.cause = e;
        throw err;
    }

    // 4. Hash + skip-if-unchanged.
    const file_hash = sha256Hex(buffer);
    if (!force && row.file_hash === file_hash && row.summary_ready) {
        return {
            ok: true,
            skipped: true,
            file_id: fileId,
            filename: row.filename,
            file_hash,
            text_status: 'ready',
            summary_ready: true,
            reason: 'hash_unchanged',
        };
    }

    // 5. Per-page extraction.
    let pages;
    try {
        const out = await extractPagesFromPdf(buffer);
        pages = out.pages;
    } catch (e) {
        await markFailure(pool, fileId, 'failed', 'pdf_parse: ' + e.message, log);
        const err = new Error('pdf-parse failed: ' + e.message);
        err.cause = e;
        throw err;
    }

    // 6. Sanitise per page.
    const sanitizedPages = pages.map((text, i) => ({
        page_number: i + 1,
        text: sanitizeExtractedText(text),
    }));
    const nonEmptyPages = sanitizedPages.filter(p => p.text);
    const fullTextRaw = nonEmptyPages.map(p => p.text).join('\n\n').replace(/\s+\n/g, '\n').trim();

    // 7. Empty PDF (scanned / image-only) — we have a hash but no text.
    if (!fullTextRaw) {
        await pool.query(
            `UPDATE assistant_file_index SET
                text_status      = 'empty',
                summary_ready    = FALSE,
                file_hash        = $2,
                extraction_error = NULL,
                text_preview     = NULL,
                text_char_count  = 0
              WHERE id = $1`,
            [fileId, file_hash]
        );
        return {
            ok: false,
            file_id: fileId,
            filename: row.filename,
            file_hash,
            text_status: 'empty',
            page_count: pages.length,
            chunk_count: 0,
            summary_ready: false,
            reason: 'scanned_pdf_or_unreadable',
        };
    }

    // 8. Build chunks.
    const chunks = chunkPages(nonEmptyPages, CHUNK_TARGET_CHARS);

    // 9. Summarise.
    const summary = summarize(fullTextRaw, row.filename) || {};

    // 10. Persist all of it atomically.
    const fullTextClipped = fullTextRaw.length > FULL_TEXT_CHARS
        ? fullTextRaw.slice(0, FULL_TEXT_CHARS)
        : fullTextRaw;
    const text_preview = fullTextRaw.slice(0, PREVIEW_CHARS);
    const text_char_count = fullTextRaw.length;

    try {
        await persistExtraction(pool, fileId, {
            r2_key:        row.r2_key,
            pages:         nonEmptyPages,
            chunks,
            summary,
            full_text:     fullTextClipped,
            file_hash,
            text_preview,
            text_char_count,
        });
    } catch (e) {
        await markFailure(pool, fileId, 'failed', 'persist: ' + e.message, log);
        throw e;
    }

    return {
        ok: true,
        file_id:         fileId,
        filename:        row.filename,
        file_hash,
        text_status:     'ready',
        summary_ready:   true,
        page_count:      nonEmptyPages.length,
        chunk_count:     chunks.length,
        text_char_count,
    };
}

module.exports = {
    extractOne,
    // Exposed so /search-text and tests can use the same helpers without
    // pulling pdf-parse into other modules.
    chunkPages,
    summarize,
    splitSentences,
    detectDataTypes,
    sha256Hex,
    CHUNK_TARGET_CHARS,
    FULL_TEXT_CHARS,
    PREVIEW_CHARS,
};
