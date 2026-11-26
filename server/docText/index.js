'use strict';
// GLP Vision R2.2 — best-effort document-text indexing for new uploads.
//
// - Feature flag DOC_TEXT_INDEX_ENABLED (default OFF): when off, nothing runs, nothing is copied.
// - Bytes come only from the upload request already in memory. No R2 access, no retry from storage.
// - One worker thread per job, concurrency 1, explicit timeout + heap limit.
// - Bounded in-memory waiting queue (jobs + bytes). Overflow is recorded as failed/QUEUE_FULL.
// - The DB rows record job status only; they are NOT a durable PDF queue. Jobs that were pending
//   or processing when the process stopped are marked 'interrupted' at startup and stay unindexed.
// - Pages + final status are written in one transaction; 'ok' is never visible without its pages.
// - Never throws into callers.

const path = require('path');
const { Worker } = require('worker_threads');

const envInt = (k, d) => { const v = parseInt(process.env[k], 10); return Number.isFinite(v) && v > 0 ? v : d; };
const CFG = {
    maxQueueJobs:  envInt('DOC_TEXT_MAX_QUEUE_JOBS', 20),
    maxQueueBytes: envInt('DOC_TEXT_MAX_QUEUE_MB', 100) * 1024 * 1024,
    baseTimeoutMs: envInt('DOC_TEXT_TIMEOUT_MS', 30000),
    perMbTimeoutMs: envInt('DOC_TEXT_TIMEOUT_PER_MB_MS', 3000),
    heapMb:        envInt('DOC_TEXT_WORKER_HEAP_MB', 256),
    maxPages:      envInt('DOC_TEXT_MAX_PAGES', 1000),
    maxChars:      envInt('DOC_TEXT_MAX_CHARS', 5000000),
};

const isEnabled = () => /^(1|true|on|yes)$/i.test(String(process.env.DOC_TEXT_INDEX_ENABLED || ''));

// Documents whose text may be exposed by search (used by R2.3 queries and the stale purge).
const VISIBLE_SUBMISSION_SQL =
    `s.r2_object_key IS NOT NULL AND s.status NOT IN ('REVISION_NEEDED','DISCARDED')`;

let pool = null, ready = null, running = false, queuedBytes = 0;
const queue = [];
const queuedIds = new Set();
const stats = { enqueued: 0, rejected: 0, done: 0 };

const sanitize = (m) => String(m || '').replace(/(\/[\w.@-]+)+/g, '[path]').replace(/\s+/g, ' ').slice(0, 200);
const log = (...a) => console.log('[docText]', ...a);

async function tablesReady() {
    const r = await pool.query(`SELECT to_regclass('public.di_doc_text_index') IS NOT NULL AS a,
                                       to_regclass('public.di_doc_text_pages') IS NOT NULL AS b`);
    return !!(r.rows[0].a && r.rows[0].b);
}

// Call once at startup. No-op (no DB access) when the flag is off.
function init(pgPool) {
    pool = pgPool;
    if (!isEnabled()) return Promise.resolve(false);
    ready = (async () => {
        try {
            if (!(await tablesReady())) { log('tables missing; indexing inactive'); return false; }
            const r = await pool.query(
                `UPDATE di_doc_text_index SET status='interrupted', error_code='PROCESS_RESTART',
                        error_message='Process stopped before indexing finished; PDF bytes no longer available',
                        finished_at=NOW()
                  WHERE status IN ('pending','processing')`);
            if (r.rowCount) log(`marked ${r.rowCount} interrupted job(s)`);
            await purgeStale();
            return true;
        } catch (e) { log('init failed; indexing inactive:', sanitize(e.message)); return false; }
    })();
    return ready;
}

async function purgeStale() {
    try {
        const r = await pool.query(
            `DELETE FROM di_doc_text_index i USING di_submissions s
              WHERE s.submission_id = i.submission_id AND NOT (${VISIBLE_SUBMISSION_SQL})`);
        if (r.rowCount) log(`purged ${r.rowCount} stale index row(s)`);
    } catch (e) { log('purge failed:', sanitize(e.message)); }
}

async function setStatus(id, status, code, message) {
    await pool.query(
        `UPDATE di_doc_text_index SET status=$2, error_code=$3, error_message=$4, finished_at=NOW()
          WHERE submission_id=$1`, [id, status, code || null, message ? sanitize(message) : null]);
}

// Hook for upload routes. Synchronous, cheap, never throws. Returns a short reason string.
function enqueueFromUpload(submissionId, buffer, source = 'server_upload') {
    try {
        if (!isEnabled() || !pool || !ready) return 'disabled';
        if (!submissionId || !Buffer.isBuffer(buffer) || buffer.length === 0) return 'invalid';
        if (queuedIds.has(submissionId)) return 'duplicate';
        // queuedIds covers staged + queued + running jobs; bytes are reserved until the worker takes them.
        const overflow = queuedIds.size >= CFG.maxQueueJobs || queuedBytes + buffer.length > CFG.maxQueueBytes;
        let job = null;
        if (!overflow) {
            // Own copy: the upload buffer may share a pooled ArrayBuffer and stays with the request.
            job = { id: submissionId, data: Uint8Array.prototype.slice.call(buffer), source };
            queuedBytes += job.data.byteLength; queuedIds.add(submissionId); stats.enqueued++;
        } else stats.rejected++;
        setImmediate(() => {
            register(submissionId, source, job).catch(e => { if (job) release(job); log('register failed:', sanitize(e.message)); });
        });
        return overflow ? 'queue_full' : 'queued';
    } catch (e) { log('enqueue error:', sanitize(e.message)); return 'error'; }
}

async function register(id, source, job) {
    const overflow = !job;
    if (!(await ready)) { if (job) release(job); return; }
    // Duplicate prevention: one index row per submission (a submission's PDF never changes
    // except approval stamping, which is not hooked). Existing row => skip.
    const ins = await pool.query(
        `INSERT INTO di_doc_text_index (submission_id, status, source) VALUES ($1, $2, $3)
         ON CONFLICT (submission_id) DO NOTHING RETURNING submission_id`,
        [id, overflow ? 'failed' : 'pending', source]);
    if (!ins.rowCount) { if (job) release(job); return; }
    if (overflow) { await setStatus(id, 'failed', 'QUEUE_FULL', 'Indexing queue full at upload time'); return; }
    queue.push(job);   // only registered jobs enter the run queue
    pump();
}

function release(job) {
    if (job.data) { queuedBytes -= job.data.byteLength; job.data = null; }
    queuedIds.delete(job.id);
}

async function pump() {
    if (running) return;
    running = true;
    try {
        while (queue.length) {
            const job = queue.shift();
            const data = job.data;
            queuedBytes -= data.byteLength; job.data = null;   // buffer is transferred to the worker
            try { await processJob(job, data); }
            catch (e) { log('job error:', sanitize(e.message)); try { await setStatus(job.id, 'failed', 'INTERNAL', e.message); } catch (_) {} }
            finally { queuedIds.delete(job.id); stats.done++; }
        }
    } finally { running = false; }
}

function runWorker(data) {
    const timeoutMs = CFG.baseTimeoutMs + Math.ceil(data.byteLength / 1048576) * CFG.perMbTimeoutMs;
    return new Promise((resolve) => {
        let settled = false;
        const w = new Worker(path.join(__dirname, 'worker.js'), {
            workerData: { data: data.buffer, maxPages: CFG.maxPages, maxChars: CFG.maxChars },
            transferList: [data.buffer],
            resourceLimits: { maxOldGenerationSizeMb: CFG.heapMb, maxYoungGenerationSizeMb: 32 },
            stdout: true, stderr: true,                       // swallow worker console output
        });
        const finish = (r) => { if (settled) return; settled = true; clearTimeout(t); w.terminate().catch(() => {}); resolve(r); };
        const t = setTimeout(() => finish({ ok: false, code: 'TIMEOUT', error: `Extraction exceeded ${timeoutMs} ms` }), timeoutMs);
        w.once('message', (m) => finish(m.ok ? m : { ok: false, code: /invalid pdf|stream must have data|empty/i.test(m.error) ? 'INVALID_PDF' : 'EXTRACT_ERROR', error: m.error }));
        w.once('error', (e) => finish({ ok: false, code: e && e.code === 'ERR_WORKER_OUT_OF_MEMORY' ? 'MEMORY_LIMIT' : 'WORKER_ERROR', error: e && e.message }));
        w.once('exit', (c) => finish({ ok: false, code: 'WORKER_EXIT', error: `Worker exited (${c})` }));
    });
}

async function processJob(job, data) {
    const upd = await pool.query(
        `UPDATE di_doc_text_index SET status='processing', attempts=attempts+1, started_at=NOW()
          WHERE submission_id=$1 AND status='pending' RETURNING submission_id`, [job.id]);
    if (!upd.rowCount) return; // row removed/changed meanwhile (e.g. deleted submission)

    const r = await runWorker(data);
    if (!r.ok) {
        await setStatus(job.id, r.code === 'TIMEOUT' ? 'timeout' : 'failed', r.code, r.error);
        return;
    }
    const status = r.limit ? 'partial' : r.pageCount === 0 ? 'empty' : r.pages.length === 0 ? 'no_text' : 'ok';
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        const s = await client.query(
            `SELECT 1 FROM di_submissions s WHERE s.submission_id=$1 AND ${VISIBLE_SUBMISSION_SQL} FOR SHARE`, [job.id]);
        if (!s.rowCount) {   // revised/discarded/deleted while extracting: expose nothing
            await client.query('DELETE FROM di_doc_text_index WHERE submission_id=$1', [job.id]);
            await client.query('COMMIT');
            return;
        }
        await client.query('DELETE FROM di_doc_text_pages WHERE submission_id=$1', [job.id]);
        for (const p of r.pages) {
            await client.query(
                `INSERT INTO di_doc_text_pages (submission_id, page_no, raw_text, norm_text, raw_word_offsets)
                 VALUES ($1,$2,$3,$4,$5)`, [job.id, p.pageNo, p.raw, p.norm, p.offsets]);
        }
        await client.query(
            `UPDATE di_doc_text_index SET status=$2, content_sha256=$3, extractor=$4, page_count=$5,
                    pages_indexed=$6, char_count=$7, error_code=$8, error_message=$9, finished_at=NOW()
              WHERE submission_id=$1`,
            [job.id, status, r.sha256, r.extractor, r.pageCount, r.pagesIndexed, r.chars,
             r.limit || null, r.limit ? `Indexed ${r.pagesIndexed} of ${r.pageCount} pages (${r.limit})` : null]);
        await client.query('COMMIT');
    } catch (e) {
        try { await client.query('ROLLBACK'); } catch (_) {}
        await setStatus(job.id, 'failed', 'DB_WRITE', e.message).catch(() => {});
    } finally { client.release(); }
}

function getState() {
    return { enabled: isEnabled(), inFlight: queuedIds.size, queued: queue.length, queuedBytes, running, ...stats, config: { ...CFG } };
}

module.exports = { init, enqueueFromUpload, purgeStale, getState, VISIBLE_SUBMISSION_SQL, _CFG: CFG };
