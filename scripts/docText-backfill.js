#!/usr/bin/env node
'use strict';
// GLP Vision — one-off historical document-text backfill (R2.5). Run manually from an operator's Mac.
//
// Reads approved NAT-Lab PDFs (inventory from PostgreSQL metadata, never an R2 listing), one at a
// time, extracts text with the SAME worker/normalization as upload indexing, and writes ONLY to
// di_doc_text_index / di_doc_text_pages. Never modifies submission records.
//
// Safety (enforced, not assumed):
//  - Database: must connect as a restricted role (see --print-role-sql). At startup the tool refuses
//    to run if that role can INSERT/UPDATE/DELETE/TRUNCATE di_submissions, owns it, or is superuser.
//    It never takes row locks on di_submissions (those need UPDATE privilege): identity is checked
//    inside the write transaction and re-checked after commit; search additionally hides any
//    document that is no longer visible.
//  - R2: dedicated read-only token via BACKFILL_R2_* variables; the service's R2_* credentials must
//    NOT be present. The client exposes a single getObject(); only GetObjectCommand is ever sent.
//    No listing, writing, copying or deleting exists in this file.
//  - No PDF is written to disk. Bytes live in memory only until the worker has them.
//  - Single instance (advisory lock). Claims use a unique token, so upload indexing and a stale
//    or concurrent run can never overwrite each other's rows.
//
// Usage: node scripts/docText-backfill.js --help

const path = require('path');
const fs = require('fs');
const os = require('os');
const crypto = require('crypto');

const ROOT = path.join(__dirname, '..');
const { Pool } = require(path.join(ROOT, 'node_modules', 'pg'));
const docText = require(path.join(ROOT, 'server', 'docText'));
const { normalizeQuery } = require(path.join(ROOT, 'server', 'docText', 'normalize'));
const { identifierVariants } = require(path.join(ROOT, 'server', 'docText', 'search'));

const SOURCE = 'backfill_r2';
const LOCK_KEY = 72026005;                     // pg advisory lock: one backfill at a time
const ROLE_SQL = `-- Run as the database owner/admin (production prerequisite). Replace the password.
CREATE ROLE glp_backfill LOGIN PASSWORD '<strong-random-password>' NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT;
GRANT CONNECT ON DATABASE railway TO glp_backfill;              -- adjust database name if different
GRANT USAGE ON SCHEMA public TO glp_backfill;
GRANT SELECT (submission_id, status, r2_object_key, signed_at, workspace_id, report_thread_role,
              file_type, original_filename) ON di_submissions TO glp_backfill;
GRANT SELECT (id, slug) ON workspaces TO glp_backfill;
GRANT SELECT, INSERT, UPDATE, DELETE ON di_doc_text_index, di_doc_text_pages TO glp_backfill;
-- Nothing else. No UPDATE/INSERT/DELETE on di_submissions or any other table.
-- After the backfill:  DROP ROLE glp_backfill;   (after REVOKE ALL / REASSIGN if required)`;

// ---------------------------------------------------------------- CLI
function parseArgs(argv) {
    const a = { dryRun: false, limit: 0, ids: null, types: null, retryFailed: false, maxAttempts: 2, delayMs: 250,
        maxMb: 25, staleMinutes: 15, healthUrl: null, log: null, mockR2Dir: null, verify: null };
    for (let i = 0; i < argv.length; i++) {
        const k = argv[i], v = () => argv[++i];
        if (k === '--dry-run') a.dryRun = true;
        else if (k === '--limit') a.limit = parseInt(v(), 10) || 0;
        else if (k === '--ids') a.ids = v().split(',').map(x => x.trim()).filter(Boolean);
        else if (k === '--ids-file') a.ids = fs.readFileSync(v(), 'utf8').split(/\s+/).filter(Boolean);
        else if (k === '--types') a.types = v().split(',').map(x => x.trim().toUpperCase());
        else if (k === '--retry-failed') a.retryFailed = true;
        else if (k === '--max-attempts') a.maxAttempts = parseInt(v(), 10) || 2;
        else if (k === '--delay-ms') a.delayMs = parseInt(v(), 10) || 0;
        else if (k === '--max-mb') a.maxMb = parseInt(v(), 10) || 25;
        else if (k === '--stale-minutes') a.staleMinutes = Math.max(0, parseInt(v(), 10));
        else if (k === '--health-url') a.healthUrl = v();
        else if (k === '--log') a.log = v();
        else if (k === '--mock-r2-dir') a.mockR2Dir = v();
        else if (k === '--verify') a.verify = v();
        else if (k === '--env-file') a.envFile = v();
        else if (k === '--print-role-sql') { console.log(ROLE_SQL); process.exit(0); }
        else if (k === '--help' || k === '-h') { console.log(HELP); process.exit(0); }
        else throw new Error('Unknown option ' + k);
    }
    return a;
}
const HELP = `GLP Vision historical backfill (read-only R2, writes only derived index tables)
Env:  BACKFILL_DATABASE_URL   restricted role (see --print-role-sql)
      BACKFILL_R2_ENDPOINT, BACKFILL_R2_BUCKET, BACKFILL_R2_ACCESS_KEY_ID, BACKFILL_R2_SECRET_ACCESS_KEY  (read-only token)
Options:
  --dry-run              privilege checks + inventory only (no R2, no writes)
  --limit N              process at most N documents this run
  --ids a,b | --ids-file f   explicit allowlist of submission_ids
  --types DATA,SOP,...   restrict file types
  --retry-failed         also retry failed/timeout/interrupted rows (attempts < --max-attempts, default 2)
  --delay-ms N           pause between documents (default 250)
  --max-mb N             refuse objects larger than N MB (default 25)
  --stale-minutes N      reclaim this tool's 'processing' rows older than N minutes (default 15)
  --health-url URL       sample portal /health latency every 30 s; stop if > 2x baseline
  --log FILE             JSONL run log (default ~/glp-backfill-logs/run-<time>.jsonl)
  --verify "t1|t2"       after the run, print hits/pages per processed document for these terms
  --env-file FILE        load the variables above from a chmod-600 file (keeps secrets out of shell history)
  --print-role-sql       print the restricted PostgreSQL role definition
TLS:  verified always. Default: certificate chain + hostname (system CAs, or BACKFILL_DB_CA_FILE=<pem>).
      For a self-signed proxy certificate: BACKFILL_DB_CERT_SHA256=<64 hex> (pinned; mismatch = refuse).
      sslmode=disable is accepted only for localhost / unix-socket test databases.`;

const sleep = ms => new Promise(r => setTimeout(r, ms));
const rssMb = () => Math.round(process.memoryUsage().rss / 1048576);
const SECRET_VARS = ['BACKFILL_DATABASE_URL', 'BACKFILL_R2_ACCESS_KEY_ID', 'BACKFILL_R2_SECRET_ACCESS_KEY'];
function sanitize(m) {   // never let URLs, passwords or keys reach the terminal or the log
    let t = String(m || '').replace(/postgres(ql)?:\/\/\S+/gi, '[db-url]');
    for (const k of SECRET_VARS) { const v = process.env[k]; if (v && v.length >= 4) t = t.split(v).join('[secret]'); }
    try { const pw = decodeURIComponent(new URL(process.env.BACKFILL_DATABASE_URL || '').password || ''); if (pw.length >= 4) t = t.split(pw).join('[secret]'); } catch (_) {}
    return t.replace(/(\/[\w.@-]+)+/g, '[path]').replace(/\s+/g, ' ').slice(0, 200);
}

// Identical to normalizeR2Key() in server.js (kept in sync; verified by the validation suite).
// Used ONLY for the retrieval key. The stored value is never changed and is what identity checks compare.
function normalizeR2Key(k) {
    if (!k) return null;
    return k.trim().replace(/^r2:/i, '').trim() || null;
}

// ---------------------------------------------------------------- credentials file (optional)
// KEY=VALUE lines; refused unless owned by the current user and not readable by group/others (chmod 600).
function loadEnvFile(file) {
    const st = fs.statSync(file);
    if ((st.mode & 0o077) !== 0) throw new Error(`Credentials file must be chmod 600 (current ${(st.mode & 0o777).toString(8)})`);
    if (typeof process.getuid === 'function' && st.uid !== process.getuid()) throw new Error('Credentials file must be owned by the current user');
    for (const line of fs.readFileSync(file, 'utf8').split(/\r?\n/)) {
        const m = /^\s*([A-Z0-9_]+)\s*=\s*(.*?)\s*$/.exec(line); if (!m || line.trim().startsWith('#')) continue;
        process.env[m[1]] = m[2].replace(/^(['"])(.*)\1$/, '$2');
    }
}

// ---------------------------------------------------------------- database TLS (no unverified mode)
// 1. Default: standard certificate-chain + hostname verification (system CAs, or BACKFILL_DB_CA_FILE).
// 2. BACKFILL_DB_CERT_SHA256 (pinning, for proxies with self-signed certificates): a credential-free
//    TLS probe (PostgreSQL SSLRequest) fetches the server chain and checks the leaf fingerprint; the
//    real connection then trusts exactly that chain and re-checks the fingerprint during the handshake,
//    so nothing (not even the startup message) is sent to a server with a different certificate.
//    Certificate rotation => mismatch => the tool refuses; obtain and independently confirm the new
//    fingerprint before updating BACKFILL_DB_CERT_SHA256. There is never a silent fallback.
// 3. Plain-text only for local test databases (localhost / unix socket) with sslmode=disable.
const normFp = f => String(f || '').replace(/[^0-9a-f]/gi, '').toUpperCase();
function probeServerChain(host, port, servername) {
    const net = require('net'), tls = require('tls');
    return new Promise((resolve, reject) => {
        const sock = net.connect({ host, port }); const done = (e, v) => { sock.destroy(); e ? reject(e) : resolve(v); };
        sock.setTimeout(10000, () => done(new Error('TLS probe timeout')));
        sock.once('error', e => done(e));
        sock.once('connect', () => sock.write(Buffer.from([0, 0, 0, 8, 0x04, 0xd2, 0x16, 0x2f])));   // SSLRequest
        sock.once('data', b => {
            if (b[0] !== 0x53) return done(new Error('Server does not offer TLS'));
            const t = tls.connect({ socket: sock, servername, rejectUnauthorized: false });   // probe only: no credentials, no data
            t.once('error', e => done(e));
            t.once('secureConnect', () => {
                const chain = []; let c = t.getPeerCertificate(true); const seen = new Set();
                while (c && c.raw && !seen.has(c.fingerprint256)) { seen.add(c.fingerprint256); chain.push(c); c = c.issuerCertificate; }
                t.destroy(); done(null, chain);
            });
        });
    });
}
const toPem = raw => `-----BEGIN CERTIFICATE-----\n${raw.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE-----\n`;
async function buildDbConfig(urlStr) {
    const u = new URL(urlStr);
    const sslmode = (u.searchParams.get('sslmode') || '').toLowerCase();
    const hostParam = u.searchParams.get('host');
    const local = (hostParam && hostParam.startsWith('/')) || ['localhost', '127.0.0.1', '::1', '[::1]'].includes(u.hostname);
    for (const k of [...u.searchParams.keys()]) if (/^ssl/i.test(k)) u.searchParams.delete(k);   // our ssl object is authoritative
    const connectionString = u.toString();
    if (sslmode === 'disable') {
        if (!local) throw new Error('sslmode=disable is only allowed for local test databases');
        return { connectionString, ssl: false, tls: 'disabled (local test database)' };
    }
    const host = u.hostname.replace(/^\[|\]$/g, ''), port = parseInt(u.port || '5432', 10);
    const servername = require('net').isIP(host) ? undefined : host;
    const pin = process.env.BACKFILL_DB_CERT_SHA256;
    if (pin) {
        const want = normFp(pin);
        if (want.length !== 64) throw new Error('BACKFILL_DB_CERT_SHA256 must be a SHA-256 fingerprint (64 hex digits)');
        const chain = await probeServerChain(host, port, servername);
        if (!chain.length || normFp(chain[0].fingerprint256) !== want) throw new Error('Database certificate does not match BACKFILL_DB_CERT_SHA256 (refusing to connect)');
        return { connectionString, tls: 'verified (pinned certificate)', ssl: {
            ca: chain.map(c => toPem(c.raw)), rejectUnauthorized: true, servername,
            checkServerIdentity: (_h, cert) => normFp(cert.fingerprint256) === want ? undefined : new Error('Database certificate fingerprint mismatch'),
        } };
    }
    // Always verify against the host actually connected to (Node would otherwise check "localhost" for IPs).
    const ssl = { rejectUnauthorized: true, servername, checkServerIdentity: (_h, cert) => require('tls').checkServerIdentity(host, cert) };
    if (process.env.BACKFILL_DB_CA_FILE) ssl.ca = fs.readFileSync(process.env.BACKFILL_DB_CA_FILE, 'utf8');
    return { connectionString, ssl, tls: process.env.BACKFILL_DB_CA_FILE ? 'verified (chain+hostname, CA file)' : 'verified (chain+hostname, system CAs)' };
}

// ---------------------------------------------------------------- R2 (read-only by construction)
function makeObjectReader(args) {
    const maxBytes = args.maxMb * 1048576;
    const ops = { get: 0 };
    if (args.mockR2Dir) {   // local validation only: object key -> file name in the directory
        return { ops, mock: true, async getObject(key) {
            ops.get++;
            const f = path.resolve(args.mockR2Dir, key);   // full object key under the mock directory
            if (!f.startsWith(path.resolve(args.mockR2Dir) + path.sep) || !fs.existsSync(f)) { const e = new Error('NoSuchKey'); e.name = 'NoSuchKey'; throw e; }
            const st = fs.statSync(f); if (st.size > maxBytes) { const e = new Error('Object too large'); e.name = 'TooLarge'; throw e; }
            const body = fs.readFileSync(f);
            return { body, etag: '"' + crypto.createHash('md5').update(body).digest('hex') + '"', contentLength: st.size };
        } };
    }
    const { S3Client, GetObjectCommand } = require(path.join(ROOT, 'node_modules', '@aws-sdk', 'client-s3'));
    const client = new S3Client({ region: 'auto', endpoint: process.env.BACKFILL_R2_ENDPOINT,
        credentials: { accessKeyId: process.env.BACKFILL_R2_ACCESS_KEY_ID, secretAccessKey: process.env.BACKFILL_R2_SECRET_ACCESS_KEY } });
    const Bucket = process.env.BACKFILL_R2_BUCKET;
    return { ops, mock: false, async getObject(key) {
        ops.get++;
        const r = await client.send(new GetObjectCommand({ Bucket, Key: key }));
        if (r.ContentLength && r.ContentLength > maxBytes) { r.Body.destroy && r.Body.destroy(); const e = new Error('Object too large'); e.name = 'TooLarge'; throw e; }
        const chunks = []; let n = 0;
        for await (const c of r.Body) { n += c.length; if (n > maxBytes) { r.Body.destroy && r.Body.destroy(); const e = new Error('Object too large'); e.name = 'TooLarge'; throw e; } chunks.push(c); }
        const body = Buffer.concat(chunks);
        if (r.ContentLength != null && r.ContentLength !== body.length) { const e = new Error('Truncated object'); e.name = 'Truncated'; throw e; }
        return { body, etag: r.ETag || null, contentLength: body.length };
    } };
}

// ---------------------------------------------------------------- safety checks
async function checkPrivileges(db) {
    const r = (await db.query(`SELECT current_user AS who,
        (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS superuser,
        pg_has_role(current_user, (SELECT relowner FROM pg_class WHERE oid = 'di_submissions'::regclass), 'USAGE') AS owns_submissions,
        has_table_privilege('di_submissions', 'INSERT') AS s_ins, has_table_privilege('di_submissions', 'UPDATE') AS s_upd,
        has_table_privilege('di_submissions', 'DELETE') AS s_del, has_table_privilege('di_submissions', 'TRUNCATE') AS s_trunc,
        has_any_column_privilege('di_submissions', 'UPDATE') AS s_col_upd,
        has_table_privilege('di_doc_text_index', 'INSERT') AND has_table_privilege('di_doc_text_index', 'UPDATE')
          AND has_table_privilege('di_doc_text_index', 'DELETE') AS idx_rw,
        has_table_privilege('di_doc_text_pages', 'INSERT') AND has_table_privilege('di_doc_text_pages', 'DELETE') AS pages_rw`)).rows[0];
    const problems = [];
    if (r.superuser) problems.push('role is superuser');
    if (r.owns_submissions) problems.push('role owns (or is member of the owner of) di_submissions');
    if (r.s_ins || r.s_upd || r.s_del || r.s_trunc || r.s_col_upd) problems.push('role can modify di_submissions');
    if (!r.idx_rw || !r.pages_rw) problems.push('role lacks write access to the derived index tables');
    return { who: r.who, ok: problems.length === 0, problems };
}

// ---------------------------------------------------------------- inventory (PostgreSQL metadata only)
async function inventory(db, args) {
    const p = [], P = v => { p.push(v); return '$' + p.length; };
    // .pdf test on the key as normalizeR2Key() will use it (trimmed), so eligibility matches retrieval.
    const w = [`w.slug = 'natlab'`, `s.status = 'APPROVED'`, `s.r2_object_key IS NOT NULL`,
               `lower(btrim(s.r2_object_key)) LIKE '%.pdf'`, `COALESCE(s.report_thread_role, '') <> 'NOTE'`];
    if (args.ids) w.push(`s.submission_id::text = ANY(${P(args.ids)})`);
    if (args.types) w.push(`s.file_type = ANY(${P(args.types)})`);
    const rows = (await db.query(`SELECT s.submission_id, s.r2_object_key, s.signed_at, s.original_filename, s.file_type,
            i.status AS idx_status, i.source AS idx_source, i.attempts, i.started_at
          FROM di_submissions s JOIN workspaces w ON w.id = s.workspace_id
          LEFT JOIN di_doc_text_index i ON i.submission_id = s.submission_id
         WHERE ${w.join(' AND ')} ORDER BY s.signed_at NULLS LAST, s.submission_id`, p)).rows;
    const staleBefore = Date.now() - args.staleMinutes * 60000;
    const plan = { todo: [], skipDone: 0, skipBusy: 0, skipFailed: 0, retry: 0, reclaim: 0 };
    for (const r of rows) {
        const st = r.idx_status;
        if (!st) { plan.todo.push(r); continue; }
        if (['ok', 'partial', 'no_text', 'empty'].includes(st)) { plan.skipDone++; continue; }
        if (st === 'pending' || st === 'processing') {
            // Only this tool's own stale claims are reclaimed; upload-indexing claims are never touched.
            if (r.idx_source === SOURCE && r.started_at && new Date(r.started_at).getTime() < staleBefore) { plan.reclaim++; plan.todo.push(r); }
            else plan.skipBusy++;
            continue;
        }
        if (args.retryFailed && r.attempts < args.maxAttempts) { plan.retry++; plan.todo.push(r); } else plan.skipFailed++;
    }
    if (args.limit) plan.todo = plan.todo.slice(0, args.limit);
    return { rows, plan };
}

// ---------------------------------------------------------------- claim / commit
async function claim(db, row, claimAt, staleMinutes) {
    // New row, or retake a retryable/own-stale row. Upload-indexing 'pending' rows never match.
    const r = await db.query(`
        INSERT INTO di_doc_text_index AS i (submission_id, status, source, attempts, started_at)
        VALUES ($1, 'processing', '${SOURCE}', 1, $2)
        ON CONFLICT (submission_id) DO UPDATE
           SET status = 'processing', source = '${SOURCE}', attempts = i.attempts + 1, started_at = $2,
               finished_at = NULL, error_code = NULL, error_message = NULL
         WHERE i.status IN ('failed', 'timeout', 'interrupted')
            OR (i.status = 'processing' AND i.source = '${SOURCE}' AND i.started_at < NOW() - make_interval(mins => $3))
        RETURNING i.submission_id`, [row.submission_id, claimAt, staleMinutes]);
    return r.rowCount === 1;
}
async function finishClaim(db, id, claimAt, status, code, message) {
    await db.query(`UPDATE di_doc_text_index SET status = $3, error_code = $4, error_message = $5, finished_at = NOW()
                     WHERE submission_id = $1 AND source = '${SOURCE}' AND started_at = $2`, [id, claimAt, status, code, message ? sanitize(message) : null]);
}
const IDENTITY_SQL = `SELECT 1 FROM di_submissions s JOIN workspaces w ON w.id = s.workspace_id
     WHERE s.submission_id = $1 AND w.slug = 'natlab' AND s.status = 'APPROVED'
       AND s.r2_object_key = $2 AND s.signed_at IS NOT DISTINCT FROM $3 AND COALESCE(s.report_thread_role, '') <> 'NOTE'`;

async function commitResult(db, row, claimAt, r) {
    const { status, code, message } = docText.deriveStatus(r);
    const c = await db.connect();
    try {
        await c.query('BEGIN');
        // Identity/version check WITHOUT row locks (restricted role has no UPDATE on di_submissions).
        if (!(await c.query(IDENTITY_SQL, [row.submission_id, row.r2_object_key, row.signed_at])).rowCount) {
            await c.query(`DELETE FROM di_doc_text_index WHERE submission_id = $1 AND source = '${SOURCE}' AND started_at = $2`, [row.submission_id, claimAt]);
            await c.query('COMMIT');
            return { status: 'skipped', code: 'IDENTITY_CHANGED' };
        }
        const own = await c.query(`SELECT 1 FROM di_doc_text_index WHERE submission_id = $1 AND source = '${SOURCE}' AND started_at = $2`, [row.submission_id, claimAt]);
        if (!own.rowCount) { await c.query('ROLLBACK'); return { status: 'skipped', code: 'CLAIM_LOST' }; }
        await c.query('DELETE FROM di_doc_text_pages WHERE submission_id = $1', [row.submission_id]);
        for (let k = 0; k < r.pages.length; k += 25) {          // batched multi-row inserts (WAN-friendly)
            const chunk = r.pages.slice(k, k + 25), vals = [], prm = [];
            chunk.forEach((pg, j) => { const b = j * 5; vals.push(`($${b + 1},$${b + 2},$${b + 3},$${b + 4},$${b + 5})`); prm.push(row.submission_id, pg.pageNo, pg.raw, pg.norm, pg.offsets); });
            await c.query(`INSERT INTO di_doc_text_pages (submission_id, page_no, raw_text, norm_text, raw_word_offsets) VALUES ${vals.join(',')}`, prm);
        }
        await c.query(`UPDATE di_doc_text_index SET status = $3, content_sha256 = $4, extractor = $5, page_count = $6, pages_indexed = $7,
                          char_count = $8, error_code = $9, error_message = $10, finished_at = NOW()
                        WHERE submission_id = $1 AND source = '${SOURCE}' AND started_at = $2`,
            [row.submission_id, claimAt, status, r.sha256, r.extractor, r.pageCount, r.pagesIndexed, r.chars, code, message]);
        await c.query('COMMIT');
    } catch (e) { try { await c.query('ROLLBACK'); } catch (_) {} throw e; } finally { c.release(); }
    // Post-commit re-check: if the submission changed meanwhile, withdraw our derived rows.
    if (!(await db.query(IDENTITY_SQL, [row.submission_id, row.r2_object_key, row.signed_at])).rowCount) {
        await db.query(`DELETE FROM di_doc_text_index WHERE submission_id = $1 AND source = '${SOURCE}' AND started_at = $2`, [row.submission_id, claimAt]);
        return { status: 'skipped', code: 'IDENTITY_CHANGED' };
    }
    return { status, code };
}

// ---------------------------------------------------------------- main
async function main() {
    const args = parseArgs(process.argv.slice(2));
    if (args.envFile) loadEnvFile(args.envFile);
    if (!process.env.BACKFILL_DATABASE_URL) throw new Error('BACKFILL_DATABASE_URL is required (restricted role)');
    if (process.env.R2_ACCESS_KEY_ID || process.env.R2_SECRET_ACCESS_KEY)
        throw new Error('Service R2 credentials (R2_ACCESS_KEY_ID/R2_SECRET_ACCESS_KEY) are present in this environment. Unset them; use the read-only BACKFILL_R2_* token.');
    if (!args.dryRun && !args.mockR2Dir && !['BACKFILL_R2_ENDPOINT', 'BACKFILL_R2_BUCKET', 'BACKFILL_R2_ACCESS_KEY_ID', 'BACKFILL_R2_SECRET_ACCESS_KEY'].every(k => process.env[k]))
        throw new Error('BACKFILL_R2_* variables are required (read-only token)');

    const dbc = await buildDbConfig(process.env.BACKFILL_DATABASE_URL);
    console.log(`Database TLS: ${dbc.tls}`);
    const db = new Pool({ connectionString: dbc.connectionString, ssl: dbc.ssl, max: 2 });
    const out = [];
    const logFile = args.log || path.join(os.homedir(), 'glp-backfill-logs', `run-${new Date().toISOString().replace(/[:.]/g, '-')}.jsonl`);
    fs.mkdirSync(path.dirname(logFile), { recursive: true });
    const log = (o) => { const line = JSON.stringify({ t: new Date().toISOString(), ...o }); fs.appendFileSync(logFile, line + '\n'); };

    const priv = await checkPrivileges(db);
    console.log(`DB role: ${priv.who} — ${priv.ok ? 'restricted (OK)' : 'REFUSED: ' + priv.problems.join('; ')}`);
    log({ event: 'privileges', ...priv });
    if (!priv.ok) { await db.end(); process.exitCode = 3; return; }

    const lock = await db.connect();
    if (!(await lock.query('SELECT pg_try_advisory_lock($1) AS ok', [LOCK_KEY])).rows[0].ok) {
        console.log('Another backfill run holds the lock. Exiting.'); lock.release(); await db.end(); process.exitCode = 4; return;
    }
    try {
        const { rows, plan } = await inventory(db, args);
        const prefixes = {}; for (const r of rows) { const k = r.r2_object_key.split('/').slice(0, 3).join('/'); prefixes[k] = (prefixes[k] || 0) + 1; }
        const types = {}; for (const r of rows) types[r.file_type] = (types[r.file_type] || 0) + 1;
        console.log(`Eligible approved NAT-Lab PDFs: ${rows.length}  by type ${JSON.stringify(types)}  by key prefix ${JSON.stringify(prefixes)}`);
        console.log(`Plan: process ${plan.todo.length}  | already indexed ${plan.skipDone} | busy (other claim) ${plan.skipBusy} | failed not retried ${plan.skipFailed} | retries ${plan.retry} | stale reclaims ${plan.reclaim}`);
        log({ event: 'plan', eligible: rows.length, types, prefixes, todo: plan.todo.length, skipDone: plan.skipDone, skipBusy: plan.skipBusy, skipFailed: plan.skipFailed, retry: plan.retry, reclaim: plan.reclaim, dryRun: args.dryRun });
        if (args.dryRun) {
            plan.todo.slice(0, 20).forEach(r => console.log(`  would process ${r.submission_id}  ${r.file_type.padEnd(12)} ${r.original_filename}`));
            console.log(`Dry run: no R2 access, no writes. Log: ${logFile}`); return;
        }

        const reader = makeObjectReader(args);
        let stop = null, sigints = 0, current = null;
        process.on('SIGINT', () => { sigints++; if (sigints === 1) { stop = 'SIGINT'; console.log('\nStopping after the current document (Ctrl+C again to abort now)…'); }
            else { console.log('Aborting.'); process.exit(130); } });

        // optional portal responsiveness monitor
        let health = null;
        if (args.healthUrl) {
            const sample = async () => { const t0 = Date.now(); try { await fetch(args.healthUrl, { signal: AbortSignal.timeout(10000) }); } catch (_) { return 10000; } return Date.now() - t0; };
            const base = [await sample(), await sample(), await sample()].sort((a, b) => a - b)[1];
            health = { base, last: base };
            const iv = setInterval(async () => { health.last = await sample(); log({ event: 'health', ms: health.last, base }); if (health.last > Math.max(2 * base, base + 300)) stop = stop || `HEALTH_LATENCY ${health.last}ms (baseline ${base}ms)`; }, 30000);
            iv.unref(); console.log(`Health baseline ${base} ms`);
        }

        let done = 0, failed = 0, consecFail = 0, consecTimeout = 0, peak = rssMb(); const t0 = Date.now();
        let lastClaim = 0;
        for (const row of plan.todo) {
            if (stop) break;
            lastClaim = Math.max(Date.now(), lastClaim + 1); const claimAt = new Date(lastClaim);   // unique claim token
            const started = Date.now();
            if (!(await claim(db, row, claimAt, args.staleMinutes))) { log({ event: 'skip', id: row.submission_id, code: 'NOT_CLAIMABLE' }); continue; }
            current = row.submission_id;
            let res, bytes = 0, etag = null;
            try {
                let obj;
                try { obj = await reader.getObject(normalizeR2Key(row.r2_object_key)); }   // stored key stays untouched
                catch (e) {
                    const code = e.name === 'NoSuchKey' ? 'R2_NOT_FOUND' : e.name === 'TooLarge' ? 'TOO_LARGE' : e.name === 'Truncated' ? 'R2_TRUNCATED' : 'R2_ERROR';
                    await finishClaim(db, row.submission_id, claimAt, 'failed', code, e.message);
                    res = { status: 'failed', code };
                    if (code === 'R2_ERROR' || code === 'R2_TRUNCATED') stop = `R2 error (${sanitize(e.name)}: ${sanitize(e.message)})`;
                }
                if (obj) {
                    bytes = obj.body.length; etag = obj.etag;
                    if (obj.body.subarray(0, 5).toString('latin1') !== '%PDF-') {
                        await finishClaim(db, row.submission_id, claimAt, 'failed', 'NOT_PDF', 'Object is not a PDF'); res = { status: 'failed', code: 'NOT_PDF' };
                    } else {
                        const data = Uint8Array.prototype.slice.call(obj.body); obj.body = null;   // own buffer, transferred to the worker
                        const r = await docText.runWorker(data);
                        if (!r.ok) {
                            const st = r.code === 'TIMEOUT' ? 'timeout' : 'failed';
                            await finishClaim(db, row.submission_id, claimAt, st, r.code, r.error); res = { status: st, code: r.code };
                        } else res = await commitResult(db, row, claimAt, r);
                    }
                }
            } catch (e) {
                res = { status: 'failed', code: 'DB_ERROR' };
                try { await finishClaim(db, row.submission_id, claimAt, 'failed', 'DB_ERROR', e.message); } catch (_) {}
                stop = 'Database error: ' + sanitize(e.message);
            }
            current = null; done++;
            const ms = Date.now() - started; peak = Math.max(peak, rssMb());
            const isFail = res.status === 'failed' || res.status === 'timeout';
            if (isFail) { failed++; consecFail++; } else consecFail = 0;
            consecTimeout = res.status === 'timeout' ? consecTimeout + 1 : 0;
            log({ event: 'doc', id: row.submission_id, file_type: row.file_type, status: res.status, code: res.code || null, bytes, etag, ms, rssMb: rssMb() });
            out.push({ id: row.submission_id, name: row.original_filename, status: res.status, code: res.code });
            console.log(`[${done}/${plan.todo.length}] ${res.status.padEnd(8)} ${(res.code || '').padEnd(16)} ${String(ms).padStart(6)} ms  ${String(rssMb()).padStart(4)} MB  ${row.original_filename}`);
            // automatic stop conditions
            if (consecFail >= 3) stop = stop || '3 consecutive failures';
            if (done >= 10 && failed / done > 0.10) stop = stop || `failure rate ${(100 * failed / done).toFixed(0)}% > 10%`;
            if (consecTimeout >= 2) stop = stop || '2 consecutive timeouts';
            if (rssMb() > 600) stop = stop || `memory ${rssMb()} MB > 600 MB`;
            if (!stop && args.delayMs) await sleep(args.delayMs);
        }
        const summary = { event: 'summary', processed: done, failed, peakRssMb: peak, seconds: Math.round((Date.now() - t0) / 1000), r2GetObject: reader.ops.get, mockR2: reader.mock, stoppedBy: stop };
        log(summary);
        console.log(`\nProcessed ${done}, failed ${failed}, peak RSS ${peak} MB, ${summary.seconds} s, R2 GetObject calls ${reader.ops.get}${reader.mock ? ' (mock)' : ''}${stop ? `\nSTOPPED: ${stop}` : ''}\nLog: ${logFile}`);
        if (stop && stop !== 'SIGINT') process.exitCode = 2;

        if (args.verify && out.length) {
            const terms = args.verify.split('|').map(t => t.trim()).filter(Boolean);
            for (const o of out.filter(x => !['failed', 'timeout', 'skipped'].includes(x.status))) {
                const pages = (await db.query('SELECT page_no, norm_text FROM di_doc_text_pages WHERE submission_id = $1 ORDER BY page_no', [o.id])).rows;
                // same matching rules as search: original spelling (substring) + equivalent identifier spellings (whole token)
                const parts = terms.map(t => {
                    const q = normalizeQuery(t), vs = identifierVariants(t);
                    const re = vs.length ? new RegExp(`(?<![\\p{L}\\p{N}])(?:${vs.map(x => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')).join('|')})(?![\\p{L}\\p{N}])`, 'gu') : null;
                    let n = 0; const pg = [];
                    for (const p of pages) { let k = p.norm_text.indexOf(q), c = 0; while (k !== -1) { c++; k = p.norm_text.indexOf(q, k + q.length); } if (re) c += [...p.norm_text.matchAll(re)].length; if (c) { n += c; pg.push(p.page_no); } }
                    return `${t}=${n}${pg.length ? '[p' + pg.join(',') + ']' : ''}`;
                });
                console.log(`  verify ${o.status.padEnd(8)} ${o.name}: ${parts.join('  ')}`);
            }
        }
    } finally {
        try { await lock.query('SELECT pg_advisory_unlock($1)', [LOCK_KEY]); } catch (_) {}
        lock.release(); await db.end();
    }
}

if (require.main === module) main().catch(e => { console.error('Backfill error:', sanitize(e.message)); process.exitCode = 1; });
module.exports = { claim, finishClaim, commitResult, checkPrivileges, inventory, makeObjectReader, normalizeR2Key, buildDbConfig, sanitize, ROLE_SQL, SOURCE, LOCK_KEY };
