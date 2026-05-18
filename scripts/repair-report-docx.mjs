#!/usr/bin/env node
// scripts/repair-report-docx.mjs
//
// Phase 1.1 repair — backfill text extraction for REPORT DOCX rows that were
// indexed BEFORE the mammoth path existed. Those rows were stamped with
// text_status = 'unsupported' (or 'failed' on an earlier crash) and never
// re-extracted, so /api/assistant/files/indexed/:id/text returns
// has_full_text=false for them.
//
// What it does:
//   1. Connects to the same Postgres + R2 the indexer uses (DATABASE_URL +
//      R2_* env). This script does NOT call the HTTP API — it shares the
//      backend's extractor module directly, same as scripts/reindexAssistantFiles.js.
//   2. Lists rows in assistant_file_index where:
//        file_type = 'REPORT' AND file_ext = 'docx'
//        AND text_status IN ('unsupported','failed','empty','pending')
//      (i.e. anything not 'ready') and reports the count.
//   3. With --apply: walks each candidate and runs
//      extractor.extractOne(deps, id, { force: true }). force:true matters —
//      a previous run may have stamped a file_hash with empty text, and the
//      hash short-circuit would otherwise skip it.
//   4. Prints a per-row line and a final summary.
//
// Usage:
//   node scripts/repair-report-docx.mjs               # dry-run (default)
//   node scripts/repair-report-docx.mjs --apply       # actually re-extract
//   node scripts/repair-report-docx.mjs --apply --token <ignored>
//   node scripts/repair-report-docx.mjs --limit=50    # cap candidates this run
//
// Required env (same as scripts/reindexAssistantFiles.js):
//   DATABASE_URL
//   R2_ENDPOINT
//   R2_ACCESS_KEY_ID
//   R2_SECRET_ACCESS_KEY
//   R2_BUCKET
//
// The --token flag is accepted for command-line compatibility with the
// Phase 1.1 deployment brief but is intentionally NOT used: this script
// connects to the database directly via DATABASE_URL, which is already a
// stronger credential than any HTTP token would be. If you need an HTTP
// repair flow later, build it explicitly behind an auth-gated endpoint
// rather than reading the token here as a no-op.

import { Pool } from 'pg';
import { S3Client } from '@aws-sdk/client-s3';
import { createRequire } from 'module';

const require = createRequire(import.meta.url);
const extractor = require('../services/assistantFileExtractor.js');

function parseArgs(argv) {
    const out = { apply: false, token: null, limit: 0 };
    for (const a of argv.slice(2)) {
        if (a === '--apply') out.apply = true;
        else if (a === '--token') {
            // bare --token consumes the next positional; handled below
        }
        else if (a.startsWith('--token=')) out.token = a.split('=').slice(1).join('=');
        else if (a.startsWith('--limit=')) out.limit = parseInt(a.split('=')[1], 10) || 0;
        else if (a === '-h' || a === '--help') {
            process.stdout.write([
                'repair-report-docx.mjs — backfill text for REPORT DOCX rows',
                '',
                '  --apply              actually re-extract (default: dry-run)',
                '  --token <t>          accepted for compat; intentionally unused',
                '  --limit=N            cap candidates processed this run (0 = no cap)',
                ''
            ].join('\n'));
            process.exit(0);
        }
    }
    // Pair up `--token <value>` form
    const idx = argv.indexOf('--token');
    if (idx !== -1 && argv[idx + 1] && !argv[idx + 1].startsWith('--')) {
        out.token = argv[idx + 1];
    }
    return out;
}

const opts = parseArgs(process.argv);

const required = ['DATABASE_URL', 'R2_ENDPOINT', 'R2_ACCESS_KEY_ID', 'R2_SECRET_ACCESS_KEY', 'R2_BUCKET'];
const missing = required.filter(k => !process.env[k]);
if (missing.length) {
    process.stderr.write('Missing required env: ' + missing.join(', ') + '\n');
    process.exit(2);
}

if (opts.token) {
    process.stderr.write('[repair-report-docx] --token received; ignored (direct-DB mode).\n');
}

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});
const r2Client = new S3Client({
    region: 'auto',
    endpoint: process.env.R2_ENDPOINT,
    credentials: {
        accessKeyId:     process.env.R2_ACCESS_KEY_ID,
        secretAccessKey: process.env.R2_SECRET_ACCESS_KEY
    }
});
const r2Bucket = process.env.R2_BUCKET;
const deps = { pool, r2Client, r2Bucket, log: console };

let exitCode = 0;
try {
    // Candidate set: REPORT DOCX rows that are NOT already 'ready'. We also
    // accept rows where file_ext is null but the filename ends in .docx —
    // older indexer runs sometimes left file_ext null when the parser bailed
    // on path parsing. Belt-and-braces for completeness.
    const limitClause = opts.limit ? `LIMIT ${parseInt(opts.limit, 10)}` : '';
    const r = await pool.query(
        `SELECT id, r2_key, filename, file_type, file_ext, text_status, text_char_count
           FROM assistant_file_index
          WHERE file_type = 'REPORT'
            AND (file_ext = 'docx' OR LOWER(filename) LIKE '%.docx')
            AND text_status <> 'ready'
          ORDER BY indexed_at DESC
          ${limitClause}`
    );
    const rows = r.rows;

    process.stdout.write(`[repair-report-docx] candidates: ${rows.length}\n`);
    if (!rows.length) {
        process.stdout.write('[repair-report-docx] nothing to repair.\n');
    }

    if (!opts.apply) {
        for (const row of rows) {
            process.stdout.write(
                `  DRY  ${row.id}  status=${row.text_status}  ` +
                `chars=${row.text_char_count || 0}  ` +
                `${row.filename}\n`
            );
        }
        process.stdout.write('[repair-report-docx] dry-run complete. Re-run with --apply to actually extract.\n');
    } else {
        let ok = 0, empty = 0, unsupported = 0, failed = 0;
        for (const row of rows) {
            try {
                const result = await extractor.extractOne(deps, row.id, { force: true });
                const status = result && result.text_status || (result && result.ok ? 'ready' : 'unknown');
                const chars  = result && result.text_char_count;
                process.stdout.write(
                    `  OK   ${row.id}  status=${status}  ` +
                    (chars != null ? `chars=${chars}  ` : '') +
                    `${row.filename}\n`
                );
                if (status === 'ready')           ok += 1;
                else if (status === 'empty')      empty += 1;
                else if (status === 'unsupported') unsupported += 1;
                else                              failed += 1;
            } catch (e) {
                failed += 1;
                process.stderr.write(
                    `  ERR  ${row.id}  ${row.filename}  — ${e && e.message || e}\n`
                );
            }
        }
        process.stdout.write(
            `[repair-report-docx] done. ready=${ok} empty=${empty} ` +
            `unsupported=${unsupported} failed=${failed} ` +
            `total=${rows.length}\n`
        );
        if (failed > 0) exitCode = 1;
    }
} catch (e) {
    process.stderr.write('[repair-report-docx] threw: ' + (e && e.stack || e) + '\n');
    exitCode = 1;
} finally {
    try { await pool.end(); } catch (_) {}
    process.exit(exitCode);
}
