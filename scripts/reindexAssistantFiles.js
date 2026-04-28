#!/usr/bin/env node
// scripts/reindexAssistantFiles.js
//
// CLI entry for the Zoe Phase 1 file indexer. Use this for the FIRST run on
// a populated bucket (it can take many minutes when extracting PDF text), or
// any time you want a foreground run with progress to stderr instead of the
// background API job.
//
// Usage:
//   node scripts/reindexAssistantFiles.js                 # full job (metadata + pdf text)
//   node scripts/reindexAssistantFiles.js --metadata-only # fast metadata pass only
//   node scripts/reindexAssistantFiles.js --text-only     # PDF text pass only
//   node scripts/reindexAssistantFiles.js --concurrency=8 # widen pdf-parse concurrency
//   node scripts/reindexAssistantFiles.js --limit=50      # cap PDFs to extract this run
//
// Required env (same as the server):
//   DATABASE_URL
//   R2_ENDPOINT
//   R2_ACCESS_KEY_ID
//   R2_SECRET_ACCESS_KEY
//   R2_BUCKET

'use strict';

const { Pool } = require('pg');
const { S3Client } = require('@aws-sdk/client-s3');
const { runJob } = require('../services/assistantFileIndexer');

function parseArgs(argv) {
    const out = { metadataOnly: false, textOnly: false, concurrency: 4, limit: 0 };
    for (const a of argv.slice(2)) {
        if (a === '--metadata-only') out.metadataOnly = true;
        else if (a === '--text-only')   out.textOnly = true;
        else if (a.startsWith('--concurrency=')) out.concurrency = parseInt(a.split('=')[1], 10) || 4;
        else if (a.startsWith('--limit='))       out.limit = parseInt(a.split('=')[1], 10) || 0;
        else if (a === '-h' || a === '--help') {
            process.stdout.write([
                'reindexAssistantFiles.js — full Zoe R2 reindex',
                '',
                '  --metadata-only      list R2 + upsert metadata, no PDF parsing',
                '  --text-only          PDF text pass only (no R2 list)',
                '  --concurrency=N      pdf-parse concurrency (default 4)',
                '  --limit=N            cap PDFs extracted this run (0 = no cap)',
                ''
            ].join('\n'));
            process.exit(0);
        } else {
            process.stderr.write('Unknown argument: ' + a + '\n');
            process.exit(2);
        }
    }
    return out;
}

(async () => {
    const opts = parseArgs(process.argv);

    const required = ['DATABASE_URL', 'R2_ENDPOINT', 'R2_ACCESS_KEY_ID', 'R2_SECRET_ACCESS_KEY', 'R2_BUCKET'];
    const missing = required.filter(k => !process.env[k]);
    if (missing.length) {
        process.stderr.write('Missing required env: ' + missing.join(', ') + '\n');
        process.exit(2);
    }

    const pool = new Pool({
        connectionString: process.env.DATABASE_URL,
        ssl: { rejectUnauthorized: false }
    });
    const r2Client = new S3Client({
        region: 'auto',
        endpoint: process.env.R2_ENDPOINT,
        credentials: {
            accessKeyId: process.env.R2_ACCESS_KEY_ID,
            secretAccessKey: process.env.R2_SECRET_ACCESS_KEY
        }
    });
    const r2Bucket = process.env.R2_BUCKET;

    // Light progress tick to stderr — job state is updated in-process by the
    // indexer; we just sample it every few seconds so the operator can see
    // movement on a long run.
    const ticker = setInterval(() => {
        const { getJobStatus } = require('../services/assistantFileIndexer');
        const s = getJobStatus();
        process.stderr.write(
            `[${new Date().toISOString()}] phase=${s.phase || '-'} ` +
            `scanned=${s.counts.scanned} ignored=${s.counts.ignored} ` +
            `upserted=${s.counts.upserted} text=${s.counts.text_processed} ` +
            `(ready=${s.counts.text_ready} failed=${s.counts.text_failed} empty=${s.counts.text_empty})\n`
        );
    }, 5000);

    let exitCode = 0;
    try {
        const result = await runJob(
            { pool, r2Client, r2Bucket, log: console },
            opts
        );
        clearInterval(ticker);
        process.stderr.write('\nFinal status:\n' + JSON.stringify(result.job, null, 2) + '\n');
        if (!result.ok) exitCode = 1;
    } catch (e) {
        clearInterval(ticker);
        process.stderr.write('Reindex job threw: ' + (e && e.stack || e) + '\n');
        exitCode = 1;
    } finally {
        try { await pool.end(); } catch (_) {}
        process.exit(exitCode);
    }
})();
