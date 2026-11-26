'use strict';
// GLP Vision R2.2 — additive, idempotent schema for the document-text index.
// Derived data only: never modifies di_submissions. Applied from db/migrate.js in a guarded
// block where each statement is isolated, so a failure here cannot affect other migrations.

const CORE = [
    `CREATE TABLE IF NOT EXISTS di_doc_text_index (
        submission_id  UUID PRIMARY KEY REFERENCES di_submissions(submission_id) ON DELETE CASCADE,
        status         VARCHAR(16) NOT NULL CHECK (status IN
                         ('pending','processing','ok','empty','no_text','partial','failed','timeout','interrupted')),
        source         VARCHAR(24) NOT NULL DEFAULT 'server_upload',
        content_sha256 CHAR(64),
        extractor      VARCHAR(40),
        page_count     INTEGER,
        pages_indexed  INTEGER,
        char_count     INTEGER,
        attempts       INTEGER NOT NULL DEFAULT 0,
        queued_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
        started_at     TIMESTAMPTZ,
        finished_at    TIMESTAMPTZ,
        error_code     VARCHAR(32),
        error_message  VARCHAR(240)
    )`,
    `CREATE INDEX IF NOT EXISTS idx_di_doc_text_index_status ON di_doc_text_index (status)`,
    `CREATE TABLE IF NOT EXISTS di_doc_text_pages (
        submission_id    UUID NOT NULL REFERENCES di_doc_text_index(submission_id) ON DELETE CASCADE,
        page_no          INTEGER NOT NULL CHECK (page_no >= 1),
        raw_text         TEXT NOT NULL,
        norm_text        TEXT NOT NULL,
        raw_word_offsets INTEGER[] NOT NULL,
        tsv              TSVECTOR GENERATED ALWAYS AS (to_tsvector('simple'::regconfig, norm_text)) STORED,
        PRIMARY KEY (submission_id, page_no)
    )`,
    `CREATE INDEX IF NOT EXISTS idx_di_doc_text_pages_tsv ON di_doc_text_pages USING GIN (tsv)`,
];

// Optional: partial-term search. Skipped (logged) if the extension cannot be created.
const TRGM = [
    `CREATE EXTENSION IF NOT EXISTS pg_trgm`,
    `CREATE INDEX IF NOT EXISTS idx_di_doc_text_pages_trgm ON di_doc_text_pages USING GIN (norm_text gin_trgm_ops)`,
];

async function applyDocTextSchema(pool, log = console.log) {
    const result = { core: true, trgm: true };
    for (const sql of CORE) {
        try { await pool.query(sql); }
        catch (e) { result.core = false; log('  [docText] schema statement failed (feature stays inactive): ' + e.message); break; }
    }
    if (result.core) {
        for (const sql of TRGM) {
            try { await pool.query(sql); }
            catch (e) { result.trgm = false; log('  [docText] pg_trgm unavailable, partial-term index skipped: ' + e.message); break; }
        }
    }
    log(`  [docText] schema: core=${result.core} trgm=${result.trgm && result.core}`);
    return result;
}

module.exports = { applyDocTextSchema, CORE, TRGM };
