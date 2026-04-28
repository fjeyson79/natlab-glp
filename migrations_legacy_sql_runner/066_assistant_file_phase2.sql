-- Migration 066: Zoe Phase 2 — file reading layer.
--
-- Builds on migration 065 (assistant_file_index, assistant_file_text). Adds
-- three new tables and three new columns on assistant_file_index so the
-- extractor can persist per-page text, chunked excerpts, and a deterministic
-- rule-based summary.
--
-- Idempotent. Safe to run multiple times.
--
-- Why these tables and not changes to assistant_file_text:
--   Phase 1's assistant_file_text holds whole-document text and is read by
--   the indexed search at routes/assistant/files.js. Repurposing it for
--   per-page rows would silently break content search until every caller
--   was rewired. Per-page text gets its own table (assistant_file_pages)
--   and assistant_file_text keeps its current shape — the extractor
--   populates BOTH so neither phase regresses.
--
-- Why the index columns we DON'T add:
--   The Phase 2 brief originally listed text_extracted (bool) and
--   extracted_at (timestamp) on assistant_file_index. Migration 065 already
--   ships richer equivalents: text_status (TEXT — pending|ready|failed|
--   empty|unsupported) and text_extracted_at (TIMESTAMPTZ). We reuse those
--   instead of duplicating semantics.

-- ---------------------------------------------------------------------------
-- assistant_file_pages — one row per PDF page
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS assistant_file_pages (
    id           UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id      UUID NOT NULL REFERENCES assistant_file_index(id) ON DELETE CASCADE,
    page_number  INT NOT NULL,
    text         TEXT,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- (file_id, page_number) is the natural identity. UNIQUE so re-extraction
-- can use ON CONFLICT, and the cascade from the FK keeps things consistent.
CREATE UNIQUE INDEX IF NOT EXISTS uq_afp_file_page ON assistant_file_pages (file_id, page_number);
CREATE INDEX        IF NOT EXISTS idx_afp_file     ON assistant_file_pages (file_id);

-- ---------------------------------------------------------------------------
-- assistant_file_chunks — text split for retrieval
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS assistant_file_chunks (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id         UUID NOT NULL REFERENCES assistant_file_index(id) ON DELETE CASCADE,
    chunk_index     INT NOT NULL,
    page_start      INT,
    page_end        INT,
    chunk_text      TEXT,
    token_estimate  INT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_afc_file_chunk ON assistant_file_chunks (file_id, chunk_index);
CREATE INDEX        IF NOT EXISTS idx_afc_file       ON assistant_file_chunks (file_id);
-- Trigram-style ILIKE on chunk_text is what /search-text uses; a btree
-- index doesn't help substring search. We rely on Postgres seq-scan with
-- limit; if /search-text gets hot, add pg_trgm + GIN here in a future
-- migration. Phase 2 keeps the schema simple.

-- ---------------------------------------------------------------------------
-- assistant_file_summaries — one row per file (UPSERT-friendly)
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS assistant_file_summaries (
    id                UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id           UUID NOT NULL UNIQUE REFERENCES assistant_file_index(id) ON DELETE CASCADE,
    summary_short     TEXT,
    summary_detailed  TEXT,
    key_methods       TEXT,
    key_results       TEXT,
    key_data_types    TEXT,
    detected_entities JSONB NOT NULL DEFAULT '{}'::jsonb,
    detected_assays   JSONB NOT NULL DEFAULT '[]'::jsonb,
    detected_controls JSONB NOT NULL DEFAULT '[]'::jsonb,
    detected_gaps     JSONB NOT NULL DEFAULT '[]'::jsonb,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_afs_file ON assistant_file_summaries (file_id);

-- ---------------------------------------------------------------------------
-- assistant_file_index — three new columns (additive only)
-- ---------------------------------------------------------------------------
ALTER TABLE assistant_file_index ADD COLUMN IF NOT EXISTS summary_ready     BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE assistant_file_index ADD COLUMN IF NOT EXISTS file_hash         TEXT;
ALTER TABLE assistant_file_index ADD COLUMN IF NOT EXISTS extraction_error  TEXT;

CREATE INDEX IF NOT EXISTS idx_afi_summary_ready ON assistant_file_index (summary_ready);
CREATE INDEX IF NOT EXISTS idx_afi_file_hash     ON assistant_file_index (file_hash);
