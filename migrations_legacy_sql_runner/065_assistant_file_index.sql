-- Migration 065: Assistant file index for Zoe Phase 1 (file visibility + keyword search)
--
-- Purpose:
--   Build a searchable map of every relevant R2 object so Zoe can answer
--   queries like "list MC's DATA files from 2026" or "find SOPs from UNAV
--   mentioning chicken embryo" without having to re-list R2 on every turn.
--
-- Source of truth: R2 (the bucket). assistant_file_index is only Zoe's map.
-- Records here can lag R2 — the reindex job re-syncs them.
--
-- All metadata fields are NULL-able. The R2 indexer fills what it can infer
-- (workspace_slug, affiliation, researcher_code, year, file_type, status,
-- topic) using services/zoeRetrieval.js parseR2Path() — anything it cannot
-- determine stays NULL rather than being faked.
--
-- Two tables to keep the metadata index small (queried often) and the bulky
-- extracted text in a separate table (queried only on content searches):
--   assistant_file_index : metadata + text_preview + status flags
--   assistant_file_text  : full extracted text + per-page text JSON
--
-- Idempotent. Safe to run multiple times.

CREATE EXTENSION IF NOT EXISTS pgcrypto;  -- for gen_random_uuid()

-- ---------------------------------------------------------------------------
-- assistant_file_index
-- ---------------------------------------------------------------------------
CREATE TABLE IF NOT EXISTS assistant_file_index (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_slug     TEXT,
    r2_key             TEXT NOT NULL UNIQUE,
    filename           TEXT,
    file_ext           TEXT,
    file_type          TEXT,         -- DATA | SOP | PRESENTATION | REPORT | PAPER | INVENTORY | TRAINING | ...
    researcher_code    TEXT,         -- e.g. 'MC', 'HJM' (initials token from path/filename)
    researcher_name    TEXT,         -- resolved from di_allowlist when researcher_code matches
    affiliation        TEXT,         -- LiU | UNAV | EXTERNAL | THERALIA | null
    year               INT,          -- 4-digit year inferred from path or filename
    date_detected      DATE,         -- ISO date inferred from filename, when present
    status             TEXT,         -- SUBMITTED | APPROVED | REVISION_NEEDED | DISCARDED | TRAINING | LEGACY | null
    source_area        TEXT,         -- top-level R2 prefix (di | rd | theralia | company | oligo | ...)
    topic              TEXT,         -- free-text topic remainder from filename convention
    tags               JSONB NOT NULL DEFAULT '[]'::jsonb,
    mime_type          TEXT,
    size_bytes         BIGINT,
    text_status        TEXT NOT NULL DEFAULT 'pending',  -- pending | ready | failed | empty | unsupported
    text_preview       TEXT,
    text_char_count    INT,
    text_extracted_at  TIMESTAMPTZ,
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    indexed_at         TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Allow upserts keyed on r2_key (already enforced by UNIQUE constraint above).
-- Indexes target the four common filter axes from /map and /search.
CREATE INDEX IF NOT EXISTS idx_afi_workspace_type ON assistant_file_index (workspace_slug, file_type);
CREATE INDEX IF NOT EXISTS idx_afi_researcher    ON assistant_file_index (researcher_code);
CREATE INDEX IF NOT EXISTS idx_afi_affiliation   ON assistant_file_index (affiliation);
CREATE INDEX IF NOT EXISTS idx_afi_year          ON assistant_file_index (year);
CREATE INDEX IF NOT EXISTS idx_afi_status        ON assistant_file_index (status);
CREATE INDEX IF NOT EXISTS idx_afi_text_status   ON assistant_file_index (text_status);
CREATE INDEX IF NOT EXISTS idx_afi_indexed_at    ON assistant_file_index (indexed_at DESC);
CREATE INDEX IF NOT EXISTS idx_afi_tags_gin      ON assistant_file_index USING GIN (tags);

-- ---------------------------------------------------------------------------
-- assistant_file_text
-- ---------------------------------------------------------------------------
-- Separated from the index so the wide TEXT column doesn't bloat the metadata
-- table that /map and /researcher query.
CREATE TABLE IF NOT EXISTS assistant_file_text (
    file_id     UUID NOT NULL PRIMARY KEY REFERENCES assistant_file_index(id) ON DELETE CASCADE,
    r2_key      TEXT NOT NULL UNIQUE,
    full_text   TEXT,
    pages_json  JSONB,        -- optional per-page split; pdf-parse returns whole-doc text by default,
                              -- so this stays NULL until a future phase adds per-page extraction
    indexed_at  TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Helper trigger: keep updated_at fresh on assistant_file_index updates.
CREATE OR REPLACE FUNCTION fn_assistant_file_index_touch_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at := NOW();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_afi_touch_updated_at ON assistant_file_index;
CREATE TRIGGER trg_afi_touch_updated_at
    BEFORE UPDATE ON assistant_file_index
    FOR EACH ROW EXECUTE FUNCTION fn_assistant_file_index_touch_updated_at();
