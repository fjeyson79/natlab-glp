-- Migration 072: PAPER metadata on assistant_file_index
--
-- Adds three nullable columns so the indexer can store identifiers it
-- extracts from scientific-paper PDFs (file_type='PAPER'). All three are
-- best-effort — left NULL when the extractor can't find them.
--
--   pmid         — PubMed ID (numeric string), detected from header text
--   doi          — DOI in canonical form "10.<reg>/<suffix>"
--   paper_title  — first plausible title line from the PDF head (heuristic)
--
-- These fields are PAPER-specific in intent but the column type is plain
-- TEXT on the shared index table — no CHECK constraint by file_type, so
-- the columns degrade harmlessly to NULL for every non-PAPER row.
--
-- Idempotent. Safe to run multiple times.

ALTER TABLE assistant_file_index ADD COLUMN IF NOT EXISTS pmid         TEXT;
ALTER TABLE assistant_file_index ADD COLUMN IF NOT EXISTS doi          TEXT;
ALTER TABLE assistant_file_index ADD COLUMN IF NOT EXISTS paper_title  TEXT;

-- Partial indexes — only populated rows are indexed, keeps the index small.
CREATE INDEX IF NOT EXISTS idx_afi_pmid ON assistant_file_index (pmid) WHERE pmid IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_afi_doi  ON assistant_file_index (doi)  WHERE doi  IS NOT NULL;
