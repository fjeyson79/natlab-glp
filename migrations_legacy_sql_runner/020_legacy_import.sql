-- Migration 020: Legacy Data Import
-- Adds columns to di_submissions and di_allowlist for legacy pre-2026 data import feature.

-- di_submissions: legacy metadata columns
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS record_origin VARCHAR(30) DEFAULT NULL;
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS original_created_at TIMESTAMPTZ DEFAULT NULL;
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS legacy_pack_id UUID DEFAULT NULL;
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS legacy_pack_title VARCHAR(255) DEFAULT NULL;
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS legacy_pack_context_type VARCHAR(20) DEFAULT NULL;
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS legacy_pack_reference TEXT DEFAULT NULL;
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS legacy_pack_submitted_at TIMESTAMPTZ DEFAULT NULL;
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS legacy_note TEXT DEFAULT NULL;

-- di_allowlist: legacy access control columns
ALTER TABLE di_allowlist ADD COLUMN IF NOT EXISTS legacy_enabled BOOLEAN DEFAULT FALSE;
ALTER TABLE di_allowlist ADD COLUMN IF NOT EXISTS legacy_expires_at TIMESTAMPTZ DEFAULT NULL;

-- Index for pack grouping queries in Laboratory Files
CREATE INDEX IF NOT EXISTS idx_di_submissions_legacy_pack_id ON di_submissions (legacy_pack_id) WHERE legacy_pack_id IS NOT NULL;

-- Index for filtering by record_origin
CREATE INDEX IF NOT EXISTS idx_di_submissions_record_origin ON di_submissions (record_origin) WHERE record_origin IS NOT NULL;
