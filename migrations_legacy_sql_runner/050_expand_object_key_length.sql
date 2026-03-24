-- Migration 050: Widen r2_object_key on di_submissions from VARCHAR(100) to TEXT
-- R2 keys for R&D uploads (rd/{workspace}/{projectId}/{type}/{ts}_{filename}) exceed 100 chars

ALTER TABLE di_submissions ALTER COLUMN r2_object_key TYPE TEXT;
