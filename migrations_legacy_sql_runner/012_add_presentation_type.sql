-- Migration 012: Add PRESENTATION document type
-- Extends di_submissions to support presentation uploads with sub-type metadata.

-- 1. Widen the file_type column from VARCHAR(10) to VARCHAR(20) to fit 'PRESENTATION'
ALTER TABLE di_submissions ALTER COLUMN file_type TYPE VARCHAR(20);

-- 2. Widen the file_type CHECK to include PRESENTATION
ALTER TABLE di_submissions DROP CONSTRAINT IF EXISTS di_submissions_file_type_check;
ALTER TABLE di_submissions ADD CONSTRAINT di_submissions_file_type_check
    CHECK (file_type IN ('SOP', 'DATA', 'INVENTORY', 'PRESENTATION'));

-- 3. Add presentation metadata columns (nullable — only populated for PRESENTATION rows)
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS presentation_type TEXT;
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS presentation_other TEXT;
