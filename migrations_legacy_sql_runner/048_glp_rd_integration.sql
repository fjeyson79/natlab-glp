-- Migration 048: GLP Vision + R&D integration
-- Adds rd_project_id linkage to di_submissions and widens file_type for R&D categories

-- 1. Add rd_project_id column for project linkage
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='di_submissions' AND column_name='rd_project_id') THEN
        ALTER TABLE di_submissions ADD COLUMN rd_project_id UUID;
    END IF;
END $$;

CREATE INDEX IF NOT EXISTS idx_di_submissions_rd_project ON di_submissions (rd_project_id) WHERE rd_project_id IS NOT NULL;

-- 2. Widen file_type CHECK to include R&D categories (REPORT, DOCS, PRES as alias)
ALTER TABLE di_submissions DROP CONSTRAINT IF EXISTS di_submissions_file_type_check;
ALTER TABLE di_submissions ADD CONSTRAINT di_submissions_file_type_check
    CHECK (file_type IN ('SOP', 'DATA', 'INVENTORY', 'PRESENTATION', 'REPORT', 'DOCS', 'PRES'));
