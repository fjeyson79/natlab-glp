-- Migration 067: REPORT category metadata
--
-- Adds nullable columns to di_submissions for the new REPORT upload category.
-- file_type='REPORT' was already accepted by the CHECK constraint as of
-- migration 048/049 (R&D integration), so no constraint changes here — this
-- migration only introduces the per-report metadata fields the upload UI
-- will populate.
--
-- All columns are NULLABLE; existing rows (DATA/SOP/PRESENTATION) are
-- untouched. No backfill is performed.

-- 1. Subcategory enum (free text + CHECK when set). Validates against the
--    eight labels listed in the REPORT spec.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                    WHERE table_name='di_submissions' AND column_name='report_subcategory') THEN
        ALTER TABLE di_submissions ADD COLUMN report_subcategory TEXT;
    END IF;
END $$;

ALTER TABLE di_submissions DROP CONSTRAINT IF EXISTS di_submissions_report_subcategory_check;
ALTER TABLE di_submissions ADD CONSTRAINT di_submissions_report_subcategory_check
    CHECK (report_subcategory IS NULL OR report_subcategory IN (
        'INTERNAL_REPORT',
        'UNDERGRADUATE_REPORT',
        'MASTER_REPORT',
        'PHD_REPORT',
        'THESIS_CHAPTER',
        'MANUSCRIPT_DRAFT',
        'GLP_REPORT',
        'OTHER_REPORT'
    ));

-- 2. Free-form project label (REPORT is loosely coupled to rd_projects;
--    storing the typed project name keeps this additive without forcing a
--    join to rd_projects from the upload path).
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                    WHERE table_name='di_submissions' AND column_name='report_project') THEN
        ALTER TABLE di_submissions ADD COLUMN report_project TEXT;
    END IF;
END $$;

-- 3. Reporting period (both nullable; either or both may be provided).
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                    WHERE table_name='di_submissions' AND column_name='report_period_start') THEN
        ALTER TABLE di_submissions ADD COLUMN report_period_start DATE;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                    WHERE table_name='di_submissions' AND column_name='report_period_end') THEN
        ALTER TABLE di_submissions ADD COLUMN report_period_end DATE;
    END IF;
END $$;

-- 4. Related DATA / SOP submission ids. JSONB arrays of submission_id UUIDs
--    keep this additive — no join table; arrays are validated server-side.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                    WHERE table_name='di_submissions' AND column_name='report_related_data_ids') THEN
        ALTER TABLE di_submissions ADD COLUMN report_related_data_ids JSONB DEFAULT '[]'::jsonb;
    END IF;
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                    WHERE table_name='di_submissions' AND column_name='report_related_sop_ids') THEN
        ALTER TABLE di_submissions ADD COLUMN report_related_sop_ids JSONB DEFAULT '[]'::jsonb;
    END IF;
END $$;

-- 5. Supervisor: free text. Pickers can populate this from di_allowlist on
--    the client, but the column itself stays TEXT for portability.
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                    WHERE table_name='di_submissions' AND column_name='report_supervisor') THEN
        ALTER TABLE di_submissions ADD COLUMN report_supervisor TEXT;
    END IF;
END $$;

-- 6. report_status — researcher-managed lifecycle that runs in parallel with
--    di_submissions.status (PI-managed). We don't reuse `status` because the
--    PI lifecycle is PENDING / APPROVED / REVISION_NEEDED / DISCARDED, which
--    overlaps but is not identical to the REPORT lifecycle requested in spec
--    (Draft / Submitted / Approved / Revision needed).
DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns
                    WHERE table_name='di_submissions' AND column_name='report_status') THEN
        ALTER TABLE di_submissions ADD COLUMN report_status TEXT;
    END IF;
END $$;

ALTER TABLE di_submissions DROP CONSTRAINT IF EXISTS di_submissions_report_status_check;
ALTER TABLE di_submissions ADD CONSTRAINT di_submissions_report_status_check
    CHECK (report_status IS NULL OR report_status IN (
        'DRAFT',
        'SUBMITTED',
        'APPROVED',
        'REVISION_NEEDED'
    ));

-- 7. Lightweight lookup index for REPORT-specific dashboards. Partial so
--    DATA/SOP/PRESENTATION rows don't bloat it.
CREATE INDEX IF NOT EXISTS idx_di_submissions_report_subcategory
    ON di_submissions (researcher_id, report_subcategory)
    WHERE file_type = 'REPORT';
