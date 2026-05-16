-- Migration 070: REPORT thread model
--
-- Adds nullable thread-state columns to di_submissions. Every REPORT row
-- becomes the root (or a revision) of a thread keyed by
-- report_thread_root_id. Pre-migration REPORTs are backfilled in place so
-- they show up as their own self-rooted thread.
--
-- Constraint names are stable so the migration is idempotent on re-runs.
-- No existing rows are deleted or had their canonical fields modified.

ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS report_thread_root_id UUID;
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS report_parent_submission_id UUID;
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS report_thread_role TEXT;
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS report_thread_status TEXT;
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS is_final_report BOOLEAN DEFAULT FALSE;
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS report_thread_comment TEXT;
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS report_closed_at TIMESTAMPTZ;
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS report_reopened_at TIMESTAMPTZ;
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS report_discarded_at TIMESTAMPTZ;
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS is_discarded BOOLEAN DEFAULT FALSE;

ALTER TABLE di_submissions DROP CONSTRAINT IF EXISTS di_submissions_report_thread_role_check;
ALTER TABLE di_submissions ADD CONSTRAINT di_submissions_report_thread_role_check
    CHECK (report_thread_role IS NULL OR report_thread_role IN (
        'STUDENT_SUBMISSION','PI_ANNOTATED_VERSION','PI_REVISED_VERSION',
        'STUDENT_REVISED_VERSION','FINAL_REPORT','NOTE','OTHER'
    ));

ALTER TABLE di_submissions DROP CONSTRAINT IF EXISTS di_submissions_report_thread_status_check;
ALTER TABLE di_submissions ADD CONSTRAINT di_submissions_report_thread_status_check
    CHECK (report_thread_status IS NULL OR report_thread_status IN (
        'OPEN','CLOSED','REOPENED','DISCARDED'
    ));

-- Backfill: every REPORT row without a thread root becomes its own root.
-- Approved REPORTs get CLOSED + is_final_report; discarded REPORTs get
-- DISCARDED + is_discarded. di_submissions.signed_at / discarded_at carry
-- forward into the new thread timestamps so PI dashboards see consistent
-- history without a separate audit pass.
UPDATE di_submissions
   SET report_thread_root_id   = submission_id,
       report_thread_role      = 'STUDENT_SUBMISSION',
       report_thread_status    = CASE
           WHEN status = 'APPROVED'  THEN 'CLOSED'
           WHEN status = 'DISCARDED' THEN 'DISCARDED'
           ELSE 'OPEN'
       END,
       is_final_report         = (status = 'APPROVED'),
       is_discarded            = (status = 'DISCARDED'),
       report_closed_at        = CASE WHEN status='APPROVED'  THEN signed_at    END,
       report_discarded_at     = CASE WHEN status='DISCARDED' THEN discarded_at END
 WHERE file_type = 'REPORT'
   AND report_thread_root_id IS NULL;

CREATE INDEX IF NOT EXISTS idx_di_submissions_thread_root
    ON di_submissions (report_thread_root_id) WHERE report_thread_root_id IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_di_submissions_thread_status
    ON di_submissions (report_thread_status) WHERE report_thread_status IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_di_submissions_thread_parent
    ON di_submissions (report_parent_submission_id) WHERE report_parent_submission_id IS NOT NULL;
