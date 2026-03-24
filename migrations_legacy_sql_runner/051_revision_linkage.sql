-- Migration 051: Add revision linkage columns to di_submissions
-- Supports linked resubmissions: new upload references the original submission it revises

ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS revision_of_submission_id UUID;
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS amendment_note TEXT;

CREATE INDEX IF NOT EXISTS idx_di_submissions_revision_of
    ON di_submissions(revision_of_submission_id)
    WHERE revision_of_submission_id IS NOT NULL;
