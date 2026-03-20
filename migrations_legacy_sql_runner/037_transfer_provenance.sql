-- Migration 037: Transfer provenance for cross-workspace file movement
-- Additive only

ALTER TABLE di_submissions
    ADD COLUMN IF NOT EXISTS source_workspace_id UUID;

ALTER TABLE di_submissions
    ADD COLUMN IF NOT EXISTS source_submission_id UUID;

ALTER TABLE di_submissions
    ADD COLUMN IF NOT EXISTS transferred_at TIMESTAMP;

CREATE INDEX IF NOT EXISTS idx_di_submissions_source_workspace_id
    ON di_submissions(source_workspace_id);

CREATE INDEX IF NOT EXISTS idx_di_submissions_source_submission_id
    ON di_submissions(source_submission_id);

CREATE INDEX IF NOT EXISTS idx_di_submissions_transferred_at
    ON di_submissions(transferred_at);
