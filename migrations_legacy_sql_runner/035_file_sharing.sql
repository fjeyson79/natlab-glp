-- Migration 035: File Sharing (PI only)
-- Allows PI to share approved/pending files between researchers without duplication

CREATE TABLE IF NOT EXISTS di_file_shares (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    submission_id UUID NOT NULL,
    owner_researcher_id TEXT NOT NULL,
    recipient_researcher_id TEXT NOT NULL,
    shared_by TEXT NOT NULL,
    share_reason TEXT,
    share_note TEXT,
    shared_at TIMESTAMP DEFAULT NOW(),
    is_active BOOLEAN DEFAULT TRUE
);

CREATE INDEX IF NOT EXISTS idx_file_shares_recipient
    ON di_file_shares(recipient_researcher_id);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_active_share
    ON di_file_shares(submission_id, recipient_researcher_id)
    WHERE is_active = TRUE;
