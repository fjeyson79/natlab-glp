-- Migration 011: Revision Requests
-- Self-cleaning revision task tracking for Laboratory Files

CREATE TABLE IF NOT EXISTS di_revision_requests (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    file_id             UUID,
    researcher_id       TEXT NOT NULL,
    year                INT NOT NULL,
    doc_type            TEXT NOT NULL,
    filename            TEXT NOT NULL,
    status              TEXT NOT NULL DEFAULT 'open'
                        CHECK (status IN ('open', 'closed', 'cancelled')),
    pi_comment          TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    closed_at           TIMESTAMPTZ,
    resubmitted_file_id UUID
);

-- Only one open revision request per original file
CREATE UNIQUE INDEX IF NOT EXISTS idx_revision_requests_file_open
    ON di_revision_requests (file_id) WHERE status = 'open';

CREATE INDEX IF NOT EXISTS idx_revision_requests_status
    ON di_revision_requests (status);

CREATE INDEX IF NOT EXISTS idx_revision_requests_researcher
    ON di_revision_requests (researcher_id, status);
