-- Migration 007: PI Portal Enhancements
-- Adds support for document permissions and user deactivation tracking

-- 1. Add download permission to group documents
-- When can_download = false, researchers can only view (not download) the document
ALTER TABLE di_group_documents
ADD COLUMN IF NOT EXISTS can_download BOOLEAN DEFAULT TRUE;

COMMENT ON COLUMN di_group_documents.can_download IS 'If false, document is view-only for researchers';

-- 2. Add deactivation tracking to allowlist
-- Tracks when and by whom a user was deactivated
ALTER TABLE di_allowlist
ADD COLUMN IF NOT EXISTS deactivated_at TIMESTAMP;

ALTER TABLE di_allowlist
ADD COLUMN IF NOT EXISTS deactivated_by VARCHAR(50);

COMMENT ON COLUMN di_allowlist.deactivated_at IS 'Timestamp when user was deactivated';
COMMENT ON COLUMN di_allowlist.deactivated_by IS 'researcher_id of PI who deactivated the user';

-- 3. Performance indexes for common queries
CREATE INDEX IF NOT EXISTS idx_di_submissions_status ON di_submissions(status);
CREATE INDEX IF NOT EXISTS idx_di_submissions_created_at ON di_submissions(created_at);
CREATE INDEX IF NOT EXISTS idx_di_allowlist_active ON di_allowlist(active);
