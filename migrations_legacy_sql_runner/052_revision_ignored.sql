-- Migration 052: Track when a user uploads a new file while ignoring an open revision request

ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS is_revision_ignored BOOLEAN DEFAULT FALSE;
