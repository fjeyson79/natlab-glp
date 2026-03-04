-- Migration 018: Add discard fields and approval_comment to di_submissions
-- Supports the new "Discard" PI action and optional approval comments.

ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS approval_comment TEXT;
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS discarded_by TEXT;
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS discarded_at TIMESTAMPTZ;
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS discard_reason TEXT;
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS discard_note TEXT;
