-- 026: Meeting notification log columns
-- Track when email notifications were sent for locked meetings

ALTER TABLE meeting_schedule ADD COLUMN IF NOT EXISTS notification_sent_at TIMESTAMPTZ;
ALTER TABLE meeting_schedule ADD COLUMN IF NOT EXISTS notification_sent_by TEXT;
ALTER TABLE meeting_schedule ADD COLUMN IF NOT EXISTS notification_sent_count INTEGER;
