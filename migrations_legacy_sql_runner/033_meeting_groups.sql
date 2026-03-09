-- 033: Meeting Groups
-- Generic meeting group containers for group meeting generator

-- Meeting groups table
CREATE TABLE IF NOT EXISTS meeting_groups (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    name VARCHAR(200) NOT NULL,
    site VARCHAR(100),
    default_day INTEGER CHECK (default_day BETWEEN 0 AND 6), -- 0=Sun..6=Sat (4=Thu, 5=Fri)
    default_time TIME DEFAULT '09:00',
    location TEXT,
    is_active BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_meeting_groups_name ON meeting_groups(name);

-- Seed default meeting groups
INSERT INTO meeting_groups (name, site, default_day, default_time, location)
VALUES
    ('LiU Weekly Meeting', 'LiU', 4, '09:00', NULL),
    ('UNAV Weekly Meeting', 'UNAV', 5, '09:00', NULL),
    ('LiU-UNAV Meeting', 'LiU-UNAV', 3, '10:00', NULL)
ON CONFLICT (name) DO NOTHING;

-- Group membership + per-group speaker pool
CREATE TABLE IF NOT EXISTS meeting_group_members (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    meeting_group_id UUID NOT NULL REFERENCES meeting_groups(id) ON DELETE CASCADE,
    researcher_id VARCHAR(100) NOT NULL,
    can_deep BOOLEAN NOT NULL DEFAULT false,
    can_focus BOOLEAN NOT NULL DEFAULT true,
    can_flash BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_meeting_group_members ON meeting_group_members(meeting_group_id, researcher_id);
CREATE INDEX IF NOT EXISTS idx_meeting_group_members_group ON meeting_group_members(meeting_group_id);

-- Add meeting_group_id to meeting_schedule
ALTER TABLE meeting_schedule ADD COLUMN IF NOT EXISTS meeting_group_id UUID REFERENCES meeting_groups(id);
CREATE INDEX IF NOT EXISTS idx_meeting_schedule_group ON meeting_schedule(meeting_group_id);

-- Replace single-date uniqueness with (date, group) uniqueness
-- Legacy meetings (meeting_group_id IS NULL) keep one-per-date constraint
DROP INDEX IF EXISTS uq_meeting_schedule_date;
CREATE UNIQUE INDEX IF NOT EXISTS uq_meeting_schedule_date_group
    ON meeting_schedule(meeting_date, meeting_group_id) WHERE meeting_group_id IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uq_meeting_schedule_date_legacy
    ON meeting_schedule(meeting_date) WHERE meeting_group_id IS NULL;
