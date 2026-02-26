-- 025: Group Meeting Schedule
-- Tables for PI-managed weekly meeting generation (DATA Deep/Focus/Flash)

CREATE TABLE IF NOT EXISTS meeting_schedule (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    meeting_date DATE NOT NULL,
    meeting_time TIME NOT NULL DEFAULT '09:00',
    duration_minutes INTEGER NOT NULL DEFAULT 60,
    status VARCHAR(10) NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT','LOCKED')),
    created_by VARCHAR(100) NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    locked_at TIMESTAMPTZ,
    unlock_note TEXT
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_meeting_schedule_date ON meeting_schedule(meeting_date);
CREATE INDEX IF NOT EXISTS idx_meeting_schedule_status ON meeting_schedule(status);

CREATE TABLE IF NOT EXISTS meeting_participation (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    meeting_id UUID NOT NULL REFERENCES meeting_schedule(id) ON DELETE CASCADE,
    user_id VARCHAR(100) NOT NULL,
    slot_type VARCHAR(20) NOT NULL CHECK (slot_type IN ('DATA_DEEP','DATA_FOCUS','DATA_FLASH')),
    minutes_allocated INTEGER NOT NULL DEFAULT 2,
    order_position INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_meeting_participation_meeting ON meeting_participation(meeting_id);
CREATE INDEX IF NOT EXISTS idx_meeting_participation_user ON meeting_participation(user_id);

CREATE TABLE IF NOT EXISTS meeting_speaker_pool (
    user_id VARCHAR(100) PRIMARY KEY,
    allow_deep BOOLEAN NOT NULL DEFAULT false,
    allow_focus BOOLEAN NOT NULL DEFAULT true,
    allow_flash BOOLEAN NOT NULL DEFAULT true,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
