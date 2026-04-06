-- Migration 059: Board meetings for Theralia dashboard
-- Stores real board meeting records with lifecycle tracking

CREATE TABLE IF NOT EXISTS theralia_board_meetings (
    id              SERIAL PRIMARY KEY,
    workspace_id    TEXT NOT NULL DEFAULT 'theralia',
    title           TEXT NOT NULL DEFAULT 'Board Meeting',
    scheduled_at    TIMESTAMPTZ NOT NULL,
    duration_minutes INTEGER NOT NULL DEFAULT 60,
    status          TEXT NOT NULL DEFAULT 'PLANNED'
                    CHECK (status IN ('PLANNED','CONFIRMED','RESCHEDULED','COMPLETED','CANCELLED')),
    notes           TEXT,
    week_number     INTEGER NOT NULL,
    year            INTEGER NOT NULL,
    week_range_label TEXT,
    original_scheduled_at TIMESTAMPTZ,
    completed_at    TIMESTAMPTZ,
    completed_by    TEXT,
    cancelled_at    TIMESTAMPTZ,
    cancelled_by    TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_by      TEXT NOT NULL,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tbm_workspace_status ON theralia_board_meetings (workspace_id, status);
CREATE INDEX IF NOT EXISTS idx_tbm_scheduled ON theralia_board_meetings (scheduled_at DESC);

-- Meeting content: preserved independently of meeting status
CREATE TABLE IF NOT EXISTS theralia_board_meeting_content (
    id          SERIAL PRIMARY KEY,
    meeting_id  INTEGER NOT NULL REFERENCES theralia_board_meetings(id),
    section     TEXT NOT NULL CHECK (section IN ('agenda','topic','action')),
    items       JSONB NOT NULL DEFAULT '[]',
    updated_at  TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_by  TEXT,
    UNIQUE (meeting_id, section)
);
