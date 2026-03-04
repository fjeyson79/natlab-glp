-- Migration 022: 1-to-1 Meeting Tracking for GLP Vision
-- Supports draft editing, immutable versioning, and PI-private comments.

-- Main meetings table (one per researcher, groups versions)
CREATE TABLE IF NOT EXISTS di_1to1_meetings (
    id            SERIAL PRIMARY KEY,
    researcher_id TEXT NOT NULL,
    affiliation   TEXT NOT NULL,
    created_by    TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_1to1_meetings_researcher ON di_1to1_meetings(researcher_id);

-- Immutable versions (append-only)
CREATE TABLE IF NOT EXISTS di_1to1_meeting_versions (
    id            SERIAL PRIMARY KEY,
    meeting_id    INTEGER NOT NULL REFERENCES di_1to1_meetings(id),
    version       INTEGER NOT NULL DEFAULT 1,
    pillar_sop    JSONB NOT NULL DEFAULT '{}',
    pillar_data   JSONB NOT NULL DEFAULT '{}',
    pillar_training JSONB NOT NULL DEFAULT '{}',
    pillar_inventory JSONB NOT NULL DEFAULT '{}',
    private_comment TEXT,
    created_by    TEXT NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(meeting_id, version)
);

CREATE INDEX IF NOT EXISTS idx_1to1_versions_meeting ON di_1to1_meeting_versions(meeting_id);

-- Actions linked to a version
CREATE TABLE IF NOT EXISTS di_1to1_actions (
    id            SERIAL PRIMARY KEY,
    version_id    INTEGER NOT NULL REFERENCES di_1to1_meeting_versions(id),
    pillar        TEXT NOT NULL CHECK (pillar IN ('sop','data','training','inventory')),
    action_text   TEXT NOT NULL,
    owner_role    TEXT NOT NULL CHECK (owner_role IN ('Researcher','Supervisor','PI')),
    due_date      DATE,
    done          BOOLEAN NOT NULL DEFAULT FALSE,
    sort_order    INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_1to1_actions_version ON di_1to1_actions(version_id);

-- Draft table (max one per researcher per PI)
CREATE TABLE IF NOT EXISTS di_1to1_drafts (
    id            SERIAL PRIMARY KEY,
    researcher_id TEXT NOT NULL,
    affiliation   TEXT NOT NULL,
    created_by    TEXT NOT NULL,
    meeting_id    INTEGER REFERENCES di_1to1_meetings(id),
    pillar_sop    JSONB NOT NULL DEFAULT '{}',
    pillar_data   JSONB NOT NULL DEFAULT '{}',
    pillar_training JSONB NOT NULL DEFAULT '{}',
    pillar_inventory JSONB NOT NULL DEFAULT '{}',
    actions       JSONB NOT NULL DEFAULT '[]',
    private_comment TEXT,
    updated_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(researcher_id, created_by)
);

CREATE INDEX IF NOT EXISTS idx_1to1_drafts_researcher ON di_1to1_drafts(researcher_id);
