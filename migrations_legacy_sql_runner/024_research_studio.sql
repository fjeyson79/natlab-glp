-- Migration 024: Research Studio
-- Creative manuscript workspace for researchers. Phase 1: projects, sections, evidence links.
-- All tables are additive; no existing tables are modified.

-- 1. Projects (one per researcher per manuscript)
CREATE TABLE IF NOT EXISTS di_studio_projects (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    owner_id        VARCHAR(50) NOT NULL,
    affiliation     VARCHAR(10) NOT NULL,
    title           VARCHAR(500) NOT NULL,
    status          VARCHAR(20) NOT NULL DEFAULT 'Active'
                        CHECK (status IN ('Active','On hold','Completed','Archived')),
    -- Reflection layer fields (nullable in Phase 1; gating enforced in Phase 2)
    hypothesis      TEXT,
    intention       TEXT,
    phase           VARCHAR(20) CHECK (phase IS NULL OR phase IN (
                        'Planning','Data generation','Analysis',
                        'Writing','Submission','Revision')),
    tension         TEXT,
    next_milestone  TEXT,
    milestone_date  DATE,
    -- Optional metadata
    target_journal  VARCHAR(255),
    notes_json      JSONB DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_studio_projects_owner
    ON di_studio_projects(owner_id);
CREATE INDEX IF NOT EXISTS idx_studio_projects_affiliation
    ON di_studio_projects(affiliation);
CREATE INDEX IF NOT EXISTS idx_studio_projects_status
    ON di_studio_projects(status);
CREATE INDEX IF NOT EXISTS idx_studio_projects_updated
    ON di_studio_projects(updated_at DESC);

-- 2. Manuscript sections (one row per section per project; 7 standard sections)
CREATE TABLE IF NOT EXISTS di_studio_sections (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES di_studio_projects(id)
                        ON DELETE CASCADE,
    section_key     VARCHAR(30) NOT NULL CHECK (section_key IN (
                        'aims','abstract','introduction','methodology',
                        'results','discussion','conclusion')),
    content_html    TEXT NOT NULL DEFAULT '',
    sort_order      INTEGER NOT NULL DEFAULT 0,
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(project_id, section_key)
);

CREATE INDEX IF NOT EXISTS idx_studio_sections_project
    ON di_studio_sections(project_id);

-- 3. Evidence links (read only references to existing GLP items)
CREATE TABLE IF NOT EXISTS di_studio_links (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES di_studio_projects(id)
                        ON DELETE CASCADE,
    evidence_type   VARCHAR(30) NOT NULL CHECK (evidence_type IN (
                        'DATA','SOP','INVENTORY','TRAINING','SUBMISSION')),
    evidence_id     VARCHAR(100) NOT NULL,
    label           VARCHAR(500),
    section_key     VARCHAR(30),
    footnote_index  INTEGER,
    created_by      VARCHAR(50) NOT NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(project_id, evidence_type, evidence_id, section_key)
);

CREATE INDEX IF NOT EXISTS idx_studio_links_project
    ON di_studio_links(project_id);
CREATE INDEX IF NOT EXISTS idx_studio_links_type
    ON di_studio_links(evidence_type);
