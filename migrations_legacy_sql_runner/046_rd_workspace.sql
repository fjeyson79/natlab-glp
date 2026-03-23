-- Migration 046: R&D workspace tables for startup portals
-- Programs, Projects, Partners, Grants, and Project Documents

-- A. Programs (strategic portfolio layer)
CREATE TABLE IF NOT EXISTS rd_programs (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id        UUID NOT NULL,
    program_name        TEXT NOT NULL,
    description         TEXT,
    status              TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','paused','completed','archived')),
    strategic_goal      TEXT,
    upcoming_deliverable TEXT,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_rd_programs_ws ON rd_programs (workspace_id);

-- B. Projects
CREATE TABLE IF NOT EXISTS rd_projects (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id          UUID NOT NULL,
    program_id            UUID REFERENCES rd_programs(id) ON DELETE SET NULL,
    title                 TEXT NOT NULL,
    project_type          TEXT NOT NULL DEFAULT 'internal' CHECK (project_type IN ('internal','co_development','collaboration')),
    description           TEXT,
    theralia_contact      TEXT,
    external_partner_name TEXT,
    status                TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('planning','active','paused','completed','archived')),
    expected_result       TEXT,
    upcoming_deliverable  TEXT,
    start_date            DATE,
    target_date           DATE,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_rd_projects_ws ON rd_projects (workspace_id);
CREATE INDEX IF NOT EXISTS idx_rd_projects_program ON rd_projects (program_id);

-- C. Partners
CREATE TABLE IF NOT EXISTS rd_partners (
    id                        UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id              UUID NOT NULL,
    organization_name         TEXT NOT NULL,
    contact_person            TEXT,
    email                     TEXT,
    phone                     TEXT,
    collaboration_description TEXT,
    status                    TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active','inactive','prospective')),
    created_at                TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at                TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_rd_partners_ws ON rd_partners (workspace_id);

-- D. Grants
CREATE TABLE IF NOT EXISTS rd_grants (
    id                    UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id          UUID NOT NULL,
    program_id            UUID REFERENCES rd_programs(id) ON DELETE SET NULL,
    linked_project_id     UUID REFERENCES rd_projects(id) ON DELETE SET NULL,
    grant_name            TEXT NOT NULL,
    funding_body          TEXT,
    status                TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('prospective','applied','active','completed','rejected')),
    amount                NUMERIC,
    timeline_notes        TEXT,
    upcoming_deliverable  TEXT,
    created_at            TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at            TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_rd_grants_ws ON rd_grants (workspace_id);

-- E. Project Documents (contextual uploads per project)
CREATE TABLE IF NOT EXISTS rd_documents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID NOT NULL,
    project_id      UUID NOT NULL REFERENCES rd_projects(id) ON DELETE CASCADE,
    document_type   TEXT NOT NULL CHECK (document_type IN ('SOP','DATA','PRES','REPORT','DOCS')),
    title           TEXT NOT NULL,
    filename        TEXT NOT NULL,
    file_type       TEXT,
    r2_key          TEXT NOT NULL,
    file_size       BIGINT,
    uploaded_by     TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_rd_documents_project ON rd_documents (project_id);
CREATE INDEX IF NOT EXISTS idx_rd_documents_ws ON rd_documents (workspace_id);
