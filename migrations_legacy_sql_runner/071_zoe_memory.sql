-- Migration 071: Zoe scientific memory tiers
--
-- Four memory scopes (file / researcher / project / workspace) + a job
-- log. Memory rows are summaries derived deterministically from
-- existing data (assistant_file_index, assistant_file_text,
-- assistant_file_summaries, assistant_report_intelligence,
-- di_submissions). No LLM is required by default — the build pipeline
-- in services/zoeMemory.js aggregates fields rule-based, so re-runs
-- are cheap and skip-unchanged-when-possible.
--
-- A single shape (memory_json + summary_text + evidence_file_ids +
-- confidence + source_updated_at + memory_updated_at) is reused across
-- all four scopes via per-scope tables — simpler than one wide table
-- with discriminator columns, and lets each scope evolve its indexes
-- independently.

-- File memory: one row per indexed file. Keyed by assistant_file_index.id.
CREATE TABLE IF NOT EXISTS assistant_file_memory (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_slug TEXT NOT NULL,
    file_id UUID NOT NULL UNIQUE,
    memory_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    summary_text TEXT,
    evidence_file_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    confidence NUMERIC,
    source_updated_at TIMESTAMPTZ,
    memory_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_afm_ws ON assistant_file_memory (workspace_slug);
CREATE INDEX IF NOT EXISTS idx_afm_updated ON assistant_file_memory (memory_updated_at);

-- Researcher memory: one row per researcher_code per workspace.
CREATE TABLE IF NOT EXISTS assistant_researcher_memory (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_slug TEXT NOT NULL,
    researcher_code TEXT NOT NULL,
    memory_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    summary_text TEXT,
    evidence_file_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    confidence NUMERIC,
    source_updated_at TIMESTAMPTZ,
    memory_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (workspace_slug, researcher_code)
);
CREATE INDEX IF NOT EXISTS idx_arm_ws ON assistant_researcher_memory (workspace_slug);

-- Project memory: project_name is a free-text key (derived from
-- di_submissions.report_project or inferred from filename/topic).
CREATE TABLE IF NOT EXISTS assistant_project_memory (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_slug TEXT NOT NULL,
    project_name TEXT NOT NULL,
    memory_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    summary_text TEXT,
    evidence_file_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    confidence NUMERIC,
    source_updated_at TIMESTAMPTZ,
    memory_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (workspace_slug, project_name)
);
CREATE INDEX IF NOT EXISTS idx_apm_ws ON assistant_project_memory (workspace_slug);

-- Workspace memory: one row per workspace_slug.
CREATE TABLE IF NOT EXISTS assistant_workspace_memory (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_slug TEXT NOT NULL UNIQUE,
    memory_json JSONB NOT NULL DEFAULT '{}'::jsonb,
    summary_text TEXT,
    evidence_file_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
    confidence NUMERIC,
    source_updated_at TIMESTAMPTZ,
    memory_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Job log: every weekly update / rebuild writes one row so operators can
-- inspect progress, durations, and last error.
CREATE TABLE IF NOT EXISTS assistant_memory_jobs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_slug TEXT,
    job_kind TEXT NOT NULL,           -- 'weekly' | 'rebuild' | 'manual'
    job_status TEXT NOT NULL,         -- 'running' | 'ok' | 'failed'
    started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    finished_at TIMESTAMPTZ,
    files_processed INT DEFAULT 0,
    researchers_processed INT DEFAULT 0,
    projects_processed INT DEFAULT 0,
    workspace_processed BOOLEAN DEFAULT FALSE,
    error_text TEXT,
    notes JSONB DEFAULT '{}'::jsonb
);
CREATE INDEX IF NOT EXISTS idx_amj_ws ON assistant_memory_jobs (workspace_slug, started_at DESC);
CREATE INDEX IF NOT EXISTS idx_amj_kind ON assistant_memory_jobs (job_kind, started_at DESC);
