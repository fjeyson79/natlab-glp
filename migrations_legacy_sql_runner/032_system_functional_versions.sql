-- ============================================
-- System Functional Versions
-- Migration 032
-- Secure registry of system recovery packages
-- ============================================

CREATE TABLE IF NOT EXISTS system_versions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    version_label   TEXT NOT NULL,
    title           TEXT,
    description     TEXT,
    git_commit          TEXT,
    db_schema_version   TEXT,
    status              TEXT NOT NULL DEFAULT 'DRAFT',
    created_by      UUID,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    files           JSONB NOT NULL DEFAULT '{}'::jsonb,

    CONSTRAINT uq_system_versions_label UNIQUE (version_label)
);

CREATE INDEX IF NOT EXISTS idx_system_versions_status ON system_versions(status);
