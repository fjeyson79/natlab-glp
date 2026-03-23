-- Migration 044: Company tab - statement versioning + supporting documents
-- Provides structured corporate/legal workspace with full version history

CREATE TABLE IF NOT EXISTS company_statements (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_slug  TEXT NOT NULL,
    section_key     TEXT NOT NULL,
    content         JSONB NOT NULL DEFAULT '{}',
    status          TEXT NOT NULL DEFAULT 'current' CHECK (status IN ('current', 'archived')),
    saved_by        TEXT,
    saved_at        TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Only one current version per workspace+section
CREATE UNIQUE INDEX IF NOT EXISTS uq_company_stmt_current
    ON company_statements (workspace_slug, section_key)
    WHERE status = 'current';

CREATE INDEX IF NOT EXISTS idx_company_stmt_section
    ON company_statements (workspace_slug, section_key, status);

CREATE TABLE IF NOT EXISTS company_documents (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_slug  TEXT NOT NULL,
    section_key     TEXT NOT NULL,
    filename        TEXT NOT NULL,
    category        TEXT,
    r2_key          TEXT NOT NULL,
    content_type    TEXT DEFAULT 'application/pdf',
    file_size       BIGINT,
    uploaded_by     TEXT,
    uploaded_at     TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_company_docs_section
    ON company_documents (workspace_slug, section_key);
