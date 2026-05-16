-- Migration 068: REPORT intelligence layer
--
-- One row per REPORT submission, containing rule-based extraction output
-- (no embeddings, no LLMs). Populated by services/reportIntelligence.js
-- right after a successful /api/di/upload-report.
--
-- The table is intentionally narrow: submission_id is UNIQUE so the upload
-- path can ON CONFLICT DO UPDATE re-runs. NULLABLE everywhere so the
-- "extract failed" / "unsupported file type" paths can still write a row
-- and surface extraction_status to callers.

CREATE TABLE IF NOT EXISTS assistant_report_intelligence (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    submission_id UUID NOT NULL UNIQUE,
    workspace_id UUID,
    researcher_id TEXT,
    report_subcategory TEXT,
    report_status TEXT,
    project TEXT,
    reporting_period_start DATE,
    reporting_period_end DATE,
    supervisor TEXT,
    title TEXT,
    short_summary TEXT,
    key_conclusions JSONB DEFAULT '[]'::jsonb,
    limitations JSONB DEFAULT '[]'::jsonb,
    future_work JSONB DEFAULT '[]'::jsonb,
    related_methods JSONB DEFAULT '[]'::jsonb,
    related_assays JSONB DEFAULT '[]'::jsonb,
    related_sops JSONB DEFAULT '[]'::jsonb,
    related_data_files JSONB DEFAULT '[]'::jsonb,
    detected_project_themes JSONB DEFAULT '[]'::jsonb,
    detected_keywords JSONB DEFAULT '[]'::jsonb,
    scientific_maturity_signal TEXT,
    glp_relevance_signal TEXT,
    source_text_chars INT,
    extraction_status TEXT,
    extraction_error TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_ari_workspace_researcher
    ON assistant_report_intelligence (workspace_id, researcher_id);

CREATE INDEX IF NOT EXISTS idx_ari_subcategory
    ON assistant_report_intelligence (report_subcategory);

CREATE INDEX IF NOT EXISTS idx_ari_status
    ON assistant_report_intelligence (extraction_status);
