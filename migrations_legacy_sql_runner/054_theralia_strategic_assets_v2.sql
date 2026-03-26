-- Migration 054: Theralia Strategic Assets v2
-- Adds details_json JSONB + summary column to theralia_strategic_assets
-- Creates theralia_strategic_asset_files for supporting document uploads

-- Add new columns to strategic assets
ALTER TABLE theralia_strategic_assets ADD COLUMN IF NOT EXISTS summary TEXT;
ALTER TABLE theralia_strategic_assets ADD COLUMN IF NOT EXISTS details_json JSONB;

-- Supporting files for strategic assets (Lead Candidate PDFs, patent docs, etc.)
CREATE TABLE IF NOT EXISTS theralia_strategic_asset_files (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    asset_id UUID NOT NULL REFERENCES theralia_strategic_assets(id) ON DELETE CASCADE,
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    file_name TEXT NOT NULL,
    file_type TEXT,
    r2_object_key TEXT NOT NULL,
    description TEXT,
    uploaded_by TEXT NOT NULL,
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_theralia_asset_files_asset ON theralia_strategic_asset_files(asset_id);
CREATE INDEX IF NOT EXISTS idx_theralia_asset_files_ws ON theralia_strategic_asset_files(workspace_id);
