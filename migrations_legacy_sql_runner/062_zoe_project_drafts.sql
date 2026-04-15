-- Migration 062: Zoe project drafts (idea layer)
-- Minimal, workspace-scoped draft/idea table. NOT connected to live project
-- tables (rd_projects / di_studio_projects) — drafts are a separate layer.
-- AI_bot can create drafts only when the `create_project_drafts` capability
-- is explicitly enabled on its account.

CREATE TABLE IF NOT EXISTS zoe_project_drafts (
    id              SERIAL PRIMARY KEY,
    workspace_id    INTEGER NULL,
    title           VARCHAR(255) NOT NULL,
    short_description TEXT NULL,
    notes           TEXT NULL,
    status          VARCHAR(32) NOT NULL DEFAULT 'draft',
    tags            TEXT NULL,
    related_project_id INTEGER NULL,
    created_by      VARCHAR(64) NOT NULL,
    created_by_role VARCHAR(32) NULL,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    CONSTRAINT zoe_project_drafts_status_chk
        CHECK (status IN ('draft', 'under_review', 'approved', 'archived'))
);

CREATE INDEX IF NOT EXISTS idx_zoe_drafts_ws_created
    ON zoe_project_drafts (workspace_id, created_at DESC);
CREATE INDEX IF NOT EXISTS idx_zoe_drafts_status
    ON zoe_project_drafts (status);

COMMENT ON TABLE zoe_project_drafts IS
    'Idea / draft-project layer for Zoe (AI_bot). Separate from live projects.';
COMMENT ON COLUMN zoe_project_drafts.status IS
    'draft | under_review | approved | archived. Promotion to a live project is a manual PI action, not an automatic transition.';
