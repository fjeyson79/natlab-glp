-- Migration 045: Custom company section definitions
-- Allows users to create additional Company tab sections beyond built-in defaults

CREATE TABLE IF NOT EXISTS company_section_defs (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_slug  TEXT NOT NULL,
    section_key     TEXT NOT NULL,
    title           TEXT NOT NULL,
    sort_order      INT NOT NULL DEFAULT 100,
    is_custom       BOOLEAN NOT NULL DEFAULT TRUE,
    created_by      TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (workspace_slug, section_key)
);
