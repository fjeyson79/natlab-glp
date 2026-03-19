-- Migration 036: Multi-workspace foundation (Phase 1)
-- Adds workspaces + workspace_users tables with seed data.
-- Purely additive — no changes to existing tables or behavior.

CREATE TABLE IF NOT EXISTS workspaces (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    slug TEXT UNIQUE NOT NULL,
    name TEXT NOT NULL,
    workspace_type TEXT NOT NULL CHECK (workspace_type IN ('LAB', 'COMPANY')),
    portal_host TEXT,
    logo_url TEXT,
    theme_color TEXT,
    header_title TEXT,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS workspace_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    user_id VARCHAR(50) NOT NULL REFERENCES di_allowlist(researcher_id) ON DELETE CASCADE,
    role TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT TRUE,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW(),
    UNIQUE(workspace_id, user_id)
);

CREATE INDEX IF NOT EXISTS idx_workspace_users_user
    ON workspace_users(user_id);

CREATE INDEX IF NOT EXISTS idx_workspace_users_workspace
    ON workspace_users(workspace_id);

-- Seed workspaces
INSERT INTO workspaces (slug, name, workspace_type, portal_host)
VALUES
    ('natlab',   'NAT-Lab',   'LAB',     NULL),
    ('skinotek', 'SKINOTEK',  'COMPANY', NULL),
    ('theralia', 'Theralia',  'COMPANY', NULL)
ON CONFLICT (slug) DO NOTHING;
