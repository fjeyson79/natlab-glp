-- Migration 025: Research Studio Phase 2, locks and structured comments
-- Additive only; no existing tables are modified.

-- 1. Editing locks (one lock per project, atomic acquire)
CREATE TABLE IF NOT EXISTS di_studio_locks (
    project_id          UUID PRIMARY KEY REFERENCES di_studio_projects(id)
                            ON DELETE CASCADE,
    locked_by_researcher_id VARCHAR(50) NOT NULL,
    locked_by_name      VARCHAR(255) NOT NULL,
    locked_by_role      VARCHAR(30) NOT NULL,
    locked_at           TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at          TIMESTAMPTZ NOT NULL DEFAULT (NOW() + INTERVAL '8 minutes')
);

CREATE INDEX IF NOT EXISTS idx_studio_locks_expires
    ON di_studio_locks(expires_at);

-- 2. Structured comments (PI, supervisor, owner can comment on any target)
CREATE TABLE IF NOT EXISTS di_studio_comments (
    id                  UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id          UUID NOT NULL REFERENCES di_studio_projects(id)
                            ON DELETE CASCADE,
    target_type         VARCHAR(20) NOT NULL CHECK (target_type IN (
                            'reflection','section','figure')),
    target_key          VARCHAR(100) NOT NULL,
    comment_type        VARCHAR(30) NOT NULL CHECK (comment_type IN (
                            'Strategic','Methodological','Interpretative',
                            'Risk warning','Encouragement')),
    body                TEXT NOT NULL,
    author_id           VARCHAR(50) NOT NULL,
    author_name         VARCHAR(255) NOT NULL,
    author_role         VARCHAR(30) NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    resolved            BOOLEAN NOT NULL DEFAULT FALSE,
    resolved_by_id      VARCHAR(50),
    resolved_by_name    VARCHAR(255),
    resolved_at         TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_studio_comments_project
    ON di_studio_comments(project_id);
CREATE INDEX IF NOT EXISTS idx_studio_comments_target
    ON di_studio_comments(project_id, target_type, target_key);
CREATE INDEX IF NOT EXISTS idx_studio_comments_unresolved
    ON di_studio_comments(project_id) WHERE resolved = FALSE;
