-- Migration 034: Portal Health & Workflow Event Logging
-- Creates tables for portal health snapshots and n8n workflow event logging.

-- n8n workflow event log — stores failure/success events reported by n8n webhooks
CREATE TABLE IF NOT EXISTS n8n_workflow_events (
    id            SERIAL PRIMARY KEY,
    workflow_name TEXT NOT NULL,
    status        TEXT NOT NULL DEFAULT 'failure',   -- 'failure' | 'success'
    detail        TEXT,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_n8n_workflow_events_created
    ON n8n_workflow_events (created_at DESC);

-- Portal health snapshot — single-row table holding latest computed health state
CREATE TABLE IF NOT EXISTS portal_health_snapshots (
    id              INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),  -- single-row enforcement
    overall_status  TEXT NOT NULL DEFAULT 'healthy',               -- healthy | warning | critical
    checked_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    categories      JSONB NOT NULL DEFAULT '{}',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed the single row so UPSERTs always work
INSERT INTO portal_health_snapshots (id, overall_status, categories)
VALUES (1, 'healthy', '{}')
ON CONFLICT (id) DO NOTHING;

-- Index for health recompute queries on di_submissions
CREATE INDEX IF NOT EXISTS idx_submissions_status_created
    ON di_submissions (status, created_at);
