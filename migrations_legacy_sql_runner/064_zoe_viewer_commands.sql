-- Migration 064: Zoe viewer command queue (v1: pending-only)
-- One row per POST /api/assistant/viewer/open. The portal browser polls for
-- pending commands in a later phase and transitions them to CONSUMED.
-- v1 is write-only from the API side; there is no consumption endpoint yet.
--
-- Additive only. No changes to existing tables.

CREATE TABLE IF NOT EXISTS zoe_viewer_commands (
    id                 UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id       UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    control_session_id UUID NOT NULL REFERENCES zoe_control_sessions(id) ON DELETE CASCADE,
    -- file_id is an rd_documents.id (UUID). We do not add a hard FK so this
    -- queue can accept additional source tables in a later phase without a
    -- schema change; validation is enforced in the API layer.
    file_id            UUID NOT NULL,
    mode               VARCHAR(32) NOT NULL DEFAULT 'viewer',
    status             VARCHAR(16) NOT NULL DEFAULT 'PENDING',
    created_at         TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    consumed_at        TIMESTAMPTZ,
    CONSTRAINT zoe_viewer_commands_status_chk
        CHECK (status IN ('PENDING','CONSUMED'))
);

CREATE INDEX IF NOT EXISTS idx_zoe_viewer_commands_session_status
    ON zoe_viewer_commands (control_session_id, status, created_at);

CREATE INDEX IF NOT EXISTS idx_zoe_viewer_commands_ws
    ON zoe_viewer_commands (workspace_id, created_at DESC);

COMMENT ON TABLE zoe_viewer_commands IS
    'Pending "open file" commands queued by Zoe for a registered control session. v1: write-only — consumption endpoint arrives in a later phase.';
