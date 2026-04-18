-- Migration 063: Zoe portal control sessions (ephemeral registration)
-- v1: registration only. Lets Zoe register one active browser session she can
-- later send an open/navigate command to. No command queue, no websocket, no
-- polling yet — those are future phases.
--
-- Additive only. No changes to existing tables.

CREATE TABLE IF NOT EXISTS zoe_control_sessions (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id    UUID NOT NULL REFERENCES workspaces(id) ON DELETE CASCADE,
    session_token   TEXT NOT NULL,
    mode            VARCHAR(32) NOT NULL DEFAULT 'viewer',
    is_active       BOOLEAN NOT NULL DEFAULT TRUE,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at      TIMESTAMPTZ NOT NULL
);

-- One active registration per (workspace, session_token). Re-registering the
-- same token in the same workspace refreshes the existing row via ON CONFLICT.
CREATE UNIQUE INDEX IF NOT EXISTS uq_zoe_control_sessions_ws_token
    ON zoe_control_sessions (workspace_id, session_token);

CREATE INDEX IF NOT EXISTS idx_zoe_control_sessions_active
    ON zoe_control_sessions (workspace_id, is_active, expires_at);

COMMENT ON TABLE zoe_control_sessions IS
    'Ephemeral Zoe portal-control sessions. One record = one registered browser session. Short TTL (~30 min).';
