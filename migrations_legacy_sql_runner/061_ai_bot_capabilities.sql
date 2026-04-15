-- Migration 061: AI_bot role capability list
-- Additive: adds JSONB capabilities column to di_allowlist for per-user AI_bot action gating.
-- Role value 'ai_bot' fits existing VARCHAR(20) role column (migration 002).

ALTER TABLE di_allowlist
    ADD COLUMN IF NOT EXISTS ai_bot_capabilities JSONB NOT NULL DEFAULT '{}'::jsonb;

COMMENT ON COLUMN di_allowlist.ai_bot_capabilities IS
    'Per-user capability flags for role=ai_bot. Keys: approve, revise, discard, seal, upload_files, edit_files, delete_files. All default OFF.';
