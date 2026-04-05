-- Migration 058: Add tab_visibility_json to workspace_users
-- Stores per-user tab visibility overrides as JSON text
-- Used by NAT-Lab PI portal to control which tabs each user sees
-- Example: {"dashboard":true,"lab_files":true,"glp_console":false,...}

ALTER TABLE workspace_users ADD COLUMN IF NOT EXISTS tab_visibility_json TEXT;

COMMENT ON COLUMN workspace_users.tab_visibility_json IS 'JSON object mapping tab keys to boolean visibility. NULL = role defaults apply.';
