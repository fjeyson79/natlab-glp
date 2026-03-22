-- Migration 042: Module Access JSON (Phase 1.4)
-- Adds module_access_json column to workspace_users for manual tab/module
-- selection when clearance_profile is 'non_scientific' or 'custom'.
-- Purely additive — no changes to existing columns or data.

ALTER TABLE workspace_users
    ADD COLUMN IF NOT EXISTS module_access_json TEXT;

-- COMMENT: module_access_json stores a JSON object like:
-- {"upload":true,"glp_vision":false,"inventory":true,"supervision":false,...}
-- Only used when clearance_profile IN ('non_scientific','custom').
-- For other profiles, effective access is computed from role + clearance_profile + membership_class.
