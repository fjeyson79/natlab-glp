-- Migration 043: Startup Position & Hidden Authority (Phase 1)
-- Adds workspace_position and internal authority flags to workspace_users.
-- Purely additive — no changes to existing columns or data.
-- Applies to COMPANY-type workspaces only (Theralia, Skinotek).

-- Leadership position (CEO, CSO, CTO, COO, Advisor, None)
ALTER TABLE workspace_users
    ADD COLUMN IF NOT EXISTS workspace_position TEXT DEFAULT NULL;

-- Hidden master authority flags (internal only, never shown in UI)
ALTER TABLE workspace_users
    ADD COLUMN IF NOT EXISTS is_workspace_master BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE workspace_users
    ADD COLUMN IF NOT EXISTS can_manage_users BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE workspace_users
    ADD COLUMN IF NOT EXISTS can_manage_workspace BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE workspace_users
    ADD COLUMN IF NOT EXISTS can_manage_portal BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE workspace_users
    ADD COLUMN IF NOT EXISTS view_management_tab BOOLEAN NOT NULL DEFAULT FALSE;

-- COMMENT: workspace_position stores a leadership title for COMPANY workspaces.
-- Valid values: 'CEO', 'CSO', 'CTO', 'COO', 'Advisor', or NULL (none).
-- Display: shown alongside role in portal header, e.g. "FOUNDER · CSO".
-- Kept separate from role — role is the access tier, position is the title.

-- COMMENT: Authority flags are internal-only and NEVER displayed in the UI.
-- is_workspace_master = TRUE grants full control equivalent to PI in lab context.
-- Other flags are granular permissions that can be toggled independently.
-- These flags are only meaningful for COMPANY workspace memberships.

-- Set Frank Hernandez as Founder · CSO with master authority in both startups.
-- Uses subquery to find researcher_id from allowlist by email.
UPDATE workspace_users
SET role = 'founder',
    workspace_position = 'CSO',
    is_workspace_master = TRUE,
    can_manage_users = TRUE,
    can_manage_workspace = TRUE,
    can_manage_portal = TRUE,
    view_management_tab = TRUE
WHERE user_id = (
    SELECT researcher_id FROM di_allowlist
    WHERE LOWER(institution_email) = 'frank.hernandez@liu.se'
    LIMIT 1
)
AND workspace_id IN (
    SELECT id FROM workspaces WHERE slug IN ('theralia', 'skinotek')
);
