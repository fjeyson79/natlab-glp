-- Migration 041: User Clearance & Membership Class (Phase 1.3)
-- Adds governance columns to workspace_users for membership_class,
-- clearance_profile, content-scope flags, status, and notes.
-- Purely additive — no changes to existing tables or data.

-- membership_class: core (broad default) vs collaborator (restricted by default)
ALTER TABLE workspace_users
    ADD COLUMN IF NOT EXISTS membership_class TEXT NOT NULL DEFAULT 'core'
        CHECK (membership_class IN ('core', 'collaborator'));

-- clearance_profile: governs access profile for the user in this workspace
ALTER TABLE workspace_users
    ADD COLUMN IF NOT EXISTS clearance_profile TEXT NOT NULL DEFAULT 'standard'
        CHECK (clearance_profile IN ('upload_only', 'standard', 'scientific', 'non_scientific', 'custom'));

-- content-scope booleans
ALTER TABLE workspace_users
    ADD COLUMN IF NOT EXISTS scientific_access BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE workspace_users
    ADD COLUMN IF NOT EXISTS operational_access BOOLEAN NOT NULL DEFAULT TRUE;

ALTER TABLE workspace_users
    ADD COLUMN IF NOT EXISTS administrative_access BOOLEAN NOT NULL DEFAULT FALSE;

-- status lifecycle (extends is_active into richer states)
ALTER TABLE workspace_users
    ADD COLUMN IF NOT EXISTS status TEXT NOT NULL DEFAULT 'active'
        CHECK (status IN ('active', 'suspended', 'removed'));

-- optional PI note per workspace membership
ALTER TABLE workspace_users
    ADD COLUMN IF NOT EXISTS notes TEXT;
