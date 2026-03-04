-- Migration 009: Add EXTERNAL affiliation support and force_password_reset flag
-- This enables:
-- 1. Adding external users (non-LIU/UNAV) to the allowlist
-- 2. Admin-triggered password reset for researchers/supervisors

-- =============================================================================
-- PART 1: Add EXTERNAL affiliation support
-- =============================================================================

-- 1a. Drop existing affiliation constraint on di_allowlist
ALTER TABLE di_allowlist DROP CONSTRAINT IF EXISTS di_allowlist_affiliation_check;

-- 1b. Add new constraint that includes EXTERNAL
ALTER TABLE di_allowlist ADD CONSTRAINT di_allowlist_affiliation_check
    CHECK (affiliation IN ('LiU', 'UNAV', 'EXTERNAL'));

-- 1c. Drop existing affiliation constraint on di_submissions
ALTER TABLE di_submissions DROP CONSTRAINT IF EXISTS di_submissions_affiliation_check;

-- 1d. Add new constraint that includes EXTERNAL
ALTER TABLE di_submissions ADD CONSTRAINT di_submissions_affiliation_check
    CHECK (affiliation IN ('LiU', 'UNAV', 'EXTERNAL'));

-- =============================================================================
-- PART 2: Add force_password_reset flag to di_users
-- =============================================================================

-- 2a. Add the column with default false (existing users unaffected)
ALTER TABLE di_users ADD COLUMN IF NOT EXISTS force_password_reset BOOLEAN DEFAULT FALSE;

-- 2b. Add comment for documentation
COMMENT ON COLUMN di_users.force_password_reset IS 'When true, user must set new password on next login';

-- =============================================================================
-- Verification queries (run manually to confirm)
-- =============================================================================
-- Check constraints:
-- SELECT conname, pg_get_constraintdef(oid) FROM pg_constraint WHERE conname LIKE '%affiliation%';
--
-- Check new column:
-- SELECT column_name, data_type, column_default FROM information_schema.columns
-- WHERE table_name = 'di_users' AND column_name = 'force_password_reset';
