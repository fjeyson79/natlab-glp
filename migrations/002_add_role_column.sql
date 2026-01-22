-- Migration: Add role column to di_allowlist table
-- Run this SQL in your Railway PostgreSQL database

-- Add role column if it doesn't exist
ALTER TABLE di_allowlist
ADD COLUMN IF NOT EXISTS role VARCHAR(20) DEFAULT 'researcher';

-- Set frank.hernandez@liu.se as PI
UPDATE di_allowlist
SET role = 'pi'
WHERE LOWER(institution_email) = 'frank.hernandez@liu.se';

-- Verify the update
SELECT researcher_id, name, institution_email, affiliation, role
FROM di_allowlist
ORDER BY role DESC, name ASC;
