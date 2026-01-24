-- Migration: Rename drive_* columns to r2_* and strip r2: prefix
-- Part of Google Drive removal - switching to Cloudflare R2 naming

-- Step 1: Rename drive_file_id to r2_object_key
ALTER TABLE di_submissions
RENAME COLUMN drive_file_id TO r2_object_key;

-- Step 2: Add r2_error column (drive_error may or may not exist)
ALTER TABLE di_submissions
ADD COLUMN IF NOT EXISTS r2_error TEXT;

-- Step 3: Add r2_last_attempt column (drive_last_attempt may or may not exist)
ALTER TABLE di_submissions
ADD COLUMN IF NOT EXISTS r2_last_attempt TIMESTAMPTZ;

-- Step 4: Drop old drive_error and drive_last_attempt if they exist
-- (safe to run even if they don't exist)
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'di_submissions' AND column_name = 'drive_error') THEN
        ALTER TABLE di_submissions DROP COLUMN drive_error;
    END IF;

    IF EXISTS (SELECT 1 FROM information_schema.columns
               WHERE table_name = 'di_submissions' AND column_name = 'drive_last_attempt') THEN
        ALTER TABLE di_submissions DROP COLUMN drive_last_attempt;
    END IF;
END $$;

-- Step 5: Strip 'r2:' prefix from existing r2_object_key values
UPDATE di_submissions
SET r2_object_key = SUBSTRING(r2_object_key FROM 4)
WHERE r2_object_key LIKE 'r2:%';

-- Step 6: Rename the index
ALTER INDEX IF EXISTS idx_di_submissions_drive_file_id
RENAME TO idx_di_submissions_r2_object_key;

-- Verify the changes
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = 'di_submissions'
AND column_name IN ('r2_object_key', 'r2_error', 'r2_last_attempt', 'revision_comments')
ORDER BY column_name;
