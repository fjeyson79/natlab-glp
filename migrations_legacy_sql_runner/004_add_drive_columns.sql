-- Migration: Add Google Drive storage columns to di_submissions table

ALTER TABLE di_submissions
ADD COLUMN IF NOT EXISTS drive_file_id VARCHAR(100);

ALTER TABLE di_submissions
ADD COLUMN IF NOT EXISTS revision_comments TEXT;

-- Create index on drive_file_id for lookups
CREATE INDEX IF NOT EXISTS idx_di_submissions_drive_file_id
ON di_submissions(drive_file_id);

-- Verify columns
SELECT column_name, data_type
FROM information_schema.columns
WHERE table_name = 'di_submissions'
AND column_name IN ('drive_file_id', 'revision_comments', 'signed_pdf_path')
ORDER BY column_name;
