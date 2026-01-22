-- Migration: Add signature and AI review columns to di_submissions table
-- Run this SQL in your Railway PostgreSQL database

-- Add signature columns if they don't exist
ALTER TABLE di_submissions
ADD COLUMN IF NOT EXISTS signature_hash VARCHAR(128);

ALTER TABLE di_submissions
ADD COLUMN IF NOT EXISTS verification_code VARCHAR(50);

ALTER TABLE di_submissions
ADD COLUMN IF NOT EXISTS signer_name VARCHAR(100);

ALTER TABLE di_submissions
ADD COLUMN IF NOT EXISTS signer_email VARCHAR(100);

ALTER TABLE di_submissions
ADD COLUMN IF NOT EXISTS ai_review_score INTEGER;

ALTER TABLE di_submissions
ADD COLUMN IF NOT EXISTS ai_review_decision VARCHAR(20);

-- Create index on verification_code for fast lookups
CREATE INDEX IF NOT EXISTS idx_di_submissions_verification_code
ON di_submissions(verification_code);

-- Verify the columns were added
SELECT column_name, data_type, is_nullable
FROM information_schema.columns
WHERE table_name = 'di_submissions'
AND column_name IN ('signature_hash', 'verification_code', 'signer_name', 'signer_email', 'ai_review_score', 'ai_review_decision')
ORDER BY column_name;
