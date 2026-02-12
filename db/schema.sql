-- Enable pgcrypto extension for gen_random_uuid
CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- Allowlist table: only these emails can register
CREATE TABLE IF NOT EXISTS di_allowlist (
    researcher_id VARCHAR(50) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    institution_email VARCHAR(255) UNIQUE NOT NULL,
    affiliation VARCHAR(10) NOT NULL CHECK (affiliation IN ('LiU', 'UNAV')),
    active BOOLEAN DEFAULT TRUE
);

-- Users table: registered users with hashed passwords
CREATE TABLE IF NOT EXISTS di_users (
    institution_email VARCHAR(255) PRIMARY KEY,
    personal_email VARCHAR(255),
    password_hash VARCHAR(255) NOT NULL,
    researcher_id VARCHAR(50) NOT NULL REFERENCES di_allowlist(researcher_id),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP
);

-- Submissions table: file upload records
CREATE TABLE IF NOT EXISTS di_submissions (
    submission_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    researcher_id VARCHAR(50) NOT NULL,
    affiliation VARCHAR(10) NOT NULL CHECK (affiliation IN ('LiU', 'UNAV')),
    file_type VARCHAR(20) NOT NULL CHECK (file_type IN ('SOP', 'DATA', 'INVENTORY', 'PRESENTATION')),
    original_filename VARCHAR(500) NOT NULL,
    status VARCHAR(20) DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REVISION_NEEDED')),
    sender_email VARCHAR(255),
    ai_review JSONB,
    revision_comments TEXT,
    signed_at TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Migration: Add new columns if table already exists
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS sender_email VARCHAR(255);
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS ai_review JSONB;
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS revision_comments TEXT;
ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS signed_at TIMESTAMP;

-- Index for faster lookups
CREATE INDEX IF NOT EXISTS idx_di_submissions_researcher ON di_submissions(researcher_id);
CREATE INDEX IF NOT EXISTS idx_di_allowlist_email ON di_allowlist(institution_email);
