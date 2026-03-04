-- Migration: Add di_group_documents table for shared lab documents
-- Group Documents are managed by PI, viewable/downloadable by all researchers

CREATE TABLE IF NOT EXISTS di_group_documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    category VARCHAR(100) NOT NULL,
    description TEXT,
    filename VARCHAR(500) NOT NULL,
    file_type VARCHAR(20) NOT NULL CHECK (file_type IN ('PDF', 'EXCEL', 'WORD', 'POWERPOINT')),
    r2_object_key VARCHAR(1000) NOT NULL,
    uploaded_by VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    is_active BOOLEAN DEFAULT TRUE
);

-- Index for faster lookups
CREATE INDEX IF NOT EXISTS idx_di_group_documents_category ON di_group_documents(category);
CREATE INDEX IF NOT EXISTS idx_di_group_documents_active ON di_group_documents(is_active);

-- Comments explaining the table
COMMENT ON TABLE di_group_documents IS 'Shared lab documents (SOPs, guidelines, templates) managed by PI';
COMMENT ON COLUMN di_group_documents.category IS 'Document category (e.g., SOP, Guidelines, Templates)';
COMMENT ON COLUMN di_group_documents.file_type IS 'File format: PDF, EXCEL, WORD, POWERPOINT';
COMMENT ON COLUMN di_group_documents.r2_object_key IS 'Cloudflare R2 storage key (no r2: prefix)';
