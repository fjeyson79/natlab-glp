-- Migration 014: File associations for Data Intelligence Console (DIC)
-- Manual PI-created links between DATA files and related SOPs/Presentations

CREATE TABLE IF NOT EXISTS di_file_associations (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    source_id UUID NOT NULL,
    target_id UUID NOT NULL,
    link_type VARCHAR(20) NOT NULL CHECK (link_type IN ('SOP', 'PRESENTATION')),
    created_by VARCHAR(50) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(source_id, target_id),
    CHECK (source_id != target_id)
);

CREATE INDEX IF NOT EXISTS idx_file_assoc_source ON di_file_associations(source_id);
CREATE INDEX IF NOT EXISTS idx_file_assoc_target ON di_file_associations(target_id);
CREATE INDEX IF NOT EXISTS idx_file_assoc_source_type ON di_file_associations(source_id, link_type);
CREATE INDEX IF NOT EXISTS idx_file_assoc_target_type ON di_file_associations(target_id, link_type);
