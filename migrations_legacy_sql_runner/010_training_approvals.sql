-- Migration 010: Training & Approvals
-- Adds tables for training document management, training packs, agreements, entries, and seal snapshots.

-- Logical training documents (PI-managed master list)
CREATE TABLE IF NOT EXISTS di_training_documents (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    title VARCHAR(255) NOT NULL,
    category VARCHAR(50) NOT NULL CHECK (category IN ('Guidelines','Authorship','Safety','Other')),
    affiliation VARCHAR(10) NOT NULL CHECK (affiliation IN ('LiU','UNAV','All')),
    requirement_rule VARCHAR(20) NOT NULL CHECK (requirement_rule IN ('Always','Conditional','Optional')),
    condition_key VARCHAR(50),
    condition_note TEXT,
    display_order INTEGER NOT NULL DEFAULT 0,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_training_docs_active ON di_training_documents(is_active);

-- Immutable document versions (each upload = new row)
CREATE TABLE IF NOT EXISTS di_training_document_versions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    document_id UUID NOT NULL REFERENCES di_training_documents(id),
    version INTEGER NOT NULL DEFAULT 1,
    r2_object_key VARCHAR(1000) NOT NULL,
    original_filename VARCHAR(500) NOT NULL,
    uploaded_by VARCHAR(50) NOT NULL,
    is_current BOOLEAN DEFAULT TRUE,
    uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_training_doc_versions_doc ON di_training_document_versions(document_id);
CREATE INDEX IF NOT EXISTS idx_training_doc_versions_current ON di_training_document_versions(is_current);
CREATE UNIQUE INDEX IF NOT EXISTS idx_training_doc_versions_one_current
    ON di_training_document_versions(document_id) WHERE is_current = TRUE;

-- Training packs (one per researcher per version)
CREATE TABLE IF NOT EXISTS di_training_packs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    researcher_id VARCHAR(50) NOT NULL,
    version INTEGER NOT NULL DEFAULT 1,
    status VARCHAR(20) DEFAULT 'DRAFT' CHECK (status IN ('DRAFT','SUBMITTED','REVISION_NEEDED','SEALED')),
    sealed_at TIMESTAMP,
    sealed_by VARCHAR(50),
    revision_comments TEXT,
    certificate_r2_key VARCHAR(1000),
    signature_hash VARCHAR(128),
    verification_code VARCHAR(50),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_training_packs_researcher ON di_training_packs(researcher_id);
CREATE INDEX IF NOT EXISTS idx_training_packs_status ON di_training_packs(status);

-- Agreement acknowledgments (references exact document version)
CREATE TABLE IF NOT EXISTS di_training_agreements (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pack_id UUID NOT NULL REFERENCES di_training_packs(id),
    document_id UUID NOT NULL REFERENCES di_training_documents(id),
    document_version_id UUID NOT NULL REFERENCES di_training_document_versions(id),
    confirmed_by VARCHAR(50) NOT NULL,
    confirmed_name VARCHAR(255) NOT NULL,
    confirmed_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_training_agreements_pack ON di_training_agreements(pack_id);

-- Training entries (researcher logs training, supervisor certifies)
CREATE TABLE IF NOT EXISTS di_training_entries (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    pack_id UUID NOT NULL REFERENCES di_training_packs(id),
    training_type VARCHAR(255) NOT NULL,
    training_date DATE NOT NULL,
    notes TEXT,
    supervisor_id VARCHAR(50) NOT NULL,
    trainee_declaration_name VARCHAR(255) NOT NULL,
    trainee_declaration_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    status VARCHAR(20) DEFAULT 'PENDING' CHECK (status IN ('PENDING','CERTIFIED','REJECTED')),
    certified_at TIMESTAMP,
    rejection_comment TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS idx_training_entries_pack ON di_training_entries(pack_id);
CREATE INDEX IF NOT EXISTS idx_training_entries_supervisor ON di_training_entries(supervisor_id);
CREATE INDEX IF NOT EXISTS idx_training_entries_status ON di_training_entries(status);

-- Snapshot of exact document version IDs at seal time
CREATE TABLE IF NOT EXISTS di_training_pack_snapshots (
    pack_id UUID NOT NULL REFERENCES di_training_packs(id),
    document_id UUID NOT NULL REFERENCES di_training_documents(id),
    document_version_id UUID NOT NULL REFERENCES di_training_document_versions(id),
    PRIMARY KEY (pack_id, document_id)
);
