-- ============================================
-- Oligo-ID Pack Architecture
-- Migration 028
-- ============================================

-- ================================
-- 1. PACK TABLE (PDF level)
-- ================================

CREATE TABLE IF NOT EXISTS oligo_pdf_imports (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    supplier TEXT NOT NULL,
    original_filename TEXT NOT NULL,
    file_storage_key TEXT NOT NULL,
    file_sha256 TEXT NOT NULL,

    po_no TEXT,
    order_no TEXT,

    parse_version TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'PENDING',

    uploaded_by TEXT NOT NULL,
    uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    UNIQUE (supplier, file_sha256)
);

-- Optional stricter duplication rule
-- ALTER TABLE oligo_pdf_imports
-- ADD CONSTRAINT unique_supplier_order UNIQUE (supplier, order_no);



-- ================================
-- 2. PACK ITEMS TABLE (Oligo level)
-- ================================

CREATE TABLE IF NOT EXISTS oligo_pdf_import_items (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    import_id UUID NOT NULL REFERENCES oligo_pdf_imports(id) ON DELETE CASCADE,

    supplier TEXT NOT NULL,

    -- Mandatory constrained columns
    canonical_id TEXT NOT NULL,             -- Order#
    polymer_type TEXT NOT NULL,             -- Type
    synthesis_oligo_no TEXT NOT NULL,       -- SynthesisOligo#
    sequence_5to3 TEXT NOT NULL,

    mod_5 TEXT NOT NULL,
    mod_3 TEXT NOT NULL,

    int_mod_5 TEXT NOT NULL,
    int_mod_6 TEXT NOT NULL,
    int_mod_7 TEXT NOT NULL,
    int_mod_8 TEXT NOT NULL,

    -- Template storage
    template_json JSONB NOT NULL,
    template_json_pi JSONB,

    warnings JSONB DEFAULT '[]'::jsonb,
    requires_pi_confirmation BOOLEAN NOT NULL DEFAULT FALSE,

    decision_status TEXT DEFAULT 'PENDING',
    decided_by TEXT,
    decided_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    -- Within-pack duplication protection
    UNIQUE (import_id, canonical_id),

    -- Global duplication protection per supplier
    UNIQUE (supplier, synthesis_oligo_no)
);

-- Index for faster lookups
CREATE INDEX IF NOT EXISTS idx_oligo_pdf_import_items_import_id
ON oligo_pdf_import_items(import_id);

CREATE INDEX IF NOT EXISTS idx_oligo_pdf_import_items_supplier
ON oligo_pdf_import_items(supplier);
