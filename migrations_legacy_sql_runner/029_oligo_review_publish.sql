-- ============================================
-- Oligo-ID Review + Publish Layer (SAFE ADDITIVE)
-- Migration 029
-- ============================================

-- 1) Pack finalization fields (additive)
ALTER TABLE oligo_pdf_imports
  ADD COLUMN IF NOT EXISTS finalized_by TEXT,
  ADD COLUMN IF NOT EXISTS finalized_at TIMESTAMPTZ;

-- 2) Link syntheses to import items (Option 1: QC remains in import tables)
ALTER TABLE probe_syntheses
  ADD COLUMN IF NOT EXISTS synthesis_oligo_no TEXT,
  ADD COLUMN IF NOT EXISTS source_import_id UUID,
  ADD COLUMN IF NOT EXISTS source_import_item_id UUID;

-- Foreign keys for traceability (no cascade)
ALTER TABLE probe_syntheses
  ADD CONSTRAINT IF NOT EXISTS probe_syntheses_source_import_id_fkey
  FOREIGN KEY (source_import_id) REFERENCES oligo_pdf_imports(id);

ALTER TABLE probe_syntheses
  ADD CONSTRAINT IF NOT EXISTS probe_syntheses_source_import_item_id_fkey
  FOREIGN KEY (source_import_item_id) REFERENCES oligo_pdf_import_items(id);

-- Indexes
CREATE INDEX IF NOT EXISTS idx_probe_syntheses_source_import_id
  ON probe_syntheses(source_import_id);

CREATE INDEX IF NOT EXISTS idx_probe_syntheses_source_import_item_id
  ON probe_syntheses(source_import_item_id);

CREATE INDEX IF NOT EXISTS idx_probe_syntheses_synthesis_oligo_no
  ON probe_syntheses(synthesis_oligo_no);
