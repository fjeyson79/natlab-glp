-- Migration 031: Oligo Inventory References
-- Reference-only tables for researcher/supervisor oligo inventory.
-- No duplication of molecular data — just pointers to probe_catalog and probe_libraries.

CREATE TABLE IF NOT EXISTS di_inventory_oligo_refs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id TEXT NOT NULL,
    probe_id UUID NOT NULL,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_inv_oligo_ref_user_probe
    ON di_inventory_oligo_refs (user_id, probe_id);

CREATE TABLE IF NOT EXISTS di_inventory_library_refs (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id TEXT NOT NULL,
    library_id UUID NOT NULL,
    notes TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_inv_lib_ref_user_library
    ON di_inventory_library_refs (user_id, library_id);
