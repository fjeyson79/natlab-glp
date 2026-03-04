-- Migration 015: Purchase item correction workflow
-- Researchers request modifications/cancellations on approved items; PI accepts or rejects

-- Item-level status for correction workflow
ALTER TABLE di_purchase_items ADD COLUMN IF NOT EXISTS item_status TEXT NOT NULL DEFAULT 'Active';
ALTER TABLE di_purchase_items ADD COLUMN IF NOT EXISTS status_note TEXT;
ALTER TABLE di_purchase_items ADD COLUMN IF NOT EXISTS proposed_vendor TEXT;
ALTER TABLE di_purchase_items ADD COLUMN IF NOT EXISTS proposed_product TEXT;
ALTER TABLE di_purchase_items ADD COLUMN IF NOT EXISTS proposed_catalog_id TEXT;
ALTER TABLE di_purchase_items ADD COLUMN IF NOT EXISTS proposed_link TEXT;
ALTER TABLE di_purchase_items ADD COLUMN IF NOT EXISTS proposed_qty NUMERIC;
ALTER TABLE di_purchase_items ADD COLUMN IF NOT EXISTS proposed_unit_price NUMERIC;
ALTER TABLE di_purchase_items ADD COLUMN IF NOT EXISTS modified_by TEXT;
ALTER TABLE di_purchase_items ADD COLUMN IF NOT EXISTS modified_at TIMESTAMPTZ;
ALTER TABLE di_purchase_items ADD COLUMN IF NOT EXISTS pi_decision_note TEXT;
ALTER TABLE di_purchase_items ADD COLUMN IF NOT EXISTS pi_decision_at TIMESTAMPTZ;
CREATE INDEX IF NOT EXISTS idx_di_purchase_items_status ON di_purchase_items(item_status);

-- Audit log for purchase item actions
CREATE TABLE IF NOT EXISTS di_purchase_audit (
    id SERIAL PRIMARY KEY,
    request_id UUID,
    item_id UUID,
    action TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_role TEXT NOT NULL,
    old_json JSONB,
    new_json JSONB,
    note TEXT,
    at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_di_purchase_audit_item ON di_purchase_audit(item_id);
CREATE INDEX IF NOT EXISTS idx_di_purchase_audit_request ON di_purchase_audit(request_id);
