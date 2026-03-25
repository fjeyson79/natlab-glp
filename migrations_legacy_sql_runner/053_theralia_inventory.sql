-- Migration 053: Theralia Inventory — Purchases, Strategic Assets, Asset Classes
-- Tables scoped to Theralia workspace. Does not modify NAT-Lab tables.

-- Asset class definitions (dynamic categories for strategic assets)
CREATE TABLE IF NOT EXISTS theralia_asset_classes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    class_key TEXT NOT NULL,
    display_name TEXT NOT NULL,
    is_default BOOLEAN NOT NULL DEFAULT FALSE,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE (workspace_id, class_key)
);

-- Seed default asset classes
INSERT INTO theralia_asset_classes (workspace_id, class_key, display_name, is_default, created_by)
SELECT w.id, v.class_key, v.display_name, TRUE, 'system'
FROM workspaces w
CROSS JOIN (VALUES
    ('patent', 'Patent'),
    ('patent_application', 'Patent Application'),
    ('lead_candidate', 'Lead Candidate'),
    ('platform_asset', 'Platform Asset')
) AS v(class_key, display_name)
WHERE w.slug = 'theralia'
ON CONFLICT (workspace_id, class_key) DO NOTHING;

-- Strategic assets
CREATE TABLE IF NOT EXISTS theralia_strategic_assets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    title TEXT NOT NULL,
    asset_class TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'draft' CHECK (status IN ('active','pending','draft','restricted','archived')),
    jurisdiction TEXT,
    filing_date DATE,
    owner_name TEXT,
    related_project TEXT,
    linked_company_ip_id UUID,
    notes TEXT,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_theralia_strategic_assets_ws ON theralia_strategic_assets(workspace_id);

-- Purchases
CREATE TABLE IF NOT EXISTS theralia_purchases (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    name TEXT NOT NULL,
    category TEXT NOT NULL CHECK (category IN ('oligonucleotide','reagent','kit','consumable','service','software','prototype_material','other')),
    supplier TEXT,
    purchase_date DATE,
    cost_value NUMERIC(12,2),
    cost_currency TEXT DEFAULT 'EUR',
    status TEXT NOT NULL DEFAULT 'ordered' CHECK (status IN ('active','ordered','received','used','archived')),
    related_project TEXT,
    notes TEXT,
    product_name TEXT,
    product_url TEXT,
    product_reference_type TEXT CHECK (product_reference_type IS NULL OR product_reference_type IN ('external','natlab','supplier')),
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_theralia_purchases_ws ON theralia_purchases(workspace_id);
