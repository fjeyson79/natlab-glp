-- Migration 038: Module Studio – Phase 1
-- Isolated module registry, toggles, workspace assignments, and toggle overrides.
-- Additive only. No changes to existing tables.

-- 1. Module registry
CREATE TABLE IF NOT EXISTS modules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    module_key VARCHAR(120) NOT NULL,
    name VARCHAR(255) NOT NULL,
    category VARCHAR(10) NOT NULL CHECK (category IN ('admin','user')),
    family VARCHAR(120),
    description TEXT,
    status VARCHAR(20) NOT NULL DEFAULT 'draft' CHECK (status IN ('draft','in_build','testing','published','archived')),
    version_label VARCHAR(40) NOT NULL DEFAULT 'v1',
    transferable BOOLEAN NOT NULL DEFAULT TRUE,
    build_notes TEXT,
    created_by UUID,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE UNIQUE INDEX IF NOT EXISTS uq_modules_module_key ON modules(module_key);
CREATE INDEX IF NOT EXISTS idx_modules_category ON modules(category);
CREATE INDEX IF NOT EXISTS idx_modules_status ON modules(status);

-- 2. Module toggles
CREATE TABLE IF NOT EXISTS module_toggles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    module_id UUID NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
    toggle_key VARCHAR(120) NOT NULL,
    label VARCHAR(255) NOT NULL,
    description TEXT,
    default_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    sort_order INTEGER NOT NULL DEFAULT 0,
    status VARCHAR(20) NOT NULL DEFAULT 'active' CHECK (status IN ('active','archived')),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_module_toggles_module_id ON module_toggles(module_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_module_toggles_key ON module_toggles(module_id, toggle_key);

-- 3. Workspace module assignments
CREATE TABLE IF NOT EXISTS workspace_modules (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    module_id UUID NOT NULL REFERENCES modules(id) ON DELETE CASCADE,
    workspace_id UUID NOT NULL,
    placement_type VARCHAR(20) NOT NULL DEFAULT 'tab' CHECK (placement_type IN ('tab','toggle')),
    placement_target VARCHAR(255),
    tab_label VARCHAR(255),
    tab_position INTEGER,
    toggle_location VARCHAR(255),
    selected_variant VARCHAR(255),
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    publish_scope VARCHAR(40),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_workspace_modules_module_id ON workspace_modules(module_id);
CREATE INDEX IF NOT EXISTS idx_workspace_modules_workspace_id ON workspace_modules(workspace_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_workspace_modules_assign ON workspace_modules(module_id, workspace_id);

-- 4. Workspace module toggle overrides
CREATE TABLE IF NOT EXISTS workspace_module_toggles (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_module_id UUID NOT NULL REFERENCES workspace_modules(id) ON DELETE CASCADE,
    module_toggle_id UUID NOT NULL REFERENCES module_toggles(id) ON DELETE CASCADE,
    is_enabled BOOLEAN NOT NULL DEFAULT TRUE,
    sort_order INTEGER,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE INDEX IF NOT EXISTS idx_wmt_workspace_module_id ON workspace_module_toggles(workspace_module_id);
CREATE INDEX IF NOT EXISTS idx_wmt_module_toggle_id ON workspace_module_toggles(module_toggle_id);
CREATE UNIQUE INDEX IF NOT EXISTS uq_wmt_pair ON workspace_module_toggles(workspace_module_id, module_toggle_id);
