-- Migration 026: Research Studio Phase 3
-- Figures, representative image assets, and figure evidence links
-- Additive only; no modifications to existing tables

-- Figures: numbered figures associated with a project
CREATE TABLE IF NOT EXISTS di_studio_figures (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES di_studio_projects(id) ON DELETE CASCADE,
    figure_number   INTEGER NOT NULL,
    title           TEXT NOT NULL DEFAULT '',
    legend          TEXT NOT NULL DEFAULT '',
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_studio_figures_project
    ON di_studio_figures(project_id);
CREATE INDEX IF NOT EXISTS idx_studio_figures_project_number
    ON di_studio_figures(project_id, figure_number);

-- Assets: images stored in R2, linked to a figure
CREATE TABLE IF NOT EXISTS di_studio_assets (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES di_studio_projects(id) ON DELETE CASCADE,
    figure_id       UUID REFERENCES di_studio_figures(id) ON DELETE SET NULL,
    kind            VARCHAR(30) NOT NULL CHECK (kind IN ('representative_image')),
    r2_key          TEXT NOT NULL,
    mime            VARCHAR(100) NOT NULL,
    bytes           INTEGER NOT NULL DEFAULT 0,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_studio_assets_project
    ON di_studio_assets(project_id);
CREATE INDEX IF NOT EXISTS idx_studio_assets_figure
    ON di_studio_assets(figure_id);

-- Figure evidence links: references from a figure to existing GLP records
CREATE TABLE IF NOT EXISTS di_studio_figure_links (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    figure_id       UUID NOT NULL REFERENCES di_studio_figures(id) ON DELETE CASCADE,
    evidence_type   VARCHAR(30) NOT NULL,
    evidence_id     VARCHAR(100) NOT NULL,
    label           VARCHAR(500),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_studio_figure_links_figure
    ON di_studio_figure_links(figure_id);
