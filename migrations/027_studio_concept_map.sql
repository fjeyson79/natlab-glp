-- Migration 027: Research Studio 2.0 — Concept Map, Edges, Story Mode
-- Phase 1: core intellectual architecture (6 core nodes, evidence peripherals,
--          edges with strength tags, editable story sections)
-- Additive only; no modifications to existing tables except one new column.

-- 1. Concept Map Nodes
-- Core nodes (core_*): fixed geometry, one per type per project.
-- Peripheral nodes (evidence): flexible positions, many per project.
CREATE TABLE IF NOT EXISTS di_studio_nodes (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES di_studio_projects(id) ON DELETE CASCADE,
    node_type       VARCHAR(40) NOT NULL,
    content_text    TEXT NOT NULL DEFAULT '',
    label           VARCHAR(300) DEFAULT '',
    position_x      REAL,
    position_y      REAL,
    evidence_ref_id VARCHAR(100),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- One core node per type per project
CREATE UNIQUE INDEX IF NOT EXISTS idx_studio_nodes_core_unique
    ON di_studio_nodes(project_id, node_type) WHERE node_type LIKE 'core_%';
CREATE INDEX IF NOT EXISTS idx_studio_nodes_project
    ON di_studio_nodes(project_id);

-- 2. Edges between nodes (manual linking with strength tags)
CREATE TABLE IF NOT EXISTS di_studio_edges (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES di_studio_projects(id) ON DELETE CASCADE,
    source_node_id  UUID NOT NULL REFERENCES di_studio_nodes(id) ON DELETE CASCADE,
    target_node_id  UUID NOT NULL REFERENCES di_studio_nodes(id) ON DELETE CASCADE,
    strength        VARCHAR(20) NOT NULL DEFAULT 'moderate'
                        CHECK (strength IN ('strong','moderate','exploratory','contradictory')),
    created_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(source_node_id, target_node_id)
);

CREATE INDEX IF NOT EXISTS idx_studio_edges_project
    ON di_studio_edges(project_id);
CREATE INDEX IF NOT EXISTS idx_studio_edges_source
    ON di_studio_edges(source_node_id);
CREATE INDEX IF NOT EXISTS idx_studio_edges_target
    ON di_studio_edges(target_node_id);

-- 3. Story Mode sections (independently editable, one-time seed from concept map)
CREATE TABLE IF NOT EXISTS di_studio_story_sections (
    id              UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id      UUID NOT NULL REFERENCES di_studio_projects(id) ON DELETE CASCADE,
    section_key     VARCHAR(30) NOT NULL CHECK (section_key IN (
                        'the_problem','the_opportunity','the_core_idea',
                        'the_proof','the_implication','why_us')),
    content_text    TEXT NOT NULL DEFAULT '',
    seeded_from     VARCHAR(40),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(project_id, section_key)
);

CREATE INDEX IF NOT EXISTS idx_studio_story_project
    ON di_studio_story_sections(project_id);

-- 4. Default mode preference on projects
ALTER TABLE di_studio_projects
    ADD COLUMN IF NOT EXISTS default_mode VARCHAR(20) DEFAULT 'concept_map';

-- 5. Seed core nodes from existing reflection data
INSERT INTO di_studio_nodes (project_id, node_type, content_text)
SELECT id, 'core_hypothesis', COALESCE(hypothesis, '')
FROM di_studio_projects
ON CONFLICT DO NOTHING;

INSERT INTO di_studio_nodes (project_id, node_type, content_text)
SELECT id, 'core_why', COALESCE(intention, '')
FROM di_studio_projects
ON CONFLICT DO NOTHING;

INSERT INTO di_studio_nodes (project_id, node_type, content_text)
SELECT id, 'core_tension', COALESCE(tension, '')
FROM di_studio_projects
ON CONFLICT DO NOTHING;

INSERT INTO di_studio_nodes (project_id, node_type, content_text)
SELECT id, t.nt, ''
FROM di_studio_projects
CROSS JOIN (VALUES ('core_translation'), ('core_landscape'), ('core_why_us')) AS t(nt)
ON CONFLICT DO NOTHING;

-- 6. Seed empty story sections for existing projects
INSERT INTO di_studio_story_sections (project_id, section_key, seeded_from)
SELECT id, s.k, s.src
FROM di_studio_projects
CROSS JOIN (VALUES
    ('the_problem',    'core_why'),
    ('the_opportunity', NULL),
    ('the_core_idea',  'core_hypothesis'),
    ('the_proof',       NULL),
    ('the_implication', 'core_translation'),
    ('why_us',          'core_why_us')
) AS s(k, src)
ON CONFLICT DO NOTHING;
