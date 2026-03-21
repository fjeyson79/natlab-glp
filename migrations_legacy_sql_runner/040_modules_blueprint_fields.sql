-- Migration 040: Module Studio – Phase 1.2 Blueprint fields
-- Adds source-reference columns so modules act as code-coordinate containers

ALTER TABLE modules ADD COLUMN IF NOT EXISTS blueprint_key VARCHAR(120);
ALTER TABLE modules ADD COLUMN IF NOT EXISTS source_type  VARCHAR(40);
ALTER TABLE modules ADD COLUMN IF NOT EXISTS source_key   VARCHAR(120);
ALTER TABLE modules ADD COLUMN IF NOT EXISTS render_key   VARCHAR(120);
