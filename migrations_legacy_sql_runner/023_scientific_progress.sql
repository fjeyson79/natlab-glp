-- Migration 023: Add scientific_json column to 1-to-1 meeting tables
-- Extends 1-to-1 meetings with optional Scientific Progress data (Junior/Senior profiles).
-- Additive only; does not alter existing GLP pillar columns.

ALTER TABLE di_1to1_meeting_versions ADD COLUMN IF NOT EXISTS scientific_json JSONB;
ALTER TABLE di_1to1_drafts ADD COLUMN IF NOT EXISTS scientific_json JSONB;
