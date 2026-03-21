-- Migration 039: Module Studio – fix created_by type
-- Changes modules.created_by from UUID to VARCHAR(50) to match
-- portal identity values (e.g. researcher_id strings like "FJH").
-- Additive, safe ALTER TYPE with USING cast.

ALTER TABLE modules
    ALTER COLUMN created_by TYPE VARCHAR(50)
    USING created_by::TEXT;
