-- Migration 021: Extend di_file_associations for GLP Vision
-- Adds role tracking and soft delete for researcher/supervisor association management

ALTER TABLE di_file_associations ADD COLUMN IF NOT EXISTS created_by_role VARCHAR(20) DEFAULT 'pi';
ALTER TABLE di_file_associations ADD COLUMN IF NOT EXISTS deleted_at TIMESTAMPTZ;

-- Replace absolute unique with partial unique (active rows only)
DROP INDEX IF EXISTS di_file_associations_source_id_target_id_key;
CREATE UNIQUE INDEX IF NOT EXISTS uq_file_assoc_active
  ON di_file_associations(source_id, target_id) WHERE deleted_at IS NULL;
