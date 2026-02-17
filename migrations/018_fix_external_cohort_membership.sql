-- Migration 018: Fix cohort mapping for EXTERNAL users
-- Problem: migration 016 backfilled non-LiU users into UNAV, including EXTERNAL.
-- Fix: remove LIU/UNAV cohort rows for EXTERNAL-affiliation users, ensure EXTERNAL cohort rows exist.

-- Remove incorrect cohort assignments for EXTERNAL-affiliation users
DELETE FROM di_glp_cohort_members c
USING di_allowlist a
WHERE a.researcher_id = c.user_id
  AND a.affiliation = 'EXTERNAL'
  AND c.cohort_id IN ('LIU', 'UNAV');

-- Ensure EXTERNAL cohort rows exist and are included
INSERT INTO di_glp_cohort_members (cohort_id, user_id, included, note, updated_by, updated_at)
SELECT
  'EXTERNAL',
  a.researcher_id,
  TRUE,
  'Backfill external cohort membership',
  'system-migration',
  NOW()
FROM di_allowlist a
WHERE a.active = TRUE
  AND a.affiliation = 'EXTERNAL'
ON CONFLICT (cohort_id, user_id) DO UPDATE
SET included = EXCLUDED.included,
    note = EXCLUDED.note,
    updated_by = EXCLUDED.updated_by,
    updated_at = NOW();
