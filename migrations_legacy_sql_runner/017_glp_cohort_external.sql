-- Migration 017: Backfill EXTERNAL users into GLP cohort membership
-- EXTERNAL users are excluded by default (included = FALSE).
-- The PI can selectively include them via the Management UI.

INSERT INTO di_glp_cohort_members (cohort_id, user_id, included, updated_by)
SELECT 'EXTERNAL', a.researcher_id, FALSE, 'system-migration'
FROM di_allowlist a
WHERE a.affiliation = 'EXTERNAL'
ON CONFLICT (cohort_id, user_id) DO NOTHING;
