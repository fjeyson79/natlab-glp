-- Migration 016: GLP Cohort membership and group weekly status
-- PI manages cohort inclusion; group snapshots aggregate individual snapshots

-- Cohort membership table
CREATE TABLE IF NOT EXISTS di_glp_cohort_members (
    id BIGSERIAL PRIMARY KEY,
    cohort_id TEXT NOT NULL,           -- 'LIU' or 'UNAV'
    user_id TEXT NOT NULL,
    included BOOLEAN NOT NULL DEFAULT TRUE,
    note TEXT,
    updated_by TEXT,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(cohort_id, user_id)
);
CREATE INDEX IF NOT EXISTS idx_di_glp_cohort_members_cohort ON di_glp_cohort_members(cohort_id);
CREATE INDEX IF NOT EXISTS idx_di_glp_cohort_members_user ON di_glp_cohort_members(user_id);

-- Backfill from allowlist
INSERT INTO di_glp_cohort_members (cohort_id, user_id, included, updated_by)
SELECT
    CASE WHEN a.affiliation = 'LiU' THEN 'LIU' ELSE 'UNAV' END,
    a.researcher_id, TRUE, 'system-migration'
FROM di_allowlist a
WHERE a.active = TRUE AND a.affiliation IS NOT NULL
ON CONFLICT (cohort_id, user_id) DO NOTHING;

-- Group weekly status index
CREATE TABLE IF NOT EXISTS glp_group_weekly_status_index (
    id BIGSERIAL PRIMARY KEY,
    cohort_id TEXT NOT NULL,           -- 'LIU' or 'UNAV' or 'BOTH'
    iso_week TEXT NOT NULL,            -- '2026W07'
    r2_snapshot_key TEXT NOT NULL,
    member_count INTEGER NOT NULL,
    membership_hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    UNIQUE(cohort_id, iso_week)
);
CREATE INDEX IF NOT EXISTS idx_glp_group_weekly_cohort ON glp_group_weekly_status_index(cohort_id);
CREATE INDEX IF NOT EXISTS idx_glp_group_weekly_week ON glp_group_weekly_status_index(iso_week);
