-- Migration 013: GLP Weekly Status Index
-- Stores weekly snapshot metadata with R2 pointers for snapshot + harmony JSONs.

CREATE TABLE IF NOT EXISTS glp_weekly_status_index (
    id               UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id          VARCHAR(50)   NOT NULL,
    iso_week         VARCHAR(7)    NOT NULL,          -- 'YYYYWww' e.g. '2026W07'
    generated_at     TIMESTAMPTZ   NOT NULL DEFAULT NOW(),
    r2_snapshot_key  VARCHAR(1000) NOT NULL,
    r2_harmony_key   VARCHAR(1000),                   -- NULL until n8n stores harmony
    evidence_hash    VARCHAR(64)   NOT NULL,           -- SHA-256 hex of canonical snapshot JSON
    snapshot_version INTEGER       NOT NULL DEFAULT 1,
    model_version    VARCHAR(30)   NOT NULL DEFAULT '1.0.0',
    UNIQUE(user_id, iso_week)
);

CREATE INDEX IF NOT EXISTS idx_glp_status_user      ON glp_weekly_status_index(user_id);
CREATE INDEX IF NOT EXISTS idx_glp_status_week      ON glp_weekly_status_index(iso_week);
CREATE INDEX IF NOT EXISTS idx_glp_status_generated  ON glp_weekly_status_index(generated_at DESC);
