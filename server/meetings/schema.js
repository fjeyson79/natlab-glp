'use strict';
// ============================================================================
// Group Meetings — additive, idempotent schema (R1).
//
// Why a runtime ensure instead of db/migrate.js: migrate.js stops at the first
// failing inline statement (see migration 070 / commit 142d024), so statements
// appended to its array are not guaranteed to run. This follows the existing
// routes/di/reportThread.js ensureSchemaFor() pattern, with two differences:
//   - it runs ONLY when GROUP_MEETINGS_ENABLED is on (flag off => zero DDL);
//   - all statements run in ONE transaction under an advisory lock, so a
//     failure leaves the database exactly as it was.
//
// Safety properties:
//   - Nothing is dropped, renamed, narrowed or deleted.
//   - Existing meeting_groups / meeting_group_members rows are never modified,
//     except that a NULL `code` is filled for the three groups seeded by
//     migration 033, matched by their exact seeded names, and only if that
//     code is not already used.
//   - Groups are seeded ONLY when meeting_groups is empty (fresh database),
//     so duplicates cannot be created.
//   - No foreign key or constraint touches di_submissions.
//   - No speaker-slot / publication tables (meeting_schedule,
//     meeting_participation, meeting_speaker_pool) are touched.
//
// Rollback (manual, NOT executed by the application):
//   DROP TABLE IF EXISTS meeting_occurrences;
//   DROP INDEX IF EXISTS uq_meeting_groups_code;
//   ALTER TABLE meeting_groups DROP CONSTRAINT IF EXISTS meeting_groups_code_check,
//       DROP COLUMN IF EXISTS code, DROP COLUMN IF EXISTS zoom_join_url,
//       DROP COLUMN IF EXISTS timezone, DROP COLUMN IF EXISTS duration_minutes;
//   (meeting_groups / meeting_group_members belong to migration 033 and stay.)
// ============================================================================

const ADVISORY_LOCK_KEY = 20261124; // distinct from db/migrate.js (20260101)

const STATEMENTS = [
    // --- Migration 033 tables, if they were never applied (identical shape) ---
    `CREATE TABLE IF NOT EXISTS meeting_groups (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(200) NOT NULL,
        site VARCHAR(100),
        default_day INTEGER CHECK (default_day BETWEEN 0 AND 6),
        default_time TIME DEFAULT '09:00',
        location TEXT,
        is_active BOOLEAN NOT NULL DEFAULT true,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`,
    `CREATE UNIQUE INDEX IF NOT EXISTS uq_meeting_groups_name ON meeting_groups(name)`,
    `CREATE TABLE IF NOT EXISTS meeting_group_members (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        meeting_group_id UUID NOT NULL REFERENCES meeting_groups(id) ON DELETE CASCADE,
        researcher_id VARCHAR(100) NOT NULL,
        can_deep BOOLEAN NOT NULL DEFAULT false,
        can_focus BOOLEAN NOT NULL DEFAULT true,
        can_flash BOOLEAN NOT NULL DEFAULT true,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`,
    `CREATE UNIQUE INDEX IF NOT EXISTS uq_meeting_group_members ON meeting_group_members(meeting_group_id, researcher_id)`,
    `CREATE INDEX IF NOT EXISTS idx_meeting_group_members_group ON meeting_group_members(meeting_group_id)`,

    // --- R1 additions to meeting_groups ---
    `ALTER TABLE meeting_groups ADD COLUMN IF NOT EXISTS code TEXT`,
    `ALTER TABLE meeting_groups ADD COLUMN IF NOT EXISTS zoom_join_url TEXT`,
    `ALTER TABLE meeting_groups ADD COLUMN IF NOT EXISTS timezone TEXT NOT NULL DEFAULT 'Europe/Stockholm'`,
    `ALTER TABLE meeting_groups ADD COLUMN IF NOT EXISTS duration_minutes INTEGER`,
    `DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'meeting_groups_code_check') THEN
            ALTER TABLE meeting_groups ADD CONSTRAINT meeting_groups_code_check
                CHECK (code IS NULL OR code IN ('LIU', 'UNAV', 'JOINT'));
        END IF;
    END $$`,
    `CREATE UNIQUE INDEX IF NOT EXISTS uq_meeting_groups_code ON meeting_groups(code) WHERE code IS NOT NULL`,

    // --- Seed the three groups ONLY on an empty table (fresh database) ---
    `INSERT INTO meeting_groups (name, site, default_day, default_time)
     SELECT v.name, v.site, v.day, v.t::time
       FROM (VALUES ('LiU Weekly Meeting', 'LiU', 4, '09:00'),
                    ('UNAV Weekly Meeting', 'UNAV', 5, '09:00'),
                    ('LiU-UNAV Meeting', 'LiU-UNAV', 3, '10:00')) AS v(name, site, day, t)
      WHERE NOT EXISTS (SELECT 1 FROM meeting_groups)`,

    // --- Map the migration-033 groups to stable codes (fill NULL only) ---
    `UPDATE meeting_groups SET code = 'LIU', updated_at = now()
      WHERE name = 'LiU Weekly Meeting' AND code IS NULL
        AND NOT EXISTS (SELECT 1 FROM meeting_groups WHERE code = 'LIU')`,
    `UPDATE meeting_groups SET code = 'UNAV', updated_at = now()
      WHERE name = 'UNAV Weekly Meeting' AND code IS NULL
        AND NOT EXISTS (SELECT 1 FROM meeting_groups WHERE code = 'UNAV')`,
    `UPDATE meeting_groups SET code = 'JOINT', updated_at = now()
      WHERE name = 'LiU-UNAV Meeting' AND code IS NULL
        AND NOT EXISTS (SELECT 1 FROM meeting_groups WHERE code = 'JOINT')`,

    // --- Independent occurrence table (no link to meeting_schedule) ---
    `CREATE TABLE IF NOT EXISTS meeting_occurrences (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        meeting_group_id UUID NOT NULL REFERENCES meeting_groups(id),
        scheduled_start TIMESTAMPTZ,
        duration_minutes INTEGER CHECK (duration_minutes IS NULL OR duration_minutes BETWEEN 5 AND 480),
        status TEXT NOT NULL DEFAULT 'SCHEDULED'
            CHECK (status IN ('SCHEDULED', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED', 'POSTPONED')),
        status_note TEXT,
        started_at TIMESTAMPTZ,
        ended_at TIMESTAMPTZ,
        created_by VARCHAR(100) NOT NULL,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_by VARCHAR(100),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_meeting_occurrences_group_start
        ON meeting_occurrences(meeting_group_id, scheduled_start DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_meeting_occurrences_group_completed
        ON meeting_occurrences(meeting_group_id, ended_at DESC) WHERE status = 'COMPLETED'`,
    `CREATE UNIQUE INDEX IF NOT EXISTS uq_meeting_occurrences_group_start
        ON meeting_occurrences(meeting_group_id, scheduled_start)
        WHERE scheduled_start IS NOT NULL AND status <> 'CANCELLED'`,
];

async function ensureSchema(pool) {
    const client = await pool.connect();
    try {
        await client.query('BEGIN');
        await client.query('SELECT pg_advisory_xact_lock($1)', [ADVISORY_LOCK_KEY]);
        for (const sql of STATEMENTS) await client.query(sql);
        await client.query('COMMIT');
        return { ok: true };
    } catch (err) {
        try { await client.query('ROLLBACK'); } catch (_) { /* ignore */ }
        return { ok: false, error: err && err.message ? err.message : String(err) };
    } finally {
        client.release();
    }
}

// Read-only readiness probe: all tables/columns the R1 API depends on.
async function isSchemaReady(pool) {
    const r = await pool.query(`
        SELECT
          to_regclass('public.meeting_groups') IS NOT NULL
          AND to_regclass('public.meeting_group_members') IS NOT NULL
          AND to_regclass('public.meeting_occurrences') IS NOT NULL
          AND to_regclass('public.di_submissions') IS NOT NULL
          AND to_regclass('public.di_allowlist') IS NOT NULL
          AND to_regclass('public.workspaces') IS NOT NULL
          AND (SELECT COUNT(*) FROM information_schema.columns
                WHERE table_schema = 'public' AND table_name = 'meeting_groups'
                  AND column_name IN ('code', 'zoom_join_url', 'timezone', 'duration_minutes')) = 4
          AS ready`);
    return r.rows[0] && r.rows[0].ready === true;
}

module.exports = { STATEMENTS, ADVISORY_LOCK_KEY, ensureSchema, isSchemaReady };
