-- Migration 069: REPORT in di_submissions_file_type_check
--
-- Production fix. Earlier inline migration (db/migrate.js lines 142-143)
-- re-asserted the CHECK as ('SOP','DATA','INVENTORY','PRESENTATION'),
-- which excludes REPORT, causing /api/di/upload-report to fail with:
--   new row for relation "di_submissions" violates check constraint
--   "di_submissions_file_type_check"
--
-- The runtime helper ensureDiSubmissionsConstraints() in server.js does
-- already widen this constraint, but it only fires from the R&D upload
-- route — REPORT uploads through /api/di/upload-report never trigger it.
--
-- The fix preserves all values the runtime widener already uses (so we
-- don't break existing INVENTORY / DOCS / PRES rows) and adds REPORT.
-- The constraint name stays di_submissions_file_type_check.

ALTER TABLE di_submissions DROP CONSTRAINT IF EXISTS di_submissions_file_type_check;
ALTER TABLE di_submissions ADD CONSTRAINT di_submissions_file_type_check
    CHECK (file_type IN (
        'SOP', 'DATA', 'INVENTORY', 'PRESENTATION', 'REPORT', 'DOCS', 'PRES'
    ));
