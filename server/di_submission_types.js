// Allowed di_submissions.file_type values, shared by db/migrate.js and the
// runtime widener ensureDiSubmissionsConstraints() in server.js.

const DI_SUBMISSIONS_FILE_TYPES = ['SOP', 'DATA', 'INVENTORY', 'PRESENTATION', 'REPORT', 'DOCS', 'PRES'];

// DROP + ADD in a single ALTER TABLE is atomic: if the ADD fails (e.g. a row
// violates it), the DROP is rolled back and the existing constraint stays.
const DI_SUBMISSIONS_FILE_TYPE_CHECK_SQL =
    `ALTER TABLE di_submissions
        DROP CONSTRAINT IF EXISTS di_submissions_file_type_check,
        ADD CONSTRAINT di_submissions_file_type_check
            CHECK (file_type IN (${DI_SUBMISSIONS_FILE_TYPES.map(t => `'${t}'`).join(', ')}))`;

module.exports = { DI_SUBMISSIONS_FILE_TYPES, DI_SUBMISSIONS_FILE_TYPE_CHECK_SQL };
