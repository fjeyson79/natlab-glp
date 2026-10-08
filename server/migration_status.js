// Interprets the glp_migration_state row written by db/migrate.js.
// A migration run is healthy only if it succeeded and no later run failed.

function assessMigrationState(row) {
    if (!row) return { ok: false, reason: 'no migration state recorded' };
    const success = row.last_success_at ? new Date(row.last_success_at) : null;
    const error = row.last_error_at ? new Date(row.last_error_at) : null;
    if (!success) return { ok: false, reason: 'no successful migration recorded' };
    if (error && error >= success) {
        return { ok: false, reason: `last migration failed at ${error.toISOString()}: ${row.last_error_text || 'unknown error'}` };
    }
    return { ok: true, reason: `last successful migration at ${success.toISOString()}` };
}

module.exports = { assessMigrationState };
