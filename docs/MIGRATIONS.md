# Migrations

This project uses a single migration mechanism.

## Source of truth

All schema changes are applied from `db/migrate.js` at startup.

The production start command runs migrations first:

node db/migrate.js, then node server.js

## Legacy SQL runner

The former SQL file runner is kept only as legacy code and is disabled by default.

The legacy folder has been archived as `migrations_legacy_sql_runner`.

To enable SQL file migrations intentionally, set:

ENABLE_SQL_MIGRATIONS=1

Do not set this in production unless you are intentionally running legacy SQL files.

## Migration safety

Migrations use a Postgres advisory lock to prevent concurrent execution across instances.

Migration health is written to `glp_migration_state`.

## Quick health check

Run in Railway psql:

SELECT last_success_at, last_error_at, last_error_text, schema_ok, schema_check_text
FROM glp_migration_state
WHERE id = 1;
