-- Migration 027: Add unique index on lower(researcher_id) for di_users
-- Safe: does not alter existing rows, only adds an index if not present.

CREATE UNIQUE INDEX IF NOT EXISTS di_users_researcher_id_lower_uidx
  ON di_users (lower(researcher_id));
