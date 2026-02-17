BEGIN;

ALTER TABLE di_submissions
  DROP CONSTRAINT IF EXISTS di_submissions_status_check;

ALTER TABLE di_submissions
  ADD CONSTRAINT di_submissions_status_check
  CHECK (
    status::text = ANY (
      ARRAY[
        'PENDING',
        'APPROVED',
        'REVISION_NEEDED',
        'SUBMITTED',
        'DISCARDED'
      ]::text[]
    )
  );

COMMIT;
