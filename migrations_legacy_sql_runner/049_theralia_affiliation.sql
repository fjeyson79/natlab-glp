-- Migration 049: Widen di_submissions affiliation CHECK to include THERALIA
-- Required for Theralia R&D → GLP upload integration

ALTER TABLE di_submissions DROP CONSTRAINT IF EXISTS di_submissions_affiliation_check;
ALTER TABLE di_submissions ADD CONSTRAINT di_submissions_affiliation_check
    CHECK (affiliation IN ('LiU', 'UNAV', 'EXTERNAL', 'THERALIA'));
