-- Migration 049: Widen di_submissions constraints for Theralia R&D → GLP integration
-- Ensures affiliation allows THERALIA and file_type allows R&D categories

-- 1. Affiliation: add THERALIA
ALTER TABLE di_submissions DROP CONSTRAINT IF EXISTS di_submissions_affiliation_check;
ALTER TABLE di_submissions ADD CONSTRAINT di_submissions_affiliation_check
    CHECK (affiliation IN ('LiU', 'UNAV', 'EXTERNAL', 'THERALIA'));

-- 2. File type: ensure R&D categories are included (idempotent with migration 048)
ALTER TABLE di_submissions DROP CONSTRAINT IF EXISTS di_submissions_file_type_check;
ALTER TABLE di_submissions ADD CONSTRAINT di_submissions_file_type_check
    CHECK (file_type IN ('SOP', 'DATA', 'INVENTORY', 'PRESENTATION', 'REPORT', 'DOCS', 'PRES'));
