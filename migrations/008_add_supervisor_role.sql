-- Migration 008: Add SUPERVISOR role support
-- Creates join table for supervisor-researcher assignments
-- Supervisors can view files of researchers assigned to them (read-only)

-- 1. Create the supervisor-researcher assignment table
CREATE TABLE IF NOT EXISTS di_supervisor_researchers (
    supervisor_id VARCHAR(50) NOT NULL,
    researcher_id VARCHAR(50) NOT NULL,
    assigned_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    assigned_by VARCHAR(50),
    CONSTRAINT pk_supervisor_researchers PRIMARY KEY (supervisor_id, researcher_id),
    CONSTRAINT fk_supervisor FOREIGN KEY (supervisor_id) REFERENCES di_allowlist(researcher_id),
    CONSTRAINT fk_researcher FOREIGN KEY (researcher_id) REFERENCES di_allowlist(researcher_id)
);

-- 2. Add indexes for common queries
CREATE INDEX IF NOT EXISTS idx_supervisor_researchers_supervisor ON di_supervisor_researchers(supervisor_id);
CREATE INDEX IF NOT EXISTS idx_supervisor_researchers_researcher ON di_supervisor_researchers(researcher_id);

-- 3. Add comments
COMMENT ON TABLE di_supervisor_researchers IS 'Maps supervisors to the researchers they can view files for';
COMMENT ON COLUMN di_supervisor_researchers.supervisor_id IS 'researcher_id of user with role=supervisor';
COMMENT ON COLUMN di_supervisor_researchers.researcher_id IS 'researcher_id of researcher assigned to this supervisor';
COMMENT ON COLUMN di_supervisor_researchers.assigned_at IS 'When the assignment was created';
COMMENT ON COLUMN di_supervisor_researchers.assigned_by IS 'researcher_id of PI who created the assignment';
