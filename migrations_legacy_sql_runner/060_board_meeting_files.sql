-- Migration 060: Board meeting supporting documents (PDF files)
-- Allows founders to attach PDF documents to specific board meetings

CREATE TABLE IF NOT EXISTS theralia_board_meeting_files (
    id              SERIAL PRIMARY KEY,
    meeting_id      INTEGER NOT NULL REFERENCES theralia_board_meetings(id),
    file_name       TEXT NOT NULL,
    original_name   TEXT NOT NULL,
    r2_object_key   TEXT NOT NULL,
    uploaded_by     TEXT NOT NULL,
    uploaded_at     TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_tbmf_meeting ON theralia_board_meeting_files (meeting_id);
