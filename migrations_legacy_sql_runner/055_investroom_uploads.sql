-- Migration 055: InvestRoom Phase Uploads
-- Adds structured upload boxes per investor phase, CSO-managed

CREATE TABLE IF NOT EXISTS investroom_phase_boxes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    workspace_id UUID NOT NULL REFERENCES workspaces(id),
    phase_number INT NOT NULL CHECK (phase_number BETWEEN 1 AND 4),
    title TEXT NOT NULL,
    box_type TEXT NOT NULL CHECK (box_type IN ('publication','sop','data','figure','deck','document')),
    description TEXT,
    order_index INT NOT NULL DEFAULT 0,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_irpb_ws_phase ON investroom_phase_boxes(workspace_id, phase_number);

CREATE TABLE IF NOT EXISTS investroom_phase_box_files (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    box_id UUID NOT NULL REFERENCES investroom_phase_boxes(id) ON DELETE CASCADE,
    file_name TEXT NOT NULL,
    r2_object_key TEXT NOT NULL,
    mime_type TEXT,
    file_size BIGINT,
    created_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_irpbf_box ON investroom_phase_box_files(box_id);
