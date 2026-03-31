-- Migration 056: InvestRoom file review status (COO SOP review)
ALTER TABLE investroom_phase_box_files ADD COLUMN IF NOT EXISTS review_status TEXT DEFAULT 'pending';
ALTER TABLE investroom_phase_box_files ADD COLUMN IF NOT EXISTS review_note TEXT;
ALTER TABLE investroom_phase_box_files ADD COLUMN IF NOT EXISTS reviewed_by TEXT;
ALTER TABLE investroom_phase_box_files ADD COLUMN IF NOT EXISTS reviewed_at TIMESTAMPTZ;
