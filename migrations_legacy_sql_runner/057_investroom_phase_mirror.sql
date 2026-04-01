-- Migration 057: InvestRoom Phase Mirror Editor
-- Adds figure_label, slot_type, layout_width to investroom_phase_boxes
-- for structured phase-specific rendering (figure cards in Phase 3, slot-based in 1/2/4)

ALTER TABLE investroom_phase_boxes
    ADD COLUMN IF NOT EXISTS figure_label TEXT,
    ADD COLUMN IF NOT EXISTS slot_type TEXT DEFAULT NULL,
    ADD COLUMN IF NOT EXISTS layout_width TEXT DEFAULT 'full';

-- slot_type: 'data' or 'sop' (for Phase 3 figure sub-boxes), NULL for regular boxes
-- layout_width: 'full' or 'half' (controls card width in grid)
-- figure_label: e.g. 'Figure 2B' (for Phase 3 figure cards)
