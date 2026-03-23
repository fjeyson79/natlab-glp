-- Migration 047: R&D refinements — next_action for projects, role_description for partners

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='rd_projects' AND column_name='next_action') THEN
        ALTER TABLE rd_projects ADD COLUMN next_action TEXT;
    END IF;
END $$;

DO $$ BEGIN
    IF NOT EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='rd_partners' AND column_name='role_description') THEN
        ALTER TABLE rd_partners ADD COLUMN role_description TEXT;
    END IF;
END $$;
