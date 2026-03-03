require('dotenv').config();
const { Pool } = require('pg');

const fs = require('fs');
const path = require('path');

const BASELINE_FILE_MIGRATION_VERSION = 28;
// If schema_migrations is empty, we assume historical migrations were applied via inline SQL list.
// We therefore mark files <= BASELINE as already applied to avoid re-applying them.


async function runSqlFileMigrations(pool) {
    // Tracks applied file migrations
    await pool.query(`
        CREATE TABLE IF NOT EXISTS schema_migrations (
            filename TEXT PRIMARY KEY,
            applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
        )
    `);

    const dir = path.join(__dirname, '..', 'migrations');
    if (!fs.existsSync(dir)) {
        console.log('No migrations directory found at:', dir);
        return;
    }

    const files = fs.readdirSync(dir)
        .filter(f => /^[0-9]{3}_.+\.sql$/i.test(f))
        .sort();

    // One-time baseline: if schema_migrations is empty, mark legacy files as applied.
    const smCount = await pool.query(`SELECT COUNT(*)::int AS n FROM schema_migrations`);
    if ((smCount.rows[0]?.n || 0) === 0) {
        const legacy = [];
        for (const f of files) {
            const m = f.match(/^([0-9]{3})_/);
            if (!m) continue;
            const v = parseInt(m[1], 10);
            if (v <= BASELINE_FILE_MIGRATION_VERSION) legacy.push(f);
        }
        if (legacy.length > 0) {
            console.log(`\n[sql-migrations] Baseline: marking ${legacy.length} file(s) <= ${BASELINE_FILE_MIGRATION_VERSION} as applied (no execution).`);
            for (const f of legacy) {
                await pool.query(`INSERT INTO schema_migrations (filename) VALUES ($1) ON CONFLICT DO NOTHING`, [f]);
            }
        }
    }


    for (const file of files) {
        const already = await pool.query(
            `SELECT 1 FROM schema_migrations WHERE filename = $1`,
            [file]
        );
        if (already.rows.length > 0) {
            continue;
        }

        const fullPath = path.join(dir, file);
        const sql = fs.readFileSync(fullPath, 'utf-8');

        console.log(`\nApplying file migration: ${file}`);
        try {
            await pool.query('BEGIN');
            await pool.query(sql);
            await pool.query(
                `INSERT INTO schema_migrations (filename) VALUES ($1)`,
                [file]
            );
            await pool.query('COMMIT');
            console.log(`  OK: ${file}`);
        } catch (err) {
            try { await pool.query('ROLLBACK'); } catch (_) {}
            console.error(`  ERROR in ${file}:`, err.message || err);
            throw err;
        }
    }
}

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    connectionTimeoutMillis: 30000
});

async function migrate() {
    console.log('Running database migrations...');

    try {
        // Add new columns to di_submissions if they don't exist
        const migrations = [
            `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS sender_email VARCHAR(255)`,
            `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS ai_review JSONB`,
            `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS revision_comments TEXT`,
            `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS signed_at TIMESTAMP`,
            `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS signer_name VARCHAR(255)`,
            `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS signature_hash VARCHAR(255)`,
            `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS verification_code VARCHAR(100)`,
            `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS signed_pdf_path VARCHAR(1000)`,

            // Group Documents table for shared lab documents (PI managed)
            `CREATE TABLE IF NOT EXISTS di_group_documents (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                title VARCHAR(255) NOT NULL,
                category VARCHAR(100) NOT NULL,
                description TEXT,
                filename VARCHAR(500) NOT NULL,
                file_type VARCHAR(20) NOT NULL CHECK (file_type IN ('PDF', 'EXCEL', 'WORD', 'POWERPOINT')),
                r2_object_key VARCHAR(1000) NOT NULL,
                uploaded_by VARCHAR(50) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                is_active BOOLEAN DEFAULT TRUE
            )`,
            `CREATE INDEX IF NOT EXISTS idx_di_group_documents_category ON di_group_documents(category)`,
            `CREATE INDEX IF NOT EXISTS idx_di_group_documents_active ON di_group_documents(is_active)`,

            // ==================== INVENTORY SYSTEM ====================

            // Extend di_submissions file_type CHECK to include INVENTORY and PRESENTATION
            `ALTER TABLE di_submissions DROP CONSTRAINT IF EXISTS di_submissions_file_type_check`,
            `ALTER TABLE di_submissions ADD CONSTRAINT di_submissions_file_type_check CHECK (file_type IN ('SOP', 'DATA', 'INVENTORY', 'PRESENTATION'))`,

            // Extend di_submissions status CHECK to include SUBMITTED (canonical GLP wording; PENDING is legacy for SOP/DATA)
            `ALTER TABLE di_submissions DROP CONSTRAINT IF EXISTS di_submissions_status_check`,
            `ALTER TABLE di_submissions ADD CONSTRAINT di_submissions_status_check CHECK (status IN ('PENDING', 'APPROVED', 'REVISION_NEEDED', 'SUBMITTED', 'DISCARDED'))`,

            // Inventory table — tracks what physically exists in the lab
            `CREATE TABLE IF NOT EXISTS di_inventory (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                affiliation VARCHAR(10) NOT NULL CHECK (affiliation IN ('LiU', 'UNAV')),
                vendor_company VARCHAR(255) NOT NULL,
                product_name VARCHAR(500) NOT NULL,
                catalog_id VARCHAR(255) NOT NULL,
                product_link VARCHAR(1000) NOT NULL,
                responsible_type VARCHAR(10) NOT NULL DEFAULT 'user' CHECK (responsible_type IN ('user', 'group')),
                responsible_user_id VARCHAR(50) REFERENCES di_allowlist(researcher_id),
                quantity_remaining NUMERIC(10,2) NOT NULL DEFAULT 0,
                unit VARCHAR(20) NOT NULL DEFAULT 'each' CHECK (unit IN ('bottle', 'box', 'pack', 'each')),
                storage VARCHAR(10) NOT NULL DEFAULT 'RT' CHECK (storage IN ('RT', '4C', '20C', '80C')),
                location VARCHAR(255),
                status VARCHAR(20) NOT NULL DEFAULT 'Active' CHECK (status IN ('Active', 'Finished')),
                origin_type VARCHAR(20) NOT NULL DEFAULT 'offline_import' CHECK (origin_type IN ('online_purchase', 'offline_import')),
                last_update_channel VARCHAR(20) DEFAULT 'offline_import' CHECK (last_update_channel IN ('online_ui', 'offline_import')),
                import_batch_id UUID,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_by VARCHAR(50) NOT NULL,
                last_updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_updated_by VARCHAR(50) NOT NULL
            )`,
            `CREATE INDEX IF NOT EXISTS idx_di_inventory_responsible ON di_inventory(responsible_type, responsible_user_id)`,
            `CREATE INDEX IF NOT EXISTS idx_di_inventory_affiliation ON di_inventory(affiliation)`,
            `CREATE INDEX IF NOT EXISTS idx_di_inventory_status ON di_inventory(status)`,
            `CREATE INDEX IF NOT EXISTS idx_di_inventory_catalog ON di_inventory(affiliation, vendor_company, catalog_id)`,

            // Inventory audit log — GLP traceability
            `CREATE TABLE IF NOT EXISTS di_inventory_log (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                inventory_id UUID NOT NULL REFERENCES di_inventory(id),
                action VARCHAR(30) NOT NULL,
                changed_by VARCHAR(50) NOT NULL,
                old_values JSONB,
                new_values JSONB,
                import_batch_id UUID,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )`,
            `CREATE INDEX IF NOT EXISTS idx_di_inventory_log_inventory ON di_inventory_log(inventory_id)`,

            // ==================== STORAGE CANONICAL FIX ====================
            // Migrate DB values to real-world labels: 20C → -20C, 80C → -80C
            `UPDATE di_inventory SET storage = '-20C' WHERE storage = '20C'`,
            `UPDATE di_inventory SET storage = '-80C' WHERE storage = '80C'`,
            `ALTER TABLE di_inventory DROP CONSTRAINT IF EXISTS di_inventory_storage_check`,
            `ALTER TABLE di_inventory ADD CONSTRAINT di_inventory_storage_check CHECK (storage IN ('RT', '4C', '-20C', '-80C'))`,

            // ==================== PURCHASE REQUEST SYSTEM ====================

            // Purchase requests — one request per researcher with justification
            `CREATE TABLE IF NOT EXISTS di_purchase_requests (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                requester_id VARCHAR(50) NOT NULL REFERENCES di_allowlist(researcher_id),
                affiliation VARCHAR(10) NOT NULL CHECK (affiliation IN ('LiU', 'UNAV')),
                justification TEXT NOT NULL,
                status VARCHAR(20) NOT NULL DEFAULT 'SUBMITTED' CHECK (status IN ('SUBMITTED', 'APPROVED', 'DECLINED')),
                request_total NUMERIC(12,2) NOT NULL DEFAULT 0,
                currency VARCHAR(10) NOT NULL,
                pi_comment TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )`,
            `CREATE INDEX IF NOT EXISTS idx_di_purchase_requests_requester ON di_purchase_requests(requester_id)`,
            `CREATE INDEX IF NOT EXISTS idx_di_purchase_requests_status ON di_purchase_requests(status)`,
            `CREATE INDEX IF NOT EXISTS idx_di_purchase_requests_affiliation ON di_purchase_requests(affiliation)`,

            // Purchase items — multiple items per request
            `CREATE TABLE IF NOT EXISTS di_purchase_items (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                request_id UUID NOT NULL REFERENCES di_purchase_requests(id) ON DELETE CASCADE,
                vendor_company VARCHAR(255) NOT NULL,
                product_name VARCHAR(500) NOT NULL,
                catalog_id VARCHAR(255) NOT NULL,
                product_link VARCHAR(1000) NOT NULL,
                quantity NUMERIC(10,2) NOT NULL,
                unit_price NUMERIC(12,2) NOT NULL,
                item_total NUMERIC(12,2) NOT NULL,
                currency VARCHAR(10) NOT NULL,
                ordered_at TIMESTAMP,
                received_at TIMESTAMP,
                inventory_id UUID REFERENCES di_inventory(id),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )`,
            `CREATE INDEX IF NOT EXISTS idx_di_purchase_items_request ON di_purchase_items(request_id)`,
            `CREATE INDEX IF NOT EXISTS idx_di_purchase_items_inventory ON di_purchase_items(inventory_id)`,

            // ==================== INVENTORY V2 — CANONICAL MODEL ====================

            // Canonical inventory items table (replaces di_inventory for new features)
            `CREATE TABLE IF NOT EXISTS di_inventory_items (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                affiliation VARCHAR(10) NOT NULL CHECK (affiliation IN ('LiU', 'UNAV')),
                item_type VARCHAR(20) NOT NULL CHECK (item_type IN ('product', 'sample', 'oligo')),
                source VARCHAR(10) NOT NULL CHECK (source IN ('Online', 'Offline')),
                item_name VARCHAR(500) NOT NULL,
                item_identifier VARCHAR(255) NOT NULL,
                quantity NUMERIC(10,2) NOT NULL DEFAULT 0,
                quantity_unit VARCHAR(30) NOT NULL,
                storage_location VARCHAR(255) NOT NULL,
                storage_temperature VARCHAR(20) NOT NULL CHECK (storage_temperature IN ('RT', '4C', '-20C', '-80C', 'LN2')),
                vendor_company VARCHAR(255),
                lot_or_batch_number VARCHAR(255),
                expiry_date DATE,
                opened_date DATE,
                notes TEXT,
                internal_order_number VARCHAR(50),
                unit_price NUMERIC(12,2),
                currency VARCHAR(10),
                product_link VARCHAR(1000),
                sample_origin VARCHAR(50),
                provider_or_collaborator VARCHAR(255),
                provider_detail VARCHAR(255),
                sample_status VARCHAR(50),
                visibility_scope VARCHAR(10) NOT NULL DEFAULT 'personal' CHECK (visibility_scope IN ('personal', 'group')),
                created_by VARCHAR(50) NOT NULL REFERENCES di_allowlist(researcher_id),
                status VARCHAR(20) NOT NULL DEFAULT 'Pending' CHECK (status IN ('Pending', 'Approved', 'Revision', 'Rejected')),
                status_comment TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )`,
            `CREATE INDEX IF NOT EXISTS idx_di_inv_items_type ON di_inventory_items(item_type)`,
            `CREATE INDEX IF NOT EXISTS idx_di_inv_items_created_by ON di_inventory_items(created_by)`,
            `CREATE INDEX IF NOT EXISTS idx_di_inv_items_status ON di_inventory_items(status)`,
            `CREATE INDEX IF NOT EXISTS idx_di_inv_items_visibility ON di_inventory_items(visibility_scope)`,
            `CREATE INDEX IF NOT EXISTS idx_di_inv_items_affiliation ON di_inventory_items(affiliation)`,
            `CREATE INDEX IF NOT EXISTS idx_di_inv_items_po ON di_inventory_items(internal_order_number)`,

            // Audit log for canonical inventory items
            `CREATE TABLE IF NOT EXISTS di_inventory_items_log (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                inventory_item_id UUID NOT NULL REFERENCES di_inventory_items(id),
                action VARCHAR(30) NOT NULL,
                changed_by VARCHAR(50) NOT NULL,
                old_values JSONB,
                new_values JSONB,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )`,
            `CREATE INDEX IF NOT EXISTS idx_di_inv_items_log_item ON di_inventory_items_log(inventory_item_id)`,

            // PO number daily sequence counter
            `CREATE TABLE IF NOT EXISTS di_po_sequence (
                date_prefix VARCHAR(20) PRIMARY KEY,
                last_seq INTEGER NOT NULL DEFAULT 0
            )`,

            // Extend di_purchase_items for v2 inventory linkage and PO numbers
            `ALTER TABLE di_purchase_items ADD COLUMN IF NOT EXISTS new_inventory_item_id UUID REFERENCES di_inventory_items(id)`,
            `ALTER TABLE di_purchase_items ADD COLUMN IF NOT EXISTS internal_order_number VARCHAR(50)`,
            `CREATE INDEX IF NOT EXISTS idx_di_purchase_items_new_inv ON di_purchase_items(new_inventory_item_id)`,

            // ==================== INVENTORY RULES — ADDITIVE EXTENSIONS ====================

            // Widen status CHECK to support new lifecycle statuses
            `ALTER TABLE di_inventory_items DROP CONSTRAINT IF EXISTS di_inventory_items_status_check`,
            `ALTER TABLE di_inventory_items ADD CONSTRAINT di_inventory_items_status_check
                CHECK (status IN ('Pending','Approved','Revision','Rejected','Received',
                    'ConsumePending','TransferPending','ApprovedLinked','Consumed',
                    'DeletePending','Deleted'))`,

            // owner_type: 'researcher' (personal) or 'group' (transferred / offline)
            `ALTER TABLE di_inventory_items ADD COLUMN IF NOT EXISTS owner_type VARCHAR(10) DEFAULT 'researcher'`,
            `ALTER TABLE di_inventory_items DROP CONSTRAINT IF EXISTS di_inventory_items_owner_type_check`,
            `ALTER TABLE di_inventory_items ADD CONSTRAINT di_inventory_items_owner_type_check
                CHECK (owner_type IN ('researcher','group'))`,

            // duplicate link for approve-as-duplicate workflow
            `ALTER TABLE di_inventory_items ADD COLUMN IF NOT EXISTS duplicate_of_inventory_id UUID`,

            // previous_status for revert-on-reject workflows
            `ALTER TABLE di_inventory_items ADD COLUMN IF NOT EXISTS previous_status VARCHAR(20)`,

            // transferred_at: set when PI approves transfer; used to hide from My Inventory
            `ALTER TABLE di_inventory_items ADD COLUMN IF NOT EXISTS transferred_at TIMESTAMP`,

            // delete request fields
            `ALTER TABLE di_inventory_items ADD COLUMN IF NOT EXISTS delete_reason VARCHAR(20)`,
            `ALTER TABLE di_inventory_items ADD COLUMN IF NOT EXISTS delete_reason_detail TEXT`,

            // Indexes for new columns
            `CREATE INDEX IF NOT EXISTS idx_di_inv_items_owner_type ON di_inventory_items(owner_type)`,
            `CREATE INDEX IF NOT EXISTS idx_di_inv_items_dup_ref ON di_inventory_items(duplicate_of_inventory_id)`,
            `CREATE INDEX IF NOT EXISTS idx_di_inv_items_transferred ON di_inventory_items(transferred_at)`,

            // Backfill owner_type for existing data
            `UPDATE di_inventory_items SET owner_type = 'researcher' WHERE owner_type IS NULL AND source = 'Online'`,
            `UPDATE di_inventory_items SET owner_type = 'group' WHERE owner_type IS NULL AND source = 'Offline'`,
            // ==================== GLP WEEKLY STATUS ====================

            `CREATE TABLE IF NOT EXISTS glp_weekly_status_index (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                user_id VARCHAR(50) NOT NULL,
                iso_week VARCHAR(7) NOT NULL,
                generated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                r2_snapshot_key VARCHAR(1000) NOT NULL,
                r2_harmony_key VARCHAR(1000),
                evidence_hash VARCHAR(64) NOT NULL,
                snapshot_version INTEGER NOT NULL DEFAULT 1,
                model_version VARCHAR(30) NOT NULL DEFAULT '1.0.0',
                UNIQUE(user_id, iso_week)
            )`,

            `CREATE INDEX IF NOT EXISTS idx_glp_weekly_user ON glp_weekly_status_index(user_id)`,
            `CREATE INDEX IF NOT EXISTS idx_glp_weekly_week ON glp_weekly_status_index(iso_week)`,
            `CREATE INDEX IF NOT EXISTS idx_glp_weekly_generated ON glp_weekly_status_index(generated_at DESC)`,

            // Migration 014: File associations for DIC (Data Intelligence Console)
            `CREATE TABLE IF NOT EXISTS di_file_associations (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                source_id UUID NOT NULL,
                target_id UUID NOT NULL,
                link_type VARCHAR(20) NOT NULL CHECK (link_type IN ('SOP', 'PRESENTATION')),
                created_by VARCHAR(50) NOT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(source_id, target_id),
                CHECK (source_id != target_id)
            )`,
            `CREATE INDEX IF NOT EXISTS idx_file_assoc_source ON di_file_associations(source_id)`,
            `CREATE INDEX IF NOT EXISTS idx_file_assoc_target ON di_file_associations(target_id)`,
            `CREATE INDEX IF NOT EXISTS idx_file_assoc_source_type ON di_file_associations(source_id, link_type)`,
            `CREATE INDEX IF NOT EXISTS idx_file_assoc_target_type ON di_file_associations(target_id, link_type)`,

            // ==================== PRESENTATION TYPE (migration 012) ====================
            `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS presentation_type TEXT`,
            `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS presentation_other TEXT`,

            // ==================== R2 OBJECT KEY (canonical storage pointer) ====================
            `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS r2_object_key TEXT`,

            // ==================== DRAGON SEAL ====================
            `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS pi_dragon_seal BOOLEAN NOT NULL DEFAULT FALSE`,
            `CREATE INDEX IF NOT EXISTS idx_di_submissions_dragon_seal ON di_submissions(pi_dragon_seal) WHERE pi_dragon_seal = TRUE`,

            // ==================== PURCHASE ITEM CORRECTIONS ====================

            // Item-level status for correction workflow
            `ALTER TABLE di_purchase_items ADD COLUMN IF NOT EXISTS item_status TEXT NOT NULL DEFAULT 'Active'`,
            `ALTER TABLE di_purchase_items ADD COLUMN IF NOT EXISTS status_note TEXT`,
            `ALTER TABLE di_purchase_items ADD COLUMN IF NOT EXISTS proposed_vendor TEXT`,
            `ALTER TABLE di_purchase_items ADD COLUMN IF NOT EXISTS proposed_product TEXT`,
            `ALTER TABLE di_purchase_items ADD COLUMN IF NOT EXISTS proposed_catalog_id TEXT`,
            `ALTER TABLE di_purchase_items ADD COLUMN IF NOT EXISTS proposed_link TEXT`,
            `ALTER TABLE di_purchase_items ADD COLUMN IF NOT EXISTS proposed_qty NUMERIC`,
            `ALTER TABLE di_purchase_items ADD COLUMN IF NOT EXISTS proposed_unit_price NUMERIC`,
            `ALTER TABLE di_purchase_items ADD COLUMN IF NOT EXISTS modified_by TEXT`,
            `ALTER TABLE di_purchase_items ADD COLUMN IF NOT EXISTS modified_at TIMESTAMPTZ`,
            `ALTER TABLE di_purchase_items ADD COLUMN IF NOT EXISTS pi_decision_note TEXT`,
            `ALTER TABLE di_purchase_items ADD COLUMN IF NOT EXISTS pi_decision_at TIMESTAMPTZ`,
            `CREATE INDEX IF NOT EXISTS idx_di_purchase_items_status ON di_purchase_items(item_status)`,

            // Audit log for purchase item actions
            `CREATE TABLE IF NOT EXISTS di_purchase_audit (
                id SERIAL PRIMARY KEY,
                request_id UUID,
                item_id UUID,
                action TEXT NOT NULL,
                actor_id TEXT NOT NULL,
                actor_role TEXT NOT NULL,
                old_json JSONB,
                new_json JSONB,
                note TEXT,
                at TIMESTAMPTZ DEFAULT NOW()
            )`,
            `CREATE INDEX IF NOT EXISTS idx_di_purchase_audit_item ON di_purchase_audit(item_id)`,
            `CREATE INDEX IF NOT EXISTS idx_di_purchase_audit_request ON di_purchase_audit(request_id)`,

            // ==================== GLP COHORT MEMBERSHIP ====================

            `CREATE TABLE IF NOT EXISTS di_glp_cohort_members (
                id BIGSERIAL PRIMARY KEY,
                cohort_id TEXT NOT NULL,
                user_id TEXT NOT NULL,
                included BOOLEAN NOT NULL DEFAULT TRUE,
                note TEXT,
                updated_by TEXT,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE(cohort_id, user_id)
            )`,
            `CREATE INDEX IF NOT EXISTS idx_di_glp_cohort_members_cohort ON di_glp_cohort_members(cohort_id)`,
            `CREATE INDEX IF NOT EXISTS idx_di_glp_cohort_members_user ON di_glp_cohort_members(user_id)`,

            // Backfill cohort membership from di_allowlist (active members only)
            `INSERT INTO di_glp_cohort_members (cohort_id, user_id, included, updated_by)
             SELECT
                 CASE WHEN a.affiliation = 'LiU' THEN 'LIU' ELSE 'UNAV' END,
                 a.researcher_id, TRUE, 'system-migration'
             FROM di_allowlist a
             WHERE a.active = TRUE AND a.affiliation IS NOT NULL
             ON CONFLICT (cohort_id, user_id) DO NOTHING`,

            // ==================== GLP GROUP WEEKLY STATUS ====================

            `CREATE TABLE IF NOT EXISTS glp_group_weekly_status_index (
                id BIGSERIAL PRIMARY KEY,
                cohort_id TEXT NOT NULL,
                iso_week TEXT NOT NULL,
                r2_snapshot_key TEXT NOT NULL,
                member_count INTEGER NOT NULL,
                membership_hash TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE(cohort_id, iso_week)
            )`,
            `CREATE INDEX IF NOT EXISTS idx_glp_group_weekly_cohort ON glp_group_weekly_status_index(cohort_id)`,
            `CREATE INDEX IF NOT EXISTS idx_glp_group_weekly_week ON glp_group_weekly_status_index(iso_week)`,

            // ==================== GROUP MEETING SCHEDULE ====================

            `CREATE TABLE IF NOT EXISTS meeting_schedule (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                meeting_date DATE NOT NULL,
                meeting_time TIME NOT NULL DEFAULT '09:00',
                duration_minutes INTEGER NOT NULL DEFAULT 60,
                status VARCHAR(10) NOT NULL DEFAULT 'DRAFT' CHECK (status IN ('DRAFT','LOCKED')),
                created_by VARCHAR(100) NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
                locked_at TIMESTAMPTZ,
                unlock_note TEXT
            )`,
            `ALTER TABLE meeting_schedule ADD COLUMN IF NOT EXISTS location_text TEXT`,
            `ALTER TABLE meeting_schedule ADD COLUMN IF NOT EXISTS notification_sent_at TIMESTAMPTZ`,
            `ALTER TABLE meeting_schedule ADD COLUMN IF NOT EXISTS notification_sent_by TEXT`,
            `ALTER TABLE meeting_schedule ADD COLUMN IF NOT EXISTS notification_sent_count INTEGER`,

            `CREATE UNIQUE INDEX IF NOT EXISTS uq_meeting_schedule_date ON meeting_schedule(meeting_date)`,
            `CREATE INDEX IF NOT EXISTS idx_meeting_schedule_status ON meeting_schedule(status)`,

            `CREATE TABLE IF NOT EXISTS meeting_participation (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                meeting_id UUID NOT NULL REFERENCES meeting_schedule(id) ON DELETE CASCADE,
                user_id VARCHAR(100) NOT NULL,
                slot_type VARCHAR(20) NOT NULL CHECK (slot_type IN ('DATA_DEEP','DATA_FOCUS','DATA_FLASH')),
                minutes_allocated INTEGER NOT NULL DEFAULT 2,
                order_position INTEGER NOT NULL DEFAULT 0
            )`,
            `CREATE INDEX IF NOT EXISTS idx_meeting_participation_meeting ON meeting_participation(meeting_id)`,
            `CREATE INDEX IF NOT EXISTS idx_meeting_participation_user ON meeting_participation(user_id)`,

            `CREATE TABLE IF NOT EXISTS meeting_speaker_pool (
                user_id VARCHAR(100) PRIMARY KEY,
                allow_deep BOOLEAN NOT NULL DEFAULT false,
                allow_focus BOOLEAN NOT NULL DEFAULT true,
                allow_flash BOOLEAN NOT NULL DEFAULT true,
                updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
            )`,

            // ==================== OLIGO-ID PHASE 1 (migration 029) ====================

            `CREATE EXTENSION IF NOT EXISTS pgcrypto`,

            `CREATE TABLE IF NOT EXISTS probe_catalog (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                canonical_id TEXT NOT NULL,
                display_name TEXT,
                notes TEXT,
                sequence TEXT,
                sequence_norm TEXT,
                chemistry_code TEXT NOT NULL DEFAULT 'STD',
                oligo_kind TEXT NOT NULL DEFAULT 'OLIGO' CHECK (oligo_kind IN ('LIBRARY','OLIGO')),
                library_type TEXT CHECK (library_type IS NULL OR library_type IN ('FRET','UNMODIFIED_MS','OTHER')),
                library_type_notes TEXT,
                fluorophore TEXT,
                quencher TEXT,
                length_nt INTEGER,
                status TEXT NOT NULL DEFAULT 'ACTIVE' CHECK (status IN ('ACTIVE','RETIRED','DRAFT')),
                finalized_at TIMESTAMPTZ,
                finalized_by TEXT,
                created_by TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )`,
            `CREATE UNIQUE INDEX IF NOT EXISTS uq_probe_catalog_canonical_id ON probe_catalog (canonical_id)`,
            `CREATE UNIQUE INDEX IF NOT EXISTS uq_probe_catalog_identity ON probe_catalog (sequence_norm, chemistry_code) WHERE sequence_norm IS NOT NULL`,
            `CREATE INDEX IF NOT EXISTS idx_probe_catalog_status ON probe_catalog (status)`,
            `CREATE INDEX IF NOT EXISTS idx_probe_catalog_created_by ON probe_catalog (created_by)`,

            `DO $$ BEGIN
                ALTER TABLE probe_catalog
                    ADD CONSTRAINT probe_catalog_library_rules_chk
                    CHECK (
                        (oligo_kind = 'OLIGO' AND library_type IS NULL AND library_type_notes IS NULL AND fluorophore IS NULL AND quencher IS NULL)
                        OR
                        (oligo_kind = 'LIBRARY' AND library_type IS NOT NULL)
                    );
            EXCEPTION WHEN duplicate_object THEN NULL; END $$;`,

            `DO $$ BEGIN
                ALTER TABLE probe_catalog
                    ADD CONSTRAINT probe_catalog_library_subtype_rules_chk
                    CHECK (
                        (library_type = 'FRET' AND fluorophore IS NOT NULL AND quencher IS NOT NULL)
                        OR
                        (library_type = 'UNMODIFIED_MS' AND fluorophore IS NULL AND quencher IS NULL)
                        OR
                        (library_type = 'OTHER' AND notes IS NOT NULL AND fluorophore IS NULL AND quencher IS NULL)
                        OR
                        (library_type IS NULL)
                    );
            EXCEPTION WHEN duplicate_object THEN NULL; END $$;`,

            `CREATE TABLE IF NOT EXISTS probe_syntheses (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                probe_id UUID NOT NULL REFERENCES probe_catalog(id),
                order_number TEXT,
                order_item TEXT,
                batch_key TEXT,
                supplier TEXT,
                review_status TEXT NOT NULL DEFAULT 'PENDING' CHECK (review_status IN ('PENDING','ACCEPTED','REJECTED','FLAGGED')),
                reviewed_by TEXT,
                reviewed_at TIMESTAMPTZ,
                created_by TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )`,
            `CREATE INDEX IF NOT EXISTS idx_probe_syntheses_probe ON probe_syntheses (probe_id)`,
            `CREATE INDEX IF NOT EXISTS idx_probe_syntheses_order ON probe_syntheses (order_number)`,
            `CREATE INDEX IF NOT EXISTS idx_probe_syntheses_review ON probe_syntheses (review_status)`,

            `CREATE TABLE IF NOT EXISTS probe_synthesis_tubes (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                synthesis_id UUID NOT NULL REFERENCES probe_syntheses(id),
                tube_label TEXT,
                concentration NUMERIC,
                concentration_unit TEXT DEFAULT 'uM',
                volume_ul NUMERIC,
                storage_location TEXT,
                storage_temp TEXT CHECK (storage_temp IS NULL OR storage_temp IN ('RT','4C','-20C','-80C','LN2')),
                status TEXT NOT NULL DEFAULT 'IN_STOCK' CHECK (status IN ('IN_STOCK','DEPLETED','DISCARDED')),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )`,
            `CREATE INDEX IF NOT EXISTS idx_probe_tubes_synthesis ON probe_synthesis_tubes (synthesis_id)`,
            `CREATE INDEX IF NOT EXISTS idx_probe_tubes_status ON probe_synthesis_tubes (status)`,

            `CREATE TABLE IF NOT EXISTS probe_libraries (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                library_name TEXT NOT NULL,
                description TEXT,
                created_by TEXT NOT NULL,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )`,
            `CREATE UNIQUE INDEX IF NOT EXISTS uq_probe_libraries_name ON probe_libraries (library_name)`,

            `CREATE TABLE IF NOT EXISTS probe_library_members (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                library_id UUID NOT NULL REFERENCES probe_libraries(id) ON DELETE CASCADE,
                probe_id UUID NOT NULL REFERENCES probe_catalog(id),
                added_by TEXT NOT NULL,
                added_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE (library_id, probe_id)
            )`,
            `CREATE INDEX IF NOT EXISTS idx_probe_lib_members_library ON probe_library_members (library_id)`,
            `CREATE INDEX IF NOT EXISTS idx_probe_lib_members_probe ON probe_library_members (probe_id)`,

            `CREATE TABLE IF NOT EXISTS probe_pdfs (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                probe_id UUID REFERENCES probe_catalog(id),
                original_filename TEXT NOT NULL,
                r2_object_key TEXT NOT NULL,
                file_size_bytes INTEGER,
                parse_status TEXT NOT NULL DEFAULT 'UPLOADED' CHECK (parse_status IN ('UPLOADED','PARSED','FAILED')),
                parsed_json JSONB,
                uploaded_by TEXT NOT NULL,
                uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )`,
            `CREATE INDEX IF NOT EXISTS idx_probe_pdfs_probe ON probe_pdfs (probe_id)`,

            // ==================== OLIGO PDF PACKS (Pack Architecture) ====================

            `CREATE TABLE IF NOT EXISTS oligo_pdf_imports (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                supplier TEXT NOT NULL,
                original_filename TEXT NOT NULL,
                file_storage_key TEXT NOT NULL,
                file_sha256 TEXT NOT NULL,
                po_no TEXT,
                order_no TEXT,
                parse_version TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'PENDING',
                uploaded_by TEXT NOT NULL,
                uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE (supplier, file_sha256)
            )`,

            `CREATE TABLE IF NOT EXISTS oligo_pdf_import_items (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                import_id UUID NOT NULL REFERENCES oligo_pdf_imports(id) ON DELETE CASCADE,
                supplier TEXT NOT NULL,
                canonical_id TEXT NOT NULL,
                polymer_type TEXT NOT NULL,
                synthesis_oligo_no TEXT NOT NULL,
                sequence_5to3 TEXT NOT NULL,
                mod_5 TEXT NOT NULL,
                mod_3 TEXT NOT NULL,
                int_mod_5 TEXT NOT NULL,
                int_mod_6 TEXT NOT NULL,
                int_mod_7 TEXT NOT NULL,
                int_mod_8 TEXT NOT NULL,
                template_json JSONB NOT NULL,
                template_json_pi JSONB,
                warnings JSONB DEFAULT '[]'::jsonb,
                requires_pi_confirmation BOOLEAN NOT NULL DEFAULT false,
                decision_status TEXT DEFAULT 'PENDING',
                decided_by TEXT,
                decided_at TIMESTAMPTZ,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE (import_id, canonical_id),
                UNIQUE (supplier, synthesis_oligo_no)
            )`,

            `CREATE INDEX IF NOT EXISTS idx_oligo_pdf_import_items_import_id ON oligo_pdf_import_items(import_id)`,
            `CREATE INDEX IF NOT EXISTS idx_oligo_pdf_import_items_supplier ON oligo_pdf_import_items(supplier)`,

// ==================== OLIGO-ID PHASE 2 (synthesis linkage) ====================
            // Additive: pack finalization fields
            `ALTER TABLE oligo_pdf_imports ADD COLUMN IF NOT EXISTS finalized_by TEXT`,
            `ALTER TABLE oligo_pdf_imports ADD COLUMN IF NOT EXISTS finalized_at TIMESTAMPTZ`,

            // Additive: link each synthesis row to its source import + item (Option 1)
            `ALTER TABLE probe_syntheses ADD COLUMN IF NOT EXISTS synthesis_oligo_no TEXT`,
            `ALTER TABLE probe_syntheses ADD COLUMN IF NOT EXISTS source_import_id UUID`,
            `ALTER TABLE probe_syntheses ADD COLUMN IF NOT EXISTS source_import_item_id UUID`,

            // Add foreign keys only if missing (Postgres lacks ADD CONSTRAINT IF NOT EXISTS)
            `DO $$ BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_constraint WHERE conname = 'probe_syntheses_source_import_id_fkey'
                ) THEN
                    ALTER TABLE probe_syntheses
                        ADD CONSTRAINT probe_syntheses_source_import_id_fkey
                        FOREIGN KEY (source_import_id) REFERENCES oligo_pdf_imports(id);
                END IF;
            EXCEPTION WHEN duplicate_object THEN NULL; END $$;`,

            `DO $$ BEGIN
                IF NOT EXISTS (
                    SELECT 1 FROM pg_constraint WHERE conname = 'probe_syntheses_source_import_item_id_fkey'
                ) THEN
                    ALTER TABLE probe_syntheses
                        ADD CONSTRAINT probe_syntheses_source_import_item_id_fkey
                        FOREIGN KEY (source_import_item_id) REFERENCES oligo_pdf_import_items(id);
                END IF;
            EXCEPTION WHEN duplicate_object THEN NULL; END $$;`,

            // Indexes for fast “show me all syntheses for this import/item/synthesis_no”
            `CREATE INDEX IF NOT EXISTS idx_probe_syntheses_source_import_id ON probe_syntheses(source_import_id)`,
            `CREATE INDEX IF NOT EXISTS idx_probe_syntheses_source_import_item_id ON probe_syntheses(source_import_item_id)`,
            `CREATE INDEX IF NOT EXISTS idx_probe_syntheses_synthesis_oligo_no ON probe_syntheses(synthesis_oligo_no)`,

            `CREATE TABLE IF NOT EXISTS probe_audit_log (
                id BIGSERIAL PRIMARY KEY,
                entity_type TEXT NOT NULL,
                entity_id UUID NOT NULL,
                action TEXT NOT NULL,
                actor TEXT NOT NULL,
                old_values JSONB,
                new_values JSONB,
                note TEXT,
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )`,
            `CREATE INDEX IF NOT EXISTS idx_probe_audit_entity ON probe_audit_log (entity_type, entity_id)`,
            `CREATE INDEX IF NOT EXISTS idx_probe_audit_actor ON probe_audit_log (actor)`,
            `CREATE INDEX IF NOT EXISTS idx_probe_audit_created ON probe_audit_log (created_at DESC)`,

            // Immutable identity trigger
            `CREATE OR REPLACE FUNCTION probe_identity_immutable()
            RETURNS TRIGGER AS $fn$
            BEGIN
                IF OLD.finalized_at IS NOT NULL THEN
                    IF NEW.canonical_id IS DISTINCT FROM OLD.canonical_id THEN
                        RAISE EXCEPTION 'Cannot modify canonical_id on a finalized probe';
                    END IF;
                    IF NEW.sequence IS DISTINCT FROM OLD.sequence THEN
                        RAISE EXCEPTION 'Cannot modify sequence on a finalized probe';
                    END IF;
                    IF NEW.sequence_norm IS DISTINCT FROM OLD.sequence_norm THEN
                        RAISE EXCEPTION 'Cannot modify sequence_norm on a finalized probe';
                    END IF;
                    IF NEW.chemistry_code IS DISTINCT FROM OLD.chemistry_code THEN
                        RAISE EXCEPTION 'Cannot modify chemistry_code on a finalized probe';
                    END IF;
                    IF NEW.oligo_kind IS DISTINCT FROM OLD.oligo_kind THEN
                        RAISE EXCEPTION 'Cannot modify oligo_kind on a finalized probe';
                    END IF;
                    IF NEW.library_type IS DISTINCT FROM OLD.library_type THEN
                        RAISE EXCEPTION 'Cannot modify library_type on a finalized probe';
                    END IF;
                    IF NEW.library_type_notes IS DISTINCT FROM OLD.library_type_notes THEN
                        RAISE EXCEPTION 'Cannot modify library_type_notes on a finalized probe';
                    END IF;
                    IF NEW.fluorophore IS DISTINCT FROM OLD.fluorophore THEN
                        RAISE EXCEPTION 'Cannot modify fluorophore on a finalized probe';
                    END IF;
                    IF NEW.quencher IS DISTINCT FROM OLD.quencher THEN
                        RAISE EXCEPTION 'Cannot modify quencher on a finalized probe';
                    END IF;
                    IF NEW.notes IS DISTINCT FROM OLD.notes THEN
                        RAISE EXCEPTION 'Cannot modify notes on a finalized probe';
                    END IF;
                END IF;
                RETURN NEW;
            END;
            $fn$ LANGUAGE plpgsql`,
            `DROP TRIGGER IF EXISTS trg_probe_identity_immutable ON probe_catalog`,
            `CREATE TRIGGER trg_probe_identity_immutable BEFORE UPDATE ON probe_catalog FOR EACH ROW EXECUTE FUNCTION probe_identity_immutable()`,

        ];

        for (const sql of migrations) {
            try {
                await pool.query(sql);
                console.log('  OK:', sql.substring(0, 60) + '...');
            } catch (err) {
                if (err.code === '42701') {
                    // Column already exists, ignore
                    console.log('  SKIP (exists):', sql.substring(0, 50) + '...');
                } else {
                    throw err;
                }
            }
        }

        await runSqlFileMigrations(pool);

        console.log('\nMigration completed successfully!');

    } catch (err) {
        console.error('Migration error:', err);
    } finally {
        await pool.end();
    }
}

migrate();
