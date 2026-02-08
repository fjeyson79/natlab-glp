require('dotenv').config();
const { Pool } = require('pg');

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

            // Extend di_submissions file_type CHECK to include INVENTORY
            `ALTER TABLE di_submissions DROP CONSTRAINT IF EXISTS di_submissions_file_type_check`,
            `ALTER TABLE di_submissions ADD CONSTRAINT di_submissions_file_type_check CHECK (file_type IN ('SOP', 'DATA', 'INVENTORY'))`,

            // Extend di_submissions status CHECK to include SUBMITTED (canonical GLP wording; PENDING is legacy for SOP/DATA)
            `ALTER TABLE di_submissions DROP CONSTRAINT IF EXISTS di_submissions_status_check`,
            `ALTER TABLE di_submissions ADD CONSTRAINT di_submissions_status_check CHECK (status IN ('PENDING', 'APPROVED', 'REVISION_NEEDED', 'SUBMITTED'))`,

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
            `CREATE INDEX IF NOT EXISTS idx_di_purchase_items_new_inv ON di_purchase_items(new_inventory_item_id)`
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

        console.log('\nMigration completed successfully!');

    } catch (err) {
        console.error('Migration error:', err);
    } finally {
        await pool.end();
    }
}

migrate();
