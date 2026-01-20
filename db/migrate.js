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
            `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS signed_at TIMESTAMP`
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
