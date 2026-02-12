require('dotenv').config();
const { Pool } = require('pg');

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false },
    connectionTimeoutMillis: 30000
});

console.log('Database URL:', process.env.DATABASE_URL ? 'Set (hidden)' : 'NOT SET');

async function seed() {
    console.log('Connecting to database...');

    try {
        // Create tables first
        console.log('Creating tables...');

        await pool.query(`
            CREATE EXTENSION IF NOT EXISTS pgcrypto;

            CREATE TABLE IF NOT EXISTS di_allowlist (
                researcher_id VARCHAR(50) PRIMARY KEY,
                name VARCHAR(255) NOT NULL,
                institution_email VARCHAR(255) UNIQUE NOT NULL,
                affiliation VARCHAR(10) NOT NULL CHECK (affiliation IN ('LiU', 'UNAV')),
                active BOOLEAN DEFAULT TRUE
            );

            CREATE TABLE IF NOT EXISTS di_users (
                institution_email VARCHAR(255) PRIMARY KEY,
                personal_email VARCHAR(255),
                password_hash VARCHAR(255) NOT NULL,
                researcher_id VARCHAR(50) NOT NULL REFERENCES di_allowlist(researcher_id),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_login TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS di_submissions (
                submission_id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                researcher_id VARCHAR(50) NOT NULL,
                affiliation VARCHAR(10) NOT NULL CHECK (affiliation IN ('LiU', 'UNAV')),
                file_type VARCHAR(20) NOT NULL CHECK (file_type IN ('SOP', 'DATA', 'INVENTORY', 'PRESENTATION')),
                original_filename VARCHAR(500) NOT NULL,
                status VARCHAR(20) DEFAULT 'PENDING' CHECK (status IN ('PENDING', 'APPROVED', 'REVISION_NEEDED')),
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );
        `);

        console.log('Tables created successfully.');

        // Insert researchers
        console.log('Inserting researchers into allowlist...');

        const researchers = [
            // Administrator
            { id: 'FJH', name: 'Frank J. Hernandez', email: 'frank.hernandez@liu.se', affiliation: 'LiU' },

            // LiU Researchers
            { id: 'BAB', name: 'Baris Ata Borsa', email: 'baris.ata.borsa@liu.se', affiliation: 'LiU' },
            { id: 'KKA', name: 'Khadija-Tul Kubra Akhtar', email: 'khadija-tul.kubra.akhtar@liu.se', affiliation: 'LiU' },
            { id: 'MC', name: 'Marina Chandrou', email: 'march354@student.liu.se', affiliation: 'LiU' },
            { id: 'ML', name: 'Matilda Lagerqvist', email: 'matla239@student.liu.se', affiliation: 'LiU' },
            { id: 'SKP', name: 'Sofia Konstantina Prentza', email: 'sofpr049@student.liu.se', affiliation: 'LiU' },
            { id: 'JS', name: 'Jiayi Sun', email: 'jiasu762@student.liu.se', affiliation: 'LiU' },
            { id: 'LH', name: 'Lovisa Hjalmarsson', email: 'lovhj143@student.liu.se', affiliation: 'LiU' },
            { id: 'NM', name: 'Nora Moein', email: 'normo079@student.liu.se', affiliation: 'LiU' },
            { id: 'SR', name: 'Sofie Rapp', email: 'sofra030@student.liu.se', affiliation: 'LiU' },
            { id: 'JB', name: 'Jessica Bergman', email: 'jesbe968@student.liu.se', affiliation: 'LiU' },
            { id: 'PMK', name: 'Penina Muthoni Kungu', email: 'penku788@student.liu.se', affiliation: 'LiU' },

            // UNAV Researchers
            { id: 'HMMU', name: 'Harold Mateo Mojica Urrego', email: 'haroldmmojica@unav.es', affiliation: 'UNAV' },
            { id: 'HJM', name: 'Helena Jorge Mendazona', email: 'hjorgemenda@unav.es', affiliation: 'UNAV' },
            { id: 'RBP', name: 'Raffaele Bellini Puglielli', email: 'rbellini@unav.es', affiliation: 'UNAV' }
        ];

        for (const r of researchers) {
            try {
                await pool.query(
                    `INSERT INTO di_allowlist (researcher_id, name, institution_email, affiliation, active)
                     VALUES ($1, $2, $3, $4, true)
                     ON CONFLICT (researcher_id) DO UPDATE SET
                         name = EXCLUDED.name,
                         institution_email = EXCLUDED.institution_email,
                         affiliation = EXCLUDED.affiliation`,
                    [r.id, r.name, r.email, r.affiliation]
                );
                console.log(`  Added: ${r.name} (${r.affiliation})`);
            } catch (err) {
                console.error(`  Error adding ${r.name}:`, err.message);
            }
        }

        // Verify
        const result = await pool.query('SELECT COUNT(*) as count FROM di_allowlist');
        console.log(`\nTotal researchers in allowlist: ${result.rows[0].count}`);

        console.log('\nSeed completed successfully!');

    } catch (err) {
        console.error('Seed error:', err);
    } finally {
        await pool.end();
    }
}

seed();
