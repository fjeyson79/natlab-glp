require('dotenv').config();

const express = require('express');
const multer = require('multer');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const FormData = require('form-data');
const fetch = require('node-fetch');

const app = express();
const PORT = process.env.PORT || 8080;

// Database connection
const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: { rejectUnauthorized: false }
});

// Middleware
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Detect production environment (Railway sets RAILWAY_ENVIRONMENT or we check for DATABASE_URL)
const isProduction = process.env.NODE_ENV === 'production' ||
                     process.env.RAILWAY_ENVIRONMENT === 'production' ||
                     !!process.env.DATABASE_URL;

console.log('Environment:', { isProduction, NODE_ENV: process.env.NODE_ENV, RAILWAY: process.env.RAILWAY_ENVIRONMENT });

// Trust proxy in production (Railway uses reverse proxy)
app.set('trust proxy', 1);

// Session configuration (in memory for V1)
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback_secret_change_me',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: true,
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: 'none'
    }
}));

// Multer configuration for file uploads (memory storage)
const upload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 50 * 1024 * 1024 } // 50MB limit
});

// Serve static files from public folder under /di
app.use('/di', express.static(path.join(__dirname, 'public')));

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Debug endpoint to check members (temporary - for troubleshooting)
app.get('/api/di/debug-members', async (req, res) => {
    try {
        // Check session
        const sessionInfo = {
            hasSession: !!req.session,
            hasUser: !!req.session?.user,
            userRole: req.session?.user?.role || 'none',
            userName: req.session?.user?.name || 'none'
        };

        // Check database connection
        const dbTest = await pool.query('SELECT 1 as test');

        // Check role column
        const columnCheck = await pool.query(`
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'di_allowlist' AND column_name = 'role'
        `);
        const hasRoleColumn = columnCheck.rows.length > 0;

        // Get all members
        let members;
        if (hasRoleColumn) {
            members = await pool.query(
                `SELECT researcher_id, name, institution_email, affiliation,
                        COALESCE(role, 'researcher') as role, active
                 FROM di_allowlist
                 ORDER BY role DESC, name ASC`
            );
        } else {
            members = await pool.query(
                `SELECT researcher_id, name, institution_email, affiliation,
                        'researcher' as role, active
                 FROM di_allowlist
                 ORDER BY name ASC`
            );
        }

        res.json({
            success: true,
            session: sessionInfo,
            database: {
                connected: true,
                hasRoleColumn: hasRoleColumn
            },
            members: {
                total: members.rows.length,
                active: members.rows.filter(m => m.active).length,
                list: members.rows
            }
        });

    } catch (err) {
        res.status(500).json({
            success: false,
            error: err.message,
            stack: err.stack
        });
    }
});

// AUTH MIDDLEWARE
function requireAuth(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    next();
}

// PI MIDDLEWARE - requires user to be a Principal Investigator
function requirePI(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    if (req.session.user.role !== 'pi') {
        return res.status(403).json({ error: 'Access denied. PI role required.' });
    }
    next();
}

// API ENDPOINTS

// Helper function to check if role column exists
// Re-checks every 60 seconds or when column is found to not exist (in case migration is run)
let roleColumnExists = null;
let roleColumnLastCheck = 0;
const ROLE_COLUMN_CHECK_INTERVAL = 60000; // 60 seconds

async function checkRoleColumn() {
    const now = Date.now();
    // Re-check if: never checked, column didn't exist last time, or cache expired
    if (roleColumnExists === null || roleColumnExists === false || (now - roleColumnLastCheck > ROLE_COLUMN_CHECK_INTERVAL)) {
        try {
            const result = await pool.query(`
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'di_allowlist' AND column_name = 'role'
            `);
            roleColumnExists = result.rows.length > 0;
            roleColumnLastCheck = now;
        } catch (err) {
            roleColumnExists = false;
        }
    }
    return roleColumnExists;
}

// Helper to get allowlist query based on role column existence
function getAllowlistQuery(hasRole) {
    if (hasRole) {
        return `SELECT researcher_id, name, institution_email, affiliation, active, COALESCE(role, 'researcher') as role
                FROM di_allowlist WHERE LOWER(institution_email) = $1`;
    }
    return `SELECT researcher_id, name, institution_email, affiliation, active, 'researcher' as role
            FROM di_allowlist WHERE LOWER(institution_email) = $1`;
}

// POST /api/di/access-check
// Check if email is in allowlist and whether user exists
app.post('/api/di/access-check', async (req, res) => {
    try {
        const { institution_email } = req.body;

        if (!institution_email) {
            return res.status(400).json({ error: 'Email is required' });
        }

        const emailLower = institution_email.toLowerCase().trim();

        // Check allowlist (handle missing role column)
        const hasRole = await checkRoleColumn();
        const allowlistResult = await pool.query(getAllowlistQuery(hasRole), [emailLower]);

        if (allowlistResult.rows.length === 0) {
            return res.json({ allowed: false, message: 'Email not in allowlist' });
        }

        const allowlistEntry = allowlistResult.rows[0];

        if (!allowlistEntry.active) {
            return res.json({ allowed: false, message: 'Account is inactive' });
        }

        // Check if user already registered
        const userResult = await pool.query(
            'SELECT institution_email FROM di_users WHERE LOWER(institution_email) = $1',
            [emailLower]
        );

        const isRegistered = userResult.rows.length > 0;

        return res.json({
            allowed: true,
            next: isRegistered ? 'login' : 'register',
            name: allowlistEntry.name,
            affiliation: allowlistEntry.affiliation,
            role: allowlistEntry.role
        });

    } catch (err) {
        console.error('Access check error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/register
// Register a new user (must be in allowlist)
app.post('/api/di/register', async (req, res) => {
    try {
        const { institution_email, personal_email, password } = req.body;

        if (!institution_email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        if (password.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters' });
        }

        const emailLower = institution_email.toLowerCase().trim();

        // Verify in allowlist (handle missing role column)
        const hasRole = await checkRoleColumn();
        const allowlistResult = await pool.query(getAllowlistQuery(hasRole), [emailLower]);

        if (allowlistResult.rows.length === 0) {
            return res.status(403).json({ error: 'Email not in allowlist' });
        }

        const allowlistEntry = allowlistResult.rows[0];

        if (!allowlistEntry.active) {
            return res.status(403).json({ error: 'Account is inactive' });
        }

        // Check if already registered
        const existingUser = await pool.query(
            'SELECT institution_email FROM di_users WHERE LOWER(institution_email) = $1',
            [emailLower]
        );

        if (existingUser.rows.length > 0) {
            return res.status(409).json({ error: 'User already registered' });
        }

        // Hash password
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        // Insert user
        await pool.query(
            `INSERT INTO di_users (institution_email, personal_email, password_hash, researcher_id, created_at)
             VALUES ($1, $2, $3, $4, CURRENT_TIMESTAMP)`,
            [emailLower, personal_email || null, passwordHash, allowlistEntry.researcher_id]
        );

        // Set session with role
        req.session.user = {
            institution_email: emailLower,
            researcher_id: allowlistEntry.researcher_id,
            name: allowlistEntry.name,
            affiliation: allowlistEntry.affiliation,
            role: allowlistEntry.role
        };

        res.json({
            success: true,
            message: 'Registration successful',
            user: req.session.user,
            redirect: allowlistEntry.role === 'pi' ? 'pi-dashboard.html' : 'upload.html'
        });

    } catch (err) {
        console.error('Registration error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/login
// Login an existing user
app.post('/api/di/login', async (req, res) => {
    try {
        const { institution_email, password } = req.body;

        if (!institution_email || !password) {
            return res.status(400).json({ error: 'Email and password are required' });
        }

        const emailLower = institution_email.toLowerCase().trim();

        // Get user with allowlist info (handle missing role column)
        const hasRole = await checkRoleColumn();
        const loginQuery = hasRole
            ? `SELECT u.institution_email, u.password_hash, u.researcher_id,
                      a.name, a.affiliation, a.active, COALESCE(a.role, 'researcher') as role
               FROM di_users u
               JOIN di_allowlist a ON u.researcher_id = a.researcher_id
               WHERE LOWER(u.institution_email) = $1`
            : `SELECT u.institution_email, u.password_hash, u.researcher_id,
                      a.name, a.affiliation, a.active, 'researcher' as role
               FROM di_users u
               JOIN di_allowlist a ON u.researcher_id = a.researcher_id
               WHERE LOWER(u.institution_email) = $1`;

        const result = await pool.query(loginQuery, [emailLower]);

        if (result.rows.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = result.rows[0];

        if (!user.active) {
            return res.status(403).json({ error: 'Account is inactive' });
        }

        // Verify password
        const passwordMatch = await bcrypt.compare(password, user.password_hash);

        if (!passwordMatch) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        // Update last login
        await pool.query(
            'UPDATE di_users SET last_login = CURRENT_TIMESTAMP WHERE LOWER(institution_email) = $1',
            [emailLower]
        );

        // Set session with role
        req.session.user = {
            institution_email: user.institution_email,
            researcher_id: user.researcher_id,
            name: user.name,
            affiliation: user.affiliation,
            role: user.role
        };

        res.json({
            success: true,
            message: 'Login successful',
            user: req.session.user,
            redirect: user.role === 'pi' ? 'pi-dashboard.html' : 'upload.html'
        });

    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/me
// Get current user profile
app.get('/api/di/me', requireAuth, (req, res) => {
    res.json({
        name: req.session.user.name,
        researcher_id: req.session.user.researcher_id,
        affiliation: req.session.user.affiliation,
        role: req.session.user.role || 'researcher',
        institution_email: req.session.user.institution_email
    });
});

// GET /api/di/my-files
// Get current researcher's files organized by year and status
// Files appear in ONLY ONE folder based on status (no duplication to save storage)
// - Submitted: files with status PENDING (under review)
// - Approved: files with status APPROVED
// - Files with REVISION_NEEDED are removed from Submitted (need to be re-uploaded)
app.get('/api/di/my-files', requireAuth, async (req, res) => {
    try {
        const user = req.session.user;

        // Get all submissions for this researcher
        const result = await pool.query(
            `SELECT submission_id, file_type, original_filename, status, created_at, signed_at,
                    EXTRACT(YEAR FROM created_at) as year
             FROM di_submissions
             WHERE researcher_id = $1
             ORDER BY created_at DESC`,
            [user.researcher_id]
        );

        // Build tree structure: My Files / Year / Submitted|Approved
        const tree = {
            name: 'My Files',
            type: 'folder',
            children: []
        };

        // Group by year
        const yearMap = {};

        // Count stats
        let pendingCount = 0;
        let approvedCount = 0;
        let revisionCount = 0;

        for (const file of result.rows) {
            const year = file.year || new Date(file.created_at).getFullYear();
            const status = file.status || 'PENDING';

            if (!yearMap[year]) {
                yearMap[year] = {
                    name: String(year),
                    type: 'folder',
                    children: [
                        { name: 'Submitted', type: 'folder', children: [], count: 0 },
                        { name: 'Approved', type: 'folder', children: [], count: 0 }
                    ]
                };
            }

            const fileNode = {
                name: file.original_filename,
                type: 'file',
                id: file.submission_id,
                status: status,
                fileType: file.file_type,
                date: file.created_at,
                signedAt: file.signed_at
            };

            // Place file in ONLY ONE folder based on status
            if (status === 'APPROVED') {
                // Approved files go to Approved folder only
                yearMap[year].children[1].children.push(fileNode);
                yearMap[year].children[1].count++;
                approvedCount++;
            } else if (status === 'PENDING') {
                // Pending files (under review) go to Submitted folder
                yearMap[year].children[0].children.push(fileNode);
                yearMap[year].children[0].count++;
                pendingCount++;
            } else if (status === 'REVISION_NEEDED') {
                // Revision needed files are NOT shown in Submitted
                // They need to be re-uploaded, so they're effectively removed
                revisionCount++;
            }
        }

        // Convert map to array and sort by year descending
        const years = Object.keys(yearMap).sort((a, b) => b - a);
        for (const year of years) {
            const yearNode = yearMap[year];
            // Update counts in folder names
            yearNode.children[0].name = `Submitted (${yearNode.children[0].count})`;
            yearNode.children[1].name = `Approved (${yearNode.children[1].count})`;
            tree.children.push(yearNode);
        }

        // Add current year if no files yet
        const currentYear = new Date().getFullYear();
        if (!yearMap[currentYear]) {
            tree.children.unshift({
                name: String(currentYear),
                type: 'folder',
                children: [
                    { name: 'Submitted (0)', type: 'folder', children: [], count: 0 },
                    { name: 'Approved (0)', type: 'folder', children: [], count: 0 }
                ]
            });
        }

        res.json({
            success: true,
            tree: tree,
            totalFiles: result.rows.length,
            pendingCount: pendingCount,
            approvedCount: approvedCount,
            revisionCount: revisionCount
        });

    } catch (err) {
        console.error('My files error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/upload
// Upload file and forward to n8n webhook
app.post('/api/di/upload', requireAuth, upload.single('file'), async (req, res) => {
    try {
        const { fileType } = req.body;
        const file = req.file;

        if (!fileType || !['SOP', 'DATA'].includes(fileType)) {
            return res.status(400).json({ error: 'fileType must be SOP or DATA' });
        }

        if (!file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const user = req.session.user;

        // Record submission in database
        const submissionResult = await pool.query(
            `INSERT INTO di_submissions (researcher_id, affiliation, file_type, original_filename)
             VALUES ($1, $2, $3, $4)
             RETURNING submission_id`,
            [user.researcher_id, user.affiliation, fileType, file.originalname]
        );

        const submissionId = submissionResult.rows[0].submission_id;

        // Forward to n8n webhook as multipart form data
        const webhookUrl = process.env.N8N_DI_WEBHOOK_URL;

        if (!webhookUrl) {
            console.error('N8N_DI_WEBHOOK_URL not configured');
            return res.status(500).json({ error: 'Webhook not configured' });
        }

        const formData = new FormData();
        formData.append('researcher_id', user.researcher_id);
        formData.append('affiliation', user.affiliation);
        formData.append('fileType', fileType);
        formData.append('original_filename', file.originalname);
        formData.append('submission_id', submissionId);
        formData.append('file', file.buffer, {
            filename: file.originalname,
            contentType: file.mimetype
        });

        const webhookResponse = await fetch(webhookUrl, {
            method: 'POST',
            body: formData,
            headers: formData.getHeaders()
        });

        if (!webhookResponse.ok) {
            console.error('Webhook error:', webhookResponse.status, await webhookResponse.text());
            // Still return success to user since we recorded the submission
            return res.json({
                success: true,
                submission_id: submissionId,
                warning: 'File recorded but webhook delivery pending'
            });
        }

        res.json({
            success: true,
            submission_id: submissionId,
            message: 'File uploaded successfully'
        });

    } catch (err) {
        console.error('Upload error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/external-upload
// API endpoint for n8n or external services to upload files
// Requires API key authentication via header: x-api-key
app.post('/api/di/external-upload', upload.single('file'), async (req, res) => {
    try {
        // Verify API key
        const apiKey = req.headers['x-api-key'];
        if (!apiKey || apiKey !== process.env.API_SECRET_KEY) {
            return res.status(401).json({ error: 'Invalid or missing API key' });
        }

        const { researcher_id, affiliation, fileType } = req.body;
        const file = req.file;

        // Validate required fields
        if (!researcher_id) {
            return res.status(400).json({ error: 'researcher_id is required' });
        }

        if (!affiliation || !['LiU', 'UNAV'].includes(affiliation)) {
            return res.status(400).json({ error: 'affiliation must be LiU or UNAV' });
        }

        if (!fileType || !['SOP', 'DATA'].includes(fileType)) {
            return res.status(400).json({ error: 'fileType must be SOP or DATA' });
        }

        if (!file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        // Verify researcher exists in allowlist
        const allowlistCheck = await pool.query(
            'SELECT researcher_id, name FROM di_allowlist WHERE researcher_id = $1 AND active = true',
            [researcher_id]
        );

        if (allowlistCheck.rows.length === 0) {
            return res.status(403).json({ error: 'Researcher not found or inactive' });
        }

        // Record submission in database
        const submissionResult = await pool.query(
            `INSERT INTO di_submissions (researcher_id, affiliation, file_type, original_filename)
             VALUES ($1, $2, $3, $4)
             RETURNING submission_id`,
            [researcher_id, affiliation, fileType, file.originalname]
        );

        const submissionId = submissionResult.rows[0].submission_id;

        // Forward to n8n webhook as multipart form data
        const webhookUrl = process.env.N8N_DI_WEBHOOK_URL;

        if (webhookUrl) {
            const formData = new FormData();
            formData.append('researcher_id', researcher_id);
            formData.append('affiliation', affiliation);
            formData.append('fileType', fileType);
            formData.append('original_filename', file.originalname);
            formData.append('submission_id', submissionId);
            formData.append('file', file.buffer, {
                filename: file.originalname,
                contentType: file.mimetype
            });

            try {
                const webhookResponse = await fetch(webhookUrl, {
                    method: 'POST',
                    body: formData,
                    headers: formData.getHeaders()
                });

                if (!webhookResponse.ok) {
                    console.error('Webhook error:', webhookResponse.status);
                }
            } catch (webhookErr) {
                console.error('Webhook call failed:', webhookErr.message);
            }
        }

        res.json({
            success: true,
            submission_id: submissionId,
            researcher_id: researcher_id,
            affiliation: affiliation,
            fileType: fileType,
            original_filename: file.originalname,
            message: 'File uploaded successfully'
        });

    } catch (err) {
        console.error('External upload error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/researchers
// Get list of researchers (for n8n to validate)
app.get('/api/di/researchers', async (req, res) => {
    try {
        const apiKey = req.headers['x-api-key'];
        if (!apiKey || apiKey !== process.env.API_SECRET_KEY) {
            return res.status(401).json({ error: 'Invalid or missing API key' });
        }

        const result = await pool.query(
            'SELECT researcher_id, name, institution_email, affiliation FROM di_allowlist WHERE active = true ORDER BY affiliation, name'
        );

        res.json({
            success: true,
            count: result.rows.length,
            researchers: result.rows
        });

    } catch (err) {
        console.error('Get researchers error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/submissions
// Get submissions list (for n8n to check status)
app.get('/api/di/submissions', async (req, res) => {
    try {
        const apiKey = req.headers['x-api-key'];
        if (!apiKey || apiKey !== process.env.API_SECRET_KEY) {
            return res.status(401).json({ error: 'Invalid or missing API key' });
        }

        const { researcher_id, status, limit } = req.query;

        let query = 'SELECT * FROM di_submissions WHERE 1=1';
        const params = [];

        if (researcher_id) {
            params.push(researcher_id);
            query += ` AND researcher_id = $${params.length}`;
        }

        if (status) {
            params.push(status);
            query += ` AND status = $${params.length}`;
        }

        query += ' ORDER BY created_at DESC';

        if (limit) {
            params.push(parseInt(limit));
            query += ` LIMIT $${params.length}`;
        }

        const result = await pool.query(query, params);

        res.json({
            success: true,
            count: result.rows.length,
            submissions: result.rows
        });

    } catch (err) {
        console.error('Get submissions error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// PATCH /api/di/submissions/:id
// Update submission status (for n8n to update after processing)
app.patch('/api/di/submissions/:id', async (req, res) => {
    try {
        const apiKey = req.headers['x-api-key'];
        if (!apiKey || apiKey !== process.env.API_SECRET_KEY) {
            return res.status(401).json({ error: 'Invalid or missing API key' });
        }

        const { id } = req.params;
        const { status } = req.body;

        if (!status || !['PENDING', 'APPROVED', 'REVISION_NEEDED'].includes(status)) {
            return res.status(400).json({ error: 'status must be PENDING, APPROVED, or REVISION_NEEDED' });
        }

        const result = await pool.query(
            'UPDATE di_submissions SET status = $1 WHERE submission_id = $2 RETURNING *',
            [status, id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Submission not found' });
        }

        res.json({
            success: true,
            submission: result.rows[0]
        });

    } catch (err) {
        console.error('Update submission error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/submissions/:id
// Get single submission by ID
app.get('/api/di/submissions/:id', async (req, res) => {
    try {
        const apiKey = req.headers['x-api-key'];
        if (!apiKey || apiKey !== process.env.API_SECRET_KEY) {
            return res.status(401).json({ error: 'Invalid or missing API key' });
        }

        const { id } = req.params;

        const result = await pool.query(
            'SELECT * FROM di_submissions WHERE submission_id = $1',
            [id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Submission not found' });
        }

        res.json({
            success: true,
            submission: result.rows[0]
        });

    } catch (err) {
        console.error('Get submission error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/extract-text
// Extract text from a submission (placeholder for PDF/document parsing)
app.post('/api/di/extract-text', async (req, res) => {
    try {
        const apiKey = req.headers['x-api-key'];
        if (!apiKey || apiKey !== process.env.API_SECRET_KEY) {
            return res.status(401).json({ error: 'Invalid or missing API key' });
        }

        const { submission_id } = req.body;

        if (!submission_id) {
            return res.status(400).json({ error: 'submission_id is required' });
        }

        // Get submission
        const result = await pool.query(
            'SELECT * FROM di_submissions WHERE submission_id = $1',
            [submission_id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Submission not found' });
        }

        const submission = result.rows[0];

        // Generate SHA256 hash placeholder (in production, compute from actual file)
        const crypto = require('crypto');
        const sha256 = crypto.createHash('sha256')
            .update(submission_id + submission.original_filename)
            .digest('hex');

        // Placeholder text extraction (in production, use PDF parsing library)
        const extracted_text = `Document: ${submission.original_filename}\n` +
            `Type: ${submission.file_type}\n` +
            `Researcher: ${submission.researcher_id}\n` +
            `Affiliation: ${submission.affiliation}\n` +
            `Submitted: ${submission.created_at}\n\n` +
            `[Document content would be extracted here using PDF parsing library like pdf-parse]\n` +
            `[For GLP compliance review, the AI will analyze structure, completeness, and data integrity]`;

        res.json({
            success: true,
            submission_id: submission_id,
            original_filename: submission.original_filename,
            sha256: sha256,
            extracted_text: extracted_text
        });

    } catch (err) {
        console.error('Extract text error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/sign
// Sign an approved submission
app.post('/api/di/sign', async (req, res) => {
    try {
        const apiKey = req.headers['x-api-key'];
        if (!apiKey || apiKey !== process.env.API_SECRET_KEY) {
            return res.status(401).json({ error: 'Invalid or missing API key' });
        }

        const { submission_id, token } = req.body;

        if (!submission_id) {
            return res.status(400).json({ error: 'submission_id is required' });
        }

        // Validate token
        const crypto = require('crypto');
        const expectedToken = crypto.createHmac('sha256', process.env.API_SECRET_KEY)
            .update(submission_id)
            .digest('hex')
            .substring(0, 32);

        if (token !== expectedToken) {
            return res.status(403).json({ error: 'Invalid token' });
        }

        // Get submission
        const result = await pool.query(
            'SELECT * FROM di_submissions WHERE submission_id = $1',
            [submission_id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Submission not found' });
        }

        const submission = result.rows[0];

        // Generate signed file URL (placeholder)
        // In production, this would create a digitally signed PDF and upload to storage
        const signedAt = new Date().toISOString();
        const signedFileUrl = `https://natlab-glp-production.up.railway.app/api/di/download/${submission_id}?signed=true&t=${Date.now()}`;

        // Update submission with signed status
        await pool.query(
            `UPDATE di_submissions SET
                status = 'APPROVED',
                signed_at = $1
             WHERE submission_id = $2`,
            [signedAt, submission_id]
        );

        res.json({
            success: true,
            submission_id: submission_id,
            signed_at: signedAt,
            signed_file_url: signedFileUrl,
            original_filename: submission.original_filename,
            message: 'Document signed successfully'
        });

    } catch (err) {
        console.error('Sign error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/download/:id
// Download a submission file (placeholder)
app.get('/api/di/download/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { signed } = req.query;

        // Get submission
        const result = await pool.query(
            'SELECT * FROM di_submissions WHERE submission_id = $1',
            [id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Submission not found' });
        }

        const submission = result.rows[0];

        // In production, this would retrieve the actual file from storage
        // For now, return a placeholder response
        res.json({
            message: 'File download endpoint',
            submission_id: id,
            filename: submission.original_filename,
            signed: signed === 'true',
            note: 'In production, this would stream the actual file'
        });

    } catch (err) {
        console.error('Download error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/approve/:id
// Browser-based approval via email link (validates token from query string)
app.get('/api/di/approve/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { token } = req.query;

        if (!token) {
            return res.status(400).send(renderHtmlPage('Error', 'Missing token parameter', 'error'));
        }

        // Validate token (base64 method matching n8n workflow)
        const expectedToken = Buffer.from(id + '_glp_2024_sec').toString('base64').replace(/[^a-zA-Z0-9]/g, '').substring(0, 32);

        if (token !== expectedToken) {
            return res.status(403).send(renderHtmlPage('Invalid Token', 'The approval link is invalid or expired.', 'error'));
        }

        // Get submission
        const result = await pool.query(
            'SELECT * FROM di_submissions WHERE submission_id = $1',
            [id]
        );

        if (result.rows.length === 0) {
            return res.status(404).send(renderHtmlPage('Not Found', 'Submission not found.', 'error'));
        }

        const submission = result.rows[0];

        // Update submission with approved status
        const signedAt = new Date().toISOString();
        await pool.query(
            `UPDATE di_submissions SET status = 'APPROVED', signed_at = $1 WHERE submission_id = $2`,
            [signedAt, id]
        );

        res.send(renderHtmlPage(
            'Document Approved',
            `<p>Submission <strong>${id}</strong> has been approved and signed.</p>
             <p>File: ${submission.original_filename}</p>
             <p>Signed at: ${signedAt}</p>
             <p><a href="/api/di/download/${id}?signed=true" style="color:#007bff;">Download Signed Document</a></p>`,
            'success'
        ));

    } catch (err) {
        console.error('Approve error:', err);
        res.status(500).send(renderHtmlPage('Error', 'Server error occurred.', 'error'));
    }
});

// GET /api/di/revise/:id
// Browser-based revision request page
app.get('/api/di/revise/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { token } = req.query;

        if (!token) {
            return res.status(400).send(renderHtmlPage('Error', 'Missing token parameter', 'error'));
        }

        // Validate token
        const expectedToken = Buffer.from(id + '_glp_2024_sec').toString('base64').replace(/[^a-zA-Z0-9]/g, '').substring(0, 32);

        if (token !== expectedToken) {
            return res.status(403).send(renderHtmlPage('Invalid Token', 'The revision link is invalid or expired.', 'error'));
        }

        // Show revision form
        res.send(`<!DOCTYPE html>
<html>
<head><title>Request Revision</title></head>
<body style="font-family:Arial;background:linear-gradient(135deg,#1a365d,#2d5a87);min-height:100vh;display:flex;justify-content:center;align-items:center;margin:0;">
<div style="background:white;padding:40px;border-radius:10px;max-width:500px;width:90%;">
<h1 style="color:#1a365d;">Request Revision</h1>
<p>Submission ID: <strong>${id}</strong></p>
<form method="POST" action="/api/di/revise/${id}?token=${token}">
<label style="display:block;margin-bottom:8px;font-weight:bold;">Revision Comments:</label>
<textarea name="comments" required style="width:100%;height:150px;padding:10px;border:2px solid #ddd;border-radius:5px;box-sizing:border-box;" placeholder="Enter your comments for the researcher..."></textarea>
<button type="submit" style="width:100%;padding:15px;background:#dc3545;color:white;border:none;border-radius:5px;cursor:pointer;margin-top:15px;font-size:16px;">Submit Revision Request</button>
</form>
</div>
</body>
</html>`);

    } catch (err) {
        console.error('Revise page error:', err);
        res.status(500).send(renderHtmlPage('Error', 'Server error occurred.', 'error'));
    }
});

// POST /api/di/revise/:id
// Process revision request
app.post('/api/di/revise/:id', async (req, res) => {
    try {
        const { id } = req.params;
        const { token } = req.query;
        const { comments } = req.body;

        if (!token) {
            return res.status(400).send(renderHtmlPage('Error', 'Missing token parameter', 'error'));
        }

        // Validate token
        const expectedToken = Buffer.from(id + '_glp_2024_sec').toString('base64').replace(/[^a-zA-Z0-9]/g, '').substring(0, 32);

        if (token !== expectedToken) {
            return res.status(403).send(renderHtmlPage('Invalid Token', 'The revision link is invalid or expired.', 'error'));
        }

        // Update submission status
        await pool.query(
            `UPDATE di_submissions SET status = 'REVISION_NEEDED' WHERE submission_id = $1`,
            [id]
        );

        res.send(renderHtmlPage(
            'Revision Requested',
            `<p>Submission <strong>${id}</strong> has been marked for revision.</p>
             <p>The researcher will be notified with your comments.</p>
             ${comments ? `<p><strong>Your comments:</strong> ${comments}</p>` : ''}`,
            'success'
        ));

    } catch (err) {
        console.error('Revise submit error:', err);
        res.status(500).send(renderHtmlPage('Error', 'Server error occurred.', 'error'));
    }
});

// Helper function to render HTML pages
function renderHtmlPage(title, content, type = 'info') {
    const colors = {
        success: { bg: '#d4edda', icon: '&#10003;', iconColor: '#28a745' },
        error: { bg: '#f8d7da', icon: '&#10007;', iconColor: '#dc3545' },
        info: { bg: '#e7f1ff', icon: '&#8505;', iconColor: '#0066cc' }
    };
    const c = colors[type] || colors.info;

    return `<!DOCTYPE html>
<html>
<head><title>${title} - NATLAB GLP</title></head>
<body style="font-family:Arial;display:flex;justify-content:center;align-items:center;height:100vh;background:#f0f0f0;margin:0;">
<div style="background:white;padding:40px;border-radius:10px;text-align:center;max-width:500px;box-shadow:0 4px 20px rgba(0,0,0,0.1);">
<div style="color:${c.iconColor};font-size:48px;margin-bottom:20px;">${c.icon}</div>
<h1 style="color:#1a365d;">${title}</h1>
<div style="text-align:left;margin-top:20px;">${content}</div>
<p style="margin-top:30px;"><a href="/di/access.html" style="color:#007bff;">Return to Portal</a></p>
</div>
</body>
</html>`;
}

// =====================================================
// PI-SPECIFIC ENDPOINTS
// =====================================================

// GET /api/di/members
// Get all lab members (PI only)
app.get('/api/di/members', requirePI, async (req, res) => {
    try {
        // Check if role column exists using the helper function
        const hasRoleColumn = await checkRoleColumn();
        console.log('Members endpoint - hasRoleColumn:', hasRoleColumn);

        let result;
        if (hasRoleColumn) {
            result = await pool.query(
                `SELECT researcher_id, name, institution_email, affiliation,
                        COALESCE(role, 'researcher') as role, active, created_at
                 FROM di_allowlist
                 WHERE active = true
                 ORDER BY role DESC, name ASC`
            );
        } else {
            // Role column doesn't exist yet - return all as researchers
            result = await pool.query(
                `SELECT researcher_id, name, institution_email, affiliation,
                        'researcher' as role, active, created_at
                 FROM di_allowlist
                 WHERE active = true
                 ORDER BY name ASC`
            );
        }

        console.log('Members endpoint - found', result.rows.length, 'members');

        res.json({
            success: true,
            count: result.rows.length,
            members: result.rows
        });

    } catch (err) {
        console.error('Get members error:', err);
        console.error('Error details:', err.message);
        res.status(500).json({ error: 'Server error: ' + err.message });
    }
});

// POST /api/di/members
// Add a new lab member (PI only)
app.post('/api/di/members', requirePI, async (req, res) => {
    try {
        const { name, researcher_id, institution_email, affiliation, role } = req.body;

        // Validate required fields
        if (!name || !researcher_id || !institution_email || !affiliation) {
            return res.status(400).json({ error: 'All fields are required' });
        }

        if (!['LiU', 'UNAV'].includes(affiliation)) {
            return res.status(400).json({ error: 'Affiliation must be LiU or UNAV' });
        }

        const memberRole = role || 'researcher';
        if (!['researcher', 'pi'].includes(memberRole)) {
            return res.status(400).json({ error: 'Role must be researcher or pi' });
        }

        const emailLower = institution_email.toLowerCase().trim();

        // Check if already exists
        const existing = await pool.query(
            'SELECT researcher_id FROM di_allowlist WHERE researcher_id = $1 OR LOWER(institution_email) = $2',
            [researcher_id, emailLower]
        );

        if (existing.rows.length > 0) {
            return res.status(409).json({ error: 'Member with this ID or email already exists' });
        }

        // Insert new member (handle missing role column)
        const hasRole = await checkRoleColumn();
        if (hasRole) {
            await pool.query(
                `INSERT INTO di_allowlist (researcher_id, name, institution_email, affiliation, role, active, created_at)
                 VALUES ($1, $2, $3, $4, $5, true, CURRENT_TIMESTAMP)`,
                [researcher_id, name, emailLower, affiliation, memberRole]
            );
        } else {
            await pool.query(
                `INSERT INTO di_allowlist (researcher_id, name, institution_email, affiliation, active, created_at)
                 VALUES ($1, $2, $3, $4, true, CURRENT_TIMESTAMP)`,
                [researcher_id, name, emailLower, affiliation]
            );
        }

        res.json({
            success: true,
            message: 'Member added successfully',
            member: { researcher_id, name, institution_email: emailLower, affiliation, role: memberRole }
        });

    } catch (err) {
        console.error('Add member error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// DELETE /api/di/members/:id
// Remove (deactivate) a lab member (PI only)
app.delete('/api/di/members/:id', requirePI, async (req, res) => {
    try {
        const { id } = req.params;

        // Check if member exists (handle missing role column)
        const hasRole = await checkRoleColumn();
        const memberQuery = hasRole
            ? 'SELECT researcher_id, COALESCE(role, \'researcher\') as role FROM di_allowlist WHERE researcher_id = $1'
            : 'SELECT researcher_id, \'researcher\' as role FROM di_allowlist WHERE researcher_id = $1';

        const member = await pool.query(memberQuery, [id]);

        if (member.rows.length === 0) {
            return res.status(404).json({ error: 'Member not found' });
        }

        // Prevent PI from removing themselves
        if (member.rows[0].researcher_id === req.session.user.researcher_id) {
            return res.status(400).json({ error: 'Cannot remove yourself' });
        }

        // Deactivate member (soft delete)
        await pool.query(
            'UPDATE di_allowlist SET active = false WHERE researcher_id = $1',
            [id]
        );

        res.json({
            success: true,
            message: 'Member removed successfully'
        });

    } catch (err) {
        console.error('Remove member error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/directory
// Get directory tree structure of all submissions (PI only)
app.get('/api/di/directory', requirePI, async (req, res) => {
    try {
        // Get all members
        const membersResult = await pool.query(
            `SELECT researcher_id, name, affiliation FROM di_allowlist WHERE active = true ORDER BY name`
        );

        // Get all submissions
        const submissionsResult = await pool.query(
            `SELECT s.submission_id, s.researcher_id, s.affiliation, s.file_type,
                    s.original_filename, s.status, s.created_at,
                    EXTRACT(YEAR FROM s.created_at) as year
             FROM di_submissions s
             ORDER BY s.created_at DESC`
        );

        // Build tree structure: General Lab / Year / Researcher Name
        const tree = {
            name: 'General Lab',
            type: 'folder',
            children: []
        };

        // Group submissions by year, then by researcher
        const yearMap = {};

        for (const sub of submissionsResult.rows) {
            const year = sub.year || new Date(sub.created_at).getFullYear();
            const researcherName = membersResult.rows.find(m => m.researcher_id === sub.researcher_id)?.name || sub.researcher_id;

            if (!yearMap[year]) {
                yearMap[year] = { name: String(year), type: 'folder', children: [], researchers: {} };
            }

            if (!yearMap[year].researchers[sub.researcher_id]) {
                yearMap[year].researchers[sub.researcher_id] = {
                    name: researcherName,
                    type: 'folder',
                    children: [],
                    count: 0
                };
            }

            yearMap[year].researchers[sub.researcher_id].children.push({
                name: sub.original_filename,
                type: 'file',
                id: sub.submission_id,
                status: sub.status,
                fileType: sub.file_type,
                date: sub.created_at
            });
            yearMap[year].researchers[sub.researcher_id].count++;
        }

        // Convert map to array and sort
        const years = Object.keys(yearMap).sort((a, b) => b - a);
        for (const year of years) {
            const yearNode = yearMap[year];
            yearNode.children = Object.values(yearNode.researchers);
            yearNode.count = `${yearNode.children.length} researchers`;
            delete yearNode.researchers;
            tree.children.push(yearNode);
        }

        // Add empty folders for members without submissions
        const currentYear = new Date().getFullYear();
        if (!yearMap[currentYear]) {
            tree.children.unshift({
                name: String(currentYear),
                type: 'folder',
                children: membersResult.rows.map(m => ({
                    name: m.name,
                    type: 'folder',
                    children: [],
                    count: 0
                })),
                count: `${membersResult.rows.length} researchers`
            });
        }

        res.json({
            success: true,
            tree: tree
        });

    } catch (err) {
        console.error('Directory error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/pi-upload
// PI uploads file on behalf of a researcher
app.post('/api/di/pi-upload', requirePI, upload.single('file'), async (req, res) => {
    try {
        const { researcher_id, fileType } = req.body;
        const file = req.file;

        if (!researcher_id) {
            return res.status(400).json({ error: 'researcher_id is required' });
        }

        if (!fileType || !['SOP', 'DATA'].includes(fileType)) {
            return res.status(400).json({ error: 'fileType must be SOP or DATA' });
        }

        if (!file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        // Verify researcher exists
        const researcherResult = await pool.query(
            'SELECT researcher_id, affiliation FROM di_allowlist WHERE researcher_id = $1 AND active = true',
            [researcher_id]
        );

        if (researcherResult.rows.length === 0) {
            return res.status(404).json({ error: 'Researcher not found' });
        }

        const researcher = researcherResult.rows[0];

        // Record submission
        const submissionResult = await pool.query(
            `INSERT INTO di_submissions (researcher_id, affiliation, file_type, original_filename)
             VALUES ($1, $2, $3, $4)
             RETURNING submission_id`,
            [researcher_id, researcher.affiliation, fileType, file.originalname]
        );

        const submissionId = submissionResult.rows[0].submission_id;

        // Forward to n8n webhook if configured
        const webhookUrl = process.env.N8N_DI_WEBHOOK_URL;
        if (webhookUrl) {
            const formData = new FormData();
            formData.append('researcher_id', researcher_id);
            formData.append('affiliation', researcher.affiliation);
            formData.append('fileType', fileType);
            formData.append('original_filename', file.originalname);
            formData.append('submission_id', submissionId);
            formData.append('uploaded_by_pi', req.session.user.researcher_id);
            formData.append('file', file.buffer, {
                filename: file.originalname,
                contentType: file.mimetype
            });

            try {
                await fetch(webhookUrl, {
                    method: 'POST',
                    body: formData,
                    headers: formData.getHeaders()
                });
            } catch (webhookErr) {
                console.error('Webhook error:', webhookErr.message);
            }
        }

        res.json({
            success: true,
            submission_id: submissionId,
            researcher_id: researcher_id,
            message: 'File uploaded successfully'
        });

    } catch (err) {
        console.error('PI upload error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// DELETE /api/di/submissions/:id
// Delete a submission (PI only)
app.delete('/api/di/submissions/:id', requirePI, async (req, res) => {
    try {
        const { id } = req.params;

        // Check if submission exists
        const result = await pool.query(
            'SELECT submission_id, original_filename FROM di_submissions WHERE submission_id = $1',
            [id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Submission not found' });
        }

        const submission = result.rows[0];

        // Delete the submission
        await pool.query('DELETE FROM di_submissions WHERE submission_id = $1', [id]);

        res.json({
            success: true,
            message: 'Submission deleted successfully',
            deleted: {
                submission_id: id,
                filename: submission.original_filename
            }
        });

    } catch (err) {
        console.error('Delete submission error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/logout
// Logout user
app.post('/api/di/logout', (req, res) => {
    req.session.destroy((err) => {
        if (err) {
            console.error('Logout error:', err);
            return res.status(500).json({ error: 'Logout failed' });
        }
        res.json({ success: true, message: 'Logged out' });
    });
});

// Start server
app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
    console.log(`Access the portal at http://localhost:${PORT}/di/access.html`);
});
