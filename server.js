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

// Detect production environment
const isProduction = process.env.NODE_ENV === 'production' || process.env.RAILWAY_ENVIRONMENT === 'production';

// Trust proxy in production (Railway uses reverse proxy)
if (isProduction) {
    app.set('trust proxy', 1);
}

// Session configuration (in memory for V1)
app.use(session({
    secret: process.env.SESSION_SECRET || 'fallback_secret_change_me',
    resave: false,
    saveUninitialized: false,
    cookie: {
        secure: isProduction,
        httpOnly: true,
        maxAge: 24 * 60 * 60 * 1000, // 24 hours
        sameSite: isProduction ? 'none' : 'lax'
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

// AUTH MIDDLEWARE
function requireAuth(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    next();
}

// API ENDPOINTS

// POST /api/di/access-check
// Check if email is in allowlist and whether user exists
app.post('/api/di/access-check', async (req, res) => {
    try {
        const { institution_email } = req.body;

        if (!institution_email) {
            return res.status(400).json({ error: 'Email is required' });
        }

        const emailLower = institution_email.toLowerCase().trim();

        // Check allowlist
        const allowlistResult = await pool.query(
            'SELECT researcher_id, name, affiliation, active FROM di_allowlist WHERE LOWER(institution_email) = $1',
            [emailLower]
        );

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
            affiliation: allowlistEntry.affiliation
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

        // Verify in allowlist
        const allowlistResult = await pool.query(
            'SELECT researcher_id, name, affiliation, active FROM di_allowlist WHERE LOWER(institution_email) = $1',
            [emailLower]
        );

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

        // Set session
        req.session.user = {
            institution_email: emailLower,
            researcher_id: allowlistEntry.researcher_id,
            name: allowlistEntry.name,
            affiliation: allowlistEntry.affiliation
        };

        res.json({
            success: true,
            message: 'Registration successful',
            user: req.session.user
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

        // Get user with allowlist info
        const result = await pool.query(
            `SELECT u.institution_email, u.password_hash, u.researcher_id,
                    a.name, a.affiliation, a.active
             FROM di_users u
             JOIN di_allowlist a ON u.researcher_id = a.researcher_id
             WHERE LOWER(u.institution_email) = $1`,
            [emailLower]
        );

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

        // Set session
        req.session.user = {
            institution_email: user.institution_email,
            researcher_id: user.researcher_id,
            name: user.name,
            affiliation: user.affiliation
        };

        res.json({
            success: true,
            message: 'Login successful',
            user: req.session.user
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
        institution_email: req.session.user.institution_email
    });
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
