require('dotenv').config();

const express = require('express');
const multer = require('multer');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
const session = require('express-session');
const path = require('path');
const FormData = require('form-data');
const fetch = require('node-fetch');
const { google } = require('googleapis');
const { PDFDocument, rgb, StandardFonts } = require('pdf-lib');
const { Readable } = require('stream');

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
    limits: { fileSize: 10 * 1024 * 1024 }, // 10MB limit for PDFs
    fileFilter: (req, file, cb) => {
        if (file.mimetype === 'application/pdf') {
            cb(null, true);
        } else {
            cb(new Error('Only PDF files are accepted'), false);
        }
    }
});

// Google Drive Configuration
const GOOGLE_DRIVE_ROOT_FOLDER = 'NATLAB-GLP';
let driveClient = null;
let driveEnabled = false;
let driveInitError = null;

// Validate Drive config at startup
function validateDriveConfig() {
    const keyEnv = process.env.GOOGLE_SERVICE_ACCOUNT_KEY;
    console.log('[DRIVE] Validating configuration...');
    console.log('[DRIVE] GOOGLE_SERVICE_ACCOUNT_KEY present:', !!keyEnv);
    console.log('[DRIVE] GOOGLE_SERVICE_ACCOUNT_KEY length:', keyEnv ? keyEnv.length : 0);

    if (!keyEnv) {
        console.error('[DRIVE] ERROR: GOOGLE_SERVICE_ACCOUNT_KEY env var is missing');
        return { valid: false, error: 'GOOGLE_SERVICE_ACCOUNT_KEY not set' };
    }

    try {
        const creds = JSON.parse(keyEnv);
        const hasRequiredFields = creds.client_email && creds.private_key && creds.project_id;
        console.log('[DRIVE] Credentials parsed successfully');
        console.log('[DRIVE] Has client_email:', !!creds.client_email);
        console.log('[DRIVE] Has private_key:', !!creds.private_key);
        console.log('[DRIVE] Has project_id:', !!creds.project_id);
        console.log('[DRIVE] Service account:', creds.client_email || 'MISSING');

        if (!hasRequiredFields) {
            return { valid: false, error: 'Missing required fields in service account JSON' };
        }
        return { valid: true, credentials: creds };
    } catch (e) {
        console.error('[DRIVE] ERROR: Failed to parse GOOGLE_SERVICE_ACCOUNT_KEY as JSON:', e.message);
        return { valid: false, error: 'Invalid JSON in GOOGLE_SERVICE_ACCOUNT_KEY: ' + e.message };
    }
}

function initializeDriveClient() {
    const validation = validateDriveConfig();
    if (!validation.valid) {
        driveInitError = validation.error;
        driveEnabled = false;
        console.error('[DRIVE] Initialization FAILED:', driveInitError);
        return null;
    }

    try {
        const auth = new google.auth.GoogleAuth({
            credentials: validation.credentials,
            scopes: ['https://www.googleapis.com/auth/drive.file']
        });
        driveClient = google.drive({ version: 'v3', auth });
        driveEnabled = true;
        console.log('[DRIVE] Client initialized successfully');
        return driveClient;
    } catch (e) {
        driveInitError = e.message;
        driveEnabled = false;
        console.error('[DRIVE] Initialization FAILED:', e.message);
        return null;
    }
}

function getGoogleDriveClient() {
    if (driveClient) return driveClient;
    return initializeDriveClient();
}

function isDriveEnabled() {
    return driveEnabled && driveClient !== null;
}

// Google Drive Helper Functions
async function findOrCreateFolder(drive, name, parentId = null) {
    const query = parentId
        ? `name='${name}' and mimeType='application/vnd.google-apps.folder' and '${parentId}' in parents and trashed=false`
        : `name='${name}' and mimeType='application/vnd.google-apps.folder' and trashed=false`;

    const res = await drive.files.list({ q: query, fields: 'files(id, name)' });

    if (res.data.files.length > 0) {
        return res.data.files[0].id;
    }

    const folderMetadata = {
        name,
        mimeType: 'application/vnd.google-apps.folder',
        ...(parentId && { parents: [parentId] })
    };

    const folder = await drive.files.create({
        requestBody: folderMetadata,
        fields: 'id'
    });

    return folder.data.id;
}

async function getSubmittedFolderId(drive, year, researcherId) {
    const rootId = await findOrCreateFolder(drive, GOOGLE_DRIVE_ROOT_FOLDER);
    const yearId = await findOrCreateFolder(drive, String(year), rootId);
    const researcherFolderId = await findOrCreateFolder(drive, researcherId, yearId);
    const submittedId = await findOrCreateFolder(drive, 'Submitted', researcherFolderId);
    return submittedId;
}

async function getApprovedFolderId(drive, year, researcherId) {
    const rootId = await findOrCreateFolder(drive, GOOGLE_DRIVE_ROOT_FOLDER);
    const yearId = await findOrCreateFolder(drive, String(year), rootId);
    const researcherFolderId = await findOrCreateFolder(drive, researcherId, yearId);
    const approvedId = await findOrCreateFolder(drive, 'Approved', researcherFolderId);
    return approvedId;
}

async function uploadFileToDrive(drive, buffer, filename, mimeType, folderId) {
    const fileMetadata = {
        name: filename,
        parents: [folderId]
    };

    const media = {
        mimeType,
        body: Readable.from(buffer)
    };

    const file = await drive.files.create({
        requestBody: fileMetadata,
        media,
        fields: 'id, webViewLink'
    });

    // Set public read permission
    await drive.permissions.create({
        fileId: file.data.id,
        requestBody: {
            role: 'reader',
            type: 'anyone'
        }
    });

    return file.data.id;
}

async function deleteFileFromDrive(drive, fileId) {
    try {
        await drive.files.delete({ fileId });
        return true;
    } catch (err) {
        console.error('Drive delete error:', err.message);
        return false;
    }
}

async function downloadFileFromDrive(drive, fileId) {
    const res = await drive.files.get(
        { fileId, alt: 'media' },
        { responseType: 'arraybuffer' }
    );
    return Buffer.from(res.data);
}

async function createStampedPdf(pdfBuffer, signerName, timestamp) {
    const pdfDoc = await PDFDocument.load(pdfBuffer);
    const pages = pdfDoc.getPages();
    const firstPage = pages[0];
    const font = await pdfDoc.embedFont(StandardFonts.Helvetica);

    const stampText = `Approved by PI (${signerName}) - ${timestamp}`;
    const { width } = firstPage.getSize();

    // Add stamp at bottom of first page
    firstPage.drawText(stampText, {
        x: 50,
        y: 30,
        size: 10,
        font,
        color: rgb(0.2, 0.4, 0.2)
    });

    // Add stamp border
    firstPage.drawRectangle({
        x: 45,
        y: 25,
        width: font.widthOfTextAtSize(stampText, 10) + 10,
        height: 18,
        borderColor: rgb(0.2, 0.4, 0.2),
        borderWidth: 1
    });

    return await pdfDoc.save();
}

function getDriveViewUrl(fileId) {
    return `https://drive.google.com/file/d/${fileId}/view`;
}

function getDriveDownloadUrl(fileId) {
    return `https://drive.google.com/uc?export=download&id=${fileId}`;
}

// Serve static files from public folder under /di
app.use('/di', express.static(path.join(__dirname, 'public')));

// Initialize Drive at startup
console.log('[STARTUP] Initializing Google Drive...');
initializeDriveClient();
console.log('[STARTUP] Drive enabled:', driveEnabled);
if (driveInitError) {
    console.error('[STARTUP] Drive init error:', driveInitError);
}

// Health check endpoint
app.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// Drive debug endpoint
app.get('/api/di/debug-drive', async (req, res) => {
    const info = {
        driveEnabled,
        driveInitError,
        envVarPresent: !!process.env.GOOGLE_SERVICE_ACCOUNT_KEY,
        envVarLength: process.env.GOOGLE_SERVICE_ACCOUNT_KEY?.length || 0,
        timestamp: new Date().toISOString()
    };

    // Try a simple Drive operation if enabled
    if (driveEnabled && driveClient) {
        try {
            const aboutRes = await driveClient.about.get({ fields: 'user' });
            info.driveUser = aboutRes.data.user?.emailAddress || 'unknown';
            info.driveTestSuccess = true;
        } catch (e) {
            info.driveTestSuccess = false;
            info.driveTestError = e.message;
        }
    }

    res.json(info);
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
                    verification_code, ai_review_score, ai_review_decision, drive_file_id,
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
                signedAt: file.signed_at,
                verificationCode: file.verification_code,
                aiScore: file.ai_review_score,
                aiDecision: file.ai_review_decision,
                driveFileId: file.drive_file_id,
                viewUrl: file.drive_file_id ? getDriveViewUrl(file.drive_file_id) : null,
                downloadUrl: file.drive_file_id ? getDriveDownloadUrl(file.drive_file_id) : null
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
// Upload PDF file to Google Drive and forward to n8n webhook
app.post('/api/di/upload', requireAuth, upload.single('file'), async (req, res) => {
    try {
        const { fileType } = req.body;
        const file = req.file;

        if (!fileType || !['SOP', 'DATA'].includes(fileType)) {
            return res.status(400).json({ error: 'fileType must be SOP or DATA' });
        }

        if (!file) {
            return res.status(400).json({ error: 'No file uploaded. Only PDF files are accepted.' });
        }

        // Additional PDF validation
        if (file.mimetype !== 'application/pdf') {
            return res.status(400).json({ error: 'Only PDF files are accepted' });
        }

        if (file.size > 10 * 1024 * 1024) {
            return res.status(400).json({ error: 'File exceeds 10MB limit' });
        }

        const user = req.session.user;
        const year = new Date().getFullYear();

        console.log(`[UPLOAD] Starting upload for user=${user.researcher_id}, file=${file.originalname}, size=${file.size}`);

        // Check if Drive is enabled
        if (!driveEnabled) {
            console.error('[UPLOAD] ERROR: Drive not enabled. driveInitError:', driveInitError);
            return res.status(503).json({
                error: 'DRIVE_NOT_CONFIGURED',
                message: 'Google Drive is not configured. Contact administrator.',
                driveInitError: driveInitError
            });
        }

        // Upload to Google Drive
        let driveFileId = null;
        try {
            console.log(`[UPLOAD] Getting Drive client...`);
            const drive = getGoogleDriveClient();

            console.log(`[UPLOAD] Creating folder structure: NATLAB-GLP/${year}/${user.researcher_id}/Submitted`);
            const submittedFolderId = await getSubmittedFolderId(drive, year, user.researcher_id);
            console.log(`[UPLOAD] Folder ID: ${submittedFolderId}`);

            console.log(`[UPLOAD] Uploading file to Drive...`);
            driveFileId = await uploadFileToDrive(drive, file.buffer, file.originalname, 'application/pdf', submittedFolderId);
            console.log(`[UPLOAD] SUCCESS: Drive file ID = ${driveFileId}`);
        } catch (driveErr) {
            console.error(`[UPLOAD] DRIVE ERROR:`, driveErr.message);
            console.error(`[UPLOAD] DRIVE ERROR STACK:`, driveErr.stack);
            return res.status(500).json({
                error: 'DRIVE_UPLOAD_FAILED',
                message: 'Failed to upload file to Google Drive: ' + driveErr.message
            });
        }

        // Record submission in database with Drive file ID
        const submissionResult = await pool.query(
            `INSERT INTO di_submissions (researcher_id, affiliation, file_type, original_filename, drive_file_id)
             VALUES ($1, $2, $3, $4, $5)
             RETURNING submission_id`,
            [user.researcher_id, user.affiliation, fileType, file.originalname, driveFileId]
        );

        const submissionId = submissionResult.rows[0].submission_id;
        console.log(`[UPLOAD] Submission recorded: submission_id=${submissionId}, drive_file_id=${driveFileId}`);

        // Forward to n8n webhook
        const webhookUrl = process.env.N8N_DI_WEBHOOK_URL;

        if (webhookUrl) {
            const formData = new FormData();
            formData.append('researcher_id', user.researcher_id);
            formData.append('affiliation', user.affiliation);
            formData.append('fileType', fileType);
            formData.append('original_filename', file.originalname);
            formData.append('submission_id', submissionId);
            formData.append('drive_file_id', driveFileId);
            formData.append('drive_view_url', getDriveViewUrl(driveFileId));
            formData.append('drive_download_url', getDriveDownloadUrl(driveFileId));
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
            drive_file_id: driveFileId,
            view_url: getDriveViewUrl(driveFileId),
            message: 'File uploaded successfully'
        });

    } catch (err) {
        console.error('Upload error:', err);
        if (err.message === 'Only PDF files are accepted') {
            return res.status(400).json({ error: err.message });
        }
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
// Sign an approved submission (API key auth for n8n)
app.post('/api/di/sign', async (req, res) => {
    try {
        const apiKey = req.headers['x-api-key'];
        if (!apiKey || apiKey !== process.env.API_SECRET_KEY) {
            return res.status(401).json({ error: 'Invalid or missing API key' });
        }

        const { submission_id, token, signer_name, signer_email, ai_score, ai_decision, doc_type } = req.body;

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

        // Generate digital signature data
        const crypto = require('crypto');
        const signedAt = new Date().toISOString();

        // Create signature hash (combines submission data + timestamp + signer)
        const signaturePayload = JSON.stringify({
            submission_id,
            original_filename: submission.original_filename,
            researcher_id: submission.researcher_id,
            file_type: submission.file_type,
            signed_at: signedAt,
            signer: signer_name || 'PI',
            ai_score: ai_score || null,
            ai_decision: ai_decision || null,
            doc_type: doc_type || submission.file_type
        });

        const signatureHash = crypto.createHmac('sha256', process.env.API_SECRET_KEY || 'natlab_glp_secret')
            .update(signaturePayload)
            .digest('hex');

        // Create verification code (short version for display)
        const verificationCode = `NATLAB-${submission_id}-${signatureHash.substring(0, 8).toUpperCase()}`;

        // Update submission with signed status and signature data
        await pool.query(
            `UPDATE di_submissions SET
                status = 'APPROVED',
                signed_at = $1,
                signature_hash = $2,
                verification_code = $3,
                signer_name = $4,
                signer_email = $5,
                ai_review_score = $6,
                ai_review_decision = $7
             WHERE submission_id = $8`,
            [signedAt, signatureHash, verificationCode, signer_name || 'Principal Investigator',
             signer_email || 'pi@natlab.liu.se', ai_score || null, ai_decision || null, submission_id]
        );

        const signedFileUrl = `https://natlab-glp-production.up.railway.app/api/di/download/${submission_id}?signed=true`;

        res.json({
            success: true,
            submission_id: submission_id,
            signed_at: signedAt,
            signature_hash: signatureHash,
            verification_code: verificationCode,
            signed_file_url: signedFileUrl,
            original_filename: submission.original_filename,
            signer: signer_name || 'Principal Investigator',
            message: 'Document digitally signed successfully'
        });

    } catch (err) {
        console.error('Sign error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/verify/:code
// Verify a signed document using verification code
app.get('/api/di/verify/:code', async (req, res) => {
    try {
        const { code } = req.params;

        // Find submission by verification code
        const result = await pool.query(
            `SELECT submission_id, original_filename, researcher_id, affiliation,
                    file_type, status, signed_at, signature_hash, verification_code,
                    signer_name, ai_review_score, ai_review_decision, created_at
             FROM di_submissions
             WHERE verification_code = $1`,
            [code]
        );

        if (result.rows.length === 0) {
            return res.send(renderHtmlPage(
                'Verification Failed',
                `<p>No document found with verification code: <strong>${code}</strong></p>
                 <p>Please check the code and try again.</p>`,
                'error'
            ));
        }

        const doc = result.rows[0];

        if (doc.status !== 'APPROVED' || !doc.signed_at) {
            return res.send(renderHtmlPage(
                'Document Not Signed',
                `<p>Document found but has not been signed yet.</p>
                 <p>Status: ${doc.status}</p>`,
                'error'
            ));
        }

        // Document is valid and signed
        res.send(renderHtmlPage(
            'Document Verified',
            `<div style="background:#d4edda;padding:20px;border-radius:8px;margin-bottom:20px;">
                <h3 style="color:#155724;margin:0 0 10px 0;">&#10003; This document is authentic and digitally signed</h3>
            </div>
            <table style="width:100%;border-collapse:collapse;">
                <tr><td style="padding:8px;color:#666;border-bottom:1px solid #eee;">Verification Code:</td>
                    <td style="padding:8px;font-weight:bold;border-bottom:1px solid #eee;">${doc.verification_code}</td></tr>
                <tr><td style="padding:8px;color:#666;border-bottom:1px solid #eee;">Document:</td>
                    <td style="padding:8px;border-bottom:1px solid #eee;">${doc.original_filename}</td></tr>
                <tr><td style="padding:8px;color:#666;border-bottom:1px solid #eee;">Researcher:</td>
                    <td style="padding:8px;border-bottom:1px solid #eee;">${doc.researcher_id}</td></tr>
                <tr><td style="padding:8px;color:#666;border-bottom:1px solid #eee;">Affiliation:</td>
                    <td style="padding:8px;border-bottom:1px solid #eee;">${doc.affiliation}</td></tr>
                <tr><td style="padding:8px;color:#666;border-bottom:1px solid #eee;">Document Type:</td>
                    <td style="padding:8px;border-bottom:1px solid #eee;">${doc.file_type}</td></tr>
                <tr><td style="padding:8px;color:#666;border-bottom:1px solid #eee;">Signed By:</td>
                    <td style="padding:8px;border-bottom:1px solid #eee;">${doc.signer_name || 'Principal Investigator'}</td></tr>
                <tr><td style="padding:8px;color:#666;border-bottom:1px solid #eee;">Signed At:</td>
                    <td style="padding:8px;border-bottom:1px solid #eee;">${new Date(doc.signed_at).toLocaleString()}</td></tr>
                ${doc.ai_review_score ? `<tr><td style="padding:8px;color:#666;border-bottom:1px solid #eee;">AI Review Score:</td>
                    <td style="padding:8px;border-bottom:1px solid #eee;">${doc.ai_review_score}/100</td></tr>` : ''}
                <tr><td style="padding:8px;color:#666;">Signature Hash:</td>
                    <td style="padding:8px;font-family:monospace;font-size:11px;word-break:break-all;">${doc.signature_hash}</td></tr>
            </table>`,
            'success'
        ));

    } catch (err) {
        console.error('Verify error:', err);
        res.status(500).send(renderHtmlPage('Error', 'Server error occurred.', 'error'));
    }
});

// GET /api/di/download/:id
// Redirect to Google Drive file or return appropriate error
app.get('/api/di/download/:id', async (req, res) => {
    const { id } = req.params;
    const { download } = req.query;

    console.log(`[DOWNLOAD] Request for submission_id=${id}, download=${download}`);

    try {
        // Get submission
        const result = await pool.query(
            'SELECT drive_file_id, original_filename, status, signed_pdf_path FROM di_submissions WHERE submission_id = $1',
            [id]
        );

        if (result.rows.length === 0) {
            console.log(`[DOWNLOAD] Submission ${id} not found in database`);
            return res.status(404).json({ error: 'SUBMISSION_NOT_FOUND', message: 'Submission not found' });
        }

        const submission = result.rows[0];
        console.log(`[DOWNLOAD] Found submission: status=${submission.status}, drive_file_id=${submission.drive_file_id || 'NULL'}, signed_pdf_path=${submission.signed_pdf_path || 'NULL'}`);

        // Determine which file ID to use (prefer signed version if available)
        const fileId = submission.signed_pdf_path || submission.drive_file_id;

        if (!fileId) {
            // File not ready - could be upload failed, or revision requested
            console.log(`[DOWNLOAD] No file ID available for submission ${id}`);
            return res.status(409).json({
                error: 'FILE_NOT_READY',
                message: 'File not available. Upload may have failed or file was removed for revision.',
                status: submission.status,
                driveEnabled: driveEnabled
            });
        }

        // Build Drive URLs
        const viewUrl = getDriveViewUrl(fileId);
        const downloadUrl = getDriveDownloadUrl(fileId);

        console.log(`[DOWNLOAD] Redirecting to Drive: fileId=${fileId}`);

        // Redirect to appropriate Google Drive URL
        if (download === 'true') {
            res.redirect(downloadUrl);
        } else {
            res.redirect(viewUrl);
        }

    } catch (err) {
        console.error(`[DOWNLOAD] Error for submission ${id}:`, err);
        res.status(500).json({ error: 'SERVER_ERROR', message: err.message });
    }
});

// GET /api/di/approve/:id
// Browser-based approval via email link (validates token from query string)
// Creates stamped PDF, uploads to Approved folder, deletes from Submitted
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

        if (!submission.drive_file_id) {
            return res.status(400).send(renderHtmlPage('Error', 'No file associated with this submission.', 'error'));
        }

        if (submission.status === 'APPROVED') {
            return res.send(renderHtmlPage('Already Approved', 'This submission has already been approved.', 'info'));
        }

        const signedAt = new Date().toISOString();
        const signerName = 'Frank J. Hernandez';
        const drive = getGoogleDriveClient();

        // Download original PDF from Drive
        const originalPdfBuffer = await downloadFileFromDrive(drive, submission.drive_file_id);

        // Create stamped PDF
        const stampedPdfBuffer = await createStampedPdf(originalPdfBuffer, signerName, signedAt);

        // Get Approved folder
        const year = new Date(submission.created_at).getFullYear();
        const approvedFolderId = await getApprovedFolderId(drive, year, submission.researcher_id);

        // Upload stamped PDF to Approved folder
        const stampedFilename = submission.original_filename.replace('.pdf', '_APPROVED.pdf');
        const newDriveFileId = await uploadFileToDrive(drive, stampedPdfBuffer, stampedFilename, 'application/pdf', approvedFolderId);

        // Delete original from Submitted
        await deleteFileFromDrive(drive, submission.drive_file_id);

        // Generate signature hash
        const crypto = require('crypto');
        const signaturePayload = JSON.stringify({
            submission_id: id,
            original_filename: submission.original_filename,
            signed_at: signedAt,
            signer: signerName
        });
        const signatureHash = crypto.createHmac('sha256', process.env.API_SECRET_KEY || 'natlab_glp_secret')
            .update(signaturePayload).digest('hex');
        const verificationCode = `NATLAB-${id}-${signatureHash.substring(0, 8).toUpperCase()}`;

        // Update DB: point to stamped PDF only
        await pool.query(
            `UPDATE di_submissions SET
                status = 'APPROVED',
                signed_at = $1,
                signer_name = $2,
                drive_file_id = $3,
                signed_pdf_path = $3,
                signature_hash = $4,
                verification_code = $5
             WHERE submission_id = $6`,
            [signedAt, signerName, newDriveFileId, signatureHash, verificationCode, id]
        );

        // Send email to researcher
        const researcherResult = await pool.query(
            'SELECT institution_email FROM di_allowlist WHERE researcher_id = $1',
            [submission.researcher_id]
        );

        if (researcherResult.rows.length > 0) {
            const researcherEmail = researcherResult.rows[0].institution_email;
            // Email would be sent via n8n or nodemailer here
            console.log(`Approval email should be sent to: ${researcherEmail}`);
        }

        res.send(renderHtmlPage(
            'Document Approved',
            `<p>Submission <strong>${id}</strong> has been approved and signed.</p>
             <p>File: ${submission.original_filename}</p>
             <p>Signed at: ${signedAt}</p>
             <p>Verification Code: <strong>${verificationCode}</strong></p>
             <p><a href="${getDriveViewUrl(newDriveFileId)}" target="_blank" style="color:#007bff;">View Signed Document</a></p>
             <p><a href="${getDriveDownloadUrl(newDriveFileId)}" style="color:#28a745;">Download Signed Document</a></p>`,
            'success'
        ));

    } catch (err) {
        console.error('Approve error:', err);
        res.status(500).send(renderHtmlPage('Error', 'Server error occurred: ' + err.message, 'error'));
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
// Process revision request - deletes file from Drive, stores comments
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

        // Get submission to find drive_file_id
        const result = await pool.query(
            'SELECT drive_file_id, researcher_id, original_filename FROM di_submissions WHERE submission_id = $1',
            [id]
        );

        if (result.rows.length === 0) {
            return res.status(404).send(renderHtmlPage('Not Found', 'Submission not found.', 'error'));
        }

        const submission = result.rows[0];

        // Delete file from Google Drive (Submitted folder)
        if (submission.drive_file_id) {
            const drive = getGoogleDriveClient();
            await deleteFileFromDrive(drive, submission.drive_file_id);
        }

        // Update submission status, clear drive_file_id, store comments
        await pool.query(
            `UPDATE di_submissions SET
                status = 'REVISION_NEEDED',
                drive_file_id = NULL,
                revision_comments = $1
             WHERE submission_id = $2`,
            [comments || '', id]
        );

        // Get researcher email and send notification
        const researcherResult = await pool.query(
            'SELECT institution_email FROM di_allowlist WHERE researcher_id = $1',
            [submission.researcher_id]
        );

        if (researcherResult.rows.length > 0) {
            const researcherEmail = researcherResult.rows[0].institution_email;
            console.log(`Revision email should be sent to: ${researcherEmail}`);
            // Email content: Subject: Revision requested | Body: File "X" needs revision. Comments: Y
        }

        res.send(renderHtmlPage(
            'Revision Requested',
            `<p>Submission <strong>${id}</strong> has been marked for revision.</p>
             <p>The file has been removed. The researcher must upload a revised PDF.</p>
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
                    s.original_filename, s.status, s.created_at, s.drive_file_id,
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
                date: sub.created_at,
                driveFileId: sub.drive_file_id,
                viewUrl: sub.drive_file_id ? getDriveViewUrl(sub.drive_file_id) : null,
                downloadUrl: sub.drive_file_id ? getDriveDownloadUrl(sub.drive_file_id) : null
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
app.post('/api/di/pi-upload-old', requirePI, upload.single('file'), async (req, res) => {
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


/* ============================
   Drive failure recorder
============================ */
async function recordDriveFailure(submissionId, err) {
    const msg =
        (err && err.message) ? err.message :
        (typeof err === 'string') ? err :
        JSON.stringify(err);

    try {
        await pool.query(
            `UPDATE di_submissions
             SET drive_error = $1,
                 drive_last_attempt = NOW()
             WHERE submission_id = $2`,
            [msg, submissionId]
        );
    } catch (dbErr) {
        console.error('[DRIVE] Failed to record drive_error in DB:', dbErr.message);
    }
}

/* ============================
   NEW PI Upload (with Drive)
============================ */
app.post('/api/di/pi-upload', requirePI, upload.single('file'), async (req, res) => {
    try {
        const { researcher_id, fileType } = req.body;
        const file = req.file;

        if (!researcher_id) return res.status(400).json({ error: 'researcher_id is required' });
        if (!fileType || !['SOP', 'DATA'].includes(fileType)) return res.status(400).json({ error: 'fileType must be SOP or DATA' });
        if (!file) return res.status(400).json({ error: 'No file uploaded. Only PDF files are accepted.' });

        if (!driveEnabled) {
            return res.status(503).json({
                error: 'DRIVE_NOT_CONFIGURED',
                message: 'Google Drive is not configured. Contact administrator.',
                driveInitError
            });
        }

        const researcherResult = await pool.query(
            'SELECT researcher_id, affiliation FROM di_allowlist WHERE researcher_id = $1 AND active = true',
            [researcher_id]
        );
        if (researcherResult.rows.length === 0) return res.status(404).json({ error: 'Researcher not found' });

        const researcher = researcherResult.rows[0];
        const year = new Date().getFullYear();

        // Create submission row first (so we can log errors against it)
        const submissionResult = await pool.query(
            `INSERT INTO di_submissions (researcher_id, affiliation, file_type, original_filename, status)
             VALUES ($1, $2, $3, $4, 'PENDING')
             RETURNING submission_id`,
            [researcher_id, researcher.affiliation, fileType, file.originalname]
        );
        const submissionId = submissionResult.rows[0].submission_id;

        try {
            const drive = getGoogleDriveClient();

            console.log(`[PI-UPLOAD] Creating folder structure: NATLAB-GLP/${year}/${researcher_id}/Submitted`);
            const submittedFolderId = await getSubmittedFolderId(drive, year, researcher_id);

            console.log(`[PI-UPLOAD] Uploading file to Drive...`);
            const driveFileId = await uploadFileToDrive(drive, file.buffer, file.originalname, 'application/pdf', submittedFolderId);

            await pool.query(
                `UPDATE di_submissions
                 SET drive_file_id = $1,
                     drive_error = NULL,
                     drive_last_attempt = NOW()
                 WHERE submission_id = $2`,
                [driveFileId, submissionId]
            );

            const webhookUrl = process.env.N8N_DI_WEBHOOK_URL;
            if (webhookUrl) {
                const formData = new FormData();
                formData.append('researcher_id', researcher_id);
                formData.append('affiliation', researcher.affiliation);
                formData.append('fileType', fileType);
                formData.append('original_filename', file.originalname);
                formData.append('submission_id', submissionId);
                formData.append('drive_file_id', driveFileId);
                formData.append('drive_view_url', getDriveViewUrl(driveFileId));
                formData.append('drive_download_url', getDriveDownloadUrl(driveFileId));
                formData.append('uploaded_by_pi', req.session.user.researcher_id);
                formData.append('file', file.buffer, { filename: file.originalname, contentType: file.mimetype });

                try {
                    await fetch(webhookUrl, { method: 'POST', body: formData, headers: formData.getHeaders() });
                } catch (webhookErr) {
                    console.error('[PI-UPLOAD] Webhook error:', webhookErr.message);
                }
            }

            return res.status(200).json({
                success: true,
                submission_id: submissionId,
                drive_file_id: driveFileId,
                view_url: getDriveViewUrl(driveFileId),
                message: 'File uploaded successfully'
            });

        } catch (driveErr) {
            console.error('[PI-UPLOAD] DRIVE ERROR:', driveErr.message);
            await recordDriveFailure(submissionId, driveErr);

            await pool.query(`UPDATE di_submissions SET status = 'FAILED' WHERE submission_id = $1`, [submissionId]);

            return res.status(502).json({
                error: 'DRIVE_UPLOAD_FAILED',
                message: 'Drive upload failed.',
                submission_id: submissionId,
                details: driveErr.message
            });
        }

    } catch (err) {
        console.error('PI upload error:', err);
        return res.status(500).json({ error: 'Server error' });
    }
});

// redeploy bump 2026-01-23T20:49:14

