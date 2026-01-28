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
const archiver = require('archiver');

// R2 (S3-compatible) SDK
const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } = require('@aws-sdk/client-s3');
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
        const name = (file.originalname || '').toLowerCase();
        const isPdfName = name.endsWith('.pdf');
        const mt = (file.mimetype || '').toLowerCase();
        const isPdfMime = (mt === 'application/pdf');
        const isOctet = (mt === 'application/octet-stream' || mt === 'binary/octet-stream');
        if (isPdfMime || (isOctet && isPdfName) || isPdfName) {
            return cb(null, true);
        }
        return cb(new Error('Only PDF files are accepted'), false);
    }
});


// =====================================================
// R2 STORAGE (S3-compatible) - minimal implementation
// Stores object key in di_submissions.drive_file_id as: r2:<key>
// Keeps Google Drive code as fallback.
// =====================================================

function r2Enabled() {
  return !!(process.env.R2_ACCESS_KEY_ID && process.env.R2_SECRET_ACCESS_KEY && process.env.R2_ENDPOINT && process.env.R2_BUCKET);
}

let _r2Client = null;
function getR2Client() {
  if (_r2Client) return _r2Client;
  _r2Client = new S3Client({
    region: 'auto',
    endpoint: process.env.R2_ENDPOINT,
    credentials: {
      accessKeyId: process.env.R2_ACCESS_KEY_ID,
      secretAccessKey: process.env.R2_SECRET_ACCESS_KEY
    }
  });
  return _r2Client;
}

async function uploadToR2(buffer, key, contentType) {
  const s3 = getR2Client();
  await s3.send(new PutObjectCommand({
    Bucket: process.env.R2_BUCKET,
    Key: key,
    Body: buffer,
    ContentType: contentType || 'application/octet-stream'
  }));
  return true;
}

async function downloadFromR2(key) {
  const s3 = getR2Client();
  const out = await s3.send(new GetObjectCommand({
    Bucket: process.env.R2_BUCKET,
    Key: key
  }));
  return out; // { Body stream, ContentType, ContentLength, Metadata, ... }
}

async function deleteFromR2(key) {
  const s3 = getR2Client();
  await s3.send(new DeleteObjectCommand({
    Bucket: process.env.R2_BUCKET,
    Key: key
  }));
  return true;
}

async function streamToBuffer(stream) {
  const chunks = [];
  for await (const chunk of stream) {
    chunks.push(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
  }
  return Buffer.concat(chunks);
}

function isR2Id(value) {
  return typeof value === 'string' && value.startsWith('r2:');
}

function r2KeyFromId(value) {
  return value.replace(/^r2:/, '');
}

// Notify researcher of PI decision (fire-and-forget)
async function notifyResearcher(payload) {
  const webhookUrl = process.env.N8N_NOTIFY_WEBHOOK_URL;
  if (!webhookUrl) {
    console.warn('[NOTIFY] N8N_NOTIFY_WEBHOOK_URL not configured, skipping notification');
    return;
  }
  try {
    const res = await fetch(webhookUrl, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload)
    });
    console.log(`[NOTIFY] Sent to researcher: ${payload.researcher_email}, status=${res.status}`);
  } catch (err) {
    console.error('[NOTIFY] Failed (non-blocking):', err.message);
  }
}

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

// Also serve static files at root level for direct access
app.use(express.static(path.join(__dirname, 'public')));

// Initialize Drive at startup
console.log('[STARTUP] Initializing Google Drive...');
initializeDriveClient();
console.log('[STARTUP] Drive enabled:', driveEnabled);
if (driveInitError) {
    console.error('[STARTUP] Drive init error:', driveInitError);
}

// Health check endpoint
app.get('/health', (req, res) => {
  res.json({
    status: 'ok',
    timestamp: new Date().toISOString(),
    service: 'natlab-glp',
    storage: 'r2',
    git: {
      sha: process.env.RAILWAY_GIT_COMMIT_SHA || null,
      branch: process.env.RAILWAY_GIT_BRANCH || null
    }
  });
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

// SUPERVISOR MIDDLEWARE - requires user to be a Supervisor
function requireSupervisor(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    if (req.session.user.role !== 'supervisor') {
        return res.status(403).json({ error: 'Access denied. Supervisor role required.' });
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

// Helper function to check if supervisor_researchers table exists (migration 008)
let supervisorTableExists = null;
let supervisorTableLastCheck = 0;

async function checkSupervisorTable() {
    const now = Date.now();
    if (supervisorTableExists === null || supervisorTableExists === false || (now - supervisorTableLastCheck > ROLE_COLUMN_CHECK_INTERVAL)) {
        try {
            const result = await pool.query(`
                SELECT table_name FROM information_schema.tables
                WHERE table_name = 'di_supervisor_researchers'
            `);
            supervisorTableExists = result.rows.length > 0;
            supervisorTableLastCheck = now;
        } catch (err) {
            supervisorTableExists = false;
        }
    }
    return supervisorTableExists;
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

        // Determine redirect based on role
        let redirectPage = 'upload.html';
        if (allowlistEntry.role === 'pi') redirectPage = 'pi-dashboard.html';
        else if (allowlistEntry.role === 'supervisor') redirectPage = 'supervisor-dashboard.html';

        res.json({
            success: true,
            message: 'Registration successful',
            user: req.session.user,
            redirect: redirectPage
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

        // Determine redirect based on role
        let redirectPage = 'upload.html';
        if (user.role === 'pi') redirectPage = 'pi-dashboard.html';
        else if (user.role === 'supervisor') redirectPage = 'supervisor-dashboard.html';

        res.json({
            success: true,
            message: 'Login successful',
            user: req.session.user,
            redirect: redirectPage
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
// Get current researcher's files organized by status (flat structure)
// - Submitted: files with status PENDING (under review)
// - Approved: files with status APPROVED
// Researchers can only view/download, not delete
app.get('/api/di/my-files', requireAuth, async (req, res) => {
    console.log('[MY-FILES] Endpoint called');
    try {
        const user = req.session.user;
        if (!user || !user.researcher_id) {
            console.log('[MY-FILES] No user or researcher_id in session');
            return res.status(400).json({ error: 'Invalid session', message: 'No researcher_id found' });
        }
        console.log('[MY-FILES] Loading files for researcher:', user.researcher_id);

        // Get all submissions for this researcher
        // Only select columns that exist in the database
        const result = await pool.query(
            `SELECT submission_id, file_type, original_filename, status, created_at, signed_at, drive_file_id
             FROM di_submissions
             WHERE researcher_id = $1
             ORDER BY created_at DESC`,
            [user.researcher_id]
        );

        console.log('[MY-FILES] Found', result.rows.length, 'submissions');

        // Build flat tree structure: My Files / Submitted | Approved
        const submittedFiles = [];
        const approvedFiles = [];

        // Count stats
        let pendingCount = 0;
        let approvedCount = 0;
        let revisionCount = 0;

        for (const file of result.rows) {
            const status = file.status || 'PENDING';
            const fileId = file.drive_file_id;

            // Check if file is stored in R2 (has r2: prefix)
            const hasR2File = fileId && typeof fileId === 'string' && fileId.startsWith('r2:');

            // Generate proper URLs - use backend download endpoint for R2 files
            const viewUrl = hasR2File ? `/api/di/download/${file.submission_id}` : null;
            const downloadUrl = hasR2File ? `/api/di/download/${file.submission_id}?download=true` : null;

            const fileNode = {
                name: file.original_filename,
                type: 'file',
                id: file.submission_id,
                status: status,
                fileType: file.file_type,
                date: file.created_at,
                signedAt: file.signed_at,
                r2ObjectKey: hasR2File ? fileId.replace(/^r2:/, '') : null,
                viewUrl: viewUrl,
                downloadUrl: downloadUrl
            };

            // Place file in appropriate folder based on status
            if (status === 'APPROVED') {
                approvedFiles.push(fileNode);
                approvedCount++;
            } else if (status === 'PENDING') {
                submittedFiles.push(fileNode);
                pendingCount++;
            } else if (status === 'REVISION_NEEDED') {
                // Revision needed files are NOT shown - need to be re-uploaded
                revisionCount++;
            }
        }

        // Build the simple two-folder structure
        const tree = {
            name: 'My Files',
            type: 'folder',
            children: [
                {
                    name: `Submitted (${pendingCount})`,
                    type: 'folder',
                    children: submittedFiles,
                    count: pendingCount
                },
                {
                    name: `Approved (${approvedCount})`,
                    type: 'folder',
                    children: approvedFiles,
                    count: approvedCount
                }
            ]
        };

        console.log('[MY-FILES] Success: pending=' + pendingCount + ', approved=' + approvedCount + ', revision=' + revisionCount);

        res.json({
            success: true,
            tree: tree,
            totalFiles: result.rows.length,
            pendingCount: pendingCount,
            approvedCount: approvedCount,
            revisionCount: revisionCount
        });

    } catch (err) {
        console.error('[MY-FILES] Error:', err.message);
        console.error('[MY-FILES] Stack:', err.stack);
        res.status(500).json({ error: 'Server error', message: err.message });
    }
});

// POST /api/di/upload
// Upload PDF file to Google Drive and forward to n8n webhook
app.post('/api/di/upload', requireAuth, upload.single('file'), async (req, res) => {
    try {
        const { fileType } = req.body;
        const file = req.file;

        const normalizedType = String(fileType || '').trim().toUpperCase();
        if (!normalizedType || !['SOP', 'DATA'].includes(normalizedType)) {
            return res.status(400).json({ error: 'fileType must be SOP or DATA' });
        }

        if (!file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        if (file.mimetype !== 'application/pdf') {
            return res.status(400).json({ error: 'Only PDF files are accepted' });
        }

        if (file.size > 10 * 1024 * 1024) {
            return res.status(400).json({ error: 'File exceeds 10MB limit' });
        }

        const user = req.session.user;
        const year = new Date().getFullYear();

        console.log('[UPLOAD] Starting upload for user=' + user.researcher_id + ', file=' + file.originalname + ', size=' + file.size);

        if (!r2Enabled()) {
            console.error('[UPLOAD] R2 not configured, missing env vars');
            return res.status(503).json({ error: 'R2 storage not configured' });
        }

        const safeOriginal = (file.originalname || 'upload.pdf').replace(/[^\w.\-]+/g, '_');
        const dateStamp = new Date().toISOString().slice(0, 10);
        const key = 'di/' + user.affiliation + '/Submitted/' + year + '/' + dateStamp + '_' + user.researcher_id + '_' + safeOriginal;

        console.log('[UPLOAD] Uploading file to R2: key=' + key);
        await uploadToR2(file.buffer, key, file.mimetype);

        const fileId = 'r2:' + key;

        const submissionResult = await pool.query(
            'INSERT INTO di_submissions (researcher_id, affiliation, file_type, original_filename, drive_file_id) VALUES ($1, $2, $3, $4, $5) RETURNING submission_id',
            [user.researcher_id, user.affiliation, normalizedType, file.originalname, fileId]
        );

        const submissionId = submissionResult.rows[0].submission_id;
        console.log('[UPLOAD] Submission recorded: submission_id=' + submissionId + ', drive_file_id=' + fileId);

        const webhookUrl = process.env.N8N_DI_WEBHOOK_URL;
        if (webhookUrl) {
            console.log('[UPLOAD] Calling n8n webhook for PI notification...');
            try {
                const formData = new FormData();
                formData.append('researcher_id', user.researcher_id);
                formData.append('affiliation', user.affiliation);
                formData.append('fileType', normalizedType);
                formData.append('original_filename', file.originalname);
                formData.append('submission_id', submissionId);
                formData.append('drive_file_id', fileId);
                formData.append('file', file.buffer, { filename: file.originalname, contentType: file.mimetype });

                const webhookRes = await fetch(webhookUrl, { method: 'POST', body: formData, headers: formData.getHeaders() });
                console.log('[UPLOAD] Webhook response status:', webhookRes.status);
            } catch (webhookErr) {
                console.error('[UPLOAD] Webhook error:', webhookErr.message);
            }
        } else {
            console.warn('[UPLOAD] N8N_DI_WEBHOOK_URL not configured, PI notification skipped');
        }

        return res.json({
            success: true,
            submission_id: submissionId,
            drive_file_id: fileId,
            view_url: '/api/di/download/' + submissionId,
            download_url: '/api/di/download/' + submissionId + '?download=true',
            message: 'File uploaded successfully'
        });

    } catch (err) {
        console.error('[UPLOAD] Upload error:', err);
        return res.status(500).json({ error: 'UPLOAD_FAILED', message: err.message });
    }
});

// API endpoint for n8n or external services to upload files
// Requires API key authentication via header: x-api-key
app.post('/api/di/external-upload', upload.single('file'), async (req, res) => {
    try {
        // Verify API key
        const apiKey = (req.headers['x-api-key'] || '').toString().trim();
        if (!apiKey || apiKey !== ((process.env.API_SECRET_KEY || '').toString().trim())) {
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
        const apiKey = (req.headers['x-api-key'] || '').toString().trim();
        if (!apiKey || apiKey !== ((process.env.API_SECRET_KEY || '').toString().trim())) {
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
        const apiKey = (req.headers['x-api-key'] || '').toString().trim();
        if (!apiKey || apiKey !== ((process.env.API_SECRET_KEY || '').toString().trim())) {
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
        const apiKey = (req.headers['x-api-key'] || '').toString().trim();
        if (!apiKey || apiKey !== ((process.env.API_SECRET_KEY || '').toString().trim())) {
            return res.status(401).json({ error: 'Invalid or missing API key' });
        }

        const { id } = req.params;
        const { status, ai_review, revision_comments } = req.body;
        // Normalize ai_review for jsonb column: accept object/array, JSON string, or plain string
        let aiReviewJson = null;
        if (ai_review !== undefined) {
            if (ai_review === null) {
                aiReviewJson = null;
            } else if (typeof ai_review === 'string') {
                try {
                    aiReviewJson = JSON.parse(ai_review);
                } catch {
                    aiReviewJson = { text: ai_review };
                }
            } else {
                aiReviewJson = ai_review;
            }
        }

        if (!status || !['PENDING', 'APPROVED', 'REVISION_NEEDED'].includes(status)) {
            return res.status(400).json({ error: 'status must be PENDING, APPROVED, or REVISION_NEEDED' });
        }

        const result = await pool.query(
            'UPDATE di_submissions SET status = $1, ai_review = $2::jsonb, revision_comments = $3 WHERE submission_id = $4 RETURNING *',
            [status, (aiReviewJson === null ? null : JSON.stringify(aiReviewJson)), revision_comments || null, id]
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
        const apiKey = (req.headers['x-api-key'] || '').toString().trim();
        if (!apiKey || apiKey !== ((process.env.API_SECRET_KEY || '').toString().trim())) {
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

// POST /api/di/api-key-check
// Lightweight API key validation endpoint for n8n and automations
app.post('/api/di/api-key-check', (req, res) => {
    const apiKey = (req.headers['x-api-key'] || '').toString().trim();
    const expected = ((process.env.API_SECRET_KEY || '').toString().trim());
    if (!apiKey || !expected || apiKey !== expected) {
        return res.status(401).json({ error: 'Invalid or missing API key' });
    }
    return res.json({ ok: true, timestamp: new Date().toISOString() });
});
// POST /api/di/extract-text
// Extract text from a submission PDF stored in R2
app.post('/api/di/extract-text', async (req, res) => {
    try {
        const apiKey = (req.headers['x-api-key'] || '').toString().trim();
        if (!apiKey || apiKey !== ((process.env.API_SECRET_KEY || '').toString().trim())) {
            return res.status(401).json({ error: 'Invalid or missing API key' });
        }

        const { submission_id } = req.body;

        if (!submission_id) {
            return res.status(400).json({ error: 'submission_id is required' });
        }

        // Get submission (FIXED: added parameter binding)
        const result = await pool.query(
            'SELECT * FROM di_submissions WHERE submission_id = $1',
            [submission_id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Submission not found' });
        }

        const submission = result.rows[0];
        const fileId = submission.drive_file_id;

        // Check if file is stored in R2
        if (!fileId || !isR2Id(fileId)) {
            console.error(`[EXTRACT-TEXT] No R2 file for submission ${submission_id}, fileId=${fileId}`);
            return res.status(404).json({
                error: 'File not found in storage',
                message: 'PDF file is not available for text extraction'
            });
        }

        if (!r2Enabled()) {
            return res.status(503).json({ error: 'R2 storage not configured' });
        }

        // Download PDF from R2
        const key = r2KeyFromId(fileId);
        console.log(`[EXTRACT-TEXT] Downloading PDF from R2: ${key}`);

        let pdfBuffer;
        try {
            const obj = await downloadFromR2(key);
            // Convert stream to buffer
            const chunks = [];
            for await (const chunk of obj.Body) {
                chunks.push(chunk);
            }
            pdfBuffer = Buffer.concat(chunks);
        } catch (e) {
            console.error(`[EXTRACT-TEXT] R2 download error:`, e.message);
            return res.status(500).json({ error: 'Failed to download PDF from storage' });
        }

        // Compute SHA256 hash of actual file content
        const crypto = require('crypto');
        const sha256 = crypto.createHash('sha256')
            .update(pdfBuffer)
            .digest('hex');

        // Extract text from PDF using pdf-parse
        let extracted_text = '';
        try {
            const pdfParse = require('pdf-parse');
            const parsed = await pdfParse(pdfBuffer);
            extracted_text = (parsed.text || '').trim();
            console.log(`[EXTRACT-TEXT] Extracted ${extracted_text.length} chars from ${submission.original_filename}`);
        } catch (e) {
            console.error(`[EXTRACT-TEXT] PDF parse error:`, e.message);
            // Return error instead of fallback - don't silently fail
            return res.status(500).json({
                error: 'PDF text extraction failed',
                message: e.message
            });
        }

        // Validate that we actually got text
        if (!extracted_text || extracted_text.length === 0) {
            console.warn(`[EXTRACT-TEXT] No text extracted from ${submission.original_filename}`);
            return res.json({
                success: true,
                submission_id: submission_id,
                original_filename: submission.original_filename,
                sha256: sha256,
                extracted_text: '',
                warning: 'No text content found in PDF - document may be image-based or empty'
            });
        }

        res.json({
            success: true,
            submission_id: submission_id,
            original_filename: submission.original_filename,
            sha256: sha256,
            extracted_text: extracted_text,
            text_length: extracted_text.length
        });

    } catch (err) {
        console.error('Extract text error:', err);
        res.status(500).json({ error: 'Server error', message: err.message });
    }
});

// POST /api/di/sign
// Sign an approved submission (API key auth for n8n)
app.post('/api/di/sign', async (req, res) => {
    try {
        const apiKey = (req.headers['x-api-key'] || '').toString().trim();
        if (!apiKey || apiKey !== ((process.env.API_SECRET_KEY || '').toString().trim())) {
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

// If stored in R2, stream it back (no public bucket needed)
if (fileId && isR2Id(fileId)) {
  if (!r2Enabled()) {
    return res.status(503).json({ error: 'R2_NOT_CONFIGURED', message: 'R2 is not configured on the server.' });
  }

  const key = r2KeyFromId(fileId);
  console.log(`[DOWNLOAD] Serving from R2: ${key}`);

  try {
    const obj = await downloadFromR2(key);

    // Stream response
    res.setHeader('Content-Type', obj.ContentType || 'application/pdf');

    // Always download if query says download=true, else inline view in browser
    const disposition = (download === 'true') ? 'attachment' : 'inline';
    const safeName = submission.original_filename || 'document.pdf';
    res.setHeader('Content-Disposition', `${disposition}; filename="${safeName}"`);

    if (obj.ContentLength) res.setHeader('Content-Length', String(obj.ContentLength));

    return obj.Body.pipe(res);
  } catch (e) {
    console.error('[DOWNLOAD] R2 error:', e.message);
    return res.status(500).json({ error: 'R2_DOWNLOAD_FAILED', message: e.message });
  }
}

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

// GET /api/di/approve/:id - R2 only, no Drive
app.get('/api/di/approve/:id', async (req, res) => {
    const { id } = req.params;
    const { token } = req.query;
    try {
        if (!token) return res.status(400).send(renderHtmlPage('Error', 'Missing token', 'error'));
        const expectedToken = Buffer.from(id + '_glp_2024_sec').toString('base64').replace(/[^a-zA-Z0-9]/g, '').substring(0, 32);
        if (token !== expectedToken) return res.status(403).send(renderHtmlPage('Invalid Token', 'Link invalid or expired.', 'error'));

        const result = await pool.query('SELECT * FROM di_submissions WHERE submission_id = $1', [id]);
        if (result.rows.length === 0) return res.status(404).send(renderHtmlPage('Not Found', 'Submission not found.', 'error'));

        const submission = result.rows[0];
        const fileId = (submission.drive_file_id || '').trim();
        const isR2 = fileId.startsWith('r2:');
        console.log(`[APPROVE] id=${id} fileId=${fileId} isR2=${isR2}`);

        if (!isR2) return res.status(400).send(renderHtmlPage('Error', 'Drive not configured. Only R2 supported.', 'error'));
        if (!fileId) return res.status(400).send(renderHtmlPage('Error', 'No file associated.', 'error'));
        if (submission.status === 'APPROVED') return res.send(renderHtmlPage('Already Approved', 'Already approved.', 'info'));

        const signedAt = new Date().toISOString();
        const signerName = 'Frank J. Hernandez';
        const originalKey = fileId.replace(/^r2:/, '');

        // Download from R2
        const r2Obj = await downloadFromR2(originalKey);
        const chunks = []; for await (const c of r2Obj.Body) chunks.push(c);
        const pdfBuffer = Buffer.concat(chunks);

        // Stamp PDF
        const stampedBuffer = await createStampedPdf(pdfBuffer, signerName, signedAt);

        // Upload to Approved folder
        const safeFilename = submission.original_filename.replace('.pdf', '_APPROVED.pdf').replace(/[^\w.\-]+/g, '_');
        const approvedKey = originalKey.replace('/Submitted/', '/Approved/').replace(/[^/]+$/, safeFilename);
        await uploadToR2(stampedBuffer, approvedKey, 'application/pdf');
        const newFileId = 'r2:' + approvedKey;

        // Delete original (best effort)
        try { await deleteFromR2(originalKey); } catch (e) { console.warn('[APPROVE] Delete warning:', e.message); }

        // Signature hash
        const crypto = require('crypto');
        const signatureHash = crypto.createHmac('sha256', process.env.API_SECRET_KEY || 'natlab_glp_secret')
            .update(JSON.stringify({ submission_id: id, original_filename: submission.original_filename, signed_at: signedAt, signer: signerName }))
            .digest('hex');
        const verificationCode = `NATLAB-${id}-${signatureHash.substring(0, 8).toUpperCase()}`;

        // Update DB
        await pool.query(
            `UPDATE di_submissions SET status='APPROVED', signed_at=$1, signer_name=$2, drive_file_id=$3, signed_pdf_path=$3, signature_hash=$4, verification_code=$5 WHERE submission_id=$6`,
            [signedAt, signerName, newFileId, signatureHash, verificationCode, id]
        );

        // Get researcher info and notify (fire-and-forget)
        const researcherResult = await pool.query(
            'SELECT institution_email, researcher_id FROM di_allowlist WHERE researcher_id = $1',
            [submission.researcher_id]
        );
        if (researcherResult.rows.length > 0) {
            const researcher = researcherResult.rows[0];
            await notifyResearcher({
                submission_id: id,
                decision: 'APPROVED',
                researcher_email: researcher.institution_email,
                researcher_name: researcher.researcher_id,
                file_name: submission.original_filename,
                affiliation: submission.affiliation,
                view_url: `https://natlab-glp-production.up.railway.app/api/di/download/${id}`,
                download_url: `https://natlab-glp-production.up.railway.app/api/di/download/${id}?download=true`,
                verification_code: verificationCode
            });
        }

        console.log(`[APPROVE] Success: ${id} -> ${newFileId}`);
        res.redirect(`/di/action-success.html?action=approved&file=${encodeURIComponent(submission.original_filename)}&id=${id}`);
    } catch (err) {
        console.error('[APPROVE] Error:', err);
        res.status(500).send(renderHtmlPage('Error', err.message, 'error'));
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

// POST /api/di/revise/:id - R2 only, no Drive
app.post('/api/di/revise/:id', async (req, res) => {
    const { id } = req.params;
    const { token } = req.query;
    const { comments } = req.body;
    try {
        if (!token) return res.status(400).send(renderHtmlPage('Error', 'Missing token', 'error'));
        const expectedToken = Buffer.from(id + '_glp_2024_sec').toString('base64').replace(/[^a-zA-Z0-9]/g, '').substring(0, 32);
        if (token !== expectedToken) return res.status(403).send(renderHtmlPage('Invalid Token', 'Link invalid or expired.', 'error'));

        const result = await pool.query('SELECT drive_file_id, researcher_id, original_filename, affiliation FROM di_submissions WHERE submission_id = $1', [id]);
        if (result.rows.length === 0) return res.status(404).send(renderHtmlPage('Not Found', 'Submission not found.', 'error'));

        const submission = result.rows[0];
        const fileId = (submission.drive_file_id || '').trim();
        const isR2 = fileId.startsWith('r2:');
        console.log(`[REVISE] id=${id} fileId=${fileId} isR2=${isR2}`);

        if (!isR2 && fileId) return res.status(400).send(renderHtmlPage('Error', 'Drive not configured. Only R2 supported.', 'error'));

        // Delete from R2 (best effort)
        if (isR2) {
            try { await deleteFromR2(fileId.replace(/^r2:/, '')); } catch (e) { console.warn('[REVISE] Delete warning:', e.message); }
        }

        // Update DB
        await pool.query(
            `UPDATE di_submissions SET status='REVISION_NEEDED', drive_file_id=NULL, revision_comments=$1 WHERE submission_id=$2`,
            [comments || '', id]
        );

        // Get researcher info and notify (fire-and-forget)
        const researcherResult = await pool.query(
            'SELECT institution_email, researcher_id FROM di_allowlist WHERE researcher_id = $1',
            [submission.researcher_id]
        );
        if (researcherResult.rows.length > 0) {
            const researcher = researcherResult.rows[0];
            await notifyResearcher({
                submission_id: id,
                decision: 'REVISION_NEEDED',
                researcher_email: researcher.institution_email,
                researcher_name: researcher.researcher_id,
                file_name: submission.original_filename,
                affiliation: submission.affiliation,
                pi_comments: comments || ''
            });
        }

        console.log(`[REVISE] Success: ${id} marked for revision`);
        res.redirect(`/di/action-success.html?action=revision&file=${encodeURIComponent(submission.original_filename)}&id=${id}`);
    } catch (err) {
        console.error('[REVISE] Error:', err);
        res.status(500).send(renderHtmlPage('Error', err.message, 'error'));
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
        if (!['researcher', 'supervisor', 'pi'].includes(memberRole)) {
            return res.status(400).json({ error: 'Role must be researcher, supervisor, or pi' });
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
    const submissionId = req.params.id;

    // Fetch stored key (drive_file_id is used as storage key for backward compatibility)
    const existing = await pool.query(
      'SELECT drive_file_id FROM di_submissions WHERE submission_id = ',
      [submissionId]
    );

    // Delete DB record
    const del = await pool.query(
      'DELETE FROM di_submissions WHERE submission_id =  RETURNING submission_id',
      [submissionId]
    );

    if (del.rowCount === 0) return res.status(404).json({ error: 'Not found' });

    // Best-effort delete from R2 if helper exists
    const key = existing.rows?.[0]?.drive_file_id;
    if (key && typeof deleteFromR2 === 'function') {
      try { await deleteFromR2(key); }
      catch (e) { console.warn('[R2] delete failed:', e?.message || e); }
    }

    res.json({ ok: true, submission_id: del.rows[0].submission_id });
  } catch (err) {
    console.error('Delete submission error:', err);
    res.status(500).json({ error: 'Server error' });
  }
});

// =====================================================
// GROUP DOCUMENTS - Shared lab documents (PI managed)
// =====================================================

// Multer config for Group Documents (multiple file types)
const groupDocUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 50 * 1024 * 1024 }, // 50MB limit for documents
    fileFilter: (req, file, cb) => {
        const name = (file.originalname || '').toLowerCase();
        const mt = (file.mimetype || '').toLowerCase();

        // Allowed file types
        const allowedExtensions = ['.pdf', '.xls', '.xlsx', '.doc', '.docx', '.ppt', '.pptx'];
        const allowedMimes = [
            'application/pdf',
            'application/vnd.ms-excel',
            'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
            'application/msword',
            'application/vnd.openxmlformats-officedocument.wordprocessingml.document',
            'application/vnd.ms-powerpoint',
            'application/vnd.openxmlformats-officedocument.presentationml.presentation',
            'application/octet-stream'
        ];

        const hasAllowedExt = allowedExtensions.some(ext => name.endsWith(ext));
        const hasAllowedMime = allowedMimes.includes(mt);

        if (hasAllowedExt || hasAllowedMime) {
            return cb(null, true);
        }
        return cb(new Error('Only PDF, Excel, Word, and PowerPoint files are accepted'), false);
    }
});

// Helper to determine file type from filename
function getFileTypeFromName(filename) {
    const name = (filename || '').toLowerCase();
    if (name.endsWith('.pdf')) return 'PDF';
    if (name.endsWith('.xls') || name.endsWith('.xlsx')) return 'EXCEL';
    if (name.endsWith('.doc') || name.endsWith('.docx')) return 'WORD';
    if (name.endsWith('.ppt') || name.endsWith('.pptx')) return 'POWERPOINT';
    return 'PDF'; // default
}

// GET /api/di/group-documents
// List all active group documents (accessible to all authenticated users)
app.get('/api/di/group-documents', requireAuth, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT id, title, category, description, filename, file_type, created_at, uploaded_by,
                    COALESCE(can_download, true) as can_download
             FROM di_group_documents
             WHERE is_active = true
             ORDER BY category, title`
        );

        res.json({
            success: true,
            count: result.rows.length,
            documents: result.rows.map(doc => ({
                ...doc,
                downloadUrl: `/api/di/group-documents/${doc.id}/download`
            }))
        });

    } catch (err) {
        console.error('Get group documents error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/group-documents/:id/download
// Download a group document
app.get('/api/di/group-documents/:id/download', requireAuth, async (req, res) => {
    try {
        const { id } = req.params;
        const user = req.session.user;
        const isPI = user.role === 'pi' || user.role === 'PI';

        const result = await pool.query(
            'SELECT filename, r2_object_key, COALESCE(can_download, true) as can_download FROM di_group_documents WHERE id = $1 AND is_active = true',
            [id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Document not found' });
        }

        const doc = result.rows[0];

        // Check download permission (PI can always download)
        if (!isPI && !doc.can_download) {
            return res.status(403).json({ error: 'This document is view-only. Download not permitted.' });
        }

        if (!r2Enabled()) {
            return res.status(503).json({ error: 'R2 storage not configured' });
        }

        try {
            const obj = await downloadFromR2(doc.r2_object_key);

            res.setHeader('Content-Type', obj.ContentType || 'application/octet-stream');
            res.setHeader('Content-Disposition', `attachment; filename="${doc.filename}"`);
            if (obj.ContentLength) res.setHeader('Content-Length', String(obj.ContentLength));

            return obj.Body.pipe(res);
        } catch (e) {
            console.error('[GROUP-DOC] R2 download error:', e.message);
            return res.status(500).json({ error: 'Failed to download document' });
        }

    } catch (err) {
        console.error('Download group document error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/group-documents
// Upload a new group document (PI only)
app.post('/api/di/group-documents', requirePI, groupDocUpload.single('file'), async (req, res) => {
    try {
        const { title, category, description } = req.body;
        const canDownload = req.body.can_download !== 'false' && req.body.can_download !== false;
        const file = req.file;

        if (!title || !category) {
            return res.status(400).json({ error: 'Title and category are required' });
        }

        if (!file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        if (!r2Enabled()) {
            return res.status(503).json({ error: 'R2 storage not configured' });
        }

        const user = req.session.user;
        const year = new Date().getFullYear();
        const fileType = getFileTypeFromName(file.originalname);
        const safeFilename = (file.originalname || 'document').replace(/[^\w.\-]+/g, '_');
        const timestamp = Date.now();
        const key = `di/GroupDocuments/${year}/${timestamp}_${safeFilename}`;

        console.log(`[GROUP-DOC] Uploading: ${key}`);
        await uploadToR2(file.buffer, key, file.mimetype);

        const result = await pool.query(
            `INSERT INTO di_group_documents (title, category, description, filename, file_type, r2_object_key, uploaded_by, can_download)
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
             RETURNING id, title, category, description, filename, file_type, created_at, can_download`,
            [title, category, description || null, file.originalname, fileType, key, user.researcher_id, canDownload]
        );

        res.json({
            success: true,
            message: 'Document uploaded successfully',
            document: {
                ...result.rows[0],
                downloadUrl: `/api/di/group-documents/${result.rows[0].id}/download`
            }
        });

    } catch (err) {
        console.error('Upload group document error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// PUT /api/di/group-documents/:id
// Update a group document metadata (PI only)
app.put('/api/di/group-documents/:id', requirePI, async (req, res) => {
    try {
        const { id } = req.params;
        const { title, category, description, can_download } = req.body;

        if (!title || !category) {
            return res.status(400).json({ error: 'Title and category are required' });
        }

        const canDownloadValue = can_download !== false && can_download !== 'false';

        const result = await pool.query(
            `UPDATE di_group_documents
             SET title = $1, category = $2, description = $3, can_download = $4, updated_at = CURRENT_TIMESTAMP
             WHERE id = $5 AND is_active = true
             RETURNING id, title, category, description, filename, file_type, created_at, updated_at, can_download`,
            [title, category, description || null, canDownloadValue, id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Document not found' });
        }

        res.json({
            success: true,
            message: 'Document updated successfully',
            document: result.rows[0]
        });

    } catch (err) {
        console.error('Update group document error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// DELETE /api/di/group-documents/:id
// Soft delete a group document (PI only)
app.delete('/api/di/group-documents/:id', requirePI, async (req, res) => {
    try {
        const { id } = req.params;

        // Get document info first
        const docResult = await pool.query(
            'SELECT r2_object_key FROM di_group_documents WHERE id = $1',
            [id]
        );

        if (docResult.rows.length === 0) {
            return res.status(404).json({ error: 'Document not found' });
        }

        // Soft delete in database
        await pool.query(
            'UPDATE di_group_documents SET is_active = false WHERE id = $1',
            [id]
        );

        // Best-effort delete from R2
        const key = docResult.rows[0].r2_object_key;
        if (key && r2Enabled()) {
            try {
                await deleteFromR2(key);
            } catch (e) {
                console.warn('[GROUP-DOC] R2 delete warning:', e.message);
            }
        }

        res.json({
            success: true,
            message: 'Document deleted successfully'
        });

    } catch (err) {
        console.error('Delete group document error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// =====================================================
// PI PORTAL ENDPOINTS
// =====================================================

// GET /api/di/pending-approvals
// List pending submissions for PI review
app.get('/api/di/pending-approvals', requirePI, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT s.submission_id, s.researcher_id, s.original_filename, s.file_type,
                    s.status, s.created_at, s.ai_review,
                    a.name as researcher_name
             FROM di_submissions s
             LEFT JOIN di_allowlist a ON s.researcher_id = a.researcher_id
             WHERE s.status = 'PENDING'
             ORDER BY s.created_at DESC`
        );

        res.json({
            success: true,
            count: result.rows.length,
            submissions: result.rows
        });

    } catch (err) {
        console.error('Get pending approvals error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/lab-files
// Get all submissions as flat list for Laboratory Files tab
app.get('/api/di/lab-files', requirePI, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT s.submission_id, s.researcher_id, s.original_filename, s.file_type,
                    s.status, s.created_at, s.signed_at, s.drive_file_id,
                    COALESCE(s.drive_file_id, s.signed_pdf_path) as r2_object_key,
                    a.name as researcher_name
             FROM di_submissions s
             LEFT JOIN di_allowlist a ON s.researcher_id = a.researcher_id
             ORDER BY s.created_at DESC`
        );

        res.json({
            success: true,
            count: result.rows.length,
            files: result.rows
        });

    } catch (err) {
        console.error('Get lab files error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/bulk-download
// Download multiple files as ZIP
app.post('/api/di/bulk-download', requirePI, async (req, res) => {
    try {
        const { submission_ids } = req.body;

        if (!Array.isArray(submission_ids) || submission_ids.length === 0) {
            return res.status(400).json({ error: 'No files selected' });
        }

        if (!r2Enabled()) {
            return res.status(503).json({ error: 'R2 storage not configured' });
        }

        // Fetch file metadata
        const result = await pool.query(
            `SELECT submission_id, original_filename, drive_file_id, signed_pdf_path
             FROM di_submissions
             WHERE submission_id = ANY($1::uuid[])`,
            [submission_ids]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'No files found' });
        }

        // Set response headers for ZIP
        res.setHeader('Content-Type', 'application/zip');
        res.setHeader('Content-Disposition', 'attachment; filename="lab-files.zip"');

        // Create archive
        const archive = archiver('zip', { zlib: { level: 5 } });

        archive.on('error', (err) => {
            console.error('[BULK-DOWNLOAD] Archive error:', err);
            if (!res.headersSent) {
                res.status(500).json({ error: 'Archive creation failed' });
            }
        });

        archive.pipe(res);

        // Add files from R2
        for (const file of result.rows) {
            const fileId = file.signed_pdf_path || file.drive_file_id;
            if (!fileId) continue;

            const key = fileId.replace(/^r2:/, '');
            try {
                const obj = await downloadFromR2(key);
                const buffer = await streamToBuffer(obj.Body);
                archive.append(buffer, { name: file.original_filename });
            } catch (e) {
                console.warn(`[BULK-DOWNLOAD] Skipping file ${file.submission_id}:`, e.message);
            }
        }

        await archive.finalize();

    } catch (err) {
        console.error('Bulk download error:', err);
        if (!res.headersSent) {
            res.status(500).json({ error: 'Server error' });
        }
    }
});

// GET /api/di/all-members
// Get all members including inactive (for User Management)
app.get('/api/di/all-members', requirePI, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT a.researcher_id, a.name, a.institution_email, a.affiliation,
                    a.active, COALESCE(a.role, 'researcher') as role,
                    a.created_at, a.deactivated_at, a.deactivated_by,
                    u.last_login,
                    (SELECT COUNT(*) FROM di_submissions s WHERE s.researcher_id = a.researcher_id) as submission_count
             FROM di_allowlist a
             LEFT JOIN di_users u ON a.institution_email = u.institution_email
             ORDER BY a.active DESC, a.name`
        );

        res.json({
            success: true,
            count: result.rows.length,
            members: result.rows
        });

    } catch (err) {
        console.error('Get all members error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// PUT /api/di/members/:id/deactivate
// Deactivate a user (soft delete)
app.put('/api/di/members/:id/deactivate', requirePI, async (req, res) => {
    try {
        const { id } = req.params;
        const piUser = req.session.user;

        // Prevent PI from deactivating themselves
        if (id === piUser.researcher_id) {
            return res.status(400).json({ error: 'Cannot deactivate yourself' });
        }

        const result = await pool.query(
            `UPDATE di_allowlist
             SET active = false, deactivated_at = CURRENT_TIMESTAMP, deactivated_by = $1
             WHERE researcher_id = $2
             RETURNING researcher_id, name, active`,
            [piUser.researcher_id, id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({
            success: true,
            message: 'User deactivated successfully',
            member: result.rows[0]
        });

    } catch (err) {
        console.error('Deactivate user error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// PUT /api/di/members/:id/reactivate
// Reactivate a user
app.put('/api/di/members/:id/reactivate', requirePI, async (req, res) => {
    try {
        const { id } = req.params;

        const result = await pool.query(
            `UPDATE di_allowlist
             SET active = true, deactivated_at = NULL, deactivated_by = NULL
             WHERE researcher_id = $1
             RETURNING researcher_id, name, active`,
            [id]
        );

        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }

        res.json({
            success: true,
            message: 'User reactivated successfully',
            member: result.rows[0]
        });

    } catch (err) {
        console.error('Reactivate user error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/metrics
// Dashboard metrics for PI portal
app.get('/api/di/metrics', requirePI, async (req, res) => {
    try {
        // Get submissions by status
        const statusResult = await pool.query(
            `SELECT status, COUNT(*)::int as count
             FROM di_submissions
             GROUP BY status`
        );

        const byStatus = {};
        let total = 0;
        statusResult.rows.forEach(row => {
            byStatus[row.status] = row.count;
            total += row.count;
        });

        // Get submissions by researcher
        const researcherResult = await pool.query(
            `SELECT researcher_id,
                    COUNT(*)::int as total,
                    COUNT(CASE WHEN status = 'APPROVED' THEN 1 END)::int as approved
             FROM di_submissions
             GROUP BY researcher_id
             ORDER BY total DESC
             LIMIT 10`
        );

        // Get total active researchers
        const activeResearchers = await pool.query(
            `SELECT COUNT(*)::int as count FROM di_allowlist WHERE active = true`
        );

        // Get this month submissions
        const thisMonthResult = await pool.query(
            `SELECT COUNT(*)::int as count
             FROM di_submissions
             WHERE created_at >= date_trunc('month', CURRENT_DATE)`
        );

        res.json({
            success: true,
            total,
            byStatus,
            byResearcher: researcherResult.rows,
            totalResearchers: activeResearchers.rows[0]?.count || 0,
            thisMonth: thisMonthResult.rows[0]?.count || 0
        });

    } catch (err) {
        console.error('Get metrics error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/reports/export
// Export submissions as CSV
app.get('/api/di/reports/export', requirePI, async (req, res) => {
    try {
        const { from, to, status, format } = req.query;

        let query = `
            SELECT s.submission_id, s.researcher_id, s.original_filename, s.file_type,
                   s.status, s.created_at, s.signed_at, s.signer_name,
                   s.verification_code, s.revision_comments,
                   a.name as researcher_name, a.affiliation
            FROM di_submissions s
            LEFT JOIN di_allowlist a ON s.researcher_id = a.researcher_id
            WHERE 1=1
        `;
        const params = [];
        let paramIndex = 1;

        if (status) {
            params.push(status);
            query += ` AND s.status = $${paramIndex}`;
            paramIndex++;
        }

        if (from) {
            params.push(from);
            query += ` AND s.created_at >= $${paramIndex}`;
            paramIndex++;
        }

        if (to) {
            params.push(to);
            query += ` AND s.created_at <= $${paramIndex}::date + interval '1 day'`;
            paramIndex++;
        }

        query += ` ORDER BY s.created_at DESC`;

        const result = await pool.query(query, params);

        if (format === 'csv') {
            // Generate CSV
            const headers = [
                'Submission ID', 'Researcher ID', 'Researcher Name', 'Affiliation',
                'Filename', 'File Type', 'Status', 'Created At', 'Signed At',
                'Signer Name', 'Verification Code', 'Revision Comments'
            ];

            const rows = result.rows.map(r => [
                r.submission_id,
                r.researcher_id,
                r.researcher_name || '',
                r.affiliation || '',
                r.original_filename,
                r.file_type,
                r.status,
                r.created_at ? new Date(r.created_at).toISOString() : '',
                r.signed_at ? new Date(r.signed_at).toISOString() : '',
                r.signer_name || '',
                r.verification_code || '',
                (r.revision_comments || '').replace(/"/g, '""')
            ]);

            const csv = [
                headers.join(','),
                ...rows.map(row => row.map(cell => `"${cell}"`).join(','))
            ].join('\n');

            res.setHeader('Content-Type', 'text/csv');
            res.setHeader('Content-Disposition', `attachment; filename="submissions-export-${new Date().toISOString().split('T')[0]}.csv"`);
            return res.send(csv);
        }

        // Default: return JSON
        res.json({
            success: true,
            count: result.rows.length,
            submissions: result.rows
        });

    } catch (err) {
        console.error('Export error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// =====================================================
// DELEGATION ENDPOINTS (PI only)
// Manage supervisor roles and researcher assignments
// =====================================================

// POST /api/di/delegation/promote
// Promote a researcher to supervisor role
app.post('/api/di/delegation/promote', requirePI, async (req, res) => {
    try {
        const { user_id } = req.body;
        if (!user_id) {
            return res.status(400).json({ error: 'user_id is required' });
        }

        // Check user exists and is currently a researcher
        const userCheck = await pool.query(
            `SELECT researcher_id, COALESCE(role, 'researcher') as role FROM di_allowlist WHERE researcher_id = $1 AND active = true`,
            [user_id]
        );
        if (userCheck.rows.length === 0) {
            return res.status(404).json({ error: 'User not found or inactive' });
        }
        if (userCheck.rows[0].role !== 'researcher') {
            return res.status(400).json({ error: 'Only researchers can be promoted to supervisor' });
        }

        // Update role to supervisor
        await pool.query(
            `UPDATE di_allowlist SET role = 'supervisor' WHERE researcher_id = $1`,
            [user_id]
        );

        res.json({ success: true, message: 'User promoted to supervisor', user_id });
    } catch (err) {
        console.error('Promote to supervisor error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/delegation/demote
// Demote a supervisor back to researcher
app.post('/api/di/delegation/demote', requirePI, async (req, res) => {
    try {
        const { user_id } = req.body;
        if (!user_id) {
            return res.status(400).json({ error: 'user_id is required' });
        }

        // Check user exists and is currently a supervisor
        const userCheck = await pool.query(
            `SELECT researcher_id, COALESCE(role, 'researcher') as role FROM di_allowlist WHERE researcher_id = $1 AND active = true`,
            [user_id]
        );
        if (userCheck.rows.length === 0) {
            return res.status(404).json({ error: 'User not found or inactive' });
        }
        if (userCheck.rows[0].role !== 'supervisor') {
            return res.status(400).json({ error: 'Only supervisors can be demoted to researcher' });
        }

        // Remove all researcher assignments for this supervisor FIRST
        // (Do this before role update so if it fails, role remains unchanged)
        const hasTable = await checkSupervisorTable();
        if (hasTable) {
            await pool.query(
                `DELETE FROM di_supervisor_researchers WHERE supervisor_id = $1`,
                [user_id]
            );
        }

        // Update role to researcher
        await pool.query(
            `UPDATE di_allowlist SET role = 'researcher' WHERE researcher_id = $1`,
            [user_id]
        );

        res.json({ success: true, message: 'User demoted to researcher', user_id });
    } catch (err) {
        console.error('Demote supervisor error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/delegation/assign
// Assign a researcher to a supervisor for viewing
app.post('/api/di/delegation/assign', requirePI, async (req, res) => {
    try {
        const { supervisor_id, researcher_id } = req.body;
        if (!supervisor_id || !researcher_id) {
            return res.status(400).json({ error: 'supervisor_id and researcher_id are required' });
        }

        // Check if supervisor assignments table exists (migration 008)
        const hasTable = await checkSupervisorTable();
        if (!hasTable) {
            return res.status(503).json({ error: 'Supervisor assignments feature not available. Migration 008 required.' });
        }

        // Verify supervisor exists and has supervisor role
        const supervisorCheck = await pool.query(
            `SELECT researcher_id, COALESCE(role, 'researcher') as role FROM di_allowlist WHERE researcher_id = $1 AND active = true`,
            [supervisor_id]
        );
        if (supervisorCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Supervisor not found' });
        }
        if (supervisorCheck.rows[0].role !== 'supervisor') {
            return res.status(400).json({ error: 'Target user is not a supervisor' });
        }

        // Verify researcher exists
        const researcherCheck = await pool.query(
            `SELECT researcher_id FROM di_allowlist WHERE researcher_id = $1 AND active = true`,
            [researcher_id]
        );
        if (researcherCheck.rows.length === 0) {
            return res.status(404).json({ error: 'Researcher not found' });
        }

        // Insert assignment (ignore if already exists)
        await pool.query(
            `INSERT INTO di_supervisor_researchers (supervisor_id, researcher_id, assigned_by)
             VALUES ($1, $2, $3)
             ON CONFLICT (supervisor_id, researcher_id) DO NOTHING`,
            [supervisor_id, researcher_id, req.session.user.researcher_id]
        );

        res.json({ success: true, message: 'Researcher assigned to supervisor', supervisor_id, researcher_id });
    } catch (err) {
        console.error('Assign researcher error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/delegation/unassign
// Remove a researcher from a supervisor
app.post('/api/di/delegation/unassign', requirePI, async (req, res) => {
    try {
        const { supervisor_id, researcher_id } = req.body;
        if (!supervisor_id || !researcher_id) {
            return res.status(400).json({ error: 'supervisor_id and researcher_id are required' });
        }

        // Check if supervisor assignments table exists (migration 008)
        const hasTable = await checkSupervisorTable();
        if (!hasTable) {
            return res.status(503).json({ error: 'Supervisor assignments feature not available. Migration 008 required.' });
        }

        const result = await pool.query(
            `DELETE FROM di_supervisor_researchers WHERE supervisor_id = $1 AND researcher_id = $2 RETURNING *`,
            [supervisor_id, researcher_id]
        );

        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Assignment not found' });
        }

        res.json({ success: true, message: 'Researcher unassigned from supervisor', supervisor_id, researcher_id });
    } catch (err) {
        console.error('Unassign researcher error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/delegation/assignments
// Get all assignments for a supervisor (or all if no supervisor_id)
app.get('/api/di/delegation/assignments', requirePI, async (req, res) => {
    try {
        const { supervisor_id } = req.query;
        let query, params;

        if (supervisor_id) {
            query = `
                SELECT sr.supervisor_id, sr.researcher_id, sr.assigned_at, sr.assigned_by,
                       a.name as researcher_name, a.institution_email as researcher_email
                FROM di_supervisor_researchers sr
                JOIN di_allowlist a ON sr.researcher_id = a.researcher_id
                WHERE sr.supervisor_id = $1
                ORDER BY a.name
            `;
            params = [supervisor_id];
        } else {
            query = `
                SELECT sr.supervisor_id, sr.researcher_id, sr.assigned_at, sr.assigned_by,
                       a.name as researcher_name, a.institution_email as researcher_email,
                       s.name as supervisor_name
                FROM di_supervisor_researchers sr
                JOIN di_allowlist a ON sr.researcher_id = a.researcher_id
                JOIN di_allowlist s ON sr.supervisor_id = s.researcher_id
                ORDER BY s.name, a.name
            `;
            params = [];
        }

        const result = await pool.query(query, params);
        res.json({ success: true, count: result.rows.length, assignments: result.rows });
    } catch (err) {
        console.error('Get assignments error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/delegation/supervisors
// Get all users with supervisor role
app.get('/api/di/delegation/supervisors', requirePI, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT researcher_id, name, institution_email, affiliation
             FROM di_allowlist
             WHERE role = 'supervisor' AND active = true
             ORDER BY name`
        );
        res.json({ success: true, count: result.rows.length, supervisors: result.rows });
    } catch (err) {
        console.error('Get supervisors error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// =====================================================
// SUPERVISION ENDPOINTS (Supervisor only)
// Read-only access to assigned researchers' files
// =====================================================

// GET /api/di/supervision/researchers
// Get list of researchers assigned to the logged-in supervisor
app.get('/api/di/supervision/researchers', requireSupervisor, async (req, res) => {
    try {
        const supervisorId = req.session.user.researcher_id;

        const result = await pool.query(
            `SELECT a.researcher_id, a.name, a.institution_email, a.affiliation,
                    sr.assigned_at,
                    (SELECT COUNT(*) FROM di_submissions s WHERE s.researcher_id = a.researcher_id) as file_count
             FROM di_supervisor_researchers sr
             JOIN di_allowlist a ON sr.researcher_id = a.researcher_id
             WHERE sr.supervisor_id = $1 AND a.active = true
             ORDER BY a.name`,
            [supervisorId]
        );

        res.json({ success: true, count: result.rows.length, researchers: result.rows });
    } catch (err) {
        console.error('Get supervised researchers error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/supervision/researchers/:researcher_id/files
// Get files for a specific researcher (must be assigned to this supervisor)
app.get('/api/di/supervision/researchers/:researcher_id/files', requireSupervisor, async (req, res) => {
    try {
        const supervisorId = req.session.user.researcher_id;
        const { researcher_id } = req.params;

        // SECURITY: Verify the researcher is assigned to this supervisor
        const assignmentCheck = await pool.query(
            `SELECT 1 FROM di_supervisor_researchers WHERE supervisor_id = $1 AND researcher_id = $2`,
            [supervisorId, researcher_id]
        );
        if (assignmentCheck.rows.length === 0) {
            return res.status(403).json({ error: 'Access denied. Researcher not assigned to you.' });
        }

        // Get researcher info
        const researcherInfo = await pool.query(
            `SELECT name, institution_email, affiliation FROM di_allowlist WHERE researcher_id = $1`,
            [researcher_id]
        );

        // Get all submissions for this researcher (same query pattern as my-files)
        const result = await pool.query(
            `SELECT submission_id, file_type, original_filename, status, created_at, signed_at, drive_file_id
             FROM di_submissions
             WHERE researcher_id = $1
             ORDER BY created_at DESC`,
            [researcher_id]
        );

        // Build tree structure matching my-files format
        const submittedFiles = [];
        const approvedFiles = [];
        let pendingCount = 0, approvedCount = 0, revisionCount = 0;

        for (const file of result.rows) {
            const status = file.status || 'PENDING';
            const fileId = file.drive_file_id;
            const hasR2File = fileId && typeof fileId === 'string' && fileId.startsWith('r2:');

            const fileNode = {
                name: file.original_filename,
                type: 'file',
                id: file.submission_id,
                status: status,
                fileType: file.file_type,
                date: file.created_at,
                signedAt: file.signed_at,
                r2ObjectKey: hasR2File ? fileId.replace(/^r2:/, '') : null,
                viewUrl: hasR2File ? `/api/di/download/${file.submission_id}` : null,
                downloadUrl: hasR2File ? `/api/di/download/${file.submission_id}?download=true` : null
            };

            if (status === 'APPROVED') {
                approvedFiles.push(fileNode);
                approvedCount++;
            } else if (status === 'PENDING') {
                submittedFiles.push(fileNode);
                pendingCount++;
            } else if (status === 'REVISION_NEEDED') {
                revisionCount++;
            }
        }

        const tree = {
            name: researcherInfo.rows[0]?.name || researcher_id,
            type: 'folder',
            children: [
                { name: `Submitted (${pendingCount})`, type: 'folder', children: submittedFiles, count: pendingCount },
                { name: `Approved (${approvedCount})`, type: 'folder', children: approvedFiles, count: approvedCount }
            ]
        };

        res.json({
            success: true,
            researcher: researcherInfo.rows[0] || { researcher_id },
            tree: tree,
            totalFiles: result.rows.length,
            pendingCount, approvedCount, revisionCount
        });
    } catch (err) {
        console.error('Get researcher files error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// redeploy bump 2026-01-23T20:49:14















//
// Server start
//
app.listen(PORT, () => {
  console.log("[STARTUP] Server listening on port ");
});












