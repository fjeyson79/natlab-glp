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
const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand, CopyObjectCommand } = require('@aws-sdk/client-s3');
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
    limits: { fileSize: 20 * 1024 * 1024 }, // 20MB limit (PRESENTATION allows 20MB; SOP/DATA capped at 10MB in route)
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

// Multer config for inventory CSV uploads (separate from PDF upload)
const inventoryUpload = multer({
    storage: multer.memoryStorage(),
    limits: { fileSize: 5 * 1024 * 1024 }, // 5MB for CSV
    fileFilter: (req, file, cb) => {
        if ((file.originalname || '').toLowerCase().endsWith('.csv')) {
            return cb(null, true);
        }
        return cb(new Error('Only CSV files are accepted for inventory imports'), false);
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

// ─── NATLAB Naming v3 Parser ───
// IMPORTANT: This function is duplicated in server.js and pi-dashboard.html.
// Any change MUST be applied to BOTH copies identically.
// Server-side test cases validate correctness (see testParseNatlabFilename below).
function parseNatlabFilename(filename) {
    const NON_COMPLIANT = {
        parsed_date: null, parsed_initials: null, parsed_project: null,
        parsed_description: null, is_sop: false, is_compliant: false, raw: filename
    };

    const base = filename.replace(/\.[^.]+$/, '');
    const parts = base.split('_');

    if (parts.length < 4) return NON_COMPLIANT;

    const date = parts[0].trim();
    const initials = parts[1].trim();
    const slot2 = parts[2].trim();
    const slot3 = parts[3].trim();

    if (!date || !initials || !/^\d{4}-\d{2}-\d{2}$/.test(date) || !/^[A-Z]{2,4}$/.test(initials)) {
        return NON_COMPLIANT;
    }

    const is_sop = slot2 === 'SOP';
    const descTokens = parts.slice(3).map(t => t.trim()).filter(Boolean);
    const description = descTokens.join(' ').replace(/\s{2,}/g, ' ');

    if (is_sop) {
        if (!slot3) return NON_COMPLIANT;
        return {
            parsed_date: date, parsed_initials: initials, parsed_project: slot3,
            parsed_description: description, is_sop: true, is_compliant: true, raw: filename
        };
    }

    if (!slot2 || !slot3) return NON_COMPLIANT;
    return {
        parsed_date: date, parsed_initials: initials, parsed_project: slot2,
        parsed_description: description, is_sop: false, is_compliant: true, raw: filename
    };
}

(function testParseNatlabFilename() {
    let pass = 0, fail = 0;
    const t = (input, expect) => {
        const r = parseNatlabFilename(input);
        for (const [k, v] of Object.entries(expect)) {
            if (r[k] !== v) {
                console.error(`[PARSER TEST FAIL] "${input}": ${k} expected "${v}", got "${r[k]}"`);
                fail++; return;
            }
        }
        pass++;
    };
    t('2025-03-15_FH_RNase7_WeeklyPlateReader.pdf', {
        parsed_date: '2025-03-15', parsed_initials: 'FH', parsed_project: 'RNase7',
        parsed_description: 'WeeklyPlateReader', is_sop: false, is_compliant: true
    });
    t('2025-01-10_HJ_SOP_RNaseActivityAssay.pdf', {
        parsed_date: '2025-01-10', parsed_initials: 'HJ', parsed_project: 'RNaseActivityAssay',
        parsed_description: 'RNaseActivityAssay', is_sop: true, is_compliant: true
    });
    t('2025-06-01_AB_Proteomics_GroupMeetingResults.pdf', {
        parsed_date: '2025-06-01', parsed_initials: 'AB', parsed_project: 'Proteomics',
        parsed_description: 'GroupMeetingResults', is_sop: false, is_compliant: true
    });
    t('2025-04-20_FH_RNase7_ELISA_Batch3_Replicates.pdf', {
        parsed_date: '2025-04-20', parsed_initials: 'FH', parsed_project: 'RNase7',
        parsed_description: 'ELISA Batch3 Replicates', is_sop: false, is_compliant: true
    });
    t('random_file_upload.pdf', { parsed_date: null, parsed_project: null, is_compliant: false });
    t('2025-03-15_FH_RNase7.pdf', { is_compliant: false });
    t('2025-01-10_HJ_SOP.pdf', { is_compliant: false });
    t('2026-01-01_FH_RNase7_.pdf', { is_compliant: false });
    console.log(`[PARSER] parseNatlabFilename: ${pass} passed, ${fail} failed`);
})();

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

// INTERNAL MIDDLEWARE - blocks external affiliations from inventory
function requireInternal(req, res, next) {
    if (!req.session.user) {
        return res.status(401).json({ error: 'Not authenticated' });
    }
    if (req.session.user.affiliation === 'EXTERNAL') {
        return res.status(403).json({ error: 'Inventory access is restricted to internal members.' });
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

// Helper function to check if di_revision_requests table exists (migration 011)
let revisionRequestsTableExists = null;
let revisionRequestsTableLastCheck = 0;

async function checkRevisionRequestsTable() {
    const now = Date.now();
    if (revisionRequestsTableExists === null || revisionRequestsTableExists === false || (now - revisionRequestsTableLastCheck > ROLE_COLUMN_CHECK_INTERVAL)) {
        try {
            const result = await pool.query(`
                SELECT table_name FROM information_schema.tables
                WHERE table_name = 'di_revision_requests'
            `);
            revisionRequestsTableExists = result.rows.length > 0;
            revisionRequestsTableLastCheck = now;
        } catch (err) {
            revisionRequestsTableExists = false;
        }
    }
    return revisionRequestsTableExists;
}

// Helper function to check if di_file_associations table exists (migration 014)
let assocTableExists = null;
let assocTableLastCheck = 0;

async function checkAssociationsTable() {
    const now = Date.now();
    if (assocTableExists === null || assocTableExists === false || (now - assocTableLastCheck > ROLE_COLUMN_CHECK_INTERVAL)) {
        try {
            const result = await pool.query(`
                SELECT table_name FROM information_schema.tables
                WHERE table_name = 'di_file_associations'
            `);
            assocTableExists = result.rows.length > 0;
            assocTableLastCheck = now;
        } catch (err) {
            assocTableExists = false;
        }
    }
    return assocTableExists;
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
        const body = req.body || {};
        const institution_email = body.institution_email;

        if (!institution_email) {
            return res.status(400).json({ error: 'Email is required' });
        }
        const emailLower = String(institution_email).toLowerCase().trim();

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
        // Supervisors go to upload.html (same as researchers) but get additional supervision panel
        let redirectPage = 'upload.html';
        if (allowlistEntry.role === 'pi') redirectPage = 'pi-dashboard.html';

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
                      a.name, a.affiliation, a.active, COALESCE(a.role, 'researcher') as role,
                      COALESCE(u.force_password_reset, false) as force_password_reset
               FROM di_users u
               JOIN di_allowlist a ON u.researcher_id = a.researcher_id
               WHERE LOWER(u.institution_email) = $1`
            : `SELECT u.institution_email, u.password_hash, u.researcher_id,
                      a.name, a.affiliation, a.active, 'researcher' as role,
                      COALESCE(u.force_password_reset, false) as force_password_reset
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

        // Check if password reset is required
        if (user.force_password_reset) {
            // Store info in session for password reset page
            req.session.pendingPasswordReset = {
                researcher_id: user.researcher_id,
                institution_email: user.institution_email,
                name: user.name,
                affiliation: user.affiliation
            };
            return res.json({
                success: true,
                message: 'Password reset required',
                requirePasswordReset: true,
                redirect: 'reset-password.html'
            });
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
        // Supervisors go to upload.html (same as researchers) but get additional supervision panel
        let redirectPage = 'upload.html';
        if (user.role === 'pi') redirectPage = 'pi-dashboard.html';

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

// POST /api/di/complete-password-reset
// Complete a forced password reset (user sets new password)
app.post('/api/di/complete-password-reset', async (req, res) => {
    try {
        const { password } = req.body;

        // Check for pending password reset in session
        if (!req.session.pendingPasswordReset) {
            return res.status(403).json({ error: 'No pending password reset' });
        }

        if (!password || password.length < 8) {
            return res.status(400).json({ error: 'Password must be at least 8 characters' });
        }

        const { researcher_id, institution_email, name, affiliation } = req.session.pendingPasswordReset;

        // Hash new password
        const saltRounds = 10;
        const passwordHash = await bcrypt.hash(password, saltRounds);

        // Update password and clear the reset flag
        await pool.query(
            `UPDATE di_users
             SET password_hash = $1, force_password_reset = false, last_login = CURRENT_TIMESTAMP
             WHERE researcher_id = $2`,
            [passwordHash, researcher_id]
        );

        // Get user role for redirect
        const hasRole = await checkRoleColumn();
        const roleQuery = hasRole
            ? `SELECT COALESCE(role, 'researcher') as role FROM di_allowlist WHERE researcher_id = $1`
            : `SELECT 'researcher' as role FROM di_allowlist WHERE researcher_id = $1`;
        const roleResult = await pool.query(roleQuery, [researcher_id]);
        const role = roleResult.rows[0]?.role || 'researcher';

        // Clear pending reset and set normal session
        delete req.session.pendingPasswordReset;
        req.session.user = {
            institution_email,
            researcher_id,
            name,
            affiliation,
            role
        };

        // Determine redirect based on role
        // Supervisors go to upload.html (same as researchers) but get additional supervision panel
        let redirectPage = 'upload.html';
        if (role === 'pi') redirectPage = 'pi-dashboard.html';

        console.log(`Password reset completed for user ${researcher_id}`);

        res.json({
            success: true,
            message: 'Password updated successfully',
            redirect: redirectPage
        });

    } catch (err) {
        console.error('Complete password reset error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/pending-reset-info
// Get info for pending password reset (for reset-password.html)
app.get('/api/di/pending-reset-info', (req, res) => {
    if (!req.session.pendingPasswordReset) {
        return res.status(403).json({ error: 'No pending password reset' });
    }
    res.json({
        name: req.session.pendingPasswordReset.name,
        affiliation: req.session.pendingPasswordReset.affiliation
    });
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

        // Use di_revision_requests for accurate revision count (self-cleaning)
        if (await checkRevisionRequestsTable()) {
            const rrResult = await pool.query(
                `SELECT COUNT(*)::int as count FROM di_revision_requests WHERE researcher_id = $1 AND status = 'open'`,
                [user.researcher_id]
            );
            revisionCount = rrResult.rows[0].count;
        }

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
        if (!normalizedType || !['SOP', 'DATA', 'PRESENTATION'].includes(normalizedType)) {
            return res.status(400).json({ error: 'fileType must be SOP, DATA or PRESENTATION' });
        }

        if (!file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        if (file.mimetype !== 'application/pdf') {
            return res.status(400).json({ error: 'Only PDF files are accepted' });
        }

        const sizeLimit = normalizedType === 'PRESENTATION' ? 20 * 1024 * 1024 : 10 * 1024 * 1024;
        if (file.size > sizeLimit) {
            return res.status(400).json({ error: `File exceeds ${sizeLimit / (1024 * 1024)}MB limit` });
        }

        // Validate presentation metadata
        let presentationType = null;
        let presentationOther = null;
        if (normalizedType === 'PRESENTATION') {
            const validPresTypes = ['1 on 1 supervision', 'Group meeting', 'External presentation', 'Conference', 'Project Evaluation', 'Other'];
            presentationType = (req.body.presentation_type || '').trim();
            if (!presentationType || !validPresTypes.includes(presentationType)) {
                return res.status(400).json({ error: 'presentation_type is required for PRESENTATION uploads' });
            }
            if (presentationType === 'Other') {
                presentationOther = (req.body.presentation_other || '').trim();
                if (!presentationOther) {
                    return res.status(400).json({ error: 'presentation_other is required when presentation_type is Other' });
                }
            }
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
            'INSERT INTO di_submissions (researcher_id, affiliation, file_type, original_filename, drive_file_id, presentation_type, presentation_other) VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING submission_id',
            [user.researcher_id, user.affiliation, normalizedType, file.originalname, fileId, presentationType, presentationOther]
        );

        const submissionId = submissionResult.rows[0].submission_id;
        console.log('[UPLOAD] Submission recorded: submission_id=' + submissionId + ', drive_file_id=' + fileId);

        // Close revision request if this is a resubmission
        const revisionRequestId = req.body.revision_request_id;
        if (revisionRequestId && await checkRevisionRequestsTable()) {
            const closeResult = await pool.query(
                `UPDATE di_revision_requests SET status = 'closed', closed_at = NOW(), resubmitted_file_id = $1
                 WHERE id = $2 AND status = 'open'`,
                [submissionId, revisionRequestId]
            );
            if (closeResult.rowCount > 0) {
                console.log('[UPLOAD] Closed revision request: ' + revisionRequestId);
            }
        }

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

        if (!fileType || !['SOP', 'DATA', 'PRESENTATION'].includes(fileType)) {
            return res.status(400).json({ error: 'fileType must be SOP, DATA or PRESENTATION' });
        }

        if (!file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        // Validate presentation metadata for external uploads
        let extPresType = null;
        let extPresOther = null;
        if (fileType === 'PRESENTATION') {
            const validPresTypes = ['1 on 1 supervision', 'Group meeting', 'External presentation', 'Conference', 'Project Evaluation', 'Other'];
            extPresType = (req.body.presentation_type || '').trim();
            if (!extPresType || !validPresTypes.includes(extPresType)) {
                return res.status(400).json({ error: 'presentation_type is required for PRESENTATION uploads' });
            }
            if (extPresType === 'Other') {
                extPresOther = (req.body.presentation_other || '').trim();
                if (!extPresOther) {
                    return res.status(400).json({ error: 'presentation_other is required when presentation_type is Other' });
                }
            }
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
            `INSERT INTO di_submissions (researcher_id, affiliation, file_type, original_filename, presentation_type, presentation_other)
             VALUES ($1, $2, $3, $4, $5, $6)
             RETURNING submission_id`,
            [researcher_id, affiliation, fileType, file.originalname, extPresType, extPresOther]
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

// ─── Shared approval/revision helpers (used by token-based and inline endpoints) ───
async function performApproval(submissionId) {
    const result = await pool.query('SELECT * FROM di_submissions WHERE submission_id = $1', [submissionId]);
    if (result.rows.length === 0) return { success: false, error: 'Submission not found', status: 404 };

    const submission = result.rows[0];
    const fileId = (submission.drive_file_id || '').trim();
    const isR2 = fileId.startsWith('r2:');
    console.log(`[APPROVE] id=${submissionId} fileId=${fileId} isR2=${isR2}`);

    if (!isR2) return { success: false, error: 'Drive not configured. Only R2 supported.', status: 400 };
    if (!fileId) return { success: false, error: 'No file associated.', status: 400 };
    if (submission.status === 'APPROVED') return { success: false, error: 'Already approved.', status: 409 };

    const signedAt = new Date().toISOString();
    const signerName = 'Frank J. Hernandez';
    const originalKey = fileId.replace(/^r2:/, '');

    const r2Obj = await downloadFromR2(originalKey);
    const chunks = []; for await (const c of r2Obj.Body) chunks.push(c);
    const pdfBuffer = Buffer.concat(chunks);

    const stampedBuffer = await createStampedPdf(pdfBuffer, signerName, signedAt);

    const safeFilename = submission.original_filename.replace('.pdf', '_APPROVED.pdf').replace(/[^\w.\-]+/g, '_');
    const approvedKey = originalKey.replace('/Submitted/', '/Approved/').replace(/[^/]+$/, safeFilename);
    await uploadToR2(stampedBuffer, approvedKey, 'application/pdf');
    const newFileId = 'r2:' + approvedKey;

    try { await deleteFromR2(originalKey); } catch (e) { console.warn('[APPROVE] Delete warning:', e.message); }

    const crypto = require('crypto');
    const signatureHash = crypto.createHmac('sha256', process.env.API_SECRET_KEY || 'natlab_glp_secret')
        .update(JSON.stringify({ submission_id: submissionId, original_filename: submission.original_filename, signed_at: signedAt, signer: signerName }))
        .digest('hex');
    const verificationCode = `NATLAB-${submissionId}-${signatureHash.substring(0, 8).toUpperCase()}`;

    await pool.query(
        `UPDATE di_submissions SET status='APPROVED', signed_at=$1, signer_name=$2, drive_file_id=$3, signed_pdf_path=$3, signature_hash=$4, verification_code=$5 WHERE submission_id=$6`,
        [signedAt, signerName, newFileId, signatureHash, verificationCode, submissionId]
    );

    const researcherResult = await pool.query(
        'SELECT institution_email, researcher_id FROM di_allowlist WHERE researcher_id = $1',
        [submission.researcher_id]
    );
    if (researcherResult.rows.length > 0) {
        const researcher = researcherResult.rows[0];
        await notifyResearcher({
            submission_id: submissionId,
            decision: 'APPROVED',
            researcher_email: researcher.institution_email,
            researcher_name: researcher.researcher_id,
            file_name: submission.original_filename,
            affiliation: submission.affiliation,
            view_url: `https://natlab-glp-production.up.railway.app/api/di/download/${submissionId}`,
            download_url: `https://natlab-glp-production.up.railway.app/api/di/download/${submissionId}?download=true`,
            verification_code: verificationCode
        });
    }

    console.log(`[APPROVE] Success: ${submissionId} -> ${newFileId}`);
    return { success: true, verification_code: verificationCode, filename: submission.original_filename };
}

async function performRevision(submissionId, comments) {
    const result = await pool.query('SELECT drive_file_id, researcher_id, original_filename, affiliation, file_type, created_at FROM di_submissions WHERE submission_id = $1', [submissionId]);
    if (result.rows.length === 0) return { success: false, error: 'Submission not found', status: 404 };

    const submission = result.rows[0];
    const fileId = (submission.drive_file_id || '').trim();
    const isR2 = fileId.startsWith('r2:');
    console.log(`[REVISE] id=${submissionId} fileId=${fileId} isR2=${isR2}`);

    if (!isR2 && fileId) return { success: false, error: 'Drive not configured. Only R2 supported.', status: 400 };

    if (isR2) {
        try { await deleteFromR2(fileId.replace(/^r2:/, '')); } catch (e) { console.warn('[REVISE] Delete warning:', e.message); }
    }

    await pool.query(
        `UPDATE di_submissions SET status='REVISION_NEEDED', drive_file_id=NULL, revision_comments=$1 WHERE submission_id=$2`,
        [comments || '', submissionId]
    );

    if (await checkRevisionRequestsTable()) {
        const submissionYear = submission.created_at ? new Date(submission.created_at).getFullYear() : new Date().getFullYear();
        const docType = submission.file_type || 'SOP';
        const existing = await pool.query(
            `SELECT id FROM di_revision_requests WHERE file_id = $1 AND status = 'open'`,
            [submissionId]
        );
        if (existing.rows.length > 0) {
            await pool.query(
                `UPDATE di_revision_requests SET pi_comment = $1 WHERE id = $2`,
                [comments || '', existing.rows[0].id]
            );
        } else {
            await pool.query(
                `INSERT INTO di_revision_requests (file_id, researcher_id, year, doc_type, filename, pi_comment)
                 VALUES ($1, $2, $3, $4, $5, $6)`,
                [submissionId, submission.researcher_id, submissionYear, docType, submission.original_filename, comments || '']
            );
        }
    }

    const researcherResult = await pool.query(
        'SELECT institution_email, researcher_id FROM di_allowlist WHERE researcher_id = $1',
        [submission.researcher_id]
    );
    if (researcherResult.rows.length > 0) {
        const researcher = researcherResult.rows[0];
        await notifyResearcher({
            submission_id: submissionId,
            decision: 'REVISION_NEEDED',
            researcher_email: researcher.institution_email,
            researcher_name: researcher.researcher_id,
            file_name: submission.original_filename,
            affiliation: submission.affiliation,
            pi_comments: comments || ''
        });
    }

    console.log(`[REVISE] Success: ${submissionId} marked for revision`);
    return { success: true, filename: submission.original_filename };
}

// GET /api/di/approve/:id - R2 only, no Drive (token-based)
app.get('/api/di/approve/:id', async (req, res) => {
    const { id } = req.params;
    const { token } = req.query;
    try {
        if (!token) return res.status(400).send(renderHtmlPage('Error', 'Missing token', 'error'));
        const expectedToken = Buffer.from(id + '_glp_2024_sec').toString('base64').replace(/[^a-zA-Z0-9]/g, '').substring(0, 32);
        if (token !== expectedToken) return res.status(403).send(renderHtmlPage('Invalid Token', 'Link invalid or expired.', 'error'));

        const result = await performApproval(id);
        if (!result.success) {
            const tpl = result.status === 409 ? 'info' : 'error';
            return res.status(result.status || 500).send(renderHtmlPage('Error', result.error, tpl));
        }

        res.redirect(`/di/action-success.html?action=approved&file=${encodeURIComponent(result.filename)}&id=${id}`);
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

// POST /api/di/revise/:id - R2 only, no Drive (token-based)
app.post('/api/di/revise/:id', async (req, res) => {
    const { id } = req.params;
    const { token } = req.query;
    const { comments } = req.body;
    try {
        if (!token) return res.status(400).send(renderHtmlPage('Error', 'Missing token', 'error'));
        const expectedToken = Buffer.from(id + '_glp_2024_sec').toString('base64').replace(/[^a-zA-Z0-9]/g, '').substring(0, 32);
        if (token !== expectedToken) return res.status(403).send(renderHtmlPage('Invalid Token', 'Link invalid or expired.', 'error'));

        const result = await performRevision(id, comments);
        if (!result.success) {
            return res.status(result.status || 500).send(renderHtmlPage('Error', result.error, 'error'));
        }

        res.redirect(`/di/action-success.html?action=revision&file=${encodeURIComponent(result.filename)}&id=${id}`);
    } catch (err) {
        console.error('[REVISE] Error:', err);
        res.status(500).send(renderHtmlPage('Error', err.message, 'error'));
    }
});

// =====================================================
// Revision Requests endpoints (migration 011)
// =====================================================

// GET /api/di/revision-requests/open-count
// Lightweight count for current researcher (or all for PI)
app.get('/api/di/revision-requests/open-count', requireAuth, async (req, res) => {
    try {
        if (!await checkRevisionRequestsTable()) {
            return res.json({ open_count: 0 });
        }
        const user = req.session.user;
        const isPI = user.role === 'pi';
        let result;
        if (isPI) {
            result = await pool.query(`SELECT COUNT(*)::int as count FROM di_revision_requests WHERE status = 'open'`);
        } else {
            result = await pool.query(`SELECT COUNT(*)::int as count FROM di_revision_requests WHERE researcher_id = $1 AND status = 'open'`, [user.researcher_id]);
        }
        res.json({ open_count: result.rows[0].count });
    } catch (err) {
        console.error('[REVISION-REQUESTS] open-count error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/revision-requests/open
// Researcher's own open revision requests (for dropdown)
app.get('/api/di/revision-requests/open', requireAuth, async (req, res) => {
    try {
        if (!await checkRevisionRequestsTable()) {
            return res.json({ requests: [] });
        }
        const user = req.session.user;
        const result = await pool.query(
            `SELECT id, file_id, researcher_id, year, doc_type, filename, pi_comment, created_at
             FROM di_revision_requests
             WHERE researcher_id = $1 AND status = 'open'
             ORDER BY created_at DESC`,
            [user.researcher_id]
        );
        res.json({ requests: result.rows });
    } catch (err) {
        console.error('[REVISION-REQUESTS] open error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/revision-requests/all
// All open revision requests for PI Lab Files view
app.get('/api/di/revision-requests/all', requirePI, async (req, res) => {
    try {
        if (!await checkRevisionRequestsTable()) {
            return res.json({ requests: [] });
        }
        const result = await pool.query(
            `SELECT rr.id, rr.file_id, rr.researcher_id, rr.year, rr.doc_type, rr.filename,
                    rr.pi_comment, rr.created_at,
                    COALESCE(a.name, rr.researcher_id) as researcher_name
             FROM di_revision_requests rr
             LEFT JOIN di_allowlist a ON rr.researcher_id = a.researcher_id
             WHERE rr.status = 'open'
             ORDER BY rr.created_at DESC`
        );
        res.json({ requests: result.rows });
    } catch (err) {
        console.error('[REVISION-REQUESTS] all error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/revision-requests/:id/cancel
// PI cancels a revision request (soft delete)
app.post('/api/di/revision-requests/:id/cancel', requirePI, async (req, res) => {
    try {
        if (!await checkRevisionRequestsTable()) {
            return res.status(404).json({ error: 'Feature not available' });
        }
        const result = await pool.query(
            `UPDATE di_revision_requests SET status = 'cancelled', closed_at = NOW()
             WHERE id = $1 AND status = 'open'`,
            [req.params.id]
        );
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Revision request not found or already closed' });
        }
        res.json({ success: true });
    } catch (err) {
        console.error('[REVISION-REQUESTS] cancel error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// PATCH /api/di/revision-requests/:id/comment
// PI edits comment on an open revision request
app.patch('/api/di/revision-requests/:id/comment', requirePI, async (req, res) => {
    try {
        if (!await checkRevisionRequestsTable()) {
            return res.status(404).json({ error: 'Feature not available' });
        }
        const { comment } = req.body;
        const result = await pool.query(
            `UPDATE di_revision_requests SET pi_comment = $1 WHERE id = $2 AND status = 'open'`,
            [comment || '', req.params.id]
        );
        if (result.rowCount === 0) {
            return res.status(404).json({ error: 'Revision request not found or already closed' });
        }
        res.json({ success: true });
    } catch (err) {
        console.error('[REVISION-REQUESTS] comment error:', err);
        res.status(500).json({ error: 'Server error' });
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
        const { name, institution_email, affiliation, role } = req.body;
        let { researcher_id } = req.body;

        // Validate required fields
        if (!name || !institution_email || !affiliation) {
            return res.status(400).json({ error: 'Name, email, and affiliation are required' });
        }

        if (!['LiU', 'UNAV', 'EXTERNAL'].includes(affiliation)) {
            return res.status(400).json({ error: 'Affiliation must be LiU, UNAV, or EXTERNAL' });
        }

        const emailLower = institution_email.toLowerCase().trim();

        // Domain validation for LIU and UNAV
        if (affiliation === 'LiU' && !emailLower.endsWith('@liu.se')) {
            return res.status(400).json({ error: 'LiU affiliation requires @liu.se email' });
        }
        if (affiliation === 'UNAV' && !emailLower.endsWith('@unav.es') && !emailLower.endsWith('@alumni.unav.es')) {
            return res.status(400).json({ error: 'UNAV affiliation requires @unav.es or @alumni.unav.es email' });
        }

        // Auto-generate researcher_id from email if not provided
        if (!researcher_id) {
            researcher_id = emailLower.split('@')[0].replace(/[^a-z0-9]/g, '.');
        }

        const memberRole = role || 'researcher';
        if (!['researcher', 'supervisor', 'pi'].includes(memberRole)) {
            return res.status(400).json({ error: 'Role must be researcher, supervisor, or pi' });
        }

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

        if (!fileType || !['SOP', 'DATA', 'PRESENTATION'].includes(fileType)) {
            return res.status(400).json({ error: 'fileType must be SOP, DATA or PRESENTATION' });
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

// =====================================================
// DIC (Data Intelligence Console) ENDPOINTS
// =====================================================

// GET /api/di/lab-files-enriched — Performance-bounded with association counts
app.get('/api/di/lab-files-enriched', requirePI, async (req, res) => {
    try {
        const months = Math.min(Math.max(parseInt(req.query.months) || 12, 6), 60);
        const hasAssoc = await checkAssociationsTable();

        // Implementation note: structured for easy future extension with ?researcher_id=
        const conditions = ['s.created_at >= NOW() - make_interval(months => $1)'];
        const params = [months];

        const whereClause = conditions.length ? 'WHERE ' + conditions.join(' AND ') : '';

        const query = hasAssoc
            ? `SELECT s.submission_id, s.researcher_id, s.original_filename, s.file_type,
                      s.status, s.created_at, s.signed_at, s.ai_review,
                      s.pi_dragon_seal,
                      COALESCE(s.drive_file_id, s.signed_pdf_path) as r2_object_key,
                      a.name as researcher_name, a.affiliation,
                      COALESCE(sop_c.cnt, 0)::int as linked_sop_count,
                      COALESCE(pres_c.cnt, 0)::int as linked_pres_count
               FROM di_submissions s
               LEFT JOIN di_allowlist a ON s.researcher_id = a.researcher_id
               LEFT JOIN (SELECT source_id, COUNT(*) as cnt FROM di_file_associations
                          WHERE link_type='SOP' GROUP BY source_id) sop_c
                          ON s.submission_id = sop_c.source_id
               LEFT JOIN (SELECT source_id, COUNT(*) as cnt FROM di_file_associations
                          WHERE link_type='PRESENTATION' GROUP BY source_id) pres_c
                          ON s.submission_id = pres_c.source_id
               ${whereClause}
               ORDER BY s.created_at DESC`
            : `SELECT s.submission_id, s.researcher_id, s.original_filename, s.file_type,
                      s.status, s.created_at, s.signed_at, s.ai_review,
                      s.pi_dragon_seal,
                      COALESCE(s.drive_file_id, s.signed_pdf_path) as r2_object_key,
                      a.name as researcher_name, a.affiliation,
                      0 as linked_sop_count, 0 as linked_pres_count
               FROM di_submissions s
               LEFT JOIN di_allowlist a ON s.researcher_id = a.researcher_id
               ${whereClause}
               ORDER BY s.created_at DESC`;

        const result = await pool.query(query, params);
        res.json({ success: true, months_used: months, files: result.rows });
    } catch (err) {
        console.error('Get enriched lab files error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/researcher-file-metrics — Per-researcher counts
app.get('/api/di/researcher-file-metrics', requirePI, async (req, res) => {
    try {
        const result = await pool.query(`
            SELECT s.researcher_id, a.name as researcher_name,
                COUNT(*)::int as total_count,
                COUNT(*) FILTER (WHERE s.file_type='DATA')::int as data_count,
                COUNT(*) FILTER (WHERE s.file_type='PRESENTATION')::int as pres_count,
                COUNT(*) FILTER (WHERE s.file_type='SOP')::int as sop_count,
                COUNT(*) FILTER (WHERE s.status='PENDING')::int as pending_count,
                MAX(s.created_at) as last_upload
            FROM di_submissions s
            LEFT JOIN di_allowlist a ON s.researcher_id = a.researcher_id
            GROUP BY s.researcher_id, a.name
            ORDER BY a.name
        `);
        res.json({ success: true, metrics: result.rows });
    } catch (err) {
        console.error('Get researcher metrics error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/file-associations/:id — Manual links + heuristic suggestions
app.get('/api/di/file-associations/:id', requirePI, async (req, res) => {
    try {
        const sourceFileId = req.params.id;
        const hasAssoc = await checkAssociationsTable();

        // Get source file
        const srcResult = await pool.query('SELECT * FROM di_submissions WHERE submission_id = $1', [sourceFileId]);
        if (srcResult.rows.length === 0) return res.status(404).json({ error: 'File not found' });
        const sourceFile = srcResult.rows[0];
        const sourceParsed = parseNatlabFilename(sourceFile.original_filename);

        // Manual links
        let manual = [];
        if (hasAssoc) {
            const manualResult = await pool.query(`
                SELECT fa.id, fa.target_id, fa.link_type, fa.created_at,
                       s.original_filename, s.status, s.created_at as file_created_at,
                       a.name as researcher_name
                FROM di_file_associations fa
                JOIN di_submissions s ON fa.target_id = s.submission_id
                LEFT JOIN di_allowlist a ON s.researcher_id = a.researcher_id
                WHERE fa.source_id = $1
                ORDER BY fa.link_type, fa.created_at DESC
            `, [sourceFileId]);
            manual = manualResult.rows;
        }

        // Heuristic helper
        function resolveDate(parsed, createdAt) {
            return parsed.is_compliant && parsed.parsed_date
                ? new Date(parsed.parsed_date)
                : new Date(createdAt);
        }

        function scoreCandidate(candidate) {
            const cParsed = parseNatlabFilename(candidate.original_filename);
            const sDate = resolveDate(sourceParsed, sourceFile.created_at);
            const cDate = resolveDate(cParsed, candidate.created_at);

            const daysBetween = Math.abs((sDate - cDate) / (1000 * 60 * 60 * 24));

            let score = 0;
            // Same project (40)
            if (sourceParsed.is_compliant && cParsed.is_compliant &&
                sourceParsed.parsed_project && cParsed.parsed_project &&
                sourceParsed.parsed_project.toLowerCase() === cParsed.parsed_project.toLowerCase()) {
                score += 40;
            }
            // Time proximity within 30d (25)
            score += 25 * Math.max(0, 1 - daysBetween / 30);
            // Description token overlap (15)
            if (sourceParsed.is_compliant && cParsed.is_compliant &&
                sourceParsed.parsed_description && cParsed.parsed_description) {
                const sTokens = new Set(sourceParsed.parsed_description.toLowerCase().split(/\s+/).filter(t => t.length >= 3));
                const cTokens = new Set(cParsed.parsed_description.toLowerCase().split(/\s+/).filter(t => t.length >= 3));
                const intersection = [...sTokens].filter(t => cTokens.has(t)).length;
                const union = new Set([...sTokens, ...cTokens]).size;
                if (union > 0) score += 15 * (intersection / union);
            }
            // Same year (10)
            if (sDate.getFullYear() === cDate.getFullYear()) score += 10;
            // Approved bonus (10)
            if (candidate.status === 'APPROVED') score += 10;

            return { ...candidate, score: Math.round(score * 10) / 10, filename: candidate.original_filename };
        }

        // Heuristic SOP candidates
        let heuristic_sops = [];
        const sopExclusion = hasAssoc
            ? `AND NOT EXISTS (SELECT 1 FROM di_file_associations fa WHERE fa.source_id = $2 AND fa.target_id = s.submission_id AND fa.link_type = 'SOP')`
            : '';
        const sopResult = await pool.query(`
            SELECT s.submission_id, s.researcher_id, s.original_filename, s.status, s.created_at
            FROM di_submissions s
            WHERE s.file_type = 'SOP' AND s.researcher_id = $1 AND s.submission_id != $2
            ${sopExclusion}
            ORDER BY s.created_at DESC LIMIT 30
        `, [sourceFile.researcher_id, sourceFileId]);
        heuristic_sops = sopResult.rows.map(scoreCandidate).sort((a, b) => b.score - a.score).slice(0, 2);

        // Heuristic PRES candidates
        let heuristic_presentations = [];
        const presExclusion = hasAssoc
            ? `AND NOT EXISTS (SELECT 1 FROM di_file_associations fa WHERE fa.source_id = $2 AND fa.target_id = s.submission_id AND fa.link_type = 'PRESENTATION')`
            : '';
        const presResult = await pool.query(`
            SELECT s.submission_id, s.researcher_id, s.original_filename, s.status, s.created_at
            FROM di_submissions s
            WHERE s.file_type = 'PRESENTATION' AND s.researcher_id = $1 AND s.submission_id != $2
            ${presExclusion}
            ORDER BY s.created_at DESC LIMIT 30
        `, [sourceFile.researcher_id, sourceFileId]);
        heuristic_presentations = presResult.rows.map(scoreCandidate).sort((a, b) => b.score - a.score).slice(0, 2);

        res.json({ success: true, manual, heuristic_sops, heuristic_presentations });
    } catch (err) {
        console.error('Get file associations error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/file-associations — Create manual link
app.post('/api/di/file-associations', requirePI, async (req, res) => {
    try {
        if (!await checkAssociationsTable()) return res.status(404).json({ error: 'Feature not available' });

        const { source_id, target_id, link_type } = req.body;
        if (!source_id || !target_id || !link_type) return res.status(400).json({ error: 'Missing required fields' });
        if (!['SOP', 'PRESENTATION'].includes(link_type)) return res.status(400).json({ error: 'Invalid link_type' });
        if (source_id === target_id) return res.status(400).json({ error: 'Cannot link a file to itself' });

        const created_by = req.session.user.researcher_id || req.session.user.email || 'pi';
        await pool.query(
            `INSERT INTO di_file_associations (source_id, target_id, link_type, created_by) VALUES ($1, $2, $3, $4)`,
            [source_id, target_id, link_type, created_by]
        );
        res.json({ success: true });
    } catch (err) {
        if (err.code === '23505') return res.status(409).json({ error: 'Association already exists' });
        if (err.code === '23514') return res.status(400).json({ error: 'Invalid association' });
        console.error('Create file association error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// DELETE /api/di/file-associations/:id — Remove manual link
app.delete('/api/di/file-associations/:id', requirePI, async (req, res) => {
    try {
        if (!await checkAssociationsTable()) return res.status(404).json({ error: 'Feature not available' });
        const result = await pool.query('DELETE FROM di_file_associations WHERE id = $1', [req.params.id]);
        if (result.rowCount === 0) return res.status(404).json({ error: 'Association not found' });
        res.json({ success: true });
    } catch (err) {
        console.error('Delete file association error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/approve-inline/:id — Session-based approval (DIC)
app.post('/api/di/approve-inline/:id', requirePI, async (req, res) => {
    try {
        const result = await performApproval(req.params.id);
        if (!result.success) return res.status(result.status || 500).json({ error: result.error });
        res.json({ success: true, verification_code: result.verification_code });
    } catch (err) {
        console.error('[APPROVE-INLINE] Error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/revise-inline/:id — Session-based revision (DIC)
app.post('/api/di/revise-inline/:id', requirePI, async (req, res) => {
    try {
        const { comments } = req.body;
        const result = await performRevision(req.params.id, comments);
        if (!result.success) return res.status(result.status || 500).json({ error: result.error });
        res.json({ success: true });
    } catch (err) {
        console.error('[REVISE-INLINE] Error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/documents/:id/dragon-seal — Toggle PI Dragon Seal
app.post('/api/di/documents/:id/dragon-seal', requirePI, async (req, res) => {
    try {
        const { enabled } = req.body;
        if (typeof enabled !== 'boolean') {
            return res.status(400).json({ error: 'enabled must be a boolean' });
        }
        const result = await pool.query(
            'UPDATE di_submissions SET pi_dragon_seal = $1 WHERE submission_id = $2 RETURNING submission_id, pi_dragon_seal',
            [enabled, req.params.id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'File not found' });
        }
        res.json({ success: true, pi_dragon_seal: result.rows[0].pi_dragon_seal });
    } catch (err) {
        console.error('Dragon seal toggle error:', err);
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

        // Check for active inventory items (non-blocking warning)
        let inventoryWarning = null;
        try {
            const invCheck = await pool.query(
                `SELECT COUNT(*) as cnt FROM di_inventory WHERE responsible_type = 'user' AND responsible_user_id = $1 AND status = 'Active'`,
                [id]
            );
            const cnt = parseInt(invCheck.rows[0].cnt, 10);
            if (cnt > 0) inventoryWarning = { count: cnt };
        } catch (invErr) { /* non-blocking */ }

        res.json({
            success: true,
            message: 'User deactivated successfully',
            member: result.rows[0],
            inventory_warning: inventoryWarning
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

// POST /api/di/members/:id/reset-password
// Force a user to reset password on next login (PI only)
// Only works for researcher and supervisor roles, not PI
app.post('/api/di/members/:id/reset-password', requirePI, async (req, res) => {
    try {
        const { id } = req.params;

        // Get user info and verify they exist and have appropriate role
        const userResult = await pool.query(
            `SELECT a.researcher_id, a.name, COALESCE(a.role, 'researcher') as role, u.institution_email
             FROM di_allowlist a
             LEFT JOIN di_users u ON a.researcher_id = u.researcher_id
             WHERE a.researcher_id = $1 AND a.active = true`,
            [id]
        );

        if (userResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found or inactive' });
        }

        const user = userResult.rows[0];

        // Prevent resetting password for PI accounts
        if (user.role === 'pi') {
            return res.status(403).json({ error: 'Cannot reset password for PI accounts' });
        }

        // Check if user has registered (has a row in di_users)
        if (!user.institution_email) {
            return res.status(400).json({ error: 'User has not registered yet - no password to reset' });
        }

        // Set force_password_reset flag
        await pool.query(
            `UPDATE di_users SET force_password_reset = true WHERE researcher_id = $1`,
            [id]
        );

        console.log(`Password reset flagged for user ${id} by PI ${req.session.user.researcher_id}`);

        res.json({
            success: true,
            message: `Password reset required for ${user.name || id} on next login`
        });

    } catch (err) {
        console.error('Reset password error:', err);
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

        // Get open revision requests count (from dedicated table)
        let openRevisionRequests = null;
        if (await checkRevisionRequestsTable()) {
            const rrResult = await pool.query(`SELECT COUNT(*)::int as count FROM di_revision_requests WHERE status = 'open'`);
            openRevisionRequests = rrResult.rows[0].count;
        }

        res.json({
            success: true,
            total,
            byStatus,
            openRevisionRequests,
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

        // Use di_revision_requests for accurate revision count (self-cleaning)
        if (await checkRevisionRequestsTable()) {
            const rrResult = await pool.query(
                `SELECT COUNT(*)::int as count FROM di_revision_requests WHERE researcher_id = $1 AND status = 'open'`,
                [researcher_id]
            );
            revisionCount = rrResult.rows[0].count;
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

// =====================================================
// BACKUP & RECOVERY (AWS S3) — PI only
// =====================================================
const { ListObjectsV2Command, HeadObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl: backupGetSignedUrl } = require('@aws-sdk/s3-request-presigner');

function backupS3Enabled() {
  return !!(process.env.AWS_ACCESS_KEY_ID && process.env.AWS_SECRET_ACCESS_KEY &&
            process.env.AWS_S3_BACKUP_BUCKET && process.env.AWS_REGION);
}

let _backupS3Client = null;
function getBackupS3Client() {
  if (_backupS3Client) return _backupS3Client;
  _backupS3Client = new S3Client({
    region: process.env.AWS_REGION,
    credentials: {
      accessKeyId: process.env.AWS_ACCESS_KEY_ID,
      secretAccessKey: process.env.AWS_SECRET_ACCESS_KEY
    }
  });
  return _backupS3Client;
}

// Count objects under a prefix without collecting keys
async function countS3Objects(s3, bucket, prefix) {
  let count = 0;
  let totalBytes = 0;
  let token;
  do {
    const resp = await s3.send(new ListObjectsV2Command({
      Bucket: bucket, Prefix: prefix, ContinuationToken: token
    }));
    if (resp.Contents) {
      count += resp.Contents.length;
      for (const o of resp.Contents) totalBytes += (o.Size || 0);
    }
    token = resp.IsTruncated ? resp.NextContinuationToken : undefined;
  } while (token);
  return { count, totalBytes };
}

// Iterate backup objects page by page, calling fn(object) for each
async function forEachBackupObject(s3, bucket, prefix, fn) {
  let token;
  do {
    const resp = await s3.send(new ListObjectsV2Command({
      Bucket: bucket, Prefix: prefix, ContinuationToken: token
    }));
    if (resp.Contents) {
      for (const obj of resp.Contents) await fn(obj);
    }
    token = resp.IsTruncated ? resp.NextContinuationToken : undefined;
  } while (token);
}

// Check if object exists in R2, return { exists, size } or { exists: false }
async function headR2Object(key) {
  try {
    const resp = await getR2Client().send(new HeadObjectCommand({
      Bucket: process.env.R2_BUCKET, Key: key
    }));
    return { exists: true, size: resp.ContentLength || 0 };
  } catch (e) {
    if (e.name === 'NotFound' || e.$metadata?.httpStatusCode === 404) {
      return { exists: false, size: 0 };
    }
    throw e;
  }
}

// Stream-copy a single object from backup S3 to R2
async function streamCopyToR2(backupS3, backupBucket, sourceKey, destKey) {
  const getResp = await backupS3.send(new GetObjectCommand({
    Bucket: backupBucket, Key: sourceKey
  }));
  const contentLength = getResp.ContentLength;
  const contentType = getResp.ContentType || 'application/octet-stream';
  // If ContentLength is known, stream directly; otherwise buffer
  if (contentLength != null) {
    await getR2Client().send(new PutObjectCommand({
      Bucket: process.env.R2_BUCKET,
      Key: destKey,
      Body: getResp.Body,
      ContentLength: contentLength,
      ContentType: contentType
    }));
  } else {
    const buffer = await streamToBuffer(getResp.Body);
    await uploadToR2(buffer, destKey, contentType);
  }
}

// --- GET /api/di/backup/snapshots ---
app.get('/api/di/backup/snapshots', requirePI, async (req, res) => {
  try {
    if (!backupS3Enabled()) return res.status(503).json({ error: 'Backup storage not configured' });
    const s3 = getBackupS3Client();
    const bucket = process.env.AWS_S3_BACKUP_BUCKET;
    const snapshots = [];

    // Check daily/ and weekly/ for sub-prefixes
    for (const pfx of ['daily/', 'weekly/']) {
      const resp = await s3.send(new ListObjectsV2Command({
        Bucket: bucket, Prefix: pfx, Delimiter: '/'
      }));
      if (resp.CommonPrefixes) {
        for (const cp of resp.CommonPrefixes) {
          snapshots.push({
            path: cp.Prefix.replace(/\/$/, ''),
            type: pfx.replace('/', ''),
            label: cp.Prefix.replace(pfx, '').replace(/\/$/, '')
          });
        }
      }
    }

    // Check if latest/ has any objects
    const latestResp = await s3.send(new ListObjectsV2Command({
      Bucket: bucket, Prefix: 'latest/', MaxKeys: 1
    }));
    if (latestResp.Contents && latestResp.Contents.length > 0) {
      snapshots.push({ path: 'latest', type: 'latest', label: 'latest' });
    }

    res.json({ success: true, snapshots });
  } catch (err) {
    console.error('[BACKUP] List snapshots error:', err);
    res.status(500).json({ error: 'Failed to list snapshots' });
  }
});

// --- POST /api/di/backup/preview (summary only) ---
app.post('/api/di/backup/preview', requirePI, async (req, res) => {
  try {
    if (!backupS3Enabled()) return res.status(503).json({ error: 'Backup storage not configured' });
    if (!r2Enabled()) return res.status(503).json({ error: 'R2 storage not configured' });

    const { snapshot } = req.body;
    if (!snapshot || typeof snapshot !== 'string') {
      return res.status(400).json({ error: 'Missing snapshot parameter' });
    }
    if (!/^(daily\/(latest|[\d-]+)|weekly\/(latest|[\d\-W]+)|latest)$/.test(snapshot)) {
      return res.status(400).json({ error: 'Invalid snapshot path' });
    }

    const backupPrefix = snapshot + '/di/';
    const [backupStats, r2Stats] = await Promise.all([
      countS3Objects(getBackupS3Client(), process.env.AWS_S3_BACKUP_BUCKET, backupPrefix),
      countS3Objects(getR2Client(), process.env.R2_BUCKET, 'di/')
    ]);

    const estimatedDifference = Math.abs(backupStats.count - r2Stats.count);
    const label = snapshot.replace('/', ' / ');
    const summaryText = `Backup snapshot contains ${backupStats.count} files, current storage contains ${r2Stats.count} files. Estimated difference: ${estimatedDifference} files.`;

    res.json({
      success: true,
      snapshot,
      snapshotLabel: label,
      backupFileCount: backupStats.count,
      r2FileCount: r2Stats.count,
      estimatedDifference,
      backupTotalBytes: backupStats.totalBytes,
      r2TotalBytes: r2Stats.totalBytes,
      summaryText
    });
  } catch (err) {
    console.error('[BACKUP] Preview error:', err);
    res.status(500).json({ error: 'Failed to generate preview' });
  }
});

// --- POST /api/di/backup/recover ---
app.post('/api/di/backup/recover', requirePI, async (req, res) => {
  try {
    if (!backupS3Enabled()) return res.status(503).json({ error: 'Backup storage not configured' });
    if (!r2Enabled()) return res.status(503).json({ error: 'R2 storage not configured' });

    const { snapshot, mode, confirm } = req.body;
    if (!snapshot || typeof snapshot !== 'string') {
      return res.status(400).json({ error: 'Missing snapshot' });
    }
    if (!/^(daily\/(latest|[\d-]+)|weekly\/(latest|[\d\-W]+)|latest)$/.test(snapshot)) {
      return res.status(400).json({ error: 'Invalid snapshot path' });
    }
    if (mode !== 'add-missing' && mode !== 'full-restore') {
      return res.status(400).json({ error: 'Invalid mode. Use "add-missing" or "full-restore".' });
    }
    if (confirm !== true) {
      return res.status(400).json({ error: 'Confirmation required. Send confirm: true.' });
    }

    const piUser = req.session.user.researcher_id;
    const startTime = new Date().toISOString();
    console.log(`[BACKUP-RECOVER] Started by ${piUser}: mode=${mode}, snapshot=${snapshot}, start=${startTime}`);

    const backupS3 = getBackupS3Client();
    const backupBucket = process.env.AWS_S3_BACKUP_BUCKET;
    const backupPrefix = snapshot + '/di/';

    let processed = 0, copied = 0, skipped = 0, failed = 0;
    const errors = [];

    await forEachBackupObject(backupS3, backupBucket, backupPrefix, async (obj) => {
      const relKey = obj.Key;
      const destKey = relKey.replace(snapshot + '/', '');
      if (!destKey.startsWith('di/')) return; // hard scope

      processed++;
      try {
        const head = await headR2Object(destKey);

        if (mode === 'add-missing') {
          if (head.exists) { skipped++; return; }
        } else {
          // full-restore: skip if exists and same size
          if (head.exists && head.size === (obj.Size || 0)) { skipped++; return; }
        }

        await streamCopyToR2(backupS3, backupBucket, relKey, destKey);
        copied++;
      } catch (copyErr) {
        failed++;
        if (errors.length < 10) errors.push({ key: destKey, error: copyErr.message });
        console.error(`[BACKUP-RECOVER] Failed ${destKey}:`, copyErr.message);
      }
    });

    const endTime = new Date().toISOString();
    console.log(`[BACKUP-RECOVER] Complete by ${piUser}: mode=${mode}, snapshot=${snapshot}, processed=${processed}, copied=${copied}, skipped=${skipped}, failed=${failed}, start=${startTime}, end=${endTime}`);

    res.json({ success: true, mode, snapshot, processed, copied, skipped, failed, errors });
  } catch (err) {
    console.error('[BACKUP-RECOVER] Fatal error:', err);
    res.status(500).json({ error: 'Recovery failed: ' + err.message });
  }
});

// --- GET /api/di/backup/exports ---
app.get('/api/di/backup/exports', requirePI, async (req, res) => {
  try {
    if (!backupS3Enabled()) return res.status(503).json({ error: 'Backup storage not configured' });
    const exports = [];
    await forEachBackupObject(getBackupS3Client(), process.env.AWS_S3_BACKUP_BUCKET, 'exports/', (obj) => {
      const key = obj.Key;
      if (!key.endsWith('.zip')) return;
      const parts = key.split('/');
      exports.push({
        key,
        date: parts.length >= 3 ? parts[1] : 'unknown',
        name: parts[parts.length - 1],
        size: obj.Size || 0,
        lastModified: obj.LastModified
      });
    });
    exports.sort((a, b) => b.date.localeCompare(a.date));
    res.json({ success: true, exports });
  } catch (err) {
    console.error('[BACKUP] List exports error:', err);
    res.status(500).json({ error: 'Failed to list exports' });
  }
});

// --- POST /api/di/backup/export-url ---
app.post('/api/di/backup/export-url', requirePI, async (req, res) => {
  try {
    if (!backupS3Enabled()) return res.status(503).json({ error: 'Backup storage not configured' });
    const { key } = req.body;
    if (!key || typeof key !== 'string') return res.status(400).json({ error: 'Missing key' });
    if (!key.startsWith('exports/') || !key.endsWith('.zip')) {
      return res.status(400).json({ error: 'Invalid export key' });
    }

    const s3 = getBackupS3Client();
    const bucket = process.env.AWS_S3_BACKUP_BUCKET;

    // Verify object exists
    try {
      await s3.send(new HeadObjectCommand({ Bucket: bucket, Key: key }));
    } catch (headErr) {
      return res.status(404).json({ error: 'Export archive not found' });
    }

    const url = await backupGetSignedUrl(s3, new GetObjectCommand({
      Bucket: bucket, Key: key
    }), { expiresIn: 900 });

    console.log(`[BACKUP] Pre-signed URL for ${key} by ${req.session.user.researcher_id}`);
    res.json({ success: true, url, expiresIn: 900 });
  } catch (err) {
    console.error('[BACKUP] Export URL error:', err);
    res.status(500).json({ error: 'Failed to generate download URL' });
  }
});

// =====================================================
// BACKUP DOWNLOAD — R2 on-demand ZIP (PI only)
// =====================================================

// Download guardrail constants
const DL_MAX_SINGLE_FILES = 500;
const DL_MAX_SINGLE_BYTES = 500 * 1024 * 1024;       // 500 MB
const DL_MAX_PART_FILES   = 2000;
const DL_MAX_PART_BYTES   = 2 * 1024 * 1024 * 1024;  // 2 GB hard cap per part
const DL_TIMEOUT_MS       = 10 * 60 * 1000;           // 10 min

// Key pattern: di/{affiliation}/Submitted/{year}/{YYYY-MM-DD}_{researcher_id}_{filename}.pdf
function dlExtractResearcher(key) {
  const fn = key.split('/').pop();
  const segs = fn ? fn.split('_') : [];
  return segs.length >= 3 ? segs[1] : null;
}

function dlExtractDate(key) {
  const fn = key.split('/').pop();
  if (!fn) return null;
  const m = fn.match(/^(\d{4}-\d{2}-\d{2})_/);
  return m ? m[1] : null;
}

function dlKeyMatches(key, filters) {
  if (!key.startsWith('di/') || !key.toLowerCase().endsWith('.pdf')) return false;
  if (filters.researchers && filters.researchers.length > 0) {
    const rid = dlExtractResearcher(key);
    if (!rid || !filters.researchers.includes(rid)) return false;
  }
  if (filters.dateFrom || filters.dateTo) {
    const d = dlExtractDate(key);
    // If date cannot be parsed from filename, exclude from date-filtered results
    if (!d) return false;
    if (filters.dateFrom && d < filters.dateFrom) return false;
    if (filters.dateTo && d > filters.dateTo) return false;
  }
  return true;
}

function dlBuildFilters(body) {
  const filters = {};
  if (body.mode === 'researcher' && Array.isArray(body.researchers)) {
    filters.researchers = body.researchers;
  }
  if (body.mode === 'daterange') {
    if (body.dateFrom) filters.dateFrom = body.dateFrom;
    if (body.dateTo) filters.dateTo = body.dateTo;
    if (Array.isArray(body.researchers) && body.researchers.length > 0) {
      filters.researchers = body.researchers;
    }
  }
  return filters;
}

// --- GET /api/di/backup/download/researchers ---
app.get('/api/di/backup/download/researchers', requirePI, async (req, res) => {
  try {
    if (!r2Enabled()) return res.status(503).json({ error: 'R2 storage not configured' });
    const dbRows = await pool.query(
      'SELECT researcher_id, name, affiliation FROM di_allowlist WHERE active = true'
    );
    const rmap = {};
    for (const r of dbRows.rows) {
      rmap[r.researcher_id] = { id: r.researcher_id, name: r.name, affiliation: r.affiliation, files: 0 };
    }
    let token;
    do {
      const resp = await getR2Client().send(new ListObjectsV2Command({
        Bucket: process.env.R2_BUCKET, Prefix: 'di/', ContinuationToken: token
      }));
      if (resp.Contents) {
        for (const obj of resp.Contents) {
          if (!obj.Key.toLowerCase().endsWith('.pdf')) continue;
          const rid = dlExtractResearcher(obj.Key);
          if (!rid) continue;
          if (rmap[rid]) { rmap[rid].files++; }
          else { rmap[rid] = { id: rid, name: 'Unknown (' + rid + ')', affiliation: 'Unknown', files: 1 }; }
        }
      }
      token = resp.IsTruncated ? resp.NextContinuationToken : undefined;
    } while (token);
    const list = Object.values(rmap).filter(r => r.files > 0).sort((a, b) => a.name.localeCompare(b.name));
    res.json({ success: true, researchers: list });
  } catch (err) {
    console.error('[BACKUP-DL] Researchers error:', err.message);
    res.status(500).json({ error: 'Failed to list researchers' });
  }
});

// --- POST /api/di/backup/download/estimate ---
app.post('/api/di/backup/download/estimate', requirePI, async (req, res) => {
  try {
    if (!r2Enabled()) return res.status(503).json({ error: 'R2 storage not configured' });
    const { mode } = req.body;
    if (!['researcher', 'daterange', 'full'].includes(mode))
      return res.status(400).json({ error: 'Invalid mode' });
    if (mode === 'researcher' && (!Array.isArray(req.body.researchers) || !req.body.researchers.length))
      return res.status(400).json({ error: 'No researchers selected' });
    if (mode === 'daterange' && (!req.body.dateFrom || !req.body.dateTo))
      return res.status(400).json({ error: 'Date range required' });

    const filters = dlBuildFilters(req.body);
    let fileCount = 0, totalBytes = 0, token;
    do {
      const resp = await getR2Client().send(new ListObjectsV2Command({
        Bucket: process.env.R2_BUCKET, Prefix: 'di/', ContinuationToken: token
      }));
      if (resp.Contents) {
        for (const obj of resp.Contents) {
          if (dlKeyMatches(obj.Key, filters)) { fileCount++; totalBytes += (obj.Size || 0); }
        }
      }
      token = resp.IsTruncated ? resp.NextContinuationToken : undefined;
    } while (token);
    const singleOk = fileCount <= DL_MAX_SINGLE_FILES && totalBytes <= DL_MAX_SINGLE_BYTES;
    res.json({ success: true, fileCount, totalBytes, singleZipAvailable: singleOk, recommendedMode: singleOk ? 'single' : 'multi' });
  } catch (err) {
    console.error('[BACKUP-DL] Estimate error:', err.message);
    res.status(500).json({ error: 'Failed to estimate' });
  }
});

// --- POST /api/di/backup/download/zip ---
// Streams a ZIP of matching R2 PDFs.
// Multi-part: send cursor (last included key) and maxBytes. Check X-Next-Cursor response header.
app.post('/api/di/backup/download/zip', requirePI, async (req, res) => {
  const t0 = Date.now();
  try {
    if (!r2Enabled()) return res.status(503).json({ error: 'R2 storage not configured' });
    const { mode, cursor, maxBytes: rawMax } = req.body;
    if (!['researcher', 'daterange', 'full'].includes(mode))
      return res.status(400).json({ error: 'Invalid mode' });
    if (mode === 'researcher' && (!Array.isArray(req.body.researchers) || !req.body.researchers.length))
      return res.status(400).json({ error: 'No researchers selected' });
    if (mode === 'daterange' && (!req.body.dateFrom || !req.body.dateTo))
      return res.status(400).json({ error: 'Date range required' });

    const filters = dlBuildFilters(req.body);
    const maxBytes = rawMax ? Math.min(Number(rawMax), DL_MAX_PART_BYTES) : null;

    // Phase 1 — collect keys for this part (ListObjectsV2 only, no GetObject yet)
    const r2 = getR2Client();
    const bucket = process.env.R2_BUCKET;
    const keys = [];
    let partBytes = 0, nextCursor = '', partDone = false, listToken;
    const listParams = { Bucket: bucket, Prefix: 'di/' };
    if (cursor) listParams.StartAfter = cursor;

    do {
      if (listToken) { listParams.ContinuationToken = listToken; delete listParams.StartAfter; }
      const resp = await r2.send(new ListObjectsV2Command(listParams));
      if (resp.Contents) {
        for (const obj of resp.Contents) {
          if (!dlKeyMatches(obj.Key, filters)) continue;
          const sz = obj.Size || 0;
          if (maxBytes && partBytes + sz > maxBytes && keys.length > 0) { partDone = true; break; }
          if (keys.length >= DL_MAX_PART_FILES) { partDone = true; break; }
          keys.push({ key: obj.Key, size: sz });
          partBytes += sz;
        }
      }
      if (partDone) { nextCursor = keys[keys.length - 1].key; break; }
      listToken = resp.IsTruncated ? resp.NextContinuationToken : undefined;
    } while (listToken);

    if (!keys.length) return res.status(404).json({ error: 'No matching files found' });

    // Phase 2 — stream ZIP
    const who = req.session.user.researcher_id;
    console.log(`[BACKUP-DL] ZIP by=${who} mode=${mode} files=${keys.length} est=${partBytes} multi=${!!maxBytes}`);

    const stamp = new Date().toISOString().slice(0, 10);
    let fn = 'natlab-' + stamp;
    if (mode === 'researcher' && req.body.researchers.length === 1) fn += '-' + req.body.researchers[0];
    else if (mode === 'daterange') fn += '-' + req.body.dateFrom + '_' + req.body.dateTo;
    if (maxBytes && cursor) fn += '-cont';
    fn += '.zip';

    res.setHeader('Content-Type', 'application/zip');
    res.setHeader('Content-Disposition', 'attachment; filename="' + fn + '"');
    res.setHeader('X-Next-Cursor', nextCursor);
    res.setHeader('X-File-Count', String(keys.length));
    res.setHeader('Access-Control-Expose-Headers', 'X-Next-Cursor, X-File-Count');

    const archive = archiver('zip', { zlib: { level: 5 } });
    const errors = [];
    archive.on('error', (e) => { console.error('[BACKUP-DL] archiver err:', e.message); });
    archive.pipe(res);

    for (const item of keys) {
      if (Date.now() - t0 > DL_TIMEOUT_MS) { errors.push({ key: item.key, error: 'timeout' }); break; }
      try {
        const obj = await r2.send(new GetObjectCommand({ Bucket: bucket, Key: item.key }));
        archive.append(obj.Body, { name: item.key });
      } catch (e) {
        errors.push({ key: item.key, error: e.message });
      }
    }
    if (errors.length) {
      archive.append(errors.map(e => e.key + ' \u2014 ' + e.error).join('\n'), { name: 'manifest_errors.txt' });
      console.log(`[BACKUP-DL] ${errors.length} file(s) skipped`);
    }
    await archive.finalize();
    console.log(`[BACKUP-DL] done files=${keys.length} errors=${errors.length} ms=${Date.now() - t0}`);
  } catch (err) {
    console.error('[BACKUP-DL] ZIP error:', err.message);
    if (!res.headersSent) res.status(500).json({ error: 'Download failed' });
  }
});









// ==================== INVENTORY SYSTEM ====================

// CSV parser — native, no dependencies
function parseInventoryCSV(buffer) {
    const text = buffer.toString('utf-8');
    const lines = text.split(/\r?\n/).filter(l => l.trim());
    if (lines.length < 2) throw new Error('CSV must have a header row and at least one data row');
    const headers = lines[0].split(',').map(h => h.trim().toLowerCase().replace(/["\s]+/g, ''));
    const rows = [];
    for (let i = 1; i < lines.length; i++) {
        const values = lines[i].split(',').map(v => v.trim().replace(/^"|"$/g, ''));
        const row = {};
        headers.forEach((h, idx) => { row[h] = values[idx] || ''; });
        rows.push(row);
    }
    return { headers, rows };
}

const INVENTORY_REQUIRED_COLS = [
    'affiliation', 'vendor_company', 'product_name', 'catalog_id',
    'product_link', 'responsible_user_email', 'quantity_remaining',
    'unit', 'storage', 'location'
];
const INVENTORY_VALID_UNITS = ['bottle', 'box', 'pack', 'each'];
const INVENTORY_VALID_STORAGE = ['RT', '4C', '-20C', '-80C'];
const INVENTORY_VALID_AFFILIATIONS = ['LiU', 'UNAV'];

// Validate CSV rows and resolve responsible_user_email → researcher_id
async function validateInventoryRows(rows) {
    const errors = [];
    const validatedRows = [];

    // Pre-fetch all active internal users for email lookup
    const usersResult = await pool.query(
        `SELECT researcher_id, institution_email, name FROM di_allowlist WHERE active = true AND affiliation != 'EXTERNAL'`
    );
    const emailMap = {};
    for (const u of usersResult.rows) {
        emailMap[u.institution_email.toLowerCase()] = u;
    }

    for (let i = 0; i < rows.length; i++) {
        const row = rows[i];
        const rowNum = i + 2; // 1-based, skip header
        const rowErrors = [];

        // Affiliation
        if (!INVENTORY_VALID_AFFILIATIONS.includes(row.affiliation)) {
            rowErrors.push(`affiliation must be LiU or UNAV, got "${row.affiliation}"`);
        }

        // Required text fields
        if (!row.vendor_company) rowErrors.push('vendor_company is required');
        if (!row.product_name) rowErrors.push('product_name is required');
        if (!row.catalog_id) rowErrors.push('catalog_id is required');
        if (!row.product_link) rowErrors.push('product_link is required');

        // Unit
        if (!INVENTORY_VALID_UNITS.includes(row.unit)) {
            rowErrors.push(`unit must be one of ${INVENTORY_VALID_UNITS.join(', ')}, got "${row.unit}"`);
        }

        // Storage
        if (!INVENTORY_VALID_STORAGE.includes(row.storage)) {
            rowErrors.push(`storage must be one of ${INVENTORY_VALID_STORAGE.join(', ')}, got "${row.storage}"`);
        }

        // Quantity
        const qty = parseFloat(row.quantity_remaining);
        if (isNaN(qty) || qty < 0) {
            rowErrors.push(`quantity_remaining must be a non-negative number, got "${row.quantity_remaining}"`);
        }

        // Responsibility
        const email = (row.responsible_user_email || '').trim().toLowerCase();
        let responsibleType = 'user';
        let responsibleUserId = null;
        if (!email) {
            rowErrors.push('responsible_user_email is required');
        } else if (email === 'group') {
            responsibleType = 'group';
            responsibleUserId = null;
        } else {
            const found = emailMap[email];
            if (!found) {
                rowErrors.push(`responsible_user_email "${row.responsible_user_email}" not found or not an active internal user`);
            } else {
                responsibleUserId = found.researcher_id;
            }
        }

        if (rowErrors.length > 0) {
            errors.push({ row: rowNum, errors: rowErrors });
        } else {
            validatedRows.push({
                affiliation: row.affiliation,
                vendor_company: row.vendor_company,
                product_name: row.product_name,
                catalog_id: row.catalog_id,
                product_link: row.product_link,
                responsible_type: responsibleType,
                responsible_user_id: responsibleUserId,
                responsible_email: email,
                quantity_remaining: qty,
                unit: row.unit,
                storage: row.storage,
                location: row.location || ''
            });
        }
    }

    return { errors, validatedRows };
}

// Compute diff between CSV rows and existing inventory
async function computeInventoryDiff(validatedRows) {
    const diff = { new: [], update: [], duplicate: [] };

    for (const row of validatedRows) {
        const existing = await pool.query(
            `SELECT * FROM di_inventory
             WHERE affiliation = $1 AND LOWER(vendor_company) = LOWER($2) AND LOWER(catalog_id) = LOWER($3)
             LIMIT 1`,
            [row.affiliation, row.vendor_company, row.catalog_id]
        );

        if (existing.rows.length === 0) {
            diff.new.push(row);
        } else {
            const ex = existing.rows[0];
            const hasChanges = (
                ex.product_name !== row.product_name ||
                Number(ex.quantity_remaining) !== row.quantity_remaining ||
                ex.unit !== row.unit ||
                ex.storage !== row.storage ||
                (ex.location || '') !== row.location ||
                ex.product_link !== row.product_link ||
                ex.responsible_type !== row.responsible_type ||
                ex.responsible_user_id !== row.responsible_user_id
            );
            if (hasChanges) {
                diff.update.push({ existing: ex, incoming: row });
            } else {
                diff.duplicate.push({ existing: ex, incoming: row });
            }
        }
    }

    return diff;
}

// POST /api/di/inventory/upload
// Upload inventory CSV — creates SUBMITTED submission in di_submissions
app.post('/api/di/inventory/upload', requireAuth, requireInternal, inventoryUpload.single('file'), async (req, res) => {
    try {
        const file = req.file;
        if (!file) {
            return res.status(400).json({ error: 'No file uploaded' });
        }

        const user = req.session.user;

        // Parse CSV
        let parsed;
        try {
            parsed = parseInventoryCSV(file.buffer);
        } catch (parseErr) {
            return res.status(400).json({ error: 'CSV parse error: ' + parseErr.message });
        }

        // Check required columns
        const missing = INVENTORY_REQUIRED_COLS.filter(c => !parsed.headers.includes(c));
        if (missing.length > 0) {
            return res.status(400).json({ error: 'Missing required columns: ' + missing.join(', ') });
        }

        // Validate rows
        const { errors, validatedRows } = await validateInventoryRows(parsed.rows);
        if (errors.length > 0) {
            return res.status(400).json({ error: 'Validation errors in CSV', details: errors });
        }

        if (validatedRows.length === 0) {
            return res.status(400).json({ error: 'CSV contains no valid data rows' });
        }

        // Upload raw CSV to R2
        if (!r2Enabled()) {
            return res.status(503).json({ error: 'R2 storage not configured' });
        }

        const year = new Date().getFullYear();
        const dateStamp = new Date().toISOString().slice(0, 10);
        const safeOriginal = (file.originalname || 'inventory.csv').replace(/[^\w.\-]+/g, '_');
        const key = `di/${user.affiliation}/Inventory/Imports/${year}/${dateStamp}_${user.researcher_id}_${safeOriginal}`;

        await uploadToR2(file.buffer, key, 'text/csv');
        const fileId = 'r2:' + key;

        // Insert into di_submissions with status SUBMITTED
        const result = await pool.query(
            `INSERT INTO di_submissions (researcher_id, affiliation, file_type, original_filename, drive_file_id, status)
             VALUES ($1, $2, 'INVENTORY', $3, $4, 'SUBMITTED')
             RETURNING submission_id`,
            [user.researcher_id, user.affiliation, file.originalname, fileId]
        );

        const submissionId = result.rows[0].submission_id;
        console.log(`[INVENTORY] CSV uploaded: submission_id=${submissionId}, rows=${validatedRows.length}, key=${key}`);

        res.json({
            success: true,
            submission_id: submissionId,
            row_count: validatedRows.length,
            message: 'Inventory CSV submitted for PI review'
        });

    } catch (err) {
        console.error('[INVENTORY] Upload error:', err);
        res.status(500).json({ error: 'Upload failed', message: err.message });
    }
});

// GET /api/di/inventory/import/pending
// List SUBMITTED inventory submissions for PI review
app.get('/api/di/inventory/import/pending', requirePI, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT s.submission_id, s.researcher_id, s.original_filename, s.affiliation,
                    s.status, s.created_at, s.revision_comments,
                    a.name as researcher_name
             FROM di_submissions s
             LEFT JOIN di_allowlist a ON s.researcher_id = a.researcher_id
             WHERE s.file_type = 'INVENTORY' AND s.status = 'SUBMITTED'
             ORDER BY s.created_at ASC`
        );

        res.json({ success: true, submissions: result.rows });
    } catch (err) {
        console.error('[INVENTORY] Pending list error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/inventory/import/preview/:id
// Parse CSV from R2 and compute diff for PI review
app.get('/api/di/inventory/import/preview/:id', requirePI, async (req, res) => {
    try {
        const { id } = req.params;

        // Fetch submission
        const sub = await pool.query(
            `SELECT * FROM di_submissions WHERE submission_id = $1 AND file_type = 'INVENTORY'`, [id]
        );
        if (sub.rows.length === 0) {
            return res.status(404).json({ error: 'Inventory submission not found' });
        }

        const submission = sub.rows[0];
        if (submission.status !== 'SUBMITTED') {
            return res.status(400).json({ error: 'Submission is not in SUBMITTED state' });
        }

        const fileId = (submission.drive_file_id || '').trim();
        if (!fileId.startsWith('r2:')) {
            return res.status(400).json({ error: 'No R2 file associated with this submission' });
        }

        // Download and parse CSV from R2
        const r2Key = fileId.replace(/^r2:/, '');
        const r2Obj = await downloadFromR2(r2Key);
        const chunks = [];
        for await (const c of r2Obj.Body) chunks.push(c);
        const csvBuffer = Buffer.concat(chunks);

        const parsed = parseInventoryCSV(csvBuffer);
        const { errors, validatedRows } = await validateInventoryRows(parsed.rows);
        if (errors.length > 0) {
            return res.json({ success: true, validation_errors: errors, diff: null });
        }

        const diff = await computeInventoryDiff(validatedRows);

        res.json({
            success: true,
            submission_id: id,
            researcher_id: submission.researcher_id,
            filename: submission.original_filename,
            row_count: validatedRows.length,
            new_count: diff.new.length,
            update_count: diff.update.length,
            duplicate_count: diff.duplicate.length,
            diff: diff
        });

    } catch (err) {
        console.error('[INVENTORY] Preview error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/inventory/import/approve/:id
// PI approves inventory import — apply CSV changes to di_inventory
app.post('/api/di/inventory/import/approve/:id', requirePI, async (req, res) => {
    try {
        const { id } = req.params;
        const piUser = req.session.user;

        // Fetch submission
        const sub = await pool.query(
            `SELECT * FROM di_submissions WHERE submission_id = $1 AND file_type = 'INVENTORY'`, [id]
        );
        if (sub.rows.length === 0) {
            return res.status(404).json({ error: 'Inventory submission not found' });
        }

        const submission = sub.rows[0];
        if (submission.status !== 'SUBMITTED') {
            return res.status(400).json({ error: 'Submission is not in SUBMITTED state' });
        }

        const fileId = (submission.drive_file_id || '').trim();
        if (!fileId.startsWith('r2:')) {
            return res.status(400).json({ error: 'No R2 file associated' });
        }

        // Re-parse CSV from R2 (authoritative at approval time)
        const r2Key = fileId.replace(/^r2:/, '');
        const r2Obj = await downloadFromR2(r2Key);
        const chunks = [];
        for await (const c of r2Obj.Body) chunks.push(c);
        const csvBuffer = Buffer.concat(chunks);

        const parsed = parseInventoryCSV(csvBuffer);
        const { errors, validatedRows } = await validateInventoryRows(parsed.rows);
        if (errors.length > 0) {
            return res.status(400).json({ error: 'CSV validation errors at approval time', details: errors });
        }

        const diff = await computeInventoryDiff(validatedRows);
        const importBatchId = id; // Use submission_id as batch ID

        let newCount = 0;
        let updateCount = 0;

        // Apply NEW items
        for (const row of diff.new) {
            await pool.query(
                `INSERT INTO di_inventory (affiliation, vendor_company, product_name, catalog_id, product_link,
                 responsible_type, responsible_user_id, quantity_remaining, unit, storage, location, status,
                 origin_type, last_update_channel, import_batch_id, created_by, last_updated_by)
                 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'Active','offline_import','offline_import',$12,$13,$13)`,
                [row.affiliation, row.vendor_company, row.product_name, row.catalog_id, row.product_link,
                 row.responsible_type, row.responsible_user_id, row.quantity_remaining, row.unit, row.storage,
                 row.location, importBatchId, submission.researcher_id]
            );
            newCount++;
        }

        // Apply UPDATE items
        for (const item of diff.update) {
            const row = item.incoming;
            const oldId = item.existing.id;

            // Audit log
            await pool.query(
                `INSERT INTO di_inventory_log (inventory_id, action, changed_by, old_values, new_values, import_batch_id)
                 VALUES ($1, 'IMPORT_UPDATE', $2, $3, $4, $5)`,
                [oldId, submission.researcher_id, JSON.stringify(item.existing), JSON.stringify(row), importBatchId]
            );

            // Apply update
            await pool.query(
                `UPDATE di_inventory SET product_name=$1, product_link=$2, quantity_remaining=$3, unit=$4,
                 storage=$5, location=$6, responsible_type=$7, responsible_user_id=$8,
                 last_update_channel='offline_import', last_updated_at=NOW(), last_updated_by=$9, import_batch_id=$10
                 WHERE id = $11`,
                [row.product_name, row.product_link, row.quantity_remaining, row.unit,
                 row.storage, row.location, row.responsible_type, row.responsible_user_id,
                 submission.researcher_id, importBatchId, oldId]
            );
            updateCount++;
        }

        // Update submission status
        await pool.query(
            `UPDATE di_submissions SET status='APPROVED', signed_at=NOW() WHERE submission_id=$1`, [id]
        );

        // Delete original CSV from R2 (same pattern as SOP/DATA approval)
        try { await deleteFromR2(r2Key); } catch (e) { console.warn('[INVENTORY] Delete CSV warning:', e.message); }

        console.log(`[INVENTORY] Approved: submission=${id}, new=${newCount}, updated=${updateCount}, duplicates=${diff.duplicate.length}`);

        res.json({
            success: true,
            message: 'Inventory import approved and applied',
            new_count: newCount,
            update_count: updateCount,
            duplicate_count: diff.duplicate.length
        });

    } catch (err) {
        console.error('[INVENTORY] Approve error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/inventory/import/revise/:id
// PI requests revision on inventory import
app.post('/api/di/inventory/import/revise/:id', requirePI, async (req, res) => {
    try {
        const { id } = req.params;
        const { comments } = req.body;

        const sub = await pool.query(
            `SELECT * FROM di_submissions WHERE submission_id = $1 AND file_type = 'INVENTORY'`, [id]
        );
        if (sub.rows.length === 0) {
            return res.status(404).json({ error: 'Inventory submission not found' });
        }

        const submission = sub.rows[0];
        if (submission.status !== 'SUBMITTED') {
            return res.status(400).json({ error: 'Submission is not in SUBMITTED state' });
        }

        // Delete CSV from R2 (same as SOP/DATA revise pattern)
        const fileId = (submission.drive_file_id || '').trim();
        if (fileId.startsWith('r2:')) {
            try { await deleteFromR2(fileId.replace(/^r2:/, '')); } catch (e) { console.warn('[INVENTORY] Delete warning:', e.message); }
        }

        // Update submission
        await pool.query(
            `UPDATE di_submissions SET status='REVISION_NEEDED', drive_file_id=NULL, revision_comments=$1 WHERE submission_id=$2`,
            [comments || '', id]
        );

        console.log(`[INVENTORY] Revision requested: submission=${id}`);
        res.json({ success: true, message: 'Revision requested' });

    } catch (err) {
        console.error('[INVENTORY] Revise error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/inventory/my-items
// Researcher/supervisor sees their own active inventory items
app.get('/api/di/inventory/my-items', requireAuth, requireInternal, async (req, res) => {
    try {
        const user = req.session.user;
        const result = await pool.query(
            `SELECT * FROM di_inventory
             WHERE responsible_type = 'user' AND responsible_user_id = $1 AND status = 'Active'
             ORDER BY last_updated_at DESC`,
            [user.researcher_id]
        );
        res.json({ success: true, items: result.rows });
    } catch (err) {
        console.error('[INVENTORY] My items error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/inventory/group-items
// All internal users see group inventory (read-only)
app.get('/api/di/inventory/group-items', requireAuth, requireInternal, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT * FROM di_inventory
             WHERE responsible_type = 'group' AND status = 'Active'
             ORDER BY vendor_company, product_name`
        );
        res.json({ success: true, items: result.rows });
    } catch (err) {
        console.error('[INVENTORY] Group items error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// PATCH /api/di/inventory/:id
// Owner updates quantity_remaining, storage, or location
app.patch('/api/di/inventory/:id', requireAuth, requireInternal, async (req, res) => {
    try {
        const { id } = req.params;
        const user = req.session.user;
        const { quantity_remaining, storage, location } = req.body;

        // Verify ownership
        const item = await pool.query(
            `SELECT * FROM di_inventory WHERE id = $1 AND responsible_type = 'user' AND responsible_user_id = $2 AND status = 'Active'`,
            [id, user.researcher_id]
        );
        if (item.rows.length === 0) {
            return res.status(404).json({ error: 'Item not found or you are not the owner' });
        }

        const old = item.rows[0];
        const updates = {};
        const setClauses = [];
        const params = [];
        let paramIdx = 1;

        if (quantity_remaining !== undefined) {
            const qty = parseFloat(quantity_remaining);
            if (isNaN(qty) || qty < 0) return res.status(400).json({ error: 'Invalid quantity' });
            setClauses.push(`quantity_remaining = $${paramIdx++}`);
            params.push(qty);
            updates.quantity_remaining = qty;
        }
        if (storage !== undefined) {
            if (!INVENTORY_VALID_STORAGE.includes(storage)) return res.status(400).json({ error: 'Invalid storage value' });
            setClauses.push(`storage = $${paramIdx++}`);
            params.push(storage);
            updates.storage = storage;
        }
        if (location !== undefined) {
            setClauses.push(`location = $${paramIdx++}`);
            params.push(location);
            updates.location = location;
        }

        if (setClauses.length === 0) {
            return res.status(400).json({ error: 'No valid fields to update' });
        }

        setClauses.push(`last_updated_at = NOW()`);
        setClauses.push(`last_updated_by = $${paramIdx++}`);
        params.push(user.researcher_id);
        setClauses.push(`last_update_channel = 'online_ui'`);
        params.push(id);

        await pool.query(
            `UPDATE di_inventory SET ${setClauses.join(', ')} WHERE id = $${paramIdx}`,
            params
        );

        // Audit log
        await pool.query(
            `INSERT INTO di_inventory_log (inventory_id, action, changed_by, old_values, new_values)
             VALUES ($1, 'UPDATE', $2, $3, $4)`,
            [id, user.researcher_id, JSON.stringify({ quantity_remaining: old.quantity_remaining, storage: old.storage, location: old.location }), JSON.stringify(updates)]
        );

        res.json({ success: true, message: 'Item updated' });
    } catch (err) {
        console.error('[INVENTORY] Update error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// PUT /api/di/inventory/:id/transfer-to-group
// Owner transfers item to group inventory
app.put('/api/di/inventory/:id/transfer-to-group', requireAuth, requireInternal, async (req, res) => {
    try {
        const { id } = req.params;
        const user = req.session.user;

        const item = await pool.query(
            `SELECT * FROM di_inventory WHERE id = $1 AND responsible_type = 'user' AND responsible_user_id = $2 AND status = 'Active'`,
            [id, user.researcher_id]
        );
        if (item.rows.length === 0) {
            return res.status(404).json({ error: 'Item not found or you are not the owner' });
        }

        await pool.query(
            `UPDATE di_inventory SET responsible_type = 'group', responsible_user_id = NULL,
             last_updated_at = NOW(), last_updated_by = $1, last_update_channel = 'online_ui'
             WHERE id = $2`,
            [user.researcher_id, id]
        );

        await pool.query(
            `INSERT INTO di_inventory_log (inventory_id, action, changed_by, old_values, new_values)
             VALUES ($1, 'TRANSFER_TO_GROUP', $2, $3, $4)`,
            [id, user.researcher_id,
             JSON.stringify({ responsible_type: 'user', responsible_user_id: user.researcher_id }),
             JSON.stringify({ responsible_type: 'group', responsible_user_id: null })]
        );

        res.json({ success: true, message: 'Item transferred to group inventory' });
    } catch (err) {
        console.error('[INVENTORY] Transfer error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// PUT /api/di/inventory/:id/mark-finished
// Owner marks item as finished
app.put('/api/di/inventory/:id/mark-finished', requireAuth, requireInternal, async (req, res) => {
    try {
        const { id } = req.params;
        const user = req.session.user;

        const item = await pool.query(
            `SELECT * FROM di_inventory WHERE id = $1 AND responsible_type = 'user' AND responsible_user_id = $2 AND status = 'Active'`,
            [id, user.researcher_id]
        );
        if (item.rows.length === 0) {
            return res.status(404).json({ error: 'Item not found or you are not the owner' });
        }

        await pool.query(
            `UPDATE di_inventory SET status = 'Finished', quantity_remaining = 0,
             last_updated_at = NOW(), last_updated_by = $1, last_update_channel = 'online_ui'
             WHERE id = $2`,
            [user.researcher_id, id]
        );

        await pool.query(
            `INSERT INTO di_inventory_log (inventory_id, action, changed_by, old_values, new_values)
             VALUES ($1, 'MARK_FINISHED', $2, $3, $4)`,
            [id, user.researcher_id,
             JSON.stringify({ status: 'Active', quantity_remaining: item.rows[0].quantity_remaining }),
             JSON.stringify({ status: 'Finished', quantity_remaining: 0 })]
        );

        res.json({ success: true, message: 'Item marked as finished' });
    } catch (err) {
        console.error('[INVENTORY] Mark finished error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/inventory/all
// PI sees all inventory items with optional filters
app.get('/api/di/inventory/all', requirePI, async (req, res) => {
    try {
        const { affiliation, responsible, status, origin } = req.query;
        const conditions = [];
        const params = [];
        let idx = 1;

        if (affiliation && INVENTORY_VALID_AFFILIATIONS.includes(affiliation)) {
            conditions.push(`i.affiliation = $${idx++}`);
            params.push(affiliation);
        }
        if (responsible === 'user' || responsible === 'group') {
            conditions.push(`i.responsible_type = $${idx++}`);
            params.push(responsible);
        }
        if (status === 'Active' || status === 'Finished') {
            conditions.push(`i.status = $${idx++}`);
            params.push(status);
        }
        if (origin === 'online_purchase' || origin === 'offline_import') {
            conditions.push(`i.origin_type = $${idx++}`);
            params.push(origin);
        }

        const where = conditions.length > 0 ? 'WHERE ' + conditions.join(' AND ') : '';
        const result = await pool.query(
            `SELECT i.*, a.name as responsible_name, a.institution_email as responsible_email
             FROM di_inventory i
             LEFT JOIN di_allowlist a ON i.responsible_user_id = a.researcher_id
             ${where}
             ORDER BY i.last_updated_at DESC`,
            params
        );

        res.json({ success: true, items: result.rows });
    } catch (err) {
        console.error('[INVENTORY] All items error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/inventory/check-user/:researcher_id
// Returns active inventory count for a user (used by deactivation warning)
app.get('/api/di/inventory/check-user/:researcher_id', requirePI, async (req, res) => {
    try {
        const { researcher_id } = req.params;
        const result = await pool.query(
            `SELECT COUNT(*) as active_count FROM di_inventory
             WHERE responsible_type = 'user' AND responsible_user_id = $1 AND status = 'Active'`,
            [researcher_id]
        );
        res.json({ success: true, active_count: parseInt(result.rows[0].active_count, 10) });
    } catch (err) {
        console.error('[INVENTORY] Check user error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});


// ==================== PURCHASE REQUEST SYSTEM ====================

// POST /api/di/purchases/request — Create a purchase request with items
app.post('/api/di/purchases/request', requireAuth, requireInternal, async (req, res) => {
    try {
        const user = req.session.user;
        const { justification, currency, items } = req.body;

        if (!justification || !justification.trim()) {
            return res.status(400).json({ error: 'Justification is required' });
        }
        if (!currency || !currency.trim()) {
            return res.status(400).json({ error: 'Currency is required' });
        }
        if (!items || !Array.isArray(items) || items.length === 0) {
            return res.status(400).json({ error: 'At least one item is required' });
        }

        // Validate each item
        for (let i = 0; i < items.length; i++) {
            const it = items[i];
            if (!it.vendor_company || !it.product_name || !it.catalog_id || !it.product_link) {
                return res.status(400).json({ error: `Item ${i + 1}: all fields are required` });
            }
            if (!it.quantity || isNaN(it.quantity) || Number(it.quantity) <= 0) {
                return res.status(400).json({ error: `Item ${i + 1}: quantity must be a positive number` });
            }
            if (it.unit_price === undefined || it.unit_price === null || isNaN(it.unit_price) || Number(it.unit_price) < 0) {
                return res.status(400).json({ error: `Item ${i + 1}: unit_price must be a non-negative number` });
            }
        }

        // Server-authoritative totals
        const computedItems = items.map(it => ({
            ...it,
            quantity: Number(it.quantity),
            unit_price: Number(it.unit_price),
            item_total: Math.round(Number(it.quantity) * Number(it.unit_price) * 100) / 100
        }));
        const request_total = Math.round(computedItems.reduce((sum, it) => sum + it.item_total, 0) * 100) / 100;

        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            const reqResult = await client.query(
                `INSERT INTO di_purchase_requests (requester_id, affiliation, justification, status, request_total, currency)
                 VALUES ($1, $2, $3, 'SUBMITTED', $4, $5) RETURNING id`,
                [user.researcher_id, user.affiliation, justification.trim(), request_total, currency.trim()]
            );
            const requestId = reqResult.rows[0].id;

            for (const it of computedItems) {
                await client.query(
                    `INSERT INTO di_purchase_items (request_id, vendor_company, product_name, catalog_id, product_link, quantity, unit_price, item_total, currency)
                     VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
                    [requestId, it.vendor_company.trim(), it.product_name.trim(), it.catalog_id.trim(), it.product_link.trim(), it.quantity, it.unit_price, it.item_total, currency.trim()]
                );
            }

            await client.query('COMMIT');
            console.log(`[PURCHASES] Request ${requestId} created by ${user.researcher_id} with ${computedItems.length} items, total ${request_total} ${currency}`);
            res.json({ success: true, request_id: requestId, request_total, item_count: computedItems.length });
        } catch (err) {
            await client.query('ROLLBACK');
            throw err;
        } finally {
            client.release();
        }
    } catch (err) {
        console.error('[PURCHASES] Create request error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/purchases/my — List current user's purchase requests
app.get('/api/di/purchases/my', requireAuth, requireInternal, async (req, res) => {
    try {
        const user = req.session.user;
        const result = await pool.query(
            `SELECT r.id, r.affiliation, r.justification, r.status, r.request_total, r.currency,
                    r.pi_comment, r.created_at, r.updated_at,
                    json_agg(json_build_object(
                        'id', i.id, 'vendor_company', i.vendor_company, 'product_name', i.product_name,
                        'catalog_id', i.catalog_id, 'product_link', i.product_link,
                        'quantity', i.quantity, 'unit_price', i.unit_price, 'item_total', i.item_total,
                        'currency', i.currency, 'ordered_at', i.ordered_at, 'received_at', i.received_at,
                        'inventory_id', i.inventory_id,
                        'item_status', COALESCE(i.item_status, 'Active'),
                        'status_note', i.status_note,
                        'proposed_vendor', i.proposed_vendor, 'proposed_product', i.proposed_product,
                        'proposed_catalog_id', i.proposed_catalog_id, 'proposed_link', i.proposed_link,
                        'proposed_qty', i.proposed_qty, 'proposed_unit_price', i.proposed_unit_price,
                        'modified_by', i.modified_by, 'modified_at', i.modified_at,
                        'pi_decision_note', i.pi_decision_note, 'pi_decision_at', i.pi_decision_at
                    ) ORDER BY i.created_at) AS items,
                    COUNT(*) FILTER (WHERE COALESCE(i.item_status,'Active') IN ('Modification Requested','Cancel Requested')) AS pending_change_count
             FROM di_purchase_requests r
             JOIN di_purchase_items i ON i.request_id = r.id
             WHERE r.requester_id = $1
             GROUP BY r.id
             ORDER BY r.created_at DESC`,
            [user.researcher_id]
        );
        const requests = result.rows.map(r => ({
            ...r,
            pending_change_count: parseInt(r.pending_change_count) || 0,
            has_pending_changes: parseInt(r.pending_change_count) > 0
        }));
        res.json({ success: true, requests });
    } catch (err) {
        console.error('[PURCHASES] My requests error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/purchases/my-approved-to-receive — Approved items not yet received for current user
app.get('/api/di/purchases/my-approved-to-receive', requireAuth, requireInternal, async (req, res) => {
    try {
        const user = req.session.user;
        const result = await pool.query(
            `SELECT i.id, i.vendor_company, i.product_name, i.catalog_id, i.product_link,
                    i.quantity, i.unit_price, i.item_total, i.currency, i.ordered_at,
                    r.id AS request_id, r.affiliation, r.justification, r.created_at AS request_date
             FROM di_purchase_items i
             JOIN di_purchase_requests r ON r.id = i.request_id
             WHERE r.requester_id = $1 AND r.status = 'APPROVED' AND i.received_at IS NULL
               AND (i.item_status = 'Active' OR i.item_status IS NULL)
             ORDER BY r.created_at DESC, i.created_at`,
            [user.researcher_id]
        );
        res.json({ success: true, items: result.rows });
    } catch (err) {
        console.error('[PURCHASES] Approved to receive error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/purchases/item/:itemId/receive — Researcher confirms item received → creates inventory v2 record
app.post('/api/di/purchases/item/:itemId/receive', requireAuth, requireInternal, async (req, res) => {
    try {
        const user = req.session.user;
        const { itemId } = req.params;
        const { quantity_received, unit, storage, location, received_at,
                lot_or_batch_number, expiry_date, opened_date, notes,
                internal_order_number } = req.body;

        // Validate inputs
        if (!quantity_received || isNaN(quantity_received) || Number(quantity_received) <= 0) {
            return res.status(400).json({ error: 'quantity_received must be a positive number' });
        }
        if (!unit || !VALID_UNITS_V2.includes(unit)) {
            return res.status(400).json({ error: 'unit must be one of: ' + VALID_UNITS_V2.join(', ') });
        }
        const validStorage = ['RT', '4C', '-20C', '-80C'];
        if (!storage || !validStorage.includes(storage)) {
            return res.status(400).json({ error: 'storage must be one of: ' + validStorage.join(', ') });
        }
        if (!location || !location.trim()) {
            return res.status(400).json({ error: 'location is required' });
        }

        // Verify item belongs to user and is eligible
        const itemResult = await pool.query(
            `SELECT i.*, r.requester_id, r.status AS request_status, r.affiliation
             FROM di_purchase_items i
             JOIN di_purchase_requests r ON r.id = i.request_id
             WHERE i.id = $1`,
            [itemId]
        );
        if (itemResult.rows.length === 0) {
            return res.status(404).json({ error: 'Item not found' });
        }
        const item = itemResult.rows[0];
        if (item.requester_id !== user.researcher_id) {
            return res.status(403).json({ error: 'You can only receive your own purchase items' });
        }
        if (item.request_status !== 'APPROVED') {
            return res.status(400).json({ error: 'Only items from approved requests can be received' });
        }
        if (item.received_at) {
            return res.status(400).json({ error: 'Item already received' });
        }

        const client = await pool.connect();
        try {
            await client.query('BEGIN');

            // Create canonical inventory v2 record
            const invResult = await client.query(
                `INSERT INTO di_inventory_items (
                    affiliation, item_type, source, item_name, item_identifier,
                    quantity, quantity_unit, storage_location, storage_temperature,
                    vendor_company, product_link, internal_order_number, unit_price, currency,
                    lot_or_batch_number, expiry_date, opened_date, notes,
                    visibility_scope, created_by, status, owner_type
                ) VALUES ($1, 'product', 'Online', $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, 'group', $17, 'Received', 'researcher')
                RETURNING id`,
                [item.affiliation, item.product_name, item.catalog_id,
                 Number(quantity_received), unit, location.trim(), storage,
                 item.vendor_company, item.product_link, internal_order_number || null,
                 item.unit_price, item.currency,
                 lot_or_batch_number || null, expiry_date || null, opened_date || null, notes || null,
                 user.researcher_id]
            );
            const inventoryItemId = invResult.rows[0].id;

            // Audit log
            await client.query(
                `INSERT INTO di_inventory_items_log (inventory_item_id, action, changed_by, new_values)
                 VALUES ($1, 'CREATE_FROM_PURCHASE', $2, $3)`,
                [inventoryItemId, user.researcher_id, JSON.stringify({ purchase_item_id: itemId, product_name: item.product_name })]
            );

            // Update purchase item with received info and link to new inventory
            const recvDate = received_at ? new Date(received_at) : new Date();
            await client.query(
                `UPDATE di_purchase_items SET received_at = $1, new_inventory_item_id = $2 WHERE id = $3`,
                [recvDate, inventoryItemId, itemId]
            );

            await client.query('COMMIT');
            console.log(`[PURCHASES] Item ${itemId} received by ${user.researcher_id}, inventory-v2 ${inventoryItemId} created`);
            res.json({ success: true, inventory_item_id: inventoryItemId });
        } catch (err) {
            await client.query('ROLLBACK');
            throw err;
        } finally {
            client.release();
        }
    } catch (err) {
        console.error('[PURCHASES] Receive item error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/purchases/all — PI views all purchase requests
app.get('/api/di/purchases/all', requirePI, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT r.id, r.requester_id, r.affiliation, r.justification, r.status,
                    r.request_total, r.currency, r.pi_comment, r.created_at, r.updated_at,
                    a.name AS requester_name,
                    json_agg(json_build_object(
                        'id', i.id, 'vendor_company', i.vendor_company, 'product_name', i.product_name,
                        'catalog_id', i.catalog_id, 'product_link', i.product_link,
                        'quantity', i.quantity, 'unit_price', i.unit_price, 'item_total', i.item_total,
                        'currency', i.currency, 'ordered_at', i.ordered_at, 'received_at', i.received_at,
                        'internal_order_number', i.internal_order_number,
                        'item_status', COALESCE(i.item_status, 'Active'),
                        'status_note', i.status_note,
                        'proposed_vendor', i.proposed_vendor, 'proposed_product', i.proposed_product,
                        'proposed_catalog_id', i.proposed_catalog_id, 'proposed_link', i.proposed_link,
                        'proposed_qty', i.proposed_qty, 'proposed_unit_price', i.proposed_unit_price,
                        'modified_by', i.modified_by, 'modified_at', i.modified_at,
                        'pi_decision_note', i.pi_decision_note, 'pi_decision_at', i.pi_decision_at
                    ) ORDER BY i.created_at) AS items,
                    COUNT(*) FILTER (WHERE COALESCE(i.item_status,'Active') IN ('Modification Requested','Cancel Requested')) AS pending_change_count
             FROM di_purchase_requests r
             JOIN di_purchase_items i ON i.request_id = r.id
             LEFT JOIN di_allowlist a ON a.researcher_id = r.requester_id
             GROUP BY r.id, a.name
             ORDER BY r.created_at DESC`
        );
        const requests = result.rows.map(r => ({
            ...r,
            pending_change_count: parseInt(r.pending_change_count) || 0,
            has_pending_changes: parseInt(r.pending_change_count) > 0
        }));
        res.json({ success: true, requests });
    } catch (err) {
        console.error('[PURCHASES] All requests error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/purchases/:id/approve — PI approves a purchase request
app.post('/api/di/purchases/:id/approve', requirePI, async (req, res) => {
    try {
        const { id } = req.params;
        const result = await pool.query(
            `UPDATE di_purchase_requests SET status = 'APPROVED', updated_at = CURRENT_TIMESTAMP
             WHERE id = $1 AND status = 'SUBMITTED' RETURNING id`,
            [id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Request not found or not in SUBMITTED status' });
        }
        console.log(`[PURCHASES] Request ${id} approved by PI`);
        res.json({ success: true });
    } catch (err) {
        console.error('[PURCHASES] Approve error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/purchases/:id/decline — PI declines a purchase request (requires comment)
app.post('/api/di/purchases/:id/decline', requirePI, async (req, res) => {
    try {
        const { id } = req.params;
        const { pi_comment } = req.body;

        if (!pi_comment || !pi_comment.trim()) {
            return res.status(400).json({ error: 'A comment is required when declining a request' });
        }

        const result = await pool.query(
            `UPDATE di_purchase_requests SET status = 'DECLINED', pi_comment = $1, updated_at = CURRENT_TIMESTAMP
             WHERE id = $2 AND status = 'SUBMITTED' RETURNING id`,
            [pi_comment.trim(), id]
        );
        if (result.rows.length === 0) {
            return res.status(404).json({ error: 'Request not found or not in SUBMITTED status' });
        }
        console.log(`[PURCHASES] Request ${id} declined by PI`);
        res.json({ success: true });
    } catch (err) {
        console.error('[PURCHASES] Decline error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/purchases/item/:itemId/mark-ordered — PI marks item as ordered + generates PO number
app.post('/api/di/purchases/item/:itemId/mark-ordered', requirePI, async (req, res) => {
    const client = await pool.connect();
    try {
        const { itemId } = req.params;
        await client.query('BEGIN');

        // Generate PO number
        const poNumber = await generatePONumber(client);

        // Verify item is Active and parent request is APPROVED before ordering
        const check = await client.query(
            `SELECT i.id, i.item_status, r.status AS request_status
             FROM di_purchase_items i JOIN di_purchase_requests r ON r.id = i.request_id
             WHERE i.id = $1`, [itemId]);
        if (check.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Item not found' });
        }
        const chk = check.rows[0];
        if (chk.request_status !== 'APPROVED') {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Parent request must be Approved' });
        }
        if ((chk.item_status || 'Active') !== 'Active') {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Item must be Active to mark as ordered' });
        }

        const result = await client.query(
            `UPDATE di_purchase_items SET ordered_at = CURRENT_TIMESTAMP, internal_order_number = $2
             WHERE id = $1 AND ordered_at IS NULL AND (item_status = 'Active' OR item_status IS NULL)
             RETURNING id, request_id, internal_order_number`,
            [itemId, poNumber]
        );
        if (result.rows.length === 0) {
            await client.query('ROLLBACK');
            return res.status(404).json({ error: 'Item not found or already marked as ordered' });
        }

        await purchaseAudit(client, {
            request_id: result.rows[0].request_id, item_id: itemId, action: 'MARK_ORDERED',
            actor_id: req.session.user.researcher_id || req.session.user.name || 'PI', actor_role: 'PI',
            old_json: { ordered_at: null }, new_json: { ordered_at: new Date().toISOString(), internal_order_number: poNumber },
            note: null
        });

        await client.query('COMMIT');
        console.log(`[PURCHASES] Item ${itemId} marked as ordered, PO: ${poNumber}`);
        res.json({ success: true, internal_order_number: poNumber });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('[PURCHASES] Mark ordered error:', err);
        res.status(500).json({ error: 'Server error' });
    } finally {
        client.release();
    }
});

// ==================== PURCHASE ITEM CORRECTION WORKFLOW ====================

// Helper: fetch item with parent request context for guard validation
async function fetchItemWithContext(itemId, client) {
    const q = client || pool;
    const result = await q.query(
        `SELECT i.*, r.requester_id, r.status AS request_status, r.id AS parent_request_id
         FROM di_purchase_items i
         JOIN di_purchase_requests r ON r.id = i.request_id
         WHERE i.id = $1`,
        [itemId]
    );
    return result.rows[0] || null;
}

// Helper: write audit record
async function purchaseAudit(client, { request_id, item_id, action, actor_id, actor_role, old_json, new_json, note }) {
    const q = client || pool;
    await q.query(
        `INSERT INTO di_purchase_audit (request_id, item_id, action, actor_id, actor_role, old_json, new_json, note)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)`,
        [request_id, item_id, action, actor_id, actor_role,
         old_json ? JSON.stringify(old_json) : null,
         new_json ? JSON.stringify(new_json) : null,
         note || null]
    );
}

// Helper: recompute request_total excluding Cancelled items
async function recomputeRequestTotal(client, requestId) {
    await client.query(
        `UPDATE di_purchase_requests SET request_total = COALESCE((
            SELECT SUM(item_total) FROM di_purchase_items
            WHERE request_id = $1 AND COALESCE(item_status, 'Active') != 'Cancelled'
         ), 0), updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
        [requestId]
    );
}

// POST /api/di/purchase-items/:item_id/request-modify — Researcher requests modification
app.post('/api/di/purchase-items/:item_id/request-modify', requireAuth, requireInternal, async (req, res) => {
    const client = await pool.connect();
    try {
        const user = req.session.user;
        const { item_id } = req.params;
        const { proposed_vendor, proposed_product, proposed_catalog_id, proposed_link, proposed_qty, proposed_unit_price, note } = req.body;

        if (!note || !note.trim()) {
            return res.status(400).json({ error: 'A note is required when requesting a modification' });
        }

        await client.query('BEGIN');
        const item = await fetchItemWithContext(item_id, client);
        if (!item) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Item not found' }); }
        if (item.requester_id !== user.researcher_id) { await client.query('ROLLBACK'); return res.status(403).json({ error: 'Not your request' }); }
        if (item.request_status !== 'APPROVED') { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Request must be Approved' }); }
        if (item.ordered_at) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Item already ordered, cannot modify' }); }
        if ((item.item_status || 'Active') !== 'Active') { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Item must be Active to request modification' }); }

        const oldValues = {
            vendor_company: item.vendor_company, product_name: item.product_name,
            catalog_id: item.catalog_id, product_link: item.product_link,
            quantity: item.quantity, unit_price: item.unit_price
        };

        await client.query(
            `UPDATE di_purchase_items SET
                item_status = 'Modification Requested',
                status_note = $2,
                proposed_vendor = COALESCE($3, proposed_vendor),
                proposed_product = COALESCE($4, proposed_product),
                proposed_catalog_id = COALESCE($5, proposed_catalog_id),
                proposed_link = COALESCE($6, proposed_link),
                proposed_qty = COALESCE($7, proposed_qty),
                proposed_unit_price = COALESCE($8, proposed_unit_price)
             WHERE id = $1`,
            [item_id, note.trim(),
             proposed_vendor || null, proposed_product || null, proposed_catalog_id || null,
             proposed_link || null, proposed_qty || null, proposed_unit_price || null]
        );

        await purchaseAudit(client, {
            request_id: item.parent_request_id, item_id, action: 'REQ_MODIFY',
            actor_id: user.researcher_id, actor_role: 'researcher',
            old_json: oldValues,
            new_json: { proposed_vendor, proposed_product, proposed_catalog_id, proposed_link, proposed_qty, proposed_unit_price },
            note: note.trim()
        });

        await client.query('COMMIT');
        console.log(`[PURCHASES] Modification requested for item ${item_id} by ${user.researcher_id}`);
        res.json({ success: true });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('[PURCHASES] Request modify error:', err);
        res.status(500).json({ error: 'Server error' });
    } finally {
        client.release();
    }
});

// POST /api/di/purchase-items/:item_id/request-cancel — Researcher requests cancellation
app.post('/api/di/purchase-items/:item_id/request-cancel', requireAuth, requireInternal, async (req, res) => {
    const client = await pool.connect();
    try {
        const user = req.session.user;
        const { item_id } = req.params;
        const { note } = req.body;

        if (!note || !note.trim()) {
            return res.status(400).json({ error: 'A note is required when requesting cancellation' });
        }

        await client.query('BEGIN');
        const item = await fetchItemWithContext(item_id, client);
        if (!item) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Item not found' }); }
        if (item.requester_id !== user.researcher_id) { await client.query('ROLLBACK'); return res.status(403).json({ error: 'Not your request' }); }
        if (item.request_status !== 'APPROVED') { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Request must be Approved' }); }
        if (item.ordered_at) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Item already ordered, cannot cancel' }); }
        if ((item.item_status || 'Active') !== 'Active') { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Item must be Active to request cancellation' }); }

        await client.query(
            `UPDATE di_purchase_items SET item_status = 'Cancel Requested', status_note = $2 WHERE id = $1`,
            [item_id, note.trim()]
        );

        await purchaseAudit(client, {
            request_id: item.parent_request_id, item_id, action: 'REQ_CANCEL',
            actor_id: user.researcher_id, actor_role: 'researcher',
            old_json: { item_status: item.item_status || 'Active' },
            new_json: { item_status: 'Cancel Requested' },
            note: note.trim()
        });

        await client.query('COMMIT');
        console.log(`[PURCHASES] Cancellation requested for item ${item_id} by ${user.researcher_id}`);
        res.json({ success: true });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('[PURCHASES] Request cancel error:', err);
        res.status(500).json({ error: 'Server error' });
    } finally {
        client.release();
    }
});

// POST /api/di/purchase-items/:item_id/pi-accept — PI accepts modification or cancellation
app.post('/api/di/purchase-items/:item_id/pi-accept', requirePI, async (req, res) => {
    const client = await pool.connect();
    try {
        const user = req.session.user;
        const { item_id } = req.params;
        const { decision_note } = req.body;

        await client.query('BEGIN');
        const item = await fetchItemWithContext(item_id, client);
        if (!item) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Item not found' }); }
        if (item.request_status !== 'APPROVED') { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Request must be Approved' }); }
        if (item.ordered_at) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Item already ordered' }); }

        const itemStatus = item.item_status || 'Active';
        if (itemStatus !== 'Modification Requested' && itemStatus !== 'Cancel Requested') {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Item has no pending change request' });
        }

        if (itemStatus === 'Modification Requested') {
            // Apply proposed values to live fields
            const oldValues = {
                vendor_company: item.vendor_company, product_name: item.product_name,
                catalog_id: item.catalog_id, product_link: item.product_link,
                quantity: item.quantity, unit_price: item.unit_price, item_total: item.item_total
            };

            const newVendor = item.proposed_vendor || item.vendor_company;
            const newProduct = item.proposed_product || item.product_name;
            const newCatalog = item.proposed_catalog_id || item.catalog_id;
            const newLink = item.proposed_link || item.product_link;
            const newQty = item.proposed_qty || item.quantity;
            const newPrice = item.proposed_unit_price || item.unit_price;
            const newTotal = Math.round(Number(newQty) * Number(newPrice) * 100) / 100;

            await client.query(
                `UPDATE di_purchase_items SET
                    vendor_company = $2, product_name = $3, catalog_id = $4, product_link = $5,
                    quantity = $6, unit_price = $7, item_total = $8,
                    item_status = 'Active',
                    proposed_vendor = NULL, proposed_product = NULL, proposed_catalog_id = NULL,
                    proposed_link = NULL, proposed_qty = NULL, proposed_unit_price = NULL,
                    status_note = NULL,
                    modified_by = $9, modified_at = NOW(),
                    pi_decision_note = $10, pi_decision_at = NOW()
                 WHERE id = $1`,
                [item_id, newVendor, newProduct, newCatalog, newLink, newQty, newPrice, newTotal,
                 user.researcher_id || user.name || 'PI', decision_note || null]
            );

            await purchaseAudit(client, {
                request_id: item.parent_request_id, item_id, action: 'PI_ACCEPT_MODIFY',
                actor_id: user.researcher_id || user.name || 'PI', actor_role: 'PI',
                old_json: oldValues,
                new_json: { vendor_company: newVendor, product_name: newProduct, catalog_id: newCatalog, product_link: newLink, quantity: newQty, unit_price: newPrice, item_total: newTotal },
                note: decision_note || null
            });

            // Recompute request total
            await recomputeRequestTotal(client, item.parent_request_id);

        } else {
            // Cancel Requested — accept cancellation
            await client.query(
                `UPDATE di_purchase_items SET
                    item_status = 'Cancelled',
                    modified_by = $2, modified_at = NOW(),
                    pi_decision_note = $3, pi_decision_at = NOW()
                 WHERE id = $1`,
                [item_id, user.researcher_id || user.name || 'PI', decision_note || null]
            );

            await purchaseAudit(client, {
                request_id: item.parent_request_id, item_id, action: 'PI_ACCEPT_CANCEL',
                actor_id: user.researcher_id || user.name || 'PI', actor_role: 'PI',
                old_json: { item_status: 'Cancel Requested' },
                new_json: { item_status: 'Cancelled' },
                note: decision_note || null
            });

            // Recompute request total excluding cancelled
            await recomputeRequestTotal(client, item.parent_request_id);
        }

        await client.query('COMMIT');
        console.log(`[PURCHASES] PI accepted ${itemStatus} for item ${item_id}`);

        // Return updated item and request total
        const updated = await pool.query(
            `SELECT i.*, r.request_total FROM di_purchase_items i
             JOIN di_purchase_requests r ON r.id = i.request_id WHERE i.id = $1`, [item_id]);
        res.json({ success: true, item: updated.rows[0] });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('[PURCHASES] PI accept error:', err);
        res.status(500).json({ error: 'Server error' });
    } finally {
        client.release();
    }
});

// POST /api/di/purchase-items/:item_id/pi-reject — PI rejects modification or cancellation
app.post('/api/di/purchase-items/:item_id/pi-reject', requirePI, async (req, res) => {
    const client = await pool.connect();
    try {
        const user = req.session.user;
        const { item_id } = req.params;
        const { decision_note } = req.body;

        if (!decision_note || !decision_note.trim()) {
            return res.status(400).json({ error: 'A decision note is required when rejecting' });
        }

        await client.query('BEGIN');
        const item = await fetchItemWithContext(item_id, client);
        if (!item) { await client.query('ROLLBACK'); return res.status(404).json({ error: 'Item not found' }); }
        if (item.request_status !== 'APPROVED') { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Request must be Approved' }); }
        if (item.ordered_at) { await client.query('ROLLBACK'); return res.status(400).json({ error: 'Item already ordered' }); }

        const itemStatus = item.item_status || 'Active';
        if (itemStatus !== 'Modification Requested' && itemStatus !== 'Cancel Requested') {
            await client.query('ROLLBACK');
            return res.status(400).json({ error: 'Item has no pending change request' });
        }

        const auditAction = itemStatus === 'Modification Requested' ? 'PI_REJECT_MODIFY' : 'PI_REJECT_CANCEL';

        await client.query(
            `UPDATE di_purchase_items SET
                item_status = 'Active',
                proposed_vendor = NULL, proposed_product = NULL, proposed_catalog_id = NULL,
                proposed_link = NULL, proposed_qty = NULL, proposed_unit_price = NULL,
                status_note = NULL,
                pi_decision_note = $2, pi_decision_at = NOW()
             WHERE id = $1`,
            [item_id, decision_note.trim()]
        );

        await purchaseAudit(client, {
            request_id: item.parent_request_id, item_id, action: auditAction,
            actor_id: user.researcher_id || user.name || 'PI', actor_role: 'PI',
            old_json: { item_status: itemStatus },
            new_json: { item_status: 'Active' },
            note: decision_note.trim()
        });

        await client.query('COMMIT');
        console.log(`[PURCHASES] PI rejected ${itemStatus} for item ${item_id}`);

        const updated = await pool.query(`SELECT * FROM di_purchase_items WHERE id = $1`, [item_id]);
        res.json({ success: true, item: updated.rows[0] });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('[PURCHASES] PI reject error:', err);
        res.status(500).json({ error: 'Server error' });
    } finally {
        client.release();
    }
});

// GET /api/di/purchases/consolidated — PI consolidated email list of approved, non-ordered items
app.get('/api/di/purchases/consolidated', requirePI, async (req, res) => {
    try {
        const { affiliation } = req.query;
        if (!affiliation || !['LiU', 'UNAV'].includes(affiliation)) {
            return res.status(400).json({ error: 'affiliation must be LiU or UNAV' });
        }

        const result = await pool.query(
            `SELECT i.id, i.vendor_company, i.product_name, i.catalog_id, i.product_link,
                    i.quantity, i.unit_price, i.item_total, i.currency, i.internal_order_number,
                    r.id AS request_id, r.requester_id,
                    a.name AS requester_name
             FROM di_purchase_items i
             JOIN di_purchase_requests r ON r.id = i.request_id
             LEFT JOIN di_allowlist a ON a.researcher_id = r.requester_id
             WHERE r.status = 'APPROVED' AND r.affiliation = $1 AND i.ordered_at IS NULL
               AND (i.item_status = 'Active' OR i.item_status IS NULL)
             ORDER BY r.created_at, i.created_at`,
            [affiliation]
        );

        // Compute total
        const items = result.rows;
        const total = Math.round(items.reduce((s, i) => s + Number(i.item_total), 0) * 100) / 100;
        const currency = items.length > 0 ? items[0].currency : '';

        res.json({ success: true, affiliation, items, total, currency });
    } catch (err) {
        console.error('[PURCHASES] Consolidated error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});


// ==================== INVENTORY V2 — CANONICAL MODEL ====================

const VALID_UNITS_V2 = ['bottle', 'box', 'pack', 'each', 'mL', 'uL', 'mg', 'g', 'vial', 'tube', 'slides', 'plate', 'aliquots', 'other'];
const VALID_STORAGE_TEMPS = ['RT', '4C', '-20C', '-80C', 'LN2'];
const VALID_ITEM_TYPES = ['product', 'sample', 'oligo'];

// PO number generator: PO-NAT-YYYYMMDD-XXX
async function generatePONumber(client) {
    const today = new Date();
    const datePrefix = today.toISOString().slice(0, 10).replace(/-/g, '');
    const result = await client.query(
        `INSERT INTO di_po_sequence (date_prefix, last_seq) VALUES ($1, 1)
         ON CONFLICT (date_prefix) DO UPDATE SET last_seq = di_po_sequence.last_seq + 1
         RETURNING last_seq`,
        [datePrefix]
    );
    const seq = String(result.rows[0].last_seq).padStart(3, '0');
    return `PO-NAT-${datePrefix}-${seq}`;
}

// GET /api/di/inventory-v2/my-items — researcher's own inventory
app.get('/api/di/inventory-v2/my-items', requireAuth, requireInternal, async (req, res) => {
    try {
        const user = req.session.user;
        const { item_type } = req.query;
        let query = `SELECT ii.*, a.name AS created_by_name FROM di_inventory_items ii
                     LEFT JOIN di_allowlist a ON a.researcher_id = ii.created_by
                     WHERE ii.created_by = $1 AND ii.status NOT IN ('Consumed','Deleted') AND ii.transferred_at IS NULL`;
        const params = [user.researcher_id];
        if (item_type && VALID_ITEM_TYPES.includes(item_type)) {
            query += ` AND ii.item_type = $${params.length + 1}`;
            params.push(item_type);
        }
        query += ` ORDER BY ii.updated_at DESC`;
        const result = await pool.query(query, params);
        res.json({ success: true, items: result.rows });
    } catch (err) {
        console.error('[INV-V2] my-items error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/inventory-v2/group-items — group inventory (visibility_scope=group, active statuses)
app.get('/api/di/inventory-v2/group-items', requireAuth, requireInternal, async (req, res) => {
    try {
        const { item_type } = req.query;
        let query = `SELECT ii.*, a.name AS created_by_name FROM di_inventory_items ii
                     LEFT JOIN di_allowlist a ON a.researcher_id = ii.created_by
                     WHERE ii.visibility_scope = 'group' AND ii.status IN ('Approved', 'Received', 'DeletePending')`;
        const params = [];
        if (item_type && VALID_ITEM_TYPES.includes(item_type)) {
            query += ` AND ii.item_type = $${params.length + 1}`;
            params.push(item_type);
        }
        query += ` ORDER BY ii.updated_at DESC`;
        const result = await pool.query(query, params);
        res.json({ success: true, items: result.rows });
    } catch (err) {
        console.error('[INV-V2] group-items error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/inventory-v2/offline-entry — create offline product/sample (status=Pending)
app.post('/api/di/inventory-v2/offline-entry', requireAuth, requireInternal, async (req, res) => {
    try {
        const user = req.session.user;
        const { item_type, item_name, item_identifier, quantity, quantity_unit,
                storage_location, storage_temperature, vendor_company, product_link,
                lot_or_batch_number, expiry_date, opened_date, notes,
                sample_origin, provider_or_collaborator, provider_detail, sample_status } = req.body;

        // Validate item_type
        if (!item_type || !['product', 'sample'].includes(item_type)) {
            return res.status(400).json({ error: 'item_type must be product or sample' });
        }
        if (!item_name || !item_name.trim()) return res.status(400).json({ error: 'item_name is required' });
        if (!item_identifier || !item_identifier.trim()) return res.status(400).json({ error: 'item_identifier is required' });
        if (!quantity || isNaN(quantity) || Number(quantity) <= 0) return res.status(400).json({ error: 'quantity must be positive' });
        if (!quantity_unit || !VALID_UNITS_V2.includes(quantity_unit)) return res.status(400).json({ error: 'Invalid quantity_unit' });
        if (!storage_location || !storage_location.trim()) return res.status(400).json({ error: 'storage_location is required' });
        if (!storage_temperature || !VALID_STORAGE_TEMPS.includes(storage_temperature)) return res.status(400).json({ error: 'Invalid storage_temperature' });

        const result = await pool.query(
            `INSERT INTO di_inventory_items (
                affiliation, item_type, source, item_name, item_identifier,
                quantity, quantity_unit, storage_location, storage_temperature,
                vendor_company, product_link, lot_or_batch_number, expiry_date, opened_date, notes,
                sample_origin, provider_or_collaborator, provider_detail, sample_status,
                visibility_scope, created_by, status, owner_type
            ) VALUES ($1, $2, 'Offline', $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15, $16, $17, $18, 'personal', $19, 'Pending', 'group')
            RETURNING *`,
            [user.affiliation, item_type, item_name.trim(), item_identifier.trim(),
             Number(quantity), quantity_unit, storage_location.trim(), storage_temperature,
             vendor_company || null, product_link || null, lot_or_batch_number || null,
             expiry_date || null, opened_date || null, notes || null,
             sample_origin || null, provider_or_collaborator || null, provider_detail || null, sample_status || null,
             user.researcher_id]
        );

        // Audit log
        await pool.query(
            `INSERT INTO di_inventory_items_log (inventory_item_id, action, changed_by, new_values)
             VALUES ($1, 'CREATE', $2, $3)`,
            [result.rows[0].id, user.researcher_id, JSON.stringify(result.rows[0])]
        );

        console.log(`[INV-V2] Offline ${item_type} created by ${user.researcher_id}: ${result.rows[0].id}`);
        res.json({ success: true, item: result.rows[0] });
    } catch (err) {
        console.error('[INV-V2] offline-entry error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// PATCH /api/di/inventory-v2/:id — owner edits own item
app.patch('/api/di/inventory-v2/:id', requireAuth, requireInternal, async (req, res) => {
    try {
        const user = req.session.user;
        const { id } = req.params;
        const { quantity, quantity_unit, storage_location, storage_temperature,
                lot_or_batch_number, expiry_date, opened_date, notes, sample_status } = req.body;

        // Verify ownership
        const existing = await pool.query('SELECT * FROM di_inventory_items WHERE id = $1', [id]);
        if (existing.rows.length === 0) return res.status(404).json({ error: 'Item not found' });
        const item = existing.rows[0];
        if (item.created_by !== user.researcher_id) return res.status(403).json({ error: 'You can only edit your own items' });

        const updates = [];
        const params = [];
        let idx = 1;

        if (quantity !== undefined && !isNaN(quantity)) { updates.push(`quantity = $${idx++}`); params.push(Number(quantity)); }
        if (quantity_unit && VALID_UNITS_V2.includes(quantity_unit)) { updates.push(`quantity_unit = $${idx++}`); params.push(quantity_unit); }
        if (storage_location) { updates.push(`storage_location = $${idx++}`); params.push(storage_location.trim()); }
        if (storage_temperature && VALID_STORAGE_TEMPS.includes(storage_temperature)) { updates.push(`storage_temperature = $${idx++}`); params.push(storage_temperature); }
        if (lot_or_batch_number !== undefined) { updates.push(`lot_or_batch_number = $${idx++}`); params.push(lot_or_batch_number || null); }
        if (expiry_date !== undefined) { updates.push(`expiry_date = $${idx++}`); params.push(expiry_date || null); }
        if (opened_date !== undefined) { updates.push(`opened_date = $${idx++}`); params.push(opened_date || null); }
        if (notes !== undefined) { updates.push(`notes = $${idx++}`); params.push(notes || null); }
        if (sample_status !== undefined) { updates.push(`sample_status = $${idx++}`); params.push(sample_status || null); }

        if (updates.length === 0) return res.status(400).json({ error: 'No valid fields to update' });

        updates.push(`updated_at = CURRENT_TIMESTAMP`);
        params.push(id);
        const result = await pool.query(
            `UPDATE di_inventory_items SET ${updates.join(', ')} WHERE id = $${idx} RETURNING *`,
            params
        );

        // Audit log
        await pool.query(
            `INSERT INTO di_inventory_items_log (inventory_item_id, action, changed_by, old_values, new_values)
             VALUES ($1, 'UPDATE', $2, $3, $4)`,
            [id, user.researcher_id, JSON.stringify(item), JSON.stringify(result.rows[0])]
        );

        res.json({ success: true, item: result.rows[0] });
    } catch (err) {
        console.error('[INV-V2] patch error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// PUT /api/di/inventory-v2/:id/mark-finished — owner marks item as finished
app.put('/api/di/inventory-v2/:id/mark-finished', requireAuth, requireInternal, async (req, res) => {
    try {
        const user = req.session.user;
        const { id } = req.params;
        const existing = await pool.query('SELECT * FROM di_inventory_items WHERE id = $1', [id]);
        if (existing.rows.length === 0) return res.status(404).json({ error: 'Item not found' });
        if (existing.rows[0].created_by !== user.researcher_id) return res.status(403).json({ error: 'You can only manage your own items' });

        const result = await pool.query(
            `UPDATE di_inventory_items SET quantity = 0, status = 'Rejected', updated_at = CURRENT_TIMESTAMP
             WHERE id = $1 RETURNING *`,
            [id]
        );

        await pool.query(
            `INSERT INTO di_inventory_items_log (inventory_item_id, action, changed_by, old_values, new_values)
             VALUES ($1, 'MARK_FINISHED', $2, $3, $4)`,
            [id, user.researcher_id, JSON.stringify(existing.rows[0]), JSON.stringify(result.rows[0])]
        );

        res.json({ success: true });
    } catch (err) {
        console.error('[INV-V2] mark-finished error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/inventory-v2/all — PI views all inventory items with filters
app.get('/api/di/inventory-v2/all', requirePI, async (req, res) => {
    try {
        const { item_type, affiliation, visibility_scope, status, source } = req.query;
        let query = `SELECT ii.*, a.name AS created_by_name FROM di_inventory_items ii
                     LEFT JOIN di_allowlist a ON a.researcher_id = ii.created_by WHERE 1=1`;
        const params = [];

        if (item_type && VALID_ITEM_TYPES.includes(item_type)) { params.push(item_type); query += ` AND ii.item_type = $${params.length}`; }
        if (affiliation && ['LiU', 'UNAV'].includes(affiliation)) { params.push(affiliation); query += ` AND ii.affiliation = $${params.length}`; }
        if (visibility_scope && ['personal', 'group'].includes(visibility_scope)) { params.push(visibility_scope); query += ` AND ii.visibility_scope = $${params.length}`; }
        if (status && ['Pending', 'Approved', 'Revision', 'Rejected', 'Received', 'ConsumePending', 'TransferPending', 'ApprovedLinked', 'Consumed', 'DeletePending', 'Deleted'].includes(status)) { params.push(status); query += ` AND ii.status = $${params.length}`; }
        if (source && ['Online', 'Offline'].includes(source)) { params.push(source); query += ` AND ii.source = $${params.length}`; }

        query += ` ORDER BY ii.updated_at DESC`;
        const result = await pool.query(query, params);
        res.json({ success: true, items: result.rows });
    } catch (err) {
        console.error('[INV-V2] all error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/inventory-v2/:id/promote-to-group — PI promotes to group inventory
app.post('/api/di/inventory-v2/:id/promote-to-group', requirePI, async (req, res) => {
    try {
        const { id } = req.params;
        const existing = await pool.query('SELECT * FROM di_inventory_items WHERE id = $1', [id]);
        if (existing.rows.length === 0) return res.status(404).json({ error: 'Item not found' });
        if (existing.rows[0].status !== 'Approved') return res.status(400).json({ error: 'Only approved items can be promoted' });
        if (existing.rows[0].visibility_scope === 'group') return res.status(400).json({ error: 'Item is already in group inventory' });

        await pool.query(
            `UPDATE di_inventory_items SET visibility_scope = 'group', updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
            [id]
        );

        await pool.query(
            `INSERT INTO di_inventory_items_log (inventory_item_id, action, changed_by, old_values, new_values)
             VALUES ($1, 'PROMOTE_TO_GROUP', $2, $3, $4)`,
            [id, req.session.user.researcher_id, JSON.stringify({ visibility_scope: 'personal' }), JSON.stringify({ visibility_scope: 'group' })]
        );

        console.log(`[INV-V2] Item ${id} promoted to group by PI`);
        res.json({ success: true });
    } catch (err) {
        console.error('[INV-V2] promote error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/inventory-v2/:id/demote-from-group — PI removes from group
app.post('/api/di/inventory-v2/:id/demote-from-group', requirePI, async (req, res) => {
    try {
        const { id } = req.params;
        const existing = await pool.query('SELECT * FROM di_inventory_items WHERE id = $1', [id]);
        if (existing.rows.length === 0) return res.status(404).json({ error: 'Item not found' });
        if (existing.rows[0].visibility_scope !== 'group') return res.status(400).json({ error: 'Item is not in group inventory' });

        await pool.query(
            `UPDATE di_inventory_items SET visibility_scope = 'personal', updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
            [id]
        );

        await pool.query(
            `INSERT INTO di_inventory_items_log (inventory_item_id, action, changed_by, old_values, new_values)
             VALUES ($1, 'DEMOTE_FROM_GROUP', $2, $3, $4)`,
            [id, req.session.user.researcher_id, JSON.stringify({ visibility_scope: 'group' }), JSON.stringify({ visibility_scope: 'personal' })]
        );

        res.json({ success: true });
    } catch (err) {
        console.error('[INV-V2] demote error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/inventory-v2/:id/approve — PI approves pending item
app.post('/api/di/inventory-v2/:id/approve', requirePI, async (req, res) => {
    try {
        const { id } = req.params;
        const existing = await pool.query('SELECT * FROM di_inventory_items WHERE id = $1', [id]);
        if (existing.rows.length === 0) return res.status(404).json({ error: 'Item not found' });
        if (existing.rows[0].status !== 'Pending' && existing.rows[0].status !== 'Revision') {
            return res.status(400).json({ error: 'Only Pending or Revision items can be approved' });
        }

        await pool.query(
            `UPDATE di_inventory_items SET status = 'Approved', status_comment = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
            [id]
        );

        await pool.query(
            `INSERT INTO di_inventory_items_log (inventory_item_id, action, changed_by, old_values, new_values)
             VALUES ($1, 'APPROVE', $2, $3, $4)`,
            [id, req.session.user.researcher_id, JSON.stringify({ status: existing.rows[0].status }), JSON.stringify({ status: 'Approved' })]
        );

        console.log(`[INV-V2] Item ${id} approved by PI`);
        res.json({ success: true });
    } catch (err) {
        console.error('[INV-V2] approve error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/inventory-v2/:id/revision — PI requests revision
app.post('/api/di/inventory-v2/:id/revision', requirePI, async (req, res) => {
    try {
        const { id } = req.params;
        const { comment } = req.body;
        if (!comment || !comment.trim()) return res.status(400).json({ error: 'Comment is required for revision request' });

        const existing = await pool.query('SELECT * FROM di_inventory_items WHERE id = $1', [id]);
        if (existing.rows.length === 0) return res.status(404).json({ error: 'Item not found' });

        await pool.query(
            `UPDATE di_inventory_items SET status = 'Revision', status_comment = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
            [id, comment.trim()]
        );

        await pool.query(
            `INSERT INTO di_inventory_items_log (inventory_item_id, action, changed_by, old_values, new_values)
             VALUES ($1, 'REVISION', $2, $3, $4)`,
            [id, req.session.user.researcher_id, JSON.stringify({ status: existing.rows[0].status }), JSON.stringify({ status: 'Revision', status_comment: comment.trim() })]
        );

        res.json({ success: true });
    } catch (err) {
        console.error('[INV-V2] revision error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/inventory-v2/:id/reject — PI rejects item
app.post('/api/di/inventory-v2/:id/reject', requirePI, async (req, res) => {
    try {
        const { id } = req.params;
        const { comment } = req.body;
        if (!comment || !comment.trim()) return res.status(400).json({ error: 'Comment is required for rejection' });

        const existing = await pool.query('SELECT * FROM di_inventory_items WHERE id = $1', [id]);
        if (existing.rows.length === 0) return res.status(404).json({ error: 'Item not found' });

        await pool.query(
            `UPDATE di_inventory_items SET status = 'Rejected', status_comment = $2, updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
            [id, comment.trim()]
        );

        await pool.query(
            `INSERT INTO di_inventory_items_log (inventory_item_id, action, changed_by, old_values, new_values)
             VALUES ($1, 'REJECT', $2, $3, $4)`,
            [id, req.session.user.researcher_id, JSON.stringify({ status: existing.rows[0].status }), JSON.stringify({ status: 'Rejected', status_comment: comment.trim() })]
        );

        res.json({ success: true });
    } catch (err) {
        console.error('[INV-V2] reject error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// GET /api/di/inventory-v2/po-numbers — PI searchable PO monitoring
app.get('/api/di/inventory-v2/po-numbers', requirePI, async (req, res) => {
    try {
        const { search } = req.query;
        let query = `SELECT pi2.internal_order_number, pi2.product_name, pi2.catalog_id, pi2.product_link,
                            pi2.ordered_at, pi2.received_at, pr.requester_id, a.name AS requester_name
                     FROM di_purchase_items pi2
                     JOIN di_purchase_requests pr ON pr.id = pi2.request_id
                     LEFT JOIN di_allowlist a ON a.researcher_id = pr.requester_id
                     WHERE pi2.internal_order_number IS NOT NULL`;
        const params = [];
        if (search && search.trim()) {
            params.push(`%${search.trim().toLowerCase()}%`);
            query += ` AND (LOWER(pi2.internal_order_number) LIKE $1 OR LOWER(pi2.product_name) LIKE $1 OR LOWER(a.name) LIKE $1 OR LOWER(pr.requester_id) LIKE $1)`;
        }
        query += ` ORDER BY pi2.ordered_at DESC NULLS LAST`;
        const result = await pool.query(query, params);
        res.json({ success: true, items: result.rows });
    } catch (err) {
        console.error('[INV-V2] po-numbers error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== INVENTORY RULES — NEW LIFECYCLE ENDPOINTS ====================

// POST /api/di/inventory-v2/:id/request-consume — researcher/supervisor requests consume
app.post('/api/di/inventory-v2/:id/request-consume', requireAuth, requireInternal, async (req, res) => {
    try {
        const user = req.session.user;
        const { id } = req.params;
        const existing = await pool.query('SELECT * FROM di_inventory_items WHERE id = $1', [id]);
        if (existing.rows.length === 0) return res.status(404).json({ error: 'Item not found' });
        const item = existing.rows[0];
        if (item.created_by !== user.researcher_id) return res.status(403).json({ error: 'You can only manage your own items' });
        if (!['Received', 'Approved', 'ApprovedLinked'].includes(item.status)) {
            return res.status(400).json({ error: 'Item must be Received, Approved, or ApprovedLinked to request consume' });
        }

        await pool.query(
            `UPDATE di_inventory_items SET previous_status = status, status = 'ConsumePending', updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
            [id]
        );

        await pool.query(
            `INSERT INTO di_inventory_items_log (inventory_item_id, action, changed_by, old_values, new_values)
             VALUES ($1, 'REQUEST_CONSUME', $2, $3, $4)`,
            [id, user.researcher_id, JSON.stringify({ status: item.status }), JSON.stringify({ status: 'ConsumePending', previous_status: item.status })]
        );

        console.log(`[INV-V2] Consume requested for ${id} by ${user.researcher_id}`);
        res.json({ success: true });
    } catch (err) {
        console.error('[INV-V2] request-consume error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/inventory-v2/:id/request-transfer — researcher/supervisor requests transfer to group
app.post('/api/di/inventory-v2/:id/request-transfer', requireAuth, requireInternal, async (req, res) => {
    try {
        const user = req.session.user;
        const { id } = req.params;
        const existing = await pool.query('SELECT * FROM di_inventory_items WHERE id = $1', [id]);
        if (existing.rows.length === 0) return res.status(404).json({ error: 'Item not found' });
        const item = existing.rows[0];
        if (item.created_by !== user.researcher_id) return res.status(403).json({ error: 'You can only manage your own items' });
        if (item.source !== 'Online') return res.status(400).json({ error: 'Only online items can be transferred to group' });
        if (item.status !== 'Received') return res.status(400).json({ error: 'Item must be Received to request transfer' });

        await pool.query(
            `UPDATE di_inventory_items SET previous_status = status, status = 'TransferPending', updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
            [id]
        );

        await pool.query(
            `INSERT INTO di_inventory_items_log (inventory_item_id, action, changed_by, old_values, new_values)
             VALUES ($1, 'REQUEST_TRANSFER', $2, $3, $4)`,
            [id, user.researcher_id, JSON.stringify({ status: item.status }), JSON.stringify({ status: 'TransferPending', previous_status: item.status })]
        );

        console.log(`[INV-V2] Transfer requested for ${id} by ${user.researcher_id}`);
        res.json({ success: true });
    } catch (err) {
        console.error('[INV-V2] request-transfer error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/inventory-v2/:id/approve-consume — PI approves consume
app.post('/api/di/inventory-v2/:id/approve-consume', requirePI, async (req, res) => {
    try {
        const { id } = req.params;
        const existing = await pool.query('SELECT * FROM di_inventory_items WHERE id = $1', [id]);
        if (existing.rows.length === 0) return res.status(404).json({ error: 'Item not found' });
        if (existing.rows[0].status !== 'ConsumePending') return res.status(400).json({ error: 'Item is not pending consume approval' });

        await pool.query(
            `UPDATE di_inventory_items SET status = 'Consumed', quantity = 0, previous_status = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
            [id]
        );

        await pool.query(
            `INSERT INTO di_inventory_items_log (inventory_item_id, action, changed_by, old_values, new_values)
             VALUES ($1, 'APPROVE_CONSUME', $2, $3, $4)`,
            [id, req.session.user.researcher_id, JSON.stringify({ status: 'ConsumePending' }), JSON.stringify({ status: 'Consumed', quantity: 0 })]
        );

        console.log(`[INV-V2] Consume approved for ${id} by PI`);
        res.json({ success: true });
    } catch (err) {
        console.error('[INV-V2] approve-consume error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/inventory-v2/:id/reject-consume — PI rejects consume
app.post('/api/di/inventory-v2/:id/reject-consume', requirePI, async (req, res) => {
    try {
        const { id } = req.params;
        const { comment } = req.body;
        if (!comment || !comment.trim()) return res.status(400).json({ error: 'Comment is required for rejection' });

        const existing = await pool.query('SELECT * FROM di_inventory_items WHERE id = $1', [id]);
        if (existing.rows.length === 0) return res.status(404).json({ error: 'Item not found' });
        if (existing.rows[0].status !== 'ConsumePending') return res.status(400).json({ error: 'Item is not pending consume approval' });

        const revertStatus = existing.rows[0].previous_status || 'Received';
        await pool.query(
            `UPDATE di_inventory_items SET status = $2, previous_status = NULL, status_comment = $3, updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
            [id, revertStatus, comment.trim()]
        );

        await pool.query(
            `INSERT INTO di_inventory_items_log (inventory_item_id, action, changed_by, old_values, new_values)
             VALUES ($1, 'REJECT_CONSUME', $2, $3, $4)`,
            [id, req.session.user.researcher_id, JSON.stringify({ status: 'ConsumePending' }), JSON.stringify({ status: revertStatus, status_comment: comment.trim() })]
        );

        console.log(`[INV-V2] Consume rejected for ${id} by PI`);
        res.json({ success: true });
    } catch (err) {
        console.error('[INV-V2] reject-consume error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/inventory-v2/:id/approve-transfer — PI approves transfer to group
app.post('/api/di/inventory-v2/:id/approve-transfer', requirePI, async (req, res) => {
    try {
        const { id } = req.params;
        const existing = await pool.query('SELECT * FROM di_inventory_items WHERE id = $1', [id]);
        if (existing.rows.length === 0) return res.status(404).json({ error: 'Item not found' });
        if (existing.rows[0].status !== 'TransferPending') return res.status(400).json({ error: 'Item is not pending transfer approval' });

        await pool.query(
            `UPDATE di_inventory_items SET owner_type = 'group', status = 'Received', transferred_at = CURRENT_TIMESTAMP, previous_status = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
            [id]
        );

        await pool.query(
            `INSERT INTO di_inventory_items_log (inventory_item_id, action, changed_by, old_values, new_values)
             VALUES ($1, 'APPROVE_TRANSFER', $2, $3, $4)`,
            [id, req.session.user.researcher_id, JSON.stringify({ status: 'TransferPending', owner_type: existing.rows[0].owner_type }), JSON.stringify({ status: 'Received', owner_type: 'group', transferred_at: new Date().toISOString() })]
        );

        console.log(`[INV-V2] Transfer approved for ${id} by PI`);
        res.json({ success: true });
    } catch (err) {
        console.error('[INV-V2] approve-transfer error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/inventory-v2/:id/reject-transfer — PI rejects transfer
app.post('/api/di/inventory-v2/:id/reject-transfer', requirePI, async (req, res) => {
    try {
        const { id } = req.params;
        const { comment } = req.body;
        if (!comment || !comment.trim()) return res.status(400).json({ error: 'Comment is required for rejection' });

        const existing = await pool.query('SELECT * FROM di_inventory_items WHERE id = $1', [id]);
        if (existing.rows.length === 0) return res.status(404).json({ error: 'Item not found' });
        if (existing.rows[0].status !== 'TransferPending') return res.status(400).json({ error: 'Item is not pending transfer approval' });

        const revertStatus = existing.rows[0].previous_status || 'Received';
        await pool.query(
            `UPDATE di_inventory_items SET status = $2, previous_status = NULL, status_comment = $3, updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
            [id, revertStatus, comment.trim()]
        );

        await pool.query(
            `INSERT INTO di_inventory_items_log (inventory_item_id, action, changed_by, old_values, new_values)
             VALUES ($1, 'REJECT_TRANSFER', $2, $3, $4)`,
            [id, req.session.user.researcher_id, JSON.stringify({ status: 'TransferPending' }), JSON.stringify({ status: revertStatus, status_comment: comment.trim() })]
        );

        console.log(`[INV-V2] Transfer rejected for ${id} by PI`);
        res.json({ success: true });
    } catch (err) {
        console.error('[INV-V2] reject-transfer error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== DELETE WORKFLOW ====================

// POST /api/di/inventory-v2/:id/request-delete — researcher/supervisor requests deletion of group item
app.post('/api/di/inventory-v2/:id/request-delete', requireAuth, requireInternal, async (req, res) => {
    try {
        const user = req.session.user;
        const { id } = req.params;
        const { delete_reason, delete_reason_detail } = req.body;

        if (!delete_reason || !['Consumed', 'Discarded', 'Lost'].includes(delete_reason)) {
            return res.status(400).json({ error: 'delete_reason must be one of: Consumed, Discarded, Lost' });
        }

        const existing = await pool.query('SELECT * FROM di_inventory_items WHERE id = $1', [id]);
        if (existing.rows.length === 0) return res.status(404).json({ error: 'Item not found' });
        const item = existing.rows[0];
        if (item.visibility_scope !== 'group') return res.status(400).json({ error: 'Only group inventory items can be requested for deletion' });
        if (!['Approved', 'Received'].includes(item.status)) return res.status(400).json({ error: 'Item must be Approved or Received to request deletion' });

        await pool.query(
            `UPDATE di_inventory_items SET previous_status = status, status = 'DeletePending', delete_reason = $2, delete_reason_detail = $3, updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
            [id, delete_reason, delete_reason_detail || null]
        );

        await pool.query(
            `INSERT INTO di_inventory_items_log (inventory_item_id, action, changed_by, old_values, new_values)
             VALUES ($1, 'REQUEST_DELETE', $2, $3, $4)`,
            [id, user.researcher_id, JSON.stringify({ status: item.status }), JSON.stringify({ status: 'DeletePending', delete_reason, delete_reason_detail: delete_reason_detail || null })]
        );

        console.log(`[INV-V2] Delete requested for ${id} by ${user.researcher_id} (reason: ${delete_reason})`);
        res.json({ success: true });
    } catch (err) {
        console.error('[INV-V2] request-delete error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/inventory-v2/:id/approve-delete — PI approves deletion
app.post('/api/di/inventory-v2/:id/approve-delete', requirePI, async (req, res) => {
    try {
        const { id } = req.params;
        const existing = await pool.query('SELECT * FROM di_inventory_items WHERE id = $1', [id]);
        if (existing.rows.length === 0) return res.status(404).json({ error: 'Item not found' });
        if (existing.rows[0].status !== 'DeletePending') return res.status(400).json({ error: 'Item is not pending delete approval' });

        await pool.query(
            `UPDATE di_inventory_items SET status = 'Deleted', previous_status = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
            [id]
        );

        await pool.query(
            `INSERT INTO di_inventory_items_log (inventory_item_id, action, changed_by, old_values, new_values)
             VALUES ($1, 'APPROVE_DELETE', $2, $3, $4)`,
            [id, req.session.user.researcher_id, JSON.stringify({ status: 'DeletePending' }), JSON.stringify({ status: 'Deleted' })]
        );

        console.log(`[INV-V2] Delete approved for ${id} by PI`);
        res.json({ success: true });
    } catch (err) {
        console.error('[INV-V2] approve-delete error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/inventory-v2/:id/reject-delete — PI rejects deletion
app.post('/api/di/inventory-v2/:id/reject-delete', requirePI, async (req, res) => {
    try {
        const { id } = req.params;
        const { comment } = req.body;
        if (!comment || !comment.trim()) return res.status(400).json({ error: 'Comment is required for rejection' });

        const existing = await pool.query('SELECT * FROM di_inventory_items WHERE id = $1', [id]);
        if (existing.rows.length === 0) return res.status(404).json({ error: 'Item not found' });
        if (existing.rows[0].status !== 'DeletePending') return res.status(400).json({ error: 'Item is not pending delete approval' });

        const revertStatus = existing.rows[0].previous_status || 'Approved';
        await pool.query(
            `UPDATE di_inventory_items SET status = $2, previous_status = NULL, status_comment = $3, delete_reason = NULL, delete_reason_detail = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
            [id, revertStatus, comment.trim()]
        );

        await pool.query(
            `INSERT INTO di_inventory_items_log (inventory_item_id, action, changed_by, old_values, new_values)
             VALUES ($1, 'REJECT_DELETE', $2, $3, $4)`,
            [id, req.session.user.researcher_id, JSON.stringify({ status: 'DeletePending' }), JSON.stringify({ status: revertStatus, status_comment: comment.trim() })]
        );

        console.log(`[INV-V2] Delete rejected for ${id} by PI`);
        res.json({ success: true });
    } catch (err) {
        console.error('[INV-V2] reject-delete error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== DUPLICATE SUGGESTIONS + OFFLINE APPROVAL ====================

// GET /api/di/inventory-v2/:id/duplicate-suggestions — PI checks for group duplicates
app.get('/api/di/inventory-v2/:id/duplicate-suggestions', requirePI, async (req, res) => {
    try {
        const { id } = req.params;
        const existing = await pool.query('SELECT * FROM di_inventory_items WHERE id = $1', [id]);
        if (existing.rows.length === 0) return res.status(404).json({ error: 'Item not found' });
        const item = existing.rows[0];
        if (item.source !== 'Offline' || !['Pending', 'Revision'].includes(item.status)) {
            return res.status(400).json({ error: 'Duplicate suggestions only available for Pending/Revision Offline items' });
        }

        const suggestions = [];
        const seenIds = new Set();

        // Priority 1: exact catalog_id (item_identifier) match
        if (item.item_identifier) {
            const r1 = await pool.query(
                `SELECT id, item_name, vendor_company, item_identifier, storage_location, lot_or_batch_number
                 FROM di_inventory_items
                 WHERE visibility_scope = 'group' AND status IN ('Approved','Received')
                   AND LOWER(item_identifier) = LOWER($1) AND id != $2
                 LIMIT 5`,
                [item.item_identifier, id]
            );
            for (const row of r1.rows) {
                if (!seenIds.has(row.id)) { suggestions.push({ ...row, match_type: 'catalog_id_exact' }); seenIds.add(row.id); }
            }
        }

        // Priority 2: vendor + product name similarity
        if (suggestions.length < 5 && item.vendor_company && item.item_name) {
            const r2 = await pool.query(
                `SELECT id, item_name, vendor_company, item_identifier, storage_location, lot_or_batch_number
                 FROM di_inventory_items
                 WHERE visibility_scope = 'group' AND status IN ('Approved','Received')
                   AND LOWER(vendor_company) = LOWER($1) AND LOWER(item_name) ILIKE $2 AND id != $3
                 LIMIT $4`,
                [item.vendor_company, '%' + item.item_name.toLowerCase() + '%', id, 5 - suggestions.length]
            );
            for (const row of r2.rows) {
                if (!seenIds.has(row.id)) { suggestions.push({ ...row, match_type: 'vendor_name' }); seenIds.add(row.id); }
            }
        }

        // Priority 3: product name similarity only
        if (suggestions.length < 5 && item.item_name) {
            const r3 = await pool.query(
                `SELECT id, item_name, vendor_company, item_identifier, storage_location, lot_or_batch_number
                 FROM di_inventory_items
                 WHERE visibility_scope = 'group' AND status IN ('Approved','Received')
                   AND LOWER(item_name) ILIKE $1 AND id != $2
                 LIMIT $3`,
                ['%' + item.item_name.toLowerCase() + '%', id, 5 - suggestions.length]
            );
            for (const row of r3.rows) {
                if (!seenIds.has(row.id)) { suggestions.push({ ...row, match_type: 'name_only' }); seenIds.add(row.id); }
            }
        }

        res.json({ success: true, suggestions: suggestions.slice(0, 5) });
    } catch (err) {
        console.error('[INV-V2] duplicate-suggestions error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/inventory-v2/:id/approve-as-new — PI approves offline item as new group entry
app.post('/api/di/inventory-v2/:id/approve-as-new', requirePI, async (req, res) => {
    try {
        const { id } = req.params;
        const existing = await pool.query('SELECT * FROM di_inventory_items WHERE id = $1', [id]);
        if (existing.rows.length === 0) return res.status(404).json({ error: 'Item not found' });
        const item = existing.rows[0];
        if (item.source !== 'Offline') return res.status(400).json({ error: 'Only offline items can be approved as new' });
        if (item.status !== 'Pending' && item.status !== 'Revision') return res.status(400).json({ error: 'Only Pending or Revision items can be approved' });

        await pool.query(
            `UPDATE di_inventory_items SET status = 'Approved', visibility_scope = 'group', status_comment = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
            [id]
        );

        await pool.query(
            `INSERT INTO di_inventory_items_log (inventory_item_id, action, changed_by, old_values, new_values)
             VALUES ($1, 'APPROVE_AS_NEW', $2, $3, $4)`,
            [id, req.session.user.researcher_id, JSON.stringify({ status: item.status, visibility_scope: 'personal' }), JSON.stringify({ status: 'Approved', visibility_scope: 'group' })]
        );

        console.log(`[INV-V2] Offline item ${id} approved as NEW by PI`);
        res.json({ success: true });
    } catch (err) {
        console.error('[INV-V2] approve-as-new error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/inventory-v2/:id/approve-as-duplicate — PI links offline item to existing group record
app.post('/api/di/inventory-v2/:id/approve-as-duplicate', requirePI, async (req, res) => {
    try {
        const { id } = req.params;
        const { duplicate_of_inventory_id } = req.body;
        if (!duplicate_of_inventory_id) return res.status(400).json({ error: 'duplicate_of_inventory_id is required' });

        const existing = await pool.query('SELECT * FROM di_inventory_items WHERE id = $1', [id]);
        if (existing.rows.length === 0) return res.status(404).json({ error: 'Item not found' });
        const item = existing.rows[0];
        if (item.source !== 'Offline') return res.status(400).json({ error: 'Only offline items can be approved as duplicate' });
        if (item.status !== 'Pending' && item.status !== 'Revision') return res.status(400).json({ error: 'Only Pending or Revision items can be approved' });

        // Verify target exists in group inventory
        const target = await pool.query(
            'SELECT id FROM di_inventory_items WHERE id = $1 AND visibility_scope = $2',
            [duplicate_of_inventory_id, 'group']
        );
        if (target.rows.length === 0) return res.status(400).json({ error: 'Target group inventory item not found' });

        await pool.query(
            `UPDATE di_inventory_items SET status = 'ApprovedLinked', duplicate_of_inventory_id = $2, status_comment = NULL, updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
            [id, duplicate_of_inventory_id]
        );

        await pool.query(
            `INSERT INTO di_inventory_items_log (inventory_item_id, action, changed_by, old_values, new_values)
             VALUES ($1, 'APPROVE_AS_DUPLICATE', $2, $3, $4)`,
            [id, req.session.user.researcher_id, JSON.stringify({ status: item.status }), JSON.stringify({ status: 'ApprovedLinked', duplicate_of_inventory_id })]
        );

        console.log(`[INV-V2] Offline item ${id} approved as DUPLICATE (linked to ${duplicate_of_inventory_id}) by PI`);
        res.json({ success: true });
    } catch (err) {
        console.error('[INV-V2] approve-as-duplicate error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// POST /api/di/inventory-v2/:id/remove-rejected — researcher/supervisor removes rejected item
app.post('/api/di/inventory-v2/:id/remove-rejected', requireAuth, requireInternal, async (req, res) => {
    try {
        const user = req.session.user;
        const { id } = req.params;
        const existing = await pool.query('SELECT * FROM di_inventory_items WHERE id = $1', [id]);
        if (existing.rows.length === 0) return res.status(404).json({ error: 'Item not found' });
        if (existing.rows[0].created_by !== user.researcher_id) return res.status(403).json({ error: 'You can only remove your own items' });
        if (existing.rows[0].status !== 'Rejected') return res.status(400).json({ error: 'Only rejected items can be removed' });

        await pool.query(
            `UPDATE di_inventory_items SET status = 'Deleted', updated_at = CURRENT_TIMESTAMP WHERE id = $1`,
            [id]
        );

        await pool.query(
            `INSERT INTO di_inventory_items_log (inventory_item_id, action, changed_by, old_values, new_values)
             VALUES ($1, 'REMOVE_REJECTED', $2, $3, $4)`,
            [id, user.researcher_id, JSON.stringify({ status: 'Rejected' }), JSON.stringify({ status: 'Deleted' })]
        );

        console.log(`[INV-V2] Rejected item ${id} removed by ${user.researcher_id}`);
        res.json({ success: true });
    } catch (err) {
        console.error('[INV-V2] remove-rejected error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// ==================== COPY PURCHASE EMAIL ====================

// POST /api/di/purchases/copy-email — researcher/supervisor generates purchase email with batch PO
app.post('/api/di/purchases/copy-email', requireAuth, requireInternal, async (req, res) => {
    const client = await pool.connect();
    try {
        const user = req.session.user;
        if (!['LiU', 'UNAV'].includes(user.affiliation)) {
            return res.status(400).json({ error: 'Copy Purchase Email is only available for LiU and UNAV affiliations' });
        }

        // Find requester's approved items not yet ordered
        const itemsResult = await client.query(
            `SELECT i.id, i.vendor_company, i.product_name, i.catalog_id, i.product_link,
                    i.quantity, i.unit_price, i.item_total, i.currency
             FROM di_purchase_items i
             JOIN di_purchase_requests r ON r.id = i.request_id
             WHERE r.requester_id = $1 AND r.status = 'APPROVED' AND r.affiliation = $2 AND i.ordered_at IS NULL
               AND (i.item_status = 'Active' OR i.item_status IS NULL)
             ORDER BY i.created_at`,
            [user.researcher_id, user.affiliation]
        );

        const items = itemsResult.rows;
        if (items.length === 0) {
            return res.status(400).json({ error: 'No approved items awaiting ordering' });
        }

        await client.query('BEGIN');

        // Generate ONE PO for the batch
        const poNumber = await generatePONumber(client);

        // Mark all items with PO and ordered_at
        const itemIds = items.map(i => i.id);
        await client.query(
            `UPDATE di_purchase_items SET internal_order_number = $1, ordered_at = CURRENT_TIMESTAMP
             WHERE id = ANY($2)`,
            [poNumber, itemIds]
        );

        await client.query('COMMIT');

        // Build email text
        const total = Math.round(items.reduce((s, i) => s + Number(i.item_total), 0) * 100) / 100;
        const currency = items[0].currency;
        const subject = `NATLAB purchase request (${user.affiliation}) — ${poNumber}`;
        let body = `Hi,\n\nPlease find below the products that have been approved and need to be ordered as soon as possible.\n\nPO Number: ${poNumber}\n\n`;

        items.forEach(i => {
            body += `- Vendor: ${i.vendor_company}\n`;
            body += `  Product name: ${i.product_name}\n`;
            body += `  Catalog ID: ${i.catalog_id}\n`;
            body += `  Quantity: ${i.quantity}\n`;
            body += `  Unit price: ${Number(i.unit_price).toFixed(2)} ${i.currency}\n`;
            body += `  Item total: ${Number(i.item_total).toFixed(2)} ${i.currency}\n`;
            body += `  Product link: ${i.product_link}\n\n`;
        });

        body += `---\nTotal: ${total.toFixed(2)} ${currency}\nPO: ${poNumber}`;

        const emailText = `Subject: ${subject}\n\n${body}`;

        console.log(`[PURCHASES] Copy email generated by ${user.researcher_id}, PO: ${poNumber}, ${items.length} items`);
        res.json({ success: true, email_text: emailText, po_number: poNumber, item_count: items.length });
    } catch (err) {
        await client.query('ROLLBACK');
        console.error('[PURCHASES] Copy email error:', err);
        res.status(500).json({ error: 'Server error' });
    } finally {
        client.release();
    }
});

// GET /api/di/inventory-v2/supervision/:researcherId/inventory — supervisor views researcher's inventory
app.get('/api/di/inventory-v2/supervision/:researcherId/inventory', requireSupervisor, async (req, res) => {
    try {
        const supervisor = req.session.user;
        const { researcherId } = req.params;

        // Verify assignment
        const assignment = await pool.query(
            'SELECT 1 FROM di_supervisor_researchers WHERE supervisor_id = $1 AND researcher_id = $2',
            [supervisor.researcher_id, researcherId]
        );
        if (assignment.rows.length === 0) return res.status(403).json({ error: 'Researcher not assigned to you' });

        const { item_type } = req.query;
        let query = `SELECT ii.*, a.name AS created_by_name FROM di_inventory_items ii
                     LEFT JOIN di_allowlist a ON a.researcher_id = ii.created_by
                     WHERE ii.created_by = $1 AND ii.status NOT IN ('Consumed','Deleted') AND ii.transferred_at IS NULL`;
        const params = [researcherId];
        if (item_type && VALID_ITEM_TYPES.includes(item_type)) {
            query += ` AND ii.item_type = $${params.length + 1}`;
            params.push(item_type);
        }
        query += ` ORDER BY ii.updated_at DESC`;
        const result = await pool.query(query, params);
        res.json({ success: true, items: result.rows });
    } catch (err) {
        console.error('[INV-V2] supervision inventory error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});


// =====================================================================
// TRAINING & APPROVALS
// =====================================================================

let trainingTablesExist = null;
let trainingTablesLastCheck = 0;

async function checkTrainingTables() {
    const now = Date.now();
    if (trainingTablesExist === null || trainingTablesExist === false || (now - trainingTablesLastCheck > 60000)) {
        try {
            const result = await pool.query(`SELECT table_name FROM information_schema.tables WHERE table_name = 'di_training_packs'`);
            trainingTablesExist = result.rows.length > 0;
            trainingTablesLastCheck = now;
        } catch (err) {
            trainingTablesExist = false;
        }
    }
    return trainingTablesExist;
}

// --- GLP Weekly Status table guard ---
let glpStatusTableExists = null;
let glpStatusTableLastCheck = 0;

async function checkGlpStatusTable() {
    const now = Date.now();
    if (glpStatusTableExists === null || glpStatusTableExists === false || (now - glpStatusTableLastCheck > 60000)) {
        try {
            const result = await pool.query(`SELECT table_name FROM information_schema.tables WHERE table_name = 'glp_weekly_status_index'`);
            glpStatusTableExists = result.rows.length > 0;
            glpStatusTableLastCheck = now;
        } catch (err) {
            glpStatusTableExists = false;
        }
    }
    return glpStatusTableExists;
}

// --- PI: Training Design - Upload new document ---
app.post('/api/di/training/documents', requirePI, upload.single('file'), async (req, res) => {
    try {
        if (!(await checkTrainingTables())) return res.status(501).json({ error: 'Training tables not available' });
        const { title, category, affiliation, requirement_rule, condition_key, condition_note, display_order } = req.body;
        const file = req.file;
        if (!file) return res.status(400).json({ error: 'PDF file required' });
        if (!title || !category || !affiliation || !requirement_rule) return res.status(400).json({ error: 'Missing required fields' });

        const year = new Date().getFullYear();
        const ts = Date.now();
        const safeName = file.originalname.replace(/[^\w.\-]+/g, '_');
        const r2Key = `di/Training/Documents/${year}/${ts}_${safeName}`;
        await uploadToR2(file.buffer, r2Key, 'application/pdf');

        const docResult = await pool.query(
            `INSERT INTO di_training_documents (title, category, affiliation, requirement_rule, condition_key, condition_note, display_order)
             VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
            [title, category, affiliation, requirement_rule, condition_key || null, condition_note || null, parseInt(display_order) || 0]
        );
        const docId = docResult.rows[0].id;

        await pool.query(
            `INSERT INTO di_training_document_versions (document_id, version, r2_object_key, original_filename, uploaded_by, is_current)
             VALUES ($1, 1, $2, $3, $4, TRUE)`,
            [docId, r2Key, file.originalname, req.session.user.researcher_id]
        );

        res.json({ success: true, document_id: docId });
    } catch (err) {
        console.error('[TRAINING] create document error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// --- PI: Upload new version of existing document ---
app.post('/api/di/training/documents/:id/versions', requirePI, upload.single('file'), async (req, res) => {
    try {
        if (!(await checkTrainingTables())) return res.status(501).json({ error: 'Training tables not available' });
        const docId = req.params.id;
        const file = req.file;
        if (!file) return res.status(400).json({ error: 'PDF file required' });

        const doc = await pool.query('SELECT id FROM di_training_documents WHERE id = $1', [docId]);
        if (doc.rows.length === 0) return res.status(404).json({ error: 'Document not found' });

        const maxV = await pool.query('SELECT COALESCE(MAX(version),0) as mv FROM di_training_document_versions WHERE document_id = $1', [docId]);
        const newVersion = maxV.rows[0].mv + 1;

        const year = new Date().getFullYear();
        const ts = Date.now();
        const safeName = file.originalname.replace(/[^\w.\-]+/g, '_');
        const r2Key = `di/Training/Documents/${year}/${ts}_v${newVersion}_${safeName}`;
        await uploadToR2(file.buffer, r2Key, 'application/pdf');

        // Mark previous current as not current
        await pool.query('UPDATE di_training_document_versions SET is_current = FALSE WHERE document_id = $1 AND is_current = TRUE', [docId]);

        await pool.query(
            `INSERT INTO di_training_document_versions (document_id, version, r2_object_key, original_filename, uploaded_by, is_current)
             VALUES ($1, $2, $3, $4, $5, TRUE)`,
            [docId, newVersion, r2Key, file.originalname, req.session.user.researcher_id]
        );

        res.json({ success: true, version: newVersion });
    } catch (err) {
        console.error('[TRAINING] upload version error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// --- List training documents ---
app.get('/api/di/training/documents', requireAuth, async (req, res) => {
    try {
        if (!(await checkTrainingTables())) return res.status(501).json({ error: 'Training tables not available' });
        const isPI = req.session.user.role === 'pi';

        if (isPI) {
            const docs = await pool.query(
                `SELECT d.*, v.id as version_id, v.version, v.original_filename as version_filename, v.is_current, v.uploaded_at as version_uploaded_at
                 FROM di_training_documents d
                 LEFT JOIN di_training_document_versions v ON v.document_id = d.id
                 ORDER BY d.display_order, d.created_at, v.version DESC`
            );
            // Group versions by document
            const docMap = {};
            for (const row of docs.rows) {
                if (!docMap[row.id]) {
                    docMap[row.id] = {
                        id: row.id, title: row.title, category: row.category, affiliation: row.affiliation,
                        requirement_rule: row.requirement_rule, condition_key: row.condition_key,
                        condition_note: row.condition_note, display_order: row.display_order,
                        is_active: row.is_active, created_at: row.created_at, versions: []
                    };
                }
                if (row.version_id) {
                    docMap[row.id].versions.push({
                        id: row.version_id, version: row.version, filename: row.version_filename,
                        is_current: row.is_current, uploaded_at: row.version_uploaded_at
                    });
                }
            }
            res.json({ success: true, documents: Object.values(docMap) });
        } else {
            // Non-PI: active documents with current version only
              const userAff = req.session.user.affiliation;
              const docs = await pool.query(
                  `SELECT d.id, d.title, d.category, d.affiliation, d.requirement_rule, d.condition_key, d.condition_note, d.display_order,
                          v.id as version_id, v.version, v.original_filename as version_filename
                   FROM di_training_documents d
                   JOIN di_training_document_versions v ON v.document_id = d.id AND v.is_current = TRUE
                   WHERE d.is_active = TRUE
                     AND (d.affiliation = 'All' OR d.affiliation = $1)
                   ORDER BY d.display_order, d.created_at`,
                  [userAff]
              );
res.json({ success: true, documents: docs.rows });
        }
    } catch (err) {
        console.error('[TRAINING] list documents error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// --- PI: Retire / Activate document ---
app.put('/api/di/training/documents/:id/retire', requirePI, async (req, res) => {
    try {
        if (!(await checkTrainingTables())) return res.status(501).json({ error: 'Training tables not available' });
        await pool.query('UPDATE di_training_documents SET is_active = FALSE WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        console.error('[TRAINING] retire error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

app.put('/api/di/training/documents/:id/activate', requirePI, async (req, res) => {
    try {
        if (!(await checkTrainingTables())) return res.status(501).json({ error: 'Training tables not available' });
        await pool.query('UPDATE di_training_documents SET is_active = TRUE WHERE id = $1', [req.params.id]);
        res.json({ success: true });
    } catch (err) {
        console.error('[TRAINING] activate error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// --- View document version PDF (stream from R2) ---
app.get('/api/di/training/document-versions/:versionId/view', requireAuth, async (req, res) => {
    try {
        if (!(await checkTrainingTables())) return res.status(501).json({ error: 'Training tables not available' });
        const v = await pool.query('SELECT r2_object_key, original_filename FROM di_training_document_versions WHERE id = $1', [req.params.versionId]);
        if (v.rows.length === 0) return res.status(404).json({ error: 'Version not found' });

        const r2Obj = await downloadFromR2(v.rows[0].r2_object_key);
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `inline; filename="${v.rows[0].original_filename}"`);
        if (r2Obj.Body.pipe) { r2Obj.Body.pipe(res); } else { res.send(Buffer.from(await r2Obj.Body.transformToByteArray())); }
    } catch (err) {
        console.error('[TRAINING] view version error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// --- List available supervisors ---
app.get('/api/di/training/supervisors', requireAuth, async (req, res) => {
    try {
        const result = await pool.query(
            `SELECT DISTINCT researcher_id, name FROM di_allowlist WHERE role = 'supervisor' AND active = TRUE ORDER BY name`
        );
          console.log('[TRAINING] supervisors rows:', result.rows);
        res.json({ success: true, supervisors: result.rows });
    } catch (err) {
        console.error('[TRAINING] list supervisors error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// --- Researcher: Get or create current training pack ---
app.get('/api/di/training/my-pack', requireAuth, async (req, res) => {
    try {
        if (!(await checkTrainingTables())) return res.status(501).json({ error: 'Training tables not available' });
        const userId = req.session.user.researcher_id;

        // Get latest pack
        let pack = await pool.query(
            'SELECT * FROM di_training_packs WHERE researcher_id = $1 ORDER BY version DESC LIMIT 1', [userId]
        );

        // If no pack or latest is SEALED, create new draft
        if (pack.rows.length === 0 || pack.rows[0].status === 'SEALED') {
            const newVersion = pack.rows.length === 0 ? 1 : pack.rows[0].version + 1;
            pack = await pool.query(
                `INSERT INTO di_training_packs (researcher_id, version, status) VALUES ($1, $2, 'DRAFT') RETURNING *`,
                [userId, newVersion]
            );
        }

        const currentPack = pack.rows[0];

        // Get agreements for this pack
        const agreements = await pool.query(
            `SELECT a.*, d.title as document_title, d.category, dv.version as doc_version, dv.original_filename
             FROM di_training_agreements a
             JOIN di_training_documents d ON d.id = a.document_id
             JOIN di_training_document_versions dv ON dv.id = a.document_version_id
             WHERE a.pack_id = $1 ORDER BY a.confirmed_at`,
            [currentPack.id]
        );

        // Get training entries for this pack
        const entries = await pool.query(
            `SELECT e.*, COALESCE(al.name, e.other_supervisor_name) as supervisor_name
             FROM di_training_entries e
             LEFT JOIN di_allowlist al ON al.researcher_id = e.supervisor_id
             WHERE e.pack_id = $1 ORDER BY e.created_at`,
            [currentPack.id]
        );

        // Get sealed packs for certificate display
        const sealedPacks = await pool.query(
            `SELECT id, version, sealed_at, verification_code FROM di_training_packs
             WHERE researcher_id = $1 AND status = 'SEALED' ORDER BY version DESC`,
            [userId]
        );

        res.json({
            success: true,
            pack: currentPack,
            agreements: agreements.rows,
            entries: entries.rows,
            sealed_packs: sealedPacks.rows
        });
    } catch (err) {
        console.error('[TRAINING] my-pack error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// --- Researcher: Confirm agreement ---
app.post('/api/di/training/agreements', requireAuth, async (req, res) => {
    try {
        if (!(await checkTrainingTables())) return res.status(501).json({ error: 'Training tables not available' });
        const userId = req.session.user.researcher_id;
        const { pack_id, document_version_id } = req.body;
        if (!pack_id || !document_version_id) return res.status(400).json({ error: 'Missing pack_id or document_version_id' });

        // Verify pack belongs to user and is editable
        const pack = await pool.query('SELECT * FROM di_training_packs WHERE id = $1 AND researcher_id = $2', [pack_id, userId]);
        if (pack.rows.length === 0) return res.status(404).json({ error: 'Pack not found' });
        if (pack.rows[0].status === 'SEALED') return res.status(403).json({ error: 'Pack is sealed — no changes allowed' });
        if (pack.rows[0].status === 'SUBMITTED') return res.status(403).json({ error: 'Pack is submitted — no changes allowed' });

        // Get document_id from version
        const ver = await pool.query('SELECT document_id FROM di_training_document_versions WHERE id = $1', [document_version_id]);
        if (ver.rows.length === 0) return res.status(404).json({ error: 'Document version not found' });
        const documentId = ver.rows[0].document_id;

        // Check if already confirmed for this document in this pack
        const existing = await pool.query(
            'SELECT id FROM di_training_agreements WHERE pack_id = $1 AND document_id = $2', [pack_id, documentId]
        );
        if (existing.rows.length > 0) return res.status(409).json({ error: 'Agreement already confirmed for this document' });

        await pool.query(
            `INSERT INTO di_training_agreements (pack_id, document_id, document_version_id, confirmed_by, confirmed_name)
             VALUES ($1, $2, $3, $4, $5)`,
            [pack_id, documentId, document_version_id, userId, req.session.user.name]
        );

        res.json({ success: true });
    } catch (err) {
        console.error('[TRAINING] confirm agreement error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// --- Researcher: Add training entry ---
app.post('/api/di/training/entries', requireAuth, async (req, res) => {
    try {
        if (!(await checkTrainingTables())) return res.status(501).json({ error: 'Training tables not available' });
        const userId = req.session.user.researcher_id;
        const { pack_id, training_type, training_date, notes, supervisor_id, other_supervisor_name, other_supervisor_email } = req.body;
        if (!pack_id || !training_type || !training_date) return res.status(400).json({ error: 'Missing required fields' });

        const pack = await pool.query('SELECT * FROM di_training_packs WHERE id = $1 AND researcher_id = $2', [pack_id, userId]);
        if (pack.rows.length === 0) return res.status(404).json({ error: 'Pack not found' });
        if (pack.rows[0].status === 'SEALED') return res.status(403).json({ error: 'Pack is sealed — no changes allowed' });
        if (pack.rows[0].status === 'SUBMITTED') return res.status(403).json({ error: 'Pack is submitted — no changes allowed' });

        // Determine certification route
        const isOtherSupervisor = (supervisor_id === '__OTHER_SUPERVISOR__');

        if (isOtherSupervisor) {
            // PI route: other supervisor, delegated delivery under PI oversight
            if (!other_supervisor_name || !other_supervisor_email) {
                return res.status(400).json({ error: 'Other supervisor name and email are required' });
            }
            const result = await pool.query(
                `INSERT INTO di_training_entries
                   (pack_id, training_type, training_date, notes, supervisor_id,
                    other_supervisor_name, other_supervisor_email, certification_route,
                    trainee_declaration_name, status)
                 VALUES ($1, $2, $3, $4, NULL, $5, $6, 'PI', $7, 'PENDING')
                 RETURNING id`,
                [pack_id, training_type, training_date, notes || null,
                 other_supervisor_name.trim(), other_supervisor_email.trim(),
                 req.session.user.name]
            );
            res.json({ success: true, entry_id: result.rows[0].id });
        } else {
            // SUPERVISOR route: normal supervisor certification
            if (!supervisor_id) return res.status(400).json({ error: 'Supervisor is required' });
            const result = await pool.query(
                `INSERT INTO di_training_entries
                   (pack_id, training_type, training_date, notes, supervisor_id,
                    certification_route, trainee_declaration_name, status)
                 VALUES ($1, $2, $3, $4, $5, 'SUPERVISOR', $6, 'PENDING')
                 RETURNING id`,
                [pack_id, training_type, training_date, notes || null,
                 supervisor_id, req.session.user.name]
            );
            res.json({ success: true, entry_id: result.rows[0].id });
        }
    } catch (err) {
        console.error('[TRAINING] add entry error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// --- Researcher: Submit pack to PI ---
app.post('/api/di/training/submit', requireAuth, async (req, res) => {
    try {
        if (!(await checkTrainingTables())) return res.status(501).json({ error: 'Training tables not available' });
        const userId = req.session.user.researcher_id;
        const { pack_id } = req.body;
        if (!pack_id) return res.status(400).json({ error: 'Missing pack_id' });

        const pack = await pool.query('SELECT * FROM di_training_packs WHERE id = $1 AND researcher_id = $2', [pack_id, userId]);
        if (pack.rows.length === 0) return res.status(404).json({ error: 'Pack not found' });
        if (!['DRAFT', 'REVISION_NEEDED'].includes(pack.rows[0].status)) {
            return res.status(400).json({ error: `Cannot submit pack with status ${pack.rows[0].status}` });
        }

        // Load required documents for this researcher
        const userAff = req.session.user.affiliation;
        const requiredDocs = await pool.query(
            `SELECT id, title, condition_key FROM di_training_documents
             WHERE is_active = TRUE AND requirement_rule IN ('Always', 'Conditional')
             AND (affiliation = 'All' OR affiliation = $1)`,
            [userAff]
        );

        // Check agreements
        const agreements = await pool.query(
            'SELECT document_id FROM di_training_agreements WHERE pack_id = $1', [pack_id]
        );
        const confirmedDocIds = new Set(agreements.rows.map(r => r.document_id));
        const missingDocs = requiredDocs.rows.filter(d => !confirmedDocIds.has(d.id));
        if (missingDocs.length > 0) {
            return res.status(400).json({
                error: 'Missing required agreements',
                missing: missingDocs.map(d => d.title)
            });
        }

        // Check all entries are CERTIFIED
        const entries = await pool.query(
            'SELECT id, training_type, status FROM di_training_entries WHERE pack_id = $1', [pack_id]
        );
        if (entries.rows.length === 0) {
            return res.status(400).json({ error: 'Pack must contain at least one training entry' });
        }
        const uncertified = entries.rows.filter(e => e.status !== 'CERTIFIED');
        if (uncertified.length > 0) {
            return res.status(400).json({
                error: 'All training entries must be certified before submission',
                uncertified: uncertified.map(e => ({ id: e.id, type: e.training_type, status: e.status }))
            });
        }

        await pool.query(
            `UPDATE di_training_packs SET status = 'SUBMITTED', updated_at = CURRENT_TIMESTAMP WHERE id = $1`, [pack_id]
        );

        res.json({ success: true });
    } catch (err) {
        console.error('[TRAINING] submit pack error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// --- Supervisor: Pending certifications ---
app.get('/api/di/training/pending-certifications', requireAuth, async (req, res) => {
    try {
        if (!(await checkTrainingTables())) return res.status(501).json({ error: 'Training tables not available' });
        const userId = req.session.user.researcher_id;
        const result = await pool.query(
            `SELECT e.*, al.name as trainee_name, p.version as pack_version, p.status as pack_status
             FROM di_training_entries e
             JOIN di_training_packs p ON p.id = e.pack_id
             JOIN di_allowlist al ON al.researcher_id = p.researcher_id
             WHERE e.supervisor_id = $1 AND e.status = 'PENDING' AND p.status IN ('DRAFT','REVISION_NEEDED')
             ORDER BY e.created_at`,
            [userId]
        );
        res.json({ success: true, entries: result.rows });
    } catch (err) {
        console.error('[TRAINING] pending certifications error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// --- Supervisor: Certify training entry ---
app.post('/api/di/training/entries/:id/certify', requireSupervisor, async (req, res) => {
    try {
        if (!(await checkTrainingTables())) return res.status(501).json({ error: 'Training tables not available' });
        const userId = req.session.user.researcher_id;
        const entry = await pool.query(
            `SELECT e.*, p.status as pack_status FROM di_training_entries e
             JOIN di_training_packs p ON p.id = e.pack_id WHERE e.id = $1`, [req.params.id]
        );
        if (entry.rows.length === 0) return res.status(404).json({ error: 'Entry not found' });
        if (entry.rows[0].certification_route !== 'SUPERVISOR') return res.status(403).json({ error: 'This entry is not on the supervisor certification route' });
        if (entry.rows[0].supervisor_id !== userId) return res.status(403).json({ error: 'Not your entry to certify' });
        if (entry.rows[0].pack_status === 'SEALED') return res.status(403).json({ error: 'Pack is sealed' });
        if (entry.rows[0].status !== 'PENDING') return res.status(400).json({ error: 'Entry is not pending' });
        if (entry.rows[0].certified_at) return res.status(400).json({ error: 'Entry is already certified' });

        await pool.query(
            `UPDATE di_training_entries SET status = 'CERTIFIED', certified_at = CURRENT_TIMESTAMP, certified_by = $1 WHERE id = $2`,
            [userId, req.params.id]
        );
        res.json({ success: true });
    } catch (err) {
        console.error('[TRAINING] certify error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// --- PI: Certify training entry (PI route only) ---
app.post('/api/di/training/entries/:id/pi-certify', requirePI, async (req, res) => {
    try {
        if (!(await checkTrainingTables())) return res.status(501).json({ error: 'Training tables not available' });
        const entry = await pool.query(
            `SELECT e.*, p.status as pack_status FROM di_training_entries e
             JOIN di_training_packs p ON p.id = e.pack_id WHERE e.id = $1`, [req.params.id]
        );
        if (entry.rows.length === 0) return res.status(404).json({ error: 'Entry not found' });
        if (entry.rows[0].certification_route !== 'PI') return res.status(403).json({ error: 'This entry is not on the PI certification route' });
        if (entry.rows[0].pack_status === 'SEALED') return res.status(403).json({ error: 'Pack is sealed' });
        if (entry.rows[0].status !== 'PENDING') return res.status(400).json({ error: 'Entry is not pending' });
        if (entry.rows[0].certified_at) return res.status(400).json({ error: 'Entry is already certified' });

        const piId = req.session.user.researcher_id;
        await pool.query(
            `UPDATE di_training_entries SET status = 'CERTIFIED', certified_at = CURRENT_TIMESTAMP, certified_by = $1 WHERE id = $2`,
            [piId, req.params.id]
        );
        res.json({ success: true });
    } catch (err) {
        console.error('[TRAINING] pi-certify error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// --- Supervisor: Reject training entry ---
app.post('/api/di/training/entries/:id/reject', requireAuth, async (req, res) => {
    try {
        if (!(await checkTrainingTables())) return res.status(501).json({ error: 'Training tables not available' });
        const userId = req.session.user.researcher_id;
        const { comment } = req.body;
        if (!comment) return res.status(400).json({ error: 'Rejection comment is required' });

        const entry = await pool.query(
            `SELECT e.*, p.status as pack_status FROM di_training_entries e
             JOIN di_training_packs p ON p.id = e.pack_id WHERE e.id = $1`, [req.params.id]
        );
        if (entry.rows.length === 0) return res.status(404).json({ error: 'Entry not found' });
        if (entry.rows[0].supervisor_id !== userId) return res.status(403).json({ error: 'Not your entry to reject' });
        if (entry.rows[0].pack_status === 'SEALED') return res.status(403).json({ error: 'Pack is sealed' });

        await pool.query(
            `UPDATE di_training_entries SET status = 'REJECTED', rejection_comment = $1 WHERE id = $2`, [comment, req.params.id]
        );
        res.json({ success: true });
    } catch (err) {
        console.error('[TRAINING] reject error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// --- PI: Clear stale PENDING entries from a pack ---
app.post('/api/di/training/packs/:pack_id/clear-pending', requirePI, async (req, res) => {
    try {
        if (!(await checkTrainingTables())) return res.status(501).json({ error: 'Training tables not available' });
        const packId = req.params.pack_id;
        const pack = await pool.query('SELECT id, status FROM di_training_packs WHERE id = $1', [packId]);
        if (pack.rows.length === 0) return res.status(404).json({ error: 'Pack not found' });
        if (pack.rows[0].status === 'SEALED') return res.status(403).json({ error: 'Cannot modify sealed pack' });

        const result = await pool.query(
            `DELETE FROM di_training_entries WHERE pack_id = $1 AND certified_at IS NULL RETURNING id`,
            [packId]
        );
        res.json({ success: true, deleted: result.rowCount });
    } catch (err) {
        console.error('[TRAINING] clear-pending error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// --- PI: List pending PI-route certifications ---
app.get('/api/di/training/pi-pending-certifications', requirePI, async (req, res) => {
    try {
        if (!(await checkTrainingTables())) return res.status(501).json({ error: 'Training tables not available' });
        const result = await pool.query(
            `SELECT e.*, al.name as trainee_name, p.version as pack_version, p.status as pack_status
             FROM di_training_entries e
             JOIN di_training_packs p ON p.id = e.pack_id
             JOIN di_allowlist al ON al.researcher_id = p.researcher_id
             WHERE e.certification_route = 'PI' AND e.certified_at IS NULL AND e.status = 'PENDING'
             ORDER BY e.created_at`
        );
        res.json({ success: true, entries: result.rows });
    } catch (err) {
        console.error('[TRAINING] pi-pending-certifications error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// --- PI: List pending packs ---
app.get('/api/di/training/packs/pending', requirePI, async (req, res) => {
    try {
        if (!(await checkTrainingTables())) return res.status(501).json({ error: 'Training tables not available' });
        const result = await pool.query(
            `SELECT p.*, al.name as researcher_name, al.affiliation as researcher_affiliation,
                    (SELECT COUNT(*) FROM di_training_agreements WHERE pack_id = p.id) as agreement_count,
                    (SELECT COUNT(*) FROM di_training_entries WHERE pack_id = p.id) as entry_count
             FROM di_training_packs p
             JOIN di_allowlist al ON al.researcher_id = p.researcher_id
             WHERE p.status = 'SUBMITTED'
             ORDER BY p.updated_at`
        );
        res.json({ success: true, packs: result.rows });
    } catch (err) {
        console.error('[TRAINING] pending packs error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// --- Get pack details ---
app.get('/api/di/training/packs/:id', requireAuth, async (req, res) => {
    try {
        if (!(await checkTrainingTables())) return res.status(501).json({ error: 'Training tables not available' });
        const pack = await pool.query(
            `SELECT p.*, al.name as researcher_name, al.affiliation as researcher_affiliation
             FROM di_training_packs p
             JOIN di_allowlist al ON al.researcher_id = p.researcher_id
             WHERE p.id = $1`, [req.params.id]
        );
        if (pack.rows.length === 0) return res.status(404).json({ error: 'Pack not found' });

        const agreements = await pool.query(
            `SELECT a.*, d.title as document_title, d.category, dv.version as doc_version, dv.original_filename
             FROM di_training_agreements a
             JOIN di_training_documents d ON d.id = a.document_id
             JOIN di_training_document_versions dv ON dv.id = a.document_version_id
             WHERE a.pack_id = $1 ORDER BY a.confirmed_at`, [req.params.id]
        );
        const entries = await pool.query(
            `SELECT e.*, COALESCE(al.name, e.other_supervisor_name) as supervisor_name
             FROM di_training_entries e
             LEFT JOIN di_allowlist al ON al.researcher_id = e.supervisor_id
             WHERE e.pack_id = $1 ORDER BY e.created_at`, [req.params.id]
        );

        res.json({ success: true, pack: pack.rows[0], agreements: agreements.rows, entries: entries.rows });
    } catch (err) {
        console.error('[TRAINING] pack details error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// --- PI: Seal pack ---
app.post('/api/di/training/packs/:id/seal', requirePI, async (req, res) => {
    try {
        if (!(await checkTrainingTables())) return res.status(501).json({ error: 'Training tables not available' });
        const packId = req.params.id;

        const pack = await pool.query(
            `SELECT p.*, al.name as researcher_name, al.affiliation as researcher_affiliation
             FROM di_training_packs p JOIN di_allowlist al ON al.researcher_id = p.researcher_id
             WHERE p.id = $1`, [packId]
        );
        if (pack.rows.length === 0) return res.status(404).json({ error: 'Pack not found' });
        if (pack.rows[0].status !== 'SUBMITTED') return res.status(400).json({ error: 'Pack must be SUBMITTED to seal' });

        const p = pack.rows[0];
        const sealedAt = new Date().toISOString();
        const signerName = req.session.user.name;

        // Snapshot version IDs
        const agreements = await pool.query(
            'SELECT document_id, document_version_id FROM di_training_agreements WHERE pack_id = $1', [packId]
        );
        for (const ag of agreements.rows) {
            await pool.query(
                `INSERT INTO di_training_pack_snapshots (pack_id, document_id, document_version_id)
                 VALUES ($1, $2, $3) ON CONFLICT DO NOTHING`,
                [packId, ag.document_id, ag.document_version_id]
            );
        }

        // Load full data for certificate
        const agreeDetails = await pool.query(
            `SELECT a.confirmed_name, a.confirmed_at, d.title, dv.version
             FROM di_training_agreements a
             JOIN di_training_documents d ON d.id = a.document_id
             JOIN di_training_document_versions dv ON dv.id = a.document_version_id
             WHERE a.pack_id = $1 ORDER BY a.confirmed_at`, [packId]
        );
        const entryDetails = await pool.query(
            `SELECT e.training_type, e.training_date, e.certified_at, e.certification_route, e.certified_by,
                    COALESCE(al.name, e.other_supervisor_name) as supervisor_name
             FROM di_training_entries e
             LEFT JOIN di_allowlist al ON al.researcher_id = e.supervisor_id
             WHERE e.pack_id = $1 AND e.status = 'CERTIFIED' ORDER BY e.training_date`, [packId]
        );

        // Generate certificate PDF
        const pdfDoc = await PDFDocument.create();
        const font = await pdfDoc.embedFont(StandardFonts.Helvetica);
        const fontBold = await pdfDoc.embedFont(StandardFonts.HelveticaBold);
        const page = pdfDoc.addPage([595, 842]); // A4
        const { width, height } = page.getSize();
        let y = height - 60;

        // Header
        page.drawText('NAT-Lab GLP', { x: 50, y, size: 20, font: fontBold, color: rgb(0.1, 0.21, 0.36) });
        y -= 28;
        page.drawText('Training & Agreements Certificate', { x: 50, y, size: 16, font: fontBold, color: rgb(0.1, 0.21, 0.36) });
        y -= 8;
        page.drawLine({ start: { x: 50, y }, end: { x: width - 50, y }, thickness: 1, color: rgb(0.1, 0.21, 0.36) });
        y -= 25;

        // Researcher info
        page.drawText(`Researcher: ${p.researcher_name}`, { x: 50, y, size: 11, font });
        y -= 16;
        page.drawText(`Affiliation: ${p.researcher_affiliation}`, { x: 50, y, size: 11, font });
        y -= 16;
        page.drawText(`Pack Version: ${p.version}`, { x: 50, y, size: 11, font });
        y -= 16;
        page.drawText(`Sealed: ${sealedAt}`, { x: 50, y, size: 11, font });
        y -= 30;

        // Agreements section
        page.drawText('Agreements', { x: 50, y, size: 13, font: fontBold, color: rgb(0.1, 0.21, 0.36) });
        y -= 18;
        for (const ag of agreeDetails.rows) {
            if (y < 60) { y = height - 50; pdfDoc.addPage([595, 842]); }
            const ts = new Date(ag.confirmed_at).toISOString().slice(0, 10);
            page.drawText(`• ${ag.title} (v${ag.version}) — confirmed ${ts} by ${ag.confirmed_name}`, { x: 60, y, size: 10, font });
            y -= 14;
        }
        y -= 15;

        // Training entries section
        page.drawText('Certified Trainings', { x: 50, y, size: 13, font: fontBold, color: rgb(0.1, 0.21, 0.36) });
        y -= 18;
        for (const en of entryDetails.rows) {
            if (y < 60) { y = height - 50; pdfDoc.addPage([595, 842]); }
            const d = new Date(en.training_date).toISOString().slice(0, 10);
            const certLabel = en.certification_route === 'PI' ? `certified under PI oversight (provider: ${en.supervisor_name})` : `certified by ${en.supervisor_name}`;
            page.drawText(`• ${en.training_type} — ${d} — ${certLabel}`, { x: 60, y, size: 10, font });
            y -= 14;
        }
        y -= 25;

        // Seal stamp
        const stampText = `Sealed by PI (${signerName}) — ${sealedAt}`;
        page.drawRectangle({ x: 45, y: y - 5, width: font.widthOfTextAtSize(stampText, 10) + 20, height: 22, borderColor: rgb(0.2, 0.4, 0.2), borderWidth: 1.5 });
        page.drawText(stampText, { x: 55, y, size: 10, font: fontBold, color: rgb(0.2, 0.4, 0.2) });

        const certBuffer = await pdfDoc.save();

        // Upload certificate
        const year = new Date().getFullYear();
        const certKey = `di/${p.researcher_affiliation}/Approved/Training/${year}/${p.researcher_id}_v${p.version}_certificate.pdf`;
        await uploadToR2(Buffer.from(certBuffer), certKey, 'application/pdf');

        // Signature hash + verification code
        const crypto = require('crypto');
        const signatureHash = crypto.createHmac('sha256', process.env.API_SECRET_KEY || 'natlab_glp_secret')
            .update(JSON.stringify({ pack_id: packId, researcher_id: p.researcher_id, version: p.version, sealed_at: sealedAt, signer: signerName }))
            .digest('hex');
        const verificationCode = `NATLAB-T-${packId.substring(0, 8).toUpperCase()}-${signatureHash.substring(0, 8).toUpperCase()}`;

        // Update pack
        await pool.query(
            `UPDATE di_training_packs SET status='SEALED', sealed_at=$1, sealed_by=$2, certificate_r2_key=$3,
             signature_hash=$4, verification_code=$5, updated_at=CURRENT_TIMESTAMP WHERE id=$6`,
            [sealedAt, req.session.user.researcher_id, certKey, signatureHash, verificationCode, packId]
        );

        res.json({ success: true, verification_code: verificationCode });
    } catch (err) {
        console.error('[TRAINING] seal pack error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// --- PI: Request revision ---
app.post('/api/di/training/packs/:id/revise', requirePI, async (req, res) => {
    try {
        if (!(await checkTrainingTables())) return res.status(501).json({ error: 'Training tables not available' });
        const { comments } = req.body;
        if (!comments) return res.status(400).json({ error: 'Revision comments required' });

        const pack = await pool.query('SELECT status FROM di_training_packs WHERE id = $1', [req.params.id]);
        if (pack.rows.length === 0) return res.status(404).json({ error: 'Pack not found' });
        if (pack.rows[0].status !== 'SUBMITTED') return res.status(400).json({ error: 'Pack must be SUBMITTED to request revision' });

        await pool.query(
            `UPDATE di_training_packs SET status='REVISION_NEEDED', revision_comments=$1, updated_at=CURRENT_TIMESTAMP WHERE id=$2`,
            [comments, req.params.id]
        );
        res.json({ success: true });
    } catch (err) {
        console.error('[TRAINING] revise pack error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// --- Download sealed certificate ---
app.get('/api/di/training/certificate/:packId', requireAuth, async (req, res) => {
    try {
        if (!(await checkTrainingTables())) return res.status(501).json({ error: 'Training tables not available' });
        const pack = await pool.query(
            'SELECT certificate_r2_key, researcher_id, version FROM di_training_packs WHERE id = $1 AND status = $2',
            [req.params.packId, 'SEALED']
        );
        if (pack.rows.length === 0) return res.status(404).json({ error: 'Sealed pack not found' });
        if (!pack.rows[0].certificate_r2_key) return res.status(404).json({ error: 'Certificate not generated' });

        const r2Obj = await downloadFromR2(pack.rows[0].certificate_r2_key);
        res.setHeader('Content-Type', 'application/pdf');
        res.setHeader('Content-Disposition', `attachment; filename="training_certificate_v${pack.rows[0].version}.pdf"`);
        if (r2Obj.Body.pipe) { r2Obj.Body.pipe(res); } else { res.send(Buffer.from(await r2Obj.Body.transformToByteArray())); }
    } catch (err) {
        console.error('[TRAINING] certificate download error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// --- Sealed overview (supervisor + PI) ---
app.get('/api/di/training/sealed-overview', requireAuth, async (req, res) => {
    try {
        if (!(await checkTrainingTables())) return res.status(501).json({ error: 'Training tables not available' });
        // Latest sealed pack per researcher
        const result = await pool.query(
            `SELECT DISTINCT ON (p.researcher_id)
                    p.id, p.researcher_id, p.version, p.sealed_at, p.verification_code,
                    al.name as researcher_name
             FROM di_training_packs p
             JOIN di_allowlist al ON al.researcher_id = p.researcher_id
             WHERE p.status = 'SEALED'
             ORDER BY p.researcher_id, p.version DESC`
        );
        res.json({ success: true, packs: result.rows });
    } catch (err) {
        console.error('[TRAINING] sealed overview error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});


// =====================================================
// GLP STATUS – Harmony Map Coherence Engine
// =====================================================

function computeCoherence(sop, data, inv, training) {
    // Pillar "has records at all" flags
    const sopHas   = sop.approvedTotal > 0 || sop.thisWeek > 0;
    const dataHas  = data.approvedTotal > 0 || data.thisWeek > 0;
    const invHas   = inv.approvedTotal > 0 || inv.thisWeek > 0;
    const trainHas = training.hasSealedPack || training.certifiedCount > 0 || training.thisWeek;

    // Score a single link (0-3, internal only)
    function linkScore(aHas, bHas, aTW, bTW) {
        if (!aHas && !bHas) return 0;
        if (!aHas || !bHas) return 1;
        if (aTW > 0 && bTW > 0) return 3;
        return 2;
    }

    const trainTW = training.thisWeek ? 1 : 0;

    const links = {
        sopData:  linkScore(sopHas,  dataHas,  sop.thisWeek,  data.thisWeek),
        sopInv:   linkScore(sopHas,  invHas,   sop.thisWeek,  inv.thisWeek),
        sopTrain: linkScore(sopHas,  trainHas, sop.thisWeek,  trainTW),
        dataInv:  linkScore(dataHas, invHas,   data.thisWeek, inv.thisWeek),
        dataTrain:linkScore(dataHas, trainHas, data.thisWeek, trainTW),
        invTrain: linkScore(invHas,  trainHas, inv.thisWeek,  trainTW)
    };

    // Full chain: all 4 pillars active this week
    const fullChain = sop.thisWeek > 0 && data.thisWeek > 0 && inv.thisWeek > 0 && training.thisWeek;

    // Previous week for trend
    const sopPrevHas   = sop.approvedTotal > 0 || sop.prevWeek > 0;
    const dataPrevHas  = data.approvedTotal > 0 || data.prevWeek > 0;
    const invPrevHas   = inv.approvedTotal > 0 || inv.prevWeek > 0;
    const trainPrevHas = training.hasSealedPack || training.certifiedCount > 0 || training.prevWeek;
    const trainPW      = training.prevWeek ? 1 : 0;

    const prevLinks = {
        sopData:  linkScore(sopPrevHas,  dataPrevHas,  sop.prevWeek,  data.prevWeek),
        sopInv:   linkScore(sopPrevHas,  invPrevHas,   sop.prevWeek,  inv.prevWeek),
        sopTrain: linkScore(sopPrevHas,  trainPrevHas, sop.prevWeek,  trainPW),
        dataInv:  linkScore(dataPrevHas, invPrevHas,   data.prevWeek, inv.prevWeek),
        dataTrain:linkScore(dataPrevHas, trainPrevHas, data.prevWeek, trainPW),
        invTrain: linkScore(invPrevHas,  trainPrevHas, inv.prevWeek,  trainPW)
    };

    const currentTotal = Object.values(links).reduce((a, b) => a + b, 0);
    const prevTotal    = Object.values(prevLinks).reduce((a, b) => a + b, 0);

    // Sort links: score desc, then key name asc (deterministic)
    const sorted = Object.entries(links).sort((a, b) => b[1] - a[1] || a[0].localeCompare(b[0]));
    const top2    = sorted.slice(0, 2);
    const weakest = sorted[sorted.length - 1];

    // Readable pillar names per link key
    const linkNames = {
        sopData:   ['SOP', 'Data'],
        sopInv:    ['SOP', 'Inventory'],
        sopTrain:  ['SOP', 'Training'],
        dataInv:   ['Data', 'Inventory'],
        dataTrain: ['Data', 'Training'],
        invTrain:  ['Inventory', 'Training']
    };

    // Check if total activity is essentially zero
    const totalThisWeek = sop.thisWeek + data.thisWeek + inv.thisWeek + (training.thisWeek ? 1 : 0);
    const limited = totalThisWeek === 0 && currentTotal <= 2;

    // --- Text generation for wins (top 2 links) ---
    const winTemplates3 = [
        (a, b) => `${a} and ${b} were consistently linked in recorded work this week, improving traceability of outcomes.`,
        (a, b) => `Activity in both ${a} and ${b} this week supports consistent documentation practices.`
    ];
    const winTemplates2 = [
        (a, b) => `${a} and ${b} records are both established, providing a foundation for traceability.`,
        (a, b) => `Both ${a} and ${b} have documented records, supporting alignment across these pillars.`
    ];
    const winTemplates1 = [
        (a, b) => `${a} has active records; extending coverage to ${b} would create a coherence link.`,
        (a, b) => `One of ${a} or ${b} has documented records; adding the other will strengthen alignment.`
    ];

    function winText(key, score, idx) {
        const [a, b] = linkNames[key];
        if (score >= 3) return winTemplates3[idx % 2](a, b);
        if (score === 2) return winTemplates2[idx % 2](a, b);
        if (score === 1) return winTemplates1[idx % 2](a, b);
        return `${a} and ${b} are both awaiting initial documented activity.`;
    }

    const wins = top2.map(([key, score], idx) => winText(key, score, idx));

    // --- Upgrade text (weakest link) ---
    const [wk, ws] = [weakest[0], weakest[1]];
    const [wa, wb] = linkNames[wk];
    let upgrade;
    if (ws >= 3) {
        upgrade = `All links are active this week. Maintain momentum across ${wa} and ${wb} to sustain full coherence.`;
    } else if (ws === 2) {
        upgrade = `${wa} and ${wb} both have records but lacked joint activity this week. Working on both next week will strengthen this link.`;
    } else if (ws === 1) {
        upgrade = `Adding ${wa.toLowerCase() === wa ? wa : wa.toLowerCase()} or ${wb.toLowerCase() === wb ? wb : wb.toLowerCase()} activity next week would close the gap between ${wa} and ${wb}.`;
    } else {
        upgrade = `Starting documented activity in ${wa} and ${wb} next week will create the first link between these pillars.`;
    }

    // --- Trend ---
    let trend;
    const hasPrevActivity = Object.values(prevLinks).some(v => v > 0);
    if (!hasPrevActivity && currentTotal <= 2) {
        trend = 'Trend will be shown after a second week of recorded activity.';
    } else if (currentTotal > prevTotal) {
        trend = 'Coherence has improved compared to the previous week.';
    } else if (currentTotal < prevTotal) {
        trend = 'Minor regression in coherence compared to the previous week.';
    } else {
        trend = 'Coherence is stable compared to the previous week.';
    }

    // Emphasized edges: top 2 scored links
    const emphasized = top2.map(e => e[0]);

    return { wins, upgrade, trend, fullChain, emphasized, limited };
}

// =====================================================
// GLP WEEKLY SNAPSHOT – helpers, scoring, builder
// =====================================================

function currentIsoWeek() {
    const now = new Date();
    const d = new Date(Date.UTC(now.getFullYear(), now.getMonth(), now.getDate()));
    d.setUTCDate(d.getUTCDate() + 4 - (d.getUTCDay() || 7));
    const yearStart = new Date(Date.UTC(d.getUTCFullYear(), 0, 1));
    const weekNo = Math.ceil((((d - yearStart) / 86400000) + 1) / 7);
    return `${d.getUTCFullYear()}W${String(weekNo).padStart(2, '0')}`;
}

function glpR2Keys(affiliation, userId, isoWeek) {
    const year = isoWeek.slice(0, 4);
    const wPart = isoWeek.slice(4); // 'W07'
    const base = `glp-status/weekly/${affiliation}/${userId}/${year}/${wPart}`;
    return {
        snapshot: `${base}/snapshot.json`,
        harmony:  `${base}/harmony.json`
    };
}

function resolveGlpLevel(score) {
    if (score >= 81) return 'dragon';
    if (score >= 61) return 'eagle';
    if (score >= 41) return 'owl';
    if (score >= 21) return 'fledgling';
    return 'hatchling';
}

// --- Sphere scoring (each 0-100) ---

function scoreDocumentation(sops, presentations) {
    let s = 0;
    s += Math.min(sops.approved, 5) * 6;                                         // max 30
    s += sops.total > 0 ? Math.round((sops.approved / sops.total) * 25) : 0;     // max 25
    if (sops.avgAiScore !== null) s += Math.round((sops.avgAiScore / 100) * 20);      // max 20, neutral if absent
    s += Math.min(sops.recentCount, 3) * 5;                                      // max 15
    s += Math.min(presentations.approved, 3) * 3;                                // max 9 (~10)
    return Math.min(Math.round(s), 100);
}

function scoreTraining(t) {
    let s = 0;
    s += t.hasSealedPack ? 35 : 0;
    s += Math.min(t.certifiedEntries, 5) * 5;                                    // max 25
    s += Math.round(t.agreementRatio * 25);                                      // max 25
    s += t.hasRevisionNeeded ? 0 : 15;
    return Math.min(s, 100);
}

function scoreTraceability(inv) {
    let s = 0;
    s += Math.min(inv.products, 10) * 2.5;                                       // max 25
    s += Math.min(inv.samples, 5) * 4;                                           // max 20
    s += Math.min(inv.oligos, 3) * 5;                                            // max 15
    s += Math.round(inv.approvedRatio * 25);                                     // max 25
    s += Math.min(inv.recentActivity, 3) * 5;                                    // max 15
    return Math.min(Math.round(s), 100);
}

function scoreDataIntegrity(data, revisions) {
    let s = 0;
    s += Math.min(data.approved, 5) * 6;                                         // max 30
    s += data.total > 0 ? Math.round((data.approved / data.total) * 25) : 0;     // max 25
    if (data.avgAiScore !== null) s += Math.round((data.avgAiScore / 100) * 20);      // max 20, neutral if absent
    s += Math.max(0, 15 - revisions.openCount * 5);                              // max 15
    s += Math.min(data.recentCount, 2) * 5;                                      // max 10
    return Math.min(Math.round(s), 100);
}

function computeOverallScore(doc, train, trace, dataInt) {
    const raw = doc * 0.30 + train * 0.25 + trace * 0.20 + dataInt * 0.25;
    return Math.max(0, Math.min(100, Math.round(raw)));
}

// --- Deterministic snapshot builder ---

async function buildGlpSnapshot(userId) {
    const crypto = require('crypto');

    const [subsResult, invResult, trainResult, revResult] = await Promise.all([
        pool.query(`
            SELECT file_type,
                COUNT(*) FILTER (WHERE status = 'APPROVED')::int AS approved,
                COUNT(*)::int AS total,
                NULL::int AS avg_ai_score,
                COUNT(*) FILTER (WHERE created_at >= CURRENT_DATE - INTERVAL '28 days')::int AS recent_count
            FROM di_submissions
            WHERE researcher_id = $1
            GROUP BY file_type
        `, [userId]),

        pool.query(`
            SELECT
                COUNT(*) FILTER (WHERE item_type = 'product')::int AS products,
                COUNT(*) FILTER (WHERE item_type = 'sample')::int AS samples,
                COUNT(*) FILTER (WHERE item_type = 'oligo')::int AS oligos,
                COUNT(*)::int AS total_items,
                COUNT(*) FILTER (WHERE status = 'Approved')::int AS approved_items,
                COUNT(*) FILTER (WHERE created_at >= CURRENT_DATE - INTERVAL '28 days')::int AS recent_items
            FROM di_inventory_items
            WHERE created_by = $1
        `, [userId]),

        checkTrainingTables().then(exists => {
            if (!exists) return { rows: [] };
            return pool.query(`
                SELECT
                    (SELECT COUNT(*)::int FROM di_training_packs WHERE researcher_id = $1 AND status = 'SEALED') AS sealed_count,
                    (SELECT COUNT(*)::int FROM di_training_packs WHERE researcher_id = $1 AND status = 'REVISION_NEEDED') AS revision_packs,
                    (SELECT COUNT(*)::int FROM di_training_entries e
                     JOIN di_training_packs p ON p.id = e.pack_id
                     WHERE p.researcher_id = $1 AND e.status = 'CERTIFIED') AS certified_entries,
                    (SELECT COUNT(*)::int FROM di_training_agreements a
                     JOIN di_training_packs p ON p.id = a.pack_id
                     WHERE p.researcher_id = $1) AS agreement_count,
                    (SELECT COUNT(*)::int FROM di_training_documents
                     WHERE is_active = TRUE
                       AND requirement_rule = 'Always') AS required_docs
            `, [userId]);
        }),

        pool.query(`
            SELECT COUNT(*)::int AS open_count
            FROM di_revision_requests
            WHERE researcher_id = $1 AND status = 'open'
        `, [userId]).catch(() => ({ rows: [{ open_count: 0 }] }))
    ]);

    // Parse submission metrics per file type
    const subs = {};
    for (const row of subsResult.rows) {
        subs[row.file_type] = {
            approved: parseInt(row.approved) || 0,
            total: parseInt(row.total) || 0,
            avgAiScore: (row.avg_ai_score === null ? null : (parseInt(row.avg_ai_score) || 0)),
            recentCount: parseInt(row.recent_count) || 0
        };
    }
    const sopM  = subs['SOP']  || { approved: 0, total: 0, avgAiScore: null, recentCount: 0 };
    const dataM = subs['DATA'] || { approved: 0, total: 0, avgAiScore: null, recentCount: 0 };
    const presM = subs['PRESENTATION'] || { approved: 0, total: 0, avgAiScore: null, recentCount: 0 };

    // Parse inventory
    const inv = invResult.rows[0] || {};
    const invProducts = parseInt(inv.products) || 0;
    const invSamples  = parseInt(inv.samples) || 0;
    const invOligos   = parseInt(inv.oligos) || 0;
    const invTotal    = parseInt(inv.total_items) || 0;
    const invApproved = parseInt(inv.approved_items) || 0;
    const invRecent   = parseInt(inv.recent_items) || 0;

    // Parse training
    const tr = trainResult.rows[0] || {};
    const sealedCount     = parseInt(tr.sealed_count) || 0;
    const revisionPacks   = parseInt(tr.revision_packs) || 0;
    const certifiedEntries = parseInt(tr.certified_entries) || 0;
    const agreementCount  = parseInt(tr.agreement_count) || 0;
    const requiredDocs    = parseInt(tr.required_docs) || 0;

    // Parse revisions
    const openRevisions = parseInt((revResult.rows[0] || {}).open_count) || 0;

    // Compute sphere scores
    const docScore   = scoreDocumentation(sopM, { approved: presM.approved });
      const agreementRatio = requiredDocs > 0 ? Math.min(agreementCount / requiredDocs, 1) : 0;

      // Training policy: agreements are foundational, cap their contribution and gate higher tiers until verified training exists
      const agreementsPoints = Math.min(Math.round(agreementRatio * 30), 20); // cap at 20

      // Base model score (includes agreements + verification), keep it but prevent agreements from dominating
      const trainBase = scoreTraining({
          hasSealedPack: sealedCount > 0,
          certifiedEntries,
          agreementRatio,
          hasRevisionNeeded: revisionPacks > 0
      });

      // Recompose conservatively: cap agreements portion, keep remaining as verified contribution
      const verifiedPoints = Math.max(0, trainBase - Math.round(agreementRatio * 30));
      let trainScore = Math.min(100, agreementsPoints + verifiedPoints);

      // Gate: no certified entries and no sealed packs means training cannot look mature yet
      if (sealedCount === 0 && certifiedEntries === 0) {
          trainScore = Math.min(trainScore, 25);
      }
    const traceScore = scoreTraceability({
        products: invProducts, samples: invSamples, oligos: invOligos,
        approvedRatio: invTotal > 0 ? invApproved / invTotal : 0,
        recentActivity: invRecent
    });
    const dataIntScore = scoreDataIntegrity(dataM, { openCount: openRevisions });

    const overallScore = computeOverallScore(docScore, trainScore, traceScore, dataIntScore);
    const glpLevel = resolveGlpLevel(overallScore);

    // Conformity flags
    const conformity = {
        training_sealed:             sealedCount > 0,
        training_entries_certified:  certifiedEntries >= 3,
        all_agreements_confirmed:    requiredDocs > 0 && agreementCount >= requiredDocs,
        has_approved_sops:           sopM.approved >= 1,
        has_approved_data:           dataM.approved >= 1,
        inventory_active:            invTotal >= 1,
        no_open_revisions:           openRevisions === 0,
        recent_activity:             (sopM.recentCount + dataM.recentCount + invRecent) > 0,
        sop_coverage_adequate:       sopM.approved >= 3,
        data_coverage_adequate:      dataM.approved >= 3,
        missing_sop_links:           sopM.approved === 0 && dataM.approved > 0,
        missing_training:            sealedCount === 0 && certifiedEntries === 0,
        missing_inventory:           invTotal === 0
    };

    const snapshot = {
    schema_version: '1.0.0',
    scoring_version: '1.0.0',
    user_id: userId,
    generated_at: new Date().toISOString(),
    overall_score: overallScore,
    glp_level: glpLevel,
    spheres: {
        documentation: docScore,
        training: trainScore,
        traceability: traceScore,
        data_integrity: dataIntScore
    },
    evidence: {
        sops:          { approved: sopM.approved, total: sopM.total, avg_ai_score: sopM.avgAiScore, recent: sopM.recentCount },
        data:          { approved: dataM.approved, total: dataM.total, avg_ai_score: dataM.avgAiScore, recent: dataM.recentCount },
        presentations: { approved: presM.approved, total: presM.total },
        inventory:     { products: invProducts, samples: invSamples, oligos: invOligos, total: invTotal, approved: invApproved },
        training:      { sealed_packs: sealedCount, certified_entries: certifiedEntries, agreements: agreementCount, required_docs: requiredDocs },
        revisions:     { open_count: openRevisions }
    },
    conformity
};

    // Deterministic hash: deep-sorted keys, scoring-relevant data only (no timestamps)
    function stableStringify(obj) {
        if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
        if (Array.isArray(obj)) return '[' + obj.map(stableStringify).join(',') + ']';
        const keys = Object.keys(obj).sort();
        return '{' + keys.map(k => JSON.stringify(k) + ':' + stableStringify(obj[k])).join(',') + '}';
    }
    const hashable = {
    scoring_version: snapshot.scoring_version,
    overall_score: snapshot.overall_score,
    glp_level: snapshot.glp_level,
    spheres: snapshot.spheres,
    evidence: snapshot.evidence,
    conformity: snapshot.conformity
};
    const canonical = stableStringify(hashable);
    const hash = crypto.createHash('sha256').update(canonical).digest('hex');
    snapshot.hash = hash;

    return { snapshot, hash };
}

app.get('/api/di/glp-status/coherence', requireAuth, async (req, res) => {
    try {
        const rid = req.session.user.researcher_id;

        // Week boundaries using ISO week (Monday start)
        const boundsCTE = `
            date_trunc('week', CURRENT_DATE) AS tw_start,
            date_trunc('week', CURRENT_DATE) - INTERVAL '7 days' AS pw_start
        `;

        // A: Submissions (SOP + DATA)
        const qSubs = pool.query(`
            WITH b AS (SELECT ${boundsCTE})
            SELECT
                s.file_type,
                COUNT(*) FILTER (WHERE s.created_at >= b.tw_start)::int AS this_week,
                COUNT(*) FILTER (WHERE s.created_at >= b.pw_start AND s.created_at < b.tw_start)::int AS prev_week,
                COUNT(*) FILTER (WHERE s.status = 'APPROVED')::int AS approved_total
            FROM di_submissions s, b
            WHERE s.researcher_id = $1
            GROUP BY s.file_type, b.tw_start, b.pw_start
        `, [rid]);

        // B: Inventory activity (items created + log actions)
        const qInv = pool.query(`
            WITH b AS (SELECT ${boundsCTE})
            SELECT
                COUNT(*) FILTER (WHERE ii.created_at >= b.tw_start)::int AS items_tw,
                COUNT(*) FILTER (WHERE ii.created_at >= b.pw_start AND ii.created_at < b.tw_start)::int AS items_pw,
                COUNT(*) FILTER (WHERE ii.status = 'Approved')::int AS approved_total,
                (SELECT COUNT(*)::int FROM di_inventory_items_log il
                 JOIN di_inventory_items ix ON ix.id = il.inventory_item_id
                 WHERE ix.created_by = $1 AND il.created_at >= b.tw_start) AS log_tw,
                (SELECT COUNT(*)::int FROM di_inventory_items_log il
                 JOIN di_inventory_items ix ON ix.id = il.inventory_item_id
                 WHERE ix.created_by = $1
                   AND il.created_at >= b.pw_start AND il.created_at < b.tw_start) AS log_pw
            FROM di_inventory_items ii, b
            WHERE ii.created_by = $1
        `, [rid]);

        // C: Training (guarded)
        let trainingData = { thisWeek: false, prevWeek: false, hasSealedPack: false, certifiedCount: 0, agreementCount: 0 };
        let qTrain = null;
        if (await checkTrainingTables()) {
            qTrain = pool.query(`
                WITH b AS (SELECT ${boundsCTE})
                SELECT
                    b.tw_start,
                    b.pw_start,
                    (SELECT COUNT(*)::int FROM di_training_packs p
                     WHERE p.researcher_id = $1 AND p.status = 'SEALED') AS sealed_count,
                    (SELECT COUNT(*)::int FROM di_training_entries e
                     JOIN di_training_packs p ON p.id = e.pack_id
                     WHERE p.researcher_id = $1 AND e.status = 'CERTIFIED') AS certified_entries,
                    (SELECT COUNT(*)::int FROM di_training_agreements a
                     JOIN di_training_packs p ON p.id = a.pack_id
                     WHERE p.researcher_id = $1) AS agreement_count,
                    (SELECT COUNT(*)::int FROM di_training_entries e
                     JOIN di_training_packs p ON p.id = e.pack_id
                     WHERE p.researcher_id = $1
                       AND (e.certified_at >= b.tw_start OR e.created_at >= b.tw_start)) AS entries_tw,
                    (SELECT COUNT(*)::int FROM di_training_entries e
                     JOIN di_training_packs p ON p.id = e.pack_id
                     WHERE p.researcher_id = $1
                       AND (e.certified_at >= b.pw_start OR e.created_at >= b.pw_start)
                       AND (e.certified_at < b.tw_start OR (e.certified_at IS NULL AND e.created_at < b.tw_start))) AS entries_pw,
                    (SELECT COUNT(*)::int FROM di_training_packs p
                     WHERE p.researcher_id = $1
                       AND p.status IN ('SUBMITTED','SEALED')
                       AND (p.sealed_at >= b.tw_start OR p.updated_at >= b.tw_start)) AS packs_tw
                FROM b
            `, [rid]);
        }

        const [subsResult, invResult] = await Promise.all([qSubs, qInv]);
        if (qTrain) {
            const tr = (await qTrain).rows[0] || {};
            trainingData = {
                thisWeek: (parseInt(tr.entries_tw) || 0) > 0 || (parseInt(tr.packs_tw) || 0) > 0,
                prevWeek: (parseInt(tr.entries_pw) || 0) > 0,
                hasSealedPack: (parseInt(tr.sealed_count) || 0) > 0,
                certifiedCount: parseInt(tr.certified_entries) || 0,
                agreementCount: parseInt(tr.agreement_count) || 0
            };
        }

        // Parse submissions
        const subs = {};
        for (const row of subsResult.rows) {
            subs[row.file_type] = {
                thisWeek: parseInt(row.this_week) || 0,
                prevWeek: parseInt(row.prev_week) || 0,
                approvedTotal: parseInt(row.approved_total) || 0
            };
        }
        const sopData  = subs['SOP']  || { thisWeek: 0, prevWeek: 0, approvedTotal: 0 };
        const dataData = subs['DATA'] || { thisWeek: 0, prevWeek: 0, approvedTotal: 0 };

        // Parse inventory
        const inv = invResult.rows[0] || {};
        const invData = {
            thisWeek: (parseInt(inv.items_tw) || 0) + (parseInt(inv.log_tw) || 0),
            prevWeek: (parseInt(inv.items_pw) || 0) + (parseInt(inv.log_pw) || 0),
            approvedTotal: parseInt(inv.approved_total) || 0
        };

        const coherence = computeCoherence(sopData, dataData, invData, trainingData);
        res.json({ success: true, coherence });
    } catch (err) {
        console.error('[GLP-COHERENCE] error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// =====================================================
// GLP WEEKLY SNAPSHOT – Internal endpoints (API-key)
// =====================================================

  // Build deterministic snapshot authority endpoint (no DB writes, no AI)
  app.get('/api/glp/status/build-snapshot/:userId', async (req, res) => {
      try {
          const apiKey = (req.headers['x-api-key'] || '').toString().trim();
          if (!apiKey || apiKey !== ((process.env.API_SECRET_KEY || '').toString().trim())) {
              return res.status(401).json({ error: 'Invalid or missing API key' });
          }

          const userId = (req.params.userId || '').trim();
          if (!userId) return res.status(400).json({ error: 'userId required' });

          const { snapshot, hash } = await buildGlpSnapshot(userId);
          return res.json({ success: true, snapshot, hash });
      } catch (err) {
          console.error('[GLP-STATUS] build-snapshot error:', err);
          res.status(500).json({ error: 'Server error' });
      }
  });

// GET eligible users for weekly snapshot generation (n8n calls this)
app.get('/api/glp/status/eligible-users', async (req, res) => {
    try {
        const apiKey = (req.headers['x-api-key'] || '').toString().trim();
        if (!apiKey || apiKey !== ((process.env.API_SECRET_KEY || '').toString().trim())) {
            return res.status(401).json({ error: 'Invalid or missing API key' });
        }
        const result = await pool.query(
            `SELECT researcher_id AS user_id, affiliation
             FROM di_allowlist
             WHERE active = true AND COALESCE(role, 'researcher') IN ('researcher', 'supervisor')
             ORDER BY affiliation, researcher_id`
        );
        res.json({ success: true, users: result.rows });
    } catch (err) {
        console.error('[GLP-STATUS] eligible-users error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Generate snapshot for one user (n8n calls this per user)
app.post('/api/glp/status/generate-one', async (req, res) => {
    try {
        const apiKey = (req.headers['x-api-key'] || '').toString().trim();
        if (!apiKey || apiKey !== ((process.env.API_SECRET_KEY || '').toString().trim())) {
            return res.status(401).json({ error: 'Invalid or missing API key' });
        }
        if (!(await checkGlpStatusTable())) {
            return res.status(501).json({ error: 'GLP status table not available' });
        }

        const userId = (req.body.user_id || '').trim();
        if (!userId) return res.status(400).json({ error: 'user_id required' });

        const isoWeek = (req.body.iso_week || '').trim() || currentIsoWeek();

        // Skip if already generated
        const existing = await pool.query(
            'SELECT id FROM glp_weekly_status_index WHERE user_id = $1 AND iso_week = $2',
            [userId, isoWeek]
        );
        if (existing.rows.length > 0) {
            return res.json({ success: true, generated: false, user_id: userId, iso_week: isoWeek, message: 'Already exists' });
        }

        // Look up affiliation
        const userRow = await pool.query(
            'SELECT affiliation FROM di_allowlist WHERE researcher_id = $1 AND active = true',
            [userId]
        );
        if (userRow.rows.length === 0) return res.status(404).json({ error: 'User not found or inactive' });
        const affiliation = userRow.rows[0].affiliation;

        // Build deterministic snapshot
        const { snapshot, hash } = await buildGlpSnapshot(userId);

        // Store snapshot.json in R2 first
        const keys = glpR2Keys(affiliation, userId, isoWeek);
        await uploadToR2(Buffer.from(JSON.stringify(snapshot, null, 2)), keys.snapshot, 'application/json');

        // Then insert DB index row
        await pool.query(`
            INSERT INTO glp_weekly_status_index
                (user_id, iso_week, generated_at, r2_snapshot_key, evidence_hash, snapshot_version, model_version)
            VALUES ($1, $2, NOW(), $3, $4, $5, $6)
        `, [userId, isoWeek, keys.snapshot, hash, 1, '1.0.0']);

        console.log(`[GLP-STATUS] Generated snapshot for ${userId} week ${isoWeek}, score=${snapshot.overall_score}, level=${snapshot.glp_level}`);

        res.json({
            success: true,
            generated: true,
            user_id: userId,
            iso_week: isoWeek,
            r2_snapshot_key: keys.snapshot,
            snapshot
        });
    } catch (err) {
        console.error('[GLP-STATUS] generate-one error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Store harmony JSON after Azure OpenAI reasoning (n8n calls this)
app.post('/api/glp/status/harmony', async (req, res) => {
    try {
        const apiKey = (req.headers['x-api-key'] || '').toString().trim();
        if (!apiKey || apiKey !== ((process.env.API_SECRET_KEY || '').toString().trim())) {
            return res.status(401).json({ error: 'Invalid or missing API key' });
        }
        if (!(await checkGlpStatusTable())) {
            return res.status(501).json({ error: 'GLP status table not available' });
        }

        const { user_id, iso_week, harmony } = req.body;
        if (!user_id || !iso_week || !harmony) {
            return res.status(400).json({ error: 'user_id, iso_week, and harmony are required' });
        }

        // Find existing index row
        const row = await pool.query(
            'SELECT id, r2_snapshot_key FROM glp_weekly_status_index WHERE user_id = $1 AND iso_week = $2',
            [user_id, iso_week]
        );
        if (row.rows.length === 0) return res.status(404).json({ error: 'Snapshot not found for this week' });

        // Derive harmony key from snapshot key path
        const snapshotKey = row.rows[0].r2_snapshot_key;
        const harmonyKey = snapshotKey.replace('/snapshot.json', '/harmony.json');

        // Upload harmony JSON to R2
        await uploadToR2(Buffer.from(JSON.stringify(harmony, null, 2)), harmonyKey, 'application/json');

        // Update index row with harmony key
        await pool.query(
            'UPDATE glp_weekly_status_index SET r2_harmony_key = $1 WHERE id = $2',
            [harmonyKey, row.rows[0].id]
        );

        console.log(`[GLP-STATUS] Stored harmony for ${user_id} week ${iso_week}`);
        res.json({ success: true, r2_harmony_key: harmonyKey });
    } catch (err) {
        console.error('[GLP-STATUS] harmony store error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// =====================================================
// GLP WEEKLY SNAPSHOT v2 – n8n endpoints (API-key)
// =====================================================

// Purchase table guard (migration 013)
let purchaseTableExists = null;
let purchaseTableLastCheck = 0;
async function checkPurchaseTable() {
    const now = Date.now();
    if (purchaseTableExists === null || purchaseTableExists === false || (now - purchaseTableLastCheck > 60000)) {
        try {
            const r = await pool.query("SELECT 1 FROM information_schema.tables WHERE table_name='di_purchase_requests'");
            purchaseTableExists = r.rows.length > 0;
            purchaseTableLastCheck = now;
        } catch (err) { purchaseTableExists = false; }
    }
    return purchaseTableExists;
}

// 1A. GET active users — returns all active users with role and affiliation, no role filtering
app.get('/api/glp/status/users-active', async (req, res) => {
    try {
        const apiKey = (req.headers['x-api-key'] || '').toString().trim();
        if (!apiKey || apiKey !== ((process.env.API_SECRET_KEY || '').toString().trim())) {
            return res.status(401).json({ error: 'Invalid or missing API key' });
        }
        const result = await pool.query(
            `SELECT researcher_id AS user_id, name,
                    COALESCE(role, 'researcher') AS role, affiliation, active
             FROM di_allowlist
             WHERE active = true
             ORDER BY affiliation, name`
        );
        res.json({ success: true, users: result.rows });
    } catch (err) {
        console.error('[GLP-STATUS-V2] users-active error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// 1B. GET user facts — aggregated raw facts for scoring in n8n
app.get('/api/glp/status/user-facts/:userId', async (req, res) => {
    try {
        const apiKey = (req.headers['x-api-key'] || '').toString().trim();
        if (!apiKey || apiKey !== ((process.env.API_SECRET_KEY || '').toString().trim())) {
            return res.status(401).json({ error: 'Invalid or missing API key' });
        }

        const userId = req.params.userId;

        // 7 parallel queries
        const hasPurchase = await checkPurchaseTable();
        const hasTraining = await checkTrainingTables();

        const [profileResult, subsResult, invResult, trainResult, revResult, purchaseResult, hygieneResult] = await Promise.all([
            // Profile
            pool.query(
                `SELECT name, COALESCE(role, 'researcher') AS role, affiliation
                 FROM di_allowlist WHERE researcher_id = $1 AND active = true`, [userId]
            ),

            // Submissions per file_type
            pool.query(`
                SELECT file_type,
                    COUNT(*)::int AS total,
                    COUNT(*) FILTER (WHERE status = 'APPROVED')::int AS approved,
                    COUNT(*) FILTER (WHERE status = 'PENDING')::int AS pending,
                    COUNT(*) FILTER (WHERE status = 'REVISION_NEEDED')::int AS revision_needed,
                    COUNT(*) FILTER (WHERE created_at >= CURRENT_DATE - INTERVAL '28 days')::int AS recent_4w,
                    ROUND(AVG(ai_review_score)::numeric, 1) AS avg_ai_score
                FROM di_submissions
                WHERE researcher_id = $1
                GROUP BY file_type
            `, [userId]),

            // Inventory
            pool.query(`
                SELECT
                    COUNT(*) FILTER (WHERE item_type = 'product')::int AS products,
                    COUNT(*) FILTER (WHERE item_type = 'sample')::int AS samples,
                    COUNT(*) FILTER (WHERE item_type = 'oligo')::int AS oligos,
                    COUNT(*)::int AS total,
                    COUNT(*) FILTER (WHERE status = 'Approved')::int AS approved,
                    COUNT(*) FILTER (WHERE status = 'Pending')::int AS pending,
                    COUNT(*) FILTER (WHERE created_at >= CURRENT_DATE - INTERVAL '28 days')::int AS recent_4w
                FROM di_inventory_items
                WHERE created_by = $1
            `, [userId]),

            // Training
            hasTraining ? pool.query(`
                SELECT
                    (SELECT COUNT(*)::int FROM di_training_packs WHERE researcher_id = $1 AND status = 'SEALED') AS sealed_packs,
                    (SELECT COUNT(*)::int FROM di_training_packs WHERE researcher_id = $1 AND status = 'REVISION_NEEDED') AS revision_packs,
                    (SELECT COUNT(*)::int FROM di_training_entries e
                     JOIN di_training_packs p ON p.id = e.pack_id
                     WHERE p.researcher_id = $1 AND e.status = 'CERTIFIED') AS certified_entries,
                    (SELECT COUNT(*)::int FROM di_training_agreements a
                     JOIN di_training_packs p ON p.id = a.pack_id
                     WHERE p.researcher_id = $1) AS agreement_count,
                    (SELECT COUNT(*)::int FROM di_training_documents
                     WHERE is_active = TRUE AND requirement_rule = 'Always') AS required_docs
            `, [userId]) : Promise.resolve({ rows: [{}] }),

            // Revisions
            pool.query(`
                SELECT COUNT(*)::int AS open_count,
                       EXTRACT(DAY FROM NOW() - MIN(created_at))::int AS oldest_open_days
                FROM di_revision_requests
                WHERE researcher_id = $1 AND status = 'open'
            `, [userId]).catch(() => ({ rows: [{ open_count: 0, oldest_open_days: null }] })),

            // Purchases
            hasPurchase ? pool.query(`
                SELECT
                    COUNT(*)::int AS submitted,
                    COUNT(*) FILTER (WHERE r.status = 'APPROVED')::int AS approved,
                    COUNT(*) FILTER (WHERE r.status = 'DECLINED')::int AS declined,
                    COUNT(*) FILTER (WHERE i.item_status = 'Modification Requested')::int AS modification_requested,
                    COUNT(*) FILTER (WHERE i.item_status = 'Cancel Requested')::int AS cancel_requested,
                    COUNT(*) FILTER (WHERE r.status = 'SUBMITTED' AND i.item_status = 'Active')::int AS blocking_consolidation
                FROM di_purchase_items i
                JOIN di_purchase_requests r ON r.id = i.request_id
                WHERE r.requester_id = $1
            `, [userId]) : Promise.resolve({ rows: [{}] }),

            // Hygiene: last portal activity across all sources
            (async () => {
                const timestamps = [];
                // Submissions
                try {
                    const r = await pool.query('SELECT MAX(created_at) AS ts FROM di_submissions WHERE researcher_id = $1', [userId]);
                    if (r.rows[0]?.ts) timestamps.push(new Date(r.rows[0].ts));
                } catch (e) { /* skip */ }
                // Inventory
                try {
                    const r = await pool.query('SELECT MAX(created_at) AS ts FROM di_inventory_items WHERE created_by = $1', [userId]);
                    if (r.rows[0]?.ts) timestamps.push(new Date(r.rows[0].ts));
                } catch (e) { /* skip */ }
                // Purchases
                if (hasPurchase) {
                    try {
                        const r = await pool.query('SELECT MAX(created_at) AS ts FROM di_purchase_requests WHERE requester_id = $1', [userId]);
                        if (r.rows[0]?.ts) timestamps.push(new Date(r.rows[0].ts));
                    } catch (e) { /* skip */ }
                }
                // Training
                if (hasTraining) {
                    try {
                        const r = await pool.query('SELECT MAX(updated_at) AS ts FROM di_training_packs WHERE researcher_id = $1', [userId]);
                        if (r.rows[0]?.ts) timestamps.push(new Date(r.rows[0].ts));
                    } catch (e) { /* skip */ }
                }
                if (timestamps.length === 0) return null;
                return new Date(Math.max(...timestamps.map(t => t.getTime()))).toISOString();
            })()
        ]);

        if (profileResult.rows.length === 0) {
            return res.status(404).json({ error: 'User not found or inactive' });
        }

        // Parse submissions
        const subs = {};
        for (const row of subsResult.rows) {
            subs[row.file_type] = row;
        }
        const sopR  = subs['SOP'] || {};
        const dataR = subs['DATA'] || {};
        const presR = subs['PRESENTATION'] || {};

        const inv = invResult.rows[0] || {};
        const tr  = trainResult.rows[0] || {};
        const rev = revResult.rows[0] || {};
        const pur = purchaseResult.rows[0] || {};

        res.json({
            success: true,
            user_id: userId,
            profile: profileResult.rows[0],
            sop: {
                total: parseInt(sopR.total) || 0,
                approved: parseInt(sopR.approved) || 0,
                recent_4w: parseInt(sopR.recent_4w) || 0,
                avg_ai_score: sopR.avg_ai_score !== undefined && sopR.avg_ai_score !== null ? parseFloat(sopR.avg_ai_score) : null
            },
            data: {
                total: parseInt(dataR.total) || 0,
                approved: parseInt(dataR.approved) || 0,
                pending: parseInt(dataR.pending) || 0,
                revision_needed: parseInt(dataR.revision_needed) || 0,
                recent_4w: parseInt(dataR.recent_4w) || 0,
                avg_ai_score: dataR.avg_ai_score !== undefined && dataR.avg_ai_score !== null ? parseFloat(dataR.avg_ai_score) : null
            },
            presentation: {
                total: parseInt(presR.total) || 0,
                approved: parseInt(presR.approved) || 0
            },
            revision: {
                open_count: parseInt(rev.open_count) || 0,
                oldest_open_days: rev.oldest_open_days !== undefined && rev.oldest_open_days !== null ? parseInt(rev.oldest_open_days) : null
            },
            inventory: {
                products: parseInt(inv.products) || 0,
                samples: parseInt(inv.samples) || 0,
                oligos: parseInt(inv.oligos) || 0,
                total: parseInt(inv.total) || 0,
                approved: parseInt(inv.approved) || 0,
                pending: parseInt(inv.pending) || 0,
                recent_4w: parseInt(inv.recent_4w) || 0
            },
            purchase: {
                submitted: parseInt(pur.submitted) || 0,
                approved: parseInt(pur.approved) || 0,
                declined: parseInt(pur.declined) || 0,
                modification_requested: parseInt(pur.modification_requested) || 0,
                cancel_requested: parseInt(pur.cancel_requested) || 0,
                blocking_consolidation: parseInt(pur.blocking_consolidation) || 0
            },
            training: {
                sealed_packs: parseInt(tr.sealed_packs) || 0,
                revision_packs: parseInt(tr.revision_packs) || 0,
                certified_entries: parseInt(tr.certified_entries) || 0,
                agreement_count: parseInt(tr.agreement_count) || 0,
                required_docs: parseInt(tr.required_docs) || 0
            },
            hygiene: {
                last_portal_activity_at: hygieneResult
            }
        });
    } catch (err) {
        console.error('[GLP-STATUS-V2] user-facts error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// 1C. POST write weekly snapshot — n8n sends computed snapshot, server writes to R2 and DB
app.post('/api/glp/status/write-weekly-snapshot', async (req, res) => {
    try {
        const apiKey = (req.headers['x-api-key'] || '').toString().trim();
        if (!apiKey || apiKey !== ((process.env.API_SECRET_KEY || '').toString().trim())) {
            return res.status(401).json({ error: 'Invalid or missing API key' });
        }
        if (!(await checkGlpStatusTable())) {
            return res.status(501).json({ error: 'GLP status table not available' });
        }

        const { user_id, iso_week, snapshot } = req.body;
        if (!user_id || !iso_week || !snapshot) {
            return res.status(400).json({ error: 'user_id, iso_week, and snapshot are required' });
        }

        // Look up affiliation
        const userRow = await pool.query(
            'SELECT affiliation FROM di_allowlist WHERE researcher_id = $1 AND active = true',
            [user_id]
        );
        if (userRow.rows.length === 0) return res.status(404).json({ error: 'User not found or inactive' });
        const affiliation = userRow.rows[0].affiliation;

        // Compute R2 keys
        const keys = glpR2Keys(affiliation, user_id, iso_week);

        // Upload snapshot.json
        await uploadToR2(Buffer.from(JSON.stringify(snapshot, null, 2)), keys.snapshot, 'application/json');

        // Backward compat: transform harmony_map to v1 harmony format and write harmony.json
        let harmonyKey = null;
        if (snapshot.harmony_map) {
            const hm = snapshot.harmony_map;
            const v1Harmony = {
                motivation: hm.documentation?.insight || '',
                reflection: hm.best_next_action || '',
                goals: [hm.best_next_action].filter(Boolean),
                actions: Object.values(hm)
                    .filter(v => v && typeof v === 'object' && v.next_action)
                    .map(v => v.next_action)
            };
            await uploadToR2(Buffer.from(JSON.stringify(v1Harmony, null, 2)), keys.harmony, 'application/json');
            harmonyKey = keys.harmony;
        }

        // Compute evidence_hash server side
        const crypto = require('crypto');
        function stableStringify(obj) {
            if (obj === null || typeof obj !== 'object') return JSON.stringify(obj);
            if (Array.isArray(obj)) return '[' + obj.map(stableStringify).join(',') + ']';
            const ks = Object.keys(obj).sort();
            return '{' + ks.map(k => JSON.stringify(k) + ':' + stableStringify(obj[k])).join(',') + '}';
        }
        const hashable = {
            user_id: snapshot.user_id,
            scoring_version: snapshot.scoring_version,
            overall_score: snapshot.overall_score,
            glp_level: snapshot.glp_level,
            spheres: snapshot.spheres,
            evidence: snapshot.evidence,
            conformity: snapshot.conformity
        };
        const evidenceHash = crypto.createHash('sha256').update(stableStringify(hashable)).digest('hex');

        // Upsert index row
        await pool.query(`
            INSERT INTO glp_weekly_status_index
                (user_id, iso_week, generated_at, r2_snapshot_key, r2_harmony_key, evidence_hash, snapshot_version, model_version)
            VALUES ($1, $2, NOW(), $3, $4, $5, $6, $7)
            ON CONFLICT (user_id, iso_week) DO UPDATE
            SET generated_at = NOW(), r2_snapshot_key = $3, r2_harmony_key = $4,
                evidence_hash = $5, snapshot_version = $6, model_version = $7
        `, [user_id, iso_week, keys.snapshot, harmonyKey, evidenceHash, 2, snapshot.model_version || 'azure-gpt-4o']);

        console.log(`[GLP-STATUS-V2] Wrote snapshot for ${user_id} week ${iso_week}, score=${snapshot.overall_score}`);

        res.json({
            success: true,
            user_id,
            iso_week,
            r2_snapshot_key: keys.snapshot,
            r2_harmony_key: harmonyKey,
            evidence_hash: evidenceHash
        });
    } catch (err) {
        console.error('[GLP-STATUS-V2] write-weekly-snapshot error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// 1D. POST write group snapshot — n8n sends aggregated group snapshot, server writes to R2 and DB
app.post('/api/glp/status/write-weekly-group-snapshot', async (req, res) => {
    try {
        const apiKey = (req.headers['x-api-key'] || '').toString().trim();
        if (!apiKey || apiKey !== ((process.env.API_SECRET_KEY || '').toString().trim())) {
            return res.status(401).json({ error: 'Invalid or missing API key' });
        }
        if (!(await checkGroupIndexTable())) {
            return res.status(501).json({ error: 'Group index table not available' });
        }

        const { affiliation, iso_week, snapshot, member_count, member_user_ids } = req.body;
        if (!affiliation || !iso_week || !snapshot || !member_count || !Array.isArray(member_user_ids)) {
            return res.status(400).json({ error: 'affiliation, iso_week, snapshot, member_count, and member_user_ids are required' });
        }

        // Compute R2 key
        const year = iso_week.slice(0, 4);
        const wPart = iso_week.slice(4);
        const r2Key = `glp-status/weekly/GROUP/${affiliation}/${year}/${wPart}/snapshot.json`;

        // Upload snapshot
        await uploadToR2(Buffer.from(JSON.stringify(snapshot, null, 2)), r2Key, 'application/json');

        // Compute membership_hash server side from sorted user_ids
        const crypto = require('crypto');
        const sortedIds = [...member_user_ids].sort();
        const membershipHash = crypto.createHash('sha256')
            .update(JSON.stringify(sortedIds))
            .digest('hex').slice(0, 16);

        // Upsert group index
        await pool.query(`
            INSERT INTO glp_group_weekly_status_index (cohort_id, iso_week, r2_snapshot_key, member_count, membership_hash)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (cohort_id, iso_week) DO UPDATE
            SET r2_snapshot_key = $3, member_count = $4, membership_hash = $5, created_at = NOW()
        `, [affiliation, iso_week, r2Key, member_count, membershipHash]);

        console.log(`[GLP-STATUS-V2] Wrote group snapshot for ${affiliation} week ${iso_week}, members=${member_count}`);

        res.json({
            success: true,
            affiliation,
            iso_week,
            r2_snapshot_key: r2Key,
            membership_hash: membershipHash
        });
    } catch (err) {
        console.error('[GLP-STATUS-V2] write-weekly-group-snapshot error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// =====================================================
// GLP WEEKLY SNAPSHOT – Public endpoints (session auth)
// =====================================================

// Helper: download JSON from R2 and parse
async function downloadR2Json(key) {
    const out = await downloadFromR2(key);
    const buf = await streamToBuffer(out.Body);
    return JSON.parse(buf.toString('utf-8'));
}

// List available weeks for session user
app.get('/api/glp/status/weeks', requireAuth, async (req, res) => {
    try {
        if (!(await checkGlpStatusTable())) return res.json({ success: true, weeks: [] });

        const rid = req.session.user.researcher_id;
        const result = await pool.query(
            `SELECT iso_week, generated_at, r2_harmony_key IS NOT NULL AS has_harmony
             FROM glp_weekly_status_index
             WHERE user_id = $1
             ORDER BY iso_week DESC
             LIMIT 52`,
            [rid]
        );
        res.json({ success: true, weeks: result.rows });
    } catch (err) {
        console.error('[GLP-STATUS] weeks error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Fetch snapshot + harmony for a specific week
app.get('/api/glp/status/week/:isoWeek', requireAuth, async (req, res) => {
    try {
        if (!(await checkGlpStatusTable())) return res.status(404).json({ error: 'No data available' });

        const rid = req.session.user.researcher_id;
        const idx = await pool.query(
            'SELECT * FROM glp_weekly_status_index WHERE user_id = $1 AND iso_week = $2',
            [rid, req.params.isoWeek]
        );
        if (idx.rows.length === 0) return res.status(404).json({ error: 'Week not found' });

        const row = idx.rows[0];
        const snapshot = await downloadR2Json(row.r2_snapshot_key);

        let harmony = null;
        if (row.r2_harmony_key) {
            try { harmony = await downloadR2Json(row.r2_harmony_key); } catch (e) {
                console.warn('[GLP-STATUS] harmony download failed:', e.message);
            }
        }

        res.json({
            success: true,
            iso_week: row.iso_week,
            generated_at: row.generated_at,
            evidence_hash: row.evidence_hash,
            snapshot,
            harmony
        });
    } catch (err) {
        console.error('[GLP-STATUS] week error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Fetch latest week snapshot
app.get('/api/glp/status/current', requireAuth, async (req, res) => {
    try {
        if (!(await checkGlpStatusTable())) return res.status(404).json({ error: 'No data available' });

        const rid = req.session.user.researcher_id;
        const latest = await pool.query(
            'SELECT * FROM glp_weekly_status_index WHERE user_id = $1 ORDER BY iso_week DESC LIMIT 1',
            [rid]
        );
        if (latest.rows.length === 0) return res.status(404).json({ error: 'No snapshots yet' });

        const row = latest.rows[0];
        const snapshot = await downloadR2Json(row.r2_snapshot_key);

        let harmony = null;
        if (row.r2_harmony_key) {
            try { harmony = await downloadR2Json(row.r2_harmony_key); } catch (e) { /* swallow */ }
        }

        res.json({
            success: true,
            iso_week: row.iso_week,
            generated_at: row.generated_at,
            evidence_hash: row.evidence_hash,
            snapshot,
            harmony
        });
    } catch (err) {
        console.error('[GLP-STATUS] current error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// =====================================================
// GLP COHORT MEMBERSHIP – PI-only endpoints
// =====================================================

let cohortTableExists = null;
let cohortTableLastCheck = 0;
async function checkCohortTable() {
    const now = Date.now();
    if (cohortTableExists === null || cohortTableExists === false || (now - cohortTableLastCheck > 60000)) {
        try {
            const r = await pool.query("SELECT 1 FROM information_schema.tables WHERE table_name='di_glp_cohort_members'");
            cohortTableExists = r.rows.length > 0;
            cohortTableLastCheck = now;
        } catch (err) { cohortTableExists = false; }
    }
    return cohortTableExists;
}

let groupIndexTableExists = null;
let groupIndexTableLastCheck = 0;
async function checkGroupIndexTable() {
    const now = Date.now();
    if (groupIndexTableExists === null || groupIndexTableExists === false || (now - groupIndexTableLastCheck > 60000)) {
        try {
            const r = await pool.query("SELECT 1 FROM information_schema.tables WHERE table_name='glp_group_weekly_status_index'");
            groupIndexTableExists = r.rows.length > 0;
            groupIndexTableLastCheck = now;
        } catch (err) { groupIndexTableExists = false; }
    }
    return groupIndexTableExists;
}

// GET cohort members — PI only
app.get('/api/glp/cohorts/members', requirePI, async (req, res) => {
    try {
        if (!(await checkCohortTable())) return res.status(501).json({ error: 'Cohort table not available' });

        const cohortId = (req.query.cohort_id || '').toUpperCase();
        if (!['LIU', 'UNAV'].includes(cohortId)) return res.status(400).json({ error: 'cohort_id must be LIU or UNAV' });

        // Get all active allowlist members for the affiliation
        const affiliation = cohortId === 'LIU' ? 'LiU' : 'UNAV';
        const result = await pool.query(`
            SELECT a.researcher_id AS user_id, a.name, COALESCE(a.role, 'researcher') AS role,
                   a.affiliation AS institution, a.active,
                   COALESCE(c.included, FALSE) AS included,
                   c.note,
                   (SELECT MAX(s.created_at) FROM di_submissions s WHERE s.researcher_id = a.researcher_id) AS last_activity,
                   (SELECT g.iso_week FROM glp_weekly_status_index g WHERE g.user_id = a.researcher_id ORDER BY g.iso_week DESC LIMIT 1) AS last_iso_week
            FROM di_allowlist a
            LEFT JOIN di_glp_cohort_members c ON c.user_id = a.researcher_id AND c.cohort_id = $1
            WHERE a.affiliation = $2
            ORDER BY a.name
        `, [cohortId, affiliation]);

        res.json({ success: true, cohort_id: cohortId, members: result.rows });
    } catch (err) {
        console.error('[GLP-COHORT] members error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// SET cohort members — PI only (upsert inclusion flags)
app.post('/api/glp/cohorts/members/set', requirePI, async (req, res) => {
    try {
        if (!(await checkCohortTable())) return res.status(501).json({ error: 'Cohort table not available' });

        const cohortId = (req.body.cohort_id || '').toUpperCase();
        if (!['LIU', 'UNAV'].includes(cohortId)) return res.status(400).json({ error: 'cohort_id must be LIU or UNAV' });

        const updates = req.body.updates;
        if (!Array.isArray(updates) || updates.length === 0) return res.status(400).json({ error: 'updates array required' });

        const piId = req.session.user.researcher_id;
        let count = 0;

        for (const u of updates) {
            if (!u.user_id) continue;
            await pool.query(`
                INSERT INTO di_glp_cohort_members (cohort_id, user_id, included, note, updated_by, updated_at)
                VALUES ($1, $2, $3, $4, $5, NOW())
                ON CONFLICT (cohort_id, user_id) DO UPDATE
                SET included = $3, note = $4, updated_by = $5, updated_at = NOW()
            `, [cohortId, u.user_id, u.included !== false, u.note || null, piId]);
            count++;
        }

        console.log(`[GLP-COHORT] PI ${piId} updated ${count} members in cohort ${cohortId}`);
        res.json({ success: true, updated: count });
    } catch (err) {
        console.error('[GLP-COHORT] set error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// =====================================================
// GLP GROUP SNAPSHOT – PI-only endpoints
// =====================================================

// Generate group snapshot — PI only (or n8n via API key)
app.post('/api/glp/status/generate-group', requirePI, async (req, res) => {
    try {
        if (!(await checkGlpStatusTable())) return res.status(501).json({ error: 'GLP status table not available' });
        if (!(await checkCohortTable())) return res.status(501).json({ error: 'Cohort table not available' });
        if (!(await checkGroupIndexTable())) return res.status(501).json({ error: 'Group index table not available' });

        const cohortId = (req.body.cohort_id || '').toUpperCase();
        if (!['LIU', 'UNAV', 'BOTH'].includes(cohortId)) return res.status(400).json({ error: 'cohort_id must be LIU, UNAV, or BOTH' });

        const isoWeek = (req.body.iso_week || '').trim() || currentIsoWeek();
        const crypto = require('crypto');

        // Resolve included member user_ids
        let memberQuery;
        if (cohortId === 'BOTH') {
            memberQuery = await pool.query(
                `SELECT DISTINCT user_id FROM di_glp_cohort_members WHERE included = TRUE`
            );
        } else {
            memberQuery = await pool.query(
                `SELECT user_id FROM di_glp_cohort_members WHERE cohort_id = $1 AND included = TRUE`,
                [cohortId]
            );
        }

        const memberIds = memberQuery.rows.map(r => r.user_id).sort();
        if (memberIds.length === 0) return res.status(400).json({ error: 'No included members in cohort' });

        const membershipHash = crypto.createHash('sha256')
            .update(cohortId + ':' + memberIds.join(','))
            .digest('hex').slice(0, 16);

        // For each member, ensure individual snapshot exists, then load it
        const snapshots = [];
        for (const userId of memberIds) {
            // Check if individual snapshot exists for this week
            const idx = await pool.query(
                'SELECT r2_snapshot_key FROM glp_weekly_status_index WHERE user_id = $1 AND iso_week = $2',
                [userId, isoWeek]
            );

            let snapshot;
            if (idx.rows.length > 0) {
                try {
                    snapshot = await downloadR2Json(idx.rows[0].r2_snapshot_key);
                } catch (e) {
                    console.warn(`[GLP-GROUP] Failed to download snapshot for ${userId} week ${isoWeek}:`, e.message);
                    continue;
                }
            } else {
                // Generate individual snapshot
                const userRow = await pool.query(
                    'SELECT affiliation FROM di_allowlist WHERE researcher_id = $1 AND active = true',
                    [userId]
                );
                if (userRow.rows.length === 0) continue;

                const affiliation = userRow.rows[0].affiliation;
                const { snapshot: s, hash } = await buildGlpSnapshot(userId);
                const keys = glpR2Keys(affiliation, userId, isoWeek);
                await uploadToR2(Buffer.from(JSON.stringify(s, null, 2)), keys.snapshot, 'application/json');
                await pool.query(`
                    INSERT INTO glp_weekly_status_index
                        (user_id, iso_week, generated_at, r2_snapshot_key, evidence_hash, snapshot_version, model_version)
                    VALUES ($1, $2, NOW(), $3, $4, $5, $6)
                    ON CONFLICT (user_id, iso_week) DO NOTHING
                `, [userId, isoWeek, keys.snapshot, hash, 1, '1.0.0']);
                snapshot = s;
            }
            snapshots.push(snapshot);
        }

        if (snapshots.length === 0) return res.status(400).json({ error: 'No snapshots could be loaded' });

        // Aggregate using median
        function median(arr) {
            if (arr.length === 0) return 0;
            const sorted = [...arr].sort((a, b) => a - b);
            const mid = Math.floor(sorted.length / 2);
            return sorted.length % 2 !== 0 ? sorted[mid] : Math.round((sorted[mid - 1] + sorted[mid]) / 2);
        }

        const overallScores = snapshots.map(s => s.overall_score || 0);
        const docScores = snapshots.map(s => s.spheres?.documentation?.score || 0);
        const trainScores = snapshots.map(s => s.spheres?.training?.score || 0);
        const traceScores = snapshots.map(s => s.spheres?.traceability?.score || 0);
        const dataScores = snapshots.map(s => s.spheres?.data_integrity?.score || 0);

        const aggOverall = median(overallScores);
        const aggLevel = resolveGlpLevel(aggOverall);

        // Sum evidence counts
        const sumEvidence = {
            sops: { total: 0, approved: 0 },
            data: { total: 0 },
            presentations: { total: 0, approved: 0 },
            inventory: { total: 0, products: 0, samples: 0, oligos: 0 },
            training: { certifiedEntries: 0 }
        };
        for (const s of snapshots) {
            const ev = s.evidence || {};
            if (ev.sops) { sumEvidence.sops.total += (ev.sops.total || 0); sumEvidence.sops.approved += (ev.sops.approved || 0); }
            if (ev.data) { sumEvidence.data.total += (ev.data.total || 0); }
            if (ev.presentations) { sumEvidence.presentations.total += (ev.presentations.total || 0); sumEvidence.presentations.approved += (ev.presentations.approved || 0); }
            if (ev.inventory) {
                sumEvidence.inventory.total += (ev.inventory.total || 0);
                sumEvidence.inventory.products += (ev.inventory.products || 0);
                sumEvidence.inventory.samples += (ev.inventory.samples || 0);
                sumEvidence.inventory.oligos += (ev.inventory.oligos || 0);
            }
            if (ev.training) { sumEvidence.training.certifiedEntries += (ev.training.certifiedEntries || 0); }
        }

        // Conformity: use conservative (min) for boolean flags
        const conformity = {};
        const confKeys = ['training_sealed', 'all_agreements_confirmed', 'has_approved_sops', 'inventory_active',
                          'no_open_revisions', 'sop_coverage_adequate', 'data_coverage_adequate', 'recent_activity'];
        for (const k of confKeys) {
            const vals = snapshots.map(s => s.conformity?.[k]).filter(v => v !== undefined);
            conformity[k] = vals.length > 0 ? vals.every(v => v === true) : false;
        }

        const groupSnapshot = {
            schema_version: 1,
            model_version: '1.0.0',
            scoring_version: '1.0.0',
            entity_type: 'group',
            cohort_id: cohortId,
            iso_week: isoWeek,
            generated_at: new Date().toISOString(),
            member_count: snapshots.length,
            membership_hash: membershipHash,
            overall_score: aggOverall,
            glp_level: aggLevel,
            spheres: {
                documentation: { score: median(docScores) },
                training: { score: median(trainScores) },
                traceability: { score: median(traceScores) },
                data_integrity: { score: median(dataScores) }
            },
            evidence: sumEvidence,
            conformity
        };

        // Store in R2
        const year = isoWeek.slice(0, 4);
        const wPart = isoWeek.slice(4);
        const r2Key = `glp-status/weekly/GROUP/${cohortId}/${year}/${wPart}/snapshot.json`;
        await uploadToR2(Buffer.from(JSON.stringify(groupSnapshot, null, 2)), r2Key, 'application/json');

        // Upsert index row
        await pool.query(`
            INSERT INTO glp_group_weekly_status_index (cohort_id, iso_week, r2_snapshot_key, member_count, membership_hash)
            VALUES ($1, $2, $3, $4, $5)
            ON CONFLICT (cohort_id, iso_week) DO UPDATE
            SET r2_snapshot_key = $3, member_count = $4, membership_hash = $5, created_at = NOW()
        `, [cohortId, isoWeek, r2Key, snapshots.length, membershipHash]);

        console.log(`[GLP-GROUP] Generated group snapshot for ${cohortId} week ${isoWeek}, members=${snapshots.length}, score=${aggOverall}`);

        res.json({
            success: true,
            generated: true,
            cohort_id: cohortId,
            iso_week: isoWeek,
            member_count: snapshots.length,
            r2_snapshot_key: r2Key
        });
    } catch (err) {
        console.error('[GLP-GROUP] generate error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// List group weeks — PI only
app.get('/api/glp/status/group/weeks', requirePI, async (req, res) => {
    try {
        if (!(await checkGroupIndexTable())) return res.json({ success: true, weeks: [] });

        const cohortId = (req.query.cohort_id || 'BOTH').toUpperCase();
        if (!['LIU', 'UNAV', 'BOTH'].includes(cohortId)) return res.status(400).json({ error: 'Invalid cohort_id' });

        const result = await pool.query(
            `SELECT iso_week, member_count, membership_hash, created_at
             FROM glp_group_weekly_status_index
             WHERE cohort_id = $1
             ORDER BY iso_week DESC
             LIMIT 52`,
            [cohortId]
        );
        res.json({ success: true, cohort_id: cohortId, weeks: result.rows });
    } catch (err) {
        console.error('[GLP-GROUP] weeks error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// Fetch group snapshot — PI only
app.get('/api/glp/status/group/snapshot', requirePI, async (req, res) => {
    try {
        if (!(await checkGroupIndexTable())) return res.status(404).json({ error: 'No data available' });

        const cohortId = (req.query.cohort_id || '').toUpperCase();
        const isoWeek = req.query.iso_week || '';
        if (!cohortId || !isoWeek) return res.status(400).json({ error: 'cohort_id and iso_week required' });

        const idx = await pool.query(
            'SELECT * FROM glp_group_weekly_status_index WHERE cohort_id = $1 AND iso_week = $2',
            [cohortId, isoWeek]
        );
        if (idx.rows.length === 0) return res.status(404).json({ error: 'Group snapshot not found' });

        const row = idx.rows[0];
        const snapshot = await downloadR2Json(row.r2_snapshot_key);

        res.json({
            success: true,
            cohort_id: cohortId,
            iso_week: row.iso_week,
            created_at: row.created_at,
            member_count: row.member_count,
            membership_hash: row.membership_hash,
            snapshot
        });
    } catch (err) {
        console.error('[GLP-GROUP] snapshot error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// PI-only: fetch weeks list for a specific user (for viewing other members' GLP status)
app.get('/api/glp/status/user/:userId/weeks', requirePI, async (req, res) => {
    try {
        if (!(await checkGlpStatusTable())) return res.json({ success: true, weeks: [] });

        const userId = req.params.userId;
        const result = await pool.query(
            `SELECT iso_week, generated_at, r2_harmony_key IS NOT NULL AS has_harmony
             FROM glp_weekly_status_index
             WHERE user_id = $1
             ORDER BY iso_week DESC
             LIMIT 52`,
            [userId]
        );
        res.json({ success: true, weeks: result.rows });
    } catch (err) {
        console.error('[GLP-STATUS] user weeks error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// PI-only: fetch snapshot for a specific user and week
app.get('/api/glp/status/user/:userId/week/:isoWeek', requirePI, async (req, res) => {
    try {
        if (!(await checkGlpStatusTable())) return res.status(404).json({ error: 'No data available' });

        const idx = await pool.query(
            'SELECT * FROM glp_weekly_status_index WHERE user_id = $1 AND iso_week = $2',
            [req.params.userId, req.params.isoWeek]
        );
        if (idx.rows.length === 0) return res.status(404).json({ error: 'Week not found' });

        const row = idx.rows[0];
        const snapshot = await downloadR2Json(row.r2_snapshot_key);

        let harmony = null;
        if (row.r2_harmony_key) {
            try { harmony = await downloadR2Json(row.r2_harmony_key); } catch (e) { /* swallow */ }
        }

        res.json({
            success: true,
            iso_week: row.iso_week,
            generated_at: row.generated_at,
            evidence_hash: row.evidence_hash,
            snapshot,
            harmony
        });
    } catch (err) {
        console.error('[GLP-STATUS] user week error:', err);
        res.status(500).json({ error: 'Server error' });
    }
});

// =====================================================
// INTERNAL DOCUMENTS — PI only, R2 storage
// =====================================================

const INTDOC_CATEGORIES = { papers: 'papers', projects: 'projects', grants: 'grants', collaborators: 'collaborators', other: 'other' };
const INTDOC_PREFIX = 'group-docs/internal/';
const INTDOC_TRASH = 'group-docs/internal/trash/';

function normalizeFolderName(name) {
  if (!name || typeof name !== 'string') return '';
  let n = name.trim();
  n = n.replace(/\s+/g, '_');
  n = n.replace(/[\/\\]/g, '');
  n = n.replace(/\.\./g, '');
  n = n.replace(/^\./g, '');
  n = n.substring(0, 60);
  return n;
}

async function listR2Prefix(prefix) {
  const s3 = getR2Client();
  const bucket = process.env.R2_BUCKET;
  const objects = [];
  let token;
  do {
    const resp = await s3.send(new ListObjectsV2Command({
      Bucket: bucket, Prefix: prefix, ContinuationToken: token
    }));
    if (resp.Contents) objects.push(...resp.Contents);
    token = resp.NextContinuationToken;
  } while (token);
  return objects;
}

// 1. GET /api/internal-docs/tree
app.get('/api/internal-docs/tree', requirePI, async (req, res) => {
  try {
    const tree = {};
    for (const [cat, slug] of Object.entries(INTDOC_CATEGORIES)) {
      const prefix = INTDOC_PREFIX + slug + '/';
      const objects = await listR2Prefix(prefix);

      if (cat === 'papers') {
        const files = objects.filter(o => !o.Key.endsWith('/.keep') && o.Key.substring(prefix.length).indexOf('/') === -1);
        tree[cat] = { count: files.length, folders: [] };
      } else {
        const folders = {};
        for (const obj of objects) {
          const relative = obj.Key.substring(prefix.length);
          const parts = relative.split('/');
          if (parts.length >= 2 && parts[0]) {
            const folder = parts[0];
            if (!folders[folder]) folders[folder] = 0;
            if (parts[1] !== '.keep' && parts[1]) folders[folder]++;
          }
        }
        const fileCount = Object.values(folders).reduce((a, b) => a + b, 0);
        tree[cat] = {
          count: fileCount,
          folders: Object.entries(folders).map(([name, count]) => ({ name, count })).sort((a, b) => a.name.localeCompare(b.name))
        };
      }
    }
    res.json({ success: true, tree });
  } catch (err) {
    console.error('[INTERNAL-DOCS] tree error:', err);
    res.status(500).json({ error: 'Failed to load document tree' });
  }
});

// 2. GET /api/internal-docs/list
app.get('/api/internal-docs/list', requirePI, async (req, res) => {
  try {
    const { category, folder } = req.query;
    if (!category) return res.status(400).json({ error: 'Category required' });

    if (category === 'all') {
      const objects = await listR2Prefix(INTDOC_PREFIX);
      const validSlugs = Object.values(INTDOC_CATEGORIES);
      const files = objects
        .filter(o => !o.Key.endsWith('/.keep') && !o.Key.startsWith(INTDOC_TRASH))
        .map(o => {
          const relative = o.Key.substring(INTDOC_PREFIX.length);
          const parts = relative.split('/');
          const catSlug = parts[0] || '';
          if (!validSlugs.includes(catSlug)) return null;
          const folderName = parts.length > 2 ? parts[1] : '';
          return { key: o.Key, name: parts[parts.length - 1], category: catSlug, folder: folderName, size: o.Size, last_modified: o.LastModified };
        })
        .filter(Boolean);
      return res.json({ success: true, files });
    }

    if (!INTDOC_CATEGORIES[category]) return res.status(400).json({ error: 'Invalid category' });
    if (category !== 'papers' && !folder) return res.status(400).json({ error: 'Folder required for this category' });

    let prefix;
    if (category === 'papers') {
      prefix = INTDOC_PREFIX + 'papers/';
    } else {
      prefix = INTDOC_PREFIX + INTDOC_CATEGORIES[category] + '/' + folder + '/';
    }

    const objects = await listR2Prefix(prefix);
    const files = objects
      .filter(o => !o.Key.endsWith('/.keep'))
      .filter(o => {
        const relative = o.Key.substring(prefix.length);
        return relative && !relative.includes('/');
      })
      .map(o => ({ key: o.Key, name: o.Key.split('/').pop(), size: o.Size, last_modified: o.LastModified }));

    res.json({ success: true, files });
  } catch (err) {
    console.error('[INTERNAL-DOCS] list error:', err);
    res.status(500).json({ error: 'Failed to list documents' });
  }
});

// 3. POST /api/internal-docs/create-folder
app.post('/api/internal-docs/create-folder', requirePI, async (req, res) => {
  try {
    const { category, folder } = req.body;
    if (!category || !INTDOC_CATEGORIES[category]) return res.status(400).json({ error: 'Invalid category' });
    if (category === 'papers') return res.status(400).json({ error: 'Papers does not support subfolders' });

    const normalized = normalizeFolderName(folder);
    if (!normalized) return res.status(400).json({ error: 'Invalid folder name' });

    const key = INTDOC_PREFIX + INTDOC_CATEGORIES[category] + '/' + normalized + '/.keep';
    await uploadToR2(Buffer.from(''), key, 'application/x-empty');
    res.json({ success: true, folder: normalized });
  } catch (err) {
    console.error('[INTERNAL-DOCS] create-folder error:', err);
    res.status(500).json({ error: 'Failed to create folder' });
  }
});

// 4. POST /api/internal-docs/upload
app.post('/api/internal-docs/upload', requirePI, upload.array('files', 20), async (req, res) => {
  try {
    const { category, folder } = req.body;
    if (!category || !INTDOC_CATEGORIES[category]) return res.status(400).json({ error: 'Invalid category' });
    if (category !== 'papers' && !folder) return res.status(400).json({ error: 'Folder required for this category' });
    if (!req.files || req.files.length === 0) return res.status(400).json({ error: 'No files provided' });

    for (const file of req.files) {
      if (!file.originalname.toLowerCase().endsWith('.pdf')) {
        return res.status(400).json({ error: `File "${file.originalname}" is not a PDF` });
      }
    }

    let prefix;
    if (category === 'papers') {
      prefix = INTDOC_PREFIX + 'papers/';
    } else {
      const normalized = normalizeFolderName(folder);
      if (!normalized) return res.status(400).json({ error: 'Invalid folder name' });
      prefix = INTDOC_PREFIX + INTDOC_CATEGORIES[category] + '/' + normalized + '/';
    }

    const uploaded = [];
    for (const file of req.files) {
      const safeName = file.originalname.replace(/[^\w.\-]+/g, '_');
      const key = prefix + safeName;
      await uploadToR2(file.buffer, key, 'application/pdf');
      uploaded.push({ key, name: safeName });
    }

    res.json({ success: true, uploaded });
  } catch (err) {
    console.error('[INTERNAL-DOCS] upload error:', err);
    res.status(500).json({ error: 'Failed to upload documents' });
  }
});

// 5. POST /api/internal-docs/delete (move to trash)
app.post('/api/internal-docs/delete', requirePI, async (req, res) => {
  try {
    const { key } = req.body;
    if (!key || !key.startsWith(INTDOC_PREFIX) || key.startsWith(INTDOC_TRASH)) {
      return res.status(400).json({ error: 'Invalid key' });
    }

    const s3 = getR2Client();
    const bucket = process.env.R2_BUCKET;
    const now = new Date();
    const datePart = `${now.getFullYear()}_${String(now.getMonth() + 1).padStart(2, '0')}_${String(now.getDate()).padStart(2, '0')}`;
    const trashKey = INTDOC_TRASH + datePart + '/' + key;

    await s3.send(new CopyObjectCommand({
      Bucket: bucket, CopySource: `${bucket}/${key}`, Key: trashKey
    }));
    await deleteFromR2(key);

    res.json({ success: true, trash_key: trashKey, original_key: key });
  } catch (err) {
    console.error('[INTERNAL-DOCS] delete error:', err);
    res.status(500).json({ error: 'Failed to delete document' });
  }
});

// 6. POST /api/internal-docs/restore
app.post('/api/internal-docs/restore', requirePI, async (req, res) => {
  try {
    const { trash_key, original_key } = req.body;
    if (!trash_key || !trash_key.startsWith(INTDOC_TRASH)) return res.status(400).json({ error: 'Invalid trash key' });
    if (!original_key || !original_key.startsWith(INTDOC_PREFIX)) return res.status(400).json({ error: 'Invalid original key' });

    const s3 = getR2Client();
    const bucket = process.env.R2_BUCKET;

    await s3.send(new CopyObjectCommand({
      Bucket: bucket, CopySource: `${bucket}/${trash_key}`, Key: original_key
    }));
    await deleteFromR2(trash_key);

    res.json({ success: true });
  } catch (err) {
    console.error('[INTERNAL-DOCS] restore error:', err);
    res.status(500).json({ error: 'Failed to restore document' });
  }
});

// 7. GET /api/internal-docs/open  (PI session OR token)
app.get('/api/internal-docs/open', (req, res, next) => {
  const { token, key } = req.query;
  if (token && key) {
    const expected = Buffer.from(key + '_glp_2024_sec').toString('base64').replace(/[^a-zA-Z0-9]/g, '').substring(0, 32);
    if (token === expected) return next();
  }
  requirePI(req, res, next);
}, async (req, res) => {
  try {
    const { key } = req.query;
    if (!key || !key.startsWith(INTDOC_PREFIX)) return res.status(400).json({ error: 'Invalid key' });

    const obj = await downloadFromR2(key);
    res.setHeader('Content-Type', 'application/pdf');
    const filename = key.split('/').pop() || 'document.pdf';
    res.setHeader('Content-Disposition', `inline; filename="${filename}"`);
    if (obj.ContentLength) res.setHeader('Content-Length', String(obj.ContentLength));

    if (obj.Body.pipe) { obj.Body.pipe(res); }
    else { res.send(Buffer.from(await obj.Body.transformToByteArray())); }
  } catch (err) {
    console.error('[INTERNAL-DOCS] open error:', err);
    res.status(500).json({ error: 'Failed to open document' });
  }
});
  // 7b. GET /api/internal-docs/openb64/:k/:token  (PI session OR token)
  // k is base64url-encoded internal-docs key, token is derived from key
  app.get('/api/internal-docs/openb64/:k/:token', (req, res, next) => {
    const token = req.params.token || '';
    let key = '';
    try {
      const b64 = (req.params.k || '').replace(/-/g, '+').replace(/_/g, '/');
      const padded = b64 + '==='.slice((b64.length + 3) % 4);
      key = Buffer.from(padded, 'base64').toString('utf8');
    } catch (e) {}

      // Pass decoded key to handler for both token and PI session paths
      req.query.key = key;

    if (token && key) {
      const expected = Buffer.from(key + '_glp_2024_sec').toString('base64').replace(/[^a-zA-Z0-9]/g, '').substring(0, 32);
      if (token === expected) {
          return next();
      }
    }
    requirePI(req, res, next);
  }, async (req, res) => {
    try {
      const key = req.query.key;
      if (!key || !key.startsWith(INTDOC_PREFIX)) return res.status(400).json({ error: 'Invalid key' });

      const obj = await downloadFromR2(key);
      res.setHeader('Content-Type', 'application/pdf');
      const filename = key.split('/').pop() || 'document.pdf';
      res.setHeader('Content-Disposition', `inline; filename="${filename}"`);
      if (obj.ContentLength) res.setHeader('Content-Length', String(obj.ContentLength));

      if (obj.Body.pipe) { obj.Body.pipe(res); }
      else { res.send(Buffer.from(await obj.Body.transformToByteArray())); }
    } catch (err) {
      console.error('[INTERNAL-DOCS] openb64 error:', err);
      res.status(500).json({ error: 'Failed to open document' });
    }
  });



// 8. GET /api/internal-docs/trash
app.get('/api/internal-docs/trash', requirePI, async (req, res) => {
  try {
    const objects = await listR2Prefix(INTDOC_TRASH);
    const items = objects
      .filter(o => !o.Key.endsWith('/.keep'))
      .sort((a, b) => (b.LastModified || 0) - (a.LastModified || 0))
      .slice(0, 50)
      .map(o => {
        const afterTrash = o.Key.substring(INTDOC_TRASH.length);
        const slashIdx = afterTrash.indexOf('/');
        const original_key = slashIdx >= 0 ? afterTrash.substring(slashIdx + 1) : afterTrash;
        return { trash_key: o.Key, original_key, name: o.Key.split('/').pop(), size: o.Size, deleted_at: o.LastModified };
      });

    res.json({ success: true, items });
  } catch (err) {
    console.error('[INTERNAL-DOCS] trash list error:', err);
    res.status(500).json({ error: 'Failed to list trash' });
  }
});

// 9. POST /api/internal-docs/delete-folder
app.post('/api/internal-docs/delete-folder', requirePI, async (req, res) => {
  try {
    const { category, folder, force } = req.body;
    if (!category || !INTDOC_CATEGORIES[category] || category === 'papers') {
      return res.status(400).json({ error: 'Invalid category' });
    }
    const normalized = normalizeFolderName(folder);
    if (!normalized) return res.status(400).json({ error: 'Invalid folder name' });

    const prefix = INTDOC_PREFIX + INTDOC_CATEGORIES[category] + '/' + normalized + '/';
    const objects = await listR2Prefix(prefix);
    const files = objects.filter(o => !o.Key.endsWith('/.keep'));

    if (files.length > 0 && !force) {
      return res.status(409).json({ error: 'Folder not empty', file_count: files.length, requires_force: true });
    }

    if (files.length > 0) {
      const s3 = getR2Client();
      const bucket = process.env.R2_BUCKET;
      const now = new Date();
      const datePart = `${now.getFullYear()}_${String(now.getMonth() + 1).padStart(2, '0')}_${String(now.getDate()).padStart(2, '0')}`;

      for (const obj of files) {
        const trashKey = INTDOC_TRASH + datePart + '/' + obj.Key;
        await s3.send(new CopyObjectCommand({
          Bucket: bucket, CopySource: `${bucket}/${obj.Key}`, Key: trashKey
        }));
        await deleteFromR2(obj.Key);
      }
    }

    for (const obj of objects.filter(o => o.Key.endsWith('/.keep'))) {
      await deleteFromR2(obj.Key);
    }

    res.json({ success: true, files_trashed: files.length });
  } catch (err) {
    console.error('[INTERNAL-DOCS] delete-folder error:', err);
    res.status(500).json({ error: 'Failed to delete folder' });
  }
});

//
// Server start
//
app.listen(PORT, "0.0.0.0", () => console.log("[STARTUP] Server listening on port " + PORT));















