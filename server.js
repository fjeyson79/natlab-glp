"use strict";

/*
  NATLAB-GLP Server (R2-only)
  - Storage: Cloudflare R2 via AWS SDK S3 client
  - DB: PostgreSQL (Railway) via DATABASE_URL
  - Auth: express-session (MemoryStore; OK for now, not for multi-instance scaling)
  - Portal: serves /di/*.html static files
*/

require("dotenv").config();

const path = require("path");
const express = require("express");
const session = require("express-session");
const multer = require("multer");
const { Pool } = require("pg");
const crypto = require("crypto");

const { S3Client, PutObjectCommand, GetObjectCommand, DeleteObjectCommand } = require("@aws-sdk/client-s3");

const app = express();


app.use(express.json({ limit: "10mb" }));
app.use(express.urlencoded({ extended: true, limit: "10mb" }));

// Return clean 400 on invalid JSON instead of crashing the request pipeline
app.use((err, req, res, next) => {
  if (err && err.type === "entity.parse.failed") {
    return res.status(400).json({ error: "Invalid JSON" });
  }
  return next(err);
});
/* -----------------------------
   Basic config
----------------------------- */

const PORT = process.env.PORT || 8080;

app.set("trust proxy", 1); // Railway/proxy


/* -----------------------------
   Sessions
----------------------------- */

const SESSION_SECRET = process.env.SESSION_SECRET || "dev-secret-change-me";

app.use(
  session({
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: process.env.RAILWAY === "production" || process.env.NODE_ENV === "production",
      maxAge: 1000 * 60 * 60 * 12
    }
  })
);

/* -----------------------------
   Static portal
----------------------------- */

app.use("/di", express.static(path.join(__dirname, "public")));/* -----------------------------
   DB
----------------------------- */

if (!process.env.DATABASE_URL) {
  console.error("[STARTUP] ERROR: DATABASE_URL is missing.");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.PGSSLMODE === "disable" ? false : { rejectUnauthorized: false }
});

/* -----------------------------
   R2
----------------------------- */

function r2Enabled() {
  return !!(process.env.R2_ACCESS_KEY_ID &&
    process.env.R2_SECRET_ACCESS_KEY &&
    process.env.R2_ENDPOINT &&
    process.env.R2_BUCKET);
}

let _r2Client = null;

function getR2Client() {
  if (_r2Client) return _r2Client;

  _r2Client = new S3Client({
    region: "auto",
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
    ContentType: contentType || "application/octet-stream"
  }));
  return true;
}

async function downloadFromR2(key) {
  const s3 = getR2Client();
  return await s3.send(new GetObjectCommand({
    Bucket: process.env.R2_BUCKET,
    Key: key
  }));
}

async function deleteFromR2(key) {
  const s3 = getR2Client();
  return await s3.send(new DeleteObjectCommand({
    Bucket: process.env.R2_BUCKET,
    Key: key
  }));
}

/* -----------------------------
   Upload middleware
----------------------------- */

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 10 * 1024 * 1024 } // 10MB
});

/* -----------------------------
   Auth helpers
----------------------------- */

function requireAuth(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ error: "NOT_AUTHENTICATED" });
  }
  next();
}

function requirePI(req, res, next) {
  if (!req.session || !req.session.user) {
    return res.status(401).json({ error: "NOT_AUTHENTICATED" });
  }
  const role = (req.session.user.role || "").toUpperCase();
  if (role !== "PI" && role !== "ADMIN") {
    return res.status(403).json({ error: "FORBIDDEN" });
  }
  next();
}

/* -----------------------------
   Utilities
----------------------------- */

function sanitizeFilename(name) {
  return (name || "upload.pdf").replace(/[^\w.\-]+/g, "_");
}

function nowYear() {
  return new Date().getFullYear();
}

function requirePdf(file) {
  if (!file) return "No file uploaded. Only PDF files are accepted.";
  if (file.mimetype !== "application/pdf") return "Only PDF files are accepted";
  return null;
}

async function getAllowlistByEmail(email) {
  // Expected columns (based on your logs and schema usage):
  // di_allowlist: researcher_id, affiliation, email, active, role (optional)
  const q = `
    SELECT researcher_id, affiliation,
           COALESCE(role, 'USER') AS role,
           institution_email AS email, active
    FROM di_allowlist
    WHERE lower(institution_email) = lower($1) AND active = true
    LIMIT 1
  `;
  const r = await pool.query(q, [email]);
  return r.rows[0] || null;
}

async function getAllowlistByResearcherId(researcherId) {
  const q = `
    SELECT researcher_id, affiliation,
           COALESCE(role, 'USER') AS role,
           institution_email AS email, active
    FROM di_allowlist
    WHERE researcher_id = $1 AND active = true
    LIMIT 1
  `;
  const r = await pool.query(q, [researcherId]);
  return r.rows[0] || null;
}

/* -----------------------------
   Health
----------------------------- */

app.get("/api/health", async (req, res) => {
  res.json({
    ok: true,
    r2Enabled: r2Enabled(),
    hasDatabaseUrl: !!process.env.DATABASE_URL,
    env: {
      RAILWAY: process.env.RAILWAY,
      NODE_ENV: process.env.NODE_ENV
    }
  });
});

/* -----------------------------
   Auth endpoints used by portal
----------------------------- */

// POST /api/di/access-check { email }
app.post("/api/di/access-check", async (req, res) => {
  try {
    const email = (req.body.email || "").trim();
    if (!email) return res.status(400).json({ error: "email is required" });

    const row = await getAllowlistByEmail(email);
    if (!row) return res.status(403).json({ allowed: false });

    return res.json({ allowed: true });
  } catch (e) {
    console.error("[ACCESS-CHECK] error:", e.message);
    return res.status(500).json({ error: "Server error" });
  }
});

// POST /api/di/login { email }
app.post("/api/di/login", async (req, res) => {
  try {
    const email = (req.body.email || "").trim();
    if (!email) return res.status(400).json({ error: "email is required" });

    const row = await getAllowlistByEmail(email);
    if (!row) return res.status(403).json({ error: "NOT_ALLOWED" });

    req.session.user = {
      researcher_id: row.researcher_id,
      affiliation: row.affiliation,
      email: row.email,
      role: row.role
    };

    return res.json({ success: true, user: req.session.user });
  } catch (e) {
    console.error("[LOGIN] error:", e.message);
    return res.status(500).json({ error: "Server error" });
  }
});

// POST /api/di/logout
app.post("/api/di/logout", (req, res) => {
  req.session.destroy(() => {
    res.json({ success: true });
  });
});

// GET /api/di/me
app.get("/api/di/me", requireAuth, (req, res) => {
  res.json({ user: req.session.user });
});

/* -----------------------------
   Members / directory
----------------------------- */

// GET /api/di/members
app.get("/api/di/members", requireAuth, async (req, res) => {
  try {
    // Return active allowlist rows. Include role if present.
    const q = `
      SELECT researcher_id, affiliation, institution_email AS email, active,
             COALESCE(role, 'USER') AS role
      FROM di_allowlist
      WHERE active = true
      ORDER BY researcher_id
    `;
    const r = await pool.query(q);
    res.json({ members: r.rows });
  } catch (e) {
    console.error("[MEMBERS] error:", e.message);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/di/directory
// Returns tree structure for PI dashboard
app.get("/api/di/directory", requirePI, async (req, res) => {
  try {
    // Get all members
    const membersResult = await pool.query(
      `SELECT researcher_id, affiliation, institution_email AS email,
              COALESCE(role, 'USER') AS role
       FROM di_allowlist WHERE active = true ORDER BY researcher_id`
    );

    // Get all submissions
    const submissionsResult = await pool.query(
      `SELECT submission_id, researcher_id, affiliation, file_type, original_filename,
              status, created_at, r2_object_key, signed_pdf_path,
              EXTRACT(YEAR FROM created_at) as year
       FROM di_submissions
       ORDER BY created_at DESC`
    );

    // Build tree: General Lab / Year / Researcher
    const tree = { name: "General Lab", type: "folder", children: [] };
    const yearMap = {};

    for (const sub of submissionsResult.rows) {
      const year = sub.year || new Date(sub.created_at).getFullYear();
      const researcherName = sub.researcher_id;

      if (!yearMap[year]) {
        yearMap[year] = { name: String(year), type: "folder", children: [], researchers: {} };
      }

      if (!yearMap[year].researchers[sub.researcher_id]) {
        yearMap[year].researchers[sub.researcher_id] = {
          name: researcherName,
          type: "folder",
          children: [],
          count: 0
        };
      }

      yearMap[year].researchers[sub.researcher_id].children.push({
        name: sub.original_filename,
        type: "file",
        id: sub.submission_id,
        status: sub.status,
        fileType: sub.file_type,
        date: sub.created_at,
        r2ObjectKey: sub.r2_object_key || sub.signed_pdf_path,
        viewUrl: `/api/di/submissions/${sub.submission_id}/file`,
        downloadUrl: `/api/di/submissions/${sub.submission_id}/file?download=true`
      });
      yearMap[year].researchers[sub.researcher_id].count++;
    }

    const years = Object.keys(yearMap).sort((a, b) => b - a);
    for (const year of years) {
      const yearNode = yearMap[year];
      yearNode.children = Object.values(yearNode.researchers);
      yearNode.count = `${yearNode.children.length} researchers`;
      delete yearNode.researchers;
      tree.children.push(yearNode);
    }

    const currentYear = new Date().getFullYear();
    if (!yearMap[currentYear]) {
      tree.children.unshift({
        name: String(currentYear),
        type: "folder",
        children: membersResult.rows.map(m => ({
          name: m.researcher_id,
          type: "folder",
          children: [],
          count: 0
        })),
        count: `${membersResult.rows.length} researchers`
      });
    }

    res.json({ success: true, tree: tree });
  } catch (e) {
    console.error("[DIRECTORY] error:", e.message);
    res.status(500).json({ error: "Server error" });
  }
});

// GET /api/di/my-files
// Returns researcher's files as tree structure for upload.html
app.get("/api/di/my-files", requireAuth, async (req, res) => {
  try {
    const user = req.session.user;

    const result = await pool.query(
      `SELECT submission_id, file_type, original_filename, status, created_at, signed_at,
              verification_code, r2_object_key, signed_pdf_path,
              EXTRACT(YEAR FROM created_at) as year
       FROM di_submissions
       WHERE researcher_id = $1
       ORDER BY created_at DESC`,
      [user.researcher_id]
    );

    // Build tree structure: My Files / Year / Submitted|Approved
    const tree = { name: "My Files", type: "folder", children: [] };
    const yearMap = {};
    let pendingCount = 0, approvedCount = 0, revisionCount = 0;

    for (const file of result.rows) {
      const year = file.year || new Date(file.created_at).getFullYear();
      const status = file.status || "PENDING";

      if (!yearMap[year]) {
        yearMap[year] = {
          name: String(year),
          type: "folder",
          children: [
            { name: "Submitted", type: "folder", children: [], count: 0 },
            { name: "Approved", type: "folder", children: [], count: 0 }
          ]
        };
      }

      const fileNode = {
        name: file.original_filename,
        type: "file",
        id: file.submission_id,
        status: status,
        fileType: file.file_type,
        date: file.created_at,
        signedAt: file.signed_at,
        verificationCode: file.verification_code,
        r2ObjectKey: file.r2_object_key || file.signed_pdf_path,
        viewUrl: `/api/di/submissions/${file.submission_id}/file`,
        downloadUrl: `/api/di/submissions/${file.submission_id}/file?download=true`
      };

      if (status === "APPROVED") {
        yearMap[year].children[1].children.push(fileNode);
        yearMap[year].children[1].count++;
        approvedCount++;
      } else if (status === "PENDING") {
        yearMap[year].children[0].children.push(fileNode);
        yearMap[year].children[0].count++;
        pendingCount++;
      } else if (status === "REVISION_NEEDED") {
        revisionCount++;
      }
    }

    const years = Object.keys(yearMap).sort((a, b) => b - a);
    for (const year of years) {
      const yearNode = yearMap[year];
      yearNode.children[0].name = `Submitted (${yearNode.children[0].count})`;
      yearNode.children[1].name = `Approved (${yearNode.children[1].count})`;
      tree.children.push(yearNode);
    }

    const currentYear = new Date().getFullYear();
    if (!yearMap[currentYear]) {
      tree.children.unshift({
        name: String(currentYear),
        type: "folder",
        children: [
          { name: "Submitted (0)", type: "folder", children: [], count: 0 },
          { name: "Approved (0)", type: "folder", children: [], count: 0 }
        ]
      });
    }

    res.json({
      success: true,
      tree: tree,
      totalFiles: result.rows.length,
      pendingCount,
      approvedCount,
      revisionCount
    });
  } catch (e) {
    console.error("[MY-FILES] error:", e.message);
    res.status(500).json({ error: "Server error" });
  }
});

/* -----------------------------
   Upload endpoints (R2 only)
----------------------------- */

// POST /api/di/upload (regular researcher upload)
app.post("/api/di/upload", requireAuth, upload.single("file"), async (req, res) => {
  try {
    if (!r2Enabled()) {
      return res.status(503).json({ error: "R2_NOT_CONFIGURED", message: "R2 is not configured on the server." });
    }

    const { fileType } = req.body;
    const file = req.file;

    if (!fileType || !["SOP", "DATA"].includes(fileType)) {
      return res.status(400).json({ error: "fileType must be SOP or DATA" });
    }

    const pdfErr = requirePdf(file);
    if (pdfErr) return res.status(400).json({ error: pdfErr });

    const user = req.session.user;
    const year = nowYear();

    const safeOriginal = sanitizeFilename(file.originalname);
    const key = `di/${year}/${user.researcher_id}/Submitted/${Date.now()}-${safeOriginal}`;

    console.log(`[UPLOAD] R2 put: ${key}`);
    await uploadToR2(file.buffer, key, file.mimetype);

    const fileId = key;

    const ins = await pool.query(
      `INSERT INTO di_submissions (researcher_id, affiliation, file_type, original_filename, r2_object_key, status)
       VALUES ($1, $2, $3, $4, $5, 'PENDING')
       RETURNING submission_id`,
      [user.researcher_id, user.affiliation, fileType, file.originalname, fileId]
    );

    const submissionId = ins.rows[0].submission_id;

    // Optional webhook to n8n
    const webhookUrl = process.env.N8N_DI_WEBHOOK_URL;
    if (webhookUrl) {
      try {
        const form = new FormData();
        form.append("researcher_id", user.researcher_id);
        form.append("affiliation", user.affiliation);
        form.append("fileType", fileType);
        form.append("original_filename", file.originalname);
        form.append("submission_id", String(submissionId));
        form.append("r2_object_key", fileId);

        // file as Blob
        const blob = new Blob([file.buffer], { type: file.mimetype });
        form.append("file", blob, file.originalname);

        await fetch(webhookUrl, { method: "POST", body: form });
      } catch (we) {
        console.error("[UPLOAD] webhook error:", we.message);
      }
    }

    return res.json({
      success: true,
      submission_id: submissionId,
      r2_object_key: fileId,
      message: "File uploaded successfully"
    });

  } catch (e) {
    console.error("[UPLOAD] error:", e.message);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/di/pi-upload (PI upload on behalf of a researcher)
app.post("/api/di/pi-upload", requirePI, upload.single("file"), async (req, res) => {
  try {
    if (!r2Enabled()) {
      return res.status(503).json({ error: "R2_NOT_CONFIGURED", message: "R2 is not configured on the server." });
    }

    const { researcher_id, fileType } = req.body;
    const file = req.file;

    if (!researcher_id) return res.status(400).json({ error: "researcher_id is required" });
    if (!fileType || !["SOP", "DATA"].includes(fileType)) return res.status(400).json({ error: "fileType must be SOP or DATA" });

    const pdfErr = requirePdf(file);
    if (pdfErr) return res.status(400).json({ error: pdfErr });

    const researcher = await getAllowlistByResearcherId(researcher_id);
    if (!researcher) return res.status(404).json({ error: "Researcher not found" });

    const year = nowYear();
    const safeOriginal = sanitizeFilename(file.originalname);
    const key = `di/${year}/${researcher_id}/Submitted/${Date.now()}-${safeOriginal}`;

    // Create submission first
    const ins = await pool.query(
      `INSERT INTO di_submissions (researcher_id, affiliation, file_type, original_filename, status)
       VALUES ($1, $2, $3, $4, 'PENDING')
       RETURNING submission_id`,
      [researcher_id, researcher.affiliation, fileType, file.originalname]
    );

    const submissionId = ins.rows[0].submission_id;

    console.log(`[PI-UPLOAD] R2 put: ${key}`);
    await uploadToR2(file.buffer, key, file.mimetype);

    const fileId = key;

    await pool.query(
      `UPDATE di_submissions
       SET r2_object_key = $1, r2_error = NULL, r2_last_attempt = NOW()
       WHERE submission_id = $2`,
      [fileId, submissionId]
    );

    const webhookUrl = process.env.N8N_DI_WEBHOOK_URL;
    if (webhookUrl) {
      try {
        const form = new FormData();
        form.append("researcher_id", researcher_id);
        form.append("affiliation", researcher.affiliation);
        form.append("fileType", fileType);
        form.append("original_filename", file.originalname);
        form.append("submission_id", String(submissionId));
        form.append("r2_object_key", fileId);
        form.append("uploaded_by_pi", req.session.user.researcher_id);

        const blob = new Blob([file.buffer], { type: file.mimetype });
        form.append("file", blob, file.originalname);

        await fetch(webhookUrl, { method: "POST", body: form });
      } catch (we) {
        console.error("[PI-UPLOAD] webhook error:", we.message);
      }
    }

    return res.json({
      success: true,
      submission_id: submissionId,
      r2_object_key: fileId,
      message: "File uploaded successfully"
    });

  } catch (e) {
    console.error("[PI-UPLOAD] error:", e.message);
    res.status(500).json({ error: "Server error" });
  }
});

// POST /api/di/external-upload (n8n/system upload)
app.post("/api/di/external-upload", upload.single("file"), async (req, res) => {
  try {
    const apiKey = req.headers["x-api-key"];
    if (!apiKey || apiKey !== process.env.API_SECRET_KEY) {
      return res.status(401).json({ error: "Invalid or missing API key" });
    }

    if (!r2Enabled()) {
      return res.status(503).json({ error: "R2_NOT_CONFIGURED", message: "R2 is not configured on the server." });
    }

    const { researcher_id, affiliation, fileType } = req.body;
    const file = req.file;

    if (!researcher_id) return res.status(400).json({ error: "researcher_id is required" });
    if (!affiliation || !["LiU", "UNAV"].includes(affiliation)) return res.status(400).json({ error: "affiliation must be LiU or UNAV" });
    if (!fileType || !["SOP", "DATA"].includes(fileType)) return res.status(400).json({ error: "fileType must be SOP or DATA" });

    const pdfErr = requirePdf(file);
    if (pdfErr) return res.status(400).json({ error: pdfErr });

    const year = nowYear();
    const safeOriginal = sanitizeFilename(file.originalname);
    const key = `di/${year}/${researcher_id}/External/${Date.now()}-${safeOriginal}`;

    console.log(`[EXTERNAL-UPLOAD] R2 put: ${key}`);
    await uploadToR2(file.buffer, key, file.mimetype);

    const fileId = key;

    const ins = await pool.query(
      `INSERT INTO di_submissions (researcher_id, affiliation, file_type, original_filename, r2_object_key, status)
       VALUES ($1, $2, $3, $4, $5, 'PENDING')
       RETURNING submission_id`,
      [researcher_id, affiliation, fileType, file.originalname, fileId]
    );

    return res.json({ success: true, submission_id: ins.rows[0].submission_id, r2_object_key: fileId });
  } catch (e) {
    console.error("[EXTERNAL-UPLOAD] error:", e.message);
    res.status(500).json({ error: "Server error" });
  }
});

/* -----------------------------
   Download from R2 by submission id
----------------------------- */

// GET /api/di/submissions/:id/file?download=true|false
app.get("/api/di/submissions/:id/file", requireAuth, async (req, res) => {
  try {
    if (!r2Enabled()) {
      return res.status(503).json({ error: "R2_NOT_CONFIGURED", message: "R2 is not configured on the server." });
    }

    const id = req.params.id;
    const download = String(req.query.download || "false");

    const user = req.session.user;
    const role = (user.role || "").toUpperCase();
    const isPI = role === "PI" || role === "ADMIN";

    // Pull submission, enforce access
    const r = await pool.query(
      `SELECT submission_id, researcher_id, original_filename, r2_object_key, signed_pdf_path
       FROM di_submissions
       WHERE submission_id = $1
       LIMIT 1`,
      [id]
    );

    if (r.rows.length === 0) return res.status(404).json({ error: "NOT_FOUND" });

    const submission = r.rows[0];
    if (!isPI && submission.researcher_id !== user.researcher_id) {
      return res.status(403).json({ error: "FORBIDDEN" });
    }

    const key = submission.signed_pdf_path || submission.r2_object_key;
    if (!key) {
      return res.status(409).json({ error: "FILE_NOT_READY", message: "No R2 file available for this submission." });
    }

    console.log(`[DOWNLOAD] R2 get: ${key}`);

    const obj = await downloadFromR2(key);

    res.setHeader("Content-Type", obj.ContentType || "application/pdf");

    const disposition = (download === "true") ? "attachment" : "inline";
    const safeName = submission.original_filename || "document.pdf";
    res.setHeader("Content-Disposition", `${disposition}; filename="${safeName}"`);

    if (obj.ContentLength) res.setHeader("Content-Length", String(obj.ContentLength));

    return obj.Body.pipe(res);

  } catch (e) {
    console.error("[DOWNLOAD] error:", e.message);
    res.status(500).json({ error: "R2_DOWNLOAD_FAILED", message: e.message });
  }
});

/* -----------------------------
   Delete submission (PI/Admin)
----------------------------- */

app.delete("/api/di/submissions/:id", requirePI, async (req, res) => {
  try {
    const id = req.params.id;

    const r = await pool.query(
      `SELECT submission_id, r2_object_key, signed_pdf_path
       FROM di_submissions
       WHERE submission_id = $1
       LIMIT 1`,
      [id]
    );

    if (r.rows.length === 0) return res.status(404).json({ error: "NOT_FOUND" });

    const sub = r.rows[0];

    // Best effort: delete R2 objects if present
    if (r2Enabled()) {
      for (const key of [sub.signed_pdf_path, sub.r2_object_key]) {
        if (key) {
          try { await deleteFromR2(key); } catch (_) {}
        }
      }
    }

    await pool.query(`DELETE FROM di_submissions WHERE submission_id = $1`, [id]);
    return res.json({ success: true });

  } catch (e) {
    console.error("[DELETE] error:", e.message);
    res.status(500).json({ error: "Server error" });
  }
});

/* -----------------------------
   Startup
----------------------------- */

console.log("Environment:", { isProduction: true, NODE_ENV: process.env.NODE_ENV, RAILWAY: process.env.RAILWAY });
console.log("[STARTUP] Google Drive removed. Using R2 only.");
console.log("[STARTUP] R2 enabled:", r2Enabled());

app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Access the portal at http://localhost:${PORT}/di/access.html`);
});





