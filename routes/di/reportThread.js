// routes/di/reportThread.js
//
// REPORT thread workflow: read the timeline of a thread, upload a revision
// (PI or student), and manage thread lifecycle (approve / discard / reopen).
//
// Mounted at /api/di/report-thread. Backed by di_submissions thread columns
// added in migration 070; report-intelligence extraction (migration 068)
// is invoked for every revision upload but never blocks the response.
//
// Auth model:
//   GET  /:root_id                  - requireAuth (PI sees any; researcher
//                                     only their own threads)
//   POST /:root_id/upload-revision  - requireAuth (role enforced server-side)
//   POST /:root_id/approve          - requirePI
//   POST /:root_id/discard          - requirePI
//   POST /:root_id/reopen           - requirePI

'use strict';

const express = require('express');

const PI_ROLES      = new Set(['PI_ANNOTATED_VERSION', 'PI_REVISED_VERSION', 'FINAL_REPORT', 'NOTE', 'OTHER']);
const STUDENT_ROLES = new Set(['STUDENT_REVISED_VERSION', 'NOTE', 'OTHER']);
const ALL_ROLES     = new Set([
    'STUDENT_SUBMISSION', 'PI_ANNOTATED_VERSION', 'PI_REVISED_VERSION',
    'STUDENT_REVISED_VERSION', 'FINAL_REPORT', 'NOTE', 'OTHER'
]);

const UUID_RE = /^[0-9a-fA-F-]{36}$/;

// Server-side label derivation. Mirrors the new simplified rules:
// CLOSED → Approved, DISCARDED → Discarded; everything else falls
// through to the last-upload-role check (REOPENED is no longer a state
// we surface, but legacy rows with that status are treated as OPEN so
// the dashboard / modal continue to work without a migration).
function deriveThreadLabel(rootStatus, lastRole, _reopenedAt, _lastUploadAt) {
    if (rootStatus === 'DISCARDED') return 'Discarded';
    if (rootStatus === 'CLOSED')    return 'Approved';
    if (lastRole === 'STUDENT_SUBMISSION' || lastRole === 'STUDENT_REVISED_VERSION')
        return 'Awaiting PI review';
    if (lastRole === 'PI_ANNOTATED_VERSION' || lastRole === 'PI_REVISED_VERSION')
        return 'Awaiting student revision';
    if (lastRole === 'FINAL_REPORT') return 'Approved';
    return 'Open';
}

// Normalize the wire value of report_thread_status. REOPENED was a
// historical state we no longer generate; legacy rows are reported as
// OPEN to clients so the simplified UI doesn't need to handle it.
function normalizeThreadStatus(s) {
    return s === 'REOPENED' ? 'OPEN' : s;
}

module.exports = function reportThreadRouter(pool, deps) {
    const {
        uploadToR2,
        reportUploadMulter, // multer instance (PDF/DOC/DOCX, 20MB)
        requireAuth,
        requirePI,
        reportIntelligence  // services/reportIntelligence — best-effort
    } = deps || {};

    if (!uploadToR2 || !reportUploadMulter || !requireAuth || !requirePI) {
        throw new Error('reportThreadRouter: missing deps');
    }

    const router = express.Router();

    // Runtime schema ensure. db/migrate.js sometimes aborts before
    // reaching migration 070 (one of the earlier inline statements
    // fails on some deploys), leaving the thread columns absent. We
    // re-assert the schema on first call from this router and cache
    // the result so it only runs once per process.
    let _schemaEnsured = null;
    async function ensureSchema() {
        if (_schemaEnsured !== null) return _schemaEnsured;
        try {
            const stmts = [
                `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS report_thread_root_id UUID`,
                `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS report_parent_submission_id UUID`,
                `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS report_thread_role TEXT`,
                `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS report_thread_status TEXT`,
                `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS is_final_report BOOLEAN DEFAULT FALSE`,
                `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS report_thread_comment TEXT`,
                `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS report_closed_at TIMESTAMPTZ`,
                `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS report_reopened_at TIMESTAMPTZ`,
                `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS report_discarded_at TIMESTAMPTZ`,
                `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS is_discarded BOOLEAN DEFAULT FALSE`,
                `ALTER TABLE di_submissions DROP CONSTRAINT IF EXISTS di_submissions_report_thread_role_check`,
                `ALTER TABLE di_submissions ADD CONSTRAINT di_submissions_report_thread_role_check
                    CHECK (report_thread_role IS NULL OR report_thread_role IN (
                        'STUDENT_SUBMISSION','PI_ANNOTATED_VERSION','PI_REVISED_VERSION',
                        'STUDENT_REVISED_VERSION','FINAL_REPORT','NOTE','OTHER'
                    ))`,
                `ALTER TABLE di_submissions DROP CONSTRAINT IF EXISTS di_submissions_report_thread_status_check`,
                `ALTER TABLE di_submissions ADD CONSTRAINT di_submissions_report_thread_status_check
                    CHECK (report_thread_status IS NULL OR report_thread_status IN (
                        'OPEN','CLOSED','REOPENED','DISCARDED'
                    ))`,
                // Backfill — only sets columns that we just added; refs
                // to `signed_at` / `discarded_at` are guarded with COALESCE
                // and CASE so missing legacy columns don't abort.
                `UPDATE di_submissions
                    SET report_thread_root_id = COALESCE(report_thread_root_id, submission_id),
                        report_thread_role    = COALESCE(report_thread_role, 'STUDENT_SUBMISSION'),
                        report_thread_status  = COALESCE(report_thread_status, CASE
                            WHEN status = 'APPROVED'  THEN 'CLOSED'
                            WHEN status = 'DISCARDED' THEN 'DISCARDED'
                            ELSE 'OPEN'
                        END),
                        is_final_report       = COALESCE(is_final_report, (status = 'APPROVED')),
                        is_discarded          = COALESCE(is_discarded, (status = 'DISCARDED'))
                    WHERE file_type = 'REPORT'
                      AND report_thread_root_id IS NULL`,
                `CREATE INDEX IF NOT EXISTS idx_di_submissions_thread_root
                    ON di_submissions (report_thread_root_id) WHERE report_thread_root_id IS NOT NULL`,
                `CREATE INDEX IF NOT EXISTS idx_di_submissions_thread_status
                    ON di_submissions (report_thread_status) WHERE report_thread_status IS NOT NULL`,
                `CREATE INDEX IF NOT EXISTS idx_di_submissions_thread_parent
                    ON di_submissions (report_parent_submission_id) WHERE report_parent_submission_id IS NOT NULL`,
            ];
            for (const s of stmts) {
                try { await pool.query(s); }
                catch (e) {
                    console.warn('[REPORT-THREAD] schema ensure stmt failed:', (e && e.message) || e);
                }
            }
            _schemaEnsured = true;
        } catch (e) {
            console.error('[REPORT-THREAD] ensureSchema failed:', (e && e.message) || e);
            _schemaEnsured = false;
        }
        return _schemaEnsured;
    }
    // Kick it off at mount so the first request doesn't pay the cost.
    ensureSchema().catch(() => {});

    // -------------------------------------------------------------
    // GET /  — list REPORT thread roots (one row per thread). Used by
    // the PI dashboard to render the Open/Approve/Discard card grid.
    // Optional query: status=OPEN|REOPENED|CLOSED|DISCARDED|active,
    // researcher=CODE.
    // -------------------------------------------------------------
    router.get('/', requireAuth, async (req, res) => {
        try {
            const piMode = isPiSession(req);
            const wantStatus = (req.query.status || '').toString().trim().toUpperCase();
            const wantResearcher = (req.query.researcher || '').toString().trim().toUpperCase();

            const params = [];
            const push = v => { params.push(v); return '$' + params.length; };

            const where = [
                `s.file_type = 'REPORT'`,
                `s.report_thread_root_id = s.submission_id`
            ];
            // 'active' is a convenience for the dashboard — anything not
            // discarded. Otherwise we filter to the exact status.
            if (wantStatus === 'ACTIVE') {
                where.push(`COALESCE(s.report_thread_status,'OPEN') IN ('OPEN','REOPENED')`);
            } else if (wantStatus) {
                where.push(`s.report_thread_status = ${push(wantStatus)}`);
            }
            if (wantResearcher) where.push(`s.researcher_id = ${push(wantResearcher)}`);
            // Researcher session: only own threads.
            const user = req.session.user || {};
            if (!piMode) where.push(`s.researcher_id = ${push(user.researcher_id || '__none__')}`);

            const sql = `
                SELECT s.submission_id, s.researcher_id, s.affiliation,
                       s.original_filename, s.created_at,
                       s.report_subcategory, s.report_status, s.report_project,
                       s.report_period_start, s.report_period_end, s.report_supervisor,
                       s.report_thread_status, s.is_final_report, s.is_discarded,
                       s.report_closed_at, s.report_reopened_at, s.report_discarded_at,
                       s.report_thread_comment,
                       a.name AS researcher_name,
                       tl.last_role,
                       tl.last_uploaded_at,
                       (SELECT COUNT(*)::int FROM di_submissions x
                         WHERE x.report_thread_root_id = s.submission_id) AS revision_count
                  FROM di_submissions s
                  LEFT JOIN di_allowlist a ON a.researcher_id = s.researcher_id
                  LEFT JOIN LATERAL (
                      SELECT report_thread_role AS last_role,
                             created_at         AS last_uploaded_at
                        FROM di_submissions
                       WHERE report_thread_root_id = s.submission_id
                         AND submission_id <> s.submission_id
                       ORDER BY created_at DESC
                       LIMIT 1
                  ) tl ON TRUE
                 WHERE ${where.join(' AND ')}
                 ORDER BY GREATEST(COALESCE(tl.last_uploaded_at, s.created_at), s.created_at) DESC NULLS LAST
                 LIMIT 200`;
            const r = await pool.query(sql, params);

            const threads = r.rows.map(row => {
                const lastRole = row.last_role || 'STUDENT_SUBMISSION';
                const lastAt   = row.last_uploaded_at || row.created_at;
                return {
                    root_submission_id:          row.submission_id,
                    researcher_id:               row.researcher_id,
                    researcher_name:             row.researcher_name || null,
                    affiliation:                 row.affiliation,
                    filename:                    row.original_filename,
                    created_at:                  row.created_at ? new Date(row.created_at).toISOString() : null,
                    report_subcategory:          row.report_subcategory,
                    report_status:               row.report_status,
                    project:                     row.report_project,
                    reporting_period_start:      row.report_period_start ? new Date(row.report_period_start).toISOString().slice(0,10) : null,
                    reporting_period_end:        row.report_period_end   ? new Date(row.report_period_end).toISOString().slice(0,10)   : null,
                    supervisor:                  row.report_supervisor,
                    thread_status:               normalizeThreadStatus(row.report_thread_status) || 'OPEN',
                    is_final_report:             !!row.is_final_report,
                    is_discarded:                !!row.is_discarded,
                    closed_at:                   row.report_closed_at    ? new Date(row.report_closed_at).toISOString()    : null,
                    reopened_at:                 row.report_reopened_at  ? new Date(row.report_reopened_at).toISOString()  : null,
                    discarded_at:                row.report_discarded_at ? new Date(row.report_discarded_at).toISOString() : null,
                    revision_count:              row.revision_count || 1,
                    last_activity_at:            lastAt ? new Date(lastAt).toISOString() : null,
                    derived_thread_status_label: deriveThreadLabel(
                        row.report_thread_status, lastRole, row.report_reopened_at, lastAt
                    )
                };
            });

            res.json({ total: threads.length, threads });
        } catch (err) {
            console.error('[REPORT-THREAD] list error:', err && err.message);
            res.status(500).json({ error: 'Failed to list report threads' });
        }
    });

    // -------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------

    // Fetch the root submission and assert it's actually a REPORT root.
    // Returns null if the row doesn't exist or isn't a REPORT.
    async function loadRoot(rootId) {
        if (!UUID_RE.test(String(rootId || ''))) return null;
        const r = await pool.query(
            `SELECT submission_id, researcher_id, affiliation, workspace_id,
                    file_type, original_filename,
                    report_subcategory, report_status, report_project,
                    report_period_start, report_period_end, report_supervisor,
                    report_thread_root_id, report_thread_role, report_thread_status,
                    is_final_report, is_discarded,
                    report_closed_at, report_reopened_at, report_discarded_at,
                    report_thread_comment, created_at
               FROM di_submissions
              WHERE submission_id = $1
                AND file_type = 'REPORT'
                AND report_thread_root_id = submission_id
              LIMIT 1`,
            [rootId]
        );
        return r.rows[0] || null;
    }

    async function loadThread(rootId) {
        const r = await pool.query(
            `SELECT s.submission_id, s.researcher_id, s.affiliation,
                    s.original_filename, s.r2_object_key,
                    s.report_thread_role, s.report_parent_submission_id,
                    s.report_thread_comment, s.is_final_report,
                    s.created_at,
                    a.name AS uploader_name,
                    a.role AS uploader_role
               FROM di_submissions s
               LEFT JOIN di_allowlist a ON a.researcher_id = s.researcher_id
              WHERE s.report_thread_root_id = $1
              ORDER BY s.created_at ASC`,
            [rootId]
        );
        return r.rows || [];
    }

    function isPiSession(req) {
        const r = req.session && req.session.user && req.session.user.role;
        return r === 'pi';
    }

    function shapeRevision(row) {
        return {
            submission_id:      row.submission_id,
            researcher_id:      row.researcher_id || null,
            uploader_name:      row.uploader_name || null,
            uploader_role:      row.uploader_role || null,
            affiliation:        row.affiliation || null,
            filename:           row.original_filename || null,
            r2_object_key:      row.r2_object_key || null,
            role:               row.report_thread_role || null,
            parent_submission_id: row.report_parent_submission_id || null,
            comment:            row.report_thread_comment || null,
            is_final_report:    !!row.is_final_report,
            created_at:         row.created_at ? new Date(row.created_at).toISOString() : null,
            download_url:       row.r2_object_key ? `/api/di/download/${row.submission_id}` : null
        };
    }

    function shapeRoot(root, revisions) {
        const lastUpload = revisions.length ? revisions[revisions.length - 1] : null;
        const lastRole   = lastUpload ? lastUpload.role : root.report_thread_role;
        const lastUploadAt = lastUpload ? lastUpload.created_at : null;
        const label = deriveThreadLabel(
            root.report_thread_status,
            lastRole,
            root.report_reopened_at,
            lastUploadAt
        );
        return {
            root_submission_id:         root.submission_id,
            researcher_id:              root.researcher_id,
            affiliation:                root.affiliation,
            workspace_id:               root.workspace_id,
            filename:                   root.original_filename,
            report_subcategory:         root.report_subcategory,
            report_status:              root.report_status,
            project:                    root.report_project,
            reporting_period_start:     root.report_period_start ? new Date(root.report_period_start).toISOString().slice(0,10) : null,
            reporting_period_end:       root.report_period_end   ? new Date(root.report_period_end).toISOString().slice(0,10)   : null,
            supervisor:                 root.report_supervisor,
            thread_status:              normalizeThreadStatus(root.report_thread_status),
            is_final_report:            !!root.is_final_report,
            is_discarded:               !!root.is_discarded,
            closed_at:                  root.report_closed_at    ? new Date(root.report_closed_at).toISOString()    : null,
            reopened_at:                root.report_reopened_at  ? new Date(root.report_reopened_at).toISOString()  : null,
            discarded_at:               root.report_discarded_at ? new Date(root.report_discarded_at).toISOString() : null,
            derived_thread_status_label: label,
            created_at:                 root.created_at ? new Date(root.created_at).toISOString() : null,
            revisions
        };
    }

    // -------------------------------------------------------------
    // GET /:root_id  — full thread for one report
    // -------------------------------------------------------------
    router.get('/:root_id', requireAuth, async (req, res) => {
        try {
            const rootId = String(req.params.root_id || '').trim();
            const root = await loadRoot(rootId);
            if (!root) return res.status(404).json({ error: 'Report thread not found' });

            // Researchers can only see their own threads. PIs see everything.
            const user = req.session.user || {};
            if (!isPiSession(req) && user.researcher_id !== root.researcher_id) {
                return res.status(403).json({ error: 'Not authorised to view this thread' });
            }

            const revs = (await loadThread(rootId)).map(shapeRevision);
            res.json(shapeRoot(root, revs));
        } catch (err) {
            console.error('[REPORT-THREAD] GET error:', err && err.message);
            res.status(500).json({ error: 'Failed to load report thread' });
        }
    });

    // -------------------------------------------------------------
    // POST /:root_id/upload-revision  — PI or researcher uploads a new
    // version. Role is enforced based on caller identity.
    // -------------------------------------------------------------
    router.post('/:root_id/upload-revision', requireAuth, reportUploadMulter.single('file'), async (req, res) => {
        try {
            const rootId = String(req.params.root_id || '').trim();
            const root = await loadRoot(rootId);
            if (!root) return res.status(404).json({ error: 'Report thread not found' });

            // Researcher must own the thread; PI can revise any.
            const user = req.session.user || {};
            const piMode = isPiSession(req);
            if (!piMode && user.researcher_id !== root.researcher_id) {
                return res.status(403).json({ error: 'Not authorised to upload to this thread' });
            }

            if (root.report_thread_status === 'DISCARDED') {
                return res.status(409).json({ error: 'Thread is discarded; reopen is not supported once discarded' });
            }
            if (root.report_thread_status === 'CLOSED') {
                return res.status(409).json({ error: 'Thread is closed/approved. Re-open before uploading new revisions.' });
            }

            const file = req.file;
            if (!file) return res.status(400).json({ error: 'No file uploaded' });
            if (file.size > 20 * 1024 * 1024) return res.status(400).json({ error: 'File exceeds 20 MB limit' });

            // Role validation. Default differs by caller: PI → PI_ANNOTATED_VERSION,
            // student → STUDENT_REVISED_VERSION.
            let role = (req.body.role || '').toString().trim().toUpperCase();
            if (!role) role = piMode ? 'PI_ANNOTATED_VERSION' : 'STUDENT_REVISED_VERSION';
            if (!ALL_ROLES.has(role)) {
                return res.status(400).json({ error: 'Invalid role', allowed: Array.from(ALL_ROLES) });
            }
            if (role === 'STUDENT_SUBMISSION') {
                return res.status(400).json({ error: 'STUDENT_SUBMISSION is only used for the root upload' });
            }
            const allowed = piMode ? PI_ROLES : STUDENT_ROLES;
            if (!allowed.has(role)) {
                return res.status(403).json({ error: 'Role not allowed for this caller', allowed: Array.from(allowed) });
            }

            const comment = (req.body.comment || '').toString().trim() || null;
            const replaceFinal = ['1', 'true', 'yes'].includes(
                (req.body.replace_final || '').toString().trim().toLowerCase()
            );

            // R2 key. Same prefix shape as /api/di/upload-report keeps R2
            // navigable by reviewers ("REPORT" sub-prefix groups thread files).
            const year = new Date().getFullYear();
            const dateStamp = new Date().toISOString().slice(0, 10);
            const safeOriginal = (file.originalname || 'revision.pdf').replace(/[^\w.\-]+/g, '_');
            const uploaderId = user.researcher_id || 'pi';
            const key = `di/${root.affiliation}/Submitted/${year}/REPORT/${rootId.slice(0,8)}/${dateStamp}_${uploaderId}_${role}_${safeOriginal}`;

            await uploadToR2(file.buffer, key, file.mimetype || 'application/octet-stream');

            // Identify the parent (most recent prior submission in the thread)
            const last = await pool.query(
                `SELECT submission_id FROM di_submissions
                  WHERE report_thread_root_id = $1
                  ORDER BY created_at DESC LIMIT 1`,
                [rootId]
            );
            const parentId = last.rows[0] ? last.rows[0].submission_id : rootId;

            const ins = await pool.query(
                `INSERT INTO di_submissions
                    (researcher_id, affiliation, file_type, original_filename, r2_object_key,
                     workspace_id, status,
                     report_thread_root_id, report_parent_submission_id,
                     report_thread_role, report_thread_status, report_thread_comment,
                     is_final_report, is_discarded,
                     report_subcategory, report_project,
                     report_period_start, report_period_end,
                     report_supervisor)
                 VALUES ($1, $2, 'REPORT', $3, $4,
                         $5, 'SUBMITTED',
                         $6, $7,
                         $8, $9, $10,
                         FALSE, FALSE,
                         $11, $12,
                         $13::date, $14::date,
                         $15)
                 RETURNING submission_id`,
                [
                    uploaderId, root.affiliation,
                    file.originalname, key,
                    root.workspace_id,
                    rootId, parentId,
                    role, root.report_thread_status || 'OPEN', comment,
                    root.report_subcategory, root.report_project,
                    root.report_period_start, root.report_period_end,
                    root.report_supervisor
                ]
            );
            const newId = ins.rows[0].submission_id;

            // If PI ticked "Replace current final report", flip the previous
            // FINAL_REPORT off and mark this new upload as the final one.
            if (piMode && replaceFinal && role !== 'FINAL_REPORT') {
                // Only FINAL_REPORT rows can carry is_final_report=true; if the
                // PI wants to replace the final with a non-FINAL_REPORT role
                // we still need an explicit FINAL_REPORT row. So we reject
                // this combination rather than silently doing the wrong thing.
                return res.status(400).json({
                    error: 'replace_final requires role=FINAL_REPORT'
                });
            }
            if (role === 'FINAL_REPORT') {
                await pool.query(
                    `UPDATE di_submissions
                        SET is_final_report = FALSE
                      WHERE report_thread_root_id = $1
                        AND submission_id <> $2`,
                    [rootId, newId]
                );
                await pool.query(
                    `UPDATE di_submissions
                        SET is_final_report = TRUE
                      WHERE submission_id = $1`,
                    [newId]
                );
            }

            // Best-effort: run report intelligence on the new revision.
            // Failure is logged but never affects the response.
            let intelOutcome = { extraction_status: 'skipped', extraction_error: null };
            if (reportIntelligence && typeof reportIntelligence.run === 'function') {
                try {
                    intelOutcome = await reportIntelligence.run(
                        { pool },
                        {
                            submissionId: newId,
                            workspaceId:  root.workspace_id,
                            researcherId: root.researcher_id, // intelligence stays keyed to thread owner
                            buffer:       file.buffer,
                            filename:     file.originalname,
                            meta: {
                                report_subcategory: root.report_subcategory,
                                report_status:      root.report_status,
                                report_project:     root.report_project,
                                report_period_start:root.report_period_start,
                                report_period_end:  root.report_period_end,
                                report_supervisor:  root.report_supervisor,
                                report_related_data_ids: [],
                                report_related_sop_ids:  []
                            }
                        }
                    );
                } catch (e) {
                    console.error('[REPORT-THREAD] intelligence threw:', e && e.message);
                    intelOutcome = { extraction_status: 'failed', extraction_error: e && e.message };
                }
            }

            res.json({
                success: true,
                submission_id: newId,
                role,
                parent_submission_id: parentId,
                r2_object_key: key,
                intelligence_status: intelOutcome.extraction_status,
                intelligence_error:  intelOutcome.extraction_error
            });
        } catch (err) {
            console.error('[REPORT-THREAD] upload-revision error:', err && err.message);
            if (err && err.code) console.error('[REPORT-THREAD] PG code=' + err.code, 'detail=' + (err.detail || '-'));
            res.status(500).json({ error: 'Failed to upload revision' });
        }
    });

    // -------------------------------------------------------------
    // POST /:root_id/approve  — PI marks the latest version final and
    // closes the thread. If a FINAL_REPORT row already exists, we keep
    // it; otherwise we elevate the latest revision to is_final_report.
    // -------------------------------------------------------------
    router.post('/:root_id/approve', requirePI, async (req, res) => {
        try {
            const rootId = String(req.params.root_id || '').trim();
            const root = await loadRoot(rootId);
            if (!root) return res.status(404).json({ error: 'Report thread not found' });
            if (root.report_thread_status === 'DISCARDED') {
                return res.status(409).json({ error: 'Cannot approve a discarded thread' });
            }

            const comment = (req.body && req.body.approval_comment || '').toString().trim() || null;

            // Pick the version to mark final: existing FINAL_REPORT wins; else
            // the most-recent revision in the thread.
            const latest = await pool.query(
                `SELECT submission_id FROM di_submissions
                  WHERE report_thread_root_id = $1
                  ORDER BY (report_thread_role = 'FINAL_REPORT') DESC, created_at DESC
                  LIMIT 1`,
                [rootId]
            );
            const finalId = latest.rows[0] && latest.rows[0].submission_id;

            // Clear any prior is_final_report flags in the thread, then set
            // is_final_report on the chosen row.
            await pool.query(
                `UPDATE di_submissions SET is_final_report = FALSE
                  WHERE report_thread_root_id = $1`,
                [rootId]
            );
            if (finalId) {
                await pool.query(
                    `UPDATE di_submissions SET is_final_report = TRUE
                      WHERE submission_id = $1`,
                    [finalId]
                );
            }

            // Close the thread at the root.
            const piName = (req.session.user && (req.session.user.name || req.session.user.researcher_id)) || 'pi';
            await pool.query(
                `UPDATE di_submissions
                    SET report_thread_status = 'CLOSED',
                        report_closed_at     = NOW(),
                        report_reopened_at   = NULL,
                        report_thread_comment = COALESCE($2, report_thread_comment),
                        status               = 'APPROVED',
                        signer_name          = COALESCE(signer_name, $3),
                        signed_at            = COALESCE(signed_at, NOW())
                  WHERE submission_id = $1`,
                [rootId, comment, piName]
            );

            res.json({ success: true, root_submission_id: rootId, final_submission_id: finalId, thread_status: 'CLOSED' });
        } catch (err) {
            console.error('[REPORT-THREAD] approve error:', err && err.message);
            res.status(500).json({ error: 'Failed to approve thread' });
        }
    });

    // -------------------------------------------------------------
    // POST /:root_id/discard  — PI flags the whole thread DISCARDED.
    // History/files preserved; canonical endpoint and dashboard
    // filtering can hide it.
    // -------------------------------------------------------------
    router.post('/:root_id/discard', requirePI, async (req, res) => {
        try {
            const rootId = String(req.params.root_id || '').trim();
            const root = await loadRoot(rootId);
            if (!root) return res.status(404).json({ error: 'Report thread not found' });

            const reason = (req.body && req.body.discard_reason || '').toString().trim() || null;

            await pool.query(
                `UPDATE di_submissions
                    SET report_thread_status = 'DISCARDED',
                        report_discarded_at  = NOW(),
                        is_discarded         = TRUE,
                        status               = 'DISCARDED',
                        discarded_at         = COALESCE(discarded_at, NOW()),
                        discard_reason       = COALESCE(discard_reason, $2)
                  WHERE submission_id = $1`,
                [rootId, reason]
            );
            // Mark child rows as is_discarded too, but keep their status to
            // preserve audit (the root carries the DISCARDED state).
            await pool.query(
                `UPDATE di_submissions
                    SET is_discarded = TRUE
                  WHERE report_thread_root_id = $1`,
                [rootId]
            );

            res.json({ success: true, root_submission_id: rootId, thread_status: 'DISCARDED' });
        } catch (err) {
            console.error('[REPORT-THREAD] discard error:', err && err.message);
            res.status(500).json({ error: 'Failed to discard thread' });
        }
    });

    // -------------------------------------------------------------
    // POST /:root_id/reopen  — DEPRECATED.
    // The simplified REPORT workflow treats CLOSED as final and
    // archived. Researchers needing to continue a workflow upload a
    // NEW REPORT (which becomes a new thread). The endpoint is kept
    // mounted for compatibility with any old caller, but it now
    // returns 410 Gone without mutating state. No UI exposes it.
    // -------------------------------------------------------------
    router.post('/:root_id/reopen', requirePI, async (req, res) => {
        return res.status(410).json({
            error: 'Reopen is no longer supported — REPORT approval is final. Upload a new REPORT submission to start a new thread.'
        });
    });

    return router;
};

module.exports.deriveThreadLabel = deriveThreadLabel;

// Shared schema-ensure used by server.js /api/di/upload-report so the
// INSERT can rely on the thread columns existing. Lazy-cached per pool.
module.exports.ensureSchemaFor = function ensureSchemaFor(pool) {
    if (!pool.__reportThreadSchemaPromise) {
        pool.__reportThreadSchemaPromise = (async () => {
            const stmts = [
                `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS report_thread_root_id UUID`,
                `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS report_parent_submission_id UUID`,
                `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS report_thread_role TEXT`,
                `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS report_thread_status TEXT`,
                `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS is_final_report BOOLEAN DEFAULT FALSE`,
                `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS report_thread_comment TEXT`,
                `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS report_closed_at TIMESTAMPTZ`,
                `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS report_reopened_at TIMESTAMPTZ`,
                `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS report_discarded_at TIMESTAMPTZ`,
                `ALTER TABLE di_submissions ADD COLUMN IF NOT EXISTS is_discarded BOOLEAN DEFAULT FALSE`,
                `ALTER TABLE di_submissions DROP CONSTRAINT IF EXISTS di_submissions_report_thread_role_check`,
                `ALTER TABLE di_submissions ADD CONSTRAINT di_submissions_report_thread_role_check
                    CHECK (report_thread_role IS NULL OR report_thread_role IN (
                        'STUDENT_SUBMISSION','PI_ANNOTATED_VERSION','PI_REVISED_VERSION',
                        'STUDENT_REVISED_VERSION','FINAL_REPORT','NOTE','OTHER'
                    ))`,
                `ALTER TABLE di_submissions DROP CONSTRAINT IF EXISTS di_submissions_report_thread_status_check`,
                `ALTER TABLE di_submissions ADD CONSTRAINT di_submissions_report_thread_status_check
                    CHECK (report_thread_status IS NULL OR report_thread_status IN (
                        'OPEN','CLOSED','REOPENED','DISCARDED'
                    ))`,
                `UPDATE di_submissions
                    SET report_thread_root_id = COALESCE(report_thread_root_id, submission_id),
                        report_thread_role    = COALESCE(report_thread_role, 'STUDENT_SUBMISSION'),
                        report_thread_status  = COALESCE(report_thread_status, CASE
                            WHEN status = 'APPROVED'  THEN 'CLOSED'
                            WHEN status = 'DISCARDED' THEN 'DISCARDED'
                            ELSE 'OPEN'
                        END),
                        is_final_report       = COALESCE(is_final_report, (status = 'APPROVED')),
                        is_discarded          = COALESCE(is_discarded, (status = 'DISCARDED'))
                    WHERE file_type = 'REPORT'
                      AND report_thread_root_id IS NULL`,
                `CREATE INDEX IF NOT EXISTS idx_di_submissions_thread_root
                    ON di_submissions (report_thread_root_id) WHERE report_thread_root_id IS NOT NULL`,
                `CREATE INDEX IF NOT EXISTS idx_di_submissions_thread_status
                    ON di_submissions (report_thread_status) WHERE report_thread_status IS NOT NULL`,
                `CREATE INDEX IF NOT EXISTS idx_di_submissions_thread_parent
                    ON di_submissions (report_parent_submission_id) WHERE report_parent_submission_id IS NOT NULL`,
            ];
            for (const s of stmts) {
                try { await pool.query(s); }
                catch (e) {
                    console.warn('[REPORT-THREAD] schema ensure stmt failed:', (e && e.message) || e);
                }
            }
            return true;
        })().catch(e => {
            console.error('[REPORT-THREAD] schema ensure root failed:', e && e.message);
            return false;
        });
    }
    return pool.__reportThreadSchemaPromise;
};
