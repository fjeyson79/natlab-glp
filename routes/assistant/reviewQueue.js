// Portal Assistant API — Zoe
// GET /api/assistant/review-queue
//
// Keeper-facing review queue for NAT-Lab.
// Complements /api/assistant/workspace/overview: that endpoint returns counts
// and top-N snapshots; this one returns the actual working list — per-item
// rows with age, priority, and reason — so a keeper (or Zoe) can answer
// "what should I look at right now?"
//
// Sources of truth:
//   - di_submissions  : the queue itself (status PENDING / REVISION_NEEDED)
//   - di_allowlist    : display name for the submitter
//   - rd_documents    : optional title enrichment when the file was ingested
//                       through the R&D path (LEFT JOIN — not required)
//
// No schema fiction: reviewer_name is exposed as null because the schema has
// no reviewer-assignment table. No invented audit rows. No project or group
// aggregation (NAT-Lab does not use those).
//
// Additive: no auth layer, no caching, no schema changes.
// Exported as a factory so we reuse the existing pg Pool from server.js.

'use strict';

const express = require('express');

// Priority thresholds. Transparent, documented, not a black-box score.
//
//   HIGH   — needs keeper attention NOW:
//              - PENDING older than HIGH_AGE_DAYS, OR
//              - REVISION_NEEDED older than HIGH_AGE_DAYS (chronic)
//   MEDIUM — above normal queue latency:
//              - PENDING older than MEDIUM_AGE_DAYS, OR
//              - any REVISION_NEEDED (even recent — still a backlog signal)
//   LOW    — fresh PENDING within MEDIUM_AGE_DAYS
//
// These match the /workspace/overview "stale pending" (>7d) and "blocked"
// (>14d) thresholds — same operational definitions, reused.
const MEDIUM_AGE_DAYS = 7;
const HIGH_AGE_DAYS   = 14;

// Cap queue size so Zoe prompts stay bounded. A keeper can page or narrow by
// affiliation later if we need more than this.
const DEFAULT_LIMIT = 25;
const MAX_LIMIT     = 50;

module.exports = function assistantReviewQueueRouter(pool) {
    const router = express.Router();

    router.get('/', async (req, res) => {
        const wsSlug = (req.query.ws || '').toString().trim();
        if (!wsSlug) return res.status(400).json({ error: 'ws query parameter is required' });

        let limit = parseInt(req.query.limit, 10);
        if (!Number.isFinite(limit) || limit < 1) limit = DEFAULT_LIMIT;
        if (limit > MAX_LIMIT) limit = MAX_LIMIT;

        try {
            const wsRow = await pool.query(
                `SELECT id, slug FROM workspaces WHERE slug = $1 AND is_active = TRUE LIMIT 1`,
                [wsSlug]
            );
            if (wsRow.rows.length === 0) {
                return res.status(404).json({ error: 'Workspace not found' });
            }
            const workspaceId   = wsRow.rows[0].id;
            const workspaceSlug = wsRow.rows[0].slug;

            // Two parallel queries:
            //   queueRes   — the capped worklist, ordered by age DESC
            //   accRes     — revision_accumulation: researchers with any
            //                REVISION_NEEDED items, with oldest-age per researcher
            // All derivations (priority, bottlenecks, oldest_pending_age_days)
            // are computed in JS from these two result sets — no extra queries.
            const [queueRes, accRes] = await Promise.all([
                pool.query(
                    `SELECT s.submission_id, s.status, s.created_at, s.researcher_id,
                            s.affiliation, s.original_filename, s.file_type, s.r2_object_key,
                            s.revision_comments,
                            a.name AS submitter_name,
                            d.id   AS rd_document_id,
                            d.title AS rd_title
                       FROM di_submissions s
                       LEFT JOIN di_allowlist a ON a.researcher_id = s.researcher_id
                       LEFT JOIN LATERAL (
                           SELECT d.id, d.title
                             FROM rd_documents d
                            WHERE d.workspace_id = s.workspace_id
                              AND d.r2_key = s.r2_object_key
                            LIMIT 1
                       ) d ON TRUE
                      WHERE s.workspace_id = $1
                        AND s.status IN ('PENDING', 'REVISION_NEEDED')
                      ORDER BY s.created_at ASC
                      LIMIT $2`,
                    [workspaceId, limit]
                ),
                pool.query(
                    `SELECT s.researcher_id, a.name AS submitter_name, a.affiliation,
                            COUNT(*)::int AS revision_needed_count,
                            MIN(s.created_at) AS oldest_revision_at
                       FROM di_submissions s
                       LEFT JOIN di_allowlist a ON a.researcher_id = s.researcher_id
                      WHERE s.workspace_id = $1
                        AND s.status = 'REVISION_NEEDED'
                      GROUP BY s.researcher_id, a.name, a.affiliation
                      ORDER BY revision_needed_count DESC, oldest_revision_at ASC
                      LIMIT 10`,
                    [workspaceId]
                )
            ]);

            const now = Date.now();
            const ageDays = (ts) => ts ? Math.floor((now - new Date(ts).getTime()) / (24 * 3600 * 1000)) : null;

            // --- Build queue items ---------------------------------------------------
            const queue = queueRes.rows.map(r => {
                const age = ageDays(r.created_at);
                // Priority rule (see block comment at top of file).
                let priority;
                if ((age !== null && age >= HIGH_AGE_DAYS)) {
                    priority = 'high';
                } else if (r.status === 'REVISION_NEEDED') {
                    // Any REVISION_NEEDED that isn't already high is at least medium —
                    // it is a backlog row, not a fresh queue item.
                    priority = 'medium';
                } else if (age !== null && age >= MEDIUM_AGE_DAYS) {
                    priority = 'medium';
                } else {
                    priority = 'low';
                }

                // Review state mapping kept consistent with /files/search and /files/:id.
                let reviewState;
                if (r.status === 'REVISION_NEEDED') reviewState = (age !== null && age > HIGH_AGE_DAYS)  ? 'blocked' : 'needs_revision';
                else if (r.status === 'PENDING')    reviewState = (age !== null && age > MEDIUM_AGE_DAYS) ? 'stalled' : 'awaiting_review';
                else                                reviewState = String(r.status).toLowerCase();

                // Reason — short, deterministic, explains the priority.
                const reason =
                    priority === 'high'
                        ? (r.status === 'REVISION_NEEDED'
                            ? `REVISION_NEEDED for ${age} day${age === 1 ? '' : 's'} — blocked`
                            : `PENDING for ${age} day${age === 1 ? '' : 's'} — stalled`)
                    : priority === 'medium'
                        ? (r.status === 'REVISION_NEEDED'
                            ? 'REVISION_NEEDED — awaiting resubmission'
                            : `PENDING for ${age} day${age === 1 ? '' : 's'}`)
                    : 'PENDING — within normal review window';

                return {
                    submission_id:     r.submission_id,
                    file_id:           r.rd_document_id || null, // matches /files/:id param
                    filename:          r.original_filename || null,
                    title:             r.rd_title || null,
                    file_type:         r.file_type || null,
                    status:            r.status,
                    review_state:      reviewState,
                    created_at:        r.created_at ? new Date(r.created_at).toISOString() : null,
                    age_days:          age,
                    researcher_id:     r.researcher_id || null,
                    submitted_by_name: r.submitter_name || null,
                    affiliation:       r.affiliation || null,
                    // Reviewer assignment is not stored in the current schema —
                    // expose null rather than fabricate. See file header.
                    reviewer_name:     null,
                    priority,
                    reason
                };
            });

            // --- Top-line counts -----------------------------------------------------
            const pendingItems  = queue.filter(q => q.status === 'PENDING');
            const revisionItems = queue.filter(q => q.status === 'REVISION_NEEDED');
            const pendingCount  = pendingItems.length;
            const revisionCount = revisionItems.length;
            // "oldest_pending_age_days" is derived only from what we actually
            // returned (the capped window). Since we sort ASC by created_at, the
            // first PENDING in the list IS the oldest.
            const oldestPending = pendingItems.length ? pendingItems[0].age_days : null;

            // --- Revision accumulation ----------------------------------------------
            const revisionAccumulation = accRes.rows.map(r => ({
                researcher_id:             r.researcher_id,
                submitted_by_name:         r.submitter_name || null,
                affiliation:               r.affiliation || null,
                revision_needed_count:     r.revision_needed_count,
                oldest_revision_age_days:  ageDays(r.oldest_revision_at)
            }));

            // --- Bottlenecks (structured observations, no narrative) ----------------
            // Keep the set small and deterministic. Each entry has a `type`, a
            // short grounded `detail` string, and the numeric evidence.
            const bottlenecks = [];

            // 1. Stale PENDING cluster
            const stalePending = pendingItems.filter(q => q.age_days !== null && q.age_days > MEDIUM_AGE_DAYS);
            if (stalePending.length >= 3) {
                bottlenecks.push({
                    type: 'stale_pending_cluster',
                    count: stalePending.length,
                    oldest_age_days: stalePending[0].age_days,
                    detail: `${stalePending.length} PENDING items older than ${MEDIUM_AGE_DAYS} days`
                });
            }

            // 2. Chronic REVISION_NEEDED
            const chronicRevision = revisionItems.filter(q => q.age_days !== null && q.age_days > HIGH_AGE_DAYS);
            if (chronicRevision.length >= 1) {
                bottlenecks.push({
                    type: 'chronic_revision',
                    count: chronicRevision.length,
                    oldest_age_days: Math.max(...chronicRevision.map(q => q.age_days || 0)),
                    detail: `${chronicRevision.length} REVISION_NEEDED items older than ${HIGH_AGE_DAYS} days`
                });
            }

            // 3. Individual revision accumulator (researcher with >= 3 open revisions)
            for (const acc of revisionAccumulation) {
                if (acc.revision_needed_count >= 3) {
                    bottlenecks.push({
                        type: 'researcher_revision_accumulation',
                        researcher_id: acc.researcher_id,
                        submitted_by_name: acc.submitted_by_name,
                        affiliation: acc.affiliation,
                        count: acc.revision_needed_count,
                        oldest_age_days: acc.oldest_revision_age_days,
                        detail: `${acc.submitted_by_name || acc.researcher_id} has ${acc.revision_needed_count} open REVISION_NEEDED items`
                    });
                }
            }

            // 4. Affiliation queue imbalance — only flag when one side is at
            //    least 3x the other AND the heavier side has >= 5 items. Pure
            //    ratios on tiny numbers produce false alarms.
            const affCounts = {};
            for (const q of queue) {
                if (!q.affiliation) continue;
                affCounts[q.affiliation] = (affCounts[q.affiliation] || 0) + 1;
            }
            const affEntries = Object.entries(affCounts);
            if (affEntries.length === 2) {
                affEntries.sort((a, b) => b[1] - a[1]);
                const [heavy, light] = affEntries;
                if (heavy[1] >= 5 && (light[1] === 0 || heavy[1] / light[1] >= 3)) {
                    bottlenecks.push({
                        type: 'affiliation_queue_imbalance',
                        heavier_affiliation: heavy[0],
                        heavier_count: heavy[1],
                        lighter_affiliation: light[0],
                        lighter_count: light[1],
                        detail: `${heavy[0]} queue (${heavy[1]}) is ${light[1] === 0 ? 'unbalanced vs 0' : (heavy[1] / light[1]).toFixed(1) + 'x'} vs ${light[0]} (${light[1]})`
                    });
                }
            }

            res.json({
                workspace: workspaceSlug,
                pending_count: pendingCount,
                revision_needed_count: revisionCount,
                oldest_pending_age_days: oldestPending,
                queue,
                revision_accumulation: revisionAccumulation,
                bottlenecks,
                updated_at: new Date().toISOString()
            });
        } catch (err) {
            console.error('[ASSISTANT] review-queue error:', err.message);
            res.status(500).json({ error: 'Failed to build review queue' });
        }
    });

    return router;
};
