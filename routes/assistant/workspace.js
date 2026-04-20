// Portal Assistant API — Zoe
// GET /api/assistant/workspace/overview
//
// Workspace-level operational snapshot for NAT-Lab.
// NAT-Lab structure: workspace -> affiliation (LiU / UNAV) -> researchers -> files / GLP.
// No groups, no projects layer. Affiliation is the only aggregation layer above researchers.
//
// Sources of truth:
//   - di_submissions  : GLP flow status + per-submission affiliation (authoritative)
//   - di_allowlist    : researcher identity + home affiliation
//   - workspaces      : slug -> id resolution
//
// Additive: no auth layer, no caching, no schema changes.
// Exported as a factory so we reuse the existing pg Pool from server.js.

'use strict';

const express = require('express');

// NAT-Lab recognizes two real institutional sites.
// EXTERNAL / THERALIA submissions still count toward workspace totals but
// are intentionally excluded from the per-affiliation summary (per spec).
const NATLAB_AFFILIATIONS = ['LiU', 'UNAV'];

module.exports = function assistantWorkspaceRouter(pool) {
    const router = express.Router();

    router.get('/overview', async (req, res) => {
        const wsSlug = (req.query.ws || '').toString().trim();
        if (!wsSlug) return res.status(400).json({ error: 'ws query parameter is required' });

        // period maps to a window in days; default = weekly (7d).
        // recent = 14d, monthly = 30d. Trend always compares current period vs
        // the immediately preceding equal-length window.
        const periodRaw = (req.query.period || 'weekly').toString().trim().toLowerCase();
        let periodDays;
        if      (periodRaw === 'monthly') periodDays = 30;
        else if (periodRaw === 'recent')  periodDays = 14;
        else                              periodDays = 7; // weekly (default)
        const periodLabel = periodRaw === 'monthly' ? 'monthly'
                         : periodRaw === 'recent'   ? 'recent'
                         : 'weekly';
        const curInterval   = `${periodDays} days`;
        const priorInterval = `${periodDays * 2} days`; // current + prior bucket

        try {
            // Resolve workspace slug -> id
            const wsRow = await pool.query(
                `SELECT id, slug FROM workspaces WHERE slug = $1 AND is_active = TRUE LIMIT 1`,
                [wsSlug]
            );
            if (wsRow.rows.length === 0) {
                return res.status(404).json({ error: 'Workspace not found' });
            }
            const workspaceId   = wsRow.rows[0].id;
            const workspaceSlug = wsRow.rows[0].slug;

            // All probes run in parallel; each is a simple bounded aggregate.
            const [
                statusCounts,
                stalePending,
                blockedRevision,
                periodBuckets,
                mostActive,
                revisionBacklog,
                affStatusCounts,
                affPeriodBuckets,
                affMemberCounts
            ] = await Promise.all([
                // 1. Workspace-wide current status buckets (all affiliations).
                pool.query(
                    `SELECT status, COUNT(*)::int AS c
                       FROM di_submissions
                      WHERE workspace_id = $1
                      GROUP BY status`,
                    [workspaceId]
                ),
                // 2. Stale PENDING (>7 days) — feeds approval_flow_state.
                pool.query(
                    `SELECT COUNT(*)::int AS c
                       FROM di_submissions
                      WHERE workspace_id = $1
                        AND status = 'PENDING'
                        AND created_at < NOW() - INTERVAL '7 days'`,
                    [workspaceId]
                ),
                // 3. Blocked = chronic REVISION_NEEDED (>14 days old, still open).
                pool.query(
                    `SELECT COUNT(*)::int AS c
                       FROM di_submissions
                      WHERE workspace_id = $1
                        AND status = 'REVISION_NEEDED'
                        AND created_at < NOW() - INTERVAL '14 days'`,
                    [workspaceId]
                ),
                // 4. Activity trend: submissions in current period vs prior period.
                //    One row with two counts for readability.
                pool.query(
                    `SELECT
                        COUNT(*) FILTER (
                            WHERE created_at >= NOW() - $2::interval
                        )::int AS cur,
                        COUNT(*) FILTER (
                            WHERE created_at <  NOW() - $2::interval
                              AND created_at >= NOW() - $3::interval
                        )::int AS prior
                       FROM di_submissions
                      WHERE workspace_id = $1
                        AND status <> 'DISCARDED'`,
                    [workspaceId, curInterval, priorInterval]
                ),
                // 5. Most active researchers in current period.
                pool.query(
                    `SELECT s.researcher_id, a.name, a.affiliation, COUNT(*)::int AS uploads
                       FROM di_submissions s
                       LEFT JOIN di_allowlist a ON a.researcher_id = s.researcher_id
                      WHERE s.workspace_id = $1
                        AND s.status <> 'DISCARDED'
                        AND s.created_at >= NOW() - $2::interval
                      GROUP BY s.researcher_id, a.name, a.affiliation
                      ORDER BY uploads DESC, s.researcher_id ASC
                      LIMIT 5`,
                    [workspaceId, curInterval]
                ),
                // 6. Revision backlog researchers — outstanding REVISION_NEEDED per researcher.
                pool.query(
                    `SELECT s.researcher_id, a.name, a.affiliation, COUNT(*)::int AS revision_needed
                       FROM di_submissions s
                       LEFT JOIN di_allowlist a ON a.researcher_id = s.researcher_id
                      WHERE s.workspace_id = $1
                        AND s.status = 'REVISION_NEEDED'
                      GROUP BY s.researcher_id, a.name, a.affiliation
                      ORDER BY revision_needed DESC, s.researcher_id ASC
                      LIMIT 5`,
                    [workspaceId]
                ),
                // 7. Per-affiliation current status buckets (LiU / UNAV only).
                pool.query(
                    `SELECT affiliation, status, COUNT(*)::int AS c
                       FROM di_submissions
                      WHERE workspace_id = $1
                        AND affiliation = ANY($2::text[])
                      GROUP BY affiliation, status`,
                    [workspaceId, NATLAB_AFFILIATIONS]
                ),
                // 8. Per-affiliation period buckets for trend.
                pool.query(
                    `SELECT
                        affiliation,
                        COUNT(*) FILTER (
                            WHERE created_at >= NOW() - $2::interval
                        )::int AS cur,
                        COUNT(*) FILTER (
                            WHERE created_at <  NOW() - $2::interval
                              AND created_at >= NOW() - $3::interval
                        )::int AS prior
                       FROM di_submissions
                      WHERE workspace_id = $1
                        AND affiliation = ANY($4::text[])
                        AND status <> 'DISCARDED'
                      GROUP BY affiliation`,
                    [workspaceId, curInterval, priorInterval, NATLAB_AFFILIATIONS]
                ),
                // 9. Per-affiliation active researcher counts (workspace-scoped).
                //    di_allowlist is the workspace's member registry; we gate by
                //    workspace_users so cross-workspace allowlist rows don't leak in.
                pool.query(
                    `SELECT a.affiliation, COUNT(*)::int AS researchers
                       FROM di_allowlist a
                       JOIN workspace_users wu ON wu.user_id = a.researcher_id
                      WHERE wu.workspace_id = $1
                        AND wu.is_active = TRUE
                        AND a.active = TRUE
                        AND a.affiliation = ANY($2::text[])
                      GROUP BY a.affiliation`,
                    [workspaceId, NATLAB_AFFILIATIONS]
                )
            ]);

            // --- Aggregate workspace-wide status buckets ------------------------------
            const statusMap = Object.fromEntries(statusCounts.rows.map(r => [r.status, r.c]));
            const pendingReviews  = statusMap['PENDING']         || 0;
            const revisionNeeded  = statusMap['REVISION_NEEDED'] || 0;
            const approvedTotal   = statusMap['APPROVED']        || 0;
            const blocked         = blockedRevision.rows[0].c;
            const stalePendingN   = stalePending.rows[0].c;

            // --- Approval flow state --------------------------------------------------
            // blocked : many chronic revisions or very large revision backlog
            // strained: visible friction (stale PENDING or growing revision backlog)
            // healthy : otherwise
            let approvalFlowState;
            if (blocked > 5 || revisionNeeded > 15) {
                approvalFlowState = 'blocked';
            } else if (stalePendingN > 3 || revisionNeeded > 5) {
                approvalFlowState = 'strained';
            } else {
                approvalFlowState = 'healthy';
            }

            // --- Workspace activity trend --------------------------------------------
            const curCount   = periodBuckets.rows[0].cur;
            const priorCount = periodBuckets.rows[0].prior;
            const activityTrend = classifyTrend(curCount, priorCount);

            // --- Top lists ------------------------------------------------------------
            const mostActiveResearchers = mostActive.rows.slice(0, 3).map(r => ({
                id: r.researcher_id,
                name: r.name || null,
                affiliation: r.affiliation || null,
                uploads: r.uploads
            }));
            const revisionBacklogResearchers = revisionBacklog.rows.slice(0, 3).map(r => ({
                id: r.researcher_id,
                name: r.name || null,
                affiliation: r.affiliation || null,
                revision_needed: r.revision_needed
            }));

            // --- Per-affiliation summary ---------------------------------------------
            const affStatus = {};
            for (const aff of NATLAB_AFFILIATIONS) affStatus[aff] = {};
            for (const row of affStatusCounts.rows) {
                affStatus[row.affiliation][row.status] = row.c;
            }
            const affPeriod = {};
            for (const row of affPeriodBuckets.rows) {
                affPeriod[row.affiliation] = { cur: row.cur, prior: row.prior };
            }
            const affMembers = {};
            for (const row of affMemberCounts.rows) {
                affMembers[row.affiliation] = row.researchers;
            }

            const affiliationSummary = NATLAB_AFFILIATIONS.map(aff => {
                const s = affStatus[aff] || {};
                const p = affPeriod[aff] || { cur: 0, prior: 0 };
                const pending  = s['PENDING']         || 0;
                const revision = s['REVISION_NEEDED'] || 0;
                const approved = s['APPROVED']        || 0;
                const decided  = approved + revision; // denominator for approval rate
                const approvalRate = decided > 0 ? +(approved / decided).toFixed(2) : null;
                return {
                    affiliation: aff,
                    researchers: affMembers[aff] || 0,
                    uploads_current_period: p.cur,
                    uploads_prior_period:   p.prior,
                    activity_trend: classifyTrend(p.cur, p.prior),
                    pending_reviews: pending,
                    revision_needed: revision,
                    approved,
                    approval_rate: approvalRate
                };
            });

            // --- Strongest / weakest affiliation -------------------------------------
            // Rank by approval_rate, tie-break on uploads_current_period.
            // Skip affiliations with no decided submissions (approval_rate === null)
            // — we can't rate what we can't measure.
            const ranked = affiliationSummary
                .filter(a => a.approval_rate !== null)
                .slice()
                .sort((x, y) => {
                    if (y.approval_rate !== x.approval_rate) return y.approval_rate - x.approval_rate;
                    return y.uploads_current_period - x.uploads_current_period;
                });
            const strongestAffiliation = ranked.length ? ranked[0].affiliation : null;
            const weakestAffiliation   = ranked.length > 1 ? ranked[ranked.length - 1].affiliation : null;

            res.json({
                workspace: workspaceSlug,
                period: periodLabel,
                pending_reviews: pendingReviews,
                revision_needed: revisionNeeded,
                blocked,
                approved_total: approvedTotal,
                approval_flow_state: approvalFlowState,
                activity_trend: activityTrend,
                uploads_current_period: curCount,
                uploads_prior_period:   priorCount,
                most_active_researchers: mostActiveResearchers,
                revision_backlog_researchers: revisionBacklogResearchers,
                affiliation_summary: affiliationSummary,
                strongest_affiliation: strongestAffiliation,
                weakest_affiliation: weakestAffiliation,
                updated_at: new Date().toISOString()
            });
        } catch (err) {
            console.error('[ASSISTANT] workspace/overview error:', err.message);
            res.status(500).json({ error: 'Failed to build workspace overview' });
        }
    });

    return router;
};

// up / flat / down — needs a decent prior baseline to avoid noise from tiny counts.
function classifyTrend(cur, prior) {
    if (prior < 3 && cur < 3) return 'flat'; // insufficient signal
    if (prior === 0)          return cur > 0 ? 'up' : 'flat';
    const ratio = cur / prior;
    if (ratio >= 1.20) return 'up';
    if (ratio <= 0.80) return 'down';
    return 'flat';
}
