// Portal Assistant API — Zoe
// GET /api/assistant/activity?ws=natlab
//
// File-type activity statistics for NAT-Lab:
//   - researcher_activity_ranked[]  — every workspace researcher, ranked by DATA count desc
//   - affiliation_activity[]         — LiU / UNAV aggregate rows
//
// DI-first: di_submissions is the primary source of truth for NAT-Lab uploads.
// rd_documents is intentionally NOT consulted here — NAT-Lab's main upload flow
// writes di_submissions only, and an rd_documents-centric count would erase the
// bulk of real activity (same mistake that bit assistant/researchers/:id/report).
//
// Counted file_type values (stored exactly as these strings in di_submissions,
// enforced by the di_submissions_file_type_check CHECK constraint):
//   - DATA
//   - SOP
//   - PRESENTATION
// INVENTORY is excluded (not researcher activity).
// DISCARDED submissions are excluded (matches workspace/overview convention).
//
// Time windows use di_submissions.created_at directly, same convention as
// assistant/workspace/overview. No COALESCE with original_created_at — legacy
// imports will appear by import time, which matches the rest of the assistant.
//
// Additive: no auth layer, no caching, no schema changes.
// Exported as a factory so we reuse the existing pg Pool from server.js.

'use strict';

const express = require('express');

// NAT-Lab recognizes two real institutional sites; EXTERNAL / THERALIA submissions
// still count toward workspace-wide researcher rows (when linked to a researcher in
// the workspace), but affiliation_activity[] is restricted to these two per spec.
const NATLAB_AFFILIATIONS = ['LiU', 'UNAV'];

module.exports = function assistantActivityRouter(pool) {
    const router = express.Router();

    router.get('/', async (req, res) => {
        const wsSlug = (req.query.ws || '').toString().trim();
        if (!wsSlug) return res.status(400).json({ error: 'ws query parameter is required' });

        // By default, drop researchers whose nine tracked counts are all zero —
        // they clutter the ranking and make Telegram reports noisy. Escape hatch:
        // include_zero=true returns every active workspace member (original shape).
        const includeZero = ['1', 'true', 'yes'].includes(
            (req.query.include_zero || '').toString().trim().toLowerCase()
        );

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

            const [researcherRows, affiliationRows] = await Promise.all([
                // Per-researcher file-type activity.
                // LEFT JOIN from allowlist so researchers with zero uploads still
                // appear in the ranking (they sort to the bottom).
                // Workspace-scope via workspace_users so cross-workspace allowlist
                // rows don't leak in — same gate as workspace/overview.
                pool.query(
                    `SELECT
                        a.researcher_id,
                        a.name        AS researcher_name,
                        a.affiliation AS affiliation,
                        COUNT(*) FILTER (WHERE s.file_type = 'DATA')::int         AS data_total,
                        COUNT(*) FILTER (WHERE s.file_type = 'SOP')::int          AS sop_total,
                        COUNT(*) FILTER (WHERE s.file_type = 'PRESENTATION')::int AS presentation_total,
                        COUNT(*) FILTER (
                            WHERE s.file_type = 'DATA'
                              AND s.created_at >= NOW() - INTERVAL '30 days'
                        )::int AS data_30d,
                        COUNT(*) FILTER (
                            WHERE s.file_type = 'SOP'
                              AND s.created_at >= NOW() - INTERVAL '30 days'
                        )::int AS sop_30d,
                        COUNT(*) FILTER (
                            WHERE s.file_type = 'PRESENTATION'
                              AND s.created_at >= NOW() - INTERVAL '30 days'
                        )::int AS presentation_30d,
                        COUNT(*) FILTER (
                            WHERE s.file_type = 'DATA'
                              AND s.created_at >= NOW() - INTERVAL '7 days'
                        )::int AS data_7d,
                        COUNT(*) FILTER (
                            WHERE s.file_type = 'SOP'
                              AND s.created_at >= NOW() - INTERVAL '7 days'
                        )::int AS sop_7d,
                        COUNT(*) FILTER (
                            WHERE s.file_type = 'PRESENTATION'
                              AND s.created_at >= NOW() - INTERVAL '7 days'
                        )::int AS presentation_7d
                       FROM di_allowlist a
                       JOIN workspace_users wu ON wu.user_id = a.researcher_id
                       LEFT JOIN di_submissions s
                              ON s.researcher_id = a.researcher_id
                             AND s.workspace_id  = wu.workspace_id
                             AND s.status <> 'DISCARDED'
                             AND s.file_type IN ('DATA', 'SOP', 'PRESENTATION')
                      WHERE wu.workspace_id = $1
                        AND wu.is_active = TRUE
                        AND a.active     = TRUE
                      GROUP BY a.researcher_id, a.name, a.affiliation
                      ORDER BY data_total DESC,
                               sop_total  DESC,
                               presentation_total DESC,
                               a.name ASC NULLS LAST,
                               a.researcher_id ASC`,
                    [workspaceId]
                ),
                // Per-affiliation file-type activity (LiU, UNAV only).
                // Aff with no uploads won't appear here — we pad zeros below.
                pool.query(
                    `SELECT
                        s.affiliation,
                        COUNT(*) FILTER (WHERE s.file_type = 'DATA')::int         AS data_total,
                        COUNT(*) FILTER (WHERE s.file_type = 'SOP')::int          AS sop_total,
                        COUNT(*) FILTER (WHERE s.file_type = 'PRESENTATION')::int AS presentation_total,
                        COUNT(*) FILTER (
                            WHERE s.file_type = 'DATA'
                              AND s.created_at >= NOW() - INTERVAL '30 days'
                        )::int AS data_30d,
                        COUNT(*) FILTER (
                            WHERE s.file_type = 'SOP'
                              AND s.created_at >= NOW() - INTERVAL '30 days'
                        )::int AS sop_30d,
                        COUNT(*) FILTER (
                            WHERE s.file_type = 'PRESENTATION'
                              AND s.created_at >= NOW() - INTERVAL '30 days'
                        )::int AS presentation_30d,
                        COUNT(*) FILTER (
                            WHERE s.file_type = 'DATA'
                              AND s.created_at >= NOW() - INTERVAL '7 days'
                        )::int AS data_7d,
                        COUNT(*) FILTER (
                            WHERE s.file_type = 'SOP'
                              AND s.created_at >= NOW() - INTERVAL '7 days'
                        )::int AS sop_7d,
                        COUNT(*) FILTER (
                            WHERE s.file_type = 'PRESENTATION'
                              AND s.created_at >= NOW() - INTERVAL '7 days'
                        )::int AS presentation_7d
                       FROM di_submissions s
                      WHERE s.workspace_id = $1
                        AND s.status <> 'DISCARDED'
                        AND s.file_type IN ('DATA', 'SOP', 'PRESENTATION')
                        AND s.affiliation = ANY($2::text[])
                      GROUP BY s.affiliation`,
                    [workspaceId, NATLAB_AFFILIATIONS]
                )
            ]);

            const researcherActivityRankedAll = researcherRows.rows.map(r => ({
                researcher_id:      r.researcher_id,
                researcher_name:    r.researcher_name || null,
                affiliation:        r.affiliation     || null,
                data_total:         r.data_total,
                sop_total:          r.sop_total,
                presentation_total: r.presentation_total,
                data_30d:           r.data_30d,
                sop_30d:            r.sop_30d,
                presentation_30d:   r.presentation_30d,
                data_7d:            r.data_7d,
                sop_7d:             r.sop_7d,
                presentation_7d:    r.presentation_7d
            }));
            const researcherActivityRanked = includeZero
                ? researcherActivityRankedAll
                : researcherActivityRankedAll.filter(r =>
                    r.data_total + r.sop_total + r.presentation_total +
                    r.data_30d  + r.sop_30d  + r.presentation_30d +
                    r.data_7d   + r.sop_7d   + r.presentation_7d > 0
                  );

            // Pad LiU / UNAV rows with zeros when the aggregate returned nothing,
            // so Zoe always gets both affiliations in the response.
            const affMap = Object.fromEntries(affiliationRows.rows.map(r => [r.affiliation, r]));
            const affiliationActivity = NATLAB_AFFILIATIONS.map(aff => {
                const r = affMap[aff];
                if (!r) {
                    return {
                        affiliation:        aff,
                        data_total:         0,
                        sop_total:          0,
                        presentation_total: 0,
                        data_30d:           0,
                        sop_30d:            0,
                        presentation_30d:   0,
                        data_7d:            0,
                        sop_7d:             0,
                        presentation_7d:    0
                    };
                }
                return {
                    affiliation:        aff,
                    data_total:         r.data_total,
                    sop_total:          r.sop_total,
                    presentation_total: r.presentation_total,
                    data_30d:           r.data_30d,
                    sop_30d:            r.sop_30d,
                    presentation_30d:   r.presentation_30d,
                    data_7d:            r.data_7d,
                    sop_7d:             r.sop_7d,
                    presentation_7d:    r.presentation_7d
                };
            });

            res.json({
                workspace: workspaceSlug,
                source: 'di_submissions',
                counted_file_types: ['DATA', 'SOP', 'PRESENTATION'],
                include_zero: includeZero,
                researcher_activity_ranked: researcherActivityRanked,
                affiliation_activity: affiliationActivity,
                updated_at: new Date().toISOString()
            });
        } catch (err) {
            console.error('[ASSISTANT] activity error:', err.message);
            res.status(500).json({ error: 'Failed to build activity report' });
        }
    });

    return router;
};
