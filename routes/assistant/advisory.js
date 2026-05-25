// routes/assistant/advisory.js
//
// Researcher Advisory v2 — MEMORY-aware, evidence-grounded, low-compute.
// Mounted at /api/assistant/researchers (alongside the existing :id/report
// route in researchers.js — Express routes by path pattern, so :id/advisory
// and :id/report do not collide).
//
// Phase 1 scope (this commit):
//   - collectPortalEvidence()
//   - buildTopicMap()
//   - schema/provenance validator (reused from advisory.schema.js)
//   - insufficient_evidence short-circuit
//   - GET /api/assistant/researchers/:id/advisory?ws=natlab
//
// NOT in Phase 1:
//   - MEMORY enrichment (Step 3 in the plan)
//   - PubMed (Step 4)
//   - LLM interpretation (Step 5)
//   - Caching (Phase 2+)
//
// Source hierarchy enforced at function boundaries (defense in depth — the
// LLM prompt repeats the rules but the structural gates live here):
//   - buildTopicMap reads only portal evidence.
//   - PubMed/Memory functions (later phases) will accept high-tier terms
//     ONLY; their function signatures forbid topic creation.

'use strict';

const express = require('express');
const { TERMS } = require('./advisory.terms');
const { validateAdvisory } = require('./advisory.schema');

// Cap per-item text scanned for topic detection. Keeps the regex sweep
// bounded even if a REPORT has hundreds of KB of extracted text. 5000
// chars is enough to surface every domain term that appears in a paper.
const MAX_TEXT_SCAN_CHARS = 5000;

// Snippet returned in portal_evidence.items for downstream display / LLM.
const SNIPPET_CHARS = 500;

// Lookback window for portal evidence. Advisory wants more history than the
// dashboard does — old REPORTs still anchor a researcher's identity.
const EVIDENCE_LOOKBACK_MONTHS = 24;

// Hard cap on items returned in portal_evidence. Prevents huge prompts later
// while keeping enough material for topic detection. Items beyond the cap
// are still counted in n_files / by_type aggregates.
const MAX_PORTAL_ITEMS = 60;

// Statuses we treat as live evidence. Excludes DISCARDED + ARCHIVED.
const LIVE_STATUSES = ['APPROVED', 'PENDING', 'SUBMITTED', 'REVISION_NEEDED'];

// Pre-compile a flat alias→canonical regex map. Word-boundary, case-insens.
// Using \b is safe here because every alias is plain ASCII/Latin tokens.
const ALIAS_REGEX = (() => {
    const out = [];
    for (const t of TERMS) {
        for (const alias of t.aliases) {
            // Escape regex metacharacters in the alias defensively, even
            // though the dictionary is hand-curated.
            const esc = alias.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
            out.push({
                canonical: t.term,
                regex: new RegExp(`\\b${esc}\\b`, 'i')
            });
        }
    }
    return out;
})();

module.exports = function assistantAdvisoryRouter(pool) {
    const router = express.Router();

    // -----------------------------------------------------------------
    // GET /:id/advisory?ws=<slug>
    // -----------------------------------------------------------------
    router.get('/:id/advisory', async (req, res) => {
        const researcherId = (req.params.id || '').toString().trim();
        const wsSlug = (req.query.ws || '').toString().trim();
        if (!wsSlug)       return res.status(400).json({ error: 'ws query parameter is required' });
        if (!researcherId) return res.status(400).json({ error: 'researcher id is required' });

        try {
            // 1) Workspace + researcher resolution. Same shape as
            //    routes/assistant/researchers.js — re-uses the di_allowlist
            //    join so we get the display name + affiliation in one trip.
            const who = await pool.query(
                `SELECT w.id AS workspace_id, w.slug AS workspace_slug,
                        a.researcher_id, a.name, a.affiliation
                   FROM workspaces w
                   JOIN workspace_users wu ON wu.workspace_id = w.id
                   JOIN di_allowlist a     ON a.researcher_id = wu.user_id
                  WHERE w.slug = $1
                    AND w.is_active = TRUE
                    AND wu.user_id = $2
                    AND wu.is_active = TRUE
                  LIMIT 1`,
                [wsSlug, researcherId]
            );
            if (who.rows.length === 0) {
                const wsCheck = await pool.query(
                    `SELECT 1 FROM workspaces WHERE slug = $1 AND is_active = TRUE LIMIT 1`,
                    [wsSlug]
                );
                if (wsCheck.rows.length === 0) {
                    return res.status(404).json({ error: 'Workspace not found' });
                }
                return res.status(404).json({ error: 'Researcher not found in workspace' });
            }
            const meta = who.rows[0];
            const researcher = {
                id: meta.researcher_id,
                name: meta.name,
                affiliation: meta.affiliation
            };

            // 2) Portal evidence — single SELECT with optional LEFT JOIN to
            //    the assistant_file_index/_text pair. The joins gracefully
            //    degrade to NULL extracted_text if those tables are absent
            //    on this deploy (migration 065 may be pending).
            const portal = await collectPortalEvidence(pool, meta.workspace_id, researcherId);

            // 3) Topic map (deterministic). PORTAL only.
            const topicMap = buildTopicMap(portal);

            const generated_at = new Date().toISOString();

            // 4) Insufficient evidence short-circuit. No MEMORY/PubMed/LLM
            //    will ever run for a researcher without high-tier topics.
            if (topicMap.high.length === 0) {
                const out = {
                    advisory_status: 'insufficient_evidence',
                    reason: 'No topic met the high-confidence threshold ' +
                            '(≥3 files with REPORT/SOP backing). MEMORY/PubMed not consulted.',
                    researcher,
                    generated_at,
                    pipeline_stage: 'portal_only',
                    topic_map: topicMap,
                    portal_evidence: portal
                };
                const v = validateAdvisory(out);
                if (!v.ok) {
                    // Structural bug in our own output — log and still send,
                    // but flag so it's visible in monitoring.
                    console.error('[ADVISORY] self-validation failed (insufficient_evidence branch):', v.errors);
                    out.self_validation_errors = v.errors;
                }
                return res.json(out);
            }

            // 5) Phase 1 stops here. Later phases will attachMemory(),
            //    queryPubMed(), callZoeAdvisory(), each gated on
            //    topicMap.high — never on medium/low/memory-only topics.
            const out = {
                advisory_status: 'topic_map_only',
                researcher,
                generated_at,
                pipeline_stage: 'portal_only',
                topic_map: topicMap,
                portal_evidence: portal
            };
            const v = validateAdvisory(out);
            if (!v.ok) {
                console.error('[ADVISORY] self-validation failed (topic_map_only branch):', v.errors);
                out.self_validation_errors = v.errors;
            }
            return res.json(out);

        } catch (err) {
            console.error('[ADVISORY] error:', err && err.message);
            return res.status(500).json({ error: 'Advisory failed' });
        }
    });

    return router;
};

// =====================================================================
// collectPortalEvidence(pool, workspaceId, researcherId)
//   Returns { n_files, by_type, items: [...] }.
//   items capped at MAX_PORTAL_ITEMS, ordered newest first.
//
//   Excluded:
//     - status IN (DISCARDED, ARCHIVED)
//     - file_type='REPORT' AND report_thread_role='NOTE' (those are
//       comment-only thread artifacts, not files)
//     - rows with NULL original_filename (defensive; NOTE rows etc.)
// =====================================================================
async function collectPortalEvidence(pool, workspaceId, researcherId) {
    // Detect optional indexed-text tables. If absent (pre-migration-065),
    // extracted_text stays NULL — the rest of the pipeline degrades to
    // filename-only topic detection.
    let hasIndex = false;
    try {
        const r = await pool.query(
            `SELECT to_regclass('public.assistant_file_index') AS i,
                    to_regclass('public.assistant_file_text')  AS t`
        );
        hasIndex = !!(r.rows[0] && r.rows[0].i && r.rows[0].t);
    } catch (_) { /* leave hasIndex=false */ }

    // Detect the report_thread_role column. If absent (pre-migration-070)
    // we drop the NOTE filter — there can be no NOTE rows on that deploy.
    let hasThreadCols = false;
    try {
        const r = await pool.query(
            `SELECT 1
               FROM information_schema.columns
              WHERE table_schema='public' AND table_name='di_submissions'
                AND column_name='report_thread_role'
              LIMIT 1`
        );
        hasThreadCols = r.rows.length > 0;
    } catch (_) { /* leave false */ }

    const noteFilter = hasThreadCols
        ? `AND COALESCE(s.report_thread_role,'') <> 'NOTE'`
        : '';

    const textJoin = hasIndex
        ? `LEFT JOIN assistant_file_index i ON i.r2_object_key = s.r2_object_key
           LEFT JOIN assistant_file_text  t ON t.file_id        = i.id`
        : '';
    const textCol = hasIndex
        ? `, t.extracted_text AS extracted_text`
        : `, NULL::text AS extracted_text`;

    // Aggregate counts (n_files, by_type) come from the full filtered set,
    // not the capped items list — so the aggregate stays honest even if
    // the researcher has more files than MAX_PORTAL_ITEMS.
    const agg = await pool.query(
        `SELECT s.file_type, COUNT(*)::int AS n
           FROM di_submissions s
          WHERE s.workspace_id = $1
            AND s.researcher_id = $2
            AND s.status = ANY($3::text[])
            AND s.original_filename IS NOT NULL
            AND s.created_at >= NOW() - make_interval(months => $4)
            ${noteFilter}
          GROUP BY s.file_type`,
        [workspaceId, researcherId, LIVE_STATUSES, EVIDENCE_LOOKBACK_MONTHS]
    );
    const by_type = {};
    let n_files = 0;
    for (const row of agg.rows) {
        by_type[row.file_type || 'UNKNOWN'] = row.n;
        n_files += row.n;
    }

    const itemsRes = await pool.query(
        `SELECT s.submission_id, s.file_type, s.original_filename,
                s.created_at, s.status
                ${textCol}
           FROM di_submissions s
           ${textJoin}
          WHERE s.workspace_id = $1
            AND s.researcher_id = $2
            AND s.status = ANY($3::text[])
            AND s.original_filename IS NOT NULL
            AND s.created_at >= NOW() - make_interval(months => $4)
            ${noteFilter}
          ORDER BY s.created_at DESC
          LIMIT $5`,
        [workspaceId, researcherId, LIVE_STATUSES, EVIDENCE_LOOKBACK_MONTHS, MAX_PORTAL_ITEMS]
    );

    const items = itemsRes.rows.map(r => ({
        submission_id: r.submission_id,
        file_type: r.file_type,
        original_filename: r.original_filename,
        created_at: r.created_at ? new Date(r.created_at).toISOString() : null,
        status: r.status,
        extracted_text_snippet: snippetFromText(r.extracted_text)
    }));

    return { n_files, by_type, items, indexed_text_available: hasIndex };
}

function snippetFromText(text) {
    if (!text) return null;
    const s = String(text).replace(/\s+/g, ' ').trim();
    if (s.length <= SNIPPET_CHARS) return s;
    return s.slice(0, SNIPPET_CHARS).trim() + '…';
}

// =====================================================================
// buildTopicMap(portalEvidence)
//   Deterministic, no I/O. Reads ONLY portal.items + the local term dict.
//   Returns { high[], medium[], low[] }.
//
//   Confidence ladder (per design):
//     high   = ≥3 distinct files AND ≥1 of those is REPORT or SOP
//     medium = ≥2 distinct files, no REPORT/SOP backing
//     low    = 1 file only (filename or text)
// =====================================================================
function buildTopicMap(portal) {
    // For each canonical term we accumulate the set of submission_ids
    // where any of its aliases matched, plus whether any of those rows
    // was a REPORT or SOP. Using a Map keyed by canonical term keeps
    // per-term aggregation O(items × aliases) — fine for ≤60 items × ~150
    // aliases.
    const acc = new Map();   // term → { sids: Set, reportOrSop: bool }

    for (const item of (portal.items || [])) {
        const filename = (item.original_filename || '');
        const text     = (item.extracted_text_snippet || '').slice(0, MAX_TEXT_SCAN_CHARS);
        const haystack = (filename + ' ' + text).toLowerCase();

        for (const ar of ALIAS_REGEX) {
            if (ar.regex.test(haystack)) {
                let cur = acc.get(ar.canonical);
                if (!cur) {
                    cur = { sids: new Set(), reportOrSop: false };
                    acc.set(ar.canonical, cur);
                }
                cur.sids.add(item.submission_id);
                if (item.file_type === 'REPORT' || item.file_type === 'SOP') {
                    cur.reportOrSop = true;
                }
            }
        }
    }

    const high = [], medium = [], low = [];
    for (const [term, info] of acc) {
        const ids = Array.from(info.sids);
        const entry = {
            term,
            n_files: ids.length,
            evidence_submission_ids: ids,
            report_backed: info.reportOrSop
        };
        if (ids.length >= 3 && info.reportOrSop) {
            high.push(entry);
        } else if (ids.length >= 2) {
            medium.push(entry);
        } else {
            low.push(entry);
        }
    }

    // Stable, deterministic ordering: by n_files desc, then term asc.
    const byCount = (a, b) => (b.n_files - a.n_files) || a.term.localeCompare(b.term);
    high.sort(byCount); medium.sort(byCount); low.sort(byCount);

    return { high, medium, low };
}
