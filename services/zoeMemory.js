// services/zoeMemory.js
//
// Zoe scientific memory system. Builds four tiers of compact summaries
// from the existing data already in the portal:
//
//   1. file memory       — one per indexed file
//   2. researcher memory — aggregated per researcher_code
//   3. project memory    — grouped by project signals
//   4. workspace memory  — single row per workspace
//
// Plus a job log (assistant_memory_jobs) that records weekly / rebuild
// runs.
//
// Design goals:
//   - Deterministic, rule-based aggregation. No LLM calls in the default
//     path — every signal is derived from columns we already populate
//     (assistant_file_index, assistant_file_summaries,
//     assistant_report_intelligence, di_submissions).
//   - Skip unchanged files. Each row tracks source_updated_at so the
//     weekly job can early-out when nothing meaningful has changed.
//   - Small footprint. memory_json is a compact object, summary_text
//     is a short prose paragraph, evidence_file_ids is a UUID array.
//   - Idempotent. Re-running rebuildAll never throws even on repeated
//     calls; per-row UPSERTs keyed on (workspace_slug, scope_key).
//
// Public surface (consumed by routes/assistant/memory.js):
//   - ensureSchema(pool)               — runtime DDL fallback
//   - buildFileMemory(deps, fileId)
//   - buildResearcherMemory(deps, code, wsSlug)
//   - buildProjectMemory(deps, projectName, wsSlug)
//   - buildWorkspaceMemory(deps, wsSlug)
//   - runWeeklyUpdate(deps, wsSlug, opts)
//   - rebuildAll(deps, wsSlug, opts)
//   - getStatus(deps, wsSlug)
//
// `deps` is always { pool }.

'use strict';

// ===========================================================================
// Schema ensure (runtime fallback for db/migrate.js)
// ===========================================================================
async function ensureSchema(pool) {
    if (pool.__zoeMemorySchemaPromise) return pool.__zoeMemorySchemaPromise;
    pool.__zoeMemorySchemaPromise = (async () => {
        const stmts = [
            `CREATE TABLE IF NOT EXISTS assistant_file_memory (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                workspace_slug TEXT NOT NULL,
                file_id UUID NOT NULL UNIQUE,
                memory_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                summary_text TEXT,
                evidence_file_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
                confidence NUMERIC,
                source_updated_at TIMESTAMPTZ,
                memory_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )`,
            `CREATE INDEX IF NOT EXISTS idx_afm_ws ON assistant_file_memory (workspace_slug)`,
            `CREATE INDEX IF NOT EXISTS idx_afm_updated ON assistant_file_memory (memory_updated_at)`,
            `CREATE TABLE IF NOT EXISTS assistant_researcher_memory (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                workspace_slug TEXT NOT NULL,
                researcher_code TEXT NOT NULL,
                memory_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                summary_text TEXT,
                evidence_file_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
                confidence NUMERIC,
                source_updated_at TIMESTAMPTZ,
                memory_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE (workspace_slug, researcher_code)
            )`,
            `CREATE INDEX IF NOT EXISTS idx_arm_ws ON assistant_researcher_memory (workspace_slug)`,
            `CREATE TABLE IF NOT EXISTS assistant_project_memory (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                workspace_slug TEXT NOT NULL,
                project_name TEXT NOT NULL,
                memory_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                summary_text TEXT,
                evidence_file_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
                confidence NUMERIC,
                source_updated_at TIMESTAMPTZ,
                memory_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                UNIQUE (workspace_slug, project_name)
            )`,
            `CREATE INDEX IF NOT EXISTS idx_apm_ws ON assistant_project_memory (workspace_slug)`,
            `CREATE TABLE IF NOT EXISTS assistant_workspace_memory (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                workspace_slug TEXT NOT NULL UNIQUE,
                memory_json JSONB NOT NULL DEFAULT '{}'::jsonb,
                summary_text TEXT,
                evidence_file_ids JSONB NOT NULL DEFAULT '[]'::jsonb,
                confidence NUMERIC,
                source_updated_at TIMESTAMPTZ,
                memory_updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
            )`,
            `CREATE TABLE IF NOT EXISTS assistant_memory_jobs (
                id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
                workspace_slug TEXT,
                job_kind TEXT NOT NULL,
                job_status TEXT NOT NULL,
                started_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
                finished_at TIMESTAMPTZ,
                files_processed INT DEFAULT 0,
                researchers_processed INT DEFAULT 0,
                projects_processed INT DEFAULT 0,
                workspace_processed BOOLEAN DEFAULT FALSE,
                error_text TEXT,
                notes JSONB DEFAULT '{}'::jsonb
            )`,
            `CREATE INDEX IF NOT EXISTS idx_amj_ws ON assistant_memory_jobs (workspace_slug, started_at DESC)`,
            `CREATE INDEX IF NOT EXISTS idx_amj_kind ON assistant_memory_jobs (job_kind, started_at DESC)`,
        ];
        for (const s of stmts) {
            try { await pool.query(s); }
            catch (e) { console.warn('[ZOE-MEMORY] schema ensure stmt failed:', e && e.message); }
        }
        return true;
    })().catch(e => {
        console.error('[ZOE-MEMORY] ensureSchema failed:', e && e.message);
        return false;
    });
    return pool.__zoeMemorySchemaPromise;
}

// ===========================================================================
// Shared deterministic vocabularies
// ===========================================================================

const METHOD_VOCAB = [
    'qPCR', 'MALDI', 'LC-MS', 'CFU', 'assay', 'fluorescence', 'microscopy',
    'biodistribution', 'infection model', 'purification', 'synthesis',
    'PCR', 'ELISA', 'flow cytometry', 'sequencing', 'NMR', 'HPLC',
    'western blot', 'cell culture'
];

const ORGANISM_VOCAB = [
    'mouse', 'rat', 'human', 'E. coli', 'S. aureus', 'P. aeruginosa',
    'C. albicans', 'A. baumannii', 'in vivo', 'in vitro', 'macrophage',
    'fibroblast', 'HEK293', 'HeLa'
];

const GLP_VOCAB = [
    'SOP', 'traceability', 'approval', 'revision', 'deviation', 'ALCOA',
    'raw data', 'control', 'replicate', 'audit'
];

// ===========================================================================
// FILE MEMORY
// ===========================================================================
//
// Per-file memory rolls together:
//   - assistant_file_index   (researcher_code, file_type, year, topic, etc.)
//   - assistant_file_summaries (key_methods/results/data_types/gaps)
//   - assistant_report_intelligence (REPORT-only signals + project hints)
//   - di_submissions          (status, report_subcategory, report_project)
//
// Skip-unchanged: source_updated_at is the max of the underlying rows'
// updated_at / indexed_at. We compare to the stored value and short-
// circuit when equal.
async function buildFileMemory(deps, fileId, opts) {
    const { pool } = deps;
    const force = !!(opts && opts.force);
    const r = await pool.query(`
        SELECT i.id, i.r2_key, i.filename, i.file_ext, i.file_type,
               i.workspace_slug, i.researcher_code, i.researcher_name,
               i.affiliation, i.year, i.status, i.topic, i.tags,
               i.text_status, i.text_char_count, i.indexed_at,
               i.updated_at AS index_updated_at,
               s.summary_short, s.summary_detailed,
               s.key_methods, s.key_results, s.key_data_types,
               s.detected_entities, s.detected_assays, s.detected_controls,
               s.detected_gaps, s.updated_at AS summary_updated_at,
               t.full_text,
               ari.report_subcategory, ari.project AS ari_project,
               ari.key_conclusions, ari.limitations, ari.future_work,
               ari.related_methods AS ari_methods, ari.related_assays AS ari_assays,
               ari.detected_project_themes, ari.detected_keywords,
               ari.scientific_maturity_signal, ari.glp_relevance_signal,
               ari.updated_at AS ari_updated_at,
               sub.report_project AS sub_project, sub.report_subcategory AS sub_subcategory,
               sub.report_supervisor, sub.report_period_start, sub.report_period_end
          FROM assistant_file_index i
          LEFT JOIN assistant_file_summaries s ON s.file_id = i.id
          LEFT JOIN assistant_file_text       t ON t.file_id = i.id
          LEFT JOIN di_submissions sub ON sub.r2_object_key = i.r2_key
          LEFT JOIN assistant_report_intelligence ari ON ari.submission_id = sub.submission_id
         WHERE i.id = $1
         LIMIT 1`, [fileId]);
    if (r.rows.length === 0) return { ok: false, reason: 'not_found' };
    const row = r.rows[0];

    // source_updated_at: max of the contributing rows' timestamps. Used
    // for skip-unchanged.
    const candidates = [
        row.index_updated_at, row.indexed_at, row.summary_updated_at, row.ari_updated_at
    ].filter(Boolean).map(d => new Date(d).getTime());
    const sourceUpdatedAt = candidates.length ? new Date(Math.max(...candidates)) : null;

    if (!force) {
        const prev = await pool.query(
            `SELECT source_updated_at FROM assistant_file_memory WHERE file_id = $1 LIMIT 1`,
            [fileId]
        );
        if (prev.rows.length && prev.rows[0].source_updated_at && sourceUpdatedAt) {
            if (new Date(prev.rows[0].source_updated_at).getTime() >= sourceUpdatedAt.getTime()) {
                return { ok: true, skipped: true, reason: 'unchanged' };
            }
        }
    }

    // Pull keywords from text (cheap regex pass). Limited to 80k chars so
    // huge PDFs don't burn CPU.
    const text = (row.full_text || '').slice(0, 80_000);
    const methods = uniqMatch(text, METHOD_VOCAB);
    const organisms = uniqMatch(text, ORGANISM_VOCAB);
    const glpHits = GLP_VOCAB.reduce((sum, w) => sum + countKw(text, w), 0);

    // Project hint: prefer the REPORT row's report_project, then the
    // intelligence row's project field, then assistant_file_index.topic.
    const project = (row.sub_project || row.ari_project || row.topic || null) || null;

    const memory = {
        file_type:           row.file_type || null,
        researcher_code:     row.researcher_code || null,
        researcher_name:     row.researcher_name || null,
        affiliation:         row.affiliation || null,
        year:                row.year || null,
        status:              row.status || null,
        topic:               row.topic || null,
        project:             project,
        report_subcategory:  row.report_subcategory || row.sub_subcategory || null,
        supervisor:          row.report_supervisor || null,
        reporting_period: {
            start: row.report_period_start ? new Date(row.report_period_start).toISOString().slice(0,10) : null,
            end:   row.report_period_end   ? new Date(row.report_period_end).toISOString().slice(0,10)   : null
        },
        experimental_methods: methods,
        organisms_or_samples: organisms,
        key_findings:        firstNonEmpty([row.key_results, row.summary_short]) || dedupArr(row.key_conclusions),
        glp_relevance:       row.glp_relevance_signal
                             || (glpHits >= 5 ? 'high' : glpHits >= 2 ? 'medium' : 'low'),
        scientific_maturity: row.scientific_maturity_signal || null,
        missing_information: row.detected_gaps || row.limitations || [],
        keywords:            uniqArr([
                                ...(row.detected_keywords || []),
                                ...(row.detected_project_themes || []),
                                ...methods,
                                ...organisms
                             ]).slice(0, 30),
        text_status:         row.text_status || null,
        text_char_count:     row.text_char_count || 0
    };

    const summary = row.summary_short
        || (memory.key_findings && memory.key_findings.length
            ? (Array.isArray(memory.key_findings) ? memory.key_findings.slice(0,2).join(' ') : memory.key_findings.toString())
            : row.summary_detailed || row.filename);

    const confidence = scoreConfidence([
        !!row.summary_short, !!row.summary_detailed,
        !!row.full_text, methods.length > 0, organisms.length > 0,
        !!row.ari_project, !!row.detected_keywords
    ]);

    await pool.query(`
        INSERT INTO assistant_file_memory
            (workspace_slug, file_id, memory_json, summary_text,
             evidence_file_ids, confidence, source_updated_at,
             memory_updated_at)
        VALUES ($1, $2, $3::jsonb, $4, $5::jsonb, $6, $7, NOW())
        ON CONFLICT (file_id) DO UPDATE SET
            workspace_slug = EXCLUDED.workspace_slug,
            memory_json = EXCLUDED.memory_json,
            summary_text = EXCLUDED.summary_text,
            evidence_file_ids = EXCLUDED.evidence_file_ids,
            confidence = EXCLUDED.confidence,
            source_updated_at = EXCLUDED.source_updated_at,
            memory_updated_at = NOW()`,
        [
            row.workspace_slug || 'natlab',
            fileId,
            JSON.stringify(memory),
            truncate(summary, 1000),
            JSON.stringify([fileId]),
            confidence,
            sourceUpdatedAt
        ]
    );
    return { ok: true, file_id: fileId, project, methods, organisms };
}

// ===========================================================================
// RESEARCHER MEMORY
// ===========================================================================
//
// Aggregates from di_submissions + assistant_file_memory (already built)
// for one researcher_code. Always rebuilds the row (cheap, single
// research per call).
async function buildResearcherMemory(deps, researcherCode, workspaceSlug) {
    const { pool } = deps;
    const code = String(researcherCode || '').trim().toUpperCase();
    const ws   = String(workspaceSlug   || 'natlab').trim();
    if (!code) return { ok: false, reason: 'no_code' };

    // Pull canonical activity counts from di_submissions.
    const counts = await pool.query(`
        SELECT
            COUNT(*) FILTER (WHERE file_type = 'DATA'         AND status <> 'DISCARDED')::int AS data_total,
            COUNT(*) FILTER (WHERE file_type = 'SOP'          AND status <> 'DISCARDED')::int AS sop_total,
            COUNT(*) FILTER (WHERE file_type = 'PRESENTATION' AND status <> 'DISCARDED')::int AS pres_total,
            COUNT(*) FILTER (WHERE file_type = 'REPORT'       AND status <> 'DISCARDED')::int AS report_total,
            COUNT(*) FILTER (WHERE status <> 'DISCARDED' AND created_at >= NOW() - INTERVAL '30 days')::int AS uploads_30d,
            MAX(created_at) AS last_upload_at
          FROM di_submissions
         WHERE researcher_id = $1
        `, [code]);

    // Pull aggregate signals from per-file memory.
    const agg = await pool.query(`
        SELECT memory_json, summary_text, file_id, memory_updated_at
          FROM assistant_file_memory
         WHERE workspace_slug = $1
           AND (memory_json->>'researcher_code') = $2`,
        [ws, code]);

    // Pull recent intelligence rows for richer scientific signal.
    const intel = await pool.query(`
        SELECT ari.report_subcategory, ari.project, ari.title, ari.short_summary,
               ari.limitations, ari.future_work, ari.detected_project_themes,
               ari.detected_keywords, ari.scientific_maturity_signal,
               ari.glp_relevance_signal, ari.related_methods, ari.related_assays,
               ari.updated_at
          FROM assistant_report_intelligence ari
          JOIN di_submissions s ON s.submission_id = ari.submission_id
         WHERE ari.researcher_id = $1
         ORDER BY ari.updated_at DESC
         LIMIT 20`, [code]);

    // Aggregate across per-file memory.
    const projectsSet = new Set();
    const methodsTally = new Map();
    const organismsTally = new Map();
    const recurringGapsTally = new Map();
    const keywordsTally = new Map();
    const evidence = [];
    for (const row of agg.rows) {
        const m = row.memory_json || {};
        if (m.project) projectsSet.add(m.project);
        (m.experimental_methods || []).forEach(x => bump(methodsTally, x));
        (m.organisms_or_samples || []).forEach(x => bump(organismsTally, x));
        const missing = Array.isArray(m.missing_information) ? m.missing_information : [];
        missing.forEach(x => bump(recurringGapsTally, typeof x === 'string' ? x : x?.label || ''));
        (m.keywords || []).forEach(x => bump(keywordsTally, x));
        evidence.push(row.file_id);
    }
    // GLP maturity heuristic — average over file memory.
    let glpScore = 0, glpCount = 0;
    for (const row of agg.rows) {
        const v = (row.memory_json && row.memory_json.glp_relevance) || null;
        if (v === 'high') { glpScore += 3; glpCount++; }
        else if (v === 'medium') { glpScore += 2; glpCount++; }
        else if (v === 'low') { glpScore += 1; glpCount++; }
    }
    const glpAvg = glpCount ? glpScore / glpCount : 0;
    const glpLabel = glpAvg >= 2.5 ? 'high' : glpAvg >= 1.6 ? 'medium' : (glpCount ? 'low' : 'unknown');

    // Recent uploads (last 5).
    const recent = await pool.query(`
        SELECT submission_id, original_filename, file_type, created_at, status
          FROM di_submissions
         WHERE researcher_id = $1
           AND status <> 'DISCARDED'
         ORDER BY created_at DESC LIMIT 5`, [code]);

    const memory = {
        researcher_code:  code,
        workspace_slug:   ws,
        upload_counts:    counts.rows[0] || {},
        active_projects:  Array.from(projectsSet).slice(0, 10),
        main_methods:     topN(methodsTally, 10),
        organisms_or_models: topN(organismsTally, 10),
        technical_strengths: deriveStrengths(methodsTally, organismsTally),
        recurring_issues: topN(recurringGapsTally, 5).filter(Boolean),
        glp_maturity_signal: glpLabel,
        recent_uploads:   recent.rows.map(r => ({
            submission_id: r.submission_id,
            filename: r.original_filename,
            file_type: r.file_type,
            status: r.status,
            created_at: r.created_at ? new Date(r.created_at).toISOString() : null
        })),
        open_scientific_questions: collectFutureWork(intel.rows).slice(0, 6),
        important_files: evidence.slice(0, 12),
        report_intelligence_count: intel.rows.length
    };

    const summary = composeResearcherSummary(memory);
    const conf = scoreConfidence([
        agg.rows.length > 0,
        intel.rows.length > 0,
        memory.main_methods.length > 0,
        memory.active_projects.length > 0,
        memory.recent_uploads.length > 0
    ]);

    const sourceUpdatedAt = mostRecent([
        counts.rows[0]?.last_upload_at,
        ...agg.rows.map(r => r.memory_updated_at),
        ...intel.rows.map(r => r.updated_at)
    ]);

    await pool.query(`
        INSERT INTO assistant_researcher_memory
            (workspace_slug, researcher_code, memory_json, summary_text,
             evidence_file_ids, confidence, source_updated_at,
             memory_updated_at)
        VALUES ($1, $2, $3::jsonb, $4, $5::jsonb, $6, $7, NOW())
        ON CONFLICT (workspace_slug, researcher_code) DO UPDATE SET
            memory_json = EXCLUDED.memory_json,
            summary_text = EXCLUDED.summary_text,
            evidence_file_ids = EXCLUDED.evidence_file_ids,
            confidence = EXCLUDED.confidence,
            source_updated_at = EXCLUDED.source_updated_at,
            memory_updated_at = NOW()`,
        [ws, code, JSON.stringify(memory), truncate(summary, 1500),
         JSON.stringify(evidence.slice(0, 50)), conf, sourceUpdatedAt]
    );
    return { ok: true, researcher_code: code, files: agg.rows.length };
}

// ===========================================================================
// PROJECT MEMORY
// ===========================================================================
async function buildProjectMemory(deps, projectName, workspaceSlug) {
    const { pool } = deps;
    const name = String(projectName || '').trim();
    const ws = String(workspaceSlug || 'natlab').trim();
    if (!name) return { ok: false, reason: 'no_project' };

    // Files attributed to this project, via file memory.
    const files = await pool.query(`
        SELECT file_id, memory_json, summary_text
          FROM assistant_file_memory
         WHERE workspace_slug = $1
           AND (memory_json->>'project') = $2`,
        [ws, name]);

    if (files.rows.length === 0) {
        // No project memory for projects with no attributed files; clear
        // any stale row so the read endpoint returns nothing.
        await pool.query(
            `DELETE FROM assistant_project_memory WHERE workspace_slug = $1 AND project_name = $2`,
            [ws, name]
        );
        return { ok: true, project_name: name, files: 0, deleted: true };
    }

    const researchers = new Set();
    const methodsTally = new Map();
    const goalsCollector = [];
    const fileTypeTally = new Map();
    const gapsTally = new Map();
    const evidence = [];
    let latest = null;
    for (const row of files.rows) {
        const m = row.memory_json || {};
        if (m.researcher_code) researchers.add(m.researcher_code);
        (m.experimental_methods || []).forEach(x => bump(methodsTally, x));
        if (m.file_type) bump(fileTypeTally, m.file_type);
        if (row.summary_text) goalsCollector.push(row.summary_text);
        const gaps = Array.isArray(m.missing_information) ? m.missing_information : [];
        gaps.forEach(g => bump(gapsTally, typeof g === 'string' ? g : g?.label || ''));
        evidence.push(row.file_id);
    }

    // Pick the most representative summary as core scientific goal.
    const coreGoal = goalsCollector.length
        ? mostInformative(goalsCollector)
        : null;

    const memory = {
        project_name:         name,
        workspace_slug:       ws,
        related_researchers:  Array.from(researchers).sort(),
        core_scientific_goal: coreGoal,
        methods_used:         topN(methodsTally, 12),
        file_type_counts:     Object.fromEntries(fileTypeTally),
        related_sops:         filterByType(files.rows, 'SOP', 10),
        related_data:         filterByType(files.rows, 'DATA', 10),
        related_presentations:filterByType(files.rows, 'PRESENTATION', 10),
        related_reports:      filterByType(files.rows, 'REPORT', 10),
        gaps_or_risks:        topN(gapsTally, 6).filter(Boolean),
        file_count:           files.rows.length
    };

    const summary = composeProjectSummary(memory);
    const conf = scoreConfidence([
        files.rows.length >= 1,
        files.rows.length >= 3,
        researchers.size >= 1,
        memory.methods_used.length > 0,
        !!coreGoal
    ]);

    await pool.query(`
        INSERT INTO assistant_project_memory
            (workspace_slug, project_name, memory_json, summary_text,
             evidence_file_ids, confidence, source_updated_at,
             memory_updated_at)
        VALUES ($1, $2, $3::jsonb, $4, $5::jsonb, $6, $7, NOW())
        ON CONFLICT (workspace_slug, project_name) DO UPDATE SET
            memory_json = EXCLUDED.memory_json,
            summary_text = EXCLUDED.summary_text,
            evidence_file_ids = EXCLUDED.evidence_file_ids,
            confidence = EXCLUDED.confidence,
            source_updated_at = EXCLUDED.source_updated_at,
            memory_updated_at = NOW()`,
        [ws, name, JSON.stringify(memory), truncate(summary, 1500),
         JSON.stringify(evidence.slice(0, 80)), conf, null]
    );
    return { ok: true, project_name: name, files: files.rows.length };
}

// ===========================================================================
// WORKSPACE MEMORY
// ===========================================================================
async function buildWorkspaceMemory(deps, workspaceSlug) {
    const { pool } = deps;
    const ws = String(workspaceSlug || 'natlab').trim();

    // Cross-researcher / cross-file aggregates. Single big query so we
    // don't fan out across many round-trips.
    //
    // NOTE: assistant_file_memory has no researcher_code / file_type /
    // project columns of its own — those live inside memory_json. The
    // GROUP BY here reads them via memory_json->>'researcher_code'.
    const stats = await pool.query(`
        WITH base AS (
            SELECT (a.memory_json->>'researcher_code') AS researcher_code,
                   a.memory_json
              FROM assistant_file_memory a
             WHERE a.workspace_slug = $1
        ),
        agg AS (
            SELECT researcher_code,
                   COUNT(*) AS file_count,
                   COALESCE(json_agg(DISTINCT memory_json->'experimental_methods')
                              FILTER (WHERE memory_json ? 'experimental_methods'),
                            '[]'::json) AS methods_blobs,
                   COALESCE(json_agg(DISTINCT memory_json->>'project')
                              FILTER (WHERE (memory_json->>'project') IS NOT NULL),
                            '[]'::json) AS projects
              FROM base
             GROUP BY researcher_code
        )
        SELECT * FROM agg`, [ws]);

    const counts = await pool.query(`
        SELECT
            COUNT(DISTINCT researcher_id)::int AS active_researchers,
            COUNT(*) FILTER (WHERE file_type='DATA'         AND status<>'DISCARDED')::int AS data_total,
            COUNT(*) FILTER (WHERE file_type='SOP'          AND status<>'DISCARDED')::int AS sop_total,
            COUNT(*) FILTER (WHERE file_type='PRESENTATION' AND status<>'DISCARDED')::int AS pres_total,
            COUNT(*) FILTER (WHERE file_type='REPORT'       AND status<>'DISCARDED')::int AS report_total,
            COUNT(*) FILTER (WHERE created_at >= NOW() - INTERVAL '14 days' AND status<>'DISCARDED')::int AS uploads_14d
          FROM di_submissions
         WHERE workspace_id = (SELECT id FROM workspaces WHERE slug = $1 LIMIT 1)`, [ws]);

    // GLP coverage hint: ratio of researchers with SOPs vs those who upload only DATA.
    const sopCoverage = await pool.query(`
        SELECT COUNT(DISTINCT researcher_id) FILTER (WHERE has_sop) AS with_sop,
               COUNT(DISTINCT researcher_id) AS total
          FROM (
            SELECT researcher_id,
                   bool_or(file_type='SOP') AS has_sop
              FROM di_submissions
             WHERE status<>'DISCARDED'
               AND workspace_id = (SELECT id FROM workspaces WHERE slug = $1 LIMIT 1)
             GROUP BY researcher_id
          ) sub`, [ws]);
    const c = counts.rows[0] || {};
    const sopCov = sopCoverage.rows[0] || {};

    // Method tally across all researchers.
    const methodTally = new Map();
    const projectSet = new Set();
    const researcherSet = new Set();
    for (const r of stats.rows) {
        if (r.researcher_code) researcherSet.add(r.researcher_code);
        const blobs = r.methods_blobs || [];
        for (const blob of blobs) {
            if (Array.isArray(blob)) blob.forEach(m => bump(methodTally, m));
        }
        const projs = r.projects || [];
        projs.forEach(p => { if (p) projectSet.add(p); });
    }

    const memory = {
        workspace_slug:           ws,
        active_researchers:       Array.from(researcherSet).sort(),
        active_scientific_areas:  Array.from(projectSet).sort().slice(0, 25),
        common_methods:           topN(methodTally, 15),
        upload_counts:            c,
        glp_status: {
            researchers_with_sop: Number(sopCov.with_sop || 0),
            total_researchers:    Number(sopCov.total || 0),
            sop_coverage_ratio:   sopCov.total ? Number(sopCov.with_sop) / Number(sopCov.total) : 0
        },
        weak_documentation_areas: deriveWeakAreas(researcherSet, sopCov),
        important_recent_changes: c.uploads_14d || 0,
        file_total_tracked:       Number(c.data_total||0) + Number(c.sop_total||0) + Number(c.pres_total||0) + Number(c.report_total||0)
    };

    const summary = composeWorkspaceSummary(memory);
    const conf = scoreConfidence([
        researcherSet.size >= 1,
        projectSet.size >= 1,
        methodTally.size >= 3,
        memory.glp_status.sop_coverage_ratio > 0,
        (memory.file_total_tracked || 0) >= 10
    ]);

    await pool.query(`
        INSERT INTO assistant_workspace_memory
            (workspace_slug, memory_json, summary_text,
             evidence_file_ids, confidence, source_updated_at,
             memory_updated_at)
        VALUES ($1, $2::jsonb, $3, $4::jsonb, $5, NOW(), NOW())
        ON CONFLICT (workspace_slug) DO UPDATE SET
            memory_json = EXCLUDED.memory_json,
            summary_text = EXCLUDED.summary_text,
            evidence_file_ids = EXCLUDED.evidence_file_ids,
            confidence = EXCLUDED.confidence,
            source_updated_at = NOW(),
            memory_updated_at = NOW()`,
        [ws, JSON.stringify(memory), truncate(summary, 1500),
         JSON.stringify([]), conf]
    );
    return { ok: true, workspace_slug: ws, researchers: researcherSet.size, projects: projectSet.size };
}

// ===========================================================================
// Orchestration: weekly update / full rebuild
// ===========================================================================
async function runWeeklyUpdate(deps, workspaceSlug, opts) {
    const { pool } = deps;
    const ws = String(workspaceSlug || 'natlab').trim();
    const limit = Math.min(Math.max(parseInt(opts?.limit, 10) || 200, 1), 1000);
    const job = await startJob(pool, ws, 'weekly');
    let stats = { files: 0, researchers: 0, projects: 0, workspace: false };
    try {
        // 1) Files modified since the most recent memory_updated_at, OR
        //    files that have never been memoized. assistant_file_index
        //    rows that changed since the last weekly run are candidates.
        const lastJob = await pool.query(`
            SELECT MAX(finished_at) AS t
              FROM assistant_memory_jobs
             WHERE workspace_slug = $1 AND job_kind IN ('weekly','rebuild') AND job_status = 'ok'`,
            [ws]);
        const since = lastJob.rows[0] && lastJob.rows[0].t;
        const filesQ = await pool.query(`
            SELECT i.id
              FROM assistant_file_index i
              LEFT JOIN assistant_file_memory m ON m.file_id = i.id
             WHERE i.workspace_slug = $1
               AND (
                    m.file_id IS NULL
                    OR ($2::timestamptz IS NULL)
                    OR GREATEST(i.indexed_at, i.updated_at) > COALESCE(m.source_updated_at, '1970-01-01')
               )
             ORDER BY i.indexed_at DESC NULLS LAST
             LIMIT $3`, [ws, since, limit]);

        const affectedResearchers = new Set();
        const affectedProjects = new Set();
        for (const r of filesQ.rows) {
            const out = await buildFileMemory(deps, r.id, { force: false });
            if (out && out.ok && !out.skipped) stats.files++;
            // Look up which researcher / project the file maps to so we
            // know what to refresh downstream.
            const meta = await pool.query(
                `SELECT memory_json->>'researcher_code' AS researcher,
                        memory_json->>'project' AS project
                   FROM assistant_file_memory WHERE file_id = $1`, [r.id]);
            if (meta.rows.length) {
                if (meta.rows[0].researcher) affectedResearchers.add(meta.rows[0].researcher);
                if (meta.rows[0].project)    affectedProjects.add(meta.rows[0].project);
            }
        }

        // 2) Refresh researcher memory for affected researchers.
        for (const code of affectedResearchers) {
            await buildResearcherMemory(deps, code, ws);
            stats.researchers++;
        }

        // 3) Refresh project memory for affected projects.
        for (const p of affectedProjects) {
            await buildProjectMemory(deps, p, ws);
            stats.projects++;
        }

        // 4) Always refresh workspace memory at the end.
        await buildWorkspaceMemory(deps, ws);
        stats.workspace = true;

        await finishJob(pool, job, 'ok', stats);
        return { ok: true, stats };
    } catch (err) {
        await finishJob(pool, job, 'failed', stats, err && err.message);
        return { ok: false, stats, error: err && err.message };
    }
}

async function rebuildAll(deps, workspaceSlug, opts) {
    const { pool } = deps;
    const ws = String(workspaceSlug || 'natlab').trim();
    const limit = Math.min(Math.max(parseInt(opts?.limit, 10) || 500, 1), 5000);
    const job = await startJob(pool, ws, 'rebuild');
    let stats = { files: 0, researchers: 0, projects: 0, workspace: false };
    try {
        // Archive the previous workspace summary by leaving the row in
        // place; per-file/researcher/project rows are upserted so they
        // self-overwrite.
        const filesQ = await pool.query(`
            SELECT id FROM assistant_file_index
             WHERE workspace_slug = $1
             ORDER BY indexed_at DESC NULLS LAST
             LIMIT $2`, [ws, limit]);
        for (const r of filesQ.rows) {
            const out = await buildFileMemory(deps, r.id, { force: true });
            if (out && out.ok) stats.files++;
        }
        // Distinct researchers and projects we just memoized.
        const groups = await pool.query(`
            SELECT DISTINCT
                   memory_json->>'researcher_code' AS researcher,
                   memory_json->>'project'         AS project
              FROM assistant_file_memory
             WHERE workspace_slug = $1`, [ws]);
        const researchers = new Set();
        const projects = new Set();
        for (const r of groups.rows) {
            if (r.researcher) researchers.add(r.researcher);
            if (r.project)    projects.add(r.project);
        }
        for (const code of researchers) {
            await buildResearcherMemory(deps, code, ws);
            stats.researchers++;
        }
        for (const p of projects) {
            await buildProjectMemory(deps, p, ws);
            stats.projects++;
        }
        await buildWorkspaceMemory(deps, ws);
        stats.workspace = true;
        await finishJob(pool, job, 'ok', stats);
        return { ok: true, stats };
    } catch (err) {
        await finishJob(pool, job, 'failed', stats, err && err.message);
        return { ok: false, stats, error: err && err.message };
    }
}

async function getStatus(deps, workspaceSlug) {
    const { pool } = deps;
    const ws = String(workspaceSlug || 'natlab').trim();
    const counts = await pool.query(`
        SELECT
            (SELECT COUNT(*)::int FROM assistant_file_memory       WHERE workspace_slug=$1) AS file_memory_rows,
            (SELECT COUNT(*)::int FROM assistant_researcher_memory WHERE workspace_slug=$1) AS researcher_memory_rows,
            (SELECT COUNT(*)::int FROM assistant_project_memory    WHERE workspace_slug=$1) AS project_memory_rows,
            (SELECT 1 FROM assistant_workspace_memory WHERE workspace_slug=$1 LIMIT 1) AS workspace_present`,
        [ws]);
    const recent = await pool.query(`
        SELECT id, job_kind, job_status, started_at, finished_at,
               files_processed, researchers_processed, projects_processed,
               workspace_processed, error_text
          FROM assistant_memory_jobs
         WHERE workspace_slug = $1 OR workspace_slug IS NULL
         ORDER BY started_at DESC LIMIT 5`, [ws]);
    return {
        workspace_slug: ws,
        counts: counts.rows[0] || {},
        recent_jobs: recent.rows
    };
}

// ===========================================================================
// Helpers
// ===========================================================================
async function startJob(pool, ws, kind) {
    const r = await pool.query(
        `INSERT INTO assistant_memory_jobs (workspace_slug, job_kind, job_status)
         VALUES ($1, $2, 'running')
         RETURNING id`, [ws, kind]);
    return r.rows[0].id;
}
async function finishJob(pool, id, status, stats, errorText) {
    await pool.query(`
        UPDATE assistant_memory_jobs SET
            job_status            = $2,
            finished_at           = NOW(),
            files_processed       = $3,
            researchers_processed = $4,
            projects_processed    = $5,
            workspace_processed   = $6,
            error_text            = $7
          WHERE id = $1`,
        [id, status, stats.files || 0, stats.researchers || 0,
         stats.projects || 0, !!stats.workspace, errorText || null]);
}

function escapeRegex(s) {
    return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}
function countKw(text, kw) {
    if (!text || !kw) return 0;
    const re = new RegExp('\\b' + escapeRegex(kw) + '\\b', 'gi');
    return (text.match(re) || []).length;
}
function uniqMatch(text, vocab) {
    if (!text) return [];
    const out = [];
    for (const v of vocab) {
        if (countKw(text, v) > 0) out.push(v);
    }
    return out;
}
function uniqArr(arr) {
    const seen = new Set();
    const out = [];
    for (const x of arr) {
        if (!x) continue;
        const k = String(x);
        if (seen.has(k)) continue;
        seen.add(k);
        out.push(x);
    }
    return out;
}
function dedupArr(arr) {
    if (!Array.isArray(arr)) return arr ? [arr] : [];
    return uniqArr(arr);
}
function bump(map, key) {
    if (!key) return;
    map.set(key, (map.get(key) || 0) + 1);
}
function topN(map, n) {
    return Array.from(map.entries())
        .sort((a, b) => b[1] - a[1])
        .slice(0, n)
        .map(([k]) => k);
}
function firstNonEmpty(arr) {
    for (const x of arr) if (x && (!Array.isArray(x) || x.length)) return x;
    return null;
}
function truncate(s, n) {
    if (!s) return s;
    return s.length > n ? s.slice(0, n) + '…' : s;
}
function scoreConfidence(flags) {
    const yes = flags.filter(Boolean).length;
    return Number(((yes / flags.length) || 0).toFixed(2));
}
function mostRecent(times) {
    const filtered = (times || []).filter(Boolean).map(t => new Date(t).getTime());
    if (!filtered.length) return null;
    return new Date(Math.max(...filtered));
}
function collectFutureWork(intelRows) {
    const out = [];
    for (const r of intelRows) {
        if (Array.isArray(r.future_work)) {
            for (const item of r.future_work) {
                if (typeof item === 'string' && item.length > 10) out.push(item);
            }
        }
    }
    return uniqArr(out);
}
function deriveStrengths(methodsTally, organismsTally) {
    const m = topN(methodsTally, 3);
    const o = topN(organismsTally, 2);
    const out = [];
    if (m.length) out.push('proficient with: ' + m.join(', '));
    if (o.length) out.push('works with: ' + o.join(', '));
    return out;
}
function deriveWeakAreas(researcherSet, sopCov) {
    const out = [];
    const ratio = (sopCov && sopCov.total) ? Number(sopCov.with_sop) / Number(sopCov.total) : 0;
    if (researcherSet.size === 0) {
        out.push('No active researchers detected — index may be empty.');
    } else if (ratio < 0.5) {
        out.push('Low SOP coverage: ' + Math.round(ratio * 100) + '% of researchers have at least one SOP.');
    }
    return out;
}
function filterByType(fileRows, type, n) {
    return fileRows
        .filter(r => (r.memory_json && r.memory_json.file_type) === type)
        .slice(0, n)
        .map(r => r.file_id);
}
function mostInformative(arr) {
    // Pick the longest non-trivial summary text, capped.
    let best = '';
    for (const s of arr) {
        if (typeof s !== 'string') continue;
        if (s.length > best.length && s.length < 1500) best = s;
    }
    return best || null;
}
function composeResearcherSummary(m) {
    const parts = [];
    parts.push(`${m.researcher_code} has ${m.upload_counts.data_total || 0} DATA, ${m.upload_counts.sop_total || 0} SOP, ${m.upload_counts.pres_total || 0} PRES, ${m.upload_counts.report_total || 0} REPORT uploads.`);
    if (m.active_projects.length) parts.push(`Active projects: ${m.active_projects.slice(0,5).join('; ')}.`);
    if (m.main_methods.length)    parts.push(`Main methods: ${m.main_methods.slice(0,5).join(', ')}.`);
    if (m.organisms_or_models.length) parts.push(`Organisms / models: ${m.organisms_or_models.slice(0,4).join(', ')}.`);
    if (m.glp_maturity_signal && m.glp_maturity_signal !== 'unknown') parts.push(`GLP maturity: ${m.glp_maturity_signal}.`);
    if (m.recurring_issues.length) parts.push(`Recurring issues: ${m.recurring_issues.slice(0,3).join('; ')}.`);
    return parts.join(' ');
}
function composeProjectSummary(m) {
    const parts = [];
    parts.push(`Project "${m.project_name}" — ${m.file_count} file(s), ${m.related_researchers.length} researcher(s).`);
    if (m.core_scientific_goal) parts.push(truncate(m.core_scientific_goal, 400));
    if (m.methods_used.length) parts.push(`Methods: ${m.methods_used.slice(0,5).join(', ')}.`);
    if (m.gaps_or_risks.length) parts.push(`Gaps/risks: ${m.gaps_or_risks.slice(0,3).join('; ')}.`);
    return parts.join(' ');
}
function composeWorkspaceSummary(m) {
    const parts = [];
    parts.push(`Workspace ${m.workspace_slug}: ${m.active_researchers.length} researchers, ${m.active_scientific_areas.length} project areas.`);
    parts.push(`Uploads — DATA:${m.upload_counts.data_total||0} SOP:${m.upload_counts.sop_total||0} PRES:${m.upload_counts.pres_total||0} REPORT:${m.upload_counts.report_total||0}.`);
    parts.push(`SOP coverage: ${Math.round((m.glp_status.sop_coverage_ratio||0)*100)}%.`);
    if (m.common_methods.length) parts.push(`Common methods: ${m.common_methods.slice(0,5).join(', ')}.`);
    if (m.weak_documentation_areas.length) parts.push(m.weak_documentation_areas.join(' '));
    return parts.join(' ');
}

module.exports = {
    ensureSchema,
    buildFileMemory,
    buildResearcherMemory,
    buildProjectMemory,
    buildWorkspaceMemory,
    runWeeklyUpdate,
    rebuildAll,
    getStatus
};
