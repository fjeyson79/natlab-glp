// services/reportIntelligence.js
//
// Rule-based REPORT intelligence extractor. Reads a PDF/DOC/DOCX buffer,
// pulls section snippets and keyword hits, derives two coarse signals
// (scientific_maturity_signal, glp_relevance_signal) and upserts a row
// into assistant_report_intelligence.
//
// Deliberately additive:
//   - No embeddings, no LLM calls, no external services.
//   - PDF via pdf-parse (already a dependency, same as assistantFileExtractor).
//   - DOCX via mammoth (already a dependency).
//   - Legacy .doc binary: not supported — row is written with
//     extraction_status='unsupported_pending_docx_extractor' so the API
//     can surface the gap without bouncing the upload.
//   - Errors at any stage NEVER throw back to the upload route; the row
//     is written with extraction_status='failed' and the error text in
//     extraction_error.
//
// Trigger lives in server.js /api/di/upload-report: it `await`s run() but
// wraps the call in try/catch so an extraction failure can't break the
// upload response.

'use strict';

// ---------------------------------------------------------------------------
// Section + keyword corpora
// ---------------------------------------------------------------------------

// Headings we want to locate. Patterns are anchored at line starts (or any
// leading whitespace) to avoid matching the word `conclusion` mid-paragraph.
// `(?:^|\n)` keeps the regex linear in `text.length` for `String.search`
// callers.
const SECTION_PATTERNS = {
    abstract:    /(?:^|\n)\s*(?:abstract|summary|executive\s+summary)\b[:.\s]/i,
    introduction:/(?:^|\n)\s*introduction\b[:.\s]/i,
    results:     /(?:^|\n)\s*results?\b[:.\s]/i,
    discussion:  /(?:^|\n)\s*discussion\b[:.\s]/i,
    conclusion:  /(?:^|\n)\s*conclusions?\b[:.\s]/i,
    limitations: /(?:^|\n)\s*(?:limitations?|caveats?)\b[:.\s]/i,
    futureWork:  /(?:^|\n)\s*(?:future\s*work|next\s*steps?|outlook|perspectives?)\b[:.\s]/i,
    methods:     /(?:^|\n)\s*(?:materials\s*and\s*methods|methods|methodology|experimental(?:\s+procedures?)?)\b[:.\s]/i,
};

const KEYWORDS = {
    // Multi-word keywords go first so phrase boundaries don't get clobbered
    // by the single-word `\bX\b` build. The escape helper handles dashes.
    methods: [
        'biodistribution', 'infection model', 'microscopy', 'purification',
        'fluorescence', 'qPCR', 'MALDI', 'LC-MS', 'CFU', 'assay'
    ],
    limitations: [
        'limitation', 'challenge', 'unclear', 'failed', 'low signal',
        'background', 'contamination', 'missing', 'not completed'
    ],
    future: [
        'future work', 'next step', 'optimize', 'optimise', 'validate',
        'repeat', 'scale', 'compare', 'expand', 'further'
    ],
    glp: [
        'SOP', 'traceability', 'approval', 'revision', 'deviation',
        'ALCOA', 'raw data', 'control', 'replicate'
    ],
};

// Project themes — small fixed vocabulary. We don't try to learn themes
// at this stage; matching against a curated list keeps the signal stable.
const THEMES = [
    'antimicrobial', 'oligonucleotide', 'peptide', 'protein', 'vaccine',
    'infection', 'biodistribution', 'fluorescence', 'MALDI', 'LC-MS',
    'qPCR', 'microscopy', 'assay', 'purification', 'synthesis',
    'characterization', 'in vivo', 'in vitro', 'aptamer', 'nanoparticle'
];

const REPORT_TEXT_HARD_CAP = 600_000; // ~150 pages — keeps regex linear

// Subcategories listed in the upload spec; only used to drive the
// `scientific_maturity_signal` fallback rules.
const SUB_THESIS  = new Set(['PHD_REPORT', 'THESIS_CHAPTER', 'MANUSCRIPT_DRAFT']);
const SUB_TRAINEE = new Set(['UNDERGRADUATE_REPORT', 'INTERNAL_REPORT']);

// ---------------------------------------------------------------------------
// Text extraction
// ---------------------------------------------------------------------------

async function extractText(buffer, filename) {
    const lname = (filename || '').toLowerCase();
    if (lname.endsWith('.pdf')) {
        try {
            const pdfParse = require('pdf-parse');
            const parsed = await pdfParse(buffer);
            const text = sanitize(parsed.text);
            return { text, method: 'pdf-parse', error: text ? null : 'empty_pdf_text' };
        } catch (e) {
            return { text: '', method: 'pdf-parse', error: 'pdf_parse_failed: ' + (e && e.message || e) };
        }
    }
    if (lname.endsWith('.docx')) {
        try {
            const mammoth = require('mammoth');
            const result = await mammoth.extractRawText({ buffer });
            const text = sanitize(result && result.value);
            return { text, method: 'mammoth', error: text ? null : 'empty_docx_text' };
        } catch (e) {
            return { text: '', method: 'mammoth', error: 'docx_extract_failed: ' + (e && e.message || e) };
        }
    }
    if (lname.endsWith('.doc')) {
        // Legacy binary .doc requires antiword or libreoffice — neither is a
        // current dependency. Return a stable marker so the upload still
        // succeeds and the row carries the gap forward to the API.
        return { text: '', method: null, error: 'unsupported_pending_docx_extractor' };
    }
    return { text: '', method: null, error: 'unsupported_file_type' };
}

function sanitize(s) {
    if (!s) return '';
    let t = String(s);
    // Strip NUL bytes that occasionally come out of pdf-parse and would
    // make Postgres reject the TEXT field on UPDATE.
    t = t.replace(/\u0000/g, '');
    t = t.replace(/\r\n?/g, '\n');
    t = t.replace(/[ \t]+\n/g, '\n');
    t = t.trim();
    if (t.length > REPORT_TEXT_HARD_CAP) t = t.slice(0, REPORT_TEXT_HARD_CAP);
    return t;
}

// ---------------------------------------------------------------------------
// Section + sentence helpers
// ---------------------------------------------------------------------------

function extractSection(text, pattern, maxChars) {
    if (!text) return null;
    pattern.lastIndex = 0;
    const m = pattern.exec(text);
    if (!m) return null;
    const start = m.index + m[0].length;
    return text.slice(start, start + (maxChars || 1500)).trim();
}

function splitSentences(text, max) {
    if (!text) return [];
    return text
        .replace(/\s+/g, ' ')
        .split(/(?<=[.!?])\s+(?=[A-Z0-9])/)
        .map(s => s.trim())
        .filter(s => s.length >= 15 && s.length <= 500)
        .slice(0, max || 5);
}

function scanForKeywordSentences(text, keywords, max) {
    const sentences = text.split(/(?<=[.!?])\s+(?=[A-Z0-9])/);
    const matches = [];
    const seen = new Set();
    for (const raw of sentences) {
        const s = raw.trim();
        if (s.length < 15 || s.length > 500) continue;
        for (const kw of keywords) {
            if (new RegExp('\\b' + escapeRegex(kw) + '\\b', 'i').test(s)) {
                if (!seen.has(s)) {
                    matches.push(s);
                    seen.add(s);
                }
                break;
            }
        }
        if (matches.length >= (max || 4)) break;
    }
    return matches;
}

function escapeRegex(s) {
    return String(s).replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function countKeyword(text, kw) {
    const re = new RegExp('\\b' + escapeRegex(kw) + '\\b', 'gi');
    return (text.match(re) || []).length;
}

function detectKeywords(text, list) {
    const out = [];
    for (const kw of list) {
        const c = countKeyword(text, kw);
        if (c > 0) out.push({ keyword: kw, count: c });
    }
    return out.sort((a, b) => b.count - a.count);
}

// ---------------------------------------------------------------------------
// Signals
// ---------------------------------------------------------------------------

function computeMaturity(meta, intel) {
    const sub = meta.report_subcategory || null;
    if (sub === 'GLP_REPORT')         return 'GLP/compliance focused';
    if (SUB_THESIS.has(sub))          return 'thesis/manuscript level';
    if (sub === 'MASTER_REPORT')      return 'validated experimental work';
    if (SUB_TRAINEE.has(sub)) {
        if ((intel.related_methods || []).length >= 3) return 'method development';
    }
    return 'early exploratory';
}

function computeGlp(meta, glpKwCount) {
    const sub = meta.report_subcategory || null;
    if (sub === 'GLP_REPORT' || glpKwCount >= 5) return 'high';
    const linkCount = (meta.report_related_sop_ids  || []).length
                    + (meta.report_related_data_ids || []).length;
    if (linkCount > 0 || glpKwCount >= 2) return 'medium';
    return 'low';
}

// ---------------------------------------------------------------------------
// Analyzer
// ---------------------------------------------------------------------------

function analyze(text, meta) {
    const intel = {
        title: null,
        short_summary: null,
        key_conclusions: [],
        limitations: [],
        future_work: [],
        related_methods: [],
        related_assays: [],
        detected_project_themes: [],
        detected_keywords: [],
        scientific_maturity_signal: null,
        glp_relevance_signal: null,
        source_text_chars: text ? text.length : 0
    };
    if (!text) {
        intel.scientific_maturity_signal = computeMaturity(meta || {}, intel);
        intel.glp_relevance_signal       = computeGlp(meta || {}, 0);
        return intel;
    }

    // Title heuristic: first non-empty line ≤ 200 chars (most PDFs put the
    // title on page 1 line 1). Falls back to filename in the route.
    const firstLine = text.split('\n').map(s => s.trim())
                          .find(s => s.length > 0 && s.length <= 200);
    intel.title = firstLine || null;

    // Short summary from Abstract → Summary → Introduction (first one wins).
    const summarySection = extractSection(text, SECTION_PATTERNS.abstract, 1500)
                       || extractSection(text, SECTION_PATTERNS.introduction, 1500);
    if (summarySection) {
        intel.short_summary = splitSentences(summarySection, 3).join(' ') || null;
    }

    // Key conclusions from Conclusion → Discussion.
    const conclusionSection = extractSection(text, SECTION_PATTERNS.conclusion, 2000)
                          || extractSection(text, SECTION_PATTERNS.discussion, 2000);
    intel.key_conclusions = splitSentences(conclusionSection, 5);

    // Limitations: section first, keyword scan as fallback.
    const limSection = extractSection(text, SECTION_PATTERNS.limitations, 1500);
    intel.limitations = limSection
        ? splitSentences(limSection, 5)
        : scanForKeywordSentences(text, KEYWORDS.limitations, 4);

    // Future work: section first, keyword scan as fallback.
    const futSection = extractSection(text, SECTION_PATTERNS.futureWork, 1500);
    intel.future_work = futSection
        ? splitSentences(futSection, 5)
        : scanForKeywordSentences(text, KEYWORDS.future, 4);

    // Methods + assays — keyword detection across the whole document.
    const methodHits = detectKeywords(text, KEYWORDS.methods);
    intel.related_methods = methodHits.map(h => h.keyword);
    const ASSAY_KW = new Set(['assay', 'CFU', 'qPCR', 'MALDI', 'LC-MS', 'microscopy', 'fluorescence']);
    intel.related_assays = intel.related_methods.filter(k => ASSAY_KW.has(k));

    // Themes.
    intel.detected_project_themes = THEMES.filter(t => countKeyword(text, t) > 0);

    // Detected keywords: union of methods + themes + future + limitations
    // (deduped, preserves order).
    const everything = [
        ...intel.related_methods,
        ...intel.detected_project_themes,
        ...detectKeywords(text, KEYWORDS.future).map(h => h.keyword),
        ...detectKeywords(text, KEYWORDS.limitations).map(h => h.keyword)
    ];
    intel.detected_keywords = [...new Set(everything)];

    // GLP keyword tally drives glp_relevance_signal.
    const glpHits = KEYWORDS.glp.reduce((sum, kw) => sum + countKeyword(text, kw), 0);

    intel.scientific_maturity_signal = computeMaturity(meta || {}, intel);
    intel.glp_relevance_signal       = computeGlp(meta || {}, glpHits);

    return intel;
}

// ---------------------------------------------------------------------------
// Persistence
// ---------------------------------------------------------------------------

async function upsertRow(pool, params) {
    const sql = `
        INSERT INTO assistant_report_intelligence (
            submission_id, workspace_id, researcher_id,
            report_subcategory, report_status, project,
            reporting_period_start, reporting_period_end, supervisor,
            title, short_summary,
            key_conclusions, limitations, future_work,
            related_methods, related_assays, related_sops, related_data_files,
            detected_project_themes, detected_keywords,
            scientific_maturity_signal, glp_relevance_signal,
            source_text_chars, extraction_status, extraction_error
        ) VALUES (
            $1, $2, $3,
            $4, $5, $6,
            $7::date, $8::date, $9,
            $10, $11,
            $12::jsonb, $13::jsonb, $14::jsonb,
            $15::jsonb, $16::jsonb, $17::jsonb, $18::jsonb,
            $19::jsonb, $20::jsonb,
            $21, $22,
            $23, $24, $25
        )
        ON CONFLICT (submission_id) DO UPDATE SET
            workspace_id              = EXCLUDED.workspace_id,
            researcher_id             = EXCLUDED.researcher_id,
            report_subcategory        = EXCLUDED.report_subcategory,
            report_status             = EXCLUDED.report_status,
            project                   = EXCLUDED.project,
            reporting_period_start    = EXCLUDED.reporting_period_start,
            reporting_period_end      = EXCLUDED.reporting_period_end,
            supervisor                = EXCLUDED.supervisor,
            title                     = EXCLUDED.title,
            short_summary             = EXCLUDED.short_summary,
            key_conclusions           = EXCLUDED.key_conclusions,
            limitations               = EXCLUDED.limitations,
            future_work               = EXCLUDED.future_work,
            related_methods           = EXCLUDED.related_methods,
            related_assays            = EXCLUDED.related_assays,
            related_sops              = EXCLUDED.related_sops,
            related_data_files        = EXCLUDED.related_data_files,
            detected_project_themes   = EXCLUDED.detected_project_themes,
            detected_keywords         = EXCLUDED.detected_keywords,
            scientific_maturity_signal= EXCLUDED.scientific_maturity_signal,
            glp_relevance_signal      = EXCLUDED.glp_relevance_signal,
            source_text_chars         = EXCLUDED.source_text_chars,
            extraction_status         = EXCLUDED.extraction_status,
            extraction_error          = EXCLUDED.extraction_error,
            updated_at                = NOW()
        RETURNING id`;
    const r = await pool.query(sql, params);
    return r.rows[0] && r.rows[0].id;
}

// ---------------------------------------------------------------------------
// Orchestrator — called from /api/di/upload-report.
//
// Never throws: any error is collapsed into an `error` field on the return
// value so the caller can log without aborting the upload response.
// ---------------------------------------------------------------------------

async function run(deps, opts) {
    const { pool } = deps || {};
    const {
        submissionId, workspaceId, researcherId,
        buffer, filename, meta
    } = opts || {};

    if (!pool || !submissionId) {
        return { ok: false, extraction_status: 'failed', extraction_error: 'missing_deps_or_submission_id' };
    }

    let text = '';
    let extractionStatus = 'failed';
    let extractionError  = null;

    try {
        const ext = await extractText(buffer, filename);
        text = ext.text || '';
        if (text) {
            extractionStatus = 'ready';
        } else if (ext.error === 'unsupported_pending_docx_extractor') {
            extractionStatus = 'unsupported_pending_docx_extractor';
        } else if (ext.error === 'unsupported_file_type') {
            extractionStatus = 'unsupported_file_type';
            extractionError  = ext.error;
        } else {
            extractionStatus = 'failed';
            extractionError  = ext.error || 'no_text_extracted';
        }
    } catch (e) {
        extractionStatus = 'failed';
        extractionError  = 'extract_threw: ' + (e && e.message || e);
    }

    // Always analyze — when text is empty the analyzer returns a row with
    // signals derived solely from meta, which is still useful to Zoe (it
    // can tell the report exists and what category it claims to be).
    let intel;
    try {
        intel = analyze(text, meta || {});
    } catch (e) {
        intel = {
            title: null, short_summary: null,
            key_conclusions: [], limitations: [], future_work: [],
            related_methods: [], related_assays: [],
            detected_project_themes: [], detected_keywords: [],
            scientific_maturity_signal: null, glp_relevance_signal: null,
            source_text_chars: text ? text.length : 0
        };
        if (!extractionError) {
            extractionError = 'analyze_threw: ' + (e && e.message || e);
            extractionStatus = 'failed';
        }
    }

    const m = meta || {};
    const params = [
        submissionId,
        workspaceId || null,
        researcherId || null,
        m.report_subcategory || null,
        m.report_status || null,
        m.report_project || null,
        m.report_period_start || null,
        m.report_period_end || null,
        m.report_supervisor || null,
        intel.title || null,
        intel.short_summary || null,
        JSON.stringify(intel.key_conclusions || []),
        JSON.stringify(intel.limitations || []),
        JSON.stringify(intel.future_work || []),
        JSON.stringify(intel.related_methods || []),
        JSON.stringify(intel.related_assays || []),
        JSON.stringify(m.report_related_sop_ids  || []),
        JSON.stringify(m.report_related_data_ids || []),
        JSON.stringify(intel.detected_project_themes || []),
        JSON.stringify(intel.detected_keywords || []),
        intel.scientific_maturity_signal || null,
        intel.glp_relevance_signal       || null,
        intel.source_text_chars || 0,
        extractionStatus,
        extractionError
    ];

    try {
        const id = await upsertRow(pool, params);
        return { ok: true, id, extraction_status: extractionStatus, extraction_error: extractionError };
    } catch (e) {
        return {
            ok: false,
            extraction_status: 'failed',
            extraction_error: 'db_upsert_failed: ' + (e && e.message || e)
        };
    }
}

module.exports = { extractText, analyze, run };
