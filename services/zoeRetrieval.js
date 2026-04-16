// ---------------------------------------------------------------------------
// Zoe Retrieval Service (Phase 4)
// ---------------------------------------------------------------------------
// Unified intelligence layer for Zoe's portal-grounded answers.
//
// Responsibilities:
//   1. Classify the user intent (paper / sop / presentation / data / report / generic).
//   2. Rank portal-metadata candidates with a multi-signal score.
//   3. Extract readable content from R2-stored files (PDF, DOCX, PPTX, XLSX,
//      CSV, TXT/MD/JSON/LOG). Returns a normalized object usable by the model.
//   4. Prepare a structure-aware chunk when the document is long.
//   5. Produce a small trace object for debug / auditability (never sent to
//      the upstream model unless explicitly requested).
//
// Design constraints honored:
//   - R2 only. This module never imports or calls AWS S3 backup utilities.
//     Callers pass either a buffer (already fetched from R2) or an R2 key
//     plus an R2-fetch callback injected by server.js.
//   - Additive. Does not replace the legacy zoeExtractFromBuffer / scoring;
//     server.js prefers this service and falls back to the legacy path only
//     if the service is unavailable.
//   - Low compute. No embeddings, no background jobs, no extra DB tables.
//   - Permission-agnostic. Callers are responsible for workspace / role
//     scoping before handing candidates to this service.
// ---------------------------------------------------------------------------

'use strict';

const ZOE_DOC_MAX_CHARS = 18000;

// ---- 1. Intent classification --------------------------------------------
//
// Returns an object with the list of plausible intent kinds (there can be
// more than one — e.g. "latest sop about plasmid prep" is sop + recency).
// Also returns the token list to feed into ranking, and a handful of
// low-level flags the ranker uses directly.

const STOPWORDS = new Set([
    'the','and','from','with','what','does','read','show','tell','find',
    'summarize','summarise','analyze','analyse','give','please','about','that',
    'this','these','those','here','there','paper','papers','file','files',
    'sop','sops','report','reports','presentation','presentations','data',
    'doc','docs','document','documents','latest','newest','last','recent',
    'for','was','are','any','our','have','has','had','can','could','would'
]);

function tokenize(q) {
    return String(q || '').toLowerCase()
        .split(/[^a-z0-9]+/)
        .filter(t => t.length >= 2 && !STOPWORDS.has(t))
        .slice(0, 12);
}

function classifyIntent(message) {
    const m = String(message || '').toLowerCase();
    const kinds = [];
    const flags = {
        wantsPaper: /\b(paper|publication|article|journal|manuscript|preprint|doi)\b/.test(m),
        wantsSop: /\bsop\b|\bstandard operating procedure\b|\bprotocol\b/.test(m),
        wantsPresentation: /\b(presentation|slides?|deck|ppt|pptx)\b/.test(m),
        wantsReport: /\b(report|summary|overview|brief)\b/.test(m),
        wantsData: /\b(data|dataset|csv|xls|xlsx|spreadsheet|table|results?)\b/.test(m),
        wantsLatest: /\b(latest|newest|last|most recent|recent|yesterday|today)\b/.test(m),
        isFollowUp: /\b(methods?|results?|discussion|conclusions?|abstract|limitations?|references?|version|compare|same|that one|it|its)\b/.test(m)
            && !/\b(paper|sop|presentation|report|file|document|data)\b/.test(m),
        isCapability: /\b(can you|are you able|do you|will you)\b[\s\S]{0,60}\b(read|access|analyz|search|find|see|retrieve|open)\b/.test(m),
    };
    if (flags.wantsPaper) kinds.push('paper');
    if (flags.wantsSop) kinds.push('sop');
    if (flags.wantsPresentation) kinds.push('presentation');
    if (flags.wantsReport) kinds.push('report');
    if (flags.wantsData) kinds.push('data');
    if (kinds.length === 0) kinds.push('generic');
    const tokens = tokenize(m);
    return { kinds, tokens, flags, raw: String(message || '') };
}

// ---- 2. Candidate ranking ------------------------------------------------
//
// Score a single candidate row against a classified intent. A candidate must
// at minimum have { title | filename, type | file_type }. Any of the other
// fields (category, project_name, uploader, date, r2_object_key, status,
// extracted_text) contribute additional signal when present.

function norm(s) { return String(s || '').toLowerCase(); }

function extOf(filenameOrTitle) {
    const s = String(filenameOrTitle || '').toLowerCase();
    const dot = s.lastIndexOf('.');
    return dot >= 0 ? s.slice(dot + 1) : '';
}

const READABLE_EXTS = new Set([
    'pdf','txt','md','markdown','json','log','csv','xls','xlsx',
    'docx','pptx'
]);

function isReadableFormat(filename, fileType) {
    const e = extOf(filename);
    if (READABLE_EXTS.has(e)) return true;
    const t = norm(fileType);
    return /pdf|text|csv|json|excel|spreadsheet|markdown|word|document|presentation|powerpoint/.test(t);
}

// Templates / admin / form filenames — penalized when the user asks for a
// scientific paper, SOP, report, or data file.
const TEMPLATE_HINTS = /\b(template|form|blank|empty|example|draft\-?template|checklist)\b/i;
const ADMIN_HINTS = /\b(admin|invoice|receipt|order|ticket|signoff|sign\-?off)\b/i;

function scoreCandidate(row, intent, opts) {
    opts = opts || {};
    const { tokens, raw } = intent;
    const qLower = String(raw || '').toLowerCase();
    const reasons = [];
    let s = 0;

    const title = norm(row.title || row.filename);
    const hay = [
        title, norm(row.filename), norm(row.type || row.file_type),
        norm(row.category), norm(row.uploader), norm(row.project_name),
        norm(row.description || '')
    ].join(' | ');

    // (a) exact whole-query substring
    if (qLower.length >= 3 && hay.includes(qLower)) {
        s += 40;
        reasons.push('exact query match');
    }
    // (b) per-token match — title hits weigh more than other-field hits
    for (const t of tokens) {
        if (!t) continue;
        if (title.includes(t)) { s += 6; reasons.push(`"${t}" in title`); }
        else if (hay.includes(t)) { s += 3; }
    }

    // (c) intent hints
    const typeStr = norm(
        (row.type || row.file_type || '') + ' ' + (row.category || '') + ' ' +
        (row.filename || row.title || '')
    );
    if (intent.flags.wantsPaper && /paper|publication|journal|article|manuscript|\.pdf|preprint/.test(typeStr)) {
        s += 8; reasons.push('matches "paper" hint');
    }
    if (intent.flags.wantsSop && /sop|protocol|procedure/.test(typeStr)) {
        s += 10; reasons.push('matches "SOP" hint');
    }
    if (intent.flags.wantsPresentation && /present|slide|deck|ppt/.test(typeStr)) {
        s += 10; reasons.push('matches "presentation" hint');
    }
    if (intent.flags.wantsReport && /report|summary|overview/.test(typeStr)) {
        s += 6; reasons.push('matches "report" hint');
    }
    if (intent.flags.wantsData && /data|csv|xls|spreadsheet|\.xlsx/.test(typeStr)) {
        s += 8; reasons.push('matches "data" hint');
    }

    // (d) readability bonus — a file whose content we can actually extract
    //     is much more useful than a binary we can only see metadata for.
    if (row.r2_object_key && isReadableFormat(row.filename || row.title, row.type || row.file_type)) {
        s += 4; reasons.push('readable');
    }

    // (e) approved / active status bonus (SOPs especially should be approved)
    if (row.status === 'APPROVED' || row.status === 'ACTIVE') {
        if (intent.flags.wantsSop || intent.flags.wantsReport) {
            s += 4; reasons.push('approved/active');
        } else {
            s += 2;
        }
    }
    if (row.status === 'DISCARDED') s -= 100; // effectively excludes

    // (f) template / admin penalty when the user asked for a scientific
    //     artefact (paper, SOP content, report, data)
    const looksTemplate = TEMPLATE_HINTS.test(title);
    const looksAdmin = ADMIN_HINTS.test(title);
    if (looksTemplate && (intent.flags.wantsPaper || intent.flags.wantsSop ||
                          intent.flags.wantsReport || intent.flags.wantsData)) {
        s -= 6; reasons.push('looks like template/form');
    }
    if (looksAdmin) {
        s -= 3;
    }

    // (g) recency — linear decay over 180d, doubled if user asked "latest"
    const now = opts.now || Date.now();
    const t = row.date ? new Date(row.date).getTime() : 0;
    if (t) {
        const ageDays = Math.max(0, (now - t) / (1000 * 3600 * 24));
        const recencyPts = Math.max(0, 5 - (ageDays / 36));
        s += recencyPts;
        if (intent.flags.wantsLatest) s += recencyPts;
    }

    // (h) missing R2 key — we can't actually read the file
    if (!row.r2_object_key) { s -= 6; reasons.push('no stored object'); }

    // (i) project continuity bonus (supplied by the caller from session memory)
    if (opts.projectHintId && row.project_id && opts.projectHintId === row.project_id) {
        s += 5; reasons.push('matches active project');
    }

    return { score: Math.round(s * 100) / 100, reasons };
}

// Rank a list of candidates and attach score + reasons. Returns a new sorted
// array (does not mutate the input).
function rankCandidates(rows, intent, opts) {
    const out = rows.map(r => {
        const sc = scoreCandidate(r, intent, opts);
        return Object.assign({}, r, {
            score: sc.score,
            match_reason: sc.reasons.slice(0, 3).join('; ') || 'field match',
            readable: !!r.r2_object_key && isReadableFormat(
                r.filename || r.title, r.type || r.file_type
            )
        });
    });
    out.sort((a, b) => b.score - a.score || new Date(b.date || 0) - new Date(a.date || 0));
    return out;
}

function confidenceOf(topN) {
    if (!topN || topN.length === 0) return 'low';
    const best = topN[0].score || 0;
    const second = topN[1] ? (topN[1].score || 0) : 0;
    if (best >= 15 && (topN.length === 1 || (best - second) >= 8)) return 'high';
    if (best >= 8) return 'medium';
    return 'low';
}

// ---- 3. Extraction pipeline ----------------------------------------------
//
// Returns a normalized result object:
//   {
//     success: true|false,
//     parser: 'pdf-parse'|'mammoth-docx'|'pptx-xml'|'xlsx-preview'|'utf8-text'|'json-pretty'|null,
//     mime: '...',          // effective mime/ext used for the decision
//     text: '...',          // extracted text (already clipped to max)
//     readable: true|false, // true iff text is non-empty
//     content_truncated: true|false,
//     pages: number|null,
//     sheets: string[]|null,
//     slides: number|null,
//     sections: [{ kind, content }]  // structure-aware chunks when available
//     preview: '...',       // ~400 char preview
//     quality: 'high'|'medium'|'low'|'empty',
//     error: string|null
//   }

function clip(s, max) {
    const t = String(s || '');
    const cap = max || ZOE_DOC_MAX_CHARS;
    return { text: t.slice(0, cap), truncated: t.length > cap };
}

function preview(txt) {
    return String(txt || '').slice(0, 400).replace(/\s+/g, ' ').trim();
}

// Detect a plausible mime/ext from contentType + filename.
function resolveKind(contentType, filename) {
    const ext = extOf(filename);
    const mime = norm(contentType);
    if (mime.includes('pdf') || ext === 'pdf') return 'pdf';
    if (mime.includes('wordprocessingml') || ext === 'docx') return 'docx';
    if (mime.includes('presentationml') || ext === 'pptx') return 'pptx';
    if (mime.includes('spreadsheetml') || mime.includes('ms-excel') ||
        ext === 'xlsx' || ext === 'xls') return 'xlsx';
    if (mime.includes('csv') || ext === 'csv') return 'csv';
    if (mime.startsWith('text/') || ['txt','md','markdown','json','log'].includes(ext)) {
        return (ext === 'json' || mime.includes('json')) ? 'json' : 'text';
    }
    return 'unknown';
}

// --- PDF ---
async function extractPdf(buffer) {
    const pdfParse = require('pdf-parse');
    const parsed = await pdfParse(buffer);
    const raw = (parsed.text || '').replace(/\s+\n/g, '\n').trim();
    const { text, truncated } = clip(raw, ZOE_DOC_MAX_CHARS);
    return {
        parser: 'pdf-parse', text,
        content_truncated: truncated,
        pages: parsed.numpages || null,
        sections: detectPaperSections(text),
    };
}

// --- DOCX via mammoth ---
async function extractDocx(buffer) {
    const mammoth = require('mammoth');
    const result = await mammoth.extractRawText({ buffer });
    const raw = (result.value || '').trim();
    const { text, truncated } = clip(raw, ZOE_DOC_MAX_CHARS);
    return {
        parser: 'mammoth-docx', text,
        content_truncated: truncated,
        sections: detectSopSections(text),
    };
}

// --- PPTX via adm-zip: pull text from ppt/slides/slideN.xml ---
async function extractPptx(buffer) {
    const AdmZip = require('adm-zip');
    const zip = new AdmZip(buffer);
    const entries = zip.getEntries()
        .filter(e => /^ppt\/slides\/slide\d+\.xml$/.test(e.entryName))
        .sort((a, b) => {
            const na = parseInt((a.entryName.match(/slide(\d+)\.xml$/) || [])[1] || '0', 10);
            const nb = parseInt((b.entryName.match(/slide(\d+)\.xml$/) || [])[1] || '0', 10);
            return na - nb;
        });
    const slides = [];
    for (const e of entries) {
        const xml = e.getData().toString('utf8');
        // Extract <a:t>...</a:t> text runs. Adequate for slide titles + bullets.
        const texts = [];
        const re = /<a:t[^>]*>([\s\S]*?)<\/a:t>/g;
        let m;
        while ((m = re.exec(xml)) !== null) {
            const t = m[1]
                .replace(/&amp;/g, '&')
                .replace(/&lt;/g, '<')
                .replace(/&gt;/g, '>')
                .replace(/&quot;/g, '"')
                .replace(/&apos;/g, "'")
                .trim();
            if (t) texts.push(t);
        }
        if (texts.length) {
            const title = texts[0];
            const body = texts.slice(1).join(' • ');
            slides.push({ idx: slides.length + 1, title, body });
        }
    }
    const lines = slides.map(s =>
        `Slide ${s.idx}: ${s.title}` + (s.body ? '\n  - ' + s.body : '')
    );
    const { text, truncated } = clip(lines.join('\n\n'), ZOE_DOC_MAX_CHARS);
    return {
        parser: 'pptx-xml', text,
        content_truncated: truncated,
        slides: slides.length || null,
        sections: slides.map(s => ({ kind: 'slide', content: `${s.title}\n${s.body}` })),
    };
}

// --- XLSX / XLS / CSV --- (xlsx handles all three via .read + SheetNames)
async function extractXlsx(buffer, kind) {
    const XLSX = require('xlsx');
    const wb = XLSX.read(buffer, { type: 'buffer' });
    const chunks = [];
    const sectionList = [];
    for (const name of wb.SheetNames) {
        const sheet = wb.Sheets[name];
        const rows = XLSX.utils.sheet_to_json(sheet, { header: 1, defval: null });
        const header = rows[0] || [];
        const preview = rows.slice(0, 40);
        const totalRows = rows.length;
        const chunk = `# Sheet: ${name} (${totalRows} row(s), showing first ${preview.length})\n`
            + `Headers: ${header.filter(Boolean).join(', ') || '(none)'}\n`
            + preview.map(r => (r || []).map(c => c == null ? '' : String(c)).join(',')).join('\n');
        chunks.push(chunk);
        sectionList.push({ kind: 'sheet', content: chunk });
        if (chunks.join('\n\n').length > ZOE_DOC_MAX_CHARS) break;
    }
    const { text, truncated } = clip(chunks.join('\n\n'), ZOE_DOC_MAX_CHARS);
    return {
        parser: kind === 'csv' ? 'xlsx-csv' : 'xlsx-preview',
        text, content_truncated: truncated,
        sheets: wb.SheetNames,
        sections: sectionList,
    };
}

// --- text / md / log / json ---
async function extractText(buffer, kind) {
    const raw = buffer.toString('utf8');
    if (kind === 'json') {
        try {
            const pretty = JSON.stringify(JSON.parse(raw), null, 2);
            const { text, truncated } = clip(pretty, ZOE_DOC_MAX_CHARS);
            return { parser: 'json-pretty', text, content_truncated: truncated };
        } catch (_) { /* fall through */ }
    }
    const { text, truncated } = clip(raw, ZOE_DOC_MAX_CHARS);
    return { parser: 'utf8-text', text, content_truncated: truncated };
}

// Structure heuristics for papers (very permissive — we look for common
// section headings and split on them). Returns empty array if no structure
// was detectable; callers can still use the raw text.
function detectPaperSections(text) {
    const HEAD = /^\s*(abstract|introduction|background|methods|materials and methods|materials & methods|results|discussion|conclusions?|limitations?|references|bibliography)\b[:\s]*$/i;
    const lines = String(text || '').split(/\r?\n/);
    const sections = [];
    let current = null;
    for (const line of lines) {
        if (HEAD.test(line)) {
            if (current) sections.push(current);
            current = { kind: line.trim().toLowerCase(), content: '' };
        } else if (current) {
            current.content += (current.content ? '\n' : '') + line;
        }
    }
    if (current) sections.push(current);
    return sections.length >= 2 ? sections : [];
}

function detectSopSections(text) {
    const HEAD = /^\s*(title|scope|purpose|materials|equipment|reagents|procedure|steps|safety|qc|quality control|version|approval)\b[:\s]*$/i;
    const lines = String(text || '').split(/\r?\n/);
    const sections = [];
    let current = null;
    for (const line of lines) {
        if (HEAD.test(line)) {
            if (current) sections.push(current);
            current = { kind: line.trim().toLowerCase(), content: '' };
        } else if (current) {
            current.content += (current.content ? '\n' : '') + line;
        }
    }
    if (current) sections.push(current);
    return sections.length >= 2 ? sections : [];
}

// Top-level extractor. Never throws; returns { success:false, error } on any
// failure so callers can try the next candidate.
async function extractContent(buffer, contentType, filename) {
    if (!buffer || !Buffer.isBuffer(buffer)) {
        return { success: false, readable: false, parser: null, mime: null,
                 text: '', quality: 'empty', error: 'Empty or invalid buffer' };
    }
    const kind = resolveKind(contentType, filename);
    try {
        let r;
        if (kind === 'pdf') r = await extractPdf(buffer);
        else if (kind === 'docx') r = await extractDocx(buffer);
        else if (kind === 'pptx') r = await extractPptx(buffer);
        else if (kind === 'xlsx' || kind === 'csv') r = await extractXlsx(buffer, kind);
        else if (kind === 'text' || kind === 'json') r = await extractText(buffer, kind);
        else return {
            success: false, readable: false, parser: null, mime: kind,
            text: '', quality: 'empty',
            error: `Unsupported format for extraction: ${contentType || extOf(filename) || 'unknown'}`
        };
        const txt = r.text || '';
        const readable = txt.trim().length > 0;
        const quality = readable ? (txt.length > 1200 ? 'high' : (txt.length > 200 ? 'medium' : 'low')) : 'empty';
        return {
            success: true,
            parser: r.parser, mime: kind,
            text: txt, readable,
            content_truncated: !!r.content_truncated,
            pages: r.pages || null,
            sheets: r.sheets || null,
            slides: r.slides || null,
            sections: r.sections || [],
            preview: preview(txt),
            quality, error: null
        };
    } catch (err) {
        return {
            success: false, readable: false,
            parser: null, mime: kind,
            text: '', quality: 'empty',
            error: String((err && err.message) || err)
        };
    }
}

// ---- 4. Structure-aware chunking for the prompt --------------------------
//
// When text_content is long, a flat blob wastes the model's budget. For
// recognized structures we pass a compact outline + key sections. The
// fallback is the original clipped text.

function chunkForPrompt(extracted, intent) {
    if (!extracted || !extracted.readable) return extracted && extracted.text || '';
    const sections = extracted.sections || [];
    const kinds = (intent && intent.kinds) || ['generic'];
    const wantPaper = kinds.includes('paper');
    const wantSop = kinds.includes('sop');
    const wantPresentation = kinds.includes('presentation');
    const wantData = kinds.includes('data');

    if (sections.length === 0) return extracted.text;

    // Paper: prefer abstract/methods/results/discussion/limitations
    if (wantPaper) {
        const pick = ['abstract','introduction','methods','materials and methods','results','discussion','conclusions','conclusion','limitations'];
        const chosen = sections.filter(s => pick.some(p => s.kind.startsWith(p)));
        if (chosen.length) return chosen.map(s => `## ${s.kind.toUpperCase()}\n${s.content}`).join('\n\n');
    }
    // SOP: title / scope / materials / procedure / qc / version
    if (wantSop) {
        const pick = ['title','scope','purpose','materials','reagents','equipment','procedure','steps','safety','qc','quality control','version'];
        const chosen = sections.filter(s => pick.some(p => s.kind.startsWith(p)));
        if (chosen.length) return chosen.map(s => `## ${s.kind.toUpperCase()}\n${s.content}`).join('\n\n');
    }
    // Presentation: already a slide-by-slide outline
    if (wantPresentation) {
        return sections.map(s => s.content).join('\n\n');
    }
    // Data: sheet list + headers + small previews (already formatted that way)
    if (wantData) return extracted.text;

    // Default: outline + first few sections
    return sections.slice(0, 6).map(s => `## ${s.kind.toUpperCase()}\n${s.content}`).join('\n\n');
}

// ---- 5. Trace object -----------------------------------------------------
//
// Small, structured, safe to log or pipe back to the frontend in a debug
// channel. Never contains raw document text or secrets — only identities,
// scores, and status flags.

function buildTrace({ intent, candidates, selected, extraction, fallbackUsed, promptSize, confidence }) {
    return {
        source_module: 'zoeRetrieval',
        intent: intent ? {
            kinds: intent.kinds, tokens: intent.tokens,
            flags: intent.flags
        } : null,
        candidates: (candidates || []).slice(0, 5).map(c => ({
            id: c.id, title: (c.title || '').slice(0, 120),
            source_kind: c.source_kind || null,
            score: c.score, match_reason: c.match_reason,
            readable: !!c.readable
        })),
        selected: selected ? {
            id: selected.id, title: (selected.title || '').slice(0, 120),
            source_kind: selected.source_kind || null,
            r2_key_present: !!selected.r2_object_key,
        } : null,
        extraction: extraction ? {
            success: !!extraction.success,
            parser: extraction.parser || null,
            quality: extraction.quality || null,
            readable: !!extraction.readable,
            content_truncated: !!extraction.content_truncated,
            error: extraction.error || null
        } : null,
        fallback_used: !!fallbackUsed,
        prompt_size: promptSize || null,
        confidence: confidence || null,
    };
}

// ---- Exports -------------------------------------------------------------

module.exports = {
    ZOE_DOC_MAX_CHARS,
    tokenize,
    classifyIntent,
    isReadableFormat,
    scoreCandidate,
    rankCandidates,
    confidenceOf,
    resolveKind,
    extractContent,
    chunkForPrompt,
    buildTrace,
};
