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

// Stopwords (Phase 4.1: widened).
// We drop short connective words plus domain nouns the user asks about
// directly ("paper", "sop", "data") — the intent flags already capture those,
// and keeping them as tokens just inflates ILIKE recall with noise like
// "%in%" matching every filename.
const STOPWORDS = new Set([
    // articles / determiners
    'the','a','an','this','that','these','those','some','any','every','each','all','many','most','few','several','such','own',
    // conjunctions / prepositions / common glue
    'and','or','but','nor','so','for','yet','if','as','at','by','in','of','on','to','up','via','per','vs',
    'into','onto','over','under','above','below','with','without','within','about','around','between','during','since','until','upon','along','against','through',
    // pronouns
    'i','me','my','mine','we','us','our','ours','you','your','yours','he','him','his','she','her','hers','it','its','they','them','their','theirs',
    // copulas / auxiliaries / common verbs
    'is','am','are','was','were','be','been','being','have','has','had','having','do','does','did','done','doing','will','shall','should','would','could','may','might','must','ought','can',
    // wh-words / discourse
    'who','whom','whose','which','what','when','where','why','how','here','there','then','than','while',
    // zoe-verbs — the user's action word, not about the content
    'read','show','tell','find','open','fetch','give','please','summarize','summarise','analyze','analyse','explain','describe','compare','review','locate','search','display',
    // domain nouns already captured by intent.flags
    'paper','papers','publication','publications','article','articles','journal','journals','manuscript','preprint',
    'sop','sops','protocol','protocols','procedure','procedures',
    'presentation','presentations','slides','slide','deck','ppt','pptx',
    'report','reports','summary','overview','brief',
    'data','dataset','datasets','spreadsheet','csv','xls','xlsx','results','result',
    'doc','docs','document','documents','file','files','pdf',
    // recency words
    'latest','newest','last','recent','today','yesterday',
    // meta-words people use in prompts
    'one','two','three','sentence','sentences','paragraph','paragraphs','line','lines','word','words','point','points','bullet','bullets','short','long','quick','brief','detail','details','more','less','very','really','just','only','also','even','still','already','again','simply','basically','actually','generally','usually','often','sometimes',
    'thing','things','item','items','case','cases','way','ways','kind','kinds','type','types','part','parts'
]);

// Tokenize (Phase 4.1): raise the min-length bar to 3 so junk tokens like
// "in", "on", "to" can't leak through into the ILIKE search and match
// everything. Keep numerics at length 2 (e.g. "A5") by allowing any token
// that contains a digit.
function tokenize(q) {
    return String(q || '').toLowerCase()
        .split(/[^a-z0-9]+/)
        .filter(t => t.length >= 3 && !STOPWORDS.has(t))
        .slice(0, 12);
}

function classifyIntent(message) {
    const m = String(message || '').toLowerCase();
    const kinds = [];
    // Phase 4.3: SOP signals split into strong (always SOP) vs weak (could
    //  overlap with a paper-methods follow-up). Weak signals defer to
    //  wantsPaper so "methods section of the paper" stays a paper intent.
    const wantsPaper = /\b(paper|publication|article|journal|manuscript|preprint|doi)\b/.test(m);
    const sopStrong = /\bsops?\b|\bstandard operating procedures?\b|\bprotocols?\b/.test(m);
    const sopWeak = /\bprocedures?\b|\bmethods?\b|\bpreps?\b|\bpreparation\b/.test(m);
    const flags = {
        wantsPaper,
        wantsSop: sopStrong || (sopWeak && !wantsPaper),
        wantsPresentation: /\b(presentation|slides?|deck|ppt|pptx)\b/.test(m),
        wantsReport: /\b(report|summary|overview|brief)\b/.test(m),
        // Phase 4.3: add explicit "excel" to data keywords.
        wantsData: /\b(data|dataset|csv|xls|xlsx|excel|spreadsheet|table|results?)\b/.test(m),
        wantsLatest: /\b(latest|newest|last|most recent|recent|yesterday|today)\b/.test(m),
        isFollowUp: /\b(methods?|results?|discussion|conclusions?|abstract|limitations?|references?|version|compare|same|that one|it|its)\b/.test(m)
            && !/\b(paper|sop|presentation|report|file|document|data)\b/.test(m),
        isCapability: /\b(can you|are you able|do you|will you)\b[\s\S]{0,60}\b(read|access|analyz|search|find|see|retrieve|open)\b/.test(m),
        // Phase 4.3: listing intent ("list SOPs", "show data", "recent presentations").
        // When set, callers should broaden the search (no token filter) and return
        // multiple ranked candidates rather than selecting a single document.
        isListing: /^\s*(list|show( me)?|all|recent|latest|any|give me|what)\s+[a-z0-9]+/i.test(m)
            || /\b(list|show all|all the)\s+(sops?|protocols?|procedures?|data|datasets?|presentations?|slides?|decks?|reports?|papers?|documents?|files?)\b/i.test(m),
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
// Phase 4.1: also match "SOP Template 7" and "form-blank" variants.
const TEMPLATE_HINTS = /\b(templates?|forms?|blank|empty|example|draft[- ]?template|checklist|placeholders?|stub)\b/i;
const ADMIN_HINTS = /\b(admin|invoice|receipt|order|ticket|signoff|sign[- ]?off)\b/i;
const PAPER_EVIDENCE = /\b(paper|publication|journal|article|manuscript|preprint|abstract|doi|authors?|references?|bibliography)\b/i;
const SOP_EVIDENCE = /\b(sop|protocol|procedure|sop[-_ ]?[0-9]+|procedure[-_ ]?[0-9]+)\b/i;

// Strong test: "Template 7", "SOP Template", "blank form" etc.
function isLikelyTemplate(row) {
    const title = String((row && (row.title || row.filename)) || '');
    const cat = String((row && (row.category || '')) || '');
    return TEMPLATE_HINTS.test(title) || TEMPLATE_HINTS.test(cat);
}

// Phase 4.3: canonical document-type taxonomy. All sources (di_submissions,
// di_group_documents, rd_documents, internal_docs) collapse to one of:
//   SOP | DATA | PRESENTATION | REPORT | PAPER | OTHER
// This lets the ranker and the prompt steer consistently regardless of how
// the file was originally tagged. Pure inspection — no DB or R2 access.
function normalizeDocType(row) {
    if (!row) return 'OTHER';
    const type = String(row.type || row.file_type || '').toLowerCase().trim();
    const category = String(row.category || '').toLowerCase().trim();
    const title = String(row.title || row.filename || '').toLowerCase();
    const ext = extOf(row.filename || row.title);
    const sourceKind = String(row.source_kind || '').toLowerCase();

    // rd_documents carry an explicit document_type tag set by the uploader.
    // Values from migration 046: 'SOP', 'DATA', 'PRES', 'REPORT', 'DOCS'.
    if (sourceKind === 'rd_document') {
        if (type === 'sop' || category === 'sop') return 'SOP';
        if (type === 'data' || category === 'data') return 'DATA';
        if (type === 'pres' || type === 'presentation' || category === 'pres') return 'PRESENTATION';
        if (type === 'report' || category === 'report') return 'REPORT';
    }
    // Internal-docs: 'papers/' folder maps to PAPER; others keep their labels.
    if (sourceKind === 'internal_doc' && (category === 'papers' || type === 'paper')) return 'PAPER';

    // Extension-based inference (fast path for submissions/group docs).
    if (ext === 'pptx' || /present|slide|deck|\bppt\b/.test(type)) return 'PRESENTATION';
    if (['xlsx', 'xls', 'csv'].includes(ext) || /spreadsheet|\bexcel\b|\bcsv\b/.test(type)) return 'DATA';

    // Title/category inspection for PDFs and docx (SOPs often live there).
    if (/\bsop\b|\bprotocols?\b|\bprocedures?\b/.test(title) ||
        /\bsop\b|\bprotocols?\b/.test(category)) return 'SOP';
    if (/\breports?\b|\bsummary\b|\boverview\b/.test(title) ||
        /\breports?\b/.test(category)) return 'REPORT';
    if (ext === 'pdf' && (PAPER_EVIDENCE.test(title) || PAPER_EVIDENCE.test(category))) return 'PAPER';
    if (/\bpresentations?\b|\bslides?\b|\bdeck\b/.test(title)) return 'PRESENTATION';
    if (/\bdata(set)?\b/.test(title)) return 'DATA';

    return 'OTHER';
}

// Phase 4.3: per-intent extraction hint for the prompt builder. Steers the
// downstream model to render SOPs as steps, DATA as summarized tables, and
// PRESENTATIONS as slide outlines — without touching the content itself.
function extractionHintFor(intent) {
    const k = (intent && intent.kinds) || ['generic'];
    const f = (intent && intent.flags) || {};
    if (k.includes('sop') || f.wantsSop) {
        return 'sop: render as a numbered step list; keep the original order; surface safety and QC notes at the end';
    }
    if (k.includes('data') || f.wantsData) {
        return 'data: summarize each sheet; list key columns and the first few rows; call out totals, ranges, or obvious outliers';
    }
    if (k.includes('presentation') || f.wantsPresentation) {
        return 'presentation: list slide titles with one-line bullets each; preserve slide order';
    }
    if (k.includes('report') || f.wantsReport) {
        return 'report: give a 3-5 sentence executive summary; list key findings as bullets';
    }
    if (k.includes('paper') || f.wantsPaper) {
        return 'paper: cite by section (abstract / methods / results / discussion); keep citations to sections present in the extract';
    }
    return null;
}

// Phase 4.1: minimum score a candidate must clear before /api/zoe/retrieve
// is willing to auto-select it. If no candidate clears the bar we return
// selected=null — the prompt then tells Zoe to say "no matching file" rather
// than forcing an irrelevant document.
// Paper queries demand real paper evidence; generic "what's new" queries
// demand nothing.
function minScoreForIntent(intent) {
    if (!intent || !intent.flags) return 0;
    if (intent.flags.wantsPaper) return 14;
    if (intent.flags.wantsSop) return 10;
    if (intent.flags.wantsPresentation) return 10;
    if (intent.flags.wantsReport) return 8;
    if (intent.flags.wantsData) return 8;
    return 0;
}

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

    // (c) intent hints — Phase 4.1: evidence-based. A paper query only
    //     rewards candidates with positive paper evidence, and actively
    //     pushes templates to the bottom. Evidence is checked against title,
    //     category, type, and filename.
    const typeStr = norm(
        (row.type || row.file_type || '') + ' ' + (row.category || '') + ' ' +
        (row.filename || row.title || '')
    );
    const extStr = extOf(row.filename || row.title);
    const template = isLikelyTemplate(row);
    const normalizedType = normalizeDocType(row);

    if (intent.flags.wantsPaper) {
        const paperEvidence = PAPER_EVIDENCE.test(typeStr) || extStr === 'pdf';
        if (paperEvidence && !template) {
            s += 14; reasons.push('paper evidence');
        }
        if (template) {
            s -= 25; reasons.push('template (paper query)');
        }
        // Non-PDF, non-paper-evidence files are very unlikely to be papers
        if (!paperEvidence && !template && extStr && !['pdf'].includes(extStr)) {
            s -= 4; reasons.push('no paper evidence');
        }
    }
    if (intent.flags.wantsSop) {
        const sopEvidence = SOP_EVIDENCE.test(typeStr);
        if (sopEvidence && !template) { s += 12; reasons.push('SOP evidence'); }
        // A SOP template is still somewhat relevant to a SOP query, but a
        // named SOP should outrank the template.
        if (sopEvidence && template) { s += 3; reasons.push('SOP template (mild)'); }
        if (!sopEvidence && template) { s -= 10; reasons.push('non-SOP template'); }
    }
    if (intent.flags.wantsPresentation && /present|slide|deck|ppt/.test(typeStr)) {
        s += 10; reasons.push('presentation evidence');
    }
    if (intent.flags.wantsReport) {
        if (/report|summary|overview/.test(typeStr)) { s += 6; reasons.push('report evidence'); }
        if (template) { s -= 15; reasons.push('template (report query)'); }
    }
    if (intent.flags.wantsData) {
        if (/data|csv|xls|spreadsheet|\.xlsx/.test(typeStr) || ['csv','xls','xlsx'].includes(extStr)) {
            s += 8; reasons.push('data evidence');
        }
        if (template) { s -= 12; reasons.push('template (data query)'); }
    }

    // (c2) Phase 4.3: additive normalized-type boosts. Complements the
    //     evidence checks above by rewarding candidates that canonicalize
    //     to the requested type even when their file extension or filename
    //     doesn't match the legacy regexes (e.g. an rd_document tagged
    //     document_type='SOP' that happens to be a DOCX).
    if (intent.flags.wantsSop && normalizedType === 'SOP') {
        s += 4; reasons.push('SOP type');
    }
    if (intent.flags.wantsData && normalizedType === 'DATA') {
        s += 4; reasons.push('DATA type');
    }
    if (intent.flags.wantsPresentation && normalizedType === 'PRESENTATION') {
        s += 4; reasons.push('PRESENTATION type');
    }
    if (intent.flags.wantsReport && normalizedType === 'REPORT') {
        s += 3; reasons.push('REPORT type');
    }
    // Project-linked bonus for operational doc queries: any project association
    // is useful signal (separate from the session projectHintId match below).
    if ((intent.flags.wantsSop || intent.flags.wantsData || intent.flags.wantsPresentation)
        && row.project_id) {
        s += 1; reasons.push('project-linked');
    }

    // (d) readability bonus — smaller than before so it cannot by itself
    //     elevate a wrong-kind file above a right-kind unreadable one.
    if (row.r2_object_key && isReadableFormat(row.filename || row.title, row.type || row.file_type)) {
        s += 2; reasons.push('readable');
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

    // (f) admin penalty — small across the board.
    if (ADMIN_HINTS.test(title)) { s -= 3; reasons.push('admin-like'); }

    // (g) recency — linear decay over 180d. Doubled if user asked "latest",
    //     but capped so recency alone cannot lift a wrong-kind candidate
    //     past the intent threshold.
    const now = opts.now || Date.now();
    const t = row.date ? new Date(row.date).getTime() : 0;
    if (t) {
        const ageDays = Math.max(0, (now - t) / (1000 * 3600 * 24));
        const recencyPts = Math.max(0, 5 - (ageDays / 36));
        s += recencyPts;
        if (intent.flags.wantsLatest) s += Math.min(recencyPts, 3);
        // Phase 4.3: for purely generic queries ("what's new", "anything
        //  recent") we lean harder on freshness — +3 for items ≤7d old.
        const isPureGeneric = Array.isArray(intent.kinds)
            && intent.kinds.length === 1 && intent.kinds[0] === 'generic';
        if (isPureGeneric && intent.flags.wantsLatest && ageDays <= 7) {
            s += 3; reasons.push('fresh (≤7d)');
        }
    }

    // (h) missing R2 key — we can't actually read the file
    if (!row.r2_object_key) { s -= 6; reasons.push('no stored object'); }

    // (i) project continuity bonus (supplied by the caller from session memory)
    if (opts.projectHintId && row.project_id && opts.projectHintId === row.project_id) {
        s += 5; reasons.push('matches active project');
    }

    return { score: Math.round(s * 100) / 100, reasons, normalized_type: normalizedType };
}

// Rank a list of candidates and attach score + reasons. Returns a new sorted
// array (does not mutate the input).
function rankCandidates(rows, intent, opts) {
    const out = rows.map(r => {
        const sc = scoreCandidate(r, intent, opts);
        return Object.assign({}, r, {
            score: sc.score,
            match_reason: sc.reasons.slice(0, 3).join('; ') || 'field match',
            // Phase 4.3: carry the ranker's verdict on the canonical document
            //  type and a compact "why selected" reason list up to the caller.
            normalized_type: sc.normalized_type || normalizeDocType(r),
            why_selected: sc.reasons.slice(0, 5),
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

    // Phase 4.3: per-intent extraction preamble. A short, labeled header the
    //  downstream model can treat as a rendering hint without changing the
    //  underlying content. Paper queries keep their existing behavior.
    const hintSop = '[FORMAT] SOP — render as numbered steps; preserve order; call out safety/QC last.\n\n';
    const hintData = '[FORMAT] DATA — summarize each sheet; list headers and preview rows.\n\n';
    const hintPres = '[FORMAT] PRESENTATION — slide titles with bullets; keep slide order.\n\n';

    if (sections.length === 0) {
        if (wantSop) return hintSop + extracted.text;
        if (wantData) return hintData + extracted.text;
        if (wantPresentation) return hintPres + extracted.text;
        return extracted.text;
    }

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
        if (chosen.length) return hintSop + chosen.map(s => `## ${s.kind.toUpperCase()}\n${s.content}`).join('\n\n');
    }
    // Presentation: already a slide-by-slide outline
    if (wantPresentation) {
        return hintPres + sections.map(s => s.content).join('\n\n');
    }
    // Data: sheet list + headers + small previews (already formatted that way)
    if (wantData) return hintData + extracted.text;

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
            // Phase 4.3: surface canonical type + why it scored as it did.
            normalized_type: c.normalized_type || normalizeDocType(c),
            score: c.score, match_reason: c.match_reason,
            readable: !!c.readable
        })),
        selected: selected ? {
            id: selected.id, title: (selected.title || '').slice(0, 120),
            source_kind: selected.source_kind || null,
            normalized_type: selected.normalized_type || normalizeDocType(selected),
            why_selected: selected.match_reason
                || (Array.isArray(selected.why_selected) ? selected.why_selected.join('; ') : null),
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
        extraction_hint: extractionHintFor(intent),
    };
}

// ---- Exports -------------------------------------------------------------

module.exports = {
    ZOE_DOC_MAX_CHARS,
    tokenize,
    classifyIntent,
    isReadableFormat,
    isLikelyTemplate,
    normalizeDocType,
    extractionHintFor,
    minScoreForIntent,
    scoreCandidate,
    rankCandidates,
    confidenceOf,
    resolveKind,
    extractContent,
    chunkForPrompt,
    buildTrace,
};
