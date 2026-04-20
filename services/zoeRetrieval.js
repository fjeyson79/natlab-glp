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
        // Phase 4.5: batch-mode intent. Triggers multi-doc retrieval + analysis
        //  when the user asks to review / compare / evaluate many files, or
        //  asks "which ones ..." questions. Distinct from isListing: listing
        //  returns a ranked list for user-facing display; batch retrieves AND
        //  extracts each file so Zoe can reason across them in one answer.
        wantsBatch:
            /\b(all|every|each|bulk)\s+([a-z-]+\s+){0,3}(sops?|protocols?|procedures?|data|datasets?|files?|docs?|documents?|presentations?|slides?|decks?|reports?|papers?)\b/i.test(m)
            || /\b(review all|compare|comparison|comparing|compared|evaluate all|analys[ez]e all|audit all|list and (review|evaluate|analys[ez]e))\b/i.test(m)
            || /\bwhich (one|ones|files?|docs?|sops?|datasets?|presentations?|papers?|documents?)\b/i.test(m)
            || /\bacross\s+(researchers?|files?|docs?|sops?|datasets?|presentations?|papers?|(the )?lab|(the )?team)\b/i.test(m),
        // Phase 4.7: status flags. Useful for "approved UNAV SOPs",
        //  "pending submissions", "legacy data" etc. Each adds a small
        //  scoring bump when the candidate's parsed status_from_path matches.
        wantsApproved: /\b(approved|signed|sealed|final(ized)?)\b/i.test(m),
        wantsSubmitted: /\b(submitted|pending|draft|awaiting)\b/i.test(m),
        wantsLegacy: /\blegacy\b/i.test(m),
    };
    if (flags.wantsPaper) kinds.push('paper');
    if (flags.wantsSop) kinds.push('sop');
    if (flags.wantsPresentation) kinds.push('presentation');
    if (flags.wantsReport) kinds.push('report');
    if (flags.wantsData) kinds.push('data');
    if (kinds.length === 0) kinds.push('generic');
    // Phase 4.7: workspace / organization hint. Detected case-insensitively
    //  against the raw query so queries like "approved UNAV SOPs" or
    //  "theralia board meetings" can steer path-aware ranking. Null when no
    //  known workspace token is present. Values match the `organization`
    //  value returned by parseR2Path so the ranker can compare directly.
    let workspaceHint = null;
    if (/\bunav\b/i.test(message || '')) workspaceHint = 'UNAV';
    else if (/\bliu\b/i.test(message || '')) workspaceHint = 'LiU';
    else if (/\btheralia\b/i.test(message || '')) workspaceHint = 'theralia';
    else if (/\bnatlab\b/i.test(message || '')) workspaceHint = 'natlab';
    const tokens = tokenize(m);
    return { kinds, tokens, flags, workspaceHint, raw: String(message || '') };
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

// Phase 4.4: diacritic-stripping lowercase normalizer. Needed so "Jürgen"
// in a filename or roster entry compares cleanly against ascii tokens from
// the query. No external deps; relies on NFD normalization.
function normAscii(s) {
    return String(s || '').normalize('NFD').replace(/[\u0300-\u036f]/g, '').toLowerCase();
}

// Phase 4.7: structural segment + filename-token maps. The same parser can
// read both: "rd/{ws}/{proj}/SOP/…" (segment-based) and the embedded-in-
// filename convention "YYYY-MM-DD_{INITIALS}_{TYPE}_{topic}.pdf".
const _PATH_TYPE_SEGMENTS = {
    SOP: 'SOP', sop: 'SOP',
    DATA: 'DATA', data: 'DATA',
    PRES: 'PRESENTATION', PRESENTATION: 'PRESENTATION', Presentation: 'PRESENTATION',
    REPORT: 'REPORT', Report: 'REPORT', REPORTS: 'REPORT',
    PAPER: 'PAPER', papers: 'PAPER', Papers: 'PAPER',
};
const _PATH_STATUS_SEGMENTS = {
    Submitted: 'SUBMITTED', submitted: 'SUBMITTED',
    Approved: 'APPROVED', approved: 'APPROVED',
    Training: 'TRAINING', training: 'TRAINING',
};
const _FILENAME_TYPE_TOKENS = {
    sop: 'SOP', protocol: 'SOP', protocols: 'SOP',
    data: 'DATA', dataflash: 'DATA', dataset: 'DATA',
    pres: 'PRESENTATION', presentation: 'PRESENTATION',
    slides: 'PRESENTATION', deck: 'PRESENTATION',
    report: 'REPORT', summary: 'REPORT',
    paper: 'PAPER', preprint: 'PAPER',
};
const _RX_ISO_DATE = /^\d{4}-\d{2}-\d{2}$/;
// Researcher initials: 2–5 uppercase letters, optional 1–2 digit suffix
// (FJH, BAB, HJM, SKP, FJH2). We keep the bar at 2+ letters to avoid
// triggering on stray single-letter joiners.
const _RX_INITIALS = /^[A-Z]{2,5}\d{0,2}$/;

// Phase 4.4/4.7: parse an R2 key into searchable parts. All operational
// files are PDFs stored under an org/researcher/date/filename-ish prefix,
// but every source uses a slightly different layout:
//   di/{aff}/Submitted/{year}/{dateStamp}_{researcher_id}_{safeOriginal}
//   di/{aff}/Approved/Training/{year}/{ts}_{safeName}
//   rd/{workspace}/{projectId}/{docType}/{ts}_{safeName}
//   group-docs/internal/{category}[/{subfolder}]*/{filename}
//   company/{ws}/{section}/{ts}_{safeName}
//   theralia/..., oligo/..., system_versions/..., glp-status/...
// This parser is intentionally lenient: it returns whatever it can, plus a
// lowercase haystack joining every segment for path-aware ranking.
//
// Phase 4.7 additive fields (all optional — null when not detected):
//   type_from_path      : SOP|DATA|PRESENTATION|REPORT|PAPER
//   type_from_filename  : same set, parsed from the filename convention
//   status_from_path    : SUBMITTED|APPROVED|TRAINING|LEGACY
//   iso_date            : 'YYYY-MM-DD' from the filename, if present
//   researcher_code     : uppercase initials token from the filename
//   topic               : description tail of the filename, or null
function parseR2Path(key) {
    if (!key) return null;
    const s = String(key);
    const parts = s.split('/').filter(Boolean);
    if (parts.length === 0) return null;
    const filename = parts[parts.length - 1];
    const organization = parts[0] || null;
    // Try to find YYYY or YYYY-MM-DD-ish segments as chronological hints.
    const chronoSegments = [];
    const RX_YEAR = /^\d{4}$/;
    const RX_DATE = /^\d{4}-\d{2}(-\d{2})?$/;
    const RX_TS   = /^\d{10,14}/; // unix ms / compact ts prefix
    for (const p of parts) {
        if (RX_YEAR.test(p) || RX_DATE.test(p)) chronoSegments.push(p);
        else if (RX_TS.test(p)) chronoSegments.push(p.slice(0, 10));
    }
    // Phase 4.7: scan segments for high-confidence type + status markers.
    let type_from_path = null;
    let status_from_path = null;
    for (const p of parts) {
        if (!type_from_path && _PATH_TYPE_SEGMENTS[p]) type_from_path = _PATH_TYPE_SEGMENTS[p];
        if (!status_from_path && _PATH_STATUS_SEGMENTS[p]) status_from_path = _PATH_STATUS_SEGMENTS[p];
    }
    // For di/{aff}/Submitted/{year}/{dateStamp}_{researcher_id}_... the
    // researcher_id is embedded in the filename; we surface the filename
    // stem as an additional haystack bucket.
    const stem = String(filename).replace(/\.[a-z0-9]{2,5}$/i, '');
    // Phase 4.7: parse the filename convention DATE_RESEARCHER_TYPE_TOPIC.
    //  Each slot is optional and parsed in order. Tokens that don't match
    //  a slot shift into the topic remainder.
    let iso_date = null;
    let researcher_code = null;
    let type_from_filename = null;
    let topic = null;
    // Split on underscore/space only — dashes are preserved inside ISO
    // dates (2026-03-17) and hyphenated descriptors (nuclease-activity).
    const stemTokens = stem.split(/[_\s]+/).filter(Boolean);
    if (stemTokens.length) {
        let idx = 0;
        if (_RX_ISO_DATE.test(stemTokens[0])) {
            iso_date = stemTokens[0];
            idx += 1;
        }
        if (idx < stemTokens.length && _RX_INITIALS.test(stemTokens[idx])) {
            researcher_code = stemTokens[idx];
            idx += 1;
        }
        if (idx < stemTokens.length) {
            const t = stemTokens[idx].toLowerCase();
            if (_FILENAME_TYPE_TOKENS[t]) {
                type_from_filename = _FILENAME_TYPE_TOKENS[t];
                idx += 1;
            }
        }
        const rest = stemTokens.slice(idx).join(' ').trim();
        topic = rest || null;
    }
    // Legacy marker in filename (not in path).
    if (!status_from_path && /\bLEGACY\b/.test(stem)) status_from_path = 'LEGACY';

    const hay = normAscii(parts.join(' ') + ' ' + stem);
    return {
        organization,
        segments: parts,
        filename,
        stem,
        chrono_segments: chronoSegments,
        hay, // lowercase ascii-folded join for substring tests
        // Phase 4.7 additive fields — null when not detectable.
        type_from_path,
        type_from_filename,
        status_from_path,
        iso_date,
        researcher_code,
        topic,
    };
}

// Phase 4.7: default-ignore list. These prefixes/substrings surface non-
// document artifacts (weekly snapshots, system-version archives, Studio
// working state, trash) that Zoe should skip unless the caller explicitly
// opts in. Callers filter candidate rows through this helper before
// ranking; no scoring penalty needed.
const _R2_IGNORE_PREFIXES = ['glp-status/', 'system_versions/', 'trash/'];
const _R2_IGNORE_SUBSTRINGS = ['/trash/', '/Studio/', '/rs-studio/', '/Studio_v1/'];
function shouldIgnoreR2Path(key) {
    if (!key) return false;
    const s = String(key);
    if (s.endsWith('/.keep')) return true;
    for (const p of _R2_IGNORE_PREFIXES) if (s.startsWith(p)) return true;
    for (const p of _R2_IGNORE_SUBSTRINGS) if (s.includes(p)) return true;
    return false;
}

// Phase 4.4: detect a researcher reference in a free-text question.
// `roster` is the list passed by the caller — each entry is
//   { researcher_id, name, first_name?, last_name?, email? }
// Returns the best-matching entry along with the token that matched, or
// null if no entry is referenced. The caller decides how aggressively to
// filter candidates based on the result.
function detectResearcherInQuery(question, roster) {
    if (!question || !Array.isArray(roster) || roster.length === 0) return null;
    const q = normAscii(question);
    // Word-boundary presence test, ascii-folded on both sides.
    const contains = (needle) => {
        const n = normAscii(needle).trim();
        if (!n || n.length < 2) return false;
        // Avoid matching 1-2 letter initials inside other words.
        const esc = n.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
        const re = new RegExp('(^|[^a-z0-9])' + esc + '([^a-z0-9]|$)');
        return re.test(q);
    };
    let best = null;
    let bestScore = 0;
    for (const r of roster) {
        const first = r.first_name || (String(r.name || '').trim().split(/\s+/)[0] || '');
        const lastParts = String(r.name || '').trim().split(/\s+/);
        const last = r.last_name || (lastParts.length > 1 ? lastParts[lastParts.length - 1] : '');
        // Score: id > last-name > first-name. Longer tokens beat shorter.
        let score = 0;
        let matched = null;
        if (r.researcher_id && contains(r.researcher_id)) {
            score = 30 + String(r.researcher_id).length;
            matched = r.researcher_id;
        } else if (last && last.length >= 3 && contains(last)) {
            score = 20 + last.length;
            matched = last;
        } else if (first && first.length >= 3 && contains(first)) {
            score = 10 + first.length;
            matched = first;
        }
        if (score > bestScore) {
            bestScore = score;
            best = {
                researcher_id: r.researcher_id || null,
                name: r.name || null,
                first_name: first || null,
                last_name: last || null,
                matched_token: matched,
                email: r.email || null,
            };
        }
    }
    return best;
}

// Phase 4.4: per-candidate researcher/path match. Returns an object the
// ranker uses for boosts and the trace uses for diagnostics. Pure
// inspection — no DB or R2 access.
function matchCandidateToResearcher(row, hint) {
    if (!row || !hint) {
        return { uploader: false, path: false, filename: false, any: false };
    }
    const rid = normAscii(hint.researcher_id || '');
    const fn = normAscii(hint.first_name || '');
    const ln = normAscii(hint.last_name || '');
    const fields = [
        normAscii(row.uploader || ''),
        normAscii(row.uploader_name || ''),
        normAscii(row.uploader_first_name || ''),
        normAscii(row.uploader_last_name || ''),
    ].join(' ');
    const pathHay = normAscii((row.r2_path && row.r2_path.hay) || '');
    const fileHay = normAscii(row.filename || row.title || '');

    const hasIn = (hay, needle) => !!(needle && needle.length >= 2 && hay.includes(needle));
    const uploader = hasIn(fields, rid) || hasIn(fields, ln) || hasIn(fields, fn);
    const path = hasIn(pathHay, rid) || hasIn(pathHay, ln) || hasIn(pathHay, fn);
    const filename = hasIn(fileHay, rid) || hasIn(fileHay, ln) || hasIn(fileHay, fn);
    return { uploader, path, filename, any: uploader || path || filename };
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

    // (j) Phase 4.4: researcher-aware boosts. Only fire when the caller has
    //     detected a researcher reference in the query (opts.researcherHint).
    //     Researcher match via uploader field is the strongest signal; R2
    //     path and filename serve as fallbacks when metadata is thin.
    let researcherMatch = null;
    if (opts.researcherHint) {
        researcherMatch = matchCandidateToResearcher(row, opts.researcherHint);
        if (researcherMatch.uploader) { s += 20; reasons.push('researcher uploader'); }
        else if (researcherMatch.path) { s += 10; reasons.push('researcher in path'); }
        else if (researcherMatch.filename) { s += 5; reasons.push('researcher in filename'); }
        else {
            // Hard downrank when the user asked for a specific researcher and
            // this candidate has no signal connecting to that researcher. Keep
            // the penalty large enough to drop mismatches below the intent
            // threshold (minScoreForIntent), but not so large it banishes
            // PAPER candidates (which legitimately may have no uploader).
            if (normalizedType !== 'PAPER') {
                s -= 10; reasons.push('researcher mismatch');
            }
        }
    }

    // (k) Phase 4.4: R2 path tokens. Score a small additive bump per query
    //     token found anywhere in the key (organization / workspace / year /
    //     folder names). Capped so path never overpowers type/researcher.
    if (row.r2_path && row.r2_path.hay) {
        const pathHay = row.r2_path.hay;
        let pathHits = 0;
        for (const t of tokens) {
            if (!t || t.length < 3) continue;
            if (pathHay.includes(t)) pathHits++;
        }
        if (pathHits > 0) {
            const add = Math.min(6, pathHits * 2);
            s += add;
            reasons.push(`path match×${pathHits}`);
        }
    }

    // (l) Phase 4.4: filename stem substring bonus. A strong signal when the
    //     query contains an unusual keyword (project code, acronym) that
    //     lines up with the filename — e.g. "TOUCAN" in "baris_toucan_v3.pdf".
    if (tokens.length) {
        const stem = normAscii(
            (row.r2_path && row.r2_path.stem) || row.filename || row.title || ''
        );
        if (stem) {
            let stemHits = 0;
            for (const t of tokens) {
                if (!t || t.length < 4) continue;
                if (stem.includes(t)) stemHits++;
            }
            if (stemHits > 0) {
                s += Math.min(6, stemHits * 3);
                reasons.push(`filename stem×${stemHits}`);
            }
        }
    }

    // (m) Phase 4.7: path- and filename-structural type boost. When the
    //     query is operational (SOP/DATA/PRES/REPORT/PAPER) and the parsed
    //     path segment or filename token resolves to the same canonical
    //     type, reward it above the general type-evidence check. Mirrors
    //     rd/*/SOP/ and DATE_XX_TYPE_topic.pdf conventions.
    if (row.r2_path) {
        const tp = row.r2_path.type_from_path;
        const tf = row.r2_path.type_from_filename;
        const wantedType =
            intent.flags.wantsSop ? 'SOP' :
            intent.flags.wantsData ? 'DATA' :
            intent.flags.wantsPresentation ? 'PRESENTATION' :
            intent.flags.wantsReport ? 'REPORT' :
            intent.flags.wantsPaper ? 'PAPER' : null;
        if (wantedType && tp === wantedType) {
            s += 8; reasons.push('type in path segment');
        }
        if (wantedType && tf === wantedType) {
            s += 6; reasons.push('type in filename token');
        }
        // (n) Phase 4.7: status match from path/filename (Submitted,
        //     Approved, LEGACY). Fires only when the user's query mentioned
        //     the corresponding status; otherwise ignored so it doesn't
        //     bias generic queries toward any particular folder.
        const sp = row.r2_path.status_from_path;
        if (intent.flags.wantsApproved && sp === 'APPROVED') {
            s += 6; reasons.push('approved path');
        }
        if (intent.flags.wantsSubmitted && sp === 'SUBMITTED') {
            s += 5; reasons.push('submitted path');
        }
        if (intent.flags.wantsLegacy && sp === 'LEGACY') {
            s += 6; reasons.push('legacy marker');
        }
        // (o) Phase 4.7: workspace / organization hint. Reward when the
        //     R2 path starts with the named workspace/org.
        if (opts.workspaceHint && row.r2_path.organization) {
            const want = String(opts.workspaceHint).toLowerCase();
            const have = String(row.r2_path.organization).toLowerCase();
            // Also match nested workspace names (rd/natlab/... or
            // rd/theralia/...) where the organization is 'rd' but the
            // workspace follows — check segments[1] too.
            const segWs = (row.r2_path.segments && row.r2_path.segments[1] || '').toLowerCase();
            if (have === want || segWs === want) {
                s += 5; reasons.push('workspace match');
            }
        }
    }

    return {
        score: Math.round(s * 100) / 100,
        reasons,
        normalized_type: normalizedType,
        researcher_match: researcherMatch,
    };
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
            // Phase 4.4: attach per-candidate researcher-match flags for trace
            //  and frontend display (null when no researcher was detected).
            researcher_match: sc.researcher_match || null,
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

// ---- 4b. Phase 4.5: per-document analysis + aggregation ------------------
//
// Lightweight, heuristic-only analyzer. No LLM calls. Inspects the extraction
// result for one document and surfaces structural flags (missing sections,
// tiny sheets, title-only slides, hedge language, etc.) that the downstream
// narrator (Zoe / OpenClaw) can reason about when building a batch answer.
// Never throws; returns a stable shape even for failed extractions.

function analyzeDocument(row, extraction, intent) {
    const out = {
        summary: '',
        issues: [],
        quality: (extraction && extraction.quality) || 'empty',
        extraction_hint: extractionHintFor(intent),
        structure: {},
    };
    if (!extraction || !extraction.success) {
        out.issues.push({
            code: 'extraction_failed', severity: 'error',
            message: (extraction && extraction.error) || 'extraction failed'
        });
        out.summary = 'Extraction failed; no content analyzed.';
        return out;
    }
    const nt = (row && (row.normalized_type || normalizeDocType(row))) || 'OTHER';
    const text = (extraction.text || '').trim();
    const chars = text.length;
    if (!extraction.readable || chars === 0) {
        out.issues.push({ code: 'empty_text', severity: 'error', message: 'No readable text extracted.' });
        out.summary = 'Document readable=false; content empty.';
        return out;
    }

    if (nt === 'DATA') {
        const sheets = extraction.sheets || [];
        const sections = extraction.sections || [];
        out.structure.sheets = sheets.length;
        out.structure.sections = sections.length;
        let totalHeaderCols = 0;
        let sheetsWithoutHeaders = 0;
        let tinySheets = 0;
        for (const s of sections) {
            const headerMatch = (s.content || '').match(/Headers:\s*([^\n]+)/);
            const rowMatch = (s.content || '').match(/\((\d+)\s+row\(s\)/);
            const cols = headerMatch && headerMatch[1] !== '(none)'
                ? headerMatch[1].split(',').filter(Boolean).length
                : 0;
            totalHeaderCols += cols;
            if (!cols) sheetsWithoutHeaders++;
            if (rowMatch && parseInt(rowMatch[1], 10) < 3) tinySheets++;
        }
        if (sheets.length === 0) {
            out.issues.push({ code: 'no_sheets', severity: 'warn', message: 'No sheets detected.' });
        }
        if (sheetsWithoutHeaders > 0) {
            out.issues.push({
                code: 'missing_headers', severity: 'warn',
                message: `${sheetsWithoutHeaders} sheet(s) without headers.`
            });
        }
        if (tinySheets > 0) {
            out.issues.push({
                code: 'tiny_sheets', severity: 'warn',
                message: `${tinySheets} sheet(s) with fewer than 3 rows.`
            });
        }
        if (chars < 300) {
            out.issues.push({ code: 'very_thin', severity: 'warn', message: 'Extracted content is very short.' });
        }
        out.summary = `DATA file: ${sheets.length} sheet(s), ${totalHeaderCols} header column(s) total.`;
    } else if (nt === 'SOP') {
        const sections = extraction.sections || [];
        out.structure.sections = sections.length;
        const hasProcedure = sections.some(s => /procedure|steps/i.test(s.kind || ''));
        const hasQC = sections.some(s => /qc|quality|safety/i.test(s.kind || ''));
        const hasVersion = sections.some(s => /version|approval/i.test(s.kind || ''));
        const stepMatches = text.match(/^\s*\d+\.\s/mg) || [];
        out.structure.steps = stepMatches.length;
        if (sections.length === 0) {
            out.issues.push({ code: 'no_sections', severity: 'warn', message: 'No structured section headings detected.' });
        }
        if (!hasProcedure) {
            out.issues.push({ code: 'missing_procedure', severity: 'warn', message: 'No PROCEDURE/STEPS section found.' });
        }
        if (!hasQC) {
            out.issues.push({ code: 'missing_qc', severity: 'info', message: 'No QC / safety section.' });
        }
        if (!hasVersion) {
            out.issues.push({ code: 'missing_version', severity: 'info', message: 'No version/approval marker.' });
        }
        if (stepMatches.length < 3) {
            out.issues.push({
                code: 'few_steps', severity: 'warn',
                message: `Only ${stepMatches.length} numbered step(s) detected.`
            });
        }
        if (chars < 500) {
            out.issues.push({ code: 'too_brief', severity: 'warn', message: 'SOP content is very short (<500 chars).' });
        }
        const ambiguous = (text.match(/\b(approximately|about|some|several|as needed|if required|somewhat|roughly|around|maybe|perhaps)\b/gi) || []).length;
        if (ambiguous >= 5) {
            out.issues.push({
                code: 'ambiguous_language', severity: 'info',
                message: `${ambiguous} hedge word(s) detected (e.g. "approximately", "as needed").`
            });
        }
        out.summary = `SOP: ${sections.length} section(s), ${stepMatches.length} numbered step(s).`;
    } else if (nt === 'PRESENTATION') {
        const slides = extraction.slides || 0;
        const sections = extraction.sections || [];
        out.structure.slides = slides;
        const emptyBody = sections.filter(s => {
            const lines = String(s.content || '').split('\n');
            return lines.length <= 1 || (lines.slice(1).join(' ').trim().length === 0);
        }).length;
        out.structure.slides_without_body = emptyBody;
        if (slides === 0) {
            out.issues.push({ code: 'no_slides', severity: 'error', message: 'No slides detected.' });
        }
        if (slides > 0 && slides < 3) {
            out.issues.push({ code: 'too_few_slides', severity: 'warn', message: `Only ${slides} slide(s).` });
        }
        if (slides > 0 && emptyBody >= Math.max(2, Math.floor(slides / 2))) {
            out.issues.push({
                code: 'sparse_slides', severity: 'warn',
                message: `${emptyBody} slide(s) have titles only (no body).`
            });
        }
        out.summary = `Presentation: ${slides} slide(s), ${emptyBody} title-only.`;
    } else if (nt === 'REPORT') {
        const sections = extraction.sections || [];
        out.structure.sections = sections.length;
        if (chars < 800) {
            out.issues.push({ code: 'too_brief', severity: 'warn', message: 'Report is very short (<800 chars).' });
        }
        if (sections.length < 2) {
            out.issues.push({ code: 'unstructured', severity: 'info', message: 'No clear section structure.' });
        }
        out.summary = `Report: ${sections.length} section(s), ${chars} chars.`;
    } else if (nt === 'PAPER') {
        const sections = extraction.sections || [];
        out.structure.sections = sections.length;
        const hasAbstract = sections.some(s => /abstract/i.test(s.kind || ''));
        const hasMethods = sections.some(s => /method/i.test(s.kind || ''));
        const hasResults = sections.some(s => /result/i.test(s.kind || ''));
        if (!hasAbstract) out.issues.push({ code: 'no_abstract', severity: 'info', message: 'No abstract section detected.' });
        if (!hasMethods) out.issues.push({ code: 'no_methods', severity: 'info', message: 'No methods section detected.' });
        if (!hasResults) out.issues.push({ code: 'no_results', severity: 'info', message: 'No results section detected.' });
        out.summary = `Paper: ${sections.length} section(s) detected.`;
    } else {
        out.summary = `${nt}: ${chars} chars extracted.`;
    }

    if (extraction.content_truncated) {
        out.issues.push({
            code: 'content_truncated', severity: 'info',
            message: `Content truncated at ${ZOE_DOC_MAX_CHARS} chars.`
        });
    }
    return out;
}

// Phase 4.5: roll up per-document analyses into an aggregate view.
// Input: array of { id, title, normalized_type, analysis } entries.
// Output: { total, by_type, strongest[], weakest[], recurring_issues[] }.
function aggregateFindings(entries) {
    const by_type = {};
    const issue_counts = {};
    const strong = [];
    const weak = [];
    for (const e of (entries || [])) {
        const t = e.normalized_type || 'OTHER';
        by_type[t] = (by_type[t] || 0) + 1;
        const a = e.analysis || {};
        const issues = a.issues || [];
        const errors = issues.filter(i => i.severity === 'error').length;
        const warns  = issues.filter(i => i.severity === 'warn').length;
        if (a.quality === 'high' && errors === 0 && warns <= 1) {
            strong.push({ id: e.id, title: e.title });
        }
        if (a.quality === 'low' || a.quality === 'empty' || errors > 0 || warns >= 3) {
            weak.push({ id: e.id, title: e.title });
        }
        for (const iss of issues) {
            issue_counts[iss.code] = (issue_counts[iss.code] || 0) + 1;
        }
    }
    const recurring = Object.entries(issue_counts)
        .filter(([, n]) => n >= 2)
        .sort((a, b) => b[1] - a[1])
        .map(([code, count]) => ({ code, count }));
    return {
        total: (entries || []).length,
        by_type,
        strongest: strong,
        weakest: weak,
        recurring_issues: recurring,
    };
}

// ---- 4d. Phase 4.7: alternatives renderer --------------------------------
//
// When a single file is selected, callers often want to show 2–5 "you might
// also mean..." alternatives. This helper takes the ranked list (after the
// selected candidate has been chosen) and produces up to `max` alternatives
// with a short human-readable relationship label. Pure inspection — no DB
// or R2 access. Preserves ranking order.
function buildAlternatives(selected, ranked, opts, max) {
    const cap = Math.max(0, Math.min(5, parseInt(max, 10) || 3));
    if (!selected || !Array.isArray(ranked) || cap === 0) return [];
    const sel = selected;
    const selTokens = new Set(
        String((sel.title || sel.filename || '')).toLowerCase()
            .split(/[^a-z0-9]+/).filter(t => t.length >= 4)
    );
    const selDate = sel.date ? new Date(sel.date).getTime() : 0;
    const out = [];
    for (const cand of ranked) {
        if (!cand || cand.id === sel.id) continue;
        if (out.length >= cap) break;
        const reason = _alternativeReason(sel, cand, selTokens, selDate, opts);
        out.push({
            id: cand.id,
            title: cand.title,
            source_kind: cand.source_kind || null,
            normalized_type: cand.normalized_type
                || (cand.r2_path && cand.r2_path.type_from_path)
                || normalizeDocType(cand),
            date: cand.date || null,
            score: cand.score,
            reason,
        });
    }
    return out;
}

function _alternativeReason(sel, cand, selTokens, selDate, opts) {
    const hint = opts && opts.researcherHint;
    const sameResearcher =
        (cand.researcher_match && cand.researcher_match.any)
        || (hint && sel.uploader && cand.uploader && sel.uploader === cand.uploader);
    const sameType = cand.normalized_type
        && sel.normalized_type
        && cand.normalized_type === sel.normalized_type;
    const candDate = cand.date ? new Date(cand.date).getTime() : 0;
    const isOlder = selDate && candDate && candDate < selDate;
    // Topic overlap: count long tokens (≥4 chars) shared with the selected title.
    const candText = String(cand.title || cand.filename || '').toLowerCase();
    let topicHits = 0;
    for (const t of selTokens) { if (candText.includes(t)) topicHits++; }
    const sameTopic = topicHits >= 2;

    if (sameResearcher && sameType && isOlder) return 'same researcher & type (older)';
    if (sameResearcher && sameType) return 'same researcher & type';
    if (sameResearcher && sameTopic) return 'same researcher, related topic';
    if (sameResearcher) return 'same researcher, different type';
    if (sameType && sameTopic) return 'same type, related topic';
    if (sameType) return `same type (${cand.normalized_type || 'document'})`;
    if (sameTopic) return 'related topic';
    if (isOlder) return 'earlier version';
    return 'also ranked';
}

// ---- 4c. Phase 4.6: deterministic batch narrative ------------------------
//
// Produce a structured, markdown-formatted answer from the batch payload
// (documents[] + aggregate). No LLM calls — pure formatting. The output is
// a self-contained answer the frontend can render as-is, or a high-fidelity
// scaffold a downstream model can expand upon. Tone is analytical, not
// alarmist. Structural issues detected automatically are labelled as such
// and kept separate from higher-level interpretation prompts.

const TYPE_LABEL = {
    SOP: 'SOP',
    DATA: 'DATA',
    PRESENTATION: 'Presentation',
    REPORT: 'Report',
    PAPER: 'Paper',
    OTHER: 'Other',
};

function _countWithIssue(docs, code) {
    return (docs || []).filter(d =>
        (d.analysis && d.analysis.issues || []).some(i => i.code === code)
    ).length;
}

function _typeSpecificNotes(type, docs) {
    const notes = [];
    const n = docs.length;
    if (n === 0) return notes;
    if (type === 'SOP') {
        const ambiguous = _countWithIssue(docs, 'ambiguous_language');
        const noProc = _countWithIssue(docs, 'missing_procedure');
        const fewSteps = _countWithIssue(docs, 'few_steps');
        const noQc = _countWithIssue(docs, 'missing_qc');
        const noVersion = _countWithIssue(docs, 'missing_version');
        const tooBrief = _countWithIssue(docs, 'too_brief');
        const noSections = _countWithIssue(docs, 'no_sections');
        if (noProc)   notes.push(`${noProc}/${n} SOP(s) lack an explicit PROCEDURE/STEPS section marker.`);
        if (fewSteps) notes.push(`${fewSteps}/${n} SOP(s) have fewer than 3 numbered steps — procedural detail may be insufficient.`);
        if (ambiguous) notes.push(`${ambiguous}/${n} SOP(s) use hedge language ("approximately", "as needed", "somewhat"), which reduces reproducibility.`);
        if (noQc)     notes.push(`${noQc}/${n} SOP(s) carry no QC or safety section.`);
        if (noVersion) notes.push(`${noVersion}/${n} SOP(s) have no version or approval marker.`);
        if (tooBrief) notes.push(`${tooBrief}/${n} SOP(s) are under 500 characters — verify the full document was captured.`);
        if (noSections) notes.push(`${noSections}/${n} SOP(s) carry no structured section headings at all.`);
        if (notes.length === 0) notes.push(`All ${n} SOP(s) carry procedure, QC, and version markers with adequate length.`);
    } else if (type === 'DATA') {
        const noHeaders = _countWithIssue(docs, 'missing_headers');
        const tiny = _countWithIssue(docs, 'tiny_sheets');
        const thin = _countWithIssue(docs, 'very_thin');
        const noSheets = _countWithIssue(docs, 'no_sheets');
        if (noSheets) notes.push(`${noSheets}/${n} DATA file(s) had no extractable sheets.`);
        if (noHeaders) notes.push(`${noHeaders}/${n} DATA file(s) contain sheets without header rows — column meanings are opaque to a reader.`);
        if (tiny)     notes.push(`${tiny}/${n} DATA file(s) have at least one sheet with fewer than 3 rows — consider whether additional replicates or validation runs are needed.`);
        if (thin)     notes.push(`${thin}/${n} DATA file(s) extracted under 300 characters of readable content — the underlying file may be very small or empty.`);
        if (notes.length === 0) notes.push(`All ${n} DATA file(s) have headers and non-trivial row counts.`);
    } else if (type === 'PRESENTATION') {
        const noSlides = _countWithIssue(docs, 'no_slides');
        const tooFew = _countWithIssue(docs, 'too_few_slides');
        const sparse = _countWithIssue(docs, 'sparse_slides');
        if (noSlides) notes.push(`${noSlides}/${n} deck(s) had no extractable slides — file may be corrupt or exported from a non-pptx source.`);
        if (tooFew)   notes.push(`${tooFew}/${n} deck(s) have fewer than 3 slides — likely drafts rather than full presentations.`);
        if (sparse)   notes.push(`${sparse}/${n} deck(s) have titles but little or no body content on at least half the slides — narrative support is thin.`);
        if (notes.length === 0) notes.push(`All ${n} deck(s) have multi-slide structure with body content.`);
    } else if (type === 'REPORT') {
        const brief = _countWithIssue(docs, 'too_brief');
        const unstructured = _countWithIssue(docs, 'unstructured');
        if (brief)        notes.push(`${brief}/${n} report(s) under 800 characters — likely summaries rather than full analyses.`);
        if (unstructured) notes.push(`${unstructured}/${n} report(s) lack clear section structure.`);
        if (notes.length === 0) notes.push(`All ${n} report(s) are structured and of reasonable length.`);
    } else if (type === 'PAPER') {
        const noAbstract = _countWithIssue(docs, 'no_abstract');
        const noMethods = _countWithIssue(docs, 'no_methods');
        const noResults = _countWithIssue(docs, 'no_results');
        const missing = [];
        if (noAbstract) missing.push(`${noAbstract} without abstract`);
        if (noMethods) missing.push(`${noMethods} without methods`);
        if (noResults) missing.push(`${noResults} without results`);
        if (missing.length) notes.push(`Canonical sections missing in a subset — ${missing.join(', ')}.`);
        if (notes.length === 0) notes.push(`All ${n} paper(s) carry abstract, methods, and results sections.`);
    } else {
        notes.push(`${n} ${TYPE_LABEL[type] || type} document(s) analyzed; type-specific heuristics not defined.`);
    }
    return notes;
}

const _RECOMMEND_MAP = {
    missing_headers: (n) => `Add header rows to sheets where they are missing (${n} file(s) affected) so columns are self-describing.`,
    tiny_sheets: (n) => `Consolidate or augment sheets with fewer than 3 rows across ${n} file(s) — verify whether data capture is complete.`,
    no_sheets: (n) => `${n} DATA file(s) yielded no sheets — confirm the file format is readable.`,
    missing_procedure: (n) => `Label the PROCEDURE or STEPS section explicitly in ${n} SOP(s) so operational detail is locatable.`,
    few_steps: (n) => `Expand procedural detail in ${n} SOP(s) where fewer than 3 numbered steps were detected.`,
    missing_qc: (n) => `Add a QC or safety section to ${n} SOP(s) to meet documentation standards.`,
    missing_version: (n) => `Include a version or approval marker in ${n} SOP(s) for traceability.`,
    ambiguous_language: (n) => `Tighten hedge language ("approximately", "as needed", "somewhat") in ${n} SOP(s) — replace with specific values or quantifiable criteria where possible.`,
    too_brief: (n) => `Expand content in ${n} file(s) flagged as short — verify whether the full document was captured.`,
    very_thin: (n) => `Investigate ${n} data file(s) with very thin extractable content — the raw file may require manual inspection.`,
    no_slides: (n) => `${n} deck(s) had no extractable slides — re-export as pptx or verify file format.`,
    too_few_slides: (n) => `Expand ${n} deck(s) with fewer than 3 slides if they are intended as full presentations.`,
    sparse_slides: (n) => `Add body content to title-only slides in ${n} deck(s) — listeners cannot follow titles alone.`,
    no_sections: (n) => `Introduce section headings in ${n} document(s) with none detected, so the structure is navigable.`,
    unstructured: (n) => `Segment ${n} report(s) into clearer sections.`,
    // These codes intentionally don't produce recommendations — they are
    // either reported elsewhere (extraction_failed) or best surfaced as
    // informational context rather than action items:
    extraction_failed: null,
    empty_text: null,
    content_truncated: null,
    no_abstract: null,
    no_methods: null,
    no_results: null,
};

function _buildRecommendations(batchDocs, aggregate) {
    const recs = [];
    const failed = (batchDocs || []).filter(d =>
        (d.analysis && d.analysis.issues || []).some(i => i.code === 'extraction_failed')
    );
    if (failed.length) {
        const names = failed.slice(0, 5).map(d => `**${d.title}**`).join(', ');
        recs.push(`Re-upload or repair: ${names}${failed.length > 5 ? ` (+${failed.length - 5} more)` : ''} — extraction failed.`);
    }
    for (const ri of (aggregate.recurring_issues || []).slice(0, 6)) {
        const fn = _RECOMMEND_MAP[ri.code];
        if (typeof fn === 'function') recs.push(fn(ri.count));
    }
    for (const w of (aggregate.weakest || []).slice(0, 3)) {
        const doc = (batchDocs || []).find(d => d.id === w.id);
        if (!doc) continue;
        const majors = (doc.analysis && doc.analysis.issues || [])
            .filter(i => i.severity === 'error' || i.severity === 'warn');
        if (majors.length >= 3) {
            recs.push(`Prioritize revising **${w.title}** — ${majors.length} structural issue(s) detected.`);
        }
    }
    // Deduplicate while preserving order.
    const seen = new Set();
    return recs.filter(r => (seen.has(r) ? false : (seen.add(r), true)));
}

function _fmtList(items, fallback) {
    if (!items || items.length === 0) return [`- ${fallback}`];
    return items.map(s => `- ${s}`);
}

function formatBatchNarrative(batchDocs, aggregate, opts) {
    opts = opts || {};
    const researcherHint = opts.researcherHint || null;
    const intent = opts.intent || null;
    const truncatedFrom = opts.truncatedFrom || null;
    const docs = Array.isArray(batchDocs) ? batchDocs : [];
    const agg = aggregate || { total: 0, by_type: {}, strongest: [], weakest: [], recurring_issues: [] };

    const typeCounts = Object.entries(agg.by_type || {})
        .sort((a, b) => b[1] - a[1])
        .map(([t, n]) => `${TYPE_LABEL[t] || t}: ${n}`)
        .join(', ');

    const out = [];

    // --- Section 1: Overview ---------------------------------------------
    out.push('## Overview');
    if (agg.total === 0) {
        out.push(`No files were analyzed. No documents matched the query filters, or every candidate was unreadable.`);
    } else {
        out.push(`Analyzed **${agg.total} file(s)** — ${typeCounts || 'unknown type mix'}.`);
    }
    const filters = [];
    if (researcherHint && researcherHint.name) {
        filters.push(`researcher = **${researcherHint.name}**` +
            (researcherHint.researcher_id ? ` (${researcherHint.researcher_id})` : ''));
    }
    if (intent && intent.kinds && intent.kinds.length && intent.kinds[0] !== 'generic') {
        filters.push(`type focus = ${intent.kinds.join('/')}`);
    }
    if (filters.length) out.push(`Filters applied: ${filters.join('; ')}.`);
    if (truncatedFrom && truncatedFrom > docs.length) {
        out.push(`_Ranked pool contained ${truncatedFrom} candidates; analysis was capped at the top ${docs.length} files._`);
    }
    out.push('');

    // --- Section 2: Strongest files --------------------------------------
    out.push('## Strongest files');
    const strongLines = (agg.strongest || []).slice(0, 5).map(s => {
        const doc = docs.find(d => d.id === s.id);
        const summary = doc && doc.analysis && doc.analysis.summary ? ` — ${doc.analysis.summary}` : '';
        const type = doc && doc.normalized_type ? ` _(${TYPE_LABEL[doc.normalized_type] || doc.normalized_type})_` : '';
        return `**${s.title}**${type}${summary}`;
    });
    for (const l of _fmtList(strongLines, 'No files met the "high quality + minimal structural issues" bar.')) out.push(l);
    out.push('');

    // --- Section 3: Weakest files ----------------------------------------
    out.push('## Weakest files');
    const weakLines = (agg.weakest || []).slice(0, 5).map(w => {
        const doc = docs.find(d => d.id === w.id);
        const codes = doc && doc.analysis && doc.analysis.issues
            ? doc.analysis.issues
                .filter(i => i.severity === 'error' || i.severity === 'warn')
                .slice(0, 4).map(i => `\`${i.code}\``).join(', ')
            : '';
        const type = doc && doc.normalized_type ? ` _(${TYPE_LABEL[doc.normalized_type] || doc.normalized_type})_` : '';
        return `**${w.title}**${type}${codes ? ' — issues: ' + codes : ''}`;
    });
    for (const l of _fmtList(weakLines, 'No files were flagged as weakest by the heuristic pass.')) out.push(l);
    out.push('');

    // --- Section 4: Recurring issues -------------------------------------
    out.push('## Recurring issues');
    const recurLines = (agg.recurring_issues || []).slice(0, 8).map(ri => {
        return `\`${ri.code}\` — ${ri.count} file(s).`;
    });
    for (const l of _fmtList(recurLines, 'No structural issue appeared in more than one file.')) out.push(l);
    out.push('');

    // --- Section 5: Per-type findings ------------------------------------
    //     Always grouped by normalized_type when the batch is mixed; folded
    //     into a single block when the batch is homogeneous.
    const typeKeys = Object.keys(agg.by_type || {});
    if (typeKeys.length > 1) {
        out.push('## Findings by document type');
        // Sort types by count, then label.
        typeKeys.sort((a, b) => (agg.by_type[b] - agg.by_type[a]) || a.localeCompare(b));
        for (const t of typeKeys) {
            const label = TYPE_LABEL[t] || t;
            out.push(`### ${label} (${agg.by_type[t]})`);
            const typeDocs = docs.filter(d => d.normalized_type === t);
            const notes = _typeSpecificNotes(t, typeDocs);
            for (const n of notes) out.push(`- ${n}`);
            out.push('');
        }
    } else if (typeKeys.length === 1) {
        const t = typeKeys[0];
        const label = TYPE_LABEL[t] || t;
        out.push(`## ${label}-specific observations`);
        const notes = _typeSpecificNotes(t, docs);
        for (const n of notes) out.push(`- ${n}`);
        out.push('');
    }

    // --- Section 6: Recommendations --------------------------------------
    out.push('## Recommendations');
    const recs = _buildRecommendations(docs, agg);
    for (const l of _fmtList(recs, 'No prioritized revisions required based on structural signals.')) out.push(l);
    out.push('');

    // --- Section 7: Detection vs interpretation --------------------------
    out.push('---');
    out.push('_The issues above are **structural signals detected automatically** from file contents — section markers, header rows, slide counts, step numbering, hedge language, and extraction quality. They do not judge scientific merit, novelty, or correctness of claims. Higher-level interpretation (whether a result supports its conclusion, whether a protocol is appropriate for a given assay) requires subject-matter review of the flagged files._');

    return out.join('\n');
}

// ---- 5. Trace object -----------------------------------------------------
//
// Small, structured, safe to log or pipe back to the frontend in a debug
// channel. Never contains raw document text or secrets — only identities,
// scores, and status flags.

function buildTrace({ intent, candidates, selected, extraction, fallbackUsed, promptSize, confidence, researcherHint }) {
    return {
        source_module: 'zoeRetrieval',
        intent: intent ? {
            kinds: intent.kinds, tokens: intent.tokens,
            flags: intent.flags
        } : null,
        // Phase 4.4: surface the detected researcher (if any) so operators
        // can debug why candidates were boosted or penalized.
        researcher_hint: researcherHint ? {
            researcher_id: researcherHint.researcher_id || null,
            name: researcherHint.name || null,
            matched_token: researcherHint.matched_token || null,
        } : null,
        candidates: (candidates || []).slice(0, 5).map(c => ({
            id: c.id, title: (c.title || '').slice(0, 120),
            source_kind: c.source_kind || null,
            // Phase 4.3: surface canonical type + why it scored as it did.
            normalized_type: c.normalized_type || normalizeDocType(c),
            score: c.score, match_reason: c.match_reason,
            readable: !!c.readable,
            // Phase 4.4: per-candidate researcher + path diagnostics.
            researcher_match: c.researcher_match || null,
            path_hay: c.r2_path && c.r2_path.hay ? c.r2_path.hay.slice(0, 160) : null,
        })),
        selected: selected ? {
            id: selected.id, title: (selected.title || '').slice(0, 120),
            source_kind: selected.source_kind || null,
            normalized_type: selected.normalized_type || normalizeDocType(selected),
            why_selected: selected.match_reason
                || (Array.isArray(selected.why_selected) ? selected.why_selected.join('; ') : null),
            researcher_match: selected.researcher_match || null,
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
    // Phase 4.4
    parseR2Path,
    detectResearcherInQuery,
    matchCandidateToResearcher,
    normAscii,
    // Phase 4.5
    analyzeDocument,
    aggregateFindings,
    // Phase 4.6
    formatBatchNarrative,
    // Phase 4.7
    shouldIgnoreR2Path,
    buildAlternatives,
};
