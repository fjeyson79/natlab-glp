// backend-patch/extractReportText.js
//
// Phase 1.1 — REPORT text extraction policy.
//
// Single source of truth for "is this file extractable, and with what method?".
// All extraction call sites (live /api/assistant/files/:submission_id/text,
// indexed extractOne, the bulk indexer) go through these helpers so the policy
// stays in one place.
//
// Rules (per Phase 1.1 brief):
//   - REPORT PDF              → pdf-parse   (unchanged from Phase 1)
//   - REPORT DOCX             → mammoth.extractRawText
//   - REPORT DOC  (legacy)    → mammoth best-effort; expected to fail cleanly
//   - SOP / DATA / PRESENTATION + PDF → pdf-parse   (unchanged)
//   - SOP / DATA / PRESENTATION + DOC/DOCX → NOT extracted
//   - anything else with DOC/DOCX → NOT extracted
//
// The non-REPORT DOC/DOCX block is load-bearing: Zoe must not start reading
// arbitrary Word docs across the bucket. Only REPORT was approved for the
// mammoth path. Adding new file_types to the DOCX whitelist is an explicit
// policy change — do it in REPORT_DOCX_FILE_TYPES below.

'use strict';

// File types for which DOCX/DOC extraction is allowed. Keep this list tight —
// every entry here means Zoe can read Word documents of that type.
const REPORT_DOCX_FILE_TYPES = new Set(['REPORT']);

// File types for which PDF extraction is allowed. Matches the Phase 1 policy.
const PDF_FILE_TYPES = new Set(['REPORT', 'SOP', 'DATA', 'PRESENTATION', 'PAPER']);

function normalizeExt(filename) {
    if (!filename) return null;
    const m = String(filename).toLowerCase().match(/\.([a-z0-9]{1,8})$/);
    return m ? m[1] : null;
}

function normalizeFileType(fileType) {
    if (!fileType) return null;
    return String(fileType).trim().toUpperCase();
}

// sanitizeText — NUL strip + low-control replacement, identical to
// assistantFileIndexer.sanitizeExtractedText. Duplicated here so this helper
// has no upstream dependencies and can be unit-tested in isolation.
function sanitizeText(value) {
    if (value == null) return '';
    return String(value)
        .replace(/\u0000/g, '')
        .replace(/[\u0001-\u0008\u000B\u000C\u000E-\u001F\u007F]/g, ' ')
        .replace(/\s+\n/g, '\n')
        .trim();
}

// classify(filename, fileType) → { method, ext, reason? }
//   method: 'pdf-parse' | 'mammoth' | 'mammoth-legacy' | null
//   reason (only when method === null): one of
//     'unsupported_file_type'        — extension not in pdf/docx/doc
//     'non_report_word_blocked'      — docx/doc on a non-REPORT file_type
//     'unknown_file_type'            — file_type missing
//
// This is the policy gate. Both /:submission_id/text and the bulk indexer
// consult it before touching the buffer.
function classify(filename, fileType) {
    const ext  = normalizeExt(filename);
    const type = normalizeFileType(fileType);

    if (ext === 'pdf') {
        if (type && PDF_FILE_TYPES.has(type)) return { method: 'pdf-parse', ext };
        // Unknown / unrecognized type still gets the PDF path — matches Phase 1
        // behaviour where ext-based extraction worked without a file_type.
        return { method: 'pdf-parse', ext };
    }

    if (ext === 'docx') {
        if (!type) return { method: null, ext, reason: 'unknown_file_type' };
        if (REPORT_DOCX_FILE_TYPES.has(type)) return { method: 'mammoth', ext };
        return { method: null, ext, reason: 'non_report_word_blocked' };
    }

    if (ext === 'doc') {
        if (!type) return { method: null, ext, reason: 'unknown_file_type' };
        if (REPORT_DOCX_FILE_TYPES.has(type)) return { method: 'mammoth-legacy', ext };
        return { method: null, ext, reason: 'non_report_word_blocked' };
    }

    return { method: null, ext, reason: 'unsupported_file_type' };
}

// Lighter shape for indexer/text-pass WHERE-clause planning. Returns true
// only when classify() would route to a method.
function shouldIndexText(filename, fileType) {
    return classify(filename, fileType).method !== null;
}

// extractReportText(buffer, filename, fileType) → Promise<{
//   ok: boolean,
//   method: 'pdf-parse'|'mammoth'|'mammoth-legacy'|null,
//   ext: string|null,
//   text: string,
//   pages: number|null,         // pdf only
//   error: string|null          // policy reason or parser error code
// }>
//
// Never throws — every failure path returns ok=false with an error code.
// Callers decide whether to stamp 'failed' / 'empty' / 'unsupported'.
async function extractReportText(buffer, filename, fileType) {
    const c = classify(filename, fileType);
    if (!c.method) {
        return {
            ok: false,
            method: null,
            ext: c.ext,
            text: '',
            pages: null,
            error: c.reason || 'unsupported_file_type'
        };
    }

    if (c.method === 'pdf-parse') {
        try {
            const pdfParse = require('pdf-parse');
            const parsed = await pdfParse(buffer);
            const text = sanitizeText(parsed && parsed.text);
            if (!text) {
                return {
                    ok: false,
                    method: 'pdf-parse',
                    ext: 'pdf',
                    text: '',
                    pages: parsed && parsed.numpages || null,
                    error: 'scanned_pdf_or_unreadable'
                };
            }
            return {
                ok: true,
                method: 'pdf-parse',
                ext: 'pdf',
                text,
                pages: parsed && parsed.numpages || null,
                error: null
            };
        } catch (e) {
            return {
                ok: false,
                method: 'pdf-parse',
                ext: 'pdf',
                text: '',
                pages: null,
                error: 'pdf_parse_failed:' + (e && e.message || 'unknown')
            };
        }
    }

    if (c.method === 'mammoth' || c.method === 'mammoth-legacy') {
        try {
            const mammoth = require('mammoth');
            const result = await mammoth.extractRawText({ buffer });
            const text = sanitizeText(result && result.value);
            if (!text) {
                return {
                    ok: false,
                    method: c.method,
                    ext: c.ext,
                    text: '',
                    pages: null,
                    error: 'empty_docx_or_unreadable'
                };
            }
            return {
                ok: true,
                method: c.method,
                ext: c.ext,
                text,
                pages: null,
                error: null
            };
        } catch (e) {
            // Legacy .doc files are NOT a docx ZIP — mammoth throws.
            // Surface as 'legacy_doc_unsupported' so the caller can stamp the
            // index row 'unsupported' (not 'failed') and stop retrying.
            const msg = e && e.message || 'unknown';
            const errCode = c.method === 'mammoth-legacy'
                ? 'legacy_doc_unsupported'
                : 'mammoth_failed:' + msg;
            return {
                ok: false,
                method: c.method,
                ext: c.ext,
                text: '',
                pages: null,
                error: errCode
            };
        }
    }

    return {
        ok: false,
        method: null,
        ext: c.ext,
        text: '',
        pages: null,
        error: 'unsupported_file_type'
    };
}

module.exports = {
    extractReportText,
    classify,
    shouldIndexText,
    sanitizeText,
    REPORT_DOCX_FILE_TYPES,
    PDF_FILE_TYPES
};
