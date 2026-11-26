'use strict';
// Scientific text normalization for GLP Vision search (R2.2).
// Raw extracted text is stored unchanged; this produces a derived, searchable copy.
// norm_text is a single-space-separated token string; rawWordOffsets[k] is the raw
// character offset where norm token k begins, so matches can be mapped back to raw text
// for contextual excerpts. Nothing is reconstructed (e.g. formatted superscripts stay as
// extracted: "1×10\n6" -> "1×10 6").

const CHAR_MAP = [
    [/[‘’‚‛′‵ʹʼ´`]/g, "'"], // quotes/primes -> '
    [/[“”„″‶]/g, '"'],
    [/[‐‑‒–—―−﹣－]/g, '-'],       // dashes/minus -> -
    [/[­​‌‍⁠﻿]/g, ''],                          // soft hyphen, zero-width
];

function normToken(t) {
    let s = t.normalize('NFKC');            // µ(U+00B5)->μ(U+03BC), ligatures, fullwidth, ⁻⁶ -> -6
    for (const [re, rep] of CHAR_MAP) s = s.replace(re, rep);
    return s.toLowerCase();
}

// Returns { norm, rawWordOffsets }
function normalizePage(raw) {
    const toks = [];
    const re = /\S+/g;
    let m;
    while ((m = re.exec(raw)) !== null) toks.push({ start: m.index, end: m.index + m[0].length, text: m[0] });

    // Merge line-end hyphenation: "diges-\ntion" -> "digestion"; "TOUCAN-\nMRSA" -> "TOUCAN-MRSA".
    const merged = [];
    for (let i = 0; i < toks.length; i++) {
        let cur = { start: toks[i].start, text: toks[i].text, end: toks[i].end };
        while (i + 1 < toks.length && /[-‐‑­]$/.test(cur.text)) {
            const gap = raw.slice(cur.end, toks[i + 1].start);
            if (!/\n/.test(gap) || /\n\s*\n/.test(gap)) break;
            const next = toks[i + 1].text;
            const prevCh = cur.text.slice(-2, -1);
            if (/\p{Ll}/u.test(prevCh) && /^\p{Ll}/u.test(next)) cur.text = cur.text.slice(0, -1) + next;   // soft line break
            else if (/^[\p{Lu}\p{N}]/u.test(next)) cur.text = cur.text + next;                              // identifier hyphen kept
            else break;
            cur.end = toks[i + 1].end; i++;
        }
        merged.push(cur);
    }

    const out = [], offsets = [];
    for (const t of merged) {
        const n = normToken(t.text);
        for (const part of n.split(/\s+/)) { if (part) { out.push(part); offsets.push(t.start); } }
    }
    return { norm: out.join(' '), rawWordOffsets: offsets };
}

// Same normalization for user queries (whitespace collapsed, no hyphen-join needed).
function normalizeQuery(q) {
    return String(q || '').split(/\s+/).filter(Boolean).map(normToken).join(' ').trim();
}

module.exports = { normalizePage, normalizeQuery };
