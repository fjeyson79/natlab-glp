'use strict';
// Per-page PDF text extraction with pdf-parse 1.1.4 (bundled pdf.js 1.10.100).
// Custom assembly validated in R2.1: newline on baseline change, space on horizontal gap
// or backwards jump (separates table cells and side-by-side PowerPoint text boxes).

function assemblePage(items) {
    let lastY, lastEnd, out = '';
    for (const it of items) {
        const x = it.transform[4], y = it.transform[5], fs = Math.abs(it.transform[0]) || 10;
        if (lastY !== undefined && Math.abs(lastY - y) > fs * 0.3) out += '\n';
        else if (lastEnd !== undefined && (x - lastEnd > fs * 0.15 || x < lastEnd - fs * 0.5)
                 && !/\s$/.test(out) && !/^\s/.test(it.str)) out += ' ';
        out += it.str; lastY = y; lastEnd = x + (it.width || 0);
    }
    return out;
}

async function extractPages(buffer, maxPages) {
    const pdfParse = require('pdf-parse/lib/pdf-parse.js'); // not index.js (debug self-test)
    const pages = [];
    const pagerender = async (pageData) => {
        const tc = await pageData.getTextContent({ normalizeWhitespace: false, disableCombineTextItems: false });
        pages[pageData.pageIndex] = assemblePage(tc.items);
        return '';
    };
    const r = await pdfParse(buffer, { pagerender, max: maxPages || 0 });
    for (let i = 0; i < r.numpages; i++) if (pages[i] === undefined) pages[i] = '';
    return { numPages: r.numpages, pages, extractor: 'pdf-parse@1.1.4' };
}

module.exports = { extractPages, assemblePage };
