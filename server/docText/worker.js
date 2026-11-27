'use strict';
// Worker-thread entry: extract + normalize one PDF, enforce caps, post result. No I/O.
const { parentPort, workerData } = require('worker_threads');
const crypto = require('crypto');

// pdf.js 1.10 writes warnings to stdout; keep the worker silent.
console.log = () => {}; console.warn = () => {}; console.info = () => {};

const { extractPages } = require('./extract');
const { normalizePage, maskSystemStamps } = require('./normalize');

(async () => {
    const { maxPages, maxChars } = workerData;
    const buf = Buffer.from(workerData.data); // transferred ArrayBuffer (no copy)
    try {
        const sha256 = crypto.createHash('sha256').update(buf).digest('hex');
        const r = await extractPages(buf, maxPages + 1);
        const pages = [];
        let chars = 0, limit = null, processed = 0, sciPages = 0, stampPages = 0;
        for (let i = 0; i < r.numPages; i++) {
            if (i >= maxPages) { limit = 'PAGE_LIMIT'; break; }
            const raw = r.pages[i] || '';
            if (chars + raw.length > maxChars) { limit = 'CHAR_LIMIT'; break; } // whole pages only, never cut a page
            chars += raw.length; processed = i + 1;
            if (!raw.trim()) continue;                 // blank page: no row, page numbering is explicit
            const st = maskSystemStamps(raw);          // raw stays complete; search copy excludes the stamp
            if (st.stamps) stampPages++;
            if (st.text.trim()) sciPages++;
            const n = normalizePage(st.text);
            pages.push({ pageNo: i + 1, raw, norm: n.norm, offsets: n.rawWordOffsets });
        }
        const pagesIndexed = processed;
        parentPort.postMessage({ ok: true, sha256, extractor: r.extractor, pageCount: r.numPages, pagesIndexed, chars, limit, pages, sciPages, stampPages });
    } catch (e) {
        parentPort.postMessage({ ok: false, error: String((e && e.message) || e) });
    }
})();
