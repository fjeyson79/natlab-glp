'use strict';
// GLP Vision R4.2 — shared full-screen PDF viewer shell (iPhone / narrow windows).
// Wraps the existing PDF.js viewer (/pdfjs/web/viewer.html) in ONE reusable iframe; documents always load
// through the caller's authorized download URL. No storage, no service worker, no backend rendering.
// - Stale-load protection: every open() gets a sequence number; late PDF.js instances are ignored.
// - Memory: one PDF.js instance at a time (switching documents unloads the previous one); release()
//   blanks the iframe. PDF.js renders only visible pages (+ small buffer) and frees off-screen canvases.
//   On phones the canvas budget is 4 MP; PDF.js's high-resolution detail canvas keeps zoomed figures sharp.
// - Gestures: native PDF.js pinch-to-zoom; double-tap toggles fit-width/2x only for a clean single tap pair
//   (never during pinch or while text is selected).
(function () {
    const PHONE_CANVAS_PIXELS = 4194304;
    const HIDE_CHROME = `#toolbarContainer, #sidebarContainer, #sidebarContent, #toolbarSidebar, #toolbarViewerMiddle,
        #toolbarViewerRight, #secondaryToolbar, #loadingBar, #viewerContainer .toolbar, #outerContainer > .toolbar,
        #findbar { display: none !important; } #viewerContainer { top: 0 !important; } #mainContainer { min-width: 0 !important; }
        #outerContainer { background: #eef1f5; } #viewerContainer { -webkit-overflow-scrolling: touch; }`;

    function create(opts) {
        opts = opts || {};
        const S = { seq: 0, docId: null, open: false, terms: [], app: null, appSeq: -1, win: null };
        const root = document.createElement('div');
        root.className = 'gpv'; root.hidden = true;
        root.setAttribute('role', 'dialog'); root.setAttribute('aria-modal', 'true'); root.setAttribute('aria-label', 'PDF document');
        root.innerHTML =
            '<header class="gpv-top"><button type="button" class="gpv-btn gpv-back" data-a="back" aria-label="Back to results">' +
            '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M12.5 4.5 7 10l5.5 5.5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg><span>Back</span></button>' +
            '<div class="gpv-title" aria-live="polite"></div></header>' +
            '<div class="gpv-stage"><iframe class="gpv-frame" title="PDF document"></iframe><div class="gpv-loading">Loading…</div></div>' +
            '<footer class="gpv-bar">' +
            '<div class="gpv-row gpv-match" hidden>' +
            '<button type="button" class="gpv-btn" data-a="prevMatch" aria-label="Previous match"><svg viewBox="0 0 20 20" aria-hidden="true"><path d="M5 12.5 10 7.5l5 5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg></button>' +
            '<span class="gpv-count" aria-live="polite">–</span>' +
            '<button type="button" class="gpv-btn" data-a="nextMatch" aria-label="Next match"><svg viewBox="0 0 20 20" aria-hidden="true"><path d="M5 7.5 10 12.5l5-5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg></button>' +
            '</div><div class="gpv-row">' +
            '<button type="button" class="gpv-btn" data-a="prevPage" aria-label="Previous page"><svg viewBox="0 0 20 20" aria-hidden="true"><path d="M12.5 4.5 7 10l5.5 5.5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg></button>' +
            '<span class="gpv-pages" aria-live="polite">–</span>' +
            '<button type="button" class="gpv-btn" data-a="nextPage" aria-label="Next page"><svg viewBox="0 0 20 20" aria-hidden="true"><path d="M7.5 4.5 13 10l-5.5 5.5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg></button>' +
            '<span class="gpv-sp"></span>' +
            '<button type="button" class="gpv-btn" data-a="zoomOut" aria-label="Zoom out">−</button>' +
            '<button type="button" class="gpv-btn gpv-fit" data-a="fit" aria-label="Fit width">Fit</button>' +
            '<button type="button" class="gpv-btn" data-a="zoomIn" aria-label="Zoom in">+</button>' +
            '</div></footer>';
        (opts.container || document.body).appendChild(root);
        const $ = sel => root.querySelector(sel);
        const frame = $('.gpv-frame');

        // Configure PDF.js before it starts (it announces itself on the parent document).
        document.addEventListener('webviewerloaded', e => {
            const src = e.detail && e.detail.source; if (!src || src !== frame.contentWindow) return;
            try { if (opts.canvasPixels !== 0) src.PDFViewerApplicationOptions.set('maxCanvasPixels', opts.canvasPixels || PHONE_CANVAS_PIXELS); } catch (x) {}
        });
        frame.addEventListener('load', () => attach(S.seq));

        root.addEventListener('click', e => {
            const b = e.target.closest('[data-a]'); if (!b) return;
            const a = b.dataset.a, app = ready() ? S.app : null;
            if (a === 'back') return opts.onBack ? opts.onBack() : hide();
            if (!app || !app.pdfViewer) return;
            const v = app.pdfViewer;
            if (a === 'prevPage') app.page = Math.max(1, app.page - 1);
            else if (a === 'nextPage') app.page = Math.min(app.pagesCount, app.page + 1);
            else if (a === 'zoomIn') v.increaseScale();
            else if (a === 'zoomOut') v.decreaseScale();
            else if (a === 'fit') v.currentScaleValue = 'page-width';
            else if (a === 'prevMatch' || a === 'nextMatch') find('again', a === 'prevMatch');
        });

        function find(type, previous) {
            if (!S.app || !S.terms.length) return;
            S.app.eventBus.dispatch('find', { source: window, type, query: S.terms.length === 1 ? S.terms[0] : S.terms,
                caseSensitive: false, entireWord: false, highlightAll: true, findPrevious: !!previous, matchDiacritics: false });
        }
        function setPages() {
            const app = S.app; $('.gpv-pages').textContent = app && app.pagesCount ? `${app.page} / ${app.pagesCount}` : '–';
        }
        function setCount(mc) {
            const el = $('.gpv-count');
            if (!S.terms.length) { el.textContent = '–'; return; }
            el.textContent = mc && mc.total ? `${mc.current || 0} / ${mc.total}${mc.total === 1 ? ' match' : ' matches'}` : 'No matches';
        }
        function setTerms(terms) {
            S.terms = Array.isArray(terms) ? terms.filter(Boolean) : [];
            $('.gpv-match').hidden = !S.terms.length; setCount(null);
        }
        // Bind to the PDF.js instance of the CURRENT load only (stale instances are ignored).
        function attach(seq) {
            if (seq !== S.seq || !S.docId) return;
            const t0 = Date.now();
            (function wait() {
                if (seq !== S.seq) return;
                // Bind only to the window that is actually showing the requested document: a late 'load' from a
                // previous (superseded) navigation must never be adopted as the current PDF.
                const win = frame.contentWindow; let href = '', app = null;
                try { href = String(win.location.href); app = win.PDFViewerApplication; } catch (x) {}
                if (S.app && S.win === win) return;   // already bound to this document
                if (!(href.includes(S.docId) && app && app.eventBus && app.pdfViewer)) { if (Date.now() - t0 < 20000) setTimeout(wait, 80); return; }
                try { const d = frame.contentDocument, st = d.createElement('style'); st.textContent = HIDE_CHROME; d.head.appendChild(st); } catch (x) {}
                S.app = app; S.appSeq = seq; S.win = win;
                const bus = app.eventBus;
                bus.on('pagechanging', () => { if (seq === S.seq) setPages(); });
                bus.on('pagesloaded', () => { if (seq === S.seq) { setPages(); $('.gpv-loading').hidden = true; } });
                bus.on('pagesinit', () => { if (seq === S.seq) { setPages(); $('.gpv-loading').hidden = true; } });
                bus.on('updatefindmatchescount', e => { if (seq === S.seq) setCount(e.matchesCount); });
                bus.on('updatefindcontrolstate', e => { if (seq === S.seq) setCount(e.matchesCount); });
                bindDoubleTap(seq);
                setPages();
            })();
        }
        function bindDoubleTap(seq) {
            let d; try { d = frame.contentDocument; } catch (x) { return; }
            const box = d && d.getElementById('viewerContainer'); if (!box || box.__gpvTap) return;
            box.__gpvTap = true;
            let last = null, multiUntil = 0, start = null;
            box.addEventListener('touchstart', e => {
                if (e.touches.length > 1) { multiUntil = Date.now() + 450; last = null; return; }
                start = { x: e.touches[0].clientX, y: e.touches[0].clientY, t: Date.now() };
            }, { passive: true });
            box.addEventListener('touchend', e => {
                if (seq !== S.seq || !S.app || e.touches.length || e.changedTouches.length !== 1 || Date.now() < multiUntil || !start) return;
                const t = e.changedTouches[0], now = Date.now();
                if (Math.hypot(t.clientX - start.x, t.clientY - start.y) > 12 || now - start.t > 300) { last = null; return; }   // a drag/long press, not a tap
                const sel = d.getSelection && d.getSelection(); if (sel && !sel.isCollapsed) { last = null; return; }        // text selection wins
                if (last && now - last.t < 320 && Math.hypot(t.clientX - last.x, t.clientY - last.y) < 30) {
                    e.preventDefault(); last = null;
                    const v = S.app.pdfViewer;
                    if (v.currentScaleValue === 'page-width') v.currentScale = Math.min(v.currentScale * 2, 6); else v.currentScaleValue = 'page-width';
                    return;
                }
                last = { t: now, x: t.clientX, y: t.clientY };
            }, { passive: false });
        }

        function show() {
            if (S.open) return; S.open = true; root.hidden = false;
            document.documentElement.classList.add('gpv-open');
            setTimeout(() => $('.gpv-back').focus({ preventScroll: true }), 0);
        }
        function hide() {
            if (!S.open) return; S.open = false; root.hidden = true;
            document.documentElement.classList.remove('gpv-open');
        }
        // open(): reuse the loaded instance for the same document, otherwise load (stale-safe).
        function open(o) {
            $('.gpv-title').textContent = o.title || ''; setTerms(o.terms);
            if (o.docId === S.docId && ready()) { show(); return false; }
            S.seq++; S.docId = o.docId; S.app = null; S.appSeq = -1; S.win = null;
            frame.dataset.gdsDoc = ''; $('.gpv-loading').hidden = false; setPages();
            frame.src = o.src;
            show(); return true;
        }
        function release() {   // drop the retained PDF (scope/authorization change, logout)
            S.seq++; S.docId = null; S.app = null; S.appSeq = -1; S.win = null; frame.dataset.gdsDoc = '';
            try { frame.src = 'about:blank'; } catch (x) {}
            setPages(); setCount(null);
        }
        function keydown(e) {
            if (!S.open) return;
            if (e.key === 'Escape') { e.preventDefault(); opts.onBack ? opts.onBack() : hide(); }
        }
        document.addEventListener('keydown', keydown);
        function ready() { return !!(S.app && S.appSeq === S.seq && S.win === frame.contentWindow); }   // bound to the live document
        return { el: root, frame, open, show, hide, release, setTerms, isOpen: () => S.open, docId: () => S.docId, ready, state: S };
    }
    window.GLPPdfViewer = { create };
})();
