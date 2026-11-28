'use strict';
// GLP Vision R4.2/R4.3 — shared PDF viewer shell for iPhone and iPad.
// Wraps the existing PDF.js viewer (/pdfjs/web/viewer.html) in ONE reusable iframe; documents always load
// through the caller's authorized download URL. No storage, no service worker, no backend rendering.
// Modes: 'overlay' (full screen: iPhone, or an expanded iPad viewer) and 'dock' (inside the iPad viewer column).
// Switching modes only changes CSS: the iframe is never moved or reloaded.
// - Stale-load protection: every open() gets a sequence number and binds only to the window that shows the
//   requested document; late PDF.js instances from superseded loads are ignored.
// - Memory: one PDF.js instance at a time; release() blanks the iframe. PDF.js renders visible pages only.
//   Canvas budget 4 MP on touch devices; the PDF.js detail canvas keeps zoomed figures sharp.
// - Gestures: native PDF.js pinch; guarded double-tap (fit width <-> 2x). Keyboard: see keyAction().
(function () {
    const TOUCH_CANVAS_PIXELS = 4194304;
    const HIDE_CHROME = `#toolbarContainer, #sidebarContainer, #sidebarContent, #toolbarSidebar, #toolbarViewerMiddle,
        #toolbarViewerRight, #secondaryToolbar, #loadingBar, #viewerContainer .toolbar, #outerContainer > .toolbar,
        #findbar { display: none !important; } #viewerContainer { top: 0 !important; } #mainContainer { min-width: 0 !important; }
        #outerContainer { background: #eef1f5; } #viewerContainer { -webkit-overflow-scrolling: touch; }`;
    const ICON = {
        back: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M12.5 4.5 7 10l5.5 5.5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"/></svg>',
        next: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M7.5 4.5 13 10l-5.5 5.5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
        up: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M5 12.5 10 7.5l5 5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
        down: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M5 7.5 10 12.5l5-5" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>',
        expand: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3.5 8V3.5H8M12 3.5h4.5V8M16.5 12v4.5H12M8 16.5H3.5V12" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
        dl: '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M10 3v10M10 13l-3.5-3.5M10 13l3.5-3.5M4 16h12" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/></svg>',
    };

    function create(opts) {
        opts = opts || {};
        const S = { seq: 0, docId: null, open: false, mode: 'overlay', terms: [], app: null, appSeq: -1, win: null };
        const root = document.createElement('div');
        root.className = 'gpv'; root.hidden = true;
        root.setAttribute('role', 'dialog'); root.setAttribute('aria-label', 'PDF document');
        root.innerHTML =
            `<header class="gpv-top"><button type="button" class="gpv-btn gpv-back" data-a="back" aria-label="Back to results">${ICON.back}<span>Back</span></button>` +
            '<div class="gpv-title" aria-live="polite"></div>' +
            `<a class="gpv-btn gpv-dl" target="_blank" rel="noopener" aria-label="Download PDF" hidden>${ICON.dl}</a>` +
            `<button type="button" class="gpv-btn gpv-expand" data-a="expand" aria-label="Expand viewer" title="Expand (F)">${ICON.expand}</button></header>` +
            '<div class="gpv-stage"><iframe class="gpv-frame" title="PDF document"></iframe><div class="gpv-loading">Loading…</div><div class="gpv-empty">Select a file to preview</div></div>' +
            '<footer class="gpv-bar">' +
            `<div class="gpv-row gpv-match" hidden><button type="button" class="gpv-btn" data-a="prevMatch" aria-label="Previous match" title="Previous match (Shift+Enter)">${ICON.up}</button>` +
            '<span class="gpv-count" aria-live="polite">–</span>' +
            `<button type="button" class="gpv-btn" data-a="nextMatch" aria-label="Next match" title="Next match (Enter)">${ICON.down}</button></div>` +
            `<div class="gpv-row"><button type="button" class="gpv-btn" data-a="prevPage" aria-label="Previous page" title="Previous page (←)">${ICON.back}</button>` +
            '<span class="gpv-pages" aria-live="polite">–</span>' +
            `<button type="button" class="gpv-btn" data-a="nextPage" aria-label="Next page" title="Next page (→)">${ICON.next}</button><span class="gpv-sp"></span>` +
            '<button type="button" class="gpv-btn" data-a="zoomOut" aria-label="Zoom out" title="Zoom out (−)">−</button>' +
            '<button type="button" class="gpv-btn gpv-fit" data-a="fit" aria-label="Fit width" title="Fit width (0)">Fit</button>' +
            '<button type="button" class="gpv-btn" data-a="zoomIn" aria-label="Zoom in" title="Zoom in (+)">+</button></div></footer>';
        (opts.container || document.body).appendChild(root);
        const $ = sel => root.querySelector(sel);
        const frame = $('.gpv-frame');

        document.addEventListener('webviewerloaded', e => {   // configure PDF.js before it starts
            const src = e.detail && e.detail.source; if (!src || src !== frame.contentWindow) return;
            try { if (opts.canvasPixels !== 0) src.PDFViewerApplicationOptions.set('maxCanvasPixels', opts.canvasPixels || TOUCH_CANVAS_PIXELS); } catch (x) {}
        });
        frame.addEventListener('load', () => attach(S.seq));
        root.addEventListener('click', e => { const b = e.target.closest('[data-a]'); if (b) action(b.dataset.a); });

        function ready() { return !!(S.app && S.appSeq === S.seq && S.win === frame.contentWindow); }
        function action(a) {
            if (a === 'back') return opts.onBack ? opts.onBack() : hide();
            if (a === 'expand') return opts.onExpand && opts.onExpand();
            const app = ready() ? S.app : null; if (!app || !app.pdfViewer) return;
            const v = app.pdfViewer;
            if (a === 'prevPage') app.page = Math.max(1, app.page - 1);
            else if (a === 'nextPage') app.page = Math.min(app.pagesCount, app.page + 1);
            else if (a === 'zoomIn') v.increaseScale();
            else if (a === 'zoomOut') v.decreaseScale();
            else if (a === 'fit') v.currentScaleValue = 'page-width';
            else if (a === 'prevMatch' || a === 'nextMatch') find('again', a === 'prevMatch');
        }
        // External keyboard (iPad): handled for the page and inside the PDF iframe.
        function keyAction(e, inFrame) {
            if (!S.open || !S.docId) return false;
            const t = e.target, typing = !inFrame && t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName));
            if (e.metaKey || e.ctrlKey || e.altKey) return false;
            if (e.key === 'Escape') { if (opts.onEscape) return opts.onEscape() !== false; if (S.mode === 'overlay') { action('back'); return true; } return false; }
            if (typing) return false;
            const map = { ArrowRight: 'nextPage', PageDown: 'nextPage', ArrowLeft: 'prevPage', PageUp: 'prevPage', '+': 'zoomIn', '=': 'zoomIn', '-': 'zoomOut', '0': 'fit' };
            if (e.key === 'Enter') { action(e.shiftKey ? 'prevMatch' : 'nextMatch'); return true; }
            if ((e.key === 'f' || e.key === 'F') && opts.onExpand) { action('expand'); return true; }
            if (e.key === '/' && opts.onSlash) { opts.onSlash(); return true; }
            if (map[e.key]) { action(map[e.key]); return true; }
            return false;
        }
        document.addEventListener('keydown', e => { if (keyAction(e, false)) e.preventDefault(); });

        function find(type, previous) {
            if (!S.app || !S.terms.length) return;
            S.app.eventBus.dispatch('find', { source: window, type, query: S.terms.length === 1 ? S.terms[0] : S.terms,
                caseSensitive: false, entireWord: false, highlightAll: true, findPrevious: !!previous, matchDiacritics: false });
        }
        function setPages() { const app = ready() ? S.app : null; $('.gpv-pages').textContent = app && app.pagesCount ? `${app.page} / ${app.pagesCount}` : '–'; }
        function setCount(mc) {
            const el = $('.gpv-count'); if (!S.terms.length) { el.textContent = '–'; return; }
            el.textContent = mc && mc.total ? `${mc.current || 0} / ${mc.total}${mc.total === 1 ? ' match' : ' matches'}` : 'No matches';
        }
        function setTerms(terms) { S.terms = Array.isArray(terms) ? terms.filter(Boolean) : []; $('.gpv-match').hidden = !S.terms.length; setCount(null); }
        function attach(seq) {
            if (seq !== S.seq || !S.docId) return;
            const t0 = Date.now();
            (function wait() {
                if (seq !== S.seq) return;
                const win = frame.contentWindow; let href = '', app = null;
                try { href = String(win.location.href); app = win.PDFViewerApplication; } catch (x) {}
                if (S.app && S.win === win) return;
                const m = /[?&]gpv=(\d+)/.exec(href);   // per-load token: never adopt a stale window, even for the same document
                if (!(m && +m[1] === seq && href.includes(S.docId) && app && app.eventBus && app.pdfViewer)) { if (Date.now() - t0 < 60000) setTimeout(wait, Date.now() - t0 < 5000 ? 80 : 250); return; }
                let d = null; try { d = frame.contentDocument; const st = d.createElement('style'); st.textContent = HIDE_CHROME; d.head.appendChild(st); } catch (x) {}
                S.app = app; S.appSeq = seq; S.win = win;
                const bus = app.eventBus;
                const loaded = () => { if (seq === S.seq) { setPages(); $('.gpv-loading').hidden = true; } };
                bus.on('pagechanging', () => { if (seq === S.seq) setPages(); });
                bus.on('pagesloaded', loaded); bus.on('pagesinit', loaded);
                bus.on('updatefindmatchescount', e => { if (seq === S.seq) setCount(e.matchesCount); });
                bus.on('updatefindcontrolstate', e => { if (seq === S.seq) setCount(e.matchesCount); });
                if (d) d.addEventListener('keydown', e => { if (seq === S.seq && keyAction(e, true)) { e.preventDefault(); e.stopPropagation(); } }, true);
                (function failWatch(n) {   // a refused or failed load (e.g. 403 after an authorization change): say so, show nothing
                    if (seq !== S.seq) return;
                    if (app.pdfLoadingTask) { app.pdfLoadingTask.promise.then(null, () => { if (seq === S.seq) { const l = $('.gpv-loading'); l.textContent = 'This document is unavailable or access was denied.'; l.hidden = false; } }); return; }
                    if (n < 100) setTimeout(() => failWatch(n + 1), 50);
                })(0);
                bindDoubleTap(seq, d);
                setPages();
                if (app.pagesCount) loaded();
            })();
        }
        function bindDoubleTap(seq, d) {
            const box = d && d.getElementById('viewerContainer'); if (!box || box.__gpvTap) return;
            box.__gpvTap = true;
            let last = null, multiUntil = 0, start = null;
            box.addEventListener('touchstart', e => {
                if (e.touches.length > 1) { multiUntil = Date.now() + 450; last = null; return; }
                start = { x: e.touches[0].clientX, y: e.touches[0].clientY, t: Date.now() };
            }, { passive: true });
            box.addEventListener('touchend', e => {
                if (seq !== S.seq || !ready() || e.touches.length || e.changedTouches.length !== 1 || Date.now() < multiUntil || !start) return;
                const t = e.changedTouches[0], now = Date.now();
                if (Math.hypot(t.clientX - start.x, t.clientY - start.y) > 12 || now - start.t > 300) { last = null; return; }
                const sel = d.getSelection && d.getSelection(); if (sel && !sel.isCollapsed) { last = null; return; }
                if (last && now - last.t < 320 && Math.hypot(t.clientX - last.x, t.clientY - last.y) < 30) {
                    e.preventDefault(); last = null;
                    const v = S.app.pdfViewer;
                    if (v.currentScaleValue === 'page-width') v.currentScale = Math.min(v.currentScale * 2, 6); else v.currentScaleValue = 'page-width';
                    return;
                }
                last = { t: now, x: t.clientX, y: t.clientY };
            }, { passive: false });
        }

        function setMode(m) {   // 'overlay' | 'dock' — CSS only, the iframe stays where it is
            S.mode = m; root.classList.toggle('gpv-dock', m === 'dock');
            root.setAttribute('aria-modal', m === 'overlay' ? 'true' : 'false');
            document.documentElement.classList.toggle('gpv-open', S.open && m === 'overlay');
            $('.gpv-back span').textContent = opts.backLabel ? opts.backLabel(m) : 'Back';
        }
        function show() {
            S.open = true; root.hidden = false;
            document.documentElement.classList.toggle('gpv-open', S.mode === 'overlay');
            if (S.mode === 'overlay') setTimeout(() => $('.gpv-back').focus({ preventScroll: true }), 0);
        }
        function hide() { S.open = false; root.hidden = S.mode !== 'dock'; document.documentElement.classList.remove('gpv-open'); }
        function open(o) {
            $('.gpv-title').textContent = o.title || ''; setTerms(o.terms); root.classList.add('gpv-has-doc');
            const dl = $('.gpv-dl'); if (o.downloadHref) { dl.href = o.downloadHref; dl.hidden = false; } else dl.hidden = true;
            if (o.docId === S.docId && ready()) { show(); return false; }
            S.seq++; S.docId = o.docId; S.app = null; S.appSeq = -1; S.win = null;
            frame.dataset.gdsDoc = ''; $('.gpv-loading').textContent = 'Loading…'; $('.gpv-loading').hidden = false; setPages();
            const h = o.src.indexOf('#'), base = h < 0 ? o.src : o.src.slice(0, h), frag = h < 0 ? '' : o.src.slice(h);
            frame.src = base + (base.includes('?') ? '&' : '?') + 'gpv=' + S.seq + frag;
            attach(S.seq);   // do not rely on the iframe 'load' event alone (it is not always delivered, e.g. WebKit-mode PDF.js)
            show(); return true;
        }
        function release() {
            S.seq++; S.docId = null; S.app = null; S.appSeq = -1; S.win = null; frame.dataset.gdsDoc = '';
            try { frame.src = 'about:blank'; } catch (x) {}
            root.classList.remove('gpv-has-doc'); $('.gpv-title').textContent = ''; $('.gpv-dl').hidden = true;
            setPages(); setCount(null);
        }
        return { el: root, frame, open, show, hide, release, setTerms, setMode, mode: () => S.mode, isOpen: () => S.open, docId: () => S.docId, ready, action, state: S };
    }
    window.GLPPdfViewer = { create };
})();
