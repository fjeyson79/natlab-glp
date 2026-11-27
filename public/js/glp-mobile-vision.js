'use strict';
// GLP Vision R4.2 — iPhone / narrow-window adapter for glp-vision.html (researcher + supervisor portal).
// Loaded only when GLP_MOBILE_VISION_ENABLED is ON (or ?mobile=preview). Active only below 820 px, or on a
// touch device with a short viewport (phone landscape). Desktop and wide windows keep the existing layout.
// State: the result list stays in the DOM under the overlay; the scroll position is restored on close;
// opening a PDF adds one history entry, so Back / swipe-back / Esc close the viewer instead of leaving.
// Security: PDFs load only through /api/di/download (server checks unchanged); a retained PDF is reused only
// while it is still present in the latest authorized list or search results, and is released on scope change.
(function () {
    const MQ = window.matchMedia('(max-width: 819.98px), (pointer: coarse) and (max-height: 520px)');
    let viewer = null, savedScroll = 0, pushed = false;

    function active() { return document.documentElement.classList.contains('gm-on') && MQ.matches; }
    function authorizedNow(id) {
        const inList = (typeof gvAllFiles !== 'undefined' ? gvAllFiles : []).some(f => f.submission_id === id);   // host top-level let
        return inList || !!(window.gvDS && gvDS.resultFile(id));
    }
    function pdfSrc(id) { return `/pdfjs/web/viewer.html?file=${encodeURIComponent('/api/di/download/' + id)}#pagemode=none&zoom=page-width`; }
    function searchTerms(id) {
        const s = window.gvDS && gvDS.state;
        return s && s.active && s.nav && s.nav.docId === id ? s.nav.terms : [];
    }

    function showOverlay() {
        if (!viewer.isOpen()) {
            savedScroll = window.scrollY;
            if (!pushed) { history.pushState({ gpv: 1 }, ''); pushed = true; }
        }
        viewer.show();
    }
    function closeOverlay(fromPop) {
        if (!viewer || !viewer.isOpen()) return;
        viewer.hide();
        if (pushed && !fromPop) { pushed = false; history.back(); } else pushed = false;
        requestAnimationFrame(() => requestAnimationFrame(() => window.scrollTo(0, savedScroll)));
    }

    // Host hook (gvSelectFile, mobile branch): browsing or search open.
    function openFile(id, file) {
        const reuse = viewer.docId() === id && authorizedNow(id);
        if (!reuse && viewer.docId() === id) viewer.release();
        const src = window.gvDS ? gvDS.viewerSrc(pdfSrc(id), id) : pdfSrc(id);
        showOverlay();
        viewer.open({ docId: id, src, title: file.original_filename, terms: searchTerms(id) });
        if (window.gvDS) gvDS.afterViewerLoad(id);
        if (typeof gvRenderResults === 'function' && !(window.gvDS && gvDS.isActive())) gvRenderResults();   // selected card highlight
    }
    // Search-module hook: before an open; reuses the retained PDF in place when still authorized.
    function beforeOpen(id) {
        if (viewer.docId() === id) {
            if (authorizedNow(id) && viewer.ready()) { viewer.setTerms(searchTerms(id)); showOverlay(); }
            else viewer.release();   // forces a fresh, server-checked load through openFile
        }
    }

    function init() {
        document.documentElement.classList.add('gm-on');
        const vp = document.querySelector('meta[name="viewport"]');   // safe areas (notch / home indicator)
        if (vp && !/viewport-fit/.test(vp.content)) vp.content += ', viewport-fit=cover';
        viewer = GLPPdfViewer.create({ onBack: () => closeOverlay(false) });
        window.addEventListener('popstate', () => { if (viewer.isOpen()) closeOverlay(true); });

        // Filters drawer: the existing sidebar (status, year, scope) slides in on narrow screens.
        const top = document.querySelector('.gv-topbar');
        const btn = document.createElement('button');
        btn.type = 'button'; btn.className = 'gm-menu'; btn.setAttribute('aria-label', 'Filters and navigation');
        btn.innerHTML = '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3 5h14M3 10h14M3 15h14" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>';
        top.insertBefore(btn, top.firstChild);
        const back = document.createElement('div'); back.className = 'gm-backdrop'; document.body.appendChild(back);
        const sidebar = document.querySelector('.gv-sidebar');
        const close = document.createElement('button'); close.type = 'button'; close.className = 'gm-drawer-close'; close.setAttribute('aria-label', 'Close'); close.textContent = '×';
        sidebar.insertBefore(close, sidebar.firstChild);
        const setDrawer = on => document.documentElement.classList.toggle('gm-drawer', on);
        btn.onclick = () => setDrawer(true); back.onclick = () => setDrawer(false); close.onclick = () => setDrawer(false);
        sidebar.addEventListener('click', e => { if (e.target.closest('.gv-scope-item')) setDrawer(false); });

        // Coverage details without hover: tap the coverage note.
        document.getElementById('gvResults').addEventListener('click', e => {
            const cov = e.target.closest('.gds-coverage'); if (!cov || !active()) return;
            const next = cov.parentElement.nextElementSibling;
            if (next && next.classList.contains('gm-cov')) { next.remove(); return; }
            const d = document.createElement('div'); d.className = 'gm-cov'; d.textContent = cov.title;
            cov.parentElement.after(d);
        });
        cov_a11y();

        // Leaving mobile mode (rotation / window resize) with the viewer open: continue in the desktop viewer.
        MQ.addEventListener('change', () => {
            if (!MQ.matches && viewer.isOpen()) {
                const id = viewer.docId(); closeOverlay(false); viewer.release();
                if (id && typeof gvSelectFile === 'function') setTimeout(() => gvSelectFile(id), 50);
            }
            if (!MQ.matches) setDrawer(false);
        });
        return { active, openFile, beforeOpen, frame: () => viewer.frame, release: () => viewer.release(), viewer };
    }
    function cov_a11y() {   // keyboard / VoiceOver access to the coverage note
        new MutationObserver(() => document.querySelectorAll('#gvResults .gds-coverage:not([tabindex])').forEach(c => {
            c.tabIndex = 0; c.setAttribute('role', 'button'); c.setAttribute('aria-label', c.textContent + '. Show details');
        })).observe(document.getElementById('gvResults'), { childList: true, subtree: true });
    }
    window.GLPMobileVision = { init };
})();
