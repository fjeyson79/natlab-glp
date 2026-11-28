'use strict';
// GLP Vision R4.2/R4.3 — iPhone and iPad adapter for glp-vision.html (researcher + supervisor portal).
// Loaded only when GLP_MOBILE_VISION_ENABLED is ON (or ?mobile=preview). Tiers (window size, so iPad split view
// and Slide Over adapt automatically):
//   phone  : < 820 px, or a touch device with a short viewport (phone landscape) -> single column + full-screen viewer
//   tablet : 820–1099 px                     -> finder + docked viewer, navigation drawer, expandable viewer
//   wide   : >= 1100 px on a touch screen    -> existing three columns + docked viewer (touch sizing, controls)
//   desktop: >= 1100 px with a fine pointer  -> adapter inactive (existing desktop layout and viewer)
// State: lists stay in the DOM; on phones the scroll position is restored; full-screen views add one history
// entry (Back / swipe-back / Esc close or collapse them). Mode changes never reload the PDF iframe.
// Security: PDFs load only through /api/di/download. Reusing a PDF already held in the viewer always requires a
// fresh server decision (/api/di/download/:id/access, same guards as the download route, no R2 access);
// a denied or failed check releases it, a 401 ends the session view.
(function () {
    const Q = { phone: '(max-width: 819.98px), (pointer: coarse) and (max-height: 520px)', tablet: '(min-width: 820px) and (max-width: 1099.98px)', wide: '(min-width: 1100px) and (pointer: coarse)' };
    const MQ = Object.fromEntries(Object.entries(Q).map(([k, v]) => [k, window.matchMedia(v)]));
    let viewer = null, cur = null, savedScroll = 0, pushed = false, ignorePop = 0, openToken = 0;

    const tier = () => MQ.phone.matches ? 'phone' : MQ.tablet.matches ? 'tablet' : MQ.wide.matches ? 'wide' : null;
    const active = () => document.documentElement.classList.contains('gm-on') && cur !== null;
    const docked = () => cur === 'tablet' || cur === 'wide';
    const pdfSrc = id => `/pdfjs/web/viewer.html?file=${encodeURIComponent('/api/di/download/' + id)}#pagemode=none&zoom=page-width`;
    function searchTerms(id) { const s = window.gvDS && gvDS.state; return s && s.active && s.nav && s.nav.docId === id ? s.nav.terms : []; }

    function push() { if (!pushed) { history.pushState({ gpv: 1 }, ''); pushed = true; } }
    function unpush() { if (pushed) { pushed = false; ignorePop++; history.back(); } }
    // phone: full-screen viewer
    function overlayOpen() { if (!viewer.isOpen() || viewer.mode() !== 'overlay') savedScroll = window.scrollY; viewer.setMode('overlay'); viewer.show(); push(); }
    function overlayClose(fromPop) {
        viewer.hide(); if (!fromPop) unpush(); else pushed = false;
        requestAnimationFrame(() => requestAnimationFrame(() => window.scrollTo(0, savedScroll)));
    }
    // tablet / wide: expand the docked viewer to full screen and back (same iframe)
    function expand(on, fromPop) {
        if (!docked() || !viewer.docId()) return;
        document.documentElement.classList.toggle('gm-expanded', on);
        viewer.setMode(on ? 'overlay' : 'dock'); viewer.show();
        if (on) push(); else if (!fromPop) unpush(); else pushed = false;
        const b = viewer.el.querySelector('.gpv-expand'); b.setAttribute('aria-label', on ? 'Collapse viewer' : 'Expand viewer');
    }
    function placeViewer() {   // apply the current tier to the viewer (no reload)
        if (cur === 'phone') { document.documentElement.classList.remove('gm-expanded'); if (viewer.isOpen() && viewer.docId()) { viewer.setMode('overlay'); push(); } else { viewer.setMode('overlay'); viewer.hide(); } }
        else if (docked()) {
            const exp = document.documentElement.classList.contains('gm-expanded');
            viewer.setMode(exp ? 'overlay' : 'dock'); viewer.show();
            if (!exp && pushed) unpush();
        }
    }

    async function accessOk(id) {   // fresh server-side authorization before reusing a retained PDF
        try {
            const r = await fetch(`/api/di/download/${encodeURIComponent(id)}/access`, { credentials: 'include', cache: 'no-store' });
            if (r.status === 401) return 'lost';
            return r.ok ? 'ok' : 'denied';
        } catch (e) { return 'denied'; }
    }
    // Host hook (gvSelectFile, mobile/tablet branch).
    async function openFile(id, file) {
        const token = ++openToken;
        const show = () => { if (cur === 'phone') overlayOpen(); else { placeViewer(); } };
        const o = { docId: id, title: file.original_filename, terms: searchTerms(id), downloadHref: `/api/di/download/${id}?download=true` };
        if (viewer.docId() === id && viewer.ready()) {
            const a = await accessOk(id);
            if (token !== openToken) return;
            if (a === 'lost') { viewer.release(); location.href = '/access.html'; return; }
            if (a === 'ok') { show(); viewer.open(o); if (window.gvDS) gvDS.afterViewerLoad(id); return refreshList(); }
            viewer.release();   // denied: never show the retained copy; a fresh load goes through the server check
        }
        show();
        viewer.open({ ...o, src: window.gvDS ? gvDS.viewerSrc(pdfSrc(id), id) : pdfSrc(id) });
        if (window.gvDS) gvDS.afterViewerLoad(id);
        refreshList();
    }
    function refreshList() { if (typeof gvRenderResults === 'function' && !(window.gvDS && gvDS.isActive())) gvRenderResults(); }
    // Search-module hook: route every open through openFile (so reuse is always re-authorized).
    function beforeOpen(id) { if (viewer.docId() === id) viewer.frame.dataset.gdsDoc = ''; }

    function applyTier() {
        const prev = cur; cur = tier();
        const h = document.documentElement;
        ['phone', 'tablet', 'wide'].forEach(t => h.classList.toggle('gm-' + t, cur === t));
        if (prev === cur) return;
        if (cur === null) {   // to desktop: continue in the existing desktop viewer
            const id = viewer.docId();
            h.classList.remove('gm-expanded', 'gm-drawer'); if (pushed) unpush();
            viewer.hide(); viewer.el.hidden = true; viewer.release();
            if (id && typeof gvSelectFile === 'function') setTimeout(() => gvSelectFile(id), 50);
            return;
        }
        if (prev === null && typeof gvSelectedFileId !== 'undefined' && gvSelectedFileId && !viewer.docId()) {   // from desktop
            const f = (typeof gvAllFiles !== 'undefined' ? gvAllFiles : []).find(x => x.submission_id === gvSelectedFileId) || (window.gvDS && gvDS.resultFile(gvSelectedFileId));
            const dsk = document.getElementById('gvViewerPdf'); if (dsk) { dsk.src = 'about:blank'; }
            if (f && cur !== 'phone') { openFile(f.submission_id, f); return; }
        }
        if (cur !== 'phone') h.classList.remove('gm-drawer');
        placeViewer();
    }

    function init() {
        const h = document.documentElement; h.classList.add('gm-on');
        const vp = document.querySelector('meta[name="viewport"]');
        if (vp && !/viewport-fit/.test(vp.content)) vp.content += ', viewport-fit=cover';
        viewer = GLPPdfViewer.create({
            container: document.querySelector('.gv-viewer'),
            onBack: () => { if (cur === 'phone') overlayClose(false); else expand(false); },
            onExpand: () => { if (docked()) expand(!h.classList.contains('gm-expanded')); },
            onEscape: () => { if (cur === 'phone' && viewer.isOpen()) { overlayClose(false); return true; } if (h.classList.contains('gm-expanded')) { expand(false); return true; } return false; },
            onSlash: () => { if (h.classList.contains('gm-expanded')) expand(false); else if (cur === 'phone' && viewer.isOpen()) overlayClose(false); setTimeout(() => document.getElementById('gvSearchInput').focus(), 0); },
            backLabel: m => cur === 'phone' ? 'Back' : 'Collapse',
        });
        window.addEventListener('popstate', () => {
            if (ignorePop) { ignorePop--; return; }
            if (cur === 'phone' && viewer.isOpen()) overlayClose(true);
            else if (h.classList.contains('gm-expanded')) expand(false, true);
        });
        // '/' focuses search from anywhere (external keyboard), Esc leaves the search field
        document.addEventListener('keydown', e => {
            if (!active() || e.metaKey || e.ctrlKey || e.altKey) return;
            const t = e.target, typing = t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName));
            if (e.key === '/' && !typing && !(viewer.isOpen() && viewer.docId())) { e.preventDefault(); document.getElementById('gvSearchInput').focus(); }
        });

        // Navigation drawer (phone + tablet): the existing sidebar slides in.
        const top = document.querySelector('.gv-topbar');
        const btn = document.createElement('button');
        btn.type = 'button'; btn.className = 'gm-menu'; btn.setAttribute('aria-label', 'Filters and navigation');
        btn.innerHTML = '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3 5h14M3 10h14M3 15h14" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>';
        top.insertBefore(btn, top.firstChild);
        if (window.top === window && new URLSearchParams(location.search).get('from') === 'portal') {   // iPhone: top-level page from the portal
            const back = document.createElement('a'); back.className = 'gm-portal'; back.href = '/upload.html'; back.textContent = '‹ Portal';
            back.setAttribute('aria-label', 'Back to Portal'); top.insertBefore(back, btn.nextSibling);
        }
        const backdrop = document.createElement('div'); backdrop.className = 'gm-backdrop'; document.body.appendChild(backdrop);
        const sidebar = document.querySelector('.gv-sidebar');
        const close = document.createElement('button'); close.type = 'button'; close.className = 'gm-drawer-close'; close.setAttribute('aria-label', 'Close'); close.textContent = '×';
        sidebar.insertBefore(close, sidebar.firstChild);
        const setDrawer = on => h.classList.toggle('gm-drawer', on);
        btn.onclick = () => setDrawer(true); backdrop.onclick = () => setDrawer(false); close.onclick = () => setDrawer(false);
        sidebar.addEventListener('click', e => { if (e.target.closest('.gv-scope-item')) setDrawer(false); });
        document.addEventListener('keydown', e => { if (e.key === 'Escape' && h.classList.contains('gm-drawer')) setDrawer(false); });

        // Coverage details without hover.
        const results = document.getElementById('gvResults');
        results.addEventListener('click', e => {
            const cov = e.target.closest('.gds-coverage'); if (!cov || !active()) return;
            const next = cov.parentElement.nextElementSibling;
            if (next && next.classList.contains('gm-cov')) { next.remove(); return; }
            const d = document.createElement('div'); d.className = 'gm-cov'; d.textContent = cov.title; cov.parentElement.after(d);
        });
        results.addEventListener('keydown', e => { if ((e.key === 'Enter' || e.key === ' ') && e.target.classList.contains('gds-coverage')) { e.preventDefault(); e.target.click(); } });
        new MutationObserver(() => results.querySelectorAll('.gds-coverage:not([tabindex])').forEach(c => {
            c.tabIndex = 0; c.setAttribute('role', 'button'); c.setAttribute('aria-label', c.textContent + '. Show details');
        })).observe(results, { childList: true, subtree: true });

        Object.values(MQ).forEach(m => m.addEventListener('change', applyTier));
        applyTier();
        return { active, openFile, beforeOpen, frame: () => viewer.frame, release: () => viewer.release(), viewer, tier: () => cur, expand };
    }
    window.GLPMobileVision = { init };
})();
