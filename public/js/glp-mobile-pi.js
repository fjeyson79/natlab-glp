'use strict';
// GLP Vision R4.5 — iPhone and iPad adapter for the PI portal GLP Vision tab (pi-dashboard.html, #tab-lab-files).
// Loaded only when GLP_MOBILE_PI_ENABLED is ON (or ?mobile=preview). Same tiers and shared PDF viewer
// (glp-pdf-viewer.js) as the researcher/supervisor adapter (glp-mobile-vision.js, R4.2/R4.3):
//   phone  : < 820 px, or a touch device with a short viewport -> single column, filters drawer, full-screen viewer
//   tablet : 820–1099 px                  -> finder + docked viewer, researcher drawer, expandable viewer
//   wide   : >= 1100 px on a touch screen -> sidebar + finder + docked viewer
//   desktop: >= 1100 px with a fine pointer -> adapter inactive (existing PI desktop interface)
// The PI search module (ds*/dic* in pi-dashboard.html) is unchanged; it calls openFile()/openInternal() and
// navigates pages/matches in frame() instead of the desktop iframe. Mode changes never reload the PDF iframe.
// Security: PDFs load only through /api/di/download (internal documents: the existing internal-docs route).
// Reusing a PDF already held in the viewer always requires a fresh server decision (/api/di/download/:id/access);
// a denied or failed check releases it, a 401 releases it and ends the session view. No storage.
(function () {
    const Q = { phone: '(max-width: 819.98px), (pointer: coarse) and (max-height: 520px)', tablet: '(min-width: 820px) and (max-width: 1099.98px)', wide: '(min-width: 1100px) and (pointer: coarse)' };
    const MQ = Object.fromEntries(Object.entries(Q).map(([k, v]) => [k, window.matchMedia(v)]));
    const h = document.documentElement;
    let viewer = null, cur = null, savedScroll = 0, pushed = false, ignorePop = 0, openToken = 0, held = null;   // held: { kind: 'sub'|'int', id }

    const tier = () => MQ.phone.matches ? 'phone' : MQ.tablet.matches ? 'tablet' : MQ.wide.matches ? 'wide' : null;
    const active = () => h.classList.contains('gm-on') && cur !== null;
    const docked = () => cur === 'tablet' || cur === 'wide';
    const tab = () => document.getElementById('tab-lab-files');
    const onTab = () => tab().classList.contains('active');
    const ds = () => (typeof dsState !== 'undefined' ? dsState : null);
    function searchTerms(id) { const s = ds(); return s && s.active && s.nav && s.nav.docId === id ? s.nav.terms : []; }

    function push() { if (!pushed) { history.pushState({ gpv: 1 }, ''); pushed = true; } }
    function unpush() { if (pushed) { pushed = false; ignorePop++; history.back(); } }
    function overlayOpen() { if (!viewer.isOpen() || viewer.mode() !== 'overlay') savedScroll = window.scrollY; viewer.setMode('overlay'); viewer.show(); push(); }
    function overlayClose(fromPop) {
        viewer.hide(); if (!fromPop) unpush(); else pushed = false;
        requestAnimationFrame(() => requestAnimationFrame(() => window.scrollTo(0, savedScroll)));
    }
    function expand(on, fromPop) {
        if (!docked() || !viewer.docId()) return;
        h.classList.toggle('gm-expanded', on);
        viewer.setMode(on ? 'overlay' : 'dock'); viewer.show();
        if (on) push(); else if (!fromPop) unpush(); else pushed = false;
        viewer.el.querySelector('.gpv-expand').setAttribute('aria-label', on ? 'Collapse viewer' : 'Expand viewer');
    }
    function placeViewer() {   // apply the current tier to the viewer (no reload)
        if (cur === 'phone') { h.classList.remove('gm-expanded'); if (viewer.isOpen() && viewer.docId() && onTab()) { viewer.setMode('overlay'); push(); } else { viewer.setMode('overlay'); viewer.hide(); } }
        else if (docked()) {
            const exp = h.classList.contains('gm-expanded');
            viewer.setMode(exp ? 'overlay' : 'dock'); viewer.show();
            if (!exp && pushed) unpush();
        }
    }
    const show = () => { if (cur === 'phone') overlayOpen(); else placeViewer(); };
    function release() { viewer.release(); viewer.frame.dataset.dsDoc = ''; held = null; }

    async function accessOk(id) {   // fresh server-side authorization before reusing a retained PDF
        try {
            const r = await fetch(`/api/di/download/${encodeURIComponent(id)}/access`, { credentials: 'include', cache: 'no-store' });
            if (r.status === 401) return 'lost';
            return r.ok ? 'ok' : 'denied';
        } catch (e) { return 'denied'; }
    }
    // Host hook (dicSelectFile, mobile branch). The desktop iframe is never loaded while the adapter is active.
    async function openFile(id, file) {
        const token = ++openToken;
        const o = { docId: id, title: file.original_filename, terms: searchTerms(id), downloadHref: `/api/di/download/${id}?download=true` };
        if (held && held.kind === 'sub' && viewer.docId() === id && viewer.ready()) {
            const a = await accessOk(id);
            if (token !== openToken) return;
            if (a === 'lost') { release(); location.href = 'access.html'; return; }
            if (a === 'ok') { show(); viewer.open(o); viewer.frame.dataset.dsDoc = id; dsAfterViewerLoad(id); return; }
            release();   // denied: never show the retained copy; a fresh load goes through the server check
        }
        show();
        viewer.open({ ...o, src: dsViewerSrc(dicBuildPdfViewerSrc('/api/di/download/' + id), id) });
        held = { kind: 'sub', id }; viewer.frame.dataset.dsDoc = id;
        dsAfterViewerLoad(id);
    }
    // Host hook (dicOpenInternalDoc, mobile branch): PDFs through PDF.js, always a fresh server request (no reuse).
    function openInternal(key) {
        const url = '/api/internal-docs/open?key=' + encodeURIComponent(key);
        if (!/\.pdf$/i.test(key)) { window.open(url, '_blank', 'noopener'); return; }
        ++openToken; release();
        const docId = 'intdoc' + Date.now().toString(36), src = dicBuildPdfViewerSrc(url);
        const i = src.indexOf('?');
        show();
        viewer.open({ docId, title: String(key).split('/').pop(), terms: [], src: src.slice(0, i + 1) + '_d=' + docId + '&' + src.slice(i + 1) });
        held = { kind: 'int', id: key };
    }

    // Host hook (dicGlpPresentation): on iPhone/iPad, presentation = the shared full-screen viewer (page controls,
    // touch scrolling, pinch, matches) instead of the keyboard-driven desktop presentation. Same authorization path.
    async function present() {
        const id = typeof dicSelectedFileId !== 'undefined' ? dicSelectedFileId : null;
        const f = id && dicFindFile(id); if (!f) return;
        await openFile(id, f);
        if (docked() && viewer.docId() === id && !h.classList.contains('gm-expanded')) expand(true);
    }

    function placeMenu() {   // phone: beside the search box; tablet: in the GLP Vision bar (visible in every mode)
        const btn = document.querySelector('.gm-menu'); if (!btn) return;
        const host = cur === 'tablet' ? document.getElementById('dicVisionBar') : document.querySelector('.dic-finder .dic-search-area');
        if (host && btn.parentElement !== host) host.insertBefore(btn, host.firstChild);
    }
    function size() {   // docked layouts: the console fills the window below the portal header and tabs
        if (!docked() || !onTab()) return;
        const c = document.querySelector('#tab-lab-files .dic-container'); if (!c) return;
        const top = c.getBoundingClientRect().top + window.scrollY;
        h.style.setProperty('--gm-dic-h', Math.max(360, Math.round(window.innerHeight - top - 8)) + 'px');
    }

    function applyTier() {
        const prev = cur; cur = tier();
        ['phone', 'tablet', 'wide'].forEach(t => h.classList.toggle('gm-' + t, cur === t));
        placeMenu(); requestAnimationFrame(size);
        if (prev === cur) return;
        if (cur === null) {   // to desktop: continue in the existing desktop viewer
            const was = held;
            h.classList.remove('gm-expanded', 'gm-drawer'); if (pushed) unpush();
            viewer.hide(); viewer.el.hidden = true; release();
            if (was && was.kind === 'sub' && typeof dicSelectFile === 'function') setTimeout(() => dicSelectFile(was.id), 50);
            else if (was && was.kind === 'int' && typeof dicOpenInternalDoc === 'function') setTimeout(() => dicOpenInternalDoc(was.id), 50);
            return;
        }
        if (cur === 'phone' && typeof dicVisionMode !== 'undefined' && dicVisionMode !== 'all') {   // Training/Inventory/1-to-1 panels: iPad/desktop
            const all = document.querySelector('#dicVisionBar .dic-vision-btn'); if (all) dicSetVisionMode('all', all);
        }
        if (prev === null) {   // from desktop: release the desktop copy; tablet/wide continue with one fresh, authorized load
            const dsk = document.getElementById('dicViewerPdf');
            const sel = typeof dicSelectedFileId !== 'undefined' ? dicSelectedFileId : null;
            const hadDesktop = dsk && dsk.dataset.dsDoc && dsk.dataset.dsDoc === sel;
            if (dsk && dsk.src && dsk.src !== 'about:blank' && !/about:blank$/.test(dsk.src)) { dsk.src = 'about:blank'; dsk.dataset.dsDoc = ''; }
            if (hadDesktop && cur !== 'phone') { const f = dicFindFile(sel); if (f) { openFile(sel, f); return; } }
        }
        if (cur !== 'phone') h.classList.remove('gm-drawer');
        placeViewer();
    }

    function init() {
        h.classList.add('gm-on');
        const vp = document.querySelector('meta[name="viewport"]');
        if (vp && !/viewport-fit/.test(vp.content)) vp.content += ', viewport-fit=cover';
        viewer = GLPPdfViewer.create({
            container: document.querySelector('#tab-lab-files .dic-viewer'),
            onBack: () => { if (cur === 'phone') overlayClose(false); else expand(false); },
            onExpand: () => { if (docked()) expand(!h.classList.contains('gm-expanded')); },
            onEscape: () => { if (cur === 'phone' && viewer.isOpen()) { overlayClose(false); return true; } if (h.classList.contains('gm-expanded')) { expand(false); return true; } return false; },
            onSlash: () => { if (h.classList.contains('gm-expanded')) expand(false); else if (cur === 'phone' && viewer.isOpen()) overlayClose(false); setTimeout(() => document.getElementById('dicSearchInput').focus(), 0); },
            backLabel: () => cur === 'phone' ? 'Back' : 'Collapse',
        });
        if (cur === null) viewer.el.hidden = true;
        window.addEventListener('popstate', () => {
            if (ignorePop) { ignorePop--; return; }
            if (cur === 'phone' && viewer.isOpen()) overlayClose(true);
            else if (h.classList.contains('gm-expanded')) expand(false, true);
        });
        document.addEventListener('keydown', e => {   // '/' focuses search (external keyboard), Esc closes the drawer
            if (!active() || !onTab() || e.metaKey || e.ctrlKey || e.altKey) return;
            const t = e.target, typing = t && (t.isContentEditable || /^(INPUT|TEXTAREA|SELECT)$/.test(t.tagName));
            if (e.key === 'Escape' && h.classList.contains('gm-drawer')) { setDrawer(false); return; }
            if (e.key === '/' && !typing && !(viewer.isOpen() && viewer.docId() && viewer.mode() === 'overlay')) { e.preventDefault(); document.getElementById('dicSearchInput').focus(); }
        });

        // Researcher / status / year navigation drawer (phone + tablet): the existing sidebar slides in.
        const btn = document.createElement('button');
        btn.type = 'button'; btn.className = 'gm-menu'; btn.setAttribute('aria-label', 'Researchers and filters');
        btn.innerHTML = '<svg viewBox="0 0 20 20" aria-hidden="true"><path d="M3 5h14M3 10h14M3 15h14" stroke="currentColor" stroke-width="2" stroke-linecap="round"/></svg>';
        document.querySelector('.dic-finder .dic-search-area').prepend(btn);
        const backdrop = document.createElement('div'); backdrop.className = 'gm-backdrop'; document.body.appendChild(backdrop);
        const sidebar = document.getElementById('dicSidebar');
        const close = document.createElement('button'); close.type = 'button'; close.className = 'gm-drawer-close'; close.setAttribute('aria-label', 'Close'); close.textContent = '×';
        sidebar.insertBefore(close, sidebar.firstChild);
        const setDrawer = on => h.classList.toggle('gm-drawer', on);
        btn.onclick = () => setDrawer(true); backdrop.onclick = () => setDrawer(false); close.onclick = () => setDrawer(false);
        sidebar.addEventListener('click', e => { if (e.target.closest('.dic-researcher-item, .dic-status-bucket, .dic-year-item')) setDrawer(false); });

        // Coverage details without hover.
        const results = document.getElementById('dicResults');
        results.addEventListener('click', e => {
            const cov = e.target.closest('.ds-coverage'); if (!cov || !active()) return;
            e.stopPropagation();
            const next = cov.parentElement.nextElementSibling;
            if (next && next.classList.contains('gm-cov')) { next.remove(); return; }
            const d = document.createElement('div'); d.className = 'gm-cov'; d.textContent = cov.title; cov.parentElement.after(d);
        }, true);

        // Leaving the GLP Vision tab closes full-screen views (the PDF stays held; reuse is re-authorized).
        new MutationObserver(() => {
            if (onTab()) { requestAnimationFrame(size); return; }
            setDrawer(false);
            if (cur === 'phone' && viewer.isOpen()) overlayClose(false);
            else if (h.classList.contains('gm-expanded')) expand(false);
        }).observe(tab(), { attributes: true, attributeFilter: ['class'] });
        window.addEventListener('resize', () => requestAnimationFrame(size));

        Object.values(MQ).forEach(m => m.addEventListener('change', applyTier));
        applyTier();
        return { active, openFile, openInternal, present, frame: () => viewer.frame, release, viewer, tier: () => cur, expand, held: () => held };
    }
    window.GLPMobilePI = { init };
})();
