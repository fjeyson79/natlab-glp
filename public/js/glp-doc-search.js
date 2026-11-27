'use strict';
// GLP Vision R3.3 — shared scientific search UI module (researcher / supervisor portal).
// Ported from the PI Portal R2 search (pi-dashboard.html, which keeps its own copy).
// The host page supplies its DOM, filters, sort, rendering and file opening through `cfg`;
// this module owns the search state, debounced requests with stale-response protection,
// result cards (excerpts, highlights, occurrences, page chips) and PDF.js page navigation.
// Server-side authorization is authoritative: the module never decides who may see what.
// No polling: the only timers are the request debounce and a bounded wait for the PDF viewer.
(function () {
    const DEBOUNCE_MS = 280, MIN_CHARS = 2, MAX_QUERY = 200, LIMIT = 50, PAGES_SHOWN = 12;
    const el = (tag, cls, text) => { const e = document.createElement(tag); if (cls) e.className = cls; if (text != null) e.textContent = text; return e; };

    function create(cfg) {
        const S = { enabled: false, scope: 'all', seq: 0, timer: null, active: false, prevSort: null,
                    data: null, loading: false, error: null, nav: null, navSeq: 0, expanded: {}, status: null };
        const C = Object.assign({ item: 'gds-item', icon: 'gds-icon', body: 'gds-body', title: 'gds-title', sub: 'gds-sub', meta: 'gds-meta', empty: 'gds-empty' }, cfg.cls || {});
        const query = () => (cfg.input.value || '').trim();

        async function init() {
            try {
                const r = await fetch(cfg.statusUrl, { credentials: 'include' });
                if (r.status === 401 && cfg.onAuthLost) return cfg.onAuthLost();
                const j = r.ok ? await r.json() : null;
                S.enabled = !!(j && j.enabled && j.available); S.status = S.enabled ? j : null;
            } catch (e) { S.enabled = false; }
            if (S.enabled) mountScope();
            if (cfg.onEnabled) cfg.onEnabled(S.enabled, S.status);
            if (S.enabled && query()) cfg.refresh();
            return S.enabled;
        }
        function mountScope() {
            cfg.wrap.classList.add('gds-on');
            if (cfg.wrap.querySelector('.gds-scope')) return;
            const box = el('div', 'gds-scope'); box.setAttribute('role', 'group'); box.setAttribute('aria-label', 'Search scope');
            [['all', 'All', 'All information: filename and PDF content'], ['filename', 'Filename', 'Filename only'], ['content', 'Content', 'PDF content only']].forEach(([v, t, tip]) => {
                const b = el('button', v === S.scope ? 'active' : '', t); b.type = 'button'; b.dataset.scope = v; b.title = tip;
                b.onclick = () => { S.scope = v; box.querySelectorAll('button').forEach(x => x.classList.toggle('active', x.dataset.scope === v)); if (isActive()) cfg.refresh(); };
                box.appendChild(b);
            });
            cfg.wrap.appendChild(box);
        }
        function isActive() { return !!(S.enabled && query().length >= MIN_CHARS && (!cfg.canSearch || cfg.canSearch())); }

        // Called by the host on every filter/input change. Returns true when the search owns the result list.
        function onFiltersChanged() {
            const active = isActive();
            if (active && !S.active) {            // enter: Relevance by default
                S.active = true; S.prevSort = cfg.getSort() === 'relevance' ? 'newest' : cfg.getSort();
                cfg.setSort('relevance'); if (cfg.onSearchState) cfg.onSearchState(true);
            } else if (!active && S.active) {     // leave: restore the browsing state exactly
                clearSearch(); cfg.setSort(S.prevSort || 'newest'); if (cfg.onSearchState) cfg.onSearchState(false);
            }
            if (!active) return false;
            clearTimeout(S.timer); S.timer = setTimeout(run, DEBOUNCE_MS);
            render(cfg.results());
            return true;
        }
        function clearSearch() { S.active = false; S.data = null; S.error = null; S.nav = null; S.loading = false; S.seq++; S.expanded = {}; clearTimeout(S.timer); }
        // Authorized scope changed (e.g. another researcher selected, re-login): drop results and in-flight responses.
        function reset() { const was = S.active; S.data = null; S.error = null; S.nav = null; S.seq++; S.expanded = {}; clearTimeout(S.timer); if (was && isActive()) { S.timer = setTimeout(run, DEBOUNCE_MS); } }

        async function run() {
            if (!isActive()) return;
            const seq = ++S.seq, f = cfg.getParams() || {};
            const p = new URLSearchParams({ q: query().slice(0, MAX_QUERY), scope: S.scope, sort: cfg.getSort() || 'relevance', window: 'all', limit: String(LIMIT) });
            if (f.type) p.set('type', f.type);
            if (f.status) p.set('status', f.status);
            if (f.days) p.set('days', f.days);
            if (f.year) p.set('year', f.year);
            if (f.researchers) f.researchers.forEach(id => p.append('researchers', id));
            S.loading = true; if (!S.data) render(cfg.results());
            try {
                const r = await fetch(cfg.searchUrl + '?' + p.toString(), { credentials: 'include' });
                if (r.status === 401) { if (seq === S.seq && cfg.onAuthLost) cfg.onAuthLost(); return; }
                const j = await r.json().catch(() => null);
                if (seq !== S.seq) return;                                   // superseded by a newer search / scope change
                if (!r.ok || !j || j.available === false) throw new Error((j && j.error) || 'unavailable');
                S.data = j; S.error = null;
            } catch (e) {
                if (seq !== S.seq) return;
                S.data = null; S.error = 'Full-text search unavailable — showing filename matches.';
            }
            S.loading = false;
            if (isActive()) render(cfg.results());
        }

        function renderExcerpt(ex) {
            const d = el('div', 'gds-excerpt'); if (!ex) return d;
            let pos = 0; if (ex.truncatedStart) d.appendChild(document.createTextNode('… '));
            for (const [s, e] of ex.highlights) {
                if (s > pos) d.appendChild(document.createTextNode(ex.text.slice(pos, s)));
                d.appendChild(el('mark', null, ex.text.slice(s, e))); pos = e;
            }
            if (pos < ex.text.length) d.appendChild(document.createTextNode(ex.text.slice(pos)));
            if (ex.truncatedEnd) d.appendChild(document.createTextNode(' …'));
            return d;
        }
        function render(container) {
            if (!container) return;
            if (S.error || (!S.data && !S.loading)) {   // fallback: the host's filename filtering, with a discreet note
                cfg.hostRender();
                if (S.error) container.insertBefore(el('div', 'gds-note', S.error), container.firstChild);
                return;
            }
            container.textContent = '';
            if (!S.data) { container.appendChild(el('div', C.empty, 'Searching…')); return; }
            const d = S.data, c = d.coverage || {}, n = d.total || 0;
            const nameOnly = (c.unindexed || 0) + (c.failed || 0) + (c.pending || 0) + (c.other || 0);
            const limited = nameOnly + (c.unavailable || 0) + (c.partial || 0);
            const head = el('div', 'gds-head');
            head.appendChild(el('b', null, n + (n === 1 ? ' result' : ' results')));
            if (limited) {
                const cov = el('span', 'gds-coverage', `${nameOnly + (c.unavailable || 0)} not text-searchable${c.partial ? `, ${c.partial} partially indexed` : ''}`);
                cov.title = `Full text indexed: ${c.ok || 0}\nPartially indexed: ${c.partial || 0}\nNot indexed (filename only): ${nameOnly}\nFile unavailable (e.g. revision requested): ${c.unavailable || 0}`;
                head.appendChild(cov);
            }
            container.appendChild(head);
            if (!d.results.length) {
                const msg = d.scope === 'filename' ? 'No filenames match.' :
                    (nameOnly + (c.unavailable || 0)) ? `No matches in indexed PDF text. ${nameOnly + (c.unavailable || 0)} document(s) are not text-searchable${d.scope === 'all' ? ' and were matched by filename only' : ''}.` : 'No matches.';
                container.appendChild(el('div', C.empty, msg)); return;
            }
            const frag = document.createDocumentFragment();
            for (const r of d.results) frag.appendChild(card(r));
            container.appendChild(frag);
            if (d.total > d.results.length) container.appendChild(el('div', 'gds-note', `Showing the first ${d.results.length} of ${d.total}. Refine the search to narrow results.`));
        }
        function card(r) {
            const nav = S.nav, sel = cfg.selectedId && cfg.selectedId();
            const c = el('div', C.item + ' gds-card' + (r.submission_id === sel ? ' active' : ''));
            c.onclick = () => open(r.submission_id, r.excerpt_page || (r.pages[0] && r.pages[0].page) || null);
            const t = r.file_type === 'SOP' ? ['sop', 'SOP'] : r.file_type === 'PRESENTATION' ? ['pres', 'PRES'] : r.file_type === 'REPORT' ? ['data', 'REPORT'] : ['data', 'DATA'];
            c.appendChild(el('div', C.icon + ' ' + t[0], t[1]));
            const body = el('div', C.body + ' gds-cbody');
            const title = el('div', C.title, r.original_filename); title.title = r.original_filename; body.appendChild(title);
            body.appendChild(el('div', C.sub, cfg.formatSub ? cfg.formatSub(r) : String(r.created_at || '').substring(0, 10)));
            const meta = el('div', C.meta);
            if (cfg.statusBadge) { const b = cfg.statusBadge(r.status); if (b) meta.appendChild(b); }
            if (r.occurrences) meta.appendChild(el('span', 'gds-hits', r.occurrences + (r.occurrences === 1 ? ' hit' : ' hits')));
            if (r.name_match) meta.appendChild(el('span', 'gds-idx', 'Filename match'));
            const ix = r.index || {};
            if (ix.status === 'partial') meta.appendChild(el('span', 'gds-idx warn', `Partial text (${ix.pages_indexed}/${ix.page_count} p.)`));
            else if (ix.status === 'no_text') {
                const nt = el('span', 'gds-idx', 'No searchable text · filename only');
                nt.title = 'This PDF has no extractable scientific text (image-based pages or only the approval stamp). It can still be found by filename.';
                meta.appendChild(nt);
            } else if (ix.status !== 'ok') meta.appendChild(el('span', 'gds-idx', 'Text not indexed'));
            body.appendChild(meta);
            if (r.excerpt) body.appendChild(renderExcerpt(r.excerpt));
            if (r.pages && r.pages.length) {
                const row = el('div', 'gds-pages'), all = !!S.expanded[r.submission_id], list = all ? r.pages : r.pages.slice(0, PAGES_SHOWN);
                for (const p of list) {
                    const b = el('button', 'gds-page' + (nav && nav.docId === r.submission_id && nav.page === p.page ? ' active' : ''), 'P. ' + p.page);
                    b.type = 'button'; b.title = `${p.occ} hit${p.occ === 1 ? '' : 's'} on page ${p.page}`;
                    b.onclick = (ev) => { ev.stopPropagation(); open(r.submission_id, p.page); };
                    row.appendChild(b);
                }
                if (!all && r.pages.length > PAGES_SHOWN) {
                    const more = el('button', 'gds-page', `+${r.pages.length - PAGES_SHOWN}`); more.type = 'button';
                    more.onclick = (ev) => { ev.stopPropagation(); S.expanded[r.submission_id] = true; render(cfg.results()); };
                    row.appendChild(more);
                }
                body.appendChild(row);
            }
            c.appendChild(body);
            return c;
        }

        // ---- viewer: open at page, same-document navigation without reload, in-PDF highlighting ----
        function viewerSrc(src, docId) {   // unique token so a rapid A->B->A switch is always a full load
            const n = S.nav; if (!(n && S.active && n.docId === docId)) return src;
            const i = src.indexOf('#'); const q = i < 0 ? src : src.slice(0, i), h = i < 0 ? '' : src.slice(i);
            return q + '&_n=' + n.seq + (h || '#') + (n.page ? `&page=${n.page}` : '');
        }
        function resultFile(docId) { return S.data && (S.data.results || []).find(x => x.submission_id === docId) || null; }
        function open(docId, page) {
            const qd = S.data && S.data.query;
            const terms = (qd && (qd.highlight || qd.terms)) || [];   // includes equivalent identifier spellings
            const nav = { docId, page: page || null, terms, seq: ++S.navSeq };
            S.nav = nav;
            const pdf = cfg.viewer();
            if (cfg.selectedId() === docId && pdf.dataset.gdsDoc === docId && pdf.style.display !== 'none') {
                withViewer(nav, app => applyNav(app, nav)); render(cfg.results());   // same PDF: navigate in place
            } else {
                cfg.openFile(docId);   // host loads the viewer with viewerSrc() and calls afterViewerLoad()
                render(cfg.results());
            }
        }
        function afterViewerLoad(docId) {
            const nav = S.nav; cfg.viewer().dataset.gdsDoc = docId;
            if (S.active && nav && nav.docId === docId) withViewer(nav, app => applyNav(app, nav));
        }
        function withViewer(nav, cb) {
            const pdf = cfg.viewer(), t0 = Date.now();
            (function wait() {
                if (!S.nav || S.nav.seq !== nav.seq || pdf.dataset.gdsDoc !== nav.docId) return;   // superseded
                let app = null; try { app = pdf.contentWindow && pdf.contentWindow.PDFViewerApplication; } catch (e) {}
                const ready = app && app.pdfDocument && app.pdfViewer && app.pdfViewer.pagesCount > 0 && String(app.url || '').includes(nav.docId);
                if (ready) return cb(app);
                if (Date.now() - t0 < 20000) setTimeout(wait, 100);
            })();
        }
        function applyNav(app, nav) {
            if (nav.page && nav.page <= app.pagesCount) app.page = nav.page;
            const key = nav.terms.join('\u0001');
            if (nav.terms.length && app.__gdsTerms !== key) {
                app.__gdsTerms = key;
                app.eventBus.dispatch('find', { source: window, type: '', query: nav.terms.length === 1 ? nav.terms[0] : nav.terms,
                    caseSensitive: false, entireWord: false, highlightAll: true, findPrevious: false, matchDiacritics: false });
            }
            [250, 800].forEach(ms => setTimeout(() => {   // highlighting must never override the selected page
                if (S.nav && S.nav.seq === nav.seq && nav.page && app.page !== nav.page) app.page = nav.page;
            }, ms));
        }

        return { init, isActive, onFiltersChanged, render: () => render(cfg.results()), reset, viewerSrc, afterViewerLoad, resultFile, open, state: S };
    }
    window.GLPDocSearch = { create };
})();
