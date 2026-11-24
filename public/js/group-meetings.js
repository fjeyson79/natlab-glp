/**
 * NAT-Lab Group Meetings — shared workspace component (R2).
 *
 * One component for both portals:
 *   - public/pi-dashboard.html  (PI: group switch, Zoom, members, settings, schedule)
 *   - public/upload.html        (members: their authorized groups only)
 * The server decides the role (/api/group-meetings/me); PI controls rendered
 * here are a convenience only — every action is authorized server-side.
 *
 * Scientific documents: listing only. The GLP Vision "View" option is rendered
 * ONLY when the server marks a document can_open (owner or PI). Opening uses
 * the existing PDF.js viewer and presentation mode (gvPresEnter) in an in-page
 * overlay, so closing it returns to the same group, researcher, filter and
 * scroll positions. No approval, discard, archive, delete or edit controls.
 *
 * No polling, timers, background work or external calls. Zoom opens externally.
 */
(function (root, factory) {
    var api = factory(root);
    if (typeof module === 'object' && module.exports) module.exports = api;
    else root.GroupMeetings = api;
})(typeof window !== 'undefined' ? window : globalThis, function (root) {
    'use strict';

    var API = '/api/group-meetings';
    var STATE_KEY = 'natlab.groupMeetings.state.v1';
    var FILTERS = [['week', 'This week'], ['since_last', 'Since last meeting'], ['all', 'All documents']];
    var STATUS_LABEL = { APPROVED: 'Approved', PENDING: 'Pending', SUBMITTED: 'Submitted', REVISION_NEEDED: 'Revision needed' };
    var TYPE_LABEL = { SOP: 'SOP', DATA: 'DATA', PRESENTATION: 'PRES' };
    var DAYS = ['Sunday', 'Monday', 'Tuesday', 'Wednesday', 'Thursday', 'Friday', 'Saturday'];
    var OCC_LABEL = { SCHEDULED: 'Scheduled', IN_PROGRESS: 'In progress', COMPLETED: 'Completed', CANCELLED: 'Cancelled', POSTPONED: 'Postponed' };

    // ------------------------------------------------------------ pure helpers
    function esc(v) {
        return String(v === undefined || v === null ? '' : v).replace(/[&<>"'`]/g, function (c) {
            return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;', '`': '&#96;' }[c];
        });
    }
    function toDate(v) { if (!v) return null; var d = new Date(v); return isNaN(d.getTime()) ? null : d; }
    // "23 Nov" in the current year, "23 Nov 2025" otherwise (complete history stays unambiguous).
    function fmtDate(v) {
        var d = toDate(v);
        if (!d) return null;
        var sameYear = d.getFullYear() === new Date().getFullYear();
        return d.toLocaleDateString('en-GB', sameYear ? { day: 'numeric', month: 'short' } : { day: 'numeric', month: 'short', year: 'numeric' });
    }
    function fmtDateTime(v) {
        var d = toDate(v);
        if (!d) return null;
        return d.toLocaleDateString('en-GB', { weekday: 'short', day: 'numeric', month: 'short', year: 'numeric' }) +
            ' ' + d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' });
    }
    function dateCell(v) {
        var s = fmtDate(v);
        return s ? '<span title="' + esc(toDate(v).toISOString()) + '">' + esc(s) + '</span>'
                 : '<span class="gm-dash" aria-label="none">—</span>';
    }
    function windowLabel(w) {
        if (!w) return '';
        if (w.basis === 'current_calendar_week') return 'This week, from ' + fmtDate(w.since);
        if (w.fallback) return 'Last 7 days (no completed meeting yet)';
        return 'Since last meeting (' + fmtDate(w.since) + ')';
    }
    function isSafeZoomHref(url) { return typeof url === 'string' && /^https:\/\/([a-z0-9-]+\.)*zoom\.(us|com)\//i.test(url); }
    function fileUrl(code, submissionId, download) {
        return API + '/groups/' + encodeURIComponent(code) + '/documents/' + encodeURIComponent(submissionId) + '/file' + (download ? '?download=1' : '');
    }
    function viewerSrc(url) {
        return '/pdfjs/web/viewer.html?file=' + encodeURIComponent(url) + '#pagemode=none&zoom=page-width';
    }

    function renderOverviewRows(rows, selectedId) {
        if (!rows || !rows.length) {
            return '<tr><td colspan="5" class="gm-empty">No researchers in this meeting group yet.</td></tr>';
        }
        return rows.map(function (r) {
            var sel = r.researcher_id === selectedId;
            return '<tr data-rid="' + esc(r.researcher_id) + '" tabindex="0" aria-selected="' + (sel ? 'true' : 'false') + '">' +
                '<td title="' + esc(r.name) + '"><span class="gm-name">' + esc(r.name) + '</span>' + (r.is_self ? '<span class="gm-you">YOU</span>' : '') + '</td>' +
                '<td class="gm-date">' + dateCell(r.last_upload) + '</td>' +
                '<td class="gm-date gm-col-presented">' + dateCell(r.last_presented) + '</td>' +
                '<td class="gm-num">' + (r.new_count > 0 ? '<span class="gm-new">' + esc(r.new_count) + '</span>' : '<span class="gm-zero">0</span>') + '</td>' +
                '<td class="gm-num">' + esc(r.total_count) + '</td>' +
                '</tr>';
        }).join('');
    }

    var EYE_ICON = '<svg viewBox="0 0 20 20" width="15" height="15" aria-hidden="true" focusable="false"><path d="M1.5 10S4.5 4 10 4s8.5 6 8.5 6-3 6-8.5 6-8.5-6-8.5-6z" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="10" cy="10" r="2.6" fill="none" stroke="currentColor" stroke-width="1.5"/></svg>';

    // Two-line document list (type tile · bold title · "TYPE · date · status").
    // The View option exists ONLY when the server says can_open === true.
    function renderDocumentRows(docs) {
        if (!docs || !docs.length) return '<tr><td colspan="2" class="gm-empty">No documents in this period.</td></tr>';
        return docs.map(function (d) {
            var type = TYPE_LABEL[d.file_type] || d.file_type;
            var status = String(d.status || '');
            var view = d.can_open === true
                ? '<button type="button" class="gm-btn gm-btn-view" data-gm-view="' + esc(d.submission_id) + '" aria-label="View ' + esc(d.title) + ' in GLP Vision">' + EYE_ICON + 'View</button>'
                : '';
            return '<tr data-sid="' + esc(d.submission_id) + '">' +
                '<td class="gm-doc-cell"><div class="gm-doc"><span class="gm-ficon gm-ficon-' + esc(d.file_type) + '" aria-hidden="true">' + esc(type) + '</span>' +
                  '<span class="gm-doc-text">' +
                    '<span class="gm-doc-title" title="' + esc(d.title) + '">' + esc(d.title) + '</span>' +
                    '<span class="gm-doc-sub">' + esc(type) + ' · ' + dateCell(d.submitted_at) +
                      ' · <span class="gm-status gm-status-' + esc(status) + '">' + esc(STATUS_LABEL[status] || status) + '</span>' +
                      (d.legacy ? '<span class="gm-legacy" title="Imported pre-2026 record">LEGACY</span>' : '') +
                    '</span>' +
                  '</span></div></td>' +
                '<td class="gm-col-view">' + view + '</td>' +
                '</tr>';
        }).join('');
    }

    // "Load more" row for the complete document history (keyset pages).
    function renderMoreRow(shown, total, hasMore) {
        if (!hasMore) return '';
        return '<tr class="gm-more-row"><td colspan="2"><button type="button" class="gm-btn gm-btn-sm" data-gm-action="more">Load more · ' +
            esc(shown) + ' of ' + esc(total) + ' shown</button></td></tr>';
    }

    function scheduleText(group, info) {
        var parts = [];
        if (info && info.next_occurrence) parts.push('Next: ' + fmtDateTime(info.next_occurrence.scheduled_start));
        else if (group && group.default_day !== null && group.default_day !== undefined) {
            parts.push(DAYS[group.default_day] + 's' + (group.default_time ? ' ' + group.default_time : ''));
        }
        if (info && info.last_completed_at) parts.push('Last meeting: ' + fmtDate(info.last_completed_at));
        if (group && group.location) parts.push(group.location);
        return parts.join(' · ');
    }

    var pure = {
        esc: esc, fmtDate: fmtDate, windowLabel: windowLabel, isSafeZoomHref: isSafeZoomHref,
        fileUrl: fileUrl, viewerSrc: viewerSrc, renderOverviewRows: renderOverviewRows,
        renderDocumentRows: renderDocumentRows, renderMoreRow: renderMoreRow, scheduleText: scheduleText,
        PAGE_SIZE: 100,
    };
    if (typeof document === 'undefined') return pure; // Node: pure helpers only (tests)

    // ------------------------------------------------------------- data access
    function request(path, opts) {
        opts = opts || {};
        var init = { method: opts.method || 'GET', credentials: 'include', headers: {} };
        if (opts.body !== undefined) { init.headers['Content-Type'] = 'application/json'; init.body = JSON.stringify(opts.body); }
        return fetch(API + path, init).then(function (r) {
            return r.json().catch(function () { return null; }).then(function (j) {
                if (!r.ok) {
                    var e = new Error((j && j.error) || ('Request failed (' + r.status + ')'));
                    e.status = r.status; e.body = j; throw e;
                }
                return j;
            });
        });
    }

    var mePromise = null;
    function probe(force) {
        if (!mePromise || force) {
            mePromise = fetch(API + '/me', { credentials: 'include' })
                .then(function (r) { return r.ok ? r.json() : null; })
                .catch(function () { return null; });
        }
        return mePromise;
    }

    // True only when GROUP_MEETINGS_ENABLED is on and the schema is ready.
    // Portals use it to retire the legacy meeting UI; any failure => false
    // (legacy behaviour preserved).
    var statusPromise = null;
    function featureEnabled() {
        if (!statusPromise) {
            statusPromise = fetch(API + '/status', { credentials: 'include' })
                .then(function (r) { return r.ok; })
                .catch(function () { return false; });
        }
        return statusPromise;
    }

    // Shows a portal tab/section button when the feature is on and the user
    // has at least one group (PI: always, once enabled).
    function enableTab(button, onShown) {
        var el = typeof button === 'string' ? document.querySelector(button) : button;
        return probe().then(function (me) {
            if (el && me && (me.role === 'pi' || (me.groups && me.groups.length))) {
                el.style.display = '';
                if (typeof onShown === 'function') onShown(me);
            }
            return me;
        });
    }

    // ------------------------------------------------------------- component
    var instances = [];

    function mount(host, opts) {
        if (!host) return null;
        for (var i = 0; i < instances.length; i++) {
            if (instances[i].host === host) { instances[i].refresh(); return instances[i]; }
        }
        var inst = createInstance(host, opts || {});
        instances.push(inst);
        inst.start();
        return inst;
    }

    function createInstance(host, opts) {
        var me = null, groups = [], code = null, info = null, overview = null, docs = [], docWindow = null;
        var docTotal = null, nextCursor = null;
        var state = { group: null, researcher: null, filter: 'all', leftScroll: 0, rightScroll: 0, loaded: 0 };
        var docSeq = 0, groupSeq = 0, lastFocus = null, saveTimer = null;

        host.innerHTML =
            '<div class="gm-root">' +
              '<div class="gm-toolbar">' +
                '<div class="gm-heading">' +
                  '<div class="gm-group-title" data-gm="gtitle">Group Meetings</div>' +
                  '<div class="gm-meta" data-gm="meta"></div>' +
                '</div>' +
                '<span class="gm-spacer"></span>' +
                '<div class="gm-seg" data-gm="groups" role="group" aria-label="Meeting group"></div>' +
                '<span data-gm="admin" style="display:inline-flex;gap:6px;"></span>' +
                '<button type="button" class="gm-btn gm-btn-icon" data-gm-action="refresh" title="Reload the latest submissions" aria-label="Refresh">&#8635;</button>' +
                '<span data-gm="zoom"></span>' +
              '</div>' +
              '<div data-gm="error"></div>' +
              '<div class="gm-panels">' +
                '<section class="gm-panel" aria-label="Research group overview">' +
                  '<div class="gm-panel-head"><span class="gm-panel-title">Research group overview</span><span class="gm-panel-sub" data-gm="ovsub"></span></div>' +
                  '<div class="gm-scroll" data-gm="leftScroll">' +
                    '<table class="gm-table gm-overview"><thead><tr>' +
                      '<th scope="col">Researcher</th><th scope="col" class="gm-date">Last upload</th>' +
                      '<th scope="col" class="gm-date gm-col-presented"><span class="gm-presented-icon" aria-hidden="true">' +
                        '<svg viewBox="0 0 20 20" width="14" height="14"><rect x="2.5" y="3" width="15" height="10" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M10 13v3M6.5 17h7" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>' +
                      '</span>Last presented</th>' +
                      '<th scope="col" class="gm-num" data-gm="newhead">New</th><th scope="col" class="gm-num">Total</th>' +
                    '</tr></thead><tbody data-gm="ovbody"><tr><td colspan="5" class="gm-empty">Loading…</td></tr></tbody></table>' +
                  '</div>' +
                '</section>' +
                '<section class="gm-panel" aria-label="Selected researcher documents">' +
                  '<div class="gm-panel-head gm-panel-head-docs"><span class="gm-panel-title" data-gm="doctitle">Documents</span>' +
                    '<div class="gm-pills" data-gm="filters" role="group" aria-label="Document filter">' +
                      FILTERS.map(function (f) { return '<button type="button" data-gm-filter="' + f[0] + '" aria-pressed="false">' + f[1] + '</button>'; }).join('') +
                    '</div></div>' +
                  '<div class="gm-scroll" data-gm="rightScroll">' +
                    '<table class="gm-table gm-docs"><tbody data-gm="docbody"></tbody></table>' +
                  '</div>' +
                  '<div class="gm-note" data-gm="docnote" hidden></div>' +
                '</section>' +
              '</div>' +
              '<div class="gm-viewer" data-gm="viewer" hidden role="dialog" aria-modal="true" aria-label="GLP Vision document viewer">' +
                '<div class="gm-viewer-box">' +
                  '<div class="gm-viewer-bar">' +
                    '<span class="gm-viewer-title" data-gm="vtitle"></span><span class="gm-viewer-owner" data-gm="vowner"></span>' +
                    '<span class="gm-spacer"></span>' +
                    '<button type="button" class="gm-btn" data-gm-action="present" title="Presentation Mode">&#127916; Present</button>' +
                    '<a class="gm-btn" data-gm="vdownload" href="#" target="_blank" rel="noopener">Download</a>' +
                    '<button type="button" class="gm-btn gm-btn-primary" data-gm-action="close-viewer">Close</button>' +
                  '</div>' +
                  '<iframe data-gm="vframe" title="Document"></iframe>' +
                '</div>' +
              '</div>' +
              '<div class="gm-dialog" data-gm="dialog" hidden role="dialog" aria-modal="true">' +
                '<div class="gm-dialog-box">' +
                  '<div class="gm-dialog-head"><h3 data-gm="dtitle"></h3><button type="button" class="gm-btn gm-btn-sm" data-gm-action="close-dialog">Close</button></div>' +
                  '<div class="gm-dialog-body" data-gm="dbody"></div>' +
                '</div>' +
              '</div>' +
            '</div>';

        var rootEl = host.querySelector('.gm-root');
        function $(name) { return rootEl.querySelector('[data-gm="' + name + '"]'); }
        var leftScroll = $('leftScroll'), rightScroll = $('rightScroll');

        // ---------------------------------------------------------- state
        function stateKey() { return STATE_KEY + ':' + (me ? me.researcher_id : '-'); }
        function loadState() {
            try { var s = JSON.parse(root.sessionStorage.getItem(stateKey()) || 'null'); if (s && typeof s === 'object') Object.assign(state, s); } catch (_) { /* ignore */ }
            if (!FILTERS.some(function (f) { return f[0] === state.filter; })) state.filter = 'all';
        }
        function saveState() {
            if (saveTimer) return;
            saveTimer = root.requestAnimationFrame(function () {
                saveTimer = null;
                state.leftScroll = leftScroll.scrollTop;
                state.rightScroll = rightScroll.scrollTop;
                try { root.sessionStorage.setItem(stateKey(), JSON.stringify(state)); } catch (_) { /* ignore */ }
            });
        }
        leftScroll.addEventListener('scroll', saveState, { passive: true });
        rightScroll.addEventListener('scroll', saveState, { passive: true });

        function fitHeight() {
            if (!rootEl.offsetParent) return; // hidden tab
            if (root.matchMedia && root.matchMedia('(max-width: 1000px)').matches) { rootEl.style.height = ''; return; }
            var top = rootEl.getBoundingClientRect().top;
            rootEl.style.height = Math.max(470, Math.floor(root.innerHeight - top - 16)) + 'px';
        }
        root.addEventListener('resize', fitHeight);

        function showError(msg) {
            $('error').innerHTML = msg ? '<div class="gm-error" role="alert">' + esc(msg) + '</div>' : '';
        }

        // ---------------------------------------------------------- loading
        function start() {
            fitHeight();
            return probe(true).then(function (m) {
                me = m;
                if (!me) { showError('Group Meetings is not available for your account.'); renderEmpty(); return; }
                loadState();
                groups = me.groups || [];
                if (!groups.length) {
                    showError(me.role === 'pi'
                        ? 'No meeting group has a code yet. Use Settings to assign LIU, UNAV and JOINT.'
                        : 'You have not been added to a meeting group yet.');
                    renderEmpty();
                    renderAdmin();
                    return;
                }
                if (!groups.some(function (g) { return g.code === state.group; })) state.group = groups[0].code;
                renderGroupSwitch();
                renderAdmin();
                return loadGroup(true);
            });
        }

        function refresh() {
            fitHeight();
            if (!me) return start();
            state.leftScroll = leftScroll.scrollTop;
            state.rightScroll = rightScroll.scrollTop;
            return loadGroup(true);
        }

        function renderEmpty() {
            $('ovbody').innerHTML = '<tr><td colspan="5" class="gm-empty">—</td></tr>';
            $('docbody').innerHTML = '';
        }

        function renderGroupSwitch() {
            $('groups').innerHTML = groups.map(function (g) {
                return '<button type="button" data-gm-group="' + esc(g.code) + '" aria-pressed="' + (g.code === state.group) + '" title="' + esc(g.name) + '">' + esc(g.code === 'JOINT' ? 'Joint' : g.code === 'LIU' ? 'LiU' : g.code) + '</button>';
            }).join('');
        }

        function renderAdmin() {
            if (!me || me.role !== 'pi') { $('admin').innerHTML = ''; return; }
            $('admin').innerHTML =
                '<button type="button" class="gm-btn" data-gm-action="members"' + (code || groups.length ? '' : ' disabled') + '>Members</button>' +
                '<button type="button" class="gm-btn" data-gm-action="settings">Settings</button>' +
                '<button type="button" class="gm-btn" data-gm-action="schedule"' + (code || groups.length ? '' : ' disabled') + '>Schedule</button>';
        }

        function renderZoom(group) {
            var label = me && me.role === 'pi' ? 'Open Zoom' : 'Join Zoom';
            if (group && isSafeZoomHref(group.zoom_join_url)) {
                $('zoom').innerHTML = '<a class="gm-btn gm-btn-zoom" href="' + esc(group.zoom_join_url) + '" target="_blank" rel="noopener noreferrer" title="Opens the recurring Zoom meeting in a new window">' + label + '</a>';
            } else {
                $('zoom').innerHTML = '<span class="gm-btn" aria-disabled="true" title="No recurring Zoom link has been configured">' + label + '</span>';
            }
        }

        function loadGroup(keepScroll) {
            code = state.group;
            var seq = ++groupSeq;
            showError('');
            return Promise.all([
                request('/groups/' + encodeURIComponent(code)),
                request('/groups/' + encodeURIComponent(code) + '/overview'),
            ]).then(function (res) {
                if (seq !== groupSeq) return;
                info = res[0]; overview = res[1];
                renderZoom(info.group);
                var n = overview.researchers.length;
                var newTotal = overview.researchers.reduce(function (s, r) { return s + (r.new_count || 0); }, 0);
                $('gtitle').textContent = info.group.name;
                var meta = [scheduleText(info.group, info), n + (n === 1 ? ' researcher' : ' researchers'),
                            newTotal + (newTotal === 1 ? ' new submission' : ' new submissions')].filter(Boolean).join(' · ');
                $('meta').textContent = meta;
                $('meta').title = meta;
                $('ovsub').textContent = 'New: ' + windowLabel(overview.new_window);
                $('newhead').title = 'New submissions — ' + windowLabel(overview.new_window);
                var ids = overview.researchers.map(function (r) { return r.researcher_id; });
                if (ids.indexOf(state.researcher) < 0) {
                    var self = overview.researchers.filter(function (r) { return r.is_self; })[0];
                    state.researcher = self ? self.researcher_id : (ids[0] || null);
                }
                renderOverview();
                if (keepScroll) leftScroll.scrollTop = state.leftScroll || 0;
                return loadDocuments(keepScroll);
            }).catch(handleLoadError);
        }

        function handleLoadError(err) {
            if (err && err.status === 403) {
                // Membership changed (e.g. removed): re-read authorized groups.
                state.group = null;
                return start();
            }
            showError(err && err.status === 503 ? 'Group Meetings is temporarily unavailable.' : ((err && err.message) || 'Could not load Group Meetings.'));
        }

        function renderOverview() {
            $('ovbody').innerHTML = renderOverviewRows(overview ? overview.researchers : [], state.researcher);
            renderGroupSwitch();
        }

        function selectedResearcher() {
            return overview ? overview.researchers.filter(function (r) { return r.researcher_id === state.researcher; })[0] : null;
        }

        function loadDocuments(keepScroll) {
            var r = selectedResearcher();
            Array.prototype.forEach.call($('filters').querySelectorAll('button'), function (b) {
                b.setAttribute('aria-pressed', String(b.getAttribute('data-gm-filter') === state.filter));
            });
            if (!r) { $('doctitle').textContent = 'Documents'; $('docbody').innerHTML = ''; setNote(''); return Promise.resolve(); }
            $('doctitle').textContent = r.name + (r.is_self ? ' (you)' : '') + ' — Documents';
            var seq = ++docSeq;
            // On refresh, reload as many items as were already loaded so the
            // preserved scroll position still points at the same rows.
            var limit = keepScroll ? Math.min(1000, Math.max(pure.PAGE_SIZE, state.loaded || 0)) : pure.PAGE_SIZE;
            return request(docsPath(r, limit, null)).then(function (res) {
                if (seq !== docSeq) return;
                docs = res.documents || [];
                docWindow = res.window;
                docTotal = res.total;
                nextCursor = res.next_cursor;
                renderDocs();
                rightScroll.scrollTop = keepScroll ? (state.rightScroll || 0) : 0;
                saveState();
            }).catch(handleLoadError);
        }

        function docsPath(r, limit, cursor) {
            return '/groups/' + encodeURIComponent(code) + '/members/' + encodeURIComponent(r.researcher_id) +
                '/documents?filter=' + encodeURIComponent(state.filter) + '&limit=' + limit +
                (cursor ? '&cursor=' + encodeURIComponent(cursor) : '');
        }

        function renderDocs() {
            var r = selectedResearcher();
            $('docbody').innerHTML = renderDocumentRows(docs) + renderMoreRow(docs.length, docTotal, !!nextCursor);
            state.loaded = docs.length;
            if (r) $('doctitle').textContent = r.name + (r.is_self ? ' (you)' : '') + ' — Documents' + (typeof docTotal === 'number' ? ' (' + docTotal + ')' : '');
            var notes = [];
            if (docs.some(function (d) { return d.can_open === true; })) notes.push('Open document using GLP Vision');
            else if (r && docs.length) notes.push('Only the document owner and the PI can open documents in Group Meetings');
            if (docWindow) notes.push(windowLabel(docWindow));
            setNote(notes.join(' · '));
        }

        function loadMore() {
            var r = selectedResearcher();
            if (!r || !nextCursor) return;
            var seq = docSeq;
            var btn = rootEl.querySelector('[data-gm-action="more"]');
            if (btn) btn.disabled = true;
            request(docsPath(r, pure.PAGE_SIZE, nextCursor)).then(function (res) {
                if (seq !== docSeq) return; // researcher/filter changed meanwhile
                var top = rightScroll.scrollTop;
                docs = docs.concat(res.documents || []);
                docTotal = res.total;
                nextCursor = res.next_cursor;
                renderDocs();
                rightScroll.scrollTop = top;
                saveState();
            }).catch(function (e) { if (btn) btn.disabled = false; showError(e.message); });
        }

        function setNote(text) { var n = $('docnote'); n.textContent = text; n.hidden = !text; }

        // ---------------------------------------------------------- actions
        function selectGroup(c) {
            if (c === state.group) return;
            state.group = c; state.researcher = null; state.leftScroll = 0; state.rightScroll = 0;
            saveState();
            loadGroup(false);
        }
        function selectResearcher(rid) {
            if (rid === state.researcher) return;
            var hadFocus = document.activeElement && document.activeElement.closest && document.activeElement.closest('tr[data-rid]');
            state.researcher = rid; state.rightScroll = 0;
            renderOverview();
            if (hadFocus) { // keep keyboard focus on the re-rendered row
                var row = rootEl.querySelector('tr[data-rid="' + cssEscape(rid) + '"]');
                if (row) row.focus({ preventScroll: true });
            }
            loadDocuments(false);
        }
        function setFilter(f) {
            if (f === state.filter) return;
            state.filter = f; state.rightScroll = 0;
            loadDocuments(false);
        }
        function cssEscape(v) { return root.CSS && root.CSS.escape ? root.CSS.escape(v) : String(v).replace(/["\\]/g, '\\$&'); }

        // ---------------------------------------------------- viewer overlay
        var viewerUrl = null;
        function openViewer(sid) {
            var d = docs.filter(function (x) { return x.submission_id === sid; })[0];
            if (!d || d.can_open !== true) return; // never offered otherwise; server enforces too
            lastFocus = document.activeElement;
            viewerUrl = fileUrl(code, sid, false);
            var r = selectedResearcher();
            $('vtitle').textContent = d.title;
            $('vowner').textContent = r ? '· ' + r.name : '';
            $('vdownload').href = fileUrl(code, sid, true);
            var frame = $('vframe');
            frame.onload = function () {
                try {
                    var doc = frame.contentDocument;
                    if (!doc || !doc.head) return;
                    var style = doc.createElement('style');
                    style.textContent = '#toolbarContainer,#sidebarContainer,#sidebarContent,#toolbarSidebar,#toolbarViewerMiddle,#toolbarViewerRight,' +
                        '#secondaryToolbar,#loadingBar,#viewerContainer .toolbar,#outerContainer>.toolbar{display:none!important}' +
                        '#viewerContainer{top:0!important}#mainContainer{min-width:0!important}#outerContainer{background:#f8f9fa}';
                    doc.head.appendChild(style);
                } catch (_) { /* same-origin expected; ignore otherwise */ }
            };
            frame.src = viewerSrc(viewerUrl);
            $('viewer').hidden = false;
            rootEl.querySelector('[data-gm-action="close-viewer"]').focus();
        }
        function closeViewer() {
            if ($('viewer').hidden) return;
            $('viewer').hidden = true;
            $('vframe').src = 'about:blank';
            viewerUrl = null;
            if (lastFocus && lastFocus.focus) lastFocus.focus({ preventScroll: true });
        }
        function present() {
            if (viewerUrl && typeof root.gvPresEnter === 'function') root.gvPresEnter(viewerUrl);
        }

        // ---------------------------------------------------------- dialogs
        function openDialog(title, html) {
            lastFocus = document.activeElement;
            $('dtitle').textContent = title;
            $('dbody').innerHTML = html;
            $('dialog').hidden = false;
            var f = $('dbody').querySelector('input,select,button');
            if (f) f.focus();
        }
        function closeDialog() {
            if ($('dialog').hidden) return;
            $('dialog').hidden = true;
            $('dbody').innerHTML = '';
            if (lastFocus && lastFocus.focus) lastFocus.focus({ preventScroll: true });
            refresh();
        }
        function dialogMsg(text, ok) {
            var m = $('dbody').querySelector('[data-gm="dmsg"]');
            if (m) { m.className = 'gm-msg ' + (ok ? 'gm-msg-ok' : 'gm-msg-error'); m.textContent = text || ''; }
        }

        function openMembers() {
            openDialog('Members — ' + groupName(), '<div class="gm-empty">Loading…</div>');
            request('/admin/groups/' + encodeURIComponent(code) + '/members').then(function (res) {
                var rows = res.candidates || [];
                $('dbody').innerHTML =
                    '<input class="gm-input" data-gm="mfilter" placeholder="Filter by name…" aria-label="Filter researchers" style="margin-bottom:8px;">' +
                    '<div data-gm="mlist">' + rows.map(function (c) {
                        var tags = '<span class="gm-tag">' + esc(c.affiliation || '—') + '</span>';
                        if (c.role === 'supervisor') tags += '<span class="gm-tag">Supervisor</span>';
                        if (c.membership_class === 'collaborator') tags += '<span class="gm-tag gm-tag-warn" title="Associated collaborator">Collaborator</span>';
                        if (!c.eligible) tags += '<span class="gm-tag gm-tag-warn" title="Inactive or non-researcher account: has no access">No access</span>';
                        return '<label class="gm-member-row" data-name="' + esc(String(c.name || '').toLowerCase()) + '">' +
                            '<input type="checkbox" data-gm-member="' + esc(c.researcher_id) + '"' + (c.in_group ? ' checked' : '') + (!c.eligible && !c.in_group ? ' disabled' : '') + '>' +
                            '<span class="gm-member-name">' + esc(c.name) + '</span>' + tags + '</label>';
                    }).join('') + '</div>' +
                    '<div class="gm-msg" data-gm="dmsg" role="status"></div>' +
                    '<p class="gm-hint" style="grid-column:auto;margin-top:8px;">Membership is never derived from affiliation. Members of this group see the document listing of all other members; only owners and the PI can open documents.</p>';
                $('dbody').querySelector('[data-gm="mfilter"]').addEventListener('input', function (e) {
                    var q = e.target.value.trim().toLowerCase();
                    Array.prototype.forEach.call($('dbody').querySelectorAll('.gm-member-row'), function (row) {
                        row.style.display = !q || row.getAttribute('data-name').indexOf(q) >= 0 ? '' : 'none';
                    });
                });
            }).catch(function (e) { $('dbody').innerHTML = '<div class="gm-error">' + esc(e.message) + '</div>'; });
        }

        function toggleMember(input) {
            var rid = input.getAttribute('data-gm-member');
            var add = input.checked;
            input.disabled = true;
            request('/admin/groups/' + encodeURIComponent(code) + '/members/' + encodeURIComponent(rid), { method: add ? 'PUT' : 'DELETE' })
                .then(function (res) {
                    var w = res.warnings || [];
                    var notes = [];
                    if (w.indexOf('collaborator') >= 0) notes.push('this person is marked as a collaborator');
                    if (w.indexOf('external_affiliation') >= 0) notes.push('this person is not LiU/UNAV');
                    dialogMsg((add ? 'Added.' : 'Removed.') + (notes.length ? ' Note: ' + notes.join('; ') + ' — they can now see this group\u2019s document listing.' : ''), true);
                })
                .catch(function (e) { input.checked = !add; dialogMsg(e.message, false); })
                .then(function () { input.disabled = false; });
        }

        function openSettings() {
            openDialog('Settings — ' + groupName(), '<div class="gm-empty">Loading…</div>');
            Promise.all([code ? request('/groups/' + encodeURIComponent(code)) : Promise.resolve(null), request('/admin/groups')]).then(function (res) {
                var g = res[0] ? res[0].group : null;
                var all = res[1].groups || [];
                var used = all.map(function (x) { return x.code; }).filter(Boolean);
                var free = ['LIU', 'UNAV', 'JOINT'].filter(function (c) { return used.indexOf(c) < 0; });
                var unmapped = all.filter(function (x) { return !x.code; });
                var html = '';
                if (g) {
                    html += '<form class="gm-form" data-gm="sform" novalidate>' +
                        '<label for="gmZoom">Recurring Zoom link</label><input id="gmZoom" name="zoom_join_url" type="url" placeholder="https://…zoom.us/j/…" value="' + esc(g.zoom_join_url || '') + '">' +
                        '<span class="gm-hint">Participant link only (https, zoom.us or zoom.com). Leave empty to remove. Host controls stay in your Zoom account.</span>' +
                        '<label for="gmDay">Default day</label><select id="gmDay" name="default_day"><option value="">—</option>' +
                            [1, 2, 3, 4, 5, 6, 0].map(function (d) { return '<option value="' + d + '"' + (g.default_day === d ? ' selected' : '') + '>' + DAYS[d] + '</option>'; }).join('') + '</select>' +
                        '<label for="gmTime">Default time</label><input id="gmTime" name="default_time" type="time" value="' + esc(g.default_time || '') + '">' +
                        '<label for="gmDur">Duration (minutes)</label><input id="gmDur" name="duration_minutes" type="number" min="5" max="480" value="' + esc(g.duration_minutes || '') + '">' +
                        '<label for="gmTz">Timezone</label><input id="gmTz" name="timezone" value="' + esc(g.timezone || 'Europe/Stockholm') + '">' +
                        '<label for="gmLoc">Room / location</label><input id="gmLoc" name="location" maxlength="200" value="' + esc(g.location || '') + '">' +
                        '</form>' +
                        '<div style="display:flex;justify-content:flex-end;margin-top:10px;"><button type="button" class="gm-btn gm-btn-primary" data-gm-action="save-settings">Save</button></div>';
                }
                if (unmapped.length && free.length) {
                    html += '<h4 style="margin:16px 0 6px;font-size:13px;color:#1a365d;">Meeting groups without a code</h4>' +
                        unmapped.map(function (x) {
                            return '<div class="gm-occ-row"><span class="gm-occ-when">' + esc(x.name) + '</span>' +
                                '<select class="gm-input" style="width:110px;" data-gm-code-for="' + esc(x.id) + '">' + free.map(function (c) { return '<option>' + c + '</option>'; }).join('') + '</select>' +
                                '<button type="button" class="gm-btn gm-btn-sm" data-gm-assign="' + esc(x.id) + '">Assign</button></div>';
                        }).join('');
                }
                html += '<div class="gm-msg" data-gm="dmsg" role="status"></div>';
                $('dbody').innerHTML = html;
            }).catch(function (e) { $('dbody').innerHTML = '<div class="gm-error">' + esc(e.message) + '</div>'; });
        }

        function saveSettings() {
            var f = $('dbody').querySelector('[data-gm="sform"]');
            if (!f) return;
            var v = function (n) { return f.elements[n].value.trim(); };
            var body = {
                zoom_join_url: v('zoom_join_url') || null,
                default_day: v('default_day') === '' ? null : Number(v('default_day')),
                default_time: v('default_time') || null,
                duration_minutes: v('duration_minutes') === '' ? null : Number(v('duration_minutes')),
                timezone: v('timezone') || 'Europe/Stockholm',
                location: v('location') || null,
            };
            request('/admin/groups/' + encodeURIComponent(code) + '/settings', { method: 'PATCH', body: body })
                .then(function () { dialogMsg('Saved.', true); })
                .catch(function (e) { dialogMsg(e.message, false); });
        }

        function assignCode(groupId) {
            var sel = $('dbody').querySelector('[data-gm-code-for="' + cssEscape(groupId) + '"]');
            request('/admin/groups/' + encodeURIComponent(groupId) + '/code', { method: 'PUT', body: { code: sel.value } })
                .then(function () { closeDialog(); start(); })
                .catch(function (e) { dialogMsg(e.message, false); });
        }

        function openSchedule() {
            openDialog('Schedule — ' + groupName(), '<div class="gm-empty">Loading…</div>');
            request('/groups/' + encodeURIComponent(code) + '/occurrences').then(function (res) {
                var occ = res.occurrences || [];
                $('dbody').innerHTML =
                    '<div class="gm-occ-row" style="gap:6px;">' +
                        '<input class="gm-input" type="datetime-local" data-gm="onew" aria-label="Date and time" style="width:210px;">' +
                        '<input class="gm-input" type="number" min="5" max="480" placeholder="min" data-gm="odur" aria-label="Duration in minutes" style="width:80px;">' +
                        '<input class="gm-input" maxlength="200" placeholder="Note (optional)" data-gm="onote" aria-label="Note" style="flex:1;">' +
                        '<button type="button" class="gm-btn gm-btn-primary" data-gm-action="schedule-new">Schedule</button>' +
                    '</div>' +
                    '<div class="gm-msg" data-gm="dmsg" role="status"></div>' +
                    '<div style="margin-top:8px;">' + (occ.length ? occ.map(function (o) {
                        var acts = '';
                        if (o.status === 'SCHEDULED' || o.status === 'POSTPONED') {
                            acts += '<button type="button" class="gm-btn gm-btn-sm" data-gm-occ="reschedule" data-id="' + esc(o.id) + '">Reschedule</button>';
                            if (o.status === 'SCHEDULED') acts += '<button type="button" class="gm-btn gm-btn-sm" data-gm-occ="postpone" data-id="' + esc(o.id) + '">Postpone</button>';
                            acts += '<button type="button" class="gm-btn gm-btn-sm gm-btn-danger" data-gm-occ="cancel" data-id="' + esc(o.id) + '">Cancel</button>';
                        }
                        return '<div class="gm-occ-row"><span class="gm-occ-when">' + esc(fmtDateTime(o.scheduled_start) || '—') + '</span>' +
                            '<span class="gm-tag">' + esc(OCC_LABEL[o.status] || o.status) + '</span>' + acts + '</div>';
                    }).join('') : '<div class="gm-empty">No meetings scheduled. The scientific workspace stays available regardless.</div>') + '</div>' +
                    '<p class="gm-hint" style="grid-column:auto;margin-top:8px;">Starting and ending a scientific meeting session (attendance, presentations, notes) arrives in R3. Cancelled and postponed meetings do not reset “Since last meeting”.</p>';
            }).catch(function (e) { $('dbody').innerHTML = '<div class="gm-error">' + esc(e.message) + '</div>'; });
        }

        function localToIso(value) { var d = toDate(value); return d ? d.toISOString() : null; }

        function scheduleNew() {
            var when = localToIso($('dbody').querySelector('[data-gm="onew"]').value);
            if (!when) { dialogMsg('Choose a date and time.', false); return; }
            var dur = $('dbody').querySelector('[data-gm="odur"]').value;
            var note = $('dbody').querySelector('[data-gm="onote"]').value;
            request('/admin/groups/' + encodeURIComponent(code) + '/occurrences', {
                method: 'POST', body: { scheduled_start: when, duration_minutes: dur === '' ? null : Number(dur), note: note || null },
            }).then(openSchedule).catch(function (e) { dialogMsg(e.message, false); });
        }

        function occurrenceAction(btn) {
            var action = btn.getAttribute('data-gm-occ');
            var id = btn.getAttribute('data-id');
            var body = {};
            if (action === 'reschedule') {
                var input = $('dbody').querySelector('[data-gm="onew"]');
                var when = localToIso(input.value);
                if (!when) { dialogMsg('Enter the new date and time in the field above, then press Reschedule.', false); input.focus(); return; }
                body.scheduled_start = when;
            }
            request('/admin/occurrences/' + encodeURIComponent(id) + '/' + action, { method: 'POST', body: body })
                .then(openSchedule).catch(function (e) { dialogMsg(e.message, false); });
        }

        function groupName() {
            var g = groups.filter(function (x) { return x.code === code; })[0];
            return g ? g.name : '';
        }

        // ---------------------------------------------------------- events
        rootEl.addEventListener('click', function (e) {
            var t = e.target.closest ? e.target : e.target.parentElement;
            var el;
            if ((el = t.closest('[data-gm-group]'))) return selectGroup(el.getAttribute('data-gm-group'));
            if ((el = t.closest('[data-gm-filter]'))) return setFilter(el.getAttribute('data-gm-filter'));
            if ((el = t.closest('[data-gm-view]'))) return openViewer(el.getAttribute('data-gm-view'));
            if ((el = t.closest('[data-gm-assign]'))) return assignCode(el.getAttribute('data-gm-assign'));
            if ((el = t.closest('[data-gm-occ]'))) return occurrenceAction(el);
            if ((el = t.closest('tr[data-rid]'))) return selectResearcher(el.getAttribute('data-rid'));
            if ((el = t.closest('[data-gm-action]'))) {
                switch (el.getAttribute('data-gm-action')) {
                    case 'refresh': return refresh();
                    case 'more': return loadMore();
                    case 'close-viewer': return closeViewer();
                    case 'present': return present();
                    case 'members': return openMembers();
                    case 'settings': return openSettings();
                    case 'schedule': return openSchedule();
                    case 'close-dialog': return closeDialog();
                    case 'save-settings': return saveSettings();
                    case 'schedule-new': return scheduleNew();
                }
            }
            if (t === $('dialog')) return closeDialog(); // backdrop click
        });
        rootEl.addEventListener('change', function (e) {
            if (e.target.matches && e.target.matches('input[data-gm-member]')) toggleMember(e.target);
        });
        $('ovbody').addEventListener('keydown', function (e) {
            var row = e.target.closest && e.target.closest('tr[data-rid]');
            if (!row) return;
            if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); selectResearcher(row.getAttribute('data-rid')); }
            else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
                e.preventDefault();
                var next = e.key === 'ArrowDown' ? row.nextElementSibling : row.previousElementSibling;
                if (next && next.hasAttribute('data-rid')) { next.focus(); selectResearcher(next.getAttribute('data-rid')); }
            }
        });
        document.addEventListener('keydown', function (e) {
            if (e.key !== 'Escape') return;
            var pres = document.getElementById('gvPresOverlay');
            if (pres && pres.classList.contains('active')) return; // presentation mode handles its own Escape
            if (!$('dialog').hidden) closeDialog();
            else if (!$('viewer').hidden) closeViewer();
        });

        return { host: host, start: start, refresh: refresh };
    }

    pure.probe = probe;
    pure.featureEnabled = featureEnabled;
    pure.enableTab = enableTab;
    pure.mount = mount;
    return pure;
});
