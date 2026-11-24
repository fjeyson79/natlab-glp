/**
 * NAT-Lab Group Meetings — shared workspace component (R2 + R3.3 sessions).
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
 * R3.3 (only when /me reports sessions: both feature flags on and the session
 * schema ready): meeting sessions. PI: start / resume / end / abandon,
 * attendance, notes and conclusions, one-click Presented / Discussed records
 * (document rows, GLP Vision viewer, presentation mode) and history with
 * corrections. Members: read-only "meeting in progress" indicator, Last
 * presented, document activity and history (shared conclusions only). With
 * sessions off the interface and its requests are exactly R2.2.
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

    var PRES_ICON_SM = '<svg viewBox="0 0 20 20" width="11" height="11" aria-hidden="true" focusable="false"><rect x="2.5" y="3" width="15" height="10" rx="1.5" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M10 13v3M6.5 17h7" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/></svg>';
    var DOT = '<span class="gm-dot" aria-hidden="true"></span>';
    var EYE_ICON = '<svg viewBox="0 0 20 20" width="15" height="15" aria-hidden="true" focusable="false"><path d="M1.5 10S4.5 4 10 4s8.5 6 8.5 6-3 6-8.5 6-8.5-6-8.5-6z" fill="none" stroke="currentColor" stroke-width="1.5"/><circle cx="10" cy="10" r="2.6" fill="none" stroke="currentColor" stroke-width="1.5"/></svg>';

    // R3: read-only meeting activity for a document (all roles). The date is
    // the MEETING date; no presentation times exist.
    function meetingActivity(ms) {
        if (!ms) return '';
        var out = '';
        if (ms.last_presented_on) {
            out += '<span class="gm-activity" title="Last presented in a group meeting">' + PRES_ICON_SM + 'Presented ' + esc(fmtDate(ms.last_presented_on)) +
                (ms.last_presenter_name ? ' by ' + esc(ms.last_presenter_name) : '') + '</span>';
        }
        if (ms.discussed_in_session) out += '<span class="gm-activity gm-activity-disc">Discussed in this meeting</span>';
        return out;
    }

    // Two-line document list (type tile · bold title · "TYPE · date · status").
    // The View option exists ONLY when the server says can_open === true.
    // opts.canMark (PI attached to the active meeting, R3): discreet
    // Presented / Discussed controls; opts.marks[sid][TYPE] = recorded event.
    function renderDocumentRows(docs, opts) {
        if (!docs || !docs.length) return '<tr><td colspan="2" class="gm-empty">No documents in this period.</td></tr>';
        opts = opts || {};
        return docs.map(function (d) {
            var type = TYPE_LABEL[d.file_type] || d.file_type;
            var status = String(d.status || '');
            var view = d.can_open === true
                ? '<button type="button" class="gm-btn gm-btn-view" data-gm-view="' + esc(d.submission_id) + '" aria-label="View ' + esc(d.title) + ' in GLP Vision">' + EYE_ICON + 'View</button>'
                : '';
            var marks = opts.canMark ? renderMarkButtons(d, (opts.marks || {})[d.submission_id], opts.pending) : '';
            return '<tr data-sid="' + esc(d.submission_id) + '">' +
                '<td class="gm-doc-cell"><div class="gm-doc"><span class="gm-ficon gm-ficon-' + esc(d.file_type) + '" aria-hidden="true">' + esc(type) + '</span>' +
                  '<span class="gm-doc-text">' +
                    '<span class="gm-doc-title" title="' + esc(d.title) + '">' + esc(d.title) + '</span>' +
                    '<span class="gm-doc-sub">' + esc(type) + ' · ' + dateCell(d.submitted_at) +
                      ' · <span class="gm-status gm-status-' + esc(status) + '">' + esc(STATUS_LABEL[status] || status) + '</span>' +
                      (d.legacy ? '<span class="gm-legacy" title="Imported pre-2026 record">LEGACY</span>' : '') +
                      meetingActivity(d.meeting_status) +
                    '</span>' +
                  '</span></div></td>' +
                '<td class="gm-col-view">' + marks + view + '</td>' +
                '</tr>';
        }).join('');
    }

    // PI-only one-click controls. Recorded => pressed (✓); clicking a
    // recorded control opens the record (presenter / private comment).
    function renderMarkButtons(d, rec, pending) {
        rec = rec || {};
        pending = pending || {};
        return '<span class="gm-marks" role="group" aria-label="Meeting record">' + ['PRESENTED', 'DISCUSSED'].map(function (t) {
            var ev = rec[t];
            var busy = !!pending[d.submission_id + ':' + t];
            var label = t === 'PRESENTED' ? 'Presented' : 'Discussed';
            var title = ev ? (label + ' in this meeting' + (ev.presenter_name ? ' — ' + ev.presenter_name : '') + '. Click to change presenter, add a private comment or invalidate.')
                           : 'Record: ' + label.toLowerCase() + ' in this meeting' + (t === 'PRESENTED' ? ' (presenter: document owner)' : '');
            return '<button type="button" class="gm-mark' + (ev ? ' gm-mark-on' : '') + '" data-gm-mark="' + t + '" data-sid="' + esc(d.submission_id) + '"' +
                ' aria-pressed="' + (ev ? 'true' : 'false') + '"' + (busy ? ' disabled' : '') + ' title="' + esc(title) + '">' +
                (ev ? '&#10003; ' : '') + label + '</button>';
        }).join('') + '</span>';
    }

    // ------------------------------------------------------ R3 session UI
    function fmtTime(v) {
        var d = toDate(v);
        return d ? d.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit' }) : '';
    }
    function fmtDuration(min) {
        if (min === null || min === undefined || isNaN(min)) return '';
        min = Math.max(0, Math.round(min));
        if (min < 60) return min + ' min';
        var m = min % 60;
        return Math.floor(min / 60) + ' h' + (m ? ' ' + (m < 10 ? '0' : '') + m + ' min' : '');
    }
    function attendanceText(a) {
        if (!a) return '';
        return a.present + ' present · ' + a.absent + ' absent · ' + a.unmarked + ' unmarked (' + a.total + ')';
    }

    // Toolbar session controls. Visible only when sessions are enabled.
    //   s = { role, active, attached, now }
    function renderSessionControls(s) {
        var a = s.active;
        var hist = '<button type="button" class="gm-btn" data-gm-action="history" title="Completed meetings of this group">History</button>';
        if (!a) {
            return (s.role === 'pi' ? '<button type="button" class="gm-btn gm-btn-start" data-gm-action="start-meeting">' + DOT + 'Start meeting</button>' : '') + hist;
        }
        var since = fmtTime(a.started_at);
        var mins = a.started_at ? Math.floor(((s.now || new Date()) - toDate(a.started_at)) / 60000) : null;
        var stale = a.stale === true;
        var tip = 'Meeting in progress since ' + fmtDateTime(a.started_at) + (a.origin === 'ADHOC' ? ' (unscheduled)' : '') +
            (a.reopened ? ' — reopened for corrections' : '') +
            (stale ? '. Started more than 12 hours ago: end or abandon it if it is no longer running.' : '');
        var live = '<span class="gm-live' + (stale ? ' gm-live-stale' : '') + '" data-gm="live" role="status" title="' + esc(tip) + '">' +
            (stale ? '&#9888; ' : '<span class="gm-live-dot" aria-hidden="true"></span>') +
            (a.reopened ? 'Reopened' : 'In progress') + ' · ' + esc(since) +
            (stale ? ' · ' + esc(fmtDuration(mins)) + ' ago' : '') +
            (s.role === 'pi' && a.attendance ? ' · <span title="' + esc(attendanceText(a.attendance)) + '">' + esc(a.attendance.present) + '/' + esc(a.attendance.total) + '</span>' : '') +
            '</span>';
        if (s.role !== 'pi') return live + hist;
        if (!s.attached) {
            return live +
                '<button type="button" class="gm-btn gm-btn-start" data-gm-action="resume-meeting" title="Continue recording this meeting in this window">Resume</button>' +
                '<button type="button" class="gm-btn" data-gm-action="end-meeting">End</button>' +
                (a.reopened ? '' : '<button type="button" class="gm-btn gm-btn-danger" data-gm-action="abandon-meeting">Abandon</button>') + hist;
        }
        return live +
            '<button type="button" class="gm-btn" data-gm-action="attendance">Attendance</button>' +
            '<button type="button" class="gm-btn" data-gm-action="notes">Notes</button>' +
            '<button type="button" class="gm-btn gm-btn-end" data-gm-action="end-meeting">End meeting</button>' + hist;
    }

    var ATT_LABEL = { PRESENT: 'Present', ABSENT: 'Absent', UNMARKED: 'Unmarked' };
    function renderAttendanceRows(roster) {
        if (!roster || !roster.length) return '<div class="gm-empty">No participants in this meeting.</div>';
        return roster.map(function (p) {
            return '<div class="gm-att-row" data-rid="' + esc(p.researcher_id) + '">' +
                '<span class="gm-member-name">' + esc(p.display_name) + '</span>' +
                (p.affiliation ? '<span class="gm-tag">' + esc(p.affiliation) + '</span>' : '') +
                (p.source === 'ADDED' ? '<span class="gm-tag" title="Added during or after the meeting">Added</span>' : '') +
                '<span class="gm-att-seg" role="radiogroup" aria-label="Attendance of ' + esc(p.display_name) + '">' +
                ['PRESENT', 'ABSENT', 'UNMARKED'].map(function (st) {
                    return '<button type="button" role="radio" class="gm-att-' + st + '" data-gm-do="att-set" data-rid="' + esc(p.researcher_id) + '" data-st="' + st + '" aria-checked="' + (p.status === st) + '">' +
                        (st === 'UNMARKED' ? '—' : ATT_LABEL[st]) + '</button>';
                }).join('') + '</span></div>';
        }).join('');
    }

    function renderHistoryList(meetings) {
        if (!meetings || !meetings.length) return '<div class="gm-empty">No completed meetings yet.</div>';
        return meetings.map(function (m) {
            return '<button type="button" class="gm-hist-row" data-gm-do="hist-open" data-id="' + esc(m.id) + '">' +
                '<span class="gm-hist-date">' + esc(fmtDateTime(m.date) || '—') + '</span>' +
                '<span class="gm-hist-dur">' + esc(fmtDuration(m.duration_minutes)) + '</span>' +
                (m.origin === 'ADHOC' ? '<span class="gm-tag">Unscheduled</span>' : '') +
                '<span class="gm-hist-counts">' + esc(m.presented) + ' presented · ' + esc(m.discussed) + ' discussed</span>' +
                '</button>';
        }).join('');
    }

    // One completed meeting. Members receive no private fields from the
    // server; the PI-only parts render only when present AND isPi.
    function renderHistoryDetail(d, isPi, names) {
        var m = d.meeting || {};
        var item = function (e) {
            var doc = e.document;
            var head = doc
                ? '<span class="gm-chip gm-chip-' + esc(doc.file_type) + '">' + esc(TYPE_LABEL[doc.file_type] || doc.file_type) + '</span> <span class="gm-hist-doc" title="' + esc(doc.title) + '">' + esc(doc.title) + '</span>'
                : '<span class="gm-hist-doc gm-muted">Document no longer available</span>';
            var who = [];
            if (e.type === 'PRESENTED' && e.presenter_name) who.push('Presented by ' + esc(e.presenter_name));
            if (e.owner_name && e.owner_name !== e.presenter_name) who.push('owner ' + esc(e.owner_name));
            var view = doc && doc.can_open === true
                ? '<button type="button" class="gm-btn gm-btn-sm" data-gm-do="hist-view" data-sid="' + esc(doc.submission_id) + '" data-title="' + esc(doc.title) + '" data-owner="' + esc(e.owner_name || '') + '">' + EYE_ICON + 'View</button>' : '';
            var pi = '';
            if (isPi && e.event_id) {
                if (e.comment) pi += '<div class="gm-hist-comment"><span class="gm-private-tag">Private</span> ' + esc(e.comment) + '</div>';
                if (e.voided) pi += '<div class="gm-hist-comment"><span class="gm-tag gm-tag-warn">Invalidated</span>' + (e.void_reason ? ' ' + esc(e.void_reason) : '') + '</div>';
            }
            var acts = isPi && e.event_id && !e.voided
                ? '<button type="button" class="gm-btn gm-btn-sm" data-gm-do="hist-rec-edit" data-ev="' + esc(e.event_id) + '">Correct</button>' : '';
            return '<li class="gm-hist-item' + (e.voided ? ' gm-voided' : '') + '"><div class="gm-hist-line">' + head + '<span class="gm-spacer"></span>' + acts + view + '</div>' +
                (who.length ? '<div class="gm-hist-who">' + who.join(' · ') + '</div>' : '') + pi + '</li>';
        };
        var list = function (rows, empty) { return rows && rows.length ? '<ul class="gm-hist-list">' + rows.map(item).join('') + '</ul>' : '<div class="gm-muted gm-hist-none">' + empty + '</div>'; };
        var html =
            '<div class="gm-hist-head"><strong>' + esc(fmtDateTime(m.date) || '—') + '</strong>' +
              (m.duration_minutes !== null && m.duration_minutes !== undefined ? ' · ' + esc(fmtDuration(m.duration_minutes)) : '') +
              (m.origin === 'ADHOC' ? ' <span class="gm-tag">Unscheduled</span>' : '') + '</div>' +
            '<h4 class="gm-h4">Presented</h4>' + list(d.presentations, 'No documents were recorded as presented.') +
            '<h4 class="gm-h4">Discussed</h4>' + list(d.discussions, 'No documents were recorded as discussed.') +
            '<h4 class="gm-h4">Shared scientific conclusions <span class="gm-vis">Visible to group members</span></h4>' +
            (d.shared_conclusions ? '<div class="gm-text-block">' + esc(d.shared_conclusions) + '</div>' : '<div class="gm-muted gm-hist-none">None recorded.</div>');
        if (isPi) {
            if ('private_notes' in d) {
                html += '<h4 class="gm-h4">Private PI notes <span class="gm-private-tag">PI only</span></h4>' +
                    (d.private_notes ? '<div class="gm-text-block gm-private-block">' + esc(d.private_notes) + '</div>' : '<div class="gm-muted gm-hist-none">None.</div>');
            }
            if (d.attendance) {
                var cnt = { PRESENT: 0, ABSENT: 0, UNMARKED: 0 };
                d.attendance.forEach(function (a) { cnt[a.status] = (cnt[a.status] || 0) + 1; });
                html += '<h4 class="gm-h4">Attendance <span class="gm-private-tag">PI only</span> <span class="gm-muted">' + cnt.PRESENT + ' present · ' + cnt.ABSENT + ' absent · ' + cnt.UNMARKED + ' unmarked</span></h4>' +
                    '<div class="gm-att-summary">' + d.attendance.map(function (a) {
                        return '<span class="gm-att-pill gm-att-pill-' + esc(a.status) + '">' + esc(a.display_name) + '</span>';
                    }).join('') + '</div>';
            }
            if (d.correction_log) {
                html += '<h4 class="gm-h4">Correction history <span class="gm-private-tag">PI only</span></h4>' +
                    (d.correction_log.length ? '<ul class="gm-log">' + d.correction_log.slice().reverse().map(function (e) {
                        return '<li><span class="gm-log-at">' + esc(fmtDateTime(e.at) || '') + '</span> ' + esc(describeLogEntry(e, names || {})) + '</li>';
                    }).join('') + '</ul>' : '<div class="gm-muted gm-hist-none">No corrections.</div>');
            }
        }
        return html;
    }

    function describeLogEntry(e, names) {
        var n = function (id) { return (id && names[id]) || (id ? 'participant' : '—'); };
        switch (e.what) {
            case 'reopen': return 'Meeting reopened';
            case 'abandon': return 'Session abandoned' + (e.reason ? ' (' + e.reason + ')' : '');
            case 'complete': return 'Meeting ended again after reopening';
            case 'attendance': return 'Attendance of ' + n(e.target) + ': ' + (ATT_LABEL[e.from] || e.from) + ' → ' + (ATT_LABEL[e.to] || e.to);
            case 'attendance_bulk': return (e.action === 'all_present' ? 'All marked present' : 'Remaining marked absent') + ' (' + ((e.changes || []).length) + ')';
            case 'attendance_add': return 'Participant added: ' + n(e.target);
            case 'shared_conclusions': return 'Shared conclusions edited';
            case 'private_notes': return 'Private notes edited';
            case 'times': return 'Start/end corrected: ' + fmtDateTime(e.from && e.from.started_at) + '–' + fmtTime(e.from && e.from.ended_at) +
                ' → ' + fmtDateTime(e.to && e.to.started_at) + '–' + fmtTime(e.to && e.to.ended_at) + (e.reason ? ' (' + e.reason + ')' : '');
            case 'presentation_add': return (e.event_type === 'DISCUSSED' ? 'Discussed' : 'Presented') + ' record added' + (e.presenter ? ' (presenter ' + n(e.presenter) + ')' : '');
            case 'presenter': return 'Presenter changed: ' + n(e.from) + ' → ' + n(e.to);
            case 'presentation_comment': return 'Private comment edited';
            case 'presentation_void': return 'Record invalidated' + (e.reason ? ' (' + e.reason + ')' : '');
            default: return String(e.what || 'Change');
        }
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
        fmtDuration: fmtDuration, renderSessionControls: renderSessionControls, renderAttendanceRows: renderAttendanceRows,
        renderHistoryList: renderHistoryList, renderHistoryDetail: renderHistoryDetail, describeLogEntry: describeLogEntry,
        meetingActivity: meetingActivity,
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
        var state = { group: null, researcher: null, filter: 'all', leftScroll: 0, rightScroll: 0, loaded: 0, attached: {} };
        var docSeq = 0, groupSeq = 0, lastFocus = null, saveTimer = null;
        // R3 (only when me.sessions): active = member-safe summary; sess = PI detail.
        var active = null, sess = null, sessError = null, pending = {}, flashText = '';
        var dialogHandlers = {}, dialogBack = null, viewerCtx = null;

        host.innerHTML =
            '<div class="gm-root">' +
              '<div class="gm-toolbar">' +
                '<div class="gm-heading">' +
                  '<div class="gm-group-title" data-gm="gtitle">Group Meetings</div>' +
                  '<div class="gm-meta" data-gm="meta"></div>' +
                '</div>' +
                '<span class="gm-spacer"></span>' +
                '<div class="gm-seg" data-gm="groups" role="group" aria-label="Meeting group"></div>' +
                '<span data-gm="session" class="gm-session"></span>' +
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
                  '<div class="gm-flash" data-gm="flash" role="status" aria-live="polite" hidden></div>' +
                  '<div class="gm-note" data-gm="docnote" hidden></div>' +
                '</section>' +
              '</div>' +
              '<div class="gm-viewer" data-gm="viewer" hidden role="dialog" aria-modal="true" aria-label="GLP Vision document viewer">' +
                '<div class="gm-viewer-box">' +
                  '<div class="gm-viewer-bar">' +
                    '<span class="gm-viewer-title" data-gm="vtitle"></span><span class="gm-viewer-owner" data-gm="vowner"></span>' +
                    '<span class="gm-spacer"></span>' +
                    '<span data-gm="vmarks" class="gm-vmarks"></span>' +
                    '<button type="button" class="gm-btn" data-gm-action="present" title="Presentation Mode">&#127916; Present</button>' +
                    '<a class="gm-btn" data-gm="vdownload" href="#" target="_blank" rel="noopener">Download</a>' +
                    '<button type="button" class="gm-btn gm-btn-primary" data-gm-action="close-viewer">Close</button>' +
                  '</div>' +
                  '<iframe data-gm="vframe" title="Document"></iframe>' +
                '</div>' +
              '</div>' +
              '<div class="gm-dialog" data-gm="dialog" hidden role="dialog" aria-modal="true">' +
                '<div class="gm-dialog-box">' +
                  '<div class="gm-dialog-head"><button type="button" class="gm-btn gm-btn-sm" data-gm-action="dialog-back" data-gm="dback" hidden>&#8592; Back</button>' +
                    '<h3 data-gm="dtitle"></h3><button type="button" class="gm-btn gm-btn-sm" data-gm-action="close-dialog">Close</button></div>' +
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
            if (!state.attached || typeof state.attached !== 'object') state.attached = {};
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
            // During an active meeting the toolbar shows the meeting controls instead.
            if (active) { $('admin').innerHTML = ''; return; }
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
            var reqs = [
                request('/groups/' + encodeURIComponent(code)),
                request('/groups/' + encodeURIComponent(code) + '/overview'),
            ];
            // R3 requests only when sessions are enabled (flag isolation).
            if (sessionsOn()) reqs.push(loadSession(code));
            return Promise.all(reqs).then(function (res) {
                if (seq !== groupSeq) return;
                info = res[0]; overview = res[1];
                renderSession();
                renderAdmin();
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
                if (!keepScroll) setFlash('');
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

        function docsPath(r, limit, cursor, filter) {
            return '/groups/' + encodeURIComponent(code) + '/members/' + encodeURIComponent(r.researcher_id) +
                '/documents?filter=' + encodeURIComponent(filter || state.filter) + '&limit=' + limit +
                (cursor ? '&cursor=' + encodeURIComponent(cursor) : '');
        }

        function renderDocs() {
            var r = selectedResearcher();
            var marking = isAttached();
            $('docbody').closest('table').classList.toggle('gm-marking', marking);
            $('docbody').innerHTML = renderDocumentRows(docs, marking ? { canMark: true, marks: marksBySid(), pending: pending } : null) +
                renderMoreRow(docs.length, docTotal, !!nextCursor);
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
        function openViewer(subId) {
            var d = docById(subId);
            if (!d || d.can_open !== true) return; // never offered otherwise; server enforces too
            var r = selectedResearcher();
            openViewerDoc({ submission_id: subId, title: d.title, owner: r ? r.name : '', fromDialog: false });
        }
        // Also used from Meeting history (owner-and-PI-only documents; the
        // server enforces it again on the file request).
        function openViewerDoc(ctx) {
            viewerCtx = ctx;
            if (!ctx.fromDialog) lastFocus = document.activeElement;
            viewerUrl = fileUrl(code, ctx.submission_id, false);
            $('vtitle').textContent = ctx.title || '';
            $('vowner').textContent = ctx.owner ? '· ' + ctx.owner : '';
            $('vdownload').href = fileUrl(code, ctx.submission_id, true);
            $('viewer').classList.toggle('gm-viewer-top', !!ctx.fromDialog);
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
            renderViewerMarks();
            rootEl.querySelector('[data-gm-action="close-viewer"]').focus();
        }
        function closeViewer() {
            if ($('viewer').hidden) return;
            var fromDialog = viewerCtx && viewerCtx.fromDialog;
            $('viewer').hidden = true;
            $('vframe').src = 'about:blank';
            viewerUrl = null; viewerCtx = null;
            $('vmarks').innerHTML = '';
            var bar = document.getElementById('gmPresMarks'); if (bar) bar.remove();
            if (fromDialog) { var b = $('dbody').querySelector('[data-gm-do="hist-view"]'); if (b) b.focus({ preventScroll: true }); return; }
            if (lastFocus && lastFocus.focus) lastFocus.focus({ preventScroll: true });
        }
        function present() {
            if (viewerUrl && typeof root.gvPresEnter === 'function') {
                root.gvPresEnter(viewerUrl);
                renderPresMarks();
            }
        }

        // ---------------------------------------------------------- dialogs
        function openDialog(title, html, back, wide) {
            if ($('dialog').hidden) lastFocus = document.activeElement;
            $('dtitle').textContent = title;
            $('dbody').innerHTML = html;
            $('dialog').classList.toggle('gm-dialog-wide', !!wide);
            setDialogBack(back || null);
            $('dialog').hidden = false;
            var f = $('dbody').querySelector('input,select,button');
            if (f) f.focus();
        }
        function closeDialog() {
            if ($('dialog').hidden) return;
            $('dialog').hidden = true;
            $('dbody').innerHTML = '';
            setDialogBack(null);
            hist = null; attCtx = null; notesCtx = null; recCtx = null;
            if (lastFocus && lastFocus.focus) lastFocus.focus({ preventScroll: true });
            refresh();
        }
        function setDialogBack(fn) { dialogBack = fn; $('dback').hidden = !fn; }
        function dialogError(e) {
            if (e && e.status === 404 && sessionsOn()) { $('dbody').innerHTML = '<div class="gm-error">' + esc(e.message || 'Not found') + '</div>'; return; }
            $('dbody').innerHTML = '<div class="gm-error">' + esc((e && e.status ? e.message : 'Network error. Nothing was changed; try again.')) + '</div>';
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

        // ======================================================= R3 sessions
        // Everything below is reached only when me.sessions is true (both flags
        // on + session schema ready). Authoritative state is on the server:
        // every render is derived from it, so refresh / logout / restart
        // simply re-read the active meeting. Nothing is completed, abandoned
        // or recorded automatically.
        function sessionsOn() { return !!(me && me.sessions); }
        function isPi() { return !!(me && me.role === 'pi'); }
        function isAttached() {
            return sessionsOn() && isPi() && !!active && !!sess && !!sess.session &&
                sess.session.id === active.id && state.attached[code] === active.id;
        }
        function sid() { return active ? active.id : null; }

        function loadSession(c) {
            sessError = null;
            return request('/groups/' + encodeURIComponent(c) + '/session').then(function (r) {
                active = r.active || null;
                if (!active) { sess = null; if (state.attached[c]) { delete state.attached[c]; saveState(); } return; }
                if (!isPi()) { sess = null; return; }
                return request('/admin/sessions/' + encodeURIComponent(active.id)).then(function (d) { sess = d; });
            }).catch(function (e) {
                // The R2 workspace keeps working; meeting controls stay hidden.
                active = null; sess = null; sessError = e;
            });
        }

        function renderSession() {
            var el = $('session');
            rootEl.classList.toggle('gm-has-session', sessionsOn());
            if (!sessionsOn()) { el.innerHTML = ''; return; }
            if (sessError) {
                el.innerHTML = '<span class="gm-live gm-live-stale" title="' + esc(sessError.message || '') + '">Meeting status unavailable</span>' +
                    '<button type="button" class="gm-btn" data-gm-action="refresh-session">Retry</button>';
                return;
            }
            el.innerHTML = renderSessionControls({ role: me.role, active: active, attached: isAttached(), now: new Date() });
            if (!$('viewer').hidden) renderViewerMarks();
        }

        function marksBySid() {
            var out = {};
            var names = rosterNames();
            ((sess && sess.events) || []).forEach(function (e) {
                if (e.voided_at) return;
                (out[e.submission_id] = out[e.submission_id] || {})[e.event_type] = {
                    id: e.id, presenter_researcher_id: e.presenter_researcher_id, comment: e.comment,
                    presenter_name: e.presenter_researcher_id ? names[e.presenter_researcher_id] : null,
                };
            });
            return out;
        }
        function rosterNames(roster) {
            var n = {};
            (roster || (sess && sess.roster) || []).forEach(function (p) { n[p.researcher_id] = p.display_name; });
            if (me) n[me.researcher_id] = n[me.researcher_id] || 'PI';
            return n;
        }

        // Re-read workspace + meeting state, keeping group, researcher,
        // filter and both scroll positions (no page reload).
        function softRefresh() {
            state.leftScroll = leftScroll.scrollTop;
            state.rightScroll = rightScroll.scrollTop;
            return loadGroup(true);
        }

        function setFlash(text, ok) {
            flashText = text || '';
            var f = $('flash');
            f.textContent = flashText;
            f.className = 'gm-flash' + (ok === false ? ' gm-flash-error' : '');
            f.hidden = !flashText;
        }

        function sessionFailure(e) {
            // The meeting ended elsewhere (another window) or the request failed.
            if (e && (e.status === 409 || e.status === 404)) {
                setFlash((e.message || 'The meeting changed meanwhile.') + ' Reloaded.', false);
                return softRefresh();
            }
            setFlash((e && e.status ? e.message : 'Network error: nothing was changed. Retrying is safe.'), false);
        }

        // ------------------------------------------- start / resume / end
        function openStart() {
            openDialog('Start meeting — ' + groupName(), '<div class="gm-empty">Loading…</div>');
            request('/groups/' + encodeURIComponent(code) + '/occurrences').then(function (res) {
                var nowT = Date.now();
                var occ = (res.occurrences || []).filter(function (o) { return o.status === 'SCHEDULED'; })
                    .sort(function (a, b) { return Math.abs(new Date(a.scheduled_start) - nowT) - Math.abs(new Date(b.scheduled_start) - nowT); })
                    .slice(0, 6);
                var pre = occ.length && Math.abs(new Date(occ[0].scheduled_start) - nowT) < 12 * 3600 * 1000 ? occ[0].id : '';
                $('dbody').innerHTML =
                    '<div class="gm-choice-list" role="radiogroup" aria-label="Meeting to start">' +
                    occ.map(function (o) {
                        return '<label class="gm-choice"><input type="radio" name="gmStartOcc" value="' + esc(o.id) + '"' + (o.id === pre ? ' checked' : '') + '>' +
                            '<span><strong>' + esc(fmtDateTime(o.scheduled_start)) + '</strong> <span class="gm-muted">Scheduled' + (o.duration_minutes ? ' · ' + esc(fmtDuration(o.duration_minutes)) : '') + '</span></span></label>';
                    }).join('') +
                    '<label class="gm-choice"><input type="radio" name="gmStartOcc" value=""' + (pre ? '' : ' checked') + '>' +
                        '<span><strong>Unscheduled meeting</strong> <span class="gm-muted">starts now, not linked to the schedule</span></span></label>' +
                    '</div>' +
                    '<p class="gm-hint gm-hint-block">The participants are the current members of ' + esc(groupName()) + '. Attendance is never marked automatically. ' +
                        'The meeting stays open until you end or abandon it — closing the browser does not end it.</p>' +
                    '<div class="gm-msg" data-gm="dmsg" role="status"></div>' +
                    '<div class="gm-dialog-actions"><button type="button" class="gm-btn gm-btn-primary" data-gm-do="start-confirm">Start meeting</button></div>';
            }).catch(dialogError);
        }
        dialogHandlers['start-confirm'] = function (btn) {
            var sel = $('dbody').querySelector('input[name="gmStartOcc"]:checked');
            var occId = sel ? sel.value : '';
            btn.disabled = true;
            request('/admin/groups/' + encodeURIComponent(code) + '/sessions', { method: 'POST', body: occId ? { occurrence_id: occId } : { adhoc: true } })
                .then(function (r) {
                    state.attached[code] = r.session.id; saveState();
                    setFlash(r.resumed ? 'Meeting resumed.' : 'Meeting started. Mark attendance with “Attendance”.', true);
                    closeDialog();
                })
                .catch(function (e) {
                    btn.disabled = false;
                    if (e.status === 409 && e.body && e.body.code === 'already_active') {
                        dialogMsg('A meeting is already in progress for this group (started in another window). Use Resume.', false);
                    } else dialogMsg(e.message, false);
                });
        };

        function resumeMeeting() {
            if (!active) return;
            state.attached[code] = active.id; saveState();
            setFlash('Meeting resumed in this window.', true);
            softRefresh();
        }

        function openEnd(abandonFirst) {
            if (!active) return;
            openDialog((abandonFirst ? 'Abandon session' : 'End meeting') + ' — ' + groupName(), '<div class="gm-empty">Loading…</div>');
            request('/admin/sessions/' + encodeURIComponent(active.id)).then(function (d) {
                var a = d.attendance || { present: 0, absent: 0, unmarked: 0, total: 0 };
                var n = (d.events || []).filter(function (e) { return !e.voided_at; });
                var pres = n.filter(function (e) { return e.event_type === 'PRESENTED'; }).length;
                var disc = n.length - pres;
                var html = '<div class="gm-end-summary">' +
                    '<div><span class="gm-muted">Started</span> ' + esc(fmtDateTime(d.session.started_at)) + (d.reopened ? ' <span class="gm-tag">Reopened</span>' : '') + '</div>' +
                    '<div><span class="gm-muted">Attendance</span> ' + esc(attendanceText(a)) + '</div>' +
                    '<div><span class="gm-muted">Records</span> ' + pres + ' presented · ' + disc + ' discussed</div></div>' +
                    (d.stale ? '<div class="gm-warn">This meeting was started more than 12 hours ago. If it did not actually run this long, end it and correct the times in History, or abandon it.</div>' : '');
                if (!abandonFirst) {
                    html += (a.unmarked ? '<div class="gm-warn">' + a.unmarked + (a.unmarked === 1 ? ' participant is' : ' participants are') +
                            ' still unmarked. You can mark them absent now, or end the meeting and they stay “Unmarked” in the record (correctable later in History).</div>' : '') +
                        '<div class="gm-msg" data-gm="dmsg" role="status"></div>' +
                        '<div class="gm-dialog-actions">' +
                        (d.reopened ? '' : '<button type="button" class="gm-btn gm-btn-danger gm-left" data-gm-do="abandon-ask">Abandon session…</button>') +
                        (a.unmarked ? '<button type="button" class="gm-btn" data-gm-do="end-confirm" data-absent="1">Mark remaining absent &amp; end</button>' : '') +
                        '<button type="button" class="gm-btn gm-btn-primary" data-gm-do="end-confirm">End meeting</button></div>';
                } else {
                    html += abandonForm(d.reopened);
                }
                $('dbody').innerHTML = html;
            }).catch(dialogError);
        }
        function abandonForm(reopened) {
            if (reopened) return '<div class="gm-warn">A reopened meeting cannot be abandoned; end it again to keep its record.</div>';
            return '<div class="gm-warn">Abandoning discards this session as a meeting: it will not appear in History and does not count as the last meeting. ' +
                    'Attendance and records stay stored but are not shown. Use this only if the meeting did not take place.</div>' +
                '<label class="gm-label" for="gmAbReason">Reason (optional) <span class="gm-private-tag">PI only</span></label><input id="gmAbReason" class="gm-input" maxlength="500" data-gm="abreason">' +
                '<div class="gm-msg" data-gm="dmsg" role="status"></div>' +
                '<div class="gm-dialog-actions"><button type="button" class="gm-btn" data-gm-action="close-dialog">Keep meeting</button>' +
                '<button type="button" class="gm-btn gm-btn-danger" data-gm-do="abandon-confirm">Abandon session</button></div>';
        }
        dialogHandlers['abandon-ask'] = function () {
            var box = $('dbody').querySelector('.gm-dialog-actions');
            if (box) box.outerHTML = abandonForm(false);
            var r = $('dbody').querySelector('[data-gm="abreason"]'); if (r) r.focus();
        };
        dialogHandlers['end-confirm'] = function (btn) {
            var id = sid(); if (!id) return;
            btn.disabled = true;
            request('/admin/sessions/' + encodeURIComponent(id) + '/end', { method: 'POST', body: { confirm: true, mark_remaining_absent: btn.getAttribute('data-absent') === '1' } })
                .then(function (r) {
                    delete state.attached[code]; saveState();
                    setFlash('Meeting ended · ' + attendanceText(r.attendance) + '.', true);
                    closeDialog();
                }).catch(function (e) { btn.disabled = false; dialogMsg(e.message, false); });
        };
        dialogHandlers['abandon-confirm'] = function (btn) {
            var id = sid(); if (!id) return;
            var reason = ($('dbody').querySelector('[data-gm="abreason"]') || {}).value || '';
            btn.disabled = true;
            request('/admin/sessions/' + encodeURIComponent(id) + '/abandon', { method: 'POST', body: { confirm: true, reason: reason.trim() || null } })
                .then(function () { delete state.attached[code]; saveState(); setFlash('Session abandoned.', true); closeDialog(); })
                .catch(function (e) { btn.disabled = false; dialogMsg(e.message, false); });
        };

        // ------------------------------------------------- attendance
        // Same dialog for the active meeting and for historical corrections.
        var attCtx = null;
        function openAttendance(occId, back) {
            attCtx = { id: occId, back: back || null };
            openDialog('Attendance — ' + groupName(), '<div class="gm-empty">Loading…</div>', back);
            renderAttendanceDialog();
        }
        function renderAttendanceDialog() {
            var ctx = attCtx;
            return Promise.all([
                request('/admin/sessions/' + encodeURIComponent(ctx.id)),
                request('/admin/groups/' + encodeURIComponent(code) + '/members').catch(function () { return { candidates: [] }; }),
            ]).then(function (res) {
                if (ctx !== attCtx) return;
                var d = res[0];
                var inRoster = {};
                (d.roster || []).forEach(function (p) { inRoster[p.researcher_id] = true; });
                var addable = (res[1].candidates || []).filter(function (c) { return c.in_group && c.eligible && !inRoster[c.researcher_id]; });
                var completed = d.session.status === 'COMPLETED';
                $('dbody').innerHTML =
                    (completed ? '<div class="gm-warn gm-warn-info">Correcting a completed meeting (' + esc(fmtDateTime(d.session.started_at)) + '). Every change is recorded in the correction history.</div>' : '') +
                    '<div class="gm-att-head"><span data-gm="attsum" class="gm-att-sum">' + esc(attendanceText(d.attendance)) + '</span><span class="gm-spacer"></span>' +
                        '<button type="button" class="gm-btn gm-btn-sm" data-gm-do="att-bulk" data-act="all_present">Mark all present</button>' +
                        '<button type="button" class="gm-btn gm-btn-sm" data-gm-do="att-bulk" data-act="remaining_absent"' + (d.attendance.unmarked ? '' : ' disabled') + '>Mark remaining absent</button></div>' +
                    '<div class="gm-att-list">' + renderAttendanceRows(d.roster) + '</div>' +
                    (addable.length ? '<div class="gm-att-add"><select class="gm-input" data-gm="attadd" aria-label="Eligible member to add">' +
                        addable.map(function (c) { return '<option value="' + esc(c.researcher_id) + '">' + esc(c.name) + '</option>'; }).join('') + '</select>' +
                        '<button type="button" class="gm-btn gm-btn-sm" data-gm-do="att-add">Add participant</button></div>' : '') +
                    '<div class="gm-msg" data-gm="dmsg" role="status"></div>' +
                    '<p class="gm-hint gm-hint-block">Attendance is visible only to you. Unmarked participants can stay unmarked when the meeting ends.</p>';
            }).catch(dialogError);
        }
        dialogHandlers['att-set'] = function (btn) {
            var rid = btn.getAttribute('data-rid'), st = btn.getAttribute('data-st');
            var group = btn.parentNode;
            Array.prototype.forEach.call(group.querySelectorAll('button'), function (b) { b.disabled = true; });
            request('/admin/sessions/' + encodeURIComponent(attCtx.id) + '/attendance/' + encodeURIComponent(rid), { method: 'PUT', body: { status: st } })
                .then(function () { return renderAttendanceDialog(); })
                .catch(function (e) { Array.prototype.forEach.call(group.querySelectorAll('button'), function (b) { b.disabled = false; }); dialogMsg(e.message, false); });
        };
        dialogHandlers['att-bulk'] = function (btn) {
            btn.disabled = true;
            request('/admin/sessions/' + encodeURIComponent(attCtx.id) + '/attendance/bulk', { method: 'POST', body: { action: btn.getAttribute('data-act') } })
                .then(function () { return renderAttendanceDialog(); })
                .catch(function (e) { btn.disabled = false; dialogMsg(e.message, false); });
        };
        dialogHandlers['att-add'] = function (btn) {
            var sel = $('dbody').querySelector('[data-gm="attadd"]');
            if (!sel || !sel.value) return;
            btn.disabled = true;
            request('/admin/sessions/' + encodeURIComponent(attCtx.id) + '/attendance', { method: 'POST', body: { researcher_id: sel.value } })
                .then(function () { return renderAttendanceDialog(); })
                .catch(function (e) { btn.disabled = false; dialogMsg(e.message, false); });
        };

        // ------------------------------------------------- notes
        var notesCtx = null;
        function openNotes(occId, back) {
            notesCtx = { id: occId, updated_at: null };
            openDialog('Notes and conclusions — ' + groupName(), '<div class="gm-empty">Loading…</div>', back);
            request('/admin/sessions/' + encodeURIComponent(occId)).then(function (d) {
                notesCtx.updated_at = d.session.updated_at;
                $('dbody').innerHTML =
                    (d.session.status === 'COMPLETED' ? '<div class="gm-warn gm-warn-info">Editing a completed meeting (' + esc(fmtDateTime(d.session.started_at)) + '). Edits are logged (field and time, never the text).</div>' : '') +
                    '<label class="gm-label" for="gmPriv">Private PI notes <span class="gm-private-tag">PI only — never shown to researchers</span></label>' +
                    '<textarea id="gmPriv" class="gm-textarea gm-private-block" data-gm="npriv" maxlength="10000" rows="6">' + esc(d.session.private_notes || '') + '</textarea>' +
                    '<label class="gm-label" for="gmShared">Shared scientific conclusions <span class="gm-vis">Visible to all group members in Meeting history</span></label>' +
                    '<textarea id="gmShared" class="gm-textarea" data-gm="nshared" maxlength="10000" rows="6">' + esc(d.session.shared_conclusions || '') + '</textarea>' +
                    '<div class="gm-msg" data-gm="dmsg" role="status"></div>' +
                    '<div class="gm-dialog-actions"><button type="button" class="gm-btn gm-btn-primary" data-gm-do="notes-save">Save</button></div>';
            }).catch(dialogError);
        }
        dialogHandlers['notes-save'] = function (btn) {
            btn.disabled = true;
            request('/admin/sessions/' + encodeURIComponent(notesCtx.id) + '/notes', {
                method: 'PATCH',
                body: {
                    private_notes: $('dbody').querySelector('[data-gm="npriv"]').value,
                    shared_conclusions: $('dbody').querySelector('[data-gm="nshared"]').value,
                    expected_updated_at: notesCtx.updated_at,
                },
            }).then(function (r) {
                notesCtx.updated_at = r.updated_at;
                btn.disabled = false;
                dialogMsg(r.changed && r.changed.length ? 'Saved.' : 'No changes.', true);
            }).catch(function (e) {
                btn.disabled = false;
                dialogMsg(e.body && e.body.code === 'stale_write'
                    ? 'These notes were changed in another window. Copy your text, close and reopen Notes, then save again.' : e.message, false);
            });
        };

        // ------------------------------------- presented / discussed records
        function docById(s) { return docs.filter(function (x) { return x.submission_id === s; })[0] || null; }

        // One click: presenter defaults to the owner (server-side). Opening a
        // document never records anything. Retries are idempotent server-side
        // and the control is disabled while a request is in flight.
        function mark(subId, type, origin) {
            if (!isAttached()) return;
            var existing = (marksBySid()[subId] || {})[type];
            if (existing) {
                if (origin === 'pres') return; // no dialogs over fullscreen presentation
                return openRecord(sid(), existing.id, { back: null });
            }
            var key = subId + ':' + type;
            if (pending[key]) return;
            pending[key] = true;
            renderDocs(); renderViewerMarks();
            postEvent(subId, type, null, null, key).then(null, function (e) {
                delete pending[key];
                renderDocs(); renderViewerMarks();
                if (e.status === 422 && e.body && e.body.code === 'presenter_required') {
                    if (origin === 'pres') return presPickPresenter(subId);
                    return openPresenterPicker(subId);
                }
                sessionFailure(e);
            });
        }
        function postEvent(subId, type, presenter, comment, pendingKey) {
            return request('/admin/sessions/' + encodeURIComponent(sid()) + '/events', {
                method: 'POST', body: { submission_id: subId, event_type: type, presenter_researcher_id: presenter || null, comment: comment || null },
            }).then(function (r) {
                if (pendingKey) delete pending[pendingKey]; // before re-rendering
                var d = docById(subId);
                var names = rosterNames();
                setFlash('✓ ' + (type === 'PRESENTED' ? 'Presented' : 'Discussed') + ' recorded' +
                    (d ? ': ' + d.title : '') + (r.event.presenter_researcher_id ? ' — presenter ' + (names[r.event.presenter_researcher_id] || '') : '') + '.', true);
                return softRefresh(); // live Last presented + indicators, same scroll
            });
        }

        function rosterOptions(roster, selected, ownerId) {
            var order = { PRESENT: 0, UNMARKED: 1, ABSENT: 2 };
            return (roster || []).slice().sort(function (a, b) { return (order[a.status] - order[b.status]) || String(a.display_name).localeCompare(b.display_name); })
                .map(function (p) {
                    return '<option value="' + esc(p.researcher_id) + '"' + (p.researcher_id === selected ? ' selected' : '') + '>' + esc(p.display_name) +
                        (p.researcher_id === ownerId ? ' (owner)' : '') + (p.status === 'ABSENT' ? ' — absent' : p.status === 'UNMARKED' ? ' — unmarked' : '') + '</option>';
                }).join('');
        }

        function openPresenterPicker(subId) {
            var d = docById(subId);
            openDialog('Who presented?', '<p class="gm-hint gm-hint-block">The owner of “' + esc(d ? d.title : 'this document') +
                '” is not a participant of this meeting. Choose the participant who presented it.</p>' +
                '<label class="gm-label" for="gmPresBy">Presenter</label><select id="gmPresBy" class="gm-input" data-gm="presby">' + rosterOptions(sess && sess.roster, null, null) + '</select>' +
                '<label class="gm-label" for="gmPresCm">Private comment (optional) <span class="gm-private-tag">PI only</span></label>' +
                '<textarea id="gmPresCm" class="gm-textarea" data-gm="prescm" maxlength="2000" rows="3"></textarea>' +
                '<div class="gm-msg" data-gm="dmsg" role="status"></div>' +
                '<div class="gm-dialog-actions"><button type="button" class="gm-btn gm-btn-primary" data-gm-do="pres-pick" data-sid="' + esc(subId) + '">Record presented</button></div>');
        }
        dialogHandlers['pres-pick'] = function (btn) {
            var subId = btn.getAttribute('data-sid');
            btn.disabled = true;
            postEvent(subId, 'PRESENTED', $('dbody').querySelector('[data-gm="presby"]').value, $('dbody').querySelector('[data-gm="prescm"]').value.trim())
                .then(function () { closeDialog(); }, function (e) { btn.disabled = false; dialogMsg(e.message, false); });
        };

        // Record editor (active meeting or history correction): presenter,
        // private comment, invalidate.
        var recCtx = null;
        function openRecord(occId, eventId, opts) {
            recCtx = { occId: occId, eventId: eventId, back: opts && opts.back };
            openDialog('Meeting record', '<div class="gm-empty">Loading…</div>', recCtx.back);
            request('/admin/sessions/' + encodeURIComponent(occId)).then(function (d) {
                var ev = (d.events || []).filter(function (e) { return e.id === eventId; })[0];
                if (!ev) throw Object.assign(new Error('Record not found.'), { status: 404 });
                var doc = docById(ev.submission_id);
                var title = (opts && opts.title) || (doc && doc.title) || 'Document';
                $('dtitle').textContent = (ev.event_type === 'PRESENTED' ? 'Presented' : 'Discussed') + ' — ' + title;
                $('dbody').innerHTML =
                    (d.session.status === 'COMPLETED' ? '<div class="gm-warn gm-warn-info">Correcting a completed meeting (' + esc(fmtDateTime(d.session.started_at)) + '). Changes are logged.</div>' : '') +
                    (ev.event_type === 'PRESENTED'
                        ? '<label class="gm-label" for="gmRecBy">Presenter</label><select id="gmRecBy" class="gm-input" data-gm="recby">' + rosterOptions(d.roster, ev.presenter_researcher_id, ev.owner_researcher_id) + '</select>'
                        : '') +
                    '<label class="gm-label" for="gmRecCm">Private comment <span class="gm-private-tag">PI only</span></label>' +
                    '<textarea id="gmRecCm" class="gm-textarea" data-gm="reccm" maxlength="2000" rows="3">' + esc(ev.comment || '') + '</textarea>' +
                    '<div class="gm-msg" data-gm="dmsg" role="status"></div>' +
                    '<div class="gm-dialog-actions">' +
                    '<input class="gm-input gm-left" data-gm="recvoid" maxlength="500" placeholder="Reason (optional)" aria-label="Reason for invalidating" style="max-width:220px;">' +
                    '<button type="button" class="gm-btn gm-btn-danger" data-gm-do="rec-void">Invalidate record</button>' +
                    '<button type="button" class="gm-btn gm-btn-primary" data-gm-do="rec-save">Save</button></div>';
            }).catch(dialogError);
        }
        function afterRecordChange(msg) {
            if (recCtx && recCtx.back) { recCtx.back(msg); return; }
            setFlash(msg, true);
            closeDialog();
        }
        dialogHandlers['rec-save'] = function (btn) {
            var body = { comment: $('dbody').querySelector('[data-gm="reccm"]').value };
            var by = $('dbody').querySelector('[data-gm="recby"]');
            if (by) body.presenter_researcher_id = by.value;
            btn.disabled = true;
            request('/admin/sessions/' + encodeURIComponent(recCtx.occId) + '/events/' + encodeURIComponent(recCtx.eventId), { method: 'PATCH', body: body })
                .then(function (r) { afterRecordChange(r.changed ? 'Record updated.' : 'No changes.'); })
                .catch(function (e) { btn.disabled = false; dialogMsg(e.message, false); });
        };
        dialogHandlers['rec-void'] = function (btn) {
            if (btn.getAttribute('data-armed') !== '1') { // explicit second click
                btn.setAttribute('data-armed', '1'); btn.textContent = 'Confirm invalidate';
                dialogMsg('The record is kept but no longer counts (Last presented updates). Click again to confirm.', false);
                return;
            }
            btn.disabled = true;
            var reason = $('dbody').querySelector('[data-gm="recvoid"]').value.trim();
            request('/admin/sessions/' + encodeURIComponent(recCtx.occId) + '/events/' + encodeURIComponent(recCtx.eventId), { method: 'DELETE', body: { reason: reason || null } })
                .then(function () { afterRecordChange('Record invalidated.'); })
                .catch(function (e) { btn.disabled = false; dialogMsg(e.message, false); });
        };

        // ------------------------------------------------- history
        var hist = null; // { meetings, cursor, detail }
        function openHistory() {
            hist = { meetings: [], cursor: null };
            openDialog('Meeting history — ' + groupName(), '<div class="gm-empty">Loading…</div>', null, true);
            loadHistoryPage();
        }
        function loadHistoryPage() {
            var h = hist;
            return request('/groups/' + encodeURIComponent(code) + '/history?limit=20' + (h.cursor ? '&cursor=' + encodeURIComponent(h.cursor) : ''))
                .then(function (r) {
                    if (h !== hist) return;
                    h.meetings = h.meetings.concat(r.meetings || []);
                    h.cursor = r.next_cursor;
                    showHistoryList();
                }).catch(dialogError);
        }
        function showHistoryList() {
            $('dtitle').textContent = 'Meeting history — ' + groupName();
            setDialogBack(null);
            $('dbody').innerHTML = '<div class="gm-hist">' + renderHistoryList(hist.meetings) + '</div>' +
                (hist.cursor ? '<div class="gm-dialog-actions"><button type="button" class="gm-btn gm-btn-sm" data-gm-do="hist-more">Load older meetings</button></div>' : '') +
                (isPi() ? '' : '<p class="gm-hint gm-hint-block">Only the document owner and the PI can open documents.</p>');
        }
        dialogHandlers['hist-more'] = function (btn) { btn.disabled = true; loadHistoryPage(); };
        dialogHandlers['hist-open'] = function (btn) { showHistoryDetail(btn.getAttribute('data-id')); };

        function showHistoryDetail(occId, msg) {
            if (!hist) hist = { meetings: [], cursor: null };
            $('dtitle').textContent = 'Meeting history — ' + groupName();
            setDialogBack(function () { showHistoryList(); });
            $('dbody').innerHTML = '<div class="gm-empty">Loading…</div>';
            request('/groups/' + encodeURIComponent(code) + '/history/' + encodeURIComponent(occId)).then(function (d) {
                hist.detail = d;
                var names = {};
                (d.attendance || []).forEach(function (a) { names[a.researcher_id] = a.display_name; });
                if (me) names[me.researcher_id] = names[me.researcher_id] || 'PI';
                var latest = hist.meetings.length && hist.meetings[0].id === occId;
                $('dbody').innerHTML =
                    (msg ? '<div class="gm-msg gm-msg-ok" role="status">' + esc(msg) + '</div>' : '') +
                    (isPi() ? '<div class="gm-hist-actions">' +
                        '<button type="button" class="gm-btn gm-btn-sm" data-gm-do="hc-att">Correct attendance</button>' +
                        '<button type="button" class="gm-btn gm-btn-sm" data-gm-do="hc-notes">Edit notes</button>' +
                        '<button type="button" class="gm-btn gm-btn-sm" data-gm-do="hc-add">Add record</button>' +
                        '<button type="button" class="gm-btn gm-btn-sm" data-gm-do="hc-times">Correct times</button>' +
                        (latest ? '<button type="button" class="gm-btn gm-btn-sm" data-gm-do="hc-reopen" title="Reopen the most recent meeting to continue it">Reopen…</button>' : '') +
                        '</div>' : '') +
                    '<div class="gm-hist-detail">' + renderHistoryDetail(d, isPi(), names) + '</div>' +
                    '<div class="gm-msg" data-gm="dmsg" role="status"></div>';
            }).catch(dialogError);
        }
        function backToDetail() { var id = hist && hist.detail && hist.detail.meeting.id; return function (msg) { openDialog('Meeting history — ' + groupName(), '', null, true); showHistoryDetail(id, typeof msg === 'string' ? msg : null); }; }
        dialogHandlers['hc-att'] = function () { openAttendance(hist.detail.meeting.id, backToDetail()); };
        dialogHandlers['hc-notes'] = function () { openNotes(hist.detail.meeting.id, backToDetail()); };
        dialogHandlers['hist-rec-edit'] = function (btn) {
            var evId = btn.getAttribute('data-ev');
            var all = (hist.detail.presentations || []).concat(hist.detail.discussions || []);
            var e = all.filter(function (x) { return x.event_id === evId; })[0];
            openRecord(hist.detail.meeting.id, evId, { back: backToDetail(), title: e && e.document ? e.document.title : null });
        };
        dialogHandlers['hist-view'] = function (btn) {
            openViewerDoc({ submission_id: btn.getAttribute('data-sid'), title: btn.getAttribute('data-title'), owner: btn.getAttribute('data-owner'), fromDialog: true });
        };
        dialogHandlers['hc-times'] = function () {
            var m = hist.detail.meeting;
            setDialogBack(backToDetail());
            $('dbody').innerHTML =
                '<div class="gm-warn gm-warn-info">Correct the start and end of this completed meeting. The start defines “Since last meeting”. A reason is required and both values are logged.</div>' +
                '<form class="gm-form" novalidate>' +
                '<label for="gmTs">Started</label><input id="gmTs" type="datetime-local" data-gm="ts" value="' + esc(toLocalInput(m.started_at)) + '">' +
                '<label for="gmTe">Ended</label><input id="gmTe" type="datetime-local" data-gm="te" value="' + esc(toLocalInput(m.ended_at)) + '">' +
                '<label for="gmTr">Reason</label><input id="gmTr" maxlength="500" data-gm="tr" placeholder="e.g. session left open after the meeting">' +
                '</form><div class="gm-msg" data-gm="dmsg" role="status"></div>' +
                '<div class="gm-dialog-actions"><button type="button" class="gm-btn gm-btn-primary" data-gm-do="hc-times-save">Save correction</button></div>';
        };
        dialogHandlers['hc-times-save'] = function (btn) {
            var g = function (n) { return $('dbody').querySelector('[data-gm="' + n + '"]').value; };
            var m = hist.detail.meeting;
            // an unchanged field keeps its exact stored value (no rounding to the minute)
            var keep = function (field, v) { return v === toLocalInput(m[field]) ? new Date(m[field]).toISOString() : localToIso(v); };
            var body = { started_at: keep('started_at', g('ts')), ended_at: keep('ended_at', g('te')), reason: g('tr').trim() };
            if (!body.started_at || !body.ended_at) return dialogMsg('Enter both times.', false);
            if (!body.reason) return dialogMsg('A reason is required.', false);
            btn.disabled = true;
            request('/admin/sessions/' + encodeURIComponent(hist.detail.meeting.id) + '/times', { method: 'PATCH', body: body })
                .then(function () { hist.meetings = []; hist.cursor = null; return loadHistoryIndexThen(hist.detail.meeting.id, 'Times corrected.'); })
                .catch(function (e) { btn.disabled = false; dialogMsg(e.message, false); });
        };
        function loadHistoryIndexThen(occId, msg) {
            return request('/groups/' + encodeURIComponent(code) + '/history?limit=20').then(function (r) {
                hist.meetings = r.meetings || []; hist.cursor = r.next_cursor;
                showHistoryDetail(occId, msg);
            });
        }
        dialogHandlers['hc-reopen'] = function () {
            setDialogBack(backToDetail());
            $('dbody').innerHTML =
                '<div class="gm-warn">Reopen the meeting of ' + esc(fmtDateTime(hist.detail.meeting.started_at)) + ' to continue it? ' +
                'Its start time is kept, so “Since last meeting” and the New counters do not change. It must be ended again afterwards; it cannot be abandoned. ' +
                'For corrections only, use the correction actions instead (no reopening needed).</div>' +
                '<div class="gm-msg" data-gm="dmsg" role="status"></div>' +
                '<div class="gm-dialog-actions"><button type="button" class="gm-btn gm-btn-primary" data-gm-do="hc-reopen-confirm">Reopen meeting</button></div>';
        };
        dialogHandlers['hc-reopen-confirm'] = function (btn) {
            btn.disabled = true;
            request('/admin/sessions/' + encodeURIComponent(hist.detail.meeting.id) + '/reopen', { method: 'POST', body: { confirm: true } })
                .then(function (r) { state.attached[code] = r.session.id; saveState(); setFlash('Meeting reopened.', true); closeDialog(); })
                .catch(function (e) { btn.disabled = false; dialogMsg(e.message, false); });
        };

        // Retrospective record on a completed meeting: researcher -> document.
        dialogHandlers['hc-add'] = function () {
            setDialogBack(backToDetail());
            var rs = (overview && overview.researchers) || [];
            $('dbody').innerHTML =
                '<div class="gm-warn gm-warn-info">Add a record to the meeting of ' + esc(fmtDateTime(hist.detail.meeting.started_at)) + '. Its date is the meeting date. The addition is logged.</div>' +
                '<form class="gm-form" novalidate>' +
                '<label for="gmAr">Researcher</label><select id="gmAr" data-gm="ar"><option value="">Choose…</option>' +
                    rs.map(function (r) { return '<option value="' + esc(r.researcher_id) + '">' + esc(r.name) + '</option>'; }).join('') + '</select>' +
                '<label for="gmAd">Document</label><select id="gmAd" data-gm="ad" disabled><option value="">Choose a researcher first</option></select>' +
                '<label for="gmAt">Record</label><select id="gmAt" data-gm="at"><option value="PRESENTED">Presented</option><option value="DISCUSSED">Discussed</option></select>' +
                '<label for="gmAp">Presenter</label><select id="gmAp" data-gm="ap"><option value="">Document owner</option>' + rosterOptions(hist.detail.attendance || [], null, null) + '</select>' +
                '</form><div class="gm-msg" data-gm="dmsg" role="status"></div>' +
                '<div class="gm-dialog-actions"><button type="button" class="gm-btn gm-btn-primary" data-gm-do="hc-add-save">Add record</button></div>';
            $('dbody').querySelector('[data-gm="ar"]').addEventListener('change', function (e) {
                var sel = $('dbody').querySelector('[data-gm="ad"]');
                sel.disabled = true; sel.innerHTML = '<option value="">Loading…</option>';
                if (!e.target.value) { sel.innerHTML = '<option value="">Choose a researcher first</option>'; return; }
                request(docsPath({ researcher_id: e.target.value }, 100, null, 'all')).then(function (r) {
                    var list = r.documents || [];
                    sel.innerHTML = list.length ? list.map(function (d) {
                        return '<option value="' + esc(d.submission_id) + '">' + esc((TYPE_LABEL[d.file_type] || d.file_type) + ' · ' + d.title) + '</option>';
                    }).join('') : '<option value="">No documents</option>';
                    sel.disabled = !list.length;
                }).catch(function (er) { dialogMsg(er.message, false); });
            });
        };
        dialogHandlers['hc-add-save'] = function (btn) {
            var g = function (n) { return $('dbody').querySelector('[data-gm="' + n + '"]').value; };
            if (!g('ad')) return dialogMsg('Choose a document.', false);
            btn.disabled = true;
            request('/admin/sessions/' + encodeURIComponent(hist.detail.meeting.id) + '/events', {
                method: 'POST', body: { submission_id: g('ad'), event_type: g('at'), presenter_researcher_id: (g('at') === 'PRESENTED' && g('ap')) || null },
            }).then(function (r) { backToDetail()(r.created ? 'Record added.' : 'This record already exists.'); })
              .catch(function (e) {
                  btn.disabled = false;
                  dialogMsg(e.body && e.body.code === 'presenter_required' ? 'The document owner was not a participant of this meeting: choose the presenter.' : e.message, false);
              });
        };

        function toLocalInput(v) {
            var d = toDate(v); if (!d) return '';
            var p = function (n) { return (n < 10 ? '0' : '') + n; };
            return d.getFullYear() + '-' + p(d.getMonth() + 1) + '-' + p(d.getDate()) + 'T' + p(d.getHours()) + ':' + p(d.getMinutes());
        }

        // ------------------------------------ viewer / presentation controls
        function renderViewerMarks() {
            var el = $('vmarks');
            if (!el) return;
            var s = viewerCtx && !viewerCtx.fromDialog ? viewerCtx.submission_id : null;
            var d = s ? docById(s) : null;
            el.innerHTML = d && isAttached() ? renderMarkButtons(d, marksBySid()[s], pending) : '';
            renderPresMarks();
        }
        // Discreet controls inside the existing presentation overlay
        // (bottom-left; the page indicator is centred and the pointer button
        // is bottom-right). The PDF.js rendering itself is not modified.
        function renderPresMarks(pickFor) {
            var ov = document.getElementById('gvPresOverlay');
            var bar = document.getElementById('gmPresMarks');
            var s = viewerCtx && !viewerCtx.fromDialog ? viewerCtx.submission_id : null;
            var d = s ? docById(s) : null;
            if (!ov || !d || !isAttached() || !ov.classList.contains('active')) { if (bar) bar.remove(); return; }
            if (!bar) {
                bar = document.createElement('div');
                bar.id = 'gmPresMarks';
                bar.className = 'gm-pres-marks';
                bar.addEventListener('click', function (e) {
                    var b = e.target.closest && e.target.closest('[data-gm-mark],[data-gm-prespick]');
                    if (!b) return;
                    e.stopPropagation();
                    if (b.hasAttribute('data-gm-mark')) mark(b.getAttribute('data-sid'), b.getAttribute('data-gm-mark'), 'pres');
                    else {
                        var sel = bar.querySelector('select');
                        pending[s + ':PRESENTED'] = true; renderPresMarks();
                        postEvent(b.getAttribute('data-gm-prespick'), 'PRESENTED', sel && sel.value, null, s + ':PRESENTED').then(function () { renderPresMarks(); },
                            function (er) { delete pending[s + ':PRESENTED']; renderPresMarks(); sessionFailure(er); });
                    }
                    if (b.blur) b.blur(); // keep arrow/space keys for slide navigation
                });
                bar.addEventListener('keydown', function (e) { e.stopPropagation(); }, true);
                ov.appendChild(bar);
            }
            bar.innerHTML = pickFor
                ? '<span class="gm-pres-q">Presenter:</span><select aria-label="Presenter">' + rosterOptions(sess && sess.roster, null, null) + '</select>' +
                  '<button type="button" class="gm-mark" data-gm-prespick="' + esc(pickFor) + '">Record</button>'
                : renderMarkButtons(d, marksBySid()[s], pending);
        }
        function presPickPresenter(subId) { renderPresMarks(subId); }

        // ---------------------------------------------------------- events
        rootEl.addEventListener('click', function (e) {
            var t = e.target.closest ? e.target : e.target.parentElement;
            var el;
            if ((el = t.closest('[data-gm-group]'))) return selectGroup(el.getAttribute('data-gm-group'));
            if ((el = t.closest('[data-gm-filter]'))) return setFilter(el.getAttribute('data-gm-filter'));
            if ((el = t.closest('[data-gm-view]'))) return openViewer(el.getAttribute('data-gm-view'));
            if ((el = t.closest('[data-gm-mark]'))) return mark(el.getAttribute('data-sid'), el.getAttribute('data-gm-mark'), 'list');
            if ((el = t.closest('[data-gm-do]'))) { var h = dialogHandlers[el.getAttribute('data-gm-do')]; return h ? h(el) : undefined; }
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
                    case 'dialog-back': return dialogBack ? dialogBack() : closeDialog();
                }
                if (sessionsOn()) switch (el.getAttribute('data-gm-action')) {
                    case 'history': return openHistory();
                    case 'refresh-session': return softRefresh();
                    case 'start-meeting': return isPi() && openStart();
                    case 'resume-meeting': return isPi() && resumeMeeting();
                    case 'end-meeting': return isPi() && openEnd(false);
                    case 'abandon-meeting': return isPi() && openEnd(true);
                    case 'attendance': return isPi() && active && openAttendance(active.id);
                    case 'notes': return isPi() && active && openNotes(active.id);
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
            if (!$('viewer').hidden && viewerCtx && viewerCtx.fromDialog) closeViewer(); // history viewer sits above the dialog
            else if (!$('dialog').hidden) closeDialog();
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
