// Zoe Portal Assistant — viewer listener (v1, polling only).
//
// What it does:
//   1. On load, registers this browser tab with the backend as a Zoe-controllable
//      session (POST /api/assistant/sessions/register).
//   2. Every 4 seconds, polls GET /api/assistant/viewer/next for a pending
//      command. The page-level fetch wrapper in pi-dashboard.html already
//      attaches the x-workspace-slug header and session cookie.
//   3. When a command arrives, opens the rd_documents file via the existing
//      portal download endpoint and POSTs /api/assistant/viewer/consume.
//
// Constraints honoured:
//   - No websockets, no Service Worker, no new auth path.
//   - Additive: if the assistant endpoints return anything non-2xx we quietly
//     back off instead of reporting errors to the user.
//   - Paused while the tab is hidden, to save request traffic.
//
// Reads workspace slug from localStorage.ws (same source the pi-dashboard
// fetch wrapper uses). Session token is persisted in sessionStorage so a
// reload keeps the same control session; a new tab gets a new one.

(function () {
    'use strict';

    var POLL_MS       = 4000;
    var REREGISTER_MS = 15 * 60 * 1000; // refresh registration every 15 min (TTL is 30)
    var TOKEN_KEY     = 'zoe_control_token';
    var SESSION_KEY   = 'zoe_control_session_id';

    function getWs() {
        try { return localStorage.getItem('ws') || 'natlab'; } catch (_) { return 'natlab'; }
    }
    function getOrCreateToken() {
        var t = null;
        try { t = sessionStorage.getItem(TOKEN_KEY); } catch (_) {}
        if (t) return t;
        t = (window.crypto && crypto.randomUUID)
            ? crypto.randomUUID()
            : ('zoe-' + Date.now() + '-' + Math.random().toString(36).slice(2, 10));
        try { sessionStorage.setItem(TOKEN_KEY, t); } catch (_) {}
        return t;
    }
    function storeSessionId(id) {
        try { sessionStorage.setItem(SESSION_KEY, id); } catch (_) {}
    }
    function readSessionId() {
        try { return sessionStorage.getItem(SESSION_KEY); } catch (_) { return null; }
    }

    var controlSessionId = readSessionId();
    var pollTimer = null;
    var reregisterTimer = null;
    var inFlight = false;
    var lastHandledCommandId = null;   // in-memory dedupe — survives polls, not reloads

    async function register() {
        try {
            var r = await fetch('/api/assistant/sessions/register', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ws: getWs(),
                    session_token: getOrCreateToken(),
                    mode: 'viewer'
                })
            });
            if (!r.ok) return false;
            var data = await r.json();
            if (data && data.control_session_id) {
                controlSessionId = data.control_session_id;
                storeSessionId(controlSessionId);
                return true;
            }
        } catch (_) {}
        return false;
    }

    function openCommandFile(cmd) {
        // Reuse the existing rd_documents download endpoint. Open in a named
        // window so subsequent commands reuse the same tab instead of piling
        // up new ones (and so a single popup-allowance covers the session).
        // Returns the window handle on success, or null if the browser blocked
        // the open (popup blocker, sandboxed frame, exception, etc.).
        try {
            var w = window.open('/api/rd/documents/' + encodeURIComponent(cmd.file_id) + '/download', 'zoe-viewer');
            if (!w) {
                console.warn('[zoe-viewer-listener] window.open returned null; leaving command ' + cmd.id + ' PENDING for retry');
                return null;
            }
            return w;
        } catch (err) {
            console.warn('[zoe-viewer-listener] window.open threw; leaving command ' + cmd.id + ' PENDING for retry:', err && err.message);
            return null;
        }
    }

    async function consume(commandId) {
        try {
            await fetch('/api/assistant/viewer/consume', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({
                    ws: getWs(),
                    control_session_id: controlSessionId,
                    command_id: commandId
                })
            });
        } catch (_) {}
    }

    async function pollOnce() {
        if (inFlight) return;                                    // never overlap a poll
        if (document.visibilityState === 'hidden') return;       // pause while tab hidden
        if (!controlSessionId) { await register(); return; }
        inFlight = true;
        try {
            var url = '/api/assistant/viewer/next'
                    + '?ws=' + encodeURIComponent(getWs())
                    + '&control_session_id=' + encodeURIComponent(controlSessionId);
            var r = await fetch(url);
            if (r.status === 404) {                              // session expired — re-register next tick
                controlSessionId = null;
                return;
            }
            if (!r.ok) return;
            var data = await r.json();
            var cmd = data && data.command;
            if (cmd && cmd.file_id) {
                // Dedupe: if we already handled this id in this tab (slow consume,
                // network retry, duplicate server response), skip reopening it.
                if (cmd.id === lastHandledCommandId) return;
                var openedWindow = openCommandFile(cmd);
                if (openedWindow) {
                    lastHandledCommandId = cmd.id;
                    await consume(cmd.id);
                }
            }
        } catch (_) {
            // swallow — listener is a best-effort side channel
        } finally {
            inFlight = false;
        }
    }

    function start() {
        register().finally(function () {
            pollTimer = setInterval(pollOnce, POLL_MS);
            reregisterTimer = setInterval(register, REREGISTER_MS);
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', start);
    } else {
        start();
    }
})();
