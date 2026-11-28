'use strict';
// GLP Vision R2.3 routes. Mounted from server.js with the existing requirePIRead middleware.
// Flag OFF => no DB access; the GLP Vision UI then keeps its filename-only search.
const docSearch = require('./search');

// R3.2: restricted search for researchers and supervisors. Identity comes ONLY from the authenticated
// session (never req.user, which PI impersonation can rewrite, and never from query parameters).
// Each role has its own flag; both also require the master DOC_TEXT_SEARCH_ENABLED flag.
const { flagOn } = require('./index');
const ROLE_FLAGS = { researcher: 'DOC_TEXT_SEARCH_RESEARCHER_ENABLED', supervisor: 'DOC_TEXT_SEARCH_SUPERVISOR_ENABLED' };
function restrictedAccess(req) {
    const u = req.session && req.session.user;
    if (!u || !u.researcher_id) return { code: 401, error: 'Not authenticated' };
    const role = String(u.role || 'researcher').toLowerCase();   // no role = researcher (as /api/di/vision/me)
    if (!ROLE_FLAGS[role]) return { code: 403, error: 'Restricted search is available to researchers and supervisors' };
    if (!docSearch.isSearchEnabled() || !flagOn(ROLE_FLAGS[role])) return { code: 404, error: 'Search disabled' };
    return { access: { viewer: { researcher_id: u.researcher_id, role } } };
}

function mountDocSearchRoutes(app, { pool, requirePIRead, requireAuth }) {
    if (requireAuth) {
        app.get('/api/di/vision/doc-search/status', requireAuth, async (req, res) => {
            res.setHeader('Cache-Control', 'private, no-store');   // R4.5: confidential search/list response, never stored by browsers or proxies
            const mobile = flagOn('GLP_MOBILE_VISION_ENABLED');   // R4.2: display-only flag for the mobile layout (default OFF)
            const a = restrictedAccess(req);
            if (!a.access) return a.code === 404 ? res.json({ enabled: false, mobile }) : res.status(a.code).json({ error: a.error });
            try { res.json({ ...(await docSearch.status(pool, req.workspace.id, a.access)), mobile }); }
            catch (e) { console.error('[vision-doc-search] status error:', e.message); res.json({ enabled: true, available: false, mobile }); }
        });
        app.get('/api/di/vision/doc-search', requireAuth, async (req, res) => {
            res.setHeader('Cache-Control', 'private, no-store');   // R4.5: confidential search/list response, never stored by browsers or proxies
            const a = restrictedAccess(req);
            if (!a.access) return res.status(a.code).json({ error: a.error });
            try { res.json(await docSearch.search(pool, req.query, req.workspace.id, a.access)); }
            catch (e) {
                const timedOut = e && e.code === '57014';
                console.error('[vision-doc-search] error:', e.message);
                res.status(timedOut ? 503 : 500).json({ error: timedOut ? 'Search timed out' : 'Search failed' });
            }
        });
    }

    app.get('/api/di/doc-search/status', requirePIRead, async (req, res) => {
        res.setHeader('Cache-Control', 'private, no-store');   // R4.5: confidential search/list response, never stored by browsers or proxies
        if (!docSearch.isSearchEnabled()) return res.json({ enabled: false });
        try { res.json(await docSearch.status(pool, req.workspace.id)); }
        catch (e) { console.error('[doc-search] status error:', e.message); res.json({ enabled: true, available: false }); }
    });
    app.get('/api/di/doc-search', requirePIRead, async (req, res) => {
        res.setHeader('Cache-Control', 'private, no-store');   // R4.5: confidential search/list response, never stored by browsers or proxies
        if (!docSearch.isSearchEnabled()) return res.status(404).json({ error: 'Search disabled' });
        try { res.json(await docSearch.search(pool, req.query, req.workspace.id)); }
        catch (e) {
            const timedOut = e && e.code === '57014';
            console.error('[doc-search] error:', e.message);
            res.status(timedOut ? 503 : 500).json({ error: timedOut ? 'Search timed out' : 'Search failed' });
        }
    });
}

module.exports = { mountDocSearchRoutes };
