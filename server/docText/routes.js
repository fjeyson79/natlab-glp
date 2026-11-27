'use strict';
// GLP Vision R2.3 routes. Mounted from server.js with the existing requirePIRead middleware.
// Flag OFF => no DB access; the GLP Vision UI then keeps its filename-only search.
const docSearch = require('./search');

function mountDocSearchRoutes(app, { pool, requirePIRead }) {
    app.get('/api/di/doc-search/status', requirePIRead, async (req, res) => {
        if (!docSearch.isSearchEnabled()) return res.json({ enabled: false });
        try { res.json(await docSearch.status(pool, req.workspace.id)); }
        catch (e) { console.error('[doc-search] status error:', e.message); res.json({ enabled: true, available: false }); }
    });
    app.get('/api/di/doc-search', requirePIRead, async (req, res) => {
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
