// S1.2b — authentication session hardening: static guarantees on server.js.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const server = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');

test('every login point regenerates the session id (no direct session.user assignment)', () => {
    assert.doesNotMatch(server, /req\.session\.user\s*=\s*\{/, 'no direct authenticated-session assignment');
    const uses = server.match(/await establishSession\(req, \{/g) || [];
    assert.strictEqual(uses.length, 6, 'register, login, complete-password-reset, investor set-code, login, renew');
    assert.match(server, /req\.session\.regenerate\(\(err\) => \{\s*if \(err\) return reject\(err\);\s*req\.session\.user = user;\s*req\.session\.authFp = authFingerprint\(credentialHash\);/);
});

test('revalidation runs at the common boundary: after static files and /health, before every API route', () => {
    const use = server.indexOf('app.use(revalidateSession);');
    const health = server.indexOf("app.get('/health'");
    const stat = server.indexOf("app.use(express.static(path.join(__dirname, 'public')));");
    const firstApi = server.search(/app\.(get|post|put|patch|delete|use|all)\(\s*\[?\s*['"]\/api\//);
    assert.ok(stat > 0 && health > stat && use > health && use < firstApi, { stat, health, use, firstApi });
    assert.strictEqual((server.match(/app\.use\(revalidateSession\)/g) || []).length, 1);
});

test('revalidation: no cache, revokes on removed/inactive/retired/role/credential/forced reset; fails closed', () => {
    const i = server.indexOf('async function revalidateSession');
    const body = server.slice(i, server.indexOf('app.use(revalidateSession);'));
    for (const r of ['account_removed', 'account_inactive', 'ai_bot_retired', 'role_changed', 'credentials_removed', 'credentials_changed', 'password_reset_required', 'access_expired', 'membership_removed']) {
        assert.match(body, new RegExp(`'${r}'`), r);
    }
    assert.match(body, /catch \(err\) \{[\s\S]*?status\(503\)/, 'database errors answer 503');
    assert.doesNotMatch(body, /cache|Map\(|setTimeout/i, 'no revocation-delaying cache');
});

test('logout: same-origin POST, destroys the session, clears the cookie with the session cookie attributes', () => {
    assert.match(server, /app\.post\('\/api\/di\/logout', requireSameOrigin, \(req, res\) => \{/);
    assert.match(server, /req\.session\.destroy\(/);
    assert.match(server, /const SESSION_COOKIE_OPTIONS = \{ path: '\/', httpOnly: true, secure: true, sameSite: 'none' \};/);
    // must match the session cookie configuration, and no cross-domain cookie
    assert.match(server, /cookie: \{\s*secure: true,\s*httpOnly: true,\s*maxAge: 24 \* 60 \* 60 \* 1000,[^}]*sameSite: 'none'\s*\}/);
    assert.doesNotMatch(server, /domain:\s*['"]/i, 'no cookie Domain attribute anywhere');
});
