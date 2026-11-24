// Site root redirect (custom domain finalization): static guarantees on server.js.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const server = fs.readFileSync(path.join(__dirname, '..', 'server.js'), 'utf8');

test('GET / redirects (302) to the relative portal entry page and keeps the query string', () => {
    const m = server.match(/app\.get\('\/', \(req, res\) => \{([\s\S]*?)\n\}\);/);
    assert.ok(m, 'exact root route present');
    assert.match(m[1], /res\.redirect\(302, '\/di\/access\.html' \+/);
    assert.match(m[1], /req\.originalUrl\.slice\(q\)/, 'query string forwarded');
    assert.doesNotMatch(m[1], /https?:|req\.(get|hostname|protocol)|host/i, 'no hostname: each domain stays on itself');
    assert.strictEqual((server.match(/app\.get\('\/',/g) || []).length, 1, 'single root route');
});

test('root route sits between the /di and root static mounts, before every API route', () => {
    const di = server.indexOf("app.use('/di', express.static(");
    const root = server.indexOf("app.get('/', (req, res) =>");
    const stat = server.indexOf('app.use(express.static(path.join(__dirname, \'public\')));');
    const firstApi = server.search(/app\.(get|post|put|patch|delete|use)\(['"]\/api\//);
    assert.ok(di > 0 && di < root && root < stat && root < firstApi, { di, root, stat, firstApi });
});

test('no Railway-to-custom-domain (or reverse) redirect was introduced', () => {
    assert.doesNotMatch(server, /hernandezlab/i);
    assert.doesNotMatch(server, /res\.redirect\([^)]*railway\.app/);
});
