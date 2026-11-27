'use strict';
// GLP Vision R2.3 — PI-only scientific document search over di_doc_text_* (derived index).
// Visibility = exactly the PI document list (/api/di/lab-files-enriched): same workspace,
// not DISCARDED, not report NOTE, same months window. Content is only ever read from
// documents that still have their file and are not REVISION_NEEDED/DISCARDED, and only
// from completed ('ok') or explicitly partial index rows. All SQL is parameterized.

const { normalizeQuery } = require('./normalize');
const { VISIBLE_SUBMISSION_SQL, flagOn } = require('./index');

const LIMITS = { maxQueryChars: 200, maxTerms: 8, minTermChars: 2, maxLimit: 50, maxOffset: 500, maxPagesListed: 60, statementTimeoutMs: 4000, excerptRadius: 110 };

const isSearchEnabled = () => flagOn('DOC_TEXT_SEARCH_ENABLED');

// ---------- scientific identifier equivalence (controlled) ----------
// For an UNQUOTED single-token identifier, joints are: an existing hyphen, a letter->digit boundary
// (STM|14028, A|549, HEK|293T, RNase|1) or an uppercase prefix of >=2 letters before a lowercase run
// of >=4 (TT|probe). Each joint may be written as nothing, a space or a hyphen. The original spelling
// keeps substring semantics; the alternative spellings only match as whole tokens (not inside other
// words). Quoted phrases never get variants. At most 3 joints (<= 26 alternatives).
const HYPHEN = /[-\u2010\u2011]/;
function identifierVariants(raw) {
    const t = String(raw || '').trim();
    if (t.length < 4 || t.length > 40 || !/^[\p{L}\p{N}]+(?:[-\u2010\u2011][\p{L}\p{N}]+)*$/u.test(t)) return [];
    const ch = [...t], segs = []; let cur = '';
    for (let i = 0; i < ch.length; i++) {
        const c = ch[i];
        if (HYPHEN.test(c)) { segs.push(cur); cur = ''; continue; }
        if (cur) {
            const p = ch[i - 1];
            let joint = /\p{L}/u.test(p) && /\p{N}/u.test(c);
            if (!joint && /\p{Lu}/u.test(p) && /\p{Ll}/u.test(c)) {
                let u = 0; for (let k = i - 1; k >= 0 && /\p{Lu}/u.test(ch[k]); k--) u++;
                let l = 0; for (let k = i; k < ch.length && /\p{Ll}/u.test(ch[k]); k++) l++;
                joint = u >= 2 && l >= 4 && (i - u === 0 || !/\p{L}/u.test(ch[i - u - 1]));
            }
            if (joint) { segs.push(cur); cur = ''; }
        }
        cur += c;
    }
    segs.push(cur);
    if (segs.length < 2 || segs.length > 4 || segs.some(x => !x)) return [];
    const orig = normalizeQuery(t), out = new Set();
    (function rec(i, acc) {
        if (i === segs.length) { const v = normalizeQuery(acc); if (v !== orig && v.length >= LIMITS.minTermChars) out.add(v); return; }
        for (const sep of ['', ' ', '-']) rec(i + 1, acc + sep + segs[i]);
    })(1, segs[0]);
    return [...out];
}
const reEsc = x => x.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
// Postgres ARE (lookbehind needs PostgreSQL >= 9.6) and the equivalent JS RegExp
const variantRegexSql = vs => vs.length ? `(?<![[:alnum:]])(?:${vs.map(reEsc).join('|')})(?![[:alnum:]])` : null;
const variantRegexJs = vs => vs.length ? new RegExp(`(?<![\\p{L}\\p{N}])(?:${vs.map(reEsc).join('|')})(?![\\p{L}\\p{N}])`, 'gu') : null;

// ---------- query parsing: "exact phrase", OR, -exclusion, plain terms ----------
function parseQuery(input) {
    const q = String(input || '').slice(0, LIMITS.maxQueryChars);
    const groups = [[]], exclude = [], display = [], variants = {};
    const re = /(-?)"([^"]*)"?|(\S+)/g;
    let m, count = 0;
    while ((m = re.exec(q)) !== null && count < LIMITS.maxTerms) {
        const neg = m[1] === '-' || (m[3] && m[3].startsWith('-') && m[3].length > 1);
        let raw = m[2] !== undefined ? m[2] : m[3];
        if (m[3] && /^or$/i.test(m[3])) { if (groups[groups.length - 1].length) groups.push([]); continue; }
        if (m[3] && neg) raw = raw.slice(1);
        const norm = normalizeQuery(raw);
        if (norm.length < LIMITS.minTermChars) continue;
        count++;
        if (m[2] === undefined && !variants[norm]) { const v = identifierVariants(raw); if (v.length) variants[norm] = v; }
        if (neg) exclude.push(norm);
        else { groups[groups.length - 1].push(norm); display.push(raw.trim()); }
    }
    const g = groups.filter(x => x.length);
    const terms = [...new Set(g.flat())];
    // websearch_to_tsquery input for ranking (normalized, same operators)
    const ws = g.map(grp => grp.map(t => (/\s/.test(t) ? `"${t}"` : t)).join(' ')).join(' or ')
             + exclude.map(t => ` -${/\s/.test(t) ? `"${t}"` : t}`).join('');
    return { groups: g, exclude, terms, display, variants, websearch: ws.trim() };
}

const likeEsc = s => s.replace(/[\\%_]/g, c => '\\' + c);

// ---------- excerpt: map normalized match positions back to raw text ----------
function buildExcerpt(page, matchers) {   // matchers: [{ lit, re }] (re = whole-token variants or null)
    const { raw_text: raw, norm_text: norm, raw_word_offsets: offs } = page;
    const words = norm.split(' ');
    const starts = []; { let p = 0; for (const w of words) { starts.push(p); p += w.length + 1; } }
    const rawWordEnd = (s) => {   // a raw token, continuing across "-\n" line-break hyphenation
        const r = /\S+(?:(?<=-)\n\s*\S+)*/y; r.lastIndex = s; const mm = r.exec(raw); return mm ? s + mm[0].length : s;
    };
    const wordAt = (pos) => { let lo = 0, hi = starts.length - 1; while (lo < hi) { const mid = (lo + hi + 1) >> 1; if (starts[mid] <= pos) lo = mid; else hi = mid - 1; } return lo; };
    const mapPos = (pos, isEnd) => {
        const w = wordAt(isEnd ? Math.max(0, pos - 1) : pos);
        const rs = offs[w], re = rawWordEnd(rs), intra = (isEnd ? pos - 1 : pos) - starts[w];
        if (re - rs === words[w].length) return rs + intra + (isEnd ? 1 : 0); // length-preserving word: exact chars
        return isEnd ? re : rs;                                                 // otherwise whole raw word
    };
    const hits = [];
    for (const mt of matchers) {
        const t = mt.lit; let i = norm.indexOf(t); while (i !== -1) { hits.push([i, i + t.length]); i = norm.indexOf(t, i + t.length); }
        if (mt.re) for (const x of norm.matchAll(mt.re)) hits.push([x.index, x.index + x[0].length]);
    }
    if (!hits.length || !offs || !offs.length) return null;
    hits.sort((a, b) => a[0] - b[0]);
    const rawHits = hits.map(([a, b]) => [mapPos(a, false), mapPos(b, true)]);
    const [h0s, h0e] = rawHits[0];
    let from = Math.max(0, h0s - LIMITS.excerptRadius), to = Math.min(raw.length, h0e + LIMITS.excerptRadius);
    while (from > 0 && !/\s/.test(raw[from - 1])) from--;
    while (to < raw.length && !/\s/.test(raw[to])) to++;
    // Display text: collapse whitespace; undo line-break hyphenation the same way the index does
    // ("diges-\ntion" -> "digestion", "TOUCAN-\nMRSA" -> "TOUCAN-MRSA"), tracking raw->display positions.
    let text = '', map = new Array(to - from + 1), prevSpace = false;
    for (let i = from; i < to; i++) {
        map[i - from] = text.length; const ch = raw[i];
        if (ch === '-' && i > from) {
            const mm = /^-([ \t]*\n\s*)(\S)/.exec(raw.slice(i, Math.min(to, i + 12)));
            if (mm) {
                const prev = raw[i - 1], next = mm[2], skip = mm[1].length;
                const join = /\p{Ll}/u.test(prev) && /\p{Ll}/u.test(next), keep = /[\p{Lu}\p{N}]/u.test(next);
                if (join || keep) {
                    if (keep) text += '-';
                    for (let k = 1; k <= skip; k++) map[i + k - from] = text.length;
                    i += skip; prevSpace = false; continue;
                }
            }
        }
        if (/\s/.test(ch)) { if (!prevSpace) text += ' '; prevSpace = true; } else { text += ch; prevSpace = false; }
    }
    map[to - from] = text.length;
    const highlights = [];
    for (const [a, b] of rawHits) {
        if (a < from || b > to) continue;
        const s = map[a - from], e = map[b - from];
        if (e > s && (!highlights.length || s >= highlights[highlights.length - 1][1])) highlights.push([s, e]);
    }
    return { text, highlights, truncatedStart: from > 0, truncatedEnd: to < raw.length };
}

// ---------- capability checks (cached) ----------
let cap = null, capAt = 0;
async function capabilities(pool) {
    if (cap && (cap.tables || Date.now() - capAt < 60000)) return cap;
    const r = await pool.query(`SELECT to_regclass('public.di_doc_text_index') IS NOT NULL AS idx,
        to_regclass('public.di_doc_text_pages') IS NOT NULL AS pages,
        EXISTS (SELECT 1 FROM pg_extension WHERE extname='pg_trgm') AS trgm,
        EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name='di_submissions' AND column_name='record_origin') AS legacy,
        to_regclass('public.di_file_shares') IS NOT NULL AS shares`);
    const x = r.rows[0]; cap = { tables: !!(x.idx && x.pages), trgm: !!x.trgm, legacy: !!x.legacy, shares: !!x.shares }; capAt = Date.now();
    return cap;
}

// ---------- filters shared by search + coverage ----------
// Base = exactly the R1 PI document list (/api/di/lab-files-enriched): the union of
//   owned:  workspace, not DISCARDED, not report NOTE, created within the months window
//   shared: active share in the workspace to another researcher, shared within the window
// R1 lists a shared document under the recipient with created_at = shared_at, so the
// researcher, date and year filters use the recipient / shared_at on the shared branch.
function baseFilters(f, P, c) {
    const ws = P(f.workspaceId), months = P(f.months);
    const days = f.days ? P(f.days) : null, year = (f.year && f.year !== 'legacy') ? P(f.year) : null;
    const researcher = f.researcher ? P(f.researcher) : null;
    const owned = [`COALESCE(s.report_thread_role,'') <> 'NOTE'`, `s.created_at >= NOW() - make_interval(months => ${months})`];
    if (researcher) owned.push(`s.researcher_id = ${researcher}`);
    if (days) owned.push(`s.created_at >= NOW() - make_interval(days => ${days})`);
    if (year) owned.push(`EXTRACT(YEAR FROM s.created_at) = ${year}`);
    const branches = ['(' + owned.join(' AND ') + ')'];
    if (c.shares && f.year !== 'legacy') {   // shared entries never carry legacy origin in R1
        const sh = [`fs.submission_id = s.submission_id`, `fs.is_active = TRUE`, `fs.recipient_researcher_id <> fs.owner_researcher_id`,
                    `fs.workspace_id = ${ws}`, `fs.shared_at >= NOW() - make_interval(months => ${months})`];
        if (researcher) sh.push(`fs.recipient_researcher_id = ${researcher}`);
        if (days) sh.push(`fs.shared_at >= NOW() - make_interval(days => ${days})`);
        if (year) sh.push(`EXTRACT(YEAR FROM fs.shared_at) = ${year}`);
        branches.push(`EXISTS (SELECT 1 FROM di_file_shares fs WHERE ${sh.join(' AND ')})`);
    }
    const w = [`s.workspace_id = ${ws}`, `s.status <> 'DISCARDED'`, '(' + branches.join(' OR ') + ')'];
    if (f.type) w.push(`s.file_type = ${P(f.type)}`);
    if (f.status) w.push(`s.status = ${P(f.status)}`);
    if (f.dragon) w.push(`s.pi_dragon_seal = TRUE`);
    if (f.year === 'legacy') w.push(c.legacy ? `s.record_origin = 'legacy_pre2026'` : 'FALSE');
    return w.join(' AND ');
}
function sharedToSql(f, P, c) {   // "shown as shared" for the current researcher filter (display only)
    if (!c.shares || !f.researcher) return 'FALSE';
    return `(s.researcher_id <> ${P(f.researcher)} AND EXISTS (SELECT 1 FROM di_file_shares fs2 WHERE fs2.submission_id = s.submission_id
              AND fs2.is_active = TRUE AND fs2.recipient_researcher_id = ${P(f.researcher)}))`;
}

function readFilters(q, workspaceId) {
    const int = (v, lo, hi, d) => { const n = parseInt(v, 10); return Number.isFinite(n) ? Math.min(Math.max(n, lo), hi) : d; };
    const TYPES = ['DATA', 'PRESENTATION', 'SOP', 'REPORT', 'INVENTORY'], ST = ['PENDING', 'APPROVED', 'REVISION_NEEDED', 'SUBMITTED'];
    const SORTS = ['relevance', 'newest', 'oldest', 'name'], SCOPES = ['all', 'filename', 'content'];
    return {
        workspaceId,
        months: int(q.months, 6, 60, 12),
        researcher: typeof q.researcher === 'string' && q.researcher.length <= 64 ? q.researcher : '',
        type: TYPES.includes(q.type) ? q.type : '',
        status: ST.includes(q.status) ? q.status : '',
        days: q.days ? int(q.days, 1, 3650, 0) : 0,
        dragon: q.dragon === '1',
        year: q.year === 'legacy' ? 'legacy' : (/^\d{4}$/.test(q.year || '') ? parseInt(q.year, 10) : ''),
        scope: SCOPES.includes(q.scope) ? q.scope : 'all',
        sort: SORTS.includes(q.sort) ? q.sort : 'relevance',
        limit: int(q.limit, 1, LIMITS.maxLimit, 30),
        offset: int(q.offset, 0, LIMITS.maxOffset, 0),
    };
}

async function search(pool, reqQuery, workspaceId) {
    const c = await capabilities(pool);
    if (!c.tables) return { available: false, reason: 'index_tables_missing' };
    const f = readFilters(reqQuery, workspaceId);
    const pq = parseQuery(reqQuery.q);
    if (!pq.terms.length) return { available: true, query: { terms: [], normalized: [], exclude: pq.exclude, groups: [] }, results: [], total: 0, coverage: null };

    const params = []; const P = v => { params.push(v); return '$' + params.length; };
    const where = baseFilters(f, P, c);
    const termP = pq.terms.map(t => { const rx = variantRegexSql(pq.variants[t] || []); return { like: P('%' + likeEsc(t) + '%'), lit: P(t), re: rx ? P(rx) : null }; });
    const exclP = pq.exclude.map(t => { const rx = variantRegexSql(pq.variants[t] || []); return { like: P('%' + likeEsc(t) + '%'), re: rx ? P(rx) : null }; });
    const termCond = (col, t) => `(${col} LIKE ${t.like} ESCAPE '\\'${t.re ? ` OR ${col} ~ ${t.re}` : ''})`;
    const wsP = P(pq.websearch || pq.terms.join(' '));
    const groupIdx = pq.groups.map(g => g.map(t => pq.terms.indexOf(t)));
    const wantContent = f.scope !== 'filename', wantName = f.scope !== 'content';

    const pageCols = termP.map((t, i) => `${termCond('p.norm_text', t)} AS t${i}`).join(', ');
    // original spelling: substring count; alternative spellings: whole-token regex matches (disjoint)
    const occExpr = termP.map(t => `(length(p.norm_text) - length(replace(p.norm_text, ${t.lit}, ''))) / length(${t.lit})`
        + (t.re ? ` + (SELECT count(*) FROM regexp_matches(p.norm_text, ${t.re}, 'g'))` : '')).join(' + ');
    const anyTerm = termP.map(t => termCond('p.norm_text', t)).join(' OR ');
    const docGroups = groupIdx.map(g => '(' + g.map(i => `d.t${i}`).join(' AND ') + ')').join(' OR ');
    const nameGroups = groupIdx.map(g => '(' + g.map(i => `lower(s.original_filename) LIKE ${termP[i].like} ESCAPE '\\'`).join(' AND ') + ')').join(' OR ');
    const nameExcl = exclP.map(e => ` AND lower(s.original_filename) NOT LIKE ${e.like} ESCAPE '\\'`).join('');
    const contentExcl = exclP.map(e => ` AND NOT EXISTS (SELECT 1 FROM di_doc_text_pages x WHERE x.submission_id = s.submission_id AND ${termCond('x.norm_text', e)})`).join('');

    const order = { relevance: 'score DESC, s.created_at DESC', newest: 's.created_at DESC', oldest: 's.created_at ASC', name: 'lower(s.original_filename) ASC' }[f.sort];
    const sql = `
      WITH tsq AS (SELECT websearch_to_tsquery('simple', ${wsP}) AS q),
      page_hits AS (
        SELECT p.submission_id, p.page_no, ${pageCols},
               (${occExpr})::int AS occ, ts_rank_cd(p.tsv, tsq.q) AS rank
          FROM di_doc_text_pages p
          JOIN di_doc_text_index i ON i.submission_id = p.submission_id AND i.status IN ('ok','partial')
          JOIN di_submissions s ON s.submission_id = p.submission_id
          CROSS JOIN tsq
         WHERE ${wantContent ? 'TRUE' : 'FALSE'} AND ${where} AND ${VISIBLE_SUBMISSION_SQL} AND (${anyTerm})
      ),
      doc_hits AS (
        SELECT submission_id, ${termP.map((_, i) => `bool_or(t${i}) AS t${i}`).join(', ')},
               SUM(occ)::int AS occ, MAX(rank) AS rank,
               array_agg(page_no ORDER BY page_no) AS pages, array_agg(occ ORDER BY page_no) AS page_occ
          FROM page_hits GROUP BY submission_id
      )
      SELECT s.submission_id, s.original_filename, s.file_type, s.status, s.created_at, s.researcher_id,
             s.pi_dragon_seal, a.name AS researcher_name, ${sharedToSql(f, P, c)} AS shared,
             i.status AS index_status, i.page_count, i.pages_indexed,
             (${wantName ? `(${nameGroups})${nameExcl}` : 'FALSE'}) AS name_match,
             (d.submission_id IS NOT NULL AND (${docGroups})${contentExcl}) AS content_match,
             COALESCE(d.occ, 0) AS occ, d.pages, d.page_occ,
             (COALESCE(d.rank, 0) + 0.05 * ln(1 + COALESCE(d.occ, 0))
               + CASE WHEN ${wantName ? `(${nameGroups})` : 'FALSE'} THEN 0.3 ELSE 0 END) AS score,
             COUNT(*) OVER () AS total
        FROM di_submissions s
        LEFT JOIN di_allowlist a ON a.researcher_id = s.researcher_id
        LEFT JOIN doc_hits d ON d.submission_id = s.submission_id
        LEFT JOIN di_doc_text_index i ON i.submission_id = s.submission_id
       WHERE ${where}
         AND ((${wantName ? `(${nameGroups})${nameExcl}` : 'FALSE'})
              OR (d.submission_id IS NOT NULL AND (${docGroups})${contentExcl}))
       ORDER BY ${order}
       LIMIT ${P(f.limit)} OFFSET ${P(f.offset)}`;

    const covParams = []; const CP = v => { covParams.push(v); return '$' + covParams.length; };
    const covSql = `SELECT CASE WHEN NOT (${VISIBLE_SUBMISSION_SQL}) THEN 'unavailable'
                                WHEN i.status IS NULL THEN 'unindexed' ELSE i.status END AS st, COUNT(*)::int AS n
                      FROM di_submissions s LEFT JOIN di_doc_text_index i ON i.submission_id = s.submission_id
                     WHERE ${baseFilters(f, CP, c)} GROUP BY 1`;

    const client = await pool.connect();
    const t0 = Date.now();
    let rows, cov, excerptRows = [];
    try {
        await client.query('BEGIN READ ONLY');
        await client.query(`SET LOCAL statement_timeout = ${LIMITS.statementTimeoutMs}`);
        rows = (await client.query(sql, params)).rows;
        cov = (await client.query(covSql, covParams)).rows;
        // best page per content hit (most occurrences, then lowest page number) for the excerpt
        const want = rows.filter(r => r.content_match && r.pages).map(r => {
            let best = 0; r.page_occ.forEach((o, k) => { if (o > r.page_occ[best]) best = k; }); return [r.submission_id, r.pages[best]];
        });
        if (want.length) {
            excerptRows = (await client.query(
                `SELECT p.submission_id, p.page_no, p.raw_text, p.norm_text, p.raw_word_offsets
                   FROM di_doc_text_pages p JOIN unnest($1::uuid[], $2::int[]) AS w(id, pg)
                     ON p.submission_id = w.id AND p.page_no = w.pg`, [want.map(x => x[0]), want.map(x => x[1])])).rows;
        }
        await client.query('COMMIT');
    } catch (e) { try { await client.query('ROLLBACK'); } catch (_) {} throw e; } finally { client.release(); }

    const ex = new Map(excerptRows.map(r => [r.submission_id, r]));
    const matchers = pq.terms.map(t => ({ lit: t, re: variantRegexJs(pq.variants[t] || []) }));
    const coverage = { ok: 0, partial: 0, unindexed: 0, unavailable: 0, failed: 0, pending: 0, other: 0 };
    for (const r of cov) {
        if (r.st in coverage) coverage[r.st] += r.n;
        else if (['timeout', 'interrupted', 'empty', 'no_text'].includes(r.st)) coverage.failed += r.n;
        else if (r.st === 'processing') coverage.pending += r.n; else coverage.other += r.n;
    }
    const results = rows.map(r => {
        const page = ex.get(r.submission_id);
        const pages = r.content_match && r.pages ? r.pages.map((p, k) => ({ page: p, occ: r.page_occ[k] })) : [];
        return {
            submission_id: r.submission_id, original_filename: r.original_filename, file_type: r.file_type, status: r.status,
            created_at: r.created_at, researcher_id: r.researcher_id, researcher_name: r.researcher_name, pi_dragon_seal: r.pi_dragon_seal, shared: !!r.shared,
            name_match: r.name_match, content_match: !!r.content_match,
            occurrences: r.content_match ? r.occ : 0,
            pages: pages.slice(0, LIMITS.maxPagesListed), pages_total: pages.length,
            excerpt_page: page ? page.page_no : null,
            excerpt: page ? buildExcerpt(page, matchers) : null,
            index: { status: r.index_status || 'unindexed', page_count: r.page_count, pages_indexed: r.pages_indexed },
            score: Number(r.score),
        };
    });
    return { available: true, trgm: c.trgm, query: { terms: pq.display, normalized: pq.terms, exclude: pq.exclude, groups: pq.groups,
             variants: pq.variants, highlight: [...new Set([...pq.display, ...Object.values(pq.variants).flat()])] },
             scope: f.scope, sort: f.sort, total: rows.length ? Number(rows[0].total) : 0, limit: f.limit, offset: f.offset,
             coverage, ms: Date.now() - t0, results };
}

async function status(pool, workspaceId) {
    const c = await capabilities(pool);
    return { enabled: true, available: c.tables, trgm: c.trgm };
}

module.exports = { search, status, parseQuery, buildExcerpt, identifierVariants, isSearchEnabled, LIMITS, _resetCapabilities: () => { cap = null; } };
