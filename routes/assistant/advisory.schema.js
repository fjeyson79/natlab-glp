// routes/assistant/advisory.schema.js
//
// Structural validator for Researcher Advisory v2 responses.
//
// Phase 1 (this commit) only emits {topic_map, portal_evidence} layers — but
// the validator already enforces the FULL provenance contract so later phases
// (MEMORY, PUBMED, INTERPRETATION) can be added without weakening the
// guarantees. The validator is the load-bearing piece: it's the bug-detector
// that makes provenance defensible.
//
// Strict invariants enforced:
//   I1. advisory_status ∈ {ok, topic_map_only, insufficient_evidence, llm_error}
//   I2. Every topic in topic_map.high has ≥1 evidence_submission_ids that
//       appears in portal_evidence.items.
//   I3. Every memory entry's matched_topic is in topic_map.high.
//   I4. Every pubmed result's matched_topic is in topic_map.high.
//   I5. Every Claim's `source` ∈ {PORTAL, MEMORY, PUBMED, INTERPRETATION}.
//   I6. Every Claim's `topic` is in topic_map.high.
//   I7. PORTAL claim:        based_on.portal ≥ 1
//       MEMORY claim:        based_on.memory ≥ 1  AND based_on.portal ≥ 1
//       PUBMED claim:        based_on.pubmed ≥ 1  AND based_on.portal ≥ 1
//       INTERPRETATION:      based_on.portal ≥ 1
//   I8. Every based_on id resolves: portal sids exist in portal_evidence,
//       memory_ids in memory.entries, pmids in pubmed.results.

'use strict';

const SOURCES = new Set(['PORTAL', 'MEMORY', 'PUBMED', 'INTERPRETATION']);
const STATUSES = new Set(['ok', 'topic_map_only', 'insufficient_evidence', 'llm_error']);
const INTERPRETATION_LISTS = [
    'strengths', 'gaps', 'improvements', 'publishability_levers',
    'next_experiments', 'missing_controls', 'analysis_suggestions'
];

function validateAdvisory(output) {
    const errors = [];
    const push = (code, msg) => errors.push({ code, message: msg });

    if (!output || typeof output !== 'object') {
        return { ok: false, errors: [{ code: 'E_NOT_OBJECT', message: 'output must be an object' }] };
    }
    if (!STATUSES.has(output.advisory_status)) {
        push('E_BAD_STATUS', `advisory_status=${JSON.stringify(output.advisory_status)} is not in ${Array.from(STATUSES).join('|')}`);
    }

    const portal = output.portal_evidence || { items: [] };
    const portalSids = new Set((portal.items || []).map(i => i.submission_id));

    const topicMap = output.topic_map || { high: [], medium: [], low: [] };
    const highTerms = new Set((topicMap.high || []).map(t => t.term));

    // I2: every high topic backed by ≥1 real portal sid
    for (const t of (topicMap.high || [])) {
        const ids = t.evidence_submission_ids || [];
        if (ids.length === 0) {
            push('E_HIGH_TOPIC_NO_EVIDENCE', `high topic "${t.term}" has no evidence_submission_ids`);
            continue;
        }
        for (const sid of ids) {
            if (!portalSids.has(sid)) {
                push('E_HIGH_TOPIC_EVIDENCE_MISSING',
                    `high topic "${t.term}" cites sid "${sid}" not present in portal_evidence.items`);
            }
        }
    }

    // I3: memory entries
    const memEntries = ((output.memory || {}).entries) || [];
    const memIds = new Set(memEntries.map(m => m.memory_id));
    for (const m of memEntries) {
        if (m.matched_topic && !highTerms.has(m.matched_topic)) {
            push('E_MEM_INTRODUCES_TOPIC',
                `memory entry "${m.memory_id}" has matched_topic "${m.matched_topic}" not in topic_map.high`);
        }
    }

    // I4: pubmed entries
    const pmResults = ((output.pubmed || {}).results) || [];
    const pmids = new Set(pmResults.map(p => p.pmid));
    for (const p of pmResults) {
        if (p.matched_topic && !highTerms.has(p.matched_topic)) {
            push('E_PUBMED_INTRODUCES_TOPIC',
                `pubmed result pmid=${p.pmid} has matched_topic "${p.matched_topic}" not in topic_map.high`);
        }
    }

    // I5–I8: interpretation claims
    const interp = output.interpretation || null;
    if (interp && typeof interp === 'object') {
        for (const key of INTERPRETATION_LISTS) {
            const list = Array.isArray(interp[key]) ? interp[key] : [];
            for (let idx = 0; idx < list.length; idx++) {
                validateClaim(interp[key][idx], { key, idx }, {
                    highTerms, portalSids, memIds, pmids
                }, push);
            }
        }
        // manuscript_direction is a single Claim (or null)
        if (interp.manuscript_direction) {
            validateClaim(interp.manuscript_direction, { key: 'manuscript_direction', idx: 0 }, {
                highTerms, portalSids, memIds, pmids
            }, push);
        }
    }

    return { ok: errors.length === 0, errors };
}

function validateClaim(c, where, refs, push) {
    const path = `interpretation.${where.key}[${where.idx}]`;
    if (!c || typeof c !== 'object') {
        push('E_CLAIM_NOT_OBJECT', `${path} is not an object`);
        return;
    }
    if (!SOURCES.has(c.source)) {
        push('E_CLAIM_BAD_SOURCE', `${path} source=${JSON.stringify(c.source)} not in ${Array.from(SOURCES).join('|')}`);
    }
    if (c.topic && !refs.highTerms.has(c.topic)) {
        push('E_CLAIM_TOPIC_OUT_OF_SET', `${path} topic "${c.topic}" not in topic_map.high`);
    }
    const based = c.based_on || {};
    const p = Array.isArray(based.portal) ? based.portal : [];
    const m = Array.isArray(based.memory) ? based.memory : [];
    const pm = Array.isArray(based.pubmed) ? based.pubmed : [];

    // I7 — anchor requirements per source
    if (c.source === 'PORTAL'         && p.length === 0) push('E_PORTAL_NO_ANCHOR',         `${path} PORTAL claim has empty based_on.portal`);
    if (c.source === 'MEMORY'         && (m.length === 0 || p.length === 0)) push('E_MEMORY_NO_ANCHOR', `${path} MEMORY claim requires based_on.memory AND based_on.portal`);
    if (c.source === 'PUBMED'         && (pm.length === 0 || p.length === 0)) push('E_PUBMED_NO_ANCHOR', `${path} PUBMED claim requires based_on.pubmed AND based_on.portal`);
    if (c.source === 'INTERPRETATION' && p.length === 0) push('E_INTERP_FLOATING',          `${path} INTERPRETATION claim has empty based_on.portal`);

    // I8 — every referenced id must resolve
    for (const sid of p) {
        if (!refs.portalSids.has(sid)) push('E_PORTAL_REF_BAD', `${path} based_on.portal cites unknown sid "${sid}"`);
    }
    for (const mid of m) {
        if (!refs.memIds.has(mid)) push('E_MEMORY_REF_BAD', `${path} based_on.memory cites unknown memory_id "${mid}"`);
    }
    for (const pmid of pm) {
        if (!refs.pmids.has(pmid)) push('E_PUBMED_REF_BAD', `${path} based_on.pubmed cites unknown pmid "${pmid}"`);
    }
}

module.exports = { validateAdvisory, SOURCES, STATUSES };
