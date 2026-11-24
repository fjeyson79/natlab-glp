'use strict';
// ============================================================================
// Group Meetings — pure policy (no I/O). Every authorization, eligibility and
// validation decision of the Group Meetings utility lives here so it can be
// unit-tested in isolation. The SQL in repo.js mirrors these rules; the
// database tests check that both agree.
//
// Scope: these rules apply ONLY inside /api/group-meetings/*. They do not
// change server/docAccess.js or any other NAT-Lab authorization decision.
// ============================================================================

// ---------------------------------------------------------------- constants
const GROUP_CODES = Object.freeze(['LIU', 'UNAV', 'JOINT']);

// Approved eligibility policy: SOP, DATA and PRESENTATION only. 'PRES' is the
// legacy shorthand that /api/di/upload normalizes to PRESENTATION.
const ELIGIBLE_FILE_TYPES = Object.freeze(['SOP', 'DATA', 'PRESENTATION', 'PRES']);
// Statuses listed in Group Meetings. Everything else (DISCARDED, ARCHIVED, any
// unknown value) is excluded. A missing status is the legacy default PENDING.
const LISTABLE_STATUSES = Object.freeze(['APPROVED', 'PENDING', 'SUBMITTED', 'REVISION_NEEDED']);
const MEMBER_ROLES = Object.freeze(['researcher', 'supervisor']);
const DOCUMENT_FILTERS = Object.freeze(['week', 'since_last', 'all']);
const NEW_FALLBACK_DAYS = 7;

const OCCURRENCE_STATUSES = Object.freeze(['SCHEDULED', 'IN_PROGRESS', 'COMPLETED', 'CANCELLED', 'POSTPONED']);

const RESEARCHER_ID_RE = /^[A-Za-z0-9._@-]{1,100}$/;
const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ------------------------------------------------------------------- actors
function lower(v) { return String(v == null ? '' : v).trim().toLowerCase(); }

// Resolves who is calling, from the authenticated SESSION identity and the
// CURRENT allowlist row (never from ?user= impersonation, headers or body).
//   sessionUser: req.session.user
//   account:     { researcher_id, role, active } from di_allowlist, or null
// Returns { ok: true, actor } or { ok: false, status, reason }.
function classifyActor(sessionUser, account) {
    if (!sessionUser || !sessionUser.researcher_id) return { ok: false, status: 401, reason: 'not_authenticated' };
    if (!account || String(account.researcher_id) !== String(sessionUser.researcher_id)) {
        return { ok: false, status: 403, reason: 'unknown_account' };
    }
    if (account.active !== true) return { ok: false, status: 403, reason: 'inactive_account' };
    const sessionRole = lower(sessionUser.role);
    const dbRole = lower(account.role) || 'researcher';
    // No automatic ai_bot access, whatever the session or the allowlist says.
    if (sessionRole === 'ai_bot' || dbRole === 'ai_bot') return { ok: false, status: 403, reason: 'ai_bot_not_permitted' };
    // PI only when BOTH the session and the current allowlist row say so.
    if (sessionRole === 'pi' && dbRole === 'pi') {
        return { ok: true, actor: { id: String(account.researcher_id), isPi: true, role: 'pi' } };
    }
    if (!MEMBER_ROLES.includes(dbRole)) return { ok: false, status: 403, reason: 'role_not_permitted' };
    return { ok: true, actor: { id: String(account.researcher_id), isPi: false, role: dbRole } };
}

// Controlled rollout (GROUP_MEETINGS_AUDIENCE), evaluated only when the
// feature flag is on. Membership still decides WHICH groups a person sees;
// the audience decides WHETHER non-PI users see Group Meetings at all yet.
//   unset / "pi"      -> PI only (safe default for the first enablement)
//   "R01,R07,..."     -> PI + these researcher ids (pilot)
//   "members"         -> PI + every PI-selected member (full rollout)
function parseAudience(env = process.env) {
    const raw = String((env && env.GROUP_MEETINGS_AUDIENCE) || '').trim();
    if (!raw || raw.toLowerCase() === 'pi') return { mode: 'pi' };
    if (raw.toLowerCase() === 'members') return { mode: 'members' };
    const ids = raw.split(',').map(s => s.trim()).filter(s => RESEARCHER_ID_RE.test(s));
    return { mode: 'list', ids: new Set(ids) };
}

function audienceIncludes(audience, actor) {
    if (!actor) return false;
    if (actor.isPi) return true;
    if (!audience) return false;
    if (audience.mode === 'members') return true;
    if (audience.mode === 'list') return audience.ids.has(String(actor.id));
    return false;
}

// Whether an allowlist row may hold (or keep) meeting membership.
function isMembershipEligibleAccount(account) {
    return !!account && account.active === true && MEMBER_ROLES.includes(lower(account.role) || 'researcher');
}

// --------------------------------------------------------------- documents
function isEligibleFileType(fileType) {
    return ELIGIBLE_FILE_TYPES.includes(String(fileType || '').toUpperCase());
}

function displayFileType(fileType) {
    const t = String(fileType || '').toUpperCase();
    return t === 'PRES' ? 'PRESENTATION' : t;
}

// A legacy (pre-2026) import that the researcher has not yet submitted in a
// pack is an unsubmitted draft and never appears in Group Meetings.
function isLegacyDraft(doc) {
    return !!doc && doc.record_origin === 'legacy_pre2026' && !doc.legacy_pack_id && String(doc.status || '').toUpperCase() === 'SUBMITTED';
}

// Group Meetings separates two decisions (final policy, Nov 2026):
//
// 1. LISTING — every authorized member of a group sees the complete list of
//    eligible submissions of all current members: SOP / DATA / PRESENTATION
//    (incl. PRES) with status APPROVED, PENDING, SUBMITTED or REVISION_NEEDED,
//    in the NAT-Lab workspace, excluding unsubmitted legacy drafts. Listed
//    documents feed Last upload, New and Total for everyone alike.
//
// 2. OPENING — viewing, preview, retrieval and download within Group Meetings
//    are allowed ONLY to the document owner and the PI, whatever the approval
//    status. Approval never lets other members open a document here.
//
//   doc: { researcher_id, file_type, status, in_natlab_workspace, record_origin?, legacy_pack_id? }
//   ctx: { ownerIsMember: owner is a CURRENT eligible member of the group,
//          actorCanAccessGroup: PI, or the actor is a current member }
function isListableDocument(doc, { ownerIsMember, actorCanAccessGroup }) {
    if (!doc || !actorCanAccessGroup || !ownerIsMember) return false;
    if (doc.in_natlab_workspace !== true) return false;
    if (!isEligibleFileType(doc.file_type)) return false;
    const status = String(doc.status || 'PENDING').toUpperCase();
    if (!LISTABLE_STATUSES.includes(status)) return false;
    if (isLegacyDraft(doc)) return false;
    return true;
}

// Owner-or-PI only, independent of approval status.
function isOwnerOrPi(actor, ownerId) {
    return !!actor && (actor.isPi === true || String(ownerId) === actor.id);
}

function canOpenDocument(actor, doc, ctx) {
    return isListableDocument(doc, ctx) && isOwnerOrPi(actor, doc.researcher_id);
}

function normalizeFilter(value) {
    const v = lower(value) || 'all';
    return DOCUMENT_FILTERS.includes(v) ? v : null;
}

// "New" window: since the end of the last COMPLETED occurrence of the group;
// before the first completed meeting, the previous seven days (flagged as a
// fallback). Cancelled and postponed occurrences never reset the window.
function newSubmissionWindow(lastCompletedAt, now) {
    const n = now instanceof Date ? now : new Date(now);
    if (lastCompletedAt) {
        return { since: new Date(lastCompletedAt), fallback: false, basis: 'last_completed_meeting' };
    }
    return { since: new Date(n.getTime() - NEW_FALLBACK_DAYS * 24 * 3600 * 1000), fallback: true, basis: 'previous_7_days' };
}

// --------------------------------------------------------------- validation
function normalizeGroupCode(value) {
    const c = String(value || '').trim().toUpperCase();
    return GROUP_CODES.includes(c) ? c : null;
}

function isValidResearcherId(value) { return typeof value === 'string' && RESEARCHER_ID_RE.test(value); }
function isUuid(value) { return typeof value === 'string' && UUID_RE.test(value); }

// Recurring Zoom participant URL, configured manually by the PI.
// Accepts only https URLs on zoom.us / zoom.com (or their subdomains) with a
// meeting path (/j/…, /my/…, /w/…). No credentials, ports, fragments,
// whitespace or arbitrary external hosts. null / '' removes the link.
const ZOOM_HOST_RE = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*zoom\.(?:us|com)$/;
const ZOOM_PATH_RE = /^\/(?:j|my|w)\/[A-Za-z0-9._-]{1,64}\/?$/;
function validateZoomJoinUrl(input) {
    if (input === null || input === undefined || (typeof input === 'string' && input.trim() === '')) {
        return { ok: true, value: null };
    }
    if (typeof input !== 'string') return { ok: false, reason: 'not_a_string' };
    const raw = input.trim();
    if (raw.length > 512) return { ok: false, reason: 'too_long' };
    if (/[\s\u0000-\u001f\u007f]/.test(raw)) return { ok: false, reason: 'invalid_characters' };
    let u;
    try { u = new URL(raw); } catch (_) { return { ok: false, reason: 'not_a_url' }; }
    if (u.protocol !== 'https:') return { ok: false, reason: 'https_required' };
    if (u.username || u.password) return { ok: false, reason: 'credentials_not_allowed' };
    if (u.port) return { ok: false, reason: 'port_not_allowed' };
    if (u.hash) return { ok: false, reason: 'fragment_not_allowed' };
    if (!ZOOM_HOST_RE.test(u.hostname)) return { ok: false, reason: 'host_not_approved' };
    if (!ZOOM_PATH_RE.test(u.pathname)) return { ok: false, reason: 'path_not_a_meeting_link' };
    return { ok: true, value: u.href };
}

// ------------------------------------------------------------- occurrences
// R1 exposes scheduling actions only. IN_PROGRESS / COMPLETED are reserved for
// the R3 "start / end scientific meeting" actions.
const OCCURRENCE_ACTIONS = Object.freeze({
    reschedule: { from: ['SCHEDULED', 'POSTPONED'], to: 'SCHEDULED', event: 'meeting.rescheduled' },
    postpone:   { from: ['SCHEDULED'],              to: 'POSTPONED', event: 'meeting.postponed' },
    cancel:     { from: ['SCHEDULED', 'POSTPONED'], to: 'CANCELLED', event: 'meeting.cancelled' },
});

function planOccurrenceAction(currentStatus, action) {
    const spec = OCCURRENCE_ACTIONS[action];
    if (!spec) return { ok: false, reason: 'unknown_action' };
    if (!spec.from.includes(String(currentStatus || '').toUpperCase())) return { ok: false, reason: 'invalid_transition' };
    return { ok: true, to: spec.to, event: spec.event };
}

function parseScheduledStart(value) {
    if (typeof value !== 'string' || value.length > 40) return null;
    // Require an explicit offset or Z so the instant is unambiguous.
    if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2}(?:\.\d{1,3})?)?(?:Z|[+-]\d{2}:\d{2})$/.test(value)) return null;
    const d = new Date(value);
    return Number.isNaN(d.getTime()) ? null : d;
}

function parseDuration(value) {
    if (value === null || value === undefined || value === '') return { ok: true, value: null };
    const n = Number(value);
    if (!Number.isInteger(n) || n < 5 || n > 480) return { ok: false };
    return { ok: true, value: n };
}

function parseNote(value, max = 1000) {
    if (value === null || value === undefined) return { ok: true, value: null };
    if (typeof value !== 'string' || value.length > max) return { ok: false };
    const t = value.trim();
    return { ok: true, value: t === '' ? null : t };
}

module.exports = {
    GROUP_CODES, ELIGIBLE_FILE_TYPES, LISTABLE_STATUSES, MEMBER_ROLES, DOCUMENT_FILTERS,
    NEW_FALLBACK_DAYS, OCCURRENCE_STATUSES, OCCURRENCE_ACTIONS,
    classifyActor, isMembershipEligibleAccount, parseAudience, audienceIncludes,
    isEligibleFileType, displayFileType, isLegacyDraft, isListableDocument, isOwnerOrPi, canOpenDocument,
    normalizeFilter, newSubmissionWindow,
    normalizeGroupCode, isValidResearcherId, isUuid, validateZoomJoinUrl,
    planOccurrenceAction, parseScheduledStart, parseDuration, parseNote,
};
