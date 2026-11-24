'use strict';
// ============================================================================
// NAT-Lab Notify (N1 + N2) — the PI's communication centre.
// ----------------------------------------------------------------------------
// Durable, auditable e-mail on top of server/notify.js (the only code that talks
// to Resend). Adapted from the TOUCAN-MRSA Notify design (message / recipient /
// template records, confirm → freeze → claim → resume); no shared code or data.
//
// Safety model
//   * Nothing is sent unless RESEND_API_KEY + NOTIFY_FROM are configured AND the
//     global switch NOTIFY_SENDING_ENABLED=true (server/notify.js).
//   * Manual sending and every automatic category are separate settings in
//     notify_settings, all OFF by default. A PI "pause" stops every send at once
//     (no restart needed).
//   * PI only; every state-changing route is behind the global same-origin guard.
//   * Recipients are resolved on the server only (the browser never supplies an
//     address), validated when the PI confirms and again just before each send.
//   * One e-mail per recipient (never CC/BCC), with a per-recipient idempotency
//     key: a repeated confirmation, a retry or a resume cannot deliver twice
//     within the provider's 24-hour idempotency window.
//   * "Accepted" means Resend accepted the request, never "delivered".
//   * A send whose outcome is unknown (timeout, provider error, restart while
//     sending) is marked UNCERTAIN and is never re-sent automatically.
//   * E-mail never blocks or invalidates a GLP operation.
// ============================================================================
const crypto = require('crypto');
const express = require('express');
const notify = require('./notify');

const MAX_RECIPIENTS = 60;              // per message (bulk protection)
const MAX_SUBJECT = 200;
const MAX_BODY = 20000;
const IDEMPOTENCY_WINDOW_MS = 23 * 3600 * 1000; // stay inside Resend's 24 h
const GROUP_CODES = ['LIU', 'UNAV', 'JOINT'];
const AFFILIATIONS = ['LiU', 'UNAV', 'EXTERNAL'];
const BASE_AUDIENCES = ['all', 'researchers', 'supervisors'];

// Automatic categories. Only `implemented` ones can be switched on (N1 hooks);
// the rest are the planned N3 programme, shown but not switchable.
const CATEGORIES = [
    { key: 'submission_received', label: 'New submission → PI (metadata only)', implemented: true },
    { key: 'decision_approved', label: 'Document approved → researcher', implemented: true },
    { key: 'decision_revision', label: 'Revision requested → researcher', implemented: true },
    { key: 'decision_discarded', label: 'Document discarded → researcher', implemented: true },
    { key: 'supervisor_sop', label: 'SOP submissions → assigned supervisors', implemented: false },
    { key: 'supervisor_data', label: 'DATA submissions → assigned supervisors', implemented: false },
    { key: 'supervisor_presentation', label: 'PRESENTATION submissions → assigned supervisors', implemented: false },
    { key: 'document_review', label: 'Document review reminders', implemented: false },
    { key: 'research_summary', label: 'Research activity summaries', implemented: false },
    { key: 'supervisor_summary', label: 'Supervisor activity summaries (daily / weekly)', implemented: false },
    { key: 'gm_invitation', label: 'Group Meetings invitations', implemented: false },
    { key: 'gm_reminder', label: 'Group Meetings reminders', implemented: false },
    { key: 'theralia_investor_booking', label: 'Theralia investor bookings (company module — out of scope)', implemented: false, locked: true },
];
const CATEGORY_KEYS = new Set(CATEGORIES.map(c => c.key));

// Built-in templates (read-only; "duplicate" makes an editable copy).
const SYSTEM_TEMPLATES = [
    { id: 'sys:general', name: 'General announcement', category: 'general',
      subject: 'NAT-Lab: announcement',
      body: 'Dear {{first_name}},\n\n[Your announcement]\n\nBest regards,\nFrank' },
    { id: 'sys:lab_reminder', name: 'Laboratory reminder', category: 'reminder',
      subject: 'NAT-Lab reminder',
      body: 'Dear {{first_name}},\n\nThis is a reminder that [what / by when].\n\nThank you,\nFrank' },
    { id: 'sys:submission_reminder', name: 'Scientific submission reminder', category: 'submission',
      subject: 'NAT-Lab: please submit your documents',
      body: 'Dear {{first_name}},\n\nPlease remember to submit your recent SOPs, DATA and presentations in the NAT-Lab GLP portal:\n{{portal_link}}\n\nThank you,\nFrank' },
    { id: 'sys:review', name: 'Document review and approval', category: 'review',
      subject: 'NAT-Lab: documents reviewed',
      body: 'Dear {{first_name}},\n\nYour recent submissions have been reviewed. Please sign in to see the outcome:\n{{portal_link}}\n\nBest regards,\nFrank' },
    { id: 'sys:revision', name: 'Revision request', category: 'review',
      subject: 'NAT-Lab: revision requested',
      body: 'Dear {{first_name}},\n\nOne or more of your submissions need a revision. Please sign in to see the details:\n{{portal_link}}\n\nBest regards,\nFrank' },
    { id: 'sys:gm_announcement', name: 'Group Meetings announcement', category: 'group_meetings',
      subject: 'NAT-Lab {{meeting_group}} meeting',
      body: 'Dear {{first_name}},\n\nThe next {{meeting_group}} group meeting is on [date] at [time].\nZoom: {{zoom_link}}\n\nAgenda and documents are in the portal:\n{{portal_link}}\n\nBest regards,\nFrank' },
    { id: 'sys:supervisor_summary', name: 'Supervisor activity summary', category: 'supervisor',
      subject: 'NAT-Lab: activity summary',
      body: 'Dear {{first_name}},\n\n[Summary of recent activity of your assigned researchers — metadata only.]\n\nDetails (sign-in required):\n{{portal_link}}\n\nBest regards,\nFrank' },
];
const VARIABLES = {
    first_name: 'Recipient first name', full_name: 'Recipient full name', affiliation: 'Recipient institution',
    portal_link: 'https://glp.hernandezlab.com (sign-in page)', today: 'Today\'s date',
    meeting_group: 'Meeting group name (audience = exactly one meeting group)', zoom_link: 'Recurring Zoom link of that meeting group (members only)',
};

// ---------------------------------------------------------------- schema
const SCHEMA = [
    `CREATE TABLE IF NOT EXISTS notify_settings (
        key VARCHAR(80) PRIMARY KEY,
        value JSONB NOT NULL,
        updated_by VARCHAR(100),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`,
    `CREATE TABLE IF NOT EXISTS notify_templates (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        name VARCHAR(120) NOT NULL,
        category VARCHAR(40) NOT NULL DEFAULT 'general',
        subject VARCHAR(${MAX_SUBJECT}) NOT NULL,
        body TEXT NOT NULL CHECK (length(body) <= ${MAX_BODY}),
        archived_at TIMESTAMPTZ,
        created_by VARCHAR(100) NOT NULL,
        updated_by VARCHAR(100),
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`,
    `CREATE TABLE IF NOT EXISTS notify_messages (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        kind VARCHAR(20) NOT NULL CHECK (kind IN ('manual','test','automatic')),
        category VARCHAR(40) NOT NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'DRAFT'
            CHECK (status IN ('DRAFT','QUEUED','SENDING','SENT','PARTIAL','FAILED','DISCARDED')),
        template_id VARCHAR(60),
        template_name VARCHAR(120),
        subject VARCHAR(${MAX_SUBJECT}) NOT NULL,
        body TEXT NOT NULL CHECK (length(body) <= ${MAX_BODY}),
        audience JSONB NOT NULL DEFAULT '{}'::jsonb CHECK (jsonb_typeof(audience) = 'object'),
        recipient_count INTEGER NOT NULL DEFAULT 0 CHECK (recipient_count BETWEEN 0 AND ${MAX_RECIPIENTS}),
        created_by VARCHAR(100) NOT NULL,
        trigger_event VARCHAR(80),
        confirmed_by VARCHAR(100),
        confirmed_at TIMESTAMPTZ,
        completed_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`,
    `CREATE TABLE IF NOT EXISTS notify_recipients (
        id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
        message_id UUID NOT NULL REFERENCES notify_messages(id) ON DELETE RESTRICT,
        researcher_id VARCHAR(100),
        name VARCHAR(200) NOT NULL,
        email VARCHAR(254) NOT NULL,
        reason VARCHAR(120),
        status VARCHAR(20) NOT NULL DEFAULT 'QUEUED'
            CHECK (status IN ('QUEUED','SENDING','ACCEPTED','FAILED','UNCERTAIN','SKIPPED','DELIVERED','BOUNCED')),
        skip_reason VARCHAR(200),
        sent_subject VARCHAR(250) NOT NULL,
        sent_text TEXT NOT NULL,
        sent_html TEXT NOT NULL,
        dedupe_key VARCHAR(120) NOT NULL UNIQUE,
        provider_id VARCHAR(100),
        error VARCHAR(200),
        attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
        queued_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        first_attempt_at TIMESTAMPTZ,
        last_attempt_at TIMESTAMPTZ,
        accepted_at TIMESTAMPTZ,
        delivered_at TIMESTAMPTZ,
        created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
        updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`,
    `CREATE INDEX IF NOT EXISTS idx_notify_messages_created ON notify_messages(created_at DESC)`,
    `CREATE INDEX IF NOT EXISTS idx_notify_messages_status ON notify_messages(status)`,
    `CREATE INDEX IF NOT EXISTS idx_notify_recipients_message ON notify_recipients(message_id)`,
    `CREATE INDEX IF NOT EXISTS idx_notify_recipients_status ON notify_recipients(status)`,
    // Sending history is an audit record: rows are never deleted.
    `CREATE OR REPLACE FUNCTION notify_refuse_delete() RETURNS trigger LANGUAGE plpgsql AS $$
     BEGIN RAISE EXCEPTION 'notify history is append-only (% on %)', TG_OP, TG_TABLE_NAME; END $$`,
    `DO $$ BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'notify_messages_no_delete') THEN
            CREATE TRIGGER notify_messages_no_delete BEFORE DELETE ON notify_messages FOR EACH ROW EXECUTE FUNCTION notify_refuse_delete();
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'notify_messages_no_truncate') THEN
            CREATE TRIGGER notify_messages_no_truncate BEFORE TRUNCATE ON notify_messages FOR EACH STATEMENT EXECUTE FUNCTION notify_refuse_delete();
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'notify_recipients_no_delete') THEN
            CREATE TRIGGER notify_recipients_no_delete BEFORE DELETE ON notify_recipients FOR EACH ROW EXECUTE FUNCTION notify_refuse_delete();
        END IF;
        IF NOT EXISTS (SELECT 1 FROM pg_trigger WHERE tgname = 'notify_recipients_no_truncate') THEN
            CREATE TRIGGER notify_recipients_no_truncate BEFORE TRUNCATE ON notify_recipients FOR EACH STATEMENT EXECUTE FUNCTION notify_refuse_delete();
        END IF;
     END $$`,
];

// ------------------------------------------------------------- rendering
const VAR_RE = /\{\{\s*([a-z_]+)\s*\}\}/g;
function variablesIn(text) {
    const used = new Set(), unknown = new Set();
    String(text || '').replace(VAR_RE, (_, name) => { (Object.prototype.hasOwnProperty.call(VARIABLES, name) ? used : unknown).add(name); return ''; });
    const stripped = String(text || '').replace(VAR_RE, '');
    return { used: [...used], unknown: [...unknown], malformed: /\{\{|\}\}/.test(stripped) };
}
function fill(text, values) {
    return String(text || '').replace(VAR_RE, (_, name) => notify.oneLine(Object.prototype.hasOwnProperty.call(values, name) ? values[name] : '', 300));
}
// Plain text → safe HTML: everything escaped; https links (only) become links;
// blank lines separate paragraphs.
const URL_RE = /https:\/\/[A-Za-z0-9.-]+(?::\d{2,5})?(?:\/[A-Za-z0-9\-._~%!$&'()*+,;=:@/?#]*)?/g;
function textToHtml(text) {
    return String(text || '').split(/\n{2,}/).map(par => {
        let out = '', last = 0;
        par.replace(URL_RE, (m, idx) => {
            const url = m.replace(/[.,;:!?)]+$/, '');
            out += notify.esc(par.slice(last, idx)) + `<a href="${notify.esc(url)}" style="color:#1a365d;">${notify.esc(url)}</a>`;
            last = idx + url.length; return m;
        });
        out += notify.esc(par.slice(last));
        return `<p style="margin:0 0 12px;">${out.replace(/\n/g, '<br>')}</p>`;
    }).join('');
}
function renderFor(recipient, subject, body, ctx) {
    const cfg = notify.config();
    const full = notify.oneLine(recipient.name, 120);
    const values = {
        first_name: full.split(/\s+/)[0] || full, full_name: full, affiliation: recipient.affiliation || '',
        portal_link: cfg.portal + '/di/access.html', today: new Date().toISOString().slice(0, 10),
        meeting_group: ctx.meetingGroup ? ctx.meetingGroup.name : '', zoom_link: ctx.meetingGroup ? (ctx.meetingGroup.zoom || '') : '',
    };
    const s = notify.oneLine(fill(subject, values), 250);
    const text = fill(body, values);
    const footer = 'Sent by the NAT-Lab PI through the NAT-Lab GLP portal.' + (cfg.replyTo ? ` Replies go to ${cfg.replyTo}.` : '');
    const html = `<!DOCTYPE html><html><body style="font-family:Arial,sans-serif;max-width:640px;margin:0 auto;color:#1f2937;">
<div style="background:#1a365d;color:#fff;padding:14px 20px;border-radius:8px 8px 0 0;font-size:16px;font-weight:bold;">NAT-Lab | GLP</div>
<div style="padding:20px 24px;background:#f8f9fa;line-height:1.55;font-size:14px;">${textToHtml(text)}</div>
<div style="padding:12px;text-align:center;font-size:12px;color:#888;">${notify.esc(footer)}</div>
</body></html>`;
    return { subject: s, text: text + '\n\n--\n' + footer + '\n', html };
}

// -------------------------------------------------------------- module
function createNotifyCenter({ pool, requirePI, spacingMs }) {
    const SPACING = Number.isFinite(spacingMs) ? spacingMs : 600;
    const running = new Set();
    const sleep = (ms) => new Promise(r => setTimeout(r, ms));
    const log = (event, outcome, extra) => console.log(`[NOTIFY] event=${event} outcome=${outcome}${extra ? ' ' + extra : ''}`);

    async function ensureSchema() {
        for (const sql of SCHEMA) await pool.query(sql);
    }

    // ---------------------------------------------------------- settings
    async function settings() {
        const r = await pool.query(`SELECT key, value FROM notify_settings`);
        const m = new Map(r.rows.map(x => [x.key, x.value]));
        const on = (k) => !!(m.get(k) && m.get(k).enabled === true);
        const categories = {};
        for (const c of CATEGORIES) categories[c.key] = c.implemented && !c.locked && on('category:' + c.key);
        return { manual_enabled: on('manual'), paused: !!(m.get('paused') && m.get('paused').paused === true), categories };
    }
    async function setSetting(key, value, by) {
        await pool.query(`INSERT INTO notify_settings (key, value, updated_by, updated_at) VALUES ($1, $2, $3, now())
                          ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_by = EXCLUDED.updated_by, updated_at = now()`,
            [key, JSON.stringify(value), by]);
    }
    // Can a message of this kind be sent right now?
    async function gate(kind, category) {
        if (!notify.isEnabled()) return { ok: false, code: 'sending_disabled', why: 'Global sending switch is off or e-mail is not configured.' };
        let st;
        try { st = await settings(); } catch (_) { return { ok: false, code: 'settings_unavailable', why: 'Notify settings unavailable.' }; }
        if (st.paused) return { ok: false, code: 'paused', why: 'Sending is paused.' };
        if (kind === 'manual' && !st.manual_enabled) return { ok: false, code: 'manual_disabled', why: 'Manual sending is switched off.' };
        if (kind === 'automatic' && !st.categories[category]) return { ok: false, code: 'category_disabled', why: 'This automatic category is off.' };
        return { ok: true };
    }

    // --------------------------------------------------------- audiences
    let _gm = null;
    async function gmInfo() {
        if (_gm && Date.now() - _gm.at < 60000) return _gm;
        const t = await pool.query(`SELECT to_regclass('public.meeting_groups') IS NOT NULL AS g, to_regclass('public.meeting_group_members') IS NOT NULL AS m,
            EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'meeting_groups' AND column_name = 'code') AS code,
            EXISTS (SELECT 1 FROM information_schema.columns WHERE table_name = 'meeting_groups' AND column_name = 'zoom_join_url') AS zoom`);
        _gm = { at: Date.now(), ok: t.rows[0].g && t.rows[0].m, code: t.rows[0].code, zoom: t.rows[0].zoom };
        return _gm;
    }
    async function meetingGroups() {
        const gi = await gmInfo();
        if (!gi.ok) return [];
        const r = await pool.query(`SELECT g.id, ${gi.code ? 'g.code' : "upper(g.name)"} AS code, g.name, ${gi.zoom ? 'g.zoom_join_url' : 'NULL'} AS zoom
            FROM meeting_groups g WHERE g.is_active = TRUE`);
        return r.rows.filter(x => GROUP_CODES.includes(String(x.code).toUpperCase())).map(x => ({ ...x, code: String(x.code).toUpperCase() }));
    }
    // Accounts kept out of BULK audiences by stable account identifier (the PI's
    // alternate accounts): NOTIFY_BULK_EXCLUDED_ACCOUNTS=id1,id2 (researcher_id values).
    function bulkExcludedIds() {
        return [...new Set(String(process.env.NOTIFY_BULK_EXCLUDED_ACCOUNTS || '').split(',').map(x => x.trim()).filter(x => x && x.length <= 100))].slice(0, 50);
    }
    // Base pool: active account + ACTIVE NAT-Lab (LAB) membership + researcher/supervisor
    // role + valid institutional address. Company/investor accounts, the PI, ai_bot and
    // inactive accounts can never appear. Accounts listed in NOTIFY_BULK_EXCLUDED_ACCOUNTS
    // are kept out of bulk audiences; as a safety net, so is any account with exactly the
    // name of an active PI account (shown separately so the list can be completed).
    async function eligiblePool() {
        const gi = await gmInfo();
        const groupsSql = gi.ok
            ? `COALESCE((SELECT array_agg(DISTINCT ${gi.code ? 'g.code' : 'upper(g.name)'}) FROM meeting_group_members m
                 JOIN meeting_groups g ON g.id = m.meeting_group_id AND g.is_active = TRUE WHERE m.researcher_id = a.researcher_id), '{}')`
            : `'{}'::text[]`;
        const r = await pool.query(`
            SELECT DISTINCT ON (a.researcher_id) a.researcher_id, a.name, a.institution_email AS email, a.role, a.affiliation,
                   ${groupsSql} AS groups,
                   (a.researcher_id = ANY($1::text[])) AS excluded_by_id,
                   EXISTS (SELECT 1 FROM di_allowlist p WHERE p.role = 'pi' AND p.active = TRUE AND lower(trim(p.name)) = lower(trim(a.name))) AS pi_name_match
              FROM di_allowlist a
              JOIN workspace_users wu ON wu.user_id = a.researcher_id AND wu.is_active = TRUE AND COALESCE(to_jsonb(wu)->>'status', 'active') = 'active'
              JOIN workspaces w ON w.id = wu.workspace_id AND w.workspace_type = 'LAB' AND COALESCE((to_jsonb(w)->>'is_active')::boolean, TRUE)
             WHERE a.active = TRUE AND a.role IN ('researcher', 'supervisor')
             ORDER BY a.researcher_id`, [bulkExcludedIds()]);
        return r.rows.filter(x => notify.validEmail(x.email)).map(x => ({ ...x, email: String(x.email).trim(), groups: (x.groups || []).map(g => String(g).toUpperCase()),
            pi_alternate: x.excluded_by_id || x.pi_name_match,
            exclusion: x.excluded_by_id ? 'Excluded from group audiences (NOTIFY_BULK_EXCLUDED_ACCOUNTS)' : (x.pi_name_match ? 'Same name as the PI account — excluded from group audiences (safety net; add it to NOTIFY_BULK_EXCLUDED_ACCOUNTS)' : null) }));
    }
    function validateSpec(spec) {
        const s = spec && typeof spec === 'object' ? spec : {};
        const groups = Array.isArray(s.groups) ? s.groups.map(String) : [];
        const okGroups = groups.filter(g => BASE_AUDIENCES.includes(g) || /^gm:(LIU|UNAV|JOINT)$/.test(g));
        if (okGroups.length !== groups.length) return { error: 'Unknown audience.' };
        const affiliation = s.affiliation ? String(s.affiliation) : null;
        if (affiliation && !AFFILIATIONS.includes(affiliation)) return { error: 'Unknown institution filter.' };
        const individuals = Array.isArray(s.individuals) ? [...new Set(s.individuals.map(String))] : [];
        if (individuals.length > 100 || individuals.some(x => x.length > 100)) return { error: 'Too many individual recipients.' };
        return { spec: { groups: [...new Set(okGroups)], affiliation, individuals } };
    }
    async function resolveAudience(spec) {
        const pool0 = await eligiblePool();
        const byId = new Map(pool0.map(p => [p.researcher_id, p]));
        const chosen = new Map(); const excluded = [];
        const add = (p, reason) => { if (!chosen.has(p.researcher_id)) chosen.set(p.researcher_id, { ...p, reason }); };
        const affOk = (p) => !spec.affiliation || String(p.affiliation || '').toLowerCase() === spec.affiliation.toLowerCase();
        const groups = await meetingGroups();
        for (const g of spec.groups) {
            let members;
            if (g === 'all') members = pool0;
            else if (g === 'researchers') members = pool0.filter(p => p.role === 'researcher');
            else if (g === 'supervisors') members = pool0.filter(p => p.role === 'supervisor');
            else {
                const code = g.slice(3);
                members = pool0.filter(p => p.groups.includes(code));
                // group members who are not eligible (inactive, no NAT-Lab membership, no address)
                const grp = groups.find(x => x.code === code);
                if (grp) {
                    const r = await pool.query(`SELECT m.researcher_id, a.name FROM meeting_group_members m LEFT JOIN di_allowlist a ON a.researcher_id = m.researcher_id WHERE m.meeting_group_id = $1`, [grp.id]);
                    for (const x of r.rows) if (!byId.has(x.researcher_id)) excluded.push({ name: x.name || x.researcher_id, reason: `${code} group member, not eligible (inactive, not an active NAT-Lab member or no valid address)` });
                }
            }
            for (const p of members) {
                if (p.pi_alternate) { excluded.push({ name: p.name, reason: p.exclusion }); continue; }
                if (!affOk(p)) continue;
                add(p, g.startsWith('gm:') ? g.slice(3) + ' meeting group' : g);
            }
        }
        for (const id of spec.individuals) {
            const p = byId.get(id);
            if (!p) {
                const r = await pool.query(`SELECT name FROM di_allowlist WHERE researcher_id = $1`, [id]);
                excluded.push({ name: (r.rows[0] && r.rows[0].name) || 'Unknown account', reason: 'Not eligible (inactive, not an active NAT-Lab member, company/investor account or no valid address)' });
                continue;
            }
            add(p, 'individual');
        }
        // de-duplicate by address as well (one e-mail per address)
        const seen = new Set(); const recipients = [];
        for (const p of chosen.values()) {
            const k = p.email.toLowerCase();
            if (seen.has(k)) { excluded.push({ name: p.name, reason: 'Duplicate address' }); continue; }
            seen.add(k); recipients.push(p);
        }
        const uniqEx = []; const exSeen = new Set();
        for (const e of excluded) { const k = e.name + '|' + e.reason; if (!exSeen.has(k)) { exSeen.add(k); uniqEx.push(e); } }
        recipients.sort((a, b) => String(a.name).localeCompare(String(b.name)));
        // Meeting-group variables ({{meeting_group}}, {{zoom_link}}) only when the audience is
        // exactly ONE meeting group and nothing else: a group's Zoom link never reaches non-members.
        const onlyGroup = spec.groups.length === 1 && spec.groups[0].startsWith('gm:') && spec.individuals.length === 0 && !spec.affiliation;
        const meetingGroup = onlyGroup ? (groups.find(x => x.code === spec.groups[0].slice(3)) || null) : null;
        return { recipients, excluded: uniqEx, meetingGroup: meetingGroup ? { name: meetingGroup.name, zoom: meetingGroup.zoom || '' } : null };
    }
    function contentProblems(subject, body, ctx) {
        const problems = [];
        if (!String(subject || '').trim()) problems.push('Subject is empty.');
        if (String(subject || '').length > MAX_SUBJECT) problems.push(`Subject is longer than ${MAX_SUBJECT} characters.`);
        if (!String(body || '').trim()) problems.push('Message is empty.');
        if (String(body || '').length > MAX_BODY) problems.push(`Message is longer than ${MAX_BODY} characters.`);
        for (const t of [subject, body]) {
            const v = variablesIn(t);
            if (v.unknown.length) problems.push('Unknown variable(s): ' + v.unknown.map(x => '{{' + x + '}}').join(', '));
            if (v.malformed) problems.push('Malformed variable braces.');
            if ((v.used.includes('meeting_group') || v.used.includes('zoom_link')) && !(ctx && ctx.meetingGroup)) problems.push('{{meeting_group}} / {{zoom_link}} need exactly one meeting group as the only audience (no other groups, filters or individuals).');
            if (v.used.includes('zoom_link') && ctx && ctx.meetingGroup && !ctx.meetingGroup.zoom) problems.push('The selected meeting group has no Zoom link.');
        }
        return [...new Set(problems)];
    }
    // Is this recipient row still allowed to receive its e-mail right now?
    async function stillEligible(msg, rcpt) {
        if (msg.kind === 'test') {
            const pi = notify.piAddress();
            return pi && pi.toLowerCase() === rcpt.email.toLowerCase() ? null : 'Test recipient is no longer the configured PI address';
        }
        if (msg.kind === 'automatic') {
            if (msg.category === 'submission_received') {
                const pi = notify.piAddress();
                return pi && pi.toLowerCase() === rcpt.email.toLowerCase() ? null : 'PI address changed';
            }
            const r = await pool.query(`SELECT 1 FROM di_allowlist WHERE active = TRUE AND lower(institution_email) = lower($1)`, [rcpt.email]);
            return r.rows.length ? null : 'Recipient account no longer active';
        }
        const p = (await eligiblePool()).find(x => x.researcher_id === rcpt.researcher_id);
        if (!p) return 'Recipient no longer eligible';
        if (p.email.toLowerCase() !== rcpt.email.toLowerCase()) return 'Recipient address changed since confirmation';
        return null;
    }

    // ------------------------------------------------------------ worker
    async function finalize(messageId) {
        const r = await pool.query(`SELECT status, count(*)::int n FROM notify_recipients WHERE message_id = $1 GROUP BY status`, [messageId]);
        const n = Object.fromEntries(r.rows.map(x => [x.status, x.n]));
        const open = (n.QUEUED || 0) + (n.SENDING || 0);
        const ok = (n.ACCEPTED || 0) + (n.DELIVERED || 0);
        const bad = (n.FAILED || 0) + (n.UNCERTAIN || 0) + (n.BOUNCED || 0);
        let status;
        if (open) status = 'QUEUED';
        else if (ok && !bad) status = 'SENT';
        else if (ok && bad) status = 'PARTIAL';
        else if (!ok && bad) status = 'FAILED';
        else status = 'SENT'; // everything skipped
        await pool.query(`UPDATE notify_messages SET status = $2::varchar, completed_at = CASE WHEN $3::boolean THEN NULL ELSE now() END, updated_at = now()
                          WHERE id = $1 AND status NOT IN ('DRAFT','DISCARDED')`, [messageId, status, status === 'QUEUED']);
        return status;
    }
    async function work(messageId) {
        const m = (await pool.query(`SELECT * FROM notify_messages WHERE id = $1`, [messageId])).rows[0];
        if (!m || m.status === 'DRAFT' || m.status === 'DISCARDED') return;
        await pool.query(`UPDATE notify_messages SET status = 'SENDING', updated_at = now() WHERE id = $1`, [messageId]);
        let first = true;
        for (;;) {
            const g = await gate(m.kind, m.category);
            if (!g.ok) { log('message.send', 'held', `message=${messageId} reason=${g.code}`); break; }
            // claim exactly one row (two workers can never send the same row)
            const c = await pool.query(`UPDATE notify_recipients SET status = 'SENDING', attempts = attempts + 1,
                    first_attempt_at = COALESCE(first_attempt_at, now()), last_attempt_at = now(), updated_at = now()
                WHERE id = (SELECT id FROM notify_recipients WHERE message_id = $1 AND status = 'QUEUED' ORDER BY queued_at, id LIMIT 1 FOR UPDATE SKIP LOCKED)
                RETURNING *`, [messageId]);
            const rc = c.rows[0];
            if (!rc) break;
            if (!first && SPACING > 0) await sleep(SPACING); // provider rate limit
            first = false;
            let notOk = null;
            try { notOk = await stillEligible(m, rc); } catch (_) { notOk = 'Eligibility check failed'; }
            if (notOk) {
                await pool.query(`UPDATE notify_recipients SET status = 'SKIPPED', skip_reason = $2, updated_at = now() WHERE id = $1`, [rc.id, notOk]);
                continue;
            }
            const out = await notify.deliver({ event: 'notify.' + m.kind, to: rc.email, subject: rc.sent_subject, html: rc.sent_html, text: rc.sent_text, idempotencyKey: rc.dedupe_key });
            if (out.status === 'accepted') {
                await pool.query(`UPDATE notify_recipients SET status = 'ACCEPTED', provider_id = $2, error = NULL, accepted_at = now(), updated_at = now() WHERE id = $1`, [rc.id, out.id]);
            } else if (out.status === 'disabled') {
                // switched off between gate and send: nothing was sent, put it back
                await pool.query(`UPDATE notify_recipients SET status = 'QUEUED', attempts = GREATEST(attempts - 1, 0), updated_at = now() WHERE id = $1`, [rc.id]);
                break;
            } else {
                await pool.query(`UPDATE notify_recipients SET status = $2, error = $3, updated_at = now() WHERE id = $1`,
                    [rc.id, out.status === 'uncertain' ? 'UNCERTAIN' : 'FAILED', out.code || 'failed']);
            }
        }
        const final = await finalize(messageId);
        log('message.send', final.toLowerCase(), `message=${messageId}`);
    }
    function startWorker(messageId) {
        if (running.has(messageId)) return;
        running.add(messageId);
        setImmediate(() => { work(messageId).catch(e => log('message.send', 'error', `message=${messageId} reason=${(e && e.code) || 'internal'}`)).finally(() => running.delete(messageId)); });
    }
    async function idle() { while (running.size) await sleep(50); }

    // Restart recovery: a row left SENDING has an unknown outcome -> UNCERTAIN (never
    // re-sent automatically). Rows still QUEUED were never attempted -> resumed.
    async function recover() {
        const u = await pool.query(`UPDATE notify_recipients SET status = 'UNCERTAIN', error = 'interrupted (application restart)', updated_at = now()
                                     WHERE status = 'SENDING' RETURNING message_id`);
        const ids = new Set(u.rows.map(r => r.message_id));
        const q = await pool.query(`SELECT DISTINCT message_id FROM notify_recipients WHERE status = 'QUEUED'`);
        for (const id of ids) await finalize(id);
        for (const r of q.rows) startWorker(r.message_id);
        if (u.rows.length || q.rows.length) log('recovery', 'done', `uncertain=${u.rows.length} resumed_messages=${q.rows.length}`);
    }

    // Automatic categories (N1 hooks), installed into server/notify.js.
    async function isCategoryEnabled(category) {
        if (!CATEGORY_KEYS.has(category)) return false;
        return (await settings()).categories[category] === true;
    }
    async function enqueueAutomatic(m) {
        try {
            const g = await gate('automatic', m.category);
            if (!g.ok) { log(m.event, 'skipped', 'reason=' + g.code); return { ok: false }; }
            if (!notify.validEmail(m.to)) { log(m.event, 'skipped', 'reason=invalid-recipient'); return { ok: false }; }
            const client = await pool.connect();
            let messageId = null;
            try {
                await client.query('BEGIN');
                const dup = await client.query(`SELECT 1 FROM notify_recipients WHERE dedupe_key = $1`, [m.dedupeKey]);
                if (!dup.rows.length) {
                    messageId = (await client.query(`INSERT INTO notify_messages (kind, category, status, subject, body, recipient_count, created_by, trigger_event, confirmed_at)
                        VALUES ('automatic', $1, 'QUEUED', $2, $3, 1, 'system', $4, now()) RETURNING id`,
                        [m.category, notify.oneLine(m.subject, MAX_SUBJECT), String(m.text || '').slice(0, MAX_BODY), m.event])).rows[0].id;
                    await client.query(`INSERT INTO notify_recipients (message_id, researcher_id, name, email, reason, sent_subject, sent_text, sent_html, dedupe_key)
                        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
                        [messageId, m.recipientId, notify.oneLine(m.name, 200) || 'Recipient', String(m.to).trim(), 'automatic: ' + m.category,
                         notify.oneLine(m.subject, 250), String(m.text || ''), String(m.html || ''), m.dedupeKey]);
                }
                await client.query('COMMIT');
            } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; } finally { client.release(); }
            if (messageId) startWorker(messageId); else log(m.event, 'skipped', 'reason=duplicate');
            return { ok: true };
        } catch (_) { log(m.event, 'failed', 'reason=internal'); return { ok: false }; }
    }

    // ------------------------------------------------------------ limits
    const windows = new Map();
    function rateLimited(key, max, windowMs) {
        const now = Date.now(); const arr = (windows.get(key) || []).filter(t => now - t < windowMs);
        if (arr.length >= max) { windows.set(key, arr); return true; }
        arr.push(now); windows.set(key, arr); return false;
    }

    // ------------------------------------------------------------ routes
    const router = express.Router();
    router.use(requirePI);
    router.use((req, res, next) => { res.set('Cache-Control', 'no-store'); next(); });
    const actor = (req) => req.session.user.researcher_id;
    const fail = (res, status, code, error) => res.status(status).json({ error, code });
    const wrapRoute = (fn) => (req, res) => Promise.resolve(fn(req, res)).catch(e => {
        log('api', 'error', `route=${req.method} ${req.baseUrl}${req.route ? req.route.path : ''} reason=${(e && e.code) || 'internal'}`);
        if (!res.headersSent) fail(res, 500, 'internal', 'Notify is temporarily unavailable.');
    });
    const isUuid = (x) => /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(String(x || ''));

    router.get('/status', wrapRoute(async (req, res) => {
        const st = await settings();
        res.json({ email: notify.status(), settings: st, limits: { max_recipients: MAX_RECIPIENTS, spacing_ms: SPACING },
            categories: CATEGORIES.map(c => ({ ...c, enabled: st.categories[c.key] === true })), variables: VARIABLES });
    }));

    router.get('/audiences', wrapRoute(async (req, res) => {
        const p = await eligiblePool();
        const groups = await meetingGroups();
        const bulk = p.filter(x => !x.pi_alternate);
        res.json({
            people: p.map(x => ({ id: x.researcher_id, name: x.name, role: x.role, affiliation: x.affiliation, groups: x.groups, pi_alternate: x.pi_alternate, exclusion: x.exclusion })),
            bulk_excluded_ids: bulkExcludedIds(),
            counts: { all: bulk.length, researchers: bulk.filter(x => x.role === 'researcher').length, supervisors: bulk.filter(x => x.role === 'supervisor').length,
                      ...Object.fromEntries(GROUP_CODES.map(c => ['gm:' + c, bulk.filter(x => x.groups.includes(c)).length])) },
            groups: groups.map(g => ({ code: g.code, name: g.name, has_zoom: !!g.zoom })),
        });
    }));

    async function prepare(body) {
        const v = validateSpec(body.audience);
        if (v.error) return { error: v.error };
        const subject = String(body.subject || ''), text = String(body.body || '');
        const aud = await resolveAudience(v.spec);
        const problems = contentProblems(subject, text, aud);
        if (!aud.recipients.length) problems.push('No eligible recipients.');
        if (aud.recipients.length > MAX_RECIPIENTS) problems.push(`More than ${MAX_RECIPIENTS} recipients.`);
        return { spec: v.spec, subject, text, aud, problems };
    }
    router.post('/preview', wrapRoute(async (req, res) => {
        const p = await prepare(req.body || {});
        if (p.error) return fail(res, 400, 'invalid_audience', p.error);
        const sample = p.aud.recipients[0] || { name: req.session.user.name || 'Recipient', affiliation: '' };
        const r = p.problems.filter(x => x !== 'No eligible recipients.').length ? null : renderFor(sample, p.subject, p.text, p.aud);
        res.json({ count: p.aud.recipients.length, recipients: p.aud.recipients.map(x => ({ id: x.researcher_id, name: x.name, email: x.email, affiliation: x.affiliation, role: x.role, reason: x.reason })),
            excluded: p.aud.excluded, problems: p.problems, sample: r ? { for: sample.name, subject: r.subject, html: r.html, text: r.text } : null });
    }));

    router.post('/test', wrapRoute(async (req, res) => {
        const g = await gate('test');
        if (!g.ok) return fail(res, 409, g.code, g.why);
        const to = notify.piAddress();
        if (!to) return fail(res, 409, 'no_test_recipient', 'NOTIFY_PI_EMAIL is not configured.');
        if (rateLimited('test:' + actor(req), 5, 10 * 60000)) return fail(res, 429, 'rate_limited', 'Too many test e-mails. Try again in a few minutes.');
        const v = validateSpec((req.body || {}).audience || { groups: [] });
        if (v.error) return fail(res, 400, 'invalid_audience', v.error);
        const aud = await resolveAudience(v.spec);
        const subject = String((req.body || {}).subject || ''), text = String((req.body || {}).body || '');
        const problems = contentProblems(subject, text, aud);
        if (problems.length) return fail(res, 400, 'invalid_content', problems.join(' '));
        const sample = aud.recipients[0] || { name: req.session.user.name || 'PI', affiliation: '' };
        const r = renderFor(sample, subject, text, aud);
        const id = (await pool.query(`INSERT INTO notify_messages (kind, category, status, subject, body, audience, recipient_count, created_by, confirmed_by, confirmed_at)
            VALUES ('test', 'test', 'QUEUED', $1, $2, $3, 1, $4, $4, now()) RETURNING id`,
            [notify.oneLine(subject, MAX_SUBJECT), text, JSON.stringify(v.spec), actor(req)])).rows[0].id;
        await pool.query(`INSERT INTO notify_recipients (message_id, researcher_id, name, email, reason, sent_subject, sent_text, sent_html, dedupe_key)
            VALUES ($1, $2, $3, $4, 'test to PI', $5, $6, $7, $8)`,
            [id, actor(req), 'PI (test, rendered for ' + notify.oneLine(sample.name, 100) + ')', to, notify.oneLine('[TEST] ' + r.subject, 250), r.text, r.html, 'test-' + crypto.randomUUID()]);
        running.add(id);
        try { await work(id); } finally { running.delete(id); }
        const rc = (await pool.query(`SELECT status, provider_id, error FROM notify_recipients WHERE message_id = $1`, [id])).rows[0];
        res.json({ message_id: id, status: rc.status, provider_id: rc.provider_id, error: rc.error });
    }));

    router.post('/drafts', wrapRoute(async (req, res) => {
        const b = req.body || {};
        const p = await prepare(b);
        if (p.error) return fail(res, 400, 'invalid_audience', p.error);
        if (p.problems.length) return fail(res, 400, 'invalid_content', p.problems.join(' '));
        const tpl = b.template_id ? String(b.template_id).slice(0, 60) : null;
        const cat = String(b.category || 'general').slice(0, 40);
        const r = await pool.query(`INSERT INTO notify_messages (kind, category, status, template_id, template_name, subject, body, audience, recipient_count, created_by)
            VALUES ('manual', $1, 'DRAFT', $2, $3, $4, $5, $6, $7, $8) RETURNING id`,
            [cat, tpl, b.template_name ? String(b.template_name).slice(0, 120) : null, p.subject, p.text, JSON.stringify(p.spec), p.aud.recipients.length, actor(req)]);
        res.json({ id: r.rows[0].id, recipient_count: p.aud.recipients.length, recipients: p.aud.recipients.map(x => ({ name: x.name, email: x.email })), excluded: p.aud.excluded });
    }));

    router.post('/messages/:id/discard', wrapRoute(async (req, res) => {
        if (!isUuid(req.params.id)) return fail(res, 404, 'not_found', 'Not found');
        const r = await pool.query(`UPDATE notify_messages SET status = 'DISCARDED', updated_at = now() WHERE id = $1 AND status = 'DRAFT' AND kind = 'manual' RETURNING id`, [req.params.id]);
        if (!r.rows.length) return fail(res, 409, 'not_draft', 'Only drafts can be discarded.');
        res.json({ ok: true });
    }));

    // Confirm: one transaction re-validates everything and freezes one row per recipient.
    router.post('/messages/:id/confirm', wrapRoute(async (req, res) => {
        if (!isUuid(req.params.id)) return fail(res, 404, 'not_found', 'Not found');
        const g = await gate('manual');
        if (!g.ok) return fail(res, 409, g.code, g.why);
        const expected = Number((req.body || {}).recipient_count);
        if (rateLimited('confirm:' + actor(req), 10, 3600000)) return fail(res, 429, 'rate_limited', 'Too many messages sent in the last hour.');
        const client = await pool.connect();
        let count = 0;
        try {
            await client.query('BEGIN');
            const m = (await client.query(`SELECT * FROM notify_messages WHERE id = $1 FOR UPDATE`, [req.params.id])).rows[0];
            if (!m || m.kind !== 'manual') { await client.query('ROLLBACK'); return fail(res, 404, 'not_found', 'Not found'); }
            if (m.status !== 'DRAFT') { await client.query('ROLLBACK'); return fail(res, 409, 'already_confirmed', 'This message has already been confirmed or discarded.'); }
            const aud = await resolveAudience(m.audience && m.audience.groups ? m.audience : { groups: [], individuals: [], affiliation: null });
            const problems = contentProblems(m.subject, m.body, aud);
            if (problems.length) { await client.query('ROLLBACK'); return fail(res, 409, 'invalid_content', problems.join(' ')); }
            count = aud.recipients.length;
            if (!Number.isInteger(expected) || expected !== m.recipient_count || count !== m.recipient_count || count < 1 || count > MAX_RECIPIENTS) {
                await client.query('ROLLBACK');
                return fail(res, 409, 'recipients_changed', `The recipient list changed (now ${count}); prepare the message again.`);
            }
            for (const p of aud.recipients) {
                const r = renderFor(p, m.subject, m.body, aud);
                await client.query(`INSERT INTO notify_recipients (message_id, researcher_id, name, email, reason, sent_subject, sent_text, sent_html, dedupe_key)
                    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)`,
                    [m.id, p.researcher_id, notify.oneLine(p.name, 200), p.email, notify.oneLine(p.reason, 120), r.subject, r.text, r.html,
                     'nm-' + notify.hashKey(m.id, p.researcher_id)]);
            }
            await client.query(`UPDATE notify_messages SET status = 'QUEUED', confirmed_by = $2, confirmed_at = now(), updated_at = now() WHERE id = $1`, [m.id, actor(req)]);
            await client.query('COMMIT');
        } catch (e) { await client.query('ROLLBACK').catch(() => {}); throw e; } finally { client.release(); }
        log('message.confirm', 'queued', `message=${req.params.id} recipients=${count}`);
        startWorker(req.params.id);
        res.json({ ok: true, status: 'QUEUED', recipient_count: count });
    }));

    // Resend: FAILED rows (definitely not accepted) with the same key. UNCERTAIN rows only
    // on explicit request; once the provider's idempotency window has passed, only with
    // an explicit acknowledgement that a duplicate is possible.
    router.post('/messages/:id/resend', wrapRoute(async (req, res) => {
        if (!isUuid(req.params.id)) return fail(res, 404, 'not_found', 'Not found');
        const m = (await pool.query(`SELECT * FROM notify_messages WHERE id = $1`, [req.params.id])).rows[0];
        if (!m || m.kind === 'test') return fail(res, 404, 'not_found', 'Not found');
        if (['DRAFT', 'DISCARDED'].includes(m.status) || running.has(m.id)) return fail(res, 409, 'not_resendable', 'Nothing to resend right now.');
        const g = await gate(m.kind, m.category);
        if (!g.ok) return fail(res, 409, g.code, g.why);
        const b = req.body || {};
        const statuses = ['FAILED'].concat(b.include_uncertain === true ? ['UNCERTAIN'] : []);
        const rows = (await pool.query(`SELECT id, status, first_attempt_at FROM notify_recipients WHERE message_id = $1 AND status = ANY($2)`, [m.id, statuses])).rows;
        const stale = rows.filter(r => r.status === 'UNCERTAIN' && r.first_attempt_at && Date.now() - new Date(r.first_attempt_at).getTime() > IDEMPOTENCY_WINDOW_MS);
        if (stale.length && b.acknowledge_duplicate_risk !== true) {
            return fail(res, 409, 'duplicate_risk', `${stale.length} uncertain e-mail(s) are older than the provider's 24-hour duplicate protection and may have been delivered; confirm the duplicate risk to resend them.`);
        }
        if (!rows.length) return fail(res, 409, 'nothing_to_resend', 'No failed recipients.');
        await pool.query(`UPDATE notify_recipients SET status = 'QUEUED', error = NULL, updated_at = now() WHERE id = ANY($1::uuid[])`, [rows.map(r => r.id)]);
        await pool.query(`UPDATE notify_messages SET status = 'QUEUED', completed_at = NULL, updated_at = now() WHERE id = $1`, [m.id]);
        log('message.resend', 'queued', `message=${m.id} recipients=${rows.length}`);
        startWorker(m.id);
        res.json({ ok: true, requeued: rows.length });
    }));

    router.get('/messages', wrapRoute(async (req, res) => {
        const limit = Math.min(200, Math.max(1, parseInt(req.query.limit, 10) || 100));
        const r = await pool.query(`SELECT m.id, m.kind, m.category, m.status, m.subject, m.template_name, m.recipient_count, m.created_by,
                COALESCE(a.name, m.created_by) AS created_by_name, m.trigger_event, m.created_at, m.confirmed_at, m.completed_at,
                COALESCE((SELECT jsonb_object_agg(s, n) FROM (SELECT status s, count(*)::int n FROM notify_recipients r WHERE r.message_id = m.id GROUP BY status) x), '{}'::jsonb) AS counts
            FROM notify_messages m LEFT JOIN di_allowlist a ON a.researcher_id = m.created_by
            WHERE ($1::text IS NULL OR m.kind = $1) ORDER BY m.created_at DESC LIMIT $2`,
            [req.query.kind && ['manual', 'test', 'automatic'].includes(req.query.kind) ? req.query.kind : null, limit]);
        res.json({ messages: r.rows });
    }));
    router.get('/messages/:id', wrapRoute(async (req, res) => {
        if (!isUuid(req.params.id)) return fail(res, 404, 'not_found', 'Not found');
        const m = (await pool.query(`SELECT m.*, COALESCE(a.name, m.created_by) AS created_by_name FROM notify_messages m LEFT JOIN di_allowlist a ON a.researcher_id = m.created_by WHERE m.id = $1`, [req.params.id])).rows[0];
        if (!m) return fail(res, 404, 'not_found', 'Not found');
        const r = await pool.query(`SELECT id, researcher_id, name, email, reason, status, skip_reason, provider_id, error, attempts,
                queued_at, first_attempt_at, last_attempt_at, accepted_at, delivered_at FROM notify_recipients WHERE message_id = $1 ORDER BY name`, [m.id]);
        const sample = (await pool.query(`SELECT sent_subject, sent_text FROM notify_recipients WHERE message_id = $1 ORDER BY name LIMIT 1`, [m.id])).rows[0] || null;
        res.json({ message: m, recipients: r.rows, sample, sending: running.has(m.id) });
    }));

    // ---------------------------------------------------------- templates
    router.get('/templates', wrapRoute(async (req, res) => {
        const r = await pool.query(`SELECT id, name, category, subject, body, archived_at, created_by, updated_at FROM notify_templates ORDER BY archived_at NULLS FIRST, name`);
        res.json({ system: SYSTEM_TEMPLATES, templates: r.rows });
    }));
    function templateInput(b) {
        const name = notify.oneLine(b.name, 120), subject = String(b.subject || ''), body = String(b.body || '');
        const category = notify.oneLine(b.category || 'general', 40) || 'general';
        if (!name) return { error: 'Name is required.' };
        const probs = contentProblems(subject, body, { meetingGroup: { name: 'x', zoom: 'x' } }); // variables are checked again when sending
        if (probs.length) return { error: probs.join(' ') };
        return { name, subject, body, category };
    }
    router.post('/templates', wrapRoute(async (req, res) => {
        const t = templateInput(req.body || {});
        if (t.error) return fail(res, 400, 'invalid_template', t.error);
        const r = await pool.query(`INSERT INTO notify_templates (name, category, subject, body, created_by, updated_by) VALUES ($1,$2,$3,$4,$5,$5) RETURNING id`,
            [t.name, t.category, t.subject, t.body, actor(req)]);
        res.json({ id: r.rows[0].id });
    }));
    router.put('/templates/:id', wrapRoute(async (req, res) => {
        if (!isUuid(req.params.id)) return fail(res, 404, 'not_found', 'Built-in templates cannot be edited; duplicate them first.');
        const t = templateInput(req.body || {});
        if (t.error) return fail(res, 400, 'invalid_template', t.error);
        const r = await pool.query(`UPDATE notify_templates SET name=$2, category=$3, subject=$4, body=$5, updated_by=$6, updated_at=now() WHERE id=$1 RETURNING id`,
            [req.params.id, t.name, t.category, t.subject, t.body, actor(req)]);
        if (!r.rows.length) return fail(res, 404, 'not_found', 'Not found');
        res.json({ ok: true });
    }));
    router.post('/templates/:id/duplicate', wrapRoute(async (req, res) => {
        let src = SYSTEM_TEMPLATES.find(x => x.id === req.params.id);
        if (!src && isUuid(req.params.id)) src = (await pool.query(`SELECT * FROM notify_templates WHERE id = $1`, [req.params.id])).rows[0];
        if (!src) return fail(res, 404, 'not_found', 'Not found');
        const r = await pool.query(`INSERT INTO notify_templates (name, category, subject, body, created_by, updated_by) VALUES ($1,$2,$3,$4,$5,$5) RETURNING id`,
            [notify.oneLine(src.name + ' (copy)', 120), src.category, src.subject, src.body, actor(req)]);
        res.json({ id: r.rows[0].id });
    }));
    router.post('/templates/:id/archive', wrapRoute(async (req, res) => {
        if (!isUuid(req.params.id)) return fail(res, 404, 'not_found', 'Built-in templates cannot be archived.');
        const archived = (req.body || {}).archived !== false;
        const r = await pool.query(`UPDATE notify_templates SET archived_at = CASE WHEN $2 THEN now() ELSE NULL END, updated_by = $3, updated_at = now() WHERE id = $1 RETURNING id`,
            [req.params.id, archived, actor(req)]);
        if (!r.rows.length) return fail(res, 404, 'not_found', 'Not found');
        res.json({ ok: true });
    }));

    // ----------------------------------------------------------- settings
    router.put('/settings', wrapRoute(async (req, res) => {
        const b = req.body || {};
        if (b.categories && typeof b.categories === 'object') {
            for (const k of Object.keys(b.categories)) {
                const c = CATEGORIES.find(x => x.key === k);
                if (!c || !c.implemented || c.locked) return fail(res, 400, 'category_not_available', 'This category is not available yet.');
            }
        }
        if (b.manual_enabled !== undefined) await setSetting('manual', { enabled: b.manual_enabled === true }, actor(req));
        if (b.paused !== undefined) await setSetting('paused', { paused: b.paused === true }, actor(req));
        if (b.categories && typeof b.categories === 'object') {
            for (const [k, v] of Object.entries(b.categories)) await setSetting('category:' + k, { enabled: v === true }, actor(req));
        }
        log('settings', 'updated');
        const st = await settings();
        if (!st.paused) { // resume anything held by a pause or a switched-off category
            const q = await pool.query(`SELECT DISTINCT message_id FROM notify_recipients WHERE status = 'QUEUED'`);
            for (const r of q.rows) startWorker(r.message_id);
        }
        res.json({ settings: st });
    }));

    return { router, ensureSchema, recover, isCategoryEnabled, enqueueAutomatic, startWorker, idle,
             _internals: { resolveAudience, eligiblePool, renderFor, contentProblems, variablesIn, textToHtml, gate, settings } };
}

module.exports = { createNotifyCenter, renderFor, variablesIn, textToHtml, fill, SYSTEM_TEMPLATES, CATEGORIES, VARIABLES, MAX_RECIPIENTS };
