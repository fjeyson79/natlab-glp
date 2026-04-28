// ---------------------------------------------------------------------------
// Zoe tool integration for OpenClaw (OpenAI-compatible /v1/chat/completions)
// ---------------------------------------------------------------------------
// Lets Zoe call the Portal Assistant API as typed tools during a chat turn.
// Activated only when ZOE_TOOLS_ENABLED=1; otherwise the existing chat path
// runs unchanged.
//
// Design constraints honoured:
//   - Additive. No backend endpoints change. No tool names invented.
//   - Low compute. Tool calls are local HTTP round-trips to the same server
//     via 127.0.0.1 (assistant routes have no auth and resolve workspace
//     from the `ws` query param). No new DB access layer.
//   - Readable. One file owns: the tools array, the dispatcher, the loop.
//
// Env variables read:
//   PORTAL_API_BASE_URL   default http://127.0.0.1:${PORT || 8080}
//   ZOE_TOOLS_MAX_ROUNDS  default 5 (safety cap on tool-call iterations)
//   OPENCLAW_BASE_URL / _API_KEY / _AUTH_HEADER / _CHAT_PATH / _MODEL /
//   _MAX_TOKENS / _TEMPERATURE / _TIMEOUT_MS — same vars callOpenClaw uses.
// ---------------------------------------------------------------------------

'use strict';

const fetch = require('node-fetch');

const DEFAULT_MAX_ROUNDS = 5;

// ---- 1. Tool catalogue (OpenAI /v1/chat/completions tool-use format) -------

const ZOE_TOOLS = [
    {
        type: 'function',
        function: {
            name: 'get_workspace_status',
            description: 'Fetch a concise operational summary for a NatLab workspace: active projects, pending/revision GLP counts, recent uploads, and up to three attention strings. Read-only. Use for general "how are we doing" questions.',
            parameters: {
                type: 'object',
                properties: {
                    ws: { type: 'string', description: "Workspace slug, e.g. 'natlab'." }
                },
                required: ['ws']
            }
        }
    },
    {
        type: 'function',
        function: {
            name: 'get_workspace_attention',
            description: 'Fetch a prioritized list of items needing attention (pending GLP reviews, revision-needed items, stale pending, inactive projects, low upload activity). Read-only. Use when the user asks what is urgent / what to look at next.',
            parameters: {
                type: 'object',
                properties: {
                    ws:    { type: 'string', description: 'Workspace slug.' },
                    limit: { type: 'integer', minimum: 1, maximum: 10, description: 'Max items; default 5, server caps at 10.' }
                },
                required: ['ws']
            }
        }
    },
    {
        type: 'function',
        function: {
            name: 'search_files',
            description: 'Search workspace files by title/filename substring. Returns a best_match plus alternatives with file_id, title, file_type, GLP status, and a short match reason. Always call this before open_file_in_portal — it is the only way to obtain a valid file_id.',
            parameters: {
                type: 'object',
                properties: {
                    ws:         { type: 'string', description: 'Workspace slug.' },
                    q:          { type: 'string', description: 'Query text to match against title/filename.' },
                    researcher: { type: 'string', description: "Optional uploader display-name substring." },
                    project_id: { type: 'string', description: 'Optional rd_projects.id UUID filter.' },
                    file_type:  { type: 'string', description: "Optional file type ('SOP','DATA','PRES','REPORT','DOCS')." },
                    status:     { type: 'string', enum: ['PENDING','APPROVED','REVISION_NEEDED','DISCARDED'], description: 'Optional GLP status filter; DISCARDED excluded unless requested.' },
                    limit:      { type: 'integer', minimum: 1, maximum: 5, description: 'Max results; default 3, server caps at 5.' }
                },
                required: ['ws', 'q']
            }
        }
    },
    {
        type: 'function',
        function: {
            name: 'get_researcher_report',
            description: "GLP-oriented report for one researcher: upload/approved/pending/revision counts, compliance signal (strong/moderate/weak), flags, priority review files. Path :id is the di_allowlist short code (e.g. 'HJM'), NOT a display name.",
            parameters: {
                type: 'object',
                properties: {
                    id:     { type: 'string', description: "Researcher short code, e.g. 'HJM'." },
                    ws:     { type: 'string', description: 'Workspace slug.' },
                    window: { type: 'string', description: "Time window as 'Nd', e.g. '7d', '30d', '90d'. Default '30d'." }
                },
                required: ['id', 'ws']
            }
        }
    },
    {
        type: 'function',
        function: {
            name: 'open_file_in_portal',
            description: "Queue a viewer command that opens a specific file on the user's registered portal tab. Call ONLY after search_files returned a concrete file_id. Requires a pre-existing control_session_id supplied by the portal; never invent one. Do not call twice in a row for the same file_id in the same intent.",
            parameters: {
                type: 'object',
                properties: {
                    ws:                 { type: 'string', description: 'Workspace slug.' },
                    control_session_id: { type: 'string', description: 'Active control session UUID (provided by portal context).' },
                    file_id:            { type: 'string', description: 'rd_documents.id UUID from search_files.' }
                },
                required: ['ws', 'control_session_id', 'file_id']
            }
        }
    },
    // ---- Phase 1 file-visibility tools (assistant_file_index) -------------
    // These hit the new /map, /search (extended), and /researcher endpoints.
    // search_files (above) is preserved for the original di_submissions flow
    // so existing behavior is untouched.
    {
        type: 'function',
        function: {
            name: 'list_files_map',
            description: "Grouped overview of every R2 file Zoe knows about: counts by workspace, affiliation, researcher, year, and file_type. Read-only. Use when the user wants a structural answer ('how many DATA files do we have', 'which years have SOPs', 'what is in the Theralia bucket'). All filters optional — pass them when the user pre-narrows the scope.",
            parameters: {
                type: 'object',
                properties: {
                    workspace:   { type: 'string', description: "Workspace slug filter (e.g. 'natlab', 'theralia')." },
                    affiliation: { type: 'string', description: "Affiliation filter (LiU, UNAV, EXTERNAL, THERALIA)." },
                    researcher:  { type: 'string', description: "Researcher short code, e.g. 'MC', 'HJM'." },
                    year:        { type: 'integer', description: "Four-digit year filter, e.g. 2026." },
                    file_type:   { type: 'string', description: "DATA | SOP | PRESENTATION | REPORT | PAPER | TRAINING | INVENTORY." },
                    status:      { type: 'string', description: "SUBMITTED | APPROVED | REVISION_NEEDED | DISCARDED | TRAINING | LEGACY." }
                }
            }
        }
    },
    {
        type: 'function',
        function: {
            name: 'search_files_indexed',
            description: "Keyword + metadata search across the assistant file index. Searches filename, r2_key, topic, text_preview, tags and (when search_scope ∈ {content, all}) the full extracted PDF text. Returns ranked results with score + match_reasons. Use this — NOT search_files — whenever the user asks about file content (\"find files about chicken embryo\", \"SOPs mentioning RNA extraction\") or wants to filter on workspace / affiliation / year. q is optional when at least one filter is supplied (e.g. all LiU DATA from 2026).",
            parameters: {
                type: 'object',
                properties: {
                    q:            { type: 'string',  description: "Free-text query. Optional when filters are provided." },
                    search_scope: { type: 'string',  enum: ['metadata', 'content', 'all'], description: "Where to look. Default 'all'." },
                    workspace:    { type: 'string',  description: "Workspace slug filter." },
                    affiliation:  { type: 'string',  description: "Affiliation filter (LiU, UNAV, EXTERNAL, THERALIA)." },
                    researcher:   { type: 'string',  description: "Researcher short code, e.g. 'MC'." },
                    year:         { type: 'integer', description: "Four-digit year filter." },
                    file_type:    { type: 'string',  description: "DATA | SOP | PRESENTATION | REPORT | PAPER | TRAINING | INVENTORY." },
                    status:       { type: 'string',  description: "SUBMITTED | APPROVED | REVISION_NEEDED | DISCARDED | TRAINING | LEGACY." },
                    limit:        { type: 'integer', minimum: 1, maximum: 50, description: "Max results; default 10, server caps at 50." }
                }
            }
        }
    },
    {
        type: 'function',
        function: {
            name: 'list_researcher_files',
            description: "All indexed files for one researcher, grouped by year and file_type. Path-style lookup: takes the researcher short code (e.g. 'MC' for Marina Chandrou) — resolve display names to codes before calling.",
            parameters: {
                type: 'object',
                properties: {
                    code: { type: 'string', description: "Researcher short code, e.g. 'MC' or 'HJM'." }
                },
                required: ['code']
            }
        }
    }
];

// ---- 2. Short system-prompt note appended when tools are enabled ----------

const ZOE_TOOLS_SYSTEM_NOTE =
    'You can call tools to reach the NatLab Portal Assistant API. Guardrails:\n' +
    '- Use get_workspace_status for general portal state.\n' +
    '- Use get_workspace_attention when the user asks what is urgent.\n' +
    '- Always call search_files before open_file_in_portal — never guess a file_id.\n' +
    '- Never invent control_session_id. If it is missing from context (e.g. Telegram), say you can only open files when the user is on the portal, instead of calling open_file_in_portal.\n' +
    '- Do not call open_file_in_portal twice for the same file_id in the same intent. If the user says "open it again", tell them it is already queued.\n' +
    '- For content-aware questions ("find files mentioning X", "what does the chicken embryo SOP say"), use search_files_indexed — NOT search_files. search_files only matches filename/title.\n' +
    '- For structural questions ("how many DATA files do we have", "what years have UNAV SOPs"), use list_files_map.\n' +
    '- For "all files from researcher X", use list_researcher_files with their short code (MC, HJM, etc.). If the user says a full name, map it to the short code before calling.\n' +
    '- Indexed-flow contract (search_files_indexed, list_researcher_files, /api/assistant/files/indexed/:id): each result carries `id` (assistant_file_index id, NOT openable), `portal_file_id` (rd_documents id, the one open_file_in_portal needs), and `can_open_in_portal`. Only call open_file_in_portal when can_open_in_portal is true; pass portal_file_id as file_id. When can_open_in_portal is false, tell the user the file was found in R2 but is not linked to a portal-openable document.\n' +
    '- list_files_map returns counts only — no file ids. Use it for structural answers, not for opening.\n' +
    '- Briefly explain what you found and why; do not act like a search box. When ambiguous, mention the strongest match plus useful alternatives.';

// ---- 3. Tool dispatcher ---------------------------------------------------
// Hits the same server over localhost. Assistant routes resolve the workspace
// from the `ws` query/body param and do not require auth.

function portalBase() {
    return process.env.PORTAL_API_BASE_URL
        || ('http://127.0.0.1:' + (process.env.PORT || '8080'));
}

async function callPortal(method, pathAndQuery, body) {
    const url = portalBase().replace(/\/$/, '') + pathAndQuery;
    const init = { method, headers: {} };
    if (body !== undefined) {
        init.headers['Content-Type'] = 'application/json';
        init.body = JSON.stringify(body);
    }
    const r = await fetch(url, init);
    const text = await r.text();
    let data = {};
    try { data = JSON.parse(text); } catch (_) { data = { raw: text }; }
    return { ok: r.ok, status: r.status, data };
}

function qs(obj) {
    const parts = [];
    for (const k of Object.keys(obj)) {
        const v = obj[k];
        if (v === undefined || v === null || v === '') continue;
        parts.push(encodeURIComponent(k) + '=' + encodeURIComponent(String(v)));
    }
    return parts.length ? ('?' + parts.join('&')) : '';
}

async function dispatchZoeToolCall(name, args, ctx) {
    args = args || {};
    ctx  = ctx  || {};
    switch (name) {
        case 'get_workspace_status': {
            return await callPortal('GET', '/api/assistant/status' + qs({ ws: args.ws }));
        }
        case 'get_workspace_attention': {
            return await callPortal('GET', '/api/assistant/attention' + qs({ ws: args.ws, limit: args.limit }));
        }
        case 'search_files': {
            return await callPortal('GET', '/api/assistant/files/search' + qs({
                ws: args.ws, q: args.q, researcher: args.researcher,
                project_id: args.project_id, file_type: args.file_type,
                status: args.status, limit: args.limit
            }));
        }
        case 'get_researcher_report': {
            const id = encodeURIComponent(String(args.id || ''));
            return await callPortal('GET', '/api/assistant/researchers/' + id + '/report'
                + qs({ ws: args.ws, window: args.window }));
        }
        case 'list_files_map': {
            return await callPortal('GET', '/api/assistant/files/map' + qs({
                workspace: args.workspace, affiliation: args.affiliation,
                researcher: args.researcher, year: args.year,
                file_type: args.file_type, status: args.status
            }));
        }
        case 'search_files_indexed': {
            // search_scope is always set so the route's new-flow trigger
            // fires even when the model omits every filter and passes only q.
            // Without it, /search would fall through to the legacy
            // di_submissions handler — which is reserved for search_files.
            return await callPortal('GET', '/api/assistant/files/search' + qs({
                q: args.q, search_scope: args.search_scope || 'all',
                workspace: args.workspace, affiliation: args.affiliation,
                researcher: args.researcher, year: args.year,
                file_type: args.file_type, status: args.status,
                limit: args.limit,
                // ws is sent as a no-op anchor; the new flow ignores it,
                // and the legacy flow won't run because search_scope is set.
                ws: args.workspace || 'natlab'
            }));
        }
        case 'list_researcher_files': {
            const code = encodeURIComponent(String(args.code || '').trim().toUpperCase());
            return await callPortal('GET', '/api/assistant/files/researcher/' + code);
        }
        case 'open_file_in_portal': {
            // Prefer an explicit arg; fall back to the control_session_id the
            // caller (web /api/zoe/chat) may have threaded in via ctx. Telegram
            // has no control_session_id — reject cleanly instead of inventing.
            const csid = args.control_session_id || ctx.controlSessionId;
            if (!csid) {
                return { ok: false, status: 400, data: {
                    error: 'control_session_id not available in this context (e.g. Telegram). Ask the user to open the portal dashboard and try again.'
                }};
            }
            return await callPortal('POST', '/api/assistant/viewer/open', {
                ws: args.ws, control_session_id: csid, file_id: args.file_id
            });
        }
        default:
            return { ok: false, status: 400, data: { error: 'Unknown tool: ' + name } };
    }
}

// ---- 4. Tool-aware chat loop ----------------------------------------------
// Calls OpenClaw, executes any returned tool_calls, feeds results back, and
// stops when OpenClaw returns a normal message (or when MAX_ROUNDS hits).

async function postChatCompletions(messages) {
    const baseUrl = process.env.OPENCLAW_BASE_URL;
    if (!baseUrl) {
        return { reply: '[Zoe offline] OPENCLAW_BASE_URL is not configured.' };
    }
    const timeoutMs = parseInt(process.env.OPENCLAW_TIMEOUT_MS || '60000', 10);
    const headers = { 'Content-Type': 'application/json' };
    if (process.env.OPENCLAW_API_KEY) {
        const authHeader = process.env.OPENCLAW_AUTH_HEADER || 'Authorization';
        headers[authHeader] = (authHeader.toLowerCase() === 'authorization')
            ? 'Bearer ' + process.env.OPENCLAW_API_KEY
            : process.env.OPENCLAW_API_KEY;
    }
    let chatPath = process.env.OPENCLAW_CHAT_PATH || '/v1/chat/completions';
    if (!chatPath.startsWith('/')) chatPath = '/' + chatPath;
    const url = baseUrl.replace(/\/$/, '') + chatPath;
    const body = {
        model: process.env.OPENCLAW_MODEL || 'default',
        messages,
        tools: ZOE_TOOLS,
        tool_choice: 'auto'
    };
    if (process.env.OPENCLAW_MAX_TOKENS)  body.max_tokens  = parseInt(process.env.OPENCLAW_MAX_TOKENS, 10);
    if (process.env.OPENCLAW_TEMPERATURE) body.temperature = parseFloat(process.env.OPENCLAW_TEMPERATURE);

    const fetchPromise = fetch(url, { method: 'POST', headers, body: JSON.stringify(body) });
    const timeoutPromise = new Promise((_, reject) =>
        setTimeout(() => reject(new Error('TIMEOUT_' + timeoutMs + 'ms')), timeoutMs)
    );
    try {
        const r = await Promise.race([fetchPromise, timeoutPromise]);
        const text = await r.text();
        let data = {};
        try { data = JSON.parse(text); } catch (_) { data = { reply: text }; }
        if (!r.ok) {
            return { reply: '[Zoe upstream error] HTTP ' + r.status + ' — ' + (text || '').slice(0, 200) };
        }
        const choice = data && data.choices && data.choices[0];
        const msg = choice && choice.message;
        return { choice, msg };
    } catch (err) {
        if (err && typeof err.message === 'string' && err.message.startsWith('TIMEOUT_')) {
            return { reply: '[Zoe timeout] Upstream did not respond in time.' };
        }
        return { reply: '[Zoe connectivity error] ' + (err && err.message ? err.message : String(err)) };
    }
}

async function runZoeToolAwareChat(payload, ctx) {
    // Build the initial messages array. Same shape zoeBuildChatCompletionsBody
    // uses, plus the tools-system note.
    const messages = [];
    if (payload.system) messages.push({ role: 'system', content: String(payload.system) });
    messages.push({ role: 'system', content: ZOE_TOOLS_SYSTEM_NOTE });
    const ctxBits = [];
    if (payload.mode)          ctxBits.push('Mode: ' + payload.mode);
    if (payload.workspace)     ctxBits.push('Workspace: ' + payload.workspace);
    if (payload.selected_file) ctxBits.push('Selected file: ' + JSON.stringify(payload.selected_file).slice(0, 2000));
    if (payload.glp_context)   ctxBits.push('GLP Vision context: ' + JSON.stringify(payload.glp_context).slice(0, 1000));
    if (payload.portal_summary) ctxBits.push('Portal summary: ' + JSON.stringify(payload.portal_summary).slice(0, 1000));
    if (ctx && ctx.controlSessionId) ctxBits.push('Portal control_session_id available: ' + ctx.controlSessionId);
    if (ctxBits.length) messages.push({ role: 'system', content: ctxBits.join('\n') });
    messages.push({ role: 'user', content: String(payload.message || '').slice(0, 120000) });

    const maxRounds = parseInt(process.env.ZOE_TOOLS_MAX_ROUNDS || String(DEFAULT_MAX_ROUNDS), 10);
    const openedFiles = new Set();  // per-turn dedupe for open_file_in_portal

    for (let round = 0; round < maxRounds; round++) {
        const resp = await postChatCompletions(messages);
        if (resp.reply) return { reply: resp.reply };          // error / terminal string
        const msg = resp.msg;
        if (!msg) return { reply: '(no content)' };

        const toolCalls = msg.tool_calls || [];
        if (!toolCalls.length) {
            return { reply: msg.content || '(no content)' };
        }

        // Record the assistant message that carried the tool_calls, then
        // append one `tool` message per call with the dispatcher result.
        messages.push(msg);
        for (const tc of toolCalls) {
            const name = tc && tc.function && tc.function.name;
            let args = {};
            try { args = JSON.parse((tc.function && tc.function.arguments) || '{}'); } catch (_) {}
            console.log('[ZOE/tool] ' + name + ' args=' + JSON.stringify(args).slice(0, 300));

            let result;
            if (name === 'open_file_in_portal' && args.file_id && openedFiles.has(args.file_id)) {
                result = { ok: false, status: 409, data: { error: 'Already opened this file earlier in this turn. Do not re-queue.' } };
            } else {
                result = await dispatchZoeToolCall(name, args, ctx);
                if (name === 'open_file_in_portal' && result.ok && args.file_id) openedFiles.add(args.file_id);
            }

            messages.push({
                role: 'tool',
                tool_call_id: tc.id,
                content: JSON.stringify(result).slice(0, 8000)
            });
        }
    }
    return { reply: '[Zoe] stopped after ' + maxRounds + ' tool rounds without a final answer.' };
}

module.exports = {
    ZOE_TOOLS,
    ZOE_TOOLS_SYSTEM_NOTE,
    dispatchZoeToolCall,
    runZoeToolAwareChat
};
