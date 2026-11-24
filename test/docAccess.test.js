'use strict';
const test = require('node:test');
const assert = require('node:assert');
const d = require('../server/docAccess');

const pi = { role: 'pi', researcher_id: 'PI1' };
const bot = { role: 'ai_bot', researcher_id: 'BOT' };
const res = { role: 'researcher', researcher_id: 'R1' };
const sup = { role: 'supervisor', researcher_id: 'S1' };
const inv = { role: 'investor', researcher_id: 'I1' };
const founder = { role: 'founder', researcher_id: 'F1' };
const base = { isOwner: false, isShareRecipient: false, isAssignedSupervisor: false, ownsThread: false, isAssociatedWithOwnFile: false,
  isApprovedSop: false, natlabMember: true, workspaceType: 'LAB', workspaceMember: false, investorTabs: {} };

// ------------------------------------------------------- configuration (D6)
test('DOC_ACCESS_ENFORCE: explicit modes, secure default, invalid values never weaken', () => {
  assert.deepStrictEqual(d.MODES, ['off', 'cross_workspace', 'all']);
  assert.strictEqual(d.parseEnforceMode(undefined).mode, 'cross_workspace');
  assert.strictEqual(d.parseEnforceMode('').source, 'default');
  for (const m of d.MODES) assert.deepStrictEqual([d.parseEnforceMode(m).mode, d.parseEnforceMode(m).ok], [m, true]);
  assert.strictEqual(d.parseEnforceMode(' ALL ').mode, 'all');
  for (const bad of ['shadow', 'true', 'false', '0', '1', 'cross-workspace', 'off ;rm', 'enforce']) {
    const c = d.parseEnforceMode(bad);
    assert.strictEqual(c.mode, 'all', bad); assert.strictEqual(c.ok, false, bad); assert.match(c.diagnostic, /strictest mode \(all\)/);
  }
});

test('enforcement by mode and scope', () => {
  const ws = { allow: false, scope: 'workspace' }, rel = { allow: false, scope: 'relationship' }, ok = { allow: true };
  assert.deepStrictEqual(['off', 'cross_workspace', 'all'].map(m => d.isEnforced(ws, m)), [false, true, true]);
  assert.deepStrictEqual(['off', 'cross_workspace', 'all'].map(m => d.isEnforced(rel, m)), [false, false, true]);
  assert.deepStrictEqual(['off', 'cross_workspace', 'all'].map(m => d.isEnforced(ok, m)), [false, false, false]);
});

// ------------------------------------------------------- submissions
test('submission: PI always allowed; the retired AI assistant never (workspace scope)', () => {
  assert.strictEqual(d.decideSubmission(pi, base).allow, true);
  for (const f of [base, { ...base, isOwner: true }, { ...base, workspaceType: 'COMPANY', workspaceMember: true }]) {
    const r = d.decideSubmission(bot, f);
    assert.deepStrictEqual([r.allow, r.rule, r.scope], [false, 'ai_bot_access_retired', 'workspace']);
  }
});

test('submission (lab): owner, share, assigned supervisor, thread, association allowed for lab members', () => {
  for (const k of ['isOwner', 'isShareRecipient', 'isAssignedSupervisor', 'ownsThread', 'isAssociatedWithOwnFile']) {
    assert.strictEqual(d.decideSubmission(res, { ...base, [k]: true }).allow, true, k);
  }
});

test('submission (lab): other researcher non-SOP file denied at relationship scope; unassigned supervisor too (D8)', () => {
  const r = d.decideSubmission(res, base);
  assert.deepStrictEqual([r.allow, r.rule, r.scope], [false, 'no_matching_rule', 'relationship']);
  assert.strictEqual(d.decideSubmission(sup, base).scope, 'relationship');
  assert.strictEqual(d.decideSubmission(sup, { ...base, isApprovedSop: true }).allow, true, 'approved SOPs remain readable');
});

test('submission (lab): approved SOP for lab members incl. collaborators (D2); never for non-lab accounts (D3)', () => {
  assert.strictEqual(d.decideSubmission(res, { ...base, isApprovedSop: true }).allow, true);
  for (const u of [res, founder, inv]) {
    const r = d.decideSubmission(u, { ...base, isApprovedSop: true, natlabMember: false });
    assert.deepStrictEqual([r.allow, r.rule, r.scope], [false, 'not_lab_member', 'workspace'], u.role);
    // even a share, supervision, thread or association does not replace lab membership
    assert.strictEqual(d.decideSubmission(u, { ...base, natlabMember: false, isShareRecipient: true, ownsThread: true, isAssociatedWithOwnFile: true }).allow, false);
  }
  assert.strictEqual(d.decideSubmission(founder, { ...base, natlabMember: false, isOwner: true }).allow, true, 'owners keep their own documents');
});

test('submission (company): members of the document workspace only; investors need rnd or glp_vision tab', () => {
  const co = { ...base, natlabMember: false, workspaceType: 'COMPANY', workspaceMember: true };
  assert.strictEqual(d.decideSubmission(founder, co).allow, true);
  assert.deepStrictEqual([d.decideSubmission(inv, co).allow, d.decideSubmission(inv, co).scope], [false, 'relationship']);
  assert.strictEqual(d.decideSubmission(inv, { ...co, investorTabs: { glp_vision: true } }).allow, true);
  // NAT-Lab membership, approved SOP status, shares etc. never open a company document (D3)
  const nonMember = { ...co, workspaceMember: false, natlabMember: true, isApprovedSop: true, isShareRecipient: true, isAssignedSupervisor: true };
  const r = d.decideSubmission(res, nonMember);
  assert.deepStrictEqual([r.allow, r.rule, r.scope], [false, 'not_member_of_document_workspace', 'workspace']);
  assert.strictEqual(d.decideSubmission(pi, nonMember).allow, true);
});

// ------------------------------------------------------- other categories
test('workspace documents: membership of the document workspace, investor tab when required', () => {
  const f = { workspaceId: 'w', workspaceMember: true, investorTabs: {} };
  assert.strictEqual(d.decideWorkspaceDoc(founder, f, 'company').allow, true);
  assert.deepStrictEqual(d.decideWorkspaceDoc(res, { ...f, workspaceMember: false }, null), { allow: false, rule: 'not_member_of_document_workspace', scope: 'workspace' });
  assert.strictEqual(d.decideWorkspaceDoc(inv, f, 'company').scope, 'relationship');
  assert.strictEqual(d.decideWorkspaceDoc(inv, { ...f, investorTabs: { company: true } }, 'company').allow, true);
  assert.strictEqual(d.decideWorkspaceDoc(inv, f, null).allow, true);
  assert.strictEqual(d.decideWorkspaceDoc(res, { ...f, workspaceId: null }, null).scope, 'workspace');
  assert.strictEqual(d.decideWorkspaceDoc(pi, { workspaceMember: false }, 'company').allow, true);
  assert.strictEqual(d.decideWorkspaceDoc(bot, f, null).rule, 'ai_bot_access_retired');
});

test('NAT-Lab documents, training certificates, system versions', () => {
  assert.strictEqual(d.decideNatlabDoc(res, { natlabMember: true }).allow, true);
  assert.deepStrictEqual(d.decideNatlabDoc(founder, { natlabMember: false }), { allow: false, rule: 'not_lab_member', scope: 'workspace' });
  assert.strictEqual(d.decideNatlabDoc(bot, { natlabMember: true }).allow, false);
  assert.strictEqual(d.decideTrainingCertificate(res, { isOwner: true, natlabMember: true }).allow, true);
  assert.strictEqual(d.decideTrainingCertificate(sup, { isAssignedSupervisor: true, natlabMember: true }).allow, true);
  assert.strictEqual(d.decideTrainingCertificate(res, { natlabMember: true }).scope, 'relationship');
  assert.strictEqual(d.decideTrainingCertificate(founder, { natlabMember: false }).scope, 'workspace');
  assert.strictEqual(d.decidePiOnly(res, { natlabMember: true }).scope, 'relationship');
  assert.strictEqual(d.decidePiOnly(founder, { natlabMember: false }).scope, 'workspace');
  assert.strictEqual(d.decidePiOnly(bot, {}).allow, false);
  assert.strictEqual(d.decidePiOnly(pi, {}).allow, true);
});

test('actor hash is short and not the researcher id', () => {
  const h = d.actorHash(res);
  assert.match(h, /^h:[0-9a-f]{10}$/); assert.ok(!h.includes('R1'));
});

test('access-denied responses: readable page for browsers, JSON for API calls', () => {
  const mk = (accept) => { const r = { code: 0, body: null, t: null, status(c) { this.code = c; return this; }, type(t) { this.t = t; return this; }, send(b) { this.body = b; return this; }, json(b) { this.body = b; return this; } }; d.sendDenied({ headers: { accept } }, r); return r; };
  const html = mk('text/html,application/xhtml+xml');
  assert.strictEqual(html.code, 403); assert.match(html.body, /You do not have permission to open this document/);
  const api = mk('application/json');
  assert.deepStrictEqual([api.code, api.body], [403, { error: 'Access denied', code: 'document_access_denied' }]);
});
