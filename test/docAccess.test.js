'use strict';
const test = require('node:test');
const assert = require('node:assert');
const d = require('../server/docAccess');

const pi = { role: 'pi', researcher_id: 'PI1' };
const bot = { role: 'ai_bot', researcher_id: 'BOT' };
const res = { role: 'researcher', researcher_id: 'R1' };
const sup = { role: 'supervisor', researcher_id: 'S1' };
const inv = { role: 'investor', researcher_id: 'I1' };
const base = { isOwner: false, isShareRecipient: false, isAssignedSupervisor: false, ownsThread: false, isAssociatedWithOwnFile: false,
  isApprovedSop: false, natlabMember: true, workspaceType: 'LAB', workspaceMember: false, investorTabs: {} };

test('R1b-1 ships in shadow mode', () => { assert.strictEqual(d.ENFORCE, false); });

test('submission: PI and AI bot always allowed', () => {
  assert.strictEqual(d.decideSubmission(pi, base).allow, true);
  assert.strictEqual(d.decideSubmission(bot, base).allow, true);
});

test('submission: owner, share, supervisor, thread, association allowed', () => {
  for (const k of ['isOwner', 'isShareRecipient', 'isAssignedSupervisor', 'ownsThread', 'isAssociatedWithOwnFile']) {
    assert.strictEqual(d.decideSubmission(res, { ...base, [k]: true }).allow, true, k);
  }
});

test('submission: other researcher non-SOP file denied', () => {
  const r = d.decideSubmission(res, base);
  assert.strictEqual(r.allow, false); assert.strictEqual(r.rule, 'no_matching_rule');
});

test('submission: approved SOP only for NAT-Lab members', () => {
  assert.strictEqual(d.decideSubmission(res, { ...base, isApprovedSop: true }).allow, true);
  const r = d.decideSubmission(res, { ...base, isApprovedSop: true, natlabMember: false });
  assert.strictEqual(r.allow, false); assert.strictEqual(r.rule, 'approved_sop_not_natlab_member');
});

test('submission: company workspace member; investors need rnd or glp_vision tab', () => {
  const co = { ...base, natlabMember: false, workspaceType: 'COMPANY', workspaceMember: true };
  assert.strictEqual(d.decideSubmission(res, co).allow, true);
  assert.strictEqual(d.decideSubmission(inv, co).allow, false);
  assert.strictEqual(d.decideSubmission(inv, { ...co, investorTabs: { glp_vision: true } }).allow, true);
  assert.strictEqual(d.decideSubmission(res, { ...co, workspaceMember: false }).allow, false);
});

test('workspace documents: membership of the document workspace, investor tab when required', () => {
  const f = { workspaceId: 'w', workspaceMember: true, investorTabs: {} };
  assert.strictEqual(d.decideWorkspaceDoc(res, f, 'company').allow, true);
  assert.strictEqual(d.decideWorkspaceDoc(res, { ...f, workspaceMember: false }, null).allow, false);
  assert.strictEqual(d.decideWorkspaceDoc(inv, f, 'company').allow, false);
  assert.strictEqual(d.decideWorkspaceDoc(inv, { ...f, investorTabs: { company: true } }, 'company').allow, true);
  assert.strictEqual(d.decideWorkspaceDoc(inv, f, null).allow, true);
  assert.strictEqual(d.decideWorkspaceDoc(res, { ...f, workspaceId: null }, null).allow, false);
  assert.strictEqual(d.decideWorkspaceDoc(pi, { workspaceMember: false }, 'company').allow, true);
});

test('NAT-Lab documents, training certificates, system versions', () => {
  assert.strictEqual(d.decideNatlabDoc(res, { natlabMember: true }).allow, true);
  assert.strictEqual(d.decideNatlabDoc(res, { natlabMember: false }).allow, false);
  assert.strictEqual(d.decideTrainingCertificate(res, { isOwner: true }).allow, true);
  assert.strictEqual(d.decideTrainingCertificate(sup, { isAssignedSupervisor: true }).allow, true);
  assert.strictEqual(d.decideTrainingCertificate(res, { isOwner: false }).allow, false);
  assert.strictEqual(d.decidePiOnly(res).allow, false);
  assert.strictEqual(d.decidePiOnly(bot).allow, true);
});

test('actor hash is short and not the researcher id', () => {
  const h = d.actorHash(res);
  assert.match(h, /^h:[0-9a-f]{10}$/); assert.ok(!h.includes('R1'));
});
