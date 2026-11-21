import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { canonicalMembersJSON, validatedMembersPlan } from '../hq/machine-members-plans.mjs';
import { isServiceHandoff, serviceHandoffArgs } from '../hq/machine-service-recovery.mjs';
import { validSoulRunnerAccounts } from '../hq/machine-soul-runner-accounts.mjs';

const NAME = (id) => `_abm-sr-${createHash('sha256').update(id).digest('hex').slice(0, 20)}`;
const SOUL = 'agent_01234567-0123-4567-0123-456789abcdef';
const ID = 'plan-20261121T140001Z-abcd';

function plan() {
  const runners = [
    { soul_id: SOUL, installation_id: 'inst_0000000000000001', account: NAME('inst_0000000000000001') },
    { soul_id: SOUL, installation_id: 'inst_existing', account: NAME('inst_existing') },
  ];
  const members = runners.map(r => r.account).sort();
  return {
    version: 3, hq_account: '_agent-bot-hq', dir: 'none', members,
    steps: [
      { kind: 'hq-account', target: '_agent-bot-hq', action: 'none', group: '_agent-bot-hq', mode: '0700',
        detail: 'exists; dedicated; home /var/agent-bot-hq; its password is checked at apply', uid: 320, gid: 320 },
      ...members.map((name, i) => ({ kind: 'account', target: name, action: 'create', group: name, mode: '0700',
        detail: `Soul runner home /var/agent-bot-soul-runner-${name}, shell /usr/bin/false, private group, no password, no other groups`, uid: 334 + i, gid: 334 + i })),
    ],
    purpose: 'soul-runner-provision', soul_runners: runners,
  };
}

const response = (p) => {
  const plan_canonical = canonicalMembersJSON(p);
  return { state: 'found', body: { plan_id: ID,
    plan_digest: createHash('sha256').update(plan_canonical).digest('hex'), plan_canonical } };
};

test('paired HQ accepts exact two-runner plan including released installation IDs', () => {
  const p = plan();
  assert.equal(validSoulRunnerAccounts(p), true);
  assert.deepEqual(validatedMembersPlan(ID, response(p)), p);
  assert.equal(isServiceHandoff('soul-runner-provision'), true);
  assert.deepEqual(serviceHandoffArgs('soul-runner-provision', ['export', ID, '--socket', '/tmp/machine.sock']),
    { operation: 'export', id: ID, socket: '/tmp/machine.sock' });
});

test('paired HQ refuses role reuse, changed Soul identity and arbitrary account', () => {
  const edits = {
    'shared UID': p => { p.steps[2].uid = p.steps[1].uid; p.steps[2].gid = p.steps[1].gid; },
    'HQ UID': p => { p.steps[1].uid = 320; p.steps[1].gid = 320; },
    'chosen account': p => { p.soul_runners[1].account = '_abm-sr-arbitrary'; },
    'shared installation': p => { p.soul_runners[1].installation_id = p.soul_runners[0].installation_id; },
    'unknown field': p => { p.soul_runners[1].command = '/bin/sh'; },
    'wrong purpose': p => { p.purpose = 'harness-account-provision'; },
  };
  for (const [name, edit] of Object.entries(edits)) {
    const p = plan(); edit(p);
    assert.throws(() => validatedMembersPlan(ID, response(p)), /unsupported structure/, name);
  }
});
