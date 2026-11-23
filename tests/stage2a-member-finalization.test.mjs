import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { canonicalDigest } from '../sdk/wire/canonical-json.mjs';
import { prepareStage2aMemberFinalization } from '../hq/stage2a-member-finalization.mjs';

const sha = (bytes) => 'sha256:' + createHash('sha256').update(bytes).digest('hex');
const id = (digit) => 'sha256:' + digit.repeat(64);

function fixture() {
  const now = Date.now();
  const assignmentBytes = Buffer.from('signed assignment');
  const observationBytes = Buffer.from('signed observation');
  const readyBytes = Buffer.from('signed ready');
  const authorityBytes = Buffer.from('signed B authority');
  const scope = { host_id: 'host-1', installation_id: 'inst_0123456789abcdef',
    soul_id: 'soul-1', start_id: 'st_0123456789abcdef01234567',
    hq_epoch: 'a'.repeat(64), reservation_sha256: id('1') };
  const assignment = { ...scope, profile_in_force: 'managed-protected',
    plan_id: 'plan-1', plan_digest: 'b'.repeat(64), members: [] };
  const observation = { ...scope, profile_in_force: 'managed-protected',
    assignment_envelope_sha256: sha(assignmentBytes), provisional_hq_mapping_sha256: id('2'),
    members: [] };
  const ready = { ...scope, profile_in_force: 'managed-protected',
    assignment_envelope_sha256: sha(assignmentBytes),
    child_observation_envelope_sha256: sha(observationBytes),
    member_b_authority_envelope_sha256: sha(authorityBytes),
    provisional_hq_mapping_sha256: id('2'),
    issued_at: new Date(now - 500).toISOString(),
    expires_at: new Date(now + 3500).toISOString(), members: [] };
  const memberGrants = [];
  const admitted_runtimes = [];
  for (let i = 0; i < 2; i++) {
    const member_id = `member-${i}`;
    const member_selector = `selector-${i}`;
    const launch_id = `ln_${String(i).repeat(24)}`;
    const runtime_id = `runtime-${i}`;
    const grant_sha256 = id(String(i + 3));
    const launcher_process = { pid: 400 + i * 10, uid: 320, gid: 320,
      start_seconds: 1000 + i, start_micros: 1 };
    const child_process = { pid: 401 + i * 10, uid: 320, gid: 320,
      parent_pid: launcher_process.pid, process_group_id: 401 + i * 10,
      start_seconds: 1000 + i, start_micros: 2, executable_sha256: id('8') };
    const base = { member_id, member_selector, launch_id };
    assignment.members.push(base);
    observation.members.push({ ...base, runtime_id, grant_sha256,
      launcher_process, child_process });
    const bridge_arm = { member_id, member_selector, runtime_id, state: 'armed',
      child_observation_envelope_sha256: sha(observationBytes),
      adapter_pid: child_process.pid };
    ready.members.push({ ...base, runtime_id, bridge_arm,
      bridge_arm_receipt_sha256: canonicalDigest(bridge_arm) });
    memberGrants.push({ ...base, grant_sha256 });
    admitted_runtimes.push({ member_id, runtime_id });
  }
  const expected = { ...scope, profile_in_force: 'managed-protected',
    launch_id: 'ln_' + '9'.repeat(24), hq_broker_bind_receipt_sha256: id('7'),
    admitted_runtimes };
  const primaryAssignment = { ...scope, launch_id: expected.launch_id,
    plan_id: assignment.plan_id, plan_digest: assignment.plan_digest };
  return { prestarted: { assignment: { payload: assignment },
    observation: { payload: observation }, ready: { payload: ready },
    assignmentBytes, observationBytes, readyBytes, authorityBytes, memberGrants },
  expected, primaryAssignment, now };
}

test('paired finalization binds both signed observations and arm rows', () => {
  const input = fixture();
  const result = prepareStage2aMemberFinalization(input);
  assert.equal(result.sha256, sha(result.bytes));
  assert.equal(result.record.members.length, 2);
  assert.equal(result.record.ready_envelope_sha256, sha(input.prestarted.readyBytes));
  const wrongRun = fixture();
  wrongRun.primaryAssignment.launch_id = 'ln_' + '8'.repeat(24);
  assert.throws(() => prepareStage2aMemberFinalization(wrongRun), /unavailable/);
  input.prestarted.ready.payload.members[1].bridge_arm.adapter_pid += 1;
  assert.throws(() => prepareStage2aMemberFinalization(input), /unavailable/);
});
