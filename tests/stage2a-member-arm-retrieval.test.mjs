import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';
import { canonicalBytes } from '../sdk/wire/canonical-json.mjs';
import { createStage2aMemberArmExchange } from '../hq/stage2a-relay-peer.mjs';

const sha = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const clock = Date.parse('2026-11-23T18:30:03Z');
const issued = '2026-11-23T18:30:02Z';
const expires = '2026-11-23T18:30:08Z';

test('two B arm pairs are retrievable only on their still-bound broker connection', async () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const machinePublicKey = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const signed = (payload, purpose) => {
    const raw = canonicalBytes(payload);
    return canonicalBytes({ schema_version: 1, purpose,
      issuer_public_key_base64url: machinePublicKey.toString('base64url'),
      payload_sha256: sha(raw), payload_base64url: raw.toString('base64url'),
      signature_base64url: sign(null, Buffer.concat([Buffer.from(`${purpose}\0`), raw]),
        privateKey).toString('base64url') });
  };
  const selectors = { installation_id: 'inst_fixture', start_id: `st_${'1'.repeat(24)}`,
    plan_id: 'plan-fixture', plan_digest: '2'.repeat(64), reservation_digest: sha('reservation'),
    assignment_envelope_sha256: '', authority_envelope_sha256: sha('B authority'),
    member_selectors_sha256: sha('selectors') };
  const members = ['m_lead', 'm_spec'].map((id, i) => ({ member_id: id,
    member_selector: `mb_${String(i + 3).repeat(64)}`,
    launch_id: `ln_${String(i + 5).repeat(24)}`, command_sha256: sha('command') }));
  const assignment = { profile_in_force: 'managed-protected', host_id: 'host-fixture',
    installation_id: selectors.installation_id, soul_id: 'agent_fixture',
    start_id: selectors.start_id, hq_epoch: '7'.repeat(64),
    reservation_sha256: selectors.reservation_digest, runner_uid: 331, runner_gid: 331,
    members, issued_at: issued, expires_at: expires };
  const assignmentBytes = signed(assignment, 'agent-bot/stage2a-member-set-assignment/v1');
  selectors.assignment_envelope_sha256 = sha(assignmentBytes);
  const map = { ...Object.fromEntries(['profile_in_force', 'host_id', 'installation_id',
    'soul_id', 'start_id', 'hq_epoch'].map((field) => [field, assignment[field]])),
    assignment_envelope_sha256: sha(assignmentBytes), runtime_state: 'provisional',
    acp_authority: 'withheld', members: members.map((m, i) => ({ member_id: m.member_id,
      member_selector: m.member_selector, runtime_id: `runtime_${i}` })) };
  const childRows = members.map((member, i) => ({ ...member, runtime_id: `runtime_${i}`,
    grant_sha256: sha(`grant-${i}`),
    launcher_process: { pid: 4001 + i, uid: 331, gid: 331,
      start_seconds: 1795458490, start_micros: 100 + i },
    child_process: { pid: 4101 + i, parent_pid: 4001 + i, uid: 331, gid: 331,
      start_seconds: 1795458491, start_micros: 100 + i,
      executable_sha256: member.command_sha256 } }));
  const child = { ...Object.fromEntries(['profile_in_force', 'host_id', 'installation_id',
    'soul_id', 'start_id', 'hq_epoch', 'reservation_sha256']
    .map((field) => [field, assignment[field]])),
    assignment_envelope_sha256: sha(assignmentBytes), provisional_hq_mapping: map,
    provisional_hq_mapping_sha256: sha(canonicalBytes(map)), members: childRows,
    observed_at: issued, issued_at: issued, expires_at: expires };
  const childBytes = signed(child, 'agent-bot/stage2a-member-set-child-observation/v1');
  let connected = true;
  const provider = { schema: { $id: 'https://example.test/arm', type: 'object' },
    childObservationSchema: { $id: 'https://example.test/observation', type: 'object' },
    observe: async () => ({ envelopeBytes: childBytes, assignmentBytes, machinePublicKey,
      provisionalMappingSHA256: sha(canonicalBytes(map)),
      memberGrants: childRows.map((m) => ({ member_id: m.member_id,
        member_selector: m.member_selector, launch_id: m.launch_id,
        grant_sha256: m.grant_sha256, launcher_process: m.launcher_process })) }),
    recordArm: async () => true };
  const exchange = createStage2aMemberArmExchange({ provider, current: () => connected,
    boundStart: async () => ({ ...selectors, bridge_uid: 332 }), clock: { now: () => clock } });
  const connection = 'bb_fixture', receipt = 'a'.repeat(64);
  for (const [i, member] of members.entries()) {
    const observed = await exchange.observe({ kind: 'bridge.member.observe.v3.request', selectors,
      member_id: member.member_id, member_selector: member.member_selector,
      observe_nonce: String(i + 8).repeat(64) }, { connection }, receipt);
    assert.equal(observed.child_observation_envelope_sha256, sha(childBytes));
    const arm = { member_id: member.member_id, member_selector: member.member_selector,
      runtime_id: `runtime_${i}`, child_observation_envelope_sha256: sha(childBytes),
      bridge_uid: 332, adapter_pid: 4101 + i, adapter_uid: 331, adapter_gid: 331,
      adapter_start_seconds: 1795458491, adapter_start_micros: 100 + i,
      state: 'armed', armed_at: '2026-11-23T18:30:03Z' };
    const result = await exchange.arm({ kind: 'bridge.member.arm.v3.request', selectors,
      member_id: member.member_id, member_selector: member.member_selector,
      observe_nonce: String(i + 8).repeat(64), arm_nonce: String(i + 5).repeat(64),
      child_observation_envelope_sha256: sha(childBytes), bridge_arm: arm,
      bridge_arm_receipt_sha256: sha(canonicalBytes(arm)) }, { connection }, receipt);
    assert.equal(result.state, 'recorded-pending-aggregate-ready');
  }
  const pairs = await exchange.armsFor(selectors, sha(Buffer.from(receipt)));
  assert.deepEqual(pairs.arms.map((pair) => pair.arm_request.member_id), ['m_lead', 'm_spec']);
  assert.equal(pairs.child_observation_envelope_sha256, sha(childBytes));
  connected = false;
  await assert.rejects(exchange.armsFor(selectors, sha(Buffer.from(receipt))), /unavailable/);
});
