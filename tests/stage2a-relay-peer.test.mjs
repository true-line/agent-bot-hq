import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { test } from 'node:test';
import { canonicalBytes } from '../sdk/wire/canonical-json.mjs';
import { createStage2aRelayPeerChallenge } from '../hq/stage2a-relay-peer.mjs';

const SHA = (s) => `sha256:${createHash('sha256').update(s).digest('hex')}`;
const PURPOSE = 'agent-bot/stage2a-relay-peer-attestation/v1';
const READY_PURPOSE = 'agent-bot/stage2a-member-set-ready/v1';
const now = Date.parse('2026-11-23T18:30:03Z');
const issued = '2026-11-23T18:30:03Z';
const at = '2026-11-23T18:30:02Z';
const expires = '2026-11-23T18:30:08Z';
const hash = (c) => `sha256:${c.repeat(64)}`;

function fixture(profile = 'managed-protected') {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const key = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const challenge = { contract: 'hq/v1', kind: 'stage2a-relay-peer-challenge',
    schema_version: 1, profile_in_force: profile, host_id: 'fixture-host',
    installation_id: 'inst_fixture', soul_id: 'agent_fixture',
    start_id: 'st_0123456789abcdef01234567', hq_epoch: 'a'.repeat(64),
    reservation_sha256: hash('1'), assignment_envelope_sha256: hash('2'),
    child_observation_envelope_sha256: hash('3'), member_id: 'm_lead',
    member_selector: `mb_${'4'.repeat(64)}`, runtime_id: 'rt_fixture',
    rpc_id: `rpc_${'a'.repeat(32)}`, nonce_hex: 'b'.repeat(64),
    peer_token: { uid: 331, pid: 4201, pid_version: 77 }, accepted_at: at,
    deadline_at: '2026-11-23T18:30:12Z' };
  const member = { member_id: 'm_lead', member_selector: challenge.member_selector,
    runtime_id: challenge.runtime_id, uid: 331, gid: 331,
    cli_path: '/fixture/r/adapter/claude', cli_sha256: hash('5'),
    acp: { pid: 4101, uid: 331, start_seconds: 1795458500,
      start_micros: 100, executable_sha256: hash('6') } };
  const envelope = (p, purpose = PURPOSE) => {
    const bytes = canonicalBytes(p);
    return canonicalBytes({ schema_version: 1, purpose,
      issuer_public_key_base64url: key.toString('base64url'),
      payload_sha256: SHA(bytes), payload_base64url: bytes.toString('base64url'),
      signature_base64url: sign(null, Buffer.concat([Buffer.from(`${purpose}\0`), bytes]),
        privateKey).toString('base64url') });
  };
  const arm = { member_id: 'm_lead', member_selector: member.member_selector,
    runtime_id: member.runtime_id,
    child_observation_envelope_sha256: challenge.child_observation_envelope_sha256,
    bridge_uid: 332,
    adapter_pid: member.acp.pid, adapter_uid: member.acp.uid, adapter_gid: member.gid,
    adapter_start_seconds: member.acp.start_seconds,
    adapter_start_micros: member.acp.start_micros,
    relay_peer_rule: 'a-attested-live-direct-child-of-adapter-v1',
    relay_peer_state: 'unobserved', provider_ingress: 'withheld-pending-per-peer-attestation',
    state: 'armed', armed_at: issued };
  const specArm = { ...arm, member_id: 'm_spec',
    member_selector: `mb_${'8'.repeat(64)}`, runtime_id: 'rt_spec',
    adapter_pid: 4102 };
  const bridge_process = { pid: 4301, uid: 332, gid: 332,
    start_seconds: 1795458490, start_micros: 1, executable_sha256: hash('9') };
  const ready = { contract: 'machine/v3', kind: 'stage2a-member-set-ready', schema_version: 1,
    ...Object.fromEntries(['profile_in_force', 'host_id', 'installation_id',
      'soul_id', 'start_id', 'hq_epoch', 'reservation_sha256',
      'assignment_envelope_sha256', 'child_observation_envelope_sha256']
      .map((field) => [field, challenge[field]])),
    b_authority_sha256: hash('a'), provisional_hq_mapping_sha256: hash('b'),
    bridge_process,
    members: [{ member_id: 'm_lead', launch_id: `ln_${'a'.repeat(24)}`,
      member_selector: member.member_selector, runtime_id: member.runtime_id,
      bridge_arm: arm, bridge_arm_receipt_sha256: SHA(canonicalBytes(arm)) },
    { member_id: 'm_spec', launch_id: `ln_${'b'.repeat(24)}`,
      member_selector: specArm.member_selector, runtime_id: specArm.runtime_id,
      bridge_arm: specArm, bridge_arm_receipt_sha256: SHA(canonicalBytes(specArm)) }],
    observed_at: issued, issued_at: issued,
    expires_at: '2026-11-23T18:31:00Z' };
  const readyEnvelopeBytes = envelope(ready, READY_PURPOSE);
  const state = { protocol: 'bridge.bind.v3', finalized: true,
    ...Object.fromEntries(['profile_in_force', 'host_id', 'installation_id', 'soul_id',
      'start_id', 'hq_epoch', 'reservation_sha256', 'assignment_envelope_sha256',
      'child_observation_envelope_sha256', 'member_id', 'member_selector',
      'runtime_id'].map((field) => [field, challenge[field]])),
    member, machinePublicKey: key, readyEnvelopeBytes,
    ready_envelope_sha256: SHA(readyEnvelopeBytes),
    finalization_envelope_sha256: hash('7'),
    b_authority_sha256: ready.b_authority_sha256,
    provisional_hq_mapping_sha256: ready.provisional_hq_mapping_sha256,
    bridge_process,
    reservation_expires_at: '2026-11-23T18:31:00Z' };
  const payload = { contract: 'machine/v3', kind: 'stage2a-relay-peer-attestation',
    schema_version: 1, ...Object.fromEntries(['profile_in_force', 'host_id',
      'installation_id', 'soul_id', 'start_id', 'hq_epoch', 'reservation_sha256',
      'assignment_envelope_sha256', 'child_observation_envelope_sha256',
      'member_id', 'member_selector', 'runtime_id'].map((field) => [field, challenge[field]])),
    ready_envelope_sha256: SHA(readyEnvelopeBytes), challenge_sha256: SHA(canonicalBytes(challenge)),
    rpc_id: challenge.rpc_id, nonce_hex: challenge.nonce_hex,
    reported_peer_token: challenge.peer_token,
    observed_cli: { pid: 4201, uid: 331, gid: 331, start_seconds: 1795458501,
      start_micros: 250, executable_path: member.cli_path,
      executable_sha256: member.cli_sha256, parent_pid: 4101 },
    observed_adapter_parent: { ...member.acp }, observed_at: issued,
    issued_at: issued, expires_at: expires };
  let connected = true;
  const service = createStage2aRelayPeerChallenge({
    current: () => connected, boundStart: async () => state,
    attest: async (bytes, ready) => {
      assert.deepEqual(bytes, canonicalBytes(challenge));
      assert.deepEqual(ready, readyEnvelopeBytes);
      return envelope(payload);
    }, clock: { now: () => now },
  });
  return { challenge, state, payload, ready, envelope, service,
    disconnect: () => { connected = false; }, meta: { connection: 'bb_fixture' },
    receipt: 'c'.repeat(64) };
}

test('signed live CLI and direct ACP parent verify for both profiles; replay is spent', async () => {
  for (const profile of ['managed-protected', 'managed-cooperative']) {
    const f = fixture(profile);
    const reply = await f.service(f.challenge, f.meta, f.receipt);
    assert.equal(reply.verdict, 'verified');
    assert.equal(reply.profile_in_force, profile);
    assert.equal(reply.challenge_sha256, SHA(canonicalBytes(f.challenge)));
    assert.equal(reply.rpc_id, f.challenge.rpc_id);
    await assert.rejects(f.service(f.challenge, f.meta, f.receipt), /unavailable/);
  }
});

test('missing v3 bind, changed member, sibling parent and lost connection refuse', async () => {
  const f = fixture();
  f.state.protocol = 'bridge.bind.v2';
  await assert.rejects(f.service(f.challenge, f.meta, f.receipt), /unavailable/);
  f.state.protocol = 'bridge.bind.v3';
  f.state.member.acp.pid++;
  await assert.rejects(f.service(f.challenge, f.meta, f.receipt), /unavailable/);
  f.disconnect();
  await assert.rejects(f.service(f.challenge, f.meta, f.receipt), /unavailable/);
});

test('A signature, exact challenge correlation, expiry and duplicate nonce are enforced', async () => {
  const f = fixture();
  const failWith = async (change) => {
    const t = fixture();
    change(t);
    await assert.rejects(t.service(t.challenge, t.meta, t.receipt));
  };
  await failWith((t) => { t.payload.challenge_sha256 = hash('f'); });
  await failWith((t) => { t.payload.expires_at = '2026-11-23T18:30:09Z'; });
  await failWith((t) => { t.payload.observed_cli.parent_pid = 999; });
  await failWith((t) => { t.payload.reported_peer_token.pid_version = 88; });
  await failWith((t) => { t.state.machinePublicKey = Buffer.alloc(32, 9); });
  await failWith((t) => {
    t.ready.members[1].member_selector = t.ready.members[0].member_selector;
    t.state.readyEnvelopeBytes = t.envelope(t.ready, READY_PURPOSE);
    t.state.ready_envelope_sha256 = SHA(t.state.readyEnvelopeBytes);
  });
  const first = await f.service(f.challenge, f.meta, f.receipt);
  assert.equal(first.verdict, 'verified');
  const second = { ...f.challenge, rpc_id: `rpc_${'d'.repeat(32)}` };
  await assert.rejects(f.service(second, f.meta, f.receipt), /unavailable/);
});

test('a paired A timeout spends the RPC and cannot produce a late result', async () => {
  const f = fixture();
  const service = createStage2aRelayPeerChallenge({
    current: () => true, boundStart: async () => f.state,
    attest: () => new Promise(() => {}), clock: { now: () => now },
    timers: { setTimeout: (fn) => { queueMicrotask(fn); return 1; }, clearTimeout() {} },
  });
  await assert.rejects(service(f.challenge, f.meta, f.receipt), /deadline exceeded/);
  await assert.rejects(service(f.challenge, f.meta, f.receipt), /unavailable/);
});
