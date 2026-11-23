// Default-off H side of the Stage 2a live adjacent CLI challenge. The caller
// must supply the current v3 B connection, finalized two-member start and the
// independently pinned A key. This module never grants provider ingress.
import { createHash } from 'node:crypto';
import { canonicalBytes, canonicalize } from '../sdk/wire/canonical-json.mjs';
import { validate } from '../sdk/wire/schema.mjs';
import { verifyStage2aMachineEnvelope } from './stage2a-stop.mjs';

const PURPOSE = 'agent-bot/stage2a-relay-peer-attestation/v1';
const READY_PURPOSE = 'agent-bot/stage2a-member-set-ready/v1';
const SHA = /^sha256:[0-9a-f]{64}$/;
const RPC = /^rpc_[0-9a-f]{32}$/;
const NONCE = /^[0-9a-f]{64}$/;
const FIELDS = ['contract', 'kind', 'schema_version', 'profile_in_force', 'host_id',
  'installation_id', 'soul_id', 'start_id', 'hq_epoch', 'reservation_sha256',
  'assignment_envelope_sha256', 'child_observation_envelope_sha256', 'member_id',
  'member_selector', 'runtime_id', 'rpc_id', 'nonce_hex', 'peer_token',
  'accepted_at', 'deadline_at'];
const JOIN = ['profile_in_force', 'host_id', 'installation_id', 'soul_id', 'start_id',
  'hq_epoch', 'reservation_sha256', 'assignment_envelope_sha256',
  'child_observation_envelope_sha256', 'member_id', 'member_selector', 'runtime_id'];
const READY_FIELDS = ['contract', 'kind', 'schema_version', 'profile_in_force', 'host_id',
  'installation_id', 'soul_id', 'start_id', 'hq_epoch', 'reservation_sha256',
  'assignment_envelope_sha256', 'child_observation_envelope_sha256',
  'b_authority_sha256', 'provisional_hq_mapping_sha256', 'bridge_process',
  'members', 'observed_at', 'issued_at', 'expires_at'];
const READY_MEMBER_FIELDS = ['member_id', 'launch_id', 'member_selector', 'runtime_id',
  'bridge_arm', 'bridge_arm_receipt_sha256'];
const ARM_FIELDS = ['member_id', 'member_selector', 'runtime_id',
  'child_observation_envelope_sha256', 'bridge_uid', 'adapter_pid', 'adapter_uid',
  'adapter_gid', 'adapter_start_seconds', 'adapter_start_micros', 'relay_peer_rule',
  'relay_peer_state', 'provider_ingress', 'state', 'armed_at'];
const exact = (value, fields) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === fields.length && fields.every((field) => Object.hasOwn(value, field));
const sha = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const refuse = () => { throw new Error('Stage 2a live relay peer is unavailable'); };
const time = (value) => typeof value === 'string' && /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,3})?Z$/.test(value)
  ? Date.parse(value) : NaN;
const positive = (value) => Number.isSafeInteger(value) && value > 0;
const same = (a, b) => canonicalize(a) === canonicalize(b);

// The expected selectors and bridge endpoint come from the registered start
// and the current kernel-authenticated B broker connection.
export function verifyStage2aBridgeMemberAuthority(bytes, { machinePublicKey, schema,
  assignmentSchema, schemas, expected, assignmentBytes, now = Date.now() } = {}) {
  if (!schema || !assignmentSchema || !expected) refuse();
  const assignment = verifyStage2aMachineEnvelope(assignmentBytes, machinePublicKey,
    'agent-bot/stage2a-member-set-assignment/v1', { maxBytes: 16_384 });
  if (validate(assignmentSchema, assignment.payload, { schemas }).length) refuse();
  const proof = verifyStage2aMachineEnvelope(bytes, machinePublicKey,
    'agent-bot/stage2a-b-member-authority/v1', { maxBytes: 16_384 });
  const a = proof.payload;
  if (validate(schema, a, { schemas }).length) refuse();
  const shared = ['profile_in_force', 'host_id', 'installation_id', 'soul_id',
    'start_id', 'hq_epoch', 'plan_id', 'plan_digest', 'reservation_sha256',
    'owner_plan_member_set_sha256', 'runner_uid'];
  const signed = assignment.payload;
  if (shared.some((field) => a[field] !== expected[field] || a[field] !== signed[field])
    || a.member_set_assignment_envelope_sha256 !== assignment.envelope_sha256
    || a.hq_uid !== expected.hq_uid
    || !same(a.bridge, signed.bridge)
    || a.bridge.uid !== expected.bridge_uid || a.bridge.gid !== expected.bridge_gid
    || a.bridge.endpoints.broker.socket_path !== expected.broker_socket
    || !same(a.b_authority, signed.b_authority)
    || !(time(signed.issued_at) <= time(a.issued_at) && time(a.issued_at) <= now
      && now < time(a.expires_at) && time(a.expires_at) <= time(signed.expires_at))
    || a.members.length !== 2 || signed.members?.length !== 2
    || a.members[0].member_id >= a.members[1].member_id
    || ['launch_id', 'member_selector'].some((field) => a.members[0][field] === a.members[1][field])) refuse();
  const memberFields = ['member_id', 'launch_id', 'member_selector', 'adjacent_cli_path', 'adjacent_cli_sha256'];
  if (a.members.some((member, index) =>
    memberFields.some((field) => member[field] !== signed.members[index][field]))) refuse();
  return proof;
}

function validChallenge(c, now) {
  if (!exact(c, FIELDS) || c.contract !== 'hq/v1' || c.kind !== 'stage2a-relay-peer-challenge'
    || c.schema_version !== 1 || !['managed-protected', 'managed-cooperative'].includes(c.profile_in_force)
    || !RPC.test(c.rpc_id) || !NONCE.test(c.nonce_hex)
    || !exact(c.peer_token, ['uid', 'pid', 'pid_version'])
    || !Number.isSafeInteger(c.peer_token.uid) || c.peer_token.uid < 300 || c.peer_token.uid > 399
    || !Number.isSafeInteger(c.peer_token.pid) || c.peer_token.pid < 2
    || !positive(c.peer_token.pid_version) || c.peer_token.pid_version > 0xffffffff
    || ['reservation_sha256', 'assignment_envelope_sha256', 'child_observation_envelope_sha256']
      .some((field) => !SHA.test(c[field]))) refuse();
  const accepted = time(c.accepted_at), deadline = time(c.deadline_at);
  if (!Number.isFinite(accepted) || !Number.isFinite(deadline) || accepted > now + 1000
    || deadline <= accepted || deadline - accepted > 10_000 || now >= deadline) refuse();
  return deadline;
}

function verifyPayload(p, c, state, challengeBytes, now) {
  if (!exact(p, ['contract', 'kind', 'schema_version', ...JOIN, 'ready_envelope_sha256',
    'challenge_sha256', 'rpc_id', 'nonce_hex', 'reported_peer_token', 'observed_cli',
    'observed_adapter_parent', 'observed_at', 'issued_at', 'expires_at'])
    || p.contract !== 'machine/v3' || p.kind !== 'stage2a-relay-peer-attestation'
    || p.schema_version !== 1 || JOIN.some((field) => p[field] !== c[field])
    || p.ready_envelope_sha256 !== sha(state.readyEnvelopeBytes)
    || p.challenge_sha256 !== sha(challengeBytes) || p.rpc_id !== c.rpc_id
    || p.nonce_hex !== c.nonce_hex || !same(p.reported_peer_token, c.peer_token)) refuse();
  const issued = time(p.issued_at), observed = time(p.observed_at), expires = time(p.expires_at);
  const reservationExpires = time(state.reservation_expires_at);
  if (![issued, observed, expires, reservationExpires].every(Number.isFinite) || observed > issued
    || issued > now + 1000 || expires <= issued || expires - issued > 5000
    || now >= expires || expires > reservationExpires) refuse();
  const cli = p.observed_cli, parent = p.observed_adapter_parent, expected = state.member;
  if (!exact(cli, ['pid', 'uid', 'gid', 'start_seconds', 'start_micros',
    'executable_path', 'executable_sha256', 'parent_pid'])
    || !exact(parent, ['pid', 'uid', 'start_seconds', 'start_micros', 'executable_sha256'])
    || cli.pid !== c.peer_token.pid || cli.uid !== c.peer_token.uid
    || cli.uid !== expected.uid || cli.gid !== expected.gid
    || cli.executable_path !== expected.cli_path || cli.executable_sha256 !== expected.cli_sha256
    || cli.parent_pid !== parent.pid || parent.pid !== expected.acp.pid
    || parent.uid !== expected.acp.uid || parent.start_seconds !== expected.acp.start_seconds
    || parent.start_micros !== expected.acp.start_micros
    || parent.executable_sha256 !== expected.acp.executable_sha256
    || !positive(cli.start_seconds) || !Number.isSafeInteger(cli.start_micros)
    || cli.start_micros < 0 || cli.start_micros > 999999
    || cli.start_seconds * 1000 + cli.start_micros / 1000 > observed
    || cli.start_seconds < parent.start_seconds
    || (cli.start_seconds === parent.start_seconds && cli.start_micros <= parent.start_micros)) refuse();
  return expires;
}

function verifyReady(state, challenge, now) {
  const { payload, envelope_sha256 } = verifyStage2aMachineEnvelope(
    state.readyEnvelopeBytes, state.machinePublicKey, READY_PURPOSE, { maxBytes: 16_384 });
  const observed = time(payload?.observed_at), issued = time(payload?.issued_at);
  const expires = time(payload?.expires_at);
  if (!exact(payload, READY_FIELDS) || envelope_sha256 !== state.ready_envelope_sha256
    || payload.contract !== 'machine/v3'
    || payload.kind !== 'stage2a-member-set-ready' || payload.schema_version !== 1
    || ['profile_in_force', 'host_id', 'installation_id', 'soul_id', 'start_id',
      'hq_epoch', 'reservation_sha256', 'assignment_envelope_sha256',
      'child_observation_envelope_sha256'].some((field) => payload[field] !== challenge[field])
    || !Array.isArray(payload.members) || payload.members.length !== 2
    || typeof payload.members[0]?.member_id !== 'string'
    || typeof payload.members[1]?.member_id !== 'string'
    || payload.members[0].member_id >= payload.members[1].member_id
    || payload.b_authority_sha256 !== state.b_authority_sha256
    || payload.provisional_hq_mapping_sha256 !== state.provisional_hq_mapping_sha256
    || !same(payload.bridge_process, state.bridge_process)
    || ![observed, issued, expires].every(Number.isFinite)
    || observed > issued || issued > now + 1000 || now >= expires) refuse();
  for (const row of payload.members) {
    const arm = row?.bridge_arm;
    if (!exact(row, READY_MEMBER_FIELDS) || !exact(arm, ARM_FIELDS)
      || !SHA.test(row.bridge_arm_receipt_sha256)
      || row.bridge_arm_receipt_sha256 !== sha(canonicalBytes(arm))
      || row.member_id !== arm.member_id || row.member_selector !== arm.member_selector
      || row.runtime_id !== arm.runtime_id
      || arm.child_observation_envelope_sha256 !== challenge.child_observation_envelope_sha256
      || arm.relay_peer_rule !== 'a-attested-live-direct-child-of-adapter-v1'
      || arm.relay_peer_state !== 'unobserved'
      || arm.provider_ingress !== 'withheld-pending-per-peer-attestation'
      || arm.state !== 'armed') refuse();
  }
  if (payload.members[0].member_selector === payload.members[1].member_selector
    || payload.members[0].runtime_id === payload.members[1].runtime_id
    || payload.members[0].launch_id === payload.members[1].launch_id) refuse();
  const member = payload.members.find((m) => m.member_id === challenge.member_id);
  const arm = member?.bridge_arm;
  if (!member || member.member_selector !== challenge.member_selector
    || member.runtime_id !== challenge.runtime_id
    || arm?.member_id !== challenge.member_id
    || arm.member_selector !== challenge.member_selector
    || arm.runtime_id !== challenge.runtime_id
    || arm.child_observation_envelope_sha256 !== challenge.child_observation_envelope_sha256
    || arm.bridge_uid !== state.bridge_process.uid
    || arm.adapter_pid !== state.member.acp.pid || arm.adapter_uid !== state.member.acp.uid
    || arm.adapter_gid !== state.member.gid
    || arm.adapter_start_seconds !== state.member.acp.start_seconds
    || arm.adapter_start_micros !== state.member.acp.start_micros
    || arm.relay_peer_rule !== 'a-attested-live-direct-child-of-adapter-v1'
    || arm.relay_peer_state !== 'unobserved'
    || arm.provider_ingress !== 'withheld-pending-per-peer-attestation'
    || arm.state !== 'armed') refuse();
}

// `current` is synchronous and must inspect the same live B connection after
// every await. `boundStart` must authenticate the v3 bind receipt and current
// A-signed finalized start, returning the exact frozen member projection.
// `attest` forwards the same canonical challenge bytes and active ready bytes
// on the paired local H->A channel. None has a production default.
export function createStage2aRelayPeerChallenge({ current, boundStart, attest,
  clock = Date, timers = { setTimeout, clearTimeout } } = {}) {
  const spent = new Map();
  async function stage2aRelayPeerChallenge(challenge, { connection } = {}, receipt) {
    if (typeof current !== 'function' || typeof boundStart !== 'function'
      || typeof attest !== 'function' || typeof connection !== 'string'
      || !/^[0-9a-f]{64}$/.test(receipt) || current(connection, receipt) !== true) refuse();
    const now = clock.now(), deadline = validChallenge(challenge, now);
    const used = spent.get(connection) ?? { rpc: new Set(), nonce: new Set() };
    if (used.rpc.has(challenge.rpc_id) || used.nonce.has(challenge.nonce_hex)
      || used.rpc.size >= 4096) refuse();
    used.rpc.add(challenge.rpc_id);
    used.nonce.add(challenge.nonce_hex);
    spent.set(connection, used); // spend before any asynchronous authority call
    const challengeBytes = canonicalBytes(challenge);
    async function beforeDeadline(operation) {
      if (clock.now() >= deadline) refuse();
      let timer;
      try {
        return await Promise.race([Promise.resolve().then(operation),
          new Promise((_, reject) => { timer = timers.setTimeout(() => reject(new Error('A live peer deadline exceeded')),
            Math.max(1, deadline - clock.now())); })]);
      } finally { if (timer !== undefined) timers.clearTimeout(timer); }
    }
    const member = Object.freeze({ member_id: challenge.member_id, member_selector: challenge.member_selector,
      runtime_id: challenge.runtime_id });
    const state = await beforeDeadline(() => boundStart(connection, receipt, member));
    if (current(connection, receipt) !== true || state?.finalized !== true
      || state?.protocol !== 'bridge.bind.v3' || !Buffer.isBuffer(state.machinePublicKey)
      || state.machinePublicKey.length !== 32 || !Buffer.isBuffer(state.readyEnvelopeBytes)
      || state.readyEnvelopeBytes.length < 1 || state.readyEnvelopeBytes.length > 16_384
      || !SHA.test(state.ready_envelope_sha256)
      || !SHA.test(state.finalization_envelope_sha256)
      || !SHA.test(state.b_authority_sha256)
      || !SHA.test(state.provisional_hq_mapping_sha256)
      || !state.member || JOIN.some((field) => state[field] !== challenge[field])
      || state.member.member_id !== challenge.member_id
      || state.member.member_selector !== challenge.member_selector
      || state.member.runtime_id !== challenge.runtime_id) refuse();
    verifyReady(state, challenge, clock.now());
    const envelopeBytes = await beforeDeadline(() => attest(challengeBytes, state.readyEnvelopeBytes, state));
    {
      if (!Buffer.isBuffer(envelopeBytes) || envelopeBytes.length > 8192) refuse();
      const { payload, envelope_sha256 } = verifyStage2aMachineEnvelope(
        envelopeBytes, state.machinePublicKey, PURPOSE);
      const verifiedAt = clock.now();
      const expires = verifyPayload(payload, challenge, state, challengeBytes, verifiedAt);
      if (verifiedAt >= deadline || current(connection, receipt) !== true) refuse();
      const rechecked = await beforeDeadline(() => boundStart(connection, receipt, member));
      if (current(connection, receipt) !== true || rechecked?.finalized !== true
        || rechecked?.protocol !== 'bridge.bind.v3'
        || rechecked.reservation_expires_at !== state.reservation_expires_at
        || rechecked.finalization_envelope_sha256 !== state.finalization_envelope_sha256
        || rechecked.ready_envelope_sha256 !== state.ready_envelope_sha256
        || JOIN.some((field) => rechecked[field] !== state[field])
        || !Buffer.isBuffer(rechecked.readyEnvelopeBytes)
        || !rechecked.readyEnvelopeBytes.equals(state.readyEnvelopeBytes)
        || !Buffer.isBuffer(rechecked.machinePublicKey)
        || !rechecked.machinePublicKey.equals(state.machinePublicKey)
        || !same(rechecked.member, state.member)) refuse();
      return Object.freeze({ contract: 'hq/v1', kind: 'stage2a-relay-peer-verified',
        schema_version: 1, profile_in_force: challenge.profile_in_force,
        start_id: challenge.start_id, rpc_id: challenge.rpc_id, nonce_hex: challenge.nonce_hex,
        member_id: challenge.member_id, member_selector: challenge.member_selector,
        runtime_id: challenge.runtime_id, peer_token: challenge.peer_token,
        challenge_sha256: sha(challengeBytes), attestation_envelope_sha256: envelope_sha256,
        attestation_envelope_base64url: envelopeBytes.toString('base64url'), verdict: 'verified',
        verified_at: new Date(verifiedAt).toISOString(), expires_at: new Date(expires).toISOString() });
    }
  }
  stage2aRelayPeerChallenge.forgetConnection = (connection) => spent.delete(connection);
  return stage2aRelayPeerChallenge;
}
