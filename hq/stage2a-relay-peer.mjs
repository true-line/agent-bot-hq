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
  'b_authority_sha256', 'member_b_authority_envelope_sha256', 'provisional_hq_mapping_sha256', 'bridge_process',
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
  const references = assignmentSchema.$id ? [...(schemas ?? []), assignmentSchema] : schemas;
  if (validate(schema, a, { schemas: references }).length) refuse();
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

// The expected rows come from the two actual per-member grant/launcher
// records retained by the prestart supervisor, in assignment member order.
export function matchesObservedMemberGrants(assignment, observedMembers, memberGrants) {
  if (assignment?.members?.length !== 2 || observedMembers?.length !== 2
    || !Array.isArray(memberGrants) || memberGrants.length !== 2) return false;
  const kernelIdentityFields = ['pid', 'uid', 'gid', 'start_seconds', 'start_micros'];
  const launchers = new Set(), children = new Set(), grants = new Set();
  for (const [i, observed] of observedMembers.entries()) {
    const expected = memberGrants[i], assigned = assignment.members[i];
    const launcher = observed.launcher_process, child = observed.child_process;
    if (!launcher || !child || !expected?.launcher_process
      || observed.member_id !== assigned.member_id || expected.member_id !== assigned.member_id
      || expected.member_selector !== assigned.member_selector || expected.launch_id !== assigned.launch_id
      || !SHA.test(observed.grant_sha256) || observed.grant_sha256 !== expected.grant_sha256
      || kernelIdentityFields.some((field) => launcher[field] !== expected.launcher_process[field])
      || launcher.uid !== assignment.runner_uid || launcher.gid !== assignment.runner_gid
      || child.parent_pid !== launcher.pid || child.pid === launcher.pid
      || child.start_seconds < launcher.start_seconds
      || (child.start_seconds === launcher.start_seconds && child.start_micros < launcher.start_micros)) return false;
    launchers.add(launcher.pid);
    children.add(child.pid);
    grants.add(observed.grant_sha256);
  }
  return launchers.size === 2 && grants.size === 2 && children.size === 2
    && Array.from(children).every((pid) => !launchers.has(pid));
}

const BIND_SELECTORS = ['installation_id', 'start_id', 'plan_id', 'plan_digest', 'reservation_digest',
  'assignment_envelope_sha256', 'authority_envelope_sha256', 'member_selectors_sha256'];

export function createStage2aMemberArmExchange({ provider, current, boundStart, clock }) {
  const connections = new Map();
  const enabled = !!provider?.schema && !!provider.childObservationSchema
    && typeof provider.observe === 'function' && typeof provider.recordArm === 'function';
  const check = (schema, payload) => {
    if (validate(schema, payload, { schemas: (provider.schemaReferences ?? []).filter((entry) =>
      entry.$id !== schema.$id) }).length) refuse();
    return payload;
  };
  const active = (connection, receipt, state) =>
    current(connection, receipt) === true && connections.get(connection) === state;
  const bound = async (request, connection, receipt, state) => {
    if (!active(connection, receipt, state)) refuse();
    const binding = await boundStart(connection, receipt);
    if (!active(connection, receipt, state)
      || !exact(request.selectors, BIND_SELECTORS)
      || BIND_SELECTORS.some((field) => request.selectors[field] !== binding[field])) refuse();
    return binding;
  };

  async function observe(request, { connection } = {}, receipt) {
    if (!enabled || current(connection, receipt) !== true
      || request?.kind !== 'bridge.member.observe.v3.request') refuse();
    check(provider.schema, request);
    const state = connections.get(connection) ?? { members: new Map(), nonces: new Set(), pending: new Map() };
    if (state.members.has(request.member_id) || state.pending.has(request.member_id)
      || state.members.size + state.pending.size >= 2 || state.nonces.has(request.observe_nonce)
      || [...state.pending.values()].some((slot) => slot.nonce === request.observe_nonce)) refuse();
    connections.set(connection, state);
    const slot = { nonce: request.observe_nonce, timedOut: false };
    state.pending.set(request.member_id, slot);
    let timer;
    try {
      return await Promise.race([observed(request, connection, receipt, state, slot),
        new Promise((_, reject) => {
          timer = setTimeout(() => {
            slot.timedOut = true;
            reject(new Error('Stage 2a child observation deadline exceeded'));
          }, 4_000);
          timer.unref?.();
        })]);
    } finally {
      clearTimeout(timer);
      state.pending.delete(request.member_id);
    }
  }

  async function observed(request, connection, receipt, state, slot) {
    const binding = await bound(request, connection, receipt, state);
    if (slot.timedOut) refuse();
    const observation = await provider.observe(binding);
    if (slot.timedOut || !active(connection, receipt, state) || !observation) refuse();
    const { envelopeBytes, assignmentBytes, machinePublicKey, provisionalMappingSHA256,
      memberGrants } = observation;
    const signed = (bytes, purpose) => verifyStage2aMachineEnvelope(bytes, machinePublicKey,
      `agent-bot/stage2a-member-set-${purpose}/v1`, { maxBytes: 16_384 });
    const assignment = signed(assignmentBytes, 'assignment');
    const child = signed(envelopeBytes, 'child-observation');
    const a = assignment.payload, c = check(provider.childObservationSchema, child.payload);
    const mapping = c.provisional_hq_mapping;
    const startFields = ['profile_in_force', 'host_id', 'installation_id', 'soul_id', 'start_id', 'hq_epoch'];
    if (assignment.envelope_sha256 !== binding.assignment_envelope_sha256
      || a.profile_in_force !== 'managed-protected'
      || a.reservation_sha256 !== binding.reservation_digest || c.reservation_sha256 !== binding.reservation_digest
      || c.assignment_envelope_sha256 !== assignment.envelope_sha256
      || startFields.some((field) => c[field] !== a[field] || mapping[field] !== a[field])
      || mapping.assignment_envelope_sha256 !== assignment.envelope_sha256
      || mapping.runtime_state !== 'provisional' || mapping.acp_authority !== 'withheld'
      || !SHA.test(provisionalMappingSHA256) || c.provisional_hq_mapping_sha256 !== provisionalMappingSHA256
      || sha(canonicalBytes(mapping)) !== provisionalMappingSHA256
      || !Array.isArray(a.members) || a.members.length !== 2 || c.members.length !== 2
      || mapping.members.length !== 2 || a.members[0].member_id >= a.members[1].member_id
      || c.members[0].runtime_id === c.members[1].runtime_id
      || !matchesObservedMemberGrants(a, c.members, memberGrants)) refuse();
    for (const [i, member] of a.members.entries()) {
      const observed = c.members[i], mapped = mapping.members[i], p = observed.child_process;
      if (['member_id', 'member_selector'].some((k) => observed[k] !== member[k] || mapped[k] !== member[k])
        || observed.launch_id !== member.launch_id || observed.runtime_id !== mapped.runtime_id
        || p.uid !== a.runner_uid || p.gid !== a.runner_gid || p.executable_sha256 !== member.command_sha256) refuse();
    }
    const member = c.members.find((m) => m.member_id === request.member_id);
    const issued = time(c.issued_at), expires = time(c.expires_at);
    if (!member || member.member_selector !== request.member_selector
      || !(time(c.observed_at) <= issued && issued <= clock.now()
        && clock.now() < expires && expires <= time(a.expires_at))
      || (state.childSHA256 && state.childSHA256 !== child.envelope_sha256)
      || !active(connection, receipt, state)) refuse();
    const result = check(provider.schema, { kind: 'bridge.member.observe.v3.result', member_id: member.member_id,
      member_selector: member.member_selector, observe_nonce: request.observe_nonce,
      child_observation_envelope_base64url: envelopeBytes.toString('base64url'),
      child_observation_envelope_sha256: child.envelope_sha256, expires_at: c.expires_at });
    state.childSHA256 = child.envelope_sha256;
    state.members.set(request.member_id, { member, nonce: request.observe_nonce,
      expires, expiresAt: c.expires_at, observedAt: time(c.observed_at), childSHA256: child.envelope_sha256 });
    state.nonces.add(request.observe_nonce);
    return result;
  }

  async function arm(request, { connection } = {}, receipt) {
    if (!enabled || request?.kind !== 'bridge.member.arm.v3.request') refuse();
    check(provider.schema, request);
    const state = connections.get(connection), slot = state?.members.get(request.member_id);
    if (!state || !active(connection, receipt, state) || !slot?.member || slot.armSpent
      || state.nonces.has(request.arm_nonce) || [...state.pending.values()].some((pending) => pending.nonce === request.arm_nonce) || slot.expires <= clock.now()
      || request.observe_nonce !== slot.nonce || request.member_selector !== slot.member.member_selector
      || request.child_observation_envelope_sha256 !== slot.childSHA256) refuse();
    slot.armSpent = true;
    state.nonces.add(request.arm_nonce);
    const binding = await bound(request, connection, receipt, state);
    const row = request.bridge_arm, p = slot.member.child_process;
    if (row.member_id !== request.member_id || row.member_selector !== request.member_selector
      || row.runtime_id !== slot.member.runtime_id || row.bridge_uid !== binding.bridge_uid
      || row.child_observation_envelope_sha256 !== slot.childSHA256
      || ['pid', 'uid', 'gid', 'start_seconds', 'start_micros'].some((field) => row[`adapter_${field}`] !== p[field])
      || !(slot.observedAt <= time(row.armed_at) && time(row.armed_at) <= clock.now())
      || sha(canonicalBytes(row)) !== request.bridge_arm_receipt_sha256
      || slot.expires <= clock.now()) refuse();
    if (await provider.recordArm(binding, canonicalBytes(row), request.bridge_arm_receipt_sha256) !== true
      || !active(connection, receipt, state) || slot.expires <= clock.now()) refuse();
    return check(provider.schema, { kind: 'bridge.member.arm.v3.result', member_id: request.member_id,
      member_selector: request.member_selector, arm_nonce: request.arm_nonce,
      bridge_arm_receipt_sha256: request.bridge_arm_receipt_sha256, state: 'recorded-pending-aggregate-ready',
      expires_at: slot.expiresAt });
  }

  return Object.freeze({ enabled, observe, arm, forgetConnection: (connection) => connections.delete(connection) });
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
    || payload.member_b_authority_envelope_sha256 !== state.member_b_authority_envelope_sha256
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
      || !SHA.test(state.member_b_authority_envelope_sha256)
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
        || rechecked.member_b_authority_envelope_sha256 !== state.member_b_authority_envelope_sha256
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
