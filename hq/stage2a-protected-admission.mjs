// HQ's paired Machine verifier for the per-start R admission listener.
// H observes the accepted socket; A independently reobserves its process,
// frozen inputs and B bind before signing each role and Hello transition.
import { createHash } from 'node:crypto';
import { canonicalBytes, canonicalize } from '../sdk/wire/canonical-json.mjs';
import { machineRoleStage2aPeerRole, machineRoleStage2aHelloStart,
  machineRoleStage2aHelloFinalize, machineRoleStage2aHelloAbort,
  machineRoleStage2aMemberFinalization, machineRoleStage2aMemberRuntime } from './machine-channel.mjs';
import { verifyStage2aMachineEnvelope } from './stage2a-stop.mjs';
import { prepareStage2aMemberFinalization } from './stage2a-member-finalization.mjs';

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const STOP_FIELDS = ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
  'plan_id', 'plan_digest', 'hq_epoch'];
const PEER_PURPOSE = 'agent-bot/stage2a-peer-role/v1';
const START_PURPOSE = 'agent-bot/stage2a-hello-start/v1';
const FINAL_PURPOSE = 'agent-bot/stage2a-hello-finalization/v1';
const MEMBER_FINAL_PURPOSE = 'agent-bot/stage2a-member-finalization-ack/v1';
const PEER_TOKEN = Symbol('stage2a-authenticated-peer');
const refuse = () => { throw new Error('Machine protected Hello authority is unavailable'); };
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const sha = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const same = (a, b) => canonicalize(a) === canonicalize(b);
const stopMatches = (value, selectors) => STOP_FIELDS.every((field) => value?.[field] === selectors[field]);
const assignmentMatches = (value, selectors) => STOP_FIELDS
  .filter((field) => field !== 'reservation_sha256')
  .every((field) => value?.[field] === selectors[field]);

function checkedReply(reply, key, purpose, schema, selectors) {
  if (!Buffer.isBuffer(reply?.envelope) || !DIGEST.test(reply?.sha256 ?? '')
    || sha(reply.envelope) !== reply.sha256) refuse();
  const checked = verifyStage2aMachineEnvelope(reply.envelope, key, purpose);
  if (checked.envelope_sha256 !== reply.sha256 || checked.payload?.schema !== schema
    || !stopMatches(checked.payload, selectors)) refuse();
  return Object.freeze(checked.payload);
}

export function createStage2aProtectedAdmission({ machinePublicKey, authority,
  machinePeerRole = machineRoleStage2aPeerRole,
  machineHelloStart = machineRoleStage2aHelloStart,
  machineHelloFinalize = machineRoleStage2aHelloFinalize,
  machineMemberFinalization = machineRoleStage2aMemberFinalization,
  machineMemberRuntime = machineRoleStage2aMemberRuntime,
  machineHelloAbort = machineRoleStage2aHelloAbort,
  readCommittedMemberFinalization = async () => refuse(), verifyRelayProvenance = () => false,
  stopReservation, now = () => Date.now() } = {}) {
  if (!Buffer.isBuffer(machinePublicKey) || machinePublicKey.length !== 32
    || typeof authority?.currentLiveStart !== 'function'
    || [machinePeerRole, machineHelloStart, machineHelloFinalize, machineMemberFinalization,
      machineMemberRuntime,
      readCommittedMemberFinalization, verifyRelayProvenance, machineHelloAbort,
      stopReservation, now].some((fn) => typeof fn !== 'function')) refuse();
  const starts = new Map();
  const contexts = new WeakMap();
  const bindings = new WeakMap();
  const peerFor = (connection) => contexts.get(connection?.[PEER_TOKEN]);

  function recordFor(selectors) {
    const record = starts.get(selectors?.reservation_sha256);
    if (!record || record.lost || !stopMatches(selectors, record.selectors)) refuse();
    return record;
  }

  function recordForExpected(expected) {
    const record = starts.get(expected?.reservation_sha256);
    if (!record || record.lost || ['reservation_sha256', 'installation_id',
      'start_id', 'launch_id', 'hq_epoch'].some((field) =>
      expected[field] !== record.selectors[field])) refuse();
    return record;
  }

  // Admission validates and freezes a copy of the binding before invoking
  // later callbacks. Match that copy to this exact signed Hello, not by JS
  // object identity.
  function recordForBinding(binding) {
    const record = starts.get(binding?.reservation_sha256);
    if (!record || record.lost || !record.hello
      || !same(record.hello.binding, binding)) refuse();
    return record;
  }

  function registerStart({ installed, assignment, selectors, getBindReceiptSHA256, prestartMembers } = {}) {
    if (!installed || !assignment || !exact(selectors, STOP_FIELDS)
      || !DIGEST.test(selectors.reservation_sha256)
      || !assignmentMatches(assignment, selectors)
      || installed.installation_id !== selectors.installation_id
      || installed.plan_id !== selectors.plan_id || installed.plan_digest !== selectors.plan_digest
      || installed.hq_epoch !== selectors.hq_epoch
      || typeof getBindReceiptSHA256 !== 'function'
      || (prestartMembers !== undefined && typeof prestartMembers !== 'function')
      || starts.has(selectors.reservation_sha256)) refuse();
    const record = { installed, assignment, selectors: Object.freeze({ ...selectors }),
      getBindReceiptSHA256, prestartMembers, prestarted: null, hello: null, finalized: false, lost: false,
      lastLiveAt: now(), watch: null, timer: null, issuedMemberLeases: new Map() };
    starts.set(selectors.reservation_sha256, record);
    return Object.freeze({ close: () => {
      record.lost = true;
      clearInterval(record.timer);
      if (starts.get(selectors.reservation_sha256) === record)
        starts.delete(selectors.reservation_sha256);
    } });
  }

  async function acceptPeer(_socket, { installed, assignment, selectors, peer_uid, peer_pid } = {}) {
    const record = recordFor(selectors);
    if (installed !== record.installed || assignment !== record.assignment
      || peer_uid !== installed.runner_uid || !Number.isSafeInteger(peer_pid) || peer_pid < 2) refuse();
    const reply = await machinePeerRole({ ...selectors, peer_uid, peer_pid });
    const signed = checkedReply(reply, machinePublicKey, PEER_PURPOSE,
      'agent-bot-machine/stage2a-peer-role/v1', selectors);
    if (!['runner', 'child'].includes(signed.role) || signed.peer_uid !== peer_uid
      || signed.peer_pid !== peer_pid || signed.peer_process?.pid !== peer_pid
      || signed.peer_process?.uid !== peer_uid
      || signed.runner?.uid !== installed.runner_uid
      || signed.bridge?.uid !== installed.bridge_uid
      || signed.definition_measurement !== installed.definition_measurement
      || signed.launch_input_measurement !== installed.launch_input_measurement
      || signed.profile_in_force !== 'managed-protected'
      || !Number.isSafeInteger(signed.issued_at_ms)
      || !Number.isSafeInteger(signed.expires_at_ms)
      || signed.issued_at_ms > now() || signed.expires_at_ms <= now()
      || signed.expires_at_ms - signed.issued_at_ms > 5000
      || (signed.role === 'child' && (!record.finalized
        || signed.hello_finalization_sha256 !== record.finalSHA256
        || !DIGEST.test(signed.child_start_receipt_sha256 ?? '')))) refuse();
    // listenSocket freezes a shallow copy of this context before dispatch.
    // The opaque token survives that copy while an untrusted wire value
    // cannot manufacture an entry in this WeakMap.
    const token = Object.freeze({});
    const context = Object.freeze({ ...selectors, peer_uid, peer_pid,
      role: signed.role, [PEER_TOKEN]: token });
    contexts.set(token, { record, expiresAt: signed.expires_at_ms,
      role: signed.role, peerProcess: signed.peer_process, socket: _socket });
    return context;
  }

  async function refreshRunnerPeer(connection) {
    const peer = peerFor(connection);
    if (!peer || peer.role !== 'runner' || peer.record.lost || peer.socket?.destroyed
      || !peer.record.finalized) refuse();
    const helloPeer = peerFor(peer.record.hello?.connection);
    if (!helloPeer || !same(peer.peerProcess, helloPeer.peerProcess)) refuse();
    const { installed, assignment, selectors } = peer.record;
    const refreshed = await acceptPeer(peer.socket, { installed, assignment, selectors,
      peer_uid: connection.peer_uid, peer_pid: connection.peer_pid });
    const live = peerFor(refreshed);
    const process = live?.peerProcess;
    if (live?.role !== 'runner' || !same(process, peer.peerProcess)
      || !Number.isSafeInteger(process.start_seconds) || process.start_seconds <= 0
      || !Number.isSafeInteger(process.start_micros) || process.start_micros < 0
      || process.start_micros >= 1e6) refuse();
    const processSHA256 = sha(canonicalBytes(process));
    return Object.freeze({ processSHA256, isCurrent: () => !peer.record.lost
      && !peer.socket?.destroyed && live.expiresAt > now() });
  }

  async function verifyHelloStart({ connection, caller, payload, hello_payload_sha256 } = {}) {
    const peer = peerFor(connection);
    if (!peer || peer.role !== 'runner' || peer.record.lost || peer.record.hello
      || peer.expiresAt <= now() || typeof caller !== 'string' || !caller) refuse();
    const record = peer.record;
    const bytes = canonicalBytes(payload);
    if (bytes.length === 0 || bytes.length > 4096 || sha(bytes) !== hello_payload_sha256
      || payload?.soul_id !== record.installed.soul_id
      || payload?.installation_id !== record.installed.installation_id
      || payload?.definition_digest !== record.installed.claimed_definition_digest
      || payload?.requested_profile !== 'managed-protected') refuse();
    const bind = record.getBindReceiptSHA256();
    if (!DIGEST.test(bind ?? '')) refuse();
    const reply = await machineHelloStart({ ...record.selectors,
      peer_uid: connection.peer_uid, peer_pid: connection.peer_pid,
      hello_payload_base64url: bytes.toString('base64url'),
      hello_payload_sha256, broker_bind_receipt_sha256: bind });
    const signed = checkedReply(reply, machinePublicKey, START_PURPOSE,
      'agent-bot-machine/stage2a-hello-start/v1', record.selectors);
    const members = payload.requested_roles?.map((role) => role.member_id).sort();
    if (signed.peer_uid !== connection.peer_uid || signed.peer_pid !== connection.peer_pid
      || signed.peer_process?.pid !== connection.peer_pid
      || signed.peer_process?.uid !== connection.peer_uid
      || signed.soul_id !== record.installed.soul_id
      || signed.host_id !== record.installed.host_id
      || signed.definition_digest !== payload.definition_digest
      || signed.definition_measurement !== record.installed.definition_measurement
      || signed.launch_input_measurement !== record.installed.launch_input_measurement
      || signed.profile_in_force !== 'managed-protected'
      || signed.broker_bind_receipt_sha256 !== bind
      || !DIGEST.test(signed.bridge_finalization_sha256 ?? '')
      || signed.hello_payload_sha256 !== hello_payload_sha256
      || signed.hello_request_id !== payload.request_id
      || !Array.isArray(members) || !same(signed.requested_member_ids, members)
      || signed.runner?.uid !== record.installed.runner_uid
      || signed.bridge?.uid !== record.installed.bridge_uid
      || !Number.isFinite(Date.parse(signed.issued_at))) refuse();
    const binding = Object.freeze({ ...record.selectors,
      soul_id: signed.soul_id, definition_digest: signed.definition_digest,
      definition_measurement: signed.definition_measurement,
      launch_input_measurement: signed.launch_input_measurement,
      broker_bind_receipt_sha256: signed.broker_bind_receipt_sha256,
      hello_payload_sha256: signed.hello_payload_sha256,
      profile_in_force: signed.profile_in_force });
    record.hello = Object.freeze({ binding, startSHA256: reply.sha256,
      bridgeFinalizationSHA256: signed.bridge_finalization_sha256,
      runnerPID: signed.runner?.pid, bridgePID: signed.bridge?.pid,
      requestedMemberIDs: members, caller, connection });
    bindings.set(binding, record);
    record.lastLiveAt = now();
    return binding;
  }

  async function verifyDefinitionMapping(binding, payload) {
    const record = recordForBinding(binding);
    if (!record
      || binding.soul_id !== payload?.soul_id
      || binding.definition_digest !== payload?.definition_digest
      || binding.installation_id !== payload?.installation_id
      || !same(record.hello.requestedMemberIDs,
        payload?.requested_roles?.map((role) => role.member_id).sort())) refuse();
    return true;
  }

  async function prepareMemberSet(expected, pendingRuntimes) {
    const record = recordForExpected(expected);
    if (!record.prestartMembers) return;
    if (!record.hello || record.finalized || record.prestarted
      || expected.hello_payload_sha256 !== record.hello.binding.hello_payload_sha256) refuse();
    record.prestarted = await record.prestartMembers({ selectors: record.selectors, pendingRuntimes });
    if (!record.prestarted || record.lost) refuse();
  }

  function prestartedFor(selectors) {
    const record = recordFor(selectors);
    if (!record.finalized || !record.prestarted) refuse();
    return record.prestarted;
  }

  function hasPendingMemberSet(expected) {
    const record = recordForExpected(expected);
    return !!record.prestartMembers && !!record.prestarted && !record.finalized;
  }

  function prepareMemberFinalization(expected) {
    const record = recordForExpected(expected);
    if (!record.hello || !record.prestarted || record.finalized || record.memberFinalization
      || expected.hello_payload_sha256 !== record.hello.binding.hello_payload_sha256) refuse();
    const prepared = prepareStage2aMemberFinalization({
      prestarted: record.prestarted, expected, primaryAssignment: record.assignment, now: now(),
    });
    record.preparedMemberFinalization = prepared;
    return prepared;
  }

  async function commitMemberFinalization(expected, prepared) {
    const record = recordForExpected(expected);
    if (!record.prestarted || record.finalized || record.lost
      || record.preparedMemberFinalization !== prepared
      || !DIGEST.test(prepared?.sha256 ?? '')
      || !Buffer.isBuffer(prepared?.bytes)
      || sha(prepared.bytes) !== prepared.sha256) refuse();
    const key = `${record.selectors.installation_id}\u0000${record.selectors.start_id}`;
    const committed = await readCommittedMemberFinalization(key, prepared.sha256, { allowPending: true });
    if (!Buffer.isBuffer(committed?.bytes) || !committed.bytes.equals(prepared.bytes)
      || committed.row?.reservation_sha256 !== record.selectors.reservation_sha256
      || committed.row?.state !== 'member-finalization-pending') refuse();
    // H cannot traverse B's private relay directory. A must independently
    // authenticate the native B/R relay provenance before this call can run.
    if (await verifyRelayProvenance({ selectors: record.selectors, prepared }) !== true) refuse();
    const reply = await machineMemberFinalization({ ...record.selectors,
      finalization_base64url: prepared.bytes.toString('base64url'),
      finalization_sha256: prepared.sha256 });
    if (!Buffer.isBuffer(reply?.envelope) || sha(reply.envelope) !== reply.sha256) refuse();
    const signed = verifyStage2aMachineEnvelope(reply.envelope, machinePublicKey,
      MEMBER_FINAL_PURPOSE, { maxBytes: 8192 });
    const ack = signed.payload;
    if (signed.envelope_sha256 !== reply.sha256
      || ack?.contract !== 'machine/v3' || ack.kind !== 'stage2a-member-finalization-ack'
      || ack.schema_version !== 1 || ack.profile_in_force !== 'managed-protected'
      || ack.host_id !== prepared.record.host_id
      || ack.installation_id !== expected.installation_id
      || ack.soul_id !== prepared.record.soul_id
      || ack.start_id !== expected.start_id || ack.hq_epoch !== expected.hq_epoch
      || ack.launch_id !== expected.launch_id
      || ack.reservation_sha256 !== expected.reservation_sha256
      || ack.plan_id !== record.selectors.plan_id
      || ack.plan_digest !== record.selectors.plan_digest
      || ack.hq_finalization_sha256 !== prepared.sha256
      || ack.ready_envelope_sha256 !== prepared.record.ready_envelope_sha256
      || ack.child_observation_envelope_sha256 !== prepared.record.child_observation_envelope_sha256
      || !Number.isFinite(Date.parse(ack.issued_at))
      || Date.parse(ack.issued_at) > now()
      || now() - Date.parse(ack.issued_at) > 5000) refuse();
    record.memberFinalization = Object.freeze({ prepared, ackEnvelope: Buffer.from(reply.envelope),
      ackSHA256: reply.sha256 });
    return Object.freeze({ sha256: prepared.sha256, ackSHA256: reply.sha256 });
  }

  function activateMemberFinalization(expected, finalizationSHA256) {
    const record = recordForExpected(expected);
    if (record.finalized || record.lost || !record.memberFinalization
      || record.memberFinalization.prepared.sha256 !== finalizationSHA256) refuse();
    record.finalized = true;
    return true;
  }

  function memberFinalizationFor(selectors) {
    const record = recordFor(selectors);
    if (!record.finalized || !record.memberFinalization) refuse();
    return record.memberFinalization;
  }

  async function renewMemberRuntime(request, connection) {
    const peer = peerFor(connection);
    const record = peer?.record;
    const final = record?.memberFinalization;
    if (!peer || peer.role !== 'child' || peer.socket?.destroyed || peer.expiresAt <= now()
      || !record.finalized || record.lost || !final
      || !stopMatches(request, record.selectors)
      || request.hq_finalization_sha256 !== final.prepared.sha256
      || request.ready_envelope_sha256 !== final.prepared.record.ready_envelope_sha256
      || request.child_observation_envelope_sha256
        !== final.prepared.record.child_observation_envelope_sha256
      || request.launcher_pid !== peer.peerProcess.pid
      || connection.peer_pid !== peer.peerProcess.pid
      || connection.peer_uid !== record.installed.runner_uid
      || !DIGEST.test(request.grant_sha256 ?? '')) refuse();
    const member = final.prepared.record.members.find((row) => row.member_id === request.member_id);
    if (!member || member.member_selector !== request.member_selector
      || member.member_launch_id !== request.member_launch_id
      || member.grant_sha256 !== request.grant_sha256
      || member.launcher_process.pid !== request.launcher_pid
      || member.child_process.pid !== request.child_pid) refuse();
    const previous = record.issuedMemberLeases.get(request.member_id);
    if (request.after_sequence === 0) {
      if (previous || request.previous_lease_envelope_sha256 !== null
        || Date.parse(request.prior_expires_at)
          !== Date.parse(record.prestarted.ready.payload.expires_at)
        || Date.parse(record.prestarted.ready.payload.expires_at) <= now()) refuse();
    } else if (!previous || previous.sequence !== request.after_sequence
      || previous.sha256 !== request.previous_lease_envelope_sha256
      || previous.expiresAt !== Date.parse(request.prior_expires_at)
      || previous.expiresAt <= now()) refuse();
    const key = `${record.selectors.installation_id}\u0000${record.selectors.start_id}`;
    const committed = await readCommittedMemberFinalization(key, final.prepared.sha256);
    if (!Buffer.isBuffer(committed?.bytes)
      || !committed.bytes.equals(final.prepared.bytes)
      || committed.row?.state !== 'active'
      || committed.row?.reservation_sha256 !== record.selectors.reservation_sha256) refuse();
    if (await verifyRelayProvenance({ selectors: record.selectors,
      prepared: final.prepared }) !== true) refuse();
    const result = await machineMemberRuntime({ ...record.selectors,
      member_id: request.member_id, member_selector: request.member_selector,
      member_launch_id: request.member_launch_id, grant_sha256: request.grant_sha256,
      child_observation_envelope_sha256: request.child_observation_envelope_sha256,
      launcher_pid: request.launcher_pid, child_pid: request.child_pid,
      peer_uid: connection.peer_uid, peer_pid: connection.peer_pid,
      challenge_nonce_base64url: request.challenge_nonce_base64url,
      after_sequence: request.after_sequence, prior_expires_at: request.prior_expires_at,
      ready_envelope_sha256: request.ready_envelope_sha256,
      previous_lease_envelope_sha256: request.previous_lease_envelope_sha256,
      hq_finalization_base64url: committed.bytes.toString('base64url'),
      hq_finalization_sha256: committed.sha256 });
    const encoded = result?.lease_envelope_base64url;
    if (typeof encoded !== 'string' || !/^[A-Za-z0-9_-]{1,10924}$/.test(encoded)
      || Buffer.from(encoded, 'base64url').toString('base64url') !== encoded
      || !DIGEST.test(result.lease_sha256 ?? '')
      || result.lease_sequence !== request.after_sequence + 1) refuse();
    const envelope = Buffer.from(encoded, 'base64url');
    if (sha(envelope) !== result.lease_sha256) refuse();
    const verified = verifyStage2aMachineEnvelope(envelope, machinePublicKey,
      'agent-bot/stage2a-member-runtime-lease/v1', { maxBytes: 8192 });
    const lease = verified.payload;
    if (verified.envelope_sha256 !== result.lease_sha256
      || lease?.contract !== 'machine/v3' || lease.kind !== 'stage2a-member-runtime-lease'
      || lease.schema_version !== 1 || lease.profile_in_force !== 'managed-protected'
      || lease.host_id !== final.prepared.record.host_id
      || lease.installation_id !== record.selectors.installation_id
      || lease.start_id !== record.selectors.start_id || lease.hq_epoch !== record.selectors.hq_epoch
      || lease.reservation_sha256 !== record.selectors.reservation_sha256
      || lease.member_id !== member.member_id || lease.member_selector !== member.member_selector
      || lease.member_launch_id !== member.member_launch_id
      || lease.grant_sha256 !== member.grant_sha256
      || !same(lease.launcher_process, member.launcher_process)
      || !same(lease.child_process, member.child_process)
      || lease.assignment_envelope_sha256 !== final.prepared.record.assignment_envelope_sha256
      || lease.child_observation_envelope_sha256 !== request.child_observation_envelope_sha256
      || lease.ready_envelope_sha256 !== request.ready_envelope_sha256
      || lease.member_b_authority_envelope_sha256
        !== final.prepared.record.member_b_authority_envelope_sha256
      || lease.bridge_arm_receipt_sha256 !== member.bridge_arm_receipt_sha256
      || lease.bind_receipt_sha256 !== final.prepared.record.bind_receipt_sha256
      || lease.hq_finalization_sha256 !== committed.sha256
      || lease.challenge_nonce_base64url !== request.challenge_nonce_base64url
      || lease.sequence !== result.lease_sequence
      || lease.previous_lease_envelope_sha256 !== request.previous_lease_envelope_sha256
      || !Number.isFinite(Date.parse(lease.issued_at))
      || !Number.isFinite(Date.parse(lease.expires_at))
      || !Number.isFinite(Date.parse(lease.approved_until))
      || Date.parse(lease.issued_at) > now() || Date.parse(lease.expires_at) <= now()
      || Date.parse(lease.expires_at) > Date.parse(lease.approved_until)
      || Date.parse(lease.expires_at) - Date.parse(lease.issued_at) > 5000) refuse();
    record.issuedMemberLeases.set(member.member_id, Object.freeze({ sequence: lease.sequence,
      sha256: result.lease_sha256, expiresAt: Date.parse(lease.expires_at) }));
    return Object.freeze({ lease_envelope_base64url: encoded,
      lease_sha256: result.lease_sha256, lease_sequence: lease.sequence });
  }

  async function finalize(expected) {
    const record = recordForExpected(expected);
    const hello = record.hello;
    if (!hello || record.finalized || expected.hello_payload_sha256 !== hello.binding.hello_payload_sha256
      || expected.definition_measurement !== hello.binding.definition_measurement
      || expected.launch_input_measurement !== hello.binding.launch_input_measurement
      || expected.hq_broker_bind_receipt_sha256 !== hello.binding.broker_bind_receipt_sha256
      || expected.soul_id !== hello.binding.soul_id
      || expected.definition_digest !== hello.binding.definition_digest
      || expected.profile_in_force !== 'managed-protected'
      || !Number.isSafeInteger(expected.installation_epoch)
      || expected.installation_epoch < 1) refuse();
    if (record.prestartMembers) refuse();
    const reply = await machineHelloFinalize({ ...record.selectors,
      start_envelope_sha256: hello.startSHA256, expected });
    const signed = checkedReply(reply, machinePublicKey, FINAL_PURPOSE,
      'agent-bot-machine/stage2a-hello-finalization/v1', record.selectors);
    if (signed.start_envelope_sha256 !== hello.startSHA256
      || !same(signed.expected, expected)
      || !Number.isFinite(Date.parse(signed.finalized_at))) refuse();
    record.finalSHA256 = reply.sha256;
    record.finalEnvelope = Buffer.from(reply.envelope);
    return Object.freeze({ ...reply, expected });
  }

  async function verifyFinalization(finalization, expected) {
    const record = recordForExpected(expected);
    if (!record.hello || !DIGEST.test(record.finalSHA256 ?? '')
      || finalization?.sha256 !== record.finalSHA256
      || !same(finalization.expected, expected)) refuse();
    checkedReply(finalization, machinePublicKey, FINAL_PURPOSE,
      'agent-bot-machine/stage2a-hello-finalization/v1', record.selectors);
    record.finalized = true;
    return true;
  }

  function finalizationFor(selectors) {
    const record = recordFor(selectors);
    if (!record.finalized || !Buffer.isBuffer(record.finalEnvelope)
      || sha(record.finalEnvelope) !== record.finalSHA256) refuse();
    return Object.freeze({ envelope: Buffer.from(record.finalEnvelope),
      sha256: record.finalSHA256 });
  }

  async function abort(binding) {
    const record = bindings.get(binding)
      ?? peerFor(binding?.connection)?.record
      ?? starts.get(binding?.reservation_sha256);
    if (!record) refuse();
    if (record.abortPromise) return record.abortPromise;
    record.lost = true;
    clearInterval(record.timer);
    record.abortPromise = Promise.allSettled([
      machineHelloAbort(record.selectors),
      stopReservation(record.selectors.reservation_sha256),
    ]).then((results) => {
      if (results.some((item) => item.status === 'rejected')) refuse();
    });
    return record.abortPromise;
  }

  function watchLiveness(binding, onLost) {
    const record = recordForBinding(binding);
    if (record.watch || typeof onLost !== 'function') refuse();
    record.watch = onLost;
    record.timer = setInterval(() => {
      void assertLive(binding).catch(() => {
        if (record.lost) return;
        record.lost = true;
        onLost();
      });
    }, 1000);
    record.timer.unref?.();
    return () => { clearInterval(record.timer); record.watch = null; };
  }

  function watchHealthy(binding) {
    const record = recordForBinding(binding);
    return !!record.watch && now() - record.lastLiveAt < 5000;
  }

  async function assertLive(binding) {
    const record = recordForBinding(binding);
    const connection = record.hello.connection;
    const peer = peerFor(connection);
    if (!peer || peer.record !== record || peer.role !== 'runner') refuse();
    const [live, roleReply] = await Promise.all([
      authority.currentLiveStart(record.selectors.reservation_sha256),
      machinePeerRole({ ...record.selectors,
        peer_uid: connection.peer_uid, peer_pid: connection.peer_pid }),
    ]);
    const signedRole = checkedReply(roleReply, machinePublicKey, PEER_PURPOSE,
      'agent-bot-machine/stage2a-peer-role/v1', record.selectors);
    if (signedRole.role !== 'runner' || signedRole.peer_uid !== connection.peer_uid
      || signedRole.peer_pid !== connection.peer_pid
      || !same(signedRole.peer_process, peer.peerProcess)
      || !Number.isSafeInteger(signedRole.issued_at_ms)
      || !Number.isSafeInteger(signedRole.expires_at_ms)
      || signedRole.issued_at_ms > now() || signedRole.expires_at_ms <= now()
      || signedRole.expires_at_ms - signedRole.issued_at_ms > 5000) refuse();
    if (live?.phase !== 'finalized' || live.reservation_sha256 !== record.selectors.reservation_sha256
      || live.runner_pid !== record.hello.runnerPID
      || live.bridge_pid !== record.hello.bridgePID
      || live.finalization_sha256 !== record.hello.bridgeFinalizationSHA256
      || live.bind_receipt_sha256 !== record.hello.binding.broker_bind_receipt_sha256
      || !Number.isSafeInteger(live.finalized_live_expires_at)
      || live.finalized_live_expires_at <= now() || record.lost) refuse();
    record.lastLiveAt = now();
    return true;
  }

  async function peerDisconnected(_socket, context) {
    const peer = peerFor(context);
    if (!peer || peer.record.lost) return;
    peer.record.watch?.();
    await abort(context);
  }

  return Object.freeze({ registerStart, acceptPeer, refreshRunnerPeer, verifyHelloStart, prepareMemberSet, prestartedFor,
    hasPendingMemberSet,
    prepareMemberFinalization, commitMemberFinalization, activateMemberFinalization,
    memberFinalizationFor, renewMemberRuntime,
    verifyDefinitionMapping, finalize, verifyFinalization, abort,
    finalizationFor, watchLiveness, assertLive, peerDisconnected, watchHealthy });
}
