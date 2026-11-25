// HQ's paired Machine verifier for the per-start R admission listener.
// H observes the accepted socket; A independently reobserves its process,
// frozen inputs and B bind before signing each role and Hello transition.
import { createHash } from 'node:crypto';
import { canonicalBytes, canonicalize } from '../sdk/wire/canonical-json.mjs';
import { machineRoleStage2aPeerRole, machineRoleStage2aHelloStart,
  machineRoleStage2aHelloFinalize, machineRoleStage2aHelloAbort } from './machine-channel.mjs';
import { verifyStage2aMachineEnvelope } from './stage2a-stop.mjs';

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const STOP_FIELDS = ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
  'plan_id', 'plan_digest', 'hq_epoch'];
const PEER_PURPOSE = 'agent-bot/stage2a-peer-role/v1';
const START_PURPOSE = 'agent-bot/stage2a-hello-start/v1';
const FINAL_PURPOSE = 'agent-bot/stage2a-hello-finalization/v1';
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
  machineHelloAbort = machineRoleStage2aHelloAbort,
  stopReservation, now = () => Date.now() } = {}) {
  if (!Buffer.isBuffer(machinePublicKey) || machinePublicKey.length !== 32
    || typeof authority?.currentLiveStart !== 'function'
    || [machinePeerRole, machineHelloStart, machineHelloFinalize, machineHelloAbort,
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
      lastLiveAt: now(), watch: null, timer: null };
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
    if (record.prestartMembers && !record.prestarted) refuse();
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
    verifyDefinitionMapping, finalize, verifyFinalization, abort,
    finalizationFor, watchLiveness, assertLive, peerDisconnected, watchHealthy });
}
