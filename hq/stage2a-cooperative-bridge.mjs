// HQ-private verification of A's detached cooperative B assignment. The
// primary reservation has its own verifier and is the only record sent to R.
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { canonicalDigest, canonicalize } from '../sdk/wire/canonical-json.mjs';
import { DARWIN_HARNESS_DIR } from './darwin-harness-accounts.mjs';
import { planBridgeEndpoints } from './bridge-endpoints.mjs';
import { createStage2aMemberArmExchange, verifyStage2aBridgeMemberAuthority } from './stage2a-relay-peer.mjs';
import { validate } from '../sdk/wire/schema.mjs';
import { verifyCooperativeProof } from './stage2a-cooperative-proof.mjs';
import { startStage2aRole } from './stage2a-role-launch.mjs';
import { verifyStage2aMachineEnvelope } from './stage2a-stop.mjs';

const PURPOSE = 'agent-bot/soul-cooperative-bridge-assignment/v3';
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const POSITIVE_DECIMAL = /^[1-9][0-9]{0,19}$/;
const SELECTORS = ['installation_id', 'start_id', 'launch_id', 'plan_id', 'plan_digest', 'hq_epoch'];
const digest = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const same = (a, b) => a !== undefined && b !== undefined && canonicalize(a) === canonicalize(b);
const refuse = () => { throw new Error('invalid Machine cooperative bridge assignment'); };

function endpointMatches(endpoint, directory, socketPath, owner, group, peer) {
  return endpoint?.directory === directory && endpoint.socket_path === socketPath
    && Buffer.byteLength(socketPath) <= 103 && endpoint.owner_uid === owner
    && endpoint.group_gid === group && endpoint.expected_peer_uid === peer
    && endpoint.dir_mode === 0o2750 && endpoint.socket_mode === 0o660
    && ['parent_device', 'parent_inode', 'parent_birthtime_ns'].every((field) =>
      typeof endpoint[field] === 'string' && POSITIVE_DECIMAL.test(endpoint[field]));
}

export function verifyCooperativeBridgeAssignment(raw, { machinePublicKey, reservation, installedBridge,
  validatePayload, platform = process.platform, account, hqUid, harnessUids, now = Date.now } = {}) {
  // reservation is HQ's trusted projection of the verified primary envelope.
  // installedBridge comes from the installed owner plan before reservation.
  if (typeof validatePayload !== 'function' || !installedBridge || !Array.isArray(harnessUids)
    || typeof now !== 'function') refuse();
  let checked;
  try {
    checked = verifyStage2aMachineEnvelope(raw, machinePublicKey, PURPOSE, {
      schemaVersion: 3, maxBytes: 16384,
    });
  } catch { refuse(); }
  const p = checked.payload;
  if (validatePayload(structuredClone(p)) !== true) refuse();
  const r = reservation?.payload;
  const a = r?.assignment;
  const b = p?.bridge;
  if (!a || !b || !DIGEST.test(reservation.sha256 ?? '')
    || r.contract !== 'machine/v3' || r.adapter_transport !== 'brokered-b'
    || r.measurement_binding?.profile_in_force !== 'managed-cooperative'
    || Object.keys(r.endpoints ?? {}).sort().join(',') !== 'admission,member,relay'
    || p.contract !== 'machine/v3' || p.kind !== 'soul-cooperative-bridge-assignment'
    || p.schema_version !== 3 || p.host_id !== r.host_id || p.expires_at !== r.expires_at
    || p.reservation_sha256 !== reservation.sha256 || !same(b, installedBridge)
    || p.bridge_launch_sha256 !== r.bridge_launch_sha256
    || p.bridge_launch_sha256 !== digest(canonicalize(b))
    || SELECTORS.some((field) => typeof a[field] !== 'string' || !a[field] || p[field] !== a[field])
    || !/^[0-9a-f]{64}$/.test(a.soul_artifact_sha256 ?? '')
    || hqUid !== a.hq_uid || a.runner_uid !== a.runner_gid
    || !Number.isSafeInteger(a.machine_uid) || a.machine_uid <= 0
    || [hqUid, a.runner_uid, b.uid].includes(a.machine_uid)) refuse();
  const time = now(), expires = Date.parse(p.expires_at);
  if (!Number.isSafeInteger(time) || !Number.isSafeInteger(expires) || expires <= time
    || expires - time > 30000) refuse();

  const { broker, member, relay } = p.endpoints ?? {};
  const directory = join(DARWIN_HARNESS_DIR, String(b.account));
  if (!endpointMatches(broker, directory, join(directory, 'broker.sock'), hqUid, b.gid, b.uid)) refuse();
  const [endpoint] = planBridgeEndpoints([{
    installation_id: a.installation_id, runner_uid: a.runner_uid,
    bridge_account: b.account, bridge_uid: b.uid, bridge_gid: b.gid,
    broker: { ...broker, peer_uids: [b.uid] },
  }], { platform, account, hqUid, harnessUids });

  const slot = (domain, ...values) => digest([domain, ...values].join('\0')).slice(7, 27);
  const installSlot = slot('agent-bot-soul-endpoint-installation/v1', a.installation_id);
  const leaf = slot('agent-bot-soul-endpoint-start/v1', a.installation_id, a.start_id) + '.sock';
  const memberDirectory = join(dirname(DARWIN_HARNESS_DIR), 'm', installSlot);
  const relayDirectory = join(dirname(DARWIN_HARNESS_DIR), 's', installSlot);
  if (!endpointMatches(member, memberDirectory, join(memberDirectory, leaf), a.runner_uid, b.gid, b.uid)
    || !endpointMatches(relay, relayDirectory, join(relayDirectory, leaf), b.uid, a.runner_gid, a.runner_uid)
    || !same(member, r.endpoints.member) || !same(relay, r.endpoints.relay)) refuse();

  return Object.freeze({
    assignmentSHA256: checked.envelope_sha256, reservationSHA256: reservation.sha256, account: b.account,
    expires,
    selectors: Object.freeze(Object.fromEntries(SELECTORS.map((field) => [field, a[field]]))),
    soulArtifactSHA256: `sha256:${a.soul_artifact_sha256}`,
    endpoint: Object.freeze({ ...endpoint, parentIdentity: Object.freeze({
      device: broker.parent_device, inode: broker.parent_inode, birthtimeNs: broker.parent_birthtime_ns,
    }) }),
    member: Object.freeze({ ...member, peer_uids: Object.freeze([a.runner_uid, b.uid]) }),
    relay: Object.freeze({ ...relay }),
  });
}

// Compose with bindBridgeAuthority and createBridgeBindAdmission. The entry
// point pins these callbacks to A's durable spent-start, proof and stop
// handlers. The verifier callback must authenticate A's current live reply,
// including any finalized lease. The one-use FD secret stays in A and B.
export function createCooperativeBridgeAuthority({ assignment, reservationBytes, verifyLiveStart,
  verifyProof, containStart, now = Date.now } = {}) {
  if (!assignment?.endpoint || !Buffer.isBuffer(reservationBytes)
    || digest(reservationBytes) !== assignment.reservationSHA256
    || [verifyLiveStart, verifyProof, containStart, now].some((fn) => typeof fn !== 'function')) refuse();
  const envelope = Buffer.from(reservationBytes);
  const { endpoint, member, selectors, reservationSHA256, expires, soulArtifactSHA256 } = assignment;
  const selected = Object.freeze({ reservation_sha256: reservationSHA256, ...selectors });
  let boundConnection;
  let containment;
  const stop = () => {
    containment ??= Promise.resolve().then(() => containStart(selected));
    return containment;
  };
  return Object.freeze({
    async verifyLiveStartV2(input, connection, peer, phase) {
      if (containment || (boundConnection !== undefined && boundConnection !== connection)
        || peer?.endpoint !== endpoint || input.reservation_digest !== reservationSHA256
        || SELECTORS.some((field) => field !== 'hq_epoch' && input[field] !== selectors[field])) refuse();
      boundConnection = connection;
      const status = await verifyLiveStart(selected, peer, phase);
      if (containment || peer.socket.destroyed || !peer.checkCurrent()
        || (status?.phase !== 'prebind' && status?.phase !== 'finalized')
        || (status.phase === 'prebind' && expires <= now())
        || (status.phase === 'finalized' && (phase !== 'receipt'
          || !Number.isSafeInteger(status.expires) || status.expires <= now()))) refuse();
      return Object.freeze({ ...input, hq_epoch: selectors.hq_epoch,
        bridge_uid: endpoint.uid, broker_socket: endpoint.path, member,
        soul_artifact_sha256: soulArtifactSHA256, reservation_bytes: Buffer.from(envelope),
        reservation_expires_at: expires,
        ...(status.phase === 'finalized' ? { finalized_live_expires_at: status.expires } : {}) });
    },
    async verifyProofV2(proof, connection, peer) {
      if (containment || boundConnection !== connection || peer?.endpoint !== endpoint
        || Object.entries(selected).some(([field, value]) => proof[field] !== value)) refuse();
      const verified = await verifyProof(proof, peer);
      return verified === true && !containment;
    },
    retainsChallengeStopV2: (connection) => boundConnection === connection,
    onDisconnectV2(connection) {
      return boundConnection === connection ? stop() : Promise.resolve(true);
    },
  });
}


const PROCESS_IDENTITY = ['pid', 'uid', 'gid', 'start_seconds', 'start_micros'];
const KERNEL_B_IDENTITY = [...PROCESS_IDENTITY, 'pid_version'];
const OBSERVE_FIELDS = ['contract', 'kind', 'schema_version', 'reservation_sha256',
  'bridge_assignment_sha256', 'bind_receipt_sha256', ...SELECTORS, 'grant_nonce',
  'launcher', 'bridge', 'relay_socket', 'observed_at', 'expires_at'];
const matchFields = (left, right, fields) => fields.every((key) => left?.[key] === right?.[key]);
const exactly = (value, keys) => value && Object.keys(value).sort().join(',') === [...keys].sort().join(',');

export function createCooperativeBRoleClient({ reservation, bridgeAssignment, machinePublicKey,
  exchange, now = Date.now } = {}) {
  const a = reservation?.payload?.assignment;
  if (!a || reservation.payload.adapter_transport !== 'brokered-b'
    || bridgeAssignment?.reservationSHA256 !== reservation.sha256
    || typeof exchange !== 'function' || !Buffer.isBuffer(machinePublicKey) || machinePublicKey.length !== 32) refuse();
  const key = Buffer.from(machinePublicKey);
  const call = async (operation, request) => {
    const response = await exchange(`stage2a-cooperative-b-${operation}-v3`, request);
    if (!Buffer.isBuffer(response?.machineKey) || !response.machineKey.equals(key)) refuse();
    return response.body;
  };
  return Object.freeze({
    async exec({ nonce, pid }) {
      if (!Number.isSafeInteger(pid) || pid < 2 || typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(nonce)
        || Buffer.from(nonce, 'base64url').toString('base64url') !== nonce) refuse();
      const body = await call('exec', { reservation_sha256: reservation.sha256,
        installation_id: a.installation_id, start_id: a.start_id, launch_id: a.launch_id, nonce, pid });
      if (!exactly(body, ['envelope_base64url', 'sha256', 'reservation_envelope_base64url', 'bridge_assignment_envelope_base64url'])
        || body.reservation_envelope_base64url !== reservation.envelope_base64url
        || body.bridge_assignment_envelope_base64url !== reservation.bridge_assignment_envelope_base64url) refuse();
      const grant = verifyCooperativeProof({ envelope_base64url: body.envelope_base64url, sha256: body.sha256 },
        key, 'b-exec');
      if (!matchFields(grant, a, ['installation_id', 'start_id', 'launch_id', 'hq_epoch', 'machine_uid'])
        || grant.reservation_sha256 !== reservation.sha256 || grant.bridge_assignment_sha256 !== bridgeAssignment.assignmentSHA256
        || grant.bridge_uid !== bridgeAssignment.endpoint.uid || grant.bridge_gid !== bridgeAssignment.endpoint.gid
        || grant.pid !== pid || grant.nonce !== nonce || !DIGEST.test(grant.proof_sha256)
        || !(Date.parse(grant.issued_at) <= now() && now() < Date.parse(grant.expires_at)
          && Date.parse(grant.expires_at) <= Date.parse(reservation.payload.expires_at))) refuse();
      if (!Number.isSafeInteger(grant.pid_start_sec) || grant.pid_start_sec <= 0
        || !Number.isSafeInteger(grant.pid_start_usec) || grant.pid_start_usec < 0 || grant.pid_start_usec >= 1e6) refuse();
      return Object.freeze({ sha256: body.sha256, grantLine: Buffer.from(JSON.stringify(body) + '\n'),
        launcherProcess: Object.freeze({ pid, uid: grant.bridge_uid, gid: grant.bridge_gid,
          start_seconds: grant.pid_start_sec, start_micros: grant.pid_start_usec }) });
    },
    async loadPolicy(observed) {
      if (!DIGEST.test(observed?.envelopeSHA256 ?? '')
        || observed.reservationSHA256 !== reservation.sha256
        || observed.bridgeAssignmentSHA256 !== bridgeAssignment.assignmentSHA256
        || observed.memberSetAssignmentSHA256 !== reservation.member_set_assignment_sha256
        || !matchFields(observed, bridgeAssignment.selectors, SELECTORS)
        || !(Date.parse(observed.expiresAt) > now())) refuse();
      const response = await exchange('stage2a-cooperative-member-policy-v3', {
        ...bridgeAssignment.selectors, reservation_sha256: reservation.sha256,
        bridge_observed_sha256: observed.envelopeSHA256,
      });
      const body = response?.body;
      if (!Buffer.isBuffer(response?.machineKey) || !response.machineKey.equals(key)
        || !exactly(body, ['member_set_assignment_envelope_base64url', 'member_set_assignment_sha256',
          'member_b_authority_envelope_base64url', 'member_b_authority_sha256', 'bridge_observed_sha256'])
        || body.bridge_observed_sha256 !== observed.envelopeSHA256
        || body.member_set_assignment_sha256 !== reservation.member_set_assignment_sha256
        || body.member_set_assignment_envelope_base64url !== reservation.member_set_assignment_envelope_base64url
        || !(Date.parse(observed.expiresAt) > now())) refuse();
      const decode = (encoded, sha256) => {
        if (typeof encoded !== 'string' || encoded.length > 22_000 || !DIGEST.test(sha256)) refuse();
        const bytes = Buffer.from(encoded, 'base64url');
        if (bytes.length > 16_384 || bytes.toString('base64url') !== encoded || digest(bytes) !== sha256) refuse();
        return bytes;
      };
      return Object.freeze({
        assignmentBytes: decode(body.member_set_assignment_envelope_base64url, body.member_set_assignment_sha256),
        authorityBytes: decode(body.member_b_authority_envelope_base64url, body.member_b_authority_sha256),
      });
    },
    async verifyHMAC({ nonce, proof }) {
      if (!/^[0-9a-f]{64}$/.test(nonce ?? '') || !/^[0-9a-f]{64}$/.test(proof ?? '')) refuse();
      const body = await call('verify', { ...bridgeAssignment.selectors,
        reservation_sha256: reservation.sha256, bridge_assignment_sha256: bridgeAssignment.assignmentSHA256,
        nonce, proof });
      return exactly(body, ['verified']) && body.verified === true;
    },
  });
}

export const COOPERATIVE_B_BIND_CONTEXT = 'agent-bot-stage2a-cooperative-bridge-bind-v3';

export function createCooperativeBBind({ reservation, bridgeAssignment, schema, schemaReferences, machine,
  kernelPeer, random, contain, now = Date.now } = {}) {
  if (!schema || !bridgeAssignment || bridgeAssignment.reservationSHA256 !== reservation?.sha256
    || reservation.payload?.adapter_transport !== 'brokered-b'
    || [machine?.verifyHMAC, kernelPeer, random, contain, now].some((fn) => typeof fn !== 'function')) refuse();
  const { selectors, endpoint } = bridgeAssignment;
  let challenge;
  let claimed = false;
  let bound;
  let stopped = false;
  const check = (value) => { if (validate(schema, value, { schemas: schemaReferences }).length) refuse(); };
  const live = (record) => !stopped && record?.peer.isCurrent() === true && record.expires > now();
  const readPeer = async (record) => {
    const actual = await record.peer.readKernelBridge();
    if (!live(record) || !matchFields(actual, record.identity, KERNEL_B_IDENTITY)) refuse();
    return actual;
  };
  async function stop(connection) {
    if (connection !== challenge?.connection && connection !== bound?.connection) return;
    if (stopped) return;
    stopped = true;
    await contain(selectors);
  }
  async function begin(request, { connection } = {}) {
    if (!exactly(request, []) || typeof connection !== 'string' || !connection || claimed || stopped) refuse();
    check(request);
    claimed = true;
    const peer = await kernelPeer(connection, endpoint);
    const identity = await peer?.readKernelBridge?.();
    if (stopped || peer?.isCurrent() !== true || identity?.uid !== endpoint.uid || identity?.gid !== endpoint.gid
      || !Number.isSafeInteger(identity.pid) || identity.pid < 2 || !Number.isSafeInteger(identity.pid_version)
      || identity.pid_version < 1 || identity.pid_version > 0xffffffff || !Number.isSafeInteger(identity.start_seconds)
      || identity.start_seconds <= 0 || !Number.isSafeInteger(identity.start_micros)
      || identity.start_micros < 0 || identity.start_micros >= 1e6) refuse();
    const nonce = random(32);
    const expires = Math.min(now() + 30_000, Date.parse(reservation.payload.expires_at), bridgeAssignment.expires);
    if (!/^[0-9a-f]{64}$/.test(nonce ?? '') || !(expires > now())) refuse();
    const first = { connection, peer, identity: Object.freeze(Object.fromEntries(KERNEL_B_IDENTITY.map((key) => [key, identity[key]]))),
      nonce, expires };
    challenge = first;
    const result = { nonce, algorithm: 'hmac-sha256', context: COOPERATIVE_B_BIND_CONTEXT,
      hq_epoch: selectors.hq_epoch, expires_at: new Date(expires).toISOString() };
    check(result);
    return Object.freeze(result);
  }
  async function finish(request, { connection } = {}) {
    const first = challenge;
    if (!first || first.connection !== connection || first.spent || !live(first)) refuse();
    first.spent = true;
    try {
      check(request);
      const expected = { ...selectors, nonce: first.nonce, reservation_sha256: reservation.sha256,
        bridge_assignment_envelope_sha256: bridgeAssignment.assignmentSHA256, bridge_uid: endpoint.uid,
        broker_socket_path: endpoint.path };
      if (!exactly(request, [...Object.keys(expected), 'proof_hex'])
        || !matchFields(request, expected, Object.keys(expected)) || !/^[0-9a-f]{64}$/.test(request.proof_hex)) refuse();
      await readPeer(first);
      if (await machine.verifyHMAC({ nonce: request.nonce, proof: request.proof_hex }) !== true) refuse();
      const identity = await readPeer(first);
      const receipt = random(32);
      if (!/^[0-9a-f]{64}$/.test(receipt ?? '')) refuse();
      const record = { contract: 'hq/v1', kind: 'stage2a-cooperative-bridge-bind-receipt', schema_version: 1,
        ...selectors, reservation_sha256: reservation.sha256,
        bridge_assignment_envelope_sha256: bridgeAssignment.assignmentSHA256,
        bridge_uid: endpoint.uid, broker_socket_path: endpoint.path,
        challenge_nonce: first.nonce, expires_at: new Date(first.expires).toISOString(),
        bridge_peer: Object.fromEntries(KERNEL_B_IDENTITY.map((key) => [key, identity[key]])) };
      const receiptSHA256 = canonicalDigest(record);
      bound = { ...first, receipt, receiptSHA256 };
      return Object.freeze({ bind_receipt: receipt, bind_receipt_sha256: receiptSHA256 });
    } catch (error) { await stop(connection); throw error; }
  }
  async function binding(connection, receipt) {
    const record = bound;
    if (!record || connection !== record.connection || receipt !== record.receipt) refuse();
    const identity = await readPeer(record);
    return Object.freeze({ connection, receipt, receiptSHA256: record.receiptSHA256, kernelBridge: identity,
      readKernelBridge: () => readPeer(record), isCurrent: () => live(record),
      brokerPath: endpoint.path, reservationSHA256: reservation.sha256,
      bridgeAssignmentSHA256: bridgeAssignment.assignmentSHA256 });
  }
  return Object.freeze({ begin, finish, binding, stop,
    byReceiptSHA256(sha256) {
      if (!bound || bound.receiptSHA256 !== sha256) refuse();
      return binding(bound.connection, bound.receipt);
    },
  });
}

// Construct this only from the verified reserve result, detached assignment
// and wrapper grant. H never receives the FD4 proof key.
export function createCooperativeBObservation({ reservation, bridgeAssignment, machinePublicKey,
  observationSchema, schemaReferences, grantNonce, launcherProcess, exchange, now = Date.now } = {}) {
  const a = reservation?.payload?.assignment;
  if (!a || !observationSchema || !Buffer.isBuffer(machinePublicKey) || machinePublicKey.length !== 32
    || reservation.payload.adapter_transport !== 'brokered-b'
    || !DIGEST.test(reservation.member_set_assignment_sha256)
    || bridgeAssignment?.reservationSHA256 !== reservation.sha256
    || typeof exchange !== 'function' || !exactly(launcherProcess, PROCESS_IDENTITY)
    || !Number.isSafeInteger(launcherProcess.pid) || launcherProcess.pid < 2
    || typeof grantNonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(grantNonce)
    || Buffer.from(grantNonce, 'base64url').toString('base64url') !== grantNonce) refuse();
  const key = Buffer.from(machinePublicKey);
  let pending;
  let observed;
  return async function observeAfterFD5(binding) {
    const fd5 = binding?.fd5;
    const peer = binding?.kernelBridge && Object.freeze({ ...binding.kernelBridge });
    const socket = fd5?.relay_socket;
    const live = () => typeof binding?.isCurrent === 'function' && binding.isCurrent() === true;
    if (!live() || typeof binding.readKernelBridge !== 'function' || !exactly(fd5, ['bind_receipt_sha256', 'relay_socket',
      'bridge_pid', 'bridge_start_seconds', 'bridge_start_micros', 'grant_nonce'])
      || fd5.grant_nonce !== grantNonce || fd5.bridge_pid !== peer?.pid
      || fd5.bridge_start_seconds !== peer?.start_seconds || fd5.bridge_start_micros !== peer?.start_micros
      || !DIGEST.test(fd5.bind_receipt_sha256) || fd5.bind_receipt_sha256 !== binding.receiptSHA256
      || binding.bridgeAssignmentSHA256 !== bridgeAssignment.assignmentSHA256
      || binding.reservationSHA256 !== reservation.sha256 || binding.brokerPath !== bridgeAssignment.endpoint.path
      || !exactly(socket, ['uid', 'gid', 'device', 'inode', 'mode'])
      || socket.uid !== bridgeAssignment.relay.owner_uid || socket.gid !== bridgeAssignment.relay.group_gid
      || socket.mode !== bridgeAssignment.relay.socket_mode
      || !Number.isSafeInteger(socket.device) || socket.device <= 0
      || !Number.isSafeInteger(socket.inode) || socket.inode <= 0
      || peer?.uid !== bridgeAssignment.endpoint.uid || peer.gid !== bridgeAssignment.endpoint.gid
      || !Number.isSafeInteger(peer.pid) || peer.pid < 2 || peer.pid === launcherProcess.pid
      || !Number.isSafeInteger(peer.pid_version) || peer.pid_version < 1 || peer.pid_version > 0xffffffff
      || !Number.isSafeInteger(peer.start_seconds) || peer.start_seconds <= 0
      || !Number.isSafeInteger(peer.start_micros) || peer.start_micros < 0 || peer.start_micros >= 1e6) refuse();
    const recheckPeer = async () => matchFields(await binding.readKernelBridge(), peer, KERNEL_B_IDENTITY) && live();
    if (!await recheckPeer()) refuse();
    const relay = { path: bridgeAssignment.relay.socket_path,
      socket: { ...socket, device: String(socket.device), inode: String(socket.inode) } };
    const request = { ...bridgeAssignment.selectors, reservation_sha256: reservation.sha256,
      bridge_assignment_sha256: bridgeAssignment.assignmentSHA256, bind_receipt_sha256: fd5.bind_receipt_sha256,
      grant_nonce: grantNonce, bridge_pid: peer.pid, bridge_start_seconds: peer.start_seconds,
      bridge_start_micros: peer.start_micros, relay_socket: relay };
    const bindingSHA256 = canonicalDigest({ connection: binding.connection, request, pid_version: peer.pid_version });
    if (observed) {
      if (observed.bindingSHA256 !== bindingSHA256 || Date.parse(observed.expiresAt) <= now() || !live()) refuse();
      return observed;
    }
    if (pending) refuse();
    pending = true;
    try {
      const response = await exchange('stage2a-cooperative-b-observe-v3', request);
      if (!Buffer.isBuffer(response?.machineKey) || !response.machineKey.equals(key) || !await recheckPeer()) refuse();
      const value = verifyCooperativeProof(response.body, key, 'b-observed');
      const at = Date.parse(value.observed_at), expires = Date.parse(value.expires_at);
      if (!exactly(value, OBSERVE_FIELDS) || validate(observationSchema, value, { schemas: schemaReferences }).length
        || !matchFields(value, request, ['reservation_sha256', 'bridge_assignment_sha256',
          'bind_receipt_sha256', 'grant_nonce', ...SELECTORS])
        || !exactly(value.launcher, PROCESS_IDENTITY) || !exactly(value.bridge, PROCESS_IDENTITY)
        || !matchFields(value.bridge, peer, PROCESS_IDENTITY)
        || !matchFields(value.launcher, launcherProcess, PROCESS_IDENTITY)
        || value.launcher.uid !== peer.uid || value.launcher.gid !== peer.gid
        || !(value.launcher.start_seconds > 0) || !Number.isSafeInteger(value.launcher.start_micros)
        || value.launcher.start_micros < 0 || value.launcher.start_micros >= 1e6
        || canonicalDigest(value.relay_socket) !== canonicalDigest(relay)
        || !(Date.parse(reservation.payload.issued_at) <= at && at <= now() && now() < expires
          && expires <= Date.parse(reservation.payload.expires_at)) || !live()) refuse();
      // PIDVersion and the #85 assignment digest were independently retained
      // by H from the kernel peer and verified reserve adjunct respectively.
      observed = Object.freeze({ bindingSHA256, ...bridgeAssignment.selectors,
        receiptSHA256: value.bind_receipt_sha256, reservationSHA256: value.reservation_sha256,
        bridgeAssignmentSHA256: value.bridge_assignment_sha256, brokerPath: bridgeAssignment.endpoint.path,
        bridgeProcess: Object.freeze({ ...value.bridge, pid_version: peer.pid_version }),
        memberSetAssignmentSHA256: reservation.member_set_assignment_sha256, expiresAt: value.expires_at,
        envelopeSHA256: response.body.sha256, envelopeBase64url: response.body.envelope_base64url });
      return observed;
    } finally { pending = false; }
  };
}

// A narrow opener for the fixed installed cooperative B wrapper. The
// binding lookup resolves the digest emitted on FD5 on the existing broker.
export async function startCooperativeBRole({ reservation, bridgeAssignment, machinePublicKey,
  observationSchema, schemaReferences, exchange, boundByReceiptSHA256, startRole = startStage2aRole,
  now = Date.now } = {}) {
  if (!observationSchema || typeof boundByReceiptSHA256 !== 'function') refuse();
  const machine = createCooperativeBRoleClient({ reservation, bridgeAssignment, machinePublicKey, exchange, now });
  let grantNonce;
  let launcherProcess;
  const wrapper = await startRole({ role: 'bridge', cooperativeBridge: true,
    account: bridgeAssignment.account,
    reservationSHA256: reservation.sha256,
    machineExec: async ({ nonce, pid }) => {
      const grant = await machine.exec({ nonce, pid });
      grantNonce = nonce;
      launcherProcess = grant.launcherProcess;
      return grant;
    },
  });
  try {
    const observeWrapperBind = createCooperativeBObservation({ reservation, bridgeAssignment, machinePublicKey,
      observationSchema, schemaReferences, grantNonce, launcherProcess, exchange, now });
    const fd5 = await wrapper.waitBridgeReady(async (status) => {
      const binding = await boundByReceiptSHA256(status.bind_receipt_sha256);
      await observeWrapperBind({ ...binding, fd5: status });
      return true;
    });
    return Object.freeze({ wrapper, observeWrapperBind: (binding) => observeWrapperBind({ ...binding, fd5 }),
      loadPolicy: machine.loadPolicy });
  } catch (error) {
    await wrapper.stop();
    throw error;
  }
}

// B policy is read once on the bootstrap connection that supplied the
// verified HMAC. The wrapper proof verifier is separately pinned by the
// trusted entry point. Until A exposes that proof, no policy can be read.
export function createCooperativeBPolicyDelivery({ reservation, bridgeAssignment, machinePublicKey,
  assignmentSchema, authoritySchema, requestSchema, resultSchema, schemaReferences, expected, boundConnection,
  observeWrapperBind, loadPolicy, policyDelivered, now = Date.now } = {}) {
  const a = reservation?.payload?.assignment;
  if (!a || reservation.payload.adapter_transport !== 'brokered-b'
    || bridgeAssignment?.reservationSHA256 !== reservation.sha256
    || !assignmentSchema || !authoritySchema || !requestSchema || !resultSchema
    || [boundConnection, observeWrapperBind, loadPolicy, now].some((fn) => typeof fn !== 'function')) refuse();
  let pending = false;
  let delivered = false;
  const matches = (left, right, fields) => fields.every((key) => left?.[key] === right?.[key]);


  return async function readPolicy(request, { connection } = {}, receipt) {
    if (pending || delivered || typeof connection !== 'string' || !/^[0-9a-f]{64}$/.test(receipt ?? '')
      || request?.reservation_sha256 !== reservation.sha256
      || request?.bridge_assignment_envelope_sha256 !== bridgeAssignment.assignmentSHA256
      || validate(requestSchema, request, { schemas: schemaReferences }).length) refuse();
    pending = true;
    try {
      const binding = await boundConnection(connection, receipt);
      const peer = binding?.kernelBridge && Object.freeze({ ...binding.kernelBridge });
      if (!binding || binding.connection !== connection || binding.receipt !== receipt || !DIGEST.test(binding.receiptSHA256)
        || binding.reservationSHA256 !== reservation.sha256
        || binding.bridgeAssignmentSHA256 !== bridgeAssignment.assignmentSHA256
        || binding.brokerPath !== bridgeAssignment.endpoint.path
        || peer?.uid !== bridgeAssignment.endpoint.uid || peer.gid !== bridgeAssignment.endpoint.gid
        || !Number.isSafeInteger(peer.pid) || peer.pid < 2 || !Number.isSafeInteger(peer.pid_version)
        || peer.pid_version < 1 || peer.pid_version > 0xffffffff
        || !Number.isSafeInteger(peer.start_seconds) || peer.start_seconds < 1
        || !Number.isSafeInteger(peer.start_micros) || peer.start_micros < 0 || peer.start_micros >= 1e6
        || typeof binding.isCurrent !== 'function' || binding.isCurrent() !== true
        || typeof binding.readKernelBridge !== 'function') refuse();

      const wrapper = await observeWrapperBind(binding);
      const expires = Date.parse(wrapper?.expiresAt ?? '');
      if (!wrapper || wrapper.receiptSHA256 !== binding.receiptSHA256
        || wrapper.reservationSHA256 !== reservation.sha256
        || wrapper.bridgeAssignmentSHA256 !== bridgeAssignment.assignmentSHA256
        || wrapper.brokerPath !== bridgeAssignment.endpoint.path
        || !matches(wrapper, a, SELECTORS) || !matches(wrapper.bridgeProcess, peer, KERNEL_B_IDENTITY)
        || !Number.isFinite(expires) || expires <= now() || binding.isCurrent() !== true) refuse();
      const records = await loadPolicy(wrapper, binding);
      if (!records || !matches(await binding.readKernelBridge(), peer, KERNEL_B_IDENTITY)
        || binding.isCurrent() !== true || expires <= now()) refuse();
      const proof = verifyStage2aBridgeMemberAuthority(records.authorityBytes, { machinePublicKey,
        schema: authoritySchema, assignmentSchema, schemas: schemaReferences,
        assignmentBytes: records.assignmentBytes, expected: { ...expected,
          ...Object.fromEntries(SELECTORS.filter((key) => key !== 'launch_id').map((key) => [key, a[key]])),
          reservation_sha256: reservation.sha256, soul_id: a.soul_id, host_id: reservation.payload.host_id,
          profile_in_force: 'managed-cooperative', runner_uid: a.runner_uid, hq_uid: a.hq_uid,
          bridge_uid: bridgeAssignment.endpoint.uid, bridge_gid: bridgeAssignment.endpoint.gid,
          broker_socket: bridgeAssignment.endpoint.path },
        now: now() });
      const authority = proof.payload;
      if (authority.b_authority.envelope_sha256 !== bridgeAssignment.assignmentSHA256
        || wrapper.memberSetAssignmentSHA256 !== authority.member_set_assignment_envelope_sha256
        || (wrapper.memberBAuthoritySHA256 !== undefined
          && wrapper.memberBAuthoritySHA256 !== proof.envelope_sha256)
        || canonicalDigest(authority.bridge.endpoints.member) !== canonicalDigest(reservation.payload.endpoints.member)
        || canonicalDigest(authority.bridge.endpoints.relay) !== canonicalDigest(reservation.payload.endpoints.relay)
        || binding.isCurrent() !== true) refuse();
      const result = Object.freeze({
        member_set_assignment_envelope_base64url: records.assignmentBytes.toString('base64url'),
        member_set_assignment_envelope_sha256: authority.member_set_assignment_envelope_sha256,
        member_b_authority_envelope_base64url: records.authorityBytes.toString('base64url'),
        member_b_authority_envelope_sha256: proof.envelope_sha256,
      });
      if (validate(resultSchema, result, { schemas: schemaReferences }).length) refuse();
      policyDelivered?.(Object.freeze({ binding, wrapper, records, proof }));
      delivered = true;
      return result;
    } finally { pending = false; }
  };
}


function createCooperativeBArmStage({ schemas, schemaReferences, reservation, bind, finalizeMemberReady, now }) {
  let policy, observation;
  const arms = new Map();
  let resolvePolicy, rejectPolicy, resolveReady, rejectReady;
  const policyResult = new Promise((resolve, reject) => { resolvePolicy = resolve; rejectPolicy = reject; });
  void policyResult.catch(() => {});
  const readyResult = new Promise((resolve, reject) => { resolveReady = resolve; rejectReady = reject; });
  void readyResult.catch(() => {});
  const current = (connection, receipt) => policy?.binding.connection === connection
    && policy.binding.receipt === receipt && policy.binding.isCurrent() === true;
  const exchange = createStage2aMemberArmExchange({
    profile: 'managed-cooperative', current, clock: { now },
    provider: {
      schema: schemas.armExchange, childObservationSchema: schemas.childObservation, schemaReferences,
      observe: () => observation,
      async recordArm(binding, bytes, sha256, arm_request, arm_result) {
        if (!current(binding.connection, binding.receipt) || arms.has(arm_request.member_id)
          || arms.size >= 2 || digest(bytes) !== sha256) refuse();
        arms.set(arm_request.member_id, { arm_request, arm_result, bytes, sha256 });
        if (arms.size === 2) {
          const ordered = [...arms.entries()].sort(([a], [b]) => a.localeCompare(b)).map(([, row]) => row);
          // Defer signing so the second pending ACK can return before the aggregate Ready.
          setImmediate(async () => {
            try {
              if (!current(binding.connection, binding.receipt)) refuse();
              await bind.binding(binding.connection, binding.receipt);
              const readyBytes = await finalizeMemberReady({
                child_observation_envelope_sha256: arm_request.child_observation_envelope_sha256,
                member_b_authority_envelope_sha256: policy.proof.envelope_sha256,
                bridge_observed_sha256: policy.wrapper.envelopeSHA256,
                arms: ordered.map(({ arm_request, arm_result }) => ({ arm_request, arm_result })),
              });
              await bind.binding(binding.connection, binding.receipt);
              const ready = Object.freeze({ readyBytes, armReceiptSHA256s: ordered.map(({ sha256 }) => sha256),
                armRowsBase64url: ordered.map(({ bytes }) => bytes.toString('base64url')),
                bridgeObservedBase64url: policy.wrapper.envelopeBase64url });
              resolveReady(ready);
            } catch (error) { rejectReady(error); }
          });
        }
        return true;
      },
    },
    async boundStart(connection, receipt) {
      const kernel = await bind.binding(connection, receipt);
      if (!current(connection, receipt)) refuse();
      const a = reservation.payload.assignment;
      return Object.freeze({ ...kernel, installation_id: a.installation_id, start_id: a.start_id,
        plan_id: a.plan_id, plan_digest: a.plan_digest, reservation_digest: reservation.sha256,
        assignment_envelope_sha256: policy.proof.payload.member_set_assignment_envelope_sha256,
        authority_envelope_sha256: policy.proof.envelope_sha256, bridge_uid: kernel.kernelBridge.uid,
        member_selectors_sha256: canonicalDigest(policy.proof.payload.members.map((row) => row.member_selector)) });
    },
  });
  return Object.freeze({
    policyDelivered(value) {
      if (policy) refuse();
      policy = value;
      resolvePolicy(value);
    },
    waitForPolicy: () => policyResult,
    observation(value) { if (observation) refuse(); observation = value; },
    waitForReady: () => readyResult,
    verifiedPolicy() {
      if (!policy || !current(policy.binding.connection, policy.binding.receipt)) refuse();
      return policy;
    },
    observe: exchange.observe, arm: exchange.arm,
    close(connection) {
      exchange.forgetConnection(connection);
      if (connection === undefined || policy?.binding.connection === connection) {
        const error = new Error('cooperative B broker closed');
        rejectPolicy(error);
        rejectReady(error);
      }
    },
  });
}

// Register the signed endpoint and callbacks before exec so the fixed B
// wrapper can complete its HMAC challenge on the same listener it will use
// for policy. The role promise releases policy only after signed FD5 proof.
export async function openCooperativeBStage({ reservation, bridgeAssignment, machinePublicKey,
  schemas, schemaReferences, expected, openEndpoint, kernelPeer, exchange, random, contain, finalizeMemberReady,
  now = Date.now } = {}) {
  if (!schemas || typeof openEndpoint !== 'function') refuse();
  const machine = createCooperativeBRoleClient({ reservation, bridgeAssignment, machinePublicKey, exchange, now });
  const bind = createCooperativeBBind({ reservation, bridgeAssignment, schema: schemas.bind,
    schemaReferences, machine, kernelPeer, random, contain, now });
  const armStage = schemas.armExchange && schemas.childObservation && typeof finalizeMemberReady === 'function'
    ? createCooperativeBArmStage({ schemas, schemaReferences, reservation, bind, finalizeMemberReady, now }) : undefined;
  let resolveRole, rejectRole;
  const roleReady = new Promise((resolve, reject) => { resolveRole = resolve; rejectRole = reject; });
  void roleReady.catch(() => {});
  const policy = createCooperativeBPolicyDelivery({ reservation, bridgeAssignment, machinePublicKey,
    assignmentSchema: schemas.assignment, authoritySchema: schemas.authority, requestSchema: schemas.policyRequest,
    resultSchema: schemas.policyResult, schemaReferences, expected, boundConnection: bind.binding, now,
    observeWrapperBind: async (binding) => (await roleReady).observeWrapperBind(binding),
    loadPolicy: async (wrapper) => (await roleReady).loadPolicy(wrapper),
    policyDelivered: armStage?.policyDelivered });
  let endpoint;
  try {
    endpoint = await openEndpoint({ bridgeAssignment, handlers: {
      stage2aCooperativeBBindChallengeV3: bind.begin,
      stage2aCooperativeBBindV3: bind.finish,
      stage2aCooperativeBPolicyV3: policy,
      ...(armStage ? { stage2aCooperativeMemberObserveV3: armStage.observe,
        stage2aCooperativeMemberArmV3: armStage.arm } : {}),
      async forgetBridgeConnection(connection) { armStage?.close(connection); await bind.stop(connection); },
    } });
    const role = await startCooperativeBRole({ reservation, bridgeAssignment, machinePublicKey,
      observationSchema: schemas.observation, schemaReferences, exchange, boundByReceiptSHA256: bind.byReceiptSHA256, now });
    resolveRole(role);
    let closing;
    return Object.freeze({ wrapper: role.wrapper, armStage, close: () => {
      armStage?.close();
      closing ??= Promise.all([role.wrapper.stop(), endpoint.close()]).then(() => {});
      return closing;
    } });
  } catch (error) {
    rejectRole(error);
    armStage?.close();
    await endpoint?.close();
    throw error;
  }
}
