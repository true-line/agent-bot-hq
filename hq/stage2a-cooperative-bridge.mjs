// HQ-private verification of A's detached cooperative B assignment. The
// primary reservation has its own verifier and is the only record sent to R.
import { createHash } from 'node:crypto';
import { dirname, join } from 'node:path';
import { canonicalDigest, canonicalize } from '../sdk/wire/canonical-json.mjs';
import { DARWIN_HARNESS_DIR } from './darwin-harness-accounts.mjs';
import { planBridgeEndpoints } from './bridge-endpoints.mjs';
import { verifyStage2aBridgeMemberAuthority } from './stage2a-relay-peer.mjs';
import { validate } from '../sdk/wire/schema.mjs';
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
    assignmentSHA256: checked.envelope_sha256, reservationSHA256: reservation.sha256,
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


// B policy is read once on the bootstrap connection that supplied the
// verified HMAC. The wrapper proof verifier is separately pinned by the
// trusted entry point. Until A exposes that proof, no policy can be read.
export function createCooperativeBPolicyDelivery({ reservation, bridgeAssignment, machinePublicKey,
  assignmentSchema, authoritySchema, requestSchema, resultSchema, schemaReferences, expected, boundConnection,
  verifyWrapperBind, loadPolicy, now = Date.now } = {}) {
  const a = reservation?.payload?.assignment;
  if (!a || reservation.payload.adapter_transport !== 'brokered-b'
    || bridgeAssignment?.reservationSHA256 !== reservation.sha256
    || !assignmentSchema || !authoritySchema || !requestSchema || !resultSchema
    || [boundConnection, verifyWrapperBind, loadPolicy, now].some((fn) => typeof fn !== 'function')) refuse();
  let pending = false;
  let delivered = false;
  const matches = (left, right, fields) => fields.every((key) => left?.[key] === right?.[key]);
  const processFields = ['uid', 'gid', 'pid', 'pid_version', 'start_seconds', 'start_micros'];

  return async function readPolicy(request, { connection } = {}, receipt) {
    if (pending || delivered || typeof connection !== 'string' || !/^[0-9a-f]{64}$/.test(receipt ?? '')
      || request?.reservation_sha256 !== reservation.sha256
      || request?.bridge_assignment_envelope_sha256 !== bridgeAssignment.assignmentSHA256
      || validate(requestSchema, request, { schemas: schemaReferences }).length) refuse();
    pending = true;
    try {
      const binding = await boundConnection(connection, receipt);
      const peer = binding?.kernelBridge;
      if (!binding || binding.connection !== connection || binding.receiptSHA256 !== digest(receipt)
        || binding.reservationSHA256 !== reservation.sha256
        || binding.bridgeAssignmentSHA256 !== bridgeAssignment.assignmentSHA256
        || binding.brokerPath !== bridgeAssignment.endpoint.path
        || peer?.uid !== bridgeAssignment.endpoint.uid || peer.gid !== bridgeAssignment.endpoint.gid
        || !Number.isSafeInteger(peer.pid) || peer.pid < 2 || !Number.isSafeInteger(peer.pid_version)
        || peer.pid_version < 1 || peer.pid_version > 0xffffffff
        || !Number.isSafeInteger(peer.start_seconds) || peer.start_seconds < 1
        || !Number.isSafeInteger(peer.start_micros) || peer.start_micros < 0 || peer.start_micros >= 1e6
        || typeof binding.isCurrent !== 'function' || binding.isCurrent() !== true) refuse();

      const wrapper = await verifyWrapperBind(binding.wrapperBindBytes);
      const expires = Date.parse(wrapper?.expiresAt ?? '');
      if (!wrapper || wrapper.receiptSHA256 !== binding.receiptSHA256
        || wrapper.reservationSHA256 !== reservation.sha256
        || wrapper.bridgeAssignmentSHA256 !== bridgeAssignment.assignmentSHA256
        || wrapper.brokerPath !== bridgeAssignment.endpoint.path
        || !matches(wrapper, a, SELECTORS) || !matches(wrapper.bridgeProcess, peer, processFields)
        || !Number.isFinite(expires) || expires <= now() || binding.isCurrent() !== true) refuse();
      const records = await loadPolicy(binding);
      if (!records || binding.isCurrent() !== true || expires <= now()) refuse();
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
      delivered = true;
      return result;
    } finally { pending = false; }
  };
}
