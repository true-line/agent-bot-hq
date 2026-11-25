// HQ's B connection authority. The paired Machine owns every durable claim;
// HQ keeps the exact verified reservation and stops both role processes if
// the authenticated B connection disappears.
import { createHash, randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { canonicalize } from '../sdk/wire/canonical-json.mjs';
import { machineRoleStage2aLive, machineRoleStage2aVerifyB, machineRoleStage2aStop } from './machine-channel.mjs';
import { verifyStage2aFinalization, verifyStage2aStop } from './stage2a-stop.mjs';

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const sha = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const refuse = () => { throw new Error('Machine protected B authority is unavailable'); };

function selectorsOf(payload, reservationSHA256) {
  const a = payload?.assignment;
  if (!a || !DIGEST.test(reservationSHA256 ?? '')) refuse();
  return Object.freeze({ reservation_sha256: reservationSHA256,
    installation_id: a.installation_id, start_id: a.start_id, launch_id: a.launch_id,
    plan_id: a.plan_id, plan_digest: a.plan_digest, hq_epoch: a.hq_epoch });
}

function matchesInstalled(payload, installed) {
  const a = payload?.assignment;
  const m = payload?.measurement_binding;
  if (!a || !m || !installed || payload.host_id !== installed.host_id
    || payload.installed_plan_receipt_sha256 !== installed.root_receipt_sha256
    || m.profile_in_force !== 'managed-protected'
    || !((m.contract === 'machine/v2' && m.schema_version === 2)
      || (payload.kind === 'stage2a-qualification-candidate-reservation'
        && m.contract === 'machine/v3' && m.schema_version === 3))
    || m.definition_measurement !== installed.definition_measurement
    || m.claimed_definition_digest !== installed.claimed_definition_digest
    || m.launch_input_measurement !== installed.launch_input_measurement
    || a.soul_artifact_sha256 !== installed.soul_artifact_sha256
    || m.soul_artifact_sha256 !== installed.soul_artifact_sha256) return false;
  for (const field of ['installation_id', 'soul_id', 'plan_id', 'plan_digest', 'hq_epoch',
    'runner_account', 'runner_uid', 'runner_gid', 'bridge_account', 'bridge_uid',
    'bridge_gid', 'hq_uid', 'machine_uid']) {
    if (a[field] !== installed[field]) return false;
  }
  if (a.package_root !== installed.package_root) return false;
  const startSocket = createHash('sha256').update([
    'agent-bot-soul-endpoint-start/v1', a.installation_id, a.start_id,
  ].join('\0')).digest('hex').slice(0, 20) + '.sock';
  const peers = { broker: [a.bridge_uid], member: [a.runner_uid, a.bridge_uid],
    relay: [a.runner_uid], admission: [a.runner_uid] };
  for (const name of ['broker', 'member', 'relay', 'admission']) {
    const endpoint = a[name];
    const pin = installed[name];
    const socketPath = name === 'broker' ? pin?.socket_path : pin && join(pin.directory, startSocket);
    if (!endpoint || !pin || endpoint.directory !== pin.directory
      || endpoint.socket_path !== socketPath
      || endpoint.owner_uid !== pin.owner_uid || endpoint.group_gid !== pin.group_gid
      || endpoint.dir_mode !== pin.dir_mode || endpoint.socket_mode !== pin.socket_mode
      || !Array.isArray(endpoint.peer_uids) || endpoint.peer_uids.length !== peers[name].length
      || endpoint.peer_uids.some((uid, index) => uid !== peers[name][index])) return false;
  }
  const { socket_path: ignored, ...member } = a.member;
  return payload.member_endpoint?.member_socket === a.member.socket_path
    && canonicalize(payload.member_endpoint.member_endpoint) === canonicalize(member);
}

export function createStage2aMachineBridgeAuthority({ machinePublicKey, verifyReservation,
  machineLive = machineRoleStage2aLive, machineVerifyB = machineRoleStage2aVerifyB,
  machineStop = machineRoleStage2aStop, onStopVerified, now = () => Date.now() } = {}) {
  if (!Buffer.isBuffer(machinePublicKey) || machinePublicKey.length !== 32
    || typeof verifyReservation !== 'function' || typeof machineLive !== 'function'
    || typeof machineVerifyB !== 'function' || typeof machineStop !== 'function'
    || (onStopVerified !== undefined && typeof onStopVerified !== 'function')
    || typeof now !== 'function') refuse();
  const starts = new Map();
  const connections = new Map();

  // verifyReservation must verify the signed contract schema and exact
  // enrolled issuer without spending the claim. Machine Live is the durable
  // active-claim check and is repeated at every admission phase.
  async function register({ envelope, sha256, installed, killRoles, runnerPid = 0,
    bridgePid = 0 } = {}) {
    if (!Buffer.isBuffer(envelope) || !DIGEST.test(sha256 ?? '') || sha(envelope) !== sha256
      || typeof killRoles !== 'function' || ![runnerPid, bridgePid].every((pid) =>
        Number.isSafeInteger(pid) && pid >= 0 && pid !== 1) || starts.has(sha256)) refuse();
    const checked = await verifyReservation(envelope, installed);
    if (checked?.reservationSHA256 !== sha256 || !matchesInstalled(checked.payload, installed)) refuse();
    const selectors = selectorsOf(checked.payload, sha256);
    const expires = Date.parse(checked.payload.expires_at);
    if (!Number.isSafeInteger(expires) || expires <= now()) refuse();
    const record = { envelope: Buffer.from(envelope), payload: checked.payload,
      installed, selectors, expires, killRoles, runnerPid, bridgePid,
      finalization: null, stopPromise: null };
    starts.set(sha256, record);
    return Object.freeze({ ...selectors });
  }

  function setRolePid(reservationSHA256, role, pid) {
    const record = starts.get(reservationSHA256);
    if (!record || !['runner', 'bridge'].includes(role) || !Number.isSafeInteger(pid) || pid < 2) refuse();
    const field = role === 'runner' ? 'runnerPid' : 'bridgePid';
    if (record[field] && record[field] !== pid) refuse();
    record[field] = pid;
  }

  function markFinalized(reservationSHA256, { envelope, sha256: finalSHA256,
    bindReceiptSHA256, relaySocket } = {}) {
    const record = starts.get(reservationSHA256);
    if (!record || record.finalization || record.bridgePid < 2 || !DIGEST.test(bindReceiptSHA256 ?? '')
      || !DIGEST.test(finalSHA256 ?? '') || !Buffer.isBuffer(envelope) || sha(envelope) !== finalSHA256) refuse();
    const checked = verifyStage2aFinalization(envelope, { machinePublicKey,
      expected: { ...record.selectors, bind_receipt_sha256: bindReceiptSHA256,
        relay_socket: relaySocket, bridge_pid: record.bridgePid } });
    if (checked.envelope_sha256 !== finalSHA256) refuse();
    record.finalization = Object.freeze({ sha256: finalSHA256, bindReceiptSHA256 });
    return checked;
  }

  async function live(record, challenge = randomBytes(32).toString('base64url')) {
    if (typeof challenge !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(challenge)
      || Buffer.from(challenge, 'base64url').length !== 32
      || Buffer.from(challenge, 'base64url').toString('base64url') !== challenge) refuse();
    const result = await machineLive({ ...record.selectors, challenge });
    if (result?.reservation_sha256 !== record.selectors.reservation_sha256
      || result.bridge_pid !== record.bridgePid || result.runner_pid !== record.runnerPid
      || !['prebind', 'finalized'].includes(result.phase)) refuse();
    if (result.phase === 'finalized') {
      if (!record.finalization || result.finalization_sha256 !== record.finalization.sha256
        || result.bind_receipt_sha256 !== record.finalization.bindReceiptSHA256
        || !Number.isSafeInteger(result.finalized_live_expires_at)
        || result.finalized_live_expires_at <= now()) refuse();
    } else if (record.finalization || record.expires <= now()) refuse();
    return result;
  }

  async function currentLiveStart(reservationSHA256, challenge) {
    const record = starts.get(reservationSHA256);
    if (!record || record.stopPromise) refuse();
    return live(record, challenge);
  }

  async function verifyLiveStartV2(selectors, connection, peer, phase) {
    if (!exact(selectors, ['installation_id', 'start_id', 'launch_id', 'plan_id',
      'plan_digest', 'reservation_digest']) || typeof connection !== 'string' || !connection
      || !['challenge', 'proof', 'receipt'].includes(phase)) refuse();
    const record = starts.get(selectors.reservation_digest);
    if (!record || record.stopPromise || !peer || peer.endpoint?.installationId !== selectors.installation_id
      || peer.endpoint.uid !== record.installed.bridge_uid
      || peer.endpoint.path !== record.installed.broker.socket_path
      || (connections.has(connection) && connections.get(connection) !== record)) refuse();
    for (const field of ['installation_id', 'start_id', 'launch_id', 'plan_id', 'plan_digest']) {
      if (selectors[field] !== record.selectors[field]) refuse();
    }
    // Retain the stop target before crossing the Machine call. An aborted
    // challenge or socket close must still cut off this exact start.
    connections.set(connection, record);
    const checked = await verifyReservation(record.envelope, record.installed);
    if (checked?.reservationSHA256 !== record.selectors.reservation_sha256
      || !matchesInstalled(checked.payload, record.installed)) refuse();
    const status = await live(record);
    const a = record.payload.assignment;
    return Object.freeze({ ...selectors, hq_epoch: a.hq_epoch,
      bridge_uid: a.bridge_uid, broker_socket: a.broker.socket_path,
      member_socket: a.member.socket_path, member: a.member,
      soul_artifact_sha256: `sha256:${a.soul_artifact_sha256}`,
      reservation_bytes: Buffer.from(record.envelope), reservation_expires_at: record.expires,
      ...(phase === 'receipt' && status.phase === 'finalized'
        ? { finalized_live_expires_at: status.finalized_live_expires_at } : {}) });
  }

  async function verifyProofV2(proof, connection) {
    const record = connections.get(connection);
    if (!record || record.stopPromise || !exact(proof, ['reservation_sha256', 'installation_id',
      'start_id', 'launch_id', 'plan_id', 'plan_digest', 'hq_epoch', 'challenge', 'proof'])) refuse();
    for (const field of Object.keys(record.selectors)) if (proof[field] !== record.selectors[field]) refuse();
    const verified = await machineVerifyB(proof);
    return verified?.verified === true;
  }

  async function stopStart(reservationSHA256) {
    const record = starts.get(reservationSHA256);
    if (!record) return true;
    if (!record.stopPromise) record.stopPromise = (async () => {
      try { await record.killRoles(); } catch { /* only Machine's signed idle record releases the slot */ }
      const stopped = await machineStop(record.selectors);
      if (sha(stopped?.envelope) !== stopped.sha256) refuse();
      const checked = verifyStage2aStop(stopped.envelope, { machinePublicKey,
        expected: { ...record.selectors, runner_uid: record.installed.runner_uid,
          bridge_uid: record.installed.bridge_uid, runner_pid: record.runnerPid,
          bridge_pid: record.bridgePid } });
      if (checked.envelope_sha256 !== stopped.sha256 || checked.both_uids_idle !== true) refuse();
      await onStopVerified?.({ expected: Object.freeze({ ...record.selectors,
        runner_uid: record.installed.runner_uid, bridge_uid: record.installed.bridge_uid,
        runner_pid: record.runnerPid, bridge_pid: record.bridgePid }),
      envelope: Buffer.from(stopped.envelope), sha256: stopped.sha256 });
      starts.delete(record.selectors.reservation_sha256);
      for (const [id, bound] of connections) if (bound === record) connections.delete(id);
      return true;
    })();
    return record.stopPromise;
  }

  async function onDisconnectV2(connection) {
    const record = connections.get(connection);
    return record ? stopStart(record.selectors.reservation_sha256) : true;
  }

  return Object.freeze({ register, setRolePid, markFinalized, verifyLiveStartV2,
    verifyProofV2, onDisconnectV2, currentLiveStart, stopStart,
    hasStart: (reservationSHA256) => starts.has(reservationSHA256) });
}
