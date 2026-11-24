// Join B's kernel-observed R relay peer to A's signed ACP child start and
// independently reobserve both processes before provider use or a positive claim.
import { verifyStage2aMachineEnvelope } from './stage2a-stop.mjs';
import { observeDarwinProcessIdentity } from './owner-control.mjs';

export const T03_PEER_FIELDS = ['uid', 'pid', 'pid_version', 'start_seconds', 'start_micros',
  'parent_pid', 'parent_uid', 'parent_start_seconds', 'parent_start_micros'];
const exact = (value, fields) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === fields.length && fields.every((field) => Object.hasOwn(value, field));
const identity = (value) => Number.isSafeInteger(value?.pid) && value.pid >= 2
  && Number.isSafeInteger(value.uid) && value.uid >= 1
  && Number.isSafeInteger(value.gid) && value.gid >= 1
  && Number.isSafeInteger(value.start_seconds) && value.start_seconds >= 1
  && Number.isSafeInteger(value.start_micros) && value.start_micros >= 0 && value.start_micros < 1_000_000;
const refuse = () => { throw new Error('protected T03 relay peer is unavailable'); };
export const validT03PeerShape = (peer) => exact(peer, T03_PEER_FIELDS)
  && T03_PEER_FIELDS.every((field) => Number.isSafeInteger(peer[field]) && peer[field] >= 0)
  && peer.pid >= 2 && peer.pid_version >= 1 && peer.pid_version <= 0xffffffff
  && peer.uid >= 1 && peer.start_seconds >= 1 && peer.start_micros < 1_000_000
  && peer.parent_pid >= 2 && peer.parent_uid >= 1
  && peer.parent_start_seconds >= 1 && peer.parent_start_micros < 1_000_000;

export function verifiedT03ChildStart(envelope, digest, machinePublicKey, expected) {
  const proof = verifyStage2aMachineEnvelope(envelope, machinePublicKey,
    'agent-bot/stage2a-child-start/v1');
  const p = proof.payload;
  if (proof.envelope_sha256 !== digest || p?.schema !== 'agent-bot-machine/stage2a-child-start/v1'
    || !identity(p.child) || !identity(p.child_launcher)
    || p.child.pid === p.child_launcher.pid || p.child.uid !== p.child_launcher.uid
    || p.child.gid !== p.child_launcher.gid
    || p.child.uid !== expected.runner_uid || p.child.gid !== expected.runner_gid
    || p.child_launcher.pid !== expected.child_launcher_pid
    || p.child.pid !== expected.child_pid
    || p.bind_receipt_sha256 !== expected.bind_receipt_sha256
    || p.finalization_sha256 !== expected.finalization_sha256
    || p.relay_socket !== expected.relay_socket
    || ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
      'plan_id', 'plan_digest', 'hq_epoch'].some((field) => p[field] !== expected[field])
    || !Number.isSafeInteger(p.expires_at_ms) || p.expires_at_ms <= Date.now()) refuse();
  return Object.freeze({ child: Object.freeze({ ...p.child }), expiresAtMS: p.expires_at_ms });
}

export async function verifyT03RelayPeer(peer, childStart, {
  observe = observeDarwinProcessIdentity,
} = {}) {
  const child = childStart?.child;
  if (!validT03PeerShape(peer)
    || !identity(child) || peer.pid === child.pid
    || peer.uid !== child.uid || peer.parent_pid !== child.pid || peer.parent_uid !== child.uid
    || peer.parent_start_seconds !== child.start_seconds
    || peer.parent_start_micros !== child.start_micros
    || peer.start_seconds < child.start_seconds
    || (peer.start_seconds === child.start_seconds && peer.start_micros <= child.start_micros)) refuse();
  const parent = await observe(child.pid, child.uid, child.gid);
  const cli = await observe(peer.pid, peer.uid, child.gid);
  if (!parent || !cli || ['pid', 'uid', 'start_seconds', 'start_micros'].some((field) => parent[field] !== child[field])
    || cli.pid !== peer.pid || cli.uid !== peer.uid
    || cli.start_seconds !== peer.start_seconds || cli.start_micros !== peer.start_micros) refuse();
  return Object.freeze({ ...peer });
}
