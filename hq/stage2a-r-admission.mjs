// The Machine reservation assigns this H-owned, R-group endpoint to one
// protected start. It is never the shared C admission/launch socket.
import { createHash } from 'node:crypto';
import { lstatSync } from 'node:fs';
import { join } from 'node:path';
import { fail } from '../sdk/errors.mjs';
import { checkDarwinACL } from './darwin-harness-accounts.mjs';
import { observePeerPid } from './owner-control.mjs';
import { listenSocket } from './socket.mjs';

const ROOT = '/Library/Application Support/ai.true-line.agent-bot-hq';
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const CHALLENGE = /^[A-Za-z0-9_-]{43}$/;
const LIVE_DEADLINE_MS = 5_000;
const ADMISSION_OPERATIONS = new Set(['Hello', 'Admit', 'Equip', 'Ready', 'Lease']);
const refuse = () => fail('host.launch_unavailable', 'protected R admission is unavailable');
const sameInode = (a, b) => BigInt(a.dev) === BigInt(b.dev) && BigInt(a.ino) === BigInt(b.ino);

function checkedEndpoint(installed, assignment, selectors, hqUid) {
  const ep = assignment?.admission;
  const pin = installed?.admission;
  const slot = createHash('sha256').update([
    'agent-bot-soul-endpoint-start/v1', installed?.installation_id, assignment?.start_id,
  ].join('\0')).digest('hex').slice(0, 20) + '.sock';
  if (!pin || !ep || !selectors || !Number.isSafeInteger(hqUid)
    || !Number.isSafeInteger(installed.runner_uid) || installed.runner_uid === hqUid
    || ep.directory !== pin.directory
    || ep.directory !== join(ROOT, 'r', createHash('sha256').update([
      'agent-bot-soul-endpoint-installation/v1', installed.installation_id,
    ].join('\0')).digest('hex').slice(0, 20))
    || ep.socket_path !== join(ep.directory, slot)
    || ep.owner_uid !== hqUid || ep.owner_uid !== pin.owner_uid
    || ep.group_gid !== installed.runner_gid || ep.group_gid !== pin.group_gid
    || ep.dir_mode !== 0o2750 || ep.socket_mode !== 0o660
    || ep.dir_mode !== pin.dir_mode || ep.socket_mode !== pin.socket_mode
    || !Array.isArray(ep.peer_uids) || ep.peer_uids.length !== 1
    || ep.peer_uids[0] !== installed.runner_uid
    || assignment.installation_id !== installed.installation_id
    || assignment.soul_id !== installed.soul_id
    || assignment.plan_id !== installed.plan_id
    || assignment.plan_digest !== installed.plan_digest
    || assignment.hq_epoch !== installed.hq_epoch
    || assignment.runner_uid !== installed.runner_uid
    || assignment.hq_uid !== hqUid
    || selectors.reservation_sha256 === undefined || !DIGEST.test(selectors.reservation_sha256)
    || selectors.installation_id !== assignment.installation_id
    || selectors.start_id !== assignment.start_id
    || selectors.launch_id !== assignment.launch_id
    || selectors.plan_id !== assignment.plan_id
    || selectors.plan_digest !== assignment.plan_digest
    || selectors.hq_epoch !== assignment.hq_epoch) refuse();
  return ep;
}

// `renewLive` is HQ's paired Machine channel. It must return the exact
// A-signed lease envelope; an HQ-generated expiry never reaches R.
export async function listenStage2aRunnerAdmission({ installed, assignment, selectors,
  hqUid, core, renewLive, onLost, protectedAdmission, admissionDispatch,
  lstat = (path) => lstatSync(path, { bigint: true }),
  checkACL = checkDarwinACL, observePeer = observePeerPid,
  listen = listenSocket } = {}) {
  if (typeof renewLive !== 'function' || typeof onLost !== 'function'
    || typeof observePeer !== 'function' || typeof listen !== 'function') refuse();
  const ep = checkedEndpoint(installed, assignment, selectors, hqUid);
  let identity;
  let closed = false;
  let closePromise;
  let lost = false;
  const helloConnections = new WeakSet();
  const peerPids = new WeakMap();
  const lose = () => {
    if (lost || closed) return;
    lost = true;
    void Promise.resolve().then(onLost).catch(() => {});
  };
  function checkDirectory() {
    for (const path of ['/', '/Library', '/Library/Application Support', ROOT, join(ROOT, 'r')]) {
      const st = lstat(path);
      if (!st.isDirectory() || Number(st.uid) !== 0 || (Number(st.mode) & 0o022)
        || !(Number(st.mode) & 0o001)) refuse();
      checkACL(path);
    }
    const dir = lstat(ep.directory);
    if (!dir.isDirectory() || Number(dir.uid) !== hqUid
      || Number(dir.gid) !== installed.runner_gid
      || (Number(dir.mode) & 0o7777) !== 0o2750) refuse();
    checkACL(ep.directory);
    return dir;
  }
  function checkSocket() {
    const st = lstat(ep.socket_path);
    if (!st.isSocket() || Number(st.uid) !== hqUid
      || Number(st.gid) !== installed.runner_gid
      || (Number(st.mode) & 0o7777) !== 0o660) refuse();
    checkACL(ep.socket_path);
    return st;
  }
  function current() {
    if (closed || lost || !identity) return false;
    try {
      const intact = sameInode(identity.dir, checkDirectory())
        && sameInode(identity.socket, checkSocket());
      if (!intact) lose();
      return intact;
    } catch { lose(); return false; }
  }
  checkDirectory();
  const listener = await listen({
    path: ep.socket_path, auth: 'entry-point', core, mode: 0o660, replaceStale: false,
    authenticatePeer: async (socket) => {
      const pid = await observePeer(socket, installed.runner_uid);
      if (!Number.isSafeInteger(pid) || pid < 2 || !current()) return false;
      peerPids.set(socket, pid);
      return true;
    },
    connectionContext: protectedAdmission ? async (socket) => {
      if (!current()) refuse();
      const peer_pid = peerPids.get(socket);
      if (!Number.isSafeInteger(peer_pid) || peer_pid < 2) refuse();
      const context = await protectedAdmission.acceptPeer(socket, { installed, assignment,
        selectors, peer_uid: installed.runner_uid, peer_pid });
      if (!context || typeof context !== 'object' || Array.isArray(context)
        || context.reservation_sha256 !== selectors.reservation_sha256
        || context.installation_id !== selectors.installation_id
        || context.start_id !== selectors.start_id
        || context.launch_id !== selectors.launch_id
        || context.plan_id !== selectors.plan_id
        || context.plan_digest !== selectors.plan_digest
        || context.hq_epoch !== selectors.hq_epoch
        || context.peer_uid !== installed.runner_uid
        || context.peer_pid !== peer_pid
        || !['runner', 'child'].includes(context.role)) refuse();
      return context;
    } : undefined,
    connectionClosed: protectedAdmission ? (socket, context) => {
      if (context && helloConnections.has(context))
        return protectedAdmission.peerDisconnected(socket, context);
    } : undefined,
    newSession: () => `rp_${core.random.hex(12)}`, endSession: () => {},
    async dispatch(op, meta) {
      if (!current() || !protectedAdmission || !meta.protectedStart) refuse();
      if (ADMISSION_OPERATIONS.has(op)) {
        if (typeof admissionDispatch !== 'function'
          || meta.protectedStart.role !== 'runner') refuse();
        if (op === 'Hello') helloConnections.add(meta.protectedStart);
        return admissionDispatch(op, meta);
      }
      if (op !== 'launch.live') refuse();
      if (!['runner', 'child'].includes(meta.protectedStart.role)) refuse();
      const { payload } = meta;
      if (!payload || typeof payload !== 'object' || Array.isArray(payload)
        || Object.keys(payload).sort().join(',') !== 'challenge,installation_id,launch_id,reservation_sha256,start_id'
        || payload.installation_id !== selectors.installation_id
        || payload.start_id !== selectors.start_id
        || payload.launch_id !== selectors.launch_id
        || payload.reservation_sha256 !== selectors.reservation_sha256
        || !CHALLENGE.test(payload.challenge)
        || Buffer.from(payload.challenge, 'base64url').length !== 32
        || Buffer.from(payload.challenge, 'base64url').toString('base64url') !== payload.challenge) refuse();
      try {
        let timer;
        const lease = await Promise.race([
          Promise.resolve().then(() => renewLive(payload)),
          new Promise((_, reject) => {
            timer = setTimeout(() => reject(new Error('Machine Live timed out')), LIVE_DEADLINE_MS);
            timer.unref?.();
          }),
        ]).finally(() => clearTimeout(timer));
        if (!lease || lease.schema !== 'agent-bot-hq/protected-live/v1'
          || lease.installation_id !== payload.installation_id
          || lease.start_id !== payload.start_id
          || lease.launch_id !== payload.launch_id
          || lease.reservation_sha256 !== payload.reservation_sha256
          || lease.challenge !== payload.challenge
          || !DIGEST.test(lease.lease_sha256)
          || !Number.isSafeInteger(lease.lease_sequence) || lease.lease_sequence < 1
          || typeof lease.lease_envelope_base64url !== 'string'
          || !/^[A-Za-z0-9_-]{1,10924}$/.test(lease.lease_envelope_base64url)
          || `sha256:${createHash('sha256').update(Buffer.from(lease.lease_envelope_base64url, 'base64url')).digest('hex')}` !== lease.lease_sha256
          || !current()) refuse();
        return Object.freeze({ lease_envelope_base64url: lease.lease_envelope_base64url,
          lease_sha256: lease.lease_sha256, lease_sequence: lease.lease_sequence });
      } catch (error) {
        lose();
        throw error;
      }
    },
  });
  try { identity = { dir: checkDirectory(), socket: checkSocket() }; }
  catch (error) { await listener.close(); throw error; }
  return Object.freeze({ path: ep.socket_path, checkCurrent: current,
    close: () => {
      if (!closePromise) { closed = true; closePromise = listener.close(); }
      return closePromise;
    } });
}
