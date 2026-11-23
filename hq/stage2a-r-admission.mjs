// The Machine reservation assigns this H-owned, R-group endpoint to one
// protected start. It is never the shared C admission/launch socket.
import { createHash } from 'node:crypto';
import { lstatSync } from 'node:fs';
import { join } from 'node:path';
import { fail } from '../sdk/errors.mjs';
import { checkDarwinACL } from './darwin-harness-accounts.mjs';
import { observePeerPid } from './owner-control.mjs';
import { listenSocket, takeover } from './socket.mjs';

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

// Bridge-free cooperative starts use their own signed C endpoint. The caller
// supplies a reservation that has already passed the pinned Machine signature,
// H/R inventory and paired-epoch checks; no wire field can create that pin.
// Production must provide a paired A attach/receipt verifier before opening
// this listener. The protected R listener above never accepts this operation.
export async function listenStage2aCooperativeAdmission({ reservation, verifyReservation, hqUid, core,
  machineAttach, verifyAttachReceipt, admissionDispatch, openAcpStream, isLive, onLost,
  lstat = (path) => lstatSync(path, { bigint: true }),
  checkACL = checkDarwinACL, observePeer = observePeerPid,
  listen = listenSocket } = {}) {
  const pinned = typeof verifyReservation === 'function'
    ? await verifyReservation(reservation) : undefined;
  const assignment = pinned?.payload?.assignment;
  const endpoints = pinned?.payload?.endpoints;
  const binding = pinned?.payload?.measurement_binding;
  const ep = endpoints?.admission;
  const broker = endpoints?.broker;
  const digest = pinned?.sha256;
  const envelope = pinned?.envelope_base64url;
  const challengeDigest = pinned?.payload?.admission_challenge_sha256;
  const refuseCooperative = () => fail('host.launch_unavailable', 'cooperative R admission is unavailable');
  const canonicalBase64 = (value, size) => typeof value === 'string'
    && /^[A-Za-z0-9_-]+$/.test(value)
    && Buffer.from(value, 'base64url').length === size
    && Buffer.from(value, 'base64url').toString('base64url') === value;
  const installationSlot = createHash('sha256').update(
    `agent-bot-soul-endpoint-installation/v1\0${assignment?.installation_id ?? ''}`).digest('hex').slice(0, 20);
  const startSlot = createHash('sha256').update(
    `agent-bot-soul-endpoint-start/v1\0${assignment?.installation_id ?? ''}\0${assignment?.start_id ?? ''}`).digest('hex').slice(0, 20);
  if (!assignment || !ep || !broker || !binding || !DIGEST.test(digest ?? '')
    || typeof envelope !== 'string' || envelope.length > 16384
    || !canonicalBase64(envelope, Buffer.from(envelope ?? '', 'base64url').length)
    || `sha256:${createHash('sha256').update(Buffer.from(envelope, 'base64url')).digest('hex')}` !== digest
    || !DIGEST.test(challengeDigest ?? '') || !Number.isSafeInteger(hqUid)
    || assignment.hq_uid !== hqUid || !Number.isSafeInteger(assignment.runner_uid)
    || assignment.runner_uid < 300 || assignment.runner_uid === hqUid
    || assignment.runner_gid !== assignment.runner_uid
    || !/^[A-Za-z_][A-Za-z0-9_-]{0,30}$/.test(assignment.runner_account ?? '')
    || binding.installation_id !== assignment.installation_id
    || binding.soul_id !== assignment.soul_id
    || binding.start_id !== assignment.start_id
    || binding.launch_id !== assignment.launch_id
    || binding.hq_epoch !== assignment.hq_epoch
    || binding.profile_in_force !== 'managed-cooperative'
    || !DIGEST.test(binding.claimed_definition_digest ?? '')
    || !DIGEST.test(binding.h_service_descriptor_digest ?? '')
    || !/^st_[0-9a-f]{24}$/.test(assignment.start_id ?? '')
    || !/^ln_[0-9a-f]{24}$/.test(assignment.launch_id ?? '')
    || ep.directory !== join(ROOT, 'c', installationSlot)
    || ep.socket_path !== join(ep.directory, `${startSlot}.sock`)
    || ep.owner_uid !== hqUid || ep.group_gid !== assignment.runner_gid
    || ep.expected_peer_uid !== assignment.runner_uid
    || ep.dir_mode !== 0o2750 || ep.socket_mode !== 0o660
    || broker.owner_uid !== hqUid || broker.group_gid !== assignment.runner_gid
    || broker.directory !== join(ROOT, 'broker', assignment.runner_account)
    || broker.socket_path !== join(broker.directory, 'broker.sock')
    || broker.expected_peer_uid !== assignment.runner_uid
    || broker.dir_mode !== 0o2750 || broker.socket_mode !== 0o660
    || typeof machineAttach !== 'function' || typeof verifyAttachReceipt !== 'function'
    || typeof admissionDispatch !== 'function' || typeof openAcpStream !== 'function'
    || typeof isLive !== 'function'
    || typeof core?.random?.bytes !== 'function'
    || typeof onLost !== 'function') refuseCooperative();
  let identity;
  let closed = false;
  let lost = false;
  let closePromise;
  const sessions = new Map();
  const peerPids = new WeakMap();
  let attachedSession;
  let acpTicket;
  let acpReady = false;
  let acpSpent = false;
  const lose = () => {
    if (lost || closed) return;
    lost = true;
    void Promise.resolve().then(onLost).catch(() => {});
  };
  function directory() {
    for (const path of ['/', '/Library', '/Library/Application Support', ROOT, join(ROOT, 'c')]) {
      const st = lstat(path);
      if (!st.isDirectory() || Number(st.uid) !== 0 || (Number(st.mode) & 0o022)
        || !(Number(st.mode) & 0o001)) refuseCooperative();
      checkACL(path);
    }
    const st = lstat(ep.directory);
    if (!st.isDirectory() || Number(st.uid) !== hqUid
      || Number(st.gid) !== assignment.runner_gid
      || (Number(st.mode) & 0o7777) !== 0o2750) refuseCooperative();
    checkACL(ep.directory);
    return st;
  }
  function socketIdentity() {
    const st = lstat(ep.socket_path);
    if (!st.isSocket() || Number(st.uid) !== hqUid
      || Number(st.gid) !== assignment.runner_gid
      || (Number(st.mode) & 0o7777) !== 0o660) refuseCooperative();
    checkACL(ep.socket_path);
    return st;
  }
  function current() {
    if (closed || lost || !identity) return false;
    try {
      const intact = sameInode(identity.dir, directory())
        && sameInode(identity.socket, socketIdentity());
      if (!intact) lose();
      return intact;
    } catch { lose(); return false; }
  }
  const attachedPeer = (pid) => {
    const state = attachedSession ? sessions.get(attachedSession) : undefined;
    if (!state || state.state !== 'attached' || state.peer_pid !== pid || !current()) return undefined;
    try { if (isLive(state.context) === true) return state.context; }
    catch { /* Treat watcher errors as liveness loss. */ }
    lose();
    return undefined;
  };
  directory();
  const listener = await listen({
    path: ep.socket_path, auth: 'entry-point', core, mode: 0o660,
    takeover: true, replaceStale: false,
    authenticatePeer: async (socket) => {
      const pid = await observePeer(socket, assignment.runner_uid);
      if (!Number.isSafeInteger(pid) || pid < 2 || !current()) return false;
      peerPids.set(socket, pid);
      return true;
    },
    newSession: (socket) => {
      const session = `cp_${core.random.hex(12)}`;
      sessions.set(session, { peer_pid: peerPids.get(socket), state: 'new' });
      return session;
    },
    endSession: (session) => {
      const state = sessions.get(session);
      sessions.delete(session);
      if (state?.state === 'pending' || state?.state === 'attached'
        || state?.state === 'acp') lose();
    },
    async dispatch(op, meta) {
      const state = sessions.get(meta.session);
      if (!current() || !state || !Number.isSafeInteger(state.peer_pid)) refuseCooperative();
      if (state.state === 'new') {
        if (op === 'cooperative.acp.v3') {
          state.state = 'acp-check';
          const p = meta.payload;
          if (!meta.takeover || !p || typeof p !== 'object' || Array.isArray(p)
            || Object.keys(p).join(',') !== 'acp_ticket_base64url'
            || !canonicalBase64(p.acp_ticket_base64url, 32)
            || acpSpent || !acpReady || !attachedSession
            || !attachedPeer(state.peer_pid)
            || p.acp_ticket_base64url !== acpTicket) refuseCooperative();
          const context = sessions.get(attachedSession).context;
          return takeover({ schema: 'hq/cooperative-acp/v3', reservation_sha256: digest,
            start_id: assignment.start_id, launch_id: assignment.launch_id }, {
            open: () => {
              if (!attachedPeer(state.peer_pid) || acpSpent) refuseCooperative();
              acpSpent = true;
              state.state = 'acp';
              return (socket) => { void Promise.resolve().then(() => openAcpStream(socket, context))
                .catch(() => { socket.destroy(); lose(); }); };
            },
            cancel: () => { acpSpent = true; },
          });
        }
        state.state = op === 'cooperative.attach.v3' ? 'pending' : 'rejected';
        if (op !== 'cooperative.attach.v3' || attachedSession) refuseCooperative();
        const p = meta.payload;
        if (!p || typeof p !== 'object' || Array.isArray(p)
          || Object.keys(p).sort().join(',') !== 'admission_challenge_base64url,reservation_envelope_base64url'
          || p.reservation_envelope_base64url !== envelope
          || !canonicalBase64(p.admission_challenge_base64url, 32)
          || `sha256:${createHash('sha256').update(Buffer.from(p.admission_challenge_base64url, 'base64url')).digest('hex')}` !== challengeDigest) refuseCooperative();
        const expected = { reservation_sha256: digest, installation_id: assignment.installation_id,
          start_id: assignment.start_id, launch_id: assignment.launch_id,
          admission_challenge_base64url: p.admission_challenge_base64url,
          runner_pid: state.peer_pid };
        let receipt;
        try {
          let timer;
          receipt = await Promise.race([
            Promise.resolve().then(() => machineAttach(expected)),
            new Promise((_, reject) => {
              timer = setTimeout(() => reject(new Error('Machine attach timed out')), LIVE_DEADLINE_MS);
              timer.unref?.();
            }),
          ]).finally(() => clearTimeout(timer));
        }
        catch { refuseCooperative(); }
        let verified;
        try { verified = await verifyAttachReceipt(receipt, expected); }
        catch { refuseCooperative(); }
        if (!verified || verified.reservation_sha256 !== digest
          || verified.start_id !== assignment.start_id
          || verified.launch_id !== assignment.launch_id
          || verified.runner_pid !== state.peer_pid
          || verified.challenge_sha256 !== challengeDigest
          || typeof verified.process_start !== 'string' || !verified.process_start
          || !Number.isFinite(Date.parse(verified.attached_at))
          || sessions.get(meta.session) !== state || !current()) refuseCooperative();
        const ticketBytes = core.random.bytes(32);
        if (!Buffer.isBuffer(ticketBytes) || ticketBytes.length !== 32) refuseCooperative();
        state.context = Object.freeze({ reservation_sha256: digest,
          installation_id: assignment.installation_id, soul_id: assignment.soul_id,
          start_id: assignment.start_id, launch_id: assignment.launch_id,
          hq_epoch: assignment.hq_epoch, peer_uid: assignment.runner_uid,
          runner_account: assignment.runner_account,
          peer_pid: state.peer_pid, process_start: verified.process_start,
          definition_digest: binding.claimed_definition_digest,
          h_service_descriptor_digest: binding.h_service_descriptor_digest,
          profile_in_force: 'managed-cooperative' });
        state.state = 'attached';
        attachedSession = meta.session;
        acpTicket = ticketBytes.toString('base64url');
        return Object.freeze({ schema: 'hq/cooperative-attach/v3', reservation_sha256: digest,
          start_id: assignment.start_id, launch_id: assignment.launch_id,
          broker_socket_path: broker.socket_path, acp_ticket_base64url: acpTicket });
      }
      if (state.state !== 'attached' || !ADMISSION_OPERATIONS.has(op)) refuseCooperative();
      if (!attachedPeer(state.peer_pid)) refuseCooperative();
      const result = await admissionDispatch(op, { ...meta, cooperativeStart: state.context });
      if (op === 'Hello') acpReady = true;
      return result;
    },
  });
  try { identity = { dir: directory(), socket: socketIdentity() }; }
  catch (error) { await listener.close(); throw error; }
  return Object.freeze({ path: ep.socket_path, checkCurrent: current, attachedPeer,
    brokerPin: Object.freeze({ endpoint: Object.freeze({ ...broker }),
      runner_uid: assignment.runner_uid, runner_gid: assignment.runner_gid,
      runner_account: assignment.runner_account,
      start_id: assignment.start_id, reservation_sha256: digest }),
    close: () => {
      if (!closePromise) { closed = true; closePromise = listener.close(); }
      return closePromise;
    } });
}

// The signed H broker endpoint is a different Unix path from C and carries
// only R's account. An existing H broker plugin still performs its normal
// per-runtime challenge/proof; the endpoint itself grants no runtime.
export async function listenStage2aCooperativeBroker({ admission, hqUid, core,
  callers, brokerDispatch, brokerClosed, onLost,
  lstat = (path) => lstatSync(path, { bigint: true }),
  checkACL = checkDarwinACL, observePeer = observePeerPid,
  listen = listenSocket } = {}) {
  const pin = admission?.brokerPin;
  const ep = pin?.endpoint;
  const refuseCooperative = () => fail('host.launch_unavailable', 'cooperative H broker is unavailable');
  if (!ep || !Number.isSafeInteger(hqUid) || ep.owner_uid !== hqUid
    || !Number.isSafeInteger(pin.runner_uid) || pin.runner_uid < 300
    || pin.runner_uid === hqUid || pin.runner_gid !== pin.runner_uid
    || ep.expected_peer_uid !== pin.runner_uid || ep.group_gid !== pin.runner_gid
    || ep.directory !== join(ROOT, 'broker', pin.runner_account)
    || ep.socket_path !== join(ep.directory, 'broker.sock')
    || ep.dir_mode !== 0o2750 || ep.socket_mode !== 0o660
    || !DIGEST.test(pin.reservation_sha256 ?? '')
    || !/^st_[0-9a-f]{24}$/.test(pin.start_id ?? '')
    || typeof admission?.attachedPeer !== 'function'
    || typeof brokerDispatch !== 'function' || typeof brokerClosed !== 'function'
    || typeof callers?.set !== 'function' || typeof callers?.delete !== 'function'
    || typeof onLost !== 'function') refuseCooperative();
  let identity;
  let closed = false;
  let lost = false;
  let closePromise;
  const peerPids = new WeakMap();
  const sessionPids = new Map();
  const lose = () => {
    if (lost || closed) return;
    lost = true;
    void Promise.resolve().then(onLost).catch(() => {});
  };
  function directory() {
    for (const path of ['/', '/Library', '/Library/Application Support', ROOT, join(ROOT, 'broker')]) {
      const st = lstat(path);
      if (!st.isDirectory() || Number(st.uid) !== 0 || (Number(st.mode) & 0o022)
        || !(Number(st.mode) & 0o001)) refuseCooperative();
      checkACL(path);
    }
    const st = lstat(ep.directory);
    if (!st.isDirectory() || Number(st.uid) !== hqUid
      || Number(st.gid) !== pin.runner_gid
      || (Number(st.mode) & 0o7777) !== 0o2750) refuseCooperative();
    checkACL(ep.directory);
    return st;
  }
  function socketIdentity() {
    const st = lstat(ep.socket_path);
    if (!st.isSocket() || Number(st.uid) !== hqUid
      || Number(st.gid) !== pin.runner_gid
      || (Number(st.mode) & 0o7777) !== 0o660) refuseCooperative();
    checkACL(ep.socket_path);
    return st;
  }
  function current() {
    if (closed || lost || !identity || !admission.checkCurrent()) return false;
    try {
      const intact = sameInode(identity.dir, directory())
        && sameInode(identity.socket, socketIdentity());
      if (!intact) lose();
      return intact;
    } catch { lose(); return false; }
  }
  directory();
  const listener = await listen({
    path: ep.socket_path, auth: 'member', core, mode: 0o660, replaceStale: false,
    authenticatePeer: async (socket) => {
      const pid = await observePeer(socket, pin.runner_uid);
      if (!Number.isSafeInteger(pid) || pid < 2 || !admission.attachedPeer(pid) || !current()) return false;
      peerPids.set(socket, pid);
      return true;
    },
    newSession: (socket) => {
      const session = `cb_${core.random.hex(12)}`;
      const pid = peerPids.get(socket);
      sessionPids.set(session, pid);
      callers.set(session, Object.freeze({ kind: 'cooperative', account: pin.runner_account,
        uid: pin.runner_uid, start_id: pin.start_id,
        reservation_sha256: pin.reservation_sha256 }));
      return session;
    },
    endSession: (session) => {
      sessionPids.delete(session);
      callers.delete(session);
      brokerClosed(session);
    },
    dispatch: (kind, { payload, session }) => {
      const pid = sessionPids.get(session);
      if (!Number.isSafeInteger(pid) || !admission.attachedPeer(pid) || !current()) refuseCooperative();
      return brokerDispatch(kind, payload, session);
    },
  });
  try { identity = { dir: directory(), socket: socketIdentity() }; }
  catch (error) { await listener.close(); throw error; }
  return Object.freeze({ path: ep.socket_path, checkCurrent: current,
    close: () => {
      if (!closePromise) { closed = true; closePromise = listener.close(); }
      return closePromise;
    } });
}
