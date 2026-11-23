// The Machine reservation assigns this H-owned, R-group endpoint to one
// protected start. It is never the shared C admission/launch socket.
import { createHash, timingSafeEqual } from 'node:crypto';
import { lstatSync } from 'node:fs';
import { join } from 'node:path';
import { fail } from '../sdk/errors.mjs';
import { checkDarwinACL } from './darwin-harness-accounts.mjs';
import { observePeerPid } from './owner-control.mjs';
import { listenSocket, takeover } from './socket.mjs';
import { canonicalBytes, canonicalDigest } from '../sdk/wire/canonical-json.mjs';
import { validate } from '../sdk/wire/schema.mjs';
import { matchesObservedMemberGrants, verifyStage2aBridgeMemberAuthority } from './stage2a-relay-peer.mjs';
import { verifyStage2aMachineEnvelope } from './stage2a-stop.mjs';

const ROOT = '/Library/Application Support/ai.true-line.agent-bot-hq';
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const CHALLENGE = /^[A-Za-z0-9_-]{43}$/;
const LIVE_DEADLINE_MS = 5_000;
const ADMISSION_OPERATIONS = new Set(['Hello', 'Admit', 'Equip', 'Ready', 'Lease']);
const refuse = () => fail('host.launch_unavailable', 'protected R admission is unavailable');
const sameInode = (a, b) => BigInt(a.dev) === BigInt(b.dev) && BigInt(a.ino) === BigInt(b.ino);

const MEMBER_ATTACH_PREPARE = 'stage2a.member.attach.prepare';
const MEMBER_ATTACH = 'stage2a.member.attach';
const ATTACH_TOKEN = /^[0-9a-f]{64}$/;
const ATTACH_CAP = 128 * 1024;
const ATTACH_TTL_MS = 30_000;
const ATTACH_ENVELOPE_CAP = 16 * 1024;

export function createStage2aMemberAttach({ provider, withLiveRuntime, selectors, runnerEndpoint,
  core, current, onLost, refreshRunnerPeer } = {}) {
  if (!provider?.resultSchema || !provider.childObservationSchema || !provider.readySchema
    || typeof provider.select !== 'function'
    || typeof withLiveRuntime !== 'function' || typeof refreshRunnerPeer !== 'function') throw new TypeError('prestarted attach needs a pinned schema and live providers');
  const slots = new Map();
  const spent = new Set();
  const bridgeTokens = new Set();
  const bridgeNonces = new Set();
  const now = () => core.clock.now();
  const checkSchema = (schema, payload) => {
    const references = [provider.assignmentSchema, ...(provider.schemaReferences ?? [])].filter((entry) =>
      entry?.$id && entry.$id !== schema.$id);
    if (validate(schema, payload, { schemas: references }).length) refuse();
  };
  const matches = (a, b, fields) => fields.every((field) => a?.[field] === b?.[field]);
  const usable = (slot) => current() && slot.expires > now() && slot.isCurrent() === true;

  async function prepare(payload, { session, protectedStart }) {
    if (!payload || Object.keys(payload).join(',') !== 'runtime_id' || typeof payload.runtime_id !== 'string'
      || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(payload.runtime_id)
      || protectedStart?.role !== 'runner' || !current()) refuse();
    const peer = await refreshRunnerPeer(protectedStart);
    if (!DIGEST.test(peer?.processSHA256 ?? '') || peer.isCurrent() !== true) refuse();
    const runtimeId = payload.runtime_id;
    const runtime = await withLiveRuntime(runtimeId, session, (rt) => rt);
    if (runtime.protected_state !== 'active' || runtime.protected_start_id !== selectors.start_id
      || runtime.installation_id !== selectors.installation_id) refuse();
    const input = await provider.select({ runtimeId, runtime, selectors, protectedStart });
    if (!input || !current() || typeof input.isCurrent !== 'function' || input.isCurrent() !== true
      || typeof input.connect !== 'function' || !DIGEST.test(input.boundAuthoritySHA256 ?? '')) refuse();
    const { machinePublicKey, assignmentBytes, childObservationBytes, readyBytes, authorityBytes } = input;
    const signed = (bytes, kind) => verifyStage2aMachineEnvelope(bytes, machinePublicKey,
      `agent-bot/stage2a-member-set-${kind}/v1`, { maxBytes: ATTACH_ENVELOPE_CAP });
    const assignment = signed(assignmentBytes, 'assignment');
    const child = signed(childObservationBytes, 'child-observation');
    const ready = signed(readyBytes, 'ready');
    const authority = verifyStage2aBridgeMemberAuthority(authorityBytes, { machinePublicKey,
      schema: provider.authoritySchema, assignmentSchema: provider.assignmentSchema,
      schemas: provider.schemaReferences, assignmentBytes,
      expected: { ...input.expected, ...selectors, soul_id: runtime.soul_id,
        profile_in_force: 'managed-protected' }, now: now() });
    const a = assignment.payload, c = child.payload, r = ready.payload;
    checkSchema(provider.childObservationSchema, c);
    checkSchema(provider.readySchema, r);
    const bridge = authority.payload.bridge;
    const ids = ['profile_in_force', 'host_id', 'installation_id', 'soul_id', 'start_id', 'hq_epoch',
      'reservation_sha256'];
    if (runnerEndpoint.peerUid !== a.runner_uid
      || authority.envelope_sha256 !== input.boundAuthoritySHA256
      || !matches(c, a, ids) || !matches(r, a, ids)
      || c.assignment_envelope_sha256 !== assignment.envelope_sha256
      || r.assignment_envelope_sha256 !== assignment.envelope_sha256
      || r.child_observation_envelope_sha256 !== child.envelope_sha256
      || r.member_b_authority_envelope_sha256 !== authority.envelope_sha256
      || r.b_authority_sha256 !== a.b_authority.envelope_sha256
      || c.provisional_hq_mapping?.runtime_state !== 'provisional'
      || c.provisional_hq_mapping?.acp_authority !== 'withheld'
      || c.provisional_hq_mapping?.assignment_envelope_sha256 !== assignment.envelope_sha256
      || c.provisional_hq_mapping_sha256 !== canonicalDigest(c.provisional_hq_mapping)
      || r.provisional_hq_mapping_sha256 !== c.provisional_hq_mapping_sha256
      || !matches(r.bridge_process, bridge, ['uid', 'gid'])
      || !input.boundBridgeProcess || canonicalDigest(r.bridge_process) !== canonicalDigest(input.boundBridgeProcess)
      || [a, c, r].some((p) => !Array.isArray(p.members) || p.members.length !== 2)
      || c.provisional_hq_mapping.members?.length !== 2
      || !matchesObservedMemberGrants(a, c.members, input.memberGrants)) refuse();
    const member = a.members.find((row) => row.member_id === runtime.member_id);
    const memberIndex = a.members.indexOf(member);
    if (!member || spent.has(member.launch_id)) refuse();
    for (const [i, row] of a.members.entries()) {
      const mapped = c.provisional_hq_mapping.members[i];
      const observed = c.members[i], armed = r.members[i];
      if (!matches(row, mapped, ['member_id', 'member_selector'])
        || !matches(row, observed, ['member_id', 'member_selector', 'launch_id'])
        || !matches(observed, armed, ['member_id', 'member_selector', 'launch_id', 'runtime_id'])
        || observed.runtime_id !== mapped.runtime_id || (i === memberIndex && observed.runtime_id !== runtimeId)
        || observed.child_process?.executable_sha256 !== row.command_sha256
        || observed.child_process?.uid !== a.runner_uid || observed.child_process?.gid !== a.runner_gid
        || armed.bridge_arm?.state !== 'armed' || armed.bridge_arm?.adapter_pid !== observed.child_process.pid
        || armed.bridge_arm?.child_observation_envelope_sha256 !== child.envelope_sha256
        || armed.bridge_arm_receipt_sha256 !== canonicalDigest(armed.bridge_arm)) refuse();
    }
    if (!(Date.parse(a.issued_at) <= Date.parse(c.provisional_hq_mapping.issued_at)
      && Date.parse(c.provisional_hq_mapping.issued_at) <= Date.parse(c.issued_at)
      && Date.parse(c.issued_at) <= Date.parse(r.issued_at) && Date.parse(r.issued_at) <= now())
      || c.members[0].runtime_id === c.members[1].runtime_id
      || a.members[0].launch_id === a.members[1].launch_id) refuse();
    const expires = Math.min(now() + ATTACH_TTL_MS, runtime.lease_expires_at,
      ...[a, c, r, authority.payload].map((p) => Date.parse(p.expires_at)));
    if (!Number.isFinite(expires) || expires <= now()) refuse();
    const attach = core.random.hex(32);
    const ep = bridge.endpoints.member;
    const { socket_path: memberSocket, ...memberEndpoint } = ep;
    const reply = Object.freeze({ version: 'stage2a-member-attach/v1', installation_id: selectors.installation_id,
      start_id: selectors.start_id, member_id: member.member_id, member_selector: member.member_selector,
      runtime_id: runtimeId, launch_id: member.launch_id, attach, expires_at: new Date(expires).toISOString(),
      cwd: input.cwd, member_socket: memberSocket, member_endpoint: memberEndpoint,
      member_bridge_token: input.memberBridgeToken, bridge_ready_nonce: input.bridgeReadyNonce,
      runner_endpoint: runnerEndpoint,
      child_observation_envelope_base64url: childObservationBytes.toString('base64url'),
      child_observation_envelope_sha256: child.envelope_sha256,
      member_b_authority_envelope_base64url: authorityBytes.toString('base64url'),
      member_b_authority_envelope_sha256: authority.envelope_sha256,
      ready_envelope_base64url: readyBytes.toString('base64url'), ready_envelope_sha256: ready.envelope_sha256 });
    if (!ATTACH_TOKEN.test(attach) || canonicalBytes(reply).length > ATTACH_CAP) refuse();
    checkSchema(provider.resultSchema, reply);
    await withLiveRuntime(runtimeId, session, (rt) => {
      if (!matches(rt, runtime, ['epoch', 'lease_generation', 'member_id', 'protected_start_id'])
        || !current() || peer.isCurrent() !== true || input.isCurrent() !== true || spent.has(member.launch_id)
        || bridgeTokens.has(reply.member_bridge_token) || bridgeNonces.has(reply.bridge_ready_nonce)) refuse();
      bridgeTokens.add(reply.member_bridge_token);
      bridgeNonces.add(reply.bridge_ready_nonce);
      spent.add(member.launch_id);
      slots.set(member.launch_id, { attach, runtimeId, session, expires, processSHA256: peer.processSHA256,
        isCurrent: input.isCurrent, connect: input.connect });
    });
    return reply;
  }

  async function attach(payload, { takeover: offer, protectedStart }) {
    if (!offer || protectedStart?.role !== 'runner' || !payload
      || Object.keys(payload).sort().join(',') !== 'attach,launch_id'
      || typeof payload.launch_id !== 'string' || typeof payload.attach !== 'string'
      || !ATTACH_TOKEN.test(payload.attach)) refuse();
    const slot = slots.get(payload.launch_id);
    if (!slot || !usable(slot)
      || !timingSafeEqual(Buffer.from(slot.attach, 'hex'), Buffer.from(payload.attach, 'hex'))) refuse();
    const peer = await refreshRunnerPeer(protectedStart);
    if (peer?.processSHA256 !== slot.processSHA256 || peer.isCurrent() !== true
      || slots.get(payload.launch_id) !== slot || !usable(slot)) refuse();
    slots.delete(payload.launch_id);
    try {
      await withLiveRuntime(slot.runtimeId, slot.session, () => {
        if (peer.isCurrent() !== true || !usable(slot)) refuse();
      });
    } catch (error) { onLost(); throw error; }
    return takeover({ launch_id: payload.launch_id }, {
      open: () => {
        if (peer.isCurrent() !== true || !usable(slot)) { onLost(); refuse(); }
        return (socket) => {
          try { slot.connect(socket); }
          catch { socket.destroy(); onLost(); }
        };
      },
      cancel: onLost,
    });
  }
  return Object.freeze({ prepare, attach });
}

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
  hqUid, core, renewLive, renewMemberRuntime, onLost, protectedAdmission, admissionDispatch,
  memberAttachProvider, withLiveRuntime,
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
  const memberAttach = memberAttachProvider ? createStage2aMemberAttach({
    provider: memberAttachProvider, withLiveRuntime, selectors, core, current, onLost: lose,
    refreshRunnerPeer: protectedAdmission?.refreshRunnerPeer,
    runnerEndpoint: Object.freeze({ socketPath: ep.socket_path, peerUid: installed.runner_uid, directory: ep.directory }),
  }) : undefined;
  checkDirectory();
  const listener = await listen({
    path: ep.socket_path, auth: 'entry-point', core, mode: 0o660, replaceStale: false,
    takeover: !!memberAttach,
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
      if (memberAttach && op === MEMBER_ATTACH_PREPARE) {
        if (!helloConnections.has(meta.protectedStart)) refuse();
        return memberAttach.prepare(meta.payload, meta);
      }
      if (memberAttach && op === MEMBER_ATTACH) return memberAttach.attach(meta.payload, meta);
      if (ADMISSION_OPERATIONS.has(op)) {
        if (typeof admissionDispatch !== 'function'
          || meta.protectedStart.role !== 'runner') refuse();
        if (op === 'Hello') helloConnections.add(meta.protectedStart);
        return admissionDispatch(op, meta);
      }
      if (op === 'launch.member.runtime') {
        const p = meta.payload;
        const fields = ['installation_id', 'start_id', 'launch_id', 'reservation_sha256',
          'member_id', 'member_selector', 'member_launch_id', 'grant_sha256',
          'child_observation_envelope_sha256', 'launcher_pid', 'child_pid',
          'challenge_nonce_base64url', 'after_sequence', 'prior_expires_at',
          'ready_envelope_sha256', 'hq_finalization_sha256',
          'previous_lease_envelope_sha256'];
        if (typeof renewMemberRuntime !== 'function' || meta.protectedStart.role !== 'child'
          || !p || typeof p !== 'object' || Array.isArray(p)
          || Object.keys(p).sort().join(',') !== fields.sort().join(',')
          || p.installation_id !== selectors.installation_id
          || p.start_id !== selectors.start_id || p.launch_id !== selectors.launch_id
          || p.reservation_sha256 !== selectors.reservation_sha256
          || !DIGEST.test(p.grant_sha256 ?? '')
          || !DIGEST.test(p.child_observation_envelope_sha256 ?? '')
          || !DIGEST.test(p.ready_envelope_sha256 ?? '')
          || !DIGEST.test(p.hq_finalization_sha256 ?? '')
          || !Number.isSafeInteger(p.launcher_pid) || p.launcher_pid !== meta.protectedStart.peer_pid
          || !Number.isSafeInteger(p.child_pid) || p.child_pid < 2 || p.child_pid === p.launcher_pid
          || !Number.isSafeInteger(p.after_sequence) || p.after_sequence < 0
          || p.after_sequence >= (1 << 30)
          || (p.after_sequence === 0 && p.previous_lease_envelope_sha256 !== null)
          || (p.after_sequence > 0 && !DIGEST.test(p.previous_lease_envelope_sha256 ?? ''))
          || !CHALLENGE.test(p.challenge_nonce_base64url ?? '')
          || Buffer.from(p.challenge_nonce_base64url, 'base64url').length !== 32
          || Buffer.from(p.challenge_nonce_base64url, 'base64url').toString('base64url')
            !== p.challenge_nonce_base64url
          || !Number.isFinite(Date.parse(p.prior_expires_at))
          || Date.parse(p.prior_expires_at) <= core.clock.now()) refuse();
        try {
          let timer;
          const lease = await Promise.race([
            Promise.resolve().then(() => renewMemberRuntime({ ...selectors, ...p }, meta.protectedStart)),
            new Promise((_, reject) => {
              timer = setTimeout(() => reject(new Error('Machine member runtime timed out')), LIVE_DEADLINE_MS);
              timer.unref?.();
            }),
          ]).finally(() => clearTimeout(timer));
          if (!lease || !DIGEST.test(lease.lease_sha256 ?? '')
            || !Number.isSafeInteger(lease.lease_sequence)
            || lease.lease_sequence !== p.after_sequence + 1
            || typeof lease.lease_envelope_base64url !== 'string'
            || !/^[A-Za-z0-9_-]{1,10924}$/.test(lease.lease_envelope_base64url)
            || `sha256:${createHash('sha256').update(Buffer.from(lease.lease_envelope_base64url, 'base64url')).digest('hex')}`
              !== lease.lease_sha256 || !current()) refuse();
          return Object.freeze({ lease_envelope_base64url: lease.lease_envelope_base64url,
            lease_sha256: lease.lease_sha256, lease_sequence: lease.lease_sequence });
        } catch (error) { lose(); throw error; }
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
  const socketSessions = new WeakMap();
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
  const closedSession = (session) => {
    const state = sessions.get(session);
    if (state && ['pending', 'attached', 'acp'].includes(state.state)) lose();
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
      if (typeof socket?.once !== 'function') refuseCooperative();
      const session = `cp_${core.random.hex(12)}`;
      sessions.set(session, { peer_pid: peerPids.get(socket), state: 'new' });
      socketSessions.set(socket, session);
      // listenSocket drains dispatch before endSession; this direct close
      // callback revokes authority in the close event itself.
      socket.once('close', () => closedSession(session));
      return session;
    },
    connectionClosed: (socket) => closedSession(socketSessions.get(socket)),
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
      if (!current() || sessions.get(meta.session) !== state) refuseCooperative();
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
      if (!closePromise) { lose(); closed = true; closePromise = listener.close(); }
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
      if (!closePromise) { lose(); closed = true; closePromise = listener.close(); }
      return closePromise;
    } });
}
