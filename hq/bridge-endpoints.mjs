// The paired Machine client supplies verified per-installation broker assignments.
// HQ checks the local directory and socket and admits only the kernel B UID.
import { createHash } from 'node:crypto';
import { lstatSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { canonicalDigest } from '../sdk/wire/canonical-json.mjs';
import { verifyStage2aBridgeMemberAuthority } from './stage2a-relay-peer.mjs';
import { fail } from '../sdk/errors.mjs';
import { checkDarwinACL, DARWIN_HARNESS_DIR } from './darwin-harness-accounts.mjs';
import { authenticatePeerUid } from './owner-control.mjs';
import { listenSocket } from './socket.mjs';

const ROLE_UID = (uid) => Number.isInteger(uid) && uid >= 300 && uid <= 399;
const INSTALLATION = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const BRIDGE_QUALIFICATION_MESSAGES = 'bridge.qualification.messages.v1';
const BRIDGE_RELAY_INGRESS = 'bridge.relay.ingress.v1';
const RELAY_PEER_CHALLENGE = 'stage2a-relay-peer-challenge';
const protectedBridgeKind = (kind) => kind === 'bridge.bind.v2.challenge' || kind === 'bridge.bind.v2'
  || kind === 'bridge.bind.v3.challenge' || kind === 'bridge.bind.v3';
const refuse = () => fail('host.launch_unavailable', 'bridge bind requires the dedicated Machine-assigned B broker');

export function memberBrokerDispatch(host, kind, payload, connection) {
  if (protectedBridgeKind(kind) || kind === BRIDGE_QUALIFICATION_MESSAGES || kind === BRIDGE_RELAY_INGRESS
    || kind === RELAY_PEER_CHALLENGE) refuse();
  return host.brokerAccept(kind, payload, { connection });
}

export function planBridgeEndpoints(assignments, { platform, account, hqUid, harnessUids }) {
  if (!Array.isArray(assignments) || assignments.length > 64) throw new Error('invalid Machine broker assignments');
  if (assignments.length && (platform !== 'darwin' || account !== '_agent-bot-hq' || !ROLE_UID(hqUid))) {
    throw new Error('Machine bridge endpoints require the dedicated Darwin HQ account');
  }
  const usedUids = new Set([hqUid, ...harnessUids]);
  const installations = new Set();
  for (const entry of assignments) {
    if (!ROLE_UID(entry?.runner_uid) || usedUids.has(entry.runner_uid)) {
      throw new Error('invalid or overlapping Machine runner account');
    }
    usedUids.add(entry.runner_uid);
  }
  return assignments.map((entry) => {
    const { installation_id, bridge_uid, bridge_gid, bridge_account, broker } = entry ?? {};
    if (typeof installation_id !== 'string' || !INSTALLATION.test(installation_id)
      || installations.has(installation_id)
      || usedUids.has(bridge_uid) || !ROLE_UID(bridge_uid) || bridge_gid !== bridge_uid) {
      throw new Error('invalid or overlapping Machine bridge account');
    }
    const slot = createHash('sha256').update('agent-bot-soul-bridge/v1\0').update(installation_id).digest('hex').slice(0, 20);
    const name = `_abm-br-${slot}`;
    const directory = join(DARWIN_HARNESS_DIR, name);
    const path = join(directory, 'broker.sock');
    if (bridge_account !== name || broker?.directory !== directory || broker.socket_path !== path
      || broker.owner_uid !== hqUid || broker.group_gid !== bridge_gid
      || broker.dir_mode !== 0o2750 || broker.socket_mode !== 0o660
      || !Array.isArray(broker.peer_uids) || broker.peer_uids.length !== 1 || broker.peer_uids[0] !== bridge_uid) {
      throw new Error('invalid Machine bridge broker endpoint');
    }
    usedUids.add(bridge_uid);
    installations.add(installation_id);
    return Object.freeze({ installationId: installation_id, runnerUid: entry.runner_uid,
      uid: bridge_uid, gid: bridge_gid, directory, path });
  });
}

export async function listenBridgeEndpoint(endpoint, { hqUid, host, core, peers,
  enableBridgeQualification = false, enableBridgeRelayIngress = false,
  enableRelayPeerChallenge = false,
  lstat = (path) => lstatSync(path, { bigint: true }),
  checkACL = checkDarwinACL, authenticate = authenticatePeerUid, listen = listenSocket } = {}) {
  function checkDirectory() {
    for (const path of ['/', '/Library', '/Library/Application Support', dirname(DARWIN_HARNESS_DIR), DARWIN_HARNESS_DIR]) {
      const st = lstat(path);
      if (!st.isDirectory() || Number(st.uid) !== 0 || (Number(st.mode) & 0o022) || !(Number(st.mode) & 0o001)) {
        throw new Error(`untrusted Darwin bridge broker parent ${path}`);
      }
      checkACL(path);
    }
    const dir = lstat(endpoint.directory);
    if (!dir.isDirectory() || Number(dir.uid) !== hqUid || Number(dir.gid) !== endpoint.gid
      || (Number(dir.mode) & 0o7777) !== 0o2750) {
      throw new Error('invalid Machine bridge broker directory on disk');
    }
    checkACL(endpoint.directory);
    const pinned = endpoint.parentIdentity;
    if (pinned && (String(dir.dev) !== pinned.device || String(dir.ino) !== pinned.inode
      || String(dir.birthtimeNs) !== pinned.birthtimeNs)) {
      throw new Error('Machine bridge broker parent identity changed');
    }
    return dir;
  }
  function checkSocket() {
    const socket = lstat(endpoint.path);
    if (!socket.isSocket() || Number(socket.uid) !== hqUid || Number(socket.gid) !== endpoint.gid
      || (Number(socket.mode) & 0o7777) !== 0o660) {
      throw new Error('invalid HQ bridge broker socket on disk');
    }
    return socket;
  }

  checkDirectory();
  let identity;
  const matchesInode = (recorded, current) => BigInt(recorded.dev) === BigInt(current.dev)
    && BigInt(recorded.ino) === BigInt(current.ino);
  function checkCurrent() {
    if (!identity) return false;
    const dir = checkDirectory();
    const socket = checkSocket();
    checkACL(endpoint.path);
    return matchesInode(identity.dir, dir) && matchesInode(identity.socket, socket);
  }
  const listener = await listen({
    path: endpoint.path, auth: 'member', core, mode: 0o660, replaceStale: false,
    authenticatePeer: async (socket) => {
      return await authenticate(socket, endpoint.uid) === true && checkCurrent();
    },
    newSession(socket) {
      const connection = `bb_${core.random.hex(12)}`;
      peers.set(connection, Object.freeze({ socket, endpoint, checkCurrent,
        dev: identity.socket.dev, ino: identity.socket.ino }));
      const end = () => {
        peers.delete(connection);
        // Revoke HQ's receipt before pending broker dispatch can finish.
        void host.provided('hq-admission')?.forgetBridgeConnection?.(connection)?.catch(() => {});
        void host.brokerClosed(connection).catch(() => {});
      };
      socket.once('close', end);
      return connection;
    },
    endSession: () => {},
    dispatch(kind, { payload, session }) {
      const qualification = kind === BRIDGE_QUALIFICATION_MESSAGES;
      const relayIngress = kind === BRIDGE_RELAY_INGRESS;
      const livePeer = kind === RELAY_PEER_CHALLENGE;
      const peer = peers.get(session);
      if (!peer || (!protectedBridgeKind(kind) && !(qualification && enableBridgeQualification === true)
        && !(relayIngress && enableBridgeRelayIngress === true)
        && !(livePeer && enableRelayPeerChallenge === true))) refuse();
      if ((qualification || relayIngress || livePeer || endpoint.parentIdentity)
        && (peer.socket.destroyed || !peer.checkCurrent())) refuse();
      return host.brokerAccept(kind, payload, { connection: session });
    },
  });
  try {
    const dir = checkDirectory();
    const socket = checkSocket();
    checkACL(endpoint.path);
    identity = { dir, socket };
  } catch (error) {
    await listener.close();
    throw error;
  }
  // The paired Machine prepare-B request can bind the identity HQ actually
  // observed. A cannot traverse H:B. B independently reopens and compares
  // these identities before it uses the broker, so H's claim is not enough.
  const brokerIdentity = () => {
    if (!checkCurrent()) refuse();
    const dir = checkDirectory();
    const socket = checkSocket();
    if (!matchesInode(identity.dir, dir) || !matchesInode(identity.socket, socket)) refuse();
    const projection = (st) => Object.freeze({ device: BigInt(st.dev).toString(),
      inode: BigInt(st.ino).toString(), owner_uid: Number(st.uid), group_gid: Number(st.gid),
      mode: Number(st.mode) & 0o7777 });
    return Object.freeze({ directory: endpoint.directory, socket_path: endpoint.path,
      directory_identity: projection(dir), socket_identity: projection(socket) });
  };
  return Object.freeze({ ...listener, brokerIdentity });
}

function matchesMemberEndpoint(member, endpoint, startId) {
  const installationId = endpoint.installationId;
  const slot = (domain, ...values) => createHash('sha256').update([domain, ...values].join('\0')).digest('hex').slice(0, 20);
  const directory = join(dirname(DARWIN_HARNESS_DIR), 'm', slot('agent-bot-soul-endpoint-installation/v1', installationId));
  const basename = `${slot('agent-bot-soul-endpoint-start/v1', installationId, startId)}.sock`;
  return member?.directory === directory && member.socket_path === join(directory, basename)
    && member.owner_uid === endpoint.runnerUid && member.group_gid === endpoint.gid
    && member.dir_mode === 0o2750 && member.socket_mode === 0o660
    && Array.isArray(member.peer_uids) && member.peer_uids.length === 2
    && member.peer_uids[0] === endpoint.runnerUid && member.peer_uids[1] === endpoint.uid;
}

export function bindBridgeAuthority(authority, peers, { hqEpoch } = {}) {
  const v2 = typeof authority?.verifyLiveStartV2 === 'function'
    && typeof authority.verifyProofV2 === 'function' && typeof authority.onDisconnectV2 === 'function';
  const v3 = typeof authority?.verifyLiveStartV3 === 'function'
    && typeof authority.verifyProofV3 === 'function' && typeof authority.onDisconnectV3 === 'function';
  if ((!v2 && !v3) || typeof hqEpoch !== 'string' || !/^[0-9a-f]{64}$/.test(hqEpoch)) return undefined;
  const isCurrentPeerV2 = (connection) => {
    const peer = peers.get(connection);
    return Boolean(peer && !peer.socket.destroyed && peer.checkCurrent());
  };
  const matchingPeer = (connection, installationId) => {
    const peer = peers.get(connection);
    if (peer?.endpoint.installationId !== installationId || !isCurrentPeerV2(connection)) refuse();
    return peer;
  };
  const protocolV3 = v3 ? {
    async verifyLiveStartV3(selectors, connection, phase) {
      const peer = matchingPeer(connection, selectors.installation_id);
      const context = await authority.verifyLiveStartV3(selectors, connection, peer, phase);
      if (!context || matchingPeer(connection, selectors.installation_id) !== peer) refuse();
      const proof = verifyStage2aBridgeMemberAuthority(context.authorityBytes, {
        machinePublicKey: context.machinePublicKey, schema: context.authoritySchema,
        assignmentSchema: context.assignmentSchema, schemas: context.schemaReferences,
        assignmentBytes: context.assignmentBytes,
        expected: { ...context.expected, installation_id: selectors.installation_id,
          start_id: selectors.start_id, plan_id: selectors.plan_id, plan_digest: selectors.plan_digest,
          reservation_sha256: selectors.reservation_digest, hq_epoch: hqEpoch,
          bridge_uid: peer.endpoint.uid, bridge_gid: peer.endpoint.gid, broker_socket: peer.endpoint.path },
      });
      const a = proof.payload;
      if (proof.envelope_sha256 !== selectors.authority_envelope_sha256
        || a.member_set_assignment_envelope_sha256 !== selectors.assignment_envelope_sha256
        || canonicalDigest(a.members.map((member) => member.member_selector)) !== selectors.member_selectors_sha256) refuse();
      return { ...selectors, hq_epoch: hqEpoch, bridge_uid: a.bridge.uid, broker_socket: peer.endpoint.path,
        member: a.bridge.endpoints.member, reservation_bytes: context.reservation_bytes,
        b_authority_sha256: a.b_authority.envelope_sha256, bridge_process: context.bridge_process,
        soul_artifact_sha256: context.soul_artifact_sha256, reservation_expires_at: context.reservation_expires_at,
        ...(context.finalized_live_expires_at === undefined ? {}
          : { finalized_live_expires_at: context.finalized_live_expires_at }) };
    },
    isCurrentPeerV3: isCurrentPeerV2,
    matchesAssignmentV3: (context, selectors, connection) => {
      const peer = matchingPeer(connection, selectors.installation_id);
      return matchesMemberEndpoint(context.member, peer.endpoint, selectors.start_id);
    },
    async verifyProofV3(proof, connection) {
      const peer = matchingPeer(connection, proof.installation_id);
      if (proof.hq_epoch !== hqEpoch || proof.bridge_uid !== peer.endpoint.uid
        || proof.broker_socket !== peer.endpoint.path) refuse();
      return await authority.verifyProofV3(proof, connection, peer) === true;
    },
    retainsChallengeStopV3: (connection) => authority.retainsChallengeStopV3?.(connection) === true,
    onDisconnectV3: (...args) => authority.onDisconnectV3(...args),
  } : {};
  return Object.freeze({
    ...protocolV3,
    ...(v2 ? {
      async verifyLiveStartV2(selectors, connection, phase) {
        const peer = peers.get(connection);
        if (!peer || peer.endpoint.installationId !== selectors.installation_id || !isCurrentPeerV2(connection)) refuse();
        return authority.verifyLiveStartV2(selectors, connection, peer, phase);
      },
      matchesAssignmentV2(context, selectors, connection) {
        const peer = peers.get(connection);
        return Boolean(peer && context.hq_epoch === hqEpoch && context.bridge_uid === peer.endpoint.uid
          && context.broker_socket === peer.endpoint.path && matchesMemberEndpoint(context.member, peer.endpoint, selectors.start_id));
      },
      async verifyProofV2(proof, connection) {
        const peer = peers.get(connection);
        if (!peer || !isCurrentPeerV2(connection)
          || peer.endpoint.installationId !== proof?.installation_id
          || proof.hq_epoch !== hqEpoch || proof.bridge_uid !== peer.endpoint.uid
          || proof.broker_socket !== peer.endpoint.path) refuse();
        return await authority.verifyProofV2({
          reservation_sha256: proof.reservation_digest,
          installation_id: proof.installation_id, start_id: proof.start_id,
          launch_id: proof.launch_id, plan_id: proof.plan_id,
          plan_digest: proof.plan_digest, hq_epoch: proof.hq_epoch,
          challenge: proof.challenge, proof: proof.proof,
        }, connection, peer) === true;
      },
      isCurrentPeerV2,
      retainsChallengeStopV2: (connection) => authority.retainsChallengeStopV2?.(connection) === true,
      onDisconnectV2: (...args) => authority.onDisconnectV2(...args),
    } : {}),
  });
}
