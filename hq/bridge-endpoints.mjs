// The paired Machine client supplies verified per-installation broker assignments.
// HQ checks the local directory and socket and admits only the kernel B UID.
import { createHash } from 'node:crypto';
import { lstatSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fail } from '../sdk/errors.mjs';
import { checkDarwinACL, DARWIN_HARNESS_DIR } from './darwin-harness-accounts.mjs';
import { authenticatePeerUid } from './owner-control.mjs';
import { listenSocket } from './socket.mjs';

const ROLE_UID = (uid) => Number.isInteger(uid) && uid >= 300 && uid <= 399;
const INSTALLATION = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const protectedBridgeKind = (kind) => kind === 'bridge.bind.v2.challenge' || kind === 'bridge.bind.v2';
const refuse = () => fail('host.launch_unavailable', 'bridge bind requires the dedicated Machine-assigned B broker');

export function memberBrokerDispatch(host, kind, payload, connection) {
  if (protectedBridgeKind(kind)) refuse();
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
    return Object.freeze({ installationId: installation_id, uid: bridge_uid, gid: bridge_gid, directory, path });
  });
}

export async function listenBridgeEndpoint(endpoint, { hqUid, host, core, peers,
  lstat = lstatSync, checkACL = checkDarwinACL, authenticate = authenticatePeerUid, listen = listenSocket } = {}) {
  function checkDirectory() {
    for (const path of ['/', '/Library', '/Library/Application Support', dirname(DARWIN_HARNESS_DIR), DARWIN_HARNESS_DIR]) {
      const st = lstat(path);
      if (!st.isDirectory() || st.uid !== 0 || (st.mode & 0o022) || !(st.mode & 0o001)) {
        throw new Error(`untrusted Darwin bridge broker parent ${path}`);
      }
      checkACL(path);
    }
    const dir = lstat(endpoint.directory);
    if (!dir.isDirectory() || dir.uid !== hqUid || dir.gid !== endpoint.gid || (dir.mode & 0o7777) !== 0o2750) {
      throw new Error('invalid Machine bridge broker directory on disk');
    }
    checkACL(endpoint.directory);
  }
  function checkSocket() {
    const socket = lstat(endpoint.path);
    if (!socket.isSocket() || socket.uid !== hqUid || socket.gid !== endpoint.gid || (socket.mode & 0o7777) !== 0o660) {
      throw new Error('invalid HQ bridge broker socket on disk');
    }
    return socket;
  }

  checkDirectory();
  let identity;
  const listener = await listen({
    path: endpoint.path, auth: 'member', core, mode: 0o660, replaceStale: false,
    authenticatePeer: async (socket) => {
      if (!identity || await authenticate(socket, endpoint.uid) !== true) return false;
      const current = checkSocket();
      return current.dev === identity.dev && current.ino === identity.ino;
    },
    newSession(socket) {
      const connection = `bb_${core.random.hex(12)}`;
      peers.set(connection, Object.freeze({ socket, endpoint,
        dev: identity.dev, ino: identity.ino }));
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
      if (!protectedBridgeKind(kind) || !peers.has(session)) refuse();
      return host.brokerAccept(kind, payload, { connection: session });
    },
  });
  try {
    checkDirectory();
    const socket = checkSocket();
    checkACL(endpoint.path);
    identity = { dev: socket.dev, ino: socket.ino };
  } catch (error) {
    await listener.close();
    throw error;
  }
  return listener;
}

export function bindBridgeAuthority(authority, peers) {
  return {
    async verifyLiveStart(selectors, connection) {
      const peer = peers.get(connection);
      if (!peer || peer.socket.destroyed || peer.endpoint.installationId !== selectors.installation_id) refuse();
      return authority.verifyLiveStart(selectors, connection, peer);
    },
    onDisconnect: (...args) => authority.onDisconnect(...args),
  };
}
