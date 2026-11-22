import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { lstat, mkdtemp, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { bindBridgeAuthority, listenBridgeEndpoint, memberBrokerDispatch, planBridgeEndpoints } from '../hq/bridge-endpoints.mjs';
import { DARWIN_HARNESS_DIR } from '../hq/darwin-harness-accounts.mjs';
import { listenSocket } from '../hq/socket.mjs';

const hqUid = 310;
const options = { platform: 'darwin', account: '_agent-bot-hq', hqUid, harnessUids: [320] };

function assignment(installation_id, runner_uid = 321, bridge_uid = 322) {
  const slot = createHash('sha256').update(`agent-bot-soul-bridge/v1\0${installation_id}`).digest('hex').slice(0, 20);
  const bridge_account = `_abm-br-${slot}`;
  const directory = join(DARWIN_HARNESS_DIR, bridge_account);
  return { installation_id, runner_uid, bridge_uid, bridge_gid: bridge_uid, bridge_account,
    broker: { directory, socket_path: join(directory, 'broker.sock'), owner_uid: hqUid,
      group_gid: bridge_uid, dir_mode: 0o2750, socket_mode: 0o660, peer_uids: [bridge_uid] } };
}

test('B endpoint plans refuse shared C and R identities, widened peer sets and caller paths', () => {
  const [endpoint] = planBridgeEndpoints([assignment('soul-a')], options);
  assert.equal(endpoint.uid, 322);
  assert.equal(endpoint.installationId, 'soul-a');
  assert.throws(() => planBridgeEndpoints([assignment('soul-a')], { ...options, platform: 'linux' }), /Darwin/);
  assert.throws(() => planBridgeEndpoints([assignment('soul-a', 321, 320)], options), /overlapping/);
  assert.throws(() => planBridgeEndpoints([assignment('soul-a', 321, 321)], options), /overlapping/);
  assert.throws(() => planBridgeEndpoints([assignment('soul-a'), assignment('soul-b', 322, 324)], options), /overlapping/);
  const bad = assignment('soul-a');
  bad.broker.peer_uids.push(bad.runner_uid);
  assert.throws(() => planBridgeEndpoints([bad], options), /broker endpoint/);
  bad.broker.peer_uids.pop();
  bad.broker.socket_path = '/tmp/broker.sock';
  assert.throws(() => planBridgeEndpoints([bad], options), /broker endpoint/);
});

test('B transport checks native UID and inode, restricts dispatch, and revokes on socket close', async () => {
  const [endpoint] = planBridgeEndpoints([assignment('soul-a')], options);
  const peers = new Map();
  const calls = [];
  const host = {
    brokerAccept: (...args) => calls.push(['accepted', ...args]),
    brokerClosed: async (connection) => { calls.push(['closed', connection]); },
    provided: () => ({ forgetBridgeConnection: async (connection) => { calls.push(['revoked', connection]); } }),
  };
  let handler;
  let inode = 42;
  const checks = [];
  await listenBridgeEndpoint(endpoint, { hqUid, host, peers, core: { random: { hex: () => 'test' } },
    checkACL() {},
    lstat(path) {
      return { isDirectory: () => path !== endpoint.path, isSocket: () => path === endpoint.path,
        uid: [endpoint.path, endpoint.directory].includes(path) ? hqUid : 0, gid: endpoint.gid,
        mode: path === endpoint.path ? 0o660 : path === endpoint.directory ? 0o2750 : 0o755, dev: 8, ino: inode };
    },
    authenticate(socket, uid) { checks.push(uid); return socket.uid === uid; },
    listen: async (config) => { handler = config; return {}; },
  });
  const socket = Object.assign(new EventEmitter(), { uid: 321, destroyed: false });
  assert.equal(await handler.authenticatePeer(socket), false);
  socket.uid = 322;
  assert.equal(await handler.authenticatePeer(socket), true);
  assert.deepEqual(checks, [322, 322]);
  inode++;
  assert.equal(await handler.authenticatePeer(socket), false);
  inode--;
  const session = handler.newSession(socket);
  assert.throws(() => memberBrokerDispatch(host, 'bridge.bind.v2', {}, 'shared'), { code: 'host.launch_unavailable' });
  assert.throws(() => memberBrokerDispatch(host, 'bridge.bind.v2.challenge', {}, 'harness'), { code: 'host.launch_unavailable' });
  memberBrokerDispatch(host, 'bind', {}, 'member');
  assert.throws(() => handler.dispatch('bind', { payload: {}, session }), { code: 'host.launch_unavailable' });
  assert.throws(() => handler.dispatch('bridge.bind.challenge', { payload: {}, session }), { code: 'host.launch_unavailable' });
  handler.dispatch('bridge.bind.v2.challenge', { payload: {}, session });
  const authority = bindBridgeAuthority({
    verifyLiveStart(_selectors, connection, peer) {
      assert.equal(connection, session);
      assert.equal(peer.socket, socket);
      assert.equal(peer.ino, 42);
      return peer.endpoint;
    },
  }, peers);
  assert.equal(await authority.verifyLiveStart({ installation_id: 'soul-a' }, session), endpoint);
  await assert.rejects(authority.verifyLiveStart({ installation_id: 'soul-b' }, session), { code: 'host.launch_unavailable' });
  socket.emit('close');
  await assert.rejects(authority.verifyLiveStart({ installation_id: 'soul-a' }, session), { code: 'host.launch_unavailable' });
  assert.deepEqual(calls, [
    ['accepted', 'bind', {}, { connection: 'member' }],
    ['accepted', 'bridge.bind.v2.challenge', {}, { connection: session }],
    ['revoked', session], ['closed', session],
  ]);
});

test('a B listener refuses an occupied path including a dangling symlink', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'b-'));
  try {
    const path = join(dir, 'broker.sock');
    await symlink(join(dir, 'missing'), path);
    await assert.rejects(listenSocket({ path, replaceStale: false }), /occupied/);
  } finally { await rm(dir, { recursive: true, force: true }); }
});

test('closing the B listener frees its socket path for a clean HQ restart', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'b-'));
  try {
    const path = join(dir, 'broker.sock');
    for (let attempt = 0; attempt < 2; attempt++) {
      const listener = await listenSocket({ path, replaceStale: false });
      assert.ok((await lstat(path)).isSocket());
      await listener.close();
      await assert.rejects(lstat(path), { code: 'ENOENT' });
    }
  } finally { await rm(dir, { recursive: true, force: true }); }
});
