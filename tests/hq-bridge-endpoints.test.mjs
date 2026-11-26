import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { lstat, mkdtemp, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { bindBridgeAuthority, listenBridgeEndpoint, memberBrokerDispatch, planBridgeEndpoints } from '../hq/bridge-endpoints.mjs';
import { DARWIN_HARNESS_DIR } from '../hq/darwin-harness-accounts.mjs';
import { connectSocket, listenSocket } from '../hq/socket.mjs';

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

test('B transport checks UID and inode, refuses qualification by default, and revokes on close', () => checkBridgeTransport(false));

test('B transport forwards qualification only from the current dedicated peer when enabled', () => checkBridgeTransport(true));

test('B transport forwards relay ingress only from the current dedicated peer when enabled', () => checkBridgeTransport(false, true));
test('B transport forwards prewrite only from the current dedicated peer when enabled', () => checkBridgeTransport(false, false, false, false, true));
test('B transport forwards completion only from the current dedicated peer when enabled', () => checkBridgeTransport(false, false, false, true));
test('B transport forwards live peer challenge only from the current dedicated peer when enabled', () => checkBridgeTransport(false, false, true));

async function checkBridgeTransport(enabled, relayEnabled = false, peerEnabled = false,
  completionEnabled = false, prewriteEnabled = false) {
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
  const listener = await listenBridgeEndpoint(endpoint, { hqUid, host, peers,
    ...(enabled ? { enableBridgeQualification: true } : {}),
    ...(relayEnabled ? { enableBridgeRelayIngress: true } : {}),
    ...(prewriteEnabled ? { enableBridgeRelayPrewrite: true } : {}),
    ...(completionEnabled ? { enableBridgeRelayCompletion: true } : {}),
    ...(peerEnabled ? { enableRelayPeerChallenge: true } : {}),
    core: { random: { hex: () => 'test' } },
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
  assert.deepEqual(listener.brokerIdentity(), {
    directory: endpoint.directory, socket_path: endpoint.path,
    directory_identity: { device: '8', inode: '42', owner_uid: hqUid, group_gid: endpoint.gid, mode: 0o2750 },
    socket_identity: { device: '8', inode: '42', owner_uid: hqUid, group_gid: endpoint.gid, mode: 0o660 },
  });
  assert.equal(await handler.authenticatePeer(socket), false);
  socket.uid = 322;
  assert.equal(await handler.authenticatePeer(socket), true);
  assert.deepEqual(checks, [322, 322]);
  inode++;
  assert.throws(() => listener.brokerIdentity(), { code: 'host.launch_unavailable' });
  assert.equal(await handler.authenticatePeer(socket), false);
  inode--;
  const session = handler.newSession(socket);
  assert.throws(() => memberBrokerDispatch(host, 'bridge.bind.v2', {}, 'shared'), { code: 'host.launch_unavailable' });
  assert.throws(() => memberBrokerDispatch(host, 'bridge.bind.v2.challenge', {}, 'harness'), { code: 'host.launch_unavailable' });
  const qualification = 'bridge.qualification.messages.v1';
  const relayIngress = 'bridge.relay.ingress.v1';
  const relayPrewrite = 'bridge.relay.prewrite.v1';
  const relayCompletion = 'bridge.relay.complete.v1';
  const livePeer = 'stage2a-relay-peer-challenge';
  assert.throws(() => memberBrokerDispatch(host, qualification, {}, 'harness'), { code: 'host.launch_unavailable' });
  assert.throws(() => memberBrokerDispatch(host, relayIngress, {}, 'harness'), { code: 'host.launch_unavailable' });
  assert.throws(() => memberBrokerDispatch(host, relayPrewrite, {}, 'harness'), { code: 'host.launch_unavailable' });
  assert.throws(() => memberBrokerDispatch(host, relayCompletion, {}, 'harness'), { code: 'host.launch_unavailable' });
  assert.throws(() => memberBrokerDispatch(host, livePeer, {}, 'harness'), { code: 'host.launch_unavailable' });
  assert.throws(() => handler.dispatch(qualification, { payload: {}, session: 'unknown' }), { code: 'host.launch_unavailable' });
  assert.throws(() => handler.dispatch(relayIngress, { payload: {}, session: 'unknown' }), { code: 'host.launch_unavailable' });
  assert.throws(() => handler.dispatch(relayPrewrite, { payload: {}, session: 'unknown' }), { code: 'host.launch_unavailable' });
  assert.throws(() => handler.dispatch(relayCompletion, { payload: {}, session: 'unknown' }), { code: 'host.launch_unavailable' });
  assert.throws(() => handler.dispatch(livePeer, { payload: {}, session: 'unknown' }), { code: 'host.launch_unavailable' });
  if (enabled) handler.dispatch(qualification, { payload: {}, session });
  else assert.throws(() => handler.dispatch(qualification, { payload: {}, session }), { code: 'host.launch_unavailable' });
  if (relayEnabled) handler.dispatch(relayIngress, { payload: {}, session });
  else assert.throws(() => handler.dispatch(relayIngress, { payload: {}, session }), { code: 'host.launch_unavailable' });
  if (prewriteEnabled) handler.dispatch(relayPrewrite, { payload: {}, session });
  else assert.throws(() => handler.dispatch(relayPrewrite, { payload: {}, session }), { code: 'host.launch_unavailable' });
  if (completionEnabled) handler.dispatch(relayCompletion, { payload: {}, session });
  else assert.throws(() => handler.dispatch(relayCompletion, { payload: {}, session }), { code: 'host.launch_unavailable' });
  if (peerEnabled) handler.dispatch(livePeer, { payload: {}, session });
  else assert.throws(() => handler.dispatch(livePeer, { payload: {}, session }), { code: 'host.launch_unavailable' });
  memberBrokerDispatch(host, 'bind', {}, 'member');
  assert.throws(() => handler.dispatch('bind', { payload: {}, session }), { code: 'host.launch_unavailable' });
  assert.throws(() => handler.dispatch('bridge.bind.challenge', { payload: {}, session }), { code: 'host.launch_unavailable' });
  assert.throws(() => handler.dispatch('bridge.bind', { payload: {}, session }), { code: 'host.launch_unavailable' });
  handler.dispatch('bridge.bind.v2.challenge', { payload: {}, session });
  const selectors = { installation_id: 'soul-a', start_id: `st_${'a'.repeat(24)}` };
  const epoch = 'a'.repeat(64);
  const directory = '/Library/Application Support/ai.true-line.agent-bot-hq/m/5d2de78b58134f80521f';
  const member = { directory, socket_path: `${directory}/7da4d062fa49525ad2c6.sock`,
    owner_uid: 321, group_gid: 322, dir_mode: 0o2750, socket_mode: 0o660, peer_uids: [321, 322] };
  const context = { hq_epoch: epoch, bridge_uid: endpoint.uid, broker_socket: endpoint.path, member };
  let observed = context;
  let observedProof;
  const authority = bindBridgeAuthority({
    verifyLiveStartV2(_selectors, connection, peer) {
      assert.equal(connection, session);
      assert.equal(peer.socket, socket);
      assert.equal(peer.ino, 42);
      return observed;
    },
    verifyProofV2(request, connection, peer) {
      assert.equal(connection, session);
      assert.equal(peer.socket, socket);
      observedProof = request;
      return true;
    },
    onDisconnectV2() {},
  }, peers, { hqEpoch: epoch });
  assert.equal(await authority.verifyLiveStartV2(selectors, session), context);
  assert.equal(authority.matchesAssignmentV2(context, selectors, session), true);
  const proof = { ...selectors, launch_id: `ln_${'b'.repeat(24)}`, plan_id: 'plan-a',
    plan_digest: 'c'.repeat(64), reservation_digest: `sha256:${'d'.repeat(64)}`,
    hq_epoch: epoch, bridge_uid: endpoint.uid, broker_socket: endpoint.path,
    challenge: 'e'.repeat(64), proof: 'f'.repeat(64) };
  assert.equal(await authority.verifyProofV2(proof, session), true);
  assert.deepEqual(observedProof, { reservation_sha256: proof.reservation_digest,
    installation_id: proof.installation_id, start_id: proof.start_id, launch_id: proof.launch_id,
    plan_id: proof.plan_id, plan_digest: proof.plan_digest, hq_epoch: proof.hq_epoch,
    challenge: proof.challenge, proof: proof.proof });
  const denied = { code: 'host.launch_unavailable' };
  await assert.rejects(authority.verifyProofV2({ ...proof, bridge_uid: 321 }, session), denied);
  await assert.rejects(authority.verifyLiveStartV2({ ...selectors, installation_id: 'soul-b' }, session), denied);
  assert.equal(authority.matchesAssignmentV2(context, { ...selectors, start_id: `st_${'b'.repeat(24)}` }, session), false);
  for (const change of [{ hq_epoch: 'b'.repeat(64) }, { bridge_uid: 321 }, { broker_socket: '/tmp/broker.sock' },
    { member: undefined }, { member: { ...member, socket_path: '/tmp/legacy.sock' } },
    { member: { ...member, owner_uid: 322 } }, { member: { ...member, dir_mode: 0o750 } },
    { member: { ...member, peer_uids: [321] } }]) {
    observed = { ...context, ...change };
    assert.equal(authority.matchesAssignmentV2(observed, selectors, session), false);
  }
  observed = context;
  inode++;
  assert.equal(authority.isCurrentPeerV2(session), false);
  assert.throws(() => handler.dispatch(qualification, { payload: {}, session }), denied);
  assert.throws(() => handler.dispatch(relayIngress, { payload: {}, session }), denied);
  assert.throws(() => handler.dispatch(relayPrewrite, { payload: {}, session }), denied);
  assert.throws(() => handler.dispatch(relayCompletion, { payload: {}, session }), denied);
  assert.throws(() => handler.dispatch(livePeer, { payload: {}, session }), denied);
  await assert.rejects(authority.verifyLiveStartV2(selectors, session), denied);
  inode--;
  socket.emit('close');
  await assert.rejects(authority.verifyLiveStartV2(selectors, session), denied);
  assert.throws(() => handler.dispatch(qualification, { payload: {}, session }), denied);
  assert.deepEqual(calls, [
    ...(enabled ? [['accepted', qualification, {}, { connection: session }]] : []),
    ...(relayEnabled ? [['accepted', relayIngress, {}, { connection: session }]] : []),
    ...(prewriteEnabled ? [['accepted', relayPrewrite, {}, { connection: session }]] : []),
    ...(completionEnabled ? [['accepted', relayCompletion, {}, { connection: session }]] : []),
    ...(peerEnabled ? [['accepted', livePeer, {}, { connection: session }]] : []),
    ['accepted', 'bind', {}, { connection: 'member' }],
    ['accepted', 'bridge.bind.v2.challenge', {}, { connection: session }],
    ['revoked', session], ['closed', session],
  ]);
}

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

test('the dedicated B response cap accepts an exact frame and refuses one byte more', async () => {
  const dir = await mkdtemp(join(tmpdir(), 'b-frame-'));
  const path = join(dir, 'broker.sock'), cap = 32 * 1024;
  const room = cap - Buffer.byteLength(JSON.stringify({ id: 1, ok: true, result: '' }) + '\n');
  const listener = await listenSocket({ path, maxResponseBytes: cap, auth: 'member',
    core: { logs: [], tokens: new Map(), clock: { now: Date.now }, random: { hex: () => '1' } },
    newSession: () => 'b', endSession: () => {}, dispatch: (op) => 'a'.repeat(room + Number(op === 'oversize')) });
  let client;
  try {
    client = await connectSocket(path);
    assert.equal((await client.request('exact')).result.length, room);
    const oversize = await client.request('oversize');
    assert.equal(oversize.ok, false);
    assert.match((oversize.host_refusal ?? oversize.refusal).explanation, /broker response exceeds its frame limit/);
  } finally {
    await client?.close();
    await listener.close();
    await rm(dir, { recursive: true, force: true });
  }
});

test('cooperative B challenge, proof and policy dispatch stay on one dedicated stream', async () => {
  const [endpoint] = planBridgeEndpoints([assignment('soul-coop')], options);
  const receipt = 'a'.repeat(64), digest = 'sha256:' + 'b'.repeat(64);
  let handler;
  let sequence = 0;
  let challengedSession;
  const isolation = { code: 'host.launch_unavailable' };
  const methods = {
    stage2aCooperativeBBindChallengeV3: async (_request, { connection }) => {
      challengedSession = connection;
      return { nonce: 'c'.repeat(64) };
    },
    stage2aCooperativeBBindV3: async (_request, { connection }) => {
      assert.equal(connection, challengedSession);
      return { bind_receipt: receipt, bind_receipt_sha256: digest };
    },
    stage2aCooperativeBPolicyV3: async (_request, { connection }, presented) => {
      assert.equal(connection, challengedSession);
      assert.equal(presented, receipt);
      return { policy: 'accepted' };
    },
    stage2aCooperativeMemberObserveV3: async (_request, { connection }, presented) => {
      assert.equal(connection, challengedSession);
      assert.equal(presented, receipt);
      return { observation: 'accepted' };
    },
    stage2aCooperativeBridgeReadyV3: async (_request, { connection }, presented) => {
      assert.equal(connection, challengedSession);
      assert.equal(presented, receipt);
      return { ready: 'accepted' };
    },
  };
  await listenBridgeEndpoint(endpoint, { hqUid, peers: new Map(),
    enableCooperativeBBind: true, enableCooperativeBPolicy: true,
    enableMemberArmExchange: true, cooperativeHandlers: methods,
    host: { provided: () => methods, brokerClosed: async () => {},
      brokerAccept: () => assert.fail('cooperative operations route only through dedicated HQ dispatch') },
    core: { random: { hex: () => String(++sequence) } },
    checkACL() {}, authenticate: () => true,
    lstat(path) {
      return { isDirectory: () => path !== endpoint.path, isSocket: () => path === endpoint.path,
        uid: [endpoint.path, endpoint.directory].includes(path) ? hqUid : 0, gid: endpoint.gid,
        mode: path === endpoint.path ? 0o660 : path === endpoint.directory ? 0o2750 : 0o755, dev: 8, ino: 42 };
    },
    listen: async (config) => { handler = config; return {}; },
  });
  const socket = new EventEmitter();
  const session = handler.newSession(socket);
  const other = handler.newSession(new EventEmitter());
  const bind = 'bridge.bind.cooperative.v3', policy = 'bridge.member-policy.v3';
  const observe = 'bridge.member.observe.cooperative.v3', ready = 'bridge.ready.cooperative.v3';
  await assert.rejects(handler.dispatch(observe, { session, payload: {} }), isolation);
  await assert.rejects(handler.dispatch(ready, { session, payload: {} }), isolation);
  await assert.rejects(handler.dispatch(policy, { session, payload: {} }), isolation);
  assert.ok((await handler.dispatch(bind, { session, payload: {} })).nonce);
  await assert.rejects(handler.dispatch(bind, { session: other, payload: { proof_hex: 'd'.repeat(64) } }), isolation);
  const proof = { session, payload: { proof_hex: 'd'.repeat(64) } };
  assert.deepEqual(await handler.dispatch(bind, proof), { bind_receipt_sha256: digest });
  assert.deepEqual(await handler.dispatch(policy, { session, payload: {} }), { policy: 'accepted' });
  await assert.rejects(handler.dispatch(observe, { session: other, payload: {} }), isolation);
  assert.deepEqual(await handler.dispatch(observe, { session, payload: {} }), { observation: 'accepted' });
  await assert.rejects(handler.dispatch(ready, { session: other, payload: {} }), isolation);
  assert.deepEqual(await handler.dispatch(ready, { session, payload: {} }), { ready: 'accepted' });
  await assert.rejects(handler.dispatch(policy, { session, payload: {} }), isolation);
  socket.emit('close');
  assert.throws(() => handler.dispatch(policy, { session, payload: {} }), isolation);
});
