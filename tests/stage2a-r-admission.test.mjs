import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { listenStage2aRunnerAdmission } from '../hq/stage2a-r-admission.mjs';

const ROOT = '/Library/Application Support/ai.true-line.agent-bot-hq';
const hash = (...parts) => createHash('sha256').update(parts.join('\0')).digest('hex').slice(0, 20);
const sha = (raw) => `sha256:${createHash('sha256').update(raw).digest('hex')}`;

function fixture({ invalidLease = false, protectedPeer = true } = {}) {
  const installation_id = 'install-1', start_id = 'st_' + 'a'.repeat(24);
  const directory = join(ROOT, 'r', hash('agent-bot-soul-endpoint-installation/v1', installation_id));
  const socket_path = join(directory, hash('agent-bot-soul-endpoint-start/v1', installation_id, start_id) + '.sock');
  const admission = { directory, socket_path, owner_uid: 309, group_gid: 311,
    dir_mode: 0o2750, socket_mode: 0o660, peer_uids: [311] };
  const installed = { installation_id, soul_id: 'soul-1', plan_id: 'plan-1',
    plan_digest: 'd'.repeat(64), hq_epoch: 'e'.repeat(64),
    runner_uid: 311, runner_gid: 311, admission };
  const assignment = { installation_id, start_id, launch_id: 'ln_' + 'b'.repeat(24),
    soul_id: installed.soul_id, plan_id: installed.plan_id,
    plan_digest: installed.plan_digest, hq_epoch: installed.hq_epoch,
    hq_uid: 309, runner_uid: 311, admission };
  const selectors = { installation_id, start_id, launch_id: assignment.launch_id,
    plan_id: installed.plan_id, plan_digest: installed.plan_digest, hq_epoch: installed.hq_epoch,
    reservation_sha256: 'sha256:' + 'c'.repeat(64) };
  let listening, closed = 0, lost = 0, calls = 0, socketInode = 5n;
  let disconnected = 0;
  const admitted = [];
  const lstat = (path) => path === directory
    ? { isDirectory: () => true, uid: 309n, gid: 311n, mode: 0o2750n, dev: 1n, ino: 4n }
    : path === socket_path
      ? { isSocket: () => true, uid: 309n, gid: 311n, mode: 0o660n, dev: 1n, ino: socketInode }
      : { isDirectory: () => true, uid: 0n, mode: 0o755n };
  const renewLive = async (request) => {
    calls++;
    const bytes = Buffer.from(JSON.stringify({ challenge: request.challenge, signed: true }));
    return { ...request, schema: 'agent-bot-hq/protected-live/v1',
      lease_envelope_base64url: bytes.toString('base64url'),
      lease_sha256: invalidLease ? 'sha256:' + '0'.repeat(64) : sha(bytes), lease_sequence: calls };
  };
  const open = () => listenStage2aRunnerAdmission({ installed, assignment, selectors,
    hqUid: 309, core: { random: { hex: () => 'a'.repeat(24) } }, renewLive,
    onLost: () => { lost++; }, lstat, checkACL: () => {},
    protectedAdmission: protectedPeer ? {
      acceptPeer: async (socket, { peer_uid, peer_pid }) => ({ ...selectors,
        peer_uid, peer_pid, role: socket.role ?? 'runner' }),
      peerDisconnected: async () => { disconnected++; },
    } : undefined,
    admissionDispatch: protectedPeer ? async (op, meta) => {
      admitted.push({ op, context: meta.protectedStart });
      return { admitted: true };
    } : undefined,
    observePeer: async (socket, uid) => uid === 311 ? (socket.pid ?? 402) : null,
    listen: async (options) => { listening = options; return { close: async () => { closed++; } }; } });
  const peer = async (role = 'runner', pid = 402) => {
    const socket = { role, pid };
    assert.equal(await listening.authenticatePeer(socket), true);
    return { socket, context: await listening.connectionContext(socket) };
  };
  return { open, peer, admission, assignment, selectors, replaceSocket: () => { socketInode++; },
    get listening() { return listening; },
    get closed() { return closed; }, get lost() { return lost; }, get calls() { return calls; },
    get disconnected() { return disconnected; }, admitted };
}

test('signed per-start R listener accepts only the assigned peer and relays A lease bytes', async () => {
  const f = fixture();
  const listener = await f.open();
  assert.equal(listener.path, f.admission.socket_path);
  assert.equal(f.listening.mode, 0o660);
  assert.equal(f.listening.replaceStale, false);
  const { context } = await f.peer();
  const challenge = randomBytes(32).toString('base64url');
  const payload = { installation_id: f.selectors.installation_id,
    start_id: f.selectors.start_id, launch_id: f.selectors.launch_id,
    reservation_sha256: f.selectors.reservation_sha256, challenge };
  const reply = await f.listening.dispatch('launch.live', { payload, protectedStart: context });
  assert.equal(JSON.parse(Buffer.from(reply.lease_envelope_base64url, 'base64url')).challenge, challenge);
  assert.equal(reply.lease_sequence, 1);
  assert.equal(f.calls, 1);
  await assert.rejects(f.listening.dispatch('launch', { payload }), /protected R admission/);
  await assert.rejects(f.listening.dispatch('Hello', { payload }), /protected R admission/);
  await assert.rejects(f.listening.dispatch('launch.live', { payload: { ...payload, start_id: 'st_' + 'f'.repeat(24) }, protectedStart: context }), /protected R admission/);
  assert.equal(f.calls, 1);
  await listener.close();
  assert.equal(listener.checkCurrent(), false);
  assert.equal(f.closed, 1);
});

test('a changed assigned R endpoint is refused before listen', async () => {
  const f = fixture();
  f.assignment.admission = { ...f.admission, socket_path: f.admission.socket_path + '.other' };
  await assert.rejects(f.open(), /protected R admission/);
  assert.equal(f.listening, undefined);
});

test('an R identity equal to H is refused before listen', async () => {
  const f = fixture();
  f.assignment.runner_uid = 309;
  await assert.rejects(f.open(), /protected R admission/);
  assert.equal(f.listening, undefined);
});

test('a changed signed plan binding is refused before listen', async () => {
  const f = fixture();
  f.assignment.plan_digest = 'f'.repeat(64);
  await assert.rejects(f.open(), /protected R admission/);
  assert.equal(f.listening, undefined);
});

test('protected Hello and later admission ops route only with the trusted R peer context', async () => {
  const f = fixture();
  await f.open();
  const { socket, context } = await f.peer();
  assert.equal(context.reservation_sha256, f.selectors.reservation_sha256);
  assert.equal(context.peer_pid, 402);
  assert.equal(context.peer_uid, 311);
  assert.deepEqual(await f.listening.dispatch('Hello', { payload: {}, protectedStart: context }), { admitted: true });
  for (const op of ['Admit', 'Equip', 'Ready', 'Lease'])
    assert.deepEqual(await f.listening.dispatch(op, { payload: {}, protectedStart: context }), { admitted: true });
  assert.deepEqual(f.admitted.map(({ op }) => op), ['Hello', 'Admit', 'Equip', 'Ready', 'Lease']);
  await assert.rejects(f.listening.dispatch('Hello', { payload: {} }), /protected R admission/);
  await assert.rejects(f.listening.dispatch('launch', { payload: {} }), /protected R admission/);
  await f.listening.connectionClosed(socket, context);
  assert.equal(f.disconnected, 1);
  const liveOnly = await f.peer('child', 403);
  await assert.rejects(f.listening.dispatch('Hello', { payload: {}, protectedStart: liveOnly.context }), /protected R admission/);
  const challenge = randomBytes(32).toString('base64url');
  const lease = await f.listening.dispatch('launch.live', { protectedStart: liveOnly.context,
    payload: { installation_id: f.selectors.installation_id, start_id: f.selectors.start_id,
      launch_id: f.selectors.launch_id, reservation_sha256: f.selectors.reservation_sha256,
      challenge } });
  assert.equal(lease.lease_sequence, 1);
  await f.listening.connectionClosed(liveOnly.socket, liveOnly.context);
  assert.equal(f.disconnected, 1, 'a separate Live renewal close does not revoke Hello');
});

test('no Machine-authenticated role context means no Live or Hello', async () => {
  const f = fixture({ protectedPeer: false });
  await f.open();
  const socket = {};
  assert.equal(await f.listening.authenticatePeer(socket), true);
  await assert.rejects(f.listening.dispatch('Hello', { payload: {} }), /protected R admission/);
  await assert.rejects(f.listening.dispatch('launch.live', { payload: {} }), /protected R admission/);
});

test('unsigned or changed lease cannot reach R and requests containment', async () => {
  const f = fixture({ invalidLease: true });
  await f.open();
  const { context } = await f.peer();
  const payload = { installation_id: f.selectors.installation_id,
    start_id: f.selectors.start_id, launch_id: f.selectors.launch_id,
    reservation_sha256: f.selectors.reservation_sha256,
    challenge: randomBytes(32).toString('base64url') };
  await assert.rejects(f.listening.dispatch('launch.live', { payload, protectedStart: context }), /protected R admission/);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(f.lost, 1);
  assert.equal(f.calls, 1);
  await assert.rejects(f.listening.dispatch('launch.live', { payload, protectedStart: context }), /protected R admission/);
  assert.equal(f.calls, 1);
});

test('socket inode replacement cuts off the assigned listener', async () => {
  const f = fixture();
  const listener = await f.open();
  f.replaceSocket();
  assert.equal(listener.checkCurrent(), false);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(f.lost, 1);
  assert.equal(await f.listening.authenticatePeer({}), false);
});
