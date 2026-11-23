import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { join } from 'node:path';
import { listenStage2aCooperativeAdmission, listenStage2aCooperativeBroker } from '../hq/stage2a-r-admission.mjs';

const ROOT = '/Library/Application Support/ai.true-line.agent-bot-hq';
const hash = (...parts) => createHash('sha256').update(parts.join('\0')).digest('hex');
const shaBytes = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

function fixture() {
  const installation_id = 'install-1';
  const start_id = `st_${'a'.repeat(24)}`;
  const launch_id = `ln_${'b'.repeat(24)}`;
  const challenge = randomBytes(32).toString('base64url');
  const challengeDigest = shaBytes(Buffer.from(challenge, 'base64url'));
  const envelope = Buffer.from('{"signed":true}').toString('base64url');
  const reservationDigest = shaBytes(Buffer.from(envelope, 'base64url'));
  const install = hash('agent-bot-soul-endpoint-installation/v1', installation_id).slice(0, 20);
  const start = hash('agent-bot-soul-endpoint-start/v1', installation_id, start_id).slice(0, 20);
  const directory = join(ROOT, 'c', install);
  const socket_path = join(directory, `${start}.sock`);
  const broker_socket_path = join(ROOT, 'broker', '_runner', 'broker.sock');
  const endpoint = { directory, socket_path, owner_uid: 309, group_gid: 311,
    expected_peer_uid: 311, dir_mode: 0o2750, socket_mode: 0o660 };
  const pinned = { envelope_base64url: envelope, sha256: reservationDigest,
    payload: { admission_challenge_sha256: challengeDigest,
      assignment: { installation_id, soul_id: 'agent_' + 'a'.repeat(8) + '-aaaa-aaaa-aaaa-' + 'a'.repeat(12),
        start_id, launch_id, hq_epoch: 'e'.repeat(64), hq_uid: 309,
        runner_uid: 311, runner_gid: 311, runner_account: '_runner' },
      measurement_binding: { installation_id, soul_id: 'agent_' + 'a'.repeat(8) + '-aaaa-aaaa-aaaa-' + 'a'.repeat(12),
        start_id, launch_id, hq_epoch: 'e'.repeat(64),
        profile_in_force: 'managed-cooperative',
        claimed_definition_digest: 'sha256:' + 'd'.repeat(64),
        h_service_descriptor_digest: 'sha256:' + 'f'.repeat(64) },
      endpoints: { admission: endpoint,
        broker: { directory: join(ROOT, 'broker', '_runner'), socket_path: broker_socket_path,
          owner_uid: 309, group_gid: 311, expected_peer_uid: 311,
          dir_mode: 0o2750, socket_mode: 0o660 } } } };
  let options;
  let receiptValid = true;
  let socketInode = 5n;
  let machineCalls = 0;
  let lost = 0;
  let admitted = 0;
  let acpOpened = 0;
  let live = true;
  const lstat = (path) => path === directory
    ? { isDirectory: () => true, uid: 309n, gid: 311n, mode: 0o2750n, dev: 1n, ino: 4n }
    : path === socket_path
      ? { isSocket: () => true, uid: 309n, gid: 311n, mode: 0o660n, dev: 1n, ino: socketInode }
      : { isDirectory: () => true, uid: 0n, mode: 0o755n };
  const open = () => listenStage2aCooperativeAdmission({ reservation: pinned,
    verifyReservation: async (value) => value, hqUid: 309,
    core: { random: { hex: () => randomBytes(12).toString('hex'), bytes: (n) => randomBytes(n) } },
    machineAttach: async (input) => { machineCalls++; return { input }; },
    verifyAttachReceipt: async ({ input }) => receiptValid ? {
      reservation_sha256: input.reservation_sha256,
      start_id: input.start_id, launch_id: input.launch_id,
      runner_pid: input.runner_pid, process_start: '123456789',
      challenge_sha256: challengeDigest, attached_at: new Date().toISOString(),
    } : { ...input, challenge_sha256: 'sha256:' + '0'.repeat(64) },
    admissionDispatch: async (op, meta) => {
      admitted++;
      assert.equal(meta.cooperativeStart.peer_uid, 311);
      assert.equal(meta.cooperativeStart.peer_pid, 402);
      return { op };
    },
    openAcpStream: async () => { acpOpened++; },
    isLive: () => live,
    onLost: () => { lost++; }, lstat, checkACL: () => {},
    observePeer: async (socket, uid) => uid === 311 ? socket.pid : null,
    listen: async (value) => { options = value; return { close: async () => {} }; } });
  const peer = async (pid = 402) => {
    const socket = { pid };
    const accepted = await options.authenticatePeer(socket);
    return { accepted, session: accepted ? options.newSession(socket) : undefined };
  };
  return { open, peer, pinned, challenge, lstat,
    get options() { return options; },
    get machineCalls() { return machineCalls; },
    get admitted() { return admitted; },
    get acpOpened() { return acpOpened; },
    get lost() { return lost; },
    badReceipt: () => { receiptValid = false; },
    loseLive: () => { live = false; },
    replaceSocket: () => { socketInode++; } };
}

test('C listener consumes a signed one-use R attach before ordinary Hello and returns only the signed H broker path', async () => {
  const f = fixture();
  const listener = await f.open();
  const { accepted, session } = await f.peer();
  assert.equal(accepted, true);
  const payload = { reservation_envelope_base64url: f.pinned.envelope_base64url,
    admission_challenge_base64url: f.challenge };
  const reply = await f.options.dispatch('cooperative.attach.v3', { session, payload });
  assert.deepEqual(reply, { schema: 'hq/cooperative-attach/v3',
    reservation_sha256: f.pinned.sha256, start_id: f.pinned.payload.assignment.start_id,
    launch_id: f.pinned.payload.assignment.launch_id,
    broker_socket_path: f.pinned.payload.endpoints.broker.socket_path,
    acp_ticket_base64url: reply.acp_ticket_base64url });
  assert.equal(Buffer.from(reply.acp_ticket_base64url, 'base64url').length, 32);
  assert.equal(f.machineCalls, 1);
  assert.deepEqual(await f.options.dispatch('Hello', { session, payload: {} }), { op: 'Hello' });
  assert.equal(f.admitted, 1);
  await assert.rejects(f.options.dispatch('cooperative.attach.v3', { session, payload }), /cooperative R admission/);
  f.options.endSession(session);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(f.lost, 1);
  await listener.close();
});

test('C ACP takeover needs the one-use ticket, same kernel PID and completed Hello', async () => {
  const f = fixture();
  await f.open();
  const first = await f.peer();
  const attached = await f.options.dispatch('cooperative.attach.v3', { session: first.session,
    payload: { reservation_envelope_base64url: f.pinned.envelope_base64url,
      admission_challenge_base64url: f.challenge } });
  const beforeHello = await f.peer();
  await assert.rejects(f.options.dispatch('cooperative.acp.v3', { session: beforeHello.session,
    takeover: true, payload: { acp_ticket_base64url: attached.acp_ticket_base64url } }), /cooperative R admission/);
  f.options.endSession(beforeHello.session);
  await f.options.dispatch('Hello', { session: first.session, payload: {} });
  const wrongPid = await f.peer(403);
  await assert.rejects(f.options.dispatch('cooperative.acp.v3', { session: wrongPid.session,
    takeover: true, payload: { acp_ticket_base64url: attached.acp_ticket_base64url } }), /cooperative R admission/);
  f.options.endSession(wrongPid.session);
  const second = await f.peer();
  const takeover = await f.options.dispatch('cooperative.acp.v3', { session: second.session,
    takeover: true, payload: { acp_ticket_base64url: attached.acp_ticket_base64url } });
  const connect = takeover[Object.getOwnPropertySymbols(takeover)[0]].open();
  connect({ destroy() {} });
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(f.acpOpened, 1);
  const replay = await f.peer();
  await assert.rejects(f.options.dispatch('cooperative.acp.v3', { session: replay.session,
    takeover: true, payload: { acp_ticket_base64url: attached.acp_ticket_base64url } }), /cooperative R admission/);
});

test('closing an attached C listener reports loss once and invalidates the peer even when A remains healthy', async () => {
  const f = fixture();
  const listener = await f.open();
  const first = await f.peer();
  await f.options.dispatch('cooperative.attach.v3', { session: first.session,
    payload: { reservation_envelope_base64url: f.pinned.envelope_base64url,
      admission_challenge_base64url: f.challenge } });
  await f.options.dispatch('Hello', { session: first.session, payload: {} });
  assert.ok(listener.attachedPeer(402));
  await listener.close();
  await listener.close();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(f.lost, 1);
  assert.equal(listener.attachedPeer(402), undefined);
});

test('a lost paired R watch revokes the C ticket before ACP takeover', async () => {
  const f = fixture();
  await f.open();
  const first = await f.peer();
  const attached = await f.options.dispatch('cooperative.attach.v3', { session: first.session,
    payload: { reservation_envelope_base64url: f.pinned.envelope_base64url,
      admission_challenge_base64url: f.challenge } });
  await f.options.dispatch('Hello', { session: first.session, payload: {} });
  f.loseLive();
  const second = await f.peer();
  await assert.rejects(f.options.dispatch('cooperative.acp.v3', { session: second.session,
    takeover: true, payload: { acp_ticket_base64url: attached.acp_ticket_base64url } }), /cooperative R admission/);
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(f.lost, 1);
  assert.equal(f.acpOpened, 0);
});

test('signed H broker endpoint admits only the attached R PID and labels its proof caller', async () => {
  const f = fixture();
  const admission = await f.open();
  const first = await f.peer();
  await f.options.dispatch('cooperative.attach.v3', { session: first.session,
    payload: { reservation_envelope_base64url: f.pinned.envelope_base64url,
      admission_challenge_base64url: f.challenge } });
  await f.options.dispatch('Hello', { session: first.session, payload: {} });
  const pin = admission.brokerPin;
  let options;
  let inode = 9n;
  let closed = 0;
  const callers = new Map();
  const broker = await listenStage2aCooperativeBroker({ admission, hqUid: 309,
    core: { random: { hex: () => randomBytes(12).toString('hex') } },
    callers, brokerDispatch: async (kind, payload, session) => ({ kind, payload, session }),
    brokerClosed: () => { closed++; }, onLost: () => {},
    observePeer: async (socket, uid) => uid === 311 ? socket.pid : null,
    checkACL: () => {},
    lstat: (path) => path === pin.endpoint.directory
      ? { isDirectory: () => true, uid: 309n, gid: 311n, mode: 0o2750n, dev: 1n, ino: 8n }
      : path === pin.endpoint.socket_path
        ? { isSocket: () => true, uid: 309n, gid: 311n, mode: 0o660n, dev: 1n, ino: inode }
        : { isDirectory: () => true, uid: 0n, mode: 0o755n },
    listen: async (value) => { options = value; return { close: async () => {} }; } });
  assert.equal(broker.path, pin.endpoint.socket_path);
  assert.equal(await options.authenticatePeer({ pid: 403 }), false);
  const socket = { pid: 402 };
  assert.equal(await options.authenticatePeer(socket), true);
  const session = options.newSession(socket);
  assert.deepEqual(callers.get(session), { kind: 'cooperative', account: '_runner', uid: 311,
    start_id: pin.start_id, reservation_sha256: pin.reservation_sha256 });
  assert.deepEqual(await options.dispatch('bind.challenge', { session,
    payload: { runtime_id: 'rt_1' } }), { kind: 'bind.challenge',
    payload: { runtime_id: 'rt_1' }, session });
  options.endSession(session);
  assert.equal(callers.has(session), false);
  assert.equal(closed, 1);
  inode++;
  assert.equal(broker.checkCurrent(), false);
  await broker.close();
  await admission.close();
});

test('C listener refuses wrong challenge, forged A receipt, changed socket and wrong R peer before Hello', async () => {
  const f = fixture();
  await f.open();
  assert.equal((await f.peer(1)).accepted, false);
  const first = await f.peer();
  await assert.rejects(f.options.dispatch('cooperative.attach.v3', { session: first.session,
    payload: { reservation_envelope_base64url: f.pinned.envelope_base64url,
      admission_challenge_base64url: randomBytes(32).toString('base64url') } }), /cooperative R admission/);
  assert.equal(f.machineCalls, 0);
  f.options.endSession(first.session);
  const g = fixture();
  g.badReceipt();
  await g.open();
  const second = await g.peer();
  await assert.rejects(g.options.dispatch('cooperative.attach.v3', { session: second.session,
    payload: { reservation_envelope_base64url: g.pinned.envelope_base64url,
      admission_challenge_base64url: g.challenge } }), /cooperative R admission/);
  assert.equal(g.machineCalls, 1);
  g.options.endSession(second.session);
  f.replaceSocket();
  assert.equal((await f.peer()).accepted, false);
  assert.equal(f.lost, 1);
});

test('C listener refuses an endpoint substitution or missing verifier before binding a socket', async () => {
  const f = fixture();
  f.pinned.payload.endpoints.admission.socket_path += '.wrong';
  await assert.rejects(f.open(), /cooperative R admission/);
  assert.equal(f.options, undefined);
  const g = fixture();
  await assert.rejects(listenStage2aCooperativeAdmission({ reservation: g.pinned, hqUid: 309 }), /cooperative R admission/);
});
