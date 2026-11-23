import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { EventEmitter } from 'node:events';
import { dirname, join } from 'node:path';
import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalize } from '../sdk/wire/canonical-json.mjs';
import { DARWIN_HARNESS_DIR } from '../hq/darwin-harness-accounts.mjs';
import { bindBridgeAuthority, listenBridgeEndpoint } from '../hq/bridge-endpoints.mjs';
import { bridgeBindProofV2, createBridgeBindAdmission } from '../hq/bridge-bind.mjs';
import { createCooperativeBridgeAuthority, verifyCooperativeBridgeAssignment } from '../hq/stage2a-cooperative-bridge.mjs';

const purpose = 'agent-bot/soul-cooperative-bridge-assignment/v3';
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const digest = (bytes) => `sha256:${sha(bytes)}`;
const bytes = (record) => Buffer.from(canonicalize(record));
const slot = (domain, ...fields) => sha([domain, ...fields].join('\0')).slice(0, 20);

function fixture() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const machinePublicKey = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const install = 'inst_0000000000000001';
  const uid = 334, runner = 333, hqUid = 309;
  const account = `_abm-br-${slot('agent-bot-soul-bridge/v1', install)}`;
  const bridge = { account, uid, gid: uid };
  const startId = `st_${'a'.repeat(24)}`;
  const installSlot = slot('agent-bot-soul-endpoint-installation/v1', install);
  const startSocket = slot('agent-bot-soul-endpoint-start/v1', install, startId) + '.sock';
  const endpoint = (directory, leaf, owner, group, peer) => ({
    directory, socket_path: join(directory, leaf), owner_uid: owner, group_gid: group, expected_peer_uid: peer,
    dir_mode: 0o2750, socket_mode: 0o660, parent_device: '8', parent_inode: '42', parent_birthtime_ns: '100',
  });
  const broker = endpoint(join(DARWIN_HARNESS_DIR, account), 'broker.sock', hqUid, uid, uid);
  const member = endpoint(join(dirname(DARWIN_HARNESS_DIR), 'm', installSlot), startSocket, runner, uid, uid);
  const relay = endpoint(join(dirname(DARWIN_HARNESS_DIR), 's', installSlot), startSocket, uid, runner, runner);
  const contract = { contract: 'machine/v3', schema_version: 3, host_id: 'test',
    expires_at: '2026-11-23T12:00:20Z', bridge_launch_sha256: digest(bytes(bridge)) };
  const selectors = { installation_id: install, start_id: startId, launch_id: `ln_${'b'.repeat(24)}`,
    hq_epoch: 'c'.repeat(64), plan_id: 'plan-20261123T120000Z-abcd', plan_digest: 'e'.repeat(64) };
  const payload = { ...contract, adapter_transport: 'brokered-b',
    measurement_binding: { profile_in_force: 'managed-cooperative' },
    endpoints: { admission: {}, member, relay },
    assignment: { ...selectors, hq_uid: hqUid, runner_uid: runner, runner_gid: runner,
      machine_uid: 501, soul_artifact_sha256: 'f'.repeat(64) } };
  const reservationBytes = bytes(payload);
  const reservation = { payload, sha256: digest(reservationBytes) };
  const privateAssignment = { ...contract, ...selectors, kind: 'soul-cooperative-bridge-assignment',
    bridge: structuredClone(bridge), endpoints: { broker, member: structuredClone(member), relay: structuredClone(relay) },
    reservation_sha256: reservation.sha256 };
  const now = () => Date.parse('2026-11-23T12:00:00Z');
  const options = { machinePublicKey, reservation, installedBridge: bridge, platform: 'darwin', hqUid,
    account: '_agent-bot-hq', harnessUids: [], validatePayload: () => true, now };
  function signed(p = privateAssignment, domain = purpose) {
    const raw = bytes(p);
    return bytes({ schema_version: 3, purpose: domain, issuer_public_key_base64url: machinePublicKey.toString('base64url'),
      payload_sha256: digest(raw), payload_base64url: raw.toString('base64url'),
      signature_base64url: sign(null, Buffer.concat([Buffer.from(domain + '\0'), raw]), privateKey).toString('base64url') });
  }
  return { signed, privateAssignment, options, reservationBytes, selectors, uid, hqUid, runner, now };
}

test('verifies the private Machine assignment against exact R reservation, installed B and signed topology', () => {
  const f = fixture();
  const valid = verifyCooperativeBridgeAssignment(f.signed(), f.options);
  assert.equal(valid.endpoint.uid, f.uid);
  assert.equal(valid.endpoint.parentIdentity.inode, '42');
  assert.equal(valid.reservationSHA256, digest(f.reservationBytes));
  const rejects = (changes) => assert.throws(() => verifyCooperativeBridgeAssignment(f.signed(),
    { ...f.options, ...changes }), /bridge assignment|overlapping|Darwin/);
  rejects({ validatePayload: () => false });
  rejects({ machinePublicKey: Buffer.alloc(32) });
  rejects({ now: () => f.now() + 20000 });
  rejects({ harnessUids: [f.uid] });
  rejects({ installedBridge: { ...f.options.installedBridge, gid: f.runner } });
  rejects({ reservation: { ...f.options.reservation, sha256: digest('other reservation') } });
  assert.throws(() => verifyCooperativeBridgeAssignment(f.signed(
    f.privateAssignment, 'agent-bot/soul-cooperative-reservation/v3'), f.options), /bridge assignment/);
  f.privateAssignment.endpoints.relay.parent_inode = '43';
  assert.throws(() => verifyCooperativeBridgeAssignment(f.signed(), f.options), /bridge assignment/);
});

test('a live receipt needs Machine verification on the authenticated B stream', async () => {
  const f = fixture();
  const assignment = verifyCooperativeBridgeAssignment(f.signed(), f.options);
  const { endpoint, selectors: { hq_epoch, ...selectorFields } } = assignment;
  const selectors = { ...selectorFields, reservation_digest: assignment.reservationSHA256 };
  const peers = new Map();
  const key = Buffer.alloc(32, 11);
  let stopped = 0;
  const authority = bindBridgeAuthority(createCooperativeBridgeAuthority({
    assignment, reservationBytes: f.reservationBytes, now: f.now,
    verifyLiveStart: async () => ({ phase: 'prebind' }),
    verifyProof: async (proof) => proof.proof === bridgeBindProofV2(key, proof.challenge,
      { ...selectors, hq_epoch, bridge_uid: f.uid, broker_socket: endpoint.path }),
    containStart: async () => { stopped++; return true; },
  }), peers, { hqEpoch: hq_epoch });
  let random = 0;
  const core = { random: { hex: (length) => (++random).toString(16).padStart(length * 2, '0') } };
  const bind = createBridgeBindAdmission({ authority, clock: { now: f.now },
    random: core.random, receipts: { append() {} } });
  let handler;
  let birthtimeNs = 100;
  const host = {
    brokerAccept: (op, payload, meta) => op.endsWith('.challenge') ? bind.bridgeBindChallengeV2(payload, meta)
      : bind.verifyBridgeBindingV2(payload, meta),
    brokerClosed: async () => {},
    provided: () => bind,
  };
  await listenBridgeEndpoint(endpoint, { hqUid: f.hqUid, core, peers, host, checkACL() {},
    authenticate: (socket, uid) => socket.uid === uid,
    lstat(path) {
      return { isDirectory: () => path !== endpoint.path, isSocket: () => path === endpoint.path,
        uid: [endpoint.path, endpoint.directory].includes(path) ? f.hqUid : 0, gid: f.uid,
        mode: path === endpoint.path ? 0o660 : path === endpoint.directory ? 0o2750 : 0o755,
        dev: 8, ino: 42, birthtimeNs };
    },
    listen: async (config) => { handler = config; return {}; },
  });
  const socket = Object.assign(new EventEmitter(), { uid: f.runner, destroyed: false });
  assert.equal(await handler.authenticatePeer(socket), false);
  socket.uid = f.uid;
  assert.equal(await handler.authenticatePeer(socket), true);
  birthtimeNs++;
  await assert.rejects(handler.authenticatePeer(socket), /parent identity changed/);
  birthtimeNs--;
  const session = handler.newSession(socket);
  const { nonce } = await handler.dispatch('bridge.bind.v2.challenge', { payload: selectors, session });
  const input = { ...selectors, proof: bridgeBindProofV2(key, nonce, {
    ...selectors, hq_epoch, bridge_uid: f.uid, broker_socket: endpoint.path,
  }) };
  const other = handler.newSession(Object.assign(new EventEmitter(), { uid: f.uid, destroyed: false }));
  await assert.rejects(handler.dispatch('bridge.bind.v2', { payload: input, session: other }), /unavailable/);
  const { bind_receipt } = await handler.dispatch('bridge.bind.v2', { payload: input, session });
  assert.equal((await bind.boundBridgeV2(selectors, digest(bind_receipt))).connected, true);
  socket.emit('close');
  assert.equal(await bind.boundBridgeV2(selectors, digest(bind_receipt)), null);
  await bind.revokeAll();
  assert.equal(stopped, 1);
});

test('close during the first A live check contains the retained start and refuses a late challenge', async () => {
  const f = fixture();
  const assignment = verifyCooperativeBridgeAssignment(f.signed(), f.options);
  const { endpoint, selectors: { hq_epoch, ...selectorFields } } = assignment;
  const selectors = { ...selectorFields, reservation_digest: assignment.reservationSHA256 };
  const socket = { destroyed: false };
  const peers = new Map([['first', { socket, endpoint, checkCurrent: () => true }]]);
  let release;
  let stopped = 0;
  const authority = bindBridgeAuthority(createCooperativeBridgeAuthority({
    assignment, reservationBytes: f.reservationBytes, now: f.now,
    verifyLiveStart: () => new Promise((resolve) => { release = resolve; }),
    verifyProof: async () => true,
    containStart: async () => { stopped++; return true; },
  }), peers, { hqEpoch: hq_epoch });
  const bind = createBridgeBindAdmission({ authority, clock: { now: f.now },
    random: { hex: () => '0'.repeat(64) }, receipts: { append() {} } });
  const pending = bind.bridgeBindChallengeV2(selectors, { connection: 'first' });
  socket.destroyed = true;
  await bind.forgetBridgeConnection('first');
  assert.equal(stopped, 1);
  release({ phase: 'prebind' });
  await assert.rejects(pending, /unavailable/);
  await bind.revokeAll();
  assert.equal(stopped, 1);
});
