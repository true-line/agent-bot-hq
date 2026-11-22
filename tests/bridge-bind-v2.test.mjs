import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { bridgeBindProofV2, createBridgeBindAdmission } from '../hq/bridge-bind.mjs';

const key = Buffer.alloc(32, 0x41);
const bytes = Buffer.from('{ "machine": "synthetic reservation" }\n');
const digest = (input) => `sha256:${createHash('sha256').update(input).digest('hex')}`;
const selectors = Object.freeze({ installation_id: 'soul-a', start_id: `st_${'a'.repeat(24)}`,
  launch_id: `ln_${'b'.repeat(24)}`, plan_id: 'plan-1', plan_digest: 'c'.repeat(64),
  reservation_digest: 'sha256:eff7c53524a3d30873e2046ed2d42c48dd7a0c87a69c2c7d3bad998e7f68079e' });
const context = Object.freeze({ ...selectors, hq_epoch: 'd'.repeat(64), bridge_uid: 322,
  broker_socket: '/private/tmp/hq-broker.sock', reservation_bytes: bytes,
  reservation_expires_at: 20_000, member: { socket_path: '/private/tmp/machine-assigned-member.sock' },
  soul_artifact_sha256: `sha256:${'f'.repeat(64)}` });
const connection = { connection: 'bb_1' };
const denied = { code: 'host.launch_unavailable' };

function fixture({ timers, qualificationAuthorizer } = {}) {
  let now = 1_000;
  let sequence = 0;
  let verified = context;
  let machineKey = key;
  let peerCurrent = true;
  let assignmentMatches = true;
  let recheck;
  let proofCheck;
  let contain;
  const scopes = [];
  const stops = [];
  const alerts = [];
  const service = createBridgeBindAdmission({
    qualificationAuthorizer,
    authority: {
      async verifyLiveStartV2(scope, peer, phase) {
        scopes.push([scope, peer]);
        await recheck?.(scope, peer, phase);
        return verified;
      },
      async verifyProofV2(proof, peer) {
        assert.equal(peer, connection.connection);
        assert.equal(Object.hasOwn(proof, 'proof_key'), false);
        assert.equal(proof.hq_epoch, context.hq_epoch);
        assert.equal(proof.bridge_uid, context.bridge_uid);
        assert.equal(proof.broker_socket, context.broker_socket);
        await proofCheck?.();
        return proof.proof === bridgeBindProofV2(machineKey, proof.challenge, context);
      },
      verifyLiveStart() { throw new Error('v2 cannot fall back to a v1 verifier'); },
      isCurrentPeerV2: () => peerCurrent,
      matchesAssignmentV2: () => assignmentMatches,
      async onDisconnectV2(connection, reason, observation) {
        stops.push({ connection, observation, reason });
        return contain ? contain() : true;
      },
      onDisconnect() { throw new Error('v2 cannot fall back to v1 containment'); },
    },
    clock: { now: () => now },
    random: { hex: () => (++sequence).toString(16).padStart(64, '0') },
    receipts: { append: async (alert) => { alerts.push(alert); } },
    ...(timers ? { timers } : {}),
  });
  const challenge = () => service.bridgeBindChallengeV2(selectors, connection);
  const withProof = ({ nonce }) => ({ ...selectors, proof: bridgeBindProofV2(key, nonce, context) });
  return { service, scopes, stops, alerts, challenge, withProof,
    bind: async () => service.verifyBridgeBindingV2(withProof(await challenge()), connection),
    setNow: (value) => { now = value; },
    setVerified: (value) => { verified = value; },
    setMachineKey: (value) => { machineKey = value; },
    rejectAssignment: () => { assignmentMatches = false; },
    losePeer: () => { peerCurrent = false; },
    onVerify: (call) => { recheck = call; },
    onProof: (call) => { proofCheck = call; },
    onContain: (call) => { contain = call; },
  };
}

test('v2 signs the fixed UTF-8 and NUL-separated interop vector', () => {
  assert.equal(digest(bytes), selectors.reservation_digest);
  assert.equal(bridgeBindProofV2(key, 'e'.repeat(64), context),
    'e72fa74108dcc4d2079f2fea9633ae54ec01feb129d8de7692a46020ff2d9f0e');
});

test('v2 refuses with no authority or with only a v1 authority', async () => {
  for (const authority of [undefined, {
    verifyLiveStart() { assert.fail('v2 used a v1 Machine authority'); },
    onDisconnect() { assert.fail('an unauthenticated request chose a stop target'); },
  }]) {
    const service = createBridgeBindAdmission({ authority, clock: { now: () => 1000 },
      random: { hex: () => 'f'.repeat(64) }, receipts: { append: async () => {} } });
    await assert.rejects(service.bridgeBindChallengeV2(selectors, connection), denied);
    await assert.rejects(service.verifyBridgeBindingV2({ ...selectors, proof: 'f'.repeat(64) }, connection), denied);
  }
});

test('v2 requires six exact typed selectors before invoking Machine', async () => {
  const f = fixture();
  for (const malformed of [{ ...selectors, runtime_id: 'rt_fake' },
    { ...selectors, reservation_digest: 'a'.repeat(64) },
    { ...selectors, plan_digest: `sha256:${selectors.plan_digest}` },
    { ...selectors, launch_id: [selectors.launch_id] },
    { ...selectors, start_id: `${selectors.start_id}\0` },
    { ...selectors, assignment: context },
  ]) await assert.rejects(f.service.bridgeBindChallengeV2(malformed, connection), denied);
  assert.deepEqual(f.scopes, []);
  assert.deepEqual(f.stops, []);
});

test('v2 refuses missing or mismatched verified reservation bytes, member assignment and context', async () => {
  for (const change of [{ reservation_bytes: undefined }, { reservation_bytes: Buffer.alloc(0) },
    { reservation_bytes: Buffer.from(JSON.stringify(JSON.parse(bytes))) },
    { reservation_bytes: bytes.toString() }, { runtime_id: 'rt_fake' },
    { member: undefined }, { member: { socket_path: 'relative.sock' } },
    { reservation_expires_at: undefined }, { proof_key: Buffer.alloc(16) },
    { soul_artifact_sha256: undefined, package_sha256: context.soul_artifact_sha256 },
    { plan_id: 'different-plan' }, { bridge_uid: 501 }, { broker_socket: '/path\0/broker.sock' }]) {
    const f = fixture();
    f.setVerified({ ...context, ...change });
    await assert.rejects(f.challenge(), denied);
    assert.deepEqual(f.stops, [{ connection: connection.connection, observation: undefined,
      reason: 'bridge-verified-context-invalid' }]);
  }
});

test('a post-verification assignment mismatch contains by the authenticated connection before refusal', async () => {
  const f = fixture();
  f.rejectAssignment();
  let finishStop;
  f.onContain(() => new Promise((resolve) => { finishStop = resolve; }));
  let refused = false;
  const challenge = assert.rejects(f.challenge(), denied).then(() => { refused = true; });
  await new Promise(setImmediate);
  assert.deepEqual(f.stops, [{ connection: connection.connection, observation: undefined,
    reason: 'bridge-verified-context-invalid' }]);
  assert.equal(refused, false);
  finishStop(true);
  await challenge;
  await assert.rejects(f.challenge(), denied);
  assert.equal(f.scopes.length, 1);
  assert.equal(f.stops.length, 1);
});

test('failed containment of an authenticated malformed assignment fences bridge authority', async () => {
  const f = fixture();
  f.rejectAssignment();
  f.onContain(() => { throw new Error('Machine stop unavailable'); });
  await assert.rejects(f.challenge(), denied);
  assert.deepEqual(f.service.bridgeStatus(), { state: 'containment_unconfirmed' });
  assert.deepEqual(f.alerts, [{ kind: 'hq.bridge.containment_unconfirmed',
    reason: 'bridge-verified-context-invalid', bridge_connection: connection.connection }]);
  await assert.rejects(f.service.bridgeBindChallengeV2(selectors, { connection: 'bb_other' }), denied);
  assert.equal(f.scopes.length, 1);
  await assert.rejects(f.service.revokeAll(), /Machine stop unavailable/);
});

test('v2 receipt is bound to the same connection and selectors, with no v1 downgrade', async () => {
  const f = fixture();
  const challenge = await f.challenge();
  assert.deepEqual(challenge, { nonce: '1'.padStart(64, '0'), algorithm: 'hmac-sha256',
    context: 'agent-bot-stage2a-bridge-bind-v2', hq_epoch: context.hq_epoch,
    expires_at: new Date(context.reservation_expires_at).toISOString() });
  const proof = f.withProof(challenge);
  await assert.rejects(f.service.verifyBridgeBindingV2(proof, { connection: 'bb_other' }), denied);
  await assert.rejects(f.service.verifyBridgeBinding(proof, connection), denied);
  const { bind_receipt } = await f.service.verifyBridgeBindingV2(proof, connection);
  const receiptDigest = digest(bind_receipt);
  assert.deepEqual(await f.service.boundBridgeV2(selectors, receiptDigest), { ...selectors,
    hq_epoch: context.hq_epoch, bridge_uid: context.bridge_uid, broker_socket: context.broker_socket,
    member_socket: context.member.socket_path, soul_artifact_sha256: context.soul_artifact_sha256,
    bind_receipt_sha256: receiptDigest,
    connected: true, hmac_verified: true });
  await assert.rejects(f.service.verifyBridgeBindingV2(proof, connection), denied);
  f.onVerify((_scope, peer) => {
    if (peer !== connection.connection) throw new Error('Machine start already spent');
  });
  await assert.rejects(f.service.bridgeBindChallengeV2(selectors, { connection: 'bb_other' }), denied);
  assert.equal(await f.service.boundBridgeV2({ ...selectors, plan_id: 'other-plan' }, receiptDigest), null);
  const closing = f.service.forgetBridgeConnection(connection.connection, bind_receipt);
  assert.equal(await f.service.boundBridgeV2(selectors, receiptDigest), null);
  await closing;
  assert.equal(f.stops.length, 1);
  assert.equal(f.stops[0].observation.bind_receipt_sha256, receiptDigest);
});

test('an inconsistent duplicate authenticated start revokes the first receipt and contains both connections', async () => {
  const f = fixture();
  const { bind_receipt } = await f.bind();
  await assert.rejects(f.service.bridgeBindChallengeV2(selectors, { connection: 'bb_other' }), denied);
  assert.equal(await f.service.boundBridgeV2(selectors, digest(bind_receipt)), null);
  assert.deepEqual(f.stops.map(({ connection }) => connection), ['bb_1', 'bb_other']);
});

test('v2 wrong proof, changed context and late verification spend or expire the challenge', async () => {
  for (const scenario of ['legacy separator', 'changed key', 'changed peer', 'late verification']) {
    const f = fixture();
    const challenge = await f.challenge();
    const proof = f.withProof(challenge);
    if (scenario === 'legacy separator') proof.proof = createHmac('sha256', key).update([
      challenge.context, challenge.nonce, challenge.hq_epoch, ...Object.values(selectors),
      context.bridge_uid, context.broker_socket,
    ].join('\n')).digest('hex');
    if (scenario === 'changed key') f.setMachineKey(Buffer.alloc(32));
    if (scenario === 'changed peer') f.onVerify(f.losePeer);
    if (scenario === 'late verification') f.onVerify(() => f.setNow(context.reservation_expires_at));
    await assert.rejects(f.service.verifyBridgeBindingV2(proof, connection), denied, scenario);
    await assert.rejects(f.service.verifyBridgeBindingV2(f.withProof(challenge), connection), denied, scenario);
    assert.equal(f.stops.length, 1, scenario);
  }
});

test('a late Machine proof cannot publish a B receipt after disconnect or expiry', async () => {
  for (const ending of ['disconnect', 'expiry']) {
    const f = fixture();
    const challenge = await f.challenge();
    const entered = Promise.withResolvers();
    const release = Promise.withResolvers();
    f.onProof(async () => { entered.resolve(); await release.promise; });
    const pending = assert.rejects(f.service.verifyBridgeBindingV2(f.withProof(challenge), connection), denied);
    await entered.promise;
    if (ending === 'disconnect') await f.service.forgetBridgeConnection(connection.connection);
    else f.setNow(context.reservation_expires_at);
    release.resolve();
    await pending;
    assert.equal(await f.service.boundBridgeV2(selectors, digest('late-receipt')), null);
    assert.equal(f.stops.length, 1);
  }
});

test('v2 live receipt rejects reservation expiry and a close during its recheck', async () => {
  for (const ending of ['expires', 'close']) {
    const f = fixture();
    const { bind_receipt } = await f.bind();
    const receiptDigest = digest(bind_receipt);
    f.onVerify(() => ending === 'expires' ? f.setNow(context.reservation_expires_at)
      : f.service.forgetBridgeConnection(connection.connection));
    await assert.rejects(f.service.boundBridgeV2(selectors, receiptDigest), denied);
    assert.equal(await f.service.boundBridgeV2(selectors, receiptDigest), null);
    assert.equal(f.stops.length, 1);
  }
});

test('v2 idle receipt expiry contains the authenticated start without a lookup', async () => {
  let id = 0;
  const deadlines = new Map();
  const f = fixture({ timers: {
    setTimeout: (run, delay) => { deadlines.set(++id, { run, delay }); return id; },
    clearTimeout: (timer) => deadlines.delete(timer),
  } });
  const { bind_receipt } = await f.bind();
  assert.equal(deadlines.size, 1, 'the challenge timer was replaced by the live receipt timer');
  const [timer] = deadlines.values();
  assert.equal(timer.delay, context.reservation_expires_at - 1_000);
  f.setNow(context.reservation_expires_at);
  timer.run();
  await assert.rejects(f.service.boundBridgeV2(selectors, digest(bind_receipt)), denied);
  assert.equal(await f.service.boundBridgeV2(selectors, digest(bind_receipt)), null);
  assert.equal(f.stops.length, 1);
  assert.equal(f.stops[0].reason, 'bridge-receipt-expired');
  await f.service.revokeAll();
});

test('a Machine-finalized live lease keeps the same B connection beyond the pre-Hello deadline', async () => {
  const f = fixture();
  const { bind_receipt } = await f.bind();
  const receiptDigest = digest(bind_receipt);
  f.setNow(15_000);
  f.setVerified({ ...context, finalized_live_expires_at: 90_000 });
  assert.equal((await f.service.boundBridgeV2(selectors, receiptDigest)).connected, true);
  f.setNow(45_000);
  assert.equal((await f.service.boundBridgeV2(selectors, receiptDigest)).connected, true);
  assert.equal(f.stops.length, 0);
  f.setNow(90_000);
  await assert.rejects(f.service.boundBridgeV2(selectors, receiptDigest), denied);
  assert.equal(f.stops[0].reason, 'bridge-receipt-expired');
});

test('a finalized receipt refuses if Machine subsequently loses finalized live authority', async () => {
  const f = fixture();
  const { bind_receipt } = await f.bind();
  const receiptDigest = digest(bind_receipt);
  f.setVerified({ ...context, finalized_live_expires_at: 90_000 });
  assert.equal((await f.service.boundBridgeV2(selectors, receiptDigest)).connected, true);
  f.setVerified(context);
  await assert.rejects(f.service.boundBridgeV2(selectors, receiptDigest), denied);
  assert.equal(f.stops[0].reason, 'bridge-live-recheck-failed');
});

const qualificationRequest = { model: 'fixture-model', prompt_sha256: `sha256:${'a'.repeat(64)}` };
const qualificationResult = { model: qualificationRequest.model, text: 'fixture', stop_reason: 'end_turn',
  usage: { input_tokens: 1, output_tokens: 1 } };

test('qualification requires the same finalized v2 connection and spends one attempt', async () => {
  const authorizations = [];
  const f = fixture({ qualificationAuthorizer: async (input) => {
    authorizations.push(input);
    return qualificationResult;
  } });
  const { bind_receipt } = await f.bind();
  f.setVerified({ ...context, finalized_live_expires_at: 90_000 });
  const qualify = (input = qualificationRequest, peer = connection, receipt = bind_receipt) =>
    f.service.qualifyBridgeMessagesV2(input, peer, receipt);
  await assert.rejects(qualify(qualificationRequest, { connection: 'another' }), denied);
  await assert.rejects(qualify(qualificationRequest, connection, '0'.repeat(64)), denied);
  for (const key of ['runtime_id', 'path', 'credential', 'destination']) {
    await assert.rejects(qualify({ ...qualificationRequest, [key]: 'extra' }), denied);
  }
  assert.deepEqual(authorizations, []);
  assert.deepEqual(await qualify(), qualificationResult);
  await assert.rejects(qualify(), denied);
  assert.equal(authorizations.length, 1);
  assert.deepEqual(authorizations[0].request, qualificationRequest);
  assert.equal(authorizations[0].observation.reservation_digest, selectors.reservation_digest);
  assert.equal(authorizations[0].observation.bind_receipt_sha256, digest(bind_receipt));
  assert.equal(Object.hasOwn(authorizations[0].observation, 'proof_key'), false);
  await f.service.revokeAll();
});

test('qualification refuses unfinalized binds without calling the authorizer', async () => {
  const f = fixture({ qualificationAuthorizer: async () => assert.fail('unfinalized bind was dispatched') });
  const { bind_receipt } = await f.bind();
  await assert.rejects(f.service.qualifyBridgeMessagesV2(qualificationRequest, connection, bind_receipt), denied);
  assert.equal(f.stops.length, 1);
});

test('qualification discards a result after the peer disconnects during authorization', async () => {
  const entered = Promise.withResolvers();
  const authorization = Promise.withResolvers();
  const f = fixture({ qualificationAuthorizer: () => {
    entered.resolve();
    return authorization.promise;
  } });
  const { bind_receipt } = await f.bind();
  f.setVerified({ ...context, finalized_live_expires_at: 90_000 });
  const pending = assert.rejects(f.service.qualifyBridgeMessagesV2(qualificationRequest, connection, bind_receipt), denied);
  await entered.promise;
  await assert.rejects(f.service.qualifyBridgeMessagesV2(qualificationRequest, connection, bind_receipt), denied);
  await f.service.forgetBridgeConnection(connection.connection, bind_receipt);
  authorization.resolve(qualificationResult);
  await pending;
  assert.equal(f.stops.length, 1);
});
