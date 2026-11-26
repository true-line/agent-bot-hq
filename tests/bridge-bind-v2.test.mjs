import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createHmac } from 'node:crypto';
import { canonicalDigest } from '../sdk/wire/canonical-json.mjs';
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
const relayPeer = { uid: 321, pid: 700, pid_version: 1, start_seconds: 1795520001,
  start_micros: 120000, parent_pid: 600, parent_uid: 321,
  parent_start_seconds: 1795520000, parent_start_micros: 110000 };

function fixture({ timers, qualificationAuthorizer, relayIngressAuthorizer,
  relayPrewriteAuthorizer, relayCompletionAuthorizer } = {}) {
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
    relayIngressAuthorizer,
    relayPrewriteAuthorizer,
    relayCompletionAuthorizer,
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

test('B relay ingress lookup requires the exact live connection and raw receipt', async () => {
  const f = fixture();
  const { bind_receipt } = await f.bind();
  const observed = await f.service.boundBridgeConnectionV2(connection.connection, bind_receipt);
  assert.equal(observed.bind_receipt_sha256, digest(bind_receipt));
  assert.equal(observed.connected, true);
  assert.equal(observed.hmac_verified, true);
  await assert.rejects(f.service.boundBridgeConnectionV2('bb_other', bind_receipt), denied);
  await assert.rejects(f.service.boundBridgeConnectionV2(connection.connection, digest(bind_receipt)), denied);
  await assert.rejects(f.service.boundBridgeConnectionV2(connection.connection, '0'.repeat(64)), denied);
  const closed = f.service.forgetBridgeConnection(connection.connection, bind_receipt);
  await assert.rejects(f.service.boundBridgeConnectionV2(connection.connection, bind_receipt), denied);
  await closed;
  assert.equal(f.stops.length, 1);

  const raced = fixture();
  const late = await raced.bind();
  raced.onVerify(() => raced.service.forgetBridgeConnection(connection.connection));
  await assert.rejects(raced.service.boundBridgeConnectionV2(connection.connection, late.bind_receipt), denied);
  assert.equal(raced.stops.length, 1);
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
const relayRequest = { ...qualificationRequest, peer: relayPeer };
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

test('a synthetic qualification callback cannot enable installed test-provider relay ingress', async () => {
  const f = fixture({ qualificationAuthorizer: async () => qualificationResult });
  assert.equal(f.service.bridgeRelayIngressEnabledV2(), false);
  const { bind_receipt } = await f.bind();
  f.setVerified({ ...context, finalized_live_expires_at: 90_000 });
  await assert.rejects(f.service.relayBridgeIngressV2(relayRequest, connection, bind_receipt), denied);
  assert.throws(() => fixture({ qualificationAuthorizer: async () => qualificationResult,
    relayIngressAuthorizer: async () => qualificationResult }), /cannot share a bridge/);
  await f.service.revokeAll();
});

test('installed test-provider relay ingress needs the exact finalized B connection and spends one attempt', async () => {
  const authorizations = [];
  const f = fixture({ relayIngressAuthorizer: async (input) => {
    authorizations.push(input);
    return qualificationResult;
  } });
  assert.equal(f.service.bridgeRelayIngressEnabledV2(), true);
  const { bind_receipt } = await f.bind();
  f.setVerified({ ...context, finalized_live_expires_at: 90_000 });
  const relay = (input = relayRequest, peer = connection, receipt = bind_receipt) =>
    f.service.relayBridgeIngressV2(input, peer, receipt);
  await assert.rejects(relay(relayRequest, { connection: 'bb_other' }), denied);
  await assert.rejects(relay(relayRequest, connection, '0'.repeat(64)), denied);
  for (const field of ['reservation_sha256', 'bind_receipt_sha256', 'path', 'credential']) {
    await assert.rejects(relay({ ...relayRequest, [field]: 'caller-claim' }), denied);
  }
  assert.deepEqual(authorizations, []);
  assert.deepEqual(await relay(), qualificationResult);
  await assert.rejects(relay(), denied);
  assert.equal(authorizations.length, 1);
  assert.deepEqual(authorizations[0].request, relayRequest);
  assert.equal(authorizations[0].observation.reservation_digest, selectors.reservation_digest);
  assert.equal(authorizations[0].observation.bind_receipt_sha256, digest(bind_receipt));
  assert.equal(Object.hasOwn(authorizations[0].observation, 'proof_key'), false);
  await f.service.revokeAll();
});

test('installed test-provider relay ingress refuses unfinalized B and a disconnected in-flight result', async () => {
  const unfinalized = fixture({ relayIngressAuthorizer: async () => assert.fail('unfinalized B dispatched') });
  const first = await unfinalized.bind();
  await assert.rejects(unfinalized.service.relayBridgeIngressV2(relayRequest, connection, first.bind_receipt), denied);
  assert.equal(unfinalized.stops.length, 1);

  const entered = Promise.withResolvers();
  const answer = Promise.withResolvers();
  const raced = fixture({ relayIngressAuthorizer: () => { entered.resolve(); return answer.promise; } });
  const second = await raced.bind();
  raced.setVerified({ ...context, finalized_live_expires_at: 90_000 });
  const pending = assert.rejects(raced.service.relayBridgeIngressV2(relayRequest, connection, second.bind_receipt), denied);
  await entered.promise;
  await assert.rejects(raced.service.relayBridgeIngressV2(relayRequest, connection, second.bind_receipt), denied);
  await raced.service.forgetBridgeConnection(connection.connection, second.bind_receipt);
  answer.resolve(qualificationResult);
  await pending;
  assert.equal(raced.stops.length, 1);
});

test('installed test-provider relay ingress contains an altered response without rearming', async () => {
  let calls = 0;
  const f = fixture({ relayIngressAuthorizer: async () => {
    calls++;
    return { ...qualificationResult, model: 'another-model' };
  } });
  const { bind_receipt } = await f.bind();
  f.setVerified({ ...context, finalized_live_expires_at: 90_000 });
  await assert.rejects(f.service.relayBridgeIngressV2(relayRequest, connection, bind_receipt), denied);
  await assert.rejects(f.service.relayBridgeIngressV2(relayRequest, connection, bind_receipt), denied);
  assert.equal(calls, 1);
  assert.equal(f.stops.length, 1);
});

test('B completion needs the same finalized ingress and records one checked client write', async () => {
  const completed = [];
  const prewrites = [];
  const f = fixture({ relayIngressAuthorizer: async () => qualificationResult,
    relayPrewriteAuthorizer: async (value) => {
      prewrites.push(value);
      return { accepted: true, prewrite_receipt: 'a'.repeat(64) };
    },
    relayCompletionAuthorizer: async (value) => { completed.push(value); return true; } });
  assert.equal(f.service.bridgeRelayPrewriteEnabledV2(), true);
  assert.equal(f.service.bridgeRelayCompletionEnabledV2(), true);
  const { bind_receipt } = await f.bind();
  f.setVerified({ ...context, finalized_live_expires_at: 90_000 });
  const prewrite = { selectors, bind_receipt_sha256: digest(bind_receipt),
    request_sha256: qualificationRequest.prompt_sha256, prompt_sha256: digest('stock prompt'),
    model: qualificationRequest.model, peer: relayPeer, peer_sha256: canonicalDigest(relayPeer), http_status: 200,
    response_wire_sha256: digest('HTTP/1.1 200 OK\r\n'), response_wire_bytes: 19 };
  const completion = { ...prewrite,
    write_started_at: '2026-11-24T01:02:03.123456789Z',
    write_completed_at: '2026-11-24T01:02:03.124456789Z',
    prewrite_receipt: 'a'.repeat(64), completion_origin_mac: 'b'.repeat(64) };
  const report = (value = completion, peer = connection, receipt = bind_receipt) =>
    f.service.completeBridgeIngressV2(value, peer, receipt);
  await assert.rejects(report(), denied);
  await assert.rejects(report(completion, { connection: 'bb_other' }), denied);
  await f.service.relayBridgeIngressV2(relayRequest, connection, bind_receipt);
  assert.notEqual(prewrite.request_sha256, prewrite.prompt_sha256);
  await assert.rejects(report(), denied);
  await assert.rejects(f.service.prewriteBridgeRelayV2({ ...prewrite, peer_sha256: digest('wrong') },
    connection, bind_receipt), denied);
  await assert.rejects(f.service.prewriteBridgeRelayV2(prewrite, { connection: 'bb_other' }, bind_receipt), denied);
  assert.deepEqual(await f.service.prewriteBridgeRelayV2(prewrite, connection, bind_receipt),
    { accepted: true, prewrite_receipt: 'a'.repeat(64) });
  assert.equal(prewrites.length, 1);
  assert.equal(prewrites[0].prewrite.prompt_sha256, prewrite.prompt_sha256);
  await assert.rejects(f.service.prewriteBridgeRelayV2(prewrite, connection, bind_receipt), denied);
  await assert.rejects(report({ ...completion, selectors: { ...selectors, start_id: `st_${'0'.repeat(24)}` } }), denied);
  await assert.rejects(report({ ...completion, request_sha256: digest('other request') }), denied);
  await assert.rejects(report({ ...completion, prompt_sha256: undefined }), denied);
  await assert.rejects(report({ ...completion, peer_sha256: digest('wrong peer') }), denied);
  await assert.rejects(report({ ...completion, peer: { ...relayPeer, pid_version: 2 },
    peer_sha256: canonicalDigest({ ...relayPeer, pid_version: 2 }) }), denied);
  await assert.rejects(report({ ...completion, http_status: 503 }), denied);
  await assert.rejects(report({ ...completion, prewrite_receipt: 'c'.repeat(64) }), denied);
  await assert.rejects(report({ ...completion, response_wire_sha256: digest('different wire') }), denied);
  await assert.rejects(report({ ...completion, completion_origin_mac: 'bad' }), denied);
  assert.equal(completed.length, 0);
  assert.deepEqual(await report(), { accepted: true });
  assert.equal(completed.length, 1);
  assert.equal(completed[0].completion.response_wire_sha256, completion.response_wire_sha256);
  assert.equal(completed[0].observation.bind_receipt_sha256, completion.bind_receipt_sha256);
  await assert.rejects(report(), denied);
  await f.service.revokeAll();
});

test('a late Machine prewrite response after B disconnect cannot authorize completion', async () => {
  const entered = Promise.withResolvers();
  const answer = Promise.withResolvers();
  let completed = 0;
  const f = fixture({ relayIngressAuthorizer: async () => qualificationResult,
    relayPrewriteAuthorizer: () => { entered.resolve(); return answer.promise; },
    relayCompletionAuthorizer: async () => { completed++; return true; } });
  const { bind_receipt } = await f.bind();
  f.setVerified({ ...context, finalized_live_expires_at: 90_000 });
  await f.service.relayBridgeIngressV2(relayRequest, connection, bind_receipt);
  const prewrite = { selectors, bind_receipt_sha256: digest(bind_receipt),
    request_sha256: qualificationRequest.prompt_sha256, prompt_sha256: digest('different prompt'),
    model: qualificationRequest.model, peer: relayPeer, peer_sha256: canonicalDigest(relayPeer),
    response_wire_sha256: digest('wire'), response_wire_bytes: 4, http_status: 200 };
  const pending = assert.rejects(f.service.prewriteBridgeRelayV2(prewrite, connection, bind_receipt), denied);
  await entered.promise;
  await f.service.forgetBridgeConnection(connection.connection, bind_receipt);
  answer.resolve({ accepted: true, prewrite_receipt: 'a'.repeat(64) });
  await pending;
  await assert.rejects(f.service.completeBridgeIngressV2({ ...prewrite,
    write_started_at: '2026-11-24T01:02:03Z', write_completed_at: '2026-11-24T01:02:04Z',
    prewrite_receipt: 'a'.repeat(64), completion_origin_mac: 'b'.repeat(64) },
  connection, bind_receipt), denied);
  assert.equal(completed, 0);
  assert.equal(f.stops.length, 1);
});

test('v3 binds the exact member set and gates finalized state on the same B connection', async () => {
  const { launch_id: _legacyLaunch, ...base } = selectors;
  const v3 = { ...base, assignment_envelope_sha256: digest('assignment'),
    authority_envelope_sha256: digest('authority'), member_selectors_sha256: digest('selectors') };
  const process = { pid: 401, uid: context.bridge_uid, gid: context.bridge_uid,
    start_seconds: 1234, start_micros: 56, executable_sha256: digest('bridge') };
  let verified = { ...context, ...v3, b_authority_sha256: v3.reservation_digest, bridge_process: process };
  let current = true;
  let sequence = 0;
  const label = 'agent-bot-stage2a-bridge-bind-v3';
  const proofFor = (nonce) => createHmac('sha256', key).update([
    label, nonce, context.hq_epoch, v3.installation_id, v3.start_id, v3.plan_id, v3.plan_digest,
    v3.reservation_digest, v3.assignment_envelope_sha256, v3.authority_envelope_sha256,
    v3.member_selectors_sha256, String(context.bridge_uid), context.broker_socket,
  ].join('\0')).digest('hex');
  const svc = createBridgeBindAdmission({ authority: {
    verifyLiveStartV3: async () => verified,
    verifyProofV3: async (request, id) => id === connection.connection
      && request.proof === proofFor(request.challenge) && request.member_selectors_sha256 === v3.member_selectors_sha256,
    matchesAssignmentV3: () => true,
    isCurrentPeerV3: () => current,
    onDisconnectV3: async () => true,
  }, clock: { now: () => 1000 }, random: { hex: () => (++sequence).toString(16).padStart(64, '0') },
  receipts: { append: async () => {} } });
  try {
    const challenge = await svc.bridgeBindChallengeV3(v3, connection);
    assert.equal(challenge.context, label);
    const proof = { ...v3, proof: proofFor(challenge.nonce) };
    await assert.rejects(svc.verifyBridgeBindingV3(proof, { connection: 'bb_other' }), denied);
    const { bind_receipt } = await svc.verifyBridgeBindingV3(proof, connection);
    assert.equal(svc.currentBridgeConnectionV3(connection.connection, bind_receipt), true);
    await assert.rejects(svc.finalizedBridgeConnectionV3(connection.connection, bind_receipt), denied);
    verified = { ...verified, finalized_live_expires_at: 10_000 };
    const finalized = await svc.finalizedBridgeConnectionV3(connection.connection, bind_receipt);
    assert.equal(finalized.member_selectors_sha256, v3.member_selectors_sha256);
    assert.deepEqual(finalized.bridge_process, process);
    current = false;
    assert.equal(svc.currentBridgeConnectionV3(connection.connection, bind_receipt), false);
    await assert.rejects(svc.finalizedBridgeConnectionV3(connection.connection, bind_receipt), denied);
  } finally { await svc.revokeAll(); }
});
