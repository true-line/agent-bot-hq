import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { bridgeBindProof, createBridgeBindAdmission } from '../hq/bridge-bind.mjs';

const selectors = Object.freeze({ installation_id: 'inst_1', start_id: `st_${'a'.repeat(24)}`,
  launch_id: `ln_${'b'.repeat(24)}`, runtime_id: 'rt_1', plan_id: 'plan-1',
  plan_digest: 'c'.repeat(64) });
const key = Buffer.alloc(32, 0x41);
const context = Object.freeze({ ...selectors, hq_epoch: 'd'.repeat(64), bridge_uid: 302,
  broker_socket: '/private/var/run/agent-bot/bridge/broker.sock', proof_key: key });
const connection = { connection: 'bc_1' };
const denied = { code: 'host.launch_unavailable' };
const deferred = () => {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
};

function fixture({ timers } = {}) {
  let now = 1_000;
  let sequence = 0;
  let current = context;
  const stops = [];
  const alerts = [];
  const service = createBridgeBindAdmission({
    authority: {
      verifyLiveStart: async () => current,
      onDisconnect: (observation) => { stops.push(observation); },
    },
    clock: { now: () => now },
    random: { hex: () => (++sequence).toString(16).padStart(64, '0') },
    receipts: { append: async (record) => { alerts.push(record); } },
    ...(timers ? { timers } : {}),
  });
  const bind = async (s = selectors, peer = connection) => {
    const challenge = await service.bridgeBindChallenge(s, peer);
    const proof = bridgeBindProof(key, challenge.nonce, current);
    const result = await service.verifyBridgeBinding({ ...s, proof }, peer);
    const digest = `sha256:${createHash('sha256').update(result.bind_receipt).digest('hex')}`;
    return { challenge, result, digest };
  };
  return { service, bind, stops, alerts, setNow: (value) => { now = value; },
    setContext: (value) => { current = value; } };
}

test('a production admission with no trusted Machine authority refuses B bind', async () => {
  const closed = createBridgeBindAdmission({ clock: { now: () => 1000 }, random: { hex: () => 'f'.repeat(64) } });
  await assert.rejects(closed.bridgeBindChallenge(selectors, connection), denied);
  await assert.rejects(closed.verifyBridgeBinding({ ...selectors, proof: 'e'.repeat(64) }, connection), denied);
});

test('one exact Machine start and one-use HMAC bind yields a live receipt until close', async () => {
  const f = fixture();
  const { challenge, result, digest } = await f.bind();
  assert.equal(challenge.hq_epoch, context.hq_epoch);
  assert.equal(challenge.context, 'agent-bot-stage2a-bridge-bind-v1');
  assert.equal((await f.service.boundBridge(selectors, digest))?.bridge_uid, 302);
  assert.equal((await f.service.boundBridge(selectors, digest))?.connected, true);
  await assert.rejects(f.service.verifyBridgeBinding({ ...selectors, proof: bridgeBindProof(key, challenge.nonce, context) }, connection), denied);
  const closed = f.service.forgetBridgeConnection(connection.connection, result.bind_receipt);
  assert.equal(await f.service.boundBridge(selectors, digest), null, 'close revokes before containment can await');
  await closed;
  assert.equal(f.stops.length, 1);
  assert.equal(f.stops[0].bind_receipt_sha256, digest);
  await assert.rejects(f.service.bridgeBindChallenge(selectors, connection), denied);
  await assert.rejects(f.service.bridgeBindChallenge(selectors, { connection: 'bc_2' }), denied,
    'the same start cannot bootstrap another B connection');
});

test('a second challenge on one B connection cannot replace its first authenticated start', async () => {
  const other = { ...selectors, start_id: `st_${'e'.repeat(24)}` };
  const stops = [];
  const timers = new Map();
  let sequence = 0;
  const service = createBridgeBindAdmission({
    authority: {
      verifyLiveStart: async (input) => ({ ...context, ...input }),
      onDisconnect: async (observation) => { stops.push(observation.start_id); },
    },
    clock: { now: () => 1000 },
    random: { hex: () => (++sequence).toString(16).padStart(64, '0') },
    receipts: { append: async () => {} },
    timers: { setTimeout: (fn) => { const id = ++sequence; timers.set(id, fn); return id; },
      clearTimeout: (id) => timers.delete(id) },
  });
  await service.bridgeBindChallenge(selectors, connection);
  await assert.rejects(service.bridgeBindChallenge(other, connection), denied);
  assert.equal(timers.size, 1, 'the original challenge deadline remains registered');
  await service.forgetBridgeConnection(connection.connection);
  assert.deepEqual(stops, [selectors.start_id], 'close contains the first authenticated start');
});

test('an uncertain Machine stop fences every in-flight B authority publication', async () => {
  for (const phase of ['challenge', 'bind', 'lookup']) {
    const other = { ...selectors, start_id: `st_${'e'.repeat(24)}` };
    const contexts = new Map([[selectors.start_id, context], [other.start_id, { ...context, ...other }]]);
    const stopped = [];
    const entered = deferred();
    const gate = deferred();
    let gateArmed = false;
    let sequence = 0;
    const targetPeer = { connection: 'bc_target' };
    const otherPeer = { connection: 'bc_other' };
    const service = createBridgeBindAdmission({
      authority: {
        verifyLiveStart: async (input, peer) => {
          if (gateArmed && peer === targetPeer.connection) { entered.resolve(); await gate.promise; }
          return contexts.get(input.start_id);
        },
        onDisconnect: async (observation) => {
          stopped.push(observation.start_id);
          if (observation.start_id === other.start_id) throw new Error('Machine stop unavailable');
        },
      },
      clock: { now: () => 1000 },
      random: { hex: () => (++sequence).toString(16).padStart(64, '0') },
      receipts: { append: async () => {} },
    });
    let challenge;
    let digest;
    if (phase !== 'challenge') {
      challenge = await service.bridgeBindChallenge(selectors, targetPeer);
      if (phase === 'lookup') {
        const bound = await service.verifyBridgeBinding({ ...selectors,
          proof: bridgeBindProof(key, challenge.nonce, context) }, targetPeer);
        digest = `sha256:${createHash('sha256').update(bound.bind_receipt).digest('hex')}`;
      }
    }
    await service.bridgeBindChallenge(other, otherPeer);
    gateArmed = true;
    const operation = phase === 'challenge' ? service.bridgeBindChallenge(selectors, targetPeer)
      : phase === 'bind' ? service.verifyBridgeBinding({ ...selectors,
        proof: bridgeBindProof(key, challenge.nonce, context) }, targetPeer)
        : service.boundBridge(selectors, digest);
    await entered.promise;
    await assert.rejects(service.forgetBridgeConnection(otherPeer.connection), /Machine stop unavailable/);
    assert.deepEqual(service.bridgeStatus(), { state: 'containment_unconfirmed' });
    gate.resolve();
    await assert.rejects(operation, denied, `${phase}: no authority after Machine uncertainty`);
    assert.ok(stopped.includes(selectors.start_id), `${phase}: authenticated target is contained`);
  }
});

test('close and HQ stop win over delayed B bind and live-receipt checks', async () => {
  for (const phase of ['bind', 'lookup']) for (const ending of ['close', 'stop']) {
    const entered = deferred();
    const gate = deferred();
    const stopped = [];
    let gateArmed = false;
    let sequence = 0;
    const service = createBridgeBindAdmission({
      authority: {
        verifyLiveStart: async () => {
          if (gateArmed) { entered.resolve(); await gate.promise; }
          return context;
        },
        onDisconnect: async (observation) => { stopped.push(observation.start_id); },
      },
      clock: { now: () => 1000 },
      random: { hex: () => (++sequence).toString(16).padStart(64, '0') },
      receipts: { append: async () => {} },
    });
    const challenge = await service.bridgeBindChallenge(selectors, connection);
    let digest;
    if (phase === 'lookup') {
      const bound = await service.verifyBridgeBinding({ ...selectors,
        proof: bridgeBindProof(key, challenge.nonce, context) }, connection);
      digest = `sha256:${createHash('sha256').update(bound.bind_receipt).digest('hex')}`;
    }
    gateArmed = true;
    const operation = phase === 'bind'
      ? service.verifyBridgeBinding({ ...selectors,
        proof: bridgeBindProof(key, challenge.nonce, context) }, connection)
      : service.boundBridge(selectors, digest);
    await entered.promise;
    const cleanup = ending === 'close'
      ? service.forgetBridgeConnection(connection.connection) : service.revokeAll();
    gate.resolve();
    await cleanup;
    await assert.rejects(operation, denied, `${ending} during ${phase} check`);
    assert.deepEqual(stopped, [selectors.start_id], `${ending} contains the start once`);
  }
});

test('changed plan, B UID, broker endpoint or key after challenge cannot bind', async () => {
  for (const changed of [
    { ...context, plan_digest: 'e'.repeat(64) },
    { ...context, bridge_uid: 303 },
    { ...context, broker_socket: '/private/var/run/agent-bot/other.sock' },
    { ...context, proof_key: Buffer.alloc(32, 0x42) },
  ]) {
    const f = fixture();
    const challenge = await f.service.bridgeBindChallenge(selectors, connection);
    f.setContext(changed);
    const proof = bridgeBindProof(key, challenge.nonce, context);
    await assert.rejects(f.service.verifyBridgeBinding({ ...selectors, proof }, connection), denied);
    assert.equal(await f.service.boundBridge(selectors, 'sha256:' + '0'.repeat(64)), null);
  }
});

test('wrong proof spends the challenge; expired challenge and connection-close race refuse', async () => {
  const wrong = fixture();
  const first = await wrong.service.bridgeBindChallenge(selectors, connection);
  await assert.rejects(wrong.service.verifyBridgeBinding({ ...selectors, proof: '0'.repeat(64) }, connection), denied);
  await assert.rejects(wrong.service.verifyBridgeBinding({ ...selectors,
    proof: bridgeBindProof(key, first.nonce, context) }, connection), denied);

  const expired = fixture();
  const challenge = await expired.service.bridgeBindChallenge(selectors, connection);
  expired.setNow(31_000);
  await assert.rejects(expired.service.verifyBridgeBinding({ ...selectors,
    proof: bridgeBindProof(key, challenge.nonce, context) }, connection), denied);

  const closed = fixture();
  closed.setContext(context);
  const pending = closed.service.bridgeBindChallenge(selectors, connection);
  // A pending authenticated Machine read may complete only after B has gone.
  // The real authority can delay; closing the connection must still win.
  closed.service.forgetBridgeConnection(connection.connection);
  await assert.rejects(pending, denied);
});

test('close before Comms receives a minted receipt revokes it and contains once', async () => {
  const f = fixture();
  const { digest } = await f.bind();
  await f.service.forgetBridgeConnection(connection.connection, undefined);
  assert.equal(await f.service.boundBridge(selectors, digest), null);
  assert.equal(f.stops.length, 1);
  await f.service.forgetBridgeConnection(connection.connection, '0'.repeat(64));
  assert.equal(f.stops.length, 1);
});

test('a revoked Machine start after B binds cannot pass a pre-ACP live receipt lookup', async () => {
  for (const changed of [null, { ...context, bridge_uid: 303 },
    { ...context, broker_socket: '/private/var/run/agent-bot/other.sock' }]) {
    const f = fixture();
    const { digest } = await f.bind();
    f.setContext(changed);
    await assert.rejects(f.service.boundBridge(selectors, digest), denied);
    assert.equal(await f.service.boundBridge(selectors, digest), null);
    assert.equal(f.stops.length, 1, 'stale authority requests containment once');
  }
});

test('failed or abandoned authenticated B challenge quarantines R before it can attach', async () => {
  for (const failure of ['wrong-proof', 'malformed-proof', 'closed-before-bind']) {
    const f = fixture();
    await f.service.bridgeBindChallenge(selectors, connection);
    if (failure === 'closed-before-bind') await f.service.forgetBridgeConnection(connection.connection);
    else await assert.rejects(f.service.verifyBridgeBinding({ ...selectors,
      proof: failure === 'wrong-proof' ? '0'.repeat(64) : 'not-a-proof' }, connection), denied);
    assert.equal(f.stops.length, 1, `${failure}: authenticated pending start must stop`);
    assert.equal(f.stops[0].bind_receipt_sha256, undefined);
    await assert.rejects(f.service.bridgeBindChallenge(selectors, { connection: 'bc_2' }), denied);
    assert.equal(f.stops.length, 1, 'repeat close or bind refusal does not duplicate quarantine');
  }
});

test('unauthenticated bridge frames cannot choose a Machine stop target', async () => {
  const f = fixture();
  await assert.rejects(f.service.bridgeBindChallenge({ ...selectors, plan_digest: 'wrong' }, connection), denied);
  await assert.rejects(f.service.verifyBridgeBinding({ ...selectors, proof: '0'.repeat(64) }, connection), denied);
  assert.equal(f.stops.length, 0);
});

test('a silent B is quarantined when its authenticated challenge expires', async () => {
  const scheduled = new Map();
  let next = 0;
  const f = fixture({ timers: {
    setTimeout: (fn, delay) => { const id = ++next; scheduled.set(id, { fn, delay }); return id; },
    clearTimeout: (id) => scheduled.delete(id),
  } });
  await f.service.bridgeBindChallenge(selectors, connection);
  const timeout = [...scheduled.values()][0];
  assert.equal(timeout.delay, 30_000);
  f.setNow(31_000);
  timeout.fn();
  await new Promise((resolve) => setImmediate(resolve));
  assert.equal(f.stops.length, 1);
  await assert.rejects(f.service.verifyBridgeBinding({ ...selectors, proof: '0'.repeat(64) }, connection), denied);
  await assert.rejects(f.service.bridgeBindChallenge(selectors, { connection: 'bc_2' }), denied);
});

test('close or HQ stop during expired-start cleanup cannot resurrect a new B challenge', async () => {
  for (const ending of ['close', 'stop']) {
    const newer = { ...selectors, start_id: `st_${'f'.repeat(24)}` };
    const contexts = new Map([[selectors.start_id, context],
      [newer.start_id, { ...context, ...newer }]]);
    const stopped = [];
    let now = 1_000;
    let releaseOld;
    let sequence = 0;
    const service = createBridgeBindAdmission({
      authority: {
        verifyLiveStart: async (input) => contexts.get(input.start_id),
        onDisconnect: (observation) => {
          stopped.push(observation.start_id);
          if (observation.start_id === selectors.start_id)
            return new Promise((resolve) => { releaseOld = resolve; });
        },
      },
      clock: { now: () => now },
      random: { hex: () => (++sequence).toString(16).padStart(64, '0') },
      receipts: { append: async () => {} },
    });
    await service.bridgeBindChallenge(selectors, { connection: 'bc_old' });
    now = 31_000;
    const pending = service.bridgeBindChallenge(newer, { connection: 'bc_new' });
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(typeof releaseOld, 'function');
    const cleanup = ending === 'close'
      ? service.forgetBridgeConnection('bc_new') : service.revokeAll();
    releaseOld();
    await cleanup;
    await assert.rejects(pending, denied);
    assert.deepEqual(stopped.sort(), [selectors.start_id, newer.start_id].sort());
    await assert.rejects(service.bridgeBindChallenge(newer, { connection: 'bc_retry' }), denied);
  }
});

test('stop revokes live B receipts and requests containment once', async () => {
  const f = fixture();
  const { digest } = await f.bind();
  await f.service.revokeAll();
  await assert.rejects(f.service.boundBridge(selectors, digest), denied);
  assert.equal(f.stops.length, 1);
  await f.service.revokeAll();
  assert.equal(f.stops.length, 1);
});

test('uncertain Machine containment stays a failed HQ stop, never a successful cleanup', async () => {
  let calls = 0;
  const alerts = [];
  const service = createBridgeBindAdmission({
    authority: {
      verifyLiveStart: async () => context,
      onDisconnect: () => { calls += 1; throw new Error('containment unconfirmed'); },
    },
    clock: { now: () => 1000 },
    random: { hex: () => 'f'.repeat(64) },
    receipts: { append: async (record) => { alerts.push(record); } },
  });
  await service.bridgeBindChallenge(selectors, connection);
  await assert.rejects(service.forgetBridgeConnection(connection.connection), /containment unconfirmed/);
  assert.deepEqual(service.bridgeStatus(), { state: 'containment_unconfirmed' });
  assert.equal(alerts[0].kind, 'hq.bridge.containment_unconfirmed');
  assert.equal(alerts[0].start_id, selectors.start_id);
  await assert.rejects(service.revokeAll(), /containment unconfirmed/);
  assert.equal(calls, 1, 'uncertain cleanup is retained and cannot be retried as a fresh bind');
});

test('silent-B timer failure raises a live degraded signal and durable HQ alert', async () => {
  const scheduled = [];
  const alerts = [];
  const service = createBridgeBindAdmission({
    authority: {
      verifyLiveStart: async () => context,
      onDisconnect: async () => { throw new Error('Machine stop unavailable'); },
    },
    clock: { now: () => 1000 },
    random: { hex: () => 'f'.repeat(64) },
    receipts: { append: async (record) => { alerts.push(record); } },
    timers: { setTimeout: (fn) => { scheduled.push(fn); return scheduled.length; }, clearTimeout: () => {} },
  });
  await service.bridgeBindChallenge(selectors, connection);
  scheduled[0]();
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(service.bridgeStatus(), { state: 'containment_unconfirmed' });
  assert.equal(alerts[0].kind, 'hq.bridge.containment_unconfirmed');
  await assert.rejects(service.bridgeBindChallenge(selectors, { connection: 'bc_new' }), denied);
  await assert.rejects(service.revokeAll(), /Machine stop unavailable/);
});

test('a hung Machine stop reaches a bounded degraded alert without a successful close', async () => {
  const scheduled = [];
  const alerts = [];
  const service = createBridgeBindAdmission({
    authority: {
      verifyLiveStart: async () => context,
      onDisconnect: () => new Promise(() => {}),
    },
    clock: { now: () => 1000 },
    random: { hex: () => 'f'.repeat(64) },
    receipts: { append: async (record) => { alerts.push(record); } },
    timers: { setTimeout: (fn, delay) => { scheduled.push({ fn, delay }); return scheduled.length; },
      clearTimeout: () => {} },
  });
  await service.bridgeBindChallenge(selectors, connection);
  const close = service.forgetBridgeConnection(connection.connection);
  assert.equal(scheduled.find((timer) => timer.delay === 5000) !== undefined, true);
  scheduled.find((timer) => timer.delay === 5000).fn();
  await assert.rejects(close, /containment deadline exceeded/);
  assert.deepEqual(service.bridgeStatus(), { state: 'containment_unconfirmed' });
  assert.equal(alerts[0].kind, 'hq.bridge.containment_unconfirmed');
});

test('a hung HQ alert write leaves bridge degraded and fails cleanup by deadline', async () => {
  const scheduled = new Map();
  let nextTimer = 0;
  const service = createBridgeBindAdmission({
    authority: { verifyLiveStart: async () => context,
      onDisconnect: () => { throw new Error('Machine stop unavailable'); } },
    clock: { now: () => 1000 }, random: { hex: () => 'f'.repeat(64) },
    receipts: { append: () => new Promise(() => {}) },
    timers: { setTimeout: (fn, delay) => { const id = ++nextTimer; scheduled.set(id, { fn, delay }); return id; },
      clearTimeout: (id) => scheduled.delete(id) },
  });
  await service.bridgeBindChallenge(selectors, connection);
  const closing = service.forgetBridgeConnection(connection.connection);
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(service.bridgeStatus(), { state: 'containment_unconfirmed' });
  const alertTimer = [...scheduled.values()].find((timer) => timer.delay === 5000);
  assert.ok(alertTimer, 'alert persistence has its own deadline');
  alertTimer.fn();
  await assert.rejects(closing, /bridge containment and alert persistence failed/);
  await assert.rejects(service.revokeAll(), /bridge containment and alert persistence failed/);
});

test('a hung live-start verifier and immediate containment failure both reach HQ shutdown', async () => {
  const scheduled = new Map();
  let nextTimer = 0;
  const alerts = [];
  let calls = 0;
  const service = createBridgeBindAdmission({
    authority: { verifyLiveStart: async () => {
      if (++calls === 1) return context;
      return new Promise(() => {});
    }, onDisconnect: async () => { throw new Error('Machine stop unavailable'); } },
    clock: { now: () => 1000 }, random: { hex: () => 'f'.repeat(64) },
    receipts: { append: async (record) => { alerts.push(record); } },
    timers: { setTimeout: (fn, delay) => { const id = ++nextTimer; scheduled.set(id, { fn, delay }); return id; },
      clearTimeout: (id) => scheduled.delete(id) },
  });
  await service.bridgeBindChallenge(selectors, connection);
  const newer = { ...selectors, start_id: `st_${'e'.repeat(24)}` };
  void service.bridgeBindChallenge(newer, { connection: 'bc_new' });
  await new Promise((resolve) => setImmediate(resolve));
  const stopping = service.revokeAll();
  const drainTimer = [...scheduled.values()].filter((timer) => timer.delay === 5000).at(-1);
  assert.ok(drainTimer, 'active verifier drain has a deadline');
  drainTimer.fn();
  await assert.rejects(stopping, (error) => {
    assert.match(error.message, /verifier drain deadline exceeded/);
    assert.ok(error.errors.some((cause) => /Machine stop unavailable/.test(cause.message)));
    return true;
  });
  assert.deepEqual(service.bridgeStatus(), { state: 'containment_unconfirmed' });
  assert.ok(alerts.some((alert) => alert.reason === 'bridge-verifier-drain-timeout'));
});
