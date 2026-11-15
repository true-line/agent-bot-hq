import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createMemberQueryPort, checkMemberQueryPort } from '../sdk/index.mjs';

const pair = (generation, request = async (_kind, message) => message, epoch = 2) => Object.freeze({
  freshness: Object.freeze({ installation_epoch: epoch, lease_generation: generation }), request,
});
const driver = (extra = {}) => ({ capture: () => pair(1), reconnect: () => pair(2), isRetryableReadFailure: () => true, ...extra });

test('member query port satisfies the portable semantic checks', async () => {
  const report = await checkMemberQueryPort();
  assert.equal(report.ok, true, JSON.stringify(report.results.filter((result) => !result.ok)));
  assert.equal(report.results.length, 5);
});

test('conformance detects an implementation that silently enables default replay', async () => {
  const report = await checkMemberQueryPort((source) => {
    const port = createMemberQueryPort(source);
    return Object.freeze({ request: (kind, build, options = { replay: 'read-once' }) => port.request(kind, build, options) });
  });
  assert.equal(report.ok, false);
  assert.ok(report.results.some((result) => result.check.startsWith('default and refused') && !result.ok));
});

test('driver and request arguments refuse before any capture or send', async () => {
  for (const bad of [undefined, {}, { capture() {} }, []]) assert.throws(() => createMemberQueryPort(bad), TypeError);
  let captures = 0;
  const port = createMemberQueryPort(driver({ capture: () => { captures++; return pair(1); } }));
  for (const [kind, build, options] of [
    ['notices.peek\n', () => ({})], ['', () => ({})], ['notices.peek', {}],
    ['notices.peek', () => ({}), { replay: 'always' }], ['notices.peek', () => ({}), { recover: true }],
    ['notices.peek', () => ({}), { replay: null }],
    ['notices.peek', () => ({}), null],
  ]) await assert.rejects(port.request(kind, build, options), TypeError);
  assert.equal(captures, 0);
});

test('inherited replay policy cannot opt an omitted policy into recovery', async () => {
  const previous = Object.getOwnPropertyDescriptor(Object.prototype, 'replay');
  Object.defineProperty(Object.prototype, 'replay', { value: 'read-once', configurable: true });
  try {
    for (const options of [undefined, {}, Object.create(null), { replay: 'never' }, { replay: 'read-once' }]) {
      const failure = new Error('lost read response');
      let sends = 0;
      let classifications = 0;
      let reconnects = 0;
      const port = createMemberQueryPort(driver({
        capture: () => pair(1, () => { sends++; throw failure; }),
        isRetryableReadFailure: () => { classifications++; return true; },
        reconnect: () => { reconnects++; return pair(2, () => { sends++; return 'recovered'; }); },
      }));
      if (options && Object.hasOwn(options, 'replay') && options.replay === 'read-once') {
        assert.equal(await port.request('notices.peek', () => ({}), options), 'recovered');
        assert.deepEqual([sends, classifications, reconnects], [2, 1, 1]);
      } else {
        await assert.rejects(port.request('notices.peek', () => ({}), options), (error) => error === failure);
        assert.deepEqual([sends, classifications, reconnects], [1, 0, 0]);
      }
    }
  } finally {
    if (previous) Object.defineProperty(Object.prototype, 'replay', previous);
    else delete Object.prototype.replay;
  }
});

test('mutable, malformed and invalid replacement captures refuse without sending', async () => {
  let sends = 0;
  const request = () => { sends++; };
  const badCaptures = [null, {}, { ...pair(1, request) }, Object.freeze({ freshness: { installation_epoch: 2, lease_generation: 1 }, request }),
    Object.freeze({ freshness: Object.freeze({ installation_epoch: 0, lease_generation: 1 }), request }),
    Object.freeze({ freshness: Object.freeze({ installation_epoch: 2, lease_generation: Number.MAX_SAFE_INTEGER + 1 }), request })];
  for (const captured of badCaptures) await assert.rejects(createMemberQueryPort(driver({ capture: () => captured })).request('notices.peek', () => ({})), TypeError);
  assert.equal(sends, 0);
  const failure = new Error('lost reply');
  const port = createMemberQueryPort(driver({ capture: () => pair(1, () => { sends++; throw failure; }), reconnect: () => badCaptures[2] }));
  await assert.rejects(port.request('notices.peek', () => ({}), { replay: 'read-once' }), TypeError);
  assert.equal(sends, 1);
});

test('validated read recovery uses replacement epoch/generation and reconstructs the payload', async () => {
  for (const code of ['transport', 'lease_expired', 'stale_epoch']) {
    const failure = { code };
    const seen = [];
    let builds = 0;
    const old = pair(3, (_kind, payload) => { seen.push(payload); throw failure; });
    const next = pair(1, (_kind, payload) => { seen.push(payload); return payload; }, 4);
    const port = createMemberQueryPort(driver({
      capture: () => old,
      isRetryableReadFailure: (error, captured) => { assert.equal(error, failure); assert.equal(captured, old); return true; },
      reconnect: (captured, error) => { assert.equal(captured, old); assert.equal(error, failure); return next; },
    }));
    const result = await port.request('notices.peek', (freshness) => ({ ...freshness, request_id: `query:${++builds}` }), { replay: 'read-once' });
    assert.deepEqual(seen, [
      { installation_epoch: 2, lease_generation: 3, request_id: 'query:1' },
      { installation_epoch: 4, lease_generation: 1, request_id: 'query:2' },
    ]);
    assert.deepEqual(result, seen[1]);
  }
});

test('overlapping attempts preserve captured connection/freshness and reuse newer binding on reconnect', async () => {
  let rejectOld;
  let started;
  const entered = new Promise((resolve) => { started = resolve; });
  const old = pair(1, (_kind, payload) => {
    assert.equal(payload.lease_generation, 1);
    started();
    return new Promise((_resolve, reject) => { rejectOld = reject; });
  });
  const calls = [];
  const newer = pair(2, (kind, payload) => { calls.push([kind, payload]); return payload; });
  let current = old;
  const port = createMemberQueryPort(driver({
    capture: () => current,
    reconnect: (previous) => { assert.equal(previous, old); assert.equal(current, newer); return current; },
  }));
  const waiting = port.request('notices.peek', (freshness) => ({ ...freshness }), { replay: 'read-once' });
  await entered;
  current = newer;
  const other = await port.request('notices.consume-one', (freshness) => ({ ...freshness }));
  rejectOld(new Error('old socket closed'));
  const recovered = await waiting;
  assert.equal(other.lease_generation, 2);
  assert.equal(recovered.lease_generation, 2);
  assert.deepEqual(calls.map(([kind]) => kind), ['notices.consume-one', 'notices.peek']);
});

test('failed or asynchronous classifier does not retry or mask the original failure', async () => {
  const failure = new Error('original transport outcome');
  for (const classifier of [() => false, () => { throw new Error('classifier failed'); }, async () => true, async () => { throw new Error('async classifier failed'); }]) {
    let reconnects = 0;
    const port = createMemberQueryPort(driver({ capture: () => pair(1, () => { throw failure; }), isRetryableReadFailure: classifier, reconnect: () => { reconnects++; } }));
    await assert.rejects(port.request('notices.peek', () => ({}), { replay: 'read-once' }), (error) => error === failure);
    assert.equal(reconnects, 0);
  }
});

test('capture/reconnect failures and async builder rejection never trigger another attempt', async () => {
  const failure = new Error('capture failed');
  let builds = 0;
  const failing = createMemberQueryPort(driver({ capture: () => { throw failure; } }));
  await assert.rejects(failing.request('notices.peek', () => { builds++; return {}; }, { replay: 'read-once' }), (error) => error === failure);
  assert.equal(builds, 0);
  let sends = 0;
  const port = createMemberQueryPort(driver({ capture: () => pair(1, () => { sends++; throw new Error('lost'); }), reconnect: () => { throw failure; } }));
  await assert.rejects(port.request('notices.peek', () => ({}), { replay: 'read-once' }), (error) => error === failure);
  await assert.rejects(port.request('notices.peek', async () => { throw new Error('builder rejected'); }, { replay: 'read-once' }), /must be synchronous/);
  assert.equal(sends, 1);
});
