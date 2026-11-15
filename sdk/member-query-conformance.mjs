// Portable SDK-port checks with an instrumented private transport driver.
// This checks port semantics, not a real provider's authentication/capture.
import assert from 'node:assert/strict';
import { createMemberQueryPort } from './member-query.mjs';

export async function checkMemberQueryPort(createPort = createMemberQueryPort) {
  const results = [];
  const check = async (name, fn) => {
    try { await fn(); results.push({ check: name, ok: true }); }
    catch (error) { results.push({ check: name, ok: false, error: error.message }); }
  };
  const setup = (failures = []) => {
    const calls = [];
    let reconnects = 0;
    let classifications = 0;
    const pair = (generation) => Object.freeze({
      freshness: Object.freeze({ installation_epoch: 7, lease_generation: generation, private_key: 'private-test-marker' }),
      secret: 'private-test-marker',
      async request(kind, payload) {
        calls.push({ generation, kind, payload });
        if (failures.length) throw failures.shift();
        return { generation, payload };
      },
    });
    let current = pair(1);
    const driver = {
      capture: async () => current,
      reconnect: async (previous) => { reconnects++; if (current === previous) current = pair(2); return current; },
      isRetryableReadFailure: (error) => { classifications++; return error.validated === true && ['transport', 'lease_expired', 'stale_epoch'].includes(error.code); },
    };
    return { port: createPort(driver), calls, rotate: () => { current = pair(2); }, reconnects: () => reconnects, classifications: () => classifications };
  };
  await check('private captured pair survives rebind during payload construction', async () => {
    const t = setup();
    assert.deepEqual(Reflect.ownKeys(t.port), ['request']);
    assert.equal(Object.isFrozen(t.port), true);
    const result = await t.port.request('notices.peek', (freshness) => {
      assert.deepEqual(freshness, { installation_epoch: 7, lease_generation: 1 });
      assert.equal(Object.isFrozen(freshness), true);
      t.rotate();
      return { ...freshness };
    });
    assert.equal(result.generation, 1);
    assert.equal(t.calls[0].payload.lease_generation, t.calls[0].generation);
    assert.equal(JSON.stringify(result).includes('private-test-marker'), false);
  });
  await check('opt-in read recovery rebuilds freshness and stops after one replay', async () => {
    for (const kind of ['task.get', 'task.directives', 'notices.peek']) {
      const first = { code: 'transport', validated: true };
      const second = { code: 'lease_expired', validated: true };
      const t = setup([first, second]);
      await assert.rejects(t.port.request(kind, (freshness) => ({ ...freshness }), { replay: 'read-once' }), (error) => error === second);
      assert.deepEqual(t.calls.map((call) => call.payload.lease_generation), [1, 2]);
      assert.deepEqual(t.calls.map((call) => call.generation), [1, 2]);
      assert.equal(t.reconnects(), 1);
      assert.equal(t.classifications(), 1);
    }
  });
  await check('destructive and unknown kinds never classify or replay lost replies', async () => {
    for (const kind of ['notices.consume-one', 'task.commit', 'future.read']) {
      const failure = { code: 'transport', validated: true };
      const t = setup([failure]);
      await assert.rejects(t.port.request(kind, (freshness) => ({ ...freshness }), { replay: 'read-once' }), (error) => error === failure);
      assert.equal(t.calls.length, 1);
      assert.equal(t.reconnects(), 0);
      assert.equal(t.classifications(), 0);
    }
  });
  await check('default and refused reads preserve original failure without reconnect', async () => {
    for (const [failure, options] of [
      [{ code: 'transport', validated: true }, undefined],
      [{ code: 'transport' }, { replay: 'read-once' }],
      [{ code: 'caller_mismatch', validated: true }, { replay: 'read-once' }],
    ]) {
      const t = setup([failure]);
      await assert.rejects(t.port.request('notices.peek', () => ({}), options), (error) => error === failure);
      assert.equal(t.calls.length, 1);
      assert.equal(t.reconnects(), 0);
    }
  });
  await check('builder failures never send or reconnect', async () => {
    for (const build of [() => { throw new Error('builder failed'); }, async () => ({}), () => null]) {
      const t = setup();
      await assert.rejects(t.port.request('notices.peek', build, { replay: 'read-once' }));
      assert.equal(t.calls.length, 0);
      assert.equal(t.reconnects(), 0);
    }
  });
  return { ok: results.every((result) => result.ok), results };
}
