import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { test } from 'node:test';
import { setImmediate } from 'node:timers/promises';
import { MAX_LINE_BYTES } from '../hq/socket.mjs';
import { MODEL_CATALOG, RESPONSES } from '../sdk/broker-stream.mjs';
import { fail } from '../sdk/errors.mjs';
import { connectHq } from '../sdk/local-socket-client.mjs';
import { bindProof } from '../sdk/member-session.mjs';
import { definePlugin } from '../sdk/plugin.mjs';
import { revokeDevice } from '../sdk/services.mjs';
import { referenceBroker } from './broker-fixture.mjs';
import { hello, startHQ } from './hq-harness.mjs';
import { contracts } from './support/member-client-contracts.mjs';

function deferred() {
  let resolve;
  const promise = new Promise((res) => { resolve = res; });
  return { promise, resolve };
}

const delta = (text) => ({ type: 'response.output_text.delta', delta: text });
const terminal = { usage: { input_tokens: 1, output_tokens: 2 }, actualCost: 0.25 };
const code = (want) => (error) => error.code === want;

async function setup(produce, home, beforeAuthorize) {
  const grants = new Map();
  const consumer = definePlugin({
    name: 'fixture-inference',
    version: '0.1.0',
    hostApi: 1,
    requires: { 'hq-admission': '^0.1.0' },
    services: ['budgets', 'store'],
    async init(ctx) {
      const authorize = (payload, { runtime_id }) => ctx.deps['hq-admission'].withBoundRuntime(runtime_id, (rt) => {
        const grant = grants.get(runtime_id);
        if (!grant || !rt.handle || rt.handle !== payload.handle || grant.destination !== payload.destination
          || grant.task_id !== payload.task_id || (payload.model && !grant.models.includes(payload.model))) {
          fail('credential_unavailable', 'no approved fixture provider operation');
        }
        return { ...grant, soul: rt.soul_id };
      });
      ctx.broker.registerInference({
        async authorize(payload, caller, signal) {
          if (beforeAuthorize) await beforeAuthorize(signal);
          return authorize(payload, caller);
        },
        catalog: (_request, grant) => ({ models: grant.models }),
        responses: (_request, _grant, signal) => produce(signal),
      });
    },
  });
  const t = await startHQ({ home, plugins: [referenceBroker(), ...(produce ? [consumer] : [])] });
  const entry = await t.entry();
  const { result: admission } = await entry.request('Hello', hello(home ? { request_id: 'req_after_restart' } : {}));
  const runtime = admission.admitted_runtimes[0];
  const { result: equip } = await entry.request('Equip', { runtime_id: runtime.runtime_id });
  assert.deepEqual(equip.approved_destinations, []);
  assert.deepEqual(equip.credential_references, []);
  const clients = [];
  async function openClient() {
    const controller = new AbortController();
    const client = await connectHq(t.hq.paths.broker, { contracts, signal: controller.signal });
    clients.push(client);
    return {
      client,
      abort() { controller.abort(new Error('member cancelled')); },
      async bind() {
        const challenge = await client.request('bind.challenge', { runtime_id: runtime.runtime_id });
        const proof = bindProof(runtime.channel_binding, challenge.nonce, runtime.runtime_id);
        const response = await client.request('bind', { runtime_id: runtime.runtime_id, proof });
        assert.equal(response.runtime_id, runtime.runtime_id);
      },
    };
  }
  const scope = { handle: equip.grant_handles[0].handle, destination: 'fixture-provider', task_id: 'task_fixture', operation_id: 'op_fixture' };
  const request = { ...scope, model: 'fixture-codex', input: 'two deltas' };
  return {
    ...await openClient(), scope, request, home: t.home, openClient,
    revoke() { revokeDevice(t.hq.core); },
    revocationHooks() { return t.hq.core.onDeviceRevoked.length; },
    approve(amount) {
      t.hq.core.budgets.set(hello().soul_id, { ceilings: { working: amount }, reserved: new Map() });
      grants.set(runtime.runtime_id, { destination: scope.destination, task_id: scope.task_id, models: [request.model], maxCost: 1 });
    },
    reservations() { return [...t.hq.core.budgets.get(hello().soul_id).reserved.values()]; },
    records() {
      const stored = JSON.parse(readFileSync(join(t.home, 'store.json'), 'utf8'));
      const table = stored.tables.find(([name]) => name === 'fixture-inference\0inference_operations');
      return table?.[1].map(([, record]) => record) ?? [];
    },
    async close(options) { for (const client of clients) client.destroy(); await t.done(options); },
  };
}

test('the member socket has no inference operations without a registered provider', { timeout: 5000 }, async () => {
  const t = await setup();
  try {
    await t.bind();
    await assert.rejects(t.client.request(MODEL_CATALOG, t.scope), code('host.unknown_kind'));
    await assert.rejects(t.client.requestResponses(t.request, () => {}), code('host.unknown_kind'));
    assert.deepEqual(t.records(), []);
  } finally { await t.close(); }
});

test('repeated aborted authorization disposes the device hooks for both registered operations', { timeout: 5000 }, async () => {
  let started;
  let block = true;
  const hung = new Promise(() => {});
  const t = await setup(async function* () { assert.fail('producer should not open'); }, undefined, (signal) => {
    if (!block) return;
    started.resolve(signal);
    return hung;
  });
  try {
    t.approve(1);
    const baseline = t.revocationHooks();
    for (const kind of [MODEL_CATALOG, RESPONSES, MODEL_CATALOG, RESPONSES]) {
      const attempt = await t.openClient();
      await attempt.bind();
      started = deferred();
      const reply = kind === MODEL_CATALOG ? attempt.client.request(kind, t.scope) : attempt.client.requestResponses(t.request, () => {});
      const signal = await Promise.race([started.promise, reply]);
      assert.equal(t.revocationHooks(), baseline + 1);
      const aborted = deferred();
      signal.addEventListener('abort', aborted.resolve, { once: true });
      attempt.abort();
      await assert.rejects(reply, /member cancelled/);
      await aborted.promise;
      await setImmediate();
      assert.equal(t.revocationHooks(), baseline);
    }
    assert.deepEqual(t.records(), []);
    assert.deepEqual(t.reservations(), []);
    block = false;
    await t.bind();
    assert.deepEqual(await t.client.request(MODEL_CATALOG, t.scope), { models: ['fixture-codex'] });
    assert.equal(t.revocationHooks(), baseline);
  } finally { await t.close(); }
});

test('typed member client enforces binding and live scope, delivers incremental output and settles measured usage', { timeout: 5000 }, async () => {
  const gate = deferred();
  const first = deferred();
  let opened = 0;
  const t = await setup(async function* () {
    opened++;
    yield delta('one');
    await gate.promise;
    yield delta('two');
    return terminal;
  });
  try {
    await assert.rejects(t.client.requestResponses(t.request, () => {}), code('caller_mismatch'));
    await t.bind();
    await assert.rejects(t.client.request(MODEL_CATALOG, t.scope), code('credential_unavailable'));
    await assert.rejects(t.client.requestResponses(t.request, () => {}), code('credential_unavailable'));
    assert.equal(opened, 0);
    assert.deepEqual(t.records(), []);
    t.approve(1);
    await assert.rejects(t.client.request(MODEL_CATALOG, { ...t.scope, destination: 'other-provider' }), code('credential_unavailable'));
    await assert.rejects(t.client.requestResponses({ ...t.request, task_id: 'other_task' }, () => {}), code('credential_unavailable'));
    await assert.rejects(t.client.requestResponses({ ...t.request, upstream: 'injected-url' }, () => {}), /invalid inference/);
    assert.deepEqual(await t.client.request(MODEL_CATALOG, t.scope), { models: ['fixture-codex'] });
    await assert.rejects(t.client.request(RESPONSES, t.request), /chunk handler/);
    const chunks = [];
    const response = t.client.requestResponses(t.request, (event) => {
      chunks.push(event);
      if (chunks.length === 1) first.resolve();
    });
    await Promise.race([first.promise, response]);
    assert.deepEqual(chunks, [delta('one')]);
    assert.equal(t.records()[0].outcome, 'outcome_unknown');
    gate.resolve();
    assert.deepEqual(await response, { usage: terminal.usage });
    assert.deepEqual(chunks, [delta('one'), delta('two')]);
    assert.equal(t.records()[0].outcome, 'completed');
    assert.equal(t.records()[0].actual_cost, terminal.actualCost);
    assert.equal(t.reservations()[0].amount, terminal.actualCost);
    assert.equal(t.reservations()[0].settled, true);
    await assert.rejects(t.client.requestResponses({ ...t.request, operation_id: 'unfunded_op' }, () => {}), code('budget_exhausted'));
    assert.equal(opened, 1);
  } finally {
    gate.resolve();
    await t.close();
  }
});

test('oversized data leaves its operation unknown and retains the reservation', { timeout: 5000 }, async () => {
  const t = await setup(async function* () { yield delta('x'.repeat(MAX_LINE_BYTES)); return terminal; });
  try {
    await t.bind();
    t.approve(2);
    await assert.rejects(t.client.requestResponses(t.request, () => {}), /byte limit/);
    assert.equal(t.records()[0].outcome, 'outcome_unknown');
    assert.equal(t.reservations()[0].amount, 1);
    await assert.rejects(t.client.requestResponses(t.request, () => {}), /reconcile before retrying/);
  } finally { await t.close(); }
});

test('restart preserves uncertainty and refuses to redispatch the same operation', { timeout: 5000 }, async () => {
  const t = await setup(async function* () { yield delta('x'.repeat(MAX_LINE_BYTES)); return terminal; });
  try {
    await t.bind();
    t.approve(2);
    await assert.rejects(t.client.requestResponses(t.request, () => {}), /byte limit/);
  } finally { await t.close({ keep: true }); }
  let opened = 0;
  const restart = await setup(async function* () { opened++; return terminal; }, t.home);
  try {
    await restart.bind();
    restart.approve(2);
    assert.equal(restart.records()[0].outcome, 'outcome_unknown');
    await assert.rejects(restart.client.requestResponses(restart.request, () => {}), /reconcile before retrying/);
    assert.equal(opened, 0);
  } finally { await restart.close(); }
});

test('client abort destroys active producer I/O and preserves the unknown operation', { timeout: 5000 }, async () => {
  const io = new PassThrough();
  const destroyed = deferred();
  io.on('close', destroyed.resolve);
  const t = await setup(async function* (signal) {
    const cancel = () => io.destroy();
    signal.addEventListener('abort', cancel, { once: true });
    try {
      yield delta('started');
      for await (const chunk of io) yield delta(chunk.toString());
      return terminal;
    } finally { signal.removeEventListener('abort', cancel); }
  });
  try {
    await t.bind();
    t.approve(1);
    await assert.rejects(t.client.requestResponses(t.request, () => t.abort()), /member cancelled/);
    await destroyed.promise;
    assert.equal(io.destroyed, true);
    assert.equal(t.records()[0].outcome, 'outcome_unknown');
    assert.equal(t.reservations()[0].settled, undefined);
  } finally { await t.close(); }
});

test('device revocation returns a refusal and records uncertainty even when a producer ignores abort', { timeout: 5000 }, async () => {
  const entered = deferred();
  const blocked = deferred();
  const t = await setup(async function* () {
    yield delta('started');
    entered.resolve();
    await blocked.promise;
    return terminal;
  });
  try {
    await t.bind();
    t.approve(1);
    const response = t.client.requestResponses(t.request, () => {});
    await Promise.race([entered.promise, response]);
    t.revoke();
    await assert.rejects(response, code('credential_unavailable'));
    assert.equal(t.records()[0].outcome, 'outcome_unknown');
    assert.equal(t.reservations()[0].settled, undefined);
    await assert.rejects(t.client.request(MODEL_CATALOG, t.scope), code('credential_unavailable'));
  } finally {
    blocked.resolve();
    await t.close();
  }
});
