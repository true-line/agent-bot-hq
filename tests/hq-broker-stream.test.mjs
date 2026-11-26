import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { mkdirSync, readFileSync, rmdirSync } from 'node:fs';
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

async function setup(produce, home, beforeAuthorize, { enableFixture = true } = {}) {
  const grants = new Map();
  let budgets;
  let receipts;
  const consumer = definePlugin({
    name: 'fixture-inference',
    version: '0.1.0',
    hostApi: 1,
    requires: { 'hq-admission': '^0.1.0' },
    services: ['budgets', 'store', 'receipts'],
    async init(ctx) {
      budgets = ctx.services.budgets;
      receipts = ctx.services.receipts;
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
        responses: (request, _grant, signal) => produce(signal, request),
      });
    },
  });
  const t = await startHQ({
    home,
    plugins: [referenceBroker(), ...(produce ? [consumer] : [])],
    draftInferenceFixture: produce && enableFixture ? consumer : undefined,
  });
  const entry = await t.entry();
  const { result: admission } = await entry.request('Hello', hello(home ? { request_id: `req_${randomUUID()}` } : {}));
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
  const soul = hello().soul_id;
  const budgetTable = '@hq\0inference_budget';
  return {
    ...await openClient(), scope, request, home: t.home, openClient,
    revoke() { revokeDevice(t.hq.core); },
    revocationHooks() { return t.hq.core.onDeviceRevoked.length; },
    approve(amount) {
      t.hq.core.budgets.set(soul, { ceilings: { working: amount, maintenance: amount } });
      grants.set(runtime.runtime_id, { destination: scope.destination, task_id: scope.task_id, models: [request.model], maxCost: 1 });
    },
    remaining: (pool) => budgets.remaining({ soul, pool }),
    reserveUnary: (amount, pool) => budgets.reserve({ soul, amount, pool }),
    releaseUnary: (reservation) => budgets.release(reservation),
    settleUnary: (reservation, cost) => budgets.settle(reservation, cost),
    records() {
      const stored = JSON.parse(readFileSync(join(t.home, 'store.json'), 'utf8'));
      const table = stored.tables.find(([name]) => name === budgetTable);
      return table?.[1].map(([, record]) => record) ?? [];
    },
    appendMarker: () => receipts.append({ kind: 'fixture.audit_marker' }),
    markers: () => t.hq.core.receipts.filter(({ kind }) => kind === 'fixture.audit_marker'),
    failNextWrite(outcome) {
      const core = t.hq.core;
      const persist = core.persistPluginWrite;
      core.persistPluginWrite = (change) => persist((context) => {
        const previous = core.tables.get(budgetTable);
        const rollback = change(context);
        const updated = core.tables.get(budgetTable);
        if (updated !== previous && [...(updated?.values() ?? [])].some((record) => record.outcome === outcome)) {
          core.persistPluginWrite = persist;
          rollback();
          throw new Error('injected budget store failure');
        }
        return rollback;
      });
    },
    failUnaryWriteAfterUnrelatedPersist() {
      const core = t.hq.core;
      const persist = core.persistPluginWrite;
      core.persistPluginWrite = async (change) => {
        core.persistPluginWrite = persist;
        await core.persist(); // An independent snapshot must exclude staged budget rows.
        return persist((context) => {
          const rollback = change(context);
          rollback();
          throw new Error('injected unary budget store failure');
        });
      };
    },
    holdNextInferenceWrite(outcome) {
      const written = deferred();
      const release = deferred();
      const core = t.hq.core;
      const persist = core.persistPluginWrite;
      core.persistPluginWrite = async (change) => {
        const previous = core.tables.get(budgetTable);
        await persist(change);
        const updated = core.tables.get(budgetTable);
        if (updated !== previous && [...(updated?.values() ?? [])].some((record) => record.outcome === outcome)) {
          core.persistPluginWrite = persist;
          written.resolve();
          await release.promise;
        }
      };
      return { written: written.promise, release: release.resolve };
    },
    async legacyRecord(operationId, row, plugin = 'fixture-inference') {
      const core = t.hq.core;
      const key = `${plugin}\0inference_operations`;
      if (!core.tables.has(key)) core.tables.set(key, new Map());
      core.tables.get(key).set(JSON.stringify([soul, scope.task_id, operationId]), row);
      await core.persist();
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

test('an ordinary plugin cannot register draft inference or reach its provider', { timeout: 5000 }, async () => {
  const t = await setup(() => assert.fail('producer should not open'), undefined,
    () => assert.fail('authorization should not run'), { enableFixture: false });
  try {
    await t.bind();
    await assert.rejects(t.client.request(MODEL_CATALOG, t.scope), code('host.unknown_kind'));
    await assert.rejects(t.client.requestResponses(t.request, () => {}), code('host.unknown_kind'));
    assert.deepEqual(t.records(), []);
  } finally { await t.close(); }
});

test('the inference ledger namespace cannot be a plugin name', () => {
  assert.throws(() => definePlugin({ name: '@hq', hostApi: 1, version: '0.1.0', init() {} }), code('host.invalid_manifest'));
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
    assert.equal(await t.remaining(), 1);
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
    const unary = t.client.request('task.directives', {});
    gate.resolve();
    assert.deepEqual(await response, { usage: terminal.usage });
    assert.deepEqual(await unary, { directives: [] });
    assert.deepEqual(chunks, [delta('one'), delta('two')]);
    assert.equal(t.records()[0].outcome, 'completed');
    assert.equal(t.records()[0].actual_cost, terminal.actualCost);
    assert.equal(await t.remaining(), 1 - terminal.actualCost);
    await assert.rejects(t.client.requestResponses({ ...t.request, operation_id: 'unfunded_op' }, () => {}), code('budget_exhausted'));
    assert.equal(opened, 1);
  } finally {
    gate.resolve();
    await t.close();
  }
});

const readId = 'toolu_fixture_read';
const readInput = { file_path: '/private/work/fixture.txt' };
const readStart = { type: 'response.tool_call.start', call_id: readId, name: 'Read' };
const readArg = (delta, call_id = readId) => ({ type: 'response.tool_call.arguments.delta', call_id, delta });
function readTurn(scope) {
  return {
    ...scope,
    model: 'fixture-codex',
    turn: {
      system: [
        { type: 'text', text: 'Use the fixture tool.' },
        { type: 'text', text: 'Return the fixture conclusion.', cache_control: { type: 'ephemeral' } },
      ],
      max_output_tokens: 32,
      tools: [{ name: 'Read', description: 'Read the fixture path.', input_schema: {
        type: 'object',
        properties: {
          file_path: { type: 'string', description: 'An absolute path.' },
          offset: { type: 'number', description: 'Starting line.', minimum: 0 },
          limit: { type: 'number', description: 'Maximum number of lines.' },
          pages: { type: 'string', description: 'Page range for documents.' },
        },
        required: ['file_path'], additionalProperties: false,
      } }],
      messages: [{ role: 'user', content: [
        { type: 'text', text: 'Read one fixture file.' }, { type: 'text', text: 'Use the specified path.' },
      ] }],
    },
  };
}

test('two structured requests carry a Read call and matching result through the bound broker', { timeout: 5000 }, async () => {
  const gate = deferred();
  const first = deferred();
  const requests = [];
  const t = await setup(async function* (_signal, request) {
    requests.push(request);
    if (requests.length === 1) {
      yield readStart;
      yield readArg('{"file_path":');
      yield readArg('"/private/work/fixture.txt"}');
      return { ...terminal, stop_reason: 'tool_use' };
    }
    yield delta('file ');
    await gate.promise;
    yield delta('read');
    return { ...terminal, stop_reason: 'end_turn' };
  });
  try {
    const initial = readTurn(t.scope);
    await assert.rejects(t.client.requestResponses(initial, () => {}), code('caller_mismatch'));
    await t.bind();
    await assert.rejects(t.client.requestResponses(initial, () => {}), code('credential_unavailable'));
    assert.deepEqual(t.records(), []);
    t.approve(1.25);
    await assert.rejects(t.client.requestResponses({ ...initial, input: 'mixed modes' }, () => {}), /invalid inference/);
    await assert.rejects(t.client.requestResponses({
      ...initial, turn: { ...initial.turn, tools: [{ ...initial.turn.tools[0], name: 'Bash' }] },
    }, () => {}), /invalid inference/);
    await assert.rejects(t.client.requestResponses({
      ...initial, turn: { ...initial.turn, max_output_tokens: 128_001 },
    }, () => {}), /invalid inference/);
    const callChunks = [];
    assert.deepEqual(await t.client.requestResponses(initial, (chunk) => callChunks.push(chunk)),
      { stop_reason: 'tool_use', usage: terminal.usage });
    assert.deepEqual(callChunks, [readStart, readArg('{"file_path":'), readArg('"/private/work/fixture.txt"}')]);
    assert.deepEqual(requests, [initial]);
    const toolCall = { type: 'tool_use', id: callChunks[0].call_id, name: callChunks[0].name,
      input: JSON.parse(callChunks.slice(1).map(({ delta }) => delta).join('')) };
    const continuation = {
      ...initial, operation_id: 'op_fixture_continue',
      turn: { ...initial.turn, messages: [
        ...initial.turn.messages,
        { role: 'assistant', content: [toolCall] },
        { role: 'user', content: [
          { type: 'tool_result', tool_use_id: toolCall.id, content: 'private fixture marker', is_error: false },
        ] },
      ] },
    };
    const mismatched = structuredClone(continuation);
    mismatched.turn.messages[2].content[0].tool_use_id = 'toolu_other';
    await assert.rejects(t.client.requestResponses(mismatched, () => {}), /invalid inference/);
    assert.equal(await t.remaining(), 1);
    const chunks = [];
    const next = t.client.requestResponses(continuation, (chunk) => {
      chunks.push(chunk);
      first.resolve();
    });
    await Promise.race([first.promise, next]);
    assert.deepEqual(chunks, [delta('file ')]);
    assert.deepEqual(toolCall.input, readInput);
    assert.deepEqual(requests, [initial, continuation]);
    assert.deepEqual(t.records().map(({ outcome }) => outcome), ['completed', 'outcome_unknown']);
    gate.resolve();
    assert.deepEqual(await next, { stop_reason: 'end_turn', usage: terminal.usage });
    assert.deepEqual(chunks, [delta('file '), delta('read')]);
    assert.deepEqual(t.records().map(({ outcome, actual_cost }) => [outcome, actual_cost]), [
      ['completed', terminal.actualCost], ['completed', terminal.actualCost],
    ]);
    assert.equal(await t.remaining(), 0.75);
    await assert.rejects(t.client.requestResponses(continuation, () => {}), code('credential_unavailable'));
    assert.equal(requests.length, 2);
  } finally {
    gate.resolve();
    await t.close();
  }
});

test('an empty Read result is a valid structured continuation', { timeout: 5000 }, async () => {
  const t = await setup(async function* (_signal, request) {
    assert.equal(request.turn.messages[2].content[0].content, '');
    yield delta('empty file');
    return { ...terminal, stop_reason: 'end_turn' };
  });
  try {
    await t.bind();
    t.approve(1);
    const request = readTurn(t.scope);
    request.turn.messages.push(
      { role: 'assistant', content: [{ type: 'tool_use', id: readId, name: 'Read', input: readInput }] },
      { role: 'user', content: [{ type: 'tool_result', tool_use_id: readId, content: '' }] },
    );
    const chunks = [];
    assert.deepEqual(await t.client.requestResponses(request, (chunk) => chunks.push(chunk)),
      { stop_reason: 'end_turn', usage: terminal.usage });
    assert.deepEqual(chunks, [delta('empty file')]);
    assert.equal(t.records()[0].outcome, 'completed');
  } finally { await t.close(); }
});

test('incoherent tool output fails with the existing unknown billing hold', { timeout: 5000 }, async () => {
  const t = await setup(async function* (_signal, request) {
    if (request.operation_id === 'op_mixed_output') yield delta('unrepresented transcript text');
    yield readStart;
    yield readArg('{"file_path":"first","file_path":"duplicate"}');
    return { ...terminal, stop_reason: 'tool_use' };
  });
  try {
    await t.bind();
    t.approve(2);
    await assert.rejects(t.client.requestResponses(readTurn(t.scope), () => {}), code('host.internal'));
    const mixed = readTurn({ ...t.scope, operation_id: 'op_mixed_output' });
    await assert.rejects(t.client.requestResponses(mixed, () => {}), code('host.internal'));
    assert.deepEqual(t.records().map(({ outcome }) => outcome), ['outcome_unknown', 'outcome_unknown']);
    assert.equal(await t.remaining(), 0);
  } finally { await t.close(); }
});

test('the terminal reply and durable accounting use the same measured usage snapshot', { timeout: 5000 }, async () => {
  const usage = { ...terminal.usage };
  const t = await setup(async function* () {
    yield delta('reply');
    return { ...terminal, usage };
  });
  const settlement = t.holdNextInferenceWrite('completed');
  try {
    await t.bind();
    t.approve(2);
    const reply = t.client.requestResponses(t.request, () => {});
    await settlement.written;
    // A provider can reuse its own usage counters while HQ waits for a commit.
    usage.output_tokens += 1;
    settlement.release();
    assert.deepEqual(await reply, { usage: terminal.usage });
    assert.deepEqual(t.records()[0].usage, terminal.usage);
  } finally {
    settlement.release();
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
    assert.equal(await t.remaining(), 1);
    await assert.rejects(t.client.requestResponses(t.request, () => {}), /reconcile before retrying/);
  } finally { await t.close(); }
});

test('restart preserves uncertainty and refuses to redispatch the same operation', { timeout: 5000 }, async () => {
  const t = await setup(async function* () { yield delta('x'.repeat(MAX_LINE_BYTES)); return terminal; });
  try {
    await t.bind();
    t.approve(1.5);
    await assert.rejects(t.client.requestResponses(t.request, () => {}), /byte limit/);
  } finally { await t.close({ keep: true }); }
  let opened = 0;
  const restart = await setup(async function* () { opened++; return terminal; }, t.home);
  try {
    await restart.bind();
    restart.approve(1.5);
    assert.equal(restart.records()[0].outcome, 'outcome_unknown');
    assert.equal(await restart.remaining(), 0.5);
    await assert.rejects(restart.client.requestResponses({ ...restart.request, operation_id: 'different_op' }, () => {}), code('budget_exhausted'));
    await assert.rejects(restart.client.requestResponses(restart.request, () => {}), /reconcile before retrying/);
    assert.equal(opened, 0);
  } finally { await restart.close(); }
});

test('unary spending, open holds and typed inference share one ceiling across restart', { timeout: 5000 }, async () => {
  const first = await setup(async function* () { return terminal; });
  let settled, held, released;
  try {
    await first.bind();
    first.approve(1.75);
    assert.deepEqual(await first.client.requestResponses(first.request, () => {}), { usage: terminal.usage });
    settled = await first.reserveUnary(0.5);
    await first.settleUnary(settled, 0.5);
    held = await first.reserveUnary(0.25);
    released = await first.reserveUnary(0.25);
    await first.releaseUnary(released);
    await first.reserveUnary(0.25, 'maintenance');
    assert.equal(await first.remaining(), 0.75);
    assert.equal(await first.remaining('maintenance'), 1.5);
  } finally { await first.close({ keep: true }); }

  const second = await setup(async function* () { return { ...terminal, actualCost: 0.5 }; }, first.home);
  try {
    await second.bind();
    second.approve(1.75);
    assert.equal(await second.remaining(), 0.75);
    const request = { ...second.request, operation_id: 'second_turn' };
    await assert.rejects(second.client.requestResponses(request, () => {}), code('budget_exhausted'));
    await assert.rejects(second.client.requestResponses(second.request, () => {}), /reconcile before retrying/);
    await assert.rejects(second.releaseUnary(released), code('host.invalid_request'));
    await assert.rejects(second.settleUnary(settled, 0), code('host.invalid_request'));
    await second.releaseUnary(held);
    assert.equal(await second.remaining(), 1);
    assert.deepEqual(await second.client.requestResponses(request, () => {}), { usage: terminal.usage });
    assert.equal(await second.remaining(), 0.5);
    assert.deepEqual(second.records().map(({ outcome, actual_cost }) => [outcome, actual_cost]), [['completed', 0.25], ['completed', 0.5]]);
    await assert.rejects(second.client.requestResponses({ ...second.request, operation_id: 'third_turn' }, () => {}), code('budget_exhausted'));
    await assert.rejects(second.reserveUnary(1), code('budget_exhausted'));
    assert.equal(await second.remaining('maintenance'), 1.5);
  } finally { await second.close(); }
});

test('an unrelated snapshot cannot publish a failed unary reserve, settlement or release', { timeout: 5000 }, async () => {
  const first = await setup(async function* () { assert.fail('producer should not open'); });
  let held;
  try {
    first.approve(1.25);
    first.failUnaryWriteAfterUnrelatedPersist();
    await assert.rejects(first.reserveUnary(0.5), /injected unary/);
    assert.equal(await first.remaining(), 1.25);
    held = await first.reserveUnary(1);
    first.failUnaryWriteAfterUnrelatedPersist();
    await assert.rejects(first.settleUnary(held, 0.25), /injected unary/);
    assert.equal(await first.remaining(), 0.25);
    first.failUnaryWriteAfterUnrelatedPersist();
    await assert.rejects(first.releaseUnary(held), /injected unary/);
    assert.equal(await first.remaining(), 0.25);
  } finally { await first.close({ keep: true }); }

  const second = await setup(async function* () { return terminal; }, first.home);
  try {
    await second.bind();
    second.approve(1.25);
    assert.equal(await second.remaining(), 0.25);
    await assert.rejects(second.client.requestResponses(second.request, () => {}), code('budget_exhausted'));
    await second.settleUnary(held, 0.25);
    assert.equal(await second.remaining(), 1);
    await second.client.requestResponses(second.request, () => {});
    assert.equal(await second.remaining(), 0.75);
  } finally { await second.close(); }
});

test('overlapping bound sockets and unary reservations share the ceiling without double dispatch', { timeout: 5000 }, async () => {
  const entered = deferred();
  const finish = deferred();
  let opened = 0;
  const t = await setup(async function* () {
    opened++;
    yield delta('started');
    await finish.promise;
    return terminal;
  });
  try {
    await t.bind();
    const other = await t.openClient();
    await other.bind();
    t.approve(1);
    const unary = await t.reserveUnary(0.25);
    await assert.rejects(t.client.requestResponses(t.request, () => {}), code('budget_exhausted'));
    assert.equal(opened, 0);
    await t.releaseUnary(unary);
    const pending = t.client.requestResponses(t.request, () => { entered.resolve(); });
    await Promise.race([entered.promise, pending]);
    await assert.rejects(other.client.requestResponses(t.request, () => {}), /reconcile before retrying/);
    await assert.rejects(other.client.requestResponses({ ...t.request, operation_id: 'another_turn' }, () => {}), code('budget_exhausted'));
    await assert.rejects(t.reserveUnary(0.25), code('budget_exhausted'));
    assert.equal(opened, 1);
    finish.resolve();
    await pending;
  } finally { finish.resolve(); await t.close(); }
});

test('a failed reservation write does not dispatch and a failed settlement retains the durable hold', { timeout: 5000 }, async () => {
  let opened = 0;
  const t = await setup(async function* () { opened++; return terminal; });
  try {
    await t.bind();
    t.approve(1);
    t.failNextWrite('outcome_unknown');
    await assert.rejects(t.client.requestResponses(t.request, () => {}), code('host.internal'));
    assert.equal(opened, 0);
    assert.deepEqual(t.records(), []);
    assert.equal(await t.remaining(), 1);

    t.failNextWrite('completed');
    await assert.rejects(t.client.requestResponses(t.request, () => {}), code('host.internal'));
    assert.equal(opened, 1);
    assert.equal(t.records()[0].outcome, 'outcome_unknown');
    assert.equal(t.records()[0].reserved_cost, 1);
    assert.equal(await t.remaining(), 0);
    await assert.rejects(t.client.requestResponses(t.request, () => {}), /reconcile before retrying/);
    await assert.rejects(t.client.requestResponses({ ...t.request, operation_id: 'another_turn' }, () => {}), code('budget_exhausted'));
    assert.equal(opened, 1);
  } finally { await t.close(); }
});

test('a failed Read continuation settlement keeps the hold across later writes and restart', { timeout: 5000 }, async () => {
  const completeProvider = deferred();
  const continuation = (scope) => {
    const initial = readTurn(scope);
    return {
      ...initial,
      operation_id: 'op_fixture_continue',
      turn: { ...initial.turn, messages: [
        ...initial.turn.messages,
        { role: 'assistant', content: [{ type: 'tool_use', id: readId, name: 'Read', input: readInput }] },
        { role: 'user', content: [{ type: 'tool_result', tool_use_id: readId, content: 'private fixture marker' }] },
      ] },
    };
  };
  const first = await setup(async function* (_signal, request) {
    if (request.turn.messages.length === 1) {
      yield readStart;
      yield readArg(JSON.stringify(readInput));
      return { ...terminal, stop_reason: 'tool_use' };
    }
    yield delta('reply before settlement');
    await completeProvider.promise;
    return { ...terminal, stop_reason: 'end_turn' };
  });
  const scratchEntry = join(first.home, `store.json.tmp-${process.pid}`);
  try {
    await first.bind();
    first.approve(1.25);
    assert.deepEqual(await first.client.requestResponses(readTurn(first.scope), () => {}),
      { stop_reason: 'tool_use', usage: terminal.usage });
    const streamed = deferred();
    const response = first.client.requestResponses(continuation(first.scope), streamed.resolve);
    const refusal = assert.rejects(response, code('host.internal'));
    await Promise.race([streamed.promise, response]);

    // A real file-store error, after dispatch and before settlement.
    mkdirSync(scratchEntry);
    try {
      completeProvider.resolve();
      await refusal;
    } finally { rmdirSync(scratchEntry); }

    await first.appendMarker();
    await first.settleUnary(await first.reserveUnary(0.5, 'maintenance'), 0.25);
    assert.equal(await first.remaining(), 0);
    assert.equal(await first.remaining('maintenance'), 1);
    assert.deepEqual(first.records().map(({ outcome, reserved_cost, actual_cost }) => [outcome, reserved_cost, actual_cost]), [
      ['completed', 1, 0.25], ['outcome_unknown', 1, undefined],
    ]);
  } finally {
    completeProvider.resolve();
    await first.close({ keep: true });
  }

  const second = await setup(async function* () { assert.fail('producer should not reopen'); }, first.home);
  try {
    await second.bind();
    second.approve(1.25);
    assert.equal(second.markers().length, 1);
    assert.equal(await second.remaining('maintenance'), 1);
    assert.equal(await second.remaining(), 0);
    await assert.rejects(second.client.requestResponses(readTurn(second.scope), () => {}), /reconcile before retrying/);
    await assert.rejects(second.client.requestResponses(continuation(second.scope), () => {}), /reconcile before retrying/);
  } finally { await second.close(); }
});

test('cancelling a committed reservation before dispatch releases its hold', { timeout: 5000 }, async () => {
  let providerSignal;
  const t = await setup(async function* () { assert.fail('producer should not open'); }, undefined, (signal) => { providerSignal = signal; });
  await t.bind();
  t.approve(1);
  const hold = t.holdNextInferenceWrite('outcome_unknown');
  try {
    const response = t.client.requestResponses(t.request, () => {});
    await Promise.race([hold.written, response]);
    assert.equal(t.records()[0].outcome, 'outcome_unknown');
    const aborted = deferred();
    providerSignal.addEventListener('abort', aborted.resolve, { once: true });
    t.abort();
    await assert.rejects(response, /member cancelled/);
    await aborted.promise;
    hold.release();
    for (let i = 0; i < 100 && t.records().length; i++) await setImmediate();
    assert.deepEqual(t.records(), []);
    assert.equal(await t.remaining(), 1);
  } finally { hold.release(); await t.close(); }
});

test('verified spend above the reservation is charged and restricts subsequent requests', { timeout: 5000 }, async () => {
  const t = await setup(async function* () { return { ...terminal, actualCost: 1.25 }; });
  try {
    await t.bind();
    t.approve(1.5);
    await t.client.requestResponses(t.request, () => {});
    assert.equal(t.records()[0].actual_cost, 1.25);
    assert.equal(await t.remaining(), 0.25);
    await assert.rejects(t.client.requestResponses({ ...t.request, operation_id: 'another_turn' }, () => {}), code('budget_exhausted'));
  } finally { await t.close(); }
});

test('only the registered provider’s earlier draft records count after restart', { timeout: 5000 }, async () => {
  const first = await setup(async function* () { assert.fail('producer should not open'); });
  try {
    await first.legacyRecord('old_completed', { outcome: 'completed', actual_cost: 0.75 });
    await first.legacyRecord(first.request.operation_id, { outcome: 'outcome_unknown' }, 'unrelated-plugin');
  } finally { await first.close({ keep: true }); }

  const next = await setup(async function* () { return terminal; }, first.home);
  try {
    await next.bind();
    next.approve(2);
    assert.equal(await next.remaining(), 1.25);
    await assert.rejects(next.client.requestResponses({ ...next.request, operation_id: 'old_completed' }, () => {}), /reconcile before retrying/);
    await next.legacyRecord('old_unknown', { outcome: 'outcome_unknown' });
    // The loaded historical view is stable during this run.
    assert.deepEqual(await next.client.requestResponses(next.request, () => {}), { usage: terminal.usage });
    assert.equal(await next.remaining(), 1);
  } finally { await next.close({ keep: true }); }

  const last = await setup(async function* () { assert.fail('producer should not open'); }, first.home);
  try {
    await last.bind();
    last.approve(2);
    await assert.rejects(last.client.requestResponses({ ...last.request, operation_id: 'fresh_operation' }, () => {}), /accounting requires reconciliation/);
    assert.equal(await last.remaining('maintenance'), 2);
  } finally { await last.close(); }
});

test('duplicate old and current inference operation records require working-pool reconciliation', { timeout: 5000 }, async () => {
  const first = await setup(async function* () { return terminal; });
  try {
    await first.bind();
    first.approve(2);
    await first.client.requestResponses(first.request, () => {});
    await first.legacyRecord(first.request.operation_id, { outcome: 'completed', actual_cost: terminal.actualCost });
  } finally { await first.close({ keep: true }); }

  const next = await setup(async function* () { assert.fail('producer should not open'); }, first.home);
  try {
    await next.bind();
    next.approve(2);
    await assert.rejects(next.client.requestResponses(next.request, () => {}), /reconcile before retrying/);
    await assert.rejects(next.reserveUnary(0), /accounting requires reconciliation/);
    await assert.rejects(next.client.requestResponses({
      ...next.request, operation_id: 'different_operation',
    }, () => {}), /accounting requires reconciliation/);
    assert.equal(await next.remaining('maintenance'), 2);
  } finally { await next.close(); }
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
    assert.equal(await t.remaining(), 0);
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
    assert.equal(await t.remaining(), 0);
    await assert.rejects(t.client.request(MODEL_CATALOG, t.scope), code('credential_unavailable'));
  } finally {
    blocked.resolve();
    await t.close();
  }
});
