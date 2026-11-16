// Session regression cases adapted from true-line/agent-bot-souls
// tests/member-queries.test.mjs at 2097b8dc129737df23ae1fb1f8dc30eb4f7d8033.
// Uses this repository's real HQ and reference broker; no MCP acceptance claim.
// Transport/provider integration, not notice-consumer or MCP acceptance:
// the reviewed SDK port runs against real pinned HQ admission, broker and
// durable store; a namespaced test-only kind handler isolates connection/replay
// effects. The test proxy translates the two SDK operation names so the real
// default notice consumer retains its public kind registrations unchanged.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createConnection, createServer } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { openMemberSession, bindProof, BIND_CONTEXT } from '../sdk/member-session.mjs';
import { connectMemberQueries } from '../sdk/member-client.mjs';
import { contracts } from './support/member-client-contracts.mjs';
import { definePlugin } from '../sdk/plugin.mjs';
import { fail } from '../sdk/errors.mjs';
import { referenceBroker as brokerPlugin } from './broker-fixture.mjs';
import { readLines, writeLine } from '../sdk/local-socket-lines.mjs';
import { hello, SOUL, startHQ } from './hq-harness.mjs';

const deferred = () => { let resolve; const promise = new Promise((r) => { resolve = r; }); return { promise, resolve }; };

async function listening(path, accept) {
  const sockets = new Set();
  const server = createServer((socket) => {
    sockets.add(socket); socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket)); accept(socket);
  });
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(path, resolve); });
  return { path, close: () => new Promise((resolve) => { for (const socket of sockets) socket.destroy(); server.close(resolve); }) };
}

async function world(t, { beforeBind, beforeQuery, reply } = {}) {
  const dir = mkdtempSync(join(tmpdir(), 'mq-'));
  const members = [];
  const upstream = new Set();
  const frames = [];
  const state = { runtime: null, asked: 0, received: [], binds: 0, dropped: 0 };
  let hq, entry, proxy;
  t.after(async () => { for (const member of members) await member.close(); for (const socket of upstream) socket.destroy(); await proxy?.close(); await entry?.close(); await hq?.done(); rmSync(dir, { recursive: true, force: true }); });
  const handler = definePlugin({
    name: 'query-transport-fixture', version: '0.1.0', hostApi: 1, requires: { 'hq-admission': '^0.1.0' }, services: ['store'],
    async init(ctx) {
      for (const kind of ['notices.peek', 'notices.consume-one']) ctx.broker.registerKind({ kind: `transport-fixture.${kind}`, async consume(message, meta) {
        state.received.push({ kind, message, runtime_id: meta.runtime_id });
        if (beforeQuery) await beforeQuery({ kind, message, meta, state });
        return ctx.deps['hq-admission'].withBoundRuntime(meta.runtime_id, async (rt) => {
          if (message.installation_epoch !== rt.epoch) fail('stale_epoch', 'test query epoch differs');
          if (message.lease_generation !== rt.lease_generation) fail('lease_expired', 'test query generation differs');
          let effect;
          if (kind === 'notices.consume-one') effect = await ctx.services.store.tx((tx) => {
            const n = (tx.get('effects', 'count') ?? 0) + 1; tx.put('effects', 'count', n); return n;
          });
          return { installation_epoch: rt.epoch, lease_generation: rt.lease_generation, runtime_id: meta.runtime_id, ...(effect ? { effect } : {}) };
        });
      } });
    },
  });
  hq = await startHQ({ plugins: [brokerPlugin({ beforeBind: async () => { state.binds++; if (beforeBind) await beforeBind(state); } }), handler] });
  const admission = await hq.entry();
  let sequence = 0;
  const admit = async () => {
    const response = await admission.request('Hello', hello({ request_id: `provider_${++sequence}` }));
    assert.equal(response.ok, true, JSON.stringify(response));
    const value = response.result;
    const runtime = value.admitted_runtimes[0];
    state.runtime = { runtime_id: runtime.runtime_id, channel_binding: runtime.channel_binding, installation_epoch: value.installation_epoch, lease_generation: value.lease_generation };
    return state.runtime;
  };
  await admit();
  entry = await listening(join(dir, 'member.sock'), (socket) => readLines(socket, (line) => {
    const request = JSON.parse(line);
    if (request.op === 'hello') {
      if (request.payload.token !== 'MEMBER_TOKEN_CANARY') {
        writeLine(socket, { id: request.id, ok: false, host_refusal: { code: 'souls.unknown_member', explanation: 'not a running member token' } });
        return;
      }
      writeLine(socket, { id: request.id, ok: true, result: { soul_id: SOUL, member_id: 'm_lead', role: 'lead' } });
    } else if (request.op === 'runtime') {
      state.asked++;
      writeLine(socket, { id: request.id, ok: true, result: { broker: proxy.path, soul_id: SOUL, member_id: 'm_lead', role: 'lead', ...state.runtime } });
    } else if (['route', 'note', 'handoffs'].includes(request.op)) {
      writeLine(socket, { id: request.id, ok: true, result: { operation: request.op, payload: request.payload ?? null } });
    } else throw new Error('unexpected member request');
  }));
  proxy = await listening(join(dir, 'proxy.sock'), (client) => {
    const server = createConnection(hq.hq.paths.broker);
    upstream.add(server); server.on('error', () => client.destroy()); server.on('close', () => { upstream.delete(server); client.destroy(); }); client.on('close', () => server.destroy());
    const pending = new Map();
    readLines(client, (line) => { const request = JSON.parse(line); frames.push(request); pending.set(request.id, request);
      const op = ['notices.peek', 'notices.consume-one'].includes(request.op) ? `transport-fixture.${request.op}` : request.op;
      writeLine(server, { ...request, op }); });
    readLines(server, (line) => {
      const result = JSON.parse(line); const request = pending.get(result.id); const kind = request?.op; pending.delete(result.id);
      const output = reply ? reply({ kind, result, request, state }) : result;
      if (output === null) { state.dropped++; client.destroy(); server.destroy(); }
      else if (output !== undefined) writeLine(client, output);
    });
  });
  const connect = async () => {
    const member = await connectMemberQueries({ memberSocket: entry.path, memberToken: 'MEMBER_TOKEN_CANARY', contracts });
    members.push(member); return member;
  };
  return { hq, state, frames, connect, admit, options: { memberSocket: entry.path, memberToken: 'MEMBER_TOKEN_CANARY', contracts } };
}

const build = (freshness) => ({ ...freshness });
// Establish through the public port, then isolate the recovery observations
// from this initial successful read. No public runtime accessor is invented.
const bindMember = async (member, world) => {
  await member.queries.request('notices.peek', build);
  world.state.received.length = 0;
  return world.state.runtime;
};

async function helloPeer(t, response) {
  const root = mkdtempSync(join(tmpdir(), 'hello-'));
  const path = join(root, 'member.sock');
  const operations = [];
  const sockets = new Set();
  const ended = deferred();
  // A peer that keeps its writable half open exposes cleanup that merely
  // waits for graceful close instead of forcibly dropping bootstrap state.
  const server = createServer({ allowHalfOpen: true }, (socket) => {
    sockets.add(socket); socket.on('error', () => {});
    socket.on('end', () => ended.resolve());
    socket.on('close', () => sockets.delete(socket));
    readLines(socket, (line) => {
      const request = JSON.parse(line);
      operations.push(request.op);
      writeLine(socket, { id: request.id, ...response });
    });
  });
  await new Promise((resolve) => server.listen(path, resolve));
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
    rmSync(root, { recursive: true, force: true });
  });
  return { options: { memberSocket: path, memberToken: 'MEMBER_TOKEN_CANARY', contracts }, operations, ended: ended.promise };
}

async function refusedHello(peer, options = peer.options) {
  let timer;
  try {
    const deadline = new Promise((resolve) => { timer = setTimeout(() => resolve({ timeout: true }), 500); });
    const outcome = await Promise.race([
      connectMemberQueries(options).then((member) => ({ member }), (error) => ({ error })),
      deadline,
    ]);
    if (outcome.member) await outcome.member.close();
    assert.equal(outcome.timeout, undefined, 'bootstrap must not wait for the malformed peer to close');
    assert.ok(outcome.error, 'malformed hello must not produce a query capability');
    assert.equal(await Promise.race([peer.ended.then(() => true), deadline.then(() => false)]), true, 'failed bootstrap must close its entry socket');
    assert.deepEqual(peer.operations, ['hello'], 'no runtime, bind or query before valid member identity');
    return outcome.error;
  } finally { clearTimeout(timer); }
}

test('bootstrap rejects malformed hello identities and force-closes before any runtime or query', async (t) => {
  const valid = { soul_id: SOUL, member_id: 'm_lead', role: 'lead' };
  const malformed = [null, {}, [], ['soul', 'member', 'role']];
  for (const field of Object.keys(valid)) {
    const missing = { ...valid }; delete missing[field]; malformed.push(missing);
    for (const value of [null, 1, '', 'bad value', valid[field] + '\n']) malformed.push({ ...valid, [field]: value });
  }
  for (const result of malformed) await t.test(JSON.stringify(result), async (t) => {
    const peer = await helloPeer(t, { ok: true, result });
    assert.match((await refusedHello(peer)).message, /invalid member identity/);
  });
});

test('hello identity fields must be own properties even when a prototype supplies valid values', async (t) => {
  const peer = await helloPeer(t, { ok: true, result: {} });
  const values = { soul_id: SOUL, member_id: 'm_lead', role: 'lead' };
  const previous = Object.fromEntries(Object.keys(values).map((key) => [key, Object.getOwnPropertyDescriptor(Object.prototype, key)]));
  try {
    for (const [key, value] of Object.entries(values)) Object.defineProperty(Object.prototype, key, { value, writable: true, configurable: true });
    assert.match((await refusedHello(peer)).message, /invalid member identity/);
  } finally {
    for (const key of Object.keys(values)) {
      if (previous[key]) Object.defineProperty(Object.prototype, key, previous[key]);
      else delete Object.prototype[key];
    }
  }
});

test('bootstrap force-closes an unsuccessful hello and preserves its original validation error', async (t) => {
  const failure = new Error('original hello refusal validation failure');
  const peer = await helloPeer(t, { ok: false, refusal: {} });
  const options = { ...peer.options, contracts: { ...contracts, record() { throw failure; } } };
  assert.equal(await refusedHello(peer, options), failure);
  const refusal = await helloPeer(t, { ok: false, host_refusal: { code: 'souls.unknown_member', explanation: 'not a running member token' } });
  const error = await refusedHello(refusal);
  assert.equal(error.code, 'souls.unknown_member');
  assert.equal(error.op, 'hello');
  assert.equal(error.transport, false);
});

test('public bootstrap refuses missing inputs and unknown member tokens without a broker bind', async (t) => {
  for (const options of [undefined, {}, { memberSocket: '/missing', memberToken: '' }]) await assert.rejects(connectMemberQueries(options), TypeError);
  const w = await world(t);
  // The entry point is the token issuer/verifier; this test confirms an entry
  // failure propagates without any broker attempt or returned capability.
  await assert.rejects(connectMemberQueries({ ...w.options, memberToken: 'WRONG_TOKEN' }));
  assert.equal(w.state.binds, 0);
});

test('private facade rejects foreign captures, redacts full runtime metadata and restricts entry delegation', async (t) => {
  const w = await world(t);
  const owner = await openMemberSession(w.options);
  t.after(() => owner.close());
  const captured = await owner.capture();
  assert.equal(Object.isFrozen(captured), true);
  const metadata = owner.runtimeFor(captured);
  assert.equal(Object.isFrozen(metadata), true);
  assert.equal(metadata.broker.endsWith('proxy.sock'), true);
  assert.equal(metadata.soul_id, SOUL);
  assert.equal(metadata.member_id, 'm_lead');
  assert.equal(metadata.role, 'lead');
  assert.equal(metadata.runtime_id, w.state.runtime.runtime_id);
  assert.equal(Object.hasOwn(metadata, 'channel_binding'), false);
  assert.equal(JSON.stringify(metadata).includes('MEMBER_TOKEN_CANARY'), false);
  assert.deepEqual(owner.member, { soul_id: SOUL, member_id: 'm_lead', role: 'lead' });
  assert.throws(() => owner.runtimeFor({ ...captured }), /unknown member query capture/);
  assert.throws(() => owner.requestOnce({}, 'notices.peek', {}), /unknown member query capture/);
  await assert.rejects(owner.reconnect({}), /unknown member query capture/);
  assert.equal(owner.isRetryableReadFailure({ transport: true }, {}), false);
  assert.throws(() => owner.entryRequest('runtime'), TypeError);
  assert.throws(() => owner.entryRequest('hello', {}), TypeError);
  assert.deepEqual(await owner.entryRequest('note', { text: 'note' }), { operation: 'note', payload: { text: 'note' } });
  owner.dropBroker();
  const replacement = await owner.capture();
  assert.notEqual(replacement, captured);
  assert.equal(w.state.binds, 2);
});

test('owner requestOnce preserves the raw request path used by task commitment recovery', async (t) => {
  const w = await world(t);
  const owner = await openMemberSession(w.options);
  t.after(() => owner.close());
  const captured = await owner.capture();
  const old = owner.runtimeFor(captured);
  await w.admit();
  await assert.rejects(owner.requestOnce(captured, 'notices.peek', old), (error) => error.code === 'lease_expired');
  assert.equal(await owner.capture(), captured, 'raw owner path does not adopt generic-query invalidation');
  await assert.rejects(captured.request('notices.peek', captured.freshness), (error) => error.code === 'lease_expired');
  const next = await owner.capture();
  assert.notEqual(next, captured, 'query wrapper marks a failed pair for a later explicit capture');
  assert.equal(owner.runtimeFor(next).lease_generation, w.state.runtime.lease_generation);
  // A capture fixes the proof input and session together; binding bytes are
  // used only by the implementation and never sent directly on broker frames.
  assert.equal(typeof bindProof('own_binding_material', 'ab'.repeat(32), 'rt_1'), 'string');
  assert.equal(BIND_CONTEXT, 'agent-bot-hq/bind/v1');
});

test('real HQ: concurrent first captures share one completed bind and expose only the SDK capability', async (t) => {
  const entered = deferred(), release = deferred();
  t.after(() => release.resolve());
  const w = await world(t, { beforeBind: async () => { entered.resolve(); await release.promise; } });
  const member = await w.connect();
  assert.deepEqual(Reflect.ownKeys(member), ['queries', 'close']);
  assert.equal(Object.isFrozen(member), true);
  assert.equal(Object.isFrozen(member.queries), true);
  assert.deepEqual(Object.keys(member.queries), ['request']);
  const fresh = [];
  const pending = Array.from({ length: 12 }, () => member.queries.request('notices.peek', (value) => {
    assert.equal(Object.isFrozen(value), true); assert.deepEqual(Object.keys(value).sort(), ['installation_epoch', 'lease_generation']); fresh.push(value); return build(value);
  }, { replay: 'read-once' }));
  await entered.promise;
  assert.equal(w.state.asked, 1); assert.equal(w.state.binds, 1); assert.equal(w.state.received.length, 0);
  release.resolve();
  const results = await Promise.all(pending);
  assert.ok(results.every((result) => result.runtime_id === w.state.runtime.runtime_id));
  assert.equal(fresh.length, 12); assert.equal(w.state.binds, 1);
  assert.equal(JSON.stringify(fresh).includes('MEMBER_TOKEN_CANARY'), false);
  assert.equal(JSON.stringify(fresh).includes(w.state.runtime.channel_binding), false);
  assert.equal(JSON.stringify(w.frames).includes(w.state.runtime.channel_binding), false);
});

test('real HQ: read recovery rebuilds freshness on the replacement binding', async (t) => {
  const w = await world(t); const member = await w.connect();
  const old = await bindMember(member, w); await w.admit();
  const attempts = [];
  const result = await member.queries.request('notices.peek', (value) => { attempts.push(value); return build(value); }, { replay: 'read-once' });
  assert.deepEqual(attempts.map((x) => x.lease_generation), [old.lease_generation, w.state.runtime.lease_generation]);
  assert.equal(result.runtime_id, w.state.runtime.runtime_id); assert.equal(w.state.binds, 2);
});

test('real HQ: a late failure from an old capture reuses the newer pair instead of destroying it', async (t) => {
  const held = deferred(), replacing = deferred(), bindRelease = deferred();
  t.after(() => bindRelease.resolve());
  let holdOnce = true;
  const w = await world(t, {
    // Hold only the old socket's reply, not HQ's request handler: HQ serializes
    // requests on one connection. Retirement will cut this pending response
    // after the new pair is published, producing the deliberately late error.
    reply: ({ kind, result, request }) => {
      if (kind === 'notices.peek' && request.payload.slow && holdOnce) { holdOnce = false; held.resolve(); return undefined; }
      return result;
    },
    beforeBind: async (state) => { if (state.binds === 2) { replacing.resolve(); await bindRelease.promise; } },
  });
  const member = await w.connect(); await bindMember(member, w); await w.admit();
  const slow = member.queries.request('notices.peek', (value) => ({ ...value, slow: true }), { replay: 'read-once' });
  await held.promise;
  const trigger = member.queries.request('notices.peek', build, { replay: 'read-once' });
  await replacing.promise; bindRelease.resolve();
  const [a, b] = await Promise.all([slow, trigger]);
  assert.equal(a.runtime_id, w.state.runtime.runtime_id); assert.equal(b.runtime_id, a.runtime_id);
  assert.equal(w.state.binds, 2); assert.equal(w.state.asked, 2);
});

test('real HQ: committed consume with a lost socket reply sends exactly once even when read replay is requested', async (t) => {
  const w = await world(t, { reply: ({ kind, result }) => kind === 'notices.consume-one' && result.ok ? null : result });
  const member = await w.connect();
  await assert.rejects(member.queries.request('notices.consume-one', build, { replay: 'read-once' }), (error) => error.transport === true);
  assert.equal(w.state.received.filter((x) => x.kind === 'notices.consume-one').length, 1);
  assert.equal(w.hq.hq.core.tables.get('query-transport-fixture\0effects').get('count'), 1, 'effect durably committed before the reply was cut');
  assert.equal(w.state.binds, 1); assert.equal(w.state.dropped, 1);
  const result = await member.queries.request('notices.peek', build, { replay: 'read-once' });
  assert.equal(result.runtime_id, w.state.runtime.runtime_id); assert.equal(w.state.binds, 2);
});

test('real HQ: a host code imitating a shared freshness refusal does not authorize replay', async (t) => {
  const w = await world(t, {
    beforeQuery: () => fail('lease_expired', 'test shared refusal'),
    reply: ({ kind, result }) => kind === 'notices.peek' ? { id: result.id, ok: false, host_refusal: { code: 'lease_expired', explanation: 'host string is not a validated shared refusal' } } : result,
  });
  const member = await w.connect();
  await assert.rejects(member.queries.request('notices.peek', build, { replay: 'read-once' }), (error) => error.code === 'lease_expired');
  assert.equal(w.state.received.length, 1); assert.equal(w.state.binds, 1);
});

test('real HQ: shared nonfreshness refusals and local contract failures are not retried', async (t) => {
  const w = await world(t, {
    beforeQuery: () => fail('caller_mismatch', 'test scope refusal'),
    reply: ({ kind, result }) => kind === 'task.get' ? { id: result.id, ok: true, result: { task: {} } } : result,
  });
  const member = await w.connect();
  await assert.rejects(member.queries.request('notices.peek', build, { replay: 'read-once' }), (error) => error.code === 'caller_mismatch');
  await assert.rejects(member.queries.request('task.get', () => ({ task_id: 'missing' }), { replay: 'read-once' }), (error) => /invalid shared record/.test(error.message));
  assert.equal(w.state.binds, 1); assert.equal(w.frames.filter((x) => x.op === 'task.get').length, 1);
});

test('real HQ: an invalid challenge publishes no capture and the next explicit query can bind afresh', async (t) => {
  let corrupt = true;
  const w = await world(t, { reply: ({ kind, result }) => {
    if (kind === 'bind.challenge' && corrupt) { corrupt = false; return { ...result, result: { ...result.result, nonce: 'ab'.repeat(32) + '\n' } }; }
    return result;
  } });
  const member = await w.connect(); let builds = 0;
  await assert.rejects(member.queries.request('notices.peek', (value) => { builds++; return build(value); }, { replay: 'read-once' }), /cannot answer/);
  assert.equal(builds, 0); assert.equal(w.state.binds, 0); assert.equal(w.state.received.length, 0);
  await w.admit();
  const result = await member.queries.request('notices.peek', build);
  assert.equal(result.runtime_id, w.state.runtime.runtime_id); assert.equal(w.state.binds, 1); assert.equal(w.state.asked, 2);
});

test('real HQ: close aborts an in-flight bind, is idempotent, and a new member can start independently', async (t) => {
  const entered = deferred(), release = deferred(); t.after(() => release.resolve());
  const w = await world(t, { beforeBind: async (state) => { if (state.binds === 1) { entered.resolve(); await release.promise; } } });
  const member = await w.connect(); let builds = 0;
  const failure = assert.rejects(member.queries.request('notices.peek', (value) => { builds++; return build(value); }), (error) => error.transport === true);
  await entered.promise;
  await member.close(); await member.close(); await failure;
  release.resolve();
  await assert.rejects(member.queries.request('notices.peek', build), (error) => error.transport === true);
  assert.equal(builds, 0);
  const replacement = await w.connect();
  assert.equal((await replacement.queries.request('notices.peek', build)).runtime_id, w.state.runtime.runtime_id);
  assert.equal(w.state.received.length, 1);
});

test('real HQ: failed replacement is not published or replayed again; a later explicit request repairs it', async (t) => {
  let challenges = 0;
  const w = await world(t, { reply: ({ kind, result }) => {
    if (kind === 'bind.challenge' && ++challenges === 2) return { ...result, result: { ...result.result, context: 'unsupported-context' } };
    return result;
  } });
  const member = await w.connect(); const old = await bindMember(member, w); await w.admit();
  const built = [];
  await assert.rejects(member.queries.request('notices.peek', (freshness) => { built.push(freshness); return build(freshness); }, { replay: 'read-once' }), /cannot answer/);
  assert.deepEqual(built.map((value) => value.lease_generation), [old.lease_generation]);
  assert.equal(w.state.received.length, 1, 'failed reconnect is not an implicit third request');
  const next = await member.queries.request('notices.peek', build);
  assert.equal(next.runtime_id, w.state.runtime.runtime_id); assert.equal(w.state.asked, 3); assert.equal(w.state.binds, 2);
});

test('real HQ: malformed entry runtime freshness fails capture before challenge or payload building', async (t) => {
  const w = await world(t); const member = await w.connect();
  const valid = w.state.runtime; w.state.runtime = { ...valid, lease_generation: 0 };
  let built = 0;
  await assert.rejects(member.queries.request('notices.peek', (freshness) => { built++; return build(freshness); }, { replay: 'read-once' }), /invalid runtime binding metadata/);
  assert.equal(built, 0); assert.equal(w.frames.length, 0);
  w.state.runtime = valid;
  const result = await member.queries.request('notices.peek', build);
  assert.equal(result.runtime_id, valid.runtime_id); assert.equal(w.state.binds, 1);
});

test('real HQ: never-replay freshness refusal marks only that pair for the next explicit capture', async (t) => {
  const w = await world(t); const member = await w.connect();
  await bindMember(member, w); await w.admit();
  await assert.rejects(member.queries.request('notices.consume-one', build), (error) => error.code === 'lease_expired');
  assert.equal(w.state.binds, 1, 'no reconnect inside the refused destructive call');
  assert.equal(w.state.received.length, 1);
  assert.equal(w.hq.hq.core.tables.has('query-transport-fixture\0effects'), false);
  const fresh = await member.queries.request('notices.consume-one', build);
  assert.equal(fresh.runtime_id, w.state.runtime.runtime_id);
  assert.equal(w.state.binds, 2); assert.equal(w.state.received.length, 2);
  assert.equal(w.hq.hq.core.tables.get('query-transport-fixture\0effects').get('count'), 1);
});
