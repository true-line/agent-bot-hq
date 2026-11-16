// Real local sockets isolate cancellation; notice payload/consumer acceptance
// remains in the existing HQ integration suites.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHmac } from 'node:crypto';
import { getEventListeners } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { connectMemberQueries } from '../sdk/member-client.mjs';
import { connectHq } from '../sdk/local-socket-client.mjs';
import { BIND_CONTEXT } from '../sdk/member-session.mjs';
import { readLines, writeLine } from '../sdk/local-socket-lines.mjs';
import { contracts } from './support/member-client-contracts.mjs';
import { fixture, SOUL } from './hq-harness.mjs';

const deferred = () => { let resolve; const promise = new Promise((done) => { resolve = done; }); return { promise, resolve }; };
const turn = () => new Promise((resolve) => setImmediate(resolve));
const binding = 'MEMBER_BINDING_CANARY';
const nonce = 'ab'.repeat(32);
const build = (freshness) => ({ ...freshness });

async function world(t, { silentHello = false, silentRuntime = false, holdBind = () => false, query, helloSent, helloResult = { soul_id: SOUL, member_id: 'm_lead', role: 'lead' } } = {}) {
  const root = mkdtempSync(join(tmpdir(), 'member-abort-'));
  const sockets = new Set();
  const servers = [];
  const state = { accepted: 0, runtimes: 0, binds: 0, queries: [], frames: [] };
  const seen = Object.fromEntries(['hello', 'runtime', 'bind', 'secondBind', 'query'].map((name) => [name, deferred()]));
  const listen = async (name, receive) => {
    const path = join(root, name + '.sock');
    const server = createServer((socket) => {
      state.accepted++; sockets.add(socket); socket.on('error', () => {}); socket.on('close', () => sockets.delete(socket));
      readLines(socket, (line) => {
        const frame = JSON.parse(line); state.frames.push({ source: name, ...frame });
        receive(socket, frame, (value) => writeLine(socket, { id: frame.id, ok: true, result: value }));
      });
    });
    servers.push(server);
    await new Promise((resolve) => server.listen(path, resolve));
    return path;
  };
  const brokerSocket = await listen('broker', (socket, frame, reply) => {
    if (frame.op === 'bind.challenge') return reply({ runtime_id: 'rt_member', nonce, context: BIND_CONTEXT, algorithm: 'hmac-sha256' });
    if (frame.op === 'bind') {
      const proof = createHmac('sha256', binding).update(`${BIND_CONTEXT}\n${nonce}\nrt_member`).digest('hex');
      assert.equal(frame.payload.proof, proof);
      state.binds++; seen.bind.resolve(); if (state.binds === 2) seen.secondBind.resolve();
      if (!holdBind(state.binds)) reply({ runtime_id: 'rt_member' });
      return;
    }
    state.queries.push(frame); seen.query.resolve();
    if (query) query(socket, frame, reply, state);
  });
  const memberSocket = await listen('entry', (_socket, frame, reply) => {
    if (frame.op === 'hello') {
      seen.hello.resolve();
      if (!silentHello) { reply(helloResult); helloSent?.(); }
    } else if (frame.op === 'runtime') {
      state.runtimes++; seen.runtime.resolve();
      if (!silentRuntime) reply({ broker: brokerSocket, runtime_id: 'rt_member', channel_binding: binding, installation_epoch: 1, lease_generation: state.runtimes });
    } else assert.fail(`unexpected entry request ${frame.op}`);
  });
  const closed = async () => {
    await Promise.all([...sockets].map((socket) => socket.destroyed ? undefined : new Promise((resolve) => socket.once('close', resolve))));
    await turn();
  };
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await Promise.all(servers.map((server) => new Promise((resolve) => server.close(resolve))));
    rmSync(root, { recursive: true, force: true });
  });
  return { options: { memberSocket, memberToken: 'MEMBER_TOKEN_CANARY', contracts }, state, seen, closed };
}

test('already-aborted bootstrap and local connection open no socket and add no listener', async (t) => {
  const w = await world(t);
  const controller = new AbortController();
  const reason = new Error('already stopped'); controller.abort(reason);
  await assert.rejects(connectMemberQueries({ ...w.options, signal: controller.signal }), (error) => error === reason);
  assert.throws(() => connectHq(w.options.memberSocket, { contracts, signal: controller.signal }), (error) => error === reason);
  await turn();
  assert.equal(w.state.accepted, 0);
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
});

test('aborting silent initial hello closes bootstrap without a capability or broker request', { timeout: 2000 }, async (t) => {
  const w = await world(t, { silentHello: true });
  const controller = new AbortController(); const reason = new Error('MCP EOF');
  const refused = assert.rejects(connectMemberQueries({ ...w.options, signal: controller.signal }), (error) => error === reason);
  await w.seen.hello.promise; controller.abort(reason);
  await refused; await w.closed();
  assert.deepEqual(w.state.frames.map((frame) => frame.op), ['hello']);
  assert.equal(w.state.accepted, 1);
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
});

test('abort racing hello completion refuses publication and cleans socket listeners', { timeout: 2000 }, async (t) => {
  const controller = new AbortController(); const reason = new Error('shutdown at hello');
  const w = await world(t, { helloSent: () => controller.abort(reason) });
  await assert.rejects(connectMemberQueries({ ...w.options, signal: controller.signal }), (error) => error === reason);
  await w.closed();
  assert.deepEqual(w.state.frames.map((frame) => frame.op), ['hello']);
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
});

test('abort during runtime discovery or bind refuses capture and prevents reopening', { timeout: 3000 }, async (t) => {
  for (const phase of ['runtime', 'bind']) {
    const w = await world(t, { silentRuntime: phase === 'runtime', holdBind: () => phase === 'bind' });
    const controller = new AbortController(); const reason = new Error('stop ' + phase);
    const member = await connectMemberQueries({ ...w.options, signal: controller.signal });
    let builds = 0;
    const refused = assert.rejects(member.queries.request('notices.peek', (freshness) => { builds++; return build(freshness); }, { replay: 'read-once' }), (error) => error === reason);
    await w.seen[phase].promise; controller.abort(reason);
    await refused; await w.closed();
    const frames = w.state.frames.length;
    await assert.rejects(member.queries.request('notices.peek', build, { replay: 'read-once' }), (error) => error === reason);
    await member.close(); await member.close();
    assert.equal(builds, 0); assert.equal(w.state.queries.length, 0); assert.equal(w.state.frames.length, frames);
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  }
});

test('aborted pending consume sends once, never replays, and closes current connections', { timeout: 2000 }, async (t) => {
  const w = await world(t);
  const controller = new AbortController(); const reason = new Error('stop after send');
  const member = await connectMemberQueries({ ...w.options, signal: controller.signal });
  const refused = assert.rejects(member.queries.request('notices.consume-one', build, { replay: 'read-once' }), (error) => error === reason);
  await w.seen.query.promise; controller.abort(reason);
  await refused; await w.closed();
  await assert.rejects(member.queries.request('notices.consume-one', build), (error) => error === reason);
  await member.close(); await member.close();
  assert.equal(w.state.queries.length, 1); assert.equal(w.state.binds, 1); assert.equal(w.state.runtimes, 1);
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
});

test('abort closes a retiring pair and its pending replacement without another read attempt', { timeout: 3000 }, async (t) => {
  const w = await world(t, {
    holdBind: (count) => count === 2,
    query: (socket, frame) => {
      if (!frame.payload.slow) writeLine(socket, { id: frame.id, ok: false, refusal: fixture('positive/error-response.stale-epoch.json').input });
    },
  });
  const controller = new AbortController(); const reason = new Error('stop replacement');
  const member = await connectMemberQueries({ ...w.options, signal: controller.signal });
  const slow = assert.rejects(member.queries.request('notices.peek', (freshness) => ({ ...freshness, slow: true }), { replay: 'read-once' }), (error) => error === reason);
  await w.seen.query.promise;
  const replacement = assert.rejects(member.queries.request('notices.peek', build, { replay: 'read-once' }), (error) => error === reason);
  await w.seen.secondBind.promise; controller.abort(reason);
  await Promise.all([slow, replacement]); await w.closed();
  await member.close();
  assert.equal(w.state.binds, 2); assert.equal(w.state.queries.length, 2); assert.equal(w.state.runtimes, 2);
  assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
});

test('manual close and abort are idempotent in either order and remove native listeners', { timeout: 2000 }, async (t) => {
  for (const abortFirst of [false, true]) {
    const w = await world(t);
    const controller = new AbortController(); const reason = new Error('close race');
    const member = await connectMemberQueries({ ...w.options, signal: controller.signal });
    if (abortFirst) controller.abort(reason);
    const closing = member.close();
    assert.equal(member.close(), closing);
    if (!abortFirst) controller.abort(reason);
    await closing; await w.closed();
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
    await assert.rejects(member.queries.request('notices.peek', build), (error) => error === reason);
    assert.equal(w.state.runtimes, 0); assert.equal(w.state.queries.length, 0);
  }
});

test('normal close and failed bootstrap remove listeners without requiring an abort', { timeout: 2000 }, async (t) => {
  for (const mode of ['normal', 'malformed', 'missingSocket']) {
    const w = await world(t, mode === 'malformed' ? { helloResult: null } : {});
    const controller = new AbortController();
    if (mode === 'malformed') await assert.rejects(connectMemberQueries({ ...w.options, signal: controller.signal }), /invalid member identity/);
    else if (mode === 'missingSocket') await assert.rejects(connectMemberQueries({ ...w.options, memberSocket: w.options.memberSocket + '.missing', signal: controller.signal }));
    else {
      const member = await connectMemberQueries({ ...w.options, signal: controller.signal });
      await member.close();
    }
    await w.closed();
    assert.equal(controller.signal.aborted, false);
    assert.equal(getEventListeners(controller.signal, 'abort').length, 0);
  }
});

test('abort during payload construction prevents the first destructive send', { timeout: 2000 }, async (t) => {
  const w = await world(t);
  const controller = new AbortController(); const reason = new Error('stop before send');
  const member = await connectMemberQueries({ ...w.options, signal: controller.signal });
  await assert.rejects(member.queries.request('notices.consume-one', (freshness) => {
    controller.abort(reason); return build(freshness);
  }, { replay: 'read-once' }), (error) => error === reason);
  await member.close(); await w.closed();
  assert.equal(w.state.binds, 1); assert.equal(w.state.queries.length, 0);
});
