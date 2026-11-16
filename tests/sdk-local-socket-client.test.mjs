import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { connectHq, HqRefusal } from '../sdk/local-socket-client.mjs';
import { MAX_LINE_BYTES, readLines } from '../sdk/local-socket-lines.mjs';
import { fixture, hello, startHQ } from './hq-harness.mjs';
import { contracts } from './support/member-client-contracts.mjs';
const open = (path) => connectHq(path, { contracts });
const transport = (error) => error instanceof HqRefusal && error.transport;

async function serve(t, handle) {
  const root = mkdtempSync(join(tmpdir(), 'hq-sdk-client-'));
  const path = join(root, 'test.sock');
  const sockets = new Set();
  const received = [];
  const server = createServer((socket) => {
    sockets.add(socket);
    socket.on('error', () => {});
    socket.on('close', () => sockets.delete(socket));
    let buffer = '';
    socket.on('data', (chunk) => {
      buffer += chunk.toString('utf8');
      let line;
      while ((line = buffer.indexOf('\n')) !== -1) {
        const request = JSON.parse(buffer.slice(0, line));
        buffer = buffer.slice(line + 1);
        received.push(request);
        handle(socket, request, received);
      }
    });
  });
  await new Promise((resolve) => server.listen(path, resolve));
  t.after(async () => {
    for (const socket of sockets) socket.destroy();
    await new Promise((resolve) => server.close(resolve));
    rmSync(root, { recursive: true, force: true });
  });
  return { path, received };
}

test('local SDK client speaks to the real HQ admission socket and validates the shared records', async (t) => {
  const host = await startHQ();
  t.after(() => host.done());
  const client = await open(host.hq.paths.admission);
  t.after(() => client.close());
  const result = await client.request('Hello', hello());
  assert.equal(result.contract, 'hq/v1');
  assert.equal(result.request_id, hello().request_id);
  assert.ok(result.admitted_runtimes.length > 0);
  const equipment = await client.request('Equip', { runtime_id: result.admitted_runtimes[0].runtime_id });
  assert.equal(equipment.runtime_id, result.admitted_runtimes[0].runtime_id);
});

test('missing contract validation refuses before connecting; outbound invalid records never send', async (t) => {
  assert.throws(() => connectHq('/not-opened'), /verified shared contract/);
  assert.throws(() => connectHq('/not-opened', { contracts: {} }), TypeError);
  const server = await serve(t, (socket, request) => socket.write(JSON.stringify({ id: request.id, ok: true, result: null }) + '\n'));
  const client = await open(server.path);
  t.after(() => client.close());
  for (const kind of ['Hello', 'Ready', 'Lease', 'task.commit']) await assert.rejects(client.request(kind, {}), /invalid shared record/);
  assert.equal(server.received.length, 0);
  assert.equal(await client.request('opaque', { bounded: true }), null);
  assert.deepEqual(server.received, [{ id: 5, op: 'opaque', payload: { bounded: true } }]);
});

test('request IDs correlate concurrent responses and valid refusals preserve their class', async (t) => {
  const error = fixture('positive/error-response.stale-epoch.json').input;
  contracts.record('common/v1/error-response.schema.json', error);
  const server = await serve(t, (socket, request, received) => {
    if (received.length < 2) return;
    socket.write(JSON.stringify({ id: received[1].id, ok: false, refusal: error }) + '\n');
    socket.write(JSON.stringify({ id: received[0].id, ok: true, result: { first: true } }) + '\n');
  });
  const client = await open(server.path);
  t.after(() => client.close());
  const first = client.request('opaque', {});
  const second = client.request('opaque', {});
  await assert.rejects(second, (e) => e instanceof HqRefusal && !e.transport && e.code === 'stale_epoch');
  assert.deepEqual(await first, { first: true });
});

test('malformed JSON, UTF-8, IDs and closed envelopes poison the connection', { timeout: 5000 }, async (t) => {
  for (const raw of [
    Buffer.from('{"id":1,"id":1,"ok":true,"result":{}}\n'),
    Buffer.from('{"id":1,"ok":true,"result":{},"extra":true}\n'),
    Buffer.from('{"id":999,"ok":true,"result":{}}\n'),
    Buffer.from('{"id":1,"ok":false,"host_refusal":{"code":2}}\n'),
    Buffer.from([0xef, 0xbb, 0xbf, ...Buffer.from('{"id":1,"ok":true,"result":{}}\n')]),
    Buffer.from([0xff, 0x0a]),
    Buffer.from('{"id":1,"ok":true,"result":{},}\n'),
    Buffer.from('x'.repeat(MAX_LINE_BYTES + 1) + '\n'),
  ]) {
    const server = await serve(t, (socket) => socket.write(raw));
    const client = await open(server.path);
    await assert.rejects(client.request('opaque', {}), transport);
    assert.equal(client.closed, true);
    await assert.rejects(client.request('opaque', {}), transport);
    await client.close();
    assert.equal(server.received.length, 1);
  }
});

test('malformed first reply refuses all waiters and ignores later same-chunk replies', async (t) => {
  const server = await serve(t, (socket, _request, received) => {
    if (received.length !== 2) return;
    socket.write('{"id":1,"ok":true,"result":{},"extra":true}\n{"id":2,"ok":true,"result":"must-not-pass"}\n');
  });
  const client = await open(server.path);
  const results = await Promise.allSettled([client.request('opaque', {}), client.request('opaque', {})]);
  assert.ok(results.every((result) => result.status === 'rejected' && transport(result.reason)));
  await client.close();
});

test('contract-invalid results preserve original validation failure and poison other pending replies', async (t) => {
  const server = await serve(t, (socket, _request, received) => {
    if (received.length !== 2) return;
    socket.write('{"id":1,"ok":true,"result":{"task":{}}}\n{"id":2,"ok":true,"result":"must-not-pass"}\n');
  });
  const client = await open(server.path);
  const results = await Promise.allSettled([client.request('task.get', { task_id: 'task_x' }), client.request('opaque', {})]);
  assert.match(results[0].reason.message, /invalid shared record/);
  assert.ok(transport(results[1].reason));
  await client.close();
});

test('lost replies are unknown outcomes; the local socket client never reconnects or resends', async (t) => {
  const server = await serve(t, (socket) => socket.destroy());
  const client = await open(server.path);
  await assert.rejects(client.request('notices.consume-one', { request_id: 'one' }), transport);
  await assert.rejects(client.request('notices.consume-one', { request_id: 'two' }), transport);
  assert.equal(server.received.length, 1);
  await client.close();
  await client.close();
});

test('line codec preserves split multi-byte input and latches final truncation/errors', () => {
  const stream = new PassThrough();
  const lines = [];
  const errors = [];
  readLines(stream, (line) => lines.push(line), (error) => errors.push(error));
  const bytes = Buffer.from('"λ"\n');
  stream.write(bytes.subarray(0, 2));
  stream.write(bytes.subarray(2));
  assert.deepEqual(lines, ['"λ"']);
  stream.emit('end');
  assert.equal(errors.length, 0);
  for (const bytes of [Buffer.from('unfinished'), Buffer.from([0xc3])]) {
    const broken = new PassThrough();
    let failed = 0;
    readLines(broken, () => assert.fail('no complete line'), () => { failed++; });
    broken.write(bytes);
    broken.emit('end');
    broken.write(Buffer.from('later\n'));
    assert.equal(failed, 1);
  }
});

test('async or thenable outbound validation refuses before sending and observes rejections', async (t) => {
  for (const record of [
    async () => undefined,
    async () => { throw new Error('async invalid record'); },
    () => ({ then(_resolve, reject) { reject(new Error('thenable invalid record')); } }),
  ]) {
    for (const operation of ['Hello', 'task.commit']) {
      const server = await serve(t, (socket, request) => socket.write(JSON.stringify({ id: request.id, ok: true, result: {} }) + '\n'));
      const client = await connectHq(server.path, { contracts: { ...contracts, record } });
      t.after(() => client.close());
      await assert.rejects(client.request(operation, {}), /validation must be synchronous/);
      assert.equal(server.received.length, 0);
    }
  }
});

test('synchronous adapter failures retain the original error on both socket directions', async (t) => {
  const failure = new Error('specific sync validation failure');
  const record = () => { throw failure; };
  const server = await serve(t, (socket, request) => socket.write(JSON.stringify({ id: request.id, ok: true, result: {} }) + '\n'));
  const client = await connectHq(server.path, { contracts: { ...contracts, record } });
  await assert.rejects(client.request('task.commit', {}), (error) => error === failure);
  assert.equal(server.received.length, 0);
  await assert.rejects(client.request('Equip', {}), (error) => error === failure);
  assert.equal(client.closed, true);
  await client.close();
});

test('async or thenable inbound validation poisons the connection without accepting a result', async (t) => {
  for (const validation of [
    async () => undefined,
    async () => { throw new Error('async invalid response'); },
    () => ({ then(_resolve, reject) { reject(new Error('thenable invalid response')); } }),
  ]) {
    for (const operation of ['Equip', 'Hello']) {
      const server = await serve(t, (socket, request) => socket.write(JSON.stringify({ id: request.id, ok: true, result: {} }) + '\n'));
      const adapter = { ...contracts, ...(operation === 'Hello' ? { admission: validation } : { record: validation }) };
      const client = await connectHq(server.path, { contracts: adapter });
      await assert.rejects(client.request(operation, operation === 'Hello' ? hello() : {}), /validation must be synchronous/);
      assert.equal(client.closed, true);
      assert.equal(server.received.length, 1);
      await client.close();
    }
  }
});
