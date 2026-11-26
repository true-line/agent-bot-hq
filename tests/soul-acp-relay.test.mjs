import test from 'node:test';
import assert from 'node:assert/strict';
import { PassThrough } from 'node:stream';
import { relaySoulAcp } from '../hq/soul-acp-relay.mjs';

test('ACP input error closes the HQ owner connection instead of leaving the runner attached', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const socket = new PassThrough();
  const relaying = relaySoulAcp(input, output, socket);
  input.emit('error', new Error('private fixture detail'));
  await assert.rejects(relaying, /Soul ACP input failed/);
  assert.equal(socket.destroyed, true);
  assert.equal(input.listenerCount('error'), 0);
});

test('ACP output error also closes the HQ owner connection', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const socket = new PassThrough();
  const relaying = relaySoulAcp(input, output, socket);
  output.emit('error', new Error('private fixture detail'));
  await assert.rejects(relaying, /Soul ACP output failed/);
  assert.equal(socket.destroyed, true);
});

test('ordinary owner connection close releases the ACP relay without an error', async () => {
  const input = new PassThrough();
  const output = new PassThrough();
  const socket = new PassThrough();
  const relaying = relaySoulAcp(input, output, socket);
  socket.destroy();
  await relaying;
  assert.equal(input.listenerCount('error'), 0);
});
