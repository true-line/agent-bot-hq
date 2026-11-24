import test from 'node:test';
import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, sign, verify, createPublicKey } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { machineCommandInHome } from '../hq/machine-channel.mjs';

test('T03 positive, ready and completion use the pinned signed Machine channel', async (t) => {
  const home = mkdtempSync(join(tmpdir(), 'hq-t03-channel-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const socket = join(home, 'machine.sock');
  const identity = await machineCommandInHome(['identity'], home, process.getuid());
  const hqPublic = createPublicKey({ key: Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(identity.public_key, 'hex'),
  ]), format: 'der', type: 'spki' });
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  writeFileSync(join(home, '.config/agent-machine/daemon.pub'),
    publicKey.export({ format: 'der', type: 'spki' }).subarray(12), { mode: 0o600 });
  const seen = [];
  const server = createServer((stream) => {
    let line = '';
    stream.on('data', (chunk) => {
      line += chunk;
      if (!line.includes('\n')) return;
      try {
        const request = JSON.parse(line.slice(0, line.indexOf('\n')));
        const fields = JSON.parse(Buffer.from(request.stage2a_request, 'base64url').toString('utf8'));
        const signed = [request.verb, '', '', '', '', '', '', '', request.timestamp, request.nonce,
          'stage2a_request', request.stage2a_request].join('\n');
        assert.equal(verify(null, Buffer.from(signed), hqPublic,
          Buffer.from(request.signature, 'base64')), true);
        seen.push({ verb: request.verb, fields });
        const state = { 'stage2a-t03-positive': 't03-positive-recorded',
          'stage2a-t03-ready': 't03-ready-observed',
          'stage2a-t03-complete': 't03-completion-recorded' }[request.verb];
        const body = request.verb === 'stage2a-t03-ready' ? { accepted: true }
          : { sha256: `sha256:${'a'.repeat(64)}` };
        const response = { ok: true, state, body, timestamp: request.timestamp,
          nonce: randomBytes(16).toString('base64url'), request_nonce: request.nonce };
        response.signature = sign(null, Buffer.from([true, '', '', state, JSON.stringify(body),
          response.timestamp, response.nonce, response.request_nonce].join('\n')), privateKey).toString('base64');
        stream.end(JSON.stringify(response) + '\n');
      } catch (error) { stream.destroy(error); }
    });
  });
  await new Promise((resolve, reject) => server.once('error', reject).listen(socket, resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const run = (verb, request) => machineCommandInHome([verb, '--socket', socket], home,
    process.getuid(), request);
  const base = { reservation_sha256: `sha256:${'1'.repeat(64)}`,
    installation_id: 'installation-1', start_id: `st_${'2'.repeat(24)}`,
    launch_id: `ln_${'3'.repeat(24)}`, plan_id: 'plan-1',
    plan_digest: '4'.repeat(64), hq_epoch: '5'.repeat(64) };
  assert.equal((await run('stage2a-t03-positive', { ...base, receipt: { schema: 'receipt' } })).sha256,
    `sha256:${'a'.repeat(64)}`);
  assert.equal((await run('stage2a-t03-ready', { ...base, ready: { schema: 'ready' } })).accepted,
    true);
  assert.equal((await run('stage2a-t03-complete', { ...base, result: { schema: 'result' },
    network: { schema: 'network' } })).sha256, `sha256:${'a'.repeat(64)}`);
  assert.deepEqual(seen.map(({ verb }) => verb), ['stage2a-t03-positive',
    'stage2a-t03-ready', 'stage2a-t03-complete']);
  assert.deepEqual(seen.map(({ fields }) => Object.keys(fields)), [
    [...Object.keys(base), 'receipt'], [...Object.keys(base), 'ready'],
    [...Object.keys(base), 'result', 'network'],
  ]);
  await assert.rejects(run('stage2a-t03-positive', { ...base, receipt: 'untrusted' }),
    /invalid Stage 2a Machine reservation selectors/);
  assert.equal(seen.length, 3);
});
