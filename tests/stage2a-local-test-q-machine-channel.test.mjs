import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { machineCommandInHome } from '../hq/machine-channel.mjs';

const planId = 'plan-20261124T120001Z-abcd';
const digest = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;

test('Q issue signs the one-field selector and verifies the paired response nonce', async (t) => {
  const home = mkdtempSync(join(tmpdir(), 'hq-q-issue-channel-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const socket = join(home, 'machine.sock');
  const identity = await machineCommandInHome(['identity'], home, process.getuid());
  const hqKey = createPublicKey({ key: Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(identity.public_key, 'hex'),
  ]), format: 'der', type: 'spki' });
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  writeFileSync(join(home, '.config/agent-machine/daemon.pub'),
    publicKey.export({ format: 'der', type: 'spki' }).subarray(12), { mode: 0o600 });
  const envelope = Buffer.from('signed-envelope-fixture');
  const body = { plan_id: planId, plan_sha256: digest(Buffer.from('plan')),
    approval_envelope_base64url: envelope.toString('base64url'),
    approval_envelope_sha256: digest(envelope) };
  let wrongNonce = false;
  const seen = [];
  const server = createServer((stream) => {
    let raw = '';
    stream.on('data', (chunk) => {
      raw += chunk;
      if (!raw.includes('\n')) return;
      try {
        const request = JSON.parse(raw.slice(0, raw.indexOf('\n')));
        const selector = Buffer.from(request.stage2a_request, 'base64url').toString('utf8');
        assert.equal(request.verb, 'stage2a-local-test-q-issue-v1');
        assert.equal(selector, JSON.stringify({ plan_id: planId }));
        const preimage = [request.verb, '', '', '', '', '', '', '', request.timestamp,
          request.nonce, 'stage2a_request', request.stage2a_request].join('\n');
        assert.equal(verify(null, Buffer.from(preimage), hqKey,
          Buffer.from(request.signature, 'base64')), true);
        seen.push(request.nonce);
        const response = { ok: true, state: 'local-test-q-issued', body,
          timestamp: request.timestamp, nonce: randomBytes(16).toString('base64url'),
          request_nonce: wrongNonce ? randomBytes(16).toString('base64url') : request.nonce };
        response.signature = sign(null, Buffer.from([true, '', '', response.state,
          JSON.stringify(body), response.timestamp, response.nonce,
          response.request_nonce].join('\n')), privateKey).toString('base64');
        stream.end(JSON.stringify(response) + '\n');
      } catch (error) { stream.destroy(error); }
    });
  });
  await new Promise((resolve, reject) => server.once('error', reject).listen(socket, resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const call = (id) => machineCommandInHome(['stage2a-local-test-q-issue-v1', '--socket', socket],
    home, process.getuid(), { plan_id: id });
  const result = await call(planId);
  assert.equal(result.plan_id, planId);
  assert.equal(result.approval_envelope_sha256, body.approval_envelope_sha256);
  await assert.rejects(call('../other'), /invalid Stage 2a Machine reservation selectors/);
  assert.equal(seen.length, 1);
  wrongNonce = true;
  await assert.rejects(call(planId), /invalid or stale Machine/);
  assert.equal(seen.length, 2);
  assert.notEqual(seen[0], seen[1]);
});
