import assert from 'node:assert/strict';
import { once } from 'node:events';
import { createHash, createPublicKey, generateKeyPairSync, sign, verify } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { machineCommandInHome } from '../hq/machine-channel.mjs';
import { createMachineSigner } from '../hq/machine-device.mjs';
import { jwkThumbprint } from '../hq/signer.mjs';

test('paired qualification captures the fixed signed request, Machine refusal and definite socket outage', async (t) => {
  const home = mkdtempSync(join(tmpdir(), 't02-hq-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const socket = join(home, 'machine.sock');
  const uid = process.getuid();
  const pair = generateKeyPairSync('ed25519');
  const daemon = pair.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32).toString('hex');
  const run = (args, fields, nonce, ordinary = false) => machineCommandInHome(args, home, uid,
    fields, ordinary, uid, undefined, nonce);
  const identity = await run(['identity']);
  const hqKey = createPublicKey({
    key: Buffer.from('302a300506032b6570032100' + identity.public_key, 'hex'), format: 'der', type: 'spki',
  });

  let lastRequest;
  let lastResponse;
  let signatureValid = true;
  let revoked = false;
  const server = createServer(stream => {
    stream.setEncoding('utf8');
    let wire = '';
    stream.on('data', chunk => {
      wire += chunk;
      if (!wire.endsWith('\n')) return;
      lastRequest = wire.slice(0, -1);
      const request = JSON.parse(lastRequest);
      const timestamp = Math.floor(Date.now() / 1000);
      const nonce = 'machine-reply';
      const response = request.verb === 'status' ? { ok: true, state: 'reported' }
        : revoked ? { ok: false, diagnostic: 'MM_DAEMON_PEER_REFUSED', message: 'HQ device custody requires the approved HQ pairing' }
          : { ok: true, state: 'proved', body: { proof: 'example-wire-signature' } };
      const body = response.body ? JSON.stringify(response.body) : '';
      const bytes = [response.ok, response.diagnostic ?? '', response.message ?? '', response.state ?? '',
        body, timestamp, nonce, request.nonce].join('\n');
      const signature = sign(null, Buffer.from(bytes), pair.privateKey);
      if (!signatureValid) signature[0] ^= 1;
      lastResponse = JSON.stringify({ ...response, timestamp, nonce, request_nonce: request.nonce,
        signature: signature.toString('base64') });
      stream.end(lastResponse + '\n');
    });
  });
  server.listen(socket);
  await once(server, 'listening');
  t.after(() => server.close());
  await run(['status', '--socket', socket, '--daemon-key', daemon]);

  const epoch = 'a'.repeat(64);
  const nonce = Buffer.alloc(16, 7).toString('base64url');
  const fields = { hq_epoch: epoch };
  const args = ['hq-device', 'enrollment-proof', '--socket', socket];
  const captured = await run(args, fields, nonce);
  assert.deepEqual(captured, { requestRaw: lastRequest, responseRaw: lastResponse });
  assert.deepEqual(JSON.parse(lastRequest), {
    verb: 'hq-device', option: 'enrollment-proof', hq_epoch: epoch,
    timestamp: JSON.parse(lastRequest).timestamp, nonce, public_key: Buffer.from(identity.public_key, 'hex').toString('base64'),
    signature: JSON.parse(lastRequest).signature,
  });

  revoked = true;
  const revokedNonce = Buffer.alloc(16, 9).toString('base64url');
  assert.equal(JSON.parse((await run(args, fields, revokedNonce)).responseRaw).diagnostic, 'MM_DAEMON_PEER_REFUSED');
  await assert.rejects(run(args, fields), { code: 'credential_unavailable' });
  signatureValid = false;
  await assert.rejects(run(args, fields, nonce), /signature does not match/);
  await assert.rejects(run(['hq-device', 'access-assertion', '--socket', socket], fields, nonce),
    /fixed paired enrollment proof/);
  await assert.rejects(run(args, fields, nonce, true), /fixed paired enrollment proof/);

  const closed = once(server, 'close');
  server.close();
  await closed;
  const isolated = await run(args, fields, nonce);
  assert.deepEqual(Object.keys(isolated).sort(), ['outageSignature', 'requestRaw']);
  assert.equal(JSON.parse(isolated.requestRaw).nonce, nonce);
  const requestHash = createHash('sha256').update(isolated.requestRaw).digest('hex');
  const payload = Buffer.from(['agent-bot-hq/t02-machine-outage/v1', requestHash, 'machine-unreachable'].join('\n'));
  assert.ok(verify(null, payload, hqKey, Buffer.from(isolated.outageSignature, 'base64')));
  await assert.rejects(run(args, fields), { code: 'credential_unavailable' });
});


test('the paired signer checks custody and the fixed proof before exposing a qualification capture', async (t) => {
  const home = mkdtempSync(join(tmpdir(), 't02-signer-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const publicDevice = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicDevice.publicKey.export({ format: 'jwk' });
  const identity = { jwk, hq_epoch: 'a'.repeat(64), key_storage: 'hardware', generation: 1, thumbprint: jwkThumbprint(jwk) };
  const now = 1_795_440_000;
  const nonce = Buffer.alloc(16, 1).toString('base64url');
  let returnedAudience = 'https://agents.true-line.ai/oauth/device_authorization';
  let refused = false;
  const encoded = value => Buffer.from(JSON.stringify(value)).toString('base64url');
  const signer = createMachineSigner({
    home,
    enrollment: () => ({ deviceStatus: () => 'unenrolled' }),
    clock: { now: () => now * 1000 },
    request: async (option) => {
      assert.equal(option, 'identity');
      return { state: 'identity', body: identity };
    },
    capture: async (epoch, caseNonce) => {
      assert.equal(epoch, identity.hq_epoch);
      assert.equal(caseNonce, nonce);
      if (refused) return { requestRaw: 'signed request', outageSignature: 'signed refusal' };
      const payload = [encoded({ alg: 'ES256', typ: 'ab-enroll+jwt', jwk }),
        encoded({ aud: returnedAudience, iat: now, jti: 'a-fresh-case-proof' })].join('.');
      const signature = sign('sha256', Buffer.from(payload), {
        key: publicDevice.privateKey, dsaEncoding: 'ieee-p1363',
      }).toString('base64url');
      const response = { ok: true, state: 'proved', body: { ...identity, proof: payload + '.' + signature } };
      return { requestRaw: 'signed request', responseRaw: JSON.stringify(response) };
    },
  });
  await assert.rejects(signer.captureT02EnrollmentProof(nonce), { code: 'credential_unavailable' });
  await signer.deviceStatus();
  assert.equal(JSON.parse((await signer.captureT02EnrollmentProof(nonce)).responseRaw).state, 'proved');
  returnedAudience = 'https://example.com';
  await assert.rejects(signer.captureT02EnrollmentProof(nonce), /audience/);
  refused = true;
  assert.equal((await signer.captureT02EnrollmentProof(nonce)).outageSignature, 'signed refusal');
  assert.equal(signer.report().available, false);
});
