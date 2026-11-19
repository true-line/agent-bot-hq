import test from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { chmodSync, existsSync, lstatSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { join } from 'node:path';
import { createHQ } from '../hq/hq.mjs';
import { legacyDaemon } from '../hq/legacy.mjs';
import { connectSocket } from '../hq/socket.mjs';
import { backendFromConfig, createSigner, jwkThumbprint } from '../hq/signer.mjs';
import { signatureBytes } from '../hq/identity-service.mjs';
import { machineCommandInHome } from '../hq/machine-channel.mjs';
import { createMachineSigner } from '../hq/machine-device.mjs';
import { decideApproval } from '../sdk/services.mjs';
import { fakeIdentityService } from './identity-service-fixture.mjs';
import { schemas, fakeLegacy, tempHome } from './hq-harness.mjs';

const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const b64 = (v) => Buffer.from(JSON.stringify(v)).toString('base64url');

test('paired HQ enrolls through admin custody, retries lost binding, and authenticates its saved grant on restart', async (t) => {
  const role = tempHome(), home = tempHome();
  const service = await fakeIdentityService();
  t.after(() => service.close());
  const socket = join(role, 'machine.sock');
  const machine = generateKeyPairSync('ed25519'), device = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = device.publicKey.export({ format: 'jwk' });
  const identity = { jwk, thumbprint: jwkThumbprint(jwk), generation: 1, key_storage: 'hardware', hq_epoch: 'ab'.repeat(32) };
  const run = (args, fields) => machineCommandInHome(args, role, process.getuid(), fields);
  const client = await run(['identity']);
  const clientKey = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(client.public_key, 'hex')]), type: 'spki', format: 'der' });
  let binding, lostReply = true, receiptJti, accessJti, session, revoked = false;
  const options = [];
  const handler = createServer((stream) => {
    let line = '';
    stream.setEncoding('utf8');
    stream.on('data', (chunk) => {
      line += chunk;
      if (!line.endsWith('\n')) return;
      const r = JSON.parse(line);
      const parts = [r.verb, '', r.option ?? '', '', '', '', '', '', r.timestamp, r.nonce];
      let state = 'reported', body = {};
      if (r.verb === 'hq-device') {
        options.push(r.option);
        if (r.option !== 'identity') { assert.equal(r.hq_epoch, identity.hq_epoch); parts.push('hq_epoch', r.hq_epoch); }
        if (r.option === 'identity') {
          state = 'identity'; body = { ...identity, ...binding };
        } else if (r.option === 'enrollment-proof') {
          const bytes = b64({ typ: 'ab-enroll+jwt', alg: 'ES256', jwk }) + '.' + b64({
            aud: service.url + '/oauth/device_authorization', iat: Math.floor(Date.now() / 1000), jti: randomBytes(16).toString('base64url'),
          });
          const proof = bytes + '.' + sign('sha256', Buffer.from(bytes), { key: device.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
          state = 'proved'; body = { ...identity, proof }; receiptJti = 'enroll-v1:' + hash(proof);
        } else if (r.option === 'access-assertion') {
          const ephemeralJwk = generateKeyPairSync('ec', { namedCurve: 'P-256' }).publicKey.export({ format: 'jwk' });
          session = jwkThumbprint(ephemeralJwk);
          accessJti = randomBytes(16).toString('base64url');
          const iat = Math.floor(Date.now() / 1000);
          const input = b64({ typ: 'JWT', alg: 'ES256' }) + '.' + b64({ iss: binding.device_id, sub: binding.device_id,
            aud: service.url + '/oauth/token', iat, exp: iat + 120, jti: accessJti, cnf: { jwk: ephemeralJwk } });
          state = 'asserted'; body = { ...identity, assertion: input + '.' + sign('sha256', Buffer.from(input), { key: device.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url') };
        } else {
          assert.ok(['bind-enrollment', 'bind-access'].includes(r.option));
          for (const field of ['receipt_body', 'receipt_jti', 'receipt_kid', 'receipt_signature']) parts.push(field, r[field]);
          const bytes = Buffer.from(r.receipt_body, 'base64url');
          const expectedJti = r.option === 'bind-access' ? accessJti : receiptJti;
          assert.equal(r.receipt_jti, expectedJti);
          assert.equal(r.receipt_kid, service.key.kid);
          assert.ok(verify(null, signatureBytes(200, bytes, expectedJti), createPublicKey({
            key: { kty: 'OKP', crv: 'Ed25519', x: service.key.x }, format: 'jwk',
          }), Buffer.from(r.receipt_signature, 'base64url')));
          if (r.option === 'bind-access') {
            assert.equal(JSON.parse(bytes).access_token, 'disposable-fixture-token');
            state = 'access-bound'; body = { session, expires_at: Math.floor(Date.now() / 1000) + 300, hq_epoch: identity.hq_epoch };
          } else {
            binding = { device_id: JSON.parse(bytes).device_id, receipt_jti: receiptJti, receipt_sha256: hash(bytes) };
            state = 'bound'; body = { ...identity, ...binding };
          }
        }
      }
      assert.equal(r.public_key, Buffer.from(client.public_key, 'hex').toString('base64'));
      assert.ok(verify(null, Buffer.from(parts.join('\n')), clientKey, Buffer.from(r.signature, 'base64')));
      if (r.option === 'bind-enrollment' && lostReply) { lostReply = false; stream.destroy(); return; }
      const response = { ok: !revoked, ...(revoked && { diagnostic: 'MM_DAEMON_UNKNOWN_KEY' }), state, body, timestamp: r.timestamp, nonce: randomBytes(16).toString('base64url'), request_nonce: r.nonce };
      response.signature = sign(null, Buffer.from([response.ok, response.diagnostic ?? '', '', state, JSON.stringify(body), r.timestamp, response.nonce, r.nonce].join('\n')), machine.privateKey).toString('base64');
      stream.end(JSON.stringify(response) + '\n');
    });
  });
  await new Promise((resolve, reject) => handler.once('error', reject).listen(socket, resolve));
  t.after(() => new Promise((resolve) => handler.close(resolve)));
  const request = (option, fields) => run(['hq-device', option, '--socket', socket], fields);
  await assert.rejects(request('identity'), /requires the daemon pin/);
  const machineKey = machine.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  await run(['status', '--socket', socket, '--daemon-key', machineKey.toString('hex')]);
  const open = async (config = {}) => {
    const hq = createHQ({ home, schemas, config: { enrollment: { source: 'hq', server: service.url }, ...config },
      serverKeys: [service.key], createDeviceSigner: (opts) => createMachineSigner({ ...opts, request, keysFor: () => [service.key] }),
      legacy: legacyDaemon({ run: fakeLegacy().run }),
    });
    const status = await hq.start();
    const owner = await connectSocket(hq.paths.control);
    return { hq, status, owner, close: async () => { await owner.close(); await hq.stop(); } };
  };
  let active = await open();
  t.after(async () => { try { await active?.close(); } finally { for (const dir of [home, role]) rmSync(dir, { recursive: true, force: true }); } });
  assert.equal(active.status.mode, 'safe');
  const consoleStatus = async () => (await promisify(execFile)(process.execPath, [
    fileURLToPath(new URL('../hq/main.mjs', import.meta.url)), 'status', '--home', home,
  ])).stdout;
  const offer = () => active.owner.request('device.enroll', { harnesses: ['codex'] });
  assert.equal((await offer()).result.pending, true);
  const [grant] = service.state.grants.values();
  grant.receiptErrors = ['credential_unavailable', 'temporarily_unavailable'];
  service.decide('approved');
  await active.hq.core.signer.enrollment.settled();
  assert.deepEqual(grant.receiptErrors, []);
  assert.equal(service.state.grants.size, 1);
  assert.equal(service.state.devices.length, 1);
  assert.equal(existsSync(join(home, 'identity/device.json')), false);
  assert.equal(existsSync(join(home, 'identity/pending-receipt.json')), true);
  await active.close(); active = null;
  active = await open();
  assert.equal((await offer()).result.state, 'approved');
  assert.equal(options.filter((name) => name === 'enrollment-proof').length, 1);
  assert.equal(options.filter((name) => name === 'bind-enrollment').length, 2);
  await active.close(); active = null;
  active = await open();
  assert.equal(active.status.mode, 'running');
  assert.equal(active.status.profile, 'managed-cooperative');
  assert.equal(active.status.hq.signer.backend, 'machine');
  assert.equal(active.status.hq.features.hardwareSigner, false);
  const statusText = await consoleStatus();
  assert.match(statusText, /^signer: hardware key, paired Machine\/keyd backend, key /m);
  assert.doesNotMatch(statusText, /hardwareSigner|experimental feature/);
  assert.equal(existsSync(join(home, 'signer')), false);
  await assert.rejects(active.hq.core.identity.call('GET', '/api/daemon/issuances/example-op'), /no authorized DPoP action/);
  assert.ok(options.includes('access-assertion') && options.includes('bind-access'));
  assert.equal(service.state.requests.filter((r) => r.url.includes('/api/daemon/')).length, 0);
  await assert.rejects(active.hq.core.identity.call('POST', '/api/daemon/credentials', {}), /administrator-side credential use/);
  const trap = join(home, 'standalone-invoked');
  const localHelper = { backend: 'helper', command: [process.execPath, '-e',
    "require('node:fs').appendFileSync(process.argv[1], 'called\\n')", trap] };
  async function checkNoFallback() {
    assert.equal(existsSync(join(home, 'signer/device-key.pem')), false);
    await assert.rejects(open({ signer: localHelper, features: { hardwareSigner: true } }), /paired Machine backend/);
    await assert.rejects(open({ standalone: true, signer: { backend: 'secure-enclave' } }),
      /verified dedicated-account installation without Agent Machine/);
    assert.equal(existsSync(trap), false, 'the local helper must never run');
  }
  await checkNoFallback();
  await active.close(); active = null;
  await new Promise((resolve) => handler.close(resolve));
  active = await open();
  assert.equal(active.status.mode, 'safe');
  assert.equal(active.status.hq.signer.available, false);
  await checkNoFallback();
  await active.close(); active = null;
  await new Promise((resolve, reject) => handler.once('error', reject).listen(socket, resolve));
  active = await open();
  assert.equal(active.status.mode, 'running');
  await checkNoFallback();
  await active.close(); active = null;
  revoked = true;
  active = await open();
  assert.equal(active.status.mode, 'safe');
  assert.match(active.status.hq.signer.reason, /MM_DAEMON_UNKNOWN_KEY/);
  assert.match(await consoleStatus(), /^signer: paired Machine\/keyd unavailable \(.*MM_DAEMON_UNKNOWN_KEY/m);
  await checkNoFallback();
  await active.close(); active = null;
  revoked = false;
  active = await open();
  const stored = JSON.parse(readFileSync(join(home, 'identity/device.json')));
  assert.equal(stored.device_id, binding.device_id);
  assert.equal(active.hq.core.signer.enrollment.allowsHarness('codex'), true);
  const approvedBytes = Buffer.from('appr_fixture\n' + 'ab'.repeat(32) + '\napproved');
  const signature = 'hq-sig-v1.' + identity.thumbprint + '.' + sign('sha256', approvedBytes,
    { key: device.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
  assert.equal(await active.hq.core.signer.verify(approvedBytes, signature), true);
  assert.equal(await active.hq.core.signer.verify(Buffer.from('different decision'), signature), false);
  stored.harnesses.push('unapproved');
  writeFileSync(join(home, 'identity/device.json'), JSON.stringify(stored));
  assert.equal(active.hq.core.signer.enrollment.allowsHarness('unapproved'), false);
  assert.equal(await active.hq.core.signer.deviceStatus(), 'unenrolled');
  active.hq.core.approvals.set('pending', { id: 'pending', digest: 'digest', state: 'pending' });
  assert.throws(() => decideApproval(active.hq.core, 'pending', 'approved'), /Machine approval-record/);
  assert.equal(active.hq.core.approvals.get('pending').state, 'pending');
});

test('paired upgrade reports prior signer and enrollment files through HQ status without opening them', async t => {
  const home = tempHome();
  let hq;
  t.after(async () => { try { await hq?.stop(); } finally { rmSync(home, { recursive: true, force: true }); } });
  // The earlier HQ default created this key and pin on its first status report.
  const previous = createSigner({ home, backend: backendFromConfig({}, { home }) });
  assert.equal(previous.report().backend, 'software');
  const key = join(home, 'signer/device-key.pem');
  const pin = join(home, 'signer/pin.json');
  const grant = join(home, 'identity/device.json');
  const pending = join(home, 'identity/pending-receipt.json');
  const past = join(home, 'identity/device.previous.json');
  const oldKey = lstatSync(key);
  // Presence detection must work even when the probe cannot open the key.
  chmodSync(key, 0);
  hq = createHQ({ home, schemas, legacy: legacyDaemon({ run: fakeLegacy().run }) });
  const first = await hq.start();
  assert.equal(first.mode, 'safe');
  assert.equal(first.hq.signer.available, false);
  assert.match(first.hq.signer.reason, /Found signer\/device-key.pem, signer\/pin.json\./);
  assert.match(first.hq.signer.reason, /No local entry for identity\/device.json, identity\/device.previous.json, identity\/pending-receipt.json\./);
  assert.match(first.hq.signer.reason, /Verify enrollment history/);
  const noRequest = () => assert.fail('legacy state must refuse before delegating');
  const signer = createMachineSigner({ home, request: noRequest, enrollment: () => ({
    progress: () => assert.fail('paused status must not read the historical enrollment record'),
  }) });
  await assert.rejects(signer.deviceStatus(), /Paired custody upgrade paused/);
  assert.equal(signer.enrollmentProgress(), undefined);

  mkdirSync(join(home, 'identity'), { mode: 0o700 });
  // The issuer key can be pinned before the service grants enrollment.
  writeFileSync(join(home, 'identity/server-key.json'), '{}', { mode: 0o600 });
  assert.equal(signer.report().reason, first.hq.signer.reason);
  for (const f of [grant, past, pending]) writeFileSync(f, 'private fixture contents', { mode: 0 });
  const owner = await connectSocket(hq.paths.control);
  try {
    const status = (await owner.request('status')).result.hq;
    assert.equal(status.enrollment, undefined);
    const report = status.signer;
    assert.equal(report.available, false);
    assert.match(report.reason, /Found signer\/device-key.pem, signer\/pin.json, identity\/device.json, identity\/device.previous.json, identity\/pending-receipt.json/);
    assert.ok(!report.reason.includes(home) && !report.reason.includes('private fixture contents'));
  } finally { await owner.close(); }

  if (process.getuid?.() > 0) {
    const dir = join(home, 'identity');
    chmodSync(dir, 0);
    try {
      const report = signer.report();
      assert.match(report.reason, /Could not safely inspect identity\/device.json, identity\/device.previous.json, identity\/pending-receipt.json/);
      assert.doesNotMatch(report.reason, /No local entry for identity/);
    } finally { chmodSync(dir, 0o700); }
    const keyDir = join(home, 'signer');
    chmodSync(keyDir, 0);
    try {
      await assert.rejects(signer.deviceStatus(), /Could not safely inspect signer\/device-key.pem, signer\/pin.json/);
    } finally { chmodSync(keyDir, 0o700); }
  }
  assert.equal(lstatSync(key).ino, oldKey.ino);
  assert.equal(lstatSync(key).mtimeMs, oldKey.mtimeMs);
  assert.equal(lstatSync(pin).isFile(), true);
});
