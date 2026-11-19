// HQ's own enrollment (plan §9 row 15c; hq/enrollment.mjs): the device-code
// grant against a stand-in identity service, signed by the HQ signer's key.
import { test } from 'node:test';
import { spawn } from 'node:child_process';
import { once } from 'node:events';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import assert from 'node:assert/strict';
import { createPublicKey, generateKeyPairSync, verify as cryptoVerify } from 'node:crypto';
import { chmodSync, existsSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { validateConfig } from '../hq/hq.mjs';
import { createEnrollment, validateServiceUrl } from '../hq/enrollment.mjs';
import { createSigner, softwareKeyBackend } from '../hq/signer.mjs';
import { connectSocket } from '../hq/socket.mjs';
import { startHQ, tempHome } from './hq-harness.mjs';
import { fakeIdentityService } from './identity-service-fixture.mjs';

const fast = () => new Promise((r) => setTimeout(r, 5));
const setup = (home, svc, events = []) => createSigner({
  home,
  backend: softwareKeyBackend({ dir: join(home, 'signer') }),
  enrollment: (signer) => createEnrollment({ home, signer, server: svc.url, sleep: fast, deviceName: 'test-host', platform: 'linux', onEvent: (e) => events.push(e) }),
});
const until = async (fn) => { for (let i = 0; i < 400; i++) { if (await fn()) return; await fast(); } throw new Error('timed out'); };

test('enroll: the proof is signed by the signer\'s key, the owner approves, and the device record names that key', async () => {
  const svc = await fakeIdentityService();
  const home = tempHome();
  const events = [];
  try {
    const signer = setup(home, svc, events);
    assert.equal(await signer.deviceStatus(), 'unenrolled');
    const thumbprint = signer.report().thumbprint;

    const started = await signer.enroll({ harnesses: ['claude-code'] });
    assert.deepEqual([started.pending, started.state, started.user_code, started.key_thumbprint, started.key_storage], [true, 'pending', 'WXYZ-1234', thumbprint, 'software']);
    assert.match(started.verification_uri_complete, /code=WXYZ-1234$/);
    assert.equal((await signer.enroll({ harnesses: ['claude-code'] })).user_code, 'WXYZ-1234', 'a second ask reports the grant in flight');
    assert.equal(svc.state.grants.size, 1);
    assert.equal(await signer.deviceStatus(), 'unenrolled', 'nothing is enrolled before approval');

    svc.decide('approved');
    await signer.enrollment.settled();
    const rec = JSON.parse(readFileSync(join(home, 'identity/device.json'), 'utf8'));
    assert.deepEqual([rec.device_id, rec.jkt, rec.key_storage, rec.server, rec.device_name, rec.platform, rec.server_key_id], ['dev_1', thumbprint, 'software', svc.url, 'test-host', 'linux', 'srv-1']);
    assert.equal(statSync(join(home, 'identity/device.json')).mode & 0o777, 0o600);
    assert.equal(statSync(join(home, 'identity')).mode & 0o777, 0o700);
    assert.deepEqual(svc.state.devices[0], { device_id: 'dev_1', jkt: thumbprint, key_storage: 'software', device_name: 'test-host', platform: 'linux', harnesses: ['claude-code'] });
    assert.equal(await signer.deviceStatus(), 'enrolled');
    assert.deepEqual(signer.enrollmentProgress().grant, { state: 'approved', device_id: 'dev_1', key_thumbprint: thumbprint, key_storage: 'software', restart: true });
    assert.deepEqual(events.map((e) => e.kind), ['device.enroll.started', 'device.enrolled']);

    // A new process reads the same enrollment, and refuses a second one without force.
    const again = setup(home, svc);
    assert.equal(await again.deviceStatus(), 'enrolled');
    await assert.rejects(again.enroll({ harnesses: ['claude-code'] }), (e) => e.code === 'host.invalid_request' && /already enrolled/.test(e.message));
  } finally { await svc.close(); rmSync(home, { recursive: true, force: true }); }
});

test('the jwt-bearer assertion is signed by the device key and bound to the ephemeral key', async () => {
  const svc = await fakeIdentityService();
  const home = tempHome();
  try {
    const signer = setup(home, svc);
    const eph = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' });
    assert.throws(() => signer.enrollment.assertion({ ephemeralJwk: eph }), (e) => e.code === 'host.invalid_request');
    await signer.enroll({ harnesses: ['claude-code'] });
    svc.decide('approved');
    await signer.enrollment.settled();
    const [h, p, s] = signer.enrollment.assertion({ ephemeralJwk: eph }).split('.');
    assert.deepEqual(JSON.parse(Buffer.from(h, 'base64url')), { typ: 'JWT', alg: 'ES256' });
    const claims = JSON.parse(Buffer.from(p, 'base64url'));
    assert.deepEqual([claims.iss, claims.sub, claims.aud, claims.exp - claims.iat], ['dev_1', 'dev_1', `${svc.url}/oauth/token`, 120]);
    assert.deepEqual(claims.cnf.jwk, eph);
    const key = createPublicKey({ key: signer.publicJwk(), format: 'jwk' });
    assert.equal(cryptoVerify('sha256', Buffer.from(`${h}.${p}`), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(s, 'base64url')), true);
    assert.throws(() => signer.enrollment.assertion({ ephemeralJwk: { ...eph, d: 'x' } }), /public ephemeral key/);
  } finally { await svc.close(); rmSync(home, { recursive: true, force: true }); }
});

test('re-enrollment makes a fresh key, and a revoked record is never revived', async () => {
  const svc = await fakeIdentityService();
  const home = tempHome();
  try {
    const signer = setup(home, svc);
    await signer.enroll({ harnesses: ['claude-code'] });
    svc.decide('approved');
    await signer.enrollment.settled();
    const first = signer.report();

    signer.enrollment.markRevoked('invalid_grant');
    assert.equal(await signer.deviceStatus(), 'revoked');
    const eph = generateKeyPairSync('ec', { namedCurve: 'prime256v1' }).publicKey.export({ format: 'jwk' });
    assert.throws(() => signer.enrollment.assertion({ ephemeralJwk: eph }), (e) => e.code === 'device_revoked');

    const second = setup(home, svc); // a new HQ process, as after the restart
    const started = await second.enroll({ harnesses: ['claude-code', 'codex'] });
    assert.notEqual(started.key_thumbprint, first.thumbprint);
    assert.equal(started.key_generation, 2);
    assert.equal(await second.deviceStatus(), 'unenrolled', 'the revoked record is set aside, not reused');
    assert.equal(JSON.parse(readFileSync(join(home, 'identity/device.previous.json'), 'utf8')).device_id, 'dev_1');
    svc.decide('approved');
    await second.enrollment.settled();
    assert.equal(await second.deviceStatus(), 'enrolled');
    assert.deepEqual(svc.state.devices.map((d) => d.jkt), [first.thumbprint, started.key_thumbprint]);
    assert.deepEqual(svc.state.devices[1].harnesses, ['claude-code', 'codex']);

    // force on a healthy enrollment also re-keys.
    const third = setup(home, svc);
    const forced = await third.enroll({ harnesses: ['claude-code'], force: true });
    assert.equal(forced.key_generation, 3);
    svc.decide('approved');
    await third.enrollment.settled();
    assert.equal(svc.state.devices.length, 3);
  } finally { await svc.close(); rmSync(home, { recursive: true, force: true }); }
});

test('a denied or refused grant enrolls nothing and says why; a redirect and a bad server key are refused', async () => {
  const svc = await fakeIdentityService();
  const home = tempHome();
  const events = [];
  try {
    const signer = setup(home, svc, events);
    await signer.enroll({ harnesses: ['claude-code'] });
    svc.decide('denied');
    await signer.enrollment.settled();
    assert.equal(await signer.deviceStatus(), 'unenrolled');
    assert.match(signer.enrollmentProgress().grant.reason, /access_denied \(the owner denied this device\)/);
    assert.equal(existsSync(join(home, 'identity/device.json')), false);
    assert.equal(events.at(-1).kind, 'device.enroll.failed');

    svc.state.mode = 'refuse';
    await assert.rejects(signer.enroll({ harnesses: ['claude-code'] }), /device authorization failed: invalid_request \(software keys are not accepted\)/);
    svc.state.mode = 'redirect';
    await assert.rejects(signer.enroll({ harnesses: ['claude-code'] }), (e) => e.code === 'credential_unavailable');

    for (const bad of [{}, { harnesses: [] }, { harnesses: ['Bad Name'] }, { harnesses: ['x'], force: 'yes' }, { harnesses: ['x'], device_name: '' }]) {
      await assert.rejects(signer.enroll(bad), (e) => e.code === 'host.invalid_request');
    }
  } finally { await svc.close(); rmSync(home, { recursive: true, force: true }); }

  const svc2 = await fakeIdentityService();
  const home2 = tempHome();
  try {
    svc2.state.mode = 'bad-key';
    await assert.rejects(setup(home2, svc2).enroll({ harnesses: ['claude-code'] }), /response-signing key is unavailable/);
    await svc2.close();
    await assert.rejects(setup(home2, svc2).enroll({ harnesses: ['claude-code'] }), (e) => e.code === 'credential_unavailable' && /unreachable/.test(e.message));
  } finally { rmSync(home2, { recursive: true, force: true }); }
});

test('enrollment config: legacy by default, hq with an https origin', () => {
  assert.doesNotThrow(() => validateConfig({ enrollment: { source: 'hq' } }));
  assert.doesNotThrow(() => validateConfig({ enrollment: { source: 'hq', server: 'https://id.example' } }));
  assert.doesNotThrow(() => validateConfig({ enrollment: { source: 'legacy' } }));
  assert.throws(() => validateConfig({ enrollment: { source: 'cloud' } }), /legacy or hq/);
  assert.throws(() => validateConfig({ enrollment: { server: 'https://id.example' } }), /only for the hq source/);
  assert.throws(() => validateConfig({ enrollment: { source: 'hq', token: 'x' } }), /unknown key enrollment\.token/);
  assert.throws(() => validateServiceUrl('http://id.example'), /https/);
  assert.throws(() => validateServiceUrl('https://id.example/'), /bare origin/);
  assert.throws(() => validateServiceUrl('https://id.example/path'), /bare origin/);
  assert.equal(validateServiceUrl('http://127.0.0.1:8080'), 'http://127.0.0.1:8080');
});

test('HQ: unenrolled is safe mode; the owner enrolls over the control socket, approval is receipted, and the next start is running', async () => {
  const svc = await fakeIdentityService();
  const home = tempHome();
  const enrollment = (signer) => createEnrollment({ home, signer, server: svc.url, sleep: fast, deviceName: 'test-host', platform: 'linux', onEvent: (e) => events.push(e) });
  const events = [];
  try {
    const t = await startHQ({ home, enrollment });
    assert.equal(t.status.mode, 'safe');
    assert.match(t.status.reason, /not enrolled/);
    const owner = await t.owner();
    const res = await owner.request('device.enroll', { harnesses: ['claude-code'] });
    assert.equal(res.ok, true);
    assert.deepEqual([res.result.enrolled, res.result.pending, res.result.user_code, res.result.key_storage], [false, true, 'WXYZ-1234', 'software']);
    assert.equal((await owner.request('device.status')).result.enrollment.grant.state, 'pending');
    assert.equal((await owner.request('device.enroll', {})).host_refusal.code, 'host.invalid_request');

    svc.decide('approved');
    await until(async () => (await owner.request('device.status')).result.enrollment.grant.state === 'approved');
    const status = (await owner.request('status')).result;
    assert.equal(status.mode, 'safe', 'enrolled from the next start, not mid-run');
    assert.deepEqual([status.hq.enrollment.device_id, status.hq.enrollment.key_storage, status.hq.enrollment.server], ['dev_1', 'software', svc.url]);
    assert.deepEqual(events.map((e) => e.kind), ['device.enroll.started', 'device.enrolled']);
    await t.done({ keep: true });

    const next = await startHQ({ home, enrollment });
    try {
      assert.equal(next.status.mode, 'running');
      assert.equal(next.status.identity.device, 'enrolled');
      assert.equal(next.legacy.state.calls.some((c) => c.includes('server status')), false, 'device status no longer comes from the legacy bridge');
    } finally { await next.done(); }
  } finally { await svc.close(); rmSync(home, { recursive: true, force: true }); }
});

test('HQ configured with enrollment.source hq: the grant runs from config alone and its outcome is a receipt', async () => {
  const svc = await fakeIdentityService();
  const t = await startHQ({ config: { enrollment: { source: 'hq', server: svc.url } }, enrollment: null });
  try {
    assert.equal(t.status.mode, 'safe');
    assert.equal(t.status.hq.enrollment.server, svc.url);
    const owner = await t.owner();
    assert.equal((await owner.request('device.enroll', { harnesses: ['claude-code'] })).result.pending, true);
    svc.decide('approved');
    await until(async () => (await owner.request('device.status')).result.enrollment.grant?.state === 'approved');
    await until(() => t.hq.core.receipts.some((r) => r.kind === 'device.enrolled'));
    const kinds = t.hq.core.receipts.map((r) => r.kind);
    assert.ok(kinds.indexOf('device.enroll.started') < kinds.indexOf('device.enrolled'));
    assert.equal(t.hq.core.receipts.find((r) => r.kind === 'device.enrolled').key_storage, 'software');
  } finally { await t.done(); await svc.close(); }
});

test('two HQ processes use the same helper pin for independently verified owner enrollment requests', { skip: !['darwin', 'linux'].includes(process.platform) }, async (t) => {
  const home = tempHome();
  const helperHome = tempHome();
  const observations = [];
  const service = await fakeIdentityService({ observeProof: (record) => observations.push(record) });
  t.after(async () => {
    await service.close();
    for (const dir of [home, helperHome]) rmSync(dir, { recursive: true, force: true });
  });
  // The helper emulates device custody with a disposable software key outside HQ.
  const helper = fileURLToPath(new URL('signer-helper-fixture.mjs', import.meta.url));
  const main = fileURLToPath(new URL('../hq/main.mjs', import.meta.url));
  writeFileSync(join(home, 'config.json'), JSON.stringify({
    features: { hardwareSigner: true },
    signer: { backend: 'helper', command: [process.execPath, helper, join(helperHome, 'fixture.pem')] },
    enrollment: { source: 'hq', server: service.url },
  }), { mode: 0o600 });

  let firstPin;
  for (const round of [1, 2]) {
    const child = spawn(process.execPath, [main, 'run', '--home', home], {
      env: { HOME: home, PATH: '/usr/bin:/bin', GIT_CONFIG_NOSYSTEM: '1', GIT_TERMINAL_PROMPT: '0' },
      stdio: ['ignore', 'pipe', 'ignore'], timeout: 30000, killSignal: 'SIGKILL',
    });
    const exited = once(child, 'exit');
    const output = createInterface({ input: child.stdout });
    let owner;
    try {
      let listening = false;
      for await (const line of output) {
        if (line.startsWith('listening:')) { listening = true; break; }
      }
      assert.ok(listening, 'HQ must start its ordinary owner socket');
      owner = await connectSocket(join(home, 'control.sock'));
      const status = (await owner.request('status')).result;
      const signer = status.hq.signer;
      assert.equal(status.profile, 'managed-cooperative');
      assert.deepEqual([signer.available, signer.backend, signer.key_files, signer.generation], [true, 'helper', 0, 1]);
      if (round === 1) firstPin = signer.thumbprint;
      else assert.equal(signer.thumbprint, firstPin);

      const response = await owner.request('device.enroll', { harnesses: ['test-harness'], device_name: 't02-fixture' });
      assert.equal(response.ok, false);
      assert.equal(observations.length, round, 'the receiver verified an ES256 device proof for its own audience');
      assert.equal(observations[round - 1].thumbprint, firstPin);
      assert.match(observations[round - 1].requestID, /^[A-Za-z0-9_-]{22}$/);
      assert.equal((await owner.request('device.status')).result.device, 'unenrolled');
    } finally {
      await owner?.close();
      child.kill('SIGTERM');
      const [code] = await exited;
      assert.equal(code, 0, 'HQ must shut down cleanly');
    }
  }
  assert.notEqual(observations[0].requestID, observations[1].requestID);
  assert.equal(service.state.requests.length, 0, 'raw request forms are never retained in observation mode');
  assert.equal(service.state.grants.size, 0);
  assert.equal(service.state.devices.length, 0);
});

test('notice harness membership is secret-free and tied to the current enrolled record, server and signer key', async () => {
  const svc = await fakeIdentityService();
  const home = tempHome();
  try {
    const signer = setup(home, svc);
    assert.equal(signer.enrollment.allowsHarness('claude-code'), false);
    await signer.enroll({ harnesses: ['claude-code'] });
    svc.decide('approved'); await signer.enrollment.settled();
    assert.equal(signer.enrollment.allowsHarness('claude-code'), true);
    assert.equal(signer.enrollment.allowsHarness('different-bot'), false);
    const path = join(home, 'identity/device.json');
    const original = readFileSync(path, 'utf8');
    const record = JSON.parse(original);
    const save = (value) => writeFileSync(path, JSON.stringify(value), { mode: 0o600 });
    for (const changes of [{ server: 'https://other.example' }, { jkt: 'wrong-key' }, { key_storage: 'different' }, { key_generation: 99 }, { revoked_at: '2026-11-14T00:00:00Z' }, { device_id: '' }, { harnesses: undefined }, { harnesses: [] }, { harnesses: ['claude-code', 'bad name'] }, { harnesses: ['claude-code', 'claude-code'] }]) {
      save({ ...record, ...changes });
      assert.equal(signer.enrollment.allowsHarness('claude-code'), false, JSON.stringify(changes));
    }
    writeFileSync(path, '{broken');
    assert.equal(signer.enrollment.allowsHarness('claude-code'), false);
    writeFileSync(path, original); chmodSync(path, 0o644);
    assert.equal(signer.enrollment.allowsHarness('claude-code'), false);
    chmodSync(path, 0o600);
    assert.equal(signer.enrollment.allowsHarness('claude-code'), true);
    signer.createKey({ replace: true });
    assert.equal(signer.enrollment.allowsHarness('claude-code'), false, 'a key rotation cannot reuse the old enrollment');
  } finally { await svc.close(); rmSync(home, { recursive: true, force: true }); }
});
