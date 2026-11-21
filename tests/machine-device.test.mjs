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
import { definePlugin } from '../sdk/plugin.mjs';
import { fakeIdentityService } from './identity-service-fixture.mjs';
import { schemas, fakeLegacy, tempHome } from './hq-harness.mjs';

const hash = (bytes) => createHash('sha256').update(bytes).digest('hex');
const b64 = (v) => Buffer.from(JSON.stringify(v)).toString('base64url');

test('enroll tells an unpaired account which Machine prerequisite is missing', async (t) => {
  const home = tempHome(), role = tempHome();
  const config = join(role, '.config'), dir = join(config, 'agent-machine');
  const service = await fakeIdentityService();
  const request = (option, fields) => machineCommandInHome(
    ['hq-device', option, '--socket', join(role, 'machine.sock')], role, process.getuid(), fields, true);
  const hq = createHQ({ home, schemas, config: { enrollment: { source: 'hq', server: service.url } },
    serverKeys: [service.key], createDeviceSigner: (opts) => createMachineSigner({ ...opts, request }),
    legacy: legacyDaemon({ run: fakeLegacy().run }) });
  t.after(async () => {
    await hq.stop(); await service.close();
    for (const folder of [home, role]) rmSync(folder, { recursive: true, force: true });
  });
  await hq.start();
  const enroll = () => promisify(execFile)(process.execPath, [
    fileURLToPath(new URL('../hq/main.mjs', import.meta.url)), 'enroll', '--harness', 'codex', '--home', home,
  ]);
  const refused = async () => {
    await assert.rejects(enroll(), (error) => {
      const response = JSON.parse(error.stderr);
      assert.equal(error.code, 1);
      assert.equal(response.error, 'credential_unavailable');
      assert.match(response.explanation, /this account.s Machine pairing/);
      assert.ok(!response.explanation.includes(role));
      return true;
    });
  };
  await refused();
  assert.equal(existsSync(config), false);
  mkdirSync(config, { mode: 0o700 });
  await refused();
  assert.equal(existsSync(dir), false);
  mkdirSync(dir, { mode: 0o700 });
  await refused();
  assert.equal(existsSync(join(dir, 'client.key')), false);
  await machineCommandInHome(['identity'], role, process.getuid(), undefined, true);
  await refused();
  assert.equal(existsSync(join(dir, 'daemon.pub')), false);
  assert.equal(service.state.requests.length, 0);
});

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
  let binding, lostReply = true, receiptJti, accessJti, session, deviceRefusal;
  const options = [];
  const accessBindings = [];
  let accessResponse, sessionKey, accessHash, whoamiChange;
  // Simulate an administrator changing the pair between the identity read
  // and the next normal operation on this running HQ.
  let refuseAssertion, holdIdentity;
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
          sessionKey = generateKeyPairSync('ec', { namedCurve: 'P-256' });
          const ephemeralJwk = sessionKey.publicKey.export({ format: 'jwk' });
          session = jwkThumbprint(ephemeralJwk);
          accessJti = randomBytes(16).toString('base64url');
          const iat = Math.floor(Date.now() / 1000);
          const input = b64({ typ: 'JWT', alg: 'ES256' }) + '.' + b64({ iss: binding.device_id, sub: binding.device_id,
            aud: service.url + '/oauth/token', iat, exp: iat + 120, jti: accessJti, cnf: { jwk: ephemeralJwk } });
          state = 'asserted'; body = { ...identity, assertion: input + '.' + sign('sha256', Buffer.from(input), { key: device.privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url') };
        } else if (r.option === 'whoami') {
          assert.deepEqual(Object.keys(r).sort(), ['hq_epoch', 'nonce', 'option', 'public_key', 'session', 'signature', 'timestamp', 'verb']);
          assert.equal(r.session, session);
          parts.push('session', r.session);
          const header = { alg: 'ES256', typ: 'dpop+jwt', jwk: sessionKey.publicKey.export({ format: 'jwk' }) };
          const claims = { htm: 'GET', htu: service.url + '/api/daemon/whoami', ath: accessHash,
            iat: Math.floor(Date.now() / 1000), jti: randomBytes(16).toString('base64url') };
          body = { session, hq_epoch: identity.hq_epoch };
          const key = whoamiChange?.({ claims, header, body }) ?? sessionKey.privateKey;
          const input = b64(header) + '.' + b64(claims);
          body.proof = input + '.' + sign('sha256', Buffer.from(input), { key, dsaEncoding: 'ieee-p1363' }).toString('base64url');
          state = 'whoami-proved';
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
            const token = JSON.parse(bytes).access_token;
            assert.ok(typeof token === 'string' && token.length > 0);
            accessHash = createHash('sha256').update(token).digest('base64url');
            state = 'access-bound'; body = { session, expires_at: Math.floor(Date.now() / 1000) + 300, hq_epoch: identity.hq_epoch };
          } else {
            binding = { device_id: JSON.parse(bytes).device_id, receipt_jti: receiptJti, receipt_sha256: hash(bytes) };
            state = 'bound'; body = { ...identity, ...binding };
          }
        }
      }
      assert.equal(r.public_key, Buffer.from(client.public_key, 'hex').toString('base64'));
      assert.ok(verify(null, Buffer.from(parts.join('\n')), clientKey, Buffer.from(r.signature, 'base64')));
      if (r.option === 'bind-access') {
        const { hq_epoch, receipt_body, receipt_jti, receipt_kid, receipt_signature } = r;
        accessBindings.push({ nonce: r.nonce, receipt: { hq_epoch, receipt_body, receipt_jti, receipt_kid, receipt_signature } });
        if (accessBindings.length === 1 || accessResponse === 'closed') { stream.destroy(); return; }
        if (accessResponse === 'partial') { stream.end('{'); return; }
      }
      if (r.option === 'bind-enrollment' && lostReply) { lostReply = false; stream.destroy(); return; }
      if (refuseAssertion === 'offline' && r.option === 'access-assertion') { stream.destroy(); return; }
      const diagnostic = deviceRefusal ?? (r.option === 'bind-access' && accessResponse === 'refused'
        ? 'MM_DAEMON_CALLER_REFUSED' : (r.option === 'access-assertion' ? refuseAssertion : undefined));
      const response = { ok: !diagnostic, ...(diagnostic && { diagnostic }), state, body, timestamp: r.timestamp, nonce: randomBytes(16).toString('base64url'), request_nonce: r.nonce };
      response.signature = sign(null, Buffer.from([response.ok, response.diagnostic ?? '', '', state, JSON.stringify(body), r.timestamp, response.nonce, r.nonce].join('\n')), machine.privateKey).toString('base64');
      const send = () => stream.end(JSON.stringify(response) + '\n');
      if (r.option === 'identity' && holdIdentity) { holdIdentity(send); holdIdentity = undefined; }
      else send();
    });
  });
  await new Promise((resolve, reject) => handler.once('error', reject).listen(socket, resolve));
  t.after(() => new Promise((resolve) => handler.close(resolve)));
  const request = (option, fields) => run(['hq-device', option, '--socket', socket], fields);
  await assert.rejects(request('identity'), /requires the daemon pin/);
  const machineKey = machine.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  await run(['status', '--socket', socket, '--daemon-key', machineKey.toString('hex')]);
  const selfLookup = definePlugin({
    name: 'self-lookup', version: '1.0.0', hostApi: 1,
    services: ['identityService'], identityServiceRoutes: ['/api/daemon/whoami'],
    async init(ctx) {
      return { provides: { read: () => ctx.services.identityService.call('GET', '/api/daemon/whoami') } };
    },
  });
  const open = async (config = {}) => {
    const hq = createHQ({ home, schemas, plugins: [selfLookup], config: { enrollment: { source: 'hq', server: service.url }, ...config },
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
  const consoleStatus = async (...flags) => (await promisify(execFile)(process.execPath, [
    fileURLToPath(new URL('../hq/main.mjs', import.meta.url)), 'status', '--home', home, ...flags,
  ])).stdout;
  assert.match(await consoleStatus(), /^HQ .*device not enrolled: run enroll/m);
  const offer = () => active.owner.request('device.enroll', { harnesses: ['codex'] });
  assert.equal((await offer()).result.pending, true);
  const pendingText = await consoleStatus();
  assert.match(pendingText, /^device: unenrolled;/m);
  assert.match(pendingText, /^enrollment: awaiting owner approval$/m);
  assert.doesNotMatch(pendingText, /run enroll/);
  assert.equal(JSON.parse(await consoleStatus('--json')).reason, 'device not enrolled: run enroll');
  const pending = (await active.owner.request('device.status')).result.enrollment.grant;
  assert.ok(!pendingText.includes(pending.user_code));
  assert.ok(!pendingText.includes(pending.verification_uri));
  const [grant] = service.state.grants.values();
  grant.receiptErrors = ['credential_unavailable', 'temporarily_unavailable'];
  service.decide('approved');
  await active.hq.core.signer.enrollment.settled();
  assert.deepEqual(grant.receiptErrors, []);
  assert.equal(service.state.grants.size, 1);
  assert.equal(service.state.devices.length, 1);
  assert.equal(existsSync(join(home, 'identity/device.json')), false);
  assert.equal(existsSync(join(home, 'identity/pending-receipt.json')), true);
  const failedText = await consoleStatus();
  assert.match(failedText, /^enrollment: failed$/m);
  assert.match(failedText, /^HQ .*device not enrolled: run enroll/m);
  await active.close(); active = null;
  active = await open();
  assert.equal((await offer()).result.state, 'approved');
  const approvedText = await consoleStatus();
  assert.match(approvedText, /^enrollment: approved; restart HQ to activate$/m);
  assert.doesNotMatch(approvedText, /run enroll/);
  assert.equal(options.filter((name) => name === 'enrollment-proof').length, 1);
  assert.equal(options.filter((name) => name === 'bind-enrollment').length, 2);
  await active.close(); active = null;
  active = await open();
  assert.equal(active.status.mode, 'running');
  assert.equal(active.status.profile, 'managed-cooperative');
  assert.equal(active.status.hq.signer.backend, 'machine');
  assert.equal(active.status.hq.features.hardwareSigner, false);
  const statusText = await consoleStatus();
  assert.match(statusText, /^device: enrolled;/m);
  assert.doesNotMatch(statusText, /^enrollment:/m);
  assert.match(statusText, /^signer: hardware key, paired Machine\/keyd backend, key /m);
  assert.doesNotMatch(statusText, /hardwareSigner|experimental feature/);
  assert.equal(existsSync(join(home, 'signer')), false);
  const beforeNotices = service.state.requests.length;
  await assert.rejects(active.hq.core.identity.call('GET', '/api/daemon/notices'), {
    code: 'credential_unavailable', message: /Machine has no authority for this credential operation/,
  });
  assert.equal(service.state.requests.length, beforeNotices);
  const lookup = () => active.hq.core.identity.call('GET', '/api/daemon/issuances/example-op');
  const enrolled = readFileSync(join(home, 'identity/device.json'));
  const repeat = await offer();
  assert.equal(repeat.host_refusal.code, 'host.invalid_request');
  assert.equal(repeat.host_refusal.explanation, 'this HQ is already enrolled with its Machine-managed device key');
  const forced = await active.owner.request('device.enroll', { harnesses: ['codex'], force: true });
  assert.equal(forced.refusal.error, 'credential_unavailable');
  assert.match(forced.refusal.explanation, /rotation requires administrator action in Machine/);
  assert.equal(options.filter(name => name === 'enrollment-proof').length, 1);
  assert.equal(service.state.grants.size, 1);
  assert.deepEqual(readFileSync(join(home, 'identity/device.json')), enrolled);

  service.state.mode = 'assertion-expired';
  await assert.rejects(lookup(), { code: 'credential_unavailable' });
  const expiredJti = accessJti;
  assert.equal(options.includes('bind-access'), false);
  assert.equal((await active.owner.request('device.status')).result.device, 'enrolled');
  assert.deepEqual(readFileSync(join(home, 'identity/device.json')), enrolled);
  service.state.mode = 'ok';
  await assert.rejects(lookup(), /no authorized DPoP action/);
  assert.notEqual(accessJti, expiredJti, 'retry opens a fresh admin session');
  assert.equal(options.filter(o => o === 'access-assertion').length, 2);
  assert.equal(accessBindings.length, 2);
  assert.deepEqual(accessBindings[0].receipt, accessBindings[1].receipt);
  assert.notEqual(accessBindings[0].nonce, accessBindings[1].nonce);
  assert.equal(service.state.requests.filter(r => r.form.grant_type === 'urn:ietf:params:oauth:grant-type:jwt-bearer').length, 2);
  for (const [response, attempts] of [['closed', 2], ['partial', 1], ['refused', 1]]) {
    accessResponse = response;
    const before = accessBindings.length;
    await assert.rejects(request('bind-access', accessBindings[0].receipt));
    assert.equal(accessBindings.length - before, attempts, response);
  }
  accessResponse = undefined;
  assert.equal(service.state.requests.filter((r) => r.url.includes('/api/daemon/')).length, 0);
  await assert.rejects(active.hq.core.identity.call('POST', '/api/daemon/credentials', {}), /administrator-side credential use/);
  // The device and its signed enrollment are unchanged, but this pair has a new epoch.
  const requestsBeforeEpochChange = service.state.requests.length;
  const operationsBeforeEpochChange = options.length;
  const originalEpoch = identity.hq_epoch;
  identity.hq_epoch = 'cd'.repeat(32);
  await assert.rejects(lookup(), { code: 'credential_unavailable', message: /no longer matches the current pairing/ });
  assert.deepEqual(options.slice(operationsBeforeEpochChange), ['identity', 'identity']);
  assert.equal(service.state.requests.length, requestsBeforeEpochChange);
  assert.equal(active.hq.core.identity.status().tokenCached, false);
  identity.hq_epoch = originalEpoch;
  await assert.rejects(lookup(), /no authorized DPoP action/);
  assert.equal(active.hq.core.identity.status().tokenCached, true);
  const whoami = () => active.hq.host.provided('self-lookup').read();
  const received = () => service.state.requests.filter(r => r.url === '/api/daemon/whoami').length;
  const positive = await whoami();
  assert.equal(positive.body.device.id, binding.device_id);
  assert.equal(positive.status, 200);
  assert.equal(received(), 1);
  // The same long-lived plugin must recover after Machine actually disappears
  // and returns, without a periodic status probe refreshing its signer first.
  const beforeOutage = service.state.requests.length;
  await new Promise((resolve) => handler.close(resolve));
  await assert.rejects(whoami(), { code: 'credential_unavailable' });
  assert.equal(service.state.requests.length, beforeOutage, 'outage must not reach Identity');
  assert.equal(active.hq.core.identity.status().tokenCached, false);
  await new Promise((resolve, reject) => handler.once('error', reject).listen(socket, resolve));
  const recovered = await whoami();
  assert.equal(recovered.status, 200);
  assert.equal(recovered.body.device.id, binding.device_id);
  assert.equal(service.state.requests.length - beforeOutage, 2, 'one token exchange and one lookup, without replay');
  assert.equal(active.hq.core.identity.status().tokenCached, true);
  // A returned Machine cannot silently substitute a different enrollment.
  await new Promise((resolve) => handler.close(resolve));
  await assert.rejects(whoami(), { code: 'credential_unavailable' });
  const beforeChangedIdentity = service.state.requests.length;
  await new Promise((resolve, reject) => handler.once('error', reject).listen(socket, resolve));
  const originalBinding = binding;
  binding = { ...binding, device_id: 'dev_changed' };
  await assert.rejects(whoami(), { code: 'credential_unavailable' });
  assert.equal(service.state.requests.length, beforeChangedIdentity, 'changed enrollment must not reach Identity');
  assert.equal(active.hq.core.identity.status().tokenCached, false);
  binding = originalBinding;
  assert.equal((await whoami()).status, 200);
  for (const change of [
    ({ claims }) => { claims.ath = 'wrong-token'; },
    ({ claims }) => { claims.jti = 'invalid'; },
    ({ claims }) => { claims.htu += '?query'; },
    ({ claims }) => { claims.htm = 'POST'; },
    ({ claims }) => { claims.extra = 'extra'; },
    ({ claims }) => { claims.iat -= 61; },
    ({ claims }) => { claims.iat += 62; },
    ({ body }) => { body.session = 'another-session'; },
    ({ body }) => { body.hq_epoch = 'legacy'; },
    ({ header }) => { header.jwk = jwk; return device.privateKey; },
    () => device.privateKey,
  ]) {
    whoamiChange = change;
    await assert.rejects(whoami(), { code: 'credential_unavailable' });
    assert.equal(received(), 3, 'an invalid Machine proof never reaches Identity');
  }
  whoamiChange = undefined;
  const deviceRecord = readFileSync(join(home, 'identity/device.json'));
  const enrollmentState = async () => (await active.owner.request('device.status')).result.device;
  for (const refusal of ['MM_DAEMON_UNKNOWN_KEY', 'MM_DAEMON_PEER_REFUSED', 'MM_DAEMON_CALLER_REFUSED', 'offline']) {
    // An identity reply signed before the refusal can arrive afterwards.
    const queued = new Promise(resolve => { holdIdentity = resolve; });
    const pending = active.hq.core.signer.deviceStatus();
    const deliver = await queued;
    refuseAssertion = refusal;
    await assert.rejects(active.hq.core.signer.custody.openSession(), error => {
      if (refusal !== 'offline') {
        assert.equal(error.code, 'credential_unavailable');
        assert.equal(error.machineDiagnostic, refusal);
        assert.ok(error.message.includes(refusal));
      }
      return true;
    });
    deliver();
    await assert.rejects(pending, /custody changed/);
    const status = (await active.owner.request('status')).result;
    assert.equal(status.hq.signer.available, false, refusal);
    if (refusal === 'MM_DAEMON_UNKNOWN_KEY') {
      const beforeLookup = service.state.requests.length;
      await assert.rejects(lookup(), { code: 'credential_unavailable' });
      assert.equal(active.hq.core.identity.status().tokenCached, false);
      assert.equal(service.state.requests.length, beforeLookup);
    }
    assert.equal(await enrollmentState(), 'enrolled');
    assert.deepEqual(readFileSync(join(home, 'identity/device.json')), deviceRecord);
    refuseAssertion = undefined;
    assert.equal(await active.hq.core.signer.deviceStatus(), 'enrolled');
    assert.equal(active.hq.core.signer.report().available, true);
  }
  refuseAssertion = 'MM_DAEMON_UNIMPLEMENTED';
  await assert.rejects(active.hq.core.signer.custody.openSession(), /UNIMPLEMENTED/);
  assert.deepEqual(options.slice(-3), ['identity', 'access-assertion', 'identity']);
  assert.equal(active.hq.core.signer.report().available, true, 'signed request-specific refusal is followed by fresh identity');
  refuseAssertion = undefined;
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
  for (const [diagnostic, guidance] of [
    ['MM_DAEMON_UNKNOWN_KEY', /MM_DAEMON_UNKNOWN_KEY.*prefix owner/],
    ['MM_DAEMON_VERB_UNKNOWN', /does not support HQ device signing.*MM_DAEMON_VERB_UNKNOWN.*compatible Machine version/],
  ]) {
    deviceRefusal = diagnostic;
    const callsBeforeRefusal = service.state.requests.length;
    active = await open();
    assert.equal(active.status.mode, 'safe');
    assert.equal(active.status.hq.signer.available, false);
    assert.match(active.status.hq.signer.reason, guidance);
    const status = await consoleStatus();
    assert.match(status, /^signer: paired Machine\/keyd unavailable/m);
    assert.match(status, guidance);
    await assert.rejects(promisify(execFile)(process.execPath, [
      fileURLToPath(new URL('../hq/main.mjs', import.meta.url)), 'enroll', '--harness', 'codex', '--home', home,
    ]), (error) => {
      const response = JSON.parse(error.stderr);
      assert.equal(error.code, 1);
      assert.equal(response.error, 'credential_unavailable');
      assert.match(response.explanation, guidance);
      return true;
    });
    assert.equal(service.state.requests.length, callsBeforeRefusal);
    await checkNoFallback();
    await active.close(); active = null;
  }
  deviceRefusal = undefined;
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
