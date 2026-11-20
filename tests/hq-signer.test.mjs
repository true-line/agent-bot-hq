// The HQ signer (plan §9 PR 15, first slice; hq/signer.mjs): one pinned
// P-256 key behind a software or a helper backend, real signatures on
// approval records, and an honest key_storage in status and the profile.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createPublicKey, verify as cryptoVerify } from 'node:crypto';
import { execFile, execFileSync, spawnSync } from 'node:child_process';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { decideApproval } from '../sdk/services.mjs';
import { createHQ, validateConfig } from '../hq/hq.mjs';
import { legacyDaemon } from '../hq/legacy.mjs';
import { standaloneKeyBackend } from '../hq/standalone-signer.mjs';
import { backendFromConfig, createSigner, helperKeyBackend, helperRunner, jwkThumbprint, publicJwk, softwareKeyBackend, SIGNER_PROTOCOL } from '../hq/signer.mjs';
import { fakeLegacy, schemas, startHQ, tempHome } from './hq-harness.mjs';

const HERE = dirname(fileURLToPath(import.meta.url));
const HELPER = join(HERE, 'signer-helper-fixture.mjs');
const MAIN = join(HERE, '../hq/main.mjs');
const enrollment = { source: 'test', deviceStatus: async () => 'enrolled', enroll: () => ({}) };
const outside = () => join(mkdtempSync(join(tmpdir(), 'hq-hw-')), 'chip.pem'); // the fake chip, outside HQ's home
const helperCommand = (keyfile) => [process.execPath, HELPER, keyfile];
const helper = (keyfile, mode) => helperKeyBackend({ command: helperCommand(keyfile), run: helperRunner({ env: { ...process.env, ...(mode ? { FAKE_SIGNER_MODE: mode } : {}) } }) });
const software = (home) => softwareKeyBackend({ dir: join(home, 'signer') });
const walk = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)]));

test('software backend: the first use makes a private key file and a pin, and signatures verify against the pinned key only', async () => {
  const home = tempHome();
  try {
    const signer = createSigner({ home, backend: software(home), enrollment });
    assert.equal(await signer.deviceStatus(), 'enrolled');
    const key = join(home, 'signer/device-key.pem');
    assert.equal(statSync(key).mode & 0o777, 0o600);
    assert.equal(statSync(join(home, 'signer')).mode & 0o777, 0o700);
    const pin = JSON.parse(readFileSync(join(home, 'signer/pin.json'), 'utf8'));
    assert.deepEqual([pin.key_storage, pin.backend, pin.generation], ['software', 'software', 1]);
    assert.equal(pin.thumbprint, jwkThumbprint(pin.jwk));
    assert.equal('d' in pin.jwk, false, 'the pin holds the public key only');

    const sig = signer.sign(Buffer.from('approve this'));
    assert.match(sig, new RegExp(`^hq-sig-v1\\.${pin.thumbprint}\\.[A-Za-z0-9_-]{86}$`));
    assert.equal(signer.verify(Buffer.from('approve this'), sig), true);
    assert.equal(signer.verify(Buffer.from('approve that'), sig), false);
    assert.equal(signer.verify(Buffer.from('approve this'), sig.replace('hq-sig-v1', 'hq-sig-v2')), false);
    assert.equal(signer.verify(Buffer.from('approve this'), 'fake-sig-v0:00'), false);
    assert.deepEqual(signer.report(), { available: true, backend: 'software', key_storage: 'software', alg: 'ES256', thumbprint: pin.thumbprint, generation: 1, key_files: 1 });

    // The same key after a restart.
    const again = createSigner({ home, backend: software(home), enrollment });
    assert.equal(again.verify(Buffer.from('approve this'), sig), true);
    assert.equal(again.report().thumbprint, pin.thumbprint);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test('signJws makes a compact ES256 JWS that an outside verifier accepts with the public key', () => {
  const home = tempHome();
  try {
    const signer = createSigner({ home, backend: software(home), enrollment });
    const jws = signer.signJws({ typ: 'JWT' }, { iss: 'device', aud: 'https://agents.example' });
    const [h, p, s] = jws.split('.');
    const header = JSON.parse(Buffer.from(h, 'base64url'));
    assert.deepEqual(header, { typ: 'JWT', alg: 'ES256', kid: signer.report().thumbprint });
    assert.deepEqual(JSON.parse(Buffer.from(p, 'base64url')), { iss: 'device', aud: 'https://agents.example' });
    const key = createPublicKey({ key: signer.publicJwk(), format: 'jwk' });
    assert.equal(cryptoVerify('sha256', Buffer.from(`${h}.${p}`), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(s, 'base64url')), true);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test('a key that is gone, swapped or readable by others is an unavailable signer', async () => {
  const home = tempHome();
  try {
    createSigner({ home, backend: software(home), enrollment }).report();
    const key = join(home, 'signer/device-key.pem');
    const original = readFileSync(key, 'utf8');

    chmodSync(key, 0o644);
    await assert.rejects(createSigner({ home, backend: software(home), enrollment }).deviceStatus(), /must be 0600/);
    chmodSync(key, 0o600);

    // Another key in its place: the pin does not move with it.
    const other = tempHome();
    createSigner({ home: other, backend: software(other), enrollment }).report();
    writeFileSync(key, readFileSync(join(other, 'signer/device-key.pem')), { mode: 0o600 });
    rmSync(other, { recursive: true, force: true });
    const swapped = createSigner({ home, backend: software(home), enrollment });
    await assert.rejects(swapped.deviceStatus(), /different key from the pinned one/);
    assert.equal(swapped.report().available, false);
    assert.throws(() => swapped.sign(Buffer.from('x')), /different key/);

    rmSync(key);
    await assert.rejects(createSigner({ home, backend: software(home), enrollment }).deviceStatus(), /gone from its backend/);

    writeFileSync(key, original, { mode: 0o600 });
    assert.equal(await createSigner({ home, backend: software(home), enrollment }).deviceStatus(), 'enrolled');

    writeFileSync(join(home, 'signer/pin.json'), '{"thumbprint":"x"}', { mode: 0o600 });
    await assert.rejects(createSigner({ home, backend: software(home), enrollment }).deviceStatus(), /not a signer pin/);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test('re-keying is explicit: a fresh key, a new generation, and the old key\'s signatures stop verifying', () => {
  const home = tempHome();
  try {
    const signer = createSigner({ home, backend: software(home), enrollment });
    const before = signer.report();
    const old = signer.sign(Buffer.from('record'));
    assert.throws(() => signer.createKey(), /re-enrollment/);
    const made = signer.createKey({ replace: true });
    assert.equal(made.generation, 2);
    assert.notEqual(made.thumbprint, before.thumbprint);
    assert.equal(signer.verify(Buffer.from('record'), old), false);
    assert.equal(signer.verify(Buffer.from('record'), signer.sign(Buffer.from('record'))), true);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test('helper backend: key_storage is hardware and HQ\'s state directory holds no key file', async () => {
  const home = tempHome();
  const chip = outside();
  try {
    const signer = createSigner({ home, backend: helper(chip), enrollment });
    assert.equal(await signer.deviceStatus(), 'enrolled');
    const report = signer.report();
    assert.deepEqual([report.backend, report.key_storage, report.key_files, report.generation], ['helper', 'hardware', 0, 1]);
    const sig = signer.sign(Buffer.from('approve this'));
    assert.equal(signer.verify(Buffer.from('approve this'), sig), true);
    assert.deepEqual(walk(home).map((f) => f.slice(home.length + 1)), ['signer/pin.json']);
    assert.doesNotMatch(readFileSync(join(home, 'signer/pin.json'), 'utf8'), /PRIVATE KEY|"d"/);

    // A helper that already holds a key is adopted, not re-keyed.
    const home2 = tempHome();
    try {
      assert.equal(createSigner({ home: home2, backend: helper(chip), enrollment }).report().thumbprint, report.thumbprint);
    } finally { rmSync(home2, { recursive: true, force: true }); }
  } finally { rmSync(home, { recursive: true, force: true }); rmSync(dirname(chip), { recursive: true, force: true }); }
});

test('a helper that misbehaves is refused: wrong protocol, a software claim, a private key, a foreign signature, a failure', () => {
  const chip = outside();
  const home = tempHome();
  try {
    createSigner({ home, backend: helper(chip), enrollment }).report(); // a good key first
    const cases = [['protocol', /speaks agent-bot-hq-signer\/9/], ['software', /key_storage=software/], ['private', /returned a private key/], ['exit', /failed on status \(exit 3/], ['garbage', /not JSON/]];
    for (const [mode, why] of cases) {
      const r = createSigner({ home, backend: helper(chip, mode), enrollment }).report();
      assert.equal(r.available, false, mode);
      assert.match(r.reason, why, mode);
    }
    const foreign = createSigner({ home, backend: helper(chip, 'wrong-key'), enrollment });
    assert.equal(foreign.report().available, true);
    assert.throws(() => foreign.sign(Buffer.from('x')), /pinned key does not verify/);
    assert.throws(() => createSigner({ home, backend: helper(chip), enrollment }).sign(Buffer.alloc(40_000)), /at most 32768 bytes/);
    assert.throws(() => helperKeyBackend({ command: [] }), /helper command/);
    assert.throws(() => publicJwk({ kty: 'EC', crv: 'P-256', x: 'AA', y: 'AA' }), /no valid x/);
    assert.equal(SIGNER_PROTOCOL, 'agent-bot-hq-signer/1');
  } finally { rmSync(home, { recursive: true, force: true }); rmSync(dirname(chip), { recursive: true, force: true }); }
});

test('runtime configuration allows only paired Machine custody', () => {
  assert.doesNotThrow(() => validateConfig({ signer: { backend: 'machine' } }));
  assert.doesNotThrow(() => validateConfig({ standalone: true, signer: { backend: 'secure-enclave' } }));
  assert.throws(() => validateConfig({ signer: { backend: 'secure-enclave' } }), /paired Machine backend/);
  for (const signer of [{ backend: 'software' }, { backend: 'helper', command: ['/example/fixture'] },
    { backend: 'machine', command: ['/example/fixture'] }]) {
    assert.throws(() => validateConfig({ features: { hardwareSigner: true }, signer }), /paired Machine backend/);
  }
});

test('HQ: status names the signer and its custody, a software key is a stated reason protected is out of reach, and approvals carry a real signature', async () => {
  const t = await startHQ();
  try {
    const owner = await t.owner();
    const s = (await owner.request('status')).result;
    assert.equal(s.mode, 'running');
    assert.deepEqual([s.hq.signer.available, s.hq.signer.backend, s.hq.signer.key_storage, s.hq.signer.generation], [true, 'software', 'software', 1]);
    assert.deepEqual(s.hq.features, { hardwareSigner: false });
    assert.match(s.hq.profileReasons.join('\n'), /key_storage=software/);
    assert.equal(JSON.stringify(s).includes('PRIVATE KEY'), false);

    t.hq.core.approvals.set('appr_test', { id: 'appr_test', plugin: 'p', digest: `sha256:${'0'.repeat(64)}`, state: 'pending' });
    const decided = decideApproval(t.hq.core, 'appr_test', 'approved');
    assert.match(decided.signature, /^hq-sig-v1\./);
    assert.equal(t.hq.core.signer.verify(Buffer.from(`appr_test\n${decided.digest}\napproved`), decided.signature), true);
    assert.equal(t.hq.core.signer.verify(Buffer.from(`appr_test\n${decided.digest}\ndenied`), decided.signature), false);
  } finally { await t.done(); }
});

test('HQ on a helper: hardware custody in status, no key file in the state directory, and the software reason is gone', async () => {
  const chip = outside();
  const home = tempHome();
  const signer = createSigner({ home, backend: helper(chip), enrollment });
  const t = await startHQ({ home, signer, config: { features: { hardwareSigner: true } } });
  try {
    const s = (await (await t.owner()).request('status')).result;
    assert.deepEqual([s.hq.signer.backend, s.hq.signer.key_storage, s.hq.signer.key_files], ['helper', 'hardware', 0]);
    assert.deepEqual(s.hq.features, { hardwareSigner: true });
    assert.doesNotMatch(s.hq.profileReasons.join('\n'), /key_storage|hardware key/);
    assert.equal(s.profile, 'managed-cooperative', 'the other conditions still hold the host at cooperative');
    assert.deepEqual(walk(t.home).filter((f) => /\.pem$/.test(f)), []);

    // Model an interrupted custody transition in the fixture home.
    // Only the directory entry matters. HQ must never read key material to count it.
    writeFileSync(join(t.home, 'signer/device-key.pem'), 'fixture', { mode: 0o600 });
    const interrupted = (await (await t.owner()).request('status')).result;
    assert.equal(interrupted.hq.signer.key_storage, 'hardware');
    assert.equal(interrupted.hq.signer.key_files, 1);
    assert.match(interrupted.hq.profileReasons.join('\n'), /previous software signer key file remains/);
  } finally { await t.done(); rmSync(dirname(chip), { recursive: true, force: true }); }
});

test('HQ with an unavailable signer starts in safe mode and says why', async () => {
  const home = tempHome();
  const first = await startHQ({ home });
  await first.done({ keep: true });
  rmSync(join(home, 'signer/device-key.pem'));
  const t = await startHQ({ home });
  try {
    assert.equal(t.status.mode, 'safe');
    assert.match(t.status.reason, /signer unavailable: the pinned signer key is gone/);
    assert.equal(t.status.hq.signer.available, false);
  } finally { await t.done(); }
});

test('the stopped HQ CLI cannot create or replace a device key', () => {
  const home = tempHome();
  try {
    const result = spawnSync(process.execPath, [MAIN, 'signer', 'rekey', '--home', home], { encoding: 'utf8' });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /administrator action in Machine\/keyd/);
    assert.equal(existsSync(join(home, 'signer')), false);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test('standalone first use preserves existing enrollment or a helper key without a matching HQ pin', async (t) => {
  for (const prior of ['identity/device.json', 'identity/device.previous.json', 'identity/pending-receipt.json', 'signer/device-key.pem', 'helper key']) {
    await t.test(prior, () => {
      const home = tempHome();
      const chip = outside();
      try {
        if (prior === 'helper key') {
          helper(chip).create({ replace: false });
        } else {
          mkdirSync(dirname(join(home, prior)), { recursive: true, mode: 0o700 });
          writeFileSync(join(home, prior), 'preserved fixture state', { mode: 0o600 });
        }
        const run = helperRunner();
        const backend = standaloneKeyBackend(() => {}, ([, op], input) => {
          assert.equal(op, 'standalone-v1-status', 'prior custody permits inspection only');
          return run([...helperCommand(chip), 'status'], input);
        });
        const signer = createSigner({ home, backend, enrollment });
        const status = signer.report();
        assert.equal(status.available, false);
        assert.match(status.reason, /existing custody or enrollment requires administrator review/);
        assert.throws(() => signer.enrollmentProof('https://example.invalid'), /requires administrator review/);
        assert.equal(existsSync(join(home, 'signer/pin.json')), false);
        if (prior !== 'helper key') {
          assert.equal(readFileSync(join(home, prior), 'utf8'), 'preserved fixture state');
          assert.equal(existsSync(chip), false);
        }
      } finally {
        rmSync(home, { recursive: true, force: true });
        rmSync(dirname(chip), { recursive: true, force: true });
      }
    });
  }
});

test('configured standalone custody rechecks each signing operation and cannot reuse a cached enrollment key after retirement', async () => {
  const home = tempHome();
  const chip = outside();
  let eligible = true;
  const operations = [];
  const run = helperRunner();
  const backend = standaloneKeyBackend(() => {
    if (!eligible) throw new Error('standalone declaration retired');
  }, ([path, operation], input) => {
    assert.equal(path, '/Library/Application Support/ai.true-line.agent-bot-hq/standalone/hq-signer');
    assert.match(operation, /^standalone-v1-(status|create|sign)$/);
    operations.push(operation);
    return run([...helperCommand(chip), operation.slice('standalone-v1-'.length)], input);
  });
  const hq = createHQ({
    home, schemas, enrollment,
    config: { standalone: true, signer: { backend: 'secure-enclave' } },
    legacy: legacyDaemon({ run: fakeLegacy().run }),
    createStandaloneDeviceSigner: options => createSigner({ ...options, backend }),
    createDeviceSigner: () => assert.fail('standalone declaration does not select paired custody'),
  });
  try {
    const state = await hq.start();
    assert.equal(state.hq.signer.backend, 'secure-enclave');
    const signer = hq.core.signer;
    assert.equal(await signer.deviceStatus(), 'enrolled');
    const message = Buffer.from('disposable approval bytes');
    const signature = signer.sign(message);
    assert.equal(signer.verify(message, signature), true);
    assert.equal(signer.enrollmentProof('https://example.invalid/oauth/device_authorization').split('.').length, 3);
    const assertion = { server: 'https://example.invalid', deviceId: 'fixture', ephemeralJwk: signer.publicJwk() };
    assert.equal(signer.accessAssertion(assertion).split('.').length, 3);
    assert.equal(operations.filter(op => op === 'standalone-v1-create').length, 1);
    assert.equal(operations.filter(op => op === 'standalone-v1-sign').length, 3);
    assert.equal(existsSync(join(home, 'signer/device-key.pem')), false);
    const before = operations.length;
    eligible = false;
    assert.equal(signer.report().available, false);
    await assert.rejects(signer.deviceStatus(), /retired/);
    assert.throws(() => signer.enrollmentProof('https://example.invalid'), /retired/);
    assert.throws(() => signer.accessAssertion(assertion), /retired/);
    assert.throws(() => signer.sign(message), /retired/);
    assert.equal(signer.verify(message, signature), false);
    assert.equal(operations.length, before);
  } finally {
    await hq.stop();
    rmSync(home, { recursive: true, force: true });
    rmSync(dirname(chip), { recursive: true, force: true });
  }
});
