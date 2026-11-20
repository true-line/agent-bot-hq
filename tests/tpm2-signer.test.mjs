// The TPM 2.0 signer helper (plan §9 row 15b; tests/fixtures/tpm2-signer.mjs),
// run against a software TPM (swtpm) with tpm2-tools. A software TPM proves
// the helper and the tpm2-tools calls, not hardware custody: qualification
// on a real TPM is separate and is what changes the feature flag's default.
//
// The tests skip where swtpm or tpm2-tools is missing. CI sets
// HQ_REQUIRE_TPM=1, which turns that skip into a failure.
// HQ_TPM_TCTI may select an existing loopback swtpm for the persistent-state test.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { spawn, spawnSync } from 'node:child_process';
import { generateKeyPairSync, sign as cryptoSign, verify as cryptoVerify } from 'node:crypto';
import { derToP1363 } from '../helpers/tpm2-signer.mjs';
import { existsSync, mkdtempSync, readdirSync, rmSync } from 'node:fs';
import { createConnection } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { createSigner, helperKeyBackend, helperRunner } from '../hq/signer.mjs';
import { startHQ, tempHome } from './hq-harness.mjs';

const dir = dirname(fileURLToPath(import.meta.url));
const HELPER = join(dir, 'fixtures/tpm2-signer.mjs');
const releaseHelper = join(dir, '../helpers/tpm2-signer.mjs');
const has = (cmd) => spawnSync('sh', ['-c', `command -v ${cmd}`], { stdio: 'ignore' }).status === 0;
const tcti = process.env.HQ_TPM_TCTI || '';
if (tcti && !/^swtpm:host=127\.0\.0\.1,port=[1-9][0-9]{0,4}$/.test(tcti)) {
  throw new Error('HQ_TPM_TCTI must select a loopback software TPM');
}
const tools = has('tpm2_sign') && has('tpm2_createprimary');
const available = process.platform === 'linux' && tools && (Boolean(tcti) || has('swtpm'));
const required = process.env.HQ_REQUIRE_TPM === '1';
const missing = tcti ? 'tpm2-tools is missing' : 'swtpm and tpm2-tools are not installed';
const skip = available ? false : missing;
const PORT = 23210 + (process.pid % 500) * 2;
const env = { ...process.env, TPM2TOOLS_TCTI: tcti || `swtpm:host=127.0.0.1,port=${PORT}` };
// Every persistent handle these tests create; cleared on a persistent TPM.
// Leave the default handle untouched when reusing a software TPM.
const TEST_HANDLES = ['0x8101002e', '0x8101002f', '0x81010021', '0x81010022', '0x81010023'];
const evictTestHandles = () => {
  const listed = spawnSync('tpm2_getcap', ['handles-persistent'], { env, encoding: 'utf8' });
  if (listed.status !== 0) throw new Error(`tpm2_getcap failed: ${listed.stderr.trim()}`);
  const present = listed.stdout.toLowerCase().split(/\s+/);
  for (const h of TEST_HANDLES.filter((x) => present.includes(x))) {
    const r = spawnSync('tpm2_evictcontrol', ['-C', 'o', '-c', h], { env, encoding: 'utf8' });
    if (r.status !== 0) throw new Error(`could not evict test handle ${h}: ${r.stderr.trim()}`);
  }
};
const enrollment = { source: 'test', deviceStatus: async () => 'enrolled', enroll: () => ({}) };
const command = (handle) => [process.execPath, HELPER, ...(handle ? ['--handle', handle] : [])];
const backend = (handle) => helperKeyBackend({ command: command(handle), run: helperRunner({ env }) });
const walk = (dir) => readdirSync(dir, { withFileTypes: true }).flatMap((e) => (e.isDirectory() ? walk(join(dir, e.name)) : [join(dir, e.name)]));

let swtpm;
let state;

const listening = (port) => new Promise((resolve) => {
  const s = createConnection({ host: '127.0.0.1', port });
  s.once('connect', () => { s.destroy(); resolve(true); });
  s.once('error', () => resolve(false));
});

before(async () => {
  if (!available) return;
  if (tcti) { evictTestHandles(); return; }
  state = mkdtempSync(join(tmpdir(), 'hq-swtpm-'));
  swtpm = spawn('swtpm', ['socket', '--tpm2', '--tpmstate', `dir=${state}`, '--server', `type=tcp,port=${PORT}`, '--ctrl', `type=tcp,port=${PORT + 1}`, '--flags', 'not-need-init,startup-clear'], { stdio: 'ignore' });
  for (let i = 0; i < 100 && !(await listening(PORT + 1)); i++) await new Promise((r) => setTimeout(r, 50));
});

after(() => {
  if (available && tcti) evictTestHandles();
  swtpm?.kill('SIGTERM');
  if (state) rmSync(state, { recursive: true, force: true });
});

test('DER signatures from tpm2-tools convert to r || s, and anything else is refused', () => {
  const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  for (let i = 0; i < 200; i++) { // enough rounds to meet short and high-bit r and s
    const msg = Buffer.from(`message ${i}`);
    const p1363 = derToP1363(cryptoSign('sha256', msg, privateKey));
    assert.equal(p1363.length, 64);
    assert.equal(cryptoVerify('sha256', msg, { key: publicKey, dsaEncoding: 'ieee-p1363' }, p1363), true);
  }
  const der = cryptoSign('sha256', Buffer.from('x'), privateKey);
  for (const bad of [Buffer.alloc(64, 1), der.subarray(0, der.length - 1), Buffer.concat([der, Buffer.from([0])]), Buffer.from([0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01]), Buffer.from([0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01])]) {
    assert.throws(() => derToP1363(bad), /not a DER ECDSA signature/);
  }
});

test('CI has a software TPM to test against', { skip: !required }, () => {
  assert.equal(available, true, `HQ_REQUIRE_TPM=1 but ${tcti ? missing : 'swtpm or tpm2-tools is missing'} (or this is not Linux)`);
});

// When a helper call fails, say what tpm2-tools said: HQ itself ignores stderr.
function explain(handle, op, input = '{}') {
  const r = spawnSync(process.execPath, [HELPER, '--handle', handle, op], { input, env, encoding: 'utf8' });
  return `${op} exit ${r.status}: ${r.stderr.trim() || r.stdout.trim()}`;
}

test('TPM helper: creates a key in the TPM, signs with it, and HQ holds no key file', { skip }, async () => {
  const home = tempHome();
  try {
    const probe = spawnSync(process.execPath, [HELPER, '--handle', '0x8101002f', 'create'], { input: '{}', env, encoding: 'utf8' });
    assert.equal(probe.status, 0, `create exit ${probe.status}: ${probe.stderr}`);
    assert.match(explain('0x8101002f', 'create'), /already exists/);
    const signed = explain('0x8101002f', 'sign', '{"message":"aGVsbG8"}');
    assert.match(signed, /^sign exit 0: \{"protocol":"agent-bot-hq-signer\/1","signature":"[A-Za-z0-9_-]{86}"\}$/, signed);
    const signer = createSigner({ home, backend: backend('0x8101002e'), enrollment });
    assert.equal(await signer.deviceStatus(), 'enrolled');
    const report = signer.report();
    assert.deepEqual([report.available, report.backend, report.key_storage, report.key_files, report.generation], [true, 'helper', 'hardware', 0, 1]);
    const sig = signer.sign(Buffer.from('approve this'));
    assert.equal(signer.verify(Buffer.from('approve this'), sig), true, 'the TPM signature verifies against the pinned public key');
    assert.equal(signer.verify(Buffer.from('approve that'), sig), false);
    assert.equal(signer.signJws({ typ: 'JWT' }, { iss: 'device' }).split('.').length, 3);
    assert.deepEqual(walk(home).map((f) => f.slice(home.length + 1)), ['signer/pin.json']);

    // The key survives a new HQ process: the pin still matches what the TPM holds.
    assert.equal(createSigner({ home, backend: backend('0x8101002e'), enrollment }).report().thumbprint, report.thumbprint);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

// Only use the disposable software TPM this test file owns.
test('TPM helper refuses to adopt a P-256 signing key with different custody attributes', { skip: skip || Boolean(tcti) }, () => {
  const dir = mkdtempSync(join(tmpdir(), 'hq-key-attributes-'));
  const context = join(dir, 'primary.ctx');
  const handle = '0x81010024';
  const run = (cmd, args) => {
    const result = spawnSync(cmd, args, { env, encoding: 'utf8' });
    assert.equal(result.status, 0, result.stderr);
  };
  try {
    run('tpm2_createprimary', ['-C', 'o', '-G', 'ecc256:ecdsa-sha256', '-a', 'sensitivedataorigin|userwithauth|sign', '-c', context]);
    run('tpm2_evictcontrol', ['-C', 'o', '-c', context, handle]);
    for (const [op, input] of [['status', '{}'], ['sign', '{"message":"aGk"}']]) {
      const result = spawnSync(process.execPath, [HELPER, '--handle', handle, op], { input, env, encoding: 'utf8' });
      assert.notEqual(result.status, 0);
      assert.equal(result.stdout, '');
      assert.match(result.stderr, /lacks verified TPM signing and custody attributes/);
    }
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('TPM helper: re-keying evicts the old key and makes a new one; create without replace is refused', { skip }, () => {
  const home = tempHome();
  const handle = '0x81010021';
  try {
    const signer = createSigner({ home, backend: backend(handle), enrollment });
    const first = signer.report();
    const old = signer.sign(Buffer.from('record'));
    const refused = spawnSync(process.execPath, [HELPER, '--handle', handle, 'create'], { input: '{}', env, encoding: 'utf8' });
    assert.notEqual(refused.status, 0);
    assert.match(refused.stderr, /already exists/);
    const made = signer.createKey({ replace: true });
    assert.equal(made.generation, 2);
    assert.notEqual(made.thumbprint, first.thumbprint);
    assert.equal(signer.verify(Buffer.from('record'), old), false);
    assert.equal(signer.verify(Buffer.from('record'), signer.sign(Buffer.from('record'))), true);
  } finally { rmSync(home, { recursive: true, force: true }); }
});

test('TPM helper: bad input and a missing key fail without output HQ could mistake for an answer', { skip }, () => {
  const run = (args, input = '{}') => spawnSync(process.execPath, [HELPER, ...args], { input, env, encoding: 'utf8' });
  const empty = run(['--handle', '0x81010022', 'status']);
  assert.deepEqual(JSON.parse(empty.stdout), { protocol: 'agent-bot-hq-signer/1', key_storage: 'hardware', present: false });
  for (const r of [run(['--handle', '0x81010022', 'sign'], '{"message":"aGk"}'), run(['--handle', '0x01000000', 'status']), run(['sign'], '{"message":"not base64!"}'), run(['sign'], '{}'), run(['nope'])]) {
    assert.notEqual(r.status, 0);
    assert.equal(r.stdout, '');
    assert.match(r.stderr, /^tpm2-signer: /);
  }
});

test('HQ refuses the local TPM helper, including direct requests to its release entry point', async () => {
  for (const op of ['status', 'create', 'sign']) {
    const refused = spawnSync(process.execPath, [releaseHelper, op], { input: '{}', encoding: 'utf8' });
    assert.equal(refused.status, 1);
    assert.equal(refused.stdout, '');
    assert.match(refused.stderr, /requires the paired Machine/);
  }
  const home = tempHome();
  try {
    await assert.rejects(startHQ({ home, config: { features: { hardwareSigner: true },
      signer: { backend: 'helper', command: [process.execPath, releaseHelper] } } }), /paired Machine backend/);
    assert.equal(existsSync(join(home, 'signer')), false);
  } finally { rmSync(home, { recursive: true, force: true }); }
});
