// Cross-repository integration with the Machine test binary and keyd fixture
// build script. The issuer key is embedded
// into a fresh test provider, just as a release embeds its trusted issuer.
import assert from 'node:assert/strict';
import { execFile, execFileSync, spawn } from 'node:child_process';
import { createECDH, randomBytes } from 'node:crypto';
import { existsSync, mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { setTimeout } from 'node:timers/promises';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { createEnrollment } from '../hq/enrollment.mjs';
import { createHQ } from '../hq/hq.mjs';
import { createIdentityService } from '../hq/identity-service.mjs';
import { legacyDaemon } from '../hq/legacy.mjs';
import { machineCommandInHome } from '../hq/machine-channel.mjs';
import { createMachineSigner } from '../hq/machine-device.mjs';
import { fakeLegacy, schemas } from './hq-harness.mjs';
import { fakeIdentityService } from './identity-service-fixture.mjs';

const [machineBinary, keydBuilder] = process.argv.slice(2).map((file) => realpathSync(file));
assert.ok(machineBinary && keydBuilder && process.argv.length === 4,
  'usage: node tests/machine-device-interop.mjs MACHINE_TEST_BINARY KEYD_FIXTURE_BUILD_SCRIPT');
assert.ok(process.getuid?.() > 0, 'run as an ordinary Unix account');
const cliPath = fileURLToPath(new URL('../hq/main.mjs', import.meta.url));
const exec = promisify(execFile);
const origin = 'https://agents.true-line.ai';
const dir = mkdtempSync(join(realpathSync('/tmp'), 'hq-custody-'));
const home = join(dir, 'hq');
const role = join(dir, 'role');
const socket = join(dir, 'machine.sock');
const keydBinary = join(dir, 'keyd-fixture');
const env = { PATH: '/usr/bin:/bin', HOME: join(dir, 'home'), KEYD_FIXTURE_STATE: dir };
let machine, exit, hq, server;

async function until(check, description) {
  for (let i = 0; i < 150; i++) {
    if (check()) return;
    await setTimeout(40);
  }
  assert.fail(description);
}

async function startMachine() {
  rmSync(join(dir, 'stop'), { force: true });
  machine = spawn(machineBinary, ['-test.run', '^TestDisposableHQKeydInterop$'], {
    env: { ...env, MM_HQ_DEVICE_INTEROP: '1', KEYD_FIXTURE_BIN: keydBinary }, stdio: 'ignore',
  });
  exit = new Promise((resolve, reject) => {
    machine.once('error', reject);
    machine.once('close', resolve);
  });
  await Promise.race([until(() => existsSync(socket), 'Machine fixture did not start'),
    exit.then(() => { if (!existsSync(socket)) assert.fail('Machine fixture exited before serving'); })]);
}

async function stopMachine() {
  if (!machine) return;
  writeFileSync(join(dir, 'stop'), '');
  const code = await exit;
  machine = undefined;
  assert.equal(code, 0);
}

function cli(...args) {
  return exec(process.execPath, [cliPath, ...args, '--home', home], { env, timeout: 15_000, encoding: 'utf8' });
}
async function cliStatus() {
  return JSON.parse((await cli('status', '--json')).stdout);
}

try {
  for (const folder of [home, role, env.HOME]) mkdirSync(folder, { mode: 0o700 });
  const request = (args, fields) => machineCommandInHome(args, role, process.getuid(), fields);
  await request(['identity']);
  writeFileSync(join(dir, 'inputs.json'), JSON.stringify({
    machine_seed: randomBytes(32).toString('base64'),
    hq_seed: readFileSync(join(role, '.config/agent-machine/client.key')).toString('base64'),
    owner: createECDH('prime256v1').generateKeys('base64'),
    hq_epoch: randomBytes(32).toString('hex'),
  }), { mode: 0o600 });
  server = await fakeIdentityService({ issuer: origin });
  assert.equal(new URL(server.url).hostname, '127.0.0.1');
  const fetchImpl = (url, options) => {
    const target = new URL(url);
    assert.equal(target.origin, origin);
    return fetch(server.url + target.pathname + target.search, options);
  };
  const manifest = join(dir, 'server-keys.json');
  writeFileSync(manifest, JSON.stringify({ server: origin, keys: [server.key] }), { mode: 0o600 });
  execFileSync('/bin/bash', [keydBuilder, manifest, keydBinary], { stdio: 'inherit', timeout: 120_000 });
  await startMachine();
  execFileSync(keydBinary, ['hq-device-init'], { env, stdio: 'pipe', timeout: 10_000 });
  const pair = JSON.parse(readFileSync(join(dir, 'pair.json')));
  const pin = Buffer.from(pair.machine_pub, 'base64').toString('hex');
  assert.equal((await request(['status', '--socket', socket, '--daemon-key', pin])).channel, 'signed');

  const calls = [];
  async function startHQ() {
    const signer = createMachineSigner({
      home, keysFor: () => [server.key],
      request: (operation, fields) => {
        calls.push(operation);
        return request(['hq-device', operation, '--socket', socket], fields);
      },
      enrollment: (device) => createEnrollment({
        home, signer: device, server: origin, fetchImpl, sleep: () => setTimeout(10),
      }),
    });
    const identity = createIdentityService({ server: origin, keySet: [server.key], fetchImpl,
      enrollment: signer.enrollment, custody: signer.custody });
    hq = createHQ({ home, schemas, signer, identity, legacy: legacyDaemon({ run: fakeLegacy().run }) });
    return hq.start();
  }

  const trapHome = join(dir, 'trap');
  const marker = join(trapHome, 'invoked');
  mkdirSync(trapHome, { mode: 0o700 });
  writeFileSync(join(trapHome, 'config.json'), JSON.stringify({
    features: { hardwareSigner: true }, signer: { backend: 'helper', command: [process.execPath,
      '-e', "require('node:fs').appendFileSync(process.argv[1], 'called')", marker] },
  }), { mode: 0o600 });
  async function assertNoLocalSigner() {
    await assert.rejects(exec(process.execPath, [cliPath, 'run', '--home', trapHome], { env, timeout: 6000 }), /paired Machine backend/);
    assert.equal(existsSync(marker), false);
    assert.equal(existsSync(join(home, 'signer/device-key.pem')), false);
  }

  assert.equal((await startHQ()).mode, 'safe');
  assert.equal((await cliStatus()).mode, 'safe');
  const enrolled = cli('enroll', '--harness', 'codex');
  await until(() => server.state.grants.size > 0, 'enrollment did not reach the test issuer');
  server.decide('approved');
  assert.match((await enrolled).stdout, /Enrolled as device/);
  await hq.stop();
  assert.equal((await startHQ()).mode, 'running');
  assert.equal((await cliStatus()).mode, 'running');
  await assert.rejects(hq.core.identity.call('GET', '/api/daemon/issuances/fixture-op'), /no authorized DPoP action/);
  assert.ok(calls.includes('bind-access'));
  assert.equal(server.state.requests.filter((item) => item.url.startsWith('/api/daemon/')).length, 0);
  await assertNoLocalSigner();

  await stopMachine();
  await assert.rejects(hq.core.signer.custody.openSession());
  assert.equal((await cliStatus()).hq.signer.available, false);
  await assertNoLocalSigner();
  await startMachine();
  assert.equal(await hq.core.signer.deviceStatus(), 'enrolled');
  assert.equal((await cliStatus()).hq.signer.available, true);
  await assertNoLocalSigner();
  writeFileSync(join(dir, 'revoke'), '');
  await until(() => existsSync(join(dir, 'revoked')), 'Machine did not acknowledge revocation');
  await assert.rejects(hq.core.signer.custody.openSession());
  await hq.stop();
  assert.equal((await startHQ()).mode, 'safe');
  assert.equal((await cliStatus()).hq.signer.available, false);
  await assertNoLocalSigner();
  console.log('Verified paired enrollment, access-token binding, restart, outage and revocation with no local signer calls.');
} finally {
  try {
    await hq?.stop();
    await server?.close();
  } finally {
    try { await stopMachine(); } finally { rmSync(dir, { recursive: true, force: true }); }
  }
}
