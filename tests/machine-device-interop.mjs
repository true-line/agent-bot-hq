// Cross-repository integration with the Machine test binary and keyd fixture
// build script. The issuer key is embedded
// into a fresh test provider, just as a release embeds its trusted issuer.
import assert from 'node:assert/strict';
import { execFile, execFileSync, spawn } from 'node:child_process';
import { createECDH, randomBytes } from 'node:crypto';
import { existsSync, linkSync, mkdtempSync, mkdirSync, readFileSync, realpathSync, rmdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { userInfo } from 'node:os';
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

const [machineBinary, keydBuilder, packagedCLI] = process.argv.slice(2).map((file) => realpathSync(file));
assert.ok(machineBinary && keydBuilder && [4, 5].includes(process.argv.length),
  'usage: node tests/machine-device-interop.mjs MACHINE_TEST_BINARY KEYD_FIXTURE_BUILD_SCRIPT [UNPACKED_HQ_CLI]');
assert.ok(process.getuid?.() > 0, 'run as an ordinary Unix account');
// The shipped CLI loads its verified offline contracts during startup.
const cliPath = packagedCLI ?? fileURLToPath(new URL('../hq/main.mjs', import.meta.url));
const exec = promisify(execFile);
const origin = 'https://agents.true-line.ai';
const dir = mkdtempSync(join(realpathSync('/tmp'), 'hq-custody-'));
const home = join(dir, 'hq');
// Only the disposable hosted runner may use the installed layout. This
// single-account test models Machine's peer UID in its Go fixture. The
// dedicated-account qualification exercises the kernel peer-credential check.
const hosted = process.env.HQ_TEST_PACKAGED_HOSTED === '1';
const sharedDir = '/opt/homebrew/var/agent-machine';
if (hosted) {
  assert.ok(packagedCLI && process.env.GITHUB_ACTIONS === 'true' && process.env.RUNNER_ENVIRONMENT === 'github-hosted');
  assert.ok(process.platform === 'darwin' && process.arch === 'arm64');
  assert.equal(userInfo().uid, process.getuid());
  assert.equal(process.geteuid(), process.getuid());
}
const role = hosted ? userInfo().homedir : join(dir, 'role');
const roleConfig = join(role, '.config');
const registeredPair = join(roleConfig, 'agent-machine');
const packageSocket = join(sharedDir, 'daemon.sock');
let madeSharedDir = false, ownsPair = false, linkedSocket = false;
if (packagedCLI) assert.ok(existsSync(join(dirname(packagedCLI), 'interim-core.mjs')), 'pass the unpacked Darwin release entry point');
const socket = join(dir, 'machine.sock');
const keydBinary = join(dir, 'keyd-fixture');
const env = { PATH: '/usr/bin:/bin', HOME: join(dir, 'home'), KEYD_FIXTURE_STATE: dir };
let machine, exit, hq, server, daemon, daemonExit;
const packageHome = join(dir, 'packaged-hq');
function packageCommand(...args) {
  return exec(process.execPath, [packagedCLI, ...args, '--home', packageHome], { env, timeout: 15_000, encoding: 'utf8' });
}
async function startPackage() {
  const preload = fileURLToPath(new URL('./fixtures/paired-process-ports.mjs', import.meta.url));
  daemon = spawn(process.execPath, [...(hosted ? [] : ['--experimental-test-module-mocks']), '--import', preload, packagedCLI, 'run', '--home', packageHome], {
    env: { ...env, HQ_TEST_ISSUER: server.url, ...(hosted && { HQ_TEST_REGISTERED_LAYOUT: '1' }) }, stdio: ['ignore', 'ignore', 'pipe'],
  });
  let diagnostics = '';
  daemon.stderr.on('data', data => { diagnostics = (diagnostics + data).slice(-2048); });
  daemonExit = new Promise((resolve, reject) => {
    daemon.once('error', reject);
    daemon.once('close', resolve);
  });
  await Promise.race([until(() => existsSync(join(packageHome, 'control.sock')), 'packaged HQ did not serve'),
    daemonExit.then(() => { throw new Error('packaged HQ exited before serving: ' + diagnostics); })]);
  const status = JSON.parse((await packageCommand('status', '--json')).stdout);
  assert.equal(status.hq.signer.backend, 'machine');
  return status.hq.signer;
}
async function stopPackage() {
  if (!daemon) return;
  daemon.kill('SIGTERM');
  const code = await daemonExit;
  daemon = undefined;
  assert.equal(code, 0);
}
async function signedPackageGrant() {
  const count = server.state.grants.size;
  // The loopback issuer admits a grant only after verifying the actual ES256
  // proof. Decline it before binding an enrollment or issuing credentials.
  const declined = assert.rejects(packageCommand('enroll', '--harness', 'codex'), e =>
    e.code === 1 && /the owner denied this device/.test(e.stderr));
  await Promise.race([until(() => server.state.grants.size === count + 1, 'packaged enrollment produced no valid proof'), declined]);
  server.decide('denied');
  await declined;
  assert.equal(server.state.grants.size, count + 1);
  return [...server.state.grants.values()].at(-1);
}
async function refusedPackageGrant(reason) {
  const requests = server.state.requests.length;
  await assert.rejects(packageCommand('enroll', '--harness', 'codex'), e => {
    const refusal = JSON.parse(e.stderr);
    assert.equal(e.code, 1);
    assert.equal(refusal.error, 'credential_unavailable');
    assert.match(refusal.explanation, reason);
    assert.ok(!refusal.explanation.includes(dir));
    return true;
  });
  const status = JSON.parse((await packageCommand('status', '--json')).stdout);
  assert.equal(status.hq.signer.backend, 'machine');
  assert.equal(status.hq.signer.available, false);
  assert.match(status.hq.signer.reason, reason);
  assert.ok(status.hq.profileReasons.includes('HQ could not verify hardware custody of the device key'));
  assert.equal(server.state.requests.length, requests);
  for (const name of ['device-key.pem', 'pin.json']) assert.equal(existsSync(join(packageHome, 'signer', name)), false);
}

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
  if (hosted) {
    linkSync(socket, packageSocket);
    linkedSocket = true;
  }
}

async function stopMachine() {
  if (!machine) return;
  if (linkedSocket) {
    rmSync(packageSocket);
    linkedSocket = false;
  }
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
  for (const folder of [home, env.HOME]) mkdirSync(folder, { mode: 0o700 });
  if (hosted) {
    // Exclusive creation refuses any runner with existing Machine state.
    mkdirSync(sharedDir, { mode: 0o700 });
    madeSharedDir = true;
    mkdirSync(roleConfig, { recursive: true, mode: 0o700 });
    mkdirSync(registeredPair, { mode: 0o700 });
    ownsPair = true;
  } else mkdirSync(role, { mode: 0o700 });
  const request = (args, fields) => machineCommandInHome(args, role, process.getuid(), fields, hosted);
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

  if (packagedCLI) {
    mkdirSync(packageHome, { mode: 0o700 });
    const before = await startPackage();
    assert.equal(before.available, true);
    const first = await signedPackageGrant();
    await stopMachine();
    await refusedPackageGrant(/could not connect to the paired Machine.*check that Machine is running/);
    await startMachine();
    const second = await signedPackageGrant();
    assert.equal(second.jkt, first.jkt);
    assert.ok(second.form.proof !== first.form.proof, 'recovery requires a fresh signed proof');
  }

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
  const grants = server.state.grants.size;
  const enrolled = cli('enroll', '--harness', 'codex');
  await until(() => server.state.grants.size === grants + 1, 'enrollment did not reach the test issuer');
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
  if (packagedCLI) {
    await refusedPackageGrant(/Machine refused this HQ account.*MM_DAEMON_PEER_REFUSED.*check its pairing/);
    await stopPackage();
    assert.equal((await startPackage()).available, false);
    await refusedPackageGrant(/Machine refused this HQ account.*MM_DAEMON_PEER_REFUSED.*check its pairing/);
    console.log('Packaged HQ accepted fresh Machine signatures across restart and refused enrollment during outage and after revocation, including after HQ restart.');
  }
  await assert.rejects(hq.core.signer.custody.openSession());
  await hq.stop();
  assert.equal((await startHQ()).mode, 'safe');
  assert.equal((await cliStatus()).hq.signer.available, false);
  await assertNoLocalSigner();
  console.log('Verified paired enrollment, access-token binding, restart, outage and revocation with no local signer calls.');
} finally {
  try {
    await stopPackage();
    await hq?.stop();
    await server?.close();
  } finally {
    try { await stopMachine(); } finally {
      if (ownsPair) rmSync(registeredPair, { recursive: true });
      if (madeSharedDir) rmdirSync(sharedDir);
      rmSync(dir, { recursive: true, force: true });
    }
  }
}
