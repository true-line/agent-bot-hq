import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { realpathSync, rmSync, symlinkSync } from 'node:fs';
import { connect, createServer } from 'node:net';
import { join } from 'node:path';
import { PassThrough } from 'node:stream';
import { DIGEST, HARNESS_UIDS, SOUL, fakeSudo, harnessLayout, startHQ, tempHome } from './hq-harness.mjs';
import { validateConfig } from '../hq/hq.mjs';
import { createSoulStarter } from '../hq/soul-start.mjs';

const waitFor = async (check) => {
  for (let i = 0; i < 100; i++) {
    if (check()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.fail('timed out waiting for Soul runner to stop');
};

function fakeMachineLaunch(calls, overrides = {}, completion = { exit_code: 0, signal: 'TERM', contained: true }, launchOverrides = {}) {
  const trusted = new WeakSet();
  const completed = new WeakSet();
  return {
    async reserve(request) {
      const extra = typeof overrides === 'function' ? overrides(request) : overrides;
      const installationId = extra.installationId ?? 'inst_fixture';
      const directory = join('/var/tmp', 'hq-runner-fixture', installationId);
      const reservation = { ...request, uid: 61001, gid: 61001,
        soulId: SOUL, installationId, definitionDigest: DIGEST, packageDigest: DIGEST.slice(7),
        runnerPackagePath: join(directory, 'package'),
        endpoint: { directory, socketPath: join(directory, 'admission.sock'), ownerUid: process.getuid(),
          groupGid: 61001, dirMode: 0o2750, socketMode: 0o660, peerUid: 61001 },
        async cancel() {}, ...extra };
      trusted.add(reservation);
      return reservation;
    },
    async verifyReservation(reservation, request) {
      return trusted.has(reservation) && reservation.startId === request.startId
        && reservation.packagePath === request.packagePath && reservation.hqEpoch === request.hqEpoch;
    },
    async verifyCompletion(report, binding) {
      return completed.has(report) && report.startId === binding.startId
        && report.hqEpoch === binding.hqEpoch && report.uid === binding.uid
        && report.installationId === binding.installationId
        && report.packageDigest === binding.packageDigest;
    },
    async start(reservation) {
      assert.equal(trusted.has(reservation), true);
      calls.push(reservation);
      const stdin = new PassThrough();
      const stdout = new PassThrough();
      stdin.on('data', (chunk) => stdout.write(`ACP:${chunk}`));
      let finish;
      const done = new Promise((resolve) => { finish = resolve; });
      return { ...reservation, pid: 4242, stdin, stdout, done,
        async stop() {
          stdin.destroy(); stdout.end();
          const report = { ...completion, startId: reservation.startId, hqEpoch: reservation.hqEpoch,
            uid: reservation.uid, installationId: reservation.installationId,
            packageDigest: reservation.packageDigest };
          completed.add(report);
          finish(report);
        },
        ...launchOverrides };
    },
  };
}
const machineOptions = (machine) => ({ soulLaunch: machine, soulVerifier: machine.verifyReservation,
  soulCompletionVerifier: machine.verifyCompletion, machineHqEpoch: 'ab'.repeat(32) });
const starter = (home, machine) => createSoulStarter({
  core: { random: { hex: (n) => 'ab'.repeat(n) }, clock: { now: () => Date.now() },
    receipts: [], profile: 'managed-cooperative' },
  home, machineLaunch: machine, verifyMachineReservation: machine.verifyReservation,
  verifyMachineCompletion: machine.verifyCompletion, mode: () => 'running',
  machineHqEpoch: 'ab'.repeat(32),
});
test('Machine-backed cooperative starts require a paired HQ epoch before dispatch', () => {
  assert.throws(() => createSoulStarter({ core: { random: { hex: (n) => 'ab'.repeat(n) } },
    machineLaunch: fakeMachineLaunch([]) }), /requires a signed HQ pairing epoch/);
});
const startRequest = (path) => ({ auth: 'owner', payload: { package_path: path }, takeover: true });

async function rawStart(t, path, requestedProfile) {
  const stream = connect(t.hq.paths.control);
  await new Promise((resolve, reject) => { stream.once('connect', resolve); stream.once('error', reject); });
  let text = '';
  stream.on('data', (chunk) => { text += chunk; });
  stream.write(`${JSON.stringify({ id: 1, op: 'soul.start', payload: {
    package_path: path, ...(requestedProfile ? { requested_profile: requestedProfile } : {}),
  } })}\n`);
  await waitFor(() => text.includes('\n'));
  return { stream, response: JSON.parse(text.slice(0, text.indexOf('\n'))) };
}

test('the owner cannot configure arbitrary code to run in HQ account', () => {
  assert.throws(() => validateConfig({ soulRunner: { command: ['/bin/sh'] } }), /unknown key soulRunner/);
});

test('an explicit protected Soul start never falls back to the cooperative Machine runner', async () => {
  const home = tempHome();
  const launches = [];
  const machine = fakeMachineLaunch(launches);
  await assert.rejects(starter(home, machine).dispatch('soul.start', {
    ...startRequest(home), payload: { package_path: home, requested_profile: 'managed-protected' },
  }), (error) => error.code === 'profile_insufficient');
  assert.deepEqual(launches, []);
});

test('cooperative HQ reports profile_insufficient on the owner control socket before reservation', async () => {
  const launches = [];
  const t = await startHQ(machineOptions(fakeMachineLaunch(launches)));
  let stream;
  try {
    const refused = await rawStart(t, t.home, 'managed-protected');
    stream = refused.stream;
    assert.equal(refused.response.ok, false);
    assert.equal(refused.response.refusal.error, 'profile_insufficient');
    assert.deepEqual(launches, []);
    assert.deepEqual(t.hq.status().hq.soulStarts, []);
  } finally { stream?.destroy(); await t.done(); }
});

test('an ACP runner stream error stops the Machine process and releases only after containment', { timeout: 10000 }, async () => {
  for (const side of ['stdin', 'stdout']) {
    const home = tempHome();
    const machine = fakeMachineLaunch([]);
    const originalStart = machine.start.bind(machine);
    let launch;
    let stops = 0;
    machine.start = async (reservation) => {
      launch = await originalStart(reservation);
      const originalStop = launch.stop;
      launch.stop = async () => { stops += 1; return originalStop(); };
      return launch;
    };
    const t = await startHQ({ home, ...machineOptions(machine) });
    let stream;
    try {
      const started = await rawStart(t, home);
      stream = started.stream;
      assert.equal(started.response.ok, true);
      launch[side].emit('error', new Error('fixture transport error'));
      await waitFor(() => stops === 1);
      await waitFor(() => t.hq.status().hq.soulStarts.length === 0);
      assert.equal(t.hq.core.receipts.some((r) => r.kind === 'hq.soul.exited' && r.contained === true), true);
    } finally { stream?.destroy(); await t.done(); }
  }
});

test('only the owner can request a separate Machine runner; the ACP stream stops with its owner connection', { timeout: 10000 }, async () => {
  const home = tempHome();
  const launches = [];
  const t = await startHQ({ home, config: { acceptedDefinitions: {} },
    ...machineOptions(fakeMachineLaunch(launches)) });
  let stream;
  try {
    const entry = await t.entry();
    const denied = await entry.request('soul.start', { package_path: home });
    assert.equal(denied.host_refusal.code, 'host.auth_mismatch');
    const owner = await t.owner();
    assert.deepEqual((await owner.request('soul.starts')).result, { starts: [] });
    assert.equal((await owner.request('soul.start', { package_path: home })).host_refusal.code, 'host.invalid_request');

    stream = connect(t.hq.paths.control);
    await new Promise((resolve, reject) => { stream.once('connect', resolve); stream.once('error', reject); });
    let text = '';
    stream.setEncoding('utf8');
    stream.on('data', (chunk) => { text += chunk; });
    stream.write(`${JSON.stringify({ id: 1, op: 'soul.start', payload: { package_path: home } })}\n`);
    await waitFor(() => text.includes('\n'));
    const first = JSON.parse(text.slice(0, text.indexOf('\n')));
    assert.equal(first.ok, true);
    assert.match(first.result.start_id, /^st_[0-9a-f]{24}$/);
    assert.equal(first.result.protected, false);
    assert.equal(first.result.profile, 'managed-cooperative');
    assert.equal(first.result.runner_uid, 61001);
    assert.equal(first.result.runner_gid, 61001);
    assert.equal(first.result.installation_id, 'inst_fixture');
    assert.equal(launches.length, 1);
    assert.equal(launches[0].requireHqLaunch, true);
    assert.match(launches[0].hqEpoch, /^[0-9a-f]{64}$/);
    assert.equal(launches[0].packagePath, realpathSync(home));
    assert.equal((await owner.request('soul.starts')).result.starts.length, 1);
    assert.equal((await owner.request('status')).result.hq.soulStarts.length, 1);
    const duplicate = await (await t.owner()).request('soul.start', { package_path: home });
    assert.equal(duplicate.host_refusal.code, 'host.launch_busy');

    stream.write('ping\n');
    await waitFor(() => text.includes('ACP:ping\n'));
    stream.destroy();
    await waitFor(() => t.hq.status().hq.soulStarts.length === 0);
    assert.ok(t.hq.core.receipts.some((r) => r.kind === 'hq.soul.started' && r.start_id === first.result.start_id));
    assert.ok(t.hq.core.receipts.some((r) => r.kind === 'hq.soul.exited' && r.start_id === first.result.start_id));
  } finally { stream?.destroy(); await t.done(); }
});

test('HQ rejects a runner in its own UID and does not record a managed start', async () => {
  const launches = [];
  const t = await startHQ(machineOptions(fakeMachineLaunch(launches, { uid: process.getuid() })));
  try {
    const owner = await t.owner();
    const refused = await owner.request('soul.start', { package_path: t.home });
    assert.equal(refused.host_refusal.code, 'host.launch_unavailable');
    assert.equal(launches.length, 0);
    assert.deepEqual(t.hq.status().hq.soulStarts, []);
    assert.equal(t.hq.core.receipts.some((r) => r.kind === 'hq.soul.started'), false);
  } finally { await t.done(); }
});

test('HQ rejects a Soul runner in a harness credential UID', async () => {
  const layout = harnessLayout(['hqm_a']);
  const launches = [];
  const machine = fakeMachineLaunch(launches, { uid: HARNESS_UIDS.hqm_a });
  const t = await startHQ({ platform: 'linux', accounts: layout.resolve, harnessLstat: layout.lstat,
    launch: { spawn: fakeSudo().spawn },
    config: { acceptedDefinitions: { [SOUL]: [DIGEST] },
      harnesses: { dir: layout.dir, accounts: { 'adapter-a': 'hqm_a' } } },
    ...machineOptions(machine) });
  try {
    const owner = await t.owner();
    const refused = await owner.request('soul.start', { package_path: t.home });
    assert.equal(refused.host_refusal.code, 'host.launch_unavailable');
    assert.equal(launches.length, 0);
    assert.deepEqual(t.hq.status().hq.soulStarts, []);
  } finally { await t.done(); layout.remove(); }
});

test('HQ rejects a self-asserted Machine reservation before starting a process', async () => {
  const launches = [];
  const machine = fakeMachineLaunch(launches);
  const reserve = machine.reserve.bind(machine);
  machine.reserve = async (request) => ({ ...await reserve(request), claimed_valid: true });
  const t = await startHQ(machineOptions(machine));
  try {
    const owner = await t.owner();
    const refused = await owner.request('soul.start', { package_path: t.home });
    assert.equal(refused.host_refusal.code, 'host.launch_unavailable');
    assert.equal(launches.length, 0);
    assert.deepEqual(t.hq.status().hq.soulStarts, []);
  } finally { await t.done(); }
});

test('HQ refuses a runner endpoint inside its private home', async () => {
  const launches = [];
  const machine = fakeMachineLaunch(launches, (request) => ({
    endpoint: { directory: realpathSync(request.hqHome),
      socketPath: join(realpathSync(request.hqHome), 'runner.sock'), ownerUid: process.getuid(),
      groupGid: 61001, dirMode: 0o2750, socketMode: 0o660, peerUid: 61001 },
  }));
  const t = await startHQ(machineOptions(machine));
  try {
    const owner = await t.owner();
    const refused = await owner.request('soul.start', { package_path: t.home });
    assert.equal(refused.host_refusal.code, 'host.launch_unavailable');
    assert.equal(launches.length, 0);
  } finally { await t.done(); }
});

test('a live Soul installation keeps its own runner UID', { timeout: 10000 }, async () => {
  const home = tempHome();
  const other = tempHome();
  const launches = [];
  const t = await startHQ({ home, ...machineOptions(fakeMachineLaunch(launches,
    (request) => ({ installationId: request.packagePath === realpathSync(home) ? 'inst_one' : 'inst_two' }))) });
  let stream;
  try {
    stream = connect(t.hq.paths.control);
    await new Promise((resolve, reject) => { stream.once('connect', resolve); stream.once('error', reject); });
    let response = '';
    stream.on('data', (chunk) => { response += chunk; });
    stream.write(`${JSON.stringify({ id: 1, op: 'soul.start', payload: { package_path: home } })}\n`);
    await waitFor(() => response.includes('\n'));
    assert.equal(JSON.parse(response.slice(0, response.indexOf('\n'))).ok, true);
    const owner = await t.owner();
    const refused = await owner.request('soul.start', { package_path: other });
    assert.equal(refused.host_refusal.code, 'host.launch_busy');
    assert.equal(t.hq.status().hq.soulStarts.length, 1);
  } finally { stream?.destroy(); await t.done(); rmSync(other, { recursive: true, force: true }); }
});

test('concurrent paths sharing a runner UID reserve before either process starts', { timeout: 10000 }, async () => {
  const home = tempHome();
  const other = tempHome();
  const launches = [];
  const machine = fakeMachineLaunch(launches,
    (request) => ({ installationId: request.packagePath === realpathSync(home) ? 'inst_one' : 'inst_two' }));
  const reserve = machine.reserve.bind(machine);
  let count = 0;
  let release;
  const bothReserved = new Promise((resolve) => { release = resolve; });
  machine.reserve = async (request) => {
    const reservation = await reserve(request);
    if (++count === 2) release();
    await bothReserved;
    return reservation;
  };
  const t = await startHQ({ home, ...machineOptions(machine) });
  let first;
  let second;
  try {
    [first, second] = await Promise.all([rawStart(t, home), rawStart(t, other)]);
    assert.deepEqual([first.response.ok, second.response.ok].sort(), [false, true]);
    assert.equal([first.response, second.response].find((r) => !r.ok).host_refusal.code, 'host.launch_busy');
    assert.equal(launches.length, 1);
    assert.equal(t.hq.status().hq.soulStarts.length, 1);
  } finally { first?.stream.destroy(); second?.stream.destroy(); await t.done(); rmSync(other, { recursive: true, force: true }); }
});

test('a contained start does not let another installation reuse its runner UID', { timeout: 10000 }, async () => {
  const home = tempHome();
  const other = tempHome();
  const launches = [];
  const machine = fakeMachineLaunch(launches,
    (request) => ({ installationId: request.packagePath === realpathSync(home) ? 'inst_one' : 'inst_two' }));
  const t = await startHQ({ home, ...machineOptions(machine) });
  let first;
  try {
    first = await rawStart(t, home);
    assert.equal(first.response.ok, true);
    first.stream.destroy();
    await waitFor(() => t.hq.status().hq.soulStarts.length === 0);
    const second = await rawStart(t, other);
    assert.equal(second.response.host_refusal.code, 'host.launch_unavailable');
    second.stream.destroy();
    assert.equal(launches.length, 1);
  } finally { first?.stream.destroy(); await t.done(); rmSync(other, { recursive: true, force: true }); }
});

test('a failed Machine stop keeps the runner UID and package occupied', { timeout: 10000 }, async () => {
  const home = tempHome();
  const other = tempHome();
  const launches = [];
  const t = await startHQ({ home, ...machineOptions(fakeMachineLaunch(launches,
    (request) => ({ installationId: request.packagePath === realpathSync(home) ? 'inst_one' : 'inst_two' }),
    undefined, { async stop() { throw new Error('Machine stop unavailable'); } })) });
  let first;
  try {
    first = await rawStart(t, home);
    assert.equal(first.response.ok, true);
    first.stream.destroy();
    await waitFor(() => t.hq.status().hq.soulStarts[0]?.state === 'containment_unconfirmed');
    const second = await rawStart(t, other);
    assert.equal(second.response.host_refusal.code, 'host.launch_busy');
    second.stream.destroy();
    assert.equal(launches.length, 1);
    assert.equal(t.hq.status().hq.soulStarts.length, 1);
  } finally { first?.stream.destroy(); await t.done(); rmSync(other, { recursive: true, force: true }); }
});

test('an invalid post-start identity with failed stop remains occupied', { timeout: 10000 }, async () => {
  const home = tempHome();
  const other = tempHome();
  const launches = [];
  const machine = fakeMachineLaunch(launches,
    (request) => ({ installationId: request.packagePath === realpathSync(home) ? 'inst_one' : 'inst_two' }),
    undefined, { uid: 61002, async stop() { throw new Error('stop unavailable'); } });
  const t = await startHQ({ home, ...machineOptions(machine) });
  try {
    const first = await rawStart(t, home);
    assert.equal(first.response.host_refusal.code, 'host.launch_unavailable');
    first.stream.destroy();
    assert.equal(t.hq.status().hq.soulStarts[0]?.state, 'containment_unconfirmed');
    const second = await rawStart(t, other);
    assert.equal(second.response.host_refusal.code, 'host.launch_busy');
    second.stream.destroy();
    assert.equal(launches.length, 1);
  } finally { await t.done(); rmSync(other, { recursive: true, force: true }); }
});

test('an unsigned claim of containment cannot free a runner UID', { timeout: 10000 }, async () => {
  const home = tempHome();
  const other = tempHome();
  const launches = [];
  const machine = fakeMachineLaunch(launches,
    (request) => ({ installationId: request.packagePath === realpathSync(home) ? 'inst_one' : 'inst_two' }));
  machine.verifyCompletion = async () => false;
  const t = await startHQ({ home, ...machineOptions(machine) });
  let first;
  try {
    first = await rawStart(t, home);
    assert.equal(first.response.ok, true);
    first.stream.destroy();
    await waitFor(() => t.hq.status().hq.soulStarts[0]?.state === 'containment_unconfirmed');
    const second = await rawStart(t, other);
    assert.equal(second.response.host_refusal.code, 'host.launch_busy');
    second.stream.destroy();
    assert.equal(launches.length, 1);
    assert.ok(t.hq.core.receipts.some((r) => r.kind === 'hq.soul.exited' && r.contained === false));
  } finally { first?.stream.destroy(); await t.done(); rmSync(other, { recursive: true, force: true }); }
});

test('an unconfirmed Machine stop retains the runner UID and installation slot', { timeout: 10000 }, async () => {
  const home = tempHome();
  const other = tempHome();
  const t = await startHQ({ home, ...machineOptions(fakeMachineLaunch([],
    (request) => ({ installationId: request.packagePath === realpathSync(home) ? 'inst_one' : 'inst_two' }),
    { exit_code: null, signal: null, contained: false })) });
  let stream;
  try {
    stream = connect(t.hq.paths.control);
    await new Promise((resolve, reject) => { stream.once('connect', resolve); stream.once('error', reject); });
    let response = '';
    stream.on('data', (chunk) => { response += chunk; });
    stream.write(`${JSON.stringify({ id: 1, op: 'soul.start', payload: { package_path: home } })}\n`);
    await waitFor(() => response.includes('\n'));
    assert.equal(JSON.parse(response.slice(0, response.indexOf('\n'))).ok, true);
    stream.destroy();
    await waitFor(() => t.hq.status().hq.soulStarts[0]?.state === 'containment_unconfirmed');
    const owner = await t.owner();
    const refused = await owner.request('soul.start', { package_path: other });
    assert.equal(refused.host_refusal.code, 'host.launch_busy');
    assert.equal(t.hq.status().hq.soulStarts.length, 1);
    assert.ok(t.hq.core.receipts.some((r) => r.kind === 'hq.soul.exited' && r.contained === false));
  } finally { stream?.destroy(); await t.done(); rmSync(other, { recursive: true, force: true }); }
});

test('an unconfigured HQ refuses Soul start and never reports a live start', async () => {
  const t = await startHQ();
  try {
    const owner = await t.owner();
    const refused = await owner.request('soul.start', { package_path: t.home });
    assert.equal(refused.host_refusal.code, 'host.launch_unavailable');
    assert.deepEqual(t.hq.status().hq.soulStarts, []);
  } finally { await t.done(); }
});

test('shutdown fences a Machine reservation that completes after stopAll', async () => {
  const home = tempHome();
  const launches = [];
  const machine = fakeMachineLaunch(launches);
  const reserve = machine.reserve.bind(machine);
  let entered;
  let release;
  const reserving = new Promise((resolve) => { entered = resolve; });
  const held = new Promise((resolve) => { release = resolve; });
  machine.reserve = async (request) => { entered(); await held; return reserve(request); };
  const control = starter(home, machine);
  try {
    const pending = control.dispatch('soul.start', startRequest(home));
    await reserving;
    await control.stopAll();
    release();
    await assert.rejects(pending, (error) => error.code === 'host.launch_unavailable');
    assert.equal(launches.length, 0);
    assert.deepEqual(control.report(), []);
  } finally { release(); rmSync(home, { recursive: true, force: true }); }
});

test('shutdown during pending Machine start stops its late runner before takeover', async () => {
  const home = tempHome();
  const launches = [];
  const machine = fakeMachineLaunch(launches);
  const start = machine.start.bind(machine);
  let entered;
  let release;
  let stops = 0;
  const starting = new Promise((resolve) => { entered = resolve; });
  const held = new Promise((resolve) => { release = resolve; });
  machine.start = async (reservation) => {
    entered();
    await held;
    const launch = await start(reservation);
    const stop = launch.stop;
    launch.stop = async () => { stops += 1; return stop(); };
    return launch;
  };
  const control = starter(home, machine);
  try {
    const pending = control.dispatch('soul.start', startRequest(home));
    await starting;
    const stopped = control.stopAll();
    release();
    await assert.rejects(pending, (error) => error.code === 'host.launch_unavailable');
    await stopped;
    assert.equal(launches.length, 1);
    assert.equal(stops, 1);
    assert.deepEqual(control.report(), []);
  } finally { release(); rmSync(home, { recursive: true, force: true }); }
});

test('failed stop of a late Machine runner remains occupied and can be retried', async () => {
  const home = tempHome();
  const machine = fakeMachineLaunch([]);
  const start = machine.start.bind(machine);
  let entered;
  let release;
  let stops = 0;
  const starting = new Promise((resolve) => { entered = resolve; });
  const held = new Promise((resolve) => { release = resolve; });
  machine.start = async (reservation) => {
    entered();
    await held;
    return { ...await start(reservation), async stop() { stops += 1; throw new Error('stop unavailable'); } };
  };
  const control = starter(home, machine);
  try {
    const pending = control.dispatch('soul.start', startRequest(home));
    await starting;
    const stopped = control.stopAll();
    release();
    await assert.rejects(pending, (error) => error.code === 'host.launch_unavailable');
    await stopped;
    assert.equal(control.report()[0]?.state, 'containment_unconfirmed');
    assert.ok(stops >= 1);
    const beforeRetry = stops;
    await control.stopAll();
    assert.ok(stops > beforeRetry, 'an unconfirmed stop is retried rather than treated as contained');
  } finally { release(); rmSync(home, { recursive: true, force: true }); }
});

test('a null Machine completion cannot produce an ACP takeover or release occupancy', async () => {
  const home = tempHome();
  const machine = fakeMachineLaunch([]);
  const start = machine.start.bind(machine);
  machine.start = async (reservation) => ({ ...await start(reservation), done: Promise.resolve(null) });
  const control = starter(home, machine);
  try {
    await assert.rejects(control.dispatch('soul.start', startRequest(home)),
      (error) => error.code === 'host.launch_unavailable');
    assert.equal(control.report()[0]?.state, 'containment_unconfirmed');
  } finally { await control.stopAll(); rmSync(home, { recursive: true, force: true }); }
});

test('a completed runner cannot take over ACP while completion verification is pending', async () => {
  const home = tempHome();
  const machine = fakeMachineLaunch([]);
  const start = machine.start.bind(machine);
  let release;
  const held = new Promise((resolve) => { release = resolve; });
  machine.start = async (reservation) => ({ ...await start(reservation),
    done: Promise.resolve({ contained: true, startId: reservation.startId }) });
  machine.verifyCompletion = async () => { await held; return false; };
  const control = starter(home, machine);
  try {
    await assert.rejects(control.dispatch('soul.start', startRequest(home)),
      (error) => error.code === 'host.launch_unavailable');
    assert.equal(control.report()[0]?.state, 'containment_unconfirmed', 'terminal occupancy remains until signed containment');
  } finally {
    release();
    await control.stopAll();
    rmSync(home, { recursive: true, force: true });
  }
});

test('a symlink alias into HQ home cannot stage a runner copy or endpoint', async () => {
  const home = tempHome();
  const aliases = tempHome();
  const alias = join(aliases, 'private');
  symlinkSync(home, alias);
  try {
    for (const field of ['runnerPackagePath', 'endpoint']) {
      const launches = [];
      const machine = fakeMachineLaunch(launches, () => field === 'runnerPackagePath'
        ? { runnerPackagePath: join(alias, 'runner-copy') }
        : { endpoint: { directory: join(alias, 'runner-endpoint'),
          socketPath: join(alias, 'runner-endpoint', 'admission.sock'), ownerUid: process.getuid(),
          groupGid: 61001, dirMode: 0o2750, socketMode: 0o660, peerUid: 61001 } });
      const control = starter(home, machine);
      await assert.rejects(control.dispatch('soul.start', startRequest(home)),
        (error) => error.code === 'host.launch_unavailable');
      assert.equal(launches.length, 0);
      assert.deepEqual(control.report(), []);
    }
  } finally { rmSync(aliases, { recursive: true, force: true }); rmSync(home, { recursive: true, force: true }); }
});

test('a dangling symlink toward HQ home cannot be treated as a missing runner copy', async () => {
  const home = tempHome();
  const aliases = tempHome();
  const alias = join(aliases, 'future-private');
  symlinkSync(join(home, 'not-yet-provisioned'), alias);
  const launches = [];
  const machine = fakeMachineLaunch(launches, { runnerPackagePath: join(alias, 'copy') });
  const control = starter(home, machine);
  try {
    await assert.rejects(control.dispatch('soul.start', startRequest(home)),
      (error) => error.code === 'host.launch_unavailable');
    assert.equal(launches.length, 0);
    assert.deepEqual(control.report(), []);
  } finally { rmSync(aliases, { recursive: true, force: true }); rmSync(home, { recursive: true, force: true }); }
});

test('the owner CLI speaks the start handshake and relays ACP', { timeout: 10000 }, async () => {
  const home = tempHome();
  const server = createServer((socket) => {
    socket.once('data', () => {
      socket.write(`${JSON.stringify({ id: 1, ok: true, result: { start_id: 'st_test', pid: 42 } })}\n`);
      socket.on('data', (chunk) => socket.write(`ACP:${chunk}`));
    });
  });
  await new Promise((resolve) => server.listen(join(home, 'control.sock'), resolve));
  let cli;
  try {
    cli = spawn(process.execPath, [new URL('../hq/main.mjs', import.meta.url).pathname, 'soul', 'start', '--home', home, '--soul', home], { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    cli.stdout.on('data', (chunk) => { stdout += chunk; });
    cli.stderr.on('data', (chunk) => { stderr += chunk; });
    await waitFor(() => stderr.includes('HQ started Soul runner'));
    cli.stdin.write('ping\n');
    await waitFor(() => stdout.includes('ACP:ping\n'));
    cli.stdin.end();
    cli.kill('SIGTERM');
  } finally {
    cli?.kill('SIGKILL');
    await new Promise((resolve) => server.close(resolve));
  }
});
