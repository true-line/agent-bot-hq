// HQ-owned Soul runner control. Machine must launch the runner under an
// independently provisioned untrusted UID; HQ never directly spawns it in
// its private account. The owner connection becomes the runner's ACP stream.
// This local event is not a protected qualification or signed provenance.
import { lstatSync, realpathSync } from 'node:fs';
import { basename, dirname, isAbsolute, join, sep } from 'node:path';
import { fail } from '../sdk/errors.mjs';
import { pushReceipt } from '../sdk/services.mjs';
import { takeover } from './socket.mjs';

const START_OP = 'soul.start';
const ID = /^st_[0-9a-f]{24}$/;
const SOUL_ID = /^agent_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const INSTALLATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const PACKAGE_SHA256 = /^[0-9a-f]{64}$/;

// machineLaunch is supplied only by a trusted Machine client wired into HQ's
// entry point. reserve() must not start a process; verifyMachineReservation()
// must authenticate Machine's one-use binding independently of that client.
// Production passes no client until Machine #629/#630 implement that proof.
export function createSoulStarter({ core, home, machineLaunch, verifyMachineReservation, verifyMachineCompletion,
  mode, hqUid = process.getuid?.(), harnessUids = [] } = {}) {
  // Machine's fixed SoulRunRequest header uses exactly 64 lowercase hex.
  const hqEpoch = core.random.hex(32);
  const excludedUids = new Set(harnessUids);
  const starts = new Map();
  const byPath = new Map();
  const byInstallation = new Map();
  const byUid = new Map();
  const installationBinding = new Map();
  const uidOwner = new Map();
  let shuttingDown = false;
  const report = () => [...starts.values()].map(({ id, path, pid, uid, gid, soulId, installationId, packageDigest, startedAt, state }) => ({
    start_id: id, package_path: path, pid, runner_uid: uid, runner_gid: gid,
    soul_id: soulId, installation_id: installationId, package_digest: packageDigest,
    hq_epoch: hqEpoch, started_at: startedAt, state,
  }));

  function stop(item) {
    item.stopRequested = true;
    item.state = 'stopping';
    if (!item.launch) return item.startSettled.then(() => item.launch ? stop(item) : undefined);
    if (item.stopPromise) return item.stopPromise;
    // Machine owns group termination and must confirm containment. HQ keeps
    // the live slot until its completion report; no local signal is enough.
    item.stopPromise = Promise.resolve().then(() => item.launch.stop()).then(
      () => item.done,
      () => { item.state = 'containment_unconfirmed'; },
    ).finally(() => { if (starts.has(item.id)) item.stopPromise = null; });
    return item.stopPromise;
  }

  async function dispatch(op, { auth, payload, takeover: canTakeOver }) {
    if (op === 'soul.starts') {
      if (auth !== 'owner') fail('host.auth_mismatch', 'Soul starts are owner-only');
      return { starts: report() };
    }
    if (op !== START_OP) fail('host.invalid_request', `unknown Soul start operation ${op}`);
    if (auth !== 'owner') fail('host.auth_mismatch', 'Soul start is owner-only');
    if (!canTakeOver) fail('host.invalid_request', 'soul.start must be the first request on a new owner connection');
    if (shuttingDown || mode() !== 'running') fail('host.launch_unavailable', 'HQ is not running admissions');
    if (!machineLaunch || typeof machineLaunch.reserve !== 'function'
      || typeof verifyMachineReservation !== 'function' || typeof verifyMachineCompletion !== 'function'
      || typeof machineLaunch.start !== 'function') {
      fail('host.launch_unavailable', 'Machine has not provisioned an authenticated Soul runner launch route');
    }
    if (!payload || typeof payload !== 'object' || Array.isArray(payload)
      || Object.keys(payload).some((k) => k !== 'package_path')
      || typeof payload.package_path !== 'string' || !isAbsolute(payload.package_path)) {
      fail('host.invalid_request', 'soul.start needs an absolute package_path');
    }
    let path;
    try {
      path = realpathSync(payload.package_path);
      if (!lstatSync(path).isDirectory()) throw new Error('not a directory');
    } catch { fail('host.invalid_request', 'soul.start package_path is not an existing directory'); }
    const hqRoot = realpathSync(home);
    const canonicalCandidate = (candidate) => {
      let existing = candidate;
      const missing = [];
      while (true) {
        try { return join(realpathSync(existing), ...missing); }
        catch (error) {
          if (error?.code !== 'ENOENT') throw error;
          // A dangling symlink is an existing path component, not an absent
          // leaf that Machine may safely fill after reservation.
          if (lstatSync(existing, { throwIfNoEntry: false })) throw new Error('runner path contains an unresolved symlink');
          const parent = dirname(existing);
          if (parent === existing) throw error;
          missing.unshift(basename(existing));
          existing = parent;
        }
      }
    };
    const inHqHome = (candidate) => {
      const canonical = canonicalCandidate(candidate);
      return canonical === hqRoot || canonical.startsWith(`${hqRoot}${sep}`);
    };
    if (byPath.has(path)) fail('host.launch_busy', 'HQ has already started this Soul package');
    const id = `st_${core.random.hex(12)}`;
    if (!ID.test(id)) throw new Error('invalid HQ start ID');
    // Reserve before the first await so concurrent owner requests cannot
    // start the same package twice.
    byPath.set(path, id);
    const request = { startId: id, packagePath: path, hqEpoch, hqHome: home,
      profile: 'managed-cooperative', requireHqLaunch: true };
    let reservation;
    try {
      reservation = await machineLaunch.reserve(request);
      if (reservation?.endpoint && typeof reservation.endpoint === 'object') Object.freeze(reservation.endpoint);
      Object.freeze(reservation);
      const valid = reservation?.startId === id && reservation.packagePath === path
        && reservation.hqEpoch === hqEpoch
        && Number.isSafeInteger(reservation.uid) && reservation.uid > 0
        && reservation.uid !== hqUid && !excludedUids.has(reservation.uid)
        && Number.isSafeInteger(reservation.gid) && reservation.gid > 0
        && SOUL_ID.test(reservation.soulId ?? '') && INSTALLATION_ID.test(reservation.installationId ?? '')
        && DIGEST.test(reservation.definitionDigest ?? '') && PACKAGE_SHA256.test(reservation.packageDigest ?? '')
        && typeof reservation.runnerPackagePath === 'string' && isAbsolute(reservation.runnerPackagePath)
        && reservation.runnerPackagePath !== path && !inHqHome(reservation.runnerPackagePath)
        && typeof reservation.endpoint?.directory === 'string' && isAbsolute(reservation.endpoint.directory)
        && !inHqHome(reservation.endpoint.directory)
        && typeof reservation.endpoint.socketPath === 'string'
        && dirname(reservation.endpoint.socketPath) === reservation.endpoint.directory
        && reservation.endpoint.ownerUid === hqUid && reservation.endpoint.groupGid === reservation.gid
        && reservation.endpoint.dirMode === 0o2750 && reservation.endpoint.socketMode === 0o660
        && reservation.endpoint.peerUid === reservation.uid;
      if (!valid || await verifyMachineReservation(reservation, request) !== true) {
        fail('host.launch_unavailable', 'Machine reservation lacks an authenticated per-installation runner binding');
      }
      if (shuttingDown) {
        try { await reservation.cancel?.(); } catch { /* Machine reservation may already have expired */ }
        fail('host.launch_unavailable', 'HQ stopped before Machine reservation completed');
      }
    } catch (error) {
      byPath.delete(path);
      fail('host.launch_unavailable', `Machine refused Soul runner reservation: ${error?.code ?? error?.message ?? 'unavailable'}`);
    }
    // No process has been started yet. All three maps are occupied before
    // awaiting Machine.start, including when another path races this one.
    if (byInstallation.has(reservation.installationId) || byUid.has(reservation.uid)) {
      byPath.delete(path);
      try { await reservation.cancel?.(); } catch { /* reservation can expire in Machine */ }
      fail('host.launch_busy', 'Soul installation or runner account already has a live start');
    }
    const prior = installationBinding.get(reservation.installationId);
    if ((uidOwner.has(reservation.uid) && uidOwner.get(reservation.uid) !== reservation.installationId)
      || (prior && (prior.uid !== reservation.uid || prior.path !== path
        || prior.packageDigest !== reservation.packageDigest
        || prior.runnerPackagePath !== reservation.runnerPackagePath))) {
      byPath.delete(path);
      try { await reservation.cancel?.(); } catch { /* no process started */ }
      fail('host.launch_unavailable', 'Machine remapped a Soul installation or reused its runner UID');
    }
    installationBinding.set(reservation.installationId, {
      uid: reservation.uid, path, packageDigest: reservation.packageDigest,
      runnerPackagePath: reservation.runnerPackagePath,
    });
    uidOwner.set(reservation.uid, reservation.installationId);
    let settleStart;
    const startSettled = new Promise((resolve) => { settleStart = resolve; });
    const item = { id, path, pid: null, uid: reservation.uid, gid: reservation.gid,
      soulId: reservation.soulId, installationId: reservation.installationId,
      definitionDigest: reservation.definitionDigest, packageDigest: reservation.packageDigest,
      launch: null, startedAt: new Date(core.clock.now()).toISOString(), state: 'starting',
      stopRequested: false, stopPromise: null, startSettled, terminal: false };
    starts.set(id, item);
    byInstallation.set(item.installationId, id);
    byUid.set(item.uid, id);
    let launch;
    try { launch = await machineLaunch.start(reservation); }
    catch (error) {
      // A transport error after Machine accepted start may hide a live process.
      // Keep all reservations until a future authenticated reconciliation.
      item.state = 'containment_unconfirmed';
      settleStart();
      fail('host.launch_unavailable', `Machine Soul runner start is unconfirmed: ${error?.code ?? error?.message ?? 'unavailable'}`);
    }
    item.launch = launch;
    item.pid = launch?.pid ?? null;
    item.done = Promise.resolve(launch?.done).then((result) => result,
      () => ({ contained: false, exit_code: null, signal: null })).then(async (result) => {
      // Completion is terminal immediately. Verification may block, but no
      // ACP takeover may begin while its signed containment is pending.
      item.terminal = true;
      item.state = 'containment_unconfirmed';
      const safeResult = result && typeof result === 'object' ? result : {};
      const { exit_code = null, signal = null, contained = false } = safeResult;
      let confirmed = false;
      if (contained === true) {
        try {
          confirmed = await verifyMachineCompletion(safeResult, {
            startId: id, hqEpoch, packagePath: path, uid: item.uid, gid: item.gid,
            soulId: item.soulId, installationId: item.installationId,
            definitionDigest: item.definitionDigest, packageDigest: item.packageDigest,
            runnerPackagePath: reservation.runnerPackagePath, endpoint: reservation.endpoint,
          }) === true;
        } catch { /* an unverifiable completion keeps the slot occupied */ }
      }
      if (confirmed === true) {
        starts.delete(id);
        byPath.delete(path);
        byInstallation.delete(item.installationId);
        byUid.delete(item.uid);
      } else {
        item.state = 'containment_unconfirmed';
      }
      await pushReceipt(core, { plugin: 'hq', kind: 'hq.soul.exited', start_id: id,
        installation_id: item.installationId, hq_epoch: hqEpoch, exit_code, signal,
        contained: confirmed === true }).catch(() => {});
    }).catch(() => { item.terminal = true; item.state = 'containment_unconfirmed'; });
    settleStart();
    const validLaunch = launch?.startId === id && launch.packagePath === path
      && launch.hqEpoch === hqEpoch && launch.uid === item.uid && launch.gid === item.gid
      && launch.soulId === item.soulId && launch.installationId === item.installationId
      && launch.definitionDigest === item.definitionDigest && launch.packageDigest === item.packageDigest
      && launch.runnerPackagePath === reservation.runnerPackagePath
      && launch.endpoint?.directory === reservation.endpoint.directory
      && launch.endpoint?.socketPath === reservation.endpoint.socketPath
      && launch.endpoint?.ownerUid === reservation.endpoint.ownerUid
      && launch.endpoint?.groupGid === reservation.endpoint.groupGid
      && launch.endpoint?.dirMode === reservation.endpoint.dirMode
      && launch.endpoint?.socketMode === reservation.endpoint.socketMode
      && launch.endpoint?.peerUid === reservation.endpoint.peerUid
      && Number.isSafeInteger(launch.pid) && launch.pid > 1
      && typeof launch.stdin?.write === 'function' && typeof launch.stdout?.pipe === 'function'
      && typeof launch.stop === 'function' && typeof launch.done?.then === 'function';
    if (!validLaunch) {
      if (typeof launch?.stop === 'function') await stop(item);
      else item.state = 'containment_unconfirmed';
      fail('host.launch_unavailable', 'Machine launch response did not match its authenticated reservation');
    }
    // Let an already-settled completion run before reporting a live ACP
    // takeover. A later completion is also checked in open() below.
    await new Promise((resolve) => setImmediate(resolve));
    if (shuttingDown || item.stopRequested || item.terminal) {
      if (!item.terminal) await stop(item);
      fail('host.launch_unavailable', 'Soul runner stopped before ACP takeover');
    }
    item.state = 'running';
    launch.stdin.on?.('error', () => {});
    launch.stdout.on?.('error', () => {});
    try {
      await pushReceipt(core, { plugin: 'hq', kind: 'hq.soul.started', start_id: id, package_path: path,
        soul_id: item.soulId, installation_id: item.installationId, definition_digest: item.definitionDigest,
        package_digest: item.packageDigest, hq_epoch: hqEpoch,
        pid: item.pid, runner_uid: item.uid, runner_gid: item.gid });
    } catch (error) {
      await stop(item);
      throw error;
    }
    if (item.terminal || !starts.has(id) || shuttingDown) fail('host.launch_unavailable', 'Soul runner exited before its ACP stream was attached');
    const result = { start_id: id, package_path: path, pid: item.pid, runner_uid: item.uid, runner_gid: item.gid,
      soul_id: item.soulId, installation_id: item.installationId, definition_digest: item.definitionDigest,
      package_digest: item.packageDigest, hq_epoch: hqEpoch,
      profile: 'managed-cooperative', protected: false };
    return takeover(result, {
      open: () => (socket) => {
        if (item.terminal || !starts.has(id) || shuttingDown) { socket.destroy(); return; }
        socket.pipe(launch.stdin);
        launch.stdout.pipe(socket);
        socket.once('close', () => { stop(item); });
        item.done.then(() => socket.end());
      },
      cancel: () => { stop(item); },
    });
  }

  return { dispatch, report, stopAll: async () => {
    shuttingDown = true;
    await Promise.all([...starts.values()].map(stop));
  } };
}
