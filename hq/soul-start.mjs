// HQ-owned Soul runner control. Machine must launch the runner under an
// independently provisioned untrusted UID; HQ never directly spawns it in
// its private account. The owner connection becomes the runner's ACP stream.
// This local event is not a protected qualification or signed provenance.
import { lstatSync, realpathSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { fail } from '../sdk/errors.mjs';
import { pushReceipt } from '../sdk/services.mjs';
import { takeover } from './socket.mjs';

const START_OP = 'soul.start';
const ID = /^st_[0-9a-f]{24}$/;
const SOUL_ID = /^agent_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
const INSTALLATION_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;

// launchRunner is supplied only by a verified Machine launcher wired into
// HQ's trusted entry point. It must return a confirmed non-HQ UID, fixed
// start/path identity, bounded stop(), completion promise and ACP streams.
// Production passes no launcher until Machine #630 defines that contract.
export function createSoulStarter({ core, home, launchRunner, mode, hqUid = process.getuid?.() } = {}) {
  const starts = new Map();
  const byPath = new Map();
  const byInstallation = new Map();
  const byUid = new Map();
  const report = () => [...starts.values()].map(({ id, path, pid, uid, gid, soulId, installationId, startedAt, state }) => ({
    start_id: id, package_path: path, pid, runner_uid: uid, runner_gid: gid,
    soul_id: soulId, installation_id: installationId, started_at: startedAt, state,
  }));

  function stop(item) {
    if (item.stopping) return item.done;
    item.stopping = true;
    // Machine owns group termination and must confirm containment. HQ keeps
    // the live slot until its completion report; no local signal is enough.
    Promise.resolve().then(() => item.launch.stop()).catch(() => {});
    return item.done;
  }

  async function dispatch(op, { auth, payload, takeover: canTakeOver }) {
    if (op === 'soul.starts') {
      if (auth !== 'owner') fail('host.auth_mismatch', 'Soul starts are owner-only');
      return { starts: report() };
    }
    if (op !== START_OP) fail('host.invalid_request', `unknown Soul start operation ${op}`);
    if (auth !== 'owner') fail('host.auth_mismatch', 'Soul start is owner-only');
    if (!canTakeOver) fail('host.invalid_request', 'soul.start must be the first request on a new owner connection');
    if (mode() !== 'running') fail('host.launch_unavailable', 'HQ is not running admissions');
    if (!launchRunner) fail('host.launch_unavailable', 'Machine has not provisioned a separate Soul runner launch route');
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
    if (byPath.has(path)) fail('host.launch_busy', 'HQ has already started this Soul package');
    const id = `st_${core.random.hex(12)}`;
    if (!ID.test(id)) throw new Error('invalid HQ start ID');
    // Reserve before the first await so concurrent owner requests cannot
    // start the same package twice.
    byPath.set(path, id);
    let launch;
    try {
      launch = await launchRunner({ startId: id, packagePath: path, hqHome: home,
        profile: 'managed-cooperative', requireHqLaunch: true });
    } catch (error) {
      byPath.delete(path);
      fail('host.launch_unavailable', `Machine refused Soul runner launch: ${error?.code ?? error?.message ?? 'unavailable'}`);
    }
    const valid = launch && launch.startId === id && launch.packagePath === path
      && Number.isSafeInteger(launch.uid) && launch.uid > 0 && launch.uid !== hqUid
      && Number.isSafeInteger(launch.gid) && launch.gid > 0
      && SOUL_ID.test(launch.soulId ?? '') && INSTALLATION_ID.test(launch.installationId ?? '')
      && DIGEST.test(launch.definitionDigest ?? '')
      && Number.isSafeInteger(launch.pid) && launch.pid > 1
      && typeof launch.stdin?.write === 'function' && typeof launch.stdout?.pipe === 'function'
      && typeof launch.stop === 'function' && typeof launch.done?.then === 'function';
    if (!valid) {
      byPath.delete(path);
      try { await launch?.stop?.(); } catch { /* no usable start record */ }
      fail('host.launch_unavailable', 'Machine launch did not return a separate runner UID, installation identity and bounded stream');
    }
    if (byInstallation.has(launch.installationId) || byUid.has(launch.uid)) {
      byPath.delete(path);
      try { await launch.stop(); } catch { /* a duplicate launch is never admitted */ }
      fail('host.launch_busy', 'Soul installation or runner account already has a live start');
    }
    const item = { id, path, pid: launch.pid, uid: launch.uid, gid: launch.gid,
      soulId: launch.soulId, installationId: launch.installationId, definitionDigest: launch.definitionDigest,
      launch, startedAt: new Date(core.clock.now()).toISOString(), state: 'running', stopping: false };
    item.done = Promise.resolve(launch.done).then((result) => result,
      () => ({ contained: false, exit_code: null, signal: null })).then(async (result = {}) => {
      const { exit_code = null, signal = null, contained = false } = result;
      if (contained === true) {
        starts.delete(id);
        byPath.delete(path);
        byInstallation.delete(item.installationId);
        byUid.delete(item.uid);
      } else {
        // A lost Machine completion report cannot free the UID or path for
        // another launch. Reconciliation must establish containment first.
        item.state = 'containment_unconfirmed';
      }
      await pushReceipt(core, { plugin: 'hq', kind: 'hq.soul.exited', start_id: id, exit_code, signal,
        contained: contained === true }).catch(() => {});
    });
    starts.set(id, item);
    byInstallation.set(item.installationId, id);
    byUid.set(item.uid, id);
    try {
      await pushReceipt(core, { plugin: 'hq', kind: 'hq.soul.started', start_id: id, package_path: path,
        soul_id: item.soulId, installation_id: item.installationId, definition_digest: item.definitionDigest,
        pid: item.pid, runner_uid: item.uid, runner_gid: item.gid });
    } catch (error) {
      await stop(item);
      throw error;
    }
    if (!starts.has(id)) fail('host.launch_unavailable', 'Soul runner exited before its ACP stream was attached');
    const result = { start_id: id, package_path: path, pid: item.pid, runner_uid: item.uid, runner_gid: item.gid,
      soul_id: item.soulId, installation_id: item.installationId, definition_digest: item.definitionDigest,
      profile: 'managed-cooperative', protected: false };
    return takeover(result, {
      open: () => (socket) => {
        socket.pipe(launch.stdin);
        launch.stdout.pipe(socket);
        socket.once('close', () => { stop(item); });
        item.done.then(() => socket.end());
      },
      cancel: () => { stop(item); },
    });
  }

  return { dispatch, report, stopAll: async () => { await Promise.all([...starts.values()].map(stop)); } };
}
