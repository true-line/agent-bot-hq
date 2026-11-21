// HQ-owned Soul runner. A control connection becomes the runner's ACP stream;
// the runner is a child of HQ, and disconnect or HQ shutdown stops it. This
// records process ownership, not a protected-launch qualification or a signed
// provenance receipt. Those require a separate Machine/keyd purpose.
import { spawn } from 'node:child_process';
import { lstatSync, realpathSync } from 'node:fs';
import { isAbsolute } from 'node:path';
import { fail } from '../sdk/errors.mjs';
import { pushReceipt } from '../sdk/services.mjs';
import { takeover } from './socket.mjs';

const START_OP = 'soul.start';
const ID = /^st_[0-9a-f]{24}$/;
const STOP_GRACE_MS = 5_000;

export function createSoulStarter({ core, home, runner, mode, spawnProcess = spawn, graceMs = STOP_GRACE_MS } = {}) {
  if (runner && (!Array.isArray(runner.command) || runner.command.length < 1
    || runner.command.length > 16 || runner.command.some((arg) => typeof arg !== 'string' || !arg || arg.length > 1024)
    || !isAbsolute(runner.command[0]))) throw new TypeError('trusted Soul runner needs an absolute executable and bounded argv');
  const starts = new Map();
  const byPath = new Map();
  const report = () => [...starts.values()].map(({ id, path, pid, startedAt }) => ({ start_id: id, package_path: path, pid, started_at: startedAt }));

  function stop(item) {
    if (item.stopping) return item.done;
    item.stopping = true;
    item.child.kill('SIGTERM');
    const timer = setTimeout(() => item.child.kill('SIGKILL'), graceMs);
    timer.unref?.();
    item.done.finally(() => clearTimeout(timer));
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
    if (!runner) fail('host.launch_unavailable', 'HQ has no configured Soul runner');
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
    let child;
    try {
      child = spawnProcess(runner.command[0], [...runner.command.slice(1), 'run', '--soul', path, '--hq-home', home, '--profile', 'managed-cooperative'], {
        cwd: path, env: { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: process.env.HOME ?? home, AGENT_BOT_HQ_HOME: home, AGENT_BOT_SOULS_REQUIRE_HQ_LAUNCH: '1' },
        stdio: ['pipe', 'pipe', 'ignore'], windowsHide: true,
      });
      await new Promise((resolve, reject) => {
        child.once('spawn', () => { child.off('error', reject); resolve(); });
        child.once('error', reject);
      });
    } catch (error) {
      byPath.delete(path);
      fail('host.launch_unavailable', `Soul runner could not start: ${error?.code ?? error?.message ?? 'spawn failed'}`);
    }
    const item = { id, path, pid: child.pid, child, startedAt: new Date(core.clock.now()).toISOString(), stopping: false };
    // A runner that exits before ACP attaches can close its pipes. Pipe
    // errors must never become uncaught exceptions in the HQ process.
    child.stdin.on('error', () => {});
    child.stdout.on('error', () => {});
    child.on('error', () => {});
    item.done = new Promise((resolve) => child.once('close', (code, signal) => {
      starts.delete(id);
      byPath.delete(path);
      pushReceipt(core, { plugin: 'hq', kind: 'hq.soul.exited', start_id: id, exit_code: code, signal }).catch(() => {});
      resolve();
    }));
    starts.set(id, item);
    try {
      await pushReceipt(core, { plugin: 'hq', kind: 'hq.soul.started', start_id: id, package_path: path, pid: child.pid });
    } catch (error) {
      await stop(item);
      throw error;
    }
    if (!starts.has(id)) fail('host.launch_unavailable', 'Soul runner exited before its ACP stream was attached');
    const result = { start_id: id, package_path: path, pid: child.pid, profile: 'managed-cooperative', protected: false };
    return takeover(result, {
      open: () => (socket) => {
        socket.pipe(child.stdin);
        child.stdout.pipe(socket);
        socket.once('close', () => { stop(item); });
        item.done.then(() => socket.end());
      },
      cancel: () => { stop(item); },
    });
  }

  return { dispatch, report, stopAll: async () => { await Promise.all([...starts.values()].map(stop)); } };
}
