import { randomBytes } from 'node:crypto';
import { fail, HostError } from '../sdk/errors.mjs';
import { pushReceipt } from '../sdk/services.mjs';
import { takeover } from './socket.mjs';

const unavailable = (message) => fail('host.launch_unavailable', message);

export function createStage2aCooperativeStarter({ machine, core, openAdmission, timeoutMs = 30000 }) {
  const starts = new Map();
  const paths = new Set();
  const installations = new Set();
  const runnerUids = new Set();
  let closing = false;

  const view = (item) => {
    const assignment = item.reservation?.payload.assignment;
    return { start_id: item.id, package_path: item.path, pid: item.pid ?? null,
      runner_uid: assignment?.runner_uid ?? null, runner_gid: assignment?.runner_gid ?? null,
      soul_id: assignment?.soul_id ?? null, installation_id: item.installation?.installation_id ?? null,
      package_digest: assignment?.package_sha256 ?? null, hq_epoch: item.installation?.hq_epoch ?? null,
      started_at: item.startedAt, state: item.state };
  };

  function release(item) {
    starts.delete(item.id);
    paths.delete(item.path);
    if (item.ownsInstallation) installations.delete(item.installation.installation_id);
    if (item.ownsRunnerUid) runnerUids.delete(item.installation.runner_uid);
  }

  function stop(item) {
    if (item.stopPromise) return item.stopPromise;
    if (item.state === 'stopped') return Promise.resolve({ start_id: item.id, state: item.state, contained: true });
    item.state = 'stopping';
    item.abort.abort();
    if (item.reservation) machine.revoke(item.reservation);
    item.acp?.destroy();
    item.owner?.destroy();
    const closed = Promise.resolve(item.listener?.close());
    item.stopPromise = (async () => {
      await closed.catch(() => {});
      await item.prepared;
      let proof;
      if (item.reservation) {
        try { proof = await machine.stop(item.reservation); }
        catch { /* A refused or could not confirm containment. */ }
      }
      if (!proof && item.reserveAttempted) {
        item.state = 'containment_unconfirmed';
        return { start_id: item.id, state: item.state, contained: false };
      }
      item.state = 'stopped';
      release(item);
      if (proof) await pushReceipt(core, { plugin: 'hq', kind: 'hq.soul.exited',
        start_id: item.id, installation_id: item.installation.installation_id,
        hq_epoch: item.installation.hq_epoch, contained: true, cutoff_sha256: proof.sha256 });
      return { start_id: item.id, state: item.state, contained: true };
    })().finally(() => { item.stopPromise = undefined; });
    return item.stopPromise;
  }

  async function start(path) {
    if (closing) unavailable('HQ is stopping cooperative Soul starts');
    if (paths.has(path)) fail('host.launch_busy', 'HQ has already reserved this Soul package');
    const id = `st_${core.random.hex(12)}`;
    let settlePreparation;
    const prepared = new Promise((resolve) => { settlePreparation = resolve; });
    const item = { id, path, state: 'starting', startedAt: new Date(core.clock.now()).toISOString(),
      abort: new AbortController(), prepared };
    starts.set(id, item);
    paths.add(path);
    const running = () => !item.abort.signal.aborted && !closing;
    const checkRunning = () => { if (!running()) unavailable('cooperative Soul start was revoked'); };
    const lost = () => { void stop(item).catch(() => {}); };

    let stream;
    try {
      item.installation = await machine.lookup(path);
      checkRunning();
      const { installation_id: installationId, runner_uid: runnerUid } = item.installation;
      if (installations.has(installationId) || runnerUids.has(runnerUid))
        fail('host.launch_busy', 'HQ has already reserved this Soul installation or runner account');
      installations.add(installationId);
      item.ownsInstallation = true;
      runnerUids.add(runnerUid);
      item.ownsRunnerUid = true;
      item.reserveAttempted = true;
      item.reservation = await machine.reserve(item.installation, {
        startId: id, launchId: `ln_${core.random.hex(12)}`, challenge: randomBytes(32),
      });
      machine.watch(item.reservation, lost);
      if (!running()) machine.revoke(item.reservation);
      checkRunning();
      await machine.projection(item.reservation);
      checkRunning();

      let accept;
      const acp = new Promise((resolve) => { accept = resolve; });
      item.listener = await openAdmission({ reservation: item.reservation,
        openAcpStream: (socket, context) => {
          if (!running()) { socket.destroy(); return; }
          machine.markAcp(item.reservation, context, socket);
          item.acp = socket;
          socket.pause();
          socket.on('error', lost);
          socket.once('close', lost);
          accept({ socket, context });
        }, onLost: lost });
      if (!running()) await item.listener.close();
      checkRunning();
      settlePreparation();

      const deadline = AbortSignal.any([item.abort.signal, AbortSignal.timeout(timeoutMs)]);
      if (deadline.aborted) unavailable('cooperative R did not open its authenticated ACP stream');
      let onAbort;
      const aborted = new Promise((_, reject) => {
        onAbort = () => reject(new Error('cooperative R did not open its authenticated ACP stream'));
        deadline.addEventListener('abort', onAbort, { once: true });
      });
      ({ socket: stream } = await Promise.race([acp, aborted]).finally(() =>
        deadline.removeEventListener('abort', onAbort)));
      checkRunning();
      item.pid = machine.runnerPid(item.reservation);
      if (!Number.isSafeInteger(item.pid) || item.pid < 2) unavailable('cooperative R PID was not authenticated');
      const result = { ...view(item), definition_digest: item.reservation.payload.measurement_binding.claimed_definition_digest,
        profile: 'managed-cooperative', protected: false, state: 'running' };
      await pushReceipt(core, { plugin: 'hq', kind: 'hq.soul.started', ...result,
        reservation_sha256: item.reservation.sha256 });
      checkRunning();
      return takeover(result, {
        open: () => {
          if (!running() || stream.destroyed) unavailable('cooperative Soul ACP connection closed');
          item.state = 'running';
          return (socket) => {
            item.owner = socket;
            socket.once('error', lost);
            socket.once('close', lost);
            socket.pipe(stream);
            stream.pipe(socket);
          };
        }, cancel: lost,
      });
    } catch (error) {
      settlePreparation();
      void stop(item).catch(() => {});
      if (error instanceof HostError) throw error;
      unavailable('Machine or its cooperative Soul runner could not complete startup');
    }
  }

  return Object.freeze({
    start, report: () => [...starts.values()].map(view),
    stop(startId) {
      const item = starts.get(startId);
      if (!item) unavailable('no managed-cooperative Soul start with that ID');
      return stop(item);
    },
    stopAll: async () => {
      closing = true;
      await Promise.all([...starts.values()].map(stop));
    },
  });
}
