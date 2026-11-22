// The owner-facing protected start. HQ starts the two installed role processes;
// paired Machine authorizes their exact PIDs and signs the durable stop. The
// owner connection carries the runner ACP stream only after B is finalized.
import { lstatSync, realpathSync } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { takeover } from './socket.mjs';
import { machineRoleStage2aLookup, machineRoleStage2aReserve,
  machineRoleStage2aFinalizeB } from './machine-channel.mjs';
import { prepareStage2aBridge, stage2aRelayClaim, startStage2aRole } from './stage2a-role-launch.mjs';

const exact = (value, fields) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...fields].sort().join(',');
const refuse = () => { throw new Error('Machine protected Soul start is unavailable'); };

export function createStage2aProtectedStarter({ installations, authority, verifyReservation,
  getBrokerIdentity, verifyBoundBridge, machineLookup = machineRoleStage2aLookup,
  machineReserve = machineRoleStage2aReserve, machineFinalize = machineRoleStage2aFinalizeB,
  prepareBridge = prepareStage2aBridge, startRole = startStage2aRole,
  onFinalized, onStopped, random = (bytes) => randomBytes(bytes).toString('hex') } = {}) {
  if (!Array.isArray(installations) || typeof authority?.register !== 'function'
    || typeof authority.stopStart !== 'function' || typeof authority.currentLiveStart !== 'function'
    || typeof verifyReservation !== 'function'
    || typeof getBrokerIdentity !== 'function' || typeof verifyBoundBridge !== 'function'
    || typeof machineLookup !== 'function'
    || typeof machineReserve !== 'function' || typeof machineFinalize !== 'function'
    || typeof prepareBridge !== 'function' || typeof startRole !== 'function'
    || typeof random !== 'function') refuse();
  const byId = new Map(installations.map((i) => [i.installation_id, i]));
  if (byId.size !== installations.length) refuse();
  const slots = new Map();
  let stopping = false;

  async function stop(slot) {
    if (slot.stopPromise) return slot.stopPromise;
    slot.stopPromise = (async () => {
      await authority.stopStart(slot.reservationSHA256);
      slots.delete(slot.installed.installation_id);
      await onStopped?.(slot.reservationSHA256);
      return true;
    })();
    return slot.stopPromise;
  }

  async function start(payload) {
    if (stopping || !exact(payload, ['package_path', 'requested_profile'])
      || payload.requested_profile !== 'managed-protected'
      || typeof payload.package_path !== 'string' || !payload.package_path.startsWith('/')) refuse();
    let source;
    try {
      source = realpathSync(payload.package_path);
      if (!lstatSync(source).isDirectory() || source !== payload.package_path) refuse();
    } catch { refuse(); }
    const lookup = await machineLookup({ package_path: source });
    const installed = byId.get(lookup?.installation_id);
    if (!installed || installed.package_root !== source || lookup.plan_id !== installed.plan_id
      || lookup.plan_digest !== installed.plan_digest
      || lookup.runner_account !== installed.runner_account
      || lookup.bridge_account !== installed.bridge_account
      || slots.has(installed.installation_id)) refuse();
    const slot = { installed, reservationSHA256: null, runner: null, bridge: null,
      stopPromise: null };
    // Occupy the installation before the first await across Machine reserve.
    slots.set(installed.installation_id, slot);
    let registered = false;
    try {
      const startId = `st_${random(12)}`;
      const launchId = `ln_${random(12)}`;
      if (!/^st_[0-9a-f]{24}$/.test(startId) || !/^ln_[0-9a-f]{24}$/.test(launchId)) refuse();
      const reserved = await machineReserve({ plan_digest: installed.plan_digest,
        installation_id: installed.installation_id, start_id: startId,
        hq_epoch: installed.hq_epoch, launch_id: launchId });
      const checked = await verifyReservation(reserved?.envelope, installed);
      if (checked?.reservationSHA256 !== reserved?.sha256
        || checked.payload.assignment.start_id !== startId
        || checked.payload.assignment.launch_id !== launchId) refuse();
      const assignment = checked.payload.assignment;
      slot.reservationSHA256 = reserved.sha256;
      const selectors = await authority.register({ envelope: reserved.envelope,
        sha256: reserved.sha256, installed, killRoles: async () => {
          const roles = [slot.runner, slot.bridge].filter(Boolean);
          await Promise.allSettled(roles.map((role) => role.stop()));
        } });
      registered = true;
      await prepareBridge({ installed, observed: getBrokerIdentity(installed.installation_id),
        selectors });
      slot.bridge = await startRole({ account: installed.bridge_account, role: 'bridge',
        reservationSHA256: reserved.sha256 });
      authority.setRolePid(reserved.sha256, 'bridge', slot.bridge.pid);
      const ready = await slot.bridge.waitBridgeReady(async (observation) => {
        const bound = await verifyBoundBridge({ installation_id: installed.installation_id,
          start_id: startId, launch_id: launchId, plan_id: installed.plan_id,
          plan_digest: installed.plan_digest, reservation_digest: reserved.sha256 },
        observation.bind_receipt_sha256);
        if (!bound || bound.bind_receipt_sha256 !== observation.bind_receipt_sha256) refuse();
        const relay_socket = stage2aRelayClaim(installed, startId, observation);
        const finalized = await machineFinalize({ ...selectors,
          bind_receipt_sha256: observation.bind_receipt_sha256, relay_socket });
        authority.markFinalized(reserved.sha256, { envelope: finalized.envelope,
          sha256: finalized.sha256, bindReceiptSHA256: observation.bind_receipt_sha256,
          relaySocket: relay_socket });
        await onFinalized?.({ installed, assignment, selectors,
          bindReceiptSHA256: observation.bind_receipt_sha256 });
        return true;
      });
      if (!ready || !slot.bridge) refuse();
      slot.runner = await startRole({ account: installed.runner_account, role: 'runner',
        reservationSHA256: reserved.sha256 });
      authority.setRolePid(reserved.sha256, 'runner', slot.runner.pid);
      // A signed current Machine lease is needed after both PIDs are present.
      const live = await authority.currentLiveStart(reserved.sha256);
      if (!live || !Number.isSafeInteger(live.finalized_live_expires_at)) refuse();
      const result = { start_id: startId, launch_id: launchId, installation_id: installed.installation_id,
        soul_id: installed.soul_id, package_path: source, pid: slot.runner.pid,
        runner_uid: installed.runner_uid, runner_gid: installed.runner_gid,
        hq_epoch: installed.hq_epoch, profile: 'managed-protected', protected: true };
      return takeover(result, { open: () => (socket) => {
        if (stopping || slot.stopPromise) { socket.destroy(); return; }
        const cut = () => { socket.destroy(); void stop(slot); };
        socket.once('error', cut);
        slot.runner.stdin.once?.('error', cut);
        slot.runner.stdout.once?.('error', cut);
        socket.pipe(slot.runner.stdin);
        slot.runner.stdout.pipe(socket);
        slot.runner.resumeOutput();
        socket.once('close', () => { void stop(slot); });
        slot.runner.done.then(() => { socket.end(); void stop(slot); });
      }, cancel: () => { void stop(slot); } });
    } catch (error) {
      if (registered) {
        try { await stop(slot); } catch { /* keep the slot occupied on uncertain containment */ }
      } else if (!slot.reservationSHA256) slots.delete(installed.installation_id);
      throw error;
    }
  }

  return Object.freeze({ start, stopAll: async () => {
    stopping = true;
    await Promise.all([...slots.values()].map(stop));
  } });
}
