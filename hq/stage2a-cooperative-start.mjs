import { randomBytes } from 'node:crypto';
import { fail, HostError } from '../sdk/errors.mjs';
import { canonicalBytes } from '../sdk/wire/canonical-json.mjs';
import { digest } from './stage2a-cooperative-proof.mjs';
import { pushReceipt } from '../sdk/services.mjs';
import { observeDarwinProcessIdentity } from './owner-control.mjs';
import { takeover } from './socket.mjs';

const unavailable = (message) => fail('host.launch_unavailable', message);

export function createCooperativeChildObservationRecorder({ core, readCommittedReceipts, reservation,
  observeProcess = observeDarwinProcessIdentity } = {}) {
  const assignment = reservation?.payload?.assignment;
  if (!assignment || reservation.payload.adapter_transport !== 'brokered-b'
    || core?.profile !== 'managed-cooperative' || typeof core.persistReceipt !== 'function' || typeof readCommittedReceipts !== 'function')
    unavailable('cooperative member observation needs a durable HQ store');
  const spent = new Set();
  return async ({ member, launcherPid, childPid, grantSHA256 }) => {
    if (spent.has(member.member_id) || spent.size >= 2 || launcherPid === childPid)
      unavailable('cooperative member observation was already recorded');
    spent.add(member.member_id);
    const observe = (pid) => observeProcess(pid, assignment.runner_uid, assignment.runner_gid);
    const [launcher, child] = await Promise.all([observe(launcherPid), observe(childPid)]);
    if (!launcher || !child || launcher.pid !== launcherPid || child.pid !== childPid)
      unavailable('cooperative member kernel observation is unavailable');
    const receipt = await pushReceipt(core, {
      plugin: 'hq', kind: 'hq.soul.member.observed',
      schema: 'agent-bot-hq/stage2a-cooperative-member-observed/v1',
      reservation_sha256: reservation.sha256,
      assignment_envelope_sha256: reservation.member_set_assignment_sha256,
      installation_id: assignment.installation_id, start_id: assignment.start_id,
      launch_id: assignment.launch_id, hq_epoch: assignment.hq_epoch,
      member_id: member.member_id, member_launch_id: member.launch_id, member_selector: member.member_selector,
      grant_sha256: grantSHA256, launcher_process: launcher, child_process: child,
    });
    if (!Number.isSafeInteger(receipt?.seq) || receipt.seq < 1 || !Number.isSafeInteger(receipt.at))
      unavailable('cooperative member observation was not recorded');
    const [committed] = await readCommittedReceipts([receipt.seq]);
    if (!committed) unavailable('committed cooperative member observation is missing');
    const bytes = canonicalBytes(committed);
    if (!bytes.equals(canonicalBytes(receipt))) unavailable('committed cooperative member observation changed');
    return Object.freeze({ row: committed, sha256: digest(bytes), base64url: bytes.toString('base64url') });
  };
}

function createCooperativeArmRecorder({ core, readCommittedReceipts, reservation }) {
  return async ({ arm_request, arm_result }) => {
    const receipt = await pushReceipt(core, {
      plugin: 'hq', kind: 'hq.soul.member.arm.recorded',
      schema: 'agent-bot-hq/stage2a-cooperative-member-arm-recorded/v1',
      reservation_sha256: reservation.sha256, start_id: reservation.payload.assignment.start_id,
      hq_epoch: reservation.payload.assignment.hq_epoch, arm_request, arm_result,
    });
    if (!Number.isSafeInteger(receipt?.seq) || receipt.seq < 1) unavailable('cooperative B arm was not recorded');
    const [committed] = await readCommittedReceipts([receipt.seq]);
    if (!committed || !canonicalBytes(committed).equals(canonicalBytes(receipt)))
      unavailable('committed cooperative B arm changed');
    return Object.freeze({ arm_request: committed.arm_request, arm_result: committed.arm_result });
  };
}

export function createStage2aCooperativeStarter({ machine, core, readCommittedReceipts, openAdmission, brokeredMemberProvider, timeoutMs = 30000 }) {
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
      if (!item.reservation && item.reserveSelectors) {
        try { item.reservation = await machine.recoverReservation(item.installation, item.reserveSelectors); }
        catch { /* No signed reservation is available for containment. */ }
      }
      if (item.reservation) {
        try { proof = await machine.stop(item.reservation); }
        catch { /* A refused or could not confirm containment. */ }
      }
      if (!proof && item.reserveSelectors) {
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
    paths.add(path);
    let installation, id;
    try {
      installation = await machine.lookup(path);
      if (closing) unavailable('HQ is stopping cooperative Soul starts');
      // A reads this one-use identifier from the installed owner plan whose
      // exact argv already binds the admission socket derived from it.
      id = installation.reviewed_start_id;
      if (starts.has(id)) fail('host.launch_busy', 'HQ has already reserved this reviewed Soul start');
    } catch (error) {
      paths.delete(path);
      if (error instanceof HostError) throw error;
      unavailable('Machine could not identify the reviewed cooperative Soul start');
    }
    let settlePreparation;
    const prepared = new Promise((resolve) => { settlePreparation = resolve; });
    const item = { id, path, installation, state: 'starting', startedAt: new Date(core.clock.now()).toISOString(),
      abort: new AbortController(), prepared };
    starts.set(id, item);
    const running = () => !item.abort.signal.aborted && !closing;
    const checkRunning = () => { if (!running()) unavailable('cooperative Soul start was revoked'); };
    const lost = () => { void stop(item).catch(() => {}); };

    let stream;
    try {
      const { installation_id: installationId, runner_uid: runnerUid } = installation;
      if (installations.has(installationId) || runnerUids.has(runnerUid))
        fail('host.launch_busy', 'HQ has already reserved this Soul installation or runner account');
      installations.add(installationId);
      item.ownsInstallation = true;
      runnerUids.add(runnerUid);
      item.ownsRunnerUid = true;
      item.reserveSelectors = Object.freeze({
        startId: id, launchId: `ln_${core.random.hex(12)}`, challenge: randomBytes(32),
      });
      const brokered = item.installation.adapter_transport === 'brokered-b';
      if (brokered && typeof brokeredMemberProvider !== 'function')
        unavailable('cooperative B prestart provider is unavailable');
      item.reservation = await machine.reserve(item.installation, item.reserveSelectors);
      machine.watch(item.reservation, lost);
      if (!running()) machine.revoke(item.reservation);
      checkRunning();
      await machine.projection(item.reservation);
      checkRunning();

      let accept;
      const acp = new Promise((resolve) => { accept = resolve; });
      const memberAttachProvider = brokered
        ? await brokeredMemberProvider(item.reservation, machine.brokeredMemberInputs(item.reservation), {
          submitMap: (input) => machine.submitMemberMap(item.reservation, input),
          grantMemberChild: (input) => machine.grantMemberChild(item.reservation, input),
          observeChildren: (input) => machine.observeMemberChildren(item.reservation, input),
          finalizeMemberReady: (input) => machine.finalizeMemberReady(item.reservation, input),
          recordArmEvidence: createCooperativeArmRecorder({ core, readCommittedReceipts, reservation: item.reservation }),
          recordHChildObservation: createCooperativeChildObservationRecorder({
            core, readCommittedReceipts, reservation: item.reservation,
          }),
        }) : undefined;
      if (brokered && !memberAttachProvider) unavailable('cooperative B prestart provider is unavailable');
      checkRunning();
      item.listener = await openAdmission({ reservation: item.reservation, memberAttachProvider,
        openAcpStream: (socket, context) => {
          if (!running()) { socket.destroy(); return; }
          machine.markAcp(item.reservation, context, socket);
          item.acp = socket;
          item.acpContext = context;
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
      item.startReceipt = Object.freeze({ ...await pushReceipt(core, {
        plugin: 'hq', kind: 'hq.soul.started', ...result, reservation_sha256: item.reservation.sha256,
      }) });
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

  const live = (item) => item.state === 'running' && !item.abort.signal.aborted && !closing
    && item.owner && !item.owner.destroyed && machine.watchHealthy(item.acpContext);

  async function captureProtectedClaimRefusal(preProof, requireProtectedProfile) {
    const pre = machine.verifyDirectQualificationPre(preProof);
    const preDigest = preProof.sha256;
    const item = starts.get(pre.start_id);
    const valid = () => live(item) && Date.parse(pre.expires_at) > core.clock.now();
    if (core.profile !== 'managed-cooperative' || typeof core.persistReceipt !== 'function' || !item || !valid() || item.refusalSpent || item.reservation.sha256 !== pre.reservation_sha256
      || !Number.isSafeInteger(item.startReceipt?.seq) || item.startReceipt.seq < 1) {
      unavailable('the direct qualification start is unavailable or already used');
    }
    item.refusalSpent = true;
    if (!await machine.assertLive(item.acpContext) || !valid()) unavailable('direct qualification start is no longer live');

    let refused = false;
    try { requireProtectedProfile(item.path); }
    catch (error) {
      if (!(error instanceof HostError) || error.code !== 'profile_insufficient') throw error;
      refused = true;
    }
    if (!refused) unavailable('direct qualification did not observe the protected profile refusal');

    const receipt = await pushReceipt(core, {
      plugin: 'hq', kind: 'hq.soul.protected-claim.refused',
      schema: 'agent-bot-hq/stage2a-direct-q-protected-claim-refusal/v1',
      installation_id: pre.installation_id, start_id: pre.start_id, launch_id: pre.launch_id, hq_epoch: pre.hq_epoch,
      reservation_sha256: pre.reservation_sha256, attach_sha256: pre.attach_sha256, session_id: pre.session_id,
      q_challenge_sha256: pre.q_challenge_sha256, test_plan_sha256: pre.test_plan_sha256,
      case_nonce_base64url: pre.case_nonce_base64url, pre_response_sha256: preDigest,
      requested_profile: 'managed-protected', refusal_code: 'profile_insufficient',
      cooperative_start_receipt_seq: item.startReceipt.seq,
      cooperative_start_receipt_sha256: digest(canonicalBytes(item.startReceipt)),
    });
    if (!Number.isSafeInteger(receipt?.seq) || receipt.seq <= item.startReceipt.seq
      || !valid() || !await machine.assertLive(item.acpContext) || !valid()) {
      unavailable('the direct refusal could not be tied to a live start and committed receipt');
    }
    return Object.freeze({ ...receipt });
  }

  async function qualifyDirectProtectedClaim(startId, requireProtectedProfile) {
    const item = starts.get(startId);
    if (core.profile !== 'managed-cooperative' || typeof core.persistReceipt !== 'function'
      || typeof readCommittedReceipts !== 'function' || !item || !live(item) || item.qualificationAttempted) {
      unavailable('the direct qualification start is unavailable or already used');
    }
    item.qualificationAttempted = true;
    const pre = await machine.beginDirectQualification(item.reservation);
    const refusal = await captureProtectedClaimRefusal(pre, requireProtectedProfile);
    // A challenges the exact measured H process. Reload the two rows from
    // the committed snapshot after the challenge, never from caller input.
    const challenge = await machine.beginDirectQualificationWitness(item.reservation, pre);
    const [start, denied] = await readCommittedReceipts([item.startReceipt.seq, refusal.seq]);
    const startBytes = canonicalBytes(start), refusalBytes = canonicalBytes(denied);
    if (digest(startBytes) !== refusal.cooperative_start_receipt_sha256
      || digest(refusalBytes) !== digest(canonicalBytes(refusal)) || !live(item)) {
      unavailable('committed direct qualification receipts changed or the start stopped');
    }
    const receipt = Object.freeze({
      cooperative_start_receipt_base64url: startBytes.toString('base64url'),
      cooperative_start_receipt_sha256: digest(startBytes),
      hq_refusal_receipt_base64url: refusalBytes.toString('base64url'),
      hq_refusal_receipt_sha256: digest(refusalBytes),
    });
    const witness = await machine.finishDirectQualificationWitness(item.reservation, pre, challenge, receipt);
    return machine.finishDirectQualification(item.reservation, pre, witness, receipt.hq_refusal_receipt_sha256);
  }

  return Object.freeze({
    start, report: () => [...starts.values()].map(view),
    hasLivePackage: (path) => paths.has(path) && [...starts.values()].some((item) => item.path === path && live(item)),
    qualifyDirectProtectedClaim,
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
