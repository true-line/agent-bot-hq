import { randomBytes } from 'node:crypto';
import { pipeline } from 'node:stream';
import { fail, HostError } from '../sdk/errors.mjs';
import { canonicalBytes } from '../sdk/wire/canonical-json.mjs';
import { digest } from './stage2a-cooperative-proof.mjs';
import { pushReceipt } from '../sdk/services.mjs';
import { observeDarwinProcessIdentity } from './owner-control.mjs';
import { takeover } from './socket.mjs';

import { validate } from '../sdk/wire/schema.mjs';
import { parseStrict } from '../sdk/wire/strict-json.mjs';
import { openCooperativeBStage, verifyCooperativeBridgeAssignment } from './stage2a-cooperative-bridge.mjs';
import { createStage2aPrestartedMembers } from './stage2a-protected-start.mjs';
import { startStage2aRole } from './stage2a-role-launch.mjs';
import { verifyStage2aMachineEnvelope } from './stage2a-stop.mjs';

import { openLocalProviderService } from './stage2a-qualification-provider.mjs';

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

export async function openInstalledCooperativeMemberProvider({ core, reservation, inputs, schemas,
  schemaReferences, installedBridge, account, harnessUids, exchange, openEndpoint, kernelPeer, contain, operations,
}) {
  const r = reservation.payload, a = r.assignment, machinePublicKey = inputs.machinePublicKey;
  const now = () => core.clock.now();
  const check = (schema, payload) => validate(schema, payload, {
    schemas: schemaReferences.filter((entry) => entry.$id !== schema.$id),
  }).length === 0;
  const bridge = verifyCooperativeBridgeAssignment(inputs.cooperativeBridgeBytes, { machinePublicKey, reservation,
    installedBridge, validatePayload: (payload) => check(schemas.bridgeAssignment, payload),
    account, hqUid: a.hq_uid, harnessUids, now });
  const assigned = verifyStage2aMachineEnvelope(inputs.assignmentBytes, machinePublicKey,
    'agent-bot/stage2a-member-set-assignment/v1', { maxBytes: 16_384 });
  if (!check(schemas.assignment, assigned.payload)
    || assigned.payload.owner_plan_member_set_sha256 !== inputs.ownerPlanMemberSetSHA256)
    unavailable('cooperative signed assignment differs from the installed member plan');
  const service = openLocalProviderService(a);
  let stage;
  try {
    await service.ready;
    stage = await openCooperativeBStage({ reservation, bridgeAssignment: bridge, machinePublicKey,
      schemas, schemaReferences, expected: { owner_plan_member_set_sha256: inputs.ownerPlanMemberSetSHA256 },
      exchange, openEndpoint, kernelPeer, random: core.random.hex, contain, now,
      finalizeMemberReady: operations.finalizeMemberReady, recordArmEvidence: operations.recordArmEvidence,
      async authorizeRelayIngress(request, qualification, current) {
        const { config, expiresAt } = await operations.authorizeRelayIngress(request, qualification, current);
        if (!current() || expiresAt <= now()) unavailable('cooperative relay provider grant expired');
        await service.invoke(config);
        if (!current() || expiresAt <= now()) unavailable('cooperative relay provider grant expired');
        return Object.freeze({ model: config.model, stop_reason: 'end_turn', text: config.response_text,
          usage: Object.freeze({ input_tokens: 7, output_tokens: 3 }) });
      } });
    if (!stage.armStage) unavailable('cooperative arm schema or paired authority is unavailable');
  } catch (error) {
    await Promise.allSettled([service.close(), stage?.close()]);
    throw error;
  }
  const arm = stage.armStage;
  const isCurrent = () => {
    try { return Date.parse(assigned.payload.expires_at) > now() && !!arm.verifiedPolicy(); }
    catch { return false; }
  };
  let prepared;
  const startMember = async (_selectors, member) => {
    let cwd;
    const role = await startStage2aRole({ role: 'child', cooperativeChild: true, account: a.runner_account,
      reservationSHA256: reservation.sha256, machineExec: async ({ nonce, pid }) => {
        const grant = await operations.grantMemberChild({ nonce, pid, member_id: member.member_id,
          member_launch_id: member.launch_id, member_selector: member.member_selector });
        const raw = Buffer.from(grant?.envelope_base64url ?? '', 'base64url');
        const invocation = Buffer.from(grant?.invocation_base64url ?? '', 'base64url');
        if (raw.toString('base64url') !== grant?.envelope_base64url
          || invocation.toString('base64url') !== grant?.invocation_base64url
          || !invocation.length || invocation.length > 35_000) unavailable('invalid cooperative child grant frame');
        const checked = verifyStage2aMachineEnvelope(raw, machinePublicKey,
          'agent-bot/soul-cooperative-child-grant/v1', { maxBytes: 16_384 });
        const p = checked.payload, policy = arm.verifiedPolicy();
        if (p.contract !== 'machine/v3' || p.profile_in_force !== 'managed-cooperative'
          || p.reservation_sha256 !== reservation.sha256 || p.bridge_assignment_sha256 !== bridge.assignmentSHA256
          || p.assignment_envelope_sha256 !== assigned.envelope_sha256
          || p.member_b_authority_sha256 !== policy.proof.envelope_sha256
          || p.installation_id !== a.installation_id || p.start_id !== a.start_id || p.hq_epoch !== a.hq_epoch
          || p.member_id !== member.member_id || p.member_launch_id !== member.launch_id
          || p.member_selector !== member.member_selector || p.nonce !== nonce || p.pid !== pid
          || grant.sha256 !== checked.envelope_sha256 || p.invocation_sha256 !== digest(invocation)
          || !(Date.parse(p.expires_at) > now())) unavailable('cooperative child grant differs from the reviewed member');
        cwd = parseStrict(invocation.toString('utf8')).workdir;
        if (typeof cwd !== 'string' || !cwd.startsWith('/')) unavailable('cooperative child working directory is unavailable');
        return { sha256: grant.sha256, grantLine: Buffer.from(JSON.stringify(grant) + '\n') };
      },
    });
    return Object.freeze({ ...role, cwd });
  };
  const selectors = Object.freeze({ ...bridge.selectors, reservation_sha256: reservation.sha256 });
  const expected = { ...selectors, host_id: r.host_id, hq_uid: a.hq_uid, runner_uid: a.runner_uid,
    soul_id: a.soul_id, profile_in_force: 'managed-cooperative',
    owner_plan_member_set_sha256: inputs.ownerPlanMemberSetSHA256,
    bridge_uid: bridge.endpoint.uid, bridge_gid: bridge.endpoint.gid, broker_socket: bridge.endpoint.path };
  return Object.freeze({
    assignmentSchema: schemas.assignment, authoritySchema: schemas.authority, readySchema: schemas.ready,
    childObservationSchema: schemas.childObservation, resultSchema: schemas.memberAttach, schemaReferences,
    async bootstrap() {
      const policy = await arm.waitForPolicy();
      if (!isCurrent() || !policy.records.assignmentBytes.equals(inputs.assignmentBytes))
        unavailable('cooperative member policy differs from reservation');
      return Object.freeze({ machinePublicKey, ...inputs, authorityBytes: policy.records.authorityBytes,
        expected, boundAuthoritySHA256: policy.proof.envelope_sha256, isCurrent });
    },
    async prepareMemberSet({ runtimes }) {
      const policy = arm.verifiedPolicy();
      const prepare = createStage2aPrestartedMembers({ machinePublicKey, schemas: { ...schemas, observation: schemas.childObservation },
        schemaReferences, profile: 'managed-cooperative', now, async stop() {
          await Promise.allSettled([stage.close(), service.close()]);
          contain();
        }, startMember,
        submitMap: operations.submitMap, observeChildren: operations.observeChildren,
        recordHChildObservation: operations.recordHChildObservation,
        deliverObservation() {},
        waitForReady({ observationBytes, provisionalMappingSHA256, memberGrants }) {
          arm.observation({ envelopeBytes: observationBytes, assignmentBytes: inputs.assignmentBytes,
            machinePublicKey, provisionalMappingSHA256, memberGrants });
          return arm.waitForReady();
        } });
      if (prepared) unavailable('cooperative member set is already prepared');
      prepared = prepare({ selectors, expectedAuthority: { ...expected, bridgeObservedSHA256: policy.wrapper.envelopeSHA256 },
        assignmentBytes: inputs.assignmentBytes, authorityBytes: policy.records.authorityBytes, pendingRuntimes: runtimes });
      return prepared;
    },
    async select({ runtimeId, runtime }) {
      const ready = await prepared, policy = arm.verifiedPolicy();
      const row = ready.children.find(({ member }) => member.member_id === runtime.member_id);
      if (!row || !runtimeId || !isCurrent()) unavailable('cooperative prestarted member is unavailable');
      await row.child.waitChildAccepted(digest(ready.readyBytes));
      if (!isCurrent()) unavailable('cooperative prestarted member was revoked');
      return Object.freeze({ ...ready, expected, machinePublicKey, childObservationBytes: ready.observationBytes,
        boundAuthoritySHA256: policy.proof.envelope_sha256, cooperativeBridgeBytes: inputs.cooperativeBridgeBytes,
        cwd: row.child.cwd, memberBridgeToken: core.random.hex(24), bridgeReadyNonce: core.random.hex(32),
        isCurrent, isBridgeLive: arm.isLive, waitBridgeLive: arm.waitForBridgeLive,
        connect(socket) {
          const lost = () => { void Promise.resolve().then(contain).catch(() => {}); };
          pipeline(socket, row.child.stdin, lost);
          pipeline(row.child.stdout, socket, lost);
          row.child.resumeOutput();
        },
      });
    },
    ownerReady: ({ readyEnvelopeSHA256, authoritySHA256 }) =>
      isCurrent() && arm.verifiedPolicy().proof.envelope_sha256 === authoritySHA256 && arm.isLive(readyEnvelopeSHA256),
    renewWrapperLease: operations.renewWrapperLease, rememberWrapperLease: arm.rememberMemberLease,
    async close() {
      await Promise.allSettled([stage.close(), service.close()]);
      const members = await prepared?.catch(() => undefined);
      await Promise.allSettled((members?.children ?? []).map(({ child }) => child.stop()));
    },
  });
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
      if (item.memberAttachProvider?.close) await item.memberAttachProvider.close().catch(() => {});
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
          contain: lost,
          authorizeRelayIngress: (request, qualification, current) =>
            machine.authorizeRelayIngress(item.reservation, request, qualification, current),
          submitMap: (input) => machine.submitMemberMap(item.reservation, input),
          grantMemberChild: (input) => machine.grantMemberChild(item.reservation, input),
          observeChildren: (input) => machine.observeMemberChildren(item.reservation, input),
          finalizeMemberReady: (input) => machine.finalizeMemberReady(item.reservation, input),
          renewWrapperLease: (input) => machine.renewMemberChild(item.reservation, input),
          recordArmEvidence: createCooperativeArmRecorder({ core, readCommittedReceipts, reservation: item.reservation }),
          recordHChildObservation: createCooperativeChildObservationRecorder({
            core, readCommittedReceipts, reservation: item.reservation,
          }),
        }) : undefined;
      item.memberAttachProvider = memberAttachProvider;
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
