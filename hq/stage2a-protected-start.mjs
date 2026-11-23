// The owner-facing protected start. HQ starts the two installed role processes;
// paired Machine authorizes their exact PIDs and signs the durable stop. The
// owner connection carries the runner ACP stream only after B is finalized.
import { lstatSync, realpathSync } from 'node:fs';
import { createHash, randomBytes } from 'node:crypto';
import { pipeline } from 'node:stream';
import { canonicalBytes, canonicalDigest } from '../sdk/wire/canonical-json.mjs';
import { validate } from '../sdk/wire/schema.mjs';
import { matchesObservedMemberGrants, verifyStage2aBridgeMemberAuthority } from './stage2a-relay-peer.mjs';
import { verifyStage2aMachineEnvelope } from './stage2a-stop.mjs';
import { takeover } from './socket.mjs';
import { machineRoleStage2aLookup, machineRoleStage2aReserve,
  machineRoleStage2aFinalizeB, machineRoleStage2aChildReady } from './machine-channel.mjs';
import { prepareStage2aBridge, stage2aRelayClaim, startStage2aRole } from './stage2a-role-launch.mjs';

const exact = (value, fields) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...fields].sort().join(',');
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const refuse = () => { throw new Error('Machine protected Soul start is unavailable'); };

function checkedLiveLease(live) {
  const encoded = live?.lease_envelope_base64url;
  if (typeof encoded !== 'string' || !/^[A-Za-z0-9_-]{1,16384}$/.test(encoded)
    || !DIGEST.test(live.lease_sha256 ?? '')
    || !Number.isSafeInteger(live.lease_sequence) || live.lease_sequence < 1) refuse();
  const bytes = Buffer.from(encoded, 'base64url');
  if (!bytes.length || bytes.length > 12 * 1024
    || bytes.toString('base64url') !== encoded
    || 'sha256:' + createHash('sha256').update(bytes).digest('hex')
      !== live.lease_sha256) refuse();
  return Object.freeze({ envelope: encoded, sha256: live.lease_sha256,
    sequence: live.lease_sequence });
}

// R's stdin is a private HQ-controlled pipe until the owner ACP takeover.
// The first post-grant line releases the measured R child only after Machine
// confirms both role PIDs and HQ has published the one-use provider. Souls
// must compare these selectors with its signed FD3 protected start.
function activateRunner(runner, assignment, reservationSHA256, live, finalizationEnvelope) {
  if (!runner?.stdin || typeof runner.stdin.write !== 'function' || runner.stdin.destroyed
    || !DIGEST.test(reservationSHA256)
    || !/^st_[0-9a-f]{24}$/.test(assignment?.start_id ?? '')
    || !/^ln_[0-9a-f]{24}$/.test(assignment?.launch_id ?? '')
    || live?.phase !== 'finalized' || live.runner_pid !== runner.pid
    || !DIGEST.test(live.finalization_sha256 ?? '')
    || !DIGEST.test(live.bind_receipt_sha256 ?? '')
    || !Buffer.isBuffer(finalizationEnvelope)
    || 'sha256:' + createHash('sha256').update(finalizationEnvelope).digest('hex')
      !== live.finalization_sha256
    || !Number.isSafeInteger(live.finalized_live_expires_at)
    || live.finalized_live_expires_at <= Date.now()) refuse();
  const line = Buffer.from(JSON.stringify({
    schema: 'agent-bot-souls/protected-activation/v1',
    reservation_sha256: reservationSHA256,
    start_id: assignment.start_id,
    launch_id: assignment.launch_id,
    runner_wrapper_pid: live.runner_pid,
    finalization_sha256: live.finalization_sha256,
    finalization_envelope_base64url: finalizationEnvelope.toString('base64url'),
    bind_receipt_sha256: live.bind_receipt_sha256,
  }) + '\n');
  if (line.length > 32 * 1024) refuse();
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      runner.stdin.off?.('error', onError);
      if (error) reject(error); else resolve();
    };
    const onError = (error) => finish(error);
    const timer = setTimeout(() => finish(new Error('protected R activation timed out')), 2000);
    timer.unref?.();
    runner.stdin.once?.('error', onError);
    try { runner.stdin.write(line, finish); }
    catch (error) { finish(error); }
  });
}

export function verifyCooperativeMemberReady(bytes, machinePublicKey, {
  observation, authoritySHA256, bridgeObservedSHA256, hObservationSHA256s, armReceiptSHA256s, now,
}) {
  const ready = verifyStage2aMachineEnvelope(bytes, machinePublicKey,
    'agent-bot/soul-cooperative-member-ready/v3', { schemaVersion: 3, maxBytes: 16_384 });
  const r = ready.payload, c = observation.payload;
  const scope = ['profile_in_force', 'host_id', 'installation_id', 'start_id', 'hq_epoch',
    'reservation_sha256', 'assignment_envelope_sha256', 'provisional_hq_mapping_sha256'];
  if (!exact(r, ['contract', 'kind', 'schema_version', ...scope, 'child_observation_envelope_sha256',
    'member_b_authority_envelope_sha256', 'bridge_observed_sha256', 'members', 'issued_at', 'expires_at'])
    || r.contract !== 'machine/v3' || r.kind !== 'soul-cooperative-member-ready' || r.schema_version !== 3
    || r.profile_in_force !== 'managed-cooperative' || scope.some((field) => r[field] !== c[field])
    || r.child_observation_envelope_sha256 !== observation.envelope_sha256
    || !DIGEST.test(authoritySHA256 ?? '') || r.member_b_authority_envelope_sha256 !== authoritySHA256
    || !DIGEST.test(bridgeObservedSHA256 ?? '') || r.bridge_observed_sha256 !== bridgeObservedSHA256
    || !(Date.parse(c.issued_at) <= Date.parse(r.issued_at) && Date.parse(r.issued_at) <= now
      && now < Date.parse(r.expires_at)) || !Array.isArray(r.members) || r.members.length !== 2
    || c.members?.length !== 2 || hObservationSHA256s?.length !== 2 || armReceiptSHA256s?.length !== 2) refuse();
  for (const [i, row] of r.members.entries()) {
    const observed = c.members[i];
    if (!exact(row, ['member_id', 'member_launch_id', 'member_selector', 'grant_sha256',
      'launcher_process', 'child_process', 'h_observation_sha256', 'b_arm_receipt_sha256'])
      || ['member_id', 'member_selector', 'grant_sha256'].some((field) => row[field] !== observed[field])
      || row.member_launch_id !== observed.launch_id
      || canonicalDigest(row.launcher_process) !== canonicalDigest(observed.launcher_process)
      || canonicalDigest(row.child_process) !== canonicalDigest(observed.child_process)
      || !DIGEST.test(row.h_observation_sha256 ?? '') || row.h_observation_sha256 !== hObservationSHA256s[i]
      || !DIGEST.test(row.b_arm_receipt_sha256 ?? '') || row.b_arm_receipt_sha256 !== armReceiptSHA256s[i]) refuse();
  }
  return ready;
}

// One protected start owns both wrappers. This is invoked from the pending
// Hello transaction boundary. Only the later selector-bound attach owns ACP.
export function createStage2aPrestartedMembers({ machinePublicKey, schemas, schemaReferences = [],
  submitMap, startMember, observeChildren, deliverObservation, waitForReady, stop, recordHChildObservation,
  profile = 'managed-protected', now = Date.now } = {}) {
  if ((profile === 'managed-cooperative' && typeof recordHChildObservation !== 'function')
    || !schemas?.assignment || !schemas.mapping || !schemas.authority || !schemas.observation || !schemas.ready
    || [submitMap, startMember, observeChildren, deliverObservation, waitForReady, stop, now]
      .some((method) => typeof method !== 'function')) refuse();
  const digest = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
  const names = Object.values(schemas);
  const refs = (schema) => [...new Map([...schemaReferences, ...names].filter((entry) =>
    entry?.$id && entry.$id !== schema.$id).map((entry) => [entry.$id, entry])).values()];
  const validatePayload = (schema, payload) => {
    if (validate(schema, payload, { schemas: refs(schema) }).length) refuse();
    return payload;
  };
  const signed = (bytes, kind, schema) => {
    const envelope = verifyStage2aMachineEnvelope(bytes, machinePublicKey,
      `agent-bot/stage2a-member-set-${kind}/v1`, { maxBytes: 16_384 });
    validatePayload(schema, envelope.payload);
    return envelope;
  };
  let started = false;
  return async function prepare({ selectors, expectedAuthority, assignmentBytes, authorityBytes, pendingRuntimes }) {
    if (started) refuse();
    started = true;
    const handles = [];
    let cancelled = false;
    let timer;
    const contain = async () => {
      cancelled = true;
      await Promise.allSettled(handles.map((handle) => Promise.resolve().then(() => handle.stop())));
      await stop();
    };
    const work = async () => {
      const assignment = signed(assignmentBytes, 'assignment', schemas.assignment);
      const a = assignment.payload;
      const authority = verifyStage2aBridgeMemberAuthority(authorityBytes, { machinePublicKey,
        schema: schemas.authority, assignmentSchema: schemas.assignment,
        schemas: refs(schemas.assignment).filter((schema) => schema.$id !== schemas.authority.$id),
        expected: { ...expectedAuthority, ...selectors, profile_in_force: profile },
        assignmentBytes, now: now() });
      const match = (left, right, fields) => fields.every((field) => left?.[field] === right?.[field]);
      const scope = ['profile_in_force', 'host_id', 'installation_id', 'soul_id', 'start_id', 'hq_epoch'];
      const runtime = new Map(pendingRuntimes.map((row) => [row.member_id, row]));
      if (pendingRuntimes.length !== 2 || runtime.size !== 2 || cancelled) refuse();
      const map = validatePayload(schemas.mapping, {
        contract: 'hq/v1', kind: 'stage2a-provisional-member-map', schema_version: 1,
        ...Object.fromEntries(scope.map((field) => [field, a[field]])),
        assignment_envelope_sha256: assignment.envelope_sha256,
        runtime_state: 'provisional', acp_authority: 'withheld',
        members: a.members.map((member) => {
          const rt = runtime.get(member.member_id);
          if (!rt || rt.role !== member.role) refuse();
          return { member_id: member.member_id, member_selector: member.member_selector,
            runtime_id: rt.runtime_id, channel_binding: rt.channel_binding };
        }), issued_at: new Date(now()).toISOString().replace('.000Z', 'Z'), expires_at: a.expires_at,
      });
      const mapBytes = canonicalBytes(map), mapDigest = digest(mapBytes);
      const ack = await submitMap({ ...selectors,
        provisional_hq_mapping_base64url: mapBytes.toString('base64url'), provisional_hq_mapping_sha256: mapDigest });
      if (ack?.accepted !== true || ack.sha256 !== mapDigest || cancelled) refuse();
      const children = await Promise.all(a.members.map(async (member) => {
        const child = await startMember(selectors, Object.freeze({ ...member }));
        if (typeof child?.stop !== 'function') refuse();
        if (cancelled) { await child.stop(); refuse(); }
        handles.push(child);
        const status = await child.waitChildStarted();
        if (cancelled || status.child_launcher_pid !== child.pid || status.grant_sha256 !== child.grantSHA256
          || !DIGEST.test(child.grantSHA256) || !Number.isSafeInteger(status.child_pid)
          || status.child_pid < 2 || status.child_pid === child.pid) refuse();
        return { child, member, status };
      }));
      const hObservations = profile === 'managed-cooperative'
        ? await Promise.all(children.map(({ child, member, status }) => recordHChildObservation({
          member, launcherPid: child.pid, childPid: status.child_pid, grantSHA256: child.grantSHA256,
        }))) : [];
      if (cancelled) refuse();
      const evidence = children.map(({ child, member, status }, i) => ({
        member_id: member.member_id, member_selector: member.member_selector,
        member_launch_id: member.launch_id, child_launcher_pid: child.pid, child_pid: status.child_pid,
        grant_sha256: child.grantSHA256,
        ...(hObservations[i] ? { h_observation_sha256: hObservations[i].sha256,
          h_observation_base64url: hObservations[i].base64url } : {}),
      }));
      const observationBytes = await observeChildren({ ...selectors, members: evidence });
      const observation = signed(observationBytes, 'child-observation', schemas.observation);
      const c = observation.payload;
      if (cancelled || !match(c, a, [...scope, 'reservation_sha256'])
        || c.assignment_envelope_sha256 !== assignment.envelope_sha256
        || c.provisional_hq_mapping_sha256 !== mapDigest
        || canonicalDigest(c.provisional_hq_mapping) !== mapDigest) refuse();
      const memberGrants = c.members.map((row, i) => {
        const observed = evidence[i];
        const h = hObservations[i]?.row;
        if ((h && (!match(row.launcher_process, h.launcher_process, ['pid','uid','gid','start_seconds','start_micros'])
          || !match(row.child_process, h.child_process, ['pid','uid','gid','start_seconds','start_micros'])))
          || row.launcher_process.pid !== observed.child_launcher_pid || row.child_process.pid !== observed.child_pid
          || row.child_process.uid !== a.runner_uid || row.child_process.gid !== a.runner_gid
          || row.child_process.executable_sha256 !== a.members[i].command_sha256
          || row.runtime_id !== map.members[i].runtime_id) refuse();
        return Object.freeze({ member_id: observed.member_id, member_selector: observed.member_selector,
          launch_id: observed.member_launch_id, grant_sha256: observed.grant_sha256,
          launcher_process: Object.freeze({ ...row.launcher_process }) });
      });
      if (!matchesObservedMemberGrants(a, c.members, memberGrants) || Date.parse(c.expires_at) <= now()) refuse();
      await Promise.all(children.map(({ child, member }) =>
        deliverObservation(child, member, observationBytes, observation.envelope_sha256)));
      if (cancelled) refuse();
      const readiness = await waitForReady({ selectors, observationBytes, memberGrants, children,
        provisionalMappingSHA256: mapDigest });
      if (cancelled) refuse();
      if (profile === 'managed-cooperative') {
        const { readyBytes, armReceiptSHA256s } = readiness ?? {};
        const readyEvidence = Object.freeze({ observation, authoritySHA256: authority.envelope_sha256,
          bridgeObservedSHA256: expectedAuthority.bridgeObservedSHA256,
          hObservationSHA256s: Object.freeze(hObservations.map(({ sha256 }) => sha256)),
          armReceiptSHA256s: Object.freeze([...(armReceiptSHA256s ?? [])]) });
        verifyCooperativeMemberReady(readyBytes, machinePublicKey, { ...readyEvidence, now: now() });
        return Object.freeze({ assignment, assignmentBytes, authorityBytes, observationBytes, readyBytes, readyEvidence,
          memberGrants: Object.freeze(memberGrants), children: Object.freeze(children), provisionalMappingSHA256: mapDigest });
      }
      const readyBytes = readiness;
      const ready = signed(readyBytes, 'ready', schemas.ready);
      const r = ready.payload;
      if (cancelled || !match(r, a, [...scope, 'reservation_sha256'])
        || r.assignment_envelope_sha256 !== assignment.envelope_sha256
        || r.child_observation_envelope_sha256 !== observation.envelope_sha256
        || r.member_b_authority_envelope_sha256 !== authority.envelope_sha256
        || r.b_authority_sha256 !== a.b_authority.envelope_sha256 || r.provisional_hq_mapping_sha256 !== mapDigest
        || !match(r.bridge_process, a.bridge, ['uid', 'gid'])
        || !expectedAuthority.bridge_process
        || canonicalDigest(r.bridge_process) !== canonicalDigest(expectedAuthority.bridge_process)
        || !(Date.parse(r.issued_at) <= now() && now() < Date.parse(r.expires_at))) refuse();
      for (const [i, row] of r.members.entries()) {
        const observed = c.members[i], arm = row.bridge_arm;
        if (!match(row, observed, ['member_id', 'member_selector', 'launch_id', 'runtime_id'])
          || !match(row, arm, ['member_id', 'member_selector', 'runtime_id'])
          || arm.bridge_uid !== r.bridge_process.uid || arm.state !== 'armed'
          || arm.child_observation_envelope_sha256 !== observation.envelope_sha256
          || ['pid', 'uid', 'gid', 'start_seconds', 'start_micros'].some((field) =>
            arm[`adapter_${field}`] !== observed.child_process[field])
          || canonicalDigest(arm) !== row.bridge_arm_receipt_sha256) refuse();
      }
      return Object.freeze({ assignment, assignmentBytes, authorityBytes, observationBytes, readyBytes,
        memberGrants: Object.freeze(memberGrants), children: Object.freeze(children), provisionalMappingSHA256: mapDigest });
    };
    try {
      return await Promise.race([work(), new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('Stage 2a member-set prestart timed out')), 20_000);
        timer.unref?.();
      })]);
    } catch (error) { await contain(); throw error; }
    finally { clearTimeout(timer); }
  };
}

export function createStage2aProtectedStarter({ installations, authority, verifyReservation,
  getBrokerIdentity, verifyBoundBridge, machineLookup = machineRoleStage2aLookup,
  machineReserve = machineRoleStage2aReserve, machineFinalize = machineRoleStage2aFinalizeB,
  machineChildReady = machineRoleStage2aChildReady,
  openProtectedAdmission,
  prepareBridge = prepareStage2aBridge, startRole = startStage2aRole,
  verifyHQCodeReady = () => false,
  onFinalized, onStopped, random = (bytes) => randomBytes(bytes).toString('hex') } = {}) {
  if (!Array.isArray(installations) || typeof authority?.register !== 'function'
    || typeof authority.stopStart !== 'function' || typeof authority.currentLiveStart !== 'function'
    || typeof verifyReservation !== 'function'
    || typeof getBrokerIdentity !== 'function' || typeof verifyBoundBridge !== 'function'
    || typeof machineLookup !== 'function'
    || typeof machineReserve !== 'function' || typeof machineFinalize !== 'function'
    || typeof machineChildReady !== 'function'
    || typeof prepareBridge !== 'function' || typeof startRole !== 'function'
    || typeof verifyHQCodeReady !== 'function' || typeof random !== 'function') refuse();
  const byId = new Map(installations.map((i) => [i.installation_id, i]));
  if (byId.size !== installations.length) refuse();
  const slots = new Map();
  let stopping = false;

  function armLease(slot, expiresAt) {
    const remaining = expiresAt - Date.now();
    if (!Number.isSafeInteger(expiresAt) || remaining <= 0 || remaining > 5000) refuse();
    clearTimeout(slot.leaseTimer);
    slot.leaseTimer = setTimeout(() => { void stop(slot).catch(() => {}); }, remaining);
    slot.leaseTimer.unref?.();
  }

  async function stop(slot) {
    if (slot.stopPromise) return slot.stopPromise;
    slot.stopPromise = (async () => {
      clearTimeout(slot.leaseTimer);
      slot.activationSent = false;
      const results = await Promise.allSettled([
        Promise.resolve().then(() => onStopped?.(slot.reservationSHA256)),
        Promise.resolve().then(() => slot.admission?.close?.()),
        Promise.resolve().then(() => authority.stopStart(slot.reservationSHA256)),
      ]);
      const failures = results.filter((item) => item.status === 'rejected').map((item) => item.reason);
      if (failures.length) throw new AggregateError(failures, 'protected R/B stop is unconfirmed');
      slots.delete(slot.installed.installation_id);
      return true;
    })();
    return slot.stopPromise;
  }

  async function start(payload) {
    if (stopping || typeof openProtectedAdmission !== 'function'
      || !exact(payload, ['package_path', 'requested_profile'])
      || payload.requested_profile !== 'managed-protected'
      || typeof payload.package_path !== 'string' || !payload.package_path.startsWith('/')) refuse();
    // The machine/v2 installed policy does not authenticate HQ's selected
    // installed code. A trusted entry point must prove the static A-signed H
    // descriptor before any Machine lookup or one-use reservation. There is no
    // owner-config or v2 fallback while the versioned H seam is unfinished.
    if (await verifyHQCodeReady() !== true) refuse();
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
    const slot = { installed, reservationSHA256: null, assignment: null,
      runner: null, bridge: null, child: null, admission: null, finalizationEnvelope: null,
      bindReceiptSHA256: null, activationSent: false, activated: false,
      rLeaseReady: false, livePending: 0, liveQueue: Promise.resolve(),
      lastLeaseSequence: 0,
      issuedRLeases: new Map(),
      leaseTimer: null, stopPromise: null };
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
      const checked = await verifyReservation(reserved?.envelope, installed, reserved?.sha256);
      if (checked?.reservationSHA256 !== reserved?.sha256
        || checked.payload.assignment.start_id !== startId
        || checked.payload.assignment.launch_id !== launchId) refuse();
      const assignment = checked.payload.assignment;
      slot.reservationSHA256 = reserved.sha256;
      slot.assignment = assignment;
      const selectors = await authority.register({ envelope: reserved.envelope,
        sha256: reserved.sha256, installed, killRoles: async () => {
          const roles = [slot.child, slot.runner, slot.bridge].filter(Boolean);
          await Promise.allSettled(roles.map((role) => role.stop()));
        } });
      registered = true;
      slot.admission = await openProtectedAdmission({ installed, assignment, selectors,
        getBindReceiptSHA256: () => slot.bindReceiptSHA256 });
      if (typeof slot.admission?.close !== 'function') refuse();
      if (slot.stopPromise) {
        await slot.admission.close();
        refuse();
      }
      await prepareBridge({ installed, observed: getBrokerIdentity(installed.installation_id),
        selectors });
      slot.bridge = await startRole({ account: installed.bridge_account, role: 'bridge',
        reservationSHA256: reserved.sha256 });
      authority.setRolePid(reserved.sha256, 'bridge', slot.bridge.pid);
      slot.bridge.done?.then(() => { void stop(slot).catch(() => {}); });
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
        slot.finalizationEnvelope = Buffer.from(finalized.envelope);
        return true;
      });
      if (!ready || !slot.bridge) refuse();
      slot.runner = await startRole({ account: installed.runner_account, role: 'runner',
        reservationSHA256: reserved.sha256 });
      authority.setRolePid(reserved.sha256, 'runner', slot.runner.pid);
      slot.runner.done?.then(() => { void stop(slot).catch(() => {}); });
      // A signed current Machine lease is needed after both PIDs are present.
      const live = await authority.currentLiveStart(reserved.sha256);
      const initialLease = checkedLiveLease(live);
      if (!live || live.phase !== 'finalized' || live.runner_pid !== slot.runner.pid
        || live.bridge_pid !== slot.bridge.pid
        || !Number.isSafeInteger(live.finalized_live_expires_at)) refuse();
      slot.bindReceiptSHA256 = live.bind_receipt_sha256;
      armLease(slot, live.finalized_live_expires_at);
      slot.lastLeaseSequence = initialLease.sequence;
      // R may request its first lease as soon as the private preface enters
      // its pipe, before Node invokes the write callback. Make that request
      // eligible before writing; the start catch path contains write errors.
      slot.activationSent = true;
      await activateRunner(slot.runner, assignment, reserved.sha256, live, slot.finalizationEnvelope);
      const ack = await slot.runner.waitRunnerActivation({ reservationSHA256: reserved.sha256,
        startId, launchId });
      if (!ack || ack.reservation_sha256 !== reserved.sha256
        || ack.start_id !== startId || ack.launch_id !== launchId
        || slot.issuedRLeases.get(ack.lease_sequence)?.sha256 !== ack.lease_sha256
        || slot.issuedRLeases.get(ack.lease_sequence)?.expiresAt <= Date.now()
        || !slot.rLeaseReady || slot.stopPromise) refuse();
      const helloFinalization = slot.admission.helloFinalization?.();
      if (!Buffer.isBuffer(helloFinalization?.envelope)
        || !DIGEST.test(helloFinalization?.sha256 ?? '')
        || 'sha256:' + createHash('sha256').update(helloFinalization.envelope).digest('hex')
          !== helloFinalization.sha256) refuse();
      slot.activated = true;
      // The stock ACP child has its own one-use Machine grant and process
      // group. R remains an admission supervisor and never carries ACP bytes.
      slot.child = await startRole({ account: installed.runner_account, role: 'child',
        reservationSHA256: reserved.sha256 });
      slot.child.done?.then(() => { void stop(slot).catch(() => {}); });
      const childStarted = await slot.child.waitChildStarted();
      if (childStarted.child_launcher_pid !== slot.child.pid
        || childStarted.grant_sha256 !== slot.child.grantSHA256) refuse();
      const childReceipt = await machineChildReady({ ...selectors,
        child_launcher_pid: childStarted.child_launcher_pid,
        child_pid: childStarted.child_pid,
        grant_sha256: childStarted.grant_sha256 });
      if (!Buffer.isBuffer(childReceipt?.envelope)
        || !DIGEST.test(childReceipt?.sha256 ?? '')
        || !Number.isSafeInteger(childReceipt?.expires_at_ms)
        || childReceipt.expires_at_ms <= Date.now()) refuse();
      await slot.child.sendChildReceipt(childReceipt);
      await slot.child.waitChildAccepted(childReceipt.sha256);
      await slot.runner.waitRunnerChildReady({ reservationSHA256: reserved.sha256,
        startId, launchId, childStartSHA256: childReceipt.sha256,
        childStartEnvelope: childReceipt.envelope,
        helloFinalizationSHA256: helloFinalization.sha256,
        helloFinalizationEnvelope: helloFinalization.envelope });
      if (slot.stopPromise) refuse();
      // Do not expose the one-use provider before R and the stock child have
      // both acknowledged A's signed current start and child receipts.
      await onFinalized?.({ installed, assignment, selectors,
        bindReceiptSHA256: live.bind_receipt_sha256 });
      const result = { start_id: startId, launch_id: launchId, installation_id: installed.installation_id,
        soul_id: installed.soul_id, package_path: source, pid: childStarted.child_pid,
        runner_uid: installed.runner_uid, runner_gid: installed.runner_gid,
        hq_epoch: installed.hq_epoch, profile: 'managed-protected', protected: true };
      return takeover(result, { open: () => (socket) => {
        if (stopping || slot.stopPromise) { socket.destroy(); return; }
        const cut = () => { socket.destroy(); void stop(slot); };
        socket.once('error', cut);
        slot.child.stdin.once?.('error', cut);
        slot.child.stdout.once?.('error', cut);
        socket.pipe(slot.child.stdin);
        pipeline(slot.child.stdout, socket, (error) => { if (error) cut(); });
        slot.child.resumeOutput();
        socket.once('close', () => { void stop(slot); });
        slot.child.done.then(() => { socket.end(); void stop(slot); });
      }, cancel: () => { void stop(slot); } });
    } catch (error) {
      if (registered) {
        try { await stop(slot); } catch { /* keep the slot occupied on uncertain containment */ }
      } else if (!slot.reservationSHA256) slots.delete(installed.installation_id);
      throw error;
    }
  }

  async function renewLive(request) {
    if (!exact(request, ['installation_id', 'start_id', 'launch_id',
      'reservation_sha256', 'challenge'])
      || typeof request.challenge !== 'string'
      || !/^[A-Za-z0-9_-]{43}$/.test(request.challenge)
      || Buffer.from(request.challenge, 'base64url').length !== 32
      || Buffer.from(request.challenge, 'base64url').toString('base64url') !== request.challenge) refuse();
    const slot = byId.has(request.installation_id)
      ? slots.get(request.installation_id) : undefined;
    if (!slot || !slot.activationSent || slot.stopPromise || slot.livePending >= 2) refuse();
    if (request.reservation_sha256 !== slot.reservationSHA256
      || request.start_id !== slot.assignment?.start_id
      || request.launch_id !== slot.assignment?.launch_id) {
      await stop(slot).catch(() => {});
      refuse();
    }
    // R and the separate child each renew their five-second A lease. Serialize
    // the two paired calls, preserving each distinct challenge and sequence.
    const prior = slot.liveQueue;
    let release;
    slot.liveQueue = new Promise((resolve) => { release = resolve; });
    slot.livePending += 1;
    try {
      await prior;
      if (slot.stopPromise) refuse();
      const live = await authority.currentLiveStart(slot.reservationSHA256, request.challenge);
      const finalizationSHA256 = 'sha256:' + createHash('sha256')
        .update(slot.finalizationEnvelope).digest('hex');
      if (live?.phase !== 'finalized' || live.runner_pid !== slot.runner?.pid
        || live.bridge_pid !== slot.bridge?.pid
        || live.finalization_sha256 !== finalizationSHA256
        || live.bind_receipt_sha256 !== slot.bindReceiptSHA256 || slot.stopPromise) refuse();
      const lease = checkedLiveLease(live);
      if (lease.sequence <= slot.lastLeaseSequence) refuse();
      armLease(slot, live.finalized_live_expires_at);
      slot.lastLeaseSequence = lease.sequence;
      for (const [sequence, prior] of slot.issuedRLeases) {
        if (prior.expiresAt <= Date.now()) slot.issuedRLeases.delete(sequence);
      }
      slot.issuedRLeases.set(lease.sequence, Object.freeze({ sha256: lease.sha256,
        expiresAt: live.finalized_live_expires_at }));
      while (slot.issuedRLeases.size > 16) {
        slot.issuedRLeases.delete(slot.issuedRLeases.keys().next().value);
      }
      slot.rLeaseReady = true;
      return Object.freeze({ schema: 'agent-bot-hq/protected-live/v1',
        installation_id: request.installation_id,
        reservation_sha256: request.reservation_sha256,
        start_id: request.start_id, launch_id: request.launch_id,
        challenge: request.challenge,
        lease_envelope_base64url: lease.envelope,
        lease_sha256: lease.sha256, lease_sequence: lease.sequence,
        live_expires_at_ms: live.finalized_live_expires_at });
    } catch (error) {
      await stop(slot).catch(() => {});
      throw error;
    } finally {
      slot.livePending -= 1;
      release();
    }
  }

  async function stopReservation(reservationSHA256) {
    if (!DIGEST.test(reservationSHA256 ?? '')) refuse();
    const slot = [...slots.values()].find((value) =>
      value.reservationSHA256 === reservationSHA256);
    if (!slot) refuse();
    return stop(slot);
  }

  return Object.freeze({ start, renewLive, stopReservation, stopAll: async () => {
    stopping = true;
    await Promise.all([...slots.values()].map(stop));
  } });
}
