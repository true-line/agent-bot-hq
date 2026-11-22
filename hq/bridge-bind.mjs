// HQ-owned B-only bind state for a future Machine-authorized protected Soul
// start. The production entry point supplies no authority yet: every call
// refuses until a trusted Machine client can verify the signed live start,
// kernel B peer and exact endpoint, and supply the one-use FD secret.
import { createHmac, createHash, timingSafeEqual } from 'node:crypto';
import { fail } from '../sdk/errors.mjs';

export const BRIDGE_BIND_CONTEXT = 'agent-bot-stage2a-bridge-bind-v1';
const SELECTORS = ['installation_id', 'start_id', 'launch_id', 'runtime_id', 'plan_id', 'plan_digest'];
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const START = /^st_[0-9a-f]{24}$/;
const LAUNCH = /^ln_[0-9a-f]{24}$/;
const SHA = /^[0-9a-f]{64}$/;
const PROOF = /^[0-9a-f]{64}$/;
const MAX_PENDING = 4096;
const CONTAINMENT_DEADLINE_MS = 5000;

const refuse = () => fail('host.launch_unavailable', 'authenticated protected bridge bind is unavailable');
const record = (value) => value && typeof value === 'object' && !Array.isArray(value);
const exact = (value, keys) => record(value) && Object.keys(value).length === keys.length
  && keys.every((key) => Object.hasOwn(value, key));
const validSelectors = (input) => record(input) && ID.test(input.installation_id ?? '')
  && START.test(input.start_id ?? '') && LAUNCH.test(input.launch_id ?? '')
  && ID.test(input.runtime_id ?? '') && ID.test(input.plan_id ?? '')
  && SHA.test(input.plan_digest ?? '');
const selectorsOf = (input, withProof = false) => {
  if (!exact(input, withProof ? [...SELECTORS, 'proof'] : SELECTORS)
    || !validSelectors(input)
    || (withProof && (typeof input.proof !== 'string' || !PROOF.test(input.proof)))) refuse();
  return Object.fromEntries(SELECTORS.map((key) => [key, input[key]]));
};
const sameSelectors = (a, b) => SELECTORS.every((key) => a[key] === b[key]);
const sameContext = (a, b) => sameSelectors(a, b) && a.hq_epoch === b.hq_epoch
  && a.bridge_uid === b.bridge_uid && a.broker_socket === b.broker_socket
  && timingSafeEqual(a.proof_key, b.proof_key);
const validContext = (value, selectors) => validSelectors(value) && sameSelectors(value, selectors)
  && SHA.test(value.hq_epoch ?? '') && Number.isSafeInteger(value.bridge_uid)
  && value.bridge_uid >= 300 && value.bridge_uid <= 399
  && typeof value.broker_socket === 'string' && value.broker_socket.startsWith('/')
  && !/[\x00\r\n]/.test(value.broker_socket)
  && Buffer.isBuffer(value.proof_key) && value.proof_key.length === 32;

export function bridgeBindProof(key, nonce, context) {
  if (!Buffer.isBuffer(key) || key.length !== 32 || !SHA.test(nonce)
    || !validContext(context, context)) throw new TypeError('invalid trusted bridge bind context');
  return createHmac('sha256', key).update([
    BRIDGE_BIND_CONTEXT, nonce, context.hq_epoch,
    ...SELECTORS.map((field) => context[field]), String(context.bridge_uid), context.broker_socket,
  ].join('\n')).digest('hex');
}

// verifyLiveStart must authenticate the Machine-signed assignment from its
// verified bytes and recheck the installed rule, spent start, B kernel UID,
// endpoint inode/peer and policy checkpoint at each call. If it fails after
// authenticating a start but before returning, it must itself quarantine that
// start: HQ cannot safely derive a stop target from an unauthenticated frame.
// onDisconnect must durably record the quarantine/stop request before it
// resolves, and reject on uncertain containment. The proof key is generated
// by HQ and given only to B via its one-use inherited descriptor.
// No owner, member, configuration file or ordinary plugin can provide it.
export function createBridgeBindAdmission({ authority, clock, random, receipts, timers = { setTimeout, clearTimeout } } = {}) {
  const challenges = new Map();
  const verifying = new Map();
  const live = new Map();
  const closed = new Set();
  const inFlight = new Set();
  const claimedStarts = new Set(); // supplemental local fence; Machine must durably spend the start
  const quarantines = new Map();
  const active = new Set();
  let stopping = false;
  let containmentUnconfirmed = false;
  const track = (promise) => {
    active.add(promise);
    promise.then(() => active.delete(promise), () => active.delete(promise));
    return promise;
  };
  const configured = () => typeof authority?.verifyLiveStart === 'function'
    && typeof authority?.onDisconnect === 'function'
    && typeof clock?.now === 'function' && typeof random?.hex === 'function'
    && typeof receipts?.append === 'function'
    && typeof timers?.setTimeout === 'function' && typeof timers?.clearTimeout === 'function';
  const available = () => !stopping && !containmentUnconfirmed && configured();
  const bridgeStatus = () => ({ state: containmentUnconfirmed ? 'containment_unconfirmed'
    : stopping ? 'stopping' : configured() ? 'bind-enabled' : 'unavailable' });
  const connectionOf = (meta) => typeof meta?.connection === 'string' && meta.connection ? meta.connection : refuse();
  const check = async (selectors, connection) => {
    const context = await authority.verifyLiveStart(selectors, connection);
    if (!validContext(context, selectors)) refuse();
    // Hold an immutable field snapshot, not an authority object's mutable
    // reference across the challenge/response and Machine recheck.
    return Object.freeze({ ...selectors, hq_epoch: context.hq_epoch,
      bridge_uid: context.bridge_uid, broker_socket: context.broker_socket,
      proof_key: Buffer.from(context.proof_key) });
  };
  const startKey = (context) => [...SELECTORS.map((field) => context[field]), context.hq_epoch].join('\0');
  const observation = (context, receipt) => Object.freeze({
    ...Object.fromEntries(SELECTORS.map((field) => [field, context[field]])),
    hq_epoch: context.hq_epoch, bridge_uid: context.bridge_uid,
    broker_socket: context.broker_socket,
    ...(receipt ? { bind_receipt_sha256: `sha256:${createHash('sha256').update(receipt).digest('hex')}` } : {}),
  });
  const bounded = (operation, label) => {
    let timeout;
    return new Promise((resolve, reject) => {
      timeout = timers.setTimeout(() => reject(new Error(label)), CONTAINMENT_DEADLINE_MS);
      Promise.resolve(operation).then(resolve, reject);
    }).finally(() => timers.clearTimeout(timeout));
  };
  const alertUnconfirmed = async (reason, fields = {}) => {
    containmentUnconfirmed = true;
    const alert = { kind: 'hq.bridge.containment_unconfirmed', reason, ...fields };
    await bounded(receipts.append(alert), 'HQ bridge alert persistence deadline exceeded');
  };
  const quarantine = (context, reason, receipt) => {
    const key = startKey(context);
    if (quarantines.has(key)) return quarantines.get(key);
    const stopped = observation(context, receipt);
    let requested;
    try { requested = authority.onDisconnect(stopped, reason); }
    catch (error) { requested = Promise.reject(error); }
    const pending = bounded(requested, 'Machine bridge containment deadline exceeded').catch(async (error) => {
      // Socket-close and timer callers may have no waiter. Freeze all bridge
      // authority immediately, and persist a visible HQ alert before the
      // cleanup failure can be swallowed by the generic broker lifecycle.
      const fields = {
        installation_id: stopped.installation_id, start_id: stopped.start_id,
        launch_id: stopped.launch_id, hq_epoch: stopped.hq_epoch,
        ...(stopped.bind_receipt_sha256 ? { bind_receipt_sha256: stopped.bind_receipt_sha256 } : {}) };
      try { await alertUnconfirmed(reason, fields); }
      catch (auditError) { throw new AggregateError([error, auditError], 'bridge containment and alert persistence failed'); }
      throw error;
    });
    quarantines.set(key, pending); // even an uncertain stop cannot be replayed as a fresh bind
    // A timer or generic broker callback may discard its caller Promise.
    // Keep the failure observed here; revokeAll still reads the original
    // rejected Promise and reports it to HQ shutdown.
    pending.catch(() => {});
    return pending;
  };

  // Synchronously remove all B authority before the caller awaits Machine
  // containment. An authenticated pending challenge is a stop target too.
  function forgetBridgeConnection(connection, receipt, reason = 'bridge-disconnected') {
    if (typeof connection !== 'string' || !connection) refuse();
    if (inFlight.has(connection) || challenges.has(connection)
      || verifying.has(connection) || live.has(connection)) closed.add(connection);
    while (closed.size > MAX_PENDING) {
      const oldest = [...closed].find((id) => !inFlight.has(id));
      if (!oldest) break;
      closed.delete(oldest);
    }
    const pending = challenges.get(connection) ?? verifying.get(connection);
    const bound = live.get(connection);
    if (pending?.timer !== undefined) timers.clearTimeout(pending.timer);
    challenges.delete(connection);
    verifying.delete(connection);
    live.delete(connection);
    const context = bound?.context ?? pending?.context;
    if (!context) return Promise.resolve();
    const containment = quarantine(context, reason, bound?.receipt);
    // Comms may close while the bind reply is in flight, before it knows the
    // receipt. A wrong supplied receipt still requests containment first.
    if (receipt !== undefined && receipt !== bound?.receipt) return containment.then(refuse);
    return containment;
  }

  async function bridgeBindChallenge(input, meta) {
    if (!available()) refuse();
    const selectors = selectorsOf(input);
    const connection = connectionOf(meta);
    if (closed.has(connection) || challenges.has(connection) || verifying.has(connection)
      || live.has(connection) || inFlight.has(connection)
      || inFlight.size >= MAX_PENDING) refuse();
    inFlight.add(connection);
    let context;
    try {
      context = await check(selectors, connection);
      if (!available() || closed.has(connection)) refuse();
      const claim = startKey(context);
      if (claimedStarts.has(claim) || claimedStarts.size >= MAX_PENDING) refuse();
      claimedStarts.add(claim); // failed or abandoned challenge still spends this local start
      // Register the authenticated stop target before the first further
      // await. A close or HQ stop during expired-challenge cleanup can now
      // quarantine this start, and cannot be followed by a late challenge.
      verifying.set(connection, { selectors, context });
      const now = clock.now();
      if (!Number.isSafeInteger(now) || now < 0) refuse();
      for (const [id, entry] of challenges) if (entry.expires <= now) {
        // An expired authenticated challenge must stop its runner; do not
        // silently evict it as a reusable B start.
        await forgetBridgeConnection(id, undefined, 'bridge-challenge-expired');
      }
      if (challenges.size >= MAX_PENDING) refuse();
      const nonce = random.hex(32);
      if (!SHA.test(nonce)) refuse();
      const expires = now + 30_000;
      if (!available() || closed.has(connection) || !verifying.has(connection)) refuse();
      verifying.delete(connection);
      const timer = timers.setTimeout(() => {
        // Failure degrades the live bridge state and records an HQ alert in
        // quarantine(); the rejected cleanup remains for HQ stop to surface.
        void forgetBridgeConnection(connection, undefined, 'bridge-challenge-expired').catch(() => {});
      }, expires - now);
      timer?.unref?.();
      challenges.set(connection, { selectors, context, nonce, expires, timer });
      return { nonce, algorithm: 'hmac-sha256', context: BRIDGE_BIND_CONTEXT,
        hq_epoch: context.hq_epoch, expires_at: new Date(expires).toISOString() };
    } catch {
      if (context) {
        if (challenges.has(connection) || verifying.has(connection) || live.has(connection))
          await forgetBridgeConnection(connection, undefined, 'bridge-challenge-failed');
        else await quarantine(context, 'bridge-challenge-failed');
      }
      refuse();
    } finally { inFlight.delete(connection); }
  }

  async function verifyBridgeBinding(input, meta) {
    if (!available()) refuse();
    const connection = connectionOf(meta);
    const pending = challenges.get(connection);
    challenges.delete(connection); // one attempt, including a wrong proof
    if (pending?.timer !== undefined) timers.clearTimeout(pending.timer);
    if (pending) verifying.set(connection, pending);
    try {
      const selectors = selectorsOf(input, true);
      if (!pending || closed.has(connection) || live.has(connection)
        || pending.expires <= clock.now() || !sameSelectors(selectors, pending.selectors)
        || inFlight.has(connection) || inFlight.size >= MAX_PENDING) refuse();
      inFlight.add(connection);
      let context;
      try { context = await check(selectors, connection); }
      finally { inFlight.delete(connection); }
      if (!available() || closed.has(connection) || verifying.get(connection) !== pending
        || !sameContext(context, pending.context)) refuse();
      const expected = bridgeBindProof(context.proof_key, pending.nonce, context);
      if (!timingSafeEqual(Buffer.from(input.proof, 'hex'), Buffer.from(expected, 'hex'))) refuse();
      const receipt = random.hex(32);
      if (!SHA.test(receipt)) refuse();
      verifying.delete(connection);
      live.set(connection, { receipt, context, observation: observation(context, receipt) });
      return { bind_receipt: receipt };
    } catch {
      await forgetBridgeConnection(connection, undefined, 'bridge-bind-failed');
      refuse();
    }
  }

  async function boundBridge(selectors, receiptDigest) {
    if (!available()) refuse();
    selectorsOf(selectors);
    for (const [connection, binding] of live) {
      if (sameSelectors(binding.observation, selectors)
        && binding.observation.bind_receipt_sha256 === receiptDigest) {
        try {
          const current = await check(selectors, connection);
          if (!available() || closed.has(connection) || live.get(connection) !== binding
            || !sameContext(current, binding.context)) refuse();
          return { ...binding.observation, connected: true, hmac_verified: true };
        } catch {
          await forgetBridgeConnection(connection, binding.receipt, 'bridge-live-recheck-failed');
          refuse();
        }
      }
    }
    return null;
  }

  async function revokeAll() {
    stopping = true;
    const stops = [];
    for (const connection of new Set([...challenges.keys(), ...verifying.keys(), ...live.keys()]))
      stops.push(forgetBridgeConnection(connection, live.get(connection)?.receipt, 'bridge-hq-stopped'));
    // Observe containment failures before waiting on potentially stuck
    // Machine verification. Otherwise an immediate onDisconnect rejection
    // can become an unhandled process-level failure during the drain.
    const settledStops = Promise.allSettled(stops);
    for (const connection of inFlight) closed.add(connection);
    let drainError;
    try {
      await bounded(Promise.allSettled([...active]), 'HQ bridge verifier drain deadline exceeded');
    } catch (error) { drainError = error; }
    const outcomes = [...await settledStops, ...await Promise.allSettled([...quarantines.values()])];
    const failures = [...new Set(outcomes.filter((outcome) => outcome.status === 'rejected')
      .map((outcome) => outcome.reason))];
    if (drainError) {
      try { await alertUnconfirmed('bridge-verifier-drain-timeout', { active_operations: active.size }); }
      catch (auditError) { failures.push(auditError); }
      throw new AggregateError([drainError, ...failures], 'HQ bridge verifier drain deadline exceeded');
    }
    if (failures.length === 1) throw failures[0];
    if (failures.length) throw new AggregateError(failures, 'HQ bridge containment failed');
  }
  return Object.freeze({ bridgeStatus,
    bridgeBindChallenge: (...args) => track(bridgeBindChallenge(...args)),
    verifyBridgeBinding: (...args) => track(verifyBridgeBinding(...args)),
    forgetBridgeConnection, boundBridge: (...args) => track(boundBridge(...args)), revokeAll,
  });
}
