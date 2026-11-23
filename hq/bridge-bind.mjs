// HQ-owned B-only bind state for a future Machine-authorized protected Soul
// start. The production entry point supplies no authority yet: every call
// refuses until a trusted Machine client can verify the signed live start,
// kernel B peer and exact endpoint, and supply the one-use FD secret.
import { createHmac, createHash, timingSafeEqual } from 'node:crypto';
import { fail } from '../sdk/errors.mjs';

export const BRIDGE_BIND_CONTEXT = 'agent-bot-stage2a-bridge-bind-v1';
export const BRIDGE_BIND_V2_CONTEXT = 'agent-bot-stage2a-bridge-bind-v2';
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const START = /^st_[0-9a-f]{24}$/;
const LAUNCH = /^ln_[0-9a-f]{24}$/;
const SHA = /^[0-9a-f]{64}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const V1 = { label: BRIDGE_BIND_CONTEXT, separator: '\n', verify: 'verifyLiveStart', fields: [
  ['installation_id', ID], ['start_id', START], ['launch_id', LAUNCH], ['runtime_id', ID],
  ['plan_id', ID], ['plan_digest', SHA],
] };
const V2 = { label: BRIDGE_BIND_V2_CONTEXT, separator: '\0', verify: 'verifyLiveStartV2', fields: [
  ['installation_id', ID], ['start_id', START], ['launch_id', LAUNCH],
  ['plan_id', ID], ['plan_digest', SHA], ['reservation_digest', DIGEST],
] };
const BIND_TTL_MS = 30_000;
const MAX_TIMER_MS = 2_147_483_647;
const MAX_PENDING = 4096;
const CONTAINMENT_DEADLINE_MS = 5000;

const refuse = () => fail('host.launch_unavailable', 'authenticated protected bridge bind is unavailable');
const record = (value) => value && typeof value === 'object' && !Array.isArray(value);
const matches = (pattern, value) => typeof value === 'string' && pattern.test(value);
const validSelectors = (protocol, input) => record(input) && protocol.fields.every(([key, pattern]) =>
  Object.hasOwn(input, key) && matches(pattern, input[key]));
const selectorsOf = (protocol, input, withProof = false) => {
  if (!validSelectors(protocol, input) || Object.keys(input).length !== protocol.fields.length + Number(withProof)
    || (withProof && (!Object.hasOwn(input, 'proof') || !matches(SHA, input.proof)))) refuse();
  return Object.fromEntries(protocol.fields.map(([key]) => [key, input[key]]));
};
const sameSelectors = (protocol, a, b) => protocol.fields.every(([key]) => a[key] === b[key]);
const sameContext = (protocol, a, b) => sameSelectors(protocol, a, b) && a.hq_epoch === b.hq_epoch
  && a.bridge_uid === b.bridge_uid && a.broker_socket === b.broker_socket
  && a.reservationExpires === b.reservationExpires && a.member_socket === b.member_socket
  && a.soul_artifact_sha256 === b.soul_artifact_sha256
  && (protocol === V2 || timingSafeEqual(a.proof_key, b.proof_key));
const validContext = (protocol, value, selectors) => validSelectors(protocol, value) && sameSelectors(protocol, value, selectors)
  && matches(SHA, value.hq_epoch) && Number.isSafeInteger(value.bridge_uid)
  && value.bridge_uid >= 300 && value.bridge_uid <= 399
  && typeof value.broker_socket === 'string' && value.broker_socket.startsWith('/')
  && !/[\x00\r\n]/.test(value.broker_socket);
const digest = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const validKey = (key) => Buffer.isBuffer(key) && key.length === 32;

function proofFor(protocol, key, nonce, context) {
  if (!validKey(key) || !matches(SHA, nonce)
    || !validContext(protocol, context, context)) throw new TypeError('invalid trusted bridge bind context');
  return createHmac('sha256', key).update([
    protocol.label, nonce, context.hq_epoch,
    ...protocol.fields.map(([field]) => context[field]), String(context.bridge_uid), context.broker_socket,
  ].join(protocol.separator), 'utf8').digest('hex');
}

export const bridgeBindProof = (key, nonce, context) => proofFor(V1, key, nonce, context);
export const bridgeBindProofV2 = (key, nonce, context) => proofFor(V2, key, nonce, context);

// verifyLiveStartV2 is pinned HQ entry-point code. On each call it must
// authenticate the exact reservation_bytes with the paired Machine issuer,
// derive the context from those bytes, and recheck Machine's installed plan,
// current policy and durably spent one-use live start. The verified projection
// includes the signed member assignment, distinct soul_artifact_sha256 and
// reservation_expires_at (Unix milliseconds). The v2 proof key stays with
// Machine and B; HQ asks Machine to verify the exact proof after its local
// challenge. A receipt recheck may get
// finalized_live_expires_at only after independent verification of the exact
// Machine finalization and its current live-run lease for this bound start.
// This verifier never authorizes the Hello runtime set.
// The authority must retain the authenticated stop target keyed by connection
// before resolving, and contain it itself if verification later rejects.
// onDisconnectV2 uses that retained target even if HQ cannot validate the
// projection. It returns true only after independently confirming the durable
// containment request, and rejects on uncertainty.
export function createBridgeBindAdmission({ authority, qualificationAuthorizer, relayIngressAuthorizer,
  clock, random, receipts, timers = { setTimeout, clearTimeout } } = {}) {
  if (typeof qualificationAuthorizer === 'function' && typeof relayIngressAuthorizer === 'function') {
    throw new TypeError('fixture qualification and production relay ingress cannot share a bridge');
  }
  const challenges = new Map();
  const verifying = new Map();
  const live = new Map();
  const closed = new Set();
  const inFlight = new Set();
  const claimedStarts = new Map(); // supplemental local fence; Machine must durably spend the start
  const quarantines = new Map();
  const active = new Set();
  let stopping = false;
  let containmentUnconfirmed = false;
  const track = (promise) => {
    active.add(promise);
    promise.then(() => active.delete(promise), () => active.delete(promise));
    return promise;
  };
  const configured = (protocol) => typeof authority?.[protocol.verify] === 'function'
    && (protocol === V2 ? typeof authority.verifyProofV2 === 'function'
      && typeof authority.isCurrentPeerV2 === 'function'
      && typeof authority.matchesAssignmentV2 === 'function' && typeof authority.onDisconnectV2 === 'function'
      : typeof authority.onDisconnect === 'function')
    && typeof clock?.now === 'function' && typeof random?.hex === 'function'
    && typeof receipts?.append === 'function'
    && typeof timers?.setTimeout === 'function' && typeof timers?.clearTimeout === 'function';
  const available = (protocol) => !stopping && !containmentUnconfirmed && configured(protocol);
  const bridgeStatus = () => ({ state: containmentUnconfirmed ? 'containment_unconfirmed'
    : stopping ? 'stopping' : configured(V2) || configured(V1) ? 'bind-enabled' : 'unavailable' });
  const connectionOf = (meta) => typeof meta?.connection === 'string' && meta.connection ? meta.connection : refuse();
  const check = async (protocol, selectors, connection, phase) => {
    const context = await authority[protocol.verify](selectors, connection, phase);
    let reservationExpires;
    let finalizedLiveExpires;
    try {
      if (!validContext(protocol, context, selectors)
        || (protocol === V2 ? Object.hasOwn(context, 'proof_key') : !validKey(context.proof_key))) refuse();
      if (protocol === V2) {
        if (Object.hasOwn(context, 'runtime_id') || !Buffer.isBuffer(context.reservation_bytes)
          || !context.reservation_bytes.length || digest(context.reservation_bytes) !== selectors.reservation_digest
          || !Number.isSafeInteger(context.reservation_expires_at)
          || !matches(DIGEST, context.soul_artifact_sha256)
          || typeof context.member?.socket_path !== 'string' || !context.member.socket_path.startsWith('/')
          || authority.matchesAssignmentV2(context, selectors, connection) !== true) refuse();
        reservationExpires = context.reservation_expires_at;
        finalizedLiveExpires = context.finalized_live_expires_at;
        if (finalizedLiveExpires !== undefined && (phase !== 'receipt' || !Number.isSafeInteger(finalizedLiveExpires))) refuse();
      }
      // Keep a field snapshot across the challenge and Machine recheck.
      return Object.freeze({ ...selectors, protocol, hq_epoch: context.hq_epoch, reservationExpires, finalizedLiveExpires,
        ...(protocol === V2 ? { member_socket: context.member.socket_path,
          soul_artifact_sha256: context.soul_artifact_sha256 } : {}),
        bridge_uid: context.bridge_uid, broker_socket: context.broker_socket,
        ...(protocol === V1 ? { proof_key: Buffer.from(context.proof_key) } : {}) });
    } catch (error) {
      if (protocol === V2) await quarantine(protocol, connection, undefined, 'bridge-verified-context-invalid');
      throw error;
    }
  };
  const startKey = (context) => [context.hq_epoch, context.installation_id, context.start_id].join('\0');
  const quarantineKey = (protocol, connection, context) => protocol === V2 ? `v2:${connection}` : startKey(context);
  const usable = (context, connection) => available(context.protocol) && !closed.has(connection)
    && !quarantines.has(quarantineKey(context.protocol, connection, context))
    && (context.protocol !== V2 || authority.isCurrentPeerV2(connection) === true);
  const nowMs = () => {
    const now = clock.now();
    if (!Number.isSafeInteger(now) || now < 0 || now > 8_640_000_000_000_000 - BIND_TTL_MS) refuse();
    return now;
  };
  const observation = (context, receipt) => Object.freeze({
    ...Object.fromEntries(context.protocol.fields.map(([field]) => [field, context[field]])),
    hq_epoch: context.hq_epoch, bridge_uid: context.bridge_uid,
    broker_socket: context.broker_socket,
    ...(context.protocol === V2 ? { member_socket: context.member_socket,
      soul_artifact_sha256: context.soul_artifact_sha256 } : {}),
    ...(receipt ? { bind_receipt_sha256: digest(receipt) } : {}),
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
  const quarantine = (protocol, connection, context, reason, receipt) => {
    const key = quarantineKey(protocol, connection, context);
    if (quarantines.has(key)) return quarantines.get(key);
    const stopped = context ? observation(context, receipt) : undefined;
    let requested;
    try {
      requested = protocol === V2
        ? Promise.resolve().then(async () => {
          if (await authority.onDisconnectV2(connection, reason, stopped) !== true)
            throw new Error('Machine did not confirm the bridge containment request');
        })
        : authority.onDisconnect(stopped, reason);
    }
    catch (error) { requested = Promise.reject(error); }
    const pending = bounded(requested, 'Machine bridge containment deadline exceeded').catch(async (error) => {
      // Socket-close and timer callers may have no waiter. Freeze all bridge
      // authority immediately, and persist a visible HQ alert before the
      // cleanup failure can be swallowed by the generic broker lifecycle.
      const fields = stopped ? {
        installation_id: stopped.installation_id, start_id: stopped.start_id,
        launch_id: stopped.launch_id, hq_epoch: stopped.hq_epoch,
        ...(stopped.bind_receipt_sha256 ? { bind_receipt_sha256: stopped.bind_receipt_sha256 } : {})
      } : { bridge_connection: connection };
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
    if (bound?.timer !== undefined) timers.clearTimeout(bound.timer);
    challenges.delete(connection);
    verifying.delete(connection);
    live.delete(connection);
    const context = bound?.context ?? pending?.context;
    if (!context) return authority?.retainsChallengeStopV2?.(connection) === true
      ? quarantine(V2, connection, undefined, reason) : Promise.resolve();
    const containment = quarantine(context.protocol, connection, context, reason, bound?.receipt);
    // Comms may close while the bind reply is in flight, before it knows the
    // receipt. A wrong supplied receipt still requests containment first.
    if (receipt !== undefined && receipt !== bound?.receipt) return containment.then(refuse);
    return containment;
  }

  function expireConnection(connection, reason, delay) {
    const timer = timers.setTimeout(() => {
      // quarantine() records degradation and observes containment failures.
      void forgetBridgeConnection(connection, undefined, reason).catch(() => {});
    }, delay);
    timer?.unref?.();
    return timer;
  }

  async function bridgeBindChallenge(protocol, input, meta) {
    if (!available(protocol)) refuse();
    const selectors = selectorsOf(protocol, input);
    const connection = connectionOf(meta);
    if (closed.has(connection) || challenges.has(connection) || verifying.has(connection)
      || live.has(connection) || inFlight.has(connection)
      || (protocol === V2 && quarantines.has(quarantineKey(protocol, connection)))
      || inFlight.size >= MAX_PENDING) refuse();
    inFlight.add(connection);
    let context;
    try {
      context = await check(protocol, selectors, connection, 'challenge');
      if (!usable(context, connection)) refuse();
      const claim = startKey(context);
      if (claimedStarts.has(claim)) {
        if (protocol === V2) {
          // A trusted verifier must never retain two connections for one
          // spent start. Revoke the existing receipt and contain both claims.
          await forgetBridgeConnection(claimedStarts.get(claim), undefined, 'bridge-duplicate-verified-start');
        } else context = undefined;
        refuse();
      }
      if (claimedStarts.size >= MAX_PENDING) refuse();
      claimedStarts.set(claim, connection); // failed or abandoned challenge still spends this local start
      // Register the authenticated stop target before the first further
      // await. A close or HQ stop during expired-challenge cleanup can now
      // quarantine this start, and cannot be followed by a late challenge.
      verifying.set(connection, { selectors, context });
      const now = nowMs();
      for (const [id, entry] of challenges) if (entry.expires <= now) {
        // An expired authenticated challenge must stop its runner; do not
        // silently evict it as a reusable B start.
        await forgetBridgeConnection(id, undefined, 'bridge-challenge-expired');
      }
      if (challenges.size >= MAX_PENDING) refuse();
      const nonce = random.hex(32);
      if (!matches(SHA, nonce)) refuse();
      const expires = Math.min(now + BIND_TTL_MS, context.reservationExpires ?? Infinity);
      const delay = expires - nowMs();
      if (!usable(context, connection) || !verifying.has(connection) || delay <= 0) refuse();
      verifying.delete(connection);
      const timer = expireConnection(connection, 'bridge-challenge-expired', delay);
      challenges.set(connection, { selectors, context, nonce, expires, timer });
      return { nonce, algorithm: 'hmac-sha256', context: protocol.label,
        hq_epoch: context.hq_epoch, expires_at: new Date(expires).toISOString() };
    } catch {
      if (context) {
        if (challenges.has(connection) || verifying.has(connection) || live.has(connection))
          await forgetBridgeConnection(connection, undefined, 'bridge-challenge-failed');
        else await quarantine(protocol, connection, context, 'bridge-challenge-failed');
      } else if (protocol === V2 && authority.retainsChallengeStopV2?.(connection) === true) {
        // A cooperative authority retains its stop target before awaiting
        // A's live reply. Keep failures visible even before a challenge exists.
        await quarantine(protocol, connection, undefined, 'bridge-challenge-failed').catch(() => {});
      }
      refuse();
    } finally { inFlight.delete(connection); }
  }

  async function verifyBridgeBinding(protocol, input, meta) {
    if (!available(protocol)) refuse();
    const connection = connectionOf(meta);
    const pending = challenges.get(connection);
    if (pending?.context.protocol !== protocol) refuse();
    challenges.delete(connection); // one attempt, including a wrong proof
    verifying.set(connection, pending);
    try {
      const selectors = selectorsOf(protocol, input, true);
      if (!usable(pending.context, connection) || live.has(connection)
        || pending.expires <= nowMs() || !sameSelectors(protocol, selectors, pending.selectors)
        || inFlight.has(connection) || inFlight.size >= MAX_PENDING) refuse();
      inFlight.add(connection);
      let context;
      try { context = await check(protocol, selectors, connection, 'proof'); }
      finally { inFlight.delete(connection); }
      const now = nowMs();
      if (!usable(context, connection) || verifying.get(connection) !== pending
        || pending.expires <= now || !sameContext(protocol, context, pending.context)) refuse();
      if (protocol === V2) {
        const proof = Object.freeze({ ...selectors, hq_epoch: context.hq_epoch,
          bridge_uid: context.bridge_uid, broker_socket: context.broker_socket,
          challenge: pending.nonce, proof: input.proof });
        if (await bounded(authority.verifyProofV2(proof, connection),
          'Machine bridge proof verification deadline exceeded') !== true) refuse();
      } else {
        const expected = proofFor(protocol, context.proof_key, pending.nonce, context);
        if (!timingSafeEqual(Buffer.from(input.proof, 'hex'), Buffer.from(expected, 'hex'))) refuse();
      }
      // Machine verification crosses an await. A disconnect, expiry or HQ
      // stop during that call must never publish a late live B receipt.
      if (!usable(context, connection) || verifying.get(connection) !== pending
        || pending.expires <= nowMs()) refuse();
      const receipt = random.hex(32);
      if (!matches(SHA, receipt)) refuse();
      timers.clearTimeout(pending.timer);
      verifying.delete(connection);
      const binding = { receipt, context, observation: observation(context, receipt), expires: context.reservationExpires };
      live.set(connection, binding);
      if (protocol === V2) armReceiptDeadline(connection, binding);
      return { bind_receipt: receipt };
    } catch {
      await forgetBridgeConnection(connection, undefined, 'bridge-bind-failed');
      refuse();
    }
  }

  function armReceiptDeadline(connection, binding) {
    if (binding.timer !== undefined) timers.clearTimeout(binding.timer);
    binding.timer = timers.setTimeout(() => {
      void track(recheckBridge(connection, binding)).catch(() => {});
    }, Math.min(binding.expires - nowMs(), MAX_TIMER_MS));
    binding.timer?.unref?.();
  }

  function recheckBridge(connection, binding) {
    // A deadline and a lookup can race. Recheck the Machine lease in order.
    binding.recheck ??= checkBoundBridge(connection, binding).finally(() => { binding.recheck = undefined; });
    return binding.recheck;
  }

  async function checkBoundBridge(connection, binding) {
    const { context } = binding;
    const { protocol } = context;
    try {
      if (!usable(context, connection) || live.get(connection) !== binding) refuse();
      const selectors = Object.fromEntries(protocol.fields.map(([key]) => [key, context[key]]));
      const checking = check(protocol, selectors, connection, 'receipt');
      const current = await (protocol === V2 ? bounded(checking, 'Machine bridge verification deadline exceeded') : checking);
      if (!usable(current, connection) || live.get(connection) !== binding || !sameContext(protocol, current, context)) refuse();
      if (protocol === V2) {
        if (binding.finalized && current.finalizedLiveExpires === undefined) refuse();
        binding.finalized = current.finalizedLiveExpires !== undefined;
        binding.expires = current.finalizedLiveExpires ?? context.reservationExpires;
        if (binding.expires <= nowMs()) {
          await forgetBridgeConnection(connection, binding.receipt, 'bridge-receipt-expired');
          refuse();
        }
        armReceiptDeadline(connection, binding);
      }
      return { ...binding.observation, connected: true, hmac_verified: true };
    } catch {
      await forgetBridgeConnection(connection, binding.receipt, 'bridge-live-recheck-failed');
      refuse();
    }
  }

  async function boundBridge(protocol, input, receiptDigest) {
    if (!available(protocol) || !matches(DIGEST, receiptDigest)) refuse();
    const selectors = selectorsOf(protocol, input);
    for (const [connection, binding] of live) {
      if (binding.context.protocol === protocol && sameSelectors(protocol, binding.observation, selectors)
        && binding.observation.bind_receipt_sha256 === receiptDigest) {
        return recheckBridge(connection, binding);
      }
    }
    return null;
  }

  // Comms has already authenticated this B connection and holds its raw bind
  // receipt. Recheck A's current lease on that exact connection before any
  // future relay ingress; a digest-only lookup cannot establish this join.
  async function boundBridgeConnectionV2(connection, receipt) {
    if (!available(V2) || typeof connection !== 'string' || !connection
      || !matches(SHA, receipt)) refuse();
    const binding = live.get(connection);
    if (binding?.context.protocol !== V2 || binding.receipt !== receipt) refuse();
    const observation = await recheckBridge(connection, binding);
    if (live.get(connection) !== binding || binding.receipt !== receipt) refuse();
    return observation;
  }

  // Source-only qualification fixture. This injected host boundary must verify
  // the exact pinned provider plan and atomically consume its durable one-use
  // operation before returning the fixture result. There is no default authorizer.
  async function qualifyBridgeMessagesV2(input, { connection }, receipt) {
    const binding = live.get(connection);
    if (typeof qualificationAuthorizer !== 'function' || !available(V2)
      || binding?.context.protocol !== V2 || binding.receipt !== receipt
      || !record(input) || Object.keys(input).length !== 2
      || !Object.hasOwn(input, 'model') || !Object.hasOwn(input, 'prompt_sha256')
      || !matches(ID, input.model) || !matches(DIGEST, input.prompt_sha256)) refuse();
    if (binding.qualificationAttempted) refuse();
    binding.qualificationAttempted = true;
    const request = Object.freeze({ model: input.model, prompt_sha256: input.prompt_sha256 });
    try {
      const observation = await recheckBridge(connection, binding);
      if (!binding.finalized) refuse();
      const result = await bounded(Promise.resolve().then(() => qualificationAuthorizer({
        request, observation: Object.freeze(observation),
      })), 'Machine qualification authorization deadline exceeded');
      if (!record(result) || result.model !== request.model || result.stop_reason !== 'end_turn'
        || typeof result.text !== 'string' || !result.text || result.text.length > 4096
        || !Number.isSafeInteger(result.usage?.input_tokens) || result.usage.input_tokens < 0
        || !Number.isSafeInteger(result.usage?.output_tokens) || result.usage.output_tokens < 0) refuse();
      const response = { model: result.model, stop_reason: result.stop_reason, text: result.text,
        usage: { input_tokens: result.usage.input_tokens, output_tokens: result.usage.output_tokens } };
      await recheckBridge(connection, binding);
      return response;
    } catch {
      await forgetBridgeConnection(connection, binding.receipt, 'bridge-qualification-failed');
      refuse();
    }
  }

  // The Stage 2a installed test-provider relay has its own authorizer and
  // one-use fence. B verifies the raw vendor request before sending this
  // digest-only message; this is not a general provider-byte transport. The
  // synthetic qualification callback cannot enable or spend this route.
  async function relayBridgeIngressV2(input, { connection } = {}, receipt) {
    if (typeof relayIngressAuthorizer !== 'function' || !available(V2)
      || !record(input) || Object.keys(input).length !== 2
      || !Object.hasOwn(input, 'model') || !Object.hasOwn(input, 'prompt_sha256')
      || !matches(ID, input.model) || !matches(DIGEST, input.prompt_sha256)) refuse();
    const binding = live.get(connection);
    if (binding?.context.protocol !== V2 || binding.receipt !== receipt
      || binding.relayIngressAttempted) refuse();
    binding.relayIngressAttempted = true;
    const request = Object.freeze({ model: input.model, prompt_sha256: input.prompt_sha256 });
    try {
      const observation = await boundBridgeConnectionV2(connection, receipt);
      if (!binding.finalized) refuse();
      const result = await bounded(Promise.resolve().then(() => relayIngressAuthorizer({
        request, observation: Object.freeze(observation),
      })), 'Machine relay ingress authorization deadline exceeded');
      if (!record(result) || result.model !== request.model || result.stop_reason !== 'end_turn'
        || typeof result.text !== 'string' || !result.text || result.text.length > 4096
        || !Number.isSafeInteger(result.usage?.input_tokens) || result.usage.input_tokens < 0
        || !Number.isSafeInteger(result.usage?.output_tokens) || result.usage.output_tokens < 0) refuse();
      const response = { model: result.model, stop_reason: result.stop_reason, text: result.text,
        usage: { input_tokens: result.usage.input_tokens, output_tokens: result.usage.output_tokens } };
      await boundBridgeConnectionV2(connection, receipt);
      if (!binding.finalized) refuse();
      return response;
    } catch {
      await forgetBridgeConnection(connection, receipt, 'bridge-relay-ingress-failed');
      refuse();
    }
  }

  async function revokeAll() {
    stopping = true;
    const stops = [];
    const retained = [...inFlight].filter((connection) => authority?.retainsChallengeStopV2?.(connection) === true);
    for (const connection of new Set([...challenges.keys(), ...verifying.keys(), ...live.keys(), ...retained]))
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
    bridgeBindChallenge: (...args) => track(bridgeBindChallenge(V1, ...args)),
    verifyBridgeBinding: (...args) => track(verifyBridgeBinding(V1, ...args)),
    boundBridge: (...args) => track(boundBridge(V1, ...args)),
    bridgeBindChallengeV2: (...args) => track(bridgeBindChallenge(V2, ...args)),
    verifyBridgeBindingV2: (...args) => track(verifyBridgeBinding(V2, ...args)),
    boundBridgeV2: (...args) => track(boundBridge(V2, ...args)),
    boundBridgeConnectionV2: (...args) => track(boundBridgeConnectionV2(...args)),
    qualifyBridgeMessagesV2: (...args) => track(qualifyBridgeMessagesV2(...args)),
    bridgeRelayIngressEnabledV2: () => typeof relayIngressAuthorizer === 'function' && available(V2),
    relayBridgeIngressV2: (...args) => track(relayBridgeIngressV2(...args)),
    forgetBridgeConnection, revokeAll,
  });
}
