// hq/v1 admission (plan §9 PR 12; 0.4 §5; soul-contracts schemas/hq/v1):
// Hello, Admit, Equip, Ready and Lease, as an HQ plugin built on the SDK.
// The catalog gives admission, leases and epochs to agent-bot-daemon, so this
// plugin stays in HQ; the Soul runtime's HQ side adds validation and render
// handlers later (§4.4 step 4).
//
// What it enforces now:
// - Every record is checked against the pinned schema, inbound and outbound
//   (fail closed: HQ never sends a record its own contract refuses).
// - Versions: N and N-1 per contract, highest common wins (R7, T14).
// - Definitions: only digests the owner accepted in HQ's config admit
//   (`definition_not_accepted`), until accept-revision lands (§9 PR 21).
// - Epochs: one current installation per Soul on this HQ. A move needs the
//   current epoch; an older one is `stale_epoch` (T15).
// - Leases: a generation per admission, renewals in sequence, expiry.
// - Caller binding: the admission-socket connection that sent Hello owns its
//   runtimes; any other connection gets `caller_mismatch` (T01, in the
//   cooperative form: HQ cannot yet tell members apart, only connections).
// - Harness accounts (§9 row 16a; D7 as amended by platform PDR-0053):
//   where the owner's config gives a role's harness (its adapter_id) an OS
//   account, the runtime is bound to that account at admission. On the
//   broker socket such a runtime binds only from that account's own endpoint
//   (the file system identifies the account, the harness credential), and
//   only with a keyed proof over an HQ challenge, so the channel binding is
//   never sent. Both must hold; either failing is `caller_mismatch`, also
//   after a restart. The account is shared by every agent on that harness,
//   of every Soul: the endpoint tells HQ the account, and only the keyed
//   proof tells two agents in it apart. To the host they are one trust
//   domain.
// - Profile: the one in force, with a warning when weaker than requested (R8).
//
// It provides withLiveRuntime to the task service (hq-tasks), so a task
// commit checks the runtime and commits without an admission in between.
// For the member broker socket (plan §4.9) it provides verifyBinding, which
// the broker plugin calls on a `bind` frame, and withBoundRuntime, which a
// consumer uses for a message the broker delivered with its bound runtime.
//
// Equip carries no credentials yet: grants and credential references arrive
// with §9 PRs 18 and 21. It hands out one opaque grant handle per member.
import { createHash, createHmac, timingSafeEqual } from 'node:crypto';
import { definePlugin } from '../sdk/plugin.mjs';
import { fail, HostError } from '../sdk/errors.mjs';
import { canonicalDigest } from '../sdk/wire/canonical-json.mjs';
import { validate } from '../sdk/wire/schema.mjs';
import { negotiateVersions, supportWindow } from '../sdk/wire/versions.mjs';
import { profileWarning } from './profile.mjs';
import { createBridgeBindAdmission } from './bridge-bind.mjs';
import { resolveNoticeScope, validNoticeScope, validNoticeRepository } from './notices-config.mjs';

export const PROTECTED_GRANT_REFUSAL_RECEIPT = Symbol('committed protected grant refusal');

export const CURRENT_VERSIONS = Object.freeze({ hq: 1, wire: 1, task: 1 });
export const SCHEMA_NAMES = Object.freeze(['hello', 'admission-result', 'equip', 'ready-and-lease-renewal']);
const DEFAULT_LEASE_TTL_MS = 60_000;
const RUNTIME_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
// hq/v1 admission-result admitted_runtimes[].channel_binding.
const CHANNEL_BINDING = /^[A-Za-z0-9_-]{16,128}$/;

// A bind challenge: 32 random bytes as hex, and the proof over it.
const NONCE = /^[0-9a-f]{64}$/;
const PROOF = /^[0-9a-f]{64}$/;
export const BIND_CONTEXT = 'agent-bot-hq/bind/v1';
const CHALLENGE_TTL_MS = 60_000;
const MAX_CHALLENGES = 4096;
const PROTECTED_MACHINE_DEADLINE_MS = 5_000;
const SHA256 = /^sha256:[0-9a-f]{64}$/;
const GRANT_HANDLE = /^gh_[0-9a-f]{32}$/;
const grantHandleDigest = (handle) => 'sha256:' + createHash('sha256').update(handle, 'ascii').digest('hex');
const START_ID = /^st_[0-9a-f]{24}$/;
const LAUNCH_ID = /^ln_[0-9a-f]{24}$/;

// A protected Hello may only carry this context from HQ's trusted admission
// listener. The verifier is a Machine client pinned by HQ's entry point, not
// a caller-supplied JSON record. This shape check is supplemental to its
// signature, installed-plan, live-peer and measurement verification.
function checkedProtectedStart(binding, payload, helloDigest) {
  if (!binding || typeof binding !== 'object' || Array.isArray(binding)
    || !SHA256.test(binding.reservation_sha256 ?? '')
    || !SHA256.test(binding.definition_measurement ?? '')
    || !SHA256.test(binding.launch_input_measurement ?? '')
    || !SHA256.test(binding.broker_bind_receipt_sha256 ?? '')
    || !START_ID.test(binding.start_id ?? '') || !LAUNCH_ID.test(binding.launch_id ?? '')
    || !/^[0-9a-f]{64}$/.test(binding.hq_epoch ?? '')
    || binding.soul_id !== payload.soul_id || binding.installation_id !== payload.installation_id
    || binding.definition_digest !== payload.definition_digest
    || binding.hello_payload_sha256 !== helloDigest
    || binding.profile_in_force !== 'managed-protected') {
    fail('host.launch_unavailable', 'Machine did not authenticate the exact protected Hello and measured start');
  }
  return Object.freeze({ ...binding });
}

function boundedMachineCall(call) {
  let timer;
  return Promise.race([
    Promise.resolve().then(call),
    new Promise((_, reject) => {
      timer = setTimeout(() => reject(new Error('protected Machine call timed out')), PROTECTED_MACHINE_DEADLINE_MS);
      timer.unref?.();
    }),
  ]).finally(() => clearTimeout(timer));
}

// The proof a runtime sends in `bind`: HMAC-SHA-256, keyed with the channel
// binding it got at admission, over the context label, HQ's nonce and its
// runtime ID. A keyed proof, not a public-key signature: HQ issued the key
// and holds it too. It proves possession without sending the binding.
export function bindProof(channelBinding, nonce, runtimeId) {
  return createHmac('sha256', Buffer.from(channelBinding, 'utf8')).update(`${BIND_CONTEXT}\n${nonce}\n${runtimeId}`).digest('hex');
}

// Compare two bindings without leaking where they differ.
const sameBinding = (a, b) => {
  const x = Buffer.from(a);
  const y = Buffer.from(b);
  return x.length === y.length && timingSafeEqual(x, y);
};

const iso = (ms) => new Date(ms).toISOString();

// The runtimes of a store view with no harness account, as HQ core's profile
// reasons need them: { soul_id, member_id, adapter_id, lease_expires_at }.
const unboundOf = (tx) => tx.list('runtimes').map(([, rt]) => rt).filter((rt) => !rt.superseded
  && (rt.protected_state === undefined || rt.protected_state === 'active')
  && (rt.cooperative_state === undefined || rt.cooperative_state === 'active')
  && rt.harness_uid === undefined && rt.cooperative_runner_uid === undefined)
  .map((rt) => Object.freeze({ soul_id: rt.soul_id, member_id: rt.member_id, adapter_id: rt.adapter_id, lease_expires_at: rt.lease_expires_at }));

// profileReasons(pending, unbound) are the reasons the profile in force is
// not a stronger one: `pending` are the roles a Hello is admitting ({ soul_id,
// member_id, adapter_id }), `unbound` the other live runtimes with no harness
// account. harnessAccount(adapterId) is the OS account the owner's config
// gives that harness ({ account, uid }), or undefined. callerOf(connection) is
// the account a broker connection arrived from ({ account, uid }), or
// undefined on the shared socket. HQ core supplies all three; an agent never
// does.
export function admissionPlugin({ schemas, profileReasons = () => [], harnessAccount = () => undefined, callerOf: connectionAccount = () => undefined, allowsNoticeHarness = () => false, bridgeAuthority, qualificationAuthorizer, relayIngressAuthorizer, protectedAdmission, cooperativeAdmission } = {}) {
  for (const n of SCHEMA_NAMES) if (!schemas?.[n]) throw new TypeError(`admission needs the pinned hq/v1 ${n} schema`);
  if (protectedAdmission && (typeof protectedAdmission.acceptPeer !== 'function'
    || typeof protectedAdmission.verifyHelloStart !== 'function'
    || typeof protectedAdmission.verifyDefinitionMapping !== 'function'
    || typeof protectedAdmission.finalize !== 'function'
    || typeof protectedAdmission.verifyFinalization !== 'function'
    || typeof protectedAdmission.abort !== 'function'
    || typeof protectedAdmission.watchLiveness !== 'function'
    || typeof protectedAdmission.assertLive !== 'function'
    || typeof protectedAdmission.peerDisconnected !== 'function'
    || typeof protectedAdmission.watchHealthy !== 'function')) throw new TypeError('protected admission needs all Machine verification and containment methods');
  if (cooperativeAdmission && (typeof cooperativeAdmission.assertLive !== 'function'
    || typeof cooperativeAdmission.watchHealthy !== 'function'
    || typeof cooperativeAdmission.abort !== 'function')) throw new TypeError('cooperative admission needs Machine liveness and containment methods');

  const check = (name, value, inbound) => {
    const errors = validate(schemas[name], value);
    if (!errors.length) return;
    const first = errors.slice(0, 3).map((e) => `${e.path} ${e.message}`).join('; ');
    if (inbound) fail('host.invalid_request', `not a valid hq/v1 ${name}: ${first}`, { errors: errors.slice(0, 10) });
    throw new Error(`HQ built an invalid hq/v1 ${name} (${first}); refusing to send it`);
  };

  const normalizeScopes = new WeakMap();
  const bridgeStates = new WeakMap();
  return definePlugin({
    name: 'hq-admission',
    version: '0.1.0',
    hostApi: 1,
    services: ['store', 'receipts', 'clock', 'random', 'config', 'profile', 'log'],
    async init(ctx) {
      const { store, receipts, clock, random, config, profile } = ctx.services;
      const bridge = createBridgeBindAdmission({ authority: bridgeAuthority, qualificationAuthorizer,
        relayIngressAuthorizer, clock, random, receipts });
      bridgeStates.set(ctx, bridge);
      const atomicAudit = typeof receipts.appendIn === 'function';
      const ttl = () => config.get('leaseTtlMs') ?? DEFAULT_LEASE_TTL_MS;
      const accepted = (soul, digest) => (config.get('acceptedDefinitions')?.[soul] ?? []).includes(digest);
      const scopeOf = (assignment) => resolveNoticeScope(config.get('notices'), assignment, (harness) => {
        try { return allowsNoticeHarness(harness) === true; } catch { return false; }
      });
      // Startup migration only closes old authority; a missing snapshot is
      // never backfilled from today's configuration. Init may only read.
      normalizeScopes.set(ctx, () => store.tx((tx) => {
        for (const [rid, rt] of tx.list('runtimes')) {
          if (rt.protected_state && rt.protected_state !== 'revoked')
            tx.put('runtimes', rid, { ...rt, protected_state: 'revoked', superseded: true });
          else if (rt.cooperative_start_key && rt.cooperative_state !== 'revoked')
            tx.put('runtimes', rid, { ...rt, cooperative_state: 'revoked', superseded: true });
          else if (!Object.hasOwn(rt, 'notice_scope')) tx.put('runtimes', rid, { ...rt, notice_scope: null });
        }
        for (const [requestId, entry] of tx.list('hellos')) if (entry.protected_state && entry.protected_state !== 'revoked')
          tx.put('hellos', requestId, { ...entry, protected_state: 'revoked' });
        for (const [key, entry] of tx.list('protected_starts')) if (entry.state !== 'spent')
          tx.put('protected_starts', key, { ...entry, state: 'spent' });
        for (const [key, entry] of tx.list('cooperative_starts')) if (entry.state !== 'spent')
          tx.put('cooperative_starts', key, { ...entry, state: 'spent' });
      }));
      const id = (prefix, bytes = 12) => `${prefix}_${random.hex(bytes)}`;
      // The live runtimes with no harness account, for HQ core's status
      // (unboundRuntimes below). Refreshed after every transaction that adds
      // or renews runtimes; read without one, so status never waits on the
      // store. It informs the profile reasons only, never a decision.
      let unbound = await store.tx((tx) => unboundOf(tx));
      const lostStarts = new Set();
      const lostCooperativeStarts = new Set();
      const cooperativeStarts = new Map();
      const watchedStarts = new Map();
      const startKeyOf = (binding) => `${binding.installation_id}\0${binding.start_id}`;
      const revokeProtected = async (startKey, reason, binding) => {
        await store.tx((tx) => {
          const start = tx.get('protected_starts', startKey);
          if (start && start.state !== 'spent') tx.put('protected_starts', startKey, { ...start, state: 'spent' });
          else if (!start && binding) tx.put('protected_starts', startKey, { state: 'spent',
            start_id: binding.start_id, installation_id: binding.installation_id,
            reservation_sha256: binding.reservation_sha256 });
          for (const [requestId, entry] of tx.list('hellos')) if (entry.protected_start_key === startKey && entry.protected_state !== 'revoked')
            tx.put('hellos', requestId, { ...entry, protected_state: 'revoked' });
          for (const [rid, rt] of tx.list('runtimes')) if (rt.protected_start_key === startKey && rt.protected_state !== 'revoked')
            tx.put('runtimes', rid, { ...rt, protected_state: 'revoked', superseded: true });
          if (start || binding) receipts.appendIn(tx, { kind: 'hq.protected.revoked',
            start_id: (start ?? binding).start_id, installation_id: (start ?? binding).installation_id, reason });
        });
        unbound = await store.tx((tx) => unboundOf(tx));
      };
      const containmentUnconfirmed = async (binding) => receipts.append({
        kind: 'hq.protected.containment_unconfirmed', start_id: binding.start_id,
        installation_id: binding.installation_id, reservation_sha256: binding.reservation_sha256,
      }).catch(() => {});
      const loseProtected = (binding) => {
        const startKey = startKeyOf(binding);
        if (lostStarts.has(startKey)) return;
        lostStarts.add(startKey); // synchronous gate for every active runtime use
        void revokeProtected(startKey, 'R, B or Machine liveness watch lost', binding).catch(() => {});
        void boundedMachineCall(() => protectedAdmission.abort(binding))
          .catch(() => containmentUnconfirmed(binding));
      };
      const watchCurrent = (startKey) => {
        if (lostStarts.has(startKey)) return false;
        const binding = watchedStarts.get(startKey);
        if (!binding) return false;
        try {
          if (protectedAdmission.watchHealthy(binding) === true) return true;
        } catch { /* Treat transport errors as watcher loss. */ }
        loseProtected(binding);
        return false;
      };
      const live = async (binding) => {
        if (!watchCurrent(startKeyOf(binding)) || await boundedMachineCall(() => protectedAdmission.assertLive(binding)) !== true)
          fail('host.launch_unavailable', 'protected R or B is no longer live');
      };
      const cooperativeKeyOf = (binding) => `${binding.installation_id}\0${binding.start_id}`;
      const loseCooperative = (binding) => {
        const key = cooperativeKeyOf(binding);
        if (lostCooperativeStarts.has(key)) return;
        lostCooperativeStarts.add(key);
        void store.tx((tx) => {
          const start = tx.get('cooperative_starts', key);
          if (start) tx.put('cooperative_starts', key, { ...start, state: 'spent' });
          for (const [rid, rt] of tx.list('runtimes')) if (rt.cooperative_start_key === key)
            tx.put('runtimes', rid, { ...rt, cooperative_state: 'revoked', superseded: true });
          for (const [requestId, entry] of tx.list('hellos')) if (entry.cooperative_start_key === key)
            tx.put('hellos', requestId, { ...entry, cooperative_state: 'revoked' });
          receipts.appendIn(tx, { kind: 'hq.cooperative.revoked', installation_id: binding.installation_id,
            start_id: binding.start_id, reservation_sha256: binding.reservation_sha256 });
        }).catch(() => {});
        void boundedMachineCall(() => cooperativeAdmission?.abort(binding)).catch(() => {});
      };
      const cooperativeCurrent = (key) => {
        if (lostCooperativeStarts.has(key)) return false;
        const binding = cooperativeStarts.get(key);
        if (!binding) return false;
        try { if (cooperativeAdmission?.watchHealthy(binding) === true) return true; }
        catch { /* Treat paired Machine watch failure as lost authority. */ }
        loseCooperative(binding);
        return false;
      };
      const callerOf = (meta) => {
        if (typeof meta?.session !== 'string' || !meta.session) fail('caller_mismatch', 'no authenticated connection for this request');
        return meta.session;
      };

      // Receipt every decision, refusals included. Receipts carry no channel
      // bindings or handles.
      const receipted = (op, fn) => async (payload, meta) => {
        try {
          return await fn(payload, meta);
        } catch (e) {
          if (e instanceof HostError) {
            await receipts.append({ kind: `hq.${op.toLowerCase()}.refused`, code: e.code, caller: meta?.session, ...(payload?.request_id ? { request_id: payload.request_id } : {}), ...(payload?.runtime_id ? { runtime_id: payload.runtime_id } : {}) }).catch(() => {});
          }
          throw e;
        }
      };

      async function hello(payload, meta) {
        let caller;
        let digest;
        let protectedStart;
        let cooperativeStart;
        let startKey;
        try {
          caller = callerOf(meta);
          check('hello', payload, true);
          digest = canonicalDigest(payload);
          if (meta?.cooperativeStart !== undefined) {
            const c = meta.cooperativeStart;
            if (meta.protectedStart !== undefined || !cooperativeAdmission || !atomicAudit
              || !c || typeof c !== 'object' || Array.isArray(c)
              || !SHA256.test(c.reservation_sha256 ?? '')
              || !START_ID.test(c.start_id ?? '') || !LAUNCH_ID.test(c.launch_id ?? '')
              || !SHA256.test(c.definition_digest ?? '')
              || !SHA256.test(c.h_service_descriptor_digest ?? '')
              || !Number.isSafeInteger(c.peer_uid) || c.peer_uid < 300
              || !Number.isSafeInteger(c.peer_pid) || c.peer_pid < 2
              || typeof c.process_start !== 'string' || !c.process_start
              || typeof c.runner_account !== 'string' || !c.runner_account
              || c.profile_in_force !== 'managed-cooperative'
              || c.soul_id !== payload.soul_id
              || c.installation_id !== payload.installation_id
              || c.definition_digest !== payload.definition_digest
              || !/^[0-9a-f]{64}$/.test(c.hq_epoch ?? ''))
              fail('host.launch_unavailable', 'Machine did not authenticate the cooperative start');
            cooperativeStart = Object.freeze({ ...c });
            startKey = cooperativeKeyOf(c);
            if (await boundedMachineCall(() => cooperativeAdmission.assertLive(cooperativeStart)) !== true)
              fail('host.launch_unavailable', 'cooperative R is not live');
          }
          if (meta?.protectedStart !== undefined) {
            if (!protectedAdmission) fail('host.launch_unavailable', 'protected Hello verification is not installed');
            if (!atomicAudit) fail('host.launch_unavailable', 'protected Hello needs atomic admission receipts');
            protectedStart = checkedProtectedStart(await boundedMachineCall(() => protectedAdmission.verifyHelloStart({
              connection: meta.protectedStart, caller, payload, hello_payload_sha256: digest,
            })), payload, digest);
            startKey = startKeyOf(protectedStart);
            // The callback must synchronously mark loss; durable revocation follows.
            // Machine watches the native R process and the HQ-hosted B bind.
            const unwatch = protectedAdmission.watchLiveness(protectedStart, () => loseProtected(protectedStart));
            if (typeof unwatch !== 'function') fail('host.launch_unavailable', 'Machine liveness watch was not installed');
            watchedStarts.set(startKey, protectedStart);
            if (await boundedMachineCall(() => protectedAdmission.verifyDefinitionMapping(protectedStart, payload)) !== true)
              fail('host.launch_unavailable', 'Machine did not authenticate the accepted measured definition');
            await live(protectedStart);
          }
        const now = clock.now();
        // One transaction: the repeat check, the decision and its records, so
        // two Hellos with one request_id cannot both admit.
        const { result, repeat, audit, soulBefore, unbound: after } = await store.tx(async (tx) => {
          const earlier = tx.get('hellos', payload.request_id);
          if (earlier) {
            if (earlier.caller !== caller) fail('caller_mismatch', `request ${payload.request_id} belongs to another connection`);
            if (earlier.digest !== digest) fail('host.invalid_request', `request ${payload.request_id} was already used with different content`);
            if (protectedStart || cooperativeStart) fail('host.launch_unavailable', 'a verified start cannot reuse an earlier Hello');
            if (earlier.protected_state === 'pending' || earlier.protected_state === 'revoked')
              fail('host.launch_unavailable', 'protected Hello is not finalized');
            return { result: earlier.result, repeat: true };
          }
          if (tx.list('runtimes').some(([, rt]) => rt.soul_id === payload.soul_id && rt.protected_state === 'pending'))
            fail('host.launch_unavailable', 'another protected Hello for this Soul is pending');
          const negotiated = negotiateVersions(payload.supported_versions, supportWindow(CURRENT_VERSIONS), { required: ['hq', 'wire'] });
          if (!accepted(payload.soul_id, payload.definition_digest)) {
            fail('definition_not_accepted', `the owner has not accepted definition ${payload.definition_digest} for ${payload.soul_id}`);
          }
          if (protectedStart) {
            // startKey was fixed before the transaction.
            if (tx.get('protected_starts', startKey) || tx.list('protected_starts').some(([, spent]) =>
              spent.reservation_sha256 === protectedStart.reservation_sha256))
              fail('host.launch_unavailable', 'protected reservation was spent or another Hello is pending');
            tx.put('protected_starts', startKey, { state: 'pending', start_id: protectedStart.start_id, installation_id: protectedStart.installation_id, reservation_sha256: protectedStart.reservation_sha256,
              request_id: payload.request_id, caller, hello_payload_sha256: digest });
          }
          if (cooperativeStart) {
            if (tx.get('cooperative_starts', startKey)
              || tx.list('cooperative_starts').some(([, spent]) =>
                spent.reservation_sha256 === cooperativeStart.reservation_sha256))
              fail('host.launch_unavailable', 'cooperative reservation was spent or another Hello is pending');
            tx.put('cooperative_starts', startKey, { state: 'active',
              start_id: cooperativeStart.start_id,
              installation_id: cooperativeStart.installation_id,
              reservation_sha256: cooperativeStart.reservation_sha256,
              caller, hello_payload_sha256: digest });
          }
          const soul = tx.get('souls', payload.soul_id);
          const priorEpoch = payload.prior_installation_epoch;
          let epoch;
          if (soul && soul.installation_id === payload.installation_id) {
            if (priorEpoch !== undefined && priorEpoch !== soul.epoch) fail('stale_epoch', `installation ${payload.installation_id} is at epoch ${soul.epoch}, not ${priorEpoch}`);
            epoch = soul.epoch; // a restart of the current installation keeps its epoch
          } else if (soul) {
            if (priorEpoch === undefined) fail('stale_epoch', `${payload.soul_id} is installed here as ${soul.installation_id} (epoch ${soul.epoch}); a new installation needs a move`);
            if (priorEpoch < soul.epoch) fail('stale_epoch', `HQ's current epoch for ${payload.soul_id} is ${soul.epoch}; a copy replacing epoch ${priorEpoch} is refused`);
            epoch = priorEpoch + 1;
          } else {
            epoch = priorEpoch === undefined ? 1 : priorEpoch + 1; // first start, or arrival after a move
          }
          const leaseGeneration = (soul?.lease_generation ?? 0) + 1;
          const leaseExpires = now + ttl();
          // A new admission supersedes the Soul's earlier runtimes.
          if (!protectedStart) for (const [rid, rt] of tx.list('runtimes')) {
            if (rt.soul_id === payload.soul_id && !rt.superseded) tx.put('runtimes', rid, { ...rt, superseded: true });
          }
          const admitted = payload.requested_roles.map((r) => ({ member_id: r.member_id, role: r.role, runtime_id: id('rt', 8), channel_binding: id('cb', 16) }));
          const inForce = protectedStart ? protectedStart.profile_in_force
            : cooperativeStart ? cooperativeStart.profile_in_force : profile.current();
          const pending = payload.requested_roles.map((r) => ({ soul_id: payload.soul_id, member_id: r.member_id, adapter_id: r.adapter_id }));
          const others = unboundOf(tx).filter((rt) => now <= rt.lease_expires_at);
          const warning = profileWarning(payload.requested_profile, inForce, profileReasons(pending, others));
          const decision = {
            contract: 'hq/v1',
            request_id: payload.request_id,
            decision_id: id('dec', 8),
            installation_epoch: epoch,
            profile: inForce,
            negotiated_versions: negotiated,
            admitted_runtimes: admitted,
            lease_generation: leaseGeneration,
            lease_expires_at: iso(leaseExpires),
            ...(warning ? { warnings: [warning] } : {}),
          };
          check('admission-result', decision, false);
          if (!protectedStart) tx.put('souls', payload.soul_id, { installation_id: payload.installation_id, epoch, lease_generation: leaseGeneration, decision_id: decision.decision_id, definition_digest: payload.definition_digest, admitted_at: now });
          for (const [i, a] of admitted.entries()) {
            const adapterId = payload.requested_roles[i].adapter_id;
            const account = harnessAccount(adapterId);
            tx.put('runtimes', a.runtime_id, {
              soul_id: payload.soul_id, installation_id: payload.installation_id, member_id: a.member_id, role: a.role, adapter_id: adapterId,
              definition_digest: payload.definition_digest,
              notice_scope: scopeOf({ soul_id: payload.soul_id, definition_digest: payload.definition_digest, member_id: a.member_id, role: a.role, adapter_id: adapterId }),
              channel_binding: a.channel_binding, caller, epoch, lease_generation: leaseGeneration,
              lease_expires_at: leaseExpires, renewal_sequence: 0, ready: false, superseded: false,
              ...(protectedStart ? { protected_state: 'pending', protected_start_id: protectedStart.start_id, protected_start_key: startKey } : {}),
              ...(cooperativeStart ? { cooperative_state: 'active', cooperative_start_key: startKey,
                cooperative_runner_uid: cooperativeStart.peer_uid,
                cooperative_runner_account: cooperativeStart.runner_account,
                cooperative_reservation_sha256: cooperativeStart.reservation_sha256 } : {}),
              // The harness account this runtime belongs to, fixed at
              // admission and kept in the store, so a restart cannot loosen it.
              ...(!cooperativeStart && account ? { harness_account: account.account, harness_uid: account.uid } : {}),
            });
          }
          tx.put('hellos', payload.request_id, { caller, digest, result: decision, at: now,
            ...(protectedStart ? { protected_state: 'pending', protected_start_id: protectedStart.start_id, protected_start_key: startKey } : {}),
            ...(cooperativeStart ? { cooperative_state: 'active', cooperative_start_key: startKey } : {}) });
          const audit = { kind: protectedStart ? 'hq.admission.pending' : 'hq.admission', request_id: decision.request_id, decision_id: decision.decision_id, soul_id: payload.soul_id, installation_id: payload.installation_id, installation_epoch: decision.installation_epoch, lease_generation: decision.lease_generation, profile_in_force: decision.profile, runtimes: decision.admitted_runtimes.length, caller };
          if (atomicAudit) receipts.appendIn(tx, audit);
          return { result: decision, repeat: false, audit, soulBefore: soul ?? null, unbound: unboundOf(tx) };
        });
        if (cooperativeStart && !repeat) {
          cooperativeStarts.set(startKey, cooperativeStart);
          if (!cooperativeCurrent(startKey)
            || await boundedMachineCall(() => cooperativeAdmission.assertLive(cooperativeStart)) !== true)
            fail('host.launch_unavailable', 'cooperative R lost after Hello');
        }
        if (protectedStart && !repeat) {
          // startKey was fixed before the transaction.
          const expected = Object.freeze({
            reservation_sha256: protectedStart.reservation_sha256,
            start_id: protectedStart.start_id, launch_id: protectedStart.launch_id,
            hq_epoch: protectedStart.hq_epoch, soul_id: payload.soul_id,
            installation_id: payload.installation_id, definition_digest: payload.definition_digest,
            definition_measurement: protectedStart.definition_measurement,
            launch_input_measurement: protectedStart.launch_input_measurement,
            hello_payload_sha256: digest, admission_decision_id: result.decision_id,
            installation_epoch: result.installation_epoch, profile_in_force: result.profile,
            hq_broker_bind_receipt_sha256: protectedStart.broker_bind_receipt_sha256,
            admitted_runtimes: Object.freeze(result.admitted_runtimes.map((rt) => Object.freeze({
              member_id: rt.member_id, runtime_id: rt.runtime_id, profile_in_force: result.profile,
            })).sort((a, b) => a.member_id < b.member_id ? -1 : a.member_id > b.member_id ? 1 : 0)),
          });
          try {
            await live(protectedStart);
            const finalization = await boundedMachineCall(() => protectedAdmission.finalize(expected));
            if (await boundedMachineCall(() => protectedAdmission.verifyFinalization(finalization, expected)) !== true)
              fail('host.launch_unavailable', 'Machine did not authenticate the exact post-Hello finalization');
            await live(protectedStart);
            unbound = await store.tx((tx) => {
              if (lostStarts.has(startKey)) fail('host.launch_unavailable', 'protected R or B disconnected');
              const entry = tx.get('hellos', payload.request_id);
              const start = tx.get('protected_starts', startKey);
              if (entry?.protected_state !== 'pending' || entry.caller !== caller || entry.digest !== digest
                || start?.state !== 'pending' || start.reservation_sha256 !== protectedStart.reservation_sha256)
                fail('host.launch_unavailable', 'protected admission changed during finalization');
              if (JSON.stringify(tx.get('souls', payload.soul_id) ?? null) !== JSON.stringify(soulBefore))
                fail('host.launch_unavailable', 'Soul admission changed during Machine finalization');
              for (const [rid, rt] of tx.list('runtimes')) {
                if (rt.soul_id === payload.soul_id && rt.protected_start_id !== protectedStart.start_id && !rt.superseded)
                  tx.put('runtimes', rid, { ...rt, superseded: true });
              }
              for (const rt of result.admitted_runtimes) {
                const live = tx.get('runtimes', rt.runtime_id);
                if (live?.protected_state !== 'pending' || live.superseded
                  || live.protected_start_id !== protectedStart.start_id || live.caller !== caller)
                  fail('host.launch_unavailable', 'protected runtime changed during finalization');
                tx.put('runtimes', rt.runtime_id, { ...live, protected_state: 'active' });
              }
              tx.put('souls', payload.soul_id, { installation_id: payload.installation_id,
                epoch: result.installation_epoch, lease_generation: result.lease_generation,
                decision_id: result.decision_id, definition_digest: payload.definition_digest, admitted_at: now });
              tx.put('hellos', payload.request_id, { ...entry, protected_state: 'active' });
              tx.put('protected_starts', startKey, { ...start, state: 'active' });
              receipts.appendIn(tx, { ...audit, kind: 'hq.admission' });
              return unboundOf(tx);
            });
          } catch {
            fail('host.launch_unavailable', 'protected Hello finalization failed or is uncertain');
          }
        } else if (after) unbound = after;
        if (!atomicAudit && !repeat) await receipts.append(audit);
        if (protectedStart) await live(protectedStart);
        if (cooperativeStart && !cooperativeCurrent(startKey))
          fail('host.launch_unavailable', 'cooperative R disconnected');
        return result;
        } catch (error) {
          if (cooperativeStart) loseCooperative(cooperativeStart);
          if (meta?.protectedStart !== undefined) {
            if (startKey) {
              lostStarts.add(startKey);
              try { await revokeProtected(startKey, 'Hello refused or uncertain', protectedStart); } catch { /* abort remains mandatory */ }
            }
            // An opaque peer token lets Machine find and terminally abort a
            // start even when verification timed out before returning a binding.
            try { await boundedMachineCall(() => protectedAdmission?.abort(protectedStart ?? {
              connection: meta.protectedStart, caller, hello_payload_sha256: digest,
            })); }
            catch {
              await receipts.append({ kind: 'hq.protected.containment_unconfirmed',
                ...(protectedStart ? { start_id: protectedStart.start_id, installation_id: protectedStart.installation_id,
                  reservation_sha256: protectedStart.reservation_sha256 } : { request_id: payload.request_id }) }).catch(() => {});
            }
            await receipts.append({ kind: 'hq.protected.refused', request_id: payload.request_id,
              ...(protectedStart ? { start_id: protectedStart.start_id, installation_id: protectedStart.installation_id } : {}) }).catch(() => {});
            fail('host.launch_unavailable', 'protected Hello refused; Machine containment requested');
          }
          throw error;
        }
      }

      async function admit(payload, meta) {
        const caller = callerOf(meta);
        if (!payload || typeof payload !== 'object' || typeof payload.request_id !== 'string' || Object.keys(payload).length !== 1) {
          fail('host.invalid_request', 'Admit takes { request_id } of an earlier Hello');
        }
        const prior = await store.tx((tx) => tx.get('hellos', payload.request_id));
        if (!prior) fail('host.invalid_request', `no admission for request ${payload.request_id}`);
        if (prior.caller !== caller) fail('caller_mismatch', `request ${payload.request_id} belongs to another connection`);
        if (prior.protected_start_key && !watchCurrent(prior.protected_start_key)) fail('host.launch_unavailable', 'protected R or B disconnected');
        if (prior.protected_state && prior.protected_state !== 'active') fail('host.launch_unavailable', 'protected admission is not finalized');
        if (prior.cooperative_start_key && !cooperativeCurrent(prior.cooperative_start_key))
          fail('host.launch_unavailable', 'cooperative R disconnected');
        if (prior.cooperative_state && prior.cooperative_state !== 'active')
          fail('host.launch_unavailable', 'cooperative admission is revoked');
        return prior.result;
      }

      // A runtime that is neither superseded nor past its lease, or the reason.
      function current(rt, runtimeId, now) {
        if (rt.protected_start_key && !watchCurrent(rt.protected_start_key)) fail('host.launch_unavailable', 'protected R or B disconnected');
        if (rt.cooperative_start_key && !cooperativeCurrent(rt.cooperative_start_key))
          fail('host.launch_unavailable', 'cooperative R disconnected');
        if (rt.cooperative_state && rt.cooperative_state !== 'active')
          fail('host.launch_unavailable', `cooperative runtime ${runtimeId} is revoked`);
        if (rt.protected_state && rt.protected_state !== 'active')
          fail('host.launch_unavailable', `protected runtime ${runtimeId} is not finalized`);
        if (rt.superseded) fail('lease_expired', `runtime ${runtimeId} was superseded by a newer admission; send Hello again`);
        if (now > rt.lease_expires_at) fail('lease_expired', `runtime ${runtimeId}'s lease expired at ${iso(rt.lease_expires_at)}; send Hello again`);
        return rt;
      }

      // Look up a live runtime for its caller, or refuse with the reason.
      function liveRuntime(tx, runtimeId, caller, now) {
        const rt = tx.get('runtimes', runtimeId);
        if (!rt) fail('host.invalid_request', `unknown runtime ${runtimeId}`);
        if (rt.caller !== caller) fail('caller_mismatch', `runtime ${runtimeId} was admitted to another connection`);
        return current(rt, runtimeId, now);
      }

      async function equip(payload, meta) {
        const caller = callerOf(meta);
        if (!payload || typeof payload !== 'object' || Object.keys(payload).length !== 1 || typeof payload.runtime_id !== 'string' || !RUNTIME_ID.test(payload.runtime_id)) {
          fail('host.invalid_request', 'Equip takes { runtime_id }');
        }
        const now = clock.now();
        const { record, audit } = await store.tx((tx) => {
          const rt = liveRuntime(tx, payload.runtime_id, caller, now);
          const handle = rt.handle ?? id('gh', 16);
          if (!rt.handle) tx.put('runtimes', payload.runtime_id, { ...rt, handle });
          const result = {
            contract: 'hq/v1',
            runtime_id: payload.runtime_id,
            grant_handles: [{ member_id: rt.member_id, channel_binding: rt.channel_binding, handle }],
            credential_references: [],
            approved_destinations: [],
            budget_sub_allocations: { working: 0, maintenance: 0 },
          };
          check('equip', result, false);
          const audit = { kind: 'hq.equip', runtime_id: payload.runtime_id, credential_references: 0, caller,
            ...(rt.protected_start_id ? { start_id: rt.protected_start_id, installation_id: rt.installation_id,
              member_id: rt.member_id, grant_handle_sha256: grantHandleDigest(handle) } : {}) };
          if (atomicAudit) receipts.appendIn(tx, audit);
          return { record: result, audit };
        });
        if (!atomicAudit) await receipts.append(audit);
        return record;
      }

      const renew = (op) => async (payload, meta) => {
        const caller = callerOf(meta);
        check('ready-and-lease-renewal', payload, true);
        const now = clock.now();
        const { out, audit, unbound: after } = await store.tx((tx) => {
          const rt = liveRuntime(tx, payload.runtime_id, caller, now);
          if (payload.installation_epoch !== rt.epoch) fail('stale_epoch', `runtime ${payload.runtime_id} is at epoch ${rt.epoch}, not ${payload.installation_epoch}`);
          if (payload.lease_generation !== rt.lease_generation) fail('lease_expired', `runtime ${payload.runtime_id} holds lease generation ${rt.lease_generation}, not ${payload.lease_generation}`);
          if (payload.renewal_sequence <= rt.renewal_sequence) fail('host.invalid_request', `renewal ${payload.renewal_sequence} is not after ${rt.renewal_sequence}: replay refused`);
          if (op === 'Lease' && !rt.ready) fail('host.invalid_request', `runtime ${payload.runtime_id} has not sent Ready`);
          const leaseExpires = now + ttl();
          tx.put('runtimes', payload.runtime_id, {
            ...rt, ready: true, renewal_sequence: payload.renewal_sequence, lease_expires_at: leaseExpires,
            readiness_state: payload.readiness_state, auth_state: payload.auth_state, observed_health: payload.observed_health,
          });
          const out = { contract: 'hq/v1', runtime_id: payload.runtime_id, installation_epoch: rt.epoch, lease_generation: rt.lease_generation, lease_expires_at: iso(leaseExpires) };
          const audit = op === 'Ready' ? { kind: 'hq.ready', runtime_id: payload.runtime_id, readiness_state: payload.readiness_state, caller } : undefined;
          if (audit && atomicAudit) receipts.appendIn(tx, audit);
          return { out, audit, unbound: unboundOf(tx) };
        });
        unbound = after;
        if (audit && !atomicAudit) await receipts.append(audit);
        return out;
      };

      async function soulsList() {
        return store.tx((tx) => {
          const runtimes = tx.list('runtimes').map(([, rt]) => rt).filter((rt) => !rt.superseded
            && (rt.protected_state === undefined || rt.protected_state === 'active')
            && (rt.cooperative_state === undefined || rt.cooperative_state === 'active')
            && (!rt.cooperative_start_key || cooperativeCurrent(rt.cooperative_start_key))
            && (!rt.protected_start_key || watchCurrent(rt.protected_start_key)));
          return tx.list('souls').map(([soulId, s]) => ({
            soul_id: soulId,
            installation_id: s.installation_id,
            installation_epoch: s.epoch,
            lease_generation: s.lease_generation,
            runtimes: runtimes.filter((rt) => rt.soul_id === soulId).map((rt) => ({ member_id: rt.member_id, role: rt.role, ready: rt.ready, lease_expires_at: iso(rt.lease_expires_at) })),
          }));
        });
      }

      ctx.hq.register({ op: 'Hello', auth: 'entry-point', handler: receipted('Hello', hello) });
      ctx.hq.register({ op: 'Admit', auth: 'entry-point', handler: receipted('Admit', admit) });
      ctx.hq.register({ op: 'Equip', auth: 'entry-point', handler: receipted('Equip', equip) });
      ctx.hq.register({ op: 'Ready', auth: 'entry-point', handler: receipted('Ready', renew('Ready')) });
      ctx.hq.register({ op: 'Lease', auth: 'entry-point', handler: receipted('Lease', renew('Lease')) });
      ctx.hq.register({ op: 'souls.list', auth: 'owner', handler: soulsList });

      // For the task service (§9 PR 13): run `fn(runtime)` on a live runtime
      // of this caller, inside admission's own transaction queue, so no Hello,
      // Ready or Lease changes the runtime, its epoch or its lease while `fn`
      // decides. `fn` may open its own plugin's transaction; it must not call
      // back into admission.
      const withLiveRuntime = (runtimeId, caller, fn) => store.tx(async (tx) => fn(Object.freeze(liveRuntime(tx, runtimeId, caller, clock.now()))));
      // For the task deadline sweep: `fn(held)` inside the same queue, where
      // held(soulId, generation) says whether a live runtime of that Soul
      // still holds that lease generation.
      const withLeases = (fn) => store.tx(async (tx) => {
        const now = clock.now();
        const live = tx.list('runtimes').map(([, rt]) => rt).filter((rt) => !rt.superseded
          && (rt.protected_state === undefined || rt.protected_state === 'active')
          && (rt.cooperative_state === undefined || rt.cooperative_state === 'active')
          && (!rt.cooperative_start_key || cooperativeCurrent(rt.cooperative_start_key))
          && (!rt.protected_start_key || watchCurrent(rt.protected_start_key)) && now <= rt.lease_expires_at);
        return fn((soulId, generation) => live.some((rt) => rt.soul_id === soulId && rt.lease_generation === generation));
      });
      // Bind challenges, one per broker connection, in memory only: a restart
      // or a closed connection drops them, and the member asks again.
      const challenges = new Map(); // connection -> { runtime_id, nonce, expires }
      const connectionOf = (meta) => (typeof meta?.connection === 'string' && meta.connection ? meta.connection : undefined);
      // For the broker plugin: start a bind. Answers the same for a runtime
      // that exists and one that does not, so a probe learns nothing.
      async function bindChallenge(input, meta) {
        const connection = connectionOf(meta);
        if (!connection) fail('host.invalid_request', 'a bind challenge belongs to a broker connection');
        if (!input || typeof input !== 'object' || Object.keys(input).length !== 1 || typeof input.runtime_id !== 'string' || !RUNTIME_ID.test(input.runtime_id)) {
          fail('host.invalid_request', 'bind.challenge takes { runtime_id }');
        }
        const now = clock.now();
        for (const [c, ch] of challenges) if (ch.expires <= now) challenges.delete(c);
        challenges.delete(connection);
        while (challenges.size >= MAX_CHALLENGES) challenges.delete(challenges.keys().next().value);
        const nonce = random.hex(32);
        challenges.set(connection, { runtime_id: input.runtime_id, nonce, expires: now + CHALLENGE_TTL_MS });
        return { runtime_id: input.runtime_id, nonce, algorithm: 'hmac-sha256', context: BIND_CONTEXT, expires_at: iso(now + CHALLENGE_TTL_MS) };
      }
      const forgetConnection = (connection) => { challenges.delete(connection); };

      // For the broker plugin (§4.9): may this connection speak for this live
      // runtime? Two forms of proof:
      //   { runtime_id, proof }            the keyed proof over this
      //                                    connection's challenge (row 16a)
      //   { runtime_id, channel_binding }  the binding itself; accepted only
      //                                    for a runtime with no harness account
      // A runtime bound to a harness account also needs the connection to come
      // from that account's endpoint, and takes the proof form only. In a
      // shared account the endpoint proves the account; the proof alone tells
      // which of its agents is calling. Every
      // mismatch (unknown runtime, wrong key, wrong account, wrong form) gets
      // the same answer. Receipted without the binding or the proof.
      async function verifyBinding(input, meta) {
        const { runtime_id: runtimeId } = input ?? {};
        const connection = connectionOf(meta);
        const caller = connection ? connectionAccount(connection) : undefined;
        try {
          const keys = input && typeof input === 'object' ? Object.keys(input) : [];
          const byProof = keys.length === 2 && typeof input.proof === 'string' && PROOF.test(input.proof);
          const byBinding = keys.length === 2 && typeof input.channel_binding === 'string' && CHANNEL_BINDING.test(input.channel_binding);
          if (typeof runtimeId !== 'string' || !RUNTIME_ID.test(runtimeId) || byProof === byBinding) {
            fail('host.invalid_request', 'bind takes { runtime_id, proof } after bind.challenge, or { runtime_id, channel_binding }');
          }
          // A challenge is spent by the first bind that follows it, right or wrong.
          const challenge = byProof && connection ? challenges.get(connection) : undefined;
          if (byProof && connection) challenges.delete(connection);
          const now = clock.now();
          const mismatch = () => fail('caller_mismatch', `the caller does not match runtime ${runtimeId}`);
          const bound = await store.tx((tx) => {
            const rt = tx.get('runtimes', runtimeId);
            // An unknown runtime is compared against a stand-in of the same
            // length, so it costs what a wrong key costs.
            const key = rt?.channel_binding ?? 'x'.repeat(24);
            let matches;
            if (byProof) {
              const live = challenge && challenge.runtime_id === runtimeId && NONCE.test(challenge.nonce) && challenge.expires > now;
              matches = sameBinding(bindProof(key, live ? challenge.nonce : '0'.repeat(64), runtimeId), input.proof) && Boolean(live);
            } else {
              matches = sameBinding(rt?.channel_binding ?? 'x'.repeat(input.channel_binding.length), input.channel_binding);
            }
            if (!rt || !matches) mismatch();
            if (rt.cooperative_runner_uid !== undefined) {
              if (!caller || caller.kind !== 'cooperative'
                || caller.uid !== rt.cooperative_runner_uid
                || caller.account !== rt.cooperative_runner_account
                || caller.start_id !== rt.cooperative_start_key?.split('\0')[1]
                || caller.reservation_sha256 !== rt.cooperative_reservation_sha256
                || !byProof) mismatch();
            } else if (rt.harness_uid !== undefined) {
              // An account-bound runtime: the right account, and the proof form.
              if (!caller || caller.uid !== rt.harness_uid || !byProof) mismatch();
            } else if (caller) {
              // A harness account's endpoint speaks only for that account's runtimes.
              mismatch();
            }
            current(rt, runtimeId, now);
            return Object.freeze({ runtime_id: runtimeId, soul_id: rt.soul_id, member_id: rt.member_id, role: rt.role, installation_epoch: rt.epoch, lease_generation: rt.lease_generation, ...(rt.harness_account ? { harness_account: rt.harness_account } : {}) });
          });
          await receipts.append({ kind: 'hq.bind', runtime_id: runtimeId, soul_id: bound.soul_id, member_id: bound.member_id, proof: byProof ? 'hmac-sha256' : 'channel-binding', ...(caller ? { caller_account: caller.account } : {}) });
          return bound;
        } catch (e) {
          if (e instanceof HostError) await receipts.append({ kind: 'hq.bind.refused', code: e.code, ...(typeof runtimeId === 'string' && RUNTIME_ID.test(runtimeId) ? { runtime_id: runtimeId } : {}), ...(caller ? { caller_account: caller.account } : {}) }).catch(() => {});
          throw e;
        }
      }
      // For a consumer of a brokered message: `fn(runtime)` on the live
      // runtime the broker bound, in admission's queue, as withLiveRuntime.
      // The binding was checked at bind; liveness is checked here, every time.
      const withBoundRuntime = (runtimeId, fn) => store.tx(async (tx) => {
        const rt = tx.get('runtimes', runtimeId);
        if (!rt) fail('host.invalid_request', `unknown runtime ${runtimeId}`);
        return fn(Object.freeze(current(rt, runtimeId, clock.now())));
      });
      // A trusted protected-operation consumer supplies the authenticated
      // runtime ID and digest of its validated request. No caller-supplied
      // runtime selector is accepted here. The operation still applies its
      // own authorization before using protected resources.
      async function withProtectedGrant(boundRuntimeId, handle, requestSHA256, effect) {
        if (!atomicAudit) fail('host.launch_unavailable', 'protected grant checks need atomic receipts');
        if (typeof boundRuntimeId !== 'string' || !RUNTIME_ID.test(boundRuntimeId)
          || typeof requestSHA256 !== 'string' || requestSHA256.length !== 71 || !SHA256.test(requestSHA256)
          || typeof handle !== 'string' || handle.length !== 35 || !GRANT_HANDLE.test(handle)
          || typeof effect !== 'function') fail('host.invalid_request', 'invalid protected grant use');

        const result = await store.tx(async (tx) => {
          const rt = tx.get('runtimes', boundRuntimeId);
          try {
            if (rt && !rt.protected_start_key) fail('profile_insufficient', 'grant use requires a protected runtime');
            if (!rt?.handle || !sameBinding(rt.handle, handle))
              fail('caller_mismatch', 'grant handle does not belong to this runtime');
            current(rt, boundRuntimeId, clock.now());
            await live(watchedStarts.get(rt.protected_start_key));
            current(rt, boundRuntimeId, clock.now());
          } catch (error) {
            if (!(error instanceof HostError)) throw error;
            const committed = receipts.appendIn(tx, { kind: 'hq.protected.grant.refused',
              code: error.code, runtime_id: boundRuntimeId, request_sha256: requestSHA256,
              grant_handle_sha256: grantHandleDigest(handle), effect_invoked: false,
              ...(rt?.protected_start_id ? { start_id: rt.protected_start_id, installation_id: rt.installation_id,
                member_id: rt.member_id, installation_epoch: rt.epoch, lease_generation: rt.lease_generation } : {}) });
            return { error, committed };
          }
          return { value: await effect(Object.freeze({ runtime_id: boundRuntimeId,
            member_id: rt.member_id, soul_id: rt.soul_id, installation_id: rt.installation_id,
            start_id: rt.protected_start_id, installation_epoch: rt.epoch,
            lease_generation: rt.lease_generation })) };
        });
        if (result.error) {
          const receipt = typeof result.committed === 'function' ? result.committed() : undefined;
          if (receipt) Object.defineProperty(result.error, PROTECTED_GRANT_REFUSAL_RECEIPT,
            { value: Object.freeze(receipt) });
          throw result.error;
        }
        return result.value;
      }
      // Trusted broker consumers pass the bound runtime id, never a payload
      // runtime selector. Keep liveness, assignment and mailbox effect in the
      // same admission queue used by Hello/Lease and task commits.
      const withNoticeScope = (boundRuntimeId, context, effect) => withBoundRuntime(boundRuntimeId, (rt) => {
        if (!context || typeof context !== 'object' || Array.isArray(context)
          || Object.keys(context).some((key) => !['installation_epoch', 'lease_generation', 'expected_repository'].includes(key))
          || !Number.isSafeInteger(context.installation_epoch) || context.installation_epoch < 1
          || !Number.isSafeInteger(context.lease_generation) || context.lease_generation < 1
          || (Object.hasOwn(context, 'expected_repository') && !validNoticeRepository(context.expected_repository))
          || typeof effect !== 'function') fail('host.invalid_request', 'notice scope needs epoch/generation assertions and a trusted effect');
        if (context.installation_epoch !== rt.epoch) fail('stale_epoch', 'notice request epoch does not match the bound admission');
        if (context.lease_generation !== rt.lease_generation) fail('lease_expired', 'notice request generation does not match the bound admission');
        const frozen = rt.notice_scope;
        const configured = scopeOf(rt);
        if (!validNoticeScope(frozen) || Object.keys(frozen).length !== 2
          || !accepted(rt.soul_id, rt.definition_digest) || !configured
          || configured.harness !== frozen.harness || configured.repo.toLowerCase() !== frozen.repo.toLowerCase()) fail('caller_mismatch', 'no current owner-authorized notice scope; send Hello again');
        if (Object.hasOwn(context, 'expected_repository') && context.expected_repository.toLowerCase() !== frozen.repo.toLowerCase()) fail('caller_mismatch', 'expected repository differs from the frozen notice scope');
        return effect(Object.freeze({ harness: frozen.harness, repo: frozen.repo }));
      });
      // For HQ core's profile reasons (§9 row 16b): the live runtimes with no
      // harness account, as { soul_id, member_id, adapter_id }. HQ core reads
      // them only through this, never this plugin's tables.
      const unboundRuntimes = () => {
        const now = clock.now();
        return unbound.filter((rt) => now <= rt.lease_expires_at).map(({ soul_id: soulId, member_id: memberId, adapter_id: adapterId }) => ({ soul_id: soulId, member_id: memberId, adapter_id: adapterId }));
      };
      return { provides: { withLiveRuntime, withLeases, verifyBinding, bindChallenge, forgetConnection,
        bridgeBindChallenge: bridge.bridgeBindChallenge,
        verifyBridgeBinding: bridge.verifyBridgeBinding,
        bridgeBindChallengeV2: bridge.bridgeBindChallengeV2,
        verifyBridgeBindingV2: bridge.verifyBridgeBindingV2,
        boundBridgeV2: bridge.boundBridgeV2,
        boundBridgeConnectionV2: bridge.boundBridgeConnectionV2,
        // The packaged broker opts in to the route, but a live HQ must also
        // have the installed Machine-backed one-use provider injected here.
        bridgeQualificationEnabledV2: () => typeof qualificationAuthorizer === 'function',
        qualifyBridgeMessagesV2: bridge.qualifyBridgeMessagesV2,
        bridgeRelayIngressEnabledV2: bridge.bridgeRelayIngressEnabledV2,
        relayBridgeIngressV2: bridge.relayBridgeIngressV2,
        forgetBridgeConnection: bridge.forgetBridgeConnection,
        boundBridge: bridge.boundBridge,
        bridgeStatus: bridge.bridgeStatus,
        revokeBridges: bridge.revokeAll,
        withBoundRuntime, withProtectedGrant, withNoticeScope, unboundRuntimes } };
    },
    async start(ctx) { await normalizeScopes.get(ctx)(); },
    async stop(ctx) { await bridgeStates.get(ctx)?.revokeAll(); },
  });
}
