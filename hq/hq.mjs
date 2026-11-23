// The HQ skeleton (plan §9 PR 12): HQ core on the SDK's plugin host, with a
// durable store, the control socket and owner sessions, the admission socket,
// profile reporting, and hq/v1 Hello, Admit, Equip, Ready and Lease. It runs
// beside the existing per-account daemon and leaves it unchanged (strangler,
// RISK-008 in the platform's register); hq/legacy.mjs is the bridge.
//
// Bootstrap follows §4.4 through the SDK host: HQ core reads device status
// first (here from the legacy enrollment, through the HQ signer), an
// unenrolled device or an unavailable signer is safe mode, a revoked one is
// device_revoked, and plugins start only after that. The sockets open in every mode, so the owner
// can always ask for status.
//
// Layout of the state directory (0700; HQ's account):
//   config.json     owner-written settings, read-only to HQ (optional)
//   store.json      the authoritative store (hq/store.mjs), 0600
//   signer/         the HQ signer's pin, and its key file under the software
//                   backend only (hq/signer.mjs), 0700
//   control.sock    hq/v1 for the owner, 0600
//   admission.sock  hq/v1 for Soul entry points, 0600
//   broker.sock     member broker frames, served by one plugin (§4.9), 0600
// A harness account's own endpoint is outside this directory
// (hq/harness-accounts.mjs), and so is its agents' working state, in the
// account's 0700 home. With harness accounts on Linux, HQ starts agents in
// them (hq/launch.mjs, §9 row 16b) and nothing in this directory is open to
// them.
//
// Interim account (D4's stated risk, plan §10.3 HQ-RISK-07): until
// agent-bot-machine provisions _agent-bot-hq (D6, its S6 slice), HQ runs in
// the owner's `user` account, so any process there, agents that run there
// included, can read the store and connect to every socket. An agent HQ
// starts in its harness account (row 16b) is not in `user`. HQ reports
// managed-cooperative and says why. The identity-service link holds short-lived
// access tokens in memory; credential-reference resolution is still row 18.
import { randomBytes } from 'node:crypto';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { userInfo } from 'node:os';
import { join } from 'node:path';
import { createHost } from '../sdk/host.mjs';
import { fail } from '../sdk/errors.mjs';
import { createCore, dropTokens, pushReceipt, revokeDevice } from '../sdk/services.mjs';
import { admissionPlugin } from './admission.mjs';
import { tasksPlugin } from './tasks.mjs';
import { noticesPlugin } from './notices.mjs';
import { legacyDaemon } from './legacy.mjs';
import { detectProfile } from './profile.mjs';
import { createIdentityService } from './identity-service.mjs';
import { createMachineSigner } from './machine-device.mjs';
import { createStandaloneSigner } from './standalone-signer.mjs';
import { createEnrollment, DEFAULT_IDENTITY_SERVICE, validateEnrollmentConfig } from './enrollment.mjs';
import { createLauncher, LAUNCH_OPERATIONS } from './launch.mjs';
import { createSoulStarter } from './soul-start.mjs';
import { bindBridgeAuthority, listenBridgeEndpoint, memberBrokerDispatch, planBridgeEndpoints } from './bridge-endpoints.mjs';
import { loadPlugins } from './plugins.mjs';
import { authenticatePeerUid, checkOwnerControlSupport, OWNER_CONTROL_PATH, OWNER_PEER_CHECK } from './owner-control.mjs';
import { checkSocketPath, listenSocket } from './socket.mjs';
import { listenStage2aRunnerAdmission, listenStage2aCooperativeAdmission,
  listenStage2aCooperativeBroker } from './stage2a-r-admission.mjs';
import { checkHarnessSocket, planHarnessEndpoints, validateHarnessesConfig } from './harness-accounts.mjs';
import { coreTable, CORE_PLUGIN, ensurePrivateDir, openStore } from './store.mjs';
import { validateNoticesConfig, noticeIngestionConfig } from './notices-config.mjs';

export const HQ_VERSION = '0.1.0';
const CONFIG_KEYS = new Set(['standalone', 'leaseTtlMs', 'acceptedDefinitions', 'concurrentWriters', 'legacy', 'signer', 'features', 'enrollment', 'harnesses', 'notices']);
const FEATURE_KEYS = new Set(['hardwareSigner']);
const LEGACY_KEYS = new Set(['supervise', 'probeIntervalMs']);
const DEFAULT_PROBE_MS = 30_000;

export const cryptoRandom = () => ({ bytes: (n) => randomBytes(n), hex: (n = 16) => randomBytes(n).toString('hex') });

// Legacy enrollment cannot use HQ's own signer for the identity-service link.
// HQ resolves credential references in PR 18. Until then every
// credential waits with credential_unavailable, as an outage would (R9).
export function unlinkedIdentity() {
  const refuse = () => fail('credential_unavailable', 'HQ has no identity-service link for this credential operation');
  return { link: 'not-linked', keySet: [], check: refuse, call: async () => refuse(), mint: async () => refuse(), onRevoke() {} };
}

export function readConfig(home, { uid = process.getuid?.() } = {}) {
  const path = join(home, 'config.json');
  if (!existsSync(path)) return {};
  const st = statSync(path);
  if (uid !== undefined && st.uid !== uid) throw new Error(`${path} is owned by uid ${st.uid}, not HQ's uid ${uid}`);
  if (st.mode & 0o022) throw new Error(`${path} is writable by group or others; HQ refuses it`);
  return validateConfig(JSON.parse(readFileSync(path, 'utf8')));
}

export function validateConfig(c) {
  if (!c || typeof c !== 'object' || Array.isArray(c)) throw new Error('HQ config is a JSON object');
  // `members` (row 16a, keyed by Soul and member) was replaced before any
  // release by `harnesses`, keyed by adapter (platform PDR-0053).
  if (Object.hasOwn(c, 'members')) throw new Error('HQ config: unknown key members; accounts are now configured per harness, as harnesses: { dir?, accounts: { <adapter_id>: <account> } } (platform PDR-0053)');
  for (const k of Object.keys(c)) if (!CONFIG_KEYS.has(k)) throw new Error(`HQ config: unknown key ${k}`);
  if (c.standalone !== undefined && typeof c.standalone !== 'boolean') throw new Error('HQ config: standalone is a boolean');
  if (c.leaseTtlMs !== undefined && !(Number.isSafeInteger(c.leaseTtlMs) && c.leaseTtlMs >= 1000)) throw new Error('HQ config: leaseTtlMs is an integer of at least 1000');
  if (c.acceptedDefinitions !== undefined) {
    const a = c.acceptedDefinitions;
    if (!a || typeof a !== 'object' || Array.isArray(a)) throw new Error('HQ config: acceptedDefinitions maps Soul IDs to digest lists');
    for (const [soul, list] of Object.entries(a)) {
      if (!/^agent_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(soul)) throw new Error(`HQ config: ${soul} is not a Soul ID`);
      if (!Array.isArray(list) || list.some((d) => typeof d !== 'string' || !/^sha256:[0-9a-f]{64}$/.test(d))) throw new Error(`HQ config: ${soul} needs a list of sha256: digests`);
    }
  }
  if (c.concurrentWriters !== undefined && (!Array.isArray(c.concurrentWriters)
    || !c.concurrentWriters.every((w) => typeof w === 'string' && w.length > 0 && w.length <= 256))) {
    throw new Error('HQ config: concurrentWriters is a list of workspaces');
  }
  // Preserve the reporting flag from older configurations. It grants no signing authority.
  if (c.features !== undefined) {
    if (!c.features || typeof c.features !== 'object' || Array.isArray(c.features)) throw new Error('HQ config: features is an object');
    for (const [k, v] of Object.entries(c.features)) {
      if (!FEATURE_KEYS.has(k)) throw new Error(`HQ config: unknown key features.${k}`);
      if (typeof v !== 'boolean') throw new Error(`HQ config: features.${k} is a boolean`);
    }
  }
  if (c.enrollment !== undefined) validateEnrollmentConfig(c.enrollment);
  if (c.notices !== undefined) validateNoticesConfig(c.notices);
  if (c.harnesses !== undefined) validateHarnessesConfig(c.harnesses);
  if (c.signer !== undefined) {
    const standaloneEnclave = c.standalone === true && c.signer?.backend === 'secure-enclave';
    if (Object.keys(c.signer ?? {}).length !== 1 || (!standaloneEnclave && c.signer?.backend !== 'machine')) {
      throw new Error('HQ device key custody requires the paired Machine backend');
    }
  }
  if (c.legacy !== undefined) {
    if (!c.legacy || typeof c.legacy !== 'object' || Array.isArray(c.legacy)) throw new Error('HQ config: legacy is an object');
    for (const k of Object.keys(c.legacy)) if (!LEGACY_KEYS.has(k)) throw new Error(`HQ config: unknown key legacy.${k}`);
    if (c.legacy.supervise !== undefined && typeof c.legacy.supervise !== 'boolean') throw new Error('HQ config: legacy.supervise is a boolean');
    if (c.legacy.probeIntervalMs !== undefined && !(Number.isSafeInteger(c.legacy.probeIntervalMs) && c.legacy.probeIntervalMs >= 1000)) throw new Error('HQ config: legacy.probeIntervalMs is an integer of at least 1000');
  }
  return c;
}

// A healthy A watch cannot keep a runtime admitted after its local C/H sockets
// disappear. This guard belongs to H and cannot be reset by R or a wire field.
export function cooperativeLivenessGuard(machine) {
  if (!machine || typeof machine.assertLive !== 'function'
    || typeof machine.watchHealthy !== 'function' || typeof machine.abort !== 'function')
    throw new TypeError('cooperative liveness needs paired Machine methods');
  const revoked = new Set();
  const live = (binding) => typeof binding?.reservation_sha256 === 'string'
    && !revoked.has(binding.reservation_sha256);
  return Object.freeze({
    revoke: (digest) => { if (typeof digest === 'string') revoked.add(digest); },
    isRevoked: (digest) => revoked.has(digest),
    client: Object.freeze({
      assertLive: async (binding) => live(binding)
        && await machine.assertLive(binding) === true && live(binding),
      watchHealthy: (binding) => live(binding) && machine.watchHealthy(binding) === true,
      abort: (binding) => machine.abort(binding),
      ...(machine.projectLaunch ? { projectLaunch: async (binding) => {
        if (!live(binding)) fail('host.launch_unavailable', 'cooperative launch was revoked');
        const proof = await machine.projectLaunch(binding);
        if (!live(binding)) fail('host.launch_unavailable', 'cooperative launch was revoked');
        return proof;
      } } : {}),
      ...(machine.provide ? { provide: async ({ context, request }) => {
        if (!live(context)) fail('host.launch_unavailable', 'cooperative provider was revoked');
        const reply = await machine.provide({ context, request });
        if (!live(context)) fail('host.launch_unavailable', 'cooperative provider was revoked');
        return reply;
      } } : {}),
    }),
  });
}

export function createHQ({
  home,
  schemas,                       // pinned schemas by name: hq/v1 (admission.mjs SCHEMA_NAMES), task/v1 and wire/v1 (tasks.mjs TASK_SCHEMA_NAMES, TASK_WIRE_SCHEMA_NAMES)
  config,                        // defaults to <home>/config.json
  signer,                        // explicit signer for isolated component tests
  createDeviceSigner = createMachineSigner,
  createStandaloneDeviceSigner = createStandaloneSigner,
  enrollment,                    // where device status and enrollment come from: the config's source by
                                 // default (legacy bridge, or hq/enrollment.mjs); may be a function of the signer
  serverKeys,                    // immutable issuer key set injected by an isolated server fixture
  identity,                      // identity-service transport; tests inject a canned signed service
  legacy,                        // defaults to legacyDaemon with the config's supervise flag
  clock = { now: () => Date.now() },
  random = cryptoRandom(),
  platform = process.platform,
  account = userInfo().username,
  ownerControl,                    // verified system manager listener from activatedOwnerControl
  uid = process.getuid?.(),
  accounts,                      // how a harness account name resolves to { uid, gid, groupMembers, home }
                                 // (hq/harness-accounts.mjs resolveAccount by default)
  harnessLstat,                  // how harness account paths are inspected (lstatSync by default; tests
                                 // stand in another owner for an account's home)
  launch = {},                   // the agent launcher's spawn, timers and graceMs (hq/launch.mjs defaults)
  soulLaunch,                    // Machine-authorized launcher under a distinct per-installation UID; never owner config
  soulVerifier,                  // independent Machine reservation signature verifier pinned by trusted HQ entry point
  soulCompletionVerifier,        // independent Machine containment signature verifier
  machineHqEpoch,                // signed current paired epoch from Machine list; never owner config
  protectedStart,                // HQ-started Machine-authorized R/B lifecycle from trusted entry point
  bridgeAuthority,               // authenticated Machine live-start/B proof client; never config or owner input
  bridgeAssignments = [],       // verified installed assignments from that same trusted entry point
  qualificationAuthorizer,       // trusted one-use installed test-provider operation; never owner config
  relayIngressAuthorizer,        // trusted one-use B test-provider; absent until A finalization is wired
  memberArmProvider,             // trusted paired A observation/arm provider; absent in production
  relayPeerAuthority,            // trusted v3 bound B + paired A live CLI verifier; absent in production
  protectedAdmission,            // future pinned Machine verifier; absent in production until signed contracts ship
  createCooperativeStart,        // owner lifecycle for a paired cooperative launch
  cooperativeAdmission,          // paired A reservation/attach/watch client; never owner config
  plugins = [],                  // plugin objects (tests); installed ones come from pluginsDir
  pluginsDir,                    // installed plugins, each checked against `pins` (§4.5)
  pins = { plugins: [] },        // governance/plugins.json
  devPlugins,                    // --dev-plugins: loaded without pins, always reported
  initTimeoutMs,
  stopDeadlineMs,
} = {}) {
  if (!home) throw new TypeError('createHQ needs a state directory (home)');
  for (const p of plugins) if (p?.name === CORE_PLUGIN) throw new Error(`no plugin may be named ${CORE_PLUGIN}: HQ core's tables use that name`);

  let core;
  let host;
  let store;
  let sockets = [];
  let timer;
  let profileInfo;
  let legacyRunner = legacy;
  let running = false;
  let firstTick = Promise.resolve();
  let pluginLoad = [];
  // Harness accounts (§9 row 16a): the endpoints HQ opens, one per account,
  // and which account each live broker connection arrived from. A
  // connection on the shared broker socket has no entry.
  let harnessPlan = { endpoints: [], accountOf: () => undefined };
  const brokerCallers = new Map();
  const bridgePeers = new Map();
  const bridgeListeners = new Map();
  const runnerAdmissions = new Map();
  const openingRunnerAdmissions = new Set();
  const cooperativeListeners = new Map();
  const openingCooperativeListeners = new Set();
  const cooperativeGuard = cooperativeAdmission ? cooperativeLivenessGuard(cooperativeAdmission) : undefined;
  // Agent launch (§9 row 16b) and what the profile reasons say about it.
  let launcher;
  let soulStarter;
  let profileReasons = () => [];

  const paths = { home, control: join(home, 'control.sock'), admission: join(home, 'admission.sock'), broker: join(home, 'broker.sock') };

  function openSession(sessionAccount = account, ownerUid) {
    const id = `os_${random.hex(12)}`;
    coreTable(core, 'sessions').set(id, { opened_at: clock.now(), account: sessionAccount, ...(ownerUid === undefined ? {} : { uid: ownerUid }), auth: 'owner' });
    store.persist().catch((e) => core.logs.push({ level: 'error', plugin: 'hq', at: clock.now(), message: `owner session ${id} not persisted: ${e.message}` }));
    return id;
  }
  function closeSession(id) {
    const rows = coreTable(core, 'sessions');
    const s = rows.get(id);
    if (!s || s.closed_at) return;
    rows.set(id, { ...s, closed_at: clock.now() });
    store.persist().catch(() => {});
  }
  const openOwnerSessions = () => [...coreTable(core, 'sessions').values()].filter((s) => !s.closed_at).length;

  // One legacy pass: probe (and maybe start) the old daemon, and pick up a
  // device revocation the legacy enrollment now reports (§4.7).
  async function legacyTick() {
    try { await legacyRunner.tick(); } catch (e) { core.logs.push({ level: 'warn', plugin: 'hq', at: clock.now(), message: `legacy probe failed: ${e.message}` }); }
    if (host.mode === 'running') {
      try {
        if ((await signer.deviceStatus()) === 'revoked') revokeDevice(core, 'the enrollment reports the device revoked');
      } catch { /* an unreadable signer at runtime changes nothing; status shows the last probe */ }
    }
  }

  // The task deadline sweep (hq/tasks.mjs), on the same interval as the
  // legacy probe. A failed sweep is logged and retried on the next pass.
  async function sweepTasks() {
    const tasks = host.mode === 'running' ? host.provided('hq-tasks') : undefined;
    if (!tasks) return [];
    try { return await tasks.expire(); } catch (e) {
      core.logs.push({ level: 'warn', plugin: 'hq', at: clock.now(), message: `task sweep failed: ${e.message}` });
      return [];
    }
  }

  async function start() {
    if (running) throw new Error('HQ is already running');
    ensurePrivateDir(home, { uid });
    const cfg = validateConfig(config ?? readConfig(home, { uid }));
    // Enrollment events become receipts (an enrollment only starts once HQ is up).
    const onEnrollmentEvent = (e) => { if (core) pushReceipt(core, { plugin: 'hq', ...e }).catch(() => {}); };
    enrollment ??= (s) => createEnrollment({ home, signer: s, server: cfg.enrollment?.server, uid, clock, onEvent: onEnrollmentEvent });
    const factory = cfg.signer?.backend === 'secure-enclave' ? createStandaloneDeviceSigner : createDeviceSigner;
    signer ??= factory({ home, enrollment, clock });
    let restartRequired = false;
    const signerReport = () => {
      const report = typeof signer.report === 'function' ? signer.report() : undefined;
      return restartRequired && report?.available ? { ...report, restart_required: true } : report;
    };
    const hostProfile = (harnessAccounts) => {
      const report = signerReport();
      return detectProfile({
        platform, account, standalone: cfg.standalone === true, harnessAccounts,
        // This host-wide profile is shared by external admission requests.
        // The owner Soul-start path has no per-Soul authenticated admission
        // proof yet; agent launch is not Soul start.
        startedByHQ: false,
        keyStorage: report?.available ? report.key_storage : undefined, keyFiles: report?.key_files,
      });
    };
    profileInfo = hostProfile();
    legacyRunner ??= legacyDaemon({ supervise: cfg.legacy?.supervise === true, clock });

    harnessPlan = cfg.harnesses
      ? planHarnessEndpoints(cfg.harnesses, { hqUid: uid, hqAccount: account, platform, ...(accounts ? { resolve: accounts } : {}), ...(harnessLstat ? { lstat: harnessLstat } : {}) })
      : { endpoints: [], accountOf: () => undefined };
    const bridgeEndpoints = planBridgeEndpoints(bridgeAssignments, { platform, account, hqUid: uid,
      harnessUids: harnessPlan.endpoints.map((endpoint) => endpoint.uid) });
    if (bridgeEndpoints.length && (typeof bridgeAuthority?.verifyLiveStartV2 !== 'function'
      || typeof bridgeAuthority?.onDisconnectV2 !== 'function')) throw new Error('Machine bridge endpoints need live start and containment authority');
    if (platform === 'darwin' && (harnessPlan.endpoints.length || bridgeEndpoints.length)) checkOwnerControlSupport();
    if (platform !== 'win32') for (const p of [paths.control, paths.admission, paths.broker, ...harnessPlan.endpoints.map((e) => e.path)]) checkSocketPath(p, platform);
    store = openStore(home, { uid });
    core = createCore({
      clock, random, signer,
      profile: profileInfo.profile,
      identity: identity ?? (signer.custody || cfg.enrollment?.source === 'hq'
        ? createIdentityService({ server: cfg.enrollment?.server ?? DEFAULT_IDENTITY_SERVICE, enrollment: signer.enrollment, custody: signer.custody, keySet: serverKeys, clock })
        : unlinkedIdentity()),
      persist: () => store.persist(),
      persistReceipt: (entry) => store.persistReceipt(entry),
      persistPluginWrite: (change) => store.persistPluginWrite(change),
      atomicReceiptWrites: true,
      config: {
        'hq-admission': { acceptedDefinitions: cfg.acceptedDefinitions ?? {}, notices: cfg.notices ?? null, ...(cfg.leaseTtlMs ? { leaseTtlMs: cfg.leaseTtlMs } : {}) },
        'hq-tasks': { concurrentWriters: cfg.concurrentWriters ?? [] },
        'agent-comms': { notices: noticeIngestionConfig(cfg.notices) },
      },
    });
    // Revocation can also arrive from the signer/legacy probe, rather than
    // an identity reply. Drop the transport's access token and pending work
    // on either path, alongside the SDK's resolved-credential cache.
    core.onDeviceRevoked.push(() => core.identity.close?.());
    store.load(core);
    launcher = createLauncher({
      ...launch,
      core, harnesses: harnessPlan, configured: Boolean(cfg.harnesses), platform,
      mode: () => host?.mode ?? 'starting',
      withLiveRuntime: (runtimeId, caller, fn) => {
        const admission = host.provided('hq-admission');
        if (!admission) fail('host.plugin_degraded', 'hq-admission is not running');
        return admission.withLiveRuntime(runtimeId, caller, fn);
      },
    });
    soulStarter = createSoulStarter({ core, home, machineLaunch: soulLaunch,
      verifyMachineReservation: soulVerifier, verifyMachineCompletion: soulCompletionVerifier,
      protectedStart, cooperativeStart: createCooperativeStart?.(core, store.readCommittedReceipts),
      mode: () => host?.mode ?? 'starting', hqUid: uid,
      harnessUids: harnessPlan.endpoints.map((endpoint) => endpoint.uid), machineHqEpoch });
    // Whether the provisioner's rule lets HQ start each harness account;
    // bounded, and a missing rule leaves HQ serving row 16a.
    await launcher.probe();
    // The profile in force is fixed at start; its reasons follow what is
    // admitted. They name an admitted agent whose harness has no account, or
    // an account HQ cannot launch in. `pending` are the roles a Hello is
    // admitting and `unbound` the other live runtimes without an account,
    // both from hq-admission; with no `unbound`, HQ asks hq-admission for its
    // own (status). This states gaps only: it adds no claim of protection.
    const harnessAccounts = (pending = [], unbound) => {
      if (!cfg.harnesses) return false;
      const unready = launcher.accounts().filter((a) => !a.available);
      // The list is bounded and the tag appended after it, so "(D7)", which
      // profileWarning looks for, always survives.
      const bound = (text) => (text.length > 360 ? `${text.slice(0, 357)}...` : text);
      if (unready.length) {
        const accounts = unready.map((a) => `${a.account} (${a.reason})`).join('; ');
        return `${bound(`one or more configured adapters cannot launch in ${accounts}`)} (D7)`;
      }
      const others = unbound ?? host?.provided('hq-admission')?.unboundRuntimes() ?? [];
      const without = [...new Set([...pending.filter((p) => !harnessPlan.accountOf(p.adapter_id)), ...others]
        .map((p) => `${p.soul_id}/${p.member_id} (adapter ${p.adapter_id ?? 'unknown'})`))];
      if (without.length) return `${bound(`agents whose harness has no account of its own: ${without.slice(0, 5).join(', ')}${without.length > 5 ? ` and ${without.length - 5} more` : ''}`)} (D7)`;
      return true;
    };
    profileReasons = (pending, unbound) => hostProfile(harnessAccounts(pending, unbound)).reasons;
    // Sessions left open by a crash are closed now; they cannot be live.
    for (const [id, s] of coreTable(core, 'sessions')) if (!s.closed_at) coreTable(core, 'sessions').set(id, { ...s, closed_at: clock.now(), closed_by: 'restart' });

    // Installed plugins: digests checked against the pins before any plugin
    // code runs. A refused plugin never reaches the host; status and a
    // receipt say why.
    const admission = admissionPlugin({
      schemas,
      allowsNoticeHarness: (harness) => signer.allowsHarness ? signer.allowsHarness(harness) : signer.enrollment?.allowsHarness?.(harness) === true,
      profileReasons: (pending, unbound) => profileReasons(pending, unbound),
      harnessAccount: (adapterId) => harnessPlan.accountOf(adapterId),
      callerOf: (connection) => brokerCallers.get(connection),
      bridgeAuthority: bridgeEndpoints.length
        ? bindBridgeAuthority(bridgeAuthority, bridgePeers, { hqEpoch: soulStarter.hqEpoch })
        : { verifyLiveStart: bridgeAuthority?.verifyLiveStart?.bind(bridgeAuthority),
          onDisconnect: bridgeAuthority?.onDisconnect?.bind(bridgeAuthority) },
      qualificationAuthorizer,
      relayIngressAuthorizer,
      relayPeerAuthority,
      memberArmProvider,
      protectedAdmission,
      cooperativeAdmission: cooperativeGuard?.client,
    });
    const builtIn = [admission, tasksPlugin({ schemas }), noticesPlugin({ schemas }), ...plugins];
    pluginLoad = [];
    const accepted = [];
    const taken = new Set([CORE_PLUGIN, ...builtIn.map((p) => p.name)]);
    const available = Object.fromEntries(builtIn.map((p) => [p.name, p.version]));
    for (const [dir, dev] of [[pluginsDir, false], [devPlugins, true]]) {
      if (!dir) continue;
      const out = await loadPlugins({ dir, pins, dev, available });
      pluginLoad.push(...out.report);
      for (const { plugin, entry } of out.loaded) {
        if (taken.has(plugin.name)) { Object.assign(entry, { state: 'refused', reason: `the name ${plugin.name} is taken` }); continue; }
        taken.add(plugin.name);
        available[plugin.name] = plugin.version;
        accepted.push(plugin);
      }
    }
    for (const r of pluginLoad.filter((x) => x.state === 'refused')) await pushReceipt(core, { plugin: 'hq', kind: 'hq.plugin.refused', name: r.name, reason: r.reason });

    host = createHost({
      plugins: [...builtIn, ...accepted],
      core,
      ...(initTimeoutMs ? { initTimeoutMs } : {}),
      ...(stopDeadlineMs ? { stopDeadlineMs } : {}),
      extraStatus: () => ({
        hq: {
          version: HQ_VERSION,
          account,
          profileReasons: profileReasons(),
          sockets: {
            control: paths.control, admission: paths.admission, broker: paths.broker,
            access: 'file mode 0600 in a 0700 directory (no peer-credential check yet)',
            ...(ownerControl ? { ownerControl: { path: OWNER_CONTROL_PATH, account: ownerControl.account, uid: ownerControl.uid, peer_check: OWNER_PEER_CHECK } } : {}),
            ...(harnessPlan.endpoints.length ? { harnesses: harnessPlan.endpoints.map((e) => ({ account: e.account, adapters: e.adapters, path: e.path })), harnessAccess: 'one endpoint per harness account, mode 0660 in a 2750 directory of the account\'s private group; it identifies the account, not one agent in it' } : {}),
          },
          launch: launcher.report(),
          soulStarts: soulStarter.report(),
          bridgeBinding: host.provided('hq-admission')?.bridgeStatus?.() ?? { state: 'unavailable' },
          ownerSessions: openOwnerSessions(),
          pluginLoad,
          ...(signerReport() ? { signer: signerReport() } : {}),
          features: { hardwareSigner: cfg.features?.hardwareSigner === true },
          ...(signer.enrollmentProgress?.() ? { enrollment: signer.enrollmentProgress() } : {}),
          ...(core.identity.status ? { identityService: core.identity.status() } : {}),
          ...(devPlugins ? { devPlugins } : {}),
        },
        legacy: legacyRunner.report(),
      }),
    });
    const startup = await host.start();
    const disconnectedPair = startup.mode === 'safe' ? signer.disconnectedPair?.() : undefined;
    let checkingPair;
    async function ownerDispatch(op, meta) {
      // A cold connection refusal must leave HQ in safe mode. A requested
      // status can verify the original pairing and guide the explicit restart.
      if (op === 'status' && disconnectedPair && host.mode === 'safe') {
        checkingPair ??= signer.recheckPair(disconnectedPair).then(
          state => { restartRequired = state === 'enrolled'; },
          () => { restartRequired = false; },
        ).finally(() => { checkingPair = undefined; });
        await checkingPair;
      }
      return ['soul.start', 'soul.starts', 'soul.stop', 'soul.qualify-direct'].includes(op) ? soulStarter.dispatch(op, meta) : host.dispatch(op, meta);
    }

    try {
      sockets = [
        await listenSocket({ path: paths.control, auth: 'owner', dispatch: ownerDispatch, core, takeover: true, newSession: openSession, endSession: closeSession }),
        // Agent launch is HQ core's own framing on this socket (hq/launch.mjs);
        // launch.attach takes its connection over, so only this listener allows it.
        await listenSocket({
          path: paths.admission, auth: 'entry-point', core, takeover: true,
          dispatch: (op, meta) => (LAUNCH_OPERATIONS.includes(op) ? launcher.dispatch(op, meta)
            : ['soul.start', 'soul.starts', 'soul.stop'].includes(op) ? soulStarter.dispatch(op, meta) : host.dispatch(op, meta)),
          newSession: () => `ep_${random.hex(12)}`, endSession: () => {},
        }),
        // Each frame goes to the plugin serving the broker; `op` is the kind.
        await listenSocket({
          path: paths.broker, auth: 'member', core,
          dispatch: (kind, { payload, session }) => memberBrokerDispatch(host, kind, payload, session),
          newSession: () => `bc_${random.hex(12)}`,
          endSession: (connection) => { host.brokerClosed(connection); },
        }),
      ];
      if (ownerControl) {
        sockets.push(await listenSocket({
          path: OWNER_CONTROL_PATH, activated: ownerControl, auth: 'owner', core, dispatch: ownerDispatch, takeover: true,
          newSession: () => openSession(ownerControl.account, ownerControl.uid), endSession: closeSession,
        }));
      }
      // One endpoint per harness account. The account is recorded before the
      // connection's first frame and dropped when it closes.
      for (const endpoint of harnessPlan.endpoints) {
        sockets.push(await listenSocket({
          path: endpoint.path, auth: 'member', core, mode: 0o660,
          authenticatePeer: platform === 'darwin' ? (socket) => authenticatePeerUid(socket, endpoint.uid) : undefined,
          dispatch: (kind, { payload, session }) => memberBrokerDispatch(host, kind, payload, session),
          newSession: () => {
            const connection = `bc_${random.hex(12)}`;
            brokerCallers.set(connection, Object.freeze({ account: endpoint.account, uid: endpoint.uid }));
            return connection;
          },
          endSession: (connection) => { brokerCallers.delete(connection); host.brokerClosed(connection); },
        }));
        checkHarnessSocket(endpoint, { darwinHqUid: platform === 'darwin' ? uid : undefined });
      }
      for (const endpoint of bridgeEndpoints) {
        const listener = await listenBridgeEndpoint(endpoint, { hqUid: uid, host, core, peers: bridgePeers,
          enableBridgeQualification: typeof qualificationAuthorizer === 'function',
          enableBridgeRelayIngress: typeof relayIngressAuthorizer === 'function',
          enableMemberArmExchange: host.provided('hq-admission')?.stage2aMemberArmExchangeEnabledV3?.() === true,
          enableRelayPeerChallenge: typeof bridgeAuthority?.verifyLiveStartV3 === 'function'
            && typeof relayPeerAuthority?.boundStart === 'function'
            && typeof relayPeerAuthority?.attest === 'function' });
        bridgeListeners.set(endpoint.installationId, listener);
        sockets.push(listener);
      }
    } catch (e) {
      for (const s of sockets) await s.close();
      sockets = [];
      bridgeListeners.clear();
      await host.stop({ reason: 'socket failed' }).catch(() => {});
      throw e;
    }
    running = true;
    await pushReceipt(core, { plugin: 'hq', kind: 'hq.started', mode: host.mode, version: HQ_VERSION });
    // The first legacy pass runs in the background: the legacy CLI can be
    // slow, and HQ answers status before it finishes (legacy state "unknown").
    firstTick = legacyTick();
    const every = cfg.legacy?.probeIntervalMs ?? DEFAULT_PROBE_MS;
    timer = setInterval(() => { legacyTick(); sweepTasks(); }, every);
    timer.unref?.();
    return host.status();
  }

  async function stop({ reason = 'shutdown' } = {}) {
    if (!running) return [];
    running = false;
    clearInterval(timer);
    // revokeBridges sets its fail-closed fence before its first await. Start
    // it before any legacy probe, runner or socket shutdown can pause here.
    const bridgeStop = Promise.resolve(host.provided('hq-admission')?.revokeBridges?.());
    bridgeStop.catch(() => {}); // observed below after the other shutdown paths
    // Close the transport before awaiting the legacy probe, launch shutdown
    // or plugin callbacks. A retained context and late reply cannot extend
    // credentials while one of those callbacks is blocked.
    core.identity.close?.();
    dropTokens(core);
    const soulStop = soulStarter.stopAll();
    soulStop.catch(() => {}); // checked after the legacy probe
    await firstTick;
    // Agents first, while their connections are still open: each launch's
    // process group is stopped (hq/launch.mjs).
    await soulStop;
    await launcher.stopAll();
    const admissionsToClose = [...runnerAdmissions.values()];
    runnerAdmissions.clear();
    await Promise.all(admissionsToClose.map((listener) => listener.close()));
    const cooperativeToClose = [...cooperativeListeners.values()];
    cooperativeListeners.clear();
    await Promise.all(cooperativeToClose.map((listener) => listener.close()));
    for (const s of sockets) await s.close();
    sockets = [];
    bridgeListeners.clear();
    const report = await host.stop({ reason });
    await bridgeStop; // uncertain B containment cannot produce hq.stopped
    for (const [id, s] of coreTable(core, 'sessions')) if (!s.closed_at) coreTable(core, 'sessions').set(id, { ...s, closed_at: clock.now() });
    await pushReceipt(core, { plugin: 'hq', kind: 'hq.stopped', reason });
    return report;
  }

  return {
    start,
    stop,
    paths,
    status: () => host.status(),
    openProtectedAdmission: async ({ installed, assignment, selectors, renewLive, renewMemberRuntime,
      onLost, memberAttachProvider }) => {
      const key = selectors?.reservation_sha256;
      if (!running || !key || runnerAdmissions.has(key) || openingRunnerAdmissions.has(key))
        fail('host.launch_unavailable', 'protected R admission is unavailable');
      openingRunnerAdmissions.add(key);
      try {
        const listener = await listenStage2aRunnerAdmission({ installed, assignment, selectors,
          hqUid: uid, core, renewLive, renewMemberRuntime, onLost, protectedAdmission, memberAttachProvider,
          withLiveRuntime: host.provided('hq-admission')?.withLiveRuntime,
          admissionDispatch: (op, meta) => host.dispatch(op, meta) });
        if (!running) { await listener.close(); fail('host.launch_unavailable', 'HQ stopped during protected R admission'); }
        runnerAdmissions.set(key, listener);
        return Object.freeze({ path: listener.path, close: async () => {
          if (runnerAdmissions.get(key) !== listener) return;
          runnerAdmissions.delete(key);
          await listener.close();
        } });
      } finally { openingRunnerAdmissions.delete(key); }
    },
    readCommittedMemberFinalization: (key, digest, options) =>
      store.readCommittedMemberFinalization(key, digest, options),
    memberArmsV3: (selectors, bindReceiptSHA256) => {
      if (!running) fail('host.launch_unavailable', 'protected B arm evidence is unavailable');
      const retrieve = host.provided('hq-admission')?.stage2aMemberArmsV3;
      if (typeof retrieve !== 'function') fail('host.launch_unavailable', 'protected B arm evidence is unavailable');
      return retrieve(selectors, bindReceiptSHA256);
    },
    openCooperativeAdmission: async ({ reservation, openAcpStream, onLost }) => {
      const key = reservation?.sha256;
      if (!running || !key || cooperativeGuard?.isRevoked(key)
        || cooperativeListeners.has(key) || openingCooperativeListeners.has(key)
        || typeof cooperativeAdmission?.verifyReservation !== 'function'
        || typeof cooperativeAdmission?.attach !== 'function'
        || typeof cooperativeAdmission?.verifyAttachReceipt !== 'function'
        || typeof cooperativeAdmission?.watchHealthy !== 'function'
        || typeof onLost !== 'function')
        fail('host.launch_unavailable', 'cooperative H admission is unavailable');
      openingCooperativeListeners.add(key);
      let admission;
      let broker;
      let notified = false;
      const lost = () => {
        cooperativeGuard.revoke(key);
        if (notified) return;
        notified = true;
        return onLost();
      };
      try {
        admission = await listenStage2aCooperativeAdmission({ reservation,
          verifyReservation: (value) => cooperativeAdmission.verifyReservation(value),
          hqUid: uid, core, machineAttach: (value) => cooperativeAdmission.attach(value),
          verifyAttachReceipt: (receipt, expected) => cooperativeAdmission.verifyAttachReceipt(receipt, expected),
          isLive: (value) => cooperativeGuard.client.watchHealthy(value), openAcpStream, onLost: lost,
          admissionDispatch: (op, meta) => {
            if (op !== 'launch' && op !== 'launch.stop') return host.dispatch(op, meta);
            const service = host.provided('hq-admission');
            if (!service?.cooperativeMemberLaunch)
              fail('host.launch_unavailable', 'cooperative member launch is unavailable');
            return service.cooperativeMemberLaunch(op, meta);
          } });
        if (admission.brokerPin.reservation_sha256 !== key)
          fail('host.launch_unavailable', 'cooperative reservation digest changed after verification');
        broker = await listenStage2aCooperativeBroker({ admission, hqUid: uid, core,
          callers: brokerCallers, onLost: lost,
          brokerDispatch: (kind, payload, session) => memberBrokerDispatch(host, kind, payload, session),
          brokerClosed: (session) => host.brokerClosed(session) });
        if (!running) fail('host.launch_unavailable', 'HQ stopped during cooperative admission');
        let closing;
        const close = () => {
          if (!closing) {
            cooperativeGuard.revoke(key);
            if (cooperativeListeners.get(key)?.close === close) cooperativeListeners.delete(key);
            closing = Promise.all([broker.close(), admission.close()]).then(() => {});
          }
          return closing;
        };
        const listener = Object.freeze({ path: admission.path, brokerPath: broker.path, close });
        cooperativeListeners.set(key, listener);
        return listener;
      } catch (error) {
        await broker?.close().catch(() => {});
        await admission?.close().catch(() => {});
        throw error;
      } finally { openingCooperativeListeners.delete(key); }
    },
    qualifyDirectProtectedClaim: (startId) => {
      if (!running) fail('host.launch_unavailable', 'HQ direct qualification is unavailable');
      return soulStarter.qualifyDirectProtectedClaim(startId);
    },
    bridgeBrokerIdentity: (installationId) => {
      if (!running || typeof installationId !== 'string') fail('host.launch_unavailable', 'HQ bridge broker is unavailable');
      const listener = bridgeListeners.get(installationId);
      if (!listener) fail('host.launch_unavailable', 'Soul installation has no Machine-assigned B broker');
      return listener.brokerIdentity();
    },
    boundBridgeV2: (selectors, receiptDigest) => {
      if (!running) fail('host.launch_unavailable', 'HQ bridge admission is unavailable');
      const admission = host.provided('hq-admission');
      if (!admission) fail('host.launch_unavailable', 'HQ bridge admission is unavailable');
      return admission.boundBridgeV2(selectors, receiptDigest);
    },
    legacyTick,
    sweepTasks,
    // Resolves when the first legacy pass after start has finished.
    settled: () => firstTick,
    get host() { return host; },
    get core() { return core; },
  };
}
