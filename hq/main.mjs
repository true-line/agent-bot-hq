#!/usr/bin/env node
// The HQ skeleton's command line (plan §9 PR 12).
//
//   node hq/main.mjs run    [--home DIR] [--plugins DIR] [--dev-plugins DIR]
//                                                 run HQ in the foreground
//   node hq/main.mjs status [--home DIR] [--json] ask a running HQ for status
//   node hq/main.mjs souls  [--home DIR] [--json] list admitted Souls
//   node hq/main.mjs enroll --harness NAME [--harness NAME]... [--force] [--name DEVICE] [--home DIR]
//                                                 enroll this HQ with the identity service
//                                                 (needs enrollment.source "hq" in config)
//   node hq/main.mjs signer rekey [--home DIR]    replace the HQ signer's key
//                                                 (HQ must be stopped)
//
// `signer rekey` makes a fresh key on the backend HQ's config names and a new
// key generation, so every signature from the old key stops verifying. It is
// how custody moves from the transition key file to a hardware helper; the
// key file is removed once the hardware key is pinned.
//
// --plugins loads installed plugins, each pinned by name, version and digest
// in governance/plugins.json; --dev-plugins loads a directory without pins
// and status always reports it (§4.5).
//
// DIR defaults to $AGENT_BOT_HQ_HOME, else ~/.agent-bot-hq. It is separate
// from the existing daemon's ~/.agent-bot, which HQ leaves unchanged.
//
// `run` loads the hq/v1, task/v1 and wire/v1 schemas it uses from the pinned soul-contracts release
// (scripts/soul-contracts.mjs verifies the digest; a development checkout
// fetches it into .cache/ on first use). A release will vendor the pinned
// tree with the plugins (§4.5) instead.
import { existsSync, readFileSync, realpathSync, statSync } from 'node:fs';
import { userInfo } from 'node:os';
import { connect as netConnect } from 'node:net';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verify } from '../scripts/soul-contracts.mjs';
import { HOST_CODES, REGISTRY_CODES } from '../sdk/errors.mjs';
import { SCHEMA_NAMES } from './admission.mjs';
import { NOTICE_SCHEMA_NAMES, PROTECTED_NOTICE_PEEK_SCHEMA } from './notices.mjs';
import { TASK_SCHEMA_NAMES, TASK_WIRE_SCHEMA_NAMES } from './tasks.mjs';
import { createHQ } from './hq.mjs';
import { productionPluginsDir, readPins } from './plugins.mjs';
import { activatedOwnerControl, checkOwnerControlSupport, checkOwnerSocketPath, OWNER_CONTROL_PATH } from './owner-control.mjs';
import { connectSocket } from './socket.mjs';
import { machineRoleCommand, machineRoleStage2aCooperative, machineRoleStage2aList } from './machine-channel.mjs';
import { relaySoulAcp } from './soul-acp-relay.mjs';
import { validate } from '../sdk/wire/schema.mjs';
import { verifyStage2aProtectedCandidateReservationV3 } from './stage2a-reservation.mjs';
import { createStage2aMachineBridgeAuthority } from './stage2a-machine-bridge-authority.mjs';
import { createStage2aProtectedStarter } from './stage2a-protected-start.mjs';
import { createStage2aProtectedAdmission } from './stage2a-protected-admission.mjs';
import { authenticatedSelectedH } from './stage2a-h-preloader.mjs';
import { createStage2aCooperativeMachine } from './stage2a-cooperative-machine.mjs';
import { createStage2aCooperativeStarter } from './stage2a-cooperative-start.mjs';
import { createStage2aQualificationProvider } from './stage2a-qualification-provider.mjs';

const USAGE = 'usage: node hq/main.mjs <run|status|souls|soul start --soul DIR [--profile managed-protected]|soul stop --start-id ID|soul starts|enroll|machine identity|machine status|machine members-plans|machine hq-service-recovery|machine hq-service-upgrade|machine harness-account-provision|machine soul-runner-provision|machine harness-launch-install|machine harness-launch-retire|machine harness-qualification-run|machine soul-protected-launch-install|check-owner-control> [--home DIR] [--plugins DIR] [--dev-plugins DIR] [--owner-account NAME | --owner-control] [--json]';
const PINS = join(dirname(fileURLToPath(import.meta.url)), '../governance/plugins.json');

function parse(argv) {
  const args = { cmd: argv[0], home: process.env.AGENT_BOT_HQ_HOME || join(homedir(), '.agent-bot-hq'), json: false };
  if (args.cmd === 'signer' || args.cmd === 'soul') args.sub = argv[1];
  for (let i = args.sub ? 2 : 1; i < argv.length; i++) {
    if (argv[i] === '--home') {
      args.home = argv[++i];
      args.explicitHome = true;
    }
    else if (argv[i] === '--owner-account') {
      args.ownerAccount = argv[++i];
      if (!args.ownerAccount || args.cmd !== 'run') throw new Error('--owner-account NAME is only for the systemd HQ service');
    } else if (argv[i] === '--owner-control') {
      if (!['status', 'souls', 'soul', 'enroll'].includes(args.cmd)) throw new Error('--owner-control is only for owner socket clients');
      args.ownerControl = true;
    } else if (argv[i] === '--soul') {
      args.soul = argv[++i];
      if (!args.soul || args.cmd !== 'soul' || args.sub !== 'start') throw new Error('--soul DIR is only for soul start');
    } else if (argv[i] === '--start-id') {
      args.startId = argv[++i];
      if (!/^st_[0-9a-f]{24}$/.test(args.startId ?? '') || args.cmd !== 'soul' || args.sub !== 'stop') {
        throw new Error('--start-id needs a valid start ID and is only for soul stop');
      }
    } else if (argv[i] === '--profile') {
      args.profile = argv[++i];
      if (args.cmd !== 'soul' || args.sub !== 'start' || args.profile !== 'managed-protected') {
        throw new Error('--profile supports managed-protected only');
      }
    } else if (argv[i] === '--json') args.json = true;
    else if (argv[i] === '--harness') (args.harnesses ??= []).push(argv[++i]);
    else if (argv[i] === '--force') args.force = true;
    else if (argv[i] === '--name') args.name = argv[++i];
    else if (argv[i] === '--plugins' || argv[i] === '--dev-plugins') {
      const flag = argv[i];
      const dir = argv[++i];
      if (!dir || dir.startsWith('--')) throw new Error(`${flag} needs a directory`);
      args[flag === '--plugins' ? 'plugins' : 'devPlugins'] = dir;
    }
    else throw new Error(`unknown argument ${argv[i]}\n${USAGE}`);
  }
  if (!args.home) throw new Error(`--home needs a directory\n${USAGE}`);
  return args;
}

function loadSchemas() {
  const { dir } = verify();
  const load = (contract, names) => names.map((n) => [n, JSON.parse(readFileSync(join(dir, 'schemas', contract, `${n}.schema.json`), 'utf8'))]);
  const noticeSchemas = [...NOTICE_SCHEMA_NAMES];
  if (existsSync(join(dir, 'schemas', 'hq/v1', `${PROTECTED_NOTICE_PEEK_SCHEMA}.schema.json`))) {
    noticeSchemas.push(PROTECTED_NOTICE_PEEK_SCHEMA);
  }
  return Object.fromEntries([...load('hq/v1', [...SCHEMA_NAMES, ...noticeSchemas]), ...load('task/v1', TASK_SCHEMA_NAMES), ...load('wire/v1', TASK_WIRE_SCHEMA_NAMES)]);
}

function loadStage2aSchemas() {
  const { dir } = verify();
  const paths = ['machine/v2/snapshot-identity', 'machine/v2/measurement-binding',
    'machine/v3/inventory-ref', 'machine/v3/measurement-binding', 'machine/v3/stage2a-reservation-payload',
    'machine/v3/stage2a-qualification-candidate-binding', 'machine/v3/stage2a-qualification-candidate-reservation-payload'];
  const schemas = paths.map((path) => JSON.parse(readFileSync(join(dir, 'schemas', `${path}.schema.json`), 'utf8')));
  return (payload) => validate(schemas.at(-1), payload, { schemas: schemas.slice(0, -1) }).length === 0;
}

async function ask(controlPath, op, payload) {
  const client = await connectSocket(controlPath);
  try { return await client.request(op, payload); } finally { await client.close(); }
}

async function startSoul(controlPath, path, profile) {
  if (!path) throw new Error('soul start needs --soul DIR');
  const packagePath = realpathSync(path);
  if (!statSync(packagePath).isDirectory()) throw new Error('soul start needs a package directory');
  const socket = netConnect(controlPath);
  await new Promise((resolve, reject) => { socket.once('connect', resolve); socket.once('error', reject); });
  try {
    socket.write(`${JSON.stringify({ id: 1, op: 'soul.start', payload: { package_path: packagePath,
      ...(profile ? { requested_profile: profile } : {}) } })}\n`);
    let buf = Buffer.alloc(0);
    const response = await new Promise((resolve, reject) => {
      const onData = (chunk) => {
        buf = Buffer.concat([buf, chunk]);
        const nl = buf.indexOf(0x0a);
        if (nl < 0) { if (buf.length > 1 << 20) reject(new Error('HQ start reply is too large')); return; }
        socket.off('data', onData);
        socket.off('close', onClose);
        try { resolve({ answer: JSON.parse(buf.subarray(0, nl).toString('utf8')), rest: buf.subarray(nl + 1) }); }
        catch (error) { reject(error); }
      };
      const onClose = () => reject(new Error('HQ closed the Soul start connection'));
      socket.on('data', onData);
      socket.once('close', onClose);
    });
    if (!response.answer.ok) throw new Error(JSON.stringify(response.answer.refusal ?? response.answer.host_refusal ?? response.answer));
    process.stderr.write(response.answer.result.profile === 'managed-protected'
      ? `HQ started protected Soul runner ${response.answer.result.start_id} (pid ${response.answer.result.pid})\n`
      : `HQ started Soul runner ${response.answer.result.start_id} (pid ${response.answer.result.pid}); protected qualification remains unavailable\n`);
    if (response.rest.length) process.stdout.write(response.rest);
    await relaySoulAcp(process.stdin, process.stdout, socket);
  } finally { socket.destroy(); }
}

function signerLine(g) {
  const backend = g.backend === 'machine' ? 'paired Machine/keyd' : g.backend;
  if (!g.available) return `signer: ${backend} unavailable (${g.reason})`;
  return `signer: ${g.key_storage} key, ${backend} backend, key ${g.thumbprint.slice(0, 12)}, generation ${g.generation}`;
}

function printStatus(s) {
  const grant = s.hq?.enrollment?.grant;
  const restartForCustody = s.hq?.signer?.restart_required === true;
  const enrollment = {
    pending: 'awaiting owner approval',
    approved: 'approved; restart HQ to activate',
    failed: 'failed',
  }[grant?.state];
  const enrollmentInProgress = grant?.state === 'pending' || grant?.state === 'approved';
  const enrollHint = 'device not enrolled: run enroll';
  const reasonSuffix = (reason) => {
    if (!reason) return '';
    if (restartForCustody && (reason === s.reason || reason === `safe mode: ${s.reason}`)) return '';
    if (enrollmentInProgress && (reason === enrollHint || reason === `safe mode: ${enrollHint}`)) {
      return ` (${reason.slice(0, -': run enroll'.length)})`;
    }
    return ` (${reason})`;
  };
  const lines = [
    `HQ ${s.hq?.version ?? '?'}: ${s.mode}${reasonSuffix(s.reason)}; admissions ${s.admissions ? 'open' : 'closed'}`,
    `profile: ${s.profile}`,
    ...(s.hq?.profileReasons ?? []).map((r) => `  - ${r}`),
    `device: ${s.identity?.device}; identity-service link: ${s.identity?.link}`,
    ...(enrollment ? [`enrollment: ${enrollment}`] : []),
    ...(s.hq?.signer ? [signerLine(s.hq.signer)] : []),
    ...(restartForCustody ? ['Machine custody recovered; restart HQ to reopen admissions.'] : []),
    `legacy daemon: ${s.legacy?.state}${s.legacy?.version ? ` ${s.legacy.version}` : ''}${s.legacy?.supervise ? ' (supervised)' : ''}`,
    ...s.plugins.map((p) => `plugin ${p.name} ${p.version}: ${p.state}${reasonSuffix(p.reason)}`),
    ...(s.hq?.pluginLoad ?? []).filter((p) => p.state === 'refused').map((p) => `plugin ${p.name}: refused (${p.reason})`),
    ...(s.hq?.devPlugins ? [`dev plugins (unpinned): ${s.hq.devPlugins}`] : []),
  ];
  console.log(lines.join('\n'));
}

async function main(argv) {
  if (argv[0] === 'machine') {
    const result = await machineRoleCommand(argv.slice(1));
    console.log(typeof result === 'string' ? result : JSON.stringify(result));
    return;
  }
  const args = parse(argv);
  if (args.cmd === 'check-owner-control') {
    const capability = checkOwnerControlSupport();
    const report = { capability };
    if (process.platform === 'darwin') report.launch_diagnostics = 'darwin-hq-launch-exits/v2';
    console.log(JSON.stringify(report));
    return;
  }
  const useOwnerControl = args.ownerControl || (args.cmd === 'soul' && !args.explicitHome
    && !process.env.AGENT_BOT_HQ_HOME && existsSync(OWNER_CONTROL_PATH));
  const controlPath = useOwnerControl ? OWNER_CONTROL_PATH : join(args.home, 'control.sock');
  if (useOwnerControl) checkOwnerSocketPath(process.getuid?.());
  if (args.cmd === 'run') {
    if ([process.env.LISTEN_PID, process.env.HQ_LAUNCHD_OWNER_PID].includes(String(process.pid)) && !args.ownerAccount) throw new Error('socket activation requires --owner-account NAME');
    let ownerControl;
    try {
      if (args.ownerAccount) ownerControl = await activatedOwnerControl(args.ownerAccount);
    } catch (error) {
      if (process.platform !== 'darwin' || process.env.HQ_LAUNCHD_OWNER_PID !== String(process.pid)) throw error;
      // Only this inherited owner-control startup boundary has a versioned
      // post-exec exit status. Later service failures retain normal handling.
      console.error('HQ could not activate the inherited macOS owner-control listener');
      process.exitCode = 87;
      return;
    }
    try {
      const pins = readPins(PINS);
      const pluginsDir = productionPluginsDir(args, fileURLToPath(import.meta.url), pins);
      let installed = [];
      let machinePublicKey;
      const managedHq = process.platform === 'darwin' && process.arch === 'arm64'
        && userInfo().username === '_agent-bot-hq';
      if (managedHq) {
        try {
          const list = await machineRoleStage2aList();
          installed = list.installations;
          machinePublicKey = Buffer.from(list.machine_public_key, 'hex');
        } catch (error) {
          console.error(`Machine protected Soul plans unavailable: ${error.message}`);
        }
      }
      const epochs = new Set(installed.map((entry) => entry.hq_epoch));
      if (epochs.size > 1) throw new Error('Machine installed Soul plans disagree on HQ pairing epoch');
      const selectedH = authenticatedSelectedH();
      const verifyHQCodeReady = () => Boolean(managedHq && selectedH && machinePublicKey
        && selectedH.machinePublicKey === machinePublicKey.toString('hex')
        && installed.length && installed.every((entry) => entry.host_id === selectedH.hostId));
      const validatePayload = verifyHQCodeReady() ? loadStage2aSchemas() : undefined;
      const verifyReservation = installed.length ? (envelope, plan, reservationSHA256) =>
        verifyStage2aProtectedCandidateReservationV3(envelope, { enrolledMachineKey: machinePublicKey,
          installed: plan, reservationSHA256, validatePayload }) : undefined;
      const authority = installed.length ? createStage2aMachineBridgeAuthority({
        machinePublicKey, verifyReservation }) : undefined;
      const providers = new Map();
      let hq;
      const cooperativeMachine = managedHq && selectedH ? createStage2aCooperativeMachine({
        exchange: machineRoleStage2aCooperative, hDescriptorDigest: selectedH.descriptorDigest,
        machinePublicKey: selectedH.machinePublicKey,
      }) : undefined;
      const createCooperativeStart = cooperativeMachine ? (core, readCommittedReceipts) => createStage2aCooperativeStarter({
        core, readCommittedReceipts, machine: cooperativeMachine, openAdmission: (options) => hq.openCooperativeAdmission(options),
      }) : undefined;
      const protectedAdmission = installed.length ? createStage2aProtectedAdmission({
        machinePublicKey, authority,
        stopReservation: (reservationSHA256) => protectedStart.stopReservation(reservationSHA256),
      }) : undefined;
      const protectedStart = installed.length ? createStage2aProtectedStarter({
        installations: installed, authority, verifyReservation, verifyHQCodeReady,
        getBrokerIdentity: (installationId) => hq.bridgeBrokerIdentity(installationId),
        verifyBoundBridge: (selectors, digest) => hq.boundBridgeV2(selectors, digest),
        openProtectedAdmission: async ({ installed: plan, assignment, selectors,
          getBindReceiptSHA256 }) => {
          const registration = protectedAdmission.registerStart({ installed: plan,
            assignment, selectors, getBindReceiptSHA256 });
          try {
            const listener = await hq.openProtectedAdmission({ installed: plan, assignment,
              selectors, renewLive: (request) => protectedStart.renewLive(request),
              onLost: () => protectedStart.stopReservation(selectors.reservation_sha256) });
            return Object.freeze({ path: listener.path,
              helloFinalization: () => protectedAdmission.finalizationFor(selectors),
              close: async () => {
              registration.close();
              await listener.close();
            } });
          } catch (error) { registration.close(); throw error; }
        },
        onFinalized: async ({ installed: plan, assignment, selectors }) => {
          const provider = createStage2aQualificationProvider({
            plan: { installation_id: plan.installation_id, start_id: assignment.start_id,
              launch_id: assignment.launch_id, hq_epoch: plan.hq_epoch, plan_id: plan.plan_id,
              plan_digest: plan.plan_digest, reservation_sha256: selectors.reservation_sha256,
              soul_artifact_sha256: `sha256:${plan.soul_artifact_sha256}`,
              provider_config_sha256: plan.provider_config_sha256 },
          });
          providers.set(selectors.reservation_sha256, provider);
          try {
            // The unprivileged HQ listener must be reachable before ACP is
            // released. A port collision or bind error refuses the start.
            await provider.ready;
            if (providers.get(selectors.reservation_sha256) !== provider) {
              throw new Error('local provider stopped during activation');
            }
          } catch (error) {
            if (providers.get(selectors.reservation_sha256) === provider) {
              providers.delete(selectors.reservation_sha256);
            }
            await provider.close();
            throw error;
          }
        },
        onStopped: async (reservationSHA256) => {
          const provider = providers.get(reservationSHA256);
          providers.delete(reservationSHA256);
          await provider?.close();
        },
      }) : undefined;
      hq = createHQ({ home: args.home, ownerControl, schemas: loadSchemas(), pins,
        pluginsDir, devPlugins: args.devPlugins, bridgeAssignments: installed,
        bridgeAuthority: authority, machineHqEpoch: epochs.values().next().value,
        protectedStart, protectedAdmission, createCooperativeStart, cooperativeAdmission: cooperativeMachine,
        // Production B uses its dedicated v2 relay ingress. The synthetic
        // bridge qualification route stays disabled so it cannot consume the
        // installed one-use Machine provider response.
        relayIngressAuthorizer: installed.length ? ({ request, observation }) => {
          const provider = providers.get(observation?.reservation_digest);
          if (!provider) throw new Error('Machine protected provider start is unavailable');
          return provider({ request, observation });
        } : undefined });
      // Handlers first, so a signal during start still shuts down cleanly.
      let starting = true;
      const shutdown = (signal) => {
        const wait = starting ? new Promise((r) => { const i = setInterval(() => { if (!starting) { clearInterval(i); r(); } }, 50); }) : Promise.resolve();
        wait.then(() => hq.stop({ reason: signal })).then(() => process.exit(0), (e) => { console.error(e.message); process.exit(1); });
      };
      process.once('SIGINT', shutdown);
      process.once('SIGTERM', shutdown);
      try {
        printStatus(await hq.start());
      } finally {
        starting = false;
      }
      console.log(`listening: ${hq.paths.control} (owner), ${hq.paths.admission} (entry points), ${hq.paths.broker} (members)`);
    } finally { await ownerControl?.listener?.closeUnused(); }
    return;
  }
  if (args.cmd === 'enroll') {
    const client = await connectSocket(controlPath);
    try {
      const res = await client.request('device.enroll', { harnesses: args.harnesses ?? [], ...(args.force ? { force: true } : {}), ...(args.name ? { device_name: args.name } : {}) });
      if (!res.ok) { console.error(JSON.stringify(res.refusal ?? res.host_refusal ?? res)); process.exitCode = 1; return; }
      const g = res.result;
      if (!g.pending) { console.log(JSON.stringify(g, null, 2)); return; }
      console.log(`Approve this device at the identity service.\n  code: ${g.user_code}\n  open: ${g.verification_uri_complete ?? g.verification_uri ?? '(the identity service\'s device page)'}\n  key:  ${g.key_storage} key ${g.key_thumbprint.slice(0, 12)}, generation ${g.key_generation}\nWaiting for approval (until ${g.expires_at})...`);
      for (;;) {
        await new Promise((r) => setTimeout(r, 2000));
        const status = await client.request('device.status');
        if (status.transport_error) throw new Error('Lost connection to HQ while waiting for enrollment. Check HQ status before retrying.');
        if (!status.ok) {
          const code = status.refusal?.error ?? status.host_refusal?.code;
          const known = typeof code === 'string' && (Object.hasOwn(REGISTRY_CODES, code) || HOST_CODES.includes(code));
          throw new Error(`Enrollment status unavailable${known ? ` (${code})` : ''}. Check HQ status before retrying.`);
        }
        const s = status.result?.enrollment?.grant;
        if (s?.state === 'approved') { console.log(`Enrolled as device ${s.device_id}. Restart HQ to leave safe mode.`); return; }
        if (s?.state === 'failed') { console.error(`Enrollment failed: ${s.reason}`); process.exitCode = 1; return; }
        if (s?.state !== 'pending') throw new Error('HQ is no longer tracking this enrollment. Check HQ status before retrying.');
      }
    } finally { await client.close(); }
  }
  if (args.cmd === 'soul') {
    if (args.sub === 'start') {
      await startSoul(controlPath, args.soul, args.profile);
      return;
    }
    if (args.sub !== 'stop' && args.sub !== 'starts') throw new Error(USAGE);
    if (args.sub === 'stop' && !args.startId) throw new Error('soul stop needs --start-id ID');
    const result = await ask(controlPath, `soul.${args.sub}`,
      args.sub === 'stop' ? { start_id: args.startId } : undefined);
    if (!result.ok) throw new Error(JSON.stringify(result.refusal ?? result.host_refusal ?? result));
    console.log(JSON.stringify(result.result, null, 2));
    if (result.result.state === 'containment_unconfirmed') process.exitCode = 1;
    return;
  }
  if (args.cmd === 'signer') {
    if (args.sub !== 'rekey') throw new Error(USAGE);
    throw new Error('Device key rotation requires administrator action in Machine/keyd');
  }
  if (args.cmd === 'status' || args.cmd === 'souls') {
    const res = await ask(controlPath, args.cmd === 'status' ? 'status' : 'souls.list');
    if (!res.ok) {
      console.error(JSON.stringify(res.refusal ?? res.host_refusal ?? res));
      process.exitCode = 1;
      return;
    }
    if (args.json || args.cmd === 'souls') console.log(JSON.stringify(res.result, null, 2));
    else printStatus(res.result);
    return;
  }
  throw new Error(USAGE);
}

main(process.argv.slice(2)).catch((e) => { console.error(e.message); process.exitCode = 1; });
