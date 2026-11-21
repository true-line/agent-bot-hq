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
import { readFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { verify } from '../scripts/soul-contracts.mjs';
import { HOST_CODES, REGISTRY_CODES } from '../sdk/errors.mjs';
import { SCHEMA_NAMES } from './admission.mjs';
import { NOTICE_SCHEMA_NAMES } from './notices.mjs';
import { TASK_SCHEMA_NAMES, TASK_WIRE_SCHEMA_NAMES } from './tasks.mjs';
import { createHQ } from './hq.mjs';
import { productionPluginsDir, readPins } from './plugins.mjs';
import { activatedOwnerControl, checkOwnerControlSupport, checkOwnerSocketPath, OWNER_CONTROL_PATH } from './owner-control.mjs';
import { connectSocket } from './socket.mjs';
import { machineRoleCommand } from './machine-channel.mjs';

const USAGE = 'usage: node hq/main.mjs <run|status|souls|enroll|machine identity|machine status|machine members-plans|machine hq-service-recovery|machine hq-service-upgrade|machine harness-account-provision|machine harness-launch-install|machine harness-launch-retire|check-owner-control> [--home DIR] [--plugins DIR] [--dev-plugins DIR] [--owner-account NAME | --owner-control] [--json]';
const PINS = join(dirname(fileURLToPath(import.meta.url)), '../governance/plugins.json');

function parse(argv) {
  const args = { cmd: argv[0], home: process.env.AGENT_BOT_HQ_HOME || join(homedir(), '.agent-bot-hq'), json: false };
  if (args.cmd === 'signer') args.sub = argv[1];
  for (let i = args.cmd === 'signer' ? 2 : 1; i < argv.length; i++) {
    if (argv[i] === '--home') args.home = argv[++i];
    else if (argv[i] === '--owner-account') {
      args.ownerAccount = argv[++i];
      if (!args.ownerAccount || args.cmd !== 'run') throw new Error('--owner-account NAME is only for the systemd HQ service');
    } else if (argv[i] === '--owner-control') {
      if (!['status', 'souls', 'enroll'].includes(args.cmd)) throw new Error('--owner-control is only for owner socket clients');
      args.ownerControl = true;
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
  return Object.fromEntries([...load('hq/v1', [...SCHEMA_NAMES, ...NOTICE_SCHEMA_NAMES]), ...load('task/v1', TASK_SCHEMA_NAMES), ...load('wire/v1', TASK_WIRE_SCHEMA_NAMES)]);
}

async function ask(controlPath, op) {
  const client = await connectSocket(controlPath);
  try { return await client.request(op); } finally { await client.close(); }
}

function signerLine(g) {
  const backend = g.backend === 'machine' ? 'paired Machine/keyd' : g.backend;
  if (!g.available) return `signer: ${backend} unavailable (${g.reason})`;
  return `signer: ${g.key_storage} key, ${backend} backend, key ${g.thumbprint.slice(0, 12)}, generation ${g.generation}`;
}

function printStatus(s) {
  const grant = s.hq?.enrollment?.grant;
  const enrollment = {
    pending: 'awaiting owner approval',
    approved: 'approved; restart HQ to activate',
    failed: 'failed',
  }[grant?.state];
  const enrollmentInProgress = grant?.state === 'pending' || grant?.state === 'approved';
  const enrollHint = 'device not enrolled: run enroll';
  const reasonSuffix = (reason) => {
    if (!reason) return '';
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
  const controlPath = args.ownerControl ? OWNER_CONTROL_PATH : join(args.home, 'control.sock');
  if (args.ownerControl) checkOwnerSocketPath(process.getuid?.());
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
      const hq = createHQ({ home: args.home, ownerControl, schemas: loadSchemas(), pins, pluginsDir, devPlugins: args.devPlugins });
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
