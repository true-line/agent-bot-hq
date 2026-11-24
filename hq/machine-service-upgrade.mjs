// The paired service upgrade changes the release in an existing v2 LaunchDaemon.
// Match the concrete Machine job so both records retain the same custody and socket.
import { posix } from 'node:path';
import { createHash } from 'node:crypto';
import { parseStrict } from '../sdk/wire/strict-json.mjs';
import { validPlanId } from './machine-members-plans.mjs';

const label = 'ai.true-line.agent-bot-hq';
const role = '_agent-bot-hq';
const directory = '/Library/Application Support/' + label;
const fieldsAre = (o, names) => o && typeof o === 'object' && !Array.isArray(o) &&
  Object.keys(o).length === names.length && names.every((name) => Object.hasOwn(o, name));
const digest = (s) => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
const prefixedDigest = (s) => typeof s === 'string' && /^sha256:[0-9a-f]{64}$/.test(s);
const releasePrefix = `${directory}/releases/`;
const cleanPath = (s) => typeof s === 'string' &&
  (/^\/[a-zA-Z0-9._/+:-]+$/.test(s) ||
    (s.startsWith(releasePrefix) && /^[a-zA-Z0-9._/+:-]+$/.test(s.slice(releasePrefix.length)))) &&
  !s.endsWith('/') && posix.normalize(s) === s;

function expectedPlist(s, uid, owner) {
  return `<?xml version="1.0" encoding="UTF-8"?>
<!-- Managed by managed-machine members. -->
<!-- archive ${s.artifact_sha256} node ${s.node_sha256} owner UID ${uid} -->
<plist version="1.0"><dict>
<key>Label</key><string>${label}</string>
<key>UserName</key><string>${role}</string>
<key>GroupName</key><string>${role}</string>
<key>Umask</key><integer>63</integer>
<key>ProgramArguments</key><array>
<string>/usr/bin/ruby</string><string>--disable-gems</string><string>${s.release_dir}/helpers/darwin-owner.rb</string><string>launch</string>
<string>${s.node}</string><string>${s.release_dir}/hq/main.mjs</string><string>run</string><string>--home</string><string>/var/agent-bot-hq/.agent-bot-hq</string>
<string>--owner-account</string><string>${owner}</string></array>
<key>Sockets</key><dict><key>owner-control</key><dict>
<key>SockPathName</key><string>${directory}/owner-control.sock</string><key>SockPathMode</key><integer>438</integer>
<key>SockType</key><string>stream</string></dict></dict>
</dict></plist>
`;
}

function expectedStage2aPlist(s, uid, owner, argv) {
  const base = expectedPlist(s, uid, owner);
  const start = '<key>ProgramArguments</key><array>\n';
  const end = '</array>';
  const before = base.indexOf(start) + start.length;
  const after = base.indexOf(end, before);
  const xml = (value) => value.replaceAll('&', '&amp;').replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;').replaceAll('"', '&quot;').replaceAll("'", '&apos;');
  return base.slice(0, before) + argv.map((arg) => `<string>${xml(arg)}</string>\n`).join('') + base.slice(after);
}

function validStage2a(record, owner) {
  const s = record.service.stage2a;
  const launch = record.stage2a;
  const serviceFields = ['host_id', 'installation_id', 'machine_account', 'machine_uid', 'machine_gid',
    'reader_uid', 'reader_gid', 'authority_key_sha256', 'guard_module_sha256', 'preloader_path',
    'inventory_source', 'inventory_digest', 'inventory_limits', 'contracts_source', 'components'];
  const optionalFields = ['runtime_installation_id', 'cooperative_only', 'excluded_hq_release_paths'];
  if (!fieldsAre(s, [...serviceFields, ...optionalFields.filter((key) => Object.hasOwn(s, key))]) ||
      !fieldsAre(s.inventory_limits, ['max_files', 'max_file_bytes', 'max_total_bytes']) ||
      !fieldsAre(s.contracts_source, ['tag', 'commit', 'full_digest', 'full_files', 'runtime_digest', 'runtime_files']) ||
      !Array.isArray(s.components) || s.components.length !== 2 ||
      s.components[0]?.component_id !== 'hq' || s.components[1]?.component_id !== 'node' ||
      ![s.authority_key_sha256, s.guard_module_sha256, s.inventory_digest,
        s.contracts_source.full_digest, s.contracts_source.runtime_digest].every(prefixedDigest) ||
      !fieldsAre(launch, ['namespace', 'root', 'inventory_path', 'public_key_path',
    'descriptor_path', 'ruby_sha256', 'guard_module_path', 'launcher_sha256',
    'runtime_argv', 'outer_argv']) ||
      typeof s.installation_id !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(s.installation_id) ||
      s.preloader_path !== 'hq/stage2a-h-preloader.mjs' ||
      !prefixedDigest(launch.ruby_sha256) || !prefixedDigest(launch.launcher_sha256) ||
      !Array.isArray(launch.runtime_argv) || !Array.isArray(launch.outer_argv)) return false;
  const slot = createHash('sha256').update(`agent-bot/stage2a-domain-slot/v3\0H-code\0${s.installation_id}`).digest('hex').slice(0, 20);
  const snapshot = createHash('sha256').update(`agent-bot/stage2a-domain-snapshot/v3\0H-code\0${s.installation_id}`).digest('hex').slice(0, 24);
  const namespace = `/private/var/db/managed-machine/soul-snapshots/hq_${slot}`;
  const root = `${namespace}/snap_${snapshot}`;
  const runtime = [`${root}/bin/node`, '--no-addons', '--disallow-code-generation-from-strings',
    '--import', `${root}/${s.preloader_path}`, `${root}/hq/main.mjs`, 'run', '--home',
    '/var/agent-bot-hq/.agent-bot-hq', '--owner-account', owner];
  const outer = ['/usr/bin/ruby', '--disable-gems', `${root}/helpers/darwin-owner.rb`, 'launch', ...runtime];
  return launch.namespace === namespace && launch.root === root &&
    launch.inventory_path === `${namespace}/inventory_${snapshot}.jcs` &&
    launch.public_key_path === `${directory}/soul-authority.pub` &&
    launch.descriptor_path === `${directory}/h-v3/descriptor.json` &&
    launch.guard_module_path === `${root}/hq/stage2a-selected-code.mjs` &&
    launch.runtime_argv.length === runtime.length && launch.runtime_argv.every((arg, i) => arg === runtime[i]) &&
    launch.outer_argv.length === outer.length && launch.outer_argv.every((arg, i) => arg === outer[i]) &&
    record.plist === expectedStage2aPlist(record.service, record.owner_uid, owner, outer);
}

function validRecord(record, owner, previous) {
  const protectedNext = !previous && record && typeof record === 'object' && Object.hasOwn(record, 'stage2a');
  if (!fieldsAre(record, protectedNext ? ['service', 'plist', 'owner_uid', 'runtime_directory', 'stage2a'] :
    ['service', 'plist', 'owner_uid', 'runtime_directory'])) return false;
  const { service: s, owner_uid: uid, runtime_directory: dir } = record;
  return Number.isSafeInteger(uid) && uid > 0 &&
    fieldsAre(dir, ['path', 'action', 'owner', 'group', 'mode']) &&
    dir.path === directory && dir.owner === 'root' && dir.group === 'wheel' && dir.mode === '0755' &&
    (dir.action === 'none' || (previous && dir.action === 'create')) &&
    fieldsAre(s, protectedNext ? ['archive', 'release_dir', 'artifact_sha256', 'node', 'node_sha256', 'stage2a'] :
      ['archive', 'release_dir', 'artifact_sha256', 'node', 'node_sha256']) &&
    [s.release_dir, s.archive, s.node].every(cleanPath) && posix.basename(s.release_dir) === 'hq' &&
    digest(s.artifact_sha256) && digest(s.node_sha256) &&
    (protectedNext ? validStage2a(record, owner) : record.plist === expectedPlist(s, uid, owner));
}

export function checkUpgradeRecords(step, planId) {
  const content = parseStrict(step.content, { maxDepth: 6 });
  if (!fieldsAre(content, ['previous_plan_id', 'previous_plan_digest', 'previous', 'next']) ||
      !validPlanId(content.previous_plan_id) || content.previous_plan_id === planId || !digest(content.previous_plan_digest) ||
      !validRecord(content.previous, step.owner, true) || !validRecord(content.next, step.owner, false)) {
    throw new Error('invalid paired HQ service upgrade record');
  }
  const { previous, next } = content;
  if (previous.owner_uid !== next.owner_uid || previous.service.node !== next.service.node ||
      previous.service.node_sha256 !== next.service.node_sha256 || previous.service.release_dir === next.service.release_dir ||
      previous.service.artifact_sha256 === next.service.artifact_sha256 || previous.service.archive === next.service.archive) {
    throw new Error('paired HQ service upgrade must retain its owner and Node while replacing the approved release');
  }
}
