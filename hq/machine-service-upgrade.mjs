// The paired service upgrade changes the release in an existing v2 LaunchDaemon.
// Match the concrete Machine job so both records retain the same custody and socket.
import { posix } from 'node:path';
import { parseStrict } from '../sdk/wire/strict-json.mjs';
import { validPlanId } from './machine-members-plans.mjs';

const label = 'ai.true-line.agent-bot-hq';
const role = '_agent-bot-hq';
const directory = '/Library/Application Support/' + label;
const fieldsAre = (o, names) => o && typeof o === 'object' && !Array.isArray(o) &&
  Object.keys(o).length === names.length && names.every((name) => Object.hasOwn(o, name));
const digest = (s) => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
const cleanPath = (s) => typeof s === 'string' && /^\/[a-zA-Z0-9._/+:-]+$/.test(s) &&
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

function validRecord(record, owner, previous) {
  if (!fieldsAre(record, ['service', 'plist', 'owner_uid', 'runtime_directory'])) return false;
  const { service: s, owner_uid: uid, runtime_directory: dir } = record;
  return Number.isSafeInteger(uid) && uid > 0 &&
    fieldsAre(dir, ['path', 'action', 'owner', 'group', 'mode']) &&
    dir.path === directory && dir.owner === 'root' && dir.group === 'wheel' && dir.mode === '0755' &&
    (dir.action === 'none' || (previous && dir.action === 'create')) &&
    fieldsAre(s, ['archive', 'release_dir', 'artifact_sha256', 'node', 'node_sha256']) &&
    [s.release_dir, s.archive, s.node].every(cleanPath) && posix.basename(s.release_dir) === 'hq' &&
    digest(s.artifact_sha256) && digest(s.node_sha256) && record.plist === expectedPlist(s, uid, owner);
}

export function checkUpgradeRecords(step, planId) {
  const content = parseStrict(step.content, { maxDepth: 5 });
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
