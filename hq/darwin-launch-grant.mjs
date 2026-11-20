// Read only the installed Machine grant. The target-UID supervisor rechecks it
// under Machine's installation lock before opening any adapter executable.
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readSync } from 'node:fs';
import { isUtf8 } from 'node:buffer';
import { dirname } from 'node:path';
import { parseStrict } from '../sdk/wire/strict-json.mjs';
import { checkDarwinACL, DARWIN_HARNESS_DIR } from './darwin-harness-accounts.mjs';
import { checkHarnessLaunchPlan } from './machine-harness-launch.mjs';
import { canonicalMembersJSON, validPlanId } from './machine-members-plans.mjs';

const root = dirname(DARWIN_HARNESS_DIR);
export const DARWIN_LAUNCHER = root + '/harness-launch';
const policyPath = root + '/harness-launch-policy.json';
const invalid = () => { throw new Error('unverified installed Darwin harness launch grant'); };

function readProtected(path, mode, maxBytes, hashOnly = false) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const st = fstatSync(fd, { bigint: true });
    if (!st.isFile() || st.uid !== 0n || st.gid !== 0n || st.nlink !== 1n ||
        Number(st.mode & 0o7777n) !== mode || st.size < 1n || st.size > BigInt(maxBytes)) invalid();
    checkDarwinACL(path);
    const hash = createHash('sha256');
    const bytes = Buffer.alloc(hashOnly ? 65536 : Number(st.size));
    let offset = 0;
    while (offset < Number(st.size)) {
      const count = readSync(fd, bytes, hashOnly ? 0 : offset, Math.min(bytes.length, Number(st.size) - offset), offset);
      if (count <= 0) invalid();
      if (hashOnly) hash.update(bytes.subarray(0, count));
      offset += count;
    }
    const end = lstatSync(path, { bigint: true });
    if (end.dev !== st.dev || end.ino !== st.ino || end.ctimeNs !== st.ctimeNs || end.size !== st.size) invalid();
    if (hashOnly) return hash.digest('hex');
    if (!isUtf8(bytes)) invalid();
    return bytes.toString('utf8');
  } finally { closeSync(fd); }
}

export function decodeDarwinGrant(raw, roleUid) {
  const wrapper = parseStrict(raw, { maxDepth: 8 });
  if (Object.keys(wrapper ?? {}).join('|') !== 'plan_id|plan_digest|policy' ||
      !validPlanId(wrapper.plan_id) || canonicalMembersJSON(wrapper) !== raw) invalid();
  const p = wrapper.policy;
  if (!Array.isArray(p?.adapters)) invalid();
  const accounts = [...new Set(p.adapters.map(adapter => adapter.account))].sort();
  const rule = '# Managed by managed-machine harness launch v1.\n' + accounts.map(account =>
    `_agent-bot-hq ALL = (${account}) NOPASSWD: NOSETENV: sha256:${p.launcher.sha256} ${DARWIN_LAUNCHER.replace(' ', '\\ ')} harness-run\n`).join('');
  const file = (target, mode, content) => ({ kind: 'file', target, action: 'create', owner: 'root', group: 'wheel', mode, content });
  const plan = { version: 3, hq_account: '_agent-bot-hq', dir: DARWIN_HARNESS_DIR, members: accounts, steps: [
    file(policyPath, '0644', canonicalMembersJSON(p)), file('/private/etc/sudoers.d/agent-bot-hq-harness-launch', '0440', rule),
  ] };
  if (accounts.some(a => typeof a !== 'string' || !/^[a-z_][a-z0-9_-]{0,31}$/.test(a))) invalid();
  checkHarnessLaunchPlan(plan, 'harness-launch-install', wrapper.plan_id, roleUid);
  if (createHash('sha256').update(canonicalMembersJSON(plan)).digest('hex') !== wrapper.plan_digest) invalid();
  return wrapper;
}

export function readDarwinGrant() {
  const uid = process.getuid();
  if (uid < 300 || uid > 399 || process.geteuid() !== uid || process.getgid() !== uid || process.getegid() !== uid) invalid();
  for (const path of ['/', '/Library', '/Library/Application Support', root]) {
    const st = lstatSync(path);
    if (!st.isDirectory() || st.uid !== 0 || st.mode & 0o022 || (path === root && (st.gid !== 0 || (st.mode & 0o7777) !== 0o755))) invalid();
    checkDarwinACL(path);
  }
  const grant = decodeDarwinGrant(readProtected(policyPath, 0o644, 65536), uid);
  if (readProtected(DARWIN_LAUNCHER, 0o755, 256 << 20, true) !== grant.policy.launcher.sha256 ||
      readProtected(root + '/harness-egress.sb', 0o644, 65536, true) !== grant.policy.sandbox.sha256) invalid();
  return grant;
}

export function approvedDarwinAdapter(grant, endpoint, adapterId, command) {
  const a = grant.policy.adapters.find(entry => entry.adapter_id === adapterId);
  if (!a || a.account !== endpoint.account || a.uid !== endpoint.uid || endpoint.gid !== endpoint.uid ||
      endpoint.path !== DARWIN_HARNESS_DIR + '/' + a.account + '/broker.sock' ||
      (command && JSON.stringify(command) !== JSON.stringify([a.executable, ...a.args]))) invalid();
  return a;
}

export const supervisorArgv = account => ['-n', '-H', '-u', account, '--', DARWIN_LAUNCHER, 'harness-run'];
export const supervisorListArgv = account => ['-n', '-l', '-u', account, '--', DARWIN_LAUNCHER, 'harness-run'];
