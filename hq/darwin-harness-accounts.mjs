// Machine owns the system hierarchy and role accounts. HQ only reads their
// public directory records and verifies the filesystem before opening IPC.
import { execFileSync } from 'node:child_process';

export const DARWIN_HARNESS_DIR = '/Library/Application Support/ai.true-line.agent-bot-hq/ipc';

function command(file, args, input) {
  return execFileSync(file, args, {
    input, encoding: 'utf8', env: { LC_ALL: 'C' }, stdio: ['pipe', 'pipe', 'ignore'], timeout: 5000,
  });
}

function readRecord(path, attributes, run) {
  const plist = run('/usr/bin/dscl', ['-plist', '.', '-read', path, ...attributes]);
  const record = JSON.parse(run('/usr/bin/plutil', ['-convert', 'json', '-o', '-', '-'], plist));
  return (attribute) => {
    const standard = record[`dsAttrTypeStandard:${attribute}`];
    if (attribute !== 'IsHidden') return standard ?? [];
    // IsHidden is a native attribute in the local Directory Services node.
    const native = record['dsAttrTypeNative:IsHidden'];
    if (native && standard && JSON.stringify(native) !== JSON.stringify(standard)) throw new Error('conflicting role visibility');
    return native ?? standard ?? [];
  };
}

const only = (values, expected) => values.length === 1 && values[0] === expected;

function effectiveGroups(account, run) {
  const values = run('/usr/bin/id', ['-G', account]).trim().split(/\s+/);
  if (!values.every((id) => /^(0|[1-9][0-9]{0,9})$/.test(id) && Number(id) <= 0xffffffff)) {
    throw new Error('unreadable effective group list');
  }
  return new Set(values);
}

// Machine accepts the harness's private group plus resolved groups also held by
// nobody. It does not exempt groups by a name prefix for a harness account.
function verifyEffectiveGroups(name, primary, localGroups, run) {
  const actual = effectiveGroups(name, run);
  if (!actual.delete(primary)) throw new Error('missing private primary group');
  if (!actual.size) return;
  const common = effectiveGroups('nobody', run);
  for (const gid of actual) {
    if (!common.has(gid)) throw new Error('unexpected supplemental group');
    // id(1) prints unsigned gid_t; Directory Services also emits signed
    // decimal (for example, the built-in nobody group has GID -2).
    const signedGid = String(Number(gid) | 0);
    if (localGroups.has(gid) || localGroups.has(signedGid)) continue;
    // Directory Services can supply a group outside the local node. Match
    // Machine's refusal of an unresolved supplemental GID, even if shared.
    const group = run('/usr/bin/dscacheutil', ['-q', 'group', '-a', 'gid', gid]);
    const groups = group.split('\n');
    if (!groups.some((line) => /^name: \S/.test(line)) || !groups.some((line) => line === 'gid: ' + gid || line === 'gid: ' + signedGid)) {
      throw new Error('unresolved supplemental group');
    }
  }
}

// Check the public attributes that distinguish the local harness user and its
// dedicated group. This is the role and home emitted by Machine, not a request
// to look up arbitrary caller-supplied user metadata.
export function resolveDarwinHarness(name, { run = command } = {}) {
  try {
    const user = readRecord(`/Users/${name}`, ['RecordName', 'UniqueID', 'PrimaryGroupID', 'NFSHomeDirectory', 'RealName', 'IsHidden', 'UserShell'], run);
    const group = readRecord(`/Groups/${name}`, ['RecordName', 'PrimaryGroupID', 'GroupMembership', 'GroupMembers', 'NestedGroups'], run);
    const id = run('/usr/bin/id', ['-u', name]).trim();
    const home = `/var/agent-bot-harness-${name}`;
    if (!/^3[0-9]{2}$/.test(id) || !only(user('RecordName'), name) || !only(user('UniqueID'), id) ||
        !only(user('PrimaryGroupID'), id) || !only(user('RealName'), 'Agent Bot Harness') ||
        !only(user('IsHidden'), '1') || !only(user('UserShell'), '/usr/bin/false') || !only(user('NFSHomeDirectory'), home) ||
        !only(group('RecordName'), name) || !only(group('PrimaryGroupID'), id) ||
        group('GroupMembership').some((member) => member !== name) || group('GroupMembers').length || group('NestedGroups').length) {
      throw new Error();
    }
    for (const [path, field] of [['/Users', 'UniqueID'], ['/Users', 'PrimaryGroupID'], ['/Groups', 'PrimaryGroupID']]) {
      const rows = run('/usr/bin/dscl', ['.', '-list', path, field]).trim().split('\n');
      const records = rows.map((row) => /^(.*?)\s+(-?\d+)$/.exec(row.trim())).filter(Boolean);
      if (!only(records.filter((entry) => entry[2] === id).map((entry) => entry[1]), name)) throw new Error();
      if (path === '/Groups') verifyEffectiveGroups(name, id, new Set(records.map((entry) => entry[2])), run);
    }
    return { uid: Number(id), gid: Number(id), groupMembers: [], home };
  } catch {
    throw new Error(`harness account ${name} must be a locally provisioned Machine harness with its own uid, private group and home`);
  }
}

export function checkDarwinACL(path, run = command) {
  const [, ...entries] = run('/bin/ls', ['-ldne', path]).trimEnd().split('\n');
  if (entries.some((line) => !/^\s*\d+: .*\bdeny\b/.test(line) || /\ballow\b/.test(line))) {
    throw new Error(`harness path ${path} has an unexpected access control entry`);
  }
}
