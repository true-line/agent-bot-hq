// The exact Machine-reviewed account plan for one untrusted OS principal per
// Soul installation. This handoff grants account creation only; it cannot
// authorize a package launch or widen a harness credential account.
import { createHash } from 'node:crypto';

export const soulBridgeAccountsPurpose = 'soul-bridge-provision';
export const soulRunnerAccountsPurpose = 'soul-runner-provision';
const SOUL = /^agent_[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const INSTALL = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const HQ = '_agent-bot-hq';
const ROLE = /^_abm-sr-[0-9a-f]{20}$/;

const fields = (value, names) => value != null && typeof value === 'object' && !Array.isArray(value) &&
  Object.keys(value).join(',') === names;

const runnerName = (installationId) => `_abm-sr-${createHash('sha256').update(installationId).digest('hex').slice(0, 20)}`;

function account(step, name, ids, role = 'runner') {
  if (!fields(step, 'kind,target,action,group,mode,detail,uid,gid') ||
      step.kind !== 'account' || step.target !== name || step.group !== name || step.mode !== '0700' ||
      !Number.isInteger(step.uid) || step.uid < 300 || step.uid > 399 || step.gid !== step.uid || ids.has(step.uid)) return false;
  ids.add(step.uid);
  const home = `/var/agent-bot-soul-${role}-${name}`;
  if (step.action === 'create') return step.detail === `Soul ${role} home ${home}, shell /usr/bin/false, private group, no password, no other groups`;
  if (step.action === 'none') return step.detail === `exists; Soul ${role} home ${home}; its password is checked at apply`;
  if (step.action !== 'repair' || typeof step.detail !== 'string') return false;
  const match = /^exists; home (.+) has mode ([0-7]{4}) and is set to 0700; its password is checked at apply$/.exec(step.detail);
  return !!match && match[1] === home && match[2] !== '0700';
}

export function validSoulRunnerAccounts(plan) {
  if (plan.hq_account !== HQ || plan.dir !== 'none' || !Array.isArray(plan.soul_runners) ||
      !Array.isArray(plan.members) || !Array.isArray(plan.steps) ||
      plan.soul_runners.length < 1 || plan.soul_runners.length > 64 ||
      plan.members.length !== plan.soul_runners.length || plan.steps.length !== plan.members.length + 1) return false;
  const hq = plan.steps[0];
  if (!fields(hq, 'kind,target,action,group,mode,detail,uid,gid') || hq.kind !== 'hq-account' ||
      hq.target !== HQ || hq.action !== 'none' || hq.group !== HQ || hq.mode !== '0700' ||
      hq.detail !== 'exists; dedicated; home /var/agent-bot-hq; its password is checked at apply' ||
      !Number.isInteger(hq.uid) || hq.uid < 300 || hq.uid > 399 || hq.gid !== hq.uid) return false;
  const ids = new Set([hq.uid]);
  const names = new Set();
  let prior = '';
  for (const r of plan.soul_runners) {
    if (!fields(r, 'soul_id,installation_id,account') || !SOUL.test(r.soul_id) ||
        !INSTALL.test(r.installation_id) || r.installation_id <= prior ||
        !ROLE.test(r.account) || r.account !== runnerName(r.installation_id) || names.has(r.account)) return false;
    prior = r.installation_id;
    names.add(r.account);
  }
  if (plan.members.join(',') !== [...names].sort().join(',')) return false;
  return plan.members.every((name, i) => account(plan.steps[i + 1], name, ids));
}

export function validSoulBridgeAccounts(plan) {
  const { soul_bridges: bridges, members, steps } = plan;
  if (!Array.isArray(bridges) || !Array.isArray(members) || !Array.isArray(steps) || bridges.length !== members.length || steps.length !== 5 * bridges.length + 5) return false;
  const select = (domain, id) => createHash('sha256').update(domain + '\0' + id).digest('hex').slice(0, 20);
  let prior = '';
  const names = new Set();
  for (const item of bridges) {
    if (!fields(item, 'soul_id,installation_id,account') || !SOUL.test(item.soul_id)
      || !INSTALL.test(item.installation_id) || item.installation_id <= prior
      || item.account !== '_abm-br-' + select('agent-bot-soul-bridge/v1', item.installation_id)
      || names.has(item.account)) return false;
    prior = item.installation_id;
    names.add(item.account);
  }
  if (bridges.length < 1 || bridges.length > 64 || members.join(',') !== [...names].sort().join(',')
    || plan.hq_account !== HQ || plan.dir !== 'none') return false;
  const hq = steps[0];
  if (!fields(hq, 'kind,target,action,group,mode,detail,uid,gid') || hq.kind !== 'hq-account'
    || hq.target !== HQ || hq.action !== 'none' || hq.group !== HQ || hq.mode !== '0700'
    || hq.detail !== 'exists; dedicated; home /var/agent-bot-hq; its password is checked at apply'
    || !Number.isInteger(hq.uid) || hq.uid < 300 || hq.uid > 399 || hq.gid !== hq.uid) return false;
  const ids = new Set([hq.uid]), byName = new Map();
  for (const [i, name] of members.entries()) {
    if (!account(steps[i + 1], name, ids, 'bridge')) return false;
    byName.set(name, steps[i + 1].uid);
  }
  const root = '/Library/Application Support/ai.true-line.agent-bot-hq';
  let cursor = members.length + 1;
  const directory = (target, owner, group, mode, uid, gid) => {
    const step = steps[cursor++];
    const keys = 'kind,target,action,owner,group,mode' + (uid === undefined ? '' : ',uid,gid');
    return fields(step, keys) && step.kind === 'directory' && ['create', 'none'].includes(step.action)
      && step.target === target && step.owner === owner && step.group === group && step.mode === mode
      && step.uid === uid && step.gid === gid;
  };
  if (!['ipc', 'm', 's', 'r'].every((name) => directory(root + '/' + name, 'root', 'wheel', '0755'))) return false;
  return bridges.every(({ account: bridge, installation_id: id }) => {
    const slot = select('agent-bot-soul-endpoint-installation/v1', id);
    const runner = runnerName(id), runnerUid = steps[cursor + 1]?.uid, bridgeUid = byName.get(bridge);
    if (!Number.isInteger(runnerUid) || runnerUid < 300 || runnerUid > 399 || ids.has(runnerUid)) return false;
    ids.add(runnerUid);
    return directory(root + '/ipc/' + bridge, HQ, bridge, '2750', hq.uid, bridgeUid)
      && directory(root + '/m/' + slot, runner, bridge, '2750', runnerUid, bridgeUid)
      && directory(root + '/s/' + slot, bridge, runner, '2750', bridgeUid, runnerUid)
      && directory(root + '/r/' + slot, HQ, runner, '2750', hq.uid, runnerUid);
  });
}
