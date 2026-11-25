// The exact Machine-reviewed account plan for one untrusted OS principal per
// Soul installation. This handoff grants account creation only; it cannot
// authorize a package launch or widen a harness credential account.
import { createHash } from 'node:crypto';

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

// Machine provisions a separate credential bridge and fixed endpoint parents
// for each runner installation. Keep this validator in the existing account
// module so the selected H runtime stays within its 512-file inventory limit.
export const soulBridgeAccountsPurpose = 'soul-bridge-provision';
const bridgeRoot = '/Library/Application Support/ai.true-line.agent-bot-hq';
const endpointSlot = installation => createHash('sha256').update('agent-bot-soul-endpoint-installation/v1\0' + installation).digest('hex').slice(0, 20);
const bridgeName = installation => '_abm-br-' + createHash('sha256').update('agent-bot-soul-bridge/v1\0' + installation).digest('hex').slice(0, 20);

function bridgeAccount(step, name, ids) {
  if (!fields(step, 'kind,target,action,group,mode,detail,uid,gid') || step.kind !== 'account'
    || step.target !== name || step.group !== name || step.mode !== '0700'
    || !Number.isSafeInteger(step.uid) || step.uid < 300 || step.uid > 399
    || step.gid !== step.uid || ids.has(step.uid)) return false;
  ids.add(step.uid);
  const home = `/var/agent-bot-soul-bridge-${name}`;
  if (step.action === 'create') return step.detail === `Soul bridge home ${home}, shell /usr/bin/false, private group, no password, no other groups`;
  if (step.action === 'none') return step.detail === `exists; Soul bridge home ${home}; its password is checked at apply`;
  const match = /^exists; home (.+) has mode ([0-7]{4}) and is set to 0700; its password is checked at apply$/.exec(step.detail ?? '');
  return step.action === 'repair' && !!match && match[1] === home && match[2] !== '0700';
}

function bridgeDirectory(step, path, owner, group, mode, uid, gid) {
  const identified = uid !== undefined;
  return fields(step, identified ? 'kind,target,action,owner,group,mode,uid,gid' : 'kind,target,action,owner,group,mode')
    && step.kind === 'directory' && step.target === path && ['create', 'none'].includes(step.action)
    && step.owner === owner && step.group === group && step.mode === mode
    && (!identified || (step.uid === uid && step.gid === gid));
}

export function validSoulBridgeAccounts(plan, roleUid) {
  if (!fields(plan, 'version,hq_account,dir,members,steps,purpose,soul_bridges')
    || plan.version !== 3 || plan.hq_account !== HQ || plan.dir !== 'none'
    || plan.purpose !== soulBridgeAccountsPurpose || !Array.isArray(plan.soul_bridges)
    || plan.soul_bridges.length < 1 || plan.soul_bridges.length > 64
    || !Array.isArray(plan.members) || !Array.isArray(plan.steps)
    || plan.members.length !== plan.soul_bridges.length
    || plan.steps.length !== 5 + 5 * plan.soul_bridges.length) return false;
  const hqStep = plan.steps[0];
  if (!fields(hqStep, 'kind,target,action,group,mode,detail,uid,gid')
    || hqStep.kind !== 'hq-account' || hqStep.target !== HQ || hqStep.action !== 'none'
    || hqStep.group !== HQ || hqStep.mode !== '0700'
    || hqStep.detail !== 'exists; dedicated; home /var/agent-bot-hq; its password is checked at apply'
    || !Number.isSafeInteger(hqStep.uid) || hqStep.uid < 300 || hqStep.uid > 399
    || hqStep.gid !== hqStep.uid || (roleUid !== undefined && hqStep.uid !== roleUid)) return false;
  const ids = new Set([hqStep.uid]);
  const byName = new Map();
  let prior = '';
  for (const row of plan.soul_bridges) {
    if (!fields(row, 'soul_id,installation_id,account') || !SOUL.test(row.soul_id)
      || !INSTALL.test(row.installation_id) || row.installation_id <= prior
      || row.account !== bridgeName(row.installation_id) || byName.has(row.account)) return false;
    byName.set(row.account, row);
    prior = row.installation_id;
  }
  if (plan.members.join(',') !== [...byName.keys()].sort().join(',')) return false;
  for (let i = 0; i < plan.members.length; i++) {
    if (!bridgeAccount(plan.steps[i + 1], plan.members[i], ids)) return false;
  }
  const offset = plan.members.length + 1;
  for (const [i, path] of [`${bridgeRoot}/ipc`, `${bridgeRoot}/m`, `${bridgeRoot}/s`, `${bridgeRoot}/r`].entries()) {
    if (!bridgeDirectory(plan.steps[offset + i], path, 'root', 'wheel', '0755')) return false;
  }
  for (const [i, row] of plan.soul_bridges.entries()) {
    const base = offset + 4 + 4 * i;
    const bridgeUid = plan.steps[plan.members.indexOf(row.account) + 1].uid;
    const runner = runnerName(row.installation_id);
    const runnerUid = plan.steps[base + 1]?.uid;
    if (!Number.isSafeInteger(runnerUid) || runnerUid < 300 || runnerUid > 399
      || ids.has(runnerUid) || !bridgeDirectory(plan.steps[base], `${bridgeRoot}/ipc/${row.account}`, HQ, row.account, '2750', hqStep.uid, bridgeUid)
      || !bridgeDirectory(plan.steps[base + 1], `${bridgeRoot}/m/${endpointSlot(row.installation_id)}`, runner, row.account, '2750', runnerUid, bridgeUid)
      || !bridgeDirectory(plan.steps[base + 2], `${bridgeRoot}/s/${endpointSlot(row.installation_id)}`, row.account, runner, '2750', bridgeUid, runnerUid)
      || !bridgeDirectory(plan.steps[base + 3], `${bridgeRoot}/r/${endpointSlot(row.installation_id)}`, HQ, runner, '2750', hqStep.uid, runnerUid)) return false;
    ids.add(runnerUid);
  }
  return true;
}

export function checkSoulBridgeAccounts(plan, roleUid) {
  if (!validSoulBridgeAccounts(plan, roleUid)) throw new Error('outside the paired HQ Soul bridge account scope');
}
