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

function account(step, name, ids) {
  if (!fields(step, 'kind,target,action,group,mode,detail,uid,gid') ||
      step.kind !== 'account' || step.target !== name || step.group !== name || step.mode !== '0700' ||
      !Number.isInteger(step.uid) || step.uid < 300 || step.uid > 399 || step.gid !== step.uid || ids.has(step.uid)) return false;
  ids.add(step.uid);
  const home = `/var/agent-bot-soul-runner-${name}`;
  if (step.action === 'create') return step.detail === `Soul runner home ${home}, shell /usr/bin/false, private group, no password, no other groups`;
  if (step.action === 'none') return step.detail === `exists; Soul runner home ${home}; its password is checked at apply`;
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
