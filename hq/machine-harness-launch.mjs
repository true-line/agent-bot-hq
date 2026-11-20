// Validate the two Machine-reviewed files before the dedicated HQ exports a
// challenge, and again before it returns the physical owner's proof.
import { createHash } from 'node:crypto';
import { posix } from 'node:path';
import { parseStrict } from '../sdk/wire/strict-json.mjs';
import { canonicalMembersJSON, validPlanId } from './machine-members-plans.mjs';

const role = '_agent-bot-hq';
const root = '/Library/Application Support/ai.true-line.agent-bot-hq';
const sudoers = '/private/etc/sudoers.d/agent-bot-hq-harness-launch';
const hex = s => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
const uid = n => Number.isInteger(n) && n >= 300 && n <= 399;
function fields(o, names) {
  if (!o || typeof o !== 'object' || Array.isArray(o)) return false;
  const expected = names.split(',');
  const keys = Object.keys(o);
  return keys.length === expected.length && keys.every((k, i) => k === expected[i]);
}
const pinned = (o, name) => fields(o, 'path,sha256') && o.path === root + '/' + name && hex(o.sha256);

export const isHarnessLaunchHandoff = verb => verb === 'harness-launch-install' || verb === 'harness-launch-retire';

function file(step, path, mode, action) {
  return fields(step, 'kind,target,action,owner,group,mode,content') &&
    step.kind === 'file' && step.target === path && step.action === action && step.owner === 'root' &&
    step.group === 'wheel' && step.mode === mode;
}

function validAdapters(policy, members) {
  if (!Array.isArray(policy.adapters) || policy.adapters.length < 1 || policy.adapters.length > 16) return false;
  const accounts = new Map();
  const uids = new Map();
  let prev = '';
  for (const a of policy.adapters) {
    if (!fields(a, 'adapter_id,account,uid,executable,sha256,args') ||
        typeof a.adapter_id !== 'string' || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(a.adapter_id) ||
        a.adapter_id <= prev || !members.includes(a.account) || [role, 'root', 'admin'].includes(a.account) ||
        !uid(a.uid) || a.uid === policy.hq_uid || !hex(a.sha256) ||
        typeof a.executable !== 'string' || !posix.isAbsolute(a.executable) ||
        a.executable.length > 1024 || /[^a-zA-Z0-9._+ /-]/.test(a.executable) ||
        a.executable.endsWith('/') || posix.normalize(a.executable) !== a.executable ||
        !Array.isArray(a.args) || a.args.length > 32 ||
        a.args.some(s => typeof s !== 'string' || Buffer.byteLength(s) > 1024 || /\p{Cc}/u.test(s))) {
      return false;
    }
    if ((accounts.has(a.account) && accounts.get(a.account) !== a.uid) ||
        (uids.has(a.uid) && uids.get(a.uid) !== a.account)) return false;
    accounts.set(a.account, a.uid);
    uids.set(a.uid, a.account);
    prev = a.adapter_id;
  }
  return accounts.size === members.length;
}

function expectedRule(policy, accounts) {
  const command = policy.launcher.path.replace(' ', '\\ ') + ' harness-run';
  return '# Managed by managed-machine harness launch v1.\n' + accounts.map(account =>
    `${role} ALL = (${account}) NOPASSWD: NOSETENV: sha256:${policy.launcher.sha256} ${command}\n`).join('');
}

export function checkHarnessLaunchPlan(plan, purpose, planId, roleUid) {
  const install = purpose === 'harness-launch-install';
  const action = install ? 'create' : 'remove';
  const [policy, rule] = plan.steps;
  if (Buffer.byteLength(canonicalMembersJSON(plan)) > 32 * 1024 ||
      !isHarnessLaunchHandoff(purpose) || plan.hq_account !== role || plan.dir !== root + '/ipc' ||
      !Array.isArray(plan.members) || plan.members.length === 0 || plan.steps.length !== 2 ||
      !file(policy, root + '/harness-launch-policy.json', '0644', action) ||
      !file(rule, sudoers, '0440', action)) throw new Error('outside the paired harness launch plan scope');
  const p = parseStrict(policy.content, { maxDepth: 6 });
  if (!fields(p, 'schema,action,hq_uid,launcher,sandbox,adapters,installed_plan_id,installed_plan_digest') ||
      p.schema !== 'agent-bot-harness-launch/v1' || p.action !== (install ? 'install' : 'retire') ||
      !uid(p.hq_uid) || p.hq_uid !== roleUid || !pinned(p.launcher, 'harness-launch') || !pinned(p.sandbox, 'harness-egress.sb') ||
      !validAdapters(p, plan.members) ||
      (install ? p.installed_plan_id !== '' || p.installed_plan_digest !== '' :
        !validPlanId(p.installed_plan_id) || p.installed_plan_id === planId || !hex(p.installed_plan_digest))) {
    throw new Error('invalid paired harness launch policy');
  }
  if (canonicalMembersJSON(p) !== policy.content) {
    throw new Error('harness launch policy is not canonical');
  }
  if (rule.content !== expectedRule(p, plan.members)) throw new Error('unexpected harness launch sudoers rule');
  if (!install) {
    const priorPolicy = { ...p, action: 'install', installed_plan_id: '', installed_plan_digest: '' };
    const priorSteps = [{ ...policy, action: 'create', content: canonicalMembersJSON(priorPolicy) }, { ...rule, action: 'create' }];
    const priorBytes = canonicalMembersJSON({ ...plan, steps: priorSteps });
    if (createHash('sha256').update(priorBytes).digest('hex') !== p.installed_plan_digest) {
      throw new Error('retirement mapping differs from the referenced installation digest');
    }
  }
}
