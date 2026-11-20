// Exact macOS account-provisioning plan emitted by Machine. A distinct purpose
// keeps account creation and private home repair outside the launch-rule handoff.
export const accountsPurpose = 'harness-account-provision';
const hq = '_agent-bot-hq';
const broker = '/Library/Application Support/ai.true-line.agent-bot-hq/ipc';
const fields = (step, names) => step != null && Object.keys(step).join(',') === names;

function account(step, kind, name, ids) {
  if (!fields(step, 'kind,target,action,group,mode,detail,uid,gid') ||
      step.kind !== kind || step.target !== name || step.group !== name || step.mode !== '0700' ||
      !Number.isInteger(step.uid) || step.uid < 300 || step.uid > 399 || step.gid !== step.uid || ids.has(step.uid)) return false;
  ids.add(step.uid);
  if (kind === 'hq-account') {
    return step.action === 'none' && step.detail === 'exists; dedicated; home /var/agent-bot-hq; its password is checked at apply';
  }
  const home = '/var/agent-bot-harness-' + name;
  if (step.action === 'create') return step.detail === `home ${home}, shell /usr/bin/false, private group, no password, no other groups`;
  if (step.action === 'none') return step.detail === `exists; home ${home}; its password is checked at apply`;
  if (step.action !== 'repair' || typeof step.detail !== 'string') return false;
  const match = / has mode ([0-7]{4}) and is set to 0700;/.exec(step.detail);
  return !!match && match[1] !== '0700' &&
    step.detail === `exists; home ${home} has mode ${match[1]} and is set to 0700; its password is checked at apply`;
}

function directory(step, path, owner, group, mode) {
  return fields(step, 'kind,target,action,owner,group,mode') && step.kind === 'directory' && step.target === path &&
    ['create', 'none'].includes(step.action) && step.owner === owner && step.group === group && step.mode === mode;
}

// The common parser already checks canonical bytes and sorted, unique account names.
export function validHarnessAccounts(plan) {
  const { members, steps } = plan;
  if (plan.hq_account !== hq || !Array.isArray(members) || !members.length || members.length > 99 ||
      members.some(name => [hq, 'admin', 'root'].includes(name)) || !['none', broker].includes(plan.dir)) return false;
  const count = members.length + 1;
  if (steps.length !== (plan.dir === broker ? count * 2 : count)) return false;
  const ids = new Set();
  if (!account(steps[0], 'hq-account', hq, ids) ||
      !members.every((name, i) => account(steps[i + 1], 'account', name, ids))) return false;
  return plan.dir === 'none' || (directory(steps[count], broker, 'root', 'wheel', '0755') &&
    members.every((name, i) => directory(steps[count + i + 1], broker + '/' + name, hq, name, '2750')));
}
