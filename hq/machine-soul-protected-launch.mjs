// Scope a paired owner challenge to Machine's exact one-Soul protected
// installation. Machine remains the authority that builds and applies it.
import { createHash } from 'node:crypto';
import { posix } from 'node:path';

export const protectedInstallPurpose = 'soul-protected-launch-install';
const root = '/Library/Application Support/ai.true-line.agent-bot-hq';
const detail = 'install exact pinned launcher, sandbox policies, Machine public key, per-Soul rule and A-owned authority; publish root applied receipt';
const id = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const account = /^[a-z_][a-z0-9_-]{0,31}$/;
const hex = /^[0-9a-f]{64}$/;
const digest = /^sha256:[0-9a-f]{64}$/;
const soul = /^agent_[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const fields = (value, names) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).join(',') === names;
const absolute = (value) => typeof value === 'string' && value.length <= 1024
  && posix.isAbsolute(value) && value !== '/' && posix.normalize(value) === value
  && !/[\u0000-\u001f\u007f]/.test(value);
const prefix = (value, domain = '') => createHash('sha256').update(domain + value).digest('hex').slice(0, 20);
const emptyDirectory = (value) => fields(value, 'path,device,inode,birth_seconds,birth_nanoseconds')
  && value.path === '' && value.device === 0 && value.inode === ''
  && value.birth_seconds === 0 && value.birth_nanoseconds === 0;

export function validProtectedInstallPlan(plan, roleUid, machineKey) {
  if (!fields(plan, 'version,hq_account,dir,members,steps,purpose,soul_protected_launch')
    || plan.version !== 3 || plan.hq_account !== '_agent-bot-hq' || plan.dir !== 'none'
    || plan.purpose !== protectedInstallPurpose || !Array.isArray(plan.members)
    || plan.members.length !== 2 || !Array.isArray(plan.steps) || plan.steps.length !== 1) return false;
  const request = plan.soul_protected_launch;
  if (!fields(request, 'schema,machine_public_key,artifact_source,bridge_binary_source,definition_source,launch_inputs_source,policy')
    || request.schema !== 'agent-bot-machine/soul-protected-launch-install/v1'
    || typeof request.machine_public_key !== 'string' || !/^[0-9a-f]{64}$/.test(request.machine_public_key)
    || (machineKey !== undefined && request.machine_public_key !== machineKey)
    || ![request.artifact_source, request.bridge_binary_source, request.definition_source,
      request.launch_inputs_source].every(absolute)) return false;
  const policy = request.policy;
  if (!fields(policy, 'schema,machine_account,machine_uid,machine_gid,plan_owner,hq_uid,approved_until,canonical_plan,root_receipt,claims,snapshot_namespace,relay_parent,legacy_spent_start_ids,launcher_sha256,artifact_path,runner,bridge,measurement_binding,definition,launch_inputs,node,entry,bridge_executable,bridge_qualification')
    || policy.schema !== 'agent-bot-machine/stage2a-installed-authority/v1'
    || typeof policy.machine_account !== 'string' || !account.test(policy.machine_account)
    || !Number.isSafeInteger(policy.machine_uid) || policy.machine_uid < 400
    || !Number.isSafeInteger(policy.machine_gid) || policy.machine_gid < 1
    || typeof policy.plan_owner !== 'string' || !account.test(policy.plan_owner)
    || !Number.isSafeInteger(policy.hq_uid) || policy.hq_uid < 300 || policy.hq_uid > 399
    || (roleUid !== undefined && policy.hq_uid !== roleUid)
    || typeof policy.approved_until !== 'string' || !Number.isFinite(Date.parse(policy.approved_until))
    || policy.canonical_plan !== null || policy.root_receipt !== null
    || !emptyDirectory(policy.claims) || !emptyDirectory(policy.snapshot_namespace)
    || !emptyDirectory(policy.relay_parent)
    || !Array.isArray(policy.legacy_spent_start_ids) || policy.legacy_spent_start_ids.length !== 0
    || typeof policy.launcher_sha256 !== 'string' || !hex.test(policy.launcher_sha256)
    || !absolute(policy.artifact_path) || !absolute(policy.node) || !absolute(policy.entry)
    || !Array.isArray(policy.definition) || !policy.definition.length
    || !policy.launch_inputs || typeof policy.launch_inputs !== 'object'
    || !policy.bridge_executable || typeof policy.bridge_executable !== 'object'
    || !policy.bridge_qualification || typeof policy.bridge_qualification !== 'object') return false;
  const binding = policy.measurement_binding;
  const runner = policy.runner;
  const bridge = policy.bridge;
  if (!binding || binding.contract !== 'machine/v2' || binding.kind !== 'stage2a-measurement-binding'
    || binding.schema_version !== 2 || binding.profile_in_force !== 'managed-protected'
    || !id.test(binding.installation_id ?? '') || !soul.test(binding.soul_id ?? '')
    || !id.test(binding.host_id ?? '') || !hex.test(binding.hq_epoch ?? '')
    || binding.plan_id !== '' || binding.installed_plan_digest !== ''
    || binding.start_id !== '' || binding.launch_id !== ''
    || !hex.test(binding.package_sha256 ?? '') || !hex.test(binding.soul_artifact_sha256 ?? '')
    || !digest.test(binding.definition_measurement ?? '')
    || !digest.test(binding.launch_input_measurement ?? '')
    || !digest.test(binding.claimed_definition_digest ?? '')
    || !runner || !bridge || runner.installation_id !== binding.installation_id
    || bridge.installation_id !== binding.installation_id
    || runner.soul_id !== binding.soul_id || bridge.soul_id !== binding.soul_id
    || runner.package_sha256 !== binding.package_sha256
    || !absolute(runner.package_root)
    || runner.account !== `_abm-sr-${prefix(binding.installation_id)}`
    || bridge.account !== `_abm-br-${prefix(binding.installation_id, 'agent-bot-soul-bridge/v1\0')}`
    || !Number.isSafeInteger(runner.uid) || runner.uid < 300 || runner.uid > 399
    || !Number.isSafeInteger(bridge.uid) || bridge.uid < 300 || bridge.uid > 399
    || runner.uid === bridge.uid || runner.uid === policy.machine_uid
    || bridge.uid === policy.machine_uid || runner.uid === policy.hq_uid || bridge.uid === policy.hq_uid
    || runner.gid !== runner.uid || bridge.gid !== bridge.uid
    || runner.account === policy.machine_account || bridge.account === policy.machine_account) return false;
  const members = [runner.account, bridge.account].sort();
  const step = plan.steps[0];
  return plan.members[0] === members[0] && plan.members[1] === members[1]
    && policy.artifact_path === `${root}/soul-artifacts/${prefix(binding.installation_id, 'agent-bot-soul-endpoint-installation/v1\0')}.soul`
    && fields(step, 'kind,target,action,detail')
    && step.kind === 'soul-protected-launch' && step.target === binding.installation_id
    && step.action === 'write' && step.detail === detail;
}

export function checkProtectedInstallPlan(plan, roleUid, machineKey) {
  if (!validProtectedInstallPlan(plan, roleUid, machineKey)) {
    throw new Error('outside the paired protected Soul launch install plan scope');
  }
}
