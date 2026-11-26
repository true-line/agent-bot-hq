// The paired Machine validates and builds this plan. HQ scopes the owner
// handoff to its exact cooperative purpose, runner, and paired identities.
import { createHash } from 'node:crypto';

export const cooperativeInstallPurpose = 'soul-cooperative-launch-install';
const detail = 'seal R runtime and frozen Soul inputs; install fixed per-R launchd WatchPaths job; A:runner-group 2700 staging dir, 2750 request dir, and 2770 completion dir; write A-only signed pending journal before one-use claim; publish applied root receipt';
const id = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const hex = /^[0-9a-f]{64}$/;
const object = v => v !== null && typeof v === 'object' && !Array.isArray(v);
const keys = (v, names) => object(v) && Object.keys(v).join(',') === names;

export function validCooperativeInstallPlan(plan, roleUid, machineKey) {
  if (!keys(plan, 'version,hq_account,dir,members,steps,purpose,soul_cooperative_launch') ||
      plan.version !== 3 || plan.hq_account !== '_agent-bot-hq' || plan.dir !== 'none' ||
      plan.purpose !== cooperativeInstallPurpose || !Array.isArray(plan.members) || plan.members.length !== 1 ||
      !Array.isArray(plan.steps) || plan.steps.length !== 1) return false;
  const p = plan.soul_cooperative_launch;
  const policyFields = 'schema,purpose,profile_in_force,host_id,hq_installation_id,h_owner_plan_digest,hq_uid,machine_uid,machine_gid,hq_epoch,machine_public_key_base64url,source_package_path,definition_source,launch_inputs_source,definition,launch_inputs,definition_measurement,launch_input_measurement,state_root,runtime_root,runner,soul_artifact_sha256,definition_sha256,node_path,node_sha256,entry,launcher_path,launcher_sha256,approved_until,runtime_v3,adapter_release,hq_broker,adapter_transport,reviewed_start_id,qualification_provider,adapter_code_inputs'.split(',');
  const present = object(p) ? Object.keys(p) : [];
  if (!object(p) || present.some((k, i) => !policyFields.includes(k) || (i && policyFields.indexOf(present[i - 1]) >= policyFields.indexOf(k))) ||
      policyFields.filter(k => k !== 'qualification_provider').some(k => !Object.hasOwn(p, k)) ||
      !object(p.runtime_v3) || !object(p.adapter_release) || !object(p.hq_broker) ||
      !object(p.launch_inputs) || !Array.isArray(p.definition) || !Array.isArray(p.adapter_code_inputs) ||
      !Number.isSafeInteger(p.machine_uid) || p.machine_uid < 400 || !Number.isSafeInteger(p.machine_gid) || p.machine_gid < 1 ||
      p.adapter_transport !== 'direct-comms' || typeof p.reviewed_start_id !== 'string' ||
      !/^st_[0-9a-f]{24}$/.test(p.reviewed_start_id) || !id.test(p.hq_installation_id ?? '') || !hex.test(p.h_owner_plan_digest ?? '') ||
      !object(p) || p.schema !== 'agent-bot-machine/soul-cooperative-launch-install/v3' ||
      p.purpose !== cooperativeInstallPurpose || p.profile_in_force !== 'managed-cooperative' ||
      !Number.isSafeInteger(p.hq_uid) || p.hq_uid < 300 || p.hq_uid > 399 ||
      (roleUid !== undefined && p.hq_uid !== roleUid) || !id.test(p.host_id ?? '') ||
      !hex.test(p.hq_epoch ?? '') || typeof p.machine_public_key_base64url !== 'string') return false;
  const key = Buffer.from(p.machine_public_key_base64url, 'base64url');
  if (key.length !== 32 || key.toString('base64url') !== p.machine_public_key_base64url ||
      (machineKey !== undefined && key.toString('hex') !== machineKey)) return false;
  const runner = p.runner;
  if (!keys(runner, 'soul_id,installation_id,account,uid,gid,package_root,package_sha256') ||
      !/^agent_[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/.test(runner.soul_id ?? '') ||
      !id.test(runner.installation_id ?? '') ||
      runner.account !== `_abm-sr-${createHash('sha256').update(runner.installation_id).digest('hex').slice(0, 20)}` ||
      !Number.isSafeInteger(runner.uid) || runner.uid < 300 || runner.uid > 399 || runner.uid === p.hq_uid ||
      runner.gid !== runner.uid || !hex.test(runner.package_sha256 ?? '') || plan.members[0] !== runner.account) return false;
  const s = plan.steps[0];
  return keys(s, 'kind,target,action,detail') && s.kind === 'soul-cooperative-launch' &&
    s.target === runner.installation_id && s.action === 'write' && s.detail === detail;
}

export function checkCooperativeInstallPlan(plan, roleUid, machineKey) {
  if (!validCooperativeInstallPlan(plan, roleUid, machineKey)) {
    throw new Error('outside the paired cooperative Soul launch install plan scope');
  }
}
