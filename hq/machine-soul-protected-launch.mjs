// Scope a paired owner challenge to Machine's exact one-Soul protected
// installation. Machine remains the authority that builds and applies it.
import { createHash } from 'node:crypto';
import { posix } from 'node:path';

export const protectedInstallPurpose = 'soul-protected-launch-install';
const root = '/Library/Application Support/ai.true-line.agent-bot-hq';
const detail = 'install exact pinned launcher, sandbox policies, Machine public key, per-Soul rule and A-owned authority; publish root applied receipt';
const runtimeDetail = 'seal reviewed R runtime in A, persist per-Soul authority and root applied receipt; defer the protected launch rule';
const id = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const account = /^[a-z_][a-z0-9_-]{0,31}$/;
const hex = /^[0-9a-f]{64}$/;
const digest = /^sha256:[0-9a-f]{64}$/;
const soul = /^agent_[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const maxFileBytes = 256 * 1024 * 1024;
const maxTotalBytes = 1024 * 1024 * 1024;
const fields = (value, names) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).join(',') === names;
const absolute = (value) => typeof value === 'string' && value.length <= 4096
  && posix.isAbsolute(value) && value !== '/' && posix.normalize(value) === value
  && /^[\x20-\x7e]+$/.test(value) && !value.includes('\\') && !value.includes('//');
const prefix = (value, domain = '') => createHash('sha256').update(domain + value).digest('hex').slice(0, 20);
const emptyDirectory = (value) => fields(value, 'path,device,inode,birth_seconds,birth_nanoseconds')
  && value.path === '' && value.device === 0 && value.inode === ''
  && value.birth_seconds === 0 && value.birth_nanoseconds === 0;
const object = value => value !== null && typeof value === 'object' && !Array.isArray(value);
const relative = value => typeof value === 'string' && value.length > 0 && value.length <= 4096
  && /^[\x20-\x7e]+$/.test(value) && !value.startsWith('/') && !value.endsWith('/')
  && !value.includes('//') && !value.includes('\\')
  && value.split('/').every(part => part !== '.' && part !== '..');
function record(value) {
  if (!object(value) || !relative(value.path) || !/^0[0-7]{3}$/.test(value.mode ?? '')) return false;
  const mode = Number.parseInt(value.mode, 8);
  if (mode & 0o222) return false;
  return value.kind === 'directory' ? fields(value, 'path,kind,mode')
    : value.kind === 'regular' && fields(value, 'path,kind,mode,size,sha256')
      && Number.isSafeInteger(value.size) && value.size >= 0 && value.size <= maxFileBytes
      && hex.test(value.sha256);
}
function records(value, minimum, maximum) {
  let total = 0;
  return Array.isArray(value) && value.length >= minimum && value.length <= maximum
    && value.every((r, i) => {
      if (!record(r) || (i !== 0 && r.path <= value[i - 1].path)) return false;
      total += r.kind === 'regular' ? r.size : 0;
      return total <= maxTotalBytes;
    });
}
function snapshot(value, expectedPath, machineUid, runnerGid) {
  return fields(value, 'root_path,device,inode,generation,birthtime_ns,owner_uid,owner_gid,mode')
    && value.root_path === expectedPath && value.device === '' && value.inode === ''
    && value.generation === '' && value.birthtime_ns === ''
    && value.owner_uid === machineUid && value.owner_gid === runnerGid && value.mode === '0555';
}
function validNested(policy, request) {
  const { definition, launch_inputs: inputs, bridge_executable: executable, bridge_qualification: qualification,
    measurement_binding: binding, runner } = policy;
  if (!object(binding) || !object(runner)) return false;
  const requiredDefinition = { Contents: 'directory', 'Contents/SoulInfo.json': 'regular',
    'Contents/SoulLock.json': 'regular', 'Contents/opt': 'directory', 'Contents/primitives': 'directory' };
  if (!records(definition, 5, 512) || !Object.entries(requiredDefinition).every(([path, kind]) =>
    definition.some(r => r.path === path && r.kind === kind))
    || !fields(inputs, 'files,host_projection,selected_command,argv,environment,effective_config,system_images,sandbox_policy_digest,component_digests')
    || !records(inputs.files, 4, 64) || !inputs.files.every(r => r.kind === 'regular')
    || !['host/adapters.json', 'host/installation.json']
      .every(path => inputs.files.some(r => r.path === path))
    || !fields(inputs.host_projection, 'adapters,installation')
    || !object(inputs.host_projection.adapters) || !object(inputs.host_projection.installation)
    || inputs.selected_command !== policy.node || !Array.isArray(inputs.argv)
    || !inputs.argv.every(arg => typeof arg === 'string')
    || !object(inputs.environment) || !Object.values(inputs.environment).every(v => typeof v === 'string')
    || !object(inputs.effective_config)
    || !fields(inputs.system_images, 'product_version,build_version,darwin_kernel,selected')
    || !Array.isArray(inputs.system_images.selected) || !inputs.system_images.selected.length
    || !inputs.system_images.selected.every(image => fields(image, 'path,signing_requirement,cdhash')
      && absolute(image.path) && typeof image.signing_requirement === 'string' && typeof image.cdhash === 'string')
    || !inputs.system_images.selected.some(image => image.path === '/usr/bin/sandbox-exec')
    || !digest.test(inputs.sandbox_policy_digest) || !object(inputs.component_digests)
    || !Object.values(inputs.component_digests).every(v => digest.test(v))
    || !fields(executable, 'path,sha256') || !absolute(executable.path) || !hex.test(executable.sha256)
    || inputs.component_digests.bridge !== `sha256:${executable.sha256}`
    || !fields(qualification, 'model,request_sha256,headers_sha256,client_key_sha256,http_host,messages_query,response_text')
    || !id.test(qualification.model) || !id.test(qualification.http_host)
    || ![qualification.request_sha256, qualification.headers_sha256,
      qualification.client_key_sha256].every(value => digest.test(value))
    || typeof qualification.messages_query !== 'string' || !qualification.messages_query
    || typeof qualification.response_text !== 'string' || !qualification.response_text
    || qualification.response_text.length > 4096) return false;
  const installation = binding.installation_id;
  const slot = prefix(installation, 'agent-bot-soul-endpoint-installation/v1\0');
  const base = `/private/var/db/managed-machine/soul-snapshots/${slot}`;
  const path = kind => `${base}/snap_${createHash('sha256').update(`agent-bot-machine/stage2a-install-snapshot/v1\0${kind}\0${installation}`).digest('hex').slice(0, 24)}`;
  const runtime = (selected, suffix, executable) => {
    const root = binding.snapshots?.launch_inputs?.root_path;
    if (typeof root !== 'string' || !selected.startsWith(root + '/')) return false;
    const relativePath = selected.slice(root.length + 1);
    if (!relative(relativePath) || !relativePath.endsWith('/' + suffix)) return false;
    const file = inputs.files.find(r => r.path === relativePath);
    return !!file && (!executable || (Number.parseInt(file.mode, 8) & 0o010) !== 0);
  };
  const runtimeCode = request.runtime_v3 ? (() => {
    const installation = binding.installation_id;
    const slot = prefix(`agent-bot/stage2a-domain-slot/v3\0R-runtime\0${installation}`);
    const name = createHash('sha256').update(`agent-bot/stage2a-domain-snapshot/v3\0R-runtime\0${installation}`).digest('hex').slice(0, 24);
    const sealed = `/private/var/db/managed-machine/soul-snapshots/r_${slot}/snap_${name}`;
    return policy.node === `${sealed}/runtime/bin/node` && policy.entry === `${sealed}/runtime/bin/agent-bot-souls.mjs`;
  })() : runtime(policy.node, 'bin/node', true) && runtime(policy.entry, 'bin/agent-bot-souls.mjs', false);
  return fields(binding.snapshots, 'definition,launch_inputs')
    && snapshot(binding.snapshots.definition, path('definition'), policy.machine_uid, runner.gid)
    && snapshot(binding.snapshots.launch_inputs, path('inputs'), policy.machine_uid, runner.gid)
    && runtimeCode
    && absolute(request.definition_source) && absolute(request.launch_inputs_source);
}

function validRuntimeV3(runtime) {
  if (!fields(runtime, 'inventory_source,inventory_digest,limits,components,source_roots')
    || !absolute(runtime.inventory_source) || !digest.test(runtime.inventory_digest)
    || !fields(runtime.limits, 'max_files,max_file_bytes,max_total_bytes')
    || !Number.isSafeInteger(runtime.limits.max_files) || runtime.limits.max_files < 1 || runtime.limits.max_files > 512
    || !Number.isSafeInteger(runtime.limits.max_file_bytes) || runtime.limits.max_file_bytes < 1 || runtime.limits.max_file_bytes > 402653184
    || !Number.isSafeInteger(runtime.limits.max_total_bytes) || runtime.limits.max_total_bytes < 1 || runtime.limits.max_total_bytes > 1073741824
    || !Array.isArray(runtime.components) || runtime.components.length < 3 || runtime.components.length > 32
    || !object(runtime.source_roots) || Object.keys(runtime.source_roots).length !== runtime.components.length) return false;
  let prior = '';
  const roots = new Set();
  const components = new Set();
  for (const row of runtime.components) {
    if (!object(row) || !['component_id,source_repository,source_commit,artifact_format,artifact_source,release_artifact_sha256,manifest_source,release_manifest_sha256',
      'component_id,source_repository,source_commit,source_tag,artifact_format,artifact_source,release_artifact_sha256,manifest_source,release_manifest_sha256'].includes(Object.keys(row).join(','))
      || !id.test(row.component_id) || row.component_id <= prior
      || !/^[A-Za-z0-9._-]+\/[A-Za-z0-9._-]+$/.test(row.source_repository)
      || !/^[0-9a-f]{40}$/.test(row.source_commit)
      || (row.source_tag !== undefined && !/^[A-Za-z0-9][A-Za-z0-9._+/-]{0,127}$/.test(row.source_tag))
      || !['tar', 'raw', 'zip'].includes(row.artifact_format)
      || !absolute(row.artifact_source) || !absolute(row.manifest_source)
      || !digest.test(row.release_artifact_sha256) || !digest.test(row.release_manifest_sha256)) return false;
    const sourceRoot = runtime.source_roots[row.component_id];
    if (!absolute(sourceRoot) || sourceRoot === '/private/var/db/managed-machine/soul-snapshots'
      || sourceRoot.startsWith('/private/var/db/managed-machine/soul-snapshots/') || roots.has(sourceRoot)) return false;
    roots.add(sourceRoot);
    components.add(row.component_id);
    prior = row.component_id;
  }
  return ['node', 'souls', 'adapter'].every(component => components.has(component));
}

function validMemberQualifiers(rows, base) {
  if (!Array.isArray(rows) || rows.length !== 2
    || base.client_key_sha256 !== 'sha256:da4fec28d868ca5cf8f00f43869f703f138bd4211683b8637a751b904860ddf0'
    || base.response_text.length > 2048) return false;
  let prior = '';
  for (const row of rows) {
    if (!fields(row, 'member_id,model,request_sha256,headers_sha256,client_key_sha256,http_host,messages_query,response_text')
      || !id.test(row.member_id) || row.member_id <= prior
      || Object.keys(base).some(key => row[key] !== base[key])) return false;
    prior = row.member_id;
  }
  return true;
}

export function validProtectedInstallPlan(plan, roleUid, machineKey) {
  if (!fields(plan, 'version,hq_account,dir,members,steps,purpose,soul_protected_launch')
    || plan.version !== 3 || plan.hq_account !== '_agent-bot-hq' || plan.dir !== 'none'
    || plan.purpose !== protectedInstallPurpose || !Array.isArray(plan.members)
    || plan.members.length !== 2 || !Array.isArray(plan.steps) || plan.steps.length !== 1) return false;
  const request = plan.soul_protected_launch;
  const v3 = request?.schema === 'agent-bot-machine/soul-protected-launch-install/v3';
  const memberSet = Object.hasOwn(request ?? {}, 'owner_plan_member_set_sha256');
  if (!(v3 ? fields(request, memberSet
    ? 'schema,machine_public_key,artifact_source,bridge_binary_source,definition_source,launch_inputs_source,runtime_v3,owner_plan_member_set_sha256,policy'
    : 'schema,machine_public_key,artifact_source,bridge_binary_source,definition_source,launch_inputs_source,runtime_v3,policy')
    : fields(request, 'schema,machine_public_key,artifact_source,bridge_binary_source,definition_source,launch_inputs_source,policy'))
    || (v3 ? !validRuntimeV3(request.runtime_v3) : request.schema !== 'agent-bot-machine/soul-protected-launch-install/v1')
    || (memberSet && (!v3 || !digest.test(request.owner_plan_member_set_sha256)))
    || typeof request.machine_public_key !== 'string' || !/^[0-9a-f]{64}$/.test(request.machine_public_key)
    || (machineKey !== undefined && request.machine_public_key !== machineKey)
    || ![request.artifact_source, request.bridge_binary_source, request.definition_source,
      request.launch_inputs_source].every(absolute)) return false;
  const policy = request.policy;
  const policyFields = 'schema,machine_account,machine_uid,machine_gid,plan_owner,hq_uid,approved_until,canonical_plan,root_receipt,claims,snapshot_namespace,relay_parent,legacy_spent_start_ids,launcher_sha256,artifact_path,runner,bridge,measurement_binding,definition,launch_inputs,node,entry,bridge_executable,bridge_qualification';
  if (!fields(policy, policyFields + (memberSet ? ',member_bridge_qualifications' : ''))
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
    || !validNested(policy, request)
    || (memberSet && !validMemberQualifiers(policy.member_bridge_qualifications, policy.bridge_qualification))) return false;
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
    || !absolute(runner.package_root) || runner.package_root.length > 1024
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
    && step.action === 'write' && step.detail === (v3 ? runtimeDetail : detail);
}

export function checkProtectedInstallPlan(plan, roleUid, machineKey) {
  if (!validProtectedInstallPlan(plan, roleUid, machineKey)) {
    throw new Error('outside the paired protected Soul launch install plan scope');
  }
}
