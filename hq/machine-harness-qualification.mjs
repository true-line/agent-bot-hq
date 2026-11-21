// This handoff carries a reviewed one-use plan. Machine, not HQ, owns approval
// state and any later use. Keep this shape in sync with Machine's Go planner.
import { parseStrict } from '../sdk/wire/strict-json.mjs';

export const qualificationPurpose = 'harness-qualification-run';
const qualificationPreviewDetail = 'Review only: declared host identity, fixed conformance gates, pinned runner and test provider, disposable member state; no install or launch authorization.';
export const qualificationApprovalDetail = 'Owner approval permits one qualification run with the listed runner, test provider and disposable member state. It grants no installation or ordinary HQ access.';
const fields = (o, names) => o && typeof o === 'object' && !Array.isArray(o) && Object.keys(o).join(',') === names;
const singleLine = (s, max) => typeof s === 'string' && Buffer.byteLength(s) <= max && !/[\x00-\x1f\x7f]/.test(s);
const label = s => singleLine(s, 256) && !/^\p{White_Space}*$/u.test(s);
const digest = s => typeof s === 'string' && /^[0-9a-f]{64}$/.test(s);
const revision = s => typeof s === 'string' && /^[0-9a-f]{40}$/.test(s);
const file = (path, sha) => digest(sha) && typeof path === 'string' &&
  (path === '/' || path.startsWith('/') &&
    path.slice(1).split('/').every(part => part && part !== '.' && part !== '..' && !/[\x00-\x1f\x7f]/.test(part)));
const fileRef = f => fields(f, 'path,sha256') && file(f.path, f.sha256);
const missingFile = f => fields(f, 'path,sha256') && f.path === '' && f.sha256 === '';
const gateIds = ['T01', 'T02', 'T03', 'T21'];

export function validHarnessQualification(plan, bytes) {
  if (plan.purpose !== qualificationPurpose || plan.hq_account !== '_agent-bot-hq' ||
      plan.dir !== '/Library/Application Support/ai.true-line.agent-bot-hq/ipc' ||
      !Array.isArray(plan.members) || plan.members.length !== 0 || plan.steps.length !== 1 ||
      bytes > 28 * 1024) return false;
  const [step] = plan.steps;
  if (!fields(step, 'kind,target,action,content,detail') || step.kind !== 'qualification-run' ||
      step.action !== 'none' || ![qualificationPreviewDetail, qualificationApprovalDetail].includes(step.detail) ||
      typeof step.content !== 'string') return false;

  const run = parseStrict(step.content, { maxDepth: 8 });
  if (!fields(run, 'request_sha256,request,member_state,one_use,gates') || !digest(run.request_sha256) ||
      run.member_state !== 'disposable' || run.one_use !== true ||
      !Array.isArray(run.gates) || run.gates.length !== gateIds.length ||
      !run.gates.every((g, i) => fields(g, 'id,profile') && g.id === gateIds[i] &&
        g.profile === (g.id === 'T21' ? 'managed-cooperative' : 'managed-protected'))) return false;
  // The embedded content uses Go json.Marshal with HTML escaping enabled.
  const inner = JSON.stringify(run).replace(/[<>&\u2028\u2029]/g,
    ch => '\\u' + ch.charCodeAt(0).toString(16).padStart(4, '0'));
  if (inner !== step.content) return false;

  const r = run.request;
  if (!fields(r, 'schema_version,adapter,target,host,definition_revision,suite_revision,runner,test_provider') ||
      r.schema_version !== 1 || !revision(r.definition_revision) || !revision(r.suite_revision)) return false;
  const { adapter, target, host, runner, test_provider: provider } = r;
  if (!fields(adapter, 'id,version,package_path,package_sha256,launch,harness') ||
      !fields(target, 'account,uid') || !Number.isInteger(target.uid) || target.uid < 300 || target.uid > 399 ||
      !fields(host, 'id,model,os,os_version,os_build,architecture,enforcement_policy_sha256') ||
      host.os !== 'darwin' || host.architecture !== 'arm64' || !digest(host.enforcement_policy_sha256) ||
      !fields(runner, 'id,version,binary_path,binary_sha256') ||
      !fields(provider, 'id,configuration_path,configuration_sha256')) return false;

  const { launch, harness } = adapter;
  return step.target === adapter.id &&
    fields(launch, 'executable,executable_sha256,argv,code_inputs,code_inputs_manifest,driver') &&
    fields(harness, 'name,version,binary_path,binary_sha256') &&
    [adapter.id, adapter.version, harness.name, harness.version, target.account, host.id, host.model,
      host.os_version, host.os_build, runner.id, runner.version, provider.id].every(label) &&
    file(adapter.package_path, adapter.package_sha256) && file(launch.executable, launch.executable_sha256) &&
    file(harness.binary_path, harness.binary_sha256) && file(runner.binary_path, runner.binary_sha256) &&
    file(provider.configuration_path, provider.configuration_sha256) &&
    Array.isArray(launch.argv) && launch.argv.length <= 128 && launch.argv.every(arg => singleLine(arg, 4096)) &&
    Array.isArray(launch.code_inputs) && launch.code_inputs.length <= 2048 && launch.code_inputs.every(fileRef) &&
    new Set(launch.code_inputs.map(f => f.path)).size === launch.code_inputs.length &&
    (launch.code_inputs.length ? missingFile(launch.code_inputs_manifest) : fileRef(launch.code_inputs_manifest)) &&
    (missingFile(launch.driver) || fileRef(launch.driver));
}
