// Read-only responses for Machine's members-plans verb. The digest covers the
// original Go Plan.Canonical() bytes, including its final LF.
import { accountsPurpose, validHarnessAccounts } from './machine-harness-accounts.mjs';
import { qualificationPurpose, validHarnessQualification } from './machine-harness-qualification.mjs';
import { protectedInstallPurpose, validProtectedInstallPlan } from './machine-soul-protected-launch.mjs';
import { createHash } from 'node:crypto';
import { parseStrict } from '../sdk/wire/strict-json.mjs';

export const validPlanId = (value) => typeof value === 'string' && /^plan-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{4}$/.test(value);
const isAccount = (value) => typeof value === 'string' && /^[a-z_][a-z0-9_-]{0,31}$/.test(value);
const stepKinds = new Set(['hq-account', 'account', 'directory', 'file', 'service']);
const stepActions = new Set(['none', 'create', 'repair', 'remove', 'write']);
const stepFields = ['kind', 'target', 'action', 'owner', 'group', 'mode', 'content', 'detail'];
const object = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);

function validStep(s) {
  if (!object(s) || !stepKinds.has(s.kind) || !s.target) return false;
  const upgrade = s.action === 'upgrade' && s.kind === 'service' && s.target === 'ai.true-line.agent-bot-hq';
  if (!upgrade && !stepActions.has(s.action)) return false;
  const keys = Object.keys(s);
  return keys.length >= 3 && keys.every((key, i) =>
    typeof s[key] === 'string' && s[key].length > 0 && stepFields.includes(key) &&
    (i === 0 || stepFields.indexOf(keys[i - 1]) < stepFields.indexOf(key)));
}

function validMembers(plan) {
  if (Array.isArray(plan.members)) {
    return plan.members.every((m, i) => isAccount(m) && (i === 0 || m > plan.members[i - 1]));
  }
  // Match Identity's compatibility rule for saved Darwin HQ-only plans.
  // Keep the original null in the digest and in the returned bytes.
  const [role, service] = plan.steps;
  return plan.members === null && plan.version === 3 && plan.hq_account === '_agent-bot-hq' &&
    plan.dir === 'none' && role?.kind === 'hq-account' && role.target === plan.hq_account &&
    (plan.steps.length === 1 || (plan.steps.length === 2 && service?.kind === 'service' &&
      service.target === 'ai.true-line.agent-bot-hq'));
}

export function canonicalMembersJSON(value) {
  return JSON.stringify(value).replaceAll('\u2028', '\\u2028').replaceAll('\u2029', '\\u2029') + '\n';
}

export function validatedMembersPlan(id, response) {
  const body = response.body;
  if (!object(body) || response.state !== 'found') throw new Error('unexpected Machine members-plans lookup state');
  const { plan_id, plan_digest, plan_canonical } = body;
  if (Object.keys(body).length !== 3 || plan_id !== id || typeof plan_digest !== 'string' ||
      !/^[0-9a-f]{64}$/.test(plan_digest) || typeof plan_canonical !== 'string' || !plan_canonical.endsWith('\n') ||
      createHash('sha256').update(plan_canonical, 'utf8').digest('hex') !== plan_digest) {
    throw new Error('Machine members plan does not match the requested ID and canonical digest');
  }
  const p = parseStrict(plan_canonical, { maxDepth: 32 });
  const accounts = p?.purpose === accountsPurpose;
  const qualification = p?.purpose === qualificationPurpose;
  const protectedInstall = p?.purpose === protectedInstallPurpose;
  // The installation policy includes nested binding snapshots. Preserve the
  // previous depth limit for every other members-plan shape.
  if (!protectedInstall) parseStrict(plan_canonical, { maxDepth: 6 });
  const fields = protectedInstall ? 'version,hq_account,dir,members,steps,purpose,soul_protected_launch'
    : accounts || qualification ? 'version,hq_account,dir,members,steps,purpose' : 'version,hq_account,dir,members,steps';
  if (!object(p) || Object.keys(p).join(',') !== fields ||
      p.version !== 3 || !isAccount(p.hq_account) || typeof p.dir !== 'string' || !p.dir ||
      !Array.isArray(p.steps) || !p.steps.length || !validMembers(p) ||
      (accounts ? Buffer.byteLength(plan_canonical) > 32768 || !validHarnessAccounts(p)
        : qualification ? !validHarnessQualification(p, Buffer.byteLength(plan_canonical))
          : protectedInstall ? Buffer.byteLength(plan_canonical) > 48 * 1024 || !validProtectedInstallPlan(p)
          : !p.steps.every(validStep))) {
    throw new Error('Machine members plan has an unsupported structure');
  }
  // Go emits compact JSON without HTML escaping, but it escapes U+2028 and
  // U+2029. This checks form only; the exact received bytes are returned.
  if (canonicalMembersJSON(p) !== plan_canonical) {
    throw new Error('Machine members plan is not in canonical form');
  }
  return p;
}

export function membersPlanResult(option, id, response) {
  const body = response.body;
  if (!object(body)) throw new Error('Machine members-plans response is missing its body');
  if (option === 'get') {
    validatedMembersPlan(id, response);
  } else {
    const ids = body.plan_ids;
    if (response.state !== 'listed' || Object.keys(body).some((k) => k !== 'plan_ids' && k !== 'next_after') ||
        !Array.isArray(ids) || ids.length > 64 ||
        !ids.every((item, i) => validPlanId(item) && item > (i === 0 ? id : ids[i - 1])) ||
        (Object.hasOwn(body, 'next_after') && (ids.length !== 64 || body.next_after !== ids.at(-1)))) {
      throw new Error('invalid Machine members-plans page or continuation');
    }
  }
  return body;
}
