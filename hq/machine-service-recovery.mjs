// One native macOS service operation under the already-paired HQ identity. The signed
// handoff can cross accounts; Machine's trusted daemon pin stays in HQ custody.
import { isUtf8 } from 'node:buffer';
import { createPublicKey, verify } from 'node:crypto';
import { closeSync, constants, fstatSync, openSync, readSync } from 'node:fs';
import { parseStrict } from '../sdk/wire/strict-json.mjs';
import { validatedMembersPlan, validPlanId } from './machine-members-plans.mjs';
import { accountsPurpose } from './machine-harness-accounts.mjs';
import { soulRunnerAccountsPurpose } from './machine-soul-runner-accounts.mjs';
import { qualificationApprovalDetail, qualificationPurpose } from './machine-harness-qualification.mjs';
import { checkUpgradeRecords } from './machine-service-upgrade.mjs';
import { checkHarnessLaunchPlan, isHarnessLaunchHandoff } from './machine-harness-launch.mjs';

export const isServiceHandoff = (verb) => verb === 'hq-service-recovery' || verb === 'hq-service-upgrade' ||
  isHarnessLaunchHandoff(verb) || verb === accountsPurpose || verb === soulRunnerAccountsPurpose || verb === qualificationPurpose;
const role = '_agent-bot-hq';
const maxFrame = 64 * 1024;
const fieldsAre = (o, names) => o && typeof o === 'object' && !Array.isArray(o) &&
  Object.keys(o).length === names.length && names.every((name) => Object.hasOwn(o, name));

export function serviceHandoffArgs(action, args) {
  const [operation] = args;
  if (operation === 'export' && args.length === 4 && validPlanId(args[1]) && args[2] === '--socket') {
    return { operation, id: args[1], socket: args[3] };
  }
  if (operation === 'cancel' && args.length === 5 && args[1] === '--challenge-file' && args[2] && args[3] === '--socket') {
    return { operation, challengeFile: args[2], socket: args[4] };
  }
  if (operation === 'approve' && args.length === 7 && args[1] === '--challenge-file' && args[2] &&
      args[3] === '--proof-file' && args[4] && args[5] === '--socket') {
    return { operation, challengeFile: args[2], proofFile: args[4], socket: args[6] };
  }
  throw new Error(`usage: machine ${action} export PLAN_ID --socket PATH | approve --challenge-file FILE --proof-file FILE --socket PATH | cancel --challenge-file FILE --socket PATH`);
}

function readTransfer(path, limit) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > limit) throw new Error('expected a bounded regular transfer file');
    const bytes = Buffer.alloc(limit + 1);
    let size = 0;
    while (size <= limit) {
      const n = readSync(fd, bytes, size, bytes.length - size, null);
      if (!n) break;
      size += n;
    }
    if (size > limit || !isUtf8(bytes.subarray(0, size))) throw new Error('invalid transfer file size or encoding');
    return bytes.toString('utf8', 0, size);
  } finally { closeSync(fd); }
}

function ownerPublicKey(encoded) {
  const point = typeof encoded === 'string' ? Buffer.from(encoded, 'base64') : Buffer.alloc(0);
  if (point.length !== 65 || point[0] !== 4 || point.toString('base64') !== encoded) throw new Error('invalid pinned owner key');
  return createPublicKey({ format: 'jwk', key: { kty: 'EC', crv: 'P-256',
    x: point.subarray(1, 33).toString('base64url'), y: point.subarray(33).toString('base64url') } });
}

function checkPlanScope(plan, action, id, roleUid) {
  if (action === qualificationPurpose || plan.purpose === qualificationPurpose) {
    if (action !== plan.purpose || plan.steps[0].detail !== qualificationApprovalDetail) {
      throw new Error('outside the paired HQ qualification plan scope');
    }
    return;
  }
  if (action === accountsPurpose || plan.purpose === accountsPurpose) {
    if (action !== plan.purpose || plan.steps[0].uid !== roleUid) throw new Error('outside the paired HQ harness account scope');
    return;
  }
  if (action === soulRunnerAccountsPurpose || plan.purpose === soulRunnerAccountsPurpose) {
    if (action !== plan.purpose || plan.steps[0].uid !== roleUid) throw new Error('outside the paired HQ Soul runner account scope');
    return;
  }
  if (isHarnessLaunchHandoff(action)) return checkHarnessLaunchPlan(plan, action, id, roleUid);
  const [account, service] = plan.steps;
  if (plan.hq_account !== role || plan.dir !== 'none' || !Array.isArray(plan.members) || plan.members.length ||
      plan.steps.length !== 2 || !fieldsAre(account, ['kind', 'target', 'action', 'group', 'mode', 'detail']) ||
      account.kind !== 'hq-account' || account.target !== role || account.action !== 'none' || account.group !== role || account.mode !== '0700' ||
      !fieldsAre(service, ['kind', 'target', 'action', 'owner', 'content', 'detail']) || service.kind !== 'service' ||
      service.target !== 'ai.true-line.agent-bot-hq' || (action === 'hq-service-upgrade' ? service.action !== 'upgrade' : !['create', 'write'].includes(service.action)) ||
      !/^[a-z_][a-z0-9_-]{0,31}$/.test(service.owner) || service.owner === role || service.owner === 'root') {
    throw new Error('saved plan is outside the paired HQ service ' + (action === 'hq-service-upgrade' ? 'upgrade' : 'repair') + ' scope');
  }
  if (action === 'hq-service-upgrade') checkUpgradeRecords(service, id);
}

function validatedChallenge(r, machine, hq, action, roleUid) {
  const c = r.body;
  const now = Math.floor(Date.now() / 1000);
  if (r.state !== 'challenged' || !fieldsAre(c, ['action', 'machine_key', 'hq_key', 'owner_key', 'plan_id', 'plan_digest', 'nonce', 'expires_at', 'plan_canonical']) ||
      c.action !== action || c.machine_key !== machine || c.hq_key !== hq || !validPlanId(c.plan_id) ||
      typeof c.nonce !== 'string' || !/^[0-9a-f]{64}$/.test(c.nonce) ||
      !Number.isSafeInteger(c.expires_at) || c.expires_at <= now || c.expires_at <= r.timestamp ||
      c.expires_at > r.timestamp + 120 || c.expires_at > now + 120) {
    throw new Error('invalid, expired or misdirected Machine service challenge');
  }
  const body = { plan_id: c.plan_id, plan_digest: c.plan_digest, plan_canonical: c.plan_canonical };
  checkPlanScope(validatedMembersPlan(c.plan_id, { state: 'found', body }), action, c.plan_id, roleUid);
  ownerPublicKey(c.owner_key);
  return c;
}

function ownerSignature(c, path) {
  const proof = parseStrict(readTransfer(path, 1024));
  if (!fieldsAre(proof, ['public_key', 'signature']) || proof.public_key !== c.owner_key || typeof proof.signature !== 'string') {
    throw new Error('owner proof does not match the Machine-authenticated owner pin');
  }
  const sig = Buffer.from(proof.signature, 'base64');
  const bytes = Buffer.from(['agent-bot-machine-owner/v1', c.action, c.machine_key, c.hq_key, c.owner_key,
    c.plan_id, c.plan_digest, c.nonce, c.expires_at, ''].join('\n'));
  if (!sig.length || sig.length > 72 || sig.toString('base64') !== proof.signature ||
      !verify('sha256', bytes, ownerPublicKey(c.owner_key), sig)) {
    throw new Error('invalid owner signature on the Machine service challenge');
  }
  return proof.signature;
}

function utcSecond(value) {
  if (typeof value !== 'string' || !/^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$/.test(value)) return NaN;
  const t = Date.parse(value);
  return Number.isFinite(t) && new Date(t).toISOString().replace('.000Z', 'Z') === value ? t : NaN;
}

export async function serviceHandoff(action, args, machine, hq, send, authenticateStored, roleUid) {
  if (args.operation === 'export') {
    const { response } = await send({ verb: 'members-plans', option: 'get', plan_id: args.id });
    checkPlanScope(validatedMembersPlan(args.id, response), action, args.id, roleUid);
    const saved = response.body;
    const issued = await send({ verb: action, option: 'challenge', plan_id: saved.plan_id, plan_digest: saved.plan_digest });
    const c = validatedChallenge(issued.response, machine, hq, action, roleUid);
    if (c.plan_id !== saved.plan_id || c.plan_digest !== saved.plan_digest || c.plan_canonical !== saved.plan_canonical) {
      throw new Error('Machine service challenge differs from the retrieved plan');
    }
    return issued.line;
  }
  const line = readTransfer(args.challengeFile, maxFrame + 1).replace(/\n$/, '');
  if (!line.length || /[\r\n]/.test(line) || Buffer.byteLength(line) > maxFrame) throw new Error('expected one signed Machine response line');
  const c = validatedChallenge(authenticateStored(line), machine, hq, action, roleUid);
  const request = { verb: action, option: args.operation, plan_id: c.plan_id, plan_digest: c.plan_digest, challenge_nonce: c.nonce };
  const approving = args.operation === 'approve';
  if (approving) request.owner_signature = ownerSignature(c, args.proofFile);
  const { response } = await send(request);
  const body = response.body;
  if (response.state !== (approving ? 'approved' : 'cancelled') ||
      !fieldsAre(body, approving ? ['plan_id', 'plan_digest', 'approved_at', 'expires_at'] : ['plan_id', 'plan_digest']) ||
      body.plan_id !== c.plan_id || body.plan_digest !== c.plan_digest ||
      (approving && (utcSecond(body.expires_at) - utcSecond(body.approved_at) !== 600000 ||
        utcSecond(body.expires_at) <= Date.now() || utcSecond(body.approved_at) > (response.timestamp + 1) * 1000))) {
    throw new Error('Machine service response does not match the submitted plan');
  }
  return { state: response.state, ...body };
}
