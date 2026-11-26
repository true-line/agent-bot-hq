// Owner-control handoff for A's distinct local-test Q approval. Machine owns
// the private Q source, owner approval, pair check, and signing key. HQ only
// selects its reviewed Q plan ID and checks the signed result before release.
import { createHash } from 'node:crypto';
import { validPlanId } from './machine-members-plans.mjs';
import { canonicalDigest } from '../sdk/wire/canonical-json.mjs';
import { fail } from '../sdk/errors.mjs';
import { verifyStage2aMachineEnvelope } from './stage2a-stop.mjs';

const PURPOSE = 'agent-bot/stage2a-observed-body-local-test-q-approval/v1';
const SCHEMA = 'agent-bot-machine/stage2a-observed-body-local-test-q-approval/v1';
const Q_SCHEMA = 'agent-bot-machine/stage2a-observed-body-local-test-q/v1';
const Q_PURPOSE = 'stage2a-observed-body-local-test-qualification/v1';
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const INSTALLATION = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const exact = (value, fields) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...fields].sort().join(',');
const refuse = () => { throw new Error('invalid signed Machine local-test Q approval'); };

export function createStage2aLocalTestQIssuer({ exchange, machinePublicKey }) {
  if (typeof exchange !== 'function' || !Buffer.isBuffer(machinePublicKey)
    || machinePublicKey.length !== 32) throw new TypeError('Q issue requires the paired Machine key and exchange');
  const key = Buffer.from(machinePublicKey);
  const machineFingerprint = createHash('sha256').update(key).digest('hex');
  return async function issueLocalTestQ(payload) {
    if (!exact(payload, ['plan_id', 'installation_id'])
      || !validPlanId(payload.plan_id) || !INSTALLATION.test(payload.installation_id)) {
      fail('host.invalid_request', 'local-test Q issue needs one reviewed plan_id and installation_id');
    }
    const reply = await exchange(payload.plan_id);
    if (!exact(reply, ['plan_id', 'plan_sha256', 'approval_envelope_base64url',
      'approval_envelope_sha256', 'daemon_fingerprint'])
      || reply.plan_id !== payload.plan_id || !DIGEST.test(reply.plan_sha256)
      || !DIGEST.test(reply.approval_envelope_sha256)
      || reply.daemon_fingerprint !== machineFingerprint
      || typeof reply.approval_envelope_base64url !== 'string'
      || !/^[A-Za-z0-9_-]{1,10923}$/.test(reply.approval_envelope_base64url)) refuse();
    const envelope = Buffer.from(reply.approval_envelope_base64url, 'base64url');
    if (envelope.toString('base64url') !== reply.approval_envelope_base64url) refuse();
    const signed = verifyStage2aMachineEnvelope(envelope, key, PURPOSE);
    const q = signed.payload;
    if (signed.envelope_sha256 !== reply.approval_envelope_sha256
      || !exact(q, ['schema', 'kind', 'schema_version', 'plan', 'plan_sha256',
        'approval_reference', 'machine_fingerprint', 'issued_at', 'expires_at'])
      || q.schema !== SCHEMA || q.kind !== 'observed-body-local-test-q-approval'
      || q.schema_version !== 1 || !exact(q.plan, ['schema', 'purpose', 'host_uuid',
        'installation_id', 'installed_plan_id', 'installed_plan_digest',
        'owner_plan_sha256', 'source_revision', 'candidate_manifest_sha256',
        'driver_plan_sha256', 'a_key_id', 'expires_at'])
      || q.plan.schema !== Q_SCHEMA || q.plan.purpose !== Q_PURPOSE
      || q.plan.installation_id !== payload.installation_id
      || !validPlanId(q.plan.installed_plan_id)
      || !/^[0-9a-f]{64}$/.test(q.plan.installed_plan_digest)
      || !DIGEST.test(q.plan.owner_plan_sha256)
      || q.plan.a_key_id !== `sha256:${machineFingerprint}`
      || q.machine_fingerprint !== machineFingerprint
      || !exact(q.approval_reference, ['plan_id', 'plan_digest', 'pair_commitment'])
      || q.approval_reference.plan_id !== payload.plan_id
      || !/^[0-9a-f]{64}$/.test(q.approval_reference.pair_commitment)
      || q.approval_reference.plan_digest !== reply.plan_sha256.slice(7)
      || q.plan_sha256 !== reply.plan_sha256
      || canonicalDigest(q.plan) !== q.plan_sha256) refuse();
    // Machine's root staging command strictly decodes the four-field issue reply.
    return Object.freeze({
      plan_id: reply.plan_id,
      plan_sha256: reply.plan_sha256,
      approval_envelope_base64url: reply.approval_envelope_base64url,
      approval_envelope_sha256: reply.approval_envelope_sha256,
    });
  };
}
