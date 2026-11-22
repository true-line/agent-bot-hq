// The pinned qualification response is disclosed by Machine only after its
// durable one-use claim and current finalized B lease checks succeed.
import { createHash } from 'node:crypto';
import { parseStrict } from '../sdk/wire/strict-json.mjs';
import { canonicalize } from '../sdk/wire/canonical-json.mjs';
import { machineRoleStage2aProvider } from './machine-channel.mjs';

const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const START = /^st_[0-9a-f]{24}$/;
const LAUNCH = /^ln_[0-9a-f]{24}$/;
const SHA = /^[0-9a-f]{64}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');

export function createStage2aQualificationProvider({ plan, machineProvide = machineRoleStage2aProvider,
  now = () => Date.now() } = {}) {
  const fields = ['installation_id', 'start_id', 'launch_id', 'hq_epoch', 'plan_id', 'plan_digest',
    'reservation_sha256', 'soul_artifact_sha256', 'provider_config_sha256'];
  if (!exact(plan, fields) || !ID.test(plan.installation_id) || !START.test(plan.start_id)
    || !LAUNCH.test(plan.launch_id) || !SHA.test(plan.hq_epoch) || !ID.test(plan.plan_id)
    || !SHA.test(plan.plan_digest) || !DIGEST.test(plan.reservation_sha256)
    || !DIGEST.test(plan.soul_artifact_sha256) || !SHA.test(plan.provider_config_sha256)
    || typeof machineProvide !== 'function' || typeof now !== 'function') {
    throw new TypeError('qualification provider needs a signed installed plan and paired Machine client');
  }
  const expected = Object.freeze({ ...plan });
  let attempted = false;
  return async ({ request, observation } = {}) => {
    if (attempted) throw new Error('qualification provider attempt already spent');
    attempted = true;
    if (!exact(request, ['model', 'prompt_sha256']) || !ID.test(request.model)
      || !DIGEST.test(request.prompt_sha256)
      || !observation || typeof observation !== 'object'
      || !['installation_id', 'start_id', 'launch_id', 'hq_epoch', 'plan_id', 'plan_digest',
        'reservation_digest', 'soul_artifact_sha256'].every((field) =>
        observation[field] === expected[field === 'reservation_digest' ? 'reservation_sha256' : field])
      || !DIGEST.test(observation.bind_receipt_sha256 ?? '')) {
      throw new Error('qualification request differs from the signed installed plan');
    }
    const provided = await machineProvide({ reservation_sha256: expected.reservation_sha256,
      installation_id: expected.installation_id, start_id: expected.start_id,
      launch_id: expected.launch_id, plan_id: expected.plan_id, plan_digest: expected.plan_digest,
      hq_epoch: expected.hq_epoch, bind_receipt_sha256: observation.bind_receipt_sha256,
      model: request.model, prompt_sha256: request.prompt_sha256 });
    const configBytes = Buffer.from(provided?.config_base64url ?? '', 'base64url');
    let config;
    try { config = parseStrict(new TextDecoder('utf-8', { fatal: true }).decode(configBytes)); }
    catch { throw new Error('Machine qualification config is not strict UTF-8 JSON'); }
    if (!exact(config, ['model', 'request_sha256', 'response_text'])
      || config.model !== request.model || config.request_sha256 !== request.prompt_sha256
      || config.response_text !== provided.response_text
      || typeof config.response_text !== 'string' || !config.response_text
      || config.response_text.length > 4096
      || !Buffer.from(canonicalize(config)).equals(configBytes)
      || sha(configBytes) !== expected.provider_config_sha256
      || provided.provider_config_sha256 !== expected.provider_config_sha256
      || provided.model !== request.model || provided.request_sha256 !== request.prompt_sha256
      || !Number.isSafeInteger(provided.expires_at_ms) || now() > provided.expires_at_ms) {
      throw new Error('Machine qualification response differs from its signed installed pin');
    }
    return Object.freeze({ model: config.model, stop_reason: 'end_turn', text: config.response_text,
      usage: Object.freeze({ input_tokens: 7, output_tokens: 3 }) });
  };
}
