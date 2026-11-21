// Stage 2a qualification only. A caller must inject a verified, one-use
// Machine plan and its exact pinned test-provider config bytes. This plugin
// does not accept a plan or a response from a member.
// Production HQ does not install this plugin without an explicit plan.
import { createHash } from 'node:crypto';
import { definePlugin } from '../sdk/plugin.mjs';
import { fail } from '../sdk/errors.mjs';
import { parseStrict } from '../sdk/wire/strict-json.mjs';

const digest = (value) => `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
const SHA256 = /^[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export function qualificationProvider({ plan, providerConfigBytes, authorize, now = () => Date.now() } = {}) {
  if (!plan || typeof plan !== 'object' || Array.isArray(plan)
    || typeof plan.plan_id !== 'string' || !ID.test(plan.plan_id)
    || typeof plan.plan_digest !== 'string' || !SHA256.test(plan.plan_digest)
    || typeof plan.provider_config_sha256 !== 'string' || !SHA256.test(plan.provider_config_sha256)
    || !Number.isSafeInteger(plan.expires_at_ms) || plan.expires_at_ms <= 0
    || typeof authorize !== 'function') throw new TypeError('qualification provider requires an exact plan and Machine authorization callback');
  if (!Buffer.isBuffer(providerConfigBytes) || providerConfigBytes.length < 1 || providerConfigBytes.length > 65536
    || createHash('sha256').update(providerConfigBytes).digest('hex') !== plan.provider_config_sha256) {
    throw new TypeError('qualification provider config bytes differ from the Machine pin');
  }
  let config;
  try { config = parseStrict(new TextDecoder('utf-8', { fatal: true }).decode(providerConfigBytes)); }
  catch { throw new TypeError('qualification provider config is not strict UTF-8 JSON'); }
  if (!config || typeof config !== 'object' || Array.isArray(config)
    || Object.keys(config).sort().join(',') !== 'model,prompt,response_text'
    || typeof config.model !== 'string' || !ID.test(config.model)
    || typeof config.prompt !== 'string' || !config.prompt || config.prompt.length > 4096
    || typeof config.response_text !== 'string' || !config.response_text || config.response_text.length > 4096) {
    throw new TypeError('qualification provider config needs exact model, prompt and response_text');
  }
  plan = Object.freeze({ plan_id: plan.plan_id, plan_digest: plan.plan_digest,
    provider_config_sha256: plan.provider_config_sha256, model: config.model,
    prompt_sha256: digest(config.prompt), response_text: config.response_text,
    expires_at_ms: plan.expires_at_ms });
  let used = false;
  return definePlugin({
    name: 'hq-qualification-provider', version: '0.1.0', hostApi: 1,
    requires: { 'hq-admission': '^0.1.0' },
    services: ['store'],
    async init(ctx) {
      const store = ctx.services.store;
      ctx.broker.registerKind({ kind: 'qualification.messages', async consume(message, meta) {
        if (!message || typeof message !== 'object' || Array.isArray(message)
          || Object.keys(message).sort().join(',') !== 'model,prompt_sha256'
          || message.model !== plan.model || message.prompt_sha256 !== plan.prompt_sha256) {
          fail('host.invalid_request', 'Messages request differs from the one-use qualification plan');
        }
        return ctx.deps['hq-admission'].withBoundRuntime(meta.runtime_id, (runtime) => store.tx(async (tx) => {
          if (now() > plan.expires_at_ms) fail('lease_expired', 'qualification plan expired');
          if (used || tx.has('used_plans', plan.plan_digest)) fail('host.invalid_request', 'qualification plan was already consumed');
          if (await authorize({ plan_id: plan.plan_id, plan_digest: plan.plan_digest,
            provider_config_sha256: plan.provider_config_sha256, runtime_id: meta.runtime_id,
            runtime, model: message.model, prompt_sha256: message.prompt_sha256 }) !== true) {
            fail('caller_mismatch', 'Machine did not authorize this bound runtime and request');
          }
          if (now() > plan.expires_at_ms) fail('lease_expired', 'qualification plan expired during authorization');
          tx.put('used_plans', plan.plan_digest, { plan_id: plan.plan_id, runtime_id: meta.runtime_id, prompt_sha256: message.prompt_sha256, consumed_at_ms: now() });
          return { model: plan.model, text: plan.response_text, stop_reason: 'end_turn', usage: { input_tokens: 7, output_tokens: 3 } };
        })).then((result) => { used = true; return result; });
      } });
    },
  });
}

export const qualificationPromptDigest = digest;
