// Stage 2a qualification only. A caller must inject a verified, one-use
// Machine plan; this plugin does not accept a plan or a response from a member.
// Production HQ does not install this plugin without an explicit plan.
import { createHash } from 'node:crypto';
import { definePlugin } from '../sdk/plugin.mjs';
import { fail } from '../sdk/errors.mjs';

const digest = (value) => `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
const HEX_DIGEST = /^sha256:[0-9a-f]{64}$/;
const PLAN_DIGEST = /^[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export function qualificationProvider({ plan, authorize, now = () => Date.now() } = {}) {
  if (!plan || typeof plan !== 'object' || Array.isArray(plan)
    || typeof plan.plan_id !== 'string' || !ID.test(plan.plan_id)
    || typeof plan.plan_digest !== 'string' || !PLAN_DIGEST.test(plan.plan_digest)
    || typeof plan.model !== 'string' || !ID.test(plan.model)
    || typeof plan.prompt_sha256 !== 'string' || !HEX_DIGEST.test(plan.prompt_sha256)
    || typeof plan.response_text !== 'string' || !plan.response_text || plan.response_text.length > 4096
    || !Number.isSafeInteger(plan.expires_at_ms) || plan.expires_at_ms <= 0
    || typeof authorize !== 'function') throw new TypeError('qualification provider requires an exact plan and Machine authorization callback');
  plan = Object.freeze({ plan_id: plan.plan_id, plan_digest: plan.plan_digest, model: plan.model, prompt_sha256: plan.prompt_sha256,
    response_text: plan.response_text, expires_at_ms: plan.expires_at_ms });
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
          if (await authorize({ plan_id: plan.plan_id, plan_digest: plan.plan_digest, runtime_id: meta.runtime_id, runtime, model: message.model, prompt_sha256: message.prompt_sha256 }) !== true) {
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
