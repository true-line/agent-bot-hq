// Stage 2a qualification only. A caller must inject a verified, one-use
// Machine plan; this plugin does not accept a plan or a response from a member.
// Production HQ does not install this plugin without an explicit plan.
import { createHash } from 'node:crypto';
import { definePlugin } from '../sdk/plugin.mjs';
import { fail } from '../sdk/errors.mjs';

const digest = (value) => `sha256:${createHash('sha256').update(value, 'utf8').digest('hex')}`;
const HEX_DIGEST = /^sha256:[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

export function qualificationProvider({ plan, authorize, now = () => Date.now() } = {}) {
  if (!plan || typeof plan !== 'object' || Array.isArray(plan)
    || typeof plan.model !== 'string' || !ID.test(plan.model)
    || typeof plan.prompt_sha256 !== 'string' || !HEX_DIGEST.test(plan.prompt_sha256)
    || typeof plan.response_text !== 'string' || !plan.response_text || plan.response_text.length > 4096
    || !Number.isSafeInteger(plan.expires_at_ms) || plan.expires_at_ms <= 0
    || typeof authorize !== 'function') throw new TypeError('qualification provider requires an exact plan and Machine authorization callback');
  plan = Object.freeze({ model: plan.model, prompt_sha256: plan.prompt_sha256,
    response_text: plan.response_text, expires_at_ms: plan.expires_at_ms });
  let used = false;
  return definePlugin({
    name: 'hq-qualification-provider', version: '0.1.0', hostApi: 1,
    requires: { 'hq-admission': '^0.1.0' },
    async init(ctx) {
      ctx.broker.registerKind({ kind: 'qualification.messages', async consume(message, meta) {
        if (!message || typeof message !== 'object' || Array.isArray(message)
          || Object.keys(message).sort().join(',') !== 'model,prompt_sha256'
          || message.model !== plan.model || message.prompt_sha256 !== plan.prompt_sha256) {
          fail('host.invalid_request', 'Messages request differs from the one-use qualification plan');
        }
        return ctx.deps['hq-admission'].withBoundRuntime(meta.runtime_id, async (runtime) => {
          if (now() > plan.expires_at_ms) fail('lease_expired', 'qualification plan expired');
          if (used) fail('host.invalid_request', 'qualification plan was already consumed');
          if (await authorize({ runtime_id: meta.runtime_id, runtime, model: message.model, prompt_sha256: message.prompt_sha256 }) !== true) {
            fail('caller_mismatch', 'Machine did not authorize this bound runtime and request');
          }
          if (now() > plan.expires_at_ms) fail('lease_expired', 'qualification plan expired during authorization');
          used = true; // Consume before returning; a retry cannot repeat the turn.
          return { model: plan.model, text: plan.response_text, stop_reason: 'end_turn', usage: { input_tokens: 7, output_tokens: 3 } };
        });
      } });
    },
  });
}

export const qualificationPromptDigest = digest;
