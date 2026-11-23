import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { canonicalize } from '../sdk/wire/canonical-json.mjs';
import { createStage2aQualificationProvider } from '../hq/stage2a-qualification-provider.mjs';

const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const digest = (bytes) => `sha256:${sha(bytes)}`;
const model = 'claude-haiku-4-5-20251001';
const requestSHA256 = digest('installed normalized Messages request');
const responseText = 'local provider response';
const configBytes = Buffer.from(canonicalize({ model, request_sha256: requestSHA256,
  response_text: responseText }));
const plan = Object.freeze({ installation_id: 'installation-1', start_id: `st_${'a'.repeat(24)}`,
  launch_id: `ln_${'b'.repeat(24)}`, hq_epoch: 'c'.repeat(64), plan_id: 'plan-1',
  plan_digest: 'd'.repeat(64), reservation_sha256: digest('reservation'),
  soul_artifact_sha256: digest('soul'), provider_config_sha256: sha(configBytes) });
const observation = Object.freeze({ ...plan, reservation_digest: plan.reservation_sha256,
  bind_receipt_sha256: digest('B bind') });
const request = Object.freeze({ model, prompt_sha256: requestSHA256 });

function reply(expiresAt = 5_000) {
  return { model, request_sha256: requestSHA256, response_text: responseText,
    provider_config_sha256: plan.provider_config_sha256,
    config_base64url: configBytes.toString('base64url'), expires_at_ms: expiresAt };
}

test('installed B ingress spends one Machine provider response with exact selectors', async () => {
  const calls = [];
  const provider = createStage2aQualificationProvider({ plan, now: () => 1_000,
    machineProvide: async (input) => { calls.push(input); return reply(); } });
  const result = await provider({ request, observation });
  assert.deepEqual(result, { model, stop_reason: 'end_turn', text: responseText,
    usage: { input_tokens: 7, output_tokens: 3 } });
  assert.deepEqual(calls, [{ reservation_sha256: plan.reservation_sha256,
    installation_id: plan.installation_id, start_id: plan.start_id,
    launch_id: plan.launch_id, plan_id: plan.plan_id, plan_digest: plan.plan_digest,
    hq_epoch: plan.hq_epoch, bind_receipt_sha256: observation.bind_receipt_sha256,
    model, prompt_sha256: requestSHA256 }]);
  await assert.rejects(provider({ request, observation }), /already spent/);
  assert.equal(calls.length, 1);
});

test('wrong B observation spends the attempt without provider dispatch', async () => {
  let calls = 0;
  const provider = createStage2aQualificationProvider({ plan, now: () => 1_000,
    machineProvide: async () => { calls++; return reply(); } });
  await assert.rejects(provider({ request, observation: {
    ...observation, reservation_digest: digest('another start'),
  } }), /differs from the signed installed plan/);
  await assert.rejects(provider({ request, observation }), /already spent/);
  assert.equal(calls, 0);
});

test('altered or expired Machine provider bytes are refused', async () => {
  const altered = createStage2aQualificationProvider({ plan, now: () => 1_000,
    machineProvide: async () => ({ ...reply(), response_text: 'changed' }) });
  await assert.rejects(altered({ request, observation }), /differs from its signed installed pin/);
  const expired = createStage2aQualificationProvider({ plan, now: () => 5_001,
    machineProvide: async () => reply() });
  await assert.rejects(expired({ request, observation }), /differs from its signed installed pin/);
});
