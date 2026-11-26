import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import test from 'node:test';
import { canonicalize } from '../sdk/wire/canonical-json.mjs';
import { createStage2aQualificationProvider, stage2aLocalProviderPort }
  from '../hq/stage2a-qualification-provider.mjs';

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

test('installed B ingress reaches the local service once with exact selectors', async (t) => {
  const calls = [];
  const provider = createStage2aQualificationProvider({ plan, now: () => 1_000,
    machineProvide: async (input) => { calls.push(input); return reply(); } });
  t.after(() => provider.close());
  await provider.ready;
  assert.equal(stage2aLocalProviderPort(plan), 58878);
  assert.equal(provider.port, 58878);
  const before = await provider.probeReachability();
  assert.equal(before.ipv4.url, `http://127.0.0.1:${provider.port}/stage2a/local-provider/v1/observation`);
  assert.equal(before.ipv6.url, `http://[::1]:${provider.port}/stage2a/local-provider/v1/observation`);
  assert.equal(before.ipv4.invocations, 0);
  assert.equal(before.ipv4.traffic.ipv4.observation_gets, 1);
  assert.equal(before.ipv6.traffic.ipv6.observation_gets, 1);
  const endpoint = `http://127.0.0.1:${provider.port}/stage2a/local-provider/v1`;
  const getServiceObservation = () => fetch(`${endpoint}/observation`).then((response) => response.json());
  assert.equal((await getServiceObservation()).invocations, 0);
  const wrongBody = canonicalize({ model, request_sha256: digest('wrong request') });
  const wrong = await fetch(endpoint, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: wrongBody });
  assert.equal(wrong.status, 403);
  assert.equal((await getServiceObservation()).invocations, 0);
  const result = await provider({ request, observation });
  assert.deepEqual(result, { model, stop_reason: 'end_turn', text: responseText,
    usage: { input_tokens: 7, output_tokens: 3 } });
  const providerReceipt = provider.invocationReceipt();
  assert.equal(providerReceipt.url, `http://127.0.0.1:${provider.port}/stage2a/local-provider/v1`);
  assert.equal(providerReceipt.request_body_sha256, digest(Buffer.from(canonicalize({ model,
    request_sha256: requestSHA256 }))));
  assert.equal(providerReceipt.provider_config_sha256, plan.provider_config_sha256);
  assert.ok(providerReceipt.responded_at_ms >= providerReceipt.requested_at_ms);
  assert.ok(providerReceipt.response_body_bytes > 0);
  assert.deepEqual(calls, [{ reservation_sha256: plan.reservation_sha256,
    installation_id: plan.installation_id, start_id: plan.start_id,
    launch_id: plan.launch_id, plan_id: plan.plan_id, plan_digest: plan.plan_digest,
    hq_epoch: plan.hq_epoch, bind_receipt_sha256: observation.bind_receipt_sha256,
    model, prompt_sha256: requestSHA256 }]);
  await assert.rejects(provider({ request, observation }), /already spent/);
  assert.equal(calls.length, 1);
  const observed = await getServiceObservation();
  assert.equal(observed.invocations, 1);
  assert.equal(observed.last_request_sha256, requestSHA256);
  assert.equal(observed.last_response_sha256, digest(responseText));
  const after = await provider.probeReachability();
  assert.equal(after.ipv4.invocations, 1);
  assert.equal(after.ipv6.invocations, 1);
  assert.equal(after.ipv4.last_response_sha256, digest(responseText));
  const direct = await fetch(`http://[::1]:${provider.port}/v1/messages`, { method: 'POST',
    body: '{}' });
  assert.equal(direct.status, 400);
  const afterDirect = await provider.probeReachability();
  assert.equal(afterDirect.ipv6.traffic.ipv6.other_http_requests,
    after.ipv6.traffic.ipv6.other_http_requests + 1);
  assert.equal(afterDirect.ipv6.traffic.ipv6.tcp_accepted,
    after.ipv6.traffic.ipv6.tcp_accepted + 2);
  const replay = await fetch(endpoint, { method: 'POST', headers: { 'content-type': 'application/json' },
    body: canonicalize({ model, request_sha256: requestSHA256 }) });
  assert.equal(replay.status, 403);
  assert.equal((await getServiceObservation()).invocations, 1);
  await provider.close();
  await assert.rejects(fetch(`${endpoint}/observation`), /fetch failed/);
});

test('a colliding local service refuses a second protected start', async (t) => {
  const first = createStage2aQualificationProvider({ plan, machineProvide: async () => reply() });
  t.after(() => first.close());
  await first.ready;
  const second = createStage2aQualificationProvider({ plan, machineProvide: async () => reply() });
  t.after(() => second.close());
  await assert.rejects(second.ready, /EADDRINUSE/);
});

test('wrong B observation spends the attempt without provider dispatch', async (t) => {
  let calls = 0;
  const provider = createStage2aQualificationProvider({ plan, now: () => 1_000,
    machineProvide: async () => { calls++; return reply(); } });
  t.after(() => provider.close());
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
  await altered.close();
  const expired = createStage2aQualificationProvider({ plan, now: () => 5_001,
    machineProvide: async () => reply() });
  await assert.rejects(expired({ request, observation }), /differs from its signed installed pin/);
  await expired.close();
});
