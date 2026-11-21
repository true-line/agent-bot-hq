import { test } from 'node:test';
import assert from 'node:assert/strict';
import { request as httpRequest } from 'node:http';
import { chmodSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { bindProof } from '../sdk/member-session.mjs';
import { referenceBroker } from './broker-fixture.mjs';
import { hello, startHQ, tempHome } from './hq-harness.mjs';
import { qualificationProvider, qualificationPromptDigest } from '../hq/qualification-provider.mjs';
import { startClaudeQualificationHttp } from '../hq/claude-qualification-http.mjs';

const MODEL = 'claude-haiku-4-5-20251001';
const PROMPT = 'Return the Stage 2a fixture response.';

async function http(socketPath, method, path, body) {
  const encoded = body === undefined ? undefined : Buffer.from(JSON.stringify(body));
  return new Promise((resolve, reject) => {
    const req = httpRequest({ socketPath, method, path,
      headers: encoded ? { 'content-type': 'application/json', 'content-length': encoded.length, 'x-api-key': 'inert-placeholder' } : {} }, (res) => {
      const chunks = []; res.on('data', (chunk) => chunks.push(chunk)); res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks).toString('utf8') }));
    });
    req.on('error', reject); req.end(encoded);
  });
}

test('stock Messages HTTP reaches only a bound, one-use HQ qualification consumer', async (t) => {
  let expectedRuntime;
  const decisions = [];
  const plan = { plan_digest: 'a'.repeat(64), model: MODEL, prompt_sha256: qualificationPromptDigest(PROMPT), response_text: 'Stage 2a brokered fixture turn.', expires_at_ms: Date.now() + 60_000 };
  const provider = qualificationProvider({ plan, async authorize(input) {
    decisions.push(input);
    return input.runtime_id === expectedRuntime && input.model === MODEL && input.prompt_sha256 === plan.prompt_sha256;
  } });
  const world = await startHQ({ plugins: [referenceBroker(), provider] });
  const dir = mkdtempSync(join(tmpdir(), 'hq-qualification-http-'));
  chmodSync(dir, 0o700);
  t.after(async () => { await world.done(); rmSync(dir, { recursive: true, force: true }); });
  const entry = await world.entry();
  const admitted = await entry.request('Hello', hello({ request_id: 'qualification_1' }));
  assert.equal(admitted.ok, true);
  const runtime = admitted.result.admitted_runtimes[0];
  expectedRuntime = runtime.runtime_id;
  const member = await world.member();
  const unbound = await world.member();
  const denied = await unbound.request('qualification.messages', { model: MODEL, prompt_sha256: plan.prompt_sha256 });
  assert.equal(denied.ok, false);
  assert.equal(denied.refusal?.error, 'caller_mismatch');
  const challenge = await member.request('bind.challenge', { runtime_id: expectedRuntime });
  assert.equal(challenge.ok, true);
  const bound = await member.request('bind', { runtime_id: expectedRuntime, proof: bindProof(runtime.channel_binding, challenge.result.nonce, expectedRuntime) });
  assert.equal(bound.ok, true);
  const memberSession = { capture: async () => ({ request: async (kind, payload) => {
    const result = await member.request(kind, payload);
    if (!result.ok) throw new Error(JSON.stringify(result));
    return result.result;
  } }) };
  const bridge = await startClaudeQualificationHttp({ socketPath: join(dir, 'broker.sock'), memberSession, plan: { model: MODEL, prompt: PROMPT } });
  t.after(() => bridge.close());
  const policy = await http(bridge.socketPath, 'GET', '/api/claude_code/policy_limits');
  assert.equal(policy.status, 200);
  assert.deepEqual(JSON.parse(policy.body), { policy_limits: {}, restrictions: {}, compliance_taints: [] });
  const ancillary = await http(bridge.socketPath, 'POST', '/v1/messages', { model: MODEL, stream: true, messages: [{ role: 'user', content: 'unrelated' }] });
  assert.equal(ancillary.status, 422);
  const malformed = await http(bridge.socketPath, 'POST', '/v1/messages', { model: MODEL, stream: true, messages: { role: 'user', content: PROMPT } });
  assert.equal(malformed.status, 422);
  assert.equal(decisions.length, 0);
  const message = { model: MODEL, stream: true, max_tokens: 32000, system: 'x'.repeat(87_000), tools: [], messages: [{ role: 'user', content: [{ type: 'text', text: PROMPT }] }] };
  const turn = await http(bridge.socketPath, 'POST', '/v1/messages?beta=test', message);
  assert.equal(turn.status, 200);
  assert.match(turn.body, /event: message_start/);
  assert.match(turn.body, /Stage 2a brokered fixture turn/);
  assert.match(turn.body, /event: message_stop/);
  assert.equal(decisions.length, 1);
  assert.equal(decisions[0].plan_digest, plan.plan_digest);
  assert.equal(decisions[0].runtime_id, expectedRuntime);
  const replay = await http(bridge.socketPath, 'POST', '/v1/messages', message);
  assert.equal(replay.status, 403);
  assert.equal(decisions.length, 1);
});

test('unconfigured or malformed qualification plans fail closed', () => {
  assert.throws(() => qualificationProvider({}), /requires an exact plan/);
  assert.throws(() => qualificationProvider({ plan: { plan_digest: 'a'.repeat(64), model: MODEL, prompt_sha256: qualificationPromptDigest(PROMPT), response_text: 'x', expires_at_ms: Date.now() + 1000 } }), /Machine authorization callback/);
});

test('a consumed qualification plan stays consumed after HQ restart', async (t) => {
  const home = tempHome();
  const plan = { plan_digest: 'b'.repeat(64), model: MODEL, prompt_sha256: qualificationPromptDigest(PROMPT),
    response_text: 'one-use result', expires_at_ms: Date.now() + 60_000 };
  const plugins = () => [referenceBroker(), qualificationProvider({ plan, authorize: async () => true })];
  const first = await startHQ({ home, plugins: plugins() });
  const entry = await first.entry();
  const admitted = await entry.request('Hello', hello({ request_id: 'qualification_restart' }));
  assert.equal(admitted.ok, true);
  const runtime = admitted.result.admitted_runtimes[0];
  const payload = { model: MODEL, prompt_sha256: plan.prompt_sha256 };
  const bind = async (world) => {
    const member = await world.member();
    const challenge = await member.request('bind.challenge', { runtime_id: runtime.runtime_id });
    assert.equal(challenge.ok, true);
    const confirmed = await member.request('bind', { runtime_id: runtime.runtime_id,
      proof: bindProof(runtime.channel_binding, challenge.result.nonce, runtime.runtime_id) });
    assert.equal(confirmed.ok, true);
    return member;
  };
  const initial = await bind(first);
  const accepted = await initial.request('qualification.messages', payload);
  assert.equal(accepted.ok, true);
  await first.done({ keep: true });
  const second = await startHQ({ home, plugins: plugins() });
  t.after(async () => { await second.done({ keep: true }); rmSync(home, { recursive: true, force: true }); });
  const replay = await (await bind(second)).request('qualification.messages', payload);
  assert.equal(replay.ok, false);
  assert.equal(replay.refusal?.error ?? replay.host_refusal?.code, 'host.invalid_request', JSON.stringify(replay));
});
