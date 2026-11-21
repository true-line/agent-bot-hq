import { test } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { bindProof } from '../sdk/member-session.mjs';
import { referenceBroker } from './broker-fixture.mjs';
import { hello, startHQ, tempHome } from './hq-harness.mjs';
import { qualificationProvider, qualificationPromptDigest } from '../hq/qualification-provider.mjs';
import { startClaudeQualificationHttp } from '../hq/claude-qualification-http.mjs';

const MODEL = 'claude-haiku-4-5-20251001';
const PROMPT = 'Return the Stage 2a fixture response.';
const providerBytes = (response_text) => Buffer.from(JSON.stringify({ model: MODEL, prompt: PROMPT, response_text }));
const providerPin = (bytes) => createHash('sha256').update(bytes).digest('hex');

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
  const config = providerBytes('Stage 2a brokered fixture turn.');
  const plan = { plan_id: 'plan-qualification-a', plan_digest: 'a'.repeat(64), provider_config_sha256: providerPin(config), expires_at_ms: Date.now() + 60_000 };
  const provider = qualificationProvider({ plan, providerConfigBytes: config, async authorize(input) {
    decisions.push(input);
    return input.runtime_id === expectedRuntime && input.model === MODEL
      && input.prompt_sha256 === qualificationPromptDigest(PROMPT)
      && input.provider_config_sha256 === plan.provider_config_sha256;
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
  const denied = await unbound.request('qualification.messages', { model: MODEL, prompt_sha256: qualificationPromptDigest(PROMPT) });
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
  const bridge = await startClaudeQualificationHttp({ socketPath: join(dir, 'broker.sock'), peerUid: process.getuid(), memberSession, plan: { model: MODEL, prompt: PROMPT } });
  t.after(() => bridge.close());
  const shared = join(dir, 'shared');
  mkdirSync(shared);
  chmodSync(shared, 0o2770);
  await assert.rejects(startClaudeQualificationHttp({ socketPath: join(shared, 'refused.sock'), peerUid: process.getuid() + 1,
    groupGid: process.getgid(), memberSession, plan: { model: MODEL, prompt: PROMPT } }), /reviewed UID, group or mode/);
  chmodSync(shared, 0o2750);
  const wrongPeerBridge = await startClaudeQualificationHttp({ socketPath: join(shared, 'broker.sock'), peerUid: process.getuid() + 1,
    groupGid: process.getgid(), memberSession, plan: { model: MODEL, prompt: PROMPT } });
  t.after(() => wrongPeerBridge.close());
  assert.equal(statSync(wrongPeerBridge.socketPath).mode & 0o777, 0o660);
  assert.equal(statSync(wrongPeerBridge.socketPath).gid, process.getgid());
  assert.equal((await http(wrongPeerBridge.socketPath, 'GET', '/api/claude_code/policy_limits')).status, 403);
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
  assert.equal(decisions[0].plan_id, plan.plan_id);
  assert.equal(decisions[0].plan_digest, plan.plan_digest);
  assert.equal(decisions[0].provider_config_sha256, plan.provider_config_sha256);
  assert.equal(decisions[0].runtime_id, expectedRuntime);
  const replay = await http(bridge.socketPath, 'POST', '/v1/messages', message);
  assert.equal(replay.status, 403);
  assert.equal(decisions.length, 1);
});

test('unconfigured or malformed qualification plans fail closed', () => {
  assert.throws(() => qualificationProvider({}), /requires an exact plan/);
  const config = providerBytes('x');
  const plan = { plan_id: 'plan-qualification-a', plan_digest: 'a'.repeat(64), provider_config_sha256: providerPin(config), expires_at_ms: Date.now() + 1000 };
  assert.throws(() => qualificationProvider({ plan, providerConfigBytes: config }), /Machine authorization callback/);
  assert.throws(() => qualificationProvider({ plan: { ...plan, provider_config_sha256: '0'.repeat(64) }, providerConfigBytes: config, authorize: async () => true }), /differ from the Machine pin/);
  assert.throws(() => qualificationProvider({ plan, providerConfigBytes: Buffer.from('{"model":"changed"}'), authorize: async () => true }), /differ from the Machine pin/);
  const duplicate = Buffer.from('{"model":"first","model":"second","prompt":"x","response_text":"y"}');
  assert.throws(() => qualificationProvider({ plan: { ...plan, provider_config_sha256: providerPin(duplicate) }, providerConfigBytes: duplicate, authorize: async () => true }), /not strict UTF-8 JSON/);
});

test('a consumed qualification plan stays consumed after HQ restart', async (t) => {
  const home = tempHome();
  const config = providerBytes('one-use result');
  const plan = { plan_id: 'plan-qualification-b', plan_digest: 'b'.repeat(64),
    provider_config_sha256: providerPin(config), expires_at_ms: Date.now() + 60_000 };
  let authorizations = 0;
  const plugins = () => [referenceBroker(), qualificationProvider({ plan, providerConfigBytes: config, authorize: async () => { authorizations++; return true; } })];
  const first = await startHQ({ home, plugins: plugins() });
  const entry = await first.entry();
  const admitted = await entry.request('Hello', hello({ request_id: 'qualification_restart' }));
  assert.equal(admitted.ok, true);
  const runtime = admitted.result.admitted_runtimes[0];
  const payload = { model: MODEL, prompt_sha256: qualificationPromptDigest(PROMPT) };
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
  const concurrent = await Promise.all([initial.request('qualification.messages', payload), initial.request('qualification.messages', payload)]);
  assert.equal(concurrent.filter((reply) => reply.ok).length, 1);
  assert.equal(authorizations, 1);
  await first.done({ keep: true });
  const second = await startHQ({ home, plugins: plugins() });
  t.after(async () => { await second.done({ keep: true }); rmSync(home, { recursive: true, force: true }); });
  const replay = await (await bind(second)).request('qualification.messages', payload);
  assert.equal(replay.ok, false);
  assert.equal(replay.refusal?.error ?? replay.host_refusal?.code, 'host.invalid_request', JSON.stringify(replay));
  assert.equal(authorizations, 1);
});
