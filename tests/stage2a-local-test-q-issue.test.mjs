import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { canonicalBytes, canonicalDigest } from '../sdk/wire/canonical-json.mjs';
import { createStage2aLocalTestQIssuer } from '../hq/stage2a-local-test-q-issue.mjs';

const digest = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const PURPOSE = 'agent-bot/stage2a-observed-body-local-test-q-approval/v1';
const planId = 'plan-20261124T120001Z-abcd';
const installationId = 'inst.fixture';

function signedQ() {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const key = publicKey.export({ format: 'der', type: 'spki' }).subarray(12);
  const fingerprint = createHash('sha256').update(key).digest('hex');
  const plan = { schema: 'agent-bot-machine/stage2a-observed-body-local-test-q/v1',
    purpose: 'stage2a-observed-body-local-test-qualification/v1',
    host_uuid: 'AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE', installation_id: installationId,
    installed_plan_id: 'plan-20261124T120000Z-abcd', installed_plan_digest: '3'.repeat(64),
    owner_plan_sha256: `sha256:${'4'.repeat(64)}`, source_revision: 'source-revision',
    candidate_manifest_sha256: `sha256:${'5'.repeat(64)}`,
    driver_plan_sha256: `sha256:${'6'.repeat(64)}`, a_key_id: `sha256:${fingerprint}`,
    expires_at: '2026-11-24T12:10:00Z' };
  const planSHA256 = canonicalDigest(plan);
  const payload = { schema: 'agent-bot-machine/stage2a-observed-body-local-test-q-approval/v1',
    kind: 'observed-body-local-test-q-approval', schema_version: 1, plan,
    plan_sha256: planSHA256, approval_reference: { plan_id: planId,
      plan_digest: planSHA256.slice(7), pair_commitment: '7'.repeat(64) },
    machine_fingerprint: fingerprint, issued_at: '2026-11-24T12:01:00Z',
    expires_at: '2026-11-24T12:09:00Z' };
  const payloadBytes = canonicalBytes(payload);
  const envelope = canonicalBytes({ schema_version: 1, purpose: PURPOSE,
    issuer_public_key_base64url: key.toString('base64url'),
    payload_sha256: digest(payloadBytes), payload_base64url: payloadBytes.toString('base64url'),
    signature_base64url: sign(null, Buffer.concat([Buffer.from(`${PURPOSE}\0`), payloadBytes]),
      privateKey).toString('base64url') });
  const reply = { plan_id: planId, plan_sha256: planSHA256,
    approval_envelope_base64url: envelope.toString('base64url'),
    approval_envelope_sha256: digest(envelope), daemon_fingerprint: fingerprint };
  return { key, reply };
}

test('owner Q issue returns the exact Machine staging reply after verifying the installation', async () => {
  const { key, reply } = signedQ();
  let selected;
  const issue = createStage2aLocalTestQIssuer({ machinePublicKey: key,
    exchange: async (id) => { selected = id; return reply; } });
  const result = await issue({ plan_id: planId, installation_id: installationId });
  assert.equal(selected, planId);
  assert.deepEqual(JSON.parse(JSON.stringify(result)), {
    plan_id: reply.plan_id,
    plan_sha256: reply.plan_sha256,
    approval_envelope_base64url: reply.approval_envelope_base64url,
    approval_envelope_sha256: reply.approval_envelope_sha256,
  });
});

test('Q issue refuses selectors and envelopes that do not bind the expected guest and key', async () => {
  const { key, reply } = signedQ();
  let exchanges = 0;
  const issue = createStage2aLocalTestQIssuer({ machinePublicKey: key,
    exchange: async () => { exchanges++; return reply; } });
  await assert.rejects(issue({ plan_id: '../other', installation_id: installationId }), /reviewed/);
  await assert.rejects(issue({ plan_id: planId, installation_id: installationId,
    path: '/tmp/q.json' }), /reviewed/);
  assert.equal(exchanges, 0);
  await assert.rejects(issue({ plan_id: planId, installation_id: 'other.guest' }), /approval/);
  await assert.rejects(createStage2aLocalTestQIssuer({ machinePublicKey: key,
    exchange: async () => ({ ...reply, approval_envelope_sha256: `sha256:${'0'.repeat(64)}` }) })
    ({ plan_id: planId, installation_id: installationId }), /approval/);
  const other = generateKeyPairSync('ed25519').publicKey.export({ format: 'der', type: 'spki' }).subarray(12);
  await assert.rejects(createStage2aLocalTestQIssuer({ machinePublicKey: other,
    exchange: async () => reply })({ plan_id: planId, installation_id: installationId }), /approval/);
});

test('owner CLI does not issue Q through the private HQ account socket', () => {
  const entry = fileURLToPath(new URL('../hq/main.mjs', import.meta.url));
  const result = spawnSync(process.execPath, [entry, 'soul', 'local-test-q-issue',
    '--plan-id', planId, '--installation-id', installationId, '--home', '/tmp/hq-q-no-owner'],
  { encoding: 'utf8' });
  assert.equal(result.status, 1);
  assert.match(result.stderr, /needs owner-control/);
});
