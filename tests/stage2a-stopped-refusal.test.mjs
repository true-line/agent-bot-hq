import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import test from 'node:test';
import { canonicalize } from '../sdk/wire/canonical-json.mjs';
import { createStage2aStoppedRefusal } from '../hq/stage2a-stopped-refusal.mjs';
import { verifyStage2aLiveRefusal } from '../hq/machine-channel.mjs';
import { startHQ } from './hq-harness.mjs';

const sha = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const purpose = 'agent-bot/stage2a-stop/v1';
const keys = generateKeyPairSync('ed25519');
const publicKey = keys.publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
const expected = Object.freeze({ reservation_sha256: sha('reservation'),
  installation_id: 'installation-1', start_id: `st_${'a'.repeat(24)}`,
  launch_id: `ln_${'b'.repeat(24)}`, plan_id: 'plan-1', plan_digest: 'c'.repeat(64),
  hq_epoch: 'd'.repeat(64), runner_uid: 310, bridge_uid: 311,
  runner_pid: 410, bridge_pid: 411 });

function signedStop() {
  const payload = Buffer.from(canonicalize({ schema: 'agent-bot-machine/stage2a-stop/v1',
    ...expected, both_uids_idle: true, stopped_at: '2026-11-24T12:00:00.000Z' }));
  const envelope = Buffer.from(canonicalize({ schema_version: 1, purpose,
    issuer_public_key_base64url: publicKey.toString('base64url'),
    payload_sha256: sha(payload), payload_base64url: payload.toString('base64url'),
    signature_base64url: sign(null, Buffer.concat([Buffer.from(`${purpose}\0`), payload]),
      keys.privateKey).toString('base64url') }));
  return { expected, envelope, sha256: sha(envelope) };
}

function signedRefusal(request, ordinal) {
  const requestNonce = Buffer.alloc(16, ordinal).toString('base64url');
  const responseNonce = Buffer.alloc(16, ordinal + 8).toString('base64url');
  const requestRaw = JSON.stringify({ verb: 'stage2a-live',
    stage2a_request: Buffer.from(JSON.stringify(request)).toString('base64url'),
    timestamp: Math.floor(Date.now() / 1000), nonce: requestNonce,
    public_key: 'synthetic-HQ-public-key', signature: 'synthetic-HQ-signature' });
  const response = { ok: false, diagnostic: 'MM_DAEMON_UNIMPLEMENTED',
    message: 'Stage 2a installed authority unavailable or mismatched',
    timestamp: Math.floor(Date.now() / 1000), nonce: responseNonce,
    request_nonce: requestNonce };
  response.signature = sign(null, Buffer.from([response.ok, response.diagnostic,
    response.message, '', '', response.timestamp, response.nonce,
    response.request_nonce].join('\n')), keys.privateKey).toString('base64');
  return { diagnostic: response.diagnostic, request_nonce: requestNonce,
    signed_request_base64url: Buffer.from(requestRaw).toString('base64url'),
    signed_response_base64url: Buffer.from(JSON.stringify(response)).toString('base64url'),
    daemon_fingerprint: createHash('sha256').update(publicKey).digest('hex') };
}

test('paired live refusal verifies A signature and never accepts a live reply', () => {
  const requestNonce = Buffer.alloc(16, 7).toString('base64url');
  const responseNonce = Buffer.alloc(16, 9).toString('base64url');
  const response = { ok: false, diagnostic: 'MM_DAEMON_UNIMPLEMENTED',
    message: 'Stage 2a installed authority unavailable or mismatched',
    timestamp: Math.floor(Date.now() / 1000), nonce: responseNonce,
    request_nonce: requestNonce };
  const signed = [response.ok, response.diagnostic, response.message, '', '',
    response.timestamp, response.nonce, response.request_nonce].join('\n');
  response.signature = sign(null, Buffer.from(signed), keys.privateKey).toString('base64');
  const raw = JSON.stringify(response);
  assert.equal(verifyStage2aLiveRefusal(raw, requestNonce, publicKey).diagnostic,
    'MM_DAEMON_UNIMPLEMENTED');
  assert.throws(() => verifyStage2aLiveRefusal(raw, 'wrong', publicKey), /invalid or stale/);
  assert.throws(() => verifyStage2aLiveRefusal(raw.replace('unavailable', 'available'),
    requestNonce, publicKey), /signature/);
  assert.throws(() => verifyStage2aLiveRefusal(JSON.stringify({ ...response, ok: true }),
    requestNonce, publicKey), /signature/);
  const lease = { lease_envelope_base64url: 'would-be-live-lease' };
  const live = { ok: true, state: 'live', body: lease,
    timestamp: response.timestamp, nonce: responseNonce, request_nonce: requestNonce };
  live.signature = sign(null, Buffer.from([true, '', '', 'live', JSON.stringify(lease),
    live.timestamp, live.nonce, live.request_nonce].join('\n')), keys.privateKey).toString('base64');
  assert.throws(() => verifyStage2aLiveRefusal(JSON.stringify(live), requestNonce, publicKey),
    /did not receive a bare signed refusal/);
});

test('only an exact signed stopped start may request two fresh paired refusals across restart', async () => {
  const rows = [];
  const probes = [];
  let active = false;
  const options = { machinePublicKey: publicKey, receipts: () => rows,
    persist: async (row) => { rows.push(row); },
    isActive: () => active,
    probe: async (request) => { probes.push(request); return signedRefusal(request, probes.length); } };
  const first = createStage2aStoppedRefusal(options);
  await assert.rejects(first.inspect({ start_id: expected.start_id }), /unavailable/);
  assert.equal(probes.length, 0);
  await first.recordStop(signedStop());
  active = true;
  await assert.rejects(first.inspect({ start_id: expected.start_id }), /unavailable/);
  assert.equal(probes.length, 0);
  active = false;
  const a = await first.inspect({ start_id: expected.start_id });
  await assert.rejects(first.inspect({ start_id: expected.start_id }), /unavailable/);
  assert.equal(probes.length, 1);
  const restarted = createStage2aStoppedRefusal(options);
  const b = await restarted.inspect({ start_id: expected.start_id });
  assert.equal(probes.length, 2);
  assert.notEqual(probes[0].challenge, probes[1].challenge);
  assert.equal(probes[0].reservation_sha256, expected.reservation_sha256);
  assert.equal(Object.hasOwn(a, 'signed_response_base64url'), false);
  assert.equal(Object.hasOwn(a, 'signed_request_base64url'), false);
  assert.equal(Object.hasOwn(b, 'signed_response_base64url'), false);
  assert.notEqual(a.request_nonce, b.request_nonce);
  assert.equal(rows.filter((row) => row.kind === 'hq.protected.stopped_live_refused').length, 2);
});

test('tampered stop proof and non-refusal cannot yield an owner result', async () => {
  const rows = [];
  let probes = 0;
  const diagnostic = createStage2aStoppedRefusal({ machinePublicKey: publicKey,
    receipts: () => rows, persist: async (row) => { rows.push(row); },
    isActive: () => false, probe: async () => { probes++; return { live: true }; } });
  await diagnostic.recordStop(signedStop());
  rows[0].expected = { ...rows[0].expected, plan_digest: 'e'.repeat(64) };
  await assert.rejects(diagnostic.inspect({ start_id: expected.start_id }), /invalid signed Machine|unavailable/);
  assert.equal(probes, 0);
  rows[0].expected = { ...expected };
  await assert.rejects(diagnostic.inspect({ start_id: expected.start_id }), /unavailable/);
  assert.equal(probes, 1);
  assert.equal(rows.length, 1);
});

test('owner socket accepts only the narrow stopped-start diagnostic operation', async () => {
  const calls = [];
  const h = await startHQ({ stoppedStartDiagnostic: async (payload) => {
    calls.push(payload); return { start_id: payload.start_id, diagnostic: 'MM_DAEMON_UNIMPLEMENTED' };
  } });
  try {
    const owner = await h.owner();
    const entry = await h.entry();
    const allowed = await owner.request('soul.protected-stopped-refusal', { start_id: expected.start_id });
    assert.equal(allowed.ok, true);
    assert.deepEqual(calls, [{ start_id: expected.start_id }]);
    const denied = await entry.request('soul.protected-stopped-refusal', { start_id: expected.start_id });
    assert.equal(denied.ok, false);
    assert.equal(calls.length, 1);
  } finally { await h.done(); }
});
