import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { canonicalBytes } from '../sdk/wire/canonical-json.mjs';
import { createStage2aProtectedAdmission } from '../hq/stage2a-protected-admission.mjs';

const sha = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const digest = (char) => `sha256:${char.repeat(64)}`;

test('signed Machine role and Hello finalize the copied HQ admission binding', async () => {
  const { privateKey, publicKey } = generateKeyPairSync('ed25519');
  const machinePublicKey = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const now = Date.now();
  const selectors = { reservation_sha256: digest('a'), installation_id: 'install-1',
    start_id: 'st_' + '1'.repeat(24), launch_id: 'ln_' + '2'.repeat(24),
    plan_id: 'plan-1', plan_digest: '3'.repeat(64), hq_epoch: '4'.repeat(64) };
  const assignment = { ...selectors };
  delete assignment.reservation_sha256;
  const installed = { installation_id: selectors.installation_id,
    plan_id: selectors.plan_id, plan_digest: selectors.plan_digest,
    hq_epoch: selectors.hq_epoch, soul_id: 'soul-1', host_id: 'host-1',
    claimed_definition_digest: digest('5'), definition_measurement: digest('6'),
    launch_input_measurement: digest('7'), runner_uid: 311, bridge_uid: 312 };
  const peerProcess = { pid: 505, uid: 311 };
  const runner = { pid: 503, uid: 311 };
  const bridge = { pid: 504, uid: 312 };
  let peerChanged = false;
  const payload = { contract: 'hq/v1', request_id: 'request-1', soul_id: installed.soul_id,
    installation_id: installed.installation_id,
    definition_digest: installed.claimed_definition_digest,
    requested_profile: 'managed-protected', requested_roles: [{ member_id: 'member-1' }] };
  const helloPayloadSHA256 = sha(canonicalBytes(payload));
  const bind = digest('8');
  const bridgeFinalization = digest('9');
  const signed = (purpose, data) => {
    const bytes = canonicalBytes(data);
    const envelope = canonicalBytes({ schema_version: 1, purpose,
      issuer_public_key_base64url: machinePublicKey.toString('base64url'),
      payload_sha256: sha(bytes), payload_base64url: bytes.toString('base64url'),
      signature_base64url: sign(null,
        Buffer.concat([Buffer.from(`${purpose}\0`), bytes]), privateKey).toString('base64url') });
    return { envelope, sha256: sha(envelope) };
  };
  const calls = [];
  let startSHA256;
  const verifier = createStage2aProtectedAdmission({ machinePublicKey,
    now: () => now,
    authority: { currentLiveStart: async () => ({ phase: 'finalized',
      reservation_sha256: selectors.reservation_sha256, runner_pid: runner.pid,
      bridge_pid: bridge.pid, finalization_sha256: bridgeFinalization,
      bind_receipt_sha256: bind, finalized_live_expires_at: now + 4000 }) },
    machinePeerRole: async (request) => {
      assert.deepEqual(request, { ...selectors, peer_uid: 311, peer_pid: peerProcess.pid });
      calls.push('peer');
      return signed('agent-bot/stage2a-peer-role/v1', {
        schema: 'agent-bot-machine/stage2a-peer-role/v1', ...selectors,
        role: 'runner', peer_uid: 311, peer_pid: peerProcess.pid,
        peer_process: peerChanged ? { ...peerProcess, birthtime: 'changed' } : peerProcess,
        runner, bridge, definition_measurement: installed.definition_measurement,
        launch_input_measurement: installed.launch_input_measurement,
        profile_in_force: 'managed-protected', issued_at_ms: now - 100,
        expires_at_ms: now + 4000 });
    },
    machineHelloStart: async (request) => {
      assert.equal(request.hello_payload_base64url, canonicalBytes(payload).toString('base64url'));
      assert.equal(request.hello_payload_sha256, helloPayloadSHA256);
      assert.equal(request.broker_bind_receipt_sha256, bind);
      calls.push('hello');
      const reply = signed('agent-bot/stage2a-hello-start/v1', {
        schema: 'agent-bot-machine/stage2a-hello-start/v1', ...selectors,
        host_id: installed.host_id, soul_id: installed.soul_id,
        definition_digest: installed.claimed_definition_digest,
        definition_measurement: installed.definition_measurement,
        launch_input_measurement: installed.launch_input_measurement,
        profile_in_force: 'managed-protected', peer_uid: 311,
        peer_pid: peerProcess.pid, peer_process: peerProcess, runner, bridge,
        broker_bind_receipt_sha256: bind,
        bridge_finalization_sha256: bridgeFinalization,
        hello_payload_sha256: helloPayloadSHA256,
        hello_request_id: payload.request_id, requested_member_ids: ['member-1'],
        issued_at: new Date(now).toISOString() });
      startSHA256 = reply.sha256;
      return reply;
    },
    machineHelloFinalize: async (request) => {
      assert.equal(request.start_envelope_sha256, startSHA256);
      calls.push('finalize');
      return signed('agent-bot/stage2a-hello-finalization/v1', {
        schema: 'agent-bot-machine/stage2a-hello-finalization/v1', ...selectors,
        start_envelope_sha256: startSHA256, expected: request.expected,
        finalized_at: new Date(now).toISOString() });
    },
    machineHelloAbort: async () => { calls.push('abort'); },
    stopReservation: async () => { calls.push('stop'); },
  });
  const registration = verifier.registerStart({ installed, assignment, selectors,
    getBindReceiptSHA256: () => bind });
  const context = await verifier.acceptPeer({}, { installed, assignment, selectors,
    peer_uid: 311, peer_pid: peerProcess.pid });
  const original = await verifier.verifyHelloStart({ connection: context, caller: 'rp-1',
    payload, hello_payload_sha256: helloPayloadSHA256 });
  const copied = Object.freeze({ ...original });
  assert.equal(await verifier.verifyDefinitionMapping(copied, payload), true);
  const unwatch = verifier.watchLiveness(copied, () => {});
  assert.equal(verifier.watchHealthy(copied), true);
  assert.equal(await verifier.assertLive(copied), true);
  const expected = { reservation_sha256: selectors.reservation_sha256,
    start_id: selectors.start_id, launch_id: selectors.launch_id, hq_epoch: selectors.hq_epoch,
    soul_id: installed.soul_id, installation_id: installed.installation_id,
    definition_digest: installed.claimed_definition_digest,
    definition_measurement: installed.definition_measurement,
    launch_input_measurement: installed.launch_input_measurement,
    hello_payload_sha256: helloPayloadSHA256, admission_decision_id: 'decision-1',
    installation_epoch: 1, profile_in_force: 'managed-protected',
    hq_broker_bind_receipt_sha256: bind,
    admitted_runtimes: [{ member_id: 'member-1', runtime_id: 'runtime-1',
      profile_in_force: 'managed-protected' }] };
  const final = await verifier.finalize(expected);
  assert.equal(await verifier.verifyFinalization(final, expected), true);
  assert.deepEqual(verifier.finalizationFor(selectors),
    { envelope: final.envelope, sha256: final.sha256 });
  assert.deepEqual(calls, ['peer', 'hello', 'peer', 'finalize']);
  peerChanged = true;
  await assert.rejects(verifier.assertLive(copied),
    /Machine protected Hello authority is unavailable/);
  unwatch();
  registration.close();
});
