// Source-only cross-owner check. Contracts v0.10.3 at
// 896b693b23219444dcbe4af4083fd1bc4b9f178c owns the released neutral
// tuple and prewrite proof; HQ's installed Contracts selection stays separate.
import assert from 'node:assert/strict';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { createStage2aLocalTestProvider } from '../hq/stage2a-local-test-provider.mjs';
import { openLocalProviderService, stage2aLocalProviderPort }
  from '../hq/stage2a-qualification-provider.mjs';
import { verifyStage2aMachineEnvelope } from '../hq/stage2a-stop.mjs';
import { canonicalize } from '../sdk/wire/canonical-json.mjs';

const tuplePath = process.env.STAGE2A_SIGNED_TUPLE;
const tuple = tuplePath ? JSON.parse(readFileSync(tuplePath, 'utf8')) : null;
const contractsTuplePath = process.env.STAGE2A_CONTRACTS_LOCAL_TEST_TUPLE;
const contractsProofPath = process.env.STAGE2A_CONTRACTS_LOCAL_TEST_PREWRITE;
const contractsTuple = contractsTuplePath
  ? JSON.parse(readFileSync(contractsTuplePath, 'utf8')) : null;
const contractsProof = contractsProofPath
  ? JSON.parse(readFileSync(contractsProofPath, 'utf8')) : null;
const sha = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
const jcsSHA = (value) => sha(Buffer.from(canonicalize(value)));
const envelope = (record) => Buffer.from(record.envelope_base64url, 'base64url');
const proofPurpose = 'agent-bot/stage2a-observed-body-local-test-prewrite-acceptance/v1';
const gitBlobSHA = (bytes) => createHash('sha1')
  .update(Buffer.from(`blob ${bytes.length}\0`)).update(bytes).digest('hex');
test('merged Contracts prewrite fixture joins the A proof to the B core and ingress',
  { skip: contractsTuple?.schema !== 'stage2a-local-test-neutral-tuple/v1'
    || contractsProof?.schema !== 'stage2a-local-test-prewrite-proof-fixture/v1' }, () => {
    assert.equal(gitBlobSHA(readFileSync(contractsTuplePath)),
      'ea28e9f86da64a28412d338a8e6de39a219ef8c6');
    assert.equal(gitBlobSHA(readFileSync(contractsProofPath)),
      '6426582a9030f1e5e52b16e490fc252b8e5166f2');
    const pin = Buffer.from(contractsTuple.machine_public_key_base64url, 'base64url');
    const bytes = Buffer.from(contractsProof.proof.envelope_base64url, 'base64url');
    const proof = verifyStage2aMachineEnvelope(bytes, pin, proofPurpose).payload;
    const core = contractsProof.prewrite_core;
    const ingress = contractsTuple.ingress_core;
    assert.equal(proof.prewrite_core_sha256, jcsSHA(core));
    assert.equal(proof.authorization_envelope_sha256,
      contractsTuple.authorization.envelope_sha256);
    assert.deepEqual(proof.selectors, contractsTuple.b_fd3.selectors);
    assert.deepEqual(core.selectors, proof.selectors);
    assert.equal(core.ingress_core_sha256, jcsSHA(ingress));
    assert.equal(core.observed_body_sha256, ingress.observed_body_sha256);
    assert.equal(core.peer_sha256, jcsSHA(core.peer));
    assert.equal(core.response_wire_sha256,
      sha(Buffer.from(contractsProof.response_wire_utf8)));
    assert.equal(core.response_wire_bytes,
      Buffer.byteLength(contractsProof.response_wire_utf8));
    assert.equal(contractsProof.prewrite_reply.prewrite_receipt, proof.prewrite_receipt);
    assert.equal(contractsProof.prewrite_reply.prewrite_proof_envelope_sha256, sha(bytes));
    assert.equal(contractsProof.prewrite_reply.prewrite_proof_envelope_base64url,
      contractsProof.proof.envelope_base64url);
  });
function syntheticPrewriteReply(tuple) {
  // Candidate 4 is diagnostic: the new proof is a separate proposed checkpoint.
  const privateKey = createPrivateKey({ key: Buffer.concat([
    Buffer.from('302e020100300506032b657004220420', 'hex'), Buffer.alloc(32, 0x43)]),
  format: 'der', type: 'pkcs8' });
  const publicPin = createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32);
  assert.equal(publicPin.toString('base64url'), tuple.keys.A);
  const prewrite_receipt = tuple.completion_core.prewrite_receipt;
  const payload = { schema: 'agent-bot-machine/stage2a-observed-body-local-test-prewrite-acceptance/v1',
    kind: 'observed-body-local-test-prewrite-acceptance', schema_version: 1,
    selectors: tuple.prewrite.selectors, hq_epoch: tuple.b_policy.payload.hq_epoch,
    authorization_envelope_sha256: tuple.prewrite.authorization_envelope_sha256,
    prewrite_core_sha256: jcsSHA(tuple.prewrite),
    prewrite_receipt, issued_at: '2026-11-24T12:00:12Z',
    expires_at: '2026-11-24T12:00:15Z' };
  const bytes = Buffer.from(canonicalize(payload));
  const proof = Buffer.from(canonicalize({ schema_version: 1, purpose: proofPurpose,
    issuer_public_key_base64url: tuple.keys.A,
    payload_sha256: sha(bytes), payload_base64url: bytes.toString('base64url'),
    signature_base64url: sign(null, Buffer.concat([Buffer.from(`${proofPurpose}\0`), bytes]),
      privateKey).toString('base64url') }));
  return { prewrite_receipt,
    prewrite_proof_envelope_base64url: proof.toString('base64url'),
    prewrite_proof_envelope_sha256: sha(proof) };
}

test('candidate-4 signed policy refuses before opening a listener',
  { skip: tuple?.schema !== 'stage2a-candidate-4-synthetic-signed-tuple/v1' }, async () => {
    const pin = Buffer.from(tuple.keys.A, 'base64url');
    const selectors = tuple.b_fd3.selectors;
    assert.notEqual(tuple.b_policy.payload.local_test.selected_launch_id, selectors.launch_id);
    let opened = 0;
    let closed = 0;
    const options = {
      reservationEnvelope: envelope(tuple.reservation),
      memberAssignmentEnvelope: envelope(tuple.member_assignment),
      policyEnvelope: envelope(tuple.b_policy), selectors, machinePublicKey: pin,
      now: () => Date.parse('2026-11-24T12:00:11Z'),
      validateReservation: (payload) => payload.assignment?.schema
        === 'agent-bot-machine/soul-start-assignment-local-test/v1'
        && payload.measurement_binding?.contract === 'machine/local-test-v1',
      validateMemberAssignment: (payload) => payload.bridge?.endpoints?.broker?.socket_path
        === '/var/run/abtest/broker/broker.sock',
      verifyPolicy: (bytes) => {
        const payload = verifyStage2aMachineEnvelope(bytes, pin,
          'agent-bot/stage2a-b-member-authority-local-test/v1', { maxBytes: 65_536 }).payload;
        return { selectors, hq_epoch: payload.hq_epoch,
          local_test: payload.local_test, members: payload.members };
      },
      machineChallenge: async () => { throw new Error('not called'); },
      machineBind: async () => { throw new Error('not called'); },
      machineIngress: async () => { throw new Error('not called'); },
      machineProvider: async () => { throw new Error('not called'); },
      machinePrewrite: async () => { throw new Error('not called'); },
      machineComplete: async () => { throw new Error('not called'); },
      observeCurrentStart: async () => { throw new Error('not called'); },
      openService: (plan) => {
        opened++;
        return { port: stage2aLocalProviderPort(plan), ready: Promise.resolve(),
          invoke: async () => { throw new Error('not called'); },
          probeReachability: async () => { throw new Error('not called'); },
          invocationReceipt: () => undefined,
          close: async () => { closed++; } };
      },
    };
    assert.throws(() => createStage2aLocalTestProvider(options), /unavailable/);
    assert.equal(opened, 0);
    assert.equal(closed, 0);
  });

test('candidate-5 HQ result and completion ack match the cross-owner tuple',
  { skip: tuple?.schema !== 'stage2a-candidate-5-synthetic-signed-tuple/v1' }, async () => {
    const pin = Buffer.from(tuple.keys.A, 'base64url');
    const selectors = tuple.b_fd3.selectors;
    const core = tuple.ingress.payload.core;
    const bindReceipt = createHash('sha256')
      .update('synthetic one-use B bind receipt').digest('hex');
    const prewriteReceipt = createHash('sha256')
      .update('synthetic prewrite receipt').digest('hex');
    const fixed = { schema: 'stage2a-observed-body-local-test-fixture/v1',
      model: tuple.provider_config.model,
      response_text: tuple.provider_config.response_text };
    let time = Date.parse('2026-11-24T12:00:11Z');
    const connection = {};
    const options = {
      reservationEnvelope: envelope(tuple.reservation),
      memberAssignmentEnvelope: envelope(tuple.member_assignment),
      policyEnvelope: envelope(tuple.b_policy), selectors, machinePublicKey: pin,
      now: () => time,
      validateReservation: (payload) => payload.assignment?.schema
        === 'agent-bot-machine/soul-start-assignment-local-test/v1'
        && payload.measurement_binding?.contract === 'machine/local-test-v1',
      validateMemberAssignment: (payload) => payload.bridge?.endpoints?.broker?.socket_path
        === '/var/run/abtest/broker/broker.sock',
      verifyPolicy: (bytes) => {
        const payload = verifyStage2aMachineEnvelope(bytes, pin,
          'agent-bot/stage2a-b-member-authority-local-test/v1', { maxBytes: 65_536 }).payload;
        return { selectors, hq_epoch: payload.hq_epoch,
          local_test: payload.local_test, members: payload.members };
      },
      machineChallenge: async () => ({ nonce: 'a'.repeat(64), algorithm: 'hmac-sha256',
        context: 'agent-bot-stage2a-observed-body-local-test-bind-v1',
        hq_epoch: tuple.b_policy.payload.hq_epoch, expires_at: '2026-11-24T12:00:19Z' }),
      machineBind: async ({ proof }) => {
        assert.equal(proof, 'b'.repeat(64));
        return { bind_receipt: bindReceipt };
      },
      observeCurrentStart: async () => ({ phase: 'finalized', selectors,
        bind_receipt_sha256: sha(Buffer.from(bindReceipt)),
        expires_at_ms: Date.parse('2026-11-24T12:00:20Z'),
        runner_pid: 4001, bridge_pid: 3901, child_pid: 4101 }),
      machineIngress: async (frame) => {
        assert.deepEqual(frame, tuple.ingress.payload);
        return { authorization_envelope_base64url: tuple.authorization.envelope_base64url,
          authorization_envelope_sha256: tuple.authorization.envelope_sha256 };
      },
      machineProvider: async (request) => {
        assert.deepEqual(request, { selectors,
          authorization_envelope_sha256: tuple.authorization.envelope_sha256,
          model: tuple.provider_config.model,
          observed_body_sha256: core.observed_body_sha256 });
        return { mode: tuple.provider_config.mode,
          fixture_config_base64url: Buffer.from(canonicalize(fixed)).toString('base64url'),
          fixture_config_sha256: jcsSHA(fixed),
          authorization_envelope_sha256: tuple.authorization.envelope_sha256,
          observed_body_sha256: core.observed_body_sha256,
          provider_config_sha256: jcsSHA(tuple.provider_config),
          expires_at_ms: Date.parse('2026-11-24T12:00:15Z') };
      },
      machinePrewrite: async (value) => {
        assert.deepEqual(value, tuple.prewrite);
        const reply = syntheticPrewriteReply(tuple);
        assert.equal(reply.prewrite_receipt, prewriteReceipt);
        return reply;
      },
      machineComplete: async (frame) => {
        assert.deepEqual(frame, tuple.completion.payload);
        return { accepted: true,
          completion_core_sha256: jcsSHA(frame.core),
          completed_run_sha256: tuple.completion_ack.result.completed_run_sha256 };
      },
    };
    const provider = createStage2aLocalTestProvider(options);
    try {
      await provider.ready;
      await provider.challenge(selectors, connection);
      await provider.bind({ selectors, proof: 'b'.repeat(64) }, connection);
      const result = await provider.authorize(tuple.ingress.payload, connection);
      assert.deepEqual(result, tuple.ingress_reply.result);
      time = Date.parse('2026-11-24T12:00:12Z');
      const prewriteProof = await provider.prewrite(tuple.prewrite, connection);
      assert.deepEqual(prewriteProof, syntheticPrewriteReply(tuple));
      const proofPayload = verifyStage2aMachineEnvelope(
        Buffer.from(prewriteProof.prewrite_proof_envelope_base64url, 'base64url'),
        pin, proofPurpose).payload;
      assert.equal(proofPayload.prewrite_core_sha256, jcsSHA(tuple.prewrite));
      assert.equal(proofPayload.schema_version, 1);
      assert.equal(proofPayload.authorization_envelope_sha256,
        tuple.prewrite.authorization_envelope_sha256);
      time = Date.parse('2026-11-24T12:00:13Z');
      const ack = await provider.complete(tuple.completion.payload, connection);
      assert.deepEqual(ack, tuple.completion_ack.result);
    } finally { await provider.stop(); }

    time = Date.parse('2026-11-24T12:00:11Z');
    const badResponse = createStage2aLocalTestProvider({ ...options,
      openService: (plan, serviceOptions) => {
        const service = openLocalProviderService(plan, serviceOptions);
        return { ...service, invoke: async (...args) => ({
          ...await service.invoke(...args), response_sha256: sha('forged response') }) };
      } });
    try {
      await badResponse.ready;
      await badResponse.challenge(selectors, connection);
      await badResponse.bind({ selectors, proof: 'b'.repeat(64) }, connection);
      await assert.rejects(badResponse.authorize(tuple.ingress.payload, connection),
        /unavailable/);
      assert.equal(badResponse.invocationReceipt(), undefined);
    } finally { await badResponse.stop(); }

    const badCompletion = createStage2aLocalTestProvider({ ...options,
      machineComplete: async () => ({ accepted: true,
        completion_core_sha256: sha('forged completion'),
        completed_run_sha256: tuple.completion_ack.result.completed_run_sha256 }) });
    try {
      await badCompletion.ready;
      await badCompletion.challenge(selectors, connection);
      await badCompletion.bind({ selectors, proof: 'b'.repeat(64) }, connection);
      await badCompletion.authorize(tuple.ingress.payload, connection);
      time = Date.parse('2026-11-24T12:00:12Z');
      await badCompletion.prewrite(tuple.prewrite, connection);
      time = Date.parse('2026-11-24T12:00:13Z');
      await assert.rejects(badCompletion.complete(tuple.completion.payload, connection),
        /unavailable/);
    } finally { await badCompletion.stop(); }

    time = Date.parse('2026-11-24T12:00:11Z');
    let prewriteCalls = 0;
    const expiredBeforePrewrite = createStage2aLocalTestProvider({ ...options,
      machinePrewrite: async () => { prewriteCalls++; throw new Error('unexpected prewrite'); } });
    try {
      await expiredBeforePrewrite.ready;
      await expiredBeforePrewrite.challenge(selectors, connection);
      await expiredBeforePrewrite.bind({ selectors, proof: 'b'.repeat(64) }, connection);
      await expiredBeforePrewrite.authorize(tuple.ingress.payload, connection);
      time = Date.parse('2026-11-24T12:00:16Z');
      await assert.rejects(expiredBeforePrewrite.prewrite(tuple.prewrite, connection),
        /unavailable/);
      assert.equal(prewriteCalls, 0);
    } finally { await expiredBeforePrewrite.stop(); }
  });
