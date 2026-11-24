import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { canonicalDigest } from '../sdk/wire/canonical-json.mjs';
import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { fixtureBroker } from './fixtures/interim-broker.mjs';
import { bridgeBindProofV2, createBridgeBindAdmission } from '../hq/bridge-bind.mjs';

test('Darwin release uses the pinned source and independently verifies its staged output offline', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'hq-broker-package-'));
  try {
    const tree = join(tmp, 'hq');
    for (const dir of ['scripts','hq','governance','vendor']) mkdirSync(join(tree, dir), { recursive: true });
    const pin = fixtureBroker(tree, tmp, fileURLToPath(new URL('../', import.meta.url)));
    const policy = join(tree, 'governance/plugins.json');
    const { stageDarwinBroker } = await import(pathToFileURL(join(tree, 'scripts/darwin-broker.mjs')));
    const work = join(tmp, 'build');
    mkdirSync(work);
    // Neither uncommitted changes nor untracked files from the acquisition
    // checkout may influence the executable producer or its staged bytes.
    writeFileSync(join(tmp, 'comms/scripts/build-hq-plugin.mjs'), "throw new Error('dirty checkout ran');");
    const original = process.env.HQ_COMMS_REPO;
    try {
      process.env.HQ_COMMS_REPO = join(tmp, 'comms');
      assert.deepEqual(stageDarwinBroker(tree, work), pin);
      assert.deepEqual(JSON.parse(readFileSync(policy)).plugins, [{ name: pin.name, version: pin.version, sha256: pin.sha256 }]);
      const before = readFileSync(policy);
      const wrong = { ...pin, sha256: 'sha256:' + '0'.repeat(64) };
      writeFileSync(join(tree, 'governance/darwin-broker.json'), JSON.stringify(wrong));
      rmSync(work, { recursive: true }); mkdirSync(work);
      rmSync(join(tree, 'vendor/plugins'), { recursive: true });
      assert.throws(() => stageDarwinBroker(tree, work), /differs from its reviewed pin/);
      assert.deepEqual(readFileSync(policy), before);
      const wrongCommit = { ...pin, source_commit: '0'.repeat(40) };
      writeFileSync(join(tree, 'governance/darwin-broker.json'), JSON.stringify(wrongCommit));
      rmSync(work, { recursive: true }); mkdirSync(work);
      rmSync(join(tree, 'vendor/plugins'), { recursive: true });
      assert.throws(() => stageDarwinBroker(tree, work), /release tag does not name the pinned source commit/);
    } finally {
      if (original === undefined) delete process.env.HQ_COMMS_REPO; else process.env.HQ_COMMS_REPO = original;
    }
  } finally {
    rmSync(tmp, { recursive: true, force: true });
  }
});

test('the pinned packaged broker forwards bound B ingress and completion to HQ', async () => {
  const tmp = mkdtempSync(join(tmpdir(), 'hq-broker-relay-package-'));
  try {
    const root = fileURLToPath(new URL('../', import.meta.url));
    const tree = join(tmp, 'hq');
    for (const dir of ['scripts', 'hq', 'governance', 'vendor']) mkdirSync(join(tree, dir), { recursive: true });
    for (const path of ['scripts/darwin-broker.mjs', 'hq/plugins.mjs', 'governance/plugins.json',
      'governance/darwin-broker.json']) cpSync(join(root, path), join(tree, path));
    cpSync(join(root, 'sdk'), join(tree, 'sdk'), { recursive: true });
    const work = join(tmp, 'build');
    mkdirSync(work);
    const { stageDarwinBroker } = await import(pathToFileURL(join(tree, 'scripts/darwin-broker.mjs')));
    const pin = stageDarwinBroker(tree, work);
    const packageRoot = join(tree, 'vendor/plugins/agent-comms');
    const { default: packagedBroker } = await import(pathToFileURL(join(packageRoot, 'plugin.mjs')));
    const { createTestHost, definePlugin } = await import(pathToFileURL(join(packageRoot, 'lib/vendor/agent-bot-sdk/index.mjs')));
    const connection = 'b_relay_package';
    const reservationBytes = Buffer.from('pinned broker integration reservation');
    const scope = { installation_id: 'install_1', start_id: `st_${'a'.repeat(24)}`,
      launch_id: `ln_${'b'.repeat(24)}`, plan_id: 'plan_1', plan_digest: 'c'.repeat(64),
      reservation_digest: `sha256:${createHash('sha256').update(reservationBytes).digest('hex')}` };
    const context = { ...scope, hq_epoch: '1'.repeat(64), bridge_uid: 322,
      broker_socket: '/private/tmp/pinned-broker.sock', reservation_bytes: reservationBytes,
      reservation_expires_at: 20_000, finalized_live_expires_at: 90_000,
      member: { socket_path: '/private/tmp/pinned-member.sock' },
      soul_artifact_sha256: `sha256:${'e'.repeat(64)}` };
    const key = Buffer.alloc(32, 0x41);
    const seen = [], completed = [];
    let sequence = 0;
    const service = createBridgeBindAdmission({
      authority: {
        verifyLiveStartV2: async (_scope, _connection, phase) => ({ ...context,
          ...(phase === 'receipt' ? {} : { finalized_live_expires_at: undefined }) }),
        verifyProofV2: async (proof) => proof.proof === bridgeBindProofV2(key, proof.challenge, context),
        isCurrentPeerV2: () => true,
        matchesAssignmentV2: () => true,
        onDisconnectV2: async () => true,
      },
      relayIngressAuthorizer: async (value) => {
        seen.push(value);
        return { model: value.request.model, text: 'from provider', stop_reason: 'end_turn',
          usage: { input_tokens: 1, output_tokens: 1 } };
      },
      relayPrewriteAuthorizer: async () => ({ accepted: true, prewrite_receipt: 'a'.repeat(64) }),
      relayCompletionAuthorizer: async (value) => { completed.push(value); return true; },
      clock: { now: () => 1_000 }, random: { hex: () => (++sequence).toString(16).padStart(64, '0') },
      receipts: { append: async () => {} },
    });
    const admission = definePlugin({
      name: 'hq-admission', version: '0.1.0', hostApi: 1,
      async init() {
        return { provides: {
          ...service, completeBridgeRelayV2: service.completeBridgeIngressV2,
        } };
      },
    });
    const host = createTestHost({ plugins: [admission, packagedBroker] });
    await host.start();
    try {
      const peer = { uid: 321, pid: 700, pid_version: 12,
        start_seconds: 1795520001, start_micros: 120000,
        parent_pid: 600, parent_uid: 321,
        parent_start_seconds: 1795520000, parent_start_micros: 110000 };
      const request = { model: 'claude-test', prompt_sha256: `sha256:${'f'.repeat(64)}`, peer };
      await assert.rejects(host.brokerAccept('bridge.relay.ingress.v1', request, { connection }),
        (error) => error.code === 'caller_mismatch');
      const challenge = await host.brokerAccept('bridge.bind.v2.challenge', scope, { connection });
      const { bind_receipt } = await host.brokerAccept('bridge.bind.v2',
        { ...scope, proof: bridgeBindProofV2(key, challenge.nonce, context) }, { connection });
      assert.deepEqual(await host.brokerAccept('bridge.relay.ingress.v1', request, { connection }),
        { model: request.model, text: 'from provider', stop_reason: 'end_turn',
          usage: { input_tokens: 1, output_tokens: 1 } });
      assert.equal(seen.length, 1);
      assert.deepEqual(seen[0].request, request);
      assert.equal(seen[0].observation.bind_receipt_sha256,
        `sha256:${createHash('sha256').update(bind_receipt).digest('hex')}`);
      await assert.rejects(host.brokerAccept('bridge.relay.ingress.v1', request, { connection: 'other_b' }),
        (error) => error.code === 'caller_mismatch');
      const prewrite = {
        selectors: scope,
        bind_receipt_sha256: `sha256:${createHash('sha256').update(bind_receipt).digest('hex')}`,
        request_sha256: request.prompt_sha256,
        prompt_sha256: `sha256:${'1'.repeat(64)}`,
        model: request.model,
        peer, peer_sha256: canonicalDigest(peer),
        response_wire_sha256: `sha256:${'2'.repeat(64)}`,
        response_wire_bytes: 123,
        http_status: 200,
      };
      assert.deepEqual(await host.brokerAccept('bridge.relay.prewrite.v1', prewrite, { connection }),
        { accepted: true, prewrite_receipt: 'a'.repeat(64) });
      const completion = { ...prewrite,
        write_started_at: '2026-11-24T12:00:00.000Z',
        write_completed_at: '2026-11-24T12:00:01.000Z',
        prewrite_receipt: 'a'.repeat(64), completion_origin_mac: 'b'.repeat(64) };
      await assert.rejects(host.brokerAccept('bridge.relay.complete.v1', completion, { connection: 'other_b' }),
        (error) => error.code === 'caller_mismatch');
      assert.deepEqual(await host.brokerAccept('bridge.relay.complete.v1', completion, { connection }), { accepted: true });
      assert.equal(completed.length, 1);
      assert.deepEqual(completed[0].completion, completion);
      assert.deepEqual(completed[0].ingress.request, request);
      await assert.rejects(host.brokerAccept('bridge.relay.complete.v1', completion, { connection }),
        (error) => error.code === 'caller_mismatch');
      assert.equal(pin.name, 'agent-comms');
    } finally { await service.revokeAll(); await host.stop(); }
  } finally { rmSync(tmp, { recursive: true, force: true }); }
});
