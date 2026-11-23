import test from 'node:test';
import assert from 'node:assert/strict';
import { cpSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { fixtureBroker } from './fixtures/interim-broker.mjs';

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

test('the pinned packaged broker forwards only a bound B relay to HQ with its raw receipt', async () => {
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
    const seen = [];
    const admission = definePlugin({
      name: 'hq-admission', version: '0.1.0', hostApi: 1,
      async init() {
        return { provides: {
          bridgeRelayIngressEnabledV2: () => true,
          async bridgeBindChallengeV2() {
            return { nonce: 'a'.repeat(64), algorithm: 'hmac-sha256',
              context: 'agent-bot-stage2a-bridge-bind-v2', hq_epoch: '1'.repeat(64),
              expires_at: '2026-11-21T20:00:00.000Z' };
          },
          async verifyBridgeBindingV2() { return { bind_receipt: '2'.repeat(64) }; },
          async relayBridgeIngressV2(request, { connection }, receipt) {
            seen.push({ request, connection, receipt });
            return { accepted: true };
          },
          forgetBridgeConnection() {},
        } };
      },
    });
    const host = createTestHost({ plugins: [admission, packagedBroker] });
    await host.start();
    try {
      const connection = 'b_relay_package';
      const scope = { installation_id: 'install_1', start_id: `st_${'a'.repeat(24)}`,
        launch_id: `ln_${'b'.repeat(24)}`, plan_id: 'plan_1', plan_digest: 'c'.repeat(64),
        reservation_digest: `sha256:${'d'.repeat(64)}` };
      const request = { model: 'claude-test', prompt_sha256: `sha256:${'f'.repeat(64)}` };
      await assert.rejects(host.brokerAccept('bridge.relay.ingress.v1', request, { connection }),
        (error) => error.code === 'caller_mismatch');
      await host.brokerAccept('bridge.bind.v2.challenge', scope, { connection });
      const { bind_receipt } = await host.brokerAccept('bridge.bind.v2',
        { ...scope, proof: 'e'.repeat(64) }, { connection });
      assert.deepEqual(await host.brokerAccept('bridge.relay.ingress.v1', request, { connection }), { accepted: true });
      assert.deepEqual(seen, [{ request, connection, receipt: bind_receipt }]);
      await assert.rejects(host.brokerAccept('bridge.relay.ingress.v1', request, { connection: 'other_b' }),
        (error) => error.code === 'caller_mismatch');
      assert.equal(pin.name, 'agent-comms');
    } finally { await host.stop(); }
  } finally { rmSync(tmp, { recursive: true, force: true }); }
});
