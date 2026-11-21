import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
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
