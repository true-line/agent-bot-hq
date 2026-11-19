// Run twice by the same disposable system LaunchDaemon. Each helper operation
// is a separate process; the second Node process has no cached signer state.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { existsSync, mkdirSync, readFileSync, readdirSync, symlinkSync, unlinkSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createSigner, helperKeyBackend } from '../hq/signer.mjs';

const [, , helper, fixtureHome, expectedUid] = process.argv;
assert.equal(process.getuid(), Number(expectedUid));
const home = join(fixtureHome, 'restart-hq');
const saved = join(fixtureHome, 'restart-observation.json');
const backend = helperKeyBackend({ command: [helper], run(argv, input) {
  const result = spawnSync(argv[0], ['standalone-v1-' + argv[1]], { input, encoding: 'utf8', timeout: 30000 });
  if (result.status !== 0) process.stderr.write(result.stderr || String(result.error ?? result.signal));
  return { code: result.status ?? -1, stdout: result.stdout };
} });
const challenge = () => randomBytes(32);
if (!existsSync(saved)) {
  mkdirSync(home, { mode: 0o700 });
  const dbPath = join(fixtureHome, 'hq-device-signer.keychain-db');
  const sentinel = join(home, 'sentinel');
  writeFileSync(sentinel, 'fixture', { flag: 'wx', mode: 0o600 });
  symlinkSync(sentinel, dbPath);
  assert.throws(() => backend.create({ replace: false }));
  assert.equal(readFileSync(sentinel, 'utf8'), 'fixture');
  unlinkSync(dbPath);
  assert.equal(backend.status().present, false);
  const signer = createSigner({ home, backend });
  const before = signer.report();
  assert.equal(before.available, true, before.reason);
  assert.equal(before.key_storage, 'hardware');
  assert.equal(before.key_files, 0);
  const message = challenge();
  const signature = signer.sign(message);
  assert.throws(() => backend.create({ replace: false }));
  writeFileSync(saved, JSON.stringify({ before, message: message.toString('base64'), signature }), { flag: 'wx', mode: 0o600 });
} else {
  const { before, message, signature } = JSON.parse(readFileSync(saved));
  const signer = createSigner({ home, backend });
  assert.deepEqual(signer.report(), before);
  assert.equal(signer.verify(Buffer.from(message, 'base64'), signature), true);
  const fresh = challenge();
  assert.equal(signer.verify(fresh, signer.sign(fresh)), true);
  assert.deepEqual(readdirSync(join(home, 'signer')), ['pin.json']);
  const rotated = signer.createKey({ replace: true });
  assert.notEqual(rotated.thumbprint, before.thumbprint);
  assert.equal(rotated.generation, before.generation + 1);
  assert.equal(signer.verify(Buffer.from(message, 'base64'), signature), false);
  console.log('The restarted HQ job retained its enclave key and explicitly rekeyed.');
}
