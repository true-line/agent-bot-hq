// Verify Apple's ES256 output independently against the JWK shape HQ accepts.
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { after, before, test } from 'node:test';
import { fileURLToPath } from 'node:url';
import { verifyObservation } from './macos-enclave-observation.mjs';

const darwin = process.platform === 'darwin';
const required = process.env.HQ_REQUIRE_SECURE_ENCLAVE === '1';
const requested = required || process.env.HQ_TEST_SECURE_ENCLAVE === '1';
let dir;
let binary;

before(() => {
  if (!darwin) return;
  dir = mkdtempSync(join(tmpdir(), 'hq-enclave-'));
  binary = join(dir, 'check');
  const source = fileURLToPath(new URL('../scripts/check-macos-enclave.swift', import.meta.url));
  const build = spawnSync('xcrun', ['swiftc', source, '-o', binary], { encoding: 'utf8' });
  assert.equal(build.status, 0, build.error?.message ?? build.stderr);
});
after(() => { if (dir) rmSync(dir, { recursive: true, force: true }); });

function checkSignature(source, t) {
  const challenge = randomBytes(32);
  const run = spawnSync(binary, [source, challenge.toString('base64')], { encoding: 'utf8', timeout: 30000 });
  if (source === 'secure-enclave' && run.status === 77 && !required) {
    t.skip('Secure Enclave unavailable on this Mac');
    return;
  }
  assert.equal(run.status, 0, run.error?.message ?? run.stderr);
  verifyObservation(JSON.parse(run.stdout), source, process.geteuid(), challenge);
}

test('CryptoKit public key and signature verify with HQ encodings', { skip: !darwin }, (t) => {
  checkSignature('software-fixture', t);
});

test('a re-opened, in-memory Secure Enclave key signs a fresh challenge', { skip: !requested }, (t) => {
  assert.equal(darwin, true, 'the requested Secure Enclave check requires macOS');
  checkSignature('secure-enclave', t);
});
