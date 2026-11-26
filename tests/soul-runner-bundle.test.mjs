import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { manifestDigest } from '../scripts/soul-contracts.mjs';
import { readSoulRunnerPin, sourceEntries, stageSoulRunner, verifyBundledSoulRunner } from '../scripts/soul-runner.mjs';

test('the pinned Soul source is explicitly unreleased and cannot be called a release', () => {
  const pin = readSoulRunnerPin();
  assert.equal(pin.source_status, 'unreleased-source');
  assert.match(pin.source_commit, /^[0-9a-f]{40}$/);
});

test('bundling reads only pinned Git blobs, verifies their modes, and refuses tampering or symlinks', () => {
  const root = mkdtempSync(join(realpathSync(tmpdir()), 'hq-soul-runner-test-'));
  const source = join(root, 'source');
  const artifact = join(root, 'artifact');
  const bundle = join(artifact, 'vendor/agent-bot-souls');
  const run = (...args) => execFileSync('git', ['-C', source, ...args], { encoding: 'utf8' }).trim();
  try {
    for (const dir of ['bin', 'governance', 'lib']) mkdirSync(join(source, dir), { recursive: true });
    writeFileSync(join(source, 'bin/runner.mjs'), 'original runner\n', { mode: 0o755 });
    writeFileSync(join(source, 'governance/pin.json'), '{}\n');
    writeFileSync(join(source, 'lib/code.mjs'), 'original code\n');
    writeFileSync(join(source, 'package.json'), '{"type":"module"}\n');
    run('init', '-q');
    run('add', '.');
    const tree = run('write-tree');
    const commit = execFileSync('git', ['-C', source, 'commit-tree', tree, '-m', 'fixture'], {
      encoding: 'utf8', env: { ...process.env, GIT_AUTHOR_NAME: 'fixture', GIT_AUTHOR_EMAIL: 'fixture@example.invalid', GIT_COMMITTER_NAME: 'fixture', GIT_COMMITTER_EMAIL: 'fixture@example.invalid' },
    }).trim();
    const entries = ['bin/runner.mjs', 'governance/pin.json', 'lib/code.mjs', 'package.json'].map((path) => ({
      path, mode: path === 'bin/runner.mjs' ? '100755' : '100644', bytes: readFileSync(join(source, path)),
    }));
    const got = manifestDigest(entries);
    const pin = { source_commit: commit, paths: ['bin', 'governance', 'lib', 'package.json'], digest: got.digest, files: got.files };
    writeFileSync(join(source, 'bin/runner.mjs'), 'uncommitted attacker bytes\n');
    stageSoulRunner(source, bundle, pin);
    assert.equal(readFileSync(join(bundle, 'bin/runner.mjs'), 'utf8'), 'original runner\n');
    assert.equal(verifyBundledSoulRunner(artifact, pin).digest, got.digest);
    writeFileSync(join(bundle, 'lib/code.mjs'), 'changed');
    assert.throws(() => verifyBundledSoulRunner(artifact, pin), /digest/);
    assert.throws(() => sourceEntries(source, { ...pin, digest: `sha256:${'0'.repeat(64)}` }), /differs from the pin/);

    symlinkSync('bin/runner.mjs', join(source, 'link'));
    run('add', 'link');
    const unsafeTree = run('write-tree');
    const unsafeCommit = execFileSync('git', ['-C', source, 'commit-tree', unsafeTree, '-p', commit, '-m', 'symlink fixture'], {
      encoding: 'utf8', env: { ...process.env, GIT_AUTHOR_NAME: 'fixture', GIT_AUTHOR_EMAIL: 'fixture@example.invalid', GIT_COMMITTER_NAME: 'fixture', GIT_COMMITTER_EMAIL: 'fixture@example.invalid' },
    }).trim();
    // The symlink lies outside the pinned roots, so the pinned tree stays
    // unchanged. A symlink inside one of them must be refused.
    symlinkSync('runner.mjs', join(source, 'bin/link'));
    run('add', 'bin/link');
    const nestedTree = run('write-tree');
    const nestedCommit = execFileSync('git', ['-C', source, 'commit-tree', nestedTree, '-p', unsafeCommit, '-m', 'nested symlink fixture'], {
      encoding: 'utf8', env: { ...process.env, GIT_AUTHOR_NAME: 'fixture', GIT_AUTHOR_EMAIL: 'fixture@example.invalid', GIT_COMMITTER_NAME: 'fixture', GIT_COMMITTER_EMAIL: 'fixture@example.invalid' },
    }).trim();
    assert.throws(() => sourceEntries(source, { ...pin, source_commit: nestedCommit }), /unsupported Soul runner tree entry/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
