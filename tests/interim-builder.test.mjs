import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { fixtureBroker } from './fixtures/interim-broker.mjs';
import { manifestDigest } from '../scripts/soul-contracts.mjs';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
// The builder fixture pins its own broker in its disposable .cache.
const fixtureEnv = { ...process.env };
delete fixtureEnv.HQ_COMMS_REPO;
const run = (cmd, args, options = {}) => execFileSync(cmd, args, { encoding: 'utf8', env: fixtureEnv, ...options });

test('interim artifact is reproducible, runs offline and refuses changed contracts', () => {
  const tmp = mkdtempSync(join(realpathSync(tmpdir()), 'hq-builder-test-'));
  const darwinHost = process.platform === 'darwin';
  const nativeTarget = darwinHost ? ['--target', 'darwin'] : [];
  const tarCommand = darwinHost ? 'gtar' : 'tar';
  try {
    const repo = join(tmp, 'repo'), contracts = join(tmp, 'contracts');
    for (const d of ['scripts', 'hq', 'governance']) mkdirSync(join(repo, d), { recursive: true });
    fixtureBroker(repo, tmp, root);
    const entries = [];
    for (const d of ['errors', 'fixtures', 'schemas']) {
      mkdirSync(join(contracts, d), { recursive: true });
      const bytes = Buffer.from(`${d}\n`);
      writeFileSync(join(contracts, d, 'one.json'), bytes);
      entries.push({ path: `${d}/one.json`, mode: '100644', bytes });
    }
    const got = manifestDigest(entries);
    const pin = { schema_version: 1, repository: 'https://github.com/test/contracts.git', tag: 'v0.4.1', commit: 'a'.repeat(40), paths: ['errors', 'fixtures', 'schemas'], digest_algorithm: 'sha256-manifest-v1', digest: got.digest, files: got.files };
    writeFileSync(join(repo, 'governance/soul-contracts.json'), JSON.stringify(pin));
    writeFileSync(join(repo, 'package.json'), '{"type":"module"}\n');
    writeFileSync(join(repo, 'hq/main.mjs'), "import { verify } from '../scripts/soul-contracts.mjs'; verify(); console.log('offline-ok');\n");
    writeFileSync(join(repo, 'hq/stage2a-h-preloader.mjs'),
      'export function authenticatedSelectedH() { return null; }\n');
    for (const f of ['soul-contracts.mjs', 'h-v0103-excluded.mjs', 'soul-runner.mjs', 'build-interim-release.mjs']) {
      cpSync(join(root, 'scripts', f), join(repo, 'scripts', f));
    }
    // A local disposable Git object fixture; it is never pushed or published.
    const ident = { ...process.env, GIT_AUTHOR_NAME: 'trueline-codex-agent[bot]', GIT_COMMITTER_NAME: 'trueline-codex-agent[bot]', GIT_AUTHOR_EMAIL: '325086705+trueline-codex-agent[bot]@users.noreply.github.com', GIT_COMMITTER_EMAIL: '325086705+trueline-codex-agent[bot]@users.noreply.github.com' };
    const runnerRepo = join(tmp, 'runner');
    mkdirSync(runnerRepo);
    run('git', ['init', '-q', runnerRepo]);
    const runnerPackage = Buffer.from('{"name":"runner-fixture"}\n');
    const runnerEntries = [
      { path: 'package.json', mode: '100644', bytes: runnerPackage },
      ...['bin', 'governance', 'lib'].map((dir) => ({ path: `${dir}/fixture.txt`, mode: '100644', bytes: Buffer.from(`${dir}\n`) })),
    ];
    for (const { path, bytes } of runnerEntries) {
      const file = join(runnerRepo, path);
      mkdirSync(dirname(file), { recursive: true });
      writeFileSync(file, bytes);
    }
    run('git', ['-C', runnerRepo, 'add', '.']);
    const runnerTree = run('git', ['-C', runnerRepo, 'write-tree']).trim();
    const runnerCommit = run('git', ['-C', runnerRepo, 'commit-tree', runnerTree, '-m', 'runner fixture'], { env: ident }).trim();
    const runnerDigest = manifestDigest(runnerEntries);
    writeFileSync(join(repo, 'governance/soul-runner.json'), JSON.stringify({
      schema_version: 1, repository: 'https://github.com/true-line/agent-bot-souls.git',
      source_commit: runnerCommit, source_status: 'unreleased-source',
      paths: ['bin', 'governance', 'lib', 'package.json'], digest_algorithm: 'sha256-manifest-v1',
      digest: runnerDigest.digest, files: runnerDigest.files,
    }));
    writeFileSync(join(runnerRepo, 'package.json'), '{}\n');

    run('git', ['init', '-q', repo]);
    run('git', ['-C', repo, 'add', '.']);
    const tree = run('git', ['-C', repo, 'write-tree']).trim();
    const fixtureCommit = run('git', ['-C', repo, 'commit-tree', tree, '-m', 'fixture'], { env: ident }).trim();
    run('git', ['-C', repo, 'update-ref', 'HEAD', fixtureCommit]);
    const sha = run('git', ['-C', repo, 'rev-parse', 'HEAD']).trim();
    const { extracted, executable } = buildAndVerifyTargets(repo, sha, contracts);
    assert.equal(existsSync(join(extracted, 'hq/vendor/agent-bot-souls')), false);
    const bundle = join(tmp, 'with-runner.tar');
    run(process.execPath, [join(repo, 'scripts/build-interim-release.mjs'), sha, contracts, bundle, ...nativeTarget, '--soul-runner-source', runnerRepo], { cwd: repo });
    const bundledTree = join(tmp, 'with-runner');
    mkdirSync(bundledTree);
    run('tar', ['-xf', bundle, '-C', bundledTree]);
    assert.deepEqual(readFileSync(join(bundledTree, 'hq/vendor/agent-bot-souls/package.json')), runnerPackage);
    const bundledMetadata = JSON.parse(readFileSync(join(bundledTree, 'hq/governance/interim-release.json')));
    assert.deepEqual(bundledMetadata.soul_runner, {
      source_commit: runnerCommit, source_status: 'unreleased-source', digest: runnerDigest.digest,
    });
    assert.match(run(process.execPath, [executable], { env: { PATH: '' } }), /offline-ok/);
    writeFileSync(join(extracted, 'hq/vendor/soul-contracts/errors/one.json'), 'tampered');
    const refused = spawnSync(process.execPath, [executable], { env: { PATH: '' }, encoding: 'utf8' });
    assert.notEqual(refused.status, 0);
    assert.match(refused.stderr, /digest/);
    const dangling = join(tmp, 'dangling.tar'); symlinkSync(join(tmp, 'absent'), dangling);
    assert.notEqual(spawnSync(process.execPath, [join(repo, 'scripts/build-interim-release.mjs'), sha, contracts, dangling, ...nativeTarget], { cwd: repo }).status, 0);
    const fakeBin = join(tmp, 'bin'); mkdirSync(fakeBin);
    symlinkSync(run('which', ['git']).trim(), join(fakeBin, 'git'));
    writeFileSync(join(fakeBin, tarCommand), '#!/bin/sh\nexit 17\n', { mode: 0o755 });
    const failed = join(tmp, 'failed.tar');
    assert.notEqual(spawnSync(process.execPath, [join(repo, 'scripts/build-interim-release.mjs'), sha, contracts, failed, ...nativeTarget], { cwd: repo, env: { ...process.env, PATH: fakeBin } }).status, 0);
    assert.equal(existsSync(failed), false);
    // Even a reviewed Git tree must be inspected before any archive extraction.
    symlinkSync('hq/main.mjs', join(repo, 'source-link'));
    run('git', ['-C', repo, 'add', 'source-link']);
    const symlinkTree = run('git', ['-C', repo, 'write-tree']).trim();
    const symlinkCommit = run('git', ['-C', repo, 'commit-tree', symlinkTree, '-p', sha, '-m', 'symlink fixture'], { env: ident }).trim();
    run('git', ['-C', repo, 'update-ref', 'HEAD', symlinkCommit]);
    const tarMarker = join(tmp, 'tar-invoked');
    writeFileSync(join(fakeBin, tarCommand), '#!/bin/sh\nprintf invoked > "$MARKER"\nexit 17\n', { mode: 0o755 });
    const unsafe = spawnSync(process.execPath, [join(repo, 'scripts/build-interim-release.mjs'), symlinkCommit, contracts, join(tmp, 'unsafe.tar'), ...nativeTarget], { cwd: repo, env: { ...process.env, PATH: fakeBin, MARKER: tarMarker }, encoding: 'utf8' });
    assert.notEqual(unsafe.status, 0);
    assert.match(unsafe.stderr, /unsupported source tree entry/);
    assert.equal(existsSync(tarMarker), false);
  } finally { rmSync(tmp, { recursive: true, force: true }); }

  function buildAndVerifyTargets(repo, sha, contracts) {
    const one = join(tmp, 'one.tar'), two = join(tmp, 'two.tar');
    for (const out of [one, two]) run(process.execPath, [join(repo, 'scripts/build-interim-release.mjs'), sha, contracts, out, ...nativeTarget], { cwd: repo });
    const hash = (f) => createHash('sha256').update(readFileSync(f)).digest('hex');
    assert.equal(hash(one), hash(two));
    const darwin = darwinHost ? one : join(tmp, 'darwin.tar');
    if (darwinHost) {
      const linux = spawnSync(process.execPath, [join(repo, 'scripts/build-interim-release.mjs'), sha, contracts, join(tmp, 'linux.tar')], { cwd: repo, encoding: 'utf8' });
      assert.notEqual(linux.status, 0);
      assert.match(linux.stderr, /build the Linux target on Linux/);
    } else {
      run(process.execPath, [join(repo, 'scripts/build-interim-release.mjs'), sha, contracts, darwin, '--target', 'darwin'], { cwd: repo });
      assert.notEqual(hash(darwin), hash(one));
    }
    const darwinTree = join(tmp, 'darwin');
    mkdirSync(darwinTree);
    run('tar', ['-xf', darwin, '-C', darwinTree]);
    const darwinMetadata = JSON.parse(readFileSync(join(darwinTree, 'hq/governance/interim-release.json')));
    assert.equal(darwinMetadata.target_platform, 'darwin');
    assert.equal(darwinMetadata.owner_control_capability, 'darwin-owner-control/v2');
    if (process.platform === 'linux') {
      const wrongHost = spawnSync(process.execPath, [join(darwinTree, 'hq/hq/main.mjs')], { encoding: 'utf8' });
      assert.notEqual(wrongHost.status, 0);
      assert.match(wrongHost.stderr, /macOS only/);
    }
    if (darwinHost) return { extracted: darwinTree, executable: join(darwinTree, 'hq/hq/main.mjs') };
    const extracted = join(tmp, 'extract'); mkdirSync(extracted);
    run('tar', ['-xf', one, '-C', extracted]);
    assert.equal(Object.hasOwn(JSON.parse(readFileSync(join(extracted, 'hq/governance/interim-release.json'))), 'owner_control_capability'), false);
    const executable = join(extracted, 'hq/hq/main.mjs');
    assert.equal(JSON.parse(readFileSync(join(extracted, 'hq/governance/interim-release.json'))).target_platform, undefined);
    return { extracted, executable };
  }
});
