import assert from 'node:assert/strict';
import { execFile, execFileSync } from 'node:child_process';
import { chmodSync, copyFileSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { setTimeout as delay } from 'node:timers/promises';
import { pathToFileURL } from 'node:url';
import { promisify } from 'node:util';
import { test } from 'node:test';
import { ALGORITHM, manifestDigest } from '../scripts/soul-contracts.mjs';

const run = promisify(execFile);

test('concurrent verifiers publish a complete cache, repair it and still refuse a moved tag', async (t) => {
  const root = mkdtempSync(join(tmpdir(), 'hq-contract-cache-'));
  t.after(() => rmSync(root, { recursive: true, force: true }));
  const repository = 'https://github.com/fixture/contracts.git';
  const remote = join(root, 'remote');
  const cli = join(root, 'scripts/soul-contracts.mjs');
  const config = join(root, 'gitconfig');
  const env = { ...process.env, GIT_CONFIG_GLOBAL: config, GIT_CONFIG_NOSYSTEM: '1', GIT_ALLOW_PROTOCOL: 'file', HQ_INTERIM_OFFLINE: '0' };
  const git = (...args) => execFileSync('git', args, { env, encoding: 'utf8' }).trim();
  env.GIT_AUTHOR_NAME = env.GIT_COMMITTER_NAME = 'Contracts Fixture';
  env.GIT_AUTHOR_EMAIL = env.GIT_COMMITTER_EMAIL = 'fixture@example.invalid';
  git('config', '--file', config, `url.${pathToFileURL(remote).href}.insteadOf`, repository);
  git('init', '-q', remote);
  mkdirSync(join(remote, 'schemas/nested'), { recursive: true });
  const entries = ['schemas/ordinary', 'schemas/nested/contract', 'schemas/program', 'schemas/untouched'].map((path) => {
    const bytes = Buffer.from(path + '\n');
    const mode = path.endsWith('program') ? '100755' : '100644';
    writeFileSync(join(remote, path), bytes);
    chmodSync(join(remote, path), mode === '100755' ? 0o755 : 0o644);
    return { path, bytes, mode };
  });
  git('-C', remote, 'add', 'schemas');
  git('-C', remote, 'commit', '-qm', 'fixture');
  git('-C', remote, 'tag', '-a', 'v1.0.0', '-m', 'fixture');
  const commit = git('-C', remote, 'rev-parse', 'HEAD');
  const { digest, files } = manifestDigest(entries);
  mkdirSync(join(root, 'governance'));
  writeFileSync(join(root, 'governance/soul-contracts.json'), JSON.stringify({
    schema_version: 1, repository, tag: 'v1.0.0', commit, paths: ['schemas'], digest_algorithm: ALGORITHM, digest, files,
  }));
  mkdirSync(join(root, 'scripts'));
  mkdirSync(join(root, 'hq'));
  writeFileSync(join(root, 'hq/stage2a-h-preloader.mjs'),
    'export function authenticatedSelectedH() { return null; }\n');
  copyFileSync(new URL('../scripts/soul-contracts.mjs', import.meta.url), cli);
  copyFileSync(new URL('../scripts/h-v0103-excluded.mjs', import.meta.url),
    join(root, 'scripts/h-v0103-excluded.mjs'));
  const verify = () => run(process.execPath, [cli, 'verify'], { env });
  const cache = join(root, '.cache/soul-contracts');
  const tree = join(cache, commit);
  const checkTree = () => {
    for (const entry of entries) {
      const path = join(tree, entry.path);
      assert.deepEqual(readFileSync(path), entry.bytes);
    }
    assert.deepEqual(readdirSync(tree).sort(), ['.verified', 'schemas']);
    assert.deepEqual(readdirSync(join(tree, 'schemas')).sort(), ['nested', 'ordinary', 'program', 'untouched']);
  };

  // The reader is independent of the verifiers. From the first successful
  // return, even an already-running verifier must keep every path readable.
  async function concurrentVerification() {
    const jobs = Array.from({ length: 8 }, verify);
    const finished = Promise.allSettled(jobs);
    let done = false;
    finished.then(() => { done = true; });
    try {
      await Promise.any(jobs);
      do { checkTree(); await delay(1); } while (!done);
      const results = await Promise.all(jobs);
      for (const result of results) assert.ok(result.stdout.includes(tree));
      checkTree();
    } finally {
      await finished;
    }
  }

  await concurrentVerification();
  const program = join(tree, 'schemas/program');
  assert.ok(lstatSync(program).mode & 0o111);
  const untouched = lstatSync(join(tree, 'schemas/untouched')).ino;
  chmodSync(program, 0o644);
  writeFileSync(program, Buffer.alloc(lstatSync(program).size));
  mkdirSync(join(tree, 'schemas/unpinned'));
  rmSync(join(tree, 'schemas/nested'), { recursive: true });
  writeFileSync(join(tree, 'schemas/nested'), 'partial');
  rmSync(join(tree, 'schemas/ordinary'));
  mkdirSync(join(tree, 'schemas/ordinary'));
  writeFileSync(join(tree, 'schemas/ordinary/stale'), 'old');
  await concurrentVerification();
  assert.ok(lstatSync(program).mode & 0o111);
  assert.equal(lstatSync(join(tree, 'schemas/untouched')).ino, untouched);

  // An edited pin can describe the local cache perfectly while still being
  // inconsistent with its stated commit. Git remains the independent source.
  const pinPath = join(root, 'governance/soul-contracts.json');
  const originalPin = JSON.parse(readFileSync(pinPath, 'utf8'));
  const programEntry = entries.find((entry) => entry.path === 'schemas/program');
  for (const changed of [
    { ...programEntry, bytes: Buffer.from('different source bytes') },
    { ...programEntry, mode: '100644' },
  ]) {
    writeFileSync(program, changed.bytes);
    chmodSync(program, changed.mode === '100755' ? 0o755 : 0o644);
    const wrongDigest = manifestDigest(entries.map((entry) => entry === programEntry ? changed : entry)).digest;
    writeFileSync(pinPath, JSON.stringify({ ...originalPin, digest: wrongDigest }));
    await assert.rejects(verify(), /does not match the pin/);
    writeFileSync(pinPath, JSON.stringify(originalPin));
    await verify();
    checkTree();
    assert.ok(lstatSync(program).mode & 0o111);
  }
  mkdirSync(join(tree, 'schemas/empty'));
  await verify();
  checkTree();

  writeFileSync(join(remote, 'schemas/ordinary'), 'new revision');
  git('-C', remote, 'commit', '-qam', 'move fixture tag');
  git('-C', remote, 'tag', '-f', 'v1.0.0');
  await assert.rejects(verify(), /refusing a moved tag/);
  checkTree();
  git('-C', remote, 'tag', '-f', 'v1.0.0', commit);
  await verify();
  assert.deepEqual(readdirSync(cache), [commit]);
});
