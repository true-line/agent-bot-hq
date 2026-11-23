import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { chmodSync, mkdirSync, mkdtempSync, readFileSync, realpathSync,
  renameSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import test from 'node:test';
import { assertSelectedHQCodeDigest, selectedHQCodeHooks,
  verifySelectedHQCode } from '../hq/stage2a-selected-code.mjs';

const digest = (bytes) => createHash('sha256').update(bytes).digest('hex');

test('protected H binding refuses before a Machine-authenticated preload', () => {
  assert.throws(() => assertSelectedHQCodeDigest(`sha256:${'0'.repeat(64)}`), /unavailable/);
});

function fixture(fn) {
  const root = mkdtempSync(join(tmpdir(), 'stage2a-h-code-'));
  // macOS /var is a symlink; the verifier accepts only the canonical path.
  const path = realpathSync(root);
  try {
    mkdirSync(join(path, 'lib'), { mode: 0o700 });
    writeFileSync(join(path, 'main.mjs'), 'import "./lib/ok.mjs";\n');
    writeFileSync(join(path, 'lib/ok.mjs'), 'export default 1;\n');
    chmodSync(join(path, 'main.mjs'), 0o440);
    chmodSync(join(path, 'lib/ok.mjs'), 0o440);
    chmodSync(join(path, 'lib'), 0o550);
    chmodSync(path, 0o555);
    const records = ['lib/ok.mjs', 'main.mjs'].map((name) => {
      const bytes = readFileSync(join(path, name));
      return { path: name, kind: 'regular', mode: '0440', size_bytes: bytes.length,
        sha256: `sha256:${digest(bytes)}`, component_id: 'hq', release_path: name };
    });
    const directories = [{ path: 'lib', kind: 'directory', mode: '0550' }];
    const options = { root: path, directories, records, uid: process.getuid(), gid: process.getgid(),
      rootMode: 0o555, maxFiles: 2,
      maxFileBytes: 1000, maxBytes: 1000 };
    return fn({ root: path, directories, records, options });
  } finally {
    chmodSync(path, 0o700);
    chmodSync(join(path, 'lib'), 0o700);
    rmSync(path, { recursive: true, force: true });
  }
}

test('selected H tree accepts exact files and refuses unlisted or changed modules', () => fixture(({ root, options }) => {
  const selected = verifySelectedHQCode(options);
  assert.equal(selected.count, 2);
  const hooks = selectedHQCodeHooks(selected);
  const main = pathToFileURL(join(root, 'main.mjs')).href;
  const source = readFileSync(join(root, 'main.mjs'));
  assert.equal(hooks.resolve('./main.mjs', {}, () => ({ url: main })).url, main);
  assert.deepEqual(hooks.load(main, {}, () => { throw new Error('unverified loader reached'); }).source, source);
  selected.files.set(join(root, 'late.mjs'), digest('export default 2;\n'));
  assert.throws(() => hooks.resolve('./late.mjs', {}, () =>
    ({ url: pathToFileURL(join(root, 'late.mjs')).href })), /unavailable/);
  assert.throws(() => hooks.load('data:text/javascript,export default 1', {}, () => ({})), /unavailable/);
  assert.throws(() => hooks.load(main + '?late=1', {}, () => ({})), /unavailable/);
  for (const builtin of ['node:vm', 'node:module', 'node:worker_threads', 'node:repl',
    'node:inspector', 'node:wasi']) {
    assert.throws(() => hooks.resolve(builtin, {}, () => ({ url: builtin })), /unavailable/);
  }
  chmodSync(join(root, 'main.mjs'), 0o640);
  writeFileSync(join(root, 'main.mjs'), 'export default 3;\n');
  chmodSync(join(root, 'main.mjs'), 0o440);
  assert.throws(() => hooks.load(main, {}, () => ({})), /unavailable/);
}));

test('selected H load refuses a new inode even when bytes match', () => fixture(({ root, options }) => {
  const selected = verifySelectedHQCode(options);
  const hooks = selectedHQCodeHooks(selected);
  const mainPath = join(root, 'main.mjs');
  const main = pathToFileURL(mainPath).href;
  const bytes = readFileSync(mainPath);
  chmodSync(root, 0o700);
  writeFileSync(join(root, 'replacement.mjs'), bytes);
  chmodSync(join(root, 'replacement.mjs'), 0o440);
  renameSync(join(root, 'replacement.mjs'), mainPath);
  chmodSync(root, 0o555);
  assert.throws(() => hooks.load(main, {}, () => ({})), /unavailable/);
}));

test('selected H executable mode follows its signed file row', () => fixture(({ root, options, records }) => {
  chmodSync(join(root, 'main.mjs'), 0o550);
  records[1] = { ...records[1], mode: '0550' };
  assert.equal(verifySelectedHQCode(options).count, 2);
  records[1] = { ...records[1], mode: '0440' };
  assert.throws(() => verifySelectedHQCode(options), /unavailable/);
}));

test('selected H tree refuses extra files, directories, links, and mutated bytes', () => fixture(({ root, options }) => {
  chmodSync(root, 0o700);
  writeFileSync(join(root, 'late.mjs'), 'export default 2;\n');
  chmodSync(root, 0o555);
  assert.throws(() => verifySelectedHQCode(options), /unavailable/);
  chmodSync(root, 0o700);
  rmSync(join(root, 'late.mjs'));
  mkdirSync(join(root, 'empty'), { mode: 0o550 });
  chmodSync(root, 0o555);
  assert.throws(() => verifySelectedHQCode(options), /unavailable/);
  chmodSync(root, 0o700);
  rmSync(join(root, 'empty'), { recursive: true });
  symlinkSync('main.mjs', join(root, 'alias.mjs'));
  chmodSync(root, 0o555);
  assert.throws(() => verifySelectedHQCode(options), /unavailable/);
  chmodSync(root, 0o700);
  rmSync(join(root, 'alias.mjs'));
  chmodSync(root, 0o555);
  chmodSync(join(root, 'main.mjs'), 0o640);
  writeFileSync(join(root, 'main.mjs'), 'export default 3;\n');
  chmodSync(join(root, 'main.mjs'), 0o440);
  assert.throws(() => verifySelectedHQCode(options), /unavailable/);
}));

test('selected H tree refuses incomplete or aliased records', () => fixture(({ options, directories, records }) => {
  assert.throws(() => verifySelectedHQCode({ ...options, records: records.slice(0, 1) }), /unavailable/);
  assert.throws(() => verifySelectedHQCode({ ...options, directories: [] }), /unavailable/);
  assert.throws(() => verifySelectedHQCode({ ...options, directories: [...directories, directories[0]] }), /unavailable/);
  assert.throws(() => verifySelectedHQCode({ ...options, records: [...records, records[1]] }), /unavailable/);
  assert.throws(() => verifySelectedHQCode({ ...options, maxFiles: 1 }), /unavailable/);
  assert.throws(() => verifySelectedHQCode({ ...options, maxBytes: 1 }), /unavailable/);
  assert.throws(() => verifySelectedHQCode({ ...options, maxFileBytes: 1 }), /unavailable/);
  assert.throws(() => verifySelectedHQCode({ ...options, rootMode: 0o550 }), /unavailable/);
  assert.throws(() => verifySelectedHQCode({ ...options, records: records.map((r) =>
    r.path === 'main.mjs' ? { ...r, mode: '0777' } : r) }), /unavailable/);
}));

test('Node loads the selected graph and blocks a later outside import', () => fixture(({ root, options }) => {
  const guard = new URL('../hq/stage2a-selected-code.mjs', import.meta.url).href;
  const main = pathToFileURL(join(root, 'main.mjs')).href;
  const descriptorDigest = `sha256:${digest('signed H descriptor')}`;
  const source = `import { verifySelectedHQCode, registerSelectedHQCode, assertSelectedHQCodeDigest } from ${JSON.stringify(guard)};
    registerSelectedHQCode(verifySelectedHQCode(${JSON.stringify(options)}), ${JSON.stringify(descriptorDigest)});
    assertSelectedHQCodeDigest(${JSON.stringify(descriptorDigest)});
    try { assertSelectedHQCodeDigest('sha256:${'0'.repeat(64)}'); process.exitCode = 8; }
    catch (error) { if (!error.message.includes('Machine selected HQ code is unavailable')) throw error; }
    await import(${JSON.stringify(main)});
    try { await import('data:text/javascript,export default 1'); process.exitCode = 7; }
    catch (error) { if (!error.message.includes('Machine selected HQ code is unavailable')) throw error; }
    console.log('selected graph loaded; late import refused');`;
  const child = spawnSync(process.execPath, ['--no-addons',
    '--disallow-code-generation-from-strings', '--input-type=module', '--eval', source],
    { encoding: 'utf8', timeout: 10_000 });
  assert.equal(child.status, 0, child.stderr);
  assert.match(child.stdout, /selected graph loaded; late import refused/);
  const withoutNoAddons = spawnSync(process.execPath, ['--input-type=module', '--eval', source],
    { encoding: 'utf8', timeout: 10_000 });
  assert.notEqual(withoutNoAddons.status, 0);
  assert.match(withoutNoAddons.stderr, /Machine selected HQ code is unavailable/);
  const withoutNoCodegen = spawnSync(process.execPath, ['--no-addons', '--input-type=module', '--eval', source],
    { encoding: 'utf8', timeout: 10_000 });
  assert.notEqual(withoutNoCodegen.status, 0);
  assert.match(withoutNoCodegen.stderr, /Machine selected HQ code is unavailable/);
}));
