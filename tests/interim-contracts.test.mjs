import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { copyFileSync, mkdtempSync, mkdirSync, writeFileSync, symlinkSync, realpathSync, rmSync, chmodSync, truncateSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { H_PRIVATE_CONTRACTS_PIN, H_V0102_EXCLUDED, hRuntimeSelection, manifestDigest, readPin, verify,
  verifySelectedVendoredTree, verifyVendored } from '../scripts/soul-contracts.mjs';

test('vendored contracts verify exact content and refuse tampering and symlinks', () => {
  const dir = mkdtempSync(join(realpathSync(tmpdir()), 'hq-contracts-'));
  try {
    mkdirSync(join(dir, 'schemas'));
    const file = join(dir, 'schemas', 'one.json');
    writeFileSync(file, '{}\n');
    const pin = { paths: ['schemas'], ...manifestDigest([{path:'schemas/one.json', mode:'100644', bytes:Buffer.from('{}\n')}]) };
    assert.equal(verifyVendored(dir, pin).digest, pin.digest);
    const alias = `${dir}-alias`;
    symlinkSync(dir, alias, 'dir');
    try { assert.throws(() => verifyVendored(join(alias, 'schemas'), pin), /ancestry/); } finally { rmSync(alias); }
    writeFileSync(join(dir, 'unexpected'), '{}\n');
    assert.throws(() => verifyVendored(dir, pin), /root entries differ/);
    rmSync(join(dir, 'unexpected'));
    writeFileSync(join(dir, 'schemas', 'extra.json'), '{}\n');
    assert.throws(() => verifyVendored(dir, pin), /does not match/);
    rmSync(join(dir, 'schemas', 'extra.json'));
    chmodSync(file, 0o755);
    assert.throws(() => verifyVendored(dir, pin), /does not match/);
    chmodSync(file, 0o644);
    truncateSync(file, 8 * 1024 * 1024 + 1);
    assert.throws(() => verifyVendored(dir, pin), /size limit/);
    writeFileSync(file, '{"changed":true}\n');
    assert.throws(() => verifyVendored(dir, pin), /does not match/);
    rmSync(file);
    assert.throws(() => verifyVendored(dir, pin), /does not match/);
    symlinkSync('/etc/passwd', file);
    assert.throws(() => verifyVendored(dir, pin), /symlink/);
  } finally { rmSync(dir, { recursive:true, force:true }); }
});

test('importing the verifier from stdin, eval or print leaves CLI execution to the caller', async () => {
  const { spawnSync } = await import('node:child_process');
  const { fileURLToPath } = await import('node:url');
  const entry = fileURLToPath(new URL('../scripts/soul-contracts.mjs', import.meta.url));
  const expression = "import(process.argv.at(-1)).then(() => console.log('imported verifier'))";
  for (const args of [
    ['--input-type=module', '-', entry],
    ['-e', expression, entry], ['--eval', expression, entry], [`--eval=${expression}`, entry],
    ['-p', expression, entry], ['--print', expression, entry], ['--print=true', expression, entry], ['-pe', expression, entry],
  ]) {
    const result = spawnSync(process.execPath, args, {
      encoding: 'utf8', input: expression, env: { ...process.env, PATH: '/nonexistent', HQ_INTERIM_OFFLINE: '1' },
    });
    assert.equal(result.status, 0, result.stderr);
    assert.match(result.stdout, /^imported verifier$/m);
    assert.doesNotMatch(result.stdout, /ok soul-contracts/);
  }
});

test('interim mode verifies offline and missing payload never falls back to git', async () => {
  const { fileURLToPath } = await import('node:url');
  const dir = mkdtempSync(join(realpathSync(tmpdir()), 'hq-interim-'));
  try {
    for (const path of ['scripts', 'hq', 'governance', 'vendor/soul-contracts/schemas']) mkdirSync(join(dir, path), {recursive:true});
    writeFileSync(join(dir, 'hq/stage2a-h-preloader.mjs'),
      'export function authenticatedSelectedH() { return null; }\n');
    copyFileSync(fileURLToPath(new URL('../scripts/soul-contracts.mjs', import.meta.url)), join(dir,'scripts/soul-contracts.mjs'));
    const bytes = Buffer.from('{}\n');
    const digest = manifestDigest([{path:'schemas/one.json', mode:'100644', bytes}]);
    const pin = {schema_version:1, repository:'https://github.com/example/contracts.git', tag:'v1.0.0', commit:'a'.repeat(40), paths:['schemas'], digest_algorithm:'sha256-manifest-v1', digest:digest.digest, files:digest.files};
    writeFileSync(join(dir,'governance/soul-contracts.json'), JSON.stringify(pin));
    const file = join(dir,'vendor/soul-contracts/schemas/one.json');
    writeFileSync(file, bytes);
    const entry = join(dir, 'scripts/soul-contracts.mjs');
    const alias = join(dir, 'verify-contracts.mjs');
    symlinkSync(entry, alias);
    const run = (script) => spawnSync(process.execPath, [script, 'verify'], {encoding:'utf8', env:{...process.env, PATH:'/nonexistent', HQ_INTERIM_OFFLINE:'1'}});
    for (const script of [entry, alias]) {
      const result = run(script);
      assert.equal(result.status, 0);
      assert.match(result.stdout, /ok soul-contracts/);
    }
    rmSync(file);
    for (const script of [entry, alias]) {
      const refused = run(script);
      assert.equal(refused.status, 1);
      assert.match(refused.stderr, /does not match/);
      assert.doesNotMatch(refused.stderr, /spawnSync git/);
    }
  } finally { rmSync(dir,{recursive:true,force:true}); }
});

test('private H pin requires the exact candidate and a Machine-authenticated selected runtime', (t) => {
  const dir = mkdtempSync(join(realpathSync(tmpdir()), 'hq-private-pin-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'pin.json');
  const write = (pin) => writeFileSync(path, JSON.stringify(pin));
  write(H_PRIVATE_CONTRACTS_PIN);
  assert.deepEqual(readPin(path), H_PRIVATE_CONTRACTS_PIN);
  for (const changes of [{ tag: 'v0.10.2' }, { files: 583 }, { paths: ['errors,fixtures', 'schemas'] }]) {
    write({ ...H_PRIVATE_CONTRACTS_PIN, ...changes });
    assert.throws(() => readPin(path), /reviewed Contracts tuple/);
  }
  const entry = new URL('../scripts/soul-contracts.mjs', import.meta.url).href;
  for (const offline of ['0', '1']) {
    const result = spawnSync(process.execPath, ['--input-type=module', '-e',
      `import {verify,H_PRIVATE_CONTRACTS_PIN} from ${JSON.stringify(entry)}; verify(H_PRIVATE_CONTRACTS_PIN);`],
    { encoding: 'utf8', env: { ...process.env, PATH: '/nonexistent', HQ_INTERIM_OFFLINE: offline } });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /private H candidate requires (?:a sealed offline runtime|an authenticated selection)/);
  }
});

test('selected H Contracts verifies exactly the A-bound v0.10.2 runtime subset', () => {
  const pin = readPin();
  const full = verify(pin);
  const runtime = hRuntimeSelection(pin, full.manifest);
  assert.equal(runtime.files, 417);
  assert.equal(runtime.digest, 'sha256:94a60ddc910e1f30bdf380c384efd8a7952665d41789daa7ead973cd8c95b6d1');
  const changedFull = { ...full.manifest,
    [H_V0102_EXCLUDED[0]]: { ...full.manifest[H_V0102_EXCLUDED[0]], size: 1 } };
  assert.throws(() => hRuntimeSelection(pin, changedFull), /full source/);
  const root = mkdtempSync(join(realpathSync(tmpdir()), 'hq-selected-contracts-'));
  const dir = join(root, 'vendor/soul-contracts');
  try {
    mkdirSync(dir, { recursive: true });
    for (const path of Object.keys(full.manifest)) {
      const dest = join(dir, path);
      mkdirSync(dirname(dest), { recursive: true });
      copyFileSync(join(full.dir, path), dest);
    }
    for (const path of H_V0102_EXCLUDED) rmSync(join(dir, path));
    const rows = Object.entries(full.manifest)
      .filter(([path]) => !H_V0102_EXCLUDED.includes(path))
      .map(([path, item]) => ({ path: `vendor/soul-contracts/${path}`,
        sha256: `sha256:${item.sha256}`, size_bytes: item.size, mode: '0440' }));
    const metadata = { schema_version: 1, target_platform: 'darwin',
      contracts_commit: pin.commit, contracts_digest: pin.digest, contracts_runtime: runtime };
    const check = (m = metadata, r = rows) => verifySelectedVendoredTree(dir, pin, m, r);
    assert.equal(check().digest, runtime.digest);
    for (const path of ['scripts', 'hq', 'governance']) mkdirSync(join(root, path));
    const metadataBytes = Buffer.from(JSON.stringify(metadata) + '\n');
    writeFileSync(join(root, 'governance/interim-release.json'), metadataBytes);
    writeFileSync(join(root, 'governance/soul-contracts.json'), JSON.stringify(pin));
    copyFileSync(new URL('../scripts/soul-contracts.mjs', import.meta.url), join(root, 'scripts/soul-contracts.mjs'));
    const selection = { root,
      metadataSha256: 'sha256:' + createHash('sha256').update(metadataBytes).digest('hex'),
      metadataSize: metadataBytes.length, vendorRows: rows };
    // Only this disposable fixture has an env switch; production's getter is
    // set solely by the completed Machine-authenticated preloader.
    writeFileSync(join(root, 'hq/stage2a-h-preloader.mjs'),
      `const selected = ${JSON.stringify(selection)};\nexport function authenticatedSelectedH() { return process.env.TEST_AUTHENTICATED_H === '1' ? selected : null; }\n`);
    const entry = join(root, 'scripts/soul-contracts.mjs');
    const run = (authenticated) => spawnSync(process.execPath, [entry, 'verify'], {
      encoding: 'utf8', env: { ...process.env, PATH: '/nonexistent',
        HQ_INTERIM_OFFLINE: '1', TEST_AUTHENTICATED_H: authenticated ? '1' : '0' } });
    assert.equal(run(true).status, 0);
    const envOnly = run(false);
    assert.equal(envOnly.status, 1);
    assert.match(envOnly.stderr, /does not match/);
    const changedMetadata = JSON.parse(JSON.stringify(metadata));
    changedMetadata.contracts_runtime.excluded_hq_release_paths.pop();
    assert.throws(() => check(changedMetadata), /metadata/);
    const changedRows = rows.map((row) => ({ ...row }));
    changedRows[0].sha256 = 'sha256:' + '0'.repeat(64);
    assert.throws(() => check(metadata, changedRows), /row/);
    const omitted = H_V0102_EXCLUDED[0];
    copyFileSync(join(full.dir, omitted), join(dir, omitted));
    assert.throws(() => check(), /subset/);
    rmSync(join(dir, omitted));
    const schema = Object.keys(full.manifest).find((path) => path.startsWith('schemas/'));
    rmSync(join(dir, schema));
    assert.throws(() => check(), /subset/);
    copyFileSync(join(full.dir, schema), join(dir, schema));
    writeFileSync(join(dir, schema), '{}\n');
    assert.throws(() => check(), /subset/);
  } finally { rmSync(root, { recursive: true, force: true }); }
});
