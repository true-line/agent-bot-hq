import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { cpSync, existsSync, mkdtempSync, readFileSync, readdirSync, rmSync, unlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const native = process.platform === 'darwin' && process.arch === 'arm64';
const source = fileURLToPath(new URL('../helpers/macos-enclave', import.meta.url));
const plist = (file) => JSON.parse(execFileSync('/usr/bin/plutil', ['-convert', 'json', '-o', '-', file]));
const build = (src, out) => spawnSync('/bin/sh', [join(src, 'build.sh'), out], { encoding: 'utf8', timeout: 90_000 });

test('the Apple Silicon HQ signer builds reproducibly before provisioning', { skip: !native }, (t) => {
  const work = mkdtempSync(join(tmpdir(), 'hq-signer-bundle-'));
  t.after(() => rmSync(work, { recursive: true, force: true }));
  const copy = join(work, 'second checkout');
  cpSync(source, copy, { recursive: true });
  const outputs = [join(work, 'release one'), join(work, 'release two')];
  for (const [index, dir] of [source, copy].entries()) {
    const result = build(dir, outputs[index]);
    assert.equal(result.status, 0, result.stderr);
  }
  const app = 'AgentBotHQSigner.app';
  const info = join(app, 'Contents', 'Info.plist');
  const metadata = plist(join(outputs[0], info));
  assert.equal(metadata.CFBundleIdentifier, 'ai.true-line.hq.signer');
  assert.equal(metadata.CFBundleExecutable, 'agent-bot-hq-signer');
  assert.equal(metadata.CFBundlePackageType, 'APPL');
  assert.equal(metadata.LSMinimumSystemVersion, '15.0');
  assert.deepEqual(readdirSync(join(outputs[0], app, 'Contents')).sort(), ['Info.plist', 'MacOS']);
  assert.deepEqual(readdirSync(join(outputs[0], app, 'Contents/MacOS')), [metadata.CFBundleExecutable]);
  const entitlement = 'HQSigner.entitlements.in';
  const group = '$(AppIdentifierPrefix)' + metadata.CFBundleIdentifier;
  assert.deepEqual(plist(join(outputs[0], entitlement)), {
    'com.apple.developer.team-identifier': '$(DEVELOPMENT_TEAM)',
    'com.apple.application-identifier': group,
    'keychain-access-groups': [group],
  });
  const executable = join(app, 'Contents', 'MacOS', metadata.CFBundleExecutable);
  for (const file of [info, executable, entitlement]) {
    assert.deepEqual(readFileSync(join(outputs[0], file)), readFileSync(join(outputs[1], file)), file);
  }
  const program = join(outputs[0], executable);
  assert.equal(execFileSync('/usr/bin/lipo', ['-archs', program], { encoding: 'utf8' }).trim(), 'arm64');
  assert.match(execFileSync('/usr/bin/otool', ['-l', program], { encoding: 'utf8' }), /LC_BUILD_VERSION\s+cmdsize \d+\s+platform (1|MACOS)\s+minos 15\.0\b/i);
  const refused = spawnSync(program, ['status'], { env: { HOME: work }, input: '{}', encoding: 'utf8', timeout: 5000 });
  assert.equal(refused.status, 1);
  assert.equal(refused.stdout, '');
  assert.equal(refused.stderr.trim(), 'HQ Secure Enclave signer unavailable');

  assert.notEqual(build(source, outputs[0]).status, 0);
  assert.deepEqual(readFileSync(program), readFileSync(join(outputs[1], executable)));
  unlinkSync(join(copy, 'Signer.swift'));
  const incomplete = join(work, 'failed');
  assert.notEqual(build(copy, incomplete).status, 0);
  assert.equal(existsSync(incomplete), false);
});
