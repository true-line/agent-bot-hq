// Pin and stage an exact agent-bot-souls source tree for an HQ artifact.
// This pin currently names an unreleased source commit, not a release or
// protected qualification. No network fetch or mutable checkout bytes enter
// the artifact: all staged bytes come from the pinned Git commit's blobs.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { manifestDigest, verifyVendored } from './soul-contracts.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
const PIN_PATH = join(ROOT, 'governance/soul-runner.json');
const PATHS = ['bin', 'governance', 'lib', 'package.json'];

export function readSoulRunnerPin(path = PIN_PATH) {
  const pin = JSON.parse(readFileSync(path, 'utf8'));
  if (pin.schema_version !== 1 || pin.repository !== 'https://github.com/true-line/agent-bot-souls.git'
    || !/^[0-9a-f]{40}$/.test(pin.source_commit ?? '') || pin.source_status !== 'unreleased-source'
    || JSON.stringify(pin.paths) !== JSON.stringify(PATHS) || pin.digest_algorithm !== 'sha256-manifest-v1'
    || !/^sha256:[0-9a-f]{64}$/.test(pin.digest ?? '') || !Number.isSafeInteger(pin.files) || pin.files < 1) {
    throw new Error('invalid pinned Soul runner source manifest');
  }
  return pin;
}

export function sourceEntries(source, pin = readSoulRunnerPin()) {
  const git = (...args) => execFileSync('git', ['-C', resolve(source), ...args], { maxBuffer: 32 << 20 });
  const kind = git('cat-file', '-t', pin.source_commit).toString().trim();
  if (kind !== 'commit') throw new Error('pinned Soul runner source is not a commit');
  const lines = git('ls-tree', '-r', '-z', pin.source_commit, '--', ...pin.paths).toString('utf8').split('\0').filter(Boolean);
  const entries = lines.map((line) => {
    const tab = line.indexOf('\t');
    if (tab < 0) throw new Error('malformed Soul runner tree entry');
    const [mode, type, oid] = line.slice(0, tab).split(' ');
    const path = line.slice(tab + 1);
    if (type !== 'blob' || !['100644', '100755'].includes(mode) || !PATHS.some((root) => path === root || path.startsWith(`${root}/`))) {
      throw new Error(`unsupported Soul runner tree entry: ${path}`);
    }
    return { path, mode, bytes: git('cat-file', 'blob', oid) };
  });
  const got = manifestDigest(entries);
  if (got.digest !== pin.digest || got.files !== pin.files) throw new Error('Soul runner source content or mode differs from the pin');
  return entries;
}

export function stageSoulRunner(source, destination, pin = readSoulRunnerPin()) {
  if (existsSync(destination)) throw new Error('Soul runner destination already exists');
  const entries = sourceEntries(source, pin);
  for (const { path, mode, bytes } of entries) {
    const target = join(destination, path);
    mkdirSync(dirname(target), { recursive: true });
    writeFileSync(target, bytes, { mode: mode === '100755' ? 0o755 : 0o644 });
  }
  return verifyVendored(destination, pin);
}

export function verifyBundledSoulRunner(root = ROOT, pin = readSoulRunnerPin()) {
  const dir = join(root, 'vendor/agent-bot-souls');
  if (!existsSync(dir)) throw new Error('bundled Soul runner is missing');
  return verifyVendored(dir, pin);
}
