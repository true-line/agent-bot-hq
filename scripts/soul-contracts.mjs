#!/usr/bin/env node
// Pin of the true-line/soul-contracts release this repository builds against (D5, §9 PR 7).
//
//   node scripts/soul-contracts.mjs [verify]   fetch the pinned release into .cache/ and check it
//   node scripts/soul-contracts.mjs pin <tag>  re-pin to a newer tag (pins never move backwards, §4.5)
//
// The repository keeps no copy of the contracts. The fetched, digest-checked
// tree under .cache/soul-contracts/<commit>/ is what tests load (§4.6).
//
// Digest (sha256-manifest-v1, the §5.3 package framing): a manifest maps each
// pinned file's path to { sha256, size, mode } (git modes 100644 / 100755);
// the digest is the SHA-256 of the manifest's RFC 8785 (JCS) bytes.
import { createHash } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { closeSync, constants, fstatSync, lstatSync, mkdirSync, mkdtempSync, openSync, readFileSync, readSync, readdirSync, realpathSync, renameSync, rmSync, unlinkSync, writeFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { authenticatedSelectedH } from '../hq/stage2a-h-preloader.mjs';

const ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..');
export const PIN_PATH = join(ROOT, 'governance/soul-contracts.json');
export const ALGORITHM = 'sha256-manifest-v1';
const CACHE = join(ROOT, '.cache/soul-contracts');
const MODES = new Set(['100644', '100755']);
const H_V0102 = Object.freeze({
  tag: 'v0.10.2',
  commit: 'b216ae9f5889ba00d38ef9b3e3bc9f60f54e90bd',
  digest: 'sha256:baafaeab591c30480c5d172b7ac3db39ffd01f0c0d420e338ffce71b839c58e2',
  files: 469,
  runtimeDigest: 'sha256:54be96221e034b0878bee9aaaa42595c5d81d452162db84ff15f1a0354850012',
  runtimeFiles: 418,
});
const VENDOR_PREFIX = 'vendor/soul-contracts/';
export const H_V0102_EXCLUDED = Object.freeze([
  'fixtures/negative/domain-inventory.v3-synthetic.bad.json',
  'fixtures/negative/h-service-descriptor-payload.v3-synthetic.bad.json',
  'fixtures/negative/h-service-descriptor-signed.v3-synthetic.bad.json',
  'fixtures/negative/inventory-ref.v3-synthetic.bad.json',
  'fixtures/negative/measurement-binding.v3-synthetic.bad.json',
  'fixtures/negative/soul-cooperative-bridge-assignment-payload.missing-reservation.json',
  'fixtures/negative/soul-cooperative-bridge-signed-assignment.wrong-purpose.json',
  'fixtures/negative/soul-cooperative-reservation-payload.bridge-claim.json',
  'fixtures/negative/soul-cooperative-reservation-payload.missing-broker.json',
  'fixtures/negative/soul-cooperative-signed-reservation.wrong-purpose.json',
  'fixtures/negative/stage2a-q-begin.synthetic.bad.json',
  'fixtures/negative/stage2a-q-clean-eof.synthetic.bad.json',
  'fixtures/negative/stage2a-q-framed-wire.synthetic.bad.json',
  'fixtures/negative/stage2a-q-pre-sign-index.synthetic.bad.json',
  'fixtures/negative/stage2a-q-ready.synthetic.bad.json',
  'fixtures/negative/stage2a-q-signed-eof.synthetic.bad.json',
  'fixtures/negative/stage2a-q-signed-index.synthetic.bad.json',
  'fixtures/negative/stage2a-qualification-candidate-binding.v3-synthetic.bad.json',
  'fixtures/negative/stage2a-qualification-candidate-reservation-payload.v3-synthetic.bad.json',
  'fixtures/negative/stage2a-qualification-candidate-signed-reservation.v3-synthetic.bad.json',
  'fixtures/negative/stage2a-reservation-payload.v3-synthetic.bad.json',
  'fixtures/negative/stage2a-signed-reservation.v3-synthetic.bad.json',
  'fixtures/positive/domain-inventory.v3-synthetic.json',
  'fixtures/positive/h-service-descriptor-payload.v3-synthetic.json',
  'fixtures/positive/h-service-descriptor-signed.v3-synthetic.json',
  'fixtures/positive/inventory-ref.v3-synthetic.json',
  'fixtures/positive/measurement-binding.v3-synthetic.json',
  'fixtures/positive/soul-cooperative-bridge-assignment-payload.v3-synthetic.json',
  'fixtures/positive/soul-cooperative-bridge-signed-assignment.v3-synthetic.json',
  'fixtures/positive/soul-cooperative-reservation-payload.v3-synthetic.json',
  'fixtures/positive/soul-cooperative-signed-reservation.v3-synthetic.json',
  'fixtures/positive/stage2a-q-begin.synthetic.json',
  'fixtures/positive/stage2a-q-clean-eof.synthetic.json',
  'fixtures/positive/stage2a-q-framed-wire.synthetic.json',
  'fixtures/positive/stage2a-q-pre-sign-index.synthetic.json',
  'fixtures/positive/stage2a-q-ready.synthetic.json',
  'fixtures/positive/stage2a-q-signed-eof.synthetic.json',
  'fixtures/positive/stage2a-q-signed-index.synthetic.json',
  'fixtures/positive/stage2a-qualification-candidate-binding.v3-synthetic.json',
  'fixtures/positive/stage2a-qualification-candidate-reservation-payload.v3-synthetic.json',
  'fixtures/positive/stage2a-qualification-candidate-signed-reservation.v3-synthetic.json',
  'fixtures/positive/stage2a-reservation-payload.v3-synthetic.json',
  'fixtures/positive/stage2a-signed-reservation.v3-synthetic.json',
  'fixtures/qualification/v3/q-presign-argv-synthetic.json',
  'fixtures/reservation/v3/machine-qualification-candidate-invalid-bytes.json',
  'fixtures/reservation/v3/machine-qualification-candidate-synthetic.json',
  'fixtures/reservation/v3/soul-cooperative-launch-inputs.brokered-b.synthetic.json',
  'fixtures/reservation/v3/soul-cooperative-launch-inputs.synthetic.json',
  'fixtures/reservation/v3/soul-cooperative-r-inventory.synthetic.json',
  'fixtures/reservation/v3/soul-cooperative-signed-reservation.brokered-b.synthetic.json',
  'fixtures/reservation/v3/soul-cooperative-signed-reservation.synthetic.json',
]);

const sha256 = (buf) => createHash('sha256').update(buf).digest('hex');

// RFC 8785 for the values a manifest holds: objects, strings and safe integers.
// Keys sort by UTF-16 code units (JavaScript's default sort); strings and
// integers serialize as ECMAScript JSON does, which is what JCS specifies.
export function canonicalize(value) {
  if (typeof value === 'string') return JSON.stringify(value);
  if (Number.isSafeInteger(value)) return JSON.stringify(value);
  if (value && typeof value === 'object' && !Array.isArray(value)) {
    return `{${Object.keys(value).sort().map((k) => `${JSON.stringify(k)}:${canonicalize(value[k])}`).join(',')}}`;
  }
  throw new TypeError(`manifest values are objects, strings or safe integers, got ${JSON.stringify(value)}`);
}

// entries: [{ path, mode, bytes }]. Returns { manifest, digest, files }.
export function manifestDigest(entries) {
  const manifest = {};
  for (const { path, mode, bytes } of entries) {
    if (!MODES.has(mode)) throw new Error(`${path}: unsupported mode ${mode} (only regular files are pinned)`);
    if (path.startsWith('/') || path.split('/').some((s) => s === '' || s === '.' || s === '..')) throw new Error(`${path}: not a canonical relative path`);
    if (path in manifest) throw new Error(`${path}: duplicate`);
    manifest[path] = { sha256: sha256(bytes), size: bytes.length, mode };
  }
  return { manifest, digest: `sha256:${sha256(Buffer.from(canonicalize(manifest), 'utf8'))}`, files: entries.length };
}

const isHV0102 = (pin) => pin.tag === H_V0102.tag && pin.commit === H_V0102.commit
  && pin.digest === H_V0102.digest && pin.files === H_V0102.files;

// The raw release is checked against the entire pin before this projection is
// computed. Machine A separately proves selected+excluded equals that full
// release at installation; H rechecks the exact selected bytes at startup.
export function hRuntimeSelection(pin, fullManifest) {
  if (!isHV0102(pin) || !fullManifest || typeof fullManifest !== 'object'
    || Array.isArray(fullManifest) || Object.keys(fullManifest).length !== H_V0102.files
    || H_V0102_EXCLUDED.some((path) => !Object.hasOwn(fullManifest, path))) {
    throw new Error('H runtime Contracts selection is unavailable for this release');
  }
  if (`sha256:${sha256(Buffer.from(canonicalize(fullManifest), 'utf8'))}` !== pin.digest) {
    throw new Error('H runtime Contracts full source differs from the pin');
  }
  const omitted = new Set(H_V0102_EXCLUDED);
  const selected = Object.fromEntries(Object.entries(fullManifest).filter(([path]) => !omitted.has(path)));
  const digest = `sha256:${sha256(Buffer.from(canonicalize(selected), 'utf8'))}`;
  if (Object.keys(selected).length !== H_V0102.runtimeFiles || digest !== H_V0102.runtimeDigest) {
    throw new Error('H runtime Contracts selection differs from the reviewed release');
  }
  return Object.freeze({ digest_algorithm: ALGORITHM, digest, files: H_V0102.runtimeFiles,
    excluded_hq_release_paths: Object.freeze(H_V0102_EXCLUDED.map((path) => `${VENDOR_PREFIX}${path}`)) });
}

export function compareSemver(a, b) {
  const parse = (t) => {
    const m = /^v?(\d+)\.(\d+)\.(\d+)$/.exec(t);
    if (!m) throw new Error(`${t}: release tags are vMAJOR.MINOR.PATCH`);
    return m.slice(1).map(Number);
  };
  const [x, y] = [parse(a), parse(b)];
  for (let i = 0; i < 3; i++) if (x[i] !== y[i]) return x[i] < y[i] ? -1 : 1;
  return 0;
}

export function readPin(path = PIN_PATH) {
  const pin = JSON.parse(readFileSync(path, 'utf8'));
  const problems = [];
  if (pin.schema_version !== 1) problems.push('schema_version must be 1');
  if (!/^https:\/\/github\.com\/[\w.-]+\/[\w.-]+\.git$/.test(pin.repository ?? '')) problems.push('repository must be an https GitHub URL ending in .git');
  if (!/^v\d+\.\d+\.\d+$/.test(pin.tag ?? '')) problems.push('tag must be vMAJOR.MINOR.PATCH');
  if (!/^[0-9a-f]{40}$/.test(pin.commit ?? '')) problems.push('commit must be a full 40-hex SHA');
  if (!Array.isArray(pin.paths) || pin.paths.length === 0 || [...pin.paths].sort().join() !== pin.paths.join()) problems.push('paths must be a non-empty sorted list');
  if (pin.digest_algorithm !== ALGORITHM) problems.push(`digest_algorithm must be ${ALGORITHM}`);
  if (!/^sha256:[0-9a-f]{64}$/.test(pin.digest ?? '')) problems.push('digest must be sha256:<64 hex>');
  if (!Number.isSafeInteger(pin.files) || pin.files < 1) problems.push('files must be a positive integer');
  if (problems.length) throw new Error(`${path}: ${problems.join('; ')}`);
  return pin;
}

const git = (args, opts = {}) => execFileSync('git', args, { maxBuffer: 1 << 28, ...opts });

// A private shallow fetch has no shared refs, index or FETCH_HEAD. Keep its
// scratch on the cache filesystem so a complete verified tree can be renamed.
function withFetchedTag(repository, tag, use) {
  mkdirSync(CACHE, { recursive: true });
  const work = mkdtempSync(join(CACHE, '.verify-'));
  try {
    const repo = join(work, 'repo.git');
    git(['init', '-q', '--bare', repo]);
    git(['-C', repo, '-c', 'credential.helper=', 'fetch', '-q', '--depth', '1', '--no-tags', repository, `refs/tags/${tag}`],
      { env: { ...process.env, GIT_TERMINAL_PROMPT: '0' } });
    const commit = git(['-C', repo, 'rev-parse', 'FETCH_HEAD^{commit}']).toString().trim();
    return use(repo, commit, work);
  } finally {
    rmSync(work, { recursive: true, force: true });
  }
}

// Read the pinned paths of <commit> straight from git objects (modes as git records them).
function treeEntries(repo, commit, paths) {
  const listing = git(['-C', repo, 'ls-tree', '-r', '-z', commit, '--', ...paths]).toString();
  return listing.split('\0').filter(Boolean).map((line) => {
    const [meta, path] = line.split('\t');
    const [mode, type, oid] = meta.split(' ');
    if (type !== 'blob') throw new Error(`${path}: ${type} entries are not pinned`);
    return { path, mode, bytes: git(['-C', repo, 'cat-file', 'blob', oid]) };
  });
}

// Publish a complete new subtree in one rename. Existing cache directories
// may already be in use by callers of verify(). Repair their entries in
// place: rename complete files over old files and remove only unpinned names.
function publishTree(source, target, work) {
  const staged = lstatSync(source);
  const directory = staged.isDirectory();
  let current = lstatSync(target, { throwIfNoEntry: false });
  if (!current) {
    try { renameSync(source, target); return; } catch (error) {
      current = lstatSync(target, { throwIfNoEntry: false });
      if (!current) throw error;
    }
  }
  if (directory && current.isDirectory()) {
    const names = new Set(readdirSync(source));
    for (const name of names) publishTree(join(source, name), join(target, name), work);
    for (const name of readdirSync(target)) {
      if (!names.has(name)) rmSync(join(target, name), { recursive: true, force: true });
    }
    return;
  }
  if (directory) {
    // unlink cannot remove the directory if another verifier repaired it.
    try { unlinkSync(target); } catch (error) {
      if (error.code !== 'ENOENT' && !lstatSync(target, { throwIfNoEntry: false })?.isDirectory()) throw error;
    }
    publishTree(source, target, work);
    return;
  }
  if (current.isFile() && current.size === staged.size && (current.mode & 0o7777) === (staged.mode & 0o7777)) {
    try { if (readFileSync(target).equals(readFileSync(source))) return; } catch (error) {
      if (error.code !== 'EACCES' && error.code !== 'EPERM') throw error;
    }
  }
  if (current.isDirectory()) {
    // Moving onto a directory can only displace the unwanted directory;
    // a concurrent writer's already published regular file cannot be moved.
    const discard = mkdtempSync(join(work, 'discard-'));
    try { renameSync(target, discard); } catch (error) {
      if (error.code !== 'ENOENT' && lstatSync(target, { throwIfNoEntry: false })?.isDirectory()) throw error;
    }
  }
  renameSync(source, target);
}

function materialize(dir, entries, work) {
  const stage = join(work, 'tree');
  for (const { path, mode, bytes } of entries) {
    const file = join(stage, path);
    mkdirSync(dirname(file), { recursive: true });
    writeFileSync(file, bytes, { mode: mode === '100755' ? 0o755 : 0o644 });
  }
  writeFileSync(join(stage, '.verified'), '');
  publishTree(stage, dir, work);
}

// The raw interim artifact keeps and verifies the complete public Contracts
// tree. The protected H snapshot uses the separately authenticated selection
// below; neither path falls back to the network.
function vendoredEntries(dir, paths) {
  const root = resolve(dir);
  for (let path = root; ; path = dirname(path)) {
    const stat = lstatSync(path);
    if (stat.isSymbolicLink() || !stat.isDirectory()) throw new Error('vendored contracts ancestry must be directories without symlinks');
    if (dirname(path) === path) break;
  }
  if (JSON.stringify(readdirSync(root).sort()) !== JSON.stringify([...paths].sort())) throw new Error('vendored contracts root entries differ from the pin');
  const entries = [];
  let total = 0;
  const maxFile = 8 * 1024 * 1024, maxTotal = 32 * 1024 * 1024;
  function visit(relative) {
    const path = join(root, relative);
    const stat = lstatSync(path);
    if (stat.isSymbolicLink()) throw new Error(`vendored contracts contain a symlink: ${relative}`);
    if (stat.isDirectory()) {
      for (const name of readdirSync(path).sort()) visit(`${relative}/${name}`);
    } else if (stat.isFile()) {
      const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        const opened = fstatSync(fd);
        if (!opened.isFile() || opened.size > maxFile || (total += opened.size) > maxTotal) throw new Error(`vendored contracts exceed size limit: ${relative}`);
        const bytes = Buffer.alloc(opened.size);
        let offset = 0;
        while (offset < bytes.length) { const n = readSync(fd, bytes, offset, bytes.length - offset, null); if (!n) throw new Error(`vendored contracts changed while reading: ${relative}`); offset += n; }
        if (readSync(fd, Buffer.alloc(1), 0, 1, null)) throw new Error(`vendored contracts changed while reading: ${relative}`);
        entries.push({ path: relative, mode: (opened.mode & 0o111) ? '100755' : '100644', bytes });
      } finally { closeSync(fd); }
    } else throw new Error(`vendored contracts contain a non-regular file: ${relative}`);
  }
  for (const path of paths) visit(path);
  return { root, entries };
}

export function verifyVendored(dir, pin = readPin()) {
  const { root, entries } = vendoredEntries(dir, pin.paths);
  const got = manifestDigest(entries);
  if (got.digest !== pin.digest || got.files !== pin.files) throw new Error(`vendored soul-contracts digest ${got.digest} (${got.files} files) does not match the pin ${pin.digest} (${pin.files} files)`);
  return { dir: root, ...got };
}

// This check is selected only by the actual Machine-authenticated H preloader.
// The selected inventory has already measured every file in the A-owned H
// snapshot. Recompute the source-mode manifest here so an omitted, extra or
// changed Contracts file cannot be accepted by metadata alone.
export function verifySelectedVendored(dir, pin, selection) {
  if (!isHV0102(pin) || !selection || selection.root !== ROOT
    || !/^sha256:[0-9a-f]{64}$/.test(selection.metadataSha256)
    || !Number.isSafeInteger(selection.metadataSize) || selection.metadataSize < 1
    || selection.metadataSize > 65536 || !Array.isArray(selection.vendorRows)) {
    throw new Error('authenticated H Contracts selection is unavailable');
  }
  const metadataPath = join(ROOT, 'governance/interim-release.json');
  const fd = openSync(metadataPath, constants.O_RDONLY | constants.O_NOFOLLOW);
  let metadataBytes;
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.size !== selection.metadataSize) throw new Error('H release metadata differs from Machine inventory');
    metadataBytes = readFileSync(fd);
  } finally { closeSync(fd); }
  if (metadataBytes.length !== selection.metadataSize
    || `sha256:${sha256(metadataBytes)}` !== selection.metadataSha256) {
    throw new Error('H release metadata differs from Machine inventory');
  }
  const metadata = JSON.parse(metadataBytes.toString('utf8'));
  return verifySelectedVendoredTree(dir, pin, metadata, selection.vendorRows);
}

// Pure content check for the authenticated wrapper above. A direct call to
// this helper does not set preloader state or grant protected launch authority.
export function verifySelectedVendoredTree(dir, pin, metadata, vendorRows) {
  if (!isHV0102(pin) || !metadata || typeof metadata !== 'object'
    || !Array.isArray(vendorRows)) {
    throw new Error('H release metadata does not bind the reviewed Contracts subset');
  }
  const runtime = metadata?.contracts_runtime;
  if (metadata.schema_version !== 1 || metadata.target_platform !== 'darwin'
    || metadata.contracts_commit !== pin.commit || metadata.contracts_digest !== pin.digest
    || !runtime || typeof runtime !== 'object' || Array.isArray(runtime)
    || Object.keys(runtime).sort().join(',') !== ['digest_algorithm', 'digest', 'files',
      'excluded_hq_release_paths'].sort().join(',')
    || runtime.digest_algorithm !== ALGORITHM || runtime.digest !== H_V0102.runtimeDigest
    || runtime.files !== H_V0102.runtimeFiles
    || JSON.stringify(runtime.excluded_hq_release_paths) !== JSON.stringify(
      H_V0102_EXCLUDED.map((path) => `${VENDOR_PREFIX}${path}`))) {
    throw new Error('H release metadata does not bind the reviewed Contracts subset');
  }
  const { root, entries } = vendoredEntries(dir, pin.paths);
  const got = manifestDigest(entries);
  if (got.digest !== runtime.digest || got.files !== runtime.files
    || vendorRows.length !== runtime.files) {
    throw new Error('vendored H Contracts subset differs from the reviewed release');
  }
  const seen = new Set();
  for (const row of vendorRows) {
    if (!row || typeof row.path !== 'string' || !row.path.startsWith(VENDOR_PREFIX)
      || row.mode !== '0440' || !Number.isSafeInteger(row.size_bytes)
      || !/^sha256:[0-9a-f]{64}$/.test(row.sha256)) {
      throw new Error('H Contracts row differs from Machine inventory');
    }
    const path = row.path.slice(VENDOR_PREFIX.length);
    const actual = got.manifest[path];
    if (seen.has(path) || !actual || actual.mode !== '100644'
      || actual.size !== row.size_bytes || `sha256:${actual.sha256}` !== row.sha256) {
      throw new Error('H Contracts row differs from Machine inventory');
    }
    seen.add(path);
  }
  return { dir: root, ...got };
}

// Fetch and verify the pinned release; return the directory tests load from.
export function verify(pin = readPin()) {
  if (process.env.HQ_INTERIM_OFFLINE === '1') {
    const dir = join(ROOT, 'vendor/soul-contracts');
    const selection = authenticatedSelectedH();
    return selection ? verifySelectedVendored(dir, pin, selection) : verifyVendored(dir, pin);
  }
  return withFetchedTag(pin.repository, pin.tag, (repo, commit, work) => {
    if (commit !== pin.commit) throw new Error(`tag ${pin.tag} now points at ${commit}, not the pinned ${pin.commit}; refusing a moved tag`);
    const entries = treeEntries(repo, commit, pin.paths);
    const got = manifestDigest(entries);
    if (got.digest !== pin.digest || got.files !== pin.files) {
      throw new Error(`soul-contracts ${pin.tag} digest ${got.digest} (${got.files} files) does not match the pin ${pin.digest} (${pin.files} files)`);
    }
    const dir = join(CACHE, commit);
    materialize(dir, entries, work);
    return { dir, ...got };
  });
}

export function repin(tag, pin = readPin()) {
  if (compareSemver(tag, pin.tag) < 0) throw new Error(`pins never move backwards: ${tag} is older than ${pin.tag}`);
  return withFetchedTag(pin.repository, tag, (repo, commit) => {
    const got = manifestDigest(treeEntries(repo, commit, pin.paths));
    return { ...pin, tag, commit, digest: got.digest, files: got.files };
  });
}

function isCommandEntry() {
  if (typeof import.meta.main === 'boolean') return import.meta.main;
  // In eval and print modes argv[1] is caller data, which may be the very
  // file the expression imports. Stdin has no script entry either.
  const expressionMode = process.execArgv.some((arg) => /^(?:-e|-p|-pe|--eval|--print)(?:=|$)/.test(arg));
  if (!process.argv[1] || process.argv[1] === '-' || expressionMode) return false;
  // Node 20 can retain a symlink in argv while the module loader resolves it.
  try {
    return realpathSync(process.argv[1]) === realpathSync(fileURLToPath(import.meta.url));
  } catch {
    // REPL and stdin imports can supply an argv entry without a file.
    return false;
  }
}

if (isCommandEntry()) {
  const [cmd = 'verify', tag] = process.argv.slice(2);
  try {
    if (cmd === 'verify') {
      const pin = readPin();
      const { dir, digest, files } = verify(pin);
      console.log(`ok soul-contracts ${pin.tag} (${pin.commit.slice(0, 7)}) ${digest} ${files} files -> ${dir}`);
    } else if (cmd === 'pin' && tag) {
      const next = repin(tag);
      writeFileSync(PIN_PATH, `${JSON.stringify(next, null, 2)}\n`);
      console.log(`pinned soul-contracts ${next.tag} (${next.commit.slice(0, 7)}) ${next.digest} ${next.files} files`);
    } else {
      console.error('usage: soul-contracts.mjs [verify] | pin <tag>');
      process.exit(2);
    }
  } catch (err) {
    console.error(`FAIL ${err.message}`);
    process.exit(1);
  }
}
