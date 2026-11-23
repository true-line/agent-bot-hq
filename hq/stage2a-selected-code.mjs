// Stage 2a's H-only code guard. The caller must first authenticate Machine's
// exact installed inventory, root identity and limits. This module grants no
// authority from an owner path, environment variable or source-release list.
import { createHash } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync,
  readdirSync, realpathSync } from 'node:fs';
import * as nodeModule from 'node:module';
import { isAbsolute, join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const ASCII_PATH = /^[\x20-\x7e]+$/;
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const refuse = () => { throw new Error('Machine selected HQ code is unavailable'); };
const sha256 = (bytes) => createHash('sha256').update(bytes).digest('hex');
const BLOCKED_BUILTINS = new Set(['node:vm', 'node:module', 'node:worker_threads',
  'node:repl', 'node:inspector', 'node:inspector/promises', 'node:wasi']);
let activeDescriptorDigest;

function checkedPath(path) {
  if (typeof path !== 'string' || !ASCII_PATH.test(path) || path.includes('\\')
    || path.startsWith('/') || path.endsWith('/')
    || path.split('/').some((part) => !part || part === '.' || part === '..')) refuse();
  return path;
}

function checkedStat(path, kind, uid, gid, mode) {
  const st = lstatSync(path);
  if (st.uid !== uid || st.gid !== gid || (st.mode & 0o7777) !== mode
    || (kind === 'regular' && st.nlink !== 1)
    || (kind === 'directory' ? !st.isDirectory() : !st.isFile())) refuse();
  return st;
}

// `records` are normalized only after the signed Machine descriptor has been
// verified. `maxFiles` and `maxBytes` must come from that approved descriptor.
// A checks custody and remeasures at launch; H independently checks the files
// it will load and refuses any unlisted file in its selected snapshot.
export function verifySelectedHQCode({ root, directories, records, uid, gid,
  rootMode, maxFiles, maxFileBytes, maxBytes } = {}) {
  if (typeof root !== 'string' || !isAbsolute(root) || root.includes('\\')
    || !Array.isArray(directories) || directories.length > 1024
    || !Array.isArray(records) || records.length < 1 || !Number.isSafeInteger(uid) || uid < 1
    || !Number.isSafeInteger(gid) || gid < 1
    || rootMode !== 0o555
    || !Number.isSafeInteger(maxFiles) || maxFiles < 1 || maxFiles > 1024
    || records.length > maxFiles
    || !Number.isSafeInteger(maxFileBytes) || maxFileBytes < 1 || maxFileBytes > 384 * 1024 * 1024
    || !Number.isSafeInteger(maxBytes) || maxBytes < 1 || maxBytes > 1024 * 1024 * 1024) refuse();
  // A's installed path must be canonical. A symlink in any ancestor changes
  // the root selected by the Machine plan and is never an H code source.
  if (join(root, '.') !== root || realpathSync(root) !== root
    || !Number.isSafeInteger(constants.O_NOFOLLOW)) refuse();
  let ancestor = root;
  while (ancestor !== sep) {
    if (!lstatSync(ancestor).isDirectory()) refuse();
    ancestor = join(ancestor, '..');
  }
  checkedStat(root, 'directory', uid, gid, rootMode);
  const expectedDirectories = new Map();
  const foldedDirectories = new Set();
  let previousDirectory = '';
  for (const record of directories) {
    if (!exact(record, ['path', 'kind', 'mode']) || record.kind !== 'directory'
      || !['0550', '0555'].includes(record.mode)) refuse();
    const path = checkedPath(record.path);
    if (path <= previousDirectory || foldedDirectories.has(path.toLowerCase())) refuse();
    previousDirectory = path;
    expectedDirectories.set(path, Number.parseInt(record.mode, 8));
    foldedDirectories.add(path.toLowerCase());
  }
  const expected = new Map();
  let total = 0;
  let previous = '';
  const folded = new Set();
  for (const record of records) {
    if (!exact(record, ['path', 'kind', 'mode', 'size_bytes', 'sha256', 'component_id', 'release_path'])
      || record.kind !== 'regular' || !['0440', '0550'].includes(record.mode)
      || !Number.isSafeInteger(record.size_bytes) || record.size_bytes < 0
      || record.size_bytes > maxFileBytes || !DIGEST.test(record.sha256)
      || typeof record.component_id !== 'string'
      || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(record.component_id)) refuse();
    const path = checkedPath(record.path);
    checkedPath(record.release_path);
    if (path <= previous || folded.has(path.toLowerCase())) refuse();
    previous = path;
    folded.add(path.toLowerCase());
    total += record.size_bytes;
    if (!Number.isSafeInteger(total) || total > maxBytes) refuse();
    expected.set(path, record);
  }
  const seen = new Set();
  const seenDirectories = new Set();
  const files = new Map();
  const walk = (dir, rel = '') => {
    checkedStat(dir, 'directory', uid, gid, rel ? expectedDirectories.get(rel) : rootMode);
    for (const name of readdirSync(dir).sort()) {
      checkedPath(name);
      const childRel = rel ? `${rel}/${name}` : name;
      const child = join(dir, name);
      const st = lstatSync(child);
      if (st.isDirectory()) {
        if (!expectedDirectories.has(childRel) || seenDirectories.has(childRel)) refuse();
        seenDirectories.add(childRel);
        walk(child, childRel);
        continue;
      }
      const want = expected.get(childRel);
      if (!want || !st.isFile() || seen.has(childRel)) refuse();
      const fileMode = Number.parseInt(want.mode, 8);
      checkedStat(child, 'regular', uid, gid, fileMode);
      const fd = openSync(child, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        const opened = fstatSync(fd);
        if (!opened.isFile() || opened.dev !== st.dev || opened.ino !== st.ino
          || opened.size !== want.size_bytes || (opened.mode & 0o7777) !== fileMode) refuse();
        const bytes = readFileSync(fd);
        if (bytes.length !== want.size_bytes || `sha256:${sha256(bytes)}` !== want.sha256) refuse();
        const closed = fstatSync(fd);
        if (closed.dev !== opened.dev || closed.ino !== opened.ino
          || closed.size !== opened.size || closed.mtimeMs !== opened.mtimeMs) refuse();
        const identity = fstatSync(fd, { bigint: true });
        files.set(child, Object.freeze({ sha256: want.sha256, dev: identity.dev,
          ino: identity.ino, uid: identity.uid, gid: identity.gid, mode: identity.mode,
          nlink: identity.nlink, size: identity.size, mtimeNs: identity.mtimeNs,
          ctimeNs: identity.ctimeNs }));
      } finally { closeSync(fd); }
      seen.add(childRel);
    }
  };
  walk(root);
  if (seen.size !== records.length || seenDirectories.size !== directories.length) refuse();
  return Object.freeze({ root, files, count: files.size, bytes: total });
}

export function selectedHQCodeHooks(verified) {
  if (!verified || !(verified.files instanceof Map) || verified.files.size < 1) refuse();
  const files = new Map(verified.files);
  const root = verified.root;
  const check = (url) => {
    if (url.startsWith('node:')) {
      if (BLOCKED_BUILTINS.has(url)) refuse();
      return undefined;
    }
    if (!url.startsWith('file:') || new URL(url).search || new URL(url).hash) refuse();
    const path = fileURLToPath(url);
    if (relative(root, path).startsWith('..' + sep)
      || !files.has(path)) refuse();
    return files.get(path);
  };
  return Object.freeze({
    resolve(specifier, context, nextResolve) {
      const result = nextResolve(specifier, context);
      check(result.url);
      return result;
    },
    load(url, context, nextLoad) {
      const wanted = check(url);
      if (wanted === undefined) return nextLoad(url, context);
      const path = fileURLToPath(url);
      const format = path.endsWith('.mjs') ? 'module' : path.endsWith('.json') ? 'json' : undefined;
      if (!format) refuse();
      const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW);
      try {
        const sameIdentity = () => {
          const stat = fstatSync(fd, { bigint: true });
          return ['dev', 'ino', 'uid', 'gid', 'mode', 'nlink', 'size', 'mtimeNs', 'ctimeNs']
            .every((field) => stat[field] === wanted[field]);
        };
        if (!sameIdentity()) refuse();
        const source = readFileSync(fd);
        if (!sameIdentity() || `sha256:${sha256(source)}` !== wanted.sha256) refuse();
        return { format, source, shortCircuit: true };
      } finally { closeSync(fd); }
    },
  });
}

// Only the Machine-authenticated preloader may supply `descriptorDigest`.
// Protected reservations compare this startup digest to their separately
// signed H binding; the import hook alone is not a launch authorization.
export function registerSelectedHQCode(verified, descriptorDigest) {
  // The selected Machine argv must disable process.dlopen as well as install
  // the file-module hook. An environment-only NODE_OPTIONS claim is not one
  // of the selected argv bytes.
  if (typeof nodeModule.registerHooks !== 'function'
    || !process.execArgv.includes('--no-addons')
    || !process.execArgv.includes('--disallow-code-generation-from-strings')
    || !DIGEST.test(descriptorDigest) || activeDescriptorDigest) refuse();
  nodeModule.registerHooks(selectedHQCodeHooks(verified));
  activeDescriptorDigest = descriptorDigest;
}

export function assertSelectedHQCodeDigest(expectedDigest) {
  if (!DIGEST.test(expectedDigest) || activeDescriptorDigest !== expectedDigest) refuse();
}
