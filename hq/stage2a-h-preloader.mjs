// Opt-in H code preloader. The paired Machine installs the fixed trust anchor
// and descriptor; owner argv and environment never select either path.
// Machine must independently approve the outer launch and installed plan.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { closeSync, constants, fstatSync, lstatSync, openSync, readFileSync,
  realpathSync } from 'node:fs';
import { dirname, isAbsolute, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { canonicalize } from '../sdk/wire/canonical-json.mjs';
import { parseStrict } from '../sdk/wire/strict-json.mjs';

const PURPOSE = 'agent-bot/stage2a-h-service-descriptor/v3';
const BASE = '/Library/Application Support/ai.true-line.agent-bot-hq';
export const H_AUTHORITY_PIN = BASE + '/soul-authority.pub';
export const H_DESCRIPTOR = BASE + '/h-v3/descriptor.json';
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const refuse = () => { throw new Error('Machine selected HQ code is unavailable'); };
const sha = (bytes) => 'sha256:' + createHash('sha256').update(bytes).digest('hex');
export const hInventoryDigest = (bytes) => sha(Buffer.concat([
  Buffer.from('agent-bot/stage2a-h-code-inventory/v3\0'), bytes,
]));
const getuid = () => process.getuid?.();
const getgid = () => process.getgid?.();
const getgroups = () => process.getgroups?.() ?? [];
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');

function decode64(value, size) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) refuse();
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value || (size !== undefined && bytes.length !== size)) refuse();
  return bytes;
}

function parseCanonical(bytes) {
  const source = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const value = parseStrict(source, { maxDepth: 32 });
  if (canonicalize(value) !== source) refuse();
  return value;
}

function observedRuntimeArgv() {
  if (process.env.NODE_OPTIONS || process.env.NODE_PATH || process.argv[0] !== process.execPath) refuse();
  return [process.execPath, ...process.execArgv, ...process.argv.slice(1)];
}

// The pin is root-installed at this constant path. The descriptor is A-owned
// in a separate H-readable metadata directory. A also checks ACLs and vnode
// generation before publishing; Node rechecks ancestry, identity and bytes.
function checkedAncestors(path) {
  if (!isAbsolute(path) || realpathSync(path) !== path) refuse();
  let current = dirname(path);
  while (true) {
    const st = lstatSync(current);
    if (!st.isDirectory() || (st.mode & 0o022) !== 0 || st.uid === getuid()) refuse();
    if (current === BASE && (st.uid !== 0 || st.gid !== 0 || (st.mode & 0o7777) !== 0o755)) refuse();
    if (current === sep) break;
    current = dirname(current);
  }
}

function readMeasured(path, maxBytes, { uid, gid, mode }) {
  checkedAncestors(path);
  const before = lstatSync(path, { bigint: true });
  if (!before.isFile() || before.nlink !== 1n || before.uid !== BigInt(uid)
    || before.gid !== BigInt(gid) || (before.mode & 0o7777n) !== BigInt(mode)
    || before.size < 1n || before.size > BigInt(maxBytes)) refuse();
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const opened = fstatSync(fd, { bigint: true });
    if (opened.dev !== before.dev || opened.ino !== before.ino || opened.size !== before.size
      || opened.birthtimeNs !== before.birthtimeNs || opened.ctimeNs !== before.ctimeNs) refuse();
    const bytes = readFileSync(fd);
    const after = fstatSync(fd, { bigint: true });
    if (bytes.length !== Number(opened.size) || after.dev !== opened.dev || after.ino !== opened.ino
      || after.size !== opened.size || after.mtimeNs !== opened.mtimeNs
      || after.ctimeNs !== opened.ctimeNs) refuse();
    return { bytes, stat: after };
  } finally { closeSync(fd); }
}

export function verifyStage2aHEnvelope(raw, pin, runtimeArgv) {
  if (!Buffer.isBuffer(raw) || raw.length < 1 || raw.length > 65536
    || !Buffer.isBuffer(pin) || pin.length !== 32 || !Array.isArray(runtimeArgv)) refuse();
  const envelope = parseCanonical(raw);
  if (!exact(envelope, ['schema_version', 'purpose', 'issuer_public_key_base64url',
    'payload_sha256', 'payload_base64url', 'signature_base64url'])
    || envelope.schema_version !== 3 || envelope.purpose !== PURPOSE
    || !decode64(envelope.issuer_public_key_base64url, 32).equals(pin)) refuse();
  const payloadBytes = decode64(envelope.payload_base64url);
  if (envelope.payload_sha256 !== sha(payloadBytes)) refuse();
  const signature = decode64(envelope.signature_base64url, 64);
  const key = createPublicKey({ key: Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'), pin]), format: 'der', type: 'spki' });
  const preimage = Buffer.concat([Buffer.from(PURPOSE + '\0'), payloadBytes]);
  if (!verify(null, preimage, key, signature)) refuse();
  const payload = parseCanonical(payloadBytes);
  if (!exact(payload, ['contract', 'kind', 'schema_version', 'host_id',
    'hq_installation_id', 'owner_plan_digest', 'h_inventory', 'components',
    'outer_launch', 'runtime'])
    || payload.contract !== 'machine/v3' || payload.kind !== 'stage2a-h-service-descriptor'
    || payload.schema_version !== 3 || !DIGEST.test(payload.owner_plan_digest)
    || !Array.isArray(payload.components) || payload.components.length < 1
    || !exact(payload.runtime, ['node_path', 'node_sha256', 'preloader_path',
      'preloader_sha256', 'entry_path', 'entry_sha256', 'guard_module_path',
      'guard_module_sha256', 'argv'])
    || !exact(payload.outer_launch, ['ruby_path', 'ruby_sha256', 'helper_path',
      'helper_sha256', 'argv'])
    || payload.outer_launch.ruby_path !== '/usr/bin/ruby'
    || !Array.isArray(payload.runtime.argv) || !Array.isArray(payload.outer_launch.argv)
    || canonicalize(payload.runtime.argv) !== canonicalize(runtimeArgv)
    || canonicalize(payload.outer_launch.argv) !== canonicalize([
      '/usr/bin/ruby', '--disable-gems', payload.outer_launch.helper_path,
      'launch', ...payload.runtime.argv])
    || payload.runtime.argv.length < 7
    || payload.runtime.argv.slice(0, 7).some((v, i) => v !== [
      payload.runtime.node_path, '--no-addons',
      '--disallow-code-generation-from-strings', '--import',
      payload.runtime.preloader_path, payload.runtime.entry_path, 'run'][i])
    || payload.runtime.preloader_path !== fileURLToPath(import.meta.url)
    || payload.runtime.node_path !== process.execPath
    || payload.runtime.argv.some((v) => v === '--plugins' || v === '--dev-plugins')) refuse();
  const ref = payload.h_inventory;
  if (!exact(ref, ['contract', 'kind', 'schema_version', 'domain', 'installation_id',
    'owner_plan_digest', 'reviewed_source_inventory_digest', 'machine_uid',
    'reader_uid', 'reader_gid', 'snapshot', 'sidecar', 'file_count',
    'directory_count', 'total_bytes', 'inventory_digest'])
    || ref.contract !== 'machine/v3' || ref.kind !== 'stage2a-inventory-ref'
    || ref.schema_version !== 3 || ref.domain !== 'H-code'
    || ref.installation_id !== payload.hq_installation_id
    || ref.owner_plan_digest !== payload.owner_plan_digest
    || ref.reader_uid !== getuid() || ref.machine_uid <= 399
    || ref.machine_uid === ref.reader_uid
    || !(ref.reader_gid === getgid() || getgroups().includes(ref.reader_gid))
    || !DIGEST.test(ref.inventory_digest)) refuse();
  return Object.freeze({ payload, descriptorDigest: sha(preimage) });
}

function rowFor(inventory, root, path, digest, mode) {
  if (!isAbsolute(path) || !DIGEST.test(digest)) refuse();
  const rel = relative(root, path);
  if (!rel || rel.startsWith('..' + sep) || rel === '..') refuse();
  const row = inventory.files.find((item) => item.path === rel);
  if (!row || row.sha256 !== digest || row.mode !== mode) refuse();
  return row;
}

export async function preloadSelectedHQCode() {
  if (process.platform !== 'darwin' || process.arch !== 'arm64') refuse();
  const pin = readMeasured(H_AUTHORITY_PIN, 32, { uid: 0, gid: 0, mode: 0o444 }).bytes;
  if (pin.length !== 32) refuse();
  const preliminary = lstatSync(H_DESCRIPTOR);
  if (preliminary.uid <= 399 || !getgroups().includes(preliminary.gid)) refuse();
  const descriptor = readMeasured(H_DESCRIPTOR, 65536,
    { uid: preliminary.uid, gid: preliminary.gid, mode: 0o440 });
  const { payload, descriptorDigest } = verifyStage2aHEnvelope(
    descriptor.bytes, pin, observedRuntimeArgv());
  const ref = payload.h_inventory;
  const metadata = lstatSync(dirname(H_DESCRIPTOR));
  if (!metadata.isDirectory() || metadata.uid !== ref.machine_uid
    || metadata.gid !== ref.reader_gid
    || (metadata.mode & 0o7777) !== 0o750) refuse();
  if (descriptor.stat.uid !== BigInt(ref.machine_uid)
    || descriptor.stat.gid !== BigInt(ref.reader_gid)) refuse();
  if (!exact(ref.snapshot, ['path', 'device', 'inode', 'generation',
    'birthtime_ns', 'owner_uid', 'owner_gid', 'mode'])
    || !exact(ref.sidecar, ['path', 'device', 'inode', 'generation',
      'birthtime_ns', 'owner_uid', 'owner_gid', 'mode', 'size_bytes', 'sha256'])
    || ref.snapshot.owner_uid !== ref.machine_uid
    || ref.snapshot.owner_gid !== ref.reader_gid || ref.snapshot.mode !== '0555'
    || ref.sidecar.owner_uid !== ref.machine_uid
    || ref.sidecar.owner_gid !== ref.reader_gid || ref.sidecar.mode !== '0440') refuse();
  checkedAncestors(ref.snapshot.path);
  const rootStat = lstatSync(ref.snapshot.path, { bigint: true });
  if (!rootStat.isDirectory() || rootStat.uid !== BigInt(ref.machine_uid)
    || rootStat.gid !== BigInt(ref.reader_gid)
    || (rootStat.mode & 0o7777n) !== 0o555n
    || rootStat.dev.toString() !== ref.snapshot.device
    || rootStat.ino.toString() !== ref.snapshot.inode
    || rootStat.birthtimeNs.toString() !== ref.snapshot.birthtime_ns) refuse();
  const sidecar = readMeasured(ref.sidecar.path, 2 * 1024 * 1024,
    { uid: ref.machine_uid, gid: ref.reader_gid, mode: 0o440 });
  if (sidecar.stat.dev.toString() !== ref.sidecar.device
    || sidecar.stat.ino.toString() !== ref.sidecar.inode
    || sidecar.stat.birthtimeNs.toString() !== ref.sidecar.birthtime_ns
    || sidecar.bytes.length !== ref.sidecar.size_bytes
    || sha(sidecar.bytes) !== ref.sidecar.sha256
    || hInventoryDigest(sidecar.bytes) !== ref.inventory_digest) refuse();
  const inventory = parseCanonical(sidecar.bytes);
  if (!exact(inventory, ['contract', 'kind', 'schema_version', 'domain',
    'installation_id', 'limits', 'directories', 'files', 'total_bytes'])
    || inventory.contract !== 'machine/v3' || inventory.kind !== 'stage2a-domain-inventory'
    || inventory.schema_version !== 3 || inventory.domain !== 'H-code'
    || inventory.installation_id !== payload.hq_installation_id
    || !Array.isArray(inventory.files) || inventory.files.length !== ref.file_count
    || !Array.isArray(inventory.directories)
    || inventory.directories.length !== ref.directory_count
    || inventory.total_bytes !== ref.total_bytes
    || !exact(inventory.limits, ['max_files', 'max_file_bytes', 'max_total_bytes'])) refuse();
  const runtime = payload.runtime;
  for (const [path, digest, mode] of [
    [runtime.node_path, runtime.node_sha256, '0550'],
    [runtime.preloader_path, runtime.preloader_sha256, '0440'],
    [runtime.entry_path, runtime.entry_sha256, '0440'],
    [runtime.guard_module_path, runtime.guard_module_sha256, '0440'],
    [payload.outer_launch.helper_path, payload.outer_launch.helper_sha256, '0440'],
  ]) rowFor(inventory, ref.snapshot.path, path, digest, mode);
  // Verify the guard module's exact A-signed row before importing its code.
  const guard = readMeasured(runtime.guard_module_path, inventory.limits.max_file_bytes,
    { uid: ref.machine_uid, gid: ref.reader_gid, mode: 0o440 });
  if (sha(guard.bytes) !== runtime.guard_module_sha256) refuse();
  const { verifySelectedHQCode, registerSelectedHQCode } =
    await import('data:text/javascript;base64,' + guard.bytes.toString('base64'));
  const selected = verifySelectedHQCode({
    root: ref.snapshot.path, directories: inventory.directories,
    records: inventory.files, uid: ref.machine_uid, gid: ref.reader_gid,
    rootMode: 0o555, maxFiles: inventory.limits.max_files,
    maxFileBytes: inventory.limits.max_file_bytes,
    maxBytes: inventory.limits.max_total_bytes,
  });
  if (selected.count !== ref.file_count || selected.bytes !== ref.total_bytes) refuse();
  registerSelectedHQCode(selected, descriptorDigest);
  return descriptorDigest;
}

const requestedImport = process.execArgv.indexOf('--import');
if (requestedImport >= 0 && process.execArgv[requestedImport + 1] === fileURLToPath(import.meta.url)) {
  await preloadSelectedHQCode();
}
