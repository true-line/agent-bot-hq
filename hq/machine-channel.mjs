// HQ's agent-daemon client of Machine's daemon-machine-channel. The private
// seed belongs to the service account. It is independent of the HQ signer.
import { isUtf8 } from 'node:buffer';
import { parseStrict } from '../sdk/wire/strict-json.mjs';
import { isServiceHandoff, serviceHandoffArgs, serviceHandoff } from './machine-service-recovery.mjs';
import { membersPlanResult, validPlanId } from './machine-members-plans.mjs';
import { execFileSync } from 'node:child_process';
import { createHash, createPrivateKey, createPublicKey, randomBytes, sign, verify } from 'node:crypto';
import { closeSync, constants, fstatSync, fsyncSync, linkSync, lstatSync, mkdirSync, openSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { connect } from 'node:net';
import { userInfo } from 'node:os';
import { isAbsolute, join } from 'node:path';
import { HostError } from '../sdk/errors.mjs';

const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const HEX_KEY = /^[0-9a-f]{64}$/i;
const MAX_MESSAGE = 64 * 1024;
const COOPERATIVE_STATES = new Map([
  ['stage2a-cooperative-live-v3', 'cooperative-live'],
  ['stage2a-cooperative-lookup-v3', 'cooperative-found'],
  ['stage2a-cooperative-provider-v3', 'cooperative-provided'],
  ['stage2a-cooperative-reserve-v3', 'cooperative-reserved'],
  ['stage2a-cooperative-reserve-result-v3', 'cooperative-reserve-result'],
  ['stage2a-cooperative-attach-v3', 'cooperative-attached'],
  ['stage2a-cooperative-launch-inputs-v3', 'cooperative-launch-inputs'],
  ['stage2a-cooperative-abort-v3', 'cooperative-aborted'],
  ['stage2a-cooperative-stop-v3', 'cooperative-stopped'],
]);
const fingerprint = (raw) => createHash('sha256').update(raw).digest('hex');
const disconnectedPairs = new WeakMap();
const verifiedPairs = new WeakMap();
const qualificationOutagePurpose = 'agent-bot-hq/t02-machine-outage/v1';
export const disconnectedMachinePair = (error) => disconnectedPairs.get(error);
export const verifiedMachinePair = (reply) => verifiedPairs.get(reply);

function checkAcl(path, allowDeny = false) {
  if (process.platform === 'darwin') {
    const listing = execFileSync('/bin/ls', ['-led', path], { encoding: 'utf8', env: { LC_ALL: 'C' } });
    if (listing.split('\n').filter((line) => /^\s*\d+:/.test(line)).some((line) => !allowDeny || !/^\s*\d+:.*\sdeny\s[\w,]+$/.test(line))) throw new Error(`unexpected ACL on ${path}`);
  }
}

function roleDir(path, uid, create, { allowReadTraverse = false, allowDeny = false } = {}) {
  if (create) {
    try { mkdirSync(path, { mode: 0o700 }); } catch (e) { if (e.code !== 'EEXIST') throw e; }
  }
  const entry = lstatSync(path);
  const mode = entry.mode & 0o7777;
  // useradd can pre-create .config at 0755 beneath the private role home.
  // Only this intermediate directory may grant read/traverse to others.
  const requiredMode = allowReadTraverse ? mode & ~0o055 : mode;
  if (!entry.isDirectory() || entry.uid !== uid || requiredMode !== 0o700) {
    throw new Error(`invalid role directory at ${path} (uid ${entry.uid}, mode ${mode.toString(8)})`);
  }
  checkAcl(path, allowDeny);
}

function readKey(path, uid) {
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (e) { if (e.code === 'ENOENT') return null; throw e; }
  try {
    const entry = fstatSync(fd);
    if (!entry.isFile() || entry.uid !== uid || (entry.mode & 0o7777) !== 0o600 || entry.size !== 32) {
      throw new Error(`expected a 32-byte role-owned key at mode 0600 at ${path}`);
    }
    checkAcl(path);
    const raw = readFileSync(fd);
    if (raw.length !== 32) throw new Error(`incomplete key at ${path}`);
    return raw;
  } finally { closeSync(fd); }
}

// A concurrent first use can win. Publish only complete, fsynced bytes and
// adopt the winner without ever replacing a key or pin.
function publish(dir, name, bytes, uid) {
  const target = join(dir, name);
  const scratch = join(dir, `.${name}.${randomBytes(16).toString('hex')}`);
  const fd = openSync(scratch, 'wx', 0o600);
  try {
    try {
      checkAcl(scratch);
      writeFileSync(fd, bytes);
      fsyncSync(fd);
    } finally { closeSync(fd); }
    try { linkSync(scratch, target); } catch (e) { if (e.code !== 'EEXIST') throw e; }
  } finally { unlinkSync(scratch); }
  syncDir(dir);
  return readKey(target, uid);
}

function syncDir(path) {
  const fd = openSync(path, constants.O_DIRECTORY | constants.O_RDONLY);
  try { fsyncSync(fd); } finally { closeSync(fd); }
}

function missingDevicePair() {
  throw new HostError('credential_unavailable', "Check this account's Machine pairing with the prefix owner before enrolling HQ. Device signing requires the daemon pin saved by verified Machine status.");
}

function clientIdentity(dir, uid, create) {
  const keyPath = join(dir, 'client.key');
  let seed = readKey(keyPath, uid);
  if (!seed) {
    if (!create) return null;
    // A published identity without its seed requires recovery. A concurrent
    // initializer may just have completed, so re-read before reporting loss.
    if (readKey(join(dir, 'client.pub'), uid) || readKey(join(dir, 'daemon.pub'), uid)) {
      seed = readKey(keyPath, uid);
      if (!seed) throw new Error('HQ Machine seed is missing from an existing pairing');
    } else {
      const fresh = randomBytes(32);
      try { seed = publish(dir, 'client.key', fresh, uid); } finally { fresh.fill(0); }
    }
  }
  const der = Buffer.concat([PKCS8, seed]);
  let key;
  try { key = createPrivateKey({ key: der, type: 'pkcs8', format: 'der' }); }
  finally { der.fill(0); seed.fill(0); }
  const pub = createPublicKey(key).export({ type: 'spki', format: 'der' }).subarray(SPKI.length);
  const saved = readKey(join(dir, 'client.pub'), uid) ?? (create && publish(dir, 'client.pub', pub, uid));
  if (!saved || !saved.equals(pub)) throw new Error('HQ Machine public identity is missing or inconsistent');
  return { key, pub };
}

// Go signs body as json.RawMessage, including the original escapes and
// number spellings. Find spans at top level after validating the entire line.
function responseFields(line) {
  const value = parseStrict(line);
  if (!value || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid Machine response');
  const fields = new Map();
  let depth = 0;
  let start;
  for (const token of line.matchAll(/"(?:[^"\\]|\\.)*"|[\[\]{},]/g)) {
    const c = token[0];
    if (depth === 1 && (c === ',' || c === '}')) {
      const field = /^\s*("(?:[^"\\]|\\.)*")\s*:\s*([\s\S]+)$/.exec(line.slice(start, token.index));
      if (!field) throw new Error('invalid Machine response field');
      const key = JSON.parse(field[1]);
      if (fields.has(key)) throw new Error('duplicate Machine response field');
      fields.set(key, field[2].trimEnd());
      start = token.index + 1;
    }
    if (c === '[' || c === '{') {
      if (depth++ === 0) start = token.index + 1;
    } else if (c === ']' || c === '}') depth--;
  }
  return { value, body: fields.get('body') ?? '' };
}

function authenticatedResponse(line, nonce, pinned, verb, capture = false) {
  const { value: r, body } = responseFields(line);
  if ((isServiceHandoff(verb) || verb === 'hq-device' || COOPERATIVE_STATES.has(verb)
    || ['stage2a-lookup', 'stage2a-list', 'stage2a-reserve', 'stage2a-exec', 'stage2a-verify-b', 'stage2a-prepare-b', 'stage2a-stop', 'stage2a-finalize-b', 'stage2a-live', 'stage2a-provider', 'stage2a-child-ready', 'stage2a-hello-start', 'stage2a-hello-finalize', 'stage2a-hello-abort', 'stage2a-peer-role'].includes(verb)) && Object.keys(r).some((field) =>
    !['ok', 'diagnostic', 'message', 'state', 'body', 'timestamp', 'nonce', 'request_nonce', 'signature'].includes(field))) {
    throw new Error('unexpected Machine ' + verb + ' response field');
  }
  const singleLine = (s) => typeof s === 'string' && !/[\r\n]/.test(s);
  if (typeof r.ok !== 'boolean' || !Number.isSafeInteger(r.timestamp) ||
      Math.abs(Date.now() / 1000 - r.timestamp) > 300 ||
      (nonce === null ? typeof r.request_nonce !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(r.request_nonce) : r.request_nonce !== nonce) ||
      !singleLine(r.nonce) || !r.nonce || Buffer.byteLength(r.nonce) > 128 || ![r.state ?? '', r.diagnostic ?? '', r.message ?? ''].every(singleLine) ||
      typeof r.signature !== 'string') throw new Error(`invalid or stale Machine ${verb} response`);
  const bytes = Buffer.from([r.ok, r.diagnostic ?? '', r.message ?? '', r.state ?? '', body, r.timestamp, r.nonce, r.request_nonce].join('\n'));
  const key = createPublicKey({ key: Buffer.concat([SPKI, pinned]), type: 'spki', format: 'der' });
  const signature = Buffer.from(r.signature, 'base64');
  if (signature.length !== 64 || signature.toString('base64') !== r.signature || !verify(null, bytes, key, signature)) {
    throw new Error(`Machine ${verb} signature does not match the daemon pin`);
  }
  if (!r.ok) {
    if (capture) return r;
    let error = new Error(`Machine refused signed ${verb}: ${r.diagnostic || 'unspecified'}`);
    if (verb === 'hq-device') {
      if (r.diagnostic === 'MM_DAEMON_UNKNOWN_KEY') {
        error = new HostError('credential_unavailable', "Machine could not verify this account's pairing for device signing (MM_DAEMON_UNKNOWN_KEY). Check its pairing with the prefix owner.");
      } else if (r.diagnostic === 'MM_DAEMON_VERB_UNKNOWN') {
        error = new HostError('credential_unavailable', 'The paired Machine daemon does not support HQ device signing (MM_DAEMON_VERB_UNKNOWN). Install a compatible Machine version before using device signing.');
      } else if (r.diagnostic === 'MM_DAEMON_PEER_REFUSED' || r.diagnostic === 'MM_DAEMON_CALLER_REFUSED') {
        error = new HostError('credential_unavailable', `Machine refused this HQ account's device request (${r.diagnostic}). Ask the prefix owner to check its pairing.`);
      }
    }
    error.machineDiagnostic = r.diagnostic || 'unspecified';
    throw error;
  }
  if (!r.state) throw new Error(`signed Machine ${verb} is missing its state`);
  return r;
}

class MissingMachineReply extends Error {}

function exchange(socketPath, request) {
  return new Promise((resolve, reject) => {
    const stream = connect({ path: socketPath });
    const chunks = [];
    let size = 0;
    let connected = false;
    const timer = setTimeout(() => stream.destroy(new Error('Machine request timed out')), 10000);
    stream.once('connect', () => {
      connected = true;
      stream.write(JSON.stringify(request) + '\n');
    });
    stream.on('error', error => {
      if (!connected && request.verb === 'hq-device' && error.syscall === 'connect' && (error.code === 'ENOENT' || error.code === 'ECONNREFUSED')) {
        const unavailable = new HostError('credential_unavailable', 'HQ could not connect to the paired Machine. Ask the prefix owner to check that Machine is running, then retry.');
        disconnectedPairs.set(unavailable, undefined);
        reject(unavailable);
      } else reject(error);
    });
    stream.on('close', () => {
      clearTimeout(timer);
      reject(connected && size === 0 ? new MissingMachineReply('Machine closed without a response') : new Error('Machine closed without a complete response'));
    });
    stream.on('data', (chunk) => {
      size += chunk.length;
      if (size > MAX_MESSAGE + 1) return stream.destroy(new Error('Machine response exceeds its size limit'));
      chunks.push(chunk);
      if (chunk.includes(10)) {
        const data = Buffer.concat(chunks);
        if (data.indexOf(10) !== data.length - 1 || !isUtf8(data)) return stream.destroy(new Error('invalid Machine response framing'));
        resolve(data.subarray(0, -1).toString('utf8'));
        stream.destroy();
      }
    });
  });
}

export function machineAccountLayout(account, platform, uid, euid, dedicatedOnly) {
  const mac = platform === 'darwin';
  const role = mac ? '_agent-bot-hq' : 'agent-bot-hq';
  const homes = mac ? ['/var/agent-bot-hq', '/private/var/agent-bot-hq'] : ['/var/lib/agent-bot-hq'];
  const dedicated = account.username === role;
  if ((!mac && platform !== 'linux') || account.uid <= 0 || account.uid !== uid || account.uid !== euid
      || !isAbsolute(account.homedir) || (dedicatedOnly && !dedicated)
      || (dedicated && (!homes.includes(account.homedir) || (mac && (account.uid < 300 || account.uid > 399 || account.gid !== account.uid))))) {
    throw new Error('Machine channel command requires its authorized local account or dedicated HQ service account');
  }
  return { account, ordinary: !dedicated };
}

function roleAccount(dedicatedOnly) {
  return machineAccountLayout(userInfo(), process.platform, process.getuid?.(), process.geteuid?.(), dedicatedOnly);
}

export function machineRoleDevice(option, fields, expectedPair) {
  const { account, ordinary } = roleAccount(false);
  const prefix = process.platform === 'darwin' && process.arch === 'arm64' ? '/opt/homebrew'
    : process.platform === 'linux' && ['x64', 'arm64'].includes(process.arch) ? '/home/linuxbrew/.linuxbrew' : null;
  if (!prefix) throw new Error('Machine device custody is unavailable on this platform');
  return machineCommandInHome(['hq-device', option, '--socket', join(prefix, 'var/agent-machine/daemon.sock')], account.homedir, account.uid, fields, ordinary, account.uid, expectedPair);
}

// Internal qualification operation for the dedicated HQ service. The caller
// must derive caseNonce from an authenticated A-owned driver command.
export function capturePairedEnrollmentProof(hqEpoch, caseNonce, expectedPair) {
  const { account } = roleAccount(true);
  if (process.platform !== 'darwin' || process.arch !== 'arm64') {
    throw new Error('protected qualification requires Apple Silicon macOS');
  }
  if (!/^[a-f0-9]{64}$/.test(expectedPair ?? '')) throw new Error('qualification requires an authenticated Machine pairing');
  const socket = '/opt/homebrew/var/agent-machine/daemon.sock';
  return machineCommandInHome(['hq-device', 'enrollment-proof', '--socket', socket],
    account.homedir, account.uid, { hq_epoch: hqEpoch }, false, account.uid, expectedPair, caseNonce);
}

export function machineRoleCommand(argv) {
  const { account, ordinary } = roleAccount(!['identity', 'status'].includes(argv[0]));
  if (argv[0] === 'hq-device') throw new Error('the device port is internal to HQ enrollment');
  if (isServiceHandoff(argv[0]) && process.platform !== 'darwin') throw new Error('paired HQ service handoff requires macOS');
  return machineCommandInHome(argv, account.homedir, account.uid, undefined, ordinary);
}

// The protected start request is sent only by the dedicated HQ service over
// its existing pinned, signed local Machine channel. No path, command, UID or
// socket is accepted from the owner-facing Soul request.
function machineRoleStage2a(verb, request) {
  const { account } = roleAccount(true);
  const prefix = process.platform === 'darwin' && process.arch === 'arm64' ? '/opt/homebrew' : null;
  if (!prefix) throw new Error('Stage 2a Machine reservation requires dedicated macOS HQ');
  return machineCommandInHome(
    [verb, '--socket', join(prefix, 'var/agent-machine/daemon.sock')],
    account.homedir, account.uid, request,
  );
}

export function machineRoleStage2aCooperative(verb, request) {
  if (!COOPERATIVE_STATES.has(verb)) throw new Error('unknown cooperative Machine command');
  return machineRoleStage2a(verb, request);
}

export const machineRoleStage2aReserve = (request) => machineRoleStage2a('stage2a-reserve', request);
export const machineRoleStage2aExec = (request) => machineRoleStage2a('stage2a-exec', request);
export const machineRoleStage2aVerifyB = (request) => machineRoleStage2a('stage2a-verify-b', request);
export const machineRoleStage2aLookup = (request) => machineRoleStage2a('stage2a-lookup', request);
export const machineRoleStage2aList = () => machineRoleStage2a('stage2a-list', {});
export const machineRoleStage2aPrepareB = (request) => machineRoleStage2a('stage2a-prepare-b', request);
export const machineRoleStage2aStop = (request) => machineRoleStage2a('stage2a-stop', request);
export const machineRoleStage2aFinalizeB = (request) => machineRoleStage2a('stage2a-finalize-b', request);
export const machineRoleStage2aLive = (request) => machineRoleStage2a('stage2a-live', request);
export const machineRoleStage2aProvider = (request) => machineRoleStage2a('stage2a-provider', request);
export const machineRoleStage2aChildReady = (request) => machineRoleStage2a('stage2a-child-ready', request);
export const machineRoleStage2aHelloStart = (request) => machineRoleStage2a('stage2a-hello-start', request);
export const machineRoleStage2aHelloFinalize = (request) => machineRoleStage2a('stage2a-hello-finalize', request);
export const machineRoleStage2aHelloAbort = (request) => machineRoleStage2a('stage2a-hello-abort', request);
export const machineRoleStage2aPeerRole = (request) => machineRoleStage2a('stage2a-peer-role', request);

function stage2aListResult(body, daemon, hqUid) {
  const id = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
  const soul = /^agent_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/;
  const hex = /^[0-9a-f]{64}$/;
  const digest = /^sha256:[0-9a-f]{64}$/;
  const keys = (value, expected) => value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...expected].sort().join(',');
  const path = (value) => typeof value === 'string' && isAbsolute(value)
    && !/[\x00\r\n]/.test(value) && Buffer.byteLength(value) <= 4096;
  if (!keys(body, ['machine_public_key', 'installations'])
    || body.machine_public_key !== daemon.toString('hex')
    || !Array.isArray(body.installations) || body.installations.length > 16) {
    throw new Error('invalid signed Machine Stage 2a installed list');
  }
  const fields = ['installation_id', 'soul_id', 'package_root', 'plan_id', 'plan_digest', 'hq_epoch',
    'host_id', 'machine_uid', 'hq_uid', 'runner_account', 'runner_uid', 'runner_gid',
    'bridge_account', 'bridge_uid', 'bridge_gid', 'soul_artifact_sha256', 'provider_config_sha256',
    'definition_measurement', 'claimed_definition_digest', 'launch_input_measurement',
    'root_receipt_sha256', 'broker', 'member', 'relay', 'admission'];
  const endpointFields = ['directory', 'owner_uid', 'group_gid', 'dir_mode', 'socket_mode'];
  let previous = '';
  const packages = new Set();
  const uids = new Set([hqUid]);
  const installations = body.installations.map((entry) => {
    if (!keys(entry, fields) || !id.test(entry.installation_id) || entry.installation_id <= previous
      || !soul.test(entry.soul_id) || !path(entry.package_root) || packages.has(entry.package_root)
      || !id.test(entry.plan_id) || !hex.test(entry.plan_digest) || !hex.test(entry.hq_epoch)
      || !id.test(entry.host_id) || !Number.isSafeInteger(entry.machine_uid) || entry.machine_uid <= 399
      || entry.hq_uid !== hqUid || !Number.isSafeInteger(entry.runner_uid)
      || entry.runner_uid < 300 || entry.runner_uid > 399
      || !Number.isSafeInteger(entry.bridge_uid) || entry.bridge_uid < 300 || entry.bridge_uid > 399
      || uids.has(entry.runner_uid) || uids.has(entry.bridge_uid) || entry.runner_uid === entry.bridge_uid
      || entry.runner_gid !== entry.runner_uid || entry.bridge_gid !== entry.bridge_uid
      || entry.runner_account !== `_abm-sr-${fingerprint(Buffer.from(entry.installation_id)).slice(0, 20)}`
      || entry.bridge_account !== `_abm-br-${fingerprint(Buffer.from(`agent-bot-soul-bridge/v1\0${entry.installation_id}`)).slice(0, 20)}`
      || !hex.test(entry.soul_artifact_sha256) || !hex.test(entry.provider_config_sha256)
      || !['definition_measurement', 'claimed_definition_digest',
        'launch_input_measurement', 'root_receipt_sha256'].every((field) => digest.test(entry[field]))) {
      throw new Error('invalid signed Machine Stage 2a installed assignment');
    }
    for (const [name, owner, group] of [
      ['broker', hqUid, entry.bridge_gid], ['member', entry.runner_uid, entry.bridge_gid],
      ['relay', entry.bridge_uid, entry.runner_gid], ['admission', hqUid, entry.runner_gid],
    ]) {
      const ep = entry[name];
      if (!keys(ep, endpointFields) || !path(ep.directory) || ep.owner_uid !== owner
        || ep.group_gid !== group || ep.dir_mode !== 0o2750 || ep.socket_mode !== 0o660) {
        throw new Error('invalid signed Machine Stage 2a endpoint policy');
      }
    }
    previous = entry.installation_id;
    packages.add(entry.package_root);
    uids.add(entry.runner_uid);
    uids.add(entry.bridge_uid);
    return Object.freeze({ ...entry,
      broker: Object.freeze({ ...entry.broker, socket_path: join(entry.broker.directory, 'broker.sock'),
        peer_uids: Object.freeze([entry.bridge_uid]) }) });
  });
  return Object.freeze({ machine_public_key: body.machine_public_key,
    installations: Object.freeze(installations), daemon_fingerprint: fingerprint(daemon) });
}

function validStage2aPrepareB(request) {
  const exact = (value, fields) => value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...fields].sort().join(',');
  const decimal = (value) => typeof value === 'string' && /^(0|[1-9][0-9]*)$/.test(value)
    && BigInt(value) > 0n && BigInt(value) <= 18446744073709551615n;
  const node = (value, mode) => exact(value, ['uid', 'gid', 'device', 'inode', 'mode'])
    && Number.isSafeInteger(value.uid) && value.uid >= 300 && value.uid <= 399
    && Number.isSafeInteger(value.gid) && value.gid >= 300 && value.gid <= 399
    && decimal(value.device) && decimal(value.inode) && value.mode === mode;
  const broker = request.broker;
  return /^sha256:[0-9a-f]{64}$/.test(request.reservation_sha256)
    && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(request.installation_id)
    && /^st_[0-9a-f]{24}$/.test(request.start_id)
    && /^ln_[0-9a-f]{24}$/.test(request.launch_id)
    && /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(request.plan_id)
    && /^[0-9a-f]{64}$/.test(request.plan_digest)
    && /^[0-9a-f]{64}$/.test(request.hq_epoch)
    && exact(broker, ['path', 'parent', 'socket'])
    && typeof broker.path === 'string' && isAbsolute(broker.path)
    && !/[\x00\r\n]/.test(broker.path) && Buffer.byteLength(broker.path) <= 103
    && node(broker.parent, 0o2750) && node(broker.socket, 0o660);
}

function validStage2aFinalizeB(request) {
  const socket = request.relay_socket?.socket;
  const decimal = (value) => typeof value === 'string' && /^[1-9][0-9]*$/.test(value)
    && value.length <= 20 && BigInt(value) <= 18446744073709551615n;
  return /^sha256:[0-9a-f]{64}$/.test(request.bind_receipt_sha256)
    && request.relay_socket && typeof request.relay_socket === 'object'
    && Object.keys(request.relay_socket).sort().join(',') === 'path,socket'
    && typeof request.relay_socket.path === 'string' && isAbsolute(request.relay_socket.path)
    && !/[\x00\r\n]/.test(request.relay_socket.path)
    && Buffer.byteLength(request.relay_socket.path) <= 103
    && socket && typeof socket === 'object' && !Array.isArray(socket)
    && Object.keys(socket).sort().join(',') === 'device,gid,inode,mode,uid'
    && Number.isSafeInteger(socket.uid) && socket.uid >= 300 && socket.uid <= 399
    && Number.isSafeInteger(socket.gid) && socket.gid >= 300 && socket.gid <= 399
    && decimal(socket.device) && decimal(socket.inode) && socket.mode === 0o660;
}

function validStage2aSignedLiveLease(body) {
  const encoded = body?.lease_envelope_base64url;
  if (typeof encoded !== 'string' || !/^[A-Za-z0-9_-]{1,16384}$/.test(encoded)
    || !/^sha256:[0-9a-f]{64}$/.test(body.lease_sha256 ?? '')
    || !Number.isSafeInteger(body.lease_sequence) || body.lease_sequence < 1) return false;
  const raw = Buffer.from(encoded, 'base64url');
  return raw.length > 0 && raw.length <= 12 * 1024
    && raw.toString('base64url') === encoded
    && 'sha256:' + fingerprint(raw) === body.lease_sha256;
}

// Also exercised with a temporary private home in the protocol tests. The CLI
// always obtains its home and UID from the kernel-backed account lookup above.
export async function machineCommandInHome(argv, home, uid, deviceFields, ordinary = false, roleUid = uid, expectedPair, caseNonce) {
  const [verb, ...args] = argv;
  const identity = verb === 'identity' && !args.length;
  let socket, hex, handoff, option = '', planID = '';
  if (verb === 'status' && args[0] === '--socket' &&
      (args.length === 2 || (args.length === 4 && args[2] === '--daemon-key' && HEX_KEY.test(args[3])))) {
    [, socket, , hex] = args;
  } else if (verb === 'hq-device' && args.length === 3 && ['identity', 'enrollment-proof', 'bind-enrollment', 'access-assertion', 'bind-access', 'whoami'].includes(args[0]) && args[1] === '--socket') {
    [option, , socket] = args;
  } else if (isServiceHandoff(verb)) {
    handoff = serviceHandoffArgs(verb, args);
    socket = handoff.socket;
  } else if (verb === 'members-plans') {
    option = args[0];
    if (option === 'list' && args[1] === '--socket' &&
        (args.length === 3 || (args.length === 5 && args[3] === '--after' && validPlanId(args[4])))) {
      socket = args[2];
      planID = args[4] ?? '';
    } else if (option === 'get' && args.length === 4 && validPlanId(args[1]) && args[2] === '--socket') {
      planID = args[1];
      socket = args[3];
    }
  } else if ((COOPERATIVE_STATES.has(verb) || ['stage2a-lookup', 'stage2a-list', 'stage2a-reserve', 'stage2a-exec', 'stage2a-verify-b', 'stage2a-prepare-b', 'stage2a-stop', 'stage2a-finalize-b', 'stage2a-live', 'stage2a-provider', 'stage2a-child-ready', 'stage2a-hello-start', 'stage2a-hello-finalize', 'stage2a-hello-abort', 'stage2a-peer-role'].includes(verb))
    && args.length === 2 && args[0] === '--socket') {
    socket = args[1];
  }
  if (!identity && (!socket || !isAbsolute(socket))) {
    throw new Error('usage: machine identity | status --socket PATH [--daemon-key HEX] | members-plans list --socket PATH [--after PLAN_ID] | members-plans get PLAN_ID --socket PATH');
  }
  const capture = caseNonce !== undefined;
  if (capture && (ordinary || verb !== 'hq-device' || option !== 'enrollment-proof'
    || !/^[a-f0-9]{64}$/.test(deviceFields?.hq_epoch ?? '')
    || typeof caseNonce !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(caseNonce)
    || Buffer.from(caseNonce, 'base64url').toString('base64url') !== caseNonce)) {
    throw new Error('qualification capture requires a fixed paired enrollment proof and a case nonce');
  }
  if (ordinary && !['identity', 'status', 'hq-device'].includes(verb)) throw new Error('operation requires the dedicated HQ service account');
  roleDir(home, uid, false, { allowReadTraverse: ordinary, allowDeny: ordinary });
  const config = join(home, '.config');
  const dir = join(config, 'agent-machine');
  try {
    roleDir(config, uid, identity, { allowReadTraverse: true });
    roleDir(dir, uid, identity);
  } catch (error) {
    if (verb === 'hq-device' && error.code === 'ENOENT' && (error.path === config || error.path === dir)) missingDevicePair();
    throw error;
  }
  if (identity) { syncDir(home); syncDir(config); }
  const client = clientIdentity(dir, uid, identity);
  if (!client) {
    if (verb === 'hq-device') missingDevicePair();
    throw new Error('initialize the HQ Machine identity first');
  }
  const { key, pub } = client;
  if (identity) return { client: 'agent-daemon', public_key: pub.toString('hex'), fingerprint: fingerprint(pub) };
  const existing = readKey(join(dir, 'daemon.pub'), uid);
  const given = hex && Buffer.from(hex, 'hex');
  if (existing && given && !existing.equals(given)) throw new Error('the supplied daemon key differs from the existing pin');
  const daemon = existing || given;
  if (!daemon) {
    if (verb === 'hq-device') missingDevicePair();
    if (verb !== 'status') throw new Error(`${verb} requires the daemon pin saved by verified Machine status`);
    throw new Error('first signed status requires the prefix owner’s verified --daemon-key HEX');
  }
  // Identity recovery and qualification capture can bind both channel keys
  // to the pairing previously authenticated by this HQ process.
  const pair = verb === 'hq-device' && (option === 'identity' || capture)
    ? fingerprint(Buffer.concat([pub, daemon])) : undefined;
  if (expectedPair !== undefined && expectedPair !== pair) throw new Error('the local Machine pairing changed after HQ started');
  async function send(fields) {
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = caseNonce ?? randomBytes(16).toString('base64url');
    const parts = [fields.verb, '', fields.option ?? '', '', fields.plan_id ?? '', '', '', '', timestamp, nonce];
    for (const field of ['plan_digest', 'challenge_nonce', 'owner_signature', 'hq_epoch', 'session', 'receipt_body', 'receipt_jti', 'receipt_kid', 'receipt_signature', 'stage2a_request']) {
      if (fields[field] !== undefined) parts.push(field, fields[field]);
    }
    const request = { ...fields, timestamp, nonce, public_key: pub.toString('base64'),
      signature: sign(null, Buffer.from(parts.join('\n')), key).toString('base64') };
    let line;
    try {
      line = await exchange(socket, request);
    } catch (error) {
      if (!capture || !disconnectedPairs.has(error)) throw error;
      // Only a positively identified connect failure can attest that no
      // request reached Machine. A must corroborate the outage independently.
      const requestRaw = JSON.stringify(request);
      const evidence = [qualificationOutagePurpose, fingerprint(Buffer.from(requestRaw)), 'machine-unreachable'].join('\n');
      const observation = Object.freeze({ requestRaw, outageSignature: sign(null, Buffer.from(evidence), key).toString('base64') });
      disconnectedPairs.set(observation, pair);
      return { capture: observation };
    }
    const response = authenticatedResponse(line, nonce, daemon, fields.verb, capture);
    return { line, response, ...(capture && { capture: Object.freeze({ requestRaw: JSON.stringify(request), responseRaw: line }) }) };
  }
  if (handoff) return serviceHandoff(verb, handoff, daemon.toString('hex'), pub.toString('hex'), send,
    (line) => authenticatedResponse(line, null, daemon, verb), roleUid);
  if (verb === 'hq-device' && option !== 'identity') {
    const keys = ['hq_epoch'];
    if (['bind-enrollment', 'bind-access'].includes(option)) keys.push('receipt_body', 'receipt_jti', 'receipt_kid', 'receipt_signature');
    if (option === 'whoami') {
      keys.push('session');
      const session = deviceFields?.session;
      if (typeof session !== 'string' || !/^[a-zA-Z0-9_-]{43}$/.test(session)
        || Buffer.from(session, 'base64url').toString('base64url') !== session) throw new Error('invalid Machine session selector');
    }
    if (!deviceFields || !keys.every((key) => typeof deviceFields[key] === 'string' && !/[\r\n]/.test(deviceFields[key]))
      || Object.keys(deviceFields).length !== keys.length || !/^(legacy|[a-f0-9]{64})$/.test(deviceFields.hq_epoch)) throw new Error('invalid Machine device fields');
  } else if (['stage2a-lookup', 'stage2a-list', 'stage2a-reserve', 'stage2a-exec', 'stage2a-verify-b', 'stage2a-prepare-b', 'stage2a-live', 'stage2a-provider', 'stage2a-child-ready', 'stage2a-hello-start', 'stage2a-hello-finalize', 'stage2a-hello-abort', 'stage2a-peer-role', 'stage2a-stop', 'stage2a-finalize-b'].includes(verb)) {
    const selectors = {
      'stage2a-lookup': ['package_path'],
      'stage2a-list': [],
      'stage2a-reserve': ['plan_digest', 'installation_id', 'start_id', 'hq_epoch', 'launch_id'],
      'stage2a-exec': ['reservation_sha256', 'role', 'nonce', 'pid'],
      'stage2a-verify-b': ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
        'plan_id', 'plan_digest', 'hq_epoch', 'challenge', 'proof'],
      'stage2a-prepare-b': ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
        'plan_id', 'plan_digest', 'hq_epoch', 'broker'],
      'stage2a-stop': ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
        'plan_id', 'plan_digest', 'hq_epoch'],
      'stage2a-finalize-b': ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
        'plan_id', 'plan_digest', 'hq_epoch', 'bind_receipt_sha256', 'relay_socket'],
      'stage2a-live': ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
        'plan_id', 'plan_digest', 'hq_epoch', 'challenge'],
      'stage2a-child-ready': ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
        'plan_id', 'plan_digest', 'hq_epoch', 'child_launcher_pid', 'child_pid', 'grant_sha256'],
      'stage2a-hello-start': ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
        'plan_id', 'plan_digest', 'hq_epoch', 'peer_uid', 'peer_pid',
        'hello_payload_base64url', 'hello_payload_sha256', 'broker_bind_receipt_sha256'],
      'stage2a-hello-finalize': ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
        'plan_id', 'plan_digest', 'hq_epoch', 'start_envelope_sha256', 'expected'],
      'stage2a-hello-abort': ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
        'plan_id', 'plan_digest', 'hq_epoch'],
      'stage2a-peer-role': ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
        'plan_id', 'plan_digest', 'hq_epoch', 'peer_uid', 'peer_pid'],
      'stage2a-provider': ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
        'plan_id', 'plan_digest', 'hq_epoch', 'bind_receipt_sha256', 'model', 'prompt_sha256'],
    };
    const expected = selectors[verb];
    const id = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
    const sha = /^[0-9a-f]{64}$/;
    const reservation = /^sha256:[0-9a-f]{64}$/;
    const nonce = deviceFields?.nonce;
    if (!deviceFields || typeof deviceFields !== 'object' || Array.isArray(deviceFields)
      || Object.keys(deviceFields).length !== expected.length
      || !expected.every((key) => Object.hasOwn(deviceFields, key))
      || (verb === 'stage2a-lookup' && (typeof deviceFields.package_path !== 'string'
        || !isAbsolute(deviceFields.package_path) || /[\x00\r\n]/.test(deviceFields.package_path)
        || Buffer.byteLength(deviceFields.package_path) > 4096))
      || (verb === 'stage2a-reserve' && (!sha.test(deviceFields.plan_digest)
        || !id.test(deviceFields.installation_id) || !/^st_[0-9a-f]{24}$/.test(deviceFields.start_id)
        || !sha.test(deviceFields.hq_epoch) || !/^ln_[0-9a-f]{24}$/.test(deviceFields.launch_id)))
      || (verb === 'stage2a-exec' && (!reservation.test(deviceFields.reservation_sha256)
        || !['runner', 'bridge', 'child'].includes(deviceFields.role)
        || typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(nonce)
        || Buffer.from(nonce, 'base64url').length !== 32
        || Buffer.from(nonce, 'base64url').toString('base64url') !== nonce
        || !Number.isSafeInteger(deviceFields.pid) || deviceFields.pid < 2))
      || (verb === 'stage2a-verify-b' && (!reservation.test(deviceFields.reservation_sha256)
        || !id.test(deviceFields.installation_id) || !/^st_[0-9a-f]{24}$/.test(deviceFields.start_id)
        || !/^ln_[0-9a-f]{24}$/.test(deviceFields.launch_id) || !id.test(deviceFields.plan_id)
        || !sha.test(deviceFields.plan_digest) || !sha.test(deviceFields.hq_epoch)
        || !sha.test(deviceFields.challenge) || !sha.test(deviceFields.proof)))
      || (verb === 'stage2a-prepare-b' && !validStage2aPrepareB(deviceFields))
      || (['stage2a-stop', 'stage2a-finalize-b', 'stage2a-live', 'stage2a-provider',
        'stage2a-child-ready', 'stage2a-hello-start', 'stage2a-hello-finalize',
        'stage2a-hello-abort', 'stage2a-peer-role'].includes(verb)
        && (!reservation.test(deviceFields.reservation_sha256)
        || !id.test(deviceFields.installation_id) || !/^st_[0-9a-f]{24}$/.test(deviceFields.start_id)
        || !/^ln_[0-9a-f]{24}$/.test(deviceFields.launch_id) || !id.test(deviceFields.plan_id)
        || !sha.test(deviceFields.plan_digest) || !sha.test(deviceFields.hq_epoch)))
      || (verb === 'stage2a-finalize-b' && !validStage2aFinalizeB(deviceFields))
      || (verb === 'stage2a-live' && (typeof deviceFields.challenge !== 'string'
        || !/^[A-Za-z0-9_-]{43}$/.test(deviceFields.challenge)
        || Buffer.from(deviceFields.challenge, 'base64url').length !== 32
        || Buffer.from(deviceFields.challenge, 'base64url').toString('base64url')
          !== deviceFields.challenge))
      || (verb === 'stage2a-child-ready' && (!Number.isSafeInteger(deviceFields.child_launcher_pid)
        || deviceFields.child_launcher_pid < 2 || !Number.isSafeInteger(deviceFields.child_pid)
        || deviceFields.child_pid < 2 || deviceFields.child_pid === deviceFields.child_launcher_pid
        || !reservation.test(deviceFields.grant_sha256)))
      || (verb === 'stage2a-hello-start' && (!Number.isSafeInteger(deviceFields.peer_uid)
        || deviceFields.peer_uid < 1 || !Number.isSafeInteger(deviceFields.peer_pid)
        || deviceFields.peer_pid < 2 || !reservation.test(deviceFields.hello_payload_sha256)
        || !reservation.test(deviceFields.broker_bind_receipt_sha256)
        || typeof deviceFields.hello_payload_base64url !== 'string'
        || !/^[A-Za-z0-9_-]{1,5462}$/.test(deviceFields.hello_payload_base64url)
        || Buffer.from(deviceFields.hello_payload_base64url, 'base64url').toString('base64url')
          !== deviceFields.hello_payload_base64url
        || `sha256:${fingerprint(Buffer.from(deviceFields.hello_payload_base64url, 'base64url'))}`
          !== deviceFields.hello_payload_sha256))
      || (verb === 'stage2a-peer-role' && (!Number.isSafeInteger(deviceFields.peer_uid)
        || deviceFields.peer_uid < 1 || !Number.isSafeInteger(deviceFields.peer_pid)
        || deviceFields.peer_pid < 2))
      || (verb === 'stage2a-hello-finalize' && (!reservation.test(deviceFields.start_envelope_sha256)
        || !deviceFields.expected || typeof deviceFields.expected !== 'object'
        || Array.isArray(deviceFields.expected)
        || Buffer.byteLength(JSON.stringify(deviceFields.expected)) > 4096))
      || (verb === 'stage2a-provider' && (!reservation.test(deviceFields.bind_receipt_sha256)
        || !id.test(deviceFields.model) || !reservation.test(deviceFields.prompt_sha256)))) {
      throw new Error('invalid Stage 2a Machine reservation selectors');
    }
  } else if (COOPERATIVE_STATES.has(verb)) {
    if (!deviceFields || typeof deviceFields !== 'object' || Array.isArray(deviceFields)
      || Buffer.byteLength(JSON.stringify(deviceFields)) > 8192) throw new Error('invalid cooperative Machine selectors');
  } else if (deviceFields !== undefined) throw new Error('unexpected Machine device fields');
  const stage2aFields = {
    'stage2a-lookup': ['package_path'],
    'stage2a-list': [],
    'stage2a-reserve': ['plan_digest', 'installation_id', 'start_id', 'hq_epoch', 'launch_id'],
    'stage2a-exec': ['reservation_sha256', 'role', 'nonce', 'pid'],
    'stage2a-verify-b': ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
      'plan_id', 'plan_digest', 'hq_epoch', 'challenge', 'proof'],
    'stage2a-prepare-b': ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
      'plan_id', 'plan_digest', 'hq_epoch', 'broker'],
    'stage2a-stop': ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
      'plan_id', 'plan_digest', 'hq_epoch'],
    'stage2a-finalize-b': ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
      'plan_id', 'plan_digest', 'hq_epoch', 'bind_receipt_sha256', 'relay_socket'],
    'stage2a-live': ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
      'plan_id', 'plan_digest', 'hq_epoch', 'challenge'],
    'stage2a-child-ready': ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
      'plan_id', 'plan_digest', 'hq_epoch', 'child_launcher_pid', 'child_pid', 'grant_sha256'],
    'stage2a-hello-start': ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
      'plan_id', 'plan_digest', 'hq_epoch', 'peer_uid', 'peer_pid',
      'hello_payload_base64url', 'hello_payload_sha256', 'broker_bind_receipt_sha256'],
    'stage2a-hello-finalize': ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
      'plan_id', 'plan_digest', 'hq_epoch', 'start_envelope_sha256', 'expected'],
    'stage2a-hello-abort': ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
      'plan_id', 'plan_digest', 'hq_epoch'],
    'stage2a-peer-role': ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
      'plan_id', 'plan_digest', 'hq_epoch', 'peer_uid', 'peer_pid'],
    'stage2a-provider': ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
      'plan_id', 'plan_digest', 'hq_epoch', 'bind_receipt_sha256', 'model', 'prompt_sha256'],
  }[verb];
  const stage2aRequest = stage2aFields
    ? Buffer.from(JSON.stringify(Object.fromEntries(stage2aFields.map((key) => [key, deviceFields[key]])))).toString('base64url')
    : COOPERATIVE_STATES.has(verb) ? Buffer.from(JSON.stringify(deviceFields)).toString('base64url') : undefined;
  const fields = { verb, ...(verb === 'hq-device' ? deviceFields : {}),
    ...(stage2aRequest && { stage2a_request: stage2aRequest }),
    ...(option && { option }), ...(planID && { plan_id: planID }) };
  const resultOfSend = await send(fields).catch(error => {
    if (pair && disconnectedPairs.has(error)) disconnectedPairs.set(error, pair);
    // keyd binds this exact signed receipt idempotently. Reconnect once with
    // a fresh channel nonce if Machine closed without returning any bytes.
    if (verb === 'hq-device' && option === 'bind-access' && error instanceof MissingMachineReply) return send(fields);
    throw error;
  });
  if (capture) return resultOfSend.capture;
  const { response: r } = resultOfSend;
  const result = { client: 'agent-daemon', channel: 'signed', state: r.state, daemon_fingerprint: fingerprint(daemon) };
  if (verb === 'hq-device') {
    if (pair) verifiedPairs.set(r, pair);
    return r;
  }
  if (COOPERATIVE_STATES.has(verb)) {
    if (r.state !== COOPERATIVE_STATES.get(verb)) throw new Error('unexpected signed Machine cooperative state');
    return Object.freeze({ body: r.body, machineKey: Buffer.from(daemon) });
  }
  if (stage2aFields) {
    const expectedState = { 'stage2a-lookup': 'found', 'stage2a-list': 'listed',
      'stage2a-reserve': 'reserved', 'stage2a-exec': 'granted',
      'stage2a-verify-b': 'verified', 'stage2a-prepare-b': 'prepared',
      'stage2a-stop': 'stopped', 'stage2a-finalize-b': 'finalized',
      'stage2a-live': 'live', 'stage2a-provider': 'provided',
      'stage2a-child-ready': 'child-ready', 'stage2a-hello-start': 'hello-started',
      'stage2a-hello-finalize': 'hello-finalized', 'stage2a-hello-abort': 'hello-aborted',
      'stage2a-peer-role': 'peer-verified' }[verb];
    if (r.state !== expectedState) throw new Error('unexpected signed Machine Stage 2a state');
    const body = r.body;
    if (verb === 'stage2a-list') return stage2aListResult(body, daemon, uid);
    if (verb === 'stage2a-lookup') {
      if (!body || typeof body !== 'object' || Array.isArray(body)
        || Object.keys(body).length !== 5
        || !['installation_id', 'plan_id', 'plan_digest', 'runner_account', 'bridge_account']
          .every((key) => Object.hasOwn(body, key))
        || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(body.installation_id)
        || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(body.plan_id)
        || !/^[0-9a-f]{64}$/.test(body.plan_digest)
        || body.runner_account !== `_abm-sr-${fingerprint(Buffer.from(body.installation_id)).slice(0, 20)}`
        || body.bridge_account !== `_abm-br-${fingerprint(Buffer.from(`agent-bot-soul-bridge/v1\0${body.installation_id}`)).slice(0, 20)}`) {
        throw new Error('invalid signed Machine Stage 2a lookup');
      }
      return Object.freeze({ ...body, daemon_fingerprint: fingerprint(daemon) });
    }
    if (verb === 'stage2a-verify-b') {
      if (!body || typeof body !== 'object' || Array.isArray(body)
        || Object.keys(body).length !== 1 || body.verified !== true) throw new Error('invalid signed Machine bridge verification');
      return Object.freeze({ verified: true, daemon_fingerprint: fingerprint(daemon) });
    }
    if (verb === 'stage2a-prepare-b') {
      if (!body || typeof body !== 'object' || Array.isArray(body)
        || Object.keys(body).length !== 1 || !/^sha256:[0-9a-f]{64}$/.test(body.assignment_sha256)) {
        throw new Error('invalid signed Machine B preparation');
      }
      return Object.freeze({ assignment_sha256: body.assignment_sha256,
        daemon_fingerprint: fingerprint(daemon) });
    }
    if (verb === 'stage2a-live') {
      const base = ['reservation_sha256', 'phase', 'bridge_pid', 'runner_pid'];
      const finalized = ['finalization_sha256', 'bind_receipt_sha256', 'finalized_live_expires_at',
        'lease_envelope_base64url', 'lease_sha256', 'lease_sequence'];
      if (!body || typeof body !== 'object' || Array.isArray(body)
        || !['prebind', 'finalized'].includes(body.phase)
        || Object.keys(body).sort().join(',') !== [...base, ...(body.phase === 'finalized' ? finalized : [])].sort().join(',')
        || body.reservation_sha256 !== deviceFields.reservation_sha256
        || !Number.isSafeInteger(body.bridge_pid) || body.bridge_pid < 0 || body.bridge_pid === 1
        || !Number.isSafeInteger(body.runner_pid) || body.runner_pid < 0 || body.runner_pid === 1
        || (body.phase === 'finalized' && (!/^sha256:[0-9a-f]{64}$/.test(body.finalization_sha256)
          || !/^sha256:[0-9a-f]{64}$/.test(body.bind_receipt_sha256)
          || !Number.isSafeInteger(body.finalized_live_expires_at)
          || body.finalized_live_expires_at <= Date.now()
          || !validStage2aSignedLiveLease(body)))) {
        throw new Error('invalid signed Machine live start');
      }
      return Object.freeze({ ...body, daemon_fingerprint: fingerprint(daemon) });
    }
    if (verb === 'stage2a-provider') {
      if (!body || typeof body !== 'object' || Array.isArray(body)
        || Object.keys(body).sort().join(',') !== 'config_base64url,expires_at_ms,model,provider_config_sha256,request_sha256,response_text'
        || body.model !== deviceFields.model || body.request_sha256 !== deviceFields.prompt_sha256
        || !/^[0-9a-f]{64}$/.test(body.provider_config_sha256)
        || typeof body.config_base64url !== 'string'
        || !/^[A-Za-z0-9_-]{1,87382}$/.test(body.config_base64url)
        || Buffer.from(body.config_base64url, 'base64url').toString('base64url') !== body.config_base64url
        || typeof body.response_text !== 'string' || !body.response_text || body.response_text.length > 4096
        || !Number.isSafeInteger(body.expires_at_ms) || body.expires_at_ms <= Date.now()) {
        throw new Error('invalid signed Machine one-use provider');
      }
      return Object.freeze({ ...body, daemon_fingerprint: fingerprint(daemon) });
    }
    if (verb === 'stage2a-hello-abort') {
      if (!body || typeof body !== 'object' || Array.isArray(body)
        || Object.keys(body).join(',') !== 'aborted' || body.aborted !== true) {
        throw new Error('invalid signed Machine Hello abort');
      }
      return Object.freeze({ aborted: true, daemon_fingerprint: fingerprint(daemon) });
    }
    if (verb === 'stage2a-finalize-b' || verb === 'stage2a-child-ready') {
      if (!body || typeof body !== 'object' || Array.isArray(body)
        || Object.keys(body).sort().join(',') !== (verb === 'stage2a-finalize-b'
          ? 'envelope_base64url,finalized_live_expires_at,sha256'
          : 'envelope_base64url,expires_at_ms,sha256')
        || !Number.isSafeInteger(verb === 'stage2a-finalize-b'
          ? body.finalized_live_expires_at : body.expires_at_ms)
        || (verb === 'stage2a-finalize-b' ? body.finalized_live_expires_at
          : body.expires_at_ms) <= Date.now()) {
        throw new Error('invalid signed Machine Stage 2a finalization');
      }
    }
    const expected = verb === 'stage2a-exec'
      ? ['envelope_base64url', 'sha256', 'invocation_base64url']
      : verb === 'stage2a-finalize-b'
        ? ['envelope_base64url', 'sha256', 'finalized_live_expires_at']
        : verb === 'stage2a-child-ready'
          ? ['envelope_base64url', 'sha256', 'expires_at_ms']
        : ['envelope_base64url', 'sha256'];
    if (!body || typeof body !== 'object' || Array.isArray(body)
      || Object.keys(body).length !== expected.length
      || !expected.every((key) => Object.hasOwn(body, key))
      || typeof body.envelope_base64url !== 'string'
      || !/^[A-Za-z0-9_-]+$/.test(body.envelope_base64url)
      || !/^sha256:[0-9a-f]{64}$/.test(body.sha256)) throw new Error('invalid signed Machine Stage 2a body');
    const envelope = Buffer.from(body.envelope_base64url, 'base64url');
    if (envelope.length === 0 || envelope.toString('base64url') !== body.envelope_base64url
      || `sha256:${fingerprint(envelope)}` !== body.sha256) throw new Error('Machine reservation envelope digest mismatch');
    if (verb === 'stage2a-reserve' || verb === 'stage2a-stop'
      || verb === 'stage2a-finalize-b' || verb === 'stage2a-child-ready'
      || verb === 'stage2a-hello-start' || verb === 'stage2a-hello-finalize'
      || verb === 'stage2a-peer-role') {
      return Object.freeze({ envelope, sha256: body.sha256,
        ...(verb === 'stage2a-finalize-b' ? { finalized_live_expires_at: body.finalized_live_expires_at } : {}),
        ...(verb === 'stage2a-child-ready' ? { expires_at_ms: body.expires_at_ms } : {}),
        daemon_fingerprint: fingerprint(daemon) });
    }
    if (typeof body.invocation_base64url !== 'string' || !/^[A-Za-z0-9_-]+$/.test(body.invocation_base64url)) {
      throw new Error('invalid Machine role invocation');
    }
    const invocation = Buffer.from(body.invocation_base64url, 'base64url');
    if (invocation.length === 0 || invocation.toString('base64url') !== body.invocation_base64url) {
      throw new Error('invalid Machine role invocation');
    }
    const grantLine = Buffer.from(JSON.stringify({ envelope_base64url: body.envelope_base64url,
      sha256: body.sha256, invocation_base64url: body.invocation_base64url }) + '\n', 'utf8');
    return Object.freeze({ envelope, sha256: body.sha256, invocation, grantLine,
      daemon_fingerprint: fingerprint(daemon) });
  }
  if (verb === 'members-plans') return { ...result, ...membersPlanResult(option, planID, r) };
  if (!existing && !publish(dir, 'daemon.pub', daemon, uid).equals(daemon)) throw new Error('a different daemon key was pinned concurrently');
  return result;
}
