// HQ's agent-daemon client of Machine's daemon-machine-channel. The private
// seed belongs to the service account. It is independent of the HQ signer.
import { isUtf8 } from 'node:buffer';
import { parseStrict } from '../sdk/wire/strict-json.mjs';
import { recoveryArgs, serviceRecovery } from './machine-service-recovery.mjs';
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
const fingerprint = (raw) => createHash('sha256').update(raw).digest('hex');

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

function authenticatedResponse(line, nonce, pinned, verb) {
  const { value: r, body } = responseFields(line);
  if (['hq-service-recovery', 'hq-device'].includes(verb) && Object.keys(r).some((field) =>
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
    let error = new Error(`Machine refused signed ${verb}: ${r.diagnostic || 'unspecified'}`);
    if (verb === 'hq-device') {
      if (r.diagnostic === 'MM_DAEMON_UNKNOWN_KEY') {
        error = new HostError('credential_unavailable', "Machine could not verify this account's pairing for device signing (MM_DAEMON_UNKNOWN_KEY). Check its pairing with the prefix owner.");
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
      if (request.verb === 'hq-device' && error.syscall === 'connect' && (error.code === 'ENOENT' || error.code === 'ECONNREFUSED')) {
        reject(new HostError('credential_unavailable', 'HQ could not connect to the paired Machine. Ask the prefix owner to check that Machine is running, then retry.'));
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

export function machineRoleDevice(option, fields) {
  const { account, ordinary } = roleAccount(false);
  const prefix = process.platform === 'darwin' && process.arch === 'arm64' ? '/opt/homebrew'
    : process.platform === 'linux' && ['x64', 'arm64'].includes(process.arch) ? '/home/linuxbrew/.linuxbrew' : null;
  if (!prefix) throw new Error('Machine device custody is unavailable on this platform');
  return machineCommandInHome(['hq-device', option, '--socket', join(prefix, 'var/agent-machine/daemon.sock')], account.homedir, account.uid, fields, ordinary);
}

export function machineRoleCommand(argv) {
  const { account, ordinary } = roleAccount(!['identity', 'status'].includes(argv[0]));
  if (argv[0] === 'hq-device') throw new Error('the device port is internal to HQ enrollment');
  if (argv[0] === 'hq-service-recovery' && process.platform !== 'darwin') throw new Error('paired HQ service recovery requires macOS');
  return machineCommandInHome(argv, account.homedir, account.uid, undefined, ordinary);
}

// Also exercised with a temporary private home in the protocol tests. The CLI
// always obtains its home and UID from the kernel-backed account lookup above.
export async function machineCommandInHome(argv, home, uid, deviceFields, ordinary = false) {
  const [verb, ...args] = argv;
  const identity = verb === 'identity' && !args.length;
  let socket, hex, recovery, option = '', planID = '';
  if (verb === 'status' && args[0] === '--socket' &&
      (args.length === 2 || (args.length === 4 && args[2] === '--daemon-key' && HEX_KEY.test(args[3])))) {
    [, socket, , hex] = args;
  } else if (verb === 'hq-device' && args.length === 3 && ['identity', 'enrollment-proof', 'bind-enrollment', 'access-assertion', 'bind-access', 'whoami'].includes(args[0]) && args[1] === '--socket') {
    [option, , socket] = args;
  } else if (verb === 'hq-service-recovery') {
    recovery = recoveryArgs(args);
    socket = recovery.socket;
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
  }
  if (!identity && (!socket || !isAbsolute(socket))) {
    throw new Error('usage: machine identity | status --socket PATH [--daemon-key HEX] | members-plans list --socket PATH [--after PLAN_ID] | members-plans get PLAN_ID --socket PATH');
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
  async function send(fields) {
    const timestamp = Math.floor(Date.now() / 1000);
    const nonce = randomBytes(16).toString('base64url');
    const parts = [fields.verb, '', fields.option ?? '', '', fields.plan_id ?? '', '', '', '', timestamp, nonce];
    for (const field of ['plan_digest', 'challenge_nonce', 'owner_signature', 'hq_epoch', 'session', 'receipt_body', 'receipt_jti', 'receipt_kid', 'receipt_signature']) {
      if (fields[field] !== undefined) parts.push(field, fields[field]);
    }
    const request = { ...fields, timestamp, nonce, public_key: pub.toString('base64'),
      signature: sign(null, Buffer.from(parts.join('\n')), key).toString('base64') };
    const line = await exchange(socket, request);
    return { line, response: authenticatedResponse(line, nonce, daemon, fields.verb) };
  }
  if (recovery) return serviceRecovery(recovery, daemon.toString('hex'), pub.toString('hex'), send,
    (line) => authenticatedResponse(line, null, daemon, verb));
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
  } else if (deviceFields !== undefined) throw new Error('unexpected Machine device fields');
  const fields = { verb, ...deviceFields, ...(option && { option }), ...(planID && { plan_id: planID }) };
  const { response: r } = await send(fields).catch(error => {
    // keyd binds this exact signed receipt idempotently. Reconnect once with
    // a fresh channel nonce if Machine closed without returning any bytes.
    if (verb === 'hq-device' && option === 'bind-access' && error instanceof MissingMachineReply) return send(fields);
    throw error;
  });
  const result = { client: 'agent-daemon', channel: 'signed', state: r.state, daemon_fingerprint: fingerprint(daemon) };
  if (verb === 'hq-device') return r;
  if (verb === 'members-plans') return { ...result, ...membersPlanResult(option, planID, r) };
  if (!existing && !publish(dir, 'daemon.pub', daemon, uid).equals(daemon)) throw new Error('a different daemon key was pinned concurrently');
  return result;
}
