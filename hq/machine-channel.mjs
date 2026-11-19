// HQ's agent-daemon client of Machine's daemon-machine-channel. The private
// seed belongs to the service account. It is independent of the HQ signer.
import { isUtf8 } from 'node:buffer';
import { parseStrict } from '../sdk/wire/strict-json.mjs';
import { membersPlanResult, validPlanId } from './machine-members-plans.mjs';
import { execFileSync } from 'node:child_process';
import { createHash, createPrivateKey, createPublicKey, randomBytes, sign, verify } from 'node:crypto';
import { closeSync, constants, fstatSync, fsyncSync, linkSync, lstatSync, mkdirSync, openSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { connect } from 'node:net';
import { userInfo } from 'node:os';
import { isAbsolute, join } from 'node:path';

const PKCS8 = Buffer.from('302e020100300506032b657004220420', 'hex');
const SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const HEX_KEY = /^[0-9a-f]{64}$/i;
const MAX_MESSAGE = 64 * 1024;
const fingerprint = (raw) => createHash('sha256').update(raw).digest('hex');

function checkAcl(path) {
  if (process.platform === 'darwin') {
    const listing = execFileSync('/bin/ls', ['-led', path], { encoding: 'utf8', env: { LC_ALL: 'C' } });
    if (/^\s*\d+:/m.test(listing)) throw new Error(`unexpected ACL on ${path}`);
  }
}

function roleDir(path, uid, create, { allowReadTraverse = false } = {}) {
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
  checkAcl(path);
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

function clientIdentity(dir, uid, create) {
  const keyPath = join(dir, 'client.key');
  let seed = readKey(keyPath, uid);
  if (!seed) {
    if (!create) throw new Error('initialize the HQ Machine identity first');
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
  const singleLine = (s) => typeof s === 'string' && !/[\r\n]/.test(s);
  if (typeof r.ok !== 'boolean' || !Number.isSafeInteger(r.timestamp) ||
      Math.abs(Date.now() / 1000 - r.timestamp) > 300 || r.request_nonce !== nonce ||
      !singleLine(r.nonce) || !r.nonce || Buffer.byteLength(r.nonce) > 128 || ![r.state ?? '', r.diagnostic ?? '', r.message ?? ''].every(singleLine) ||
      typeof r.signature !== 'string') throw new Error(`invalid or stale Machine ${verb} response`);
  const bytes = Buffer.from([r.ok, r.diagnostic ?? '', r.message ?? '', r.state ?? '', body, r.timestamp, r.nonce, nonce].join('\n'));
  const key = createPublicKey({ key: Buffer.concat([SPKI, pinned]), type: 'spki', format: 'der' });
  const signature = Buffer.from(r.signature, 'base64');
  if (signature.length !== 64 || signature.toString('base64') !== r.signature || !verify(null, bytes, key, signature)) {
    throw new Error(`Machine ${verb} signature does not match the daemon pin`);
  }
  if (!r.ok) throw new Error(`Machine refused signed ${verb}: ${r.diagnostic || 'unspecified'}`);
  if (!r.state) throw new Error(`signed Machine ${verb} is missing its state`);
  return r;
}

function exchange(socketPath, request) {
  return new Promise((resolve, reject) => {
    const stream = connect({ path: socketPath });
    const chunks = [];
    let size = 0;
    const timer = setTimeout(() => stream.destroy(new Error('Machine request timed out')), 10000);
    stream.once('connect', () => stream.write(JSON.stringify(request) + '\n'));
    stream.on('error', reject);
    stream.on('close', () => { clearTimeout(timer); reject(new Error('Machine closed without a response')); });
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

export function machineRoleCommand(argv) {
  const account = userInfo();
  const mac = process.platform === 'darwin';
  const role = mac ? '_agent-bot-hq' : 'agent-bot-hq';
  const homes = mac ? ['/var/agent-bot-hq', '/private/var/agent-bot-hq'] : ['/var/lib/agent-bot-hq'];
  if ((!mac && process.platform !== 'linux') || account.username !== role || !homes.includes(account.homedir) ||
      account.uid <= 0 || account.uid !== process.getuid() || account.uid !== process.geteuid() ||
      (mac && (account.uid < 300 || account.uid > 399 || account.gid !== account.uid))) {
    throw new Error('Machine channel commands require the dedicated HQ service account');
  }
  return machineCommandInHome(argv, account.homedir, account.uid);
}

// Also exercised with a temporary private home in the protocol tests. The CLI
// always obtains its home and UID from the kernel-backed account lookup above.
export async function machineCommandInHome(argv, home, uid) {
  const [verb, ...args] = argv;
  const identity = verb === 'identity' && !args.length;
  let socket, hex, option = '', planID = '';
  if (verb === 'status' && args[0] === '--socket' &&
      (args.length === 2 || (args.length === 4 && args[2] === '--daemon-key' && HEX_KEY.test(args[3])))) {
    [, socket, , hex] = args;
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
  roleDir(home, uid, false);
  const config = join(home, '.config');
  const dir = join(config, 'agent-machine');
  roleDir(config, uid, identity, { allowReadTraverse: true });
  roleDir(dir, uid, identity);
  if (identity) { syncDir(home); syncDir(config); }
  const { key, pub } = clientIdentity(dir, uid, identity);
  if (identity) return { client: 'agent-daemon', public_key: pub.toString('hex'), fingerprint: fingerprint(pub) };
  const existing = readKey(join(dir, 'daemon.pub'), uid);
  const given = hex && Buffer.from(hex, 'hex');
  if (existing && given && !existing.equals(given)) throw new Error('the supplied daemon key differs from the existing pin');
  const daemon = existing || given;
  if (!daemon) {
    if (verb === 'members-plans') throw new Error('members-plans requires the daemon pin saved by verified Machine status');
    throw new Error('first signed status requires the prefix owner’s verified --daemon-key HEX');
  }
  const timestamp = Math.floor(Date.now() / 1000);
  const nonce = randomBytes(16).toString('base64url');
  const bytes = Buffer.from([verb, '', option, '', planID, '', '', '', timestamp, nonce].join('\n'));
  const request = { verb, ...(option && { option }), ...(planID && { plan_id: planID }), timestamp, nonce,
    public_key: pub.toString('base64'), signature: sign(null, bytes, key).toString('base64') };
  const r = authenticatedResponse(await exchange(socket, request), nonce, daemon, verb);
  const result = { client: 'agent-daemon', channel: 'signed', state: r.state, daemon_fingerprint: fingerprint(daemon) };
  if (verb === 'members-plans') return { ...result, ...membersPlanResult(option, planID, r) };
  if (!existing && !publish(dir, 'daemon.pub', daemon, uid).equals(daemon)) throw new Error('a different daemon key was pinned concurrently');
  return result;
}
