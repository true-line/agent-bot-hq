#!/usr/bin/env node
// Protocol qualification for an explicitly selected, loopback software TPM.
import { derToP1363 } from '../../helpers/tpm2-signer.mjs';
import { createPublicKey } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { mkdtempSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const PROTOCOL = 'agent-bot-hq-signer/1';
const DEFAULT_HANDLE = '0x81010020';
const MAX_MESSAGE_BYTES = 32 * 1024;
const REQUIRED_ATTRIBUTES = ['fixedtpm', 'fixedparent', 'sensitivedataorigin', 'sign'];
const KEY_ATTRIBUTES = [...REQUIRED_ATTRIBUTES, 'userwithauth'].join('|');

function parse(argv) {
  const args = { handle: DEFAULT_HANDLE };
  const rest = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === '--handle') args.handle = argv[++i];
    else rest.push(argv[i]);
  }
  if (rest.length !== 1) throw new Error('usage: tpm2-signer.mjs [--handle 0x8101XXXX] <status|create|sign>');
  // Persistent handles in the owner hierarchy: 0x81000000–0x817FFFFF.
  if (!/^0x81[0-7][0-9a-fA-F]{5}$/.test(args.handle ?? '')) throw new Error('--handle is a persistent owner-hierarchy handle, 0x81000000 to 0x817fffff');
  args.handle = args.handle.toLowerCase();
  args.op = rest[0];
  return args;
}

const tpm = (tool, args) => execFileSync(tool, args, { encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], timeout: 20_000 });

function withScratch(fn) {
  const dir = mkdtempSync(join(tmpdir(), 'hq-tpm-'));
  try { return fn(dir); } finally { rmSync(dir, { recursive: true, force: true }); }
}

function present(handle) {
  return tpm('tpm2_getcap', ['handles-persistent']).toLowerCase().split(/\s+/).includes(handle);
}

function readSigningKey(handle, dir) {
  const pem = join(dir, 'pub.pem');
  // A persistent handle can already hold an independently provisioned key.
  // Read its custody attributes and PEM in the same TPM ReadPublic response.
  const description = tpm('tpm2_readpublic', ['-c', handle, '-f', 'pem', '-o', pem]);
  const attributes = /^attributes:\r?\n  value: ([^\r\n]+)$/m.exec(description)?.[1].trim().split('|') ?? [];
  if (!REQUIRED_ATTRIBUTES.every((attr) => attributes.includes(attr))) {
    throw new Error(`the key at ${handle} lacks verified TPM signing and custody attributes`);
  }
  const { kty, crv, x, y } = createPublicKey(readFileSync(pem, 'utf8')).export({ format: 'jwk' });
  if (kty !== 'EC' || crv !== 'P-256') throw new Error(`the key at ${handle} is not a P-256 key`);
  return { kty, crv, x, y };
}

function create(handle, replace) {
  if (present(handle)) {
    if (!replace) throw new Error(`a key already exists at ${handle}; replacing it is a re-enrollment`);
    tpm('tpm2_evictcontrol', ['-C', 'o', '-c', handle]);
  }
  // Talking to a TPM directly (no resource manager, as with a software TPM
  // over a socket), each tool leaves its transient objects loaded and the
  // chip has room for about three. Flush them before, between and after. Behind the
  // kernel resource manager (/dev/tpmrm0) this flushes nothing of anyone else's.
  const flush = () => { try { tpm('tpm2_flushcontext', ['-t']); } catch { /* nothing to flush */ } };
  flush();
  withScratch((dir) => {
    const f = (n) => join(dir, n);
    // Each step saves its object to a context file, so the loaded copy can go.
    tpm('tpm2_createprimary', ['-C', 'o', '-G', 'ecc256', '-c', f('primary.ctx')]);
    flush();
    tpm('tpm2_create', ['-C', f('primary.ctx'), '-G', 'ecc256:ecdsa-sha256', '-a', KEY_ATTRIBUTES, '-u', f('key.pub'), '-r', f('key.priv')]);
    flush();
    tpm('tpm2_load', ['-C', f('primary.ctx'), '-u', f('key.pub'), '-r', f('key.priv'), '-c', f('key.ctx')]);
    flush();
    try { tpm('tpm2_evictcontrol', ['-C', 'o', '-c', f('key.ctx'), handle]); } finally { flush(); }
  });
  return withScratch((dir) => readSigningKey(handle, dir));
}

function sign(handle, message) {
  return withScratch((dir) => {
    readSigningKey(handle, dir); // A persistent handle may change between helper calls.
    const msg = join(dir, 'msg.bin');
    const sig = join(dir, 'sig.bin');
    writeFileSync(msg, message, { mode: 0o600 });
    // The TPM hashes the message itself. For ECDSA, `plain` is the DER
    // signature (SEQUENCE of r and s); the protocol wants r || s.
    tpm('tpm2_sign', ['-c', handle, '-g', 'sha256', '-s', 'ecdsa', '-f', 'plain', '-o', sig, msg]);
    return derToP1363(readFileSync(sig)).toString('base64url');
  });
}


function main() {
  if (!/^swtpm:host=127\.0\.0\.1,port=[1-9][0-9]{0,4}$/.test(process.env.TPM2TOOLS_TCTI ?? '')) {
    throw new Error('the fixture requires a loopback software TPM');
  }
  const { handle, op } = parse(process.argv.slice(2));
  const text = readFileSync(0, 'utf8');
  const body = text.trim() ? JSON.parse(text) : {};
  const base = { protocol: PROTOCOL, key_storage: 'hardware' };
  if (op === 'status') {
    return present(handle) ? { ...base, present: true, jwk: withScratch((dir) => readSigningKey(handle, dir)) } : { ...base, present: false };
  }
  if (op === 'create') return { ...base, jwk: create(handle, body.replace === true) };
  if (op === 'sign') {
    if (typeof body.message !== 'string' || !/^[A-Za-z0-9_-]*$/.test(body.message)) throw new Error('sign needs a base64url message');
    const message = Buffer.from(body.message, 'base64url');
    if (message.length === 0 || message.length > MAX_MESSAGE_BYTES) throw new Error(`sign takes 1 to ${MAX_MESSAGE_BYTES} bytes`);
    return { protocol: PROTOCOL, signature: sign(handle, message) };
  }
  throw new Error(`unknown operation ${op}`);
}

if (process.argv[1] && realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    process.stdout.write(JSON.stringify(main()));
  } catch (e) {
    // Errors go to stderr; HQ reads the exit code and treats the signer as unavailable.
    process.stderr.write(`tpm2-signer: ${String(e.stderr ?? e.message).trim()}\n`);
    process.exitCode = 1;
  }
}
