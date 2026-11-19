import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { chmodSync, existsSync, mkdtempSync, readFileSync, rmSync, statSync, unlinkSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir, userInfo } from 'node:os';
import { join } from 'node:path';
import { execFile, execFileSync, spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { machineCommandInHome } from '../hq/machine-channel.mjs';

const moduleUrl = new URL('../hq/machine-channel.mjs', import.meta.url);
const main = fileURLToPath(new URL('../hq/main.mjs', import.meta.url));
const supported = ['linux', 'darwin'].includes(process.platform);
const opts = { skip: !supported };
function fixture(t) {
  const home = mkdtempSync(join(tmpdir(), 'hq-machine-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  return { home, run: (...args) => machineCommandInHome(args, home, process.getuid()), dir: join(home, '.config', 'agent-machine') };
}

test('the operator CLI refuses a non-role caller even with a self-selected HOME', opts, (t) => {
  if (['agent-bot-hq', '_agent-bot-hq'].includes(userInfo().username)) return t.skip('this account is the role');
  const { home, dir } = fixture(t);
  assert.throws(() => execFileSync(process.execPath, [main, 'machine', 'identity'], {
    env: { ...process.env, HOME: home, AGENT_BOT_HQ_HOME: home }, stdio: 'pipe',
  }), /dedicated HQ service account/);
  assert.equal(existsSync(dir), false);
});

test('first-use races publish one identity and preserve broken existing custody', opts, async (t) => {
  const { home, dir, run } = fixture(t);
  const cli = 'const {machineCommandInHome} = await import(process.argv[1]); console.log(JSON.stringify(await machineCommandInHome(["identity"],process.argv[2],process.getuid())));';
  const outputs = await Promise.all(Array.from({ length: 6 }, () => new Promise((resolve, reject) => {
    const p = spawn(process.execPath, ['--input-type=module', '-e', cli, moduleUrl.href, home]);
    let out = '', err = '';
    p.stdout.on('data', (b) => { out += b; });
    p.stderr.on('data', (b) => { err += b; });
    p.on('error', reject);
    p.on('close', (code) => code === 0 ? resolve(out) : reject(new Error(err)));
  })));
  assert.equal(new Set(outputs).size, 1);
  const id = await run('identity');
  assert.deepEqual(Object.keys(id).sort(), ['client', 'fingerprint', 'public_key']);
  assert.equal(id.public_key, readFileSync(join(dir, 'client.pub')).toString('hex'));
  assert.equal(id.fingerprint, createHash('sha256').update(Buffer.from(id.public_key, 'hex')).digest('hex'));
  assert.equal(statSync(dir).mode & 0o777, 0o700);
  for (const f of ['client.pub', 'client.key']) {
    assert.equal(statSync(join(dir, f)).mode & 0o777, 0o600);
    assert.equal(statSync(join(dir, f)).size, 32);
  }
  chmodSync(join(dir, 'client.key'), 0o644);
  await assert.rejects(run('identity'), /mode 0600/);
  chmodSync(join(dir, 'client.key'), 0o600);
  unlinkSync(join(dir, 'client.key'));
  await assert.rejects(run('identity'), /seed is missing/);
  assert.equal(existsSync(join(dir, 'client.key')), false);
});

test('status validates the raw signed body, request/response nonce and first-use pin', opts, async (t) => {
  const fixtureState = fixture(t);
  let { dir, run } = fixtureState;
  const socket = join(fixtureState.home, 'machine.sock');
  if (process.env.HQ_TEST_MACHINE_ROLE === '1') {
    assert.equal(userInfo().username, process.platform === 'darwin' ? '_agent-bot-hq' : 'agent-bot-hq');
    dir = join(userInfo().homedir, '.config', 'agent-machine');
    assert.equal(existsSync(dir), false, 'dedicated test requires a fresh disposable role');
    run = async (...args) => JSON.parse((await promisify(execFile)(process.execPath, [main, 'machine', ...args])).stdout);
  }
  const flags = ['status', '--socket', socket];
  const id = await run('identity');
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const raw = publicKey.export({ format: 'der', type: 'spki' }).subarray(12);
  const pub = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), Buffer.from(id.public_key, 'hex')]), format: 'der', type: 'spki' });
  const responses = ['wrong-signature', 'wrong-request', 'stale', 'refusal', 'good', 'good'];
  const errors = [];
  const server = createServer((s) => {
    let input = '';
    s.on('data', (chunk) => {
      input += chunk;
      if (!input.includes('\n')) return;
      try {
        const r = JSON.parse(input);
        assert.equal(r.verb, 'status');
        assert.equal(r.public_key, Buffer.from(id.public_key, 'hex').toString('base64'));
        assert.equal(verify(null, Buffer.from('status' + '\n'.repeat(8) + r.timestamp + '\n' + r.nonce), pub, Buffer.from(r.signature, 'base64')), true);
        const mode = responses.shift();
        const body = '[{"text":"\\u003cready\\u003e","body":[1e2]}]';
        const reply = { ok: mode !== 'refusal', state: 'reported', timestamp: r.timestamp - (mode === 'stale' ? 360 : 0), nonce: randomBytes(16).toString('base64url'), request_nonce: mode === 'wrong-request' ? 'other' : r.nonce };
        if (!reply.ok) reply.diagnostic = 'MM_DAEMON_UNKNOWN_KEY';
        const signed = [reply.ok, reply.diagnostic ?? '', '', reply.state, body, reply.timestamp, reply.nonce, reply.request_nonce].join('\n');
        reply.signature = sign(null, Buffer.from(mode === 'wrong-signature' ? '' : signed), privateKey).toString('base64');
        s.end(JSON.stringify(reply).slice(0, -1) + ',"body":' + body + '}\n');
      } catch (e) { errors.push(e); s.destroy(); }
    });
  });
  await new Promise((resolve, reject) => server.once('error', reject).listen(socket, resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  await assert.rejects(run(...flags), /verified --daemon-key/);
  for (const err of [/signature/, /invalid or stale/, /invalid or stale/, /MM_DAEMON_UNKNOWN_KEY/]) {
    await assert.rejects(run(...flags, '--daemon-key', raw.toString('hex')), err);
    assert.equal(existsSync(join(dir, 'daemon.pub')), false);
  }
  const first = await run(...flags, '--daemon-key', raw.toString('hex'));
  assert.equal(first.channel, 'signed');
  assert.equal(first.state, 'reported');
  assert.equal(first.daemon_fingerprint, createHash('sha256').update(raw).digest('hex'));
  assert.deepEqual(await run(...flags), first);
  await assert.rejects(run(...flags, '--daemon-key', 'cd'.repeat(32)), /differs from the existing pin/);
  assert.deepEqual(readFileSync(join(dir, 'daemon.pub')), raw);
  assert.deepEqual(errors, []);
  assert.deepEqual(responses, []);
});
