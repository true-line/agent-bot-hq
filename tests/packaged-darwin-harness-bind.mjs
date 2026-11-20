// Hosted positive qualification, invoked by packaged-darwin-harness-accounts.py.
// Only the runner may switch users. Each ticket goes to its assigned harness via stdin.
import assert from 'node:assert/strict';
import { execFileSync, spawn } from 'node:child_process';
import { once } from 'node:events';
import { mkdirSync, readFileSync, realpathSync, writeFileSync } from 'node:fs';
import { userInfo } from 'node:os';
import { dirname, join } from 'node:path';
import { createInterface } from 'node:readline';
import { fileURLToPath } from 'node:url';
import { bindProof } from '../hq/admission.mjs';
import { DARWIN_HARNESS_DIR } from '../hq/darwin-harness-accounts.mjs';
import { createHQ } from '../hq/hq.mjs';
import { productionPluginsDir, readPins } from '../hq/plugins.mjs';
import { connectSocket } from '../hq/socket.mjs';

const role = '_agent-bot-hq';
const file = fileURLToPath(import.meta.url);
const root = dirname(dirname(file));
const cli = join(root, 'hq/main.mjs');
const json = path => JSON.parse(readFileSync(path, 'utf8'));
const out = data => process.stdout.write(JSON.stringify(data) + '\n');
const uidOf = account => Number(execFileSync('/usr/bin/id', ['-u', account], { encoding: 'utf8' }).trim());
const readLines = input => createInterface({ input })[Symbol.asyncIterator]();
const stdinJSON = async () => {
  const { value, done } = await readLines(process.stdin).next();
  assert.ok(!done, 'fixture controller closed');
  return JSON.parse(value);
};

function runAs(account, args) {
  const child = spawn('/usr/bin/sudo', ['-n', '-H', '-u', account, '--', '/usr/bin/env', '-i',
    'PATH=/usr/bin:/bin', 'HQ_INTERIM_OFFLINE=1', 'GITHUB_ACTIONS=true', 'RUNNER_OS=macOS',
    'RUNNER_ENVIRONMENT=github-hosted', process.execPath, file, ...args],
    { stdio: ['pipe', 'pipe', 'inherit'], timeout: 60_000 });
  return { child, lines: readLines(child.stdout), exit: once(child, 'exit') };
}

function checkStatus(status, accounts, available) {
  const release = json(join(root, 'governance/interim-release.json'));
  assert.equal(status.mode, available ? 'running' : 'safe');
  assert.equal(status.profile, 'managed-cooperative');
  assert.equal(status.hq.account, role);
  assert.equal(status.hq.devPlugins, undefined);
  const brokers = status.hq.pluginLoad.filter(p => p.name === 'agent-comms');
  assert.equal(brokers.length, 1);
  assert.equal(brokers[0].digest, release.broker.sha256);
  assert.equal(brokers[0].state, 'loaded');
  assert.ok(!brokers[0].dev);
  const plugin = status.plugins.find(p => p.name === 'agent-comms');
  assert.equal(plugin.version, release.broker.version);
  assert.equal(plugin.state, available ? 'running' : 'waiting');
  assert.deepEqual(status.hq.sockets.harnesses, accounts.map((account, i) => ({
    account, adapters: [i === 0 ? 'adapter-a' : 'adapter-b'], path: join(DARWIN_HARNESS_DIR, account, 'broker.sock'),
  })));
}

async function safeCLI(home, accounts, hello) {
  const child = spawn(process.execPath, [cli, 'run', '--home', home], { stdio: ['ignore', 'pipe', 'inherit'], timeout: 20_000 });
  const exit = once(child, 'exit');
  try {
    let ready = false;
    for await (const line of createInterface({ input: child.stdout })) {
      if (line.startsWith('listening:')) { ready = true; break; }
    }
    assert.ok(ready, 'archived HQ did not start');
    checkStatus(JSON.parse(execFileSync(process.execPath, [cli, 'status', '--home', home, '--json'])), accounts, false);
    const admission = await connectSocket(join(home, 'admission.sock'));
    try { assert.equal((await admission.request('Hello', hello)).host_refusal?.code, 'host.safe_mode'); }
    finally { await admission.close(); }
  } finally {
    child.kill('SIGTERM');
    assert.deepEqual(await exit, [0, null]);
  }
}

async function hostPass(state, accounts, pass) {
  assert.equal(userInfo().username, role);
  const { schemas, helloOn } = await import('./hq-harness.mjs');
  const hello = helloOn('adapter-a', 'adapter-b', { requested_profile: 'managed-cooperative' });
  const config = { harnesses: { dir: DARWIN_HARNESS_DIR, accounts: { 'adapter-a': accounts[0], 'adapter-b': accounts[1] } },
    acceptedDefinitions: { [hello.soul_id]: [hello.definition_digest] } };
  const home = join(state, 'host');
  if (pass === 1) {
    const cold = join(state, 'cli');
    for (const dir of [cold, home]) {
      mkdirSync(dir, { mode: 0o700 });
      writeFileSync(join(dir, 'config.json'), JSON.stringify(config), { mode: 0o600, flag: 'wx' });
    }
    await safeCLI(cold, accounts, hello);
  }
  const pins = readPins(join(root, 'governance/plugins.json'));
  const hq = createHQ({ home, schemas, pins, pluginsDir: productionPluginsDir({}, join(root, 'hq/interim-core.mjs'), pins),
    // Read-only test status unlocks ordinary plugin execution. No key, signing or owner operation.
    signer: { deviceStatus: async () => 'enrolled' } });
  try {
    checkStatus(await hq.start(), accounts, true);
    let tickets = [];
    if (pass === 1) {
      const admission = await connectSocket(hq.paths.admission);
      try {
        const reply = await admission.request('Hello', hello);
        assert.equal(reply.ok, true);
        assert.equal(reply.result.profile, 'managed-cooperative');
        tickets = ['lead', 'specialist'].map(roleName => {
          const rt = reply.result.admitted_runtimes.find(r => r.role === roleName);
          assert.ok(rt?.runtime_id && rt.channel_binding);
          return { runtime_id: rt.runtime_id, channel_binding: rt.channel_binding, member_id: rt.member_id, role: rt.role };
        });
      } finally { await admission.close(); }
    }
    out({ ready: true, tickets });
    const ids = await stdinJSON();
    assert.equal(ids.length, 2);
    for (const [i, account] of accounts.entries()) {
      const receipts = hq.core.receipts.filter(r => r.kind === 'hq.bind' && r.runtime_id === ids[i]);
      assert.equal(receipts.length, pass);
      for (const r of receipts) {
        assert.equal(r.caller_account, account);
        assert.equal(r.proof, 'hmac-sha256');
        assert.equal(r.profile, 'managed-cooperative');
      }
    }
  } finally { await hq.stop(); }
}

async function bindMember(account) {
  assert.equal(userInfo().username, account);
  const { runtime_id, channel_binding } = await stdinJSON();
  const conn = await connectSocket(join(DARWIN_HARNESS_DIR, account, 'broker.sock'));
  try {
    const challenge = await conn.request('bind.challenge', { runtime_id });
    assert.equal(challenge.ok, true);
    const proof = bindProof(channel_binding, challenge.result.nonce, runtime_id);
    const reply = await conn.request('bind', { runtime_id, proof });
    assert.equal(reply.ok, true);
    out({ uid: process.getuid(), binding: reply.result });
  } finally { await conn.close(); }
}

async function run(archive, state, accounts) {
  assert.equal(realpathSync(archive), realpathSync(root));
  const uids = accounts.map(uidOf);
  assert.equal(new Set([process.getuid(), uidOf(role), ...uids]).size, 4);
  let tickets;
  for (const pass of [1, 2]) {
    const host = runAs(role, ['--role', state, ...accounts, String(pass)]);
    try {
      const { ready, tickets: offered } = JSON.parse((await host.lines.next()).value);
      assert.equal(ready, true);
      if (pass === 1) {
        tickets = offered;
        assert.equal(tickets.length, 2);
        assert.equal(new Set(tickets.map(t => t.runtime_id)).size, 2);
        console.log('Packaged HQ CLI loaded the production broker, opened both verified endpoints and refused admission in safe mode.');
      } else assert.equal(offered.length, 0);
      for (const [i, account] of accounts.entries()) {
        const member = runAs(account, ['--member', account]);
        try {
          const { channel_binding, ...binding } = tickets[i];
          member.child.stdin.end(JSON.stringify({ runtime_id: binding.runtime_id, channel_binding }) + '\n');
          assert.deepEqual(JSON.parse((await member.lines.next()).value), { uid: uids[i], binding });
          assert.deepEqual(await member.exit, [0, null]);
        } finally { member.child.kill(); }
      }
      host.child.stdin.end(JSON.stringify(tickets.map(t => t.runtime_id)) + '\n');
      assert.deepEqual(await host.exit, [0, null]);
    } finally { host.child.stdin.end(); await host.exit; }
  }
  console.log('With fixture enrollment status, both native harness UIDs bound before and after HQ restarted. Four persisted cooperative receipts recorded the assigned accounts.');
}

assert.ok(process.platform === 'darwin' && process.getuid() !== 0 && process.env.GITHUB_ACTIONS === 'true' &&
  process.env.RUNNER_OS === 'macOS' && process.env.RUNNER_ENVIRONMENT === 'github-hosted', 'requires a non-root disposable macOS hosted runner');
const [mode, ...args] = process.argv.slice(2);
if (mode === '--role') await hostPass(args[0], args.slice(1, 3), Number(args[3]));
else if (mode === '--member') await bindMember(args[0]);
else await run(mode, args[0], args.slice(1));
