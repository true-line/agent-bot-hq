import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, statSync, unlinkSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir, userInfo } from 'node:os';
import { join } from 'node:path';
import { execFile, execFileSync, spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { membersPlanResult } from '../hq/machine-members-plans.mjs';
import { machineAccountLayout, machineCommandInHome } from '../hq/machine-channel.mjs';

const moduleUrl = new URL('../hq/machine-channel.mjs', import.meta.url);
const main = fileURLToPath(new URL('../hq/main.mjs', import.meta.url));
const supported = ['linux', 'darwin'].includes(process.platform);
const opts = { skip: !supported };
function fixture(t) {
  const home = mkdtempSync(join(tmpdir(), 'hq-machine-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  return { home, run: (...args) => machineCommandInHome(args, home, process.getuid()), dir: join(home, '.config', 'agent-machine') };
}

test('dedicated-only plan operations refuse a non-role caller even with a self-selected HOME', opts, (t) => {
  if (['agent-bot-hq', '_agent-bot-hq'].includes(userInfo().username)) return t.skip('this account is the role');
  const { home, dir } = fixture(t);
  for (const args of [['hq-service-recovery'], ['members-plans', 'list', '--socket', join(home, 'machine.sock')]]) {
    assert.throws(() => execFileSync(process.execPath, [main, 'machine', ...args], {
      env: { ...process.env, HOME: home, AGENT_BOT_HQ_HOME: home }, stdio: 'pipe',
    }), /dedicated HQ service account/);
  }
  assert.equal(existsSync(dir), false);
});

test('dedicated and explicitly selected ordinary UIDs use one channel, with service operations reserved for the role', opts, async (t) => {
  const user = { username: 'fixture', uid: 502, gid: 20, homedir: '/test/fixture' };
  const role = { username: '_agent-bot-hq', uid: 330, gid: 330, homedir: '/var/agent-bot-hq' };
  assert.equal(machineAccountLayout(role, 'darwin', 330, 330, true).ordinary, false);
  assert.equal(machineAccountLayout(user, 'darwin', 502, 502, false).ordinary, true);
  assert.throws(() => machineAccountLayout(user, 'darwin', 502, 502, true), /dedicated HQ/);
  assert.throws(() => machineAccountLayout(user, 'darwin', 502, 0, false), /authorized local account/);
  assert.throws(() => machineAccountLayout({ ...role, homedir: user.homedir }, 'darwin', 330, 330, false), /authorized local account/);
  const { home } = fixture(t);
  chmodSync(home, 0o755);
  const run = (...args) => machineCommandInHome(args, home, process.getuid(), undefined, true);
  const id = await run('identity');
  assert.ok(id.public_key);
  assert.equal(statSync(join(home, '.config/agent-machine/client.key')).mode & 0o777, 0o600);
  await assert.rejects(run('hq-device', 'identity', '--socket', join(home, 'machine.sock')), /requires the daemon pin/);
  await assert.rejects(run('members-plans', 'list', '--socket', join(home, 'machine.sock')), /dedicated HQ/);
  chmodSync(home, 0o775);
  await assert.rejects(run('identity'), /invalid role directory/);
});

test('a role home can contain a read/traverse-only .config while Machine custody stays private', opts, async (t) => {
  const { home, dir, run } = fixture(t);
  const config = join(home, '.config');
  mkdirSync(config);
  chmodSync(config, 0o775);
  await assert.rejects(run('identity'), /invalid role directory/);
  assert.equal(existsSync(dir), false);
  chmodSync(config, 0o755);
  const id = await run('identity');
  assert.equal(id.client, 'agent-daemon');
  assert.equal(statSync(config).mode & 0o777, 0o755);
  assert.equal(statSync(dir).mode & 0o777, 0o700);
  chmodSync(dir, 0o755);
  await assert.rejects(run('identity'), /invalid role directory/);
  chmodSync(dir, 0o700);
  chmodSync(home, 0o755);
  await assert.rejects(run('identity'), /invalid role directory/);
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

test('status establishes the pin and authenticated members lookup uses it from the role', opts, async (t) => {
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
  const planID = 'plan-20261119T001122Z-abcd';
  const saved = planBody(planID, null);
  const responses = ['wrong-signature', 'wrong-request', 'stale', 'refusal', 'good', 'good', 'list', 'after', 'get', 'tampered', 'wrong-id', 'oversize'];
  const errors = [];
  const server = createServer((s) => {
    let input = '';
    s.on('data', (chunk) => {
      input += chunk;
      if (!input.includes('\n')) return;
      try {
        const r = JSON.parse(input);
        const mode = responses.shift();
        const lookup = ['list', 'after', 'get', 'tampered', 'wrong-id', 'oversize'].includes(mode);
        const option = lookup ? (['list', 'after'].includes(mode) ? 'list' : 'get') : '';
        const expectedID = lookup && mode !== 'list' ? planID : '';
        assert.equal(r.verb, lookup ? 'members-plans' : 'status');
        assert.equal(r.option ?? '', option);
        assert.equal(r.plan_id ?? '', expectedID);
        assert.deepEqual(Object.keys(r).sort(), ['verb', 'timestamp', 'nonce', 'public_key', 'signature', ...(option ? ['option'] : []), ...(expectedID ? ['plan_id'] : [])].sort());
        assert.equal(r.public_key, Buffer.from(id.public_key, 'hex').toString('base64'));
        assert.equal(verify(null, Buffer.from([r.verb, '', option, '', expectedID, '', '', '', r.timestamp, r.nonce].join('\n')), pub, Buffer.from(r.signature, 'base64')), true);
        if (mode === 'oversize') { s.end('x'.repeat(65537) + '\n'); return; }
        const lookupBody = option === 'list' ? { plan_ids: mode === 'list' ? [planID] : [] } :
          { ...saved, ...(mode === 'wrong-id' && { plan_id: 'plan-20261119T001122Z-ffff' }) };
        const body = lookup ? JSON.stringify(lookupBody).replaceAll('<', '\\u003c') : '[{"text":"\\u003cready\\u003e","body":[1e2]}]';
        const reply = { ok: mode !== 'refusal', state: lookup ? (option === 'list' ? 'listed' : 'found') : 'reported', timestamp: r.timestamp - (mode === 'stale' ? 360 : 0), nonce: randomBytes(16).toString('base64url'), request_nonce: mode === 'wrong-request' ? 'other' : r.nonce };
        if (!reply.ok) reply.diagnostic = 'MM_DAEMON_UNKNOWN_KEY';
        const signed = [reply.ok, reply.diagnostic ?? '', '', reply.state, body, reply.timestamp, reply.nonce, reply.request_nonce].join('\n');
        reply.signature = sign(null, Buffer.from(mode === 'wrong-signature' ? '' : signed), privateKey).toString('base64');
        s.end(JSON.stringify(reply).slice(0, -1) + ',"body":' + (mode === 'tampered' ? body.replace('hello', 'changed') : body) + '}\n');
      } catch (e) { errors.push(e); s.destroy(); }
    });
  });
  await new Promise((resolve, reject) => server.once('error', reject).listen(socket, resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const listFlags = ['members-plans', 'list', '--socket', socket];
  const getFlags = ['members-plans', 'get', planID, '--socket', socket];
  await assert.rejects(run(...listFlags), /daemon pin saved by verified Machine status/);
  await assert.rejects(run(...getFlags, '--daemon-key', raw.toString('hex')), /usage/);
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
  const listed = await run(...listFlags);
  assert.deepEqual(listed, { ...first, state: 'listed', plan_ids: [planID] });
  assert.deepEqual(await run(...listFlags, '--after', planID), { ...first, state: 'listed', plan_ids: [] });
  assert.deepEqual(await run(...getFlags), { ...first, state: 'found', ...saved });
  await assert.rejects(run(...getFlags), /signature/);
  await assert.rejects(run(...getFlags), /requested ID/);
  await assert.rejects(run(...getFlags), /size limit/);
  assert.deepEqual(readFileSync(join(dir, 'daemon.pub')), raw);
  assert.deepEqual(errors, []);
  assert.deepEqual(responses, []);
});

function planBody(planID, members = []) {
  const plan = {version:3,hq_account:'_agent-bot-hq',dir:'none',members,steps:[
    {kind:'hq-account',target:'_agent-bot-hq',action:'create',group:'_agent-bot-hq',mode:'0700',detail:'hello <role>'},
  ]};
  const canonical = JSON.stringify(plan) + '\n';
  return {plan_id:planID,plan_digest:createHash('sha256').update(canonical).digest('hex'),plan_canonical:canonical};
}

test('members-plan pages are bounded, ordered and cursor-exclusive', () => {
  const ids = Array.from({length:65}, (_, i) => 'plan-20261119T000000Z-' + i.toString(16).padStart(4,'0'));
  const page = (body, cursor = '') => membersPlanResult('list',cursor,{state:'listed',body});
  const good = {plan_ids:ids.slice(0,64),next_after:ids[63]};
  assert.deepEqual(page(good),good);
  for (const bad of [{plan_ids:ids}, {plan_ids:[ids[1],ids[0]]}, {plan_ids:[ids[1],ids[1]]}, {plan_ids:['../other']},
    {plan_ids:[],next_after:''},{...good,next_after:ids[62]}, {plan_ids:[],extra:true}]) assert.throws(() => page(bad),/invalid/);
  assert.throws(() => page({plan_ids:[ids[1]]},ids[1]),/invalid/);
});

test('members-plan lookup preserves and verifies complete canonical bytes', () => {
  const id='plan-20261119T000000Z-abcd';
  const good=planBody(id);
  const check=(body) => membersPlanResult('get',id,{state:'found',body});
  const withCanonical=(str) => ({...good,plan_canonical:str,plan_digest:createHash('sha256').update(str).digest('hex')});
  assert.deepEqual(check(good),good);
  assert.throws(() => check({...good,plan_digest:'0'.repeat(64)}),/digest/);
  for (const str of [good.plan_canonical.trimEnd(), ' ' + good.plan_canonical,
    good.plan_canonical.replace('"version":3','"version":3,"version":3'),
    good.plan_canonical.replace('"version":3','"version":4'),
    good.plan_canonical.replace('"kind":"hq-account"','"kind":"future"'),
    good.plan_canonical.replace('"action":"create"','"action":"create","unknown":"field"')]) {
    assert.throws(() => check(withCanonical(str)));
  }
  const escaped=good.plan_canonical.replace('hello <role>','hello \\u2028<role>');
  assert.deepEqual(check(withCanonical(escaped)),withCanonical(escaped));
});

test('legacy Darwin HQ-only null member bytes preserve their original digest', () => {
  const id = 'plan-20261119T000000Z-abcd';
  const saved = planBody(id, null);
  const check = (body) => membersPlanResult('get', id, {state: 'found', body});
  assert.deepEqual(check(saved), saved);
  assert.notEqual(saved.plan_digest, planBody(id).plan_digest);

  const service = {kind: 'service', target: 'ai.true-line.agent-bot-hq', action: 'create'};
  const plan = JSON.parse(saved.plan_canonical);
  const withPlan = (p) => {
    const raw = JSON.stringify(p) + '\n';
    return {plan_id: id, plan_digest: createHash('sha256').update(raw).digest('hex'), plan_canonical: raw};
  };
  const remaining = withPlan({...plan, steps: [{...plan.steps[0], action: 'none'}, service]});
  assert.deepEqual(check(remaining), remaining);
  for (const p of [{...plan, hq_account: 'other'}, {...plan, dir: '/run'},
    {...plan, steps: [service]}, {...plan, steps: [plan.steps[0], {...service, target: 'other'}]},
    {...plan, steps: [plan.steps[0], service, service]}]) {
    assert.throws(() => check(withPlan(p)), /unsupported structure/);
  }
});
