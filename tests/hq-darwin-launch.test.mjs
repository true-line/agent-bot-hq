import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter, once } from 'node:events';
import { readFileSync, mkdtempSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';
import { PassThrough } from 'node:stream';
import { isDeepStrictEqual } from 'node:util';
import { createCore } from '../sdk/services.mjs';
import { approvedDarwinAdapter, DARWIN_LAUNCHER, decodeDarwinGrant } from '../hq/darwin-launch-grant.mjs';
import { supervisorReceipts } from '../hq/darwin-launch-receipts.mjs';
import { createLauncher } from '../hq/launch.mjs';
import { connectSocket, listenSocket } from '../hq/socket.mjs';
import { attachTo, SOUL } from './hq-harness.mjs';

const raw = readFileSync(new URL('./fixtures/darwin-harness-install.json', import.meta.url), 'utf8');
const grant = decodeDarwinGrant(raw, 311);
const a = grant.policy.adapters[0];
const command = [a.executable, ...a.args];
const endpoint = { account: a.account, uid: a.uid, gid: a.uid,
  home: '/var/agent-bot-harness-' + a.account, adapters: [a.adapter_id],
  path: '/Library/Application Support/ai.true-line.agent-bot-hq/ipc/' + a.account + '/broker.sock' };
const token = 'cd'.repeat(24);
const meta = { auth: 'entry-point', session: 'entry' };
const payload = { runtime_id: 'runtime', command, env: { AGENT_BOT_SOULS_MEMBER_TOKEN: token } };

test('the installed Machine plan digest covers the complete fixed command and policy', () => {
  assert.equal(approvedDarwinAdapter(grant, endpoint, a.adapter_id, command), a);
  assert.throws(() => approvedDarwinAdapter(grant, { ...endpoint, uid: a.uid + 1 }, a.adapter_id, command));
  assert.throws(() => approvedDarwinAdapter(grant, { ...endpoint, path: '/other' }, a.adapter_id, command));
  assert.throws(() => approvedDarwinAdapter(grant, endpoint, a.adapter_id, [...command, 'extra']));
  assert.throws(() => decodeDarwinGrant(raw.replace('--stdio', '--other'), 311));
  assert.throws(() => decodeDarwinGrant(raw, 312));
});

test('the supervisor must confirm its own group closed with an ordered final record and clean exit', () => {
  const start = '{"kind":"started"}\n';
  const closed = '{"kind":"closed","exit_code":7}\n';
  const wrapped = JSON.stringify({ kind:'stderr', text: closed }) + '\n';
  for (const [frames, status, signal, contained, refused] of [
    [start + wrapped + closed, 0, null, true, false], ['', 78, null, true, true],
    [start + wrapped, 0, null, false], [closed, 0, null, false], [start, 78, null, false],
    [start + closed, 70, null, false], [start + closed, null, 'SIGTERM', false],
    [start + closed + wrapped, 0, null, false], [start + closed.slice(0, -1), 0, null, false],
    [start + '{"kind":"closed","exit_code":3,"exit_code":4}\n', 0, null, false],
  ]) {
    const receipts = supervisorReceipts(() => {}, () => {});
    for (const ch of frames) receipts.push(ch);
    const result = receipts.finish({ code: status, signal }, true);
    assert.equal(result.contained, contained);
    if (contained) assert.equal(Boolean(result.refused), refused);
  }
});

const matchesReviewedAdapter = candidate => isDeepStrictEqual(candidate, a);

function setup({ qualification, permission = true, finish = 0 } = {}) {
  const core = createCore();
  const calls = [];
  const state = { grant };
  let child;
  function spawn(file, args, opts) {
    calls.push({ file, args, opts });
    const p = new EventEmitter();
    p.pid = 12345;
    p.stderr = new PassThrough();
    if (args.includes('-l')) {
      queueMicrotask(() => p.emit('close', permission ? 0 : 1, null));
    } else {
      child = p;
      p.stdin = new PassThrough(); p.stdout = new PassThrough();
      p.kill = () => assert.fail('HQ must only end supervisor input');
      p.stdin.on('finish', () => {
        if (finish === 0) p.stderr.write('{"kind":"closed","exit_code":7}\n');
        p.emit('exit', finish, null); p.stderr.end(); p.stdout.end(); p.emit('close', finish, null);
      });
    }
    return p;
  }
  const launcher = createLauncher({ core, platform: 'darwin', configured: true, spawn,
    installedDarwinGrant: () => state.grant,
    ...(qualification ? { qualifiedDarwinAdapter: qualification } : {}),
    harnesses: { endpoints:[endpoint], accountOf: () => endpoint },
    withLiveRuntime: (_, __, fn) => fn({ soul_id:SOUL, member_id:'member', role:'lead', adapter_id:a.adapter_id, harness_uid:a.uid }),
  });
  return { core, calls, state, launcher, get child() { return child; } };
}

test('production qualification stays unavailable even when the specific installed sudo command is permitted', async () => {
  for (const options of [{}, { qualification:matchesReviewedAdapter, permission:false }]) {
    const f = setup(options); await f.launcher.probe();
    assert.deepEqual(f.calls[0].args, ['-n','-l','-u',a.account,'--',DARWIN_LAUNCHER,'harness-run']);
    assert.equal(f.launcher.accounts()[0].available, false);
    await assert.rejects(f.launcher.dispatch('launch', { ...meta, payload }), { code: 'host.launch_unavailable' });
    assert.equal(f.calls.length, 1);
  }
});

for (const status of [0, 70]) test(`attached Darwin launch uses a private header then ACP, stops by EOF, supervisor exit ${status}`, async t => {
  const f = setup({ qualification:matchesReviewedAdapter, finish:status }); await f.launcher.probe();
  const dir = mkdtempSync(join(tmpdir(),'hqr-')); const path = join(dir,'admission.sock');
  const srv = await listenSocket({ path, core:f.core, auth:'entry-point', takeover:true, newSession:() => 'entry', dispatch:f.launcher.dispatch });
  const entry = await connectSocket(path);
  t.after(async () => { await entry.close(); await f.launcher.stopAll(); await srv.close(); rmSync(dir,{recursive:true,force:true}); });
  assert.equal((await entry.request('launch', { ...payload, command:[...command,'extra'] })).ok,false);
  const req = (await entry.request('launch', payload)).result;
  const attach = await attachTo(path, { launch_id:req.launch_id, attach:req.attach });
  assert.equal(attach.answer.ok,true);
  const call = f.calls[1];
  assert.deepEqual(call.args, ['-n','-H','-u',a.account,'--',DARWIN_LAUNCHER,'harness-run']);
  assert.equal(call.file, '/usr/bin/sudo'); assert.deepEqual(call.opts.env,{});
  const header = JSON.parse(f.child.stdin.read().toString());
  assert.deepEqual(header, { plan_digest:grant.plan_digest,adapter_id:a.adapter_id,launch_id:req.launch_id,
    soul_id:SOUL,member_id:'member',role:'lead',member_token:token });
  f.child.stderr.write('{"kind":"started"}\n');
  for (const part of [token.slice(0,10),token.slice(10)+'\n']) f.child.stderr.write(JSON.stringify({kind:'stderr',text:part})+'\n');
  const input = once(f.child.stdin,'data'); attach.write('ACP request\n');
  assert.equal((await input)[0].toString(),'ACP request\n');
  f.child.stdout.write('ACP reply\n'); assert.equal(await attach.line(),'ACP reply');
  const stop = await entry.request('launch.stop', { launch_id:req.launch_id });
  assert.equal(stop.result.state, status === 0 ? 'exited' : 'uncontained');
  await attach.closed;
  const ended = f.core.receipts.find(r => r.kind === 'hq.launch.exited');
  assert.equal(ended.contained,status === 0); assert.equal(ended.exit_code,status === 0 ? 7 : null);
  assert.equal(f.calls.length,2);
  assert.ok(!JSON.stringify([f.core.logs,f.core.receipts]).includes(token));
  if (status !== 0) assert.equal((await entry.request('launch',payload)).host_refusal.code,'host.launch_busy');
});

test('a pre-spawn supervisor refusal records no adapter start and releases the member slot', async t => {
  const f = setup({ qualification:matchesReviewedAdapter, finish:78 }); await f.launcher.probe();
  const dir = mkdtempSync(join(tmpdir(),'hqr-')); const path = join(dir,'admission.sock');
  const srv = await listenSocket({ path, core:f.core, auth:'entry-point', takeover:true, newSession:() => 'entry', dispatch:f.launcher.dispatch });
  const entry = await connectSocket(path);
  t.after(async () => { await entry.close(); await f.launcher.stopAll(); await srv.close(); rmSync(dir,{recursive:true,force:true}); });
  const req = (await entry.request('launch',payload)).result;
  const conn = await attachTo(path, {launch_id:req.launch_id, attach:req.attach});
  assert.equal(conn.answer.ok,true);
  const [pending] = f.launcher.report().launches;
  assert.equal(pending.state,'starting');
  assert.equal(pending.started_at,undefined);
  f.child.stdin.end();
  await conn.closed;
  assert.ok(!f.core.receipts.some(r => r.kind === 'hq.launch'));
  const ended = f.core.receipts.find(r => r.kind === 'hq.launch.exited');
  assert.equal(ended.reason,'spawn-failed');
  assert.equal(ended.contained,true);
  assert.equal((await entry.request('launch',payload)).ok,true);
});

test('retirement or replacement after reservation refuses attach before any process is started', async t => {
  const f = setup({ qualification:matchesReviewedAdapter }); await f.launcher.probe();
  const dir = mkdtempSync(join(tmpdir(),'hqr-')); const path = join(dir,'admission.sock');
  const server = await listenSocket({ path, core:f.core, auth:'entry-point', takeover:true, newSession:() => 'entry', dispatch:f.launcher.dispatch });
  const entry = await connectSocket(path);
  t.after(async () => { await entry.close(); await f.launcher.stopAll(); await server.close(); rmSync(dir,{recursive:true,force:true}); });
  for (const replacement of [null, { ...grant, plan_digest:'f'.repeat(64) }]) {
    f.state.grant = grant;
    const reserved = (await entry.request('launch',payload)).result;
    f.state.grant = replacement;
    const conn = await attachTo(path, { launch_id:reserved.launch_id, attach:reserved.attach });
    assert.equal(conn.answer.ok,false);
    assert.equal(conn.answer.host_refusal.code,'host.launch_unavailable');
    await conn.closed;
    assert.equal(f.calls.length,1);
    assert.equal(f.launcher.report().launches.length,0);
  }
});

test('Darwin rechecks qualification of the exact reviewed command at reservation and attach', async t => {
  // Both rows of the Machine fixture refer to the same executable bytes. Its
  // second adapter has another ID, target account and argument list.
  const sibling = grant.policy.adapters[1];
  assert.equal(sibling.executable, a.executable);
  assert.equal(sibling.sha256, a.sha256);
  assert.notDeepEqual(sibling.args, a.args);
  let current = a;
  const f = setup({ qualification: candidate => isDeepStrictEqual(candidate, current) });
  await f.launcher.probe();
  assert.equal(f.launcher.accounts()[0].available, true);
  const dir = mkdtempSync(join(tmpdir(), 'hqr-'));
  const path = join(dir, 'admission.sock');
  const server = await listenSocket({ path, core:f.core, auth:'entry-point', takeover:true, newSession:() => 'entry', dispatch:f.launcher.dispatch });
  const entry = await connectSocket(path);
  t.after(async () => { await entry.close(); await f.launcher.stopAll(); await server.close(); rmSync(dir,{recursive:true,force:true}); });

  current = sibling;
  assert.equal((await entry.request('launch', payload)).host_refusal.code, 'host.launch_unavailable');
  current = a;
  const reserved = (await entry.request('launch', payload)).result;
  current = sibling;
  const conn = await attachTo(path, { launch_id:reserved.launch_id, attach:reserved.attach });
  assert.equal(conn.answer.host_refusal.code, 'host.launch_unavailable');
  await conn.closed;
  assert.equal(f.calls.length, 1); // Only the startup sudo permission check.
  assert.equal(f.launcher.report().launches.length, 0);
  assert.ok(!f.core.receipts.some(r => r.kind === 'hq.launch'));
  current = a;
  assert.equal((await entry.request('launch', payload)).ok, true);
});
