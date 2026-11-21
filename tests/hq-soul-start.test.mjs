import { test } from 'node:test';
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { writeFileSync } from 'node:fs';
import { connect, createServer } from 'node:net';
import { join } from 'node:path';
import { startHQ, tempHome } from './hq-harness.mjs';
import { validateConfig } from '../hq/hq.mjs';

const waitFor = async (check) => {
  for (let i = 0; i < 100; i++) {
    if (check()) return;
    await new Promise((resolve) => setTimeout(resolve, 10));
  }
  assert.fail('timed out waiting for Soul runner to stop');
};

test('the owner cannot configure arbitrary code to run in HQ account', () => {
  assert.throws(() => validateConfig({ soulRunner: { command: ['/bin/sh'] } }), /unknown key soulRunner/);
});

test('only the owner can make HQ start and own a Soul runner; the ACP stream stops with its owner connection', { timeout: 10000 }, async () => {
  const home = tempHome();
  const runner = join(home, 'fake-runner.mjs');
  writeFileSync(runner, `process.stdin.on('data', chunk => process.stdout.write('ACP:' + chunk.toString()));\nprocess.stdin.on('end', () => process.exit(0));\nprocess.on('SIGTERM', () => process.exit(0));\n`);
  const t = await startHQ({ home, config: { acceptedDefinitions: {} }, soulRunner: { command: [process.execPath, runner] } });
  let stream;
  try {
    const entry = await t.entry();
    const denied = await entry.request('soul.start', { package_path: home });
    assert.equal(denied.host_refusal.code, 'host.auth_mismatch');
    const owner = await t.owner();
    assert.deepEqual((await owner.request('soul.starts')).result, { starts: [] });
    assert.equal((await owner.request('soul.start', { package_path: home })).host_refusal.code, 'host.invalid_request');

    stream = connect(t.hq.paths.control);
    await new Promise((resolve, reject) => { stream.once('connect', resolve); stream.once('error', reject); });
    let text = '';
    stream.setEncoding('utf8');
    stream.on('data', (chunk) => { text += chunk; });
    stream.write(`${JSON.stringify({ id: 1, op: 'soul.start', payload: { package_path: home } })}\n`);
    await waitFor(() => text.includes('\n'));
    const first = JSON.parse(text.slice(0, text.indexOf('\n')));
    assert.equal(first.ok, true);
    assert.match(first.result.start_id, /^st_[0-9a-f]{24}$/);
    assert.equal(first.result.protected, false);
    assert.equal(first.result.profile, 'managed-cooperative');
    assert.equal((await owner.request('soul.starts')).result.starts.length, 1);
    assert.equal((await owner.request('status')).result.hq.soulStarts.length, 1);
    const duplicate = await (await t.owner()).request('soul.start', { package_path: home });
    assert.equal(duplicate.host_refusal.code, 'host.launch_busy');

    stream.write('ping\n');
    await waitFor(() => text.includes('ACP:ping\n'));
    stream.destroy();
    await waitFor(() => t.hq.status().hq.soulStarts.length === 0);
    assert.ok(t.hq.core.receipts.some((r) => r.kind === 'hq.soul.started' && r.start_id === first.result.start_id));
    assert.ok(t.hq.core.receipts.some((r) => r.kind === 'hq.soul.exited' && r.start_id === first.result.start_id));
  } finally { stream?.destroy(); await t.done(); }
});

test('an unconfigured HQ refuses Soul start and never reports a live start', async () => {
  const t = await startHQ();
  try {
    const owner = await t.owner();
    const refused = await owner.request('soul.start', { package_path: t.home });
    assert.equal(refused.host_refusal.code, 'host.launch_unavailable');
    assert.deepEqual(t.hq.status().hq.soulStarts, []);
  } finally { await t.done(); }
});

test('the owner CLI speaks the start handshake and relays ACP', { timeout: 10000 }, async () => {
  const home = tempHome();
  const server = createServer((socket) => {
    socket.once('data', () => {
      socket.write(`${JSON.stringify({ id: 1, ok: true, result: { start_id: 'st_test', pid: 42 } })}\n`);
      socket.on('data', (chunk) => socket.write(`ACP:${chunk}`));
    });
  });
  await new Promise((resolve) => server.listen(join(home, 'control.sock'), resolve));
  let cli;
  try {
    cli = spawn(process.execPath, [new URL('../hq/main.mjs', import.meta.url).pathname, 'soul', 'start', '--home', home, '--soul', home], { stdio: ['pipe', 'pipe', 'pipe'] });
    let stdout = '';
    let stderr = '';
    cli.stdout.on('data', (chunk) => { stdout += chunk; });
    cli.stderr.on('data', (chunk) => { stderr += chunk; });
    await waitFor(() => stderr.includes('HQ started Soul runner'));
    cli.stdin.write('ping\n');
    await waitFor(() => stdout.includes('ACP:ping\n'));
    cli.stdin.end();
    cli.kill('SIGTERM');
  } finally {
    cli?.kill('SIGKILL');
    await new Promise((resolve) => server.close(resolve));
  }
});
