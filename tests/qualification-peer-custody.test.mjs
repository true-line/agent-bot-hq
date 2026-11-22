import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { request as httpRequest } from 'node:http';
import { chmodSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import childProcess from 'node:child_process';
import { syncBuiltinESMExports } from 'node:module';

test('HTTP refusal and sidecar close report unconfirmed peer helper custody', async (t) => {
  const originalSpawn = childProcess.spawn;
  let started;
  const helperStarted = new Promise((resolve) => { started = resolve; });
  childProcess.spawn = () => {
    const probe = new EventEmitter();
    probe.kill = () => false; // Simulates SIGKILL failure and no child close.
    started();
    return probe;
  };
  syncBuiltinESMExports();
  t.after(() => { childProcess.spawn = originalSpawn; syncBuiltinESMExports(); });
  const { startClaudeQualificationHttp } = await import('../hq/claude-qualification-http.mjs');
  const dir = mkdtempSync(join(tmpdir(), 'hq-peer-custody-'));
  chmodSync(dir, 0o700);
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  let captures = 0;
  const bridge = await startClaudeQualificationHttp({
    socketPath: join(dir, 'broker.sock'), peerUid: process.getuid(),
    memberSession: { async capture() { captures++; throw new Error('must not capture'); } },
    plan: { model: 'fixture-model', prompt: 'fixture-prompt' },
  });
  const response = new Promise((resolve, reject) => {
    const req = httpRequest({ socketPath: bridge.socketPath, path: '/v1/messages', method: 'POST',
      headers: { 'content-length': 0 } }, (res) => {
      res.resume();
      res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', reject);
    req.end();
  });
  await helperStarted;
  const closing = bridge.close();
  assert.equal(await response, 503);
  await assert.rejects(closing, /custody unconfirmed/);
  assert.equal(captures, 0);
});
