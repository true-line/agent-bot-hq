import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { startStage2aRole } from '../hq/stage2a-role-launch.mjs';

const RESERVATION = 'sha256:' + 'a'.repeat(64);
const GRANT = 'sha256:' + 'b'.repeat(64);
const RECEIPT = 'sha256:' + 'c'.repeat(64);
const NONCE = Buffer.alloc(32, 7).toString('base64url');

test('stock child ACP stays behind the signed Machine receipt and lifecycle', async () => {
  let child;
  let input = '';
  let controlLines = 0;
  const spawnProcess = () => {
    child = new EventEmitter();
    child.exitCode = null;
    child.signalCode = null;
    child.stdin = new PassThrough();
    child.stdout = new PassThrough();
    child.stderr = new PassThrough();
    child.kill = () => {};
    child.stdin.on('data', (chunk) => {
      input += chunk.toString('utf8');
      for (;;) {
        const end = input.indexOf('\n');
        if (end < 0) break;
        const line = JSON.parse(input.slice(0, end));
        input = input.slice(end + 1);
        controlLines += 1;
        if (controlLines === 1) {
          assert.equal(line.sha256, GRANT);
          child.stderr.write(JSON.stringify({ kind: 'child-started', child_pid: 404,
            child_launcher_pid: 403, grant_sha256: GRANT }) + '\n');
        } else {
          assert.equal(line.sha256, RECEIPT);
          child.stderr.write(JSON.stringify({ kind: 'child-accepted',
            receipt_sha256: RECEIPT, lease_sequence: 1 }) + '\n');
          child.stderr.write('{"kind":"started"}\n');
        }
      }
    });
    queueMicrotask(() => child.stdout.write(JSON.stringify({
      role: 'child', nonce: NONCE, pid: 403,
    }) + '\n'));
    return child;
  };
  const role = await startStage2aRole({ account: '_abm-sr-' + 'a'.repeat(20),
    role: 'child', reservationSHA256: RESERVATION, spawnProcess,
    machineExec: async (request) => {
      assert.deepEqual(request, { reservation_sha256: RESERVATION,
        role: 'child', nonce: NONCE, pid: 403 });
      return { sha256: GRANT, grantLine: Buffer.from(JSON.stringify({ sha256: GRANT }) + '\n') };
    } });
  assert.deepEqual(await role.waitChildStarted(), { kind: 'child-started',
    child_pid: 404, child_launcher_pid: 403, grant_sha256: GRANT });
  assert.equal(controlLines, 1, 'the child waits for A before exposing ACP');
  await role.sendChildReceipt({ envelope: Buffer.from('signed receipt'),
    sha256: RECEIPT, expires_at_ms: Date.now() + 4500 });
  assert.equal((await role.waitChildAccepted(RECEIPT)).lease_sequence, 1);
  assert.equal(controlLines, 2);
});

test('cooperative child accepts only its own status framing and a single grant on ACP stdin', async () => {
  let proc, grantLines = 0;
  const role = await startStage2aRole({ account: '_abm-sr-' + 'a'.repeat(20),
    role: 'child', cooperativeChild: true, reservationSHA256: RESERVATION,
    spawnProcess(command, args) {
      assert.equal(command, '/usr/bin/sudo');
      assert.equal(args.at(-1), 'cooperative-soul-child');
      proc = Object.assign(new EventEmitter(), { exitCode: null, signalCode: null,
        stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(), kill() {} });
      proc.stdin.on('data', () => {
        grantLines++;
        proc.stderr.write(JSON.stringify({ kind: 'child-started', child_pid: 404, child_launcher_pid: 403,
          grant_sha256: GRANT, child_process: { pid: 404 }, launcher_process: { pid: 403 } }) + '\n');
      });
      queueMicrotask(() => proc.stdout.write(JSON.stringify({ role: 'child', nonce: NONCE, pid: 403 }) + '\n'));
      return proc;
    },
    machineExec: async () => ({ sha256: GRANT, grantLine: Buffer.from('{}\n') }) });
  assert.equal((await role.waitChildStarted()).child_process.pid, 404);
  await assert.rejects(role.sendChildReceipt({ envelope: Buffer.from('legacy'),
    sha256: RECEIPT, expires_at_ms: Date.now() + 4500 }), /invalid protected child receipt/);
  proc.stderr.write(JSON.stringify({ kind: 'child-accepted', ready_sha256: RECEIPT, lease_sequence: 1 }) + '\n');
  proc.stderr.write('{"kind":"started"}\n');
  assert.equal((await role.waitChildAccepted(RECEIPT)).lease_sequence, 1);
  assert.equal(grantLines, 1);
});
