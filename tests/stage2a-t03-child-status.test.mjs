import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { startStage2aRole } from '../hq/stage2a-role-launch.mjs';

const digest = `sha256:${'a'.repeat(64)}`;

test('protected child status keeps T03 event kind separate from probe kind', async () => {
  const child = Object.assign(new EventEmitter(), {
    stdin: new PassThrough(), stdout: new PassThrough(), stderr: new PassThrough(),
    exitCode: null, signalCode: null, kill() { this.signalCode = 'SIGTERM'; },
  });
  const received = [];
  const pending = startStage2aRole({ account: `_abm-sr-${'b'.repeat(20)}`, role: 'child',
    reservationSHA256: digest, spawnProcess: () => child,
    machineExec: async () => ({ grantLine: Buffer.from('{}\n'), sha256: digest }),
    onT03Event: async (event) => { received.push(event); } });
  child.stdout.write(JSON.stringify({ role: 'child',
    nonce: Buffer.alloc(32, 4).toString('base64url'), pid: 702 }) + '\n');
  const role = await pending;
  child.stderr.write([
    { kind: 'child-started', child_pid: 703, child_launcher_pid: 702, grant_sha256: digest },
    { kind: 'child-accepted', receipt_sha256: digest, lease_sequence: 1 },
    { kind: 'started' },
    { kind: 't03-sibling-credential-witness', witness: {
      schema: 'agent-bot-machine/stage2a-t03-sibling-credential-witness/v1' } },
    { kind: 't03-probe-ready', ready: { schema: 'agent-bot-machine/stage2a-t03-probe-ready/v1', kind: 'ipv4' } },
    { kind: 't03-probe-result', result: { schema: 'agent-bot-machine/stage2a-t03-probe-result/v1' } },
  ].map((event) => JSON.stringify(event)).join('\n') + '\n');
  assert.equal((await role.waitChildStarted()).child_pid, 703);
  await role.waitChildAccepted(digest);
  await new Promise((resolve) => setImmediate(resolve));
  assert.deepEqual(received.map((event) => event.kind), [
    't03-sibling-credential-witness', 't03-probe-ready', 't03-probe-result']);
  assert.equal(received[1].ready.kind, 'ipv4');
  assert.equal(child.signalCode, null);
  child.stdin.destroy();
  child.stdout.destroy();
  child.stderr.destroy();
  child.emit('close', 0, null);
});
