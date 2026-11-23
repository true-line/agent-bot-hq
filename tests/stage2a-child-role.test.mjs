import test from 'node:test';
import assert from 'node:assert/strict';
import { EventEmitter } from 'node:events';
import { PassThrough } from 'node:stream';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { startStage2aRole } from '../hq/stage2a-role-launch.mjs';
import { canonicalBytes } from '../sdk/wire/canonical-json.mjs';

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

test('member child grant exposes only the identical A-signed B authority for two-member prestart', async () => {
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const machinePublicKey = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
  const sha = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;
  const assignment = Buffer.from('signed assignment fixture');
  const authority = Buffer.from('signed B authority fixture');
  const member = { member_id: 'm_lead', member_selector: `mb_${'1'.repeat(64)}`,
    launch_id: `ln_${'2'.repeat(24)}` };
  const selectors = { reservation_sha256: RESERVATION, installation_id: 'inst_test',
    start_id: `st_${'3'.repeat(24)}`, launch_id: `ln_${'4'.repeat(24)}`,
    plan_id: 'plan-test', plan_digest: '5'.repeat(64), hq_epoch: '6'.repeat(64) };
  const invocation = canonicalBytes({ child_exec: { member_id: member.member_id,
    member_selector: member.member_selector, member_launch_id: member.launch_id,
    reservation_sha256: RESERVATION,
    member_set_assignment_envelope_base64url: assignment.toString('base64url'),
    member_b_authority_envelope_base64url: authority.toString('base64url') } });
  const payload = canonicalBytes({ role: 'child', reservation_sha256: RESERVATION,
    pid: 403, nonce: NONCE, member_id: member.member_id,
    member_selector: member.member_selector, member_launch_id: member.launch_id,
    member_set_assignment_envelope_sha256: sha(assignment), invocation_sha256: sha(invocation) });
  const purpose = 'agent-bot/stage2a-exec/v1';
  const envelope = canonicalBytes({ schema_version: 1, purpose,
    issuer_public_key_base64url: machinePublicKey.toString('base64url'),
    payload_sha256: sha(payload), payload_base64url: payload.toString('base64url'),
    signature_base64url: sign(null, Buffer.concat([Buffer.from(`${purpose}\0`), payload]),
      privateKey).toString('base64url') });
  const spawnProcess = () => {
    const child = new EventEmitter();
    child.exitCode = null; child.signalCode = null;
    child.stdin = new PassThrough(); child.stdout = new PassThrough();
    child.stderr = new PassThrough(); child.kill = () => {};
    child.stdin.once('data', () => child.stderr.write(JSON.stringify({ kind: 'child-started',
      child_pid: 404, child_launcher_pid: 403, grant_sha256: sha(envelope) }) + '\n'));
    queueMicrotask(() => child.stdout.write(JSON.stringify({ role: 'child', nonce: NONCE, pid: 403 }) + '\n'));
    return child;
  };
  const role = await startStage2aRole({ account: '_abm-sr-' + 'a'.repeat(20), role: 'child',
    reservationSHA256: RESERVATION, memberGrant: { selectors, member,
      assignmentSHA256: sha(assignment), machinePublicKey }, spawnProcess,
    memberMachineExec: async (request) => {
      assert.deepEqual(request, { ...selectors, member_id: member.member_id,
        member_selector: member.member_selector, nonce: NONCE, pid: 403 });
      return { envelope, sha256: sha(envelope), invocation,
        grantLine: Buffer.from(JSON.stringify({ envelope_base64url: envelope.toString('base64url'),
          sha256: sha(envelope), invocation_base64url: invocation.toString('base64url') }) + '\n') };
    } });
  assert.deepEqual(role.memberAuthorityBytes, authority);
  assert.equal((await role.waitChildStarted()).grant_sha256, sha(envelope));
});
