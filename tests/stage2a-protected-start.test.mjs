import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createHash } from 'node:crypto';
import { createStage2aProtectedStarter } from '../hq/stage2a-protected-start.mjs';

const RESERVATION = 'sha256:' + 'a'.repeat(64);
const BIND = 'sha256:' + 'b'.repeat(64);
const PLAN = 'c'.repeat(64);
const EPOCH = 'd'.repeat(64);
const FINAL_BYTES = Buffer.from('signed-finalization');
const FINAL = 'sha256:' + createHash('sha256').update(FINAL_BYTES).digest('hex');
const CHALLENGE = Buffer.alloc(32, 7).toString('base64url');

function fixture(packageRoot, { runnerFails = false, ackFails = false,
  ackIsPreviousLease = false } = {}) {
  const events = [];
  let providerAttempts = 0;
  let activation;
  let leaseSequence = 0;
  const installed = {
    installation_id: 'install-1', package_root: packageRoot, plan_id: 'plan-1',
    plan_digest: PLAN, hq_epoch: EPOCH, soul_id: 'soul-1',
    runner_account: '_abm-sr-aaaaaaaaaaaaaaaaaaaa',
    bridge_account: '_abm-br-aaaaaaaaaaaaaaaaaaaa',
    runner_uid: 311, runner_gid: 312, bridge_uid: 310,
    relay: { directory: '/private/tmp/relay' },
  };
  let assignment;
  const authority = {
    register: async ({ sha256 }) => {
      assert.equal(sha256, RESERVATION);
      events.push('registered');
      return { reservation_sha256: RESERVATION, installation_id: installed.installation_id,
        start_id: assignment.start_id, launch_id: assignment.launch_id,
        plan_id: installed.plan_id, plan_digest: PLAN, hq_epoch: EPOCH };
    },
    setRolePid: (_, role, pid) => events.push(`${role}:${pid}`),
    markFinalized: () => events.push('B-finalized'),
    currentLiveStart: async (_reservationSHA256, challenge) => {
      assert.ok(events.includes('runner:402'), 'Machine live check follows the R launch');
      events.push('Machine-live');
      const lease = Buffer.from(JSON.stringify({ challenge: challenge ?? 'HQ', sequence: ++leaseSequence }));
      return { phase: 'finalized', runner_pid: 402, bridge_pid: 401,
        bind_receipt_sha256: BIND, finalization_sha256: FINAL,
        lease_envelope_base64url: lease.toString('base64url'),
        lease_sha256: 'sha256:' + createHash('sha256').update(lease).digest('hex'),
        lease_sequence: leaseSequence,
        finalized_live_expires_at: Date.now() + 4500 };
    },
    stopStart: async () => { events.push('Machine-stop'); },
  };
  const starter = createStage2aProtectedStarter({
    installations: [installed], authority,
    machineLookup: async () => installed,
    machineReserve: async ({ start_id, launch_id }) => {
      assignment = { start_id, launch_id };
      return { envelope: 'signed', sha256: RESERVATION };
    },
    verifyReservation: async () => ({ reservationSHA256: RESERVATION,
      payload: { assignment } }),
    openProtectedAdmission: async () => {
      events.push('R-admission-open');
      return { close: async () => { events.push('R-admission-closed'); } };
    },
    getBrokerIdentity: () => ({}),
    verifyBoundBridge: async () => ({ bind_receipt_sha256: BIND }),
    prepareBridge: async () => {},
    machineFinalize: async () => ({ envelope: FINAL_BYTES, sha256: FINAL }),
    startRole: async ({ role }) => {
      if (role === 'runner') {
        if (runnerFails) throw new Error('R failed before launch');
        events.push('runner-started');
        return { pid: 402, stop: async () => {},
          stdin: { destroyed: false, write: (line, done) => {
            activation = JSON.parse(line.toString('utf8'));
            events.push('R-activated');
            done();
          } },
          waitRunnerActivation: async ({ reservationSHA256, startId, launchId }) => {
            if (ackFails) throw new Error('R rejected activation');
            assert.equal(providerAttempts, 0,
              'one-use provider stays closed until R admission and live acknowledgment');
            assert.equal(reservationSHA256, RESERVATION);
            assert.equal(startId, assignment.start_id);
            assert.equal(launchId, assignment.launch_id);
            const live = await starter.renewLive({ installation_id: installed.installation_id,
              reservation_sha256: reservationSHA256, start_id: startId,
              launch_id: launchId, challenge: CHALLENGE });
            if (ackIsPreviousLease) await starter.renewLive({
              installation_id: installed.installation_id,
              reservation_sha256: reservationSHA256, start_id: startId,
              launch_id: launchId, challenge: CHALLENGE });
            events.push('R-live');
            events.push('R-ack');
            return { reservation_sha256: reservationSHA256,
              start_id: startId, launch_id: launchId,
              lease_sha256: live.lease_sha256,
              lease_sequence: live.lease_sequence };
          } };
      }
      return { pid: 401, stop: async () => {},
        waitBridgeReady: async (ready) => {
          await ready({ bind_receipt_sha256: BIND,
            relay_socket: { uid: 310, gid: 312, mode: 0o660, device: 1, inode: 2 } });
          assert.equal(providerAttempts, 0,
            'B cannot spend a provider after finalization but before R starts');
          return true;
        } };
    },
    onFinalized: async () => {
      assert.ok(events.includes('Machine-live'), 'provider needs Machine-confirmed live R');
      providerAttempts++;
      events.push('provider-registered');
    },
    random: () => 'a'.repeat(24),
  });
  return { starter, events, get providerAttempts() { return providerAttempts; },
    get activation() { return activation; } };
}

test('B finalization cannot publish one-use qualification before live R', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'stage2a-hq-start-'));
  try {
    const root = realpathSync(dir);
    const f = fixture(root);
    await f.starter.start({ package_path: root, requested_profile: 'managed-protected' });
    assert.equal(f.providerAttempts, 1);
    assert.deepEqual(f.events.slice(-9), ['B-finalized', 'runner-started',
      'runner:402', 'Machine-live', 'R-activated',
      'Machine-live', 'R-live', 'R-ack', 'provider-registered']);
    assert.deepEqual(Object.keys(f.activation).sort(), [
      'schema', 'reservation_sha256', 'start_id', 'launch_id',
      'runner_wrapper_pid',
      'finalization_sha256', 'finalization_envelope_base64url',
      'bind_receipt_sha256',
    ].sort());
    assert.equal(f.activation.schema, 'agent-bot-souls/protected-activation/v1');
    assert.equal(f.activation.reservation_sha256, RESERVATION);
    assert.equal(f.activation.runner_wrapper_pid, 402);
    assert.equal(Buffer.from(f.activation.finalization_envelope_base64url, 'base64url').toString(),
      FINAL_BYTES.toString());
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('R activation refusal stops both roles before owner ACP takeover', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'stage2a-hq-start-'));
  try {
    const root = realpathSync(dir);
    const f = fixture(root, { ackFails: true });
    await assert.rejects(f.starter.start({ package_path: root,
      requested_profile: 'managed-protected' }), /R rejected activation/);
    assert.equal(f.providerAttempts, 0);
    assert.ok(f.events.includes('Machine-stop'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a still-live R acknowledgment survives an overlapping renewal', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'stage2a-hq-start-'));
  try {
    const root = realpathSync(dir);
    const f = fixture(root, { ackIsPreviousLease: true });
    await f.starter.start({ package_path: root, requested_profile: 'managed-protected' });
    assert.equal(f.events.filter((event) => event === 'Machine-live').length, 3);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('paired Machine Live renews the exact occupied R start', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'stage2a-hq-start-'));
  try {
    const root = realpathSync(dir);
    const f = fixture(root);
    await f.starter.start({ package_path: root, requested_profile: 'managed-protected' });
    const reply = await f.starter.renewLive({ installation_id: 'install-1',
      reservation_sha256: f.activation.reservation_sha256,
      start_id: f.activation.start_id, launch_id: f.activation.launch_id,
      challenge: CHALLENGE });
    assert.equal(reply.schema, 'agent-bot-hq/protected-live/v1');
    assert.equal(reply.installation_id, 'install-1');
    assert.equal(reply.reservation_sha256, RESERVATION);
    assert.equal(reply.challenge, CHALLENGE);
    assert.equal(reply.lease_sequence, 3);
    assert.ok(reply.live_expires_at_ms > Date.now());
    assert.equal(f.events.filter((event) => event === 'Machine-live').length, 3);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('R launch failure leaves the Machine provider claim unspent', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'stage2a-hq-start-'));
  try {
    const root = realpathSync(dir);
    const f = fixture(root, { runnerFails: true });
    await assert.rejects(f.starter.start({ package_path: root,
      requested_profile: 'managed-protected' }), /R failed before launch/);
    assert.equal(f.providerAttempts, 0);
    assert.ok(f.events.includes('Machine-stop'));
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
