import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { createStage2aProtectedStarter } from '../hq/stage2a-protected-start.mjs';

const RESERVATION = 'sha256:' + 'a'.repeat(64);
const BIND = 'sha256:' + 'b'.repeat(64);
const PLAN = 'c'.repeat(64);
const EPOCH = 'd'.repeat(64);

function fixture(packageRoot, { runnerFails = false } = {}) {
  const events = [];
  let providerAttempts = 0;
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
    currentLiveStart: async () => {
      assert.ok(events.includes('runner:402'), 'Machine live check follows the R launch');
      events.push('Machine-live');
      return { phase: 'finalized', runner_pid: 402, bridge_pid: 401,
        bind_receipt_sha256: BIND, finalized_live_expires_at: Date.now() + 60_000 };
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
    getBrokerIdentity: () => ({}),
    verifyBoundBridge: async () => ({ bind_receipt_sha256: BIND }),
    prepareBridge: async () => {},
    machineFinalize: async () => ({ envelope: 'signed-finalization',
      sha256: 'sha256:' + 'e'.repeat(64) }),
    startRole: async ({ role }) => {
      if (role === 'runner') {
        if (runnerFails) throw new Error('R failed before launch');
        events.push('runner-started');
        return { pid: 402, stop: async () => {} };
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
    },
    random: () => 'a'.repeat(24),
  });
  return { starter, events, get providerAttempts() { return providerAttempts; } };
}

test('B finalization cannot publish one-use qualification before live R', async () => {
  const dir = mkdtempSync(join(tmpdir(), 'stage2a-hq-start-'));
  try {
    const root = realpathSync(dir);
    const f = fixture(root);
    await f.starter.start({ package_path: root, requested_profile: 'managed-protected' });
    assert.equal(f.providerAttempts, 1);
    assert.deepEqual(f.events.slice(-4), ['B-finalized', 'runner-started',
      'runner:402', 'Machine-live']);
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
