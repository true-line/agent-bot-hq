import test from 'node:test';
import assert from 'node:assert/strict';
import { admissionPlugin, bindProof } from '../hq/admission.mjs';
import { cooperativeLivenessGuard } from '../hq/hq.mjs';
import { createTestHost } from '../sdk/test-host.mjs';
import { DIGEST, hello, schemas, SOUL } from './hq-harness.mjs';

const start = Object.freeze({
  reservation_sha256: 'sha256:' + 'c'.repeat(64),
  installation_id: 'inst_0001', soul_id: SOUL,
  start_id: 'st_' + 'a'.repeat(24), launch_id: 'ln_' + 'b'.repeat(24),
  hq_epoch: 'e'.repeat(64), peer_uid: 311, peer_pid: 402,
  runner_account: '_runner', process_start: '123456789',
  definition_digest: DIGEST,
  h_service_descriptor_digest: 'sha256:' + 'f'.repeat(64),
  profile_in_force: 'managed-cooperative',
});

test('verified cooperative Hello binds the R account and requires keyed proof on its broker endpoint', async () => {
  const callers = new Map();
  let healthy = true;
  let aborts = 0;
  const machine = { assertLive: async () => healthy, watchHealthy: () => healthy,
    abort: async () => { aborts++; } };
  const host = createTestHost({
    config: { 'hq-admission': { acceptedDefinitions: { [SOUL]: [DIGEST] } } },
    plugins: [admissionPlugin({ schemas, cooperativeAdmission: machine,
      callerOf: connection => callers.get(connection),
      harnessAccount: () => ({ account: '_wrong_harness', uid: 611 }) })],
  });
  try {
    await host.start();
    const request = hello({ installation_id: start.installation_id });
    const result = await host.dispatch('Hello', { auth: 'entry-point', session: 'ep_r',
      payload: request, cooperativeStart: start });
    assert.equal(result.profile, 'managed-cooperative');
    const rt = result.admitted_runtimes[0];
    const row = host.table('hq-admission', 'runtimes')[rt.runtime_id];
    assert.equal(row.cooperative_runner_uid, 311);
    assert.equal(row.cooperative_runner_account, '_runner');
    assert.equal(row.harness_uid, undefined);
    assert.equal(row.cooperative_reservation_sha256, start.reservation_sha256);
    assert.equal(JSON.stringify(host.receipts()).includes(rt.channel_binding), false);

    const admission = host.provided('hq-admission');
    callers.set('bc_r', { kind: 'cooperative', account: '_runner', uid: 311,
      start_id: start.start_id, reservation_sha256: start.reservation_sha256 });
    const challenge = await admission.bindChallenge({ runtime_id: rt.runtime_id }, { connection: 'bc_r' });
    const proof = bindProof(rt.channel_binding, challenge.nonce, rt.runtime_id);
    assert.equal((await admission.verifyBinding({ runtime_id: rt.runtime_id, proof },
      { connection: 'bc_r' })).runtime_id, rt.runtime_id);

    callers.set('bc_wrong', { kind: 'cooperative', account: '_runner', uid: 312,
      start_id: start.start_id, reservation_sha256: start.reservation_sha256 });
    const wrongChallenge = await admission.bindChallenge({ runtime_id: rt.runtime_id }, { connection: 'bc_wrong' });
    await assert.rejects(admission.verifyBinding({ runtime_id: rt.runtime_id,
      proof: bindProof(rt.channel_binding, wrongChallenge.nonce, rt.runtime_id) },
    { connection: 'bc_wrong' }), /caller does not match/);
    await assert.rejects(host.dispatch('Hello', { auth: 'entry-point', session: 'ep_r',
      payload: request, cooperativeStart: start }), /verified start cannot reuse/);
    await assert.rejects(host.dispatch('Hello', { auth: 'entry-point', session: 'ep_r2',
      payload: hello({ installation_id: start.installation_id, request_id: 'req_0002' }),
      cooperativeStart: start }), /cooperative reservation was spent/);

    healthy = false;
    await assert.rejects(admission.withBoundRuntime(rt.runtime_id, async () => true), /cooperative R disconnected/);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(aborts, 1);
  } finally { await host.stop(); }
});

test('unverified cooperative metadata cannot upgrade a generic Hello', async () => {
  const host = createTestHost({
    config: { 'hq-admission': { acceptedDefinitions: { [SOUL]: [DIGEST] } } },
    plugins: [admissionPlugin({ schemas })],
  });
  try {
    await host.start();
    await assert.rejects(host.dispatch('Hello', { auth: 'entry-point', session: 'ep_r',
      payload: hello({ installation_id: start.installation_id }), cooperativeStart: start }),
    /Machine did not authenticate the cooperative start/);
    assert.equal(Object.keys(host.table('hq-admission', 'runtimes')).length, 0);
  } finally { await host.stop(); }
});

test('local C/H loss revokes a live cooperative runtime even while Machine reports a healthy runner', async () => {
  let aborts = 0;
  const guard = cooperativeLivenessGuard({ assertLive: async () => true,
    watchHealthy: () => true, abort: async () => { aborts++; } });
  const host = createTestHost({
    config: { 'hq-admission': { acceptedDefinitions: { [SOUL]: [DIGEST] } } },
    plugins: [admissionPlugin({ schemas, cooperativeAdmission: guard.client })],
  });
  try {
    await host.start();
    const result = await host.dispatch('Hello', { auth: 'entry-point', session: 'ep_r',
      payload: hello({ installation_id: start.installation_id }), cooperativeStart: start });
    const runtimeId = result.admitted_runtimes[0].runtime_id;
    assert.equal(guard.client.watchHealthy(start), true);
    guard.revoke(start.reservation_sha256);
    assert.equal(guard.client.watchHealthy(start), false);
    assert.equal(await guard.client.assertLive(start), false);
    await assert.rejects(host.provided('hq-admission').withBoundRuntime(runtimeId, async () => true),
      /cooperative R disconnected/);
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(aborts, 1);
  } finally { await host.stop(); }
});
