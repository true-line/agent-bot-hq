import test from 'node:test';
import assert from 'node:assert/strict';
import { startHQ } from './hq-harness.mjs';
import { definePlugin } from '../sdk/plugin.mjs';

const selectors = { installation_id: 'inst_1', start_id: `st_${'a'.repeat(24)}`,
  launch_id: `ln_${'b'.repeat(24)}`, runtime_id: 'rt_1', plan_id: 'plan_1',
  plan_digest: 'c'.repeat(64) };
const context = { ...selectors, hq_epoch: 'd'.repeat(64), bridge_uid: 302,
  broker_socket: '/private/var/run/agent-bot/bridge/broker.sock', proof_key: Buffer.alloc(32, 0x41) };

test('HQ shutdown fences B bind before awaiting Machine containment', async () => {
  let release;
  let stopRequested = false;
  const t = await startHQ({ bridgeAuthority: {
    verifyLiveStart: async () => context,
    onDisconnect: () => { stopRequested = true; return new Promise((resolve) => { release = resolve; }); },
  } });
  try {
    const bridge = t.hq.host.provided('hq-admission');
    await bridge.bridgeBindChallenge(selectors, { connection: 'bc_test' });
    const stopping = t.hq.stop();
    assert.equal(stopRequested, true, 'the B stop starts synchronously at HQ shutdown');
    assert.equal(t.hq.status().hq.bridgeBinding.state, 'stopping');
    await assert.rejects(bridge.bridgeBindChallenge({ ...selectors,
      start_id: `st_${'f'.repeat(24)}` }, { connection: 'bc_new' }), { code: 'host.launch_unavailable' });
    release();
    await stopping;
  } finally { if (release) release(); await t.done(); }
});

test('a swallowed broker-close error still degrades live HQ status and records an alert', async () => {
  const broker = definePlugin({ name: 'test-bridge-broker', version: '0.1.0', hostApi: 1,
    requires: { 'hq-admission': '^0.1.0' },
    async init(ctx) {
      const admission = ctx.deps['hq-admission'];
      ctx.broker.serve({ accept: async () => null,
        closed: (connection) => admission.forgetBridgeConnection(connection) });
    } });
  const t = await startHQ({ plugins: [broker], bridgeAuthority: {
    verifyLiveStart: async () => context,
    onDisconnect: async () => { throw new Error('Machine stop unconfirmed'); },
  } });
  try {
    const bridge = t.hq.host.provided('hq-admission');
    await bridge.bridgeBindChallenge(selectors, { connection: 'bc_test' });
    await t.hq.host.brokerClosed('bc_test'); // SDK swallows plugin close errors
    assert.equal(t.hq.status().hq.bridgeBinding.state, 'containment_unconfirmed');
    assert.ok(t.hq.core.receipts.some((receipt) => receipt.kind === 'hq.bridge.containment_unconfirmed'
      && receipt.start_id === selectors.start_id), 'HQ persisted a start-specific failure alert');
    await assert.rejects(bridge.bridgeBindChallenge(selectors, { connection: 'bc_new' }),
      { code: 'host.launch_unavailable' });
    await assert.rejects(t.hq.stop(), /Machine stop unconfirmed/);
  } finally { await t.done(); }
});

test('the shared HQ broker cannot submit protected v2 bridge bind frames to Comms', async () => {
  const accepted = [];
  const broker = definePlugin({ name: 'test-member-broker', version: '0.1.0', hostApi: 1,
    async init(ctx) {
      ctx.broker.serve({ accept: async (kind) => { accepted.push(kind); return null; } });
    } });
  const t = await startHQ({ plugins: [broker] });
  try {
    const socket = await t.member();
    for (const kind of ['bridge.bind.v2.challenge', 'bridge.bind.v2']) {
      const reply = await socket.request(kind, selectors);
      assert.equal(reply.host_refusal.code, 'host.launch_unavailable');
    }
    assert.equal((await socket.request('bind', {})).ok, true);
    assert.deepEqual(accepted, ['bind']);
  } finally { await t.done(); }
});
