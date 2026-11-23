import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs, { readFileSync, writeFileSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';
import { PROTECTED_GRANT_REFUSAL_RECEIPT } from '../hq/admission.mjs';
import { DIGEST, SOUL, hello, startHQ } from './hq-harness.mjs';

const sha = (byte) => `sha256:${byte.repeat(64)}`;
const next = () => {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
};

// Synthetic trusted-client fixture: it exercises HQ sequencing only. It is
// not a Machine signature or qualification proof and cannot enable production.
function machine({ finalized, entered, aborts, cooperativePeers = 0, startByte = '1' }) {
  return {
    async acceptPeer() { return cooperativePeers-- > 0 ? null : { machine_peer: 'fixture-live-R' }; },
    async peerDisconnected(_socket, context) { if (context) this.onLoss?.(); },
    watchLiveness(_binding, onLoss) { this.onLoss = onLoss; return () => { this.onLoss = null; }; },
    async assertLive() { return true; },
    watchHealthy() { return true; },
    async verifyHelloStart({ connection, payload, hello_payload_sha256: digest }) {
      assert.equal(connection.machine_peer, 'fixture-live-R');
      return { reservation_sha256: sha(startByte === '1' ? 'a' : '9'), definition_measurement: sha('b'),
        launch_input_measurement: sha('c'), broker_bind_receipt_sha256: sha('d'),
        start_id: `st_${startByte.repeat(24)}`, launch_id: `ln_${'2'.repeat(24)}`,
        hq_epoch: '3'.repeat(64), soul_id: payload.soul_id,
        installation_id: payload.installation_id, definition_digest: payload.definition_digest,
        hello_payload_sha256: digest, profile_in_force: 'managed-protected' };
    },
    async verifyDefinitionMapping(binding, payload) {
      return binding.soul_id === SOUL && binding.definition_digest === DIGEST
        && payload.definition_digest === DIGEST;
    },
    async finalize(expected) { entered.resolve(expected); return finalized.promise; },
    async verifyFinalization(record, expected) { return record === expected; },
    async abort(expected) { aborts.push(expected.start_id); },
  };
}

// These tests exercise admission state transitions with a synthetic trusted
// listener context. Production receives that context only on the per-start
// R socket; the shared C socket never attaches one.
async function startProtectedHQ(options) {
  const t = await startHQ(options);
  let nextSession = 0;
  const verifier = options.protectedAdmission;
  t.entry = async () => {
    const context = await verifier.acceptPeer();
    const session = `rp_fixture_${++nextSession}`;
    let closed = false;
    return {
      request: async (op, payload) => {
        if (closed) throw new Error('synthetic R entry is closed');
        try {
          const result = await t.hq.host.dispatch(op, { auth: 'entry-point',
            session, payload, protectedStart: context });
          return { ok: true, result };
        } catch (error) {
          return { ok: false, host_refusal: { code: error.code ?? 'host.internal' } };
        }
      },
      close: async () => {
        if (closed) return;
        closed = true;
        if (context) await verifier.peerDisconnected(null, context);
      },
    };
  };
  return t;
}

test('protected Hello keeps all runtimes unusable until distinct Machine finalization', async () => {
  const finalized = next();
  const entered = next();
  const aborts = [];
  const t = await startProtectedHQ({ protectedAdmission: machine({ finalized, entered, aborts }) });
  try {
    const entry = await t.entry();
    const pending = entry.request('Hello', hello());
    const expected = await Promise.race([entered.promise, pending.then((response) => { throw new Error(`Hello returned before finalization: ${JSON.stringify(response)}`); })]);
    const rows = t.hq.core.tables.get('hq-admission\0runtimes');
    assert.deepEqual(expected.admitted_runtimes.map((r) => r.member_id), ['m_lead', 'm_spec']);
    for (const rt of expected.admitted_runtimes) {
      assert.equal(rows.get(rt.runtime_id).protected_state, 'pending');
      await assert.rejects(t.hq.host.provided('hq-admission').withBoundRuntime(rt.runtime_id, () => true),
        (error) => error.code === 'host.launch_unavailable');
    }
    const owner = await t.owner();
    assert.deepEqual((await owner.request('souls.list')).result, []);
    finalized.resolve(expected);
    const response = await pending;
    assert.equal(response.ok, true, JSON.stringify(response));
    assert.equal(response.result.profile, 'managed-protected');
    const activeRows = t.hq.core.tables.get('hq-admission\0runtimes');
    for (const rt of expected.admitted_runtimes) {
      assert.equal(activeRows.get(rt.runtime_id).protected_state, 'active');
      assert.equal(await t.hq.host.provided('hq-admission').withBoundRuntime(rt.runtime_id, () => true), true);
    }
    assert.equal((await entry.request('Hello', hello({ request_id: 'req_reuse_start' }))).host_refusal.code,
      'host.launch_unavailable', 'one Machine reservation cannot create a second decision');
    assert.deepEqual(aborts, [expected.start_id], 'replayed verified start is terminally aborted');
  } finally { await t.done(); }
});

test('wrong finalization spends the protected start and revokes every runtime', async () => {
  const finalized = next();
  const entered = next();
  const aborts = [];
  const t = await startProtectedHQ({ protectedAdmission: machine({ finalized, entered, aborts }) });
  try {
    const entry = await t.entry();
    const pending = entry.request('Hello', hello());
    const expected = await Promise.race([entered.promise, pending.then((response) => { throw new Error(`Hello returned before finalization: ${JSON.stringify(response)}`); })]);
    finalized.resolve({ ...expected, admission_decision_id: 'dec_wrong' });
    const response = await pending;
    assert.equal(response.host_refusal.code, 'host.launch_unavailable');
    const rows = t.hq.core.tables.get('hq-admission\0runtimes');
    for (const rt of expected.admitted_runtimes) assert.equal(rows.get(rt.runtime_id).protected_state, 'revoked');
    assert.deepEqual(aborts, [expected.start_id]);
    const spent = t.hq.core.tables.get('hq-admission\0protected_starts');
    assert.equal([...spent.values()][0].state, 'spent');
    assert.equal((await entry.request('Hello', hello())).host_refusal.code, 'host.launch_unavailable');
  } finally { await t.done(); }
});

test('failed protected finalization leaves an earlier cooperative admission live', async () => {
  const finalized = next();
  const entered = next();
  const aborts = [];
  const t = await startProtectedHQ({ protectedAdmission: machine({ finalized, entered, aborts, cooperativePeers: 1 }) });
  try {
    const oldEntry = await t.entry();
    const old = (await oldEntry.request('Hello', hello())).result;
    const oldId = old.admitted_runtimes[0].runtime_id;
    const protectedEntry = await t.entry();
    const pending = protectedEntry.request('Hello', hello({ request_id: 'req_protected_next' }));
    const expected = await entered.promise;
    assert.equal(t.hq.core.tables.get('hq-admission\0runtimes').get(oldId).superseded, false);
    assert.equal(await t.hq.host.provided('hq-admission').withBoundRuntime(oldId, () => true), true);
    finalized.resolve(null);
    assert.equal((await pending).host_refusal.code, 'host.launch_unavailable');
    assert.equal(t.hq.core.tables.get('hq-admission\0runtimes').get(oldId).superseded, false);
    assert.equal(await t.hq.host.provided('hq-admission').withBoundRuntime(oldId, () => true), true);
    assert.equal(t.hq.core.tables.get('hq-admission\0souls').get(SOUL).decision_id, old.decision_id);
    assert.deepEqual(aborts, [expected.start_id]);
  } finally { await t.done(); }
});

test('a Machine finalization timeout refuses and spends the protected Hello', { timeout: 12_000 }, async () => {
  const finalized = next(); // deliberately never resolved
  const entered = next();
  const aborts = [];
  const t = await startProtectedHQ({ protectedAdmission: machine({ finalized, entered, aborts }) });
  try {
    const entry = await t.entry();
    const pending = entry.request('Hello', hello());
    const expected = await entered.promise;
    const response = await pending;
    assert.equal(response.host_refusal.code, 'host.launch_unavailable');
    for (const rt of expected.admitted_runtimes)
      assert.equal(t.hq.core.tables.get('hq-admission\0runtimes').get(rt.runtime_id).protected_state, 'revoked');
    assert.deepEqual(aborts, [expected.start_id]);
  } finally { await t.done(); }
});

test('restart revokes a persisted provisional Hello before serving admission', async () => {
  const t = await startHQ();
  const home = t.home;
  try {
    const entry = await t.entry();
    assert.equal((await entry.request('Hello', hello())).ok, true);
  } finally { await t.done({ keep: true }); }
  const statePath = join(home, 'store.json');
  const state = JSON.parse(readFileSync(statePath, 'utf8'));
  const table = (name) => state.tables.find(([key]) => key === `hq-admission\0${name}`)[1];
  const hellos = table('hellos');
  const runtimes = table('runtimes');
  hellos[0][1].protected_state = 'pending';
  hellos[0][1].protected_start_id = `st_${'1'.repeat(24)}`;
  for (const [, rt] of runtimes) { rt.protected_state = 'pending'; rt.protected_start_id = hellos[0][1].protected_start_id; }
  state.tables.push(['hq-admission\0protected_starts', [[`${hello().installation_id}\0${hellos[0][1].protected_start_id}`,
    { state: 'pending', request_id: hello().request_id, reservation_sha256: sha('a') }]]]);
  writeFileSync(statePath, JSON.stringify(state));
  const restarted = await startHQ({ home });
  try {
    assert.equal(restarted.hq.status().plugins.find((p) => p.name === 'hq-admission').state, 'running');
    assert.equal(restarted.hq.core.tables.get('hq-admission\0hellos').get(hello().request_id).protected_state, 'revoked');
    assert.equal([...restarted.hq.core.tables.get('hq-admission\0protected_starts').values()][0].state, 'spent');
    for (const [id, rt] of restarted.hq.core.tables.get('hq-admission\0runtimes')) {
      assert.equal(rt.protected_state, 'revoked');
      await assert.rejects(restarted.hq.host.provided('hq-admission').withBoundRuntime(id, () => true),
        (error) => error.code === 'host.launch_unavailable');
    }
  } finally { await restarted.done(); }
});

test('restart revokes even a finalized protected runtime until Machine reauthenticates it', async () => {
  const finalized = next();
  const entered = next();
  const t = await startProtectedHQ({ protectedAdmission: machine({ finalized, entered, aborts: [] }) });
  const home = t.home;
  let runtimeId;
  try {
    const entry = await t.entry();
    const pending = entry.request('Hello', hello());
    finalized.resolve(await entered.promise);
    const response = await pending;
    assert.equal(response.ok, true);
    runtimeId = response.result.admitted_runtimes[0].runtime_id;
  } finally { await t.done({ keep: true }); }
  const restarted = await startHQ({ home });
  try {
    assert.equal(restarted.hq.core.tables.get('hq-admission\0runtimes').get(runtimeId).protected_state, 'revoked');
    assert.equal([...restarted.hq.core.tables.get('hq-admission\0protected_starts').values()][0].state, 'spent');
    await assert.rejects(restarted.hq.host.provided('hq-admission').withBoundRuntime(runtimeId, () => true),
      (error) => error.code === 'host.launch_unavailable');
  } finally { await restarted.done(); }
});


test('mapping throw and accepted-definition refusal abort verified starts', async () => {
  for (const kind of ['mapping', 'acceptance']) {
    const finalized = next(), entered = next(), aborts = [];
    const verifier = machine({ finalized, entered, aborts });
    if (kind === 'mapping') verifier.verifyDefinitionMapping = async () => { throw new Error('Machine mapping failed'); };
    const t = await startProtectedHQ({ protectedAdmission: verifier,
      ...(kind === 'acceptance' ? { config: { acceptedDefinitions: {} } } : {}) });
    try {
      const entry = await t.entry();
      assert.equal((await entry.request('Hello', hello())).host_refusal.code, 'host.launch_unavailable');
      assert.deepEqual(aborts, [`st_${'1'.repeat(24)}`]);
      assert.equal(t.hq.core.tables.get('hq-admission\0runtimes')?.size ?? 0, 0);
    } finally { await t.done(); }
  }
});

test('distinct verified start cannot reuse an active cooperative Hello', async () => {
  const finalized = next(), entered = next(), aborts = [];
  const verifier = machine({ finalized, entered, aborts, cooperativePeers: 1 });
  const t = await startProtectedHQ({ protectedAdmission: verifier });
  try {
    const cooperative = await t.entry();
    const old = (await cooperative.request('Hello', hello())).result;
    const protectedEntry = await t.entry();
    assert.equal((await protectedEntry.request('Hello', hello())).host_refusal.code, 'host.launch_unavailable');
    assert.deepEqual(aborts, [`st_${'1'.repeat(24)}`]);
    assert.equal(t.hq.core.tables.get('hq-admission\0souls').get(SOUL).decision_id, old.decision_id);
  } finally { await t.done(); }
});

test('R/B loss before finalization refuses and aborts, including late finalize', async () => {
  const finalized = next(), entered = next(), aborts = [];
  const verifier = machine({ finalized, entered, aborts });
  let terminal = false;
  verifier.abort = async (expected) => { terminal = true; aborts.push(expected.start_id); };
  verifier.finalize = async (expected) => {
    entered.resolve(expected);
    await finalized.promise;
    if (terminal) throw new Error('Machine rejected late finalize after terminal abort');
    return expected;
  };
  const t = await startProtectedHQ({ protectedAdmission: verifier });
  try {
    const entry = await t.entry();
    const pending = entry.request('Hello', hello());
    const expected = await entered.promise;
    verifier.onLoss();
    finalized.resolve();
    assert.equal((await pending).host_refusal.code, 'host.launch_unavailable');
    assert.ok(aborts.length >= 1 && aborts.every((id) => id === expected.start_id));
    for (const rt of expected.admitted_runtimes)
      assert.equal(t.hq.core.tables.get('hq-admission\0runtimes').get(rt.runtime_id).protected_state, 'revoked');
  } finally { await t.done(); }
});

test('R/B loss after finalization revokes active runtimes and Admit', async () => {
  const finalized = next(), entered = next(), aborts = [];
  const verifier = machine({ finalized, entered, aborts });
  const t = await startProtectedHQ({ protectedAdmission: verifier });
  try {
    const entry = await t.entry();
    const pending = entry.request('Hello', hello());
    const expected = await entered.promise;
    finalized.resolve(expected);
    assert.equal((await pending).ok, true);
    verifier.onLoss();
    for (const rt of expected.admitted_runtimes)
      await assert.rejects(t.hq.host.provided('hq-admission').withBoundRuntime(rt.runtime_id, () => true),
        (error) => error.code === 'host.launch_unavailable');
    assert.equal((await entry.request('Admit', { request_id: hello().request_id })).host_refusal.code, 'host.launch_unavailable');
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal([...t.hq.core.tables.get('hq-admission\0protected_starts').values()][0].state, 'spent');
    assert.deepEqual(aborts, [expected.start_id]);
  } finally { await t.done(); }
});


test('verification failure aborts by authenticated peer token before a binding exists', async () => {
  const finalized = next(), entered = next(), aborts = [];
  const verifier = machine({ finalized, entered, aborts });
  verifier.verifyHelloStart = async () => { throw new Error('Machine verification failed'); };
  verifier.abort = async (target) => { aborts.push(target.connection.machine_peer); };
  const t = await startProtectedHQ({ protectedAdmission: verifier });
  try {
    const entry = await t.entry();
    assert.equal((await entry.request('Hello', hello())).host_refusal.code, 'host.launch_unavailable');
    assert.deepEqual(aborts, ['fixture-live-R']);
    assert.equal(t.hq.core.tables.get('hq-admission\0runtimes')?.size ?? 0, 0);
  } finally { await t.done(); }
});

test('pending or final admission snapshot failure aborts the verified start', async () => {
  for (const stage of ['pending', 'final']) {
    const finalized = next(), entered = next(), aborts = [];
    const verifier = machine({ finalized, entered, aborts });
    if (stage === 'final') verifier.finalize = async (expected) => expected;
    const t = await startProtectedHQ({ protectedAdmission: verifier });
    const original = fs.renameSync;
    let injected = false;
    fs.renameSync = function (from, to) {
      if (!injected && to === join(t.home, 'store.json')) {
        const snapshot = JSON.parse(readFileSync(from, 'utf8'));
        const hit = snapshot.receipts.some((r) => r.kind === `hq.admission.${stage}`
          || (stage === 'final' && r.kind === 'hq.admission' && r.profile_in_force === 'managed-protected'));
        if (hit) { injected = true; throw new Error('injected store snapshot failure'); }
      }
      return original.call(this, from, to);
    };
    syncBuiltinESMExports();
    try {
      const entry = await t.entry();
      const response = await entry.request('Hello', hello());
      assert.equal(injected, true);
      assert.equal(response.host_refusal.code, 'host.launch_unavailable');
      assert.deepEqual(aborts, [`st_${'1'.repeat(24)}`]);
      for (const rt of t.hq.core.tables.get('hq-admission\0runtimes')?.values() ?? [])
        assert.notEqual(rt.protected_state, 'active');
    } finally {
      fs.renameSync = original;
      syncBuiltinESMExports();
      await t.done();
    }
  }
});


test('closing the authenticated R entry socket revokes its finalized runtime', async () => {
  const finalized = next(), entered = next(), aborts = [];
  const verifier = machine({ finalized, entered, aborts });
  const closed = next();
  verifier.peerDisconnected = async (_socket, context) => { if (context) { verifier.onLoss?.(); closed.resolve(); } };
  const t = await startProtectedHQ({ protectedAdmission: verifier });
  try {
    const entry = await t.entry();
    const pending = entry.request('Hello', hello());
    const expected = await entered.promise;
    finalized.resolve(expected);
    assert.equal((await pending).ok, true);
    await entry.close();
    await closed.promise;
    for (const rt of expected.admitted_runtimes)
      await assert.rejects(t.hq.host.provided('hq-admission').withBoundRuntime(rt.runtime_id, () => true),
        (error) => error.code === 'host.launch_unavailable');
    assert.ok(aborts.includes(expected.start_id));
  } finally { await t.done(); }
});

test('lost R/B with rejected or timed-out abort records containment uncertainty', { timeout: 15_000 }, async () => {
  for (const outcome of ['rejected', 'timeout']) {
    const finalized = next(), entered = next(), aborts = [];
    const verifier = machine({ finalized, entered, aborts });
    verifier.abort = async () => {
      if (outcome === 'rejected') throw new Error('Machine abort refused');
      return new Promise(() => {});
    };
    const t = await startProtectedHQ({ protectedAdmission: verifier });
    try {
      const entry = await t.entry();
      const pending = entry.request('Hello', hello());
      const expected = await entered.promise;
      finalized.resolve(expected);
      assert.equal((await pending).ok, true);
      verifier.onLoss();
      for (const rt of expected.admitted_runtimes)
        await assert.rejects(t.hq.host.provided('hq-admission').withBoundRuntime(rt.runtime_id, () => true),
          (error) => error.code === 'host.launch_unavailable');
      const deadline = Date.now() + 7_000;
      while (!t.hq.core.receipts.some((r) => r.kind === 'hq.protected.containment_unconfirmed') && Date.now() < deadline)
        await new Promise((resolve) => setTimeout(resolve, 10));
      const incident = t.hq.core.receipts.find((r) => r.kind === 'hq.protected.containment_unconfirmed');
      assert.equal(incident?.start_id, expected.start_id);
      assert.equal(incident?.installation_id, expected.installation_id);
    } finally { await t.done(); }
  }
});

test('failed Machine watcher transport closes active runtime and lease authority', async () => {
  const finalized = next(), entered = next(), aborts = [];
  const verifier = machine({ finalized, entered, aborts });
  const t = await startProtectedHQ({ protectedAdmission: verifier });
  try {
    const entry = await t.entry();
    const pending = entry.request('Hello', hello());
    const expected = await entered.promise;
    finalized.resolve(expected);
    assert.equal((await pending).ok, true);
    verifier.watchHealthy = () => { throw new Error('Machine watcher transport lost'); };
    const rt = expected.admitted_runtimes[0];
    await assert.rejects(t.hq.host.provided('hq-admission').withBoundRuntime(rt.runtime_id, () => true),
      (error) => error.code === 'host.launch_unavailable');
    assert.equal((await entry.request('Admit', { request_id: hello().request_id })).host_refusal.code, 'host.launch_unavailable');
    const held = await t.hq.host.provided('hq-admission').withLeases((hasLease) => hasLease(SOUL, 1));
    assert.equal(held, false);
    assert.ok(aborts.includes(expected.start_id));
  } finally { await t.done(); }
});

test('a protected grant belongs to its bound runtime before and after HQ restart', async () => {
  let home;
  let priorHandle;
  for (const [index, startByte] of ['1', '2'].entries()) {
    const finalized = next();
    const entered = next();
    const t = await startProtectedHQ({ home, protectedAdmission: machine({ finalized, entered, aborts: [], startByte }) });
    home = t.home;
    try {
      const entry = await t.entry();
      const pending = entry.request('Hello', hello({ request_id: `req_grant_${index}` }));
      const expected = await Promise.race([entered.promise, pending.then((response) => {
        throw new Error(`Hello returned before grant test finalization: ${JSON.stringify(response)}`);
      })]);
      finalized.resolve(expected);
      const admission = await pending;
      assert.equal(admission.ok, true, JSON.stringify(admission));
      const [a, b] = admission.result.admitted_runtimes;
      const equips = await Promise.all([a, b].map(({runtime_id}) => entry.request('Equip', { runtime_id })));
      assert.ok(equips.every(({ok}) => ok));
      const [handleA, handleB] = equips.map(({result}) => result.grant_handles[0].handle);
      assert.notEqual(handleA, handleB);

      let effects = 0;
      const effect = (scope) => {
        effects++;
        assert.equal(scope.start_id, `st_${startByte.repeat(24)}`);
        assert.equal(scope.grant_handle, undefined);
        return scope.member_id;
      };
      const { withProtectedGrant } = t.hq.host.provided('hq-admission');
      await assert.rejects(withProtectedGrant(a.runtime_id, handleA + '\n', sha('c'), effect),
        (error) => error.code === 'host.invalid_request');
      await assert.rejects(withProtectedGrant(a.runtime_id, handleA, sha('c') + '\n', effect),
        (error) => error.code === 'host.invalid_request');
      assert.equal(await withProtectedGrant(a.runtime_id, handleA, sha('c'), effect), a.member_id);
      assert.equal(await withProtectedGrant(b.runtime_id, handleB, sha('d'), effect), b.member_id);
      let committedRefusal;
      await assert.rejects(withProtectedGrant(b.runtime_id, handleA, sha('e'), effect),
        (error) => {
          committedRefusal = error[PROTECTED_GRANT_REFUSAL_RECEIPT];
          return error.code === 'caller_mismatch';
        });
      if (priorHandle) {
        assert.notEqual(priorHandle, handleA);
        await assert.rejects(withProtectedGrant(b.runtime_id, priorHandle, sha('f'), effect),
          (error) => error.code === 'caller_mismatch');
      }
      assert.equal(effects, 2);
      priorHandle = handleA;

      const { receipts } = JSON.parse(readFileSync(join(home, 'store.json'), 'utf8'));
      const issued = receipts.find(({kind, runtime_id}) => kind === 'hq.equip' && runtime_id === a.runtime_id);
      const denied = receipts.find(({kind, runtime_id}) => kind === 'hq.protected.grant.refused' && runtime_id === b.runtime_id);
      assert.deepEqual(committedRefusal, denied);
      assert.ok(denied.seq > issued.seq);
      assert.equal(denied.grant_handle_sha256, issued.grant_handle_sha256);
      assert.equal(denied.start_id, issued.start_id);
      assert.equal(denied.member_id, b.member_id);
      assert.equal(denied.request_sha256, sha('e'));
      assert.equal(denied.effect_invoked, false);
      assert.equal(JSON.stringify(receipts).includes(handleA), false);
      assert.equal(JSON.stringify(receipts).includes(handleB), false);
      if (index === 1) assert.equal(receipts.filter(({kind}) => kind === 'hq.protected.grant.refused').length, 3);
    } finally {
      await t.done({ keep: index === 0 });
    }
  }
});

test('a cooperative runtime cannot use a protected grant even with its own equipped handle', async () => {
  const t = await startHQ();
  try {
    const entry = await t.entry();
    const admitted = await entry.request('Hello', hello());
    assert.equal(admitted.result.profile, 'managed-cooperative');
    const { runtime_id } = admitted.result.admitted_runtimes[0];
    const equipped = await entry.request('Equip', { runtime_id });
    const { handle } = equipped.result.grant_handles[0];
    const { withProtectedGrant } = t.hq.host.provided('hq-admission');
    await assert.rejects(withProtectedGrant(runtime_id, handle, sha('a'), () => assert.fail('protected effect')),
      (error) => error.code === 'profile_insufficient');
  } finally { await t.done(); }
});
