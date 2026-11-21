// hq/v1 admission over the real admission socket (hq/admission.mjs): Hello
// and the admission result, Admit, Equip, Ready and Lease, against the
// pinned soul-contracts schemas and fixtures.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs, { readFileSync, readdirSync } from 'node:fs';
import { syncBuiltinESMExports } from 'node:module';
import { join } from 'node:path';
import { validate } from '../sdk/wire/schema.mjs';
import { admissionPlugin } from '../hq/admission.mjs';
import { createTestHost } from '../sdk/test-host.mjs';
import { contracts, DIGEST, fixture, hello, schemas, SOUL, startHQ } from './hq-harness.mjs';

const ready = (rt, epoch, generation, sequence, over = {}) => ({
  contract: 'hq/v1', runtime_id: rt, installation_epoch: epoch, readiness_state: 'warm', auth_state: 'authenticated',
  adapter_versions: { 'fake-adapter': '0.1.0' }, lease_generation: generation, renewal_sequence: sequence, observed_health: 'healthy', ...over,
});

test('Hello admits with a schema-valid admission result: epoch 1, lease generation 1, the profile in force and a warning', async () => {
  const t = await startHQ();
  try {
    const entry = await t.entry();
    const res = await entry.request('Hello', hello());
    assert.equal(res.ok, true, JSON.stringify(res));
    const r = res.result;
    assert.deepEqual(validate(schemas['admission-result'], r), []);
    assert.equal(r.request_id, 'req_0001');
    assert.equal(r.installation_epoch, 1);
    assert.equal(r.lease_generation, 1);
    assert.equal(r.profile, 'managed-cooperative');
    assert.deepEqual(r.negotiated_versions, { hq: 1, wire: 1 });
    assert.deepEqual(r.admitted_runtimes.map((a) => [a.member_id, a.role]), [['m_lead', 'lead'], ['m_spec', 'specialist']]);
    assert.match(r.warnings[0], /^profile: managed-protected requested; managed-cooperative in force/);
    assert.equal(r.lease_expires_at, new Date(t.clock.now() + 60_000).toISOString());

    // The receipt names the decision but carries no channel binding.
    const receipt = t.hq.core.receipts.find((x) => x.kind === 'hq.admission');
    assert.equal(receipt.decision_id, r.decision_id);
    assert.equal(receipt.profile, 'managed-cooperative');
    for (const a of r.admitted_runtimes) assert.equal(JSON.stringify(t.hq.core.receipts).includes(a.channel_binding), false);
  } finally { await t.done(); }
});

test('Hello state and its admission receipt roll back together on a receipt snapshot failure', async () => {
  const t = await startHQ();
  const entry = await t.entry();
  const first = (await entry.request('Hello', hello())).result;
  const originalRuntimes = first.admitted_runtimes.map((r) => r.runtime_id);
  t.clock.advance(60_001);
  const unboundBeforeFailure = t.hq.host.provided('hq-admission').unboundRuntimes();
  const original = fs.renameSync;
  let injected = false;
  let assertionsPassed = false;
  fs.renameSync = function (from, to) {
    if (!injected && to === join(t.home, 'store.json')) {
      const snapshot = JSON.parse(readFileSync(from, 'utf8'));
      if (snapshot.receipts.some((r) => r.kind === 'hq.admission' && r.request_id === 'req_receipt_failure')) {
        injected = true;
        const error = new Error('injected admission receipt snapshot failure');
        error.code = 'EIO';
        throw error;
      }
    }
    return original.call(this, from, to);
  };
  syncBuiltinESMExports();
  try {
    const failed = await entry.request('Hello', hello({ request_id: 'req_receipt_failure' }));
    assert.equal(injected, true);
    assert.equal(failed.ok, false);
    assert.equal(failed.host_refusal.code, 'host.internal');
    assert.equal(t.hq.core.tables.get('hq-admission\0hellos')?.has('req_receipt_failure') ?? false, false);
    assert.equal(t.hq.core.tables.get('hq-admission\0runtimes')?.size, 2);
    for (const runtimeId of originalRuntimes) assert.equal(t.hq.core.tables.get('hq-admission\0runtimes').get(runtimeId).superseded, false);
    assert.deepEqual(t.hq.host.provided('hq-admission').unboundRuntimes(), unboundBeforeFailure);
    const disk = JSON.parse(readFileSync(join(t.home, 'store.json'), 'utf8'));
    const helloRows = disk.tables.find(([name]) => name === 'hq-admission\0hellos')?.[1] ?? [];
    assert.equal(helloRows.length, 1);
    assert.equal(helloRows.some(([id]) => id === 'req_receipt_failure'), false);
    const runtimeRows = disk.tables.find(([name]) => name === 'hq-admission\0runtimes')?.[1] ?? [];
    assert.equal(runtimeRows.length, 2);
    for (const runtimeId of originalRuntimes) assert.equal(runtimeRows.find(([id]) => id === runtimeId)?.[1].superseded, false);
    assert.equal(disk.receipts.some((r) => r.kind === 'hq.admission' && r.request_id === 'req_receipt_failure'), false);
    assertionsPassed = true;
  } finally {
    fs.renameSync = original;
    syncBuiltinESMExports();
    await t.done({ keep: assertionsPassed });
  }

  const restarted = await startHQ({ home: t.home });
  try {
    const retry = await (await restarted.entry()).request('Hello', hello({ request_id: 'req_receipt_failure' }));
    assert.equal(retry.ok, true, JSON.stringify(retry));
    assert.equal(retry.result.lease_generation, 2);
    assert.equal(restarted.hq.core.tables.get('hq-admission\0hellos')?.has('req_receipt_failure'), true);
    assert.equal(restarted.hq.core.tables.get('hq-admission\0runtimes')?.size, 4);
    assert.equal([...restarted.hq.core.tables.get('hq-admission\0runtimes').values()].filter((rt) => !rt.superseded).length, 2);
    assert.equal(restarted.hq.core.receipts.filter((r) => r.kind === 'hq.admission' && r.request_id === 'req_receipt_failure').length, 1);
  } finally { await restarted.done(); }
});

test('a repeated Hello returns the same decision to its caller only; a reused request_id with new content is refused', async () => {
  const t = await startHQ();
  try {
    const entry = await t.entry();
    const first = (await entry.request('Hello', hello())).result;
    const again = (await entry.request('Hello', hello())).result;
    assert.deepEqual(again, first);
    assert.equal(t.hq.core.receipts.filter((x) => x.kind === 'hq.admission').length, 1);
    assert.deepEqual((await entry.request('Admit', { request_id: 'req_0001' })).result, first);

    const changed = await entry.request('Hello', hello({ installation_id: 'inst_other' }));
    assert.equal(changed.host_refusal.code, 'host.invalid_request');
    assert.match(changed.host_refusal.explanation, /different content/);

    const other = await t.entry();
    assert.equal((await other.request('Hello', hello())).refusal.error, 'caller_mismatch');
    assert.equal((await other.request('Admit', { request_id: 'req_0001' })).refusal.error, 'caller_mismatch');
    assert.equal((await entry.request('Admit', { request_id: 'req_none' })).host_refusal.code, 'host.invalid_request');
  } finally { await t.done(); }
});

test('admission keeps the legacy append path with a non-grouping custom receipt service', async () => {
  const appended = [];
  const host = createTestHost({
    plugins: [admissionPlugin({ schemas })],
    services: { receipts: (_core, plugin) => ({ async append(record) { appended.push({ ...record, plugin }); return appended.length; } }) },
    config: { 'hq-admission': { acceptedDefinitions: { [SOUL]: [DIGEST] } } },
  });
  await host.start();
  try {
    const first = await host.dispatch('Hello', { auth: 'entry-point', payload: hello(), session: 'legacy-entry' });
    const again = await host.dispatch('Hello', { auth: 'entry-point', payload: hello(), session: 'legacy-entry' });
    assert.deepEqual(again, first);
    assert.equal(appended.filter((r) => r.kind === 'hq.admission').length, 1);
    const runtime = first.admitted_runtimes[0].runtime_id;
    await host.dispatch('Equip', { auth: 'entry-point', payload: { runtime_id: runtime }, session: 'legacy-entry' });
    await host.dispatch('Ready', { auth: 'entry-point', payload: ready(runtime, 1, 1, 1), session: 'legacy-entry' });
    assert.equal(appended.filter((r) => r.kind === 'hq.equip' && r.runtime_id === runtime).length, 1);
    assert.equal(appended.filter((r) => r.kind === 'hq.ready' && r.runtime_id === runtime).length, 1);
  } finally { await host.stop(); }
});

test('refusals: unaccepted definition, unsupported version (T14), schema-invalid Hellos', async () => {
  const t = await startHQ();
  try {
    const entry = await t.entry();
    const unaccepted = fixture('negative/hello.unaccepted-definition.json').input;
    assert.equal((await entry.request('Hello', unaccepted)).refusal.error, 'definition_not_accepted');
    const v2 = await entry.request('Hello', hello({ request_id: 'req_v2', supported_versions: { hq: [2], wire: [1] } }));
    assert.equal(v2.refusal.error, 'unsupported_version');
    const w = await entry.request('Hello', hello({ request_id: 'req_w', supported_versions: { hq: [1], wire: [3, 2] } }));
    assert.equal(w.refusal.error, 'unsupported_version');
    // Every schema-invalid Hello fixture is refused before any decision.
    const dir = join(contracts, 'fixtures/negative');
    const invalid = readdirSync(dir).filter((f) => f.startsWith('hello.')).map((f) => fixture(`negative/${f}`)).filter((f) => f.expect.schema === 'invalid');
    assert.ok(invalid.length >= 3);
    for (const f of invalid) {
      const res = await entry.request('Hello', f.input);
      assert.equal(res.host_refusal?.code, 'host.invalid_request', f.note);
    }
    assert.equal(t.hq.core.receipts.filter((x) => x.kind === 'hq.admission').length, 0);
    assert.ok(t.hq.core.receipts.filter((x) => x.kind === 'hq.hello.refused').length >= invalid.length + 3);
  } finally { await t.done(); }
});

test('epochs: a restart keeps the epoch, a second installation needs a move, and a stale copy is refused (T15)', async () => {
  const t = await startHQ();
  try {
    const entry = await t.entry();
    await entry.request('Hello', hello());
    const restart = (await entry.request('Hello', hello({ request_id: 'req_restart' }))).result;
    assert.equal(restart.installation_epoch, 1);
    assert.equal(restart.lease_generation, 2);

    const second = await entry.request('Hello', hello({ request_id: 'req_second', installation_id: 'inst_second' }));
    assert.equal(second.refusal.error, 'stale_epoch');
    assert.match(second.refusal.explanation, /needs a move/);

    const moved = (await entry.request('Hello', hello({ request_id: 'req_move', installation_id: 'inst_linux_02', prior_installation_epoch: 1 }))).result;
    assert.equal(moved.installation_epoch, 2);

    const stale = await entry.request('Hello', hello({ request_id: 'req_stale', installation_id: 'inst_old_copy', prior_installation_epoch: 1 }));
    assert.equal(stale.refusal.error, 'stale_epoch');
  } finally { await t.done(); }
});

test('a move fixture arriving at a fresh HQ advances past the prior epoch', async () => {
  const t = await startHQ();
  try {
    const entry = await t.entry();
    const res = await entry.request('Hello', fixture('positive/hello.move.json').input);
    assert.equal(res.result.installation_epoch, 5);
  } finally { await t.done(); }
});

test('Equip: a schema-valid record with one stable grant handle, no credentials, for the admitted caller only', async () => {
  const t = await startHQ();
  try {
    const entry = await t.entry();
    const r = (await entry.request('Hello', hello())).result;
    const lead = r.admitted_runtimes[0];
    const e1 = (await entry.request('Equip', { runtime_id: lead.runtime_id })).result;
    assert.deepEqual(validate(schemas.equip, e1), []);
    assert.equal(e1.grant_handles.length, 1);
    assert.equal(e1.grant_handles[0].channel_binding, lead.channel_binding);
    assert.deepEqual(e1.credential_references, []);
    assert.deepEqual(e1.budget_sub_allocations, { working: 0, maintenance: 0 });
    const e2 = (await entry.request('Equip', { runtime_id: lead.runtime_id })).result;
    assert.equal(e2.grant_handles[0].handle, e1.grant_handles[0].handle);

    const other = await t.entry();
    assert.equal((await other.request('Equip', { runtime_id: lead.runtime_id })).refusal.error, 'caller_mismatch');
    assert.equal((await entry.request('Equip', { runtime_id: lead.runtime_id, extra: 1 })).host_refusal.code, 'host.invalid_request');
  } finally { await t.done(); }
});

test('Equip handle and Ready state roll back with their receipts on snapshot failure', async () => {
  for (const operation of ['Equip', 'Ready']) {
    const t = await startHQ();
    try {
      const entry = await t.entry();
      const admission = (await entry.request('Hello', hello())).result;
      const rt = admission.admitted_runtimes[0].runtime_id;
      const receiptKind = operation === 'Equip' ? 'hq.equip' : 'hq.ready';
      const original = fs.renameSync;
      let injected = false;
      fs.renameSync = function (from, to) {
        if (!injected && to === join(t.home, 'store.json')) {
          const snapshot = JSON.parse(readFileSync(from, 'utf8'));
          if (snapshot.receipts.some((r) => r.kind === receiptKind && r.runtime_id === rt)) {
            injected = true;
            const error = new Error(`injected ${operation} receipt snapshot failure`);
            error.code = 'EIO';
            throw error;
          }
        }
        return original.call(this, from, to);
      };
      syncBuiltinESMExports();
      let failed;
      try {
        failed = await entry.request(operation, operation === 'Equip' ? { runtime_id: rt } : ready(rt, 1, 1, 1));
      } finally {
        fs.renameSync = original;
        syncBuiltinESMExports();
      }
      assert.equal(injected, true);
      assert.equal(failed.ok, false);
      assert.equal(failed.host_refusal.code, 'host.internal');
      const runtime = t.hq.core.tables.get('hq-admission\0runtimes').get(rt);
      assert.equal(operation === 'Equip' ? runtime.handle : runtime.ready, operation === 'Equip' ? undefined : false);
      assert.equal(t.hq.core.receipts.filter((r) => r.kind === receiptKind && r.runtime_id === rt).length, 0);

      const retry = await entry.request(operation, operation === 'Equip' ? { runtime_id: rt } : ready(rt, 1, 1, 1));
      assert.equal(retry.ok, true, JSON.stringify(retry));
      assert.equal(t.hq.core.receipts.filter((r) => r.kind === receiptKind && r.runtime_id === rt).length, 1);
      assert.equal(operation === 'Equip' ? t.hq.core.tables.get('hq-admission\0runtimes').get(rt).handle : t.hq.core.tables.get('hq-admission\0runtimes').get(rt).ready, operation === 'Equip' ? retry.result.grant_handles[0].handle : true);
    } finally { await t.done(); }
  }
});

test('Ready then Lease: sequence, epoch, generation, expiry and supersession are enforced', async () => {
  const t = await startHQ();
  try {
    const entry = await t.entry();
    const r = (await entry.request('Hello', hello())).result;
    const rt = r.admitted_runtimes[0].runtime_id;

    assert.match((await entry.request('Lease', ready(rt, 1, 1, 1))).host_refusal.explanation, /has not sent Ready/);
    t.clock.advance(30_000);
    const ok = await entry.request('Ready', ready(rt, 1, 1, 1));
    assert.equal(ok.ok, true, JSON.stringify(ok));
    assert.equal(ok.result.lease_expires_at, new Date(t.clock.now() + 60_000).toISOString());
    assert.equal((await entry.request('Lease', ready(rt, 1, 1, 1))).host_refusal.code, 'host.invalid_request', 'replay');
    assert.equal((await entry.request('Lease', ready(rt, 2, 1, 2))).refusal.error, 'stale_epoch');
    assert.equal((await entry.request('Lease', ready(rt, 1, 7, 2))).refusal.error, 'lease_expired');
    assert.equal((await entry.request('Lease', ready(rt, 1, 1, 2, { readiness_state: 'cold' }))).ok, true);

    const other = await t.entry();
    assert.equal((await other.request('Lease', ready(rt, 1, 1, 3))).refusal.error, 'caller_mismatch');

    t.clock.advance(60_001);
    const expired = await entry.request('Lease', ready(rt, 1, 1, 3));
    assert.equal(expired.refusal.error, 'lease_expired');
    assert.match(expired.refusal.explanation, /expired/);

    const readmit = (await entry.request('Hello', hello({ request_id: 'req_again' }))).result;
    assert.equal(readmit.lease_generation, 2);
    const superseded = await entry.request('Ready', ready(rt, 1, 1, 4));
    assert.equal(superseded.refusal.error, 'lease_expired');
    assert.match(superseded.refusal.explanation, /superseded/);
    const fresh = readmit.admitted_runtimes[0].runtime_id;
    assert.equal((await entry.request('Ready', ready(fresh, 1, 2, 1))).ok, true);
  } finally { await t.done(); }
});

test('souls.list shows the owner each admitted Soul and its live runtimes', async () => {
  const t = await startHQ();
  try {
    const entry = await t.entry();
    const r = (await entry.request('Hello', hello())).result;
    await entry.request('Ready', ready(r.admitted_runtimes[0].runtime_id, 1, 1, 1));
    const owner = await t.owner();
    const [soul] = (await owner.request('souls.list')).result;
    assert.equal(soul.soul_id, SOUL);
    assert.equal(soul.installation_epoch, 1);
    assert.deepEqual(soul.runtimes.map((x) => [x.role, x.ready]), [['lead', true], ['specialist', false]]);
    assert.equal(JSON.stringify(soul).includes('cb_'), false, 'no channel bindings in owner views');
  } finally { await t.done(); }
});

test('the accepted-definition list is the owner config, not the Soul', async () => {
  const t = await startHQ({ config: { acceptedDefinitions: { [SOUL]: [`sha256:${'b2'.repeat(32)}`] } } });
  try {
    const entry = await t.entry();
    assert.equal((await entry.request('Hello', hello())).refusal.error, 'definition_not_accepted');
    assert.equal((await entry.request('Hello', hello({ request_id: 'req_b2', definition_digest: `sha256:${'b2'.repeat(32)}` }))).ok, true);
    assert.notEqual(DIGEST, `sha256:${'b2'.repeat(32)}`);
  } finally { await t.done(); }
});
