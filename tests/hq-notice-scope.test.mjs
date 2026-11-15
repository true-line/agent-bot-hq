// Host-only notice scope; no mailbox consumer or public schema is added here.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, chmodSync } from 'node:fs';
import { join } from 'node:path';
import { validateConfig } from '../hq/hq.mjs';
import { validNoticeScope } from '../hq/notices-config.mjs';
import { DIGEST, SOUL, hello, startHQ, fakeLegacy } from './hq-harness.mjs';
import { legacySigner } from '../hq/legacy.mjs';

const mapping = { soul_id: SOUL, definition_digest: DIGEST, member_id: 'm_lead', adapter_id: 'fake-adapter', role: 'lead', harness: 'remote-bot', repo: 'true-line/agent-bot-hq' };
const config = (scopes = [mapping]) => ({ acceptedDefinitions: { [SOUL]: [DIGEST] }, notices: { harnesses: ['remote-bot'], scopes } });
const enrollment = (allowed = () => true) => ({ ...legacySigner({ run: fakeLegacy().run }), allowsHarness: allowed });
const start = (opts = {}) => startHQ({ config: config(), enrollment: enrollment(), ...opts });
const admit = async (t, overrides) => {
  const entry = await t.entry();
  const response = await entry.request('Hello', hello(overrides));
  assert.equal(response.ok, true, JSON.stringify(response));
  const result = response.result;
  return { result, runtime: result.admitted_runtimes[0].runtime_id, context: { installation_epoch: result.installation_epoch, lease_generation: result.lease_generation } };
};
const guard = (t, admitted, context = admitted.context, effect = (scope) => scope) => t.hq.host.provided('hq-admission').withNoticeScope(admitted.runtime, context, effect);
const runtimeRow = (t, id) => t.hq.core.tables.get('hq-admission\0runtimes').get(id);
const mismatch = (e) => e.code === 'caller_mismatch';

test('exact owner mapping freezes accepted assignment, no wire scope exposure, guarded equality only', async () => {
  const t = await start();
  try {
    const a = await admit(t);
    assert.deepEqual(await guard(t, a), { harness: mapping.harness, repo: mapping.repo });
    assert.equal(runtimeRow(t, a.runtime).definition_digest, DIGEST);
    assert.deepEqual(runtimeRow(t, a.runtime).notice_scope, await guard(t, a));
    assert.equal(JSON.stringify(a.result).includes('notice_scope'), false);
    const upper = await guard(t, a, { ...a.context, expected_repository: mapping.repo.toUpperCase() });
    assert.equal(upper.repo, mapping.repo);
    assert.throws(() => { upper.repo = 'elsewhere/repo'; }, TypeError);
    let effects = 0;
    for (const context of [{ ...a.context, harness: 'remote-bot' }, { ...a.context, repo: mapping.repo }, { ...a.context, runtime_id: a.runtime }, { ...a.context, notice_scope: {} }, { ...a.context, installation_epoch: 99 }, { ...a.context, lease_generation: 99 }, { ...a.context, expected_repository: 'other/repo' }, { ...a.context, expected_repository: '../bad' }]) {
      await assert.rejects(guard(t, a, context, () => { effects++; }));
    }
    assert.equal(effects, 0);
    await assert.rejects(guard(t, a, { ...a.context, installation_epoch: 99 }), (e) => e.code === 'stale_epoch');
    await assert.rejects(guard(t, a, { ...a.context, lease_generation: 99 }), (e) => e.code === 'lease_expired');
    const specialist = { ...a, runtime: a.result.admitted_runtimes[1].runtime_id };
    assert.equal(runtimeRow(t, specialist.runtime).notice_scope, null);
    await assert.rejects(guard(t, specialist), mismatch);
  } finally { await t.done(); }
});

test('notices disabled, unproved enrollment and mismatched assignments leave normal admission working with explicit null', async () => {
  for (const opts of [{ config: { acceptedDefinitions: { [SOUL]: [DIGEST] } } }, { enrollment: legacySigner({ run: fakeLegacy().run }) }, { enrollment: enrollment(() => false) }, { enrollment: enrollment(() => { throw new Error('unreadable proof'); }) }, ...['soul_id', 'definition_digest', 'member_id', 'adapter_id', 'role'].map((field) => ({ config: config([{ ...mapping, [field]: field === 'soul_id' ? SOUL.replace('0b3f', '1b3f') : field === 'definition_digest' ? `sha256:${'b2'.repeat(32)}` : 'other' }]) }))]) {
    const t = await start(opts);
    try { const a = await admit(t); assert.equal(runtimeRow(t, a.runtime).notice_scope, null); await assert.rejects(guard(t, a), mismatch); } finally { await t.done(); }
  }
});

test('restart preserves frozen snapshot/null; changed config, removed acceptance and enrollment loss cannot widen authority', async () => {
  for (const variant of ['same', 'case', 'changed', 'removed', 'null', 'legacy', 'acceptance', 'enrollment']) {
    let t = await start({ config: variant === 'null' ? config([]) : config() });
    const home = t.home;
    const a = await admit(t);
    await t.done({ keep: true });
    if (variant === 'legacy') {
      const path = join(home, 'store.json');
      const snapshot = JSON.parse(readFileSync(path, 'utf8'));
      for (const [key, rows] of snapshot.tables) if (key === 'hq-admission\0runtimes') for (const [, row] of rows) delete row.notice_scope;
      writeFileSync(path, JSON.stringify(snapshot)); chmodSync(path, 0o600);
    }
    const next = variant === 'changed' ? config([{ ...mapping, repo: 'true-line/another' }]) : variant === 'removed' ? config([]) : variant === 'case' ? config([{ ...mapping, repo: mapping.repo.toUpperCase() }]) : config();
    if (variant === 'acceptance') next.acceptedDefinitions = {};
    t = await start({ home, config: next, ...(variant === 'enrollment' ? { enrollment: enrollment(() => false) } : {}) });
    try {
      if (['same', 'case'].includes(variant)) assert.equal((await guard(t, a)).repo, mapping.repo);
      else await assert.rejects(guard(t, a), mismatch);
      if (['null', 'legacy'].includes(variant)) {
        assert.equal(runtimeRow(t, a.runtime).notice_scope, null);
        const persisted = JSON.parse(readFileSync(join(home, 'store.json'), 'utf8'));
        assert.equal(persisted.tables.find(([key]) => key === 'hq-admission\0runtimes')[1].find(([id]) => id === a.runtime)[1].notice_scope, null);
      }
      if (variant === 'changed' || variant === 'null') {
        const b = await admit(t, { request_id: 'req_new' });
        assert.equal((await guard(t, b)).repo, next.notices.scopes[0].repo);
      }
    } finally { await t.done(); }
  }
});

test('scope effect shares the admission queue: supersession and queued lease expiry refuse before effects', async () => {
  const t = await start();
  try {
    const a = await admit(t);
    let release, entered;
    const started = new Promise((r) => { entered = r; });
    const hold = new Promise((r) => { release = r; });
    const first = guard(t, a, a.context, async () => { entered(); await hold; return 'completed'; });
    await started;
    const supersede = admit(t, { request_id: 'req_again' });
    release();
    assert.equal(await first, 'completed');
    const b = await supersede;
    await assert.rejects(guard(t, a), (e) => e.code === 'lease_expired');
    let unlock, locked;
    const lockStarted = new Promise((r) => { locked = r; });
    const lock = t.hq.host.provided('hq-admission').withBoundRuntime(b.runtime, async () => { locked(); await new Promise((r) => { unlock = r; }); });
    await lockStarted;
    let effects = 0;
    const expired = guard(t, b, b.context, () => { effects++; });
    t.clock.advance(60_001); unlock(); await lock;
    await assert.rejects(expired, (e) => e.code === 'lease_expired');
    assert.equal(effects, 0);
  } finally { await t.done(); }
});

test('scope configuration is explicit, bounded and unique per accepted assignment', () => {
  assert.doesNotThrow(() => validateConfig(config()));
  for (const scopes of [null, {}, Array(1025).fill(mapping), [mapping, mapping], [{ ...mapping, unknown: true }], [{ ...mapping, harness: 'not-polled' }], [{ ...mapping, repo: 'https://github.com/a/b' }], [{ ...mapping, repo: 'owner/..' }], [{ ...mapping, repo: 'owner/a/b' }], [{ ...mapping, definition_digest: 'latest' }], [{ ...mapping, role: '*' }]]) assert.throws(() => validateConfig(config(scopes)));
});

test('notice owner mappings reject trailing line terminators in every authority field', () => {
  for (const suffix of ['\n', '\r', '\u2028', '\u2029']) {
    for (const field of Object.keys(mapping)) {
      const bad = { ...mapping, [field]: mapping[field] + suffix };
      assert.throws(() => validateConfig(config([bad])), undefined, `${field} ending ${JSON.stringify(suffix)}`);
    }
    assert.equal(validNoticeScope({ harness: mapping.harness + suffix, repo: mapping.repo }), false);
  }
});

test('notice repository assertions with trailing line terminators refuse before the effect', async () => {
  const t = await start();
  try {
    const a = await admit(t);
    let effects = 0;
    for (const suffix of ['\n', '\r', '\u2028', '\u2029']) {
      await assert.rejects(guard(t, a, { ...a.context, expected_repository: mapping.repo + suffix }, () => { effects++; }), (e) => e.code === 'host.invalid_request');
    }
    assert.equal(effects, 0);
  } finally { await t.done(); }
});
