// Shared corpus and guarded effects run with the normal verified release loader.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { definePlugin } from '../../sdk/plugin.mjs';
import { canonicalBytes } from '../../sdk/wire/canonical-json.mjs';
import { validate } from '../../sdk/wire/schema.mjs';
import { legacySigner } from '../../hq/legacy.mjs';
import { DIGEST, SOUL, fakeLegacy, hello, startHQ } from '../hq-harness.mjs';
import { referenceBroker } from '../broker-fixture.mjs';

export function registerNoticeConsumerCases(schemas, fixtures) {
  const scope = { harness: 'notice-bot', repo: 'Example/Project' };
  const source = (id = 'notice:1', content = {}) => ({ message_id: id, provenance: ['external-untrusted'], wake_class: 'notify', content: { repo: scope.repo, text: 'external content', ...content } });
  const config = { acceptedDefinitions: { [SOUL]: [DIGEST] }, notices: { harnesses: [scope.harness], scopes: [{ soul_id: SOUL, definition_digest: DIGEST, member_id: 'm_lead', role: 'lead', adapter_id: 'fake-adapter', ...scope }] } };
  const setup = async (records = [source()], { mailboxPresent = true, methodsPresent = true, selectionCount = 1 } = {}) => {
    const calls = [];
    let consumed = 0;
    const mailbox = methodsPresent ? {
      async peek(input) { calls.push(['peek', input]); return structuredClone(records.slice(0, input.count)); },
      async consumeOne(input, prepareResult) {
        calls.push(['consume-one', input]);
        const before = consumed;
        const picked = structuredClone(records.slice(0, selectionCount));
        const prepared = prepareResult(picked);
        assert.equal(typeof prepared?.then, 'undefined', 'preparation is synchronous');
        assert.equal(consumed, before, 'full result is prepared before a tombstone');
        if (picked.length) { records.shift(); consumed++; }
        return picked;
      },
    } : {};
    const base = referenceBroker({ name: 'agent-comms' });
    const comms = definePlugin({ ...base, async init(ctx) { const output = await base.init(ctx); return { provides: { ...output.provides, ...(mailboxPresent ? { notices: mailbox } : {}) } }; } });
    const t = await startHQ({ config, enrollment: { ...legacySigner({ run: fakeLegacy().run }), allowsHarness: () => true }, plugins: [comms] });
    const entry = await t.entry();
    const admission = (await entry.request('Hello', hello())).result;
    const [runtime, specialist] = admission.admitted_runtimes;
    const member = await t.member();
    assert.equal((await member.request('bind', { runtime_id: runtime.runtime_id, channel_binding: runtime.channel_binding })).ok, true);
    const query = (operation = 'peek', extra = {}) => ({ contract: 'hq/v1', request_id: 'notice_query:1', operation, required_capabilities: ['notices-v1'], installation_epoch: admission.installation_epoch, lease_generation: admission.lease_generation, ...extra });
    return { ...t, calls, records, entry, peer: member, runtime, specialist, query, consumed: () => consumed };
  };
  const errorCode = (response) => response.refusal?.error ?? response.host_refusal?.code;

  test('reviewed shared notice fixture schemas have their exact expected verdict', () => {
    assert.ok(fixtures.length >= 35);
    for (const [name, fixture] of fixtures) {
      const key = fixture.schema.endsWith('notice-query.schema.json') ? 'notice-query' : 'notice-result';
      assert.equal(validate(schemas[key], fixture.input).length ? 'invalid' : 'valid', fixture.expect.schema, name);
    }
  });

  test('bound broker query delegates only frozen scope, preserves correlation, and consumes once locally', async () => {
    const t = await setup();
    try {
      const peek = await t.peer.request('notices.peek', t.query());
      assert.equal(peek.ok, true, JSON.stringify(peek));
      assert.equal(peek.result.request_id, 'notice_query:1');
      assert.equal(peek.result.operation, 'peek');
      assert.deepEqual(peek.result.required_capabilities, ['notices-v1']);
      assert.deepEqual(peek.result.notices, [source()]);
      assert.equal(t.consumed(), 0);
      assert.deepEqual(t.calls[0], ['peek', { ...scope, count: 1 }]);
      const one = await t.peer.request('notices.consume-one', t.query('consume-one'));
      assert.equal(one.ok, true, JSON.stringify(one));
      assert.deepEqual(one.result.notices, [source()]);
      assert.equal(t.consumed(), 1);
      assert.deepEqual(t.calls[1], ['consume-one', scope]);
      const empty = await t.peer.request('notices.consume-one', t.query('consume-one'));
      assert.equal(empty.ok, true, JSON.stringify(empty));
      assert.deepEqual(empty.result.notices, []);
      assert.equal(t.consumed(), 1, 'request_id is correlation only; no replay cache or upstream fallback');
    } finally { await t.done(); }
  });

  test('protocol, schema, selector and operation checks refuse before any mailbox call', async () => {
    const t = await setup();
    try {
      const cases = [
        ['notices.peek', { contract: 'hq/v2' }, 'unsupported_version'],
        ['notices.peek', { required_capabilities: ['unknown-v1'] }, 'required_capability_missing'],
        ['notices.peek', { required_capabilities: [] }, 'required_capability_missing'],
        ['notices.peek', { required_capabilities: null }, 'required_capability_missing'],
        ['notices.peek', { operation: 'consume-one' }, 'caller_mismatch'],
        ['notices.consume-one', { operation: 'peek' }, 'caller_mismatch'],
        ['notices.consume-one', { operation: 'consume-one', count: 2 }, 'host.invalid_request'],
        ...['harness', 'repo', 'runtime_id', 'app', 'notice_scope'].map((field) => ['notices.peek', { [field]: 'override' }, 'host.invalid_request']),
        ['notices.peek', { request_id: 'query\n' }, 'host.invalid_request'],
        ['notices.peek', { expected_repository: 'Example/Project\n' }, 'host.invalid_request'],
        ['notices.peek', { expected_repository: 'another/repo' }, 'caller_mismatch'],
        ['notices.peek', { installation_epoch: 99 }, 'stale_epoch'],
        ['notices.peek', { lease_generation: 99 }, 'lease_expired'],
      ];
      for (const [kind, extra, code] of cases) assert.equal(errorCode(await t.peer.request(kind, t.query('peek', extra))), code, JSON.stringify(extra));
      assert.equal(t.calls.length, 0);
      assert.equal(t.consumed(), 0);
    } finally { await t.done(); }
  });

  test('unmapped, superseded and expired bound callers cannot reach the mailbox', async () => {
    const t = await setup();
    try {
      const other = await t.member();
      await other.request('bind', { runtime_id: t.specialist.runtime_id, channel_binding: t.specialist.channel_binding });
      assert.equal(errorCode(await other.request('notices.peek', t.query())), 'caller_mismatch');
      const fresh = (await t.entry.request('Hello', hello({ request_id: 'req_new' }))).result;
      assert.equal(errorCode(await t.peer.request('notices.peek', t.query())), 'lease_expired');
      const member = await t.member();
      await member.request('bind', { runtime_id: fresh.admitted_runtimes[0].runtime_id, channel_binding: fresh.admitted_runtimes[0].channel_binding });
      t.clock.advance(60_001);
      assert.equal(errorCode(await member.request('notices.peek', t.query('peek', { installation_epoch: fresh.installation_epoch, lease_generation: fresh.lease_generation }))), 'lease_expired');
      assert.equal(t.calls.length, 0);
    } finally { await t.done(); }
  });

  test('missing scoped mailbox refuses explicitly and has no upstream fallback', async () => {
    for (const options of [{ mailboxPresent: false }, { methodsPresent: false }]) {
      const t = await setup([], options);
      try { assert.equal(errorCode(await t.peer.request('notices.consume-one', t.query('consume-one'))), 'host.plugin_degraded'); assert.equal(t.calls.length, 0); } finally { await t.done(); }
    }
  });

  test('invalid mailbox records and oversized source refuse inside preparation before consumption', async () => {
    const sharedInvalid = fixtures.filter(([name, x]) => !name.includes('consume-many') && x.schema.endsWith('notice-result.schema.json') && (x.expect.schema === 'invalid' || x.expect.rule === 'notice-source-byte-limit'));
    assert.ok(sharedInvalid.length >= 10);
    for (const [name, fixture] of sharedInvalid) {
      const t = await setup(structuredClone(fixture.input.notices));
      try {
        const response = await t.peer.request('notices.consume-one', t.query('consume-one'));
        assert.equal(response.ok, false, name);
        assert.equal(t.consumed(), 0, name);
        assert.equal(t.records.length, fixture.input.notices.length, name);
      } finally { await t.done(); }
    }
    const many = await setup([source(), source('notice:2')], { selectionCount: 2 });
    try { assert.equal(errorCode(await many.peer.request('notices.consume-one', many.query('consume-one'))), 'host.invalid_request'); assert.equal(many.consumed(), 0); assert.equal(many.records.length, 2); } finally { await many.done(); }
    const t = await setup([source('notice:outside', { repo: 'other/repo' })]);
    try { assert.equal(errorCode(await t.peer.request('notices.consume-one', t.query('consume-one'))), 'caller_mismatch'); assert.equal(t.consumed(), 0); } finally { await t.done(); }
  });

  test('source byte boundary is inclusive and new envelope metadata does not consume source budget', async () => {
    const empty = source('notice:limit', { text: '' });
    const overhead = canonicalBytes({ id: empty.message_id, ...empty.content }).length;
    for (const extra of [0, 1]) {
      const record = source('notice:limit', { text: 'x'.repeat(65_536 - overhead + extra) });
      const t = await setup([record]);
      try {
        const response = await t.peer.request('notices.consume-one', t.query('consume-one'));
        if (extra) { assert.equal(errorCode(response), 'frame_too_large'); assert.equal(t.consumed(), 0); }
        else { assert.equal(response.ok, true, JSON.stringify(response)); assert.equal(t.consumed(), 1); assert.ok(canonicalBytes(response.result).length > 65_536); }
      } finally { await t.done(); }
    }
  });

  test('full-result budget trims read-only peek without consuming or truncating individual content', async () => {
    const records = Array.from({ length: 12 }, (_, index) => source(`notice:${index}`, { text: 'λ'.repeat(30_000) }));
    const t = await setup(records);
    try {
      const response = await t.peer.request('notices.peek', t.query('peek', { count: 12 }));
      assert.equal(response.ok, true, JSON.stringify(response));
      assert.ok(response.result.notices.length > 0 && response.result.notices.length < 12);
      assert.ok(canonicalBytes(response.result).length <= 524_288);
      assert.equal(response.result.notices[0].content.text.length, 30_000);
      assert.equal(t.records.length, 12);
      assert.equal(t.consumed(), 0);
      const first = await t.peer.request('notices.consume-one', t.query('consume-one'));
      assert.equal(first.ok, true, JSON.stringify(first));
      assert.equal(t.consumed(), 1);
    } finally { await t.done(); }
  });
}
