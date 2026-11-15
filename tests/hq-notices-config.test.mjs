// Owner-written notice queues reach only the comms plugin's config section.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import { definePlugin } from '../sdk/plugin.mjs';
import { validateConfig } from '../hq/hq.mjs';
import { DIGEST, SOUL, startHQ } from './hq-harness.mjs';

const notices = { harnesses: ['test-codex-agent'], pollIntervalMs: 5000, count: 5, leaseSeconds: 60, wakeClass: 'notify', maxMessages: 50, maxBytes: 65536, retentionMs: 8 * 24 * 60 * 60 * 1000 };

test('notice config accepts only explicit bounded queues and non-executing wake classes', () => {
  assert.deepEqual(validateConfig({ notices }), { notices });
  for (const bad of [null, [], {}, { harnesses: [] }, { harnesses: ['a', 'a'] }, { harnesses: ['a/b'] }, { harnesses: ['a'], unknown: true }, { harnesses: ['a'], wakeClass: 'cold-start' }, { harnesses: ['a'], count: 51 }, { harnesses: ['a'], pollIntervalMs: 0 }, { harnesses: ['a'], leaseSeconds: 9 }, { harnesses: ['a'], maxMessages: 0 }, { harnesses: ['a'], maxBytes: 42 }, { harnesses: ['a'], retentionMs: 60_000 }]) assert.throws(() => validateConfig({ notices: bad }));
});

test('HQ passes the owner configuration to comms, and leaves ingestion disabled by default', async () => {
  const comms = definePlugin({ name: 'agent-comms', version: '1.0.0', hostApi: 1, services: ['config'], async init(ctx) { return { provides: { notices: () => ctx.services.config.get('notices') } }; } });
  for (const config of [{}, { notices }]) {
    const t = await startHQ({ config, plugins: [comms] });
    try { assert.deepEqual(t.hq.host.provided('agent-comms').notices(), config.notices ?? null); } finally { await t.done(); }
  }
});

test('HQ keeps exact notice assignments out of the comms ingestion configuration', async () => {
  const scopes = [{ soul_id: SOUL, definition_digest: DIGEST, member_id: 'm_lead', adapter_id: 'fake-adapter', role: 'lead', harness: 'test-codex-agent', repo: 'true-line/agent-bot-hq' }];
  const comms = definePlugin({ name: 'agent-comms', version: '1.0.0', hostApi: 1, services: ['config'], async init(ctx) { return { provides: { notices: () => ctx.services.config.get('notices') } }; } });
  const t = await startHQ({ config: { notices: { ...notices, scopes } }, plugins: [comms] });
  try { assert.deepEqual(t.hq.host.provided('agent-comms').notices(), notices); } finally { await t.done(); }
});
