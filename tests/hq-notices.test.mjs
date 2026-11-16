import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { noticesPlugin } from '../hq/notices.mjs';
import { contracts, schemas, hello, startHQ } from './hq-harness.mjs';
import { referenceBroker } from './broker-fixture.mjs';
import { registerNoticeConsumerCases } from './support/notice-consumer-cases.mjs';

const fixtures = ['positive', 'negative'].flatMap((kind) => readdirSync(join(contracts, 'fixtures', kind))
  .filter((name) => /^notice-.*\.json$/.test(name))
  .map((name) => [`${kind}/${name}`, JSON.parse(readFileSync(join(contracts, 'fixtures', kind, name), 'utf8'))]));
registerNoticeConsumerCases(schemas, fixtures);

test('notice factory requires released schemas and default HQ registers guarded notice kinds', async () => {
  assert.throws(() => noticesPlugin(), /pinned hq\/v1 notice-query schema/);
  assert.throws(() => noticesPlugin({ schemas: { 'notice-query': schemas['notice-query'] } }), /pinned hq\/v1 notice-result schema/);
  const t = await startHQ({ plugins: [referenceBroker({ name: 'agent-comms' })] });
  try {
    assert.deepEqual(t.hq.host.registrations().kinds.filter(({ key }) => key.startsWith('notices.')).map(({ key }) => key).sort(), ['notices.consume-one', 'notices.peek']);
    const entry = await t.entry();
    const admitted = await entry.request('Hello', hello());
    assert.equal(admitted.ok, true);
    const a = admitted.result;
    const peer = await t.member();
    const r = a.admitted_runtimes[0];
    assert.equal((await peer.request('bind', { runtime_id: r.runtime_id, channel_binding: r.channel_binding })).ok, true);
    const response = await peer.request('notices.peek', { contract: 'hq/v1', request_id: 'no_scope', operation: 'peek', required_capabilities: ['notices-v1'], installation_epoch: a.installation_epoch, lease_generation: a.lease_generation });
    assert.equal(response.refusal.error, 'caller_mismatch');
  } finally { await t.done(); }
});
