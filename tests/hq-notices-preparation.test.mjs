// The notice consumer cannot activate from the current contract release pin.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { noticesPlugin } from '../hq/notices.mjs';
import { schemas, startHQ } from './hq-harness.mjs';
import { referenceBroker } from './broker-fixture.mjs';

test('notice consumer requires its shared schemas; no permissive replacement is supplied', () => {
  assert.throws(() => noticesPlugin(), /pinned hq\/v1 notice-query schema/);
  assert.throws(() => noticesPlugin({ schemas }), /pinned hq\/v1 notice-query schema/);
});

test('default HQ does not register prepared notice consumers', async () => {
  const t = await startHQ({ plugins: [referenceBroker()] });
  try {
    assert.equal(t.hq.host.registrations().kinds.some(({ key }) => key.startsWith('notices.')), false);
  } finally { await t.done(); }
});
