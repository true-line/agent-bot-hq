// External source vector from soul-contracts v0.10.3 at
// 896b693b23219444dcbe4af4083fd1bc4b9f178c. This is a source check,
// separate from HQ's installed Contracts selection.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { test } from 'node:test';
import { validLocalTestAncillaryOrder, validLocalTestChildPaths }
  from '../hq/stage2a-local-test-provider.mjs';
import { verifyStage2aMachineEnvelope } from '../hq/stage2a-stop.mjs';
import { canonicalize } from '../sdk/wire/canonical-json.mjs';

const vectorPath = process.env.STAGE2A_C5_PATH_VECTOR;
const vector = vectorPath ? JSON.parse(readFileSync(vectorPath, 'utf8')) : null;
const gitBlobSHA = (bytes) => createHash('sha1')
  .update(Buffer.from(`blob ${bytes.length}\0`)).update(bytes).digest('hex');
const verified = (envelope) => verifyStage2aMachineEnvelope(
  Buffer.from(envelope, 'base64url'), Buffer.from(vector.public_key_base64url, 'base64url'),
  vector.purpose).payload;
const paths = (payload) => ({ runner_account: payload.runner_account,
  expected_child_cwd_lexical: payload.cwd.lexical,
  expected_child_cwd_emitted: payload.cwd.emitted,
  expected_child_home_lexical: payload.home.lexical,
  expected_memory_path_lexical: payload.memory.lexical });
const selectors = (payload) => ({ installation_id: payload.installation_id,
  start_id: payload.start_id });
// Contracts' signed twin uses a neutral memory directory. Translate only that
// directory for the stock HQ path check; the runtime still requires .claude.
const stockPaths = (payload) => ({ ...paths(payload),
  expected_memory_path_lexical: payload.memory.lexical
    .replace('/.fixture/projects/', '/.claude/projects/') });

test('signed c5 per-start path and order source vector',
  { skip: vector?.schema !== 'agent-bot-machine/stage2a-c5-neutral-path-order-vector/v1' }, () => {
    assert.equal(gitBlobSHA(readFileSync(vectorPath)),
      '4360da4d3faae07009637bf5d49cb737d51b5220');
    const positive = verified(vector.positive_envelope_base64url);
    assert.equal(canonicalize(positive), vector.positive_payload_jcs);
    assert.equal(vector.source_c5_sha256,
      'sha256:9ed32dfb54df653d2ec1d1a11f979275f90e0705736edaa8d8bfacc2e12de8d2');
    assert.equal(positive.schema, 'agent-bot-machine/stage2a-child-path-binding-local-test/v1');
    assert.equal(positive.kind, 'stage2a-child-path-binding-local-test');
    assert.equal(positive.schema_version, 1);
    assert.deepEqual(Object.keys(positive).sort(), ['schema', 'kind', 'schema_version',
      'installation_id', 'start_id', 'runner_account', 'runner_home_lexical',
      'start_slot', 'cwd', 'home', 'memory', 'ancillary_order', 'target_after',
      'issued_at', 'expires_at'].sort());
    assert.equal(positive.start_slot, vector.start_slot);
    assert.equal(vector.slot_preimage_utf8,
      `agent-bot-soul-endpoint-start/v1\0${positive.installation_id}\0${positive.start_id}`);
    assert.equal(Buffer.from(vector.slot_preimage_hex, 'hex').toString('utf8'),
      vector.slot_preimage_utf8);
    assert.equal(createHash('sha256').update(Buffer.from(vector.slot_preimage_hex, 'hex'))
      .digest('hex').slice(0, 20), positive.start_slot);
    assert.equal(positive.memory.lexical.includes('/.fixture/projects/'), true);
    assert.equal(validLocalTestChildPaths(paths(positive), selectors(positive)), false);
    assert.equal(validLocalTestChildPaths(stockPaths(positive), selectors(positive)), true);
    const wrongSlot = Object.fromEntries(Object.entries(stockPaths(positive))
      .map(([key, value]) => [key, typeof value === 'string'
        ? value.replaceAll(positive.start_slot, 'f'.repeat(20)) : value]));
    assert.equal(validLocalTestChildPaths(wrongSlot, selectors(positive)), false);
    assert.equal(validLocalTestChildPaths({ ...stockPaths(positive),
      expected_memory_path_lexical: stockPaths(positive).expected_memory_path_lexical
        .replace('runner--abm', 'runner-_abm') }, selectors(positive)), false);
    assert.equal(positive.home.emitted, `/private${positive.home.lexical}`);
    assert.equal(positive.memory.emitted, `/private${positive.memory.lexical}`);
    assert.equal(validLocalTestAncillaryOrder(positive.ancillary_order,
      positive.target_after), true);
    assert.deepEqual(vector.accepted_sequences, ['A,B,T', 'A,T,B']);
    assert.deepEqual(vector.rejected_sequences, ['T,A,B', 'T,B,A']);

    const stale = verified(vector.stale_c4_envelope_base64url);
    assert.equal(validLocalTestChildPaths(stockPaths(stale), selectors(stale)), false);

    const targetFirst = verified(vector.target_first_envelope_base64url);
    assert.equal(validLocalTestChildPaths(stockPaths(targetFirst), selectors(targetFirst)), true);
    assert.equal(validLocalTestAncillaryOrder(targetFirst.ancillary_order,
      targetFirst.target_after), false);
  });
