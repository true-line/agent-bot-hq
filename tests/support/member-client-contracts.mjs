// Real digest-verified shared records for SDK socket/bootstrap tests.
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { validate } from '../../sdk/wire/schema.mjs';
import { contracts as directory } from '../hq-harness.mjs';

const definitions = new Map();
export const contracts = Object.freeze({
  record(path, value) {
    if (!definitions.has(path)) definitions.set(path, JSON.parse(readFileSync(join(directory, 'schemas', path), 'utf8')));
    if (validate(definitions.get(path), value).length) throw new Error(`invalid shared record: ${path}`);
    return value;
  },
  admission(result, request) {
    this.record('hq/v1/admission-result.schema.json', result);
    assert.equal(result.request_id, request.request_id);
  },
});
