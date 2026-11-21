// Driven by the issuer's disposable e2e harness. Each process opens one session.
// Only its public session key leaves this software custodian.
import assert from 'node:assert/strict';
import { createInterface } from 'node:readline';
import { createIdentityService } from '../hq/identity-service.mjs';
import { testSessionCustody } from './identity-service-fixture.mjs';

const pipe = createInterface({ input: process.stdin, crlfDelay: Infinity });
const lines = pipe[Symbol.asyncIterator]();
const read = async () => JSON.parse((await lines.next()).value);
const { server, now, key, expected } = await read();
assert.match(server, /^http:\/\/127\.0\.0\.1:[0-9]+$/);
const urls = expected.map(row => server + '/api/daemon/issuances/' + row.operation_id);
const requests = [];
const clock = { now: () => now };
const custody = testSessionCustody({
  server, clock,
  async assertion({ ephemeralJwk }) {
    process.stdout.write(JSON.stringify(ephemeralJwk) + '\n');
    return read();
  },
});
const client = createIdentityService({
  server, clock, custody, enrollment: { deviceStatus: async () => 'enrolled' },
  keySet: [{ ...key, status: 'active', notBefore: new Date(now - 60000).toISOString(), notAfter: new Date(now + 900000).toISOString() }],
  fetchImpl(url, init) {
    const i = requests.length;
    assert.equal(url, i === 0 ? server + '/oauth/token' : urls[i - 1]);
    assert.equal(init.method, i === 0 ? 'POST' : 'GET');
    if (i > 0) assert.equal(init.body, undefined);
    requests.push(url);
    return fetch(url, init);
  },
});
try {
  for (const row of expected) {
    const response = await client.call('GET', '/api/daemon/issuances/' + row.operation_id);
    assert.equal(response.status, 200);
    assert.deepEqual(Object.keys(response.body).sort(), Object.keys(row).sort());
    for (const [name, value] of Object.entries(row)) assert.equal(response.body[name], value);
  }
  assert.equal(requests.length, 1 + expected.length);
  process.stdout.write('verified\n');
} finally {
  client.close();
  pipe.close();
}
