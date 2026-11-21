// Component fixture only. The parent passes two prepared listeners; normal
// Darwin harness provisioning and start remain separate Stage 2a work.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { lstatSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { admissionPlugin } from '../hq/admission.mjs';
import { checkHarnessSocket } from '../hq/harness-accounts.mjs';
import { authenticateOwner } from '../hq/owner-control.mjs';
import { connectSocket, listenSocket } from '../hq/socket.mjs';
import { createTestHost } from '../sdk/test-host.mjs';
import { referenceBroker } from './broker-fixture.mjs';
import { DIGEST, helloOn, schemas, SOUL } from './hq-harness.mjs';

const [dir, records] = process.argv.slice(2);
const endpoints = JSON.parse(records);
assert.equal(endpoints.length, 2);
assert.equal(new Set([process.getuid(), ...endpoints.map(e => e.uid)]).size, 3);
const accounts = new Map([['adapter-a', endpoints[0]], ['adapter-b', endpoints[1]]]);
const callers = new Map();
const verified = [];
const host = createTestHost({
  config: { 'hq-admission': { acceptedDefinitions: { [SOUL]: [DIGEST] } } },
  plugins: [admissionPlugin({
    schemas,
    harnessAccount: adapter => accounts.get(adapter),
    callerOf: connection => callers.get(connection),
  }), referenceBroker()],
});

function bindAs(endpoint, runtime) {
  const request = { path: endpoint.path, steps: [{ bind: { runtime_id: runtime.runtime_id, key: runtime.channel_binding } }] };
  return new Promise((resolve, reject) => {
    const child = execFile('/usr/bin/sudo', ['-n', '-H', '-u', endpoint.account, '--',
      process.execPath, join(dir, 'member-client.mjs'), '-'], { timeout: 15_000 }, (err, stdout) => {
      if (err) return reject(new Error('fixture member client failed under its assigned account'));
      try { resolve(JSON.parse(stdout)); } catch (e) { reject(e); }
    });
    child.stdin.on('error', reject);
    child.stdin.end(JSON.stringify(request));
  });
}

const listeners = [];
let admission;
try {
  await host.start();
  const entry = join(dir, 'admission.sock');
  listeners.push(await listenSocket({ path: entry, auth: 'entry-point', core: host.core,
    dispatch: host.dispatch, newSession: () => 'ep_fixture', endSession: () => {} }));
  for (const endpoint of endpoints) {
    const parent = lstatSync(dirname(endpoint.path));
    assert.equal(parent.uid, process.getuid());
    assert.equal(parent.gid, endpoint.gid);
    assert.equal(parent.mode & 0o7777, 0o2750);
    checkHarnessSocket(endpoint);
    listeners.push(await listenSocket({
      path: endpoint.path, auth: 'member', core: host.core,
      activated: { fd: endpoint.fd, authenticate: async socket => {
        const ok = await authenticateOwner(socket, endpoint.uid);
        if (ok) verified.push(endpoint.uid);
        return ok;
      } },
      newSession: () => {
        const connection = 'bc_' + host.core.random.hex(12);
        callers.set(connection, { account: endpoint.account, uid: endpoint.uid });
        return connection;
      },
      dispatch: (kind, { payload, session }) => host.brokerAccept(kind, payload, { connection: session }),
      endSession: connection => { callers.delete(connection); host.brokerClosed(connection); },
    }));
  }
  admission = await connectSocket(entry);
  const hello = await admission.request('Hello', helloOn('adapter-a', 'adapter-b'));
  assert.equal(hello.ok, true);
  assert.equal(hello.result.profile, 'managed-cooperative');
  assert.equal(hello.result.admitted_runtimes.length, 2);
  for (const [role, adapter] of [['lead', 'adapter-a'], ['specialist', 'adapter-b']]) {
    const endpoint = accounts.get(adapter);
    const runtime = hello.result.admitted_runtimes.find(r => r.role === role);
    const row = host.table('hq-admission', 'runtimes')[runtime.runtime_id];
    assert.equal(row.harness_uid, endpoint.uid);
    assert.equal(row.harness_account, endpoint.account);
    const out = await bindAs(endpoint, runtime);
    assert.equal(out.connected, true);
    assert.equal(out.responses.length, 1);
    assert.deepEqual(out.responses[0].result, { member_id: runtime.member_id, role, runtime_id: runtime.runtime_id });
    const receipts = host.receipts().filter(r => r.kind === 'hq.bind' && r.runtime_id === runtime.runtime_id);
    assert.equal(receipts.length, 1);
    assert.equal(receipts[0].caller_account, endpoint.account);
    assert.equal(receipts[0].proof, 'hmac-sha256');
  }
  assert.deepEqual(verified, endpoints.map(e => e.uid));
  console.log('Two distinct macOS harness UIDs passed getpeereid and bound their own admitted runtimes.');
} finally {
  if (admission) await admission.close();
  await Promise.all(listeners.map(listener => listener.close()));
  await host.stop();
}
