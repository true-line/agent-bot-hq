// Node test preload for the unpacked HQ daemon. The ports below select only
// the disposable Unix socket, role home and loopback HTTP peer. The real
// signed channel, Machine identity checks and signer selection run unchanged.
import assert from 'node:assert/strict';
import { dirname, join } from 'node:path';
import { mock } from 'node:test';
import { pathToFileURL } from 'node:url';

// CI uses the registered account and the normal Homebrew Machine socket.
// Only local replay redirects the signed client to a scratch pairing.
if (process.env.HQ_TEST_REGISTERED_LAYOUT !== '1') {
  const fixture = process.env.KEYD_FIXTURE_STATE;
  const channelUrl = pathToFileURL(join(dirname(process.argv[1]), 'machine-channel.mjs'));
  const channel = await import(channelUrl);
  mock.module(channelUrl, { namedExports: { ...channel,
    machineRoleDevice(operation, fields) {
      return channel.machineCommandInHome(['hq-device', operation, '--socket', join(fixture, 'machine.sock')],
        join(fixture, 'role'), process.getuid(), fields);
    },
  } });
}

const local = new URL(process.env.HQ_TEST_ISSUER);
assert.equal(local.protocol, 'http:');
assert.equal(local.hostname, '127.0.0.1');
const fetchLocal = globalThis.fetch;
globalThis.fetch = (url, options) => {
  const target = new URL(url);
  assert.equal(target.origin, 'https://agents.true-line.ai');
  assert.ok([
    '/.well-known/agent-bot-server-key', '/oauth/device_authorization', '/oauth/token', '/api/daemon/whoami',
  ].includes(target.pathname));
  return fetchLocal(new URL(target.pathname, local), { ...options, redirect: 'error' });
};
