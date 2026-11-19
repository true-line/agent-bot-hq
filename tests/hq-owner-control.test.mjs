import assert from 'node:assert/strict';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { mkdtempSync, rmSync } from 'node:fs';
import { createConnection, createServer } from 'node:net';
import { once } from 'node:events';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { authenticateOwner, checkOwnerControlSupport } from '../hq/owner-control.mjs';

test('owner control compares the connected peer UID with the configured owner', { skip: !['linux', 'darwin'].includes(process.platform) }, async (t) => {
  checkOwnerControlSupport();
  const dir = mkdtempSync(join(tmpdir(), 'hq-peer-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const path = join(dir, 'peer.sock');
  const server = createServer().listen(path);
  await once(server, 'listening');
  try {
    const connected = once(server, 'connection');
    const client = createConnection(path);
    const [peer] = await connected;
    try {
      assert.equal(await authenticateOwner(peer, process.getuid()), true);
      assert.equal(await authenticateOwner(peer, process.getuid() + 1), false);
    } finally {
      peer.destroy();
      client.destroy();
    }
  } finally { await new Promise((resolve) => server.close(resolve)); }
});

test('Darwin matches a renamed listener to the published socket with a bounded probe', { skip: process.platform !== 'darwin' }, () => {
  execFileSync('/usr/bin/ruby', ['--disable-gems', fileURLToPath(new URL('darwin-owner-listener.rb', import.meta.url))], { timeout: 5000 });
});
