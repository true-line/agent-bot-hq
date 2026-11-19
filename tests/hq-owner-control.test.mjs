import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
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

test('Darwin preserves pending owner status requests across listener restarts', { skip: process.platform !== 'darwin' }, () => {
  execFileSync('/usr/bin/ruby', ['--disable-gems', fileURLToPath(new URL('darwin-owner-restart.rb', import.meta.url)), process.execPath], { timeout: 20000 });
});

test('Darwin reports only versioned launch failures and keeps ordinary CLI exits', { skip: process.platform !== 'darwin' }, () => {
  const helper = fileURLToPath(new URL('../helpers/darwin-owner.rb', import.meta.url));
  const entry = fileURLToPath(new URL('../hq/main.mjs', import.meta.url));
  execFileSync('/usr/bin/ruby', ['--disable-gems', fileURLToPath(new URL('darwin-owner-exits.rb', import.meta.url))]);
  const status = (error, expected) => error.status === expected && !error.stderr.includes('private-probe-marker');
  assert.throws(() => execFileSync('/usr/bin/ruby', ['--disable-gems', helper, 'launch', 'private-probe-marker'], { stdio: 'pipe' }), (e) => status(e, 80));
  assert.deepEqual(JSON.parse(execFileSync(process.execPath, [entry, 'check-owner-control'])), {
    capability: 'darwin-owner-control/v1', launch_diagnostics: 'darwin-hq-launch-exits/v1',
  });
  // Invalid account syntax fails before any socket access. In an explicitly
  // marked launch, the post-exec activation boundary has its own status.
  const argv = ['run', '--owner-account', 'private-probe-marker!'];
  const ordinary = spawnSync(process.execPath, [entry, ...argv], { encoding: 'utf8', env: {} });
  assert.equal(ordinary.status, 1);
  const launcher = 'process.env.HQ_LAUNCHD_OWNER_PID=String(process.pid); await import(process.argv[1]);';
  const launched = spawnSync(process.execPath, ['--input-type=module', '-e', launcher, entry, ...argv], { encoding: 'utf8', env: {} });
  assert.equal(launched.status, 87);
  assert.equal(launched.stderr.trim(), 'HQ could not activate the inherited macOS owner-control listener');
});
