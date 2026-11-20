// Child of the private Darwin socket fixture. Both fds refer to the manager's
// one listener; the Ruby parent retains it while this service instance exits.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { once } from 'node:events';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';
import { authenticateOwner, prepareOwnerListener } from '../hq/owner-control.mjs';
import { listenSocket } from '../hq/socket.mjs';

const [path, name, expected] = process.argv.slice(2);
const helper = fileURLToPath(new URL('../helpers/darwin-owner.rb', import.meta.url));
const verify = () => promisify(execFile)('/usr/bin/ruby', ['--disable-gems', '-r', helper,
  '-e', 'exit(published_peer?(ARGV.fetch(0), ARGV.fetch(1)))', path, name], { timeout: 2000 }).then(() => true, () => false);
if (expected === 'refused') {
  await assert.rejects(prepareOwnerListener(4, verify), /does not match/);
} else {
  const listener = await prepareOwnerListener(4, verify);
  const endpoint = await listenSocket({
    path, auth: 'owner', core: {}, newSession: () => 'session', endSession: () => {},
    dispatch: (operation) => { assert.equal(operation, 'status'); return { ready: true }; },
    activated: { fd: 3, listener, authenticate: (socket) => authenticateOwner(socket, process.getuid()) },
  });
  // The parent sends a newline after all of its pending requests completed.
  process.stdin.resume();
  await once(process.stdin, 'data');
  await endpoint.close();
  process.stdin.destroy();
}
