import assert from 'node:assert/strict';
import { once } from 'node:events';
import { mkdtempSync, rmSync } from 'node:fs';
import { createConnection } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { test } from 'node:test';
import { checkDarwinACL, DARWIN_HARNESS_DIR as dir, resolveDarwinHarness } from '../hq/darwin-harness-accounts.mjs';
import { planHarnessEndpoints } from '../hq/harness-accounts.mjs';
import { authenticatePeerUid } from '../hq/owner-control.mjs';
import { checkSocketPath, connectSocket, listenSocket } from '../hq/socket.mjs';

const account = 'hqm_a';
const home = `/var/agent-bot-harness-${account}`;

function directoryService({ additionalPrimary = '', nested = [], hiddenAttribute = 'native', standardHidden } = {}) {
  const user = { RecordName: [account], RealName: ['Agent Bot Harness'], UniqueID: ['350'], PrimaryGroupID: ['350'],
    IsHidden: ['1'], UserShell: ['/usr/bin/false'], NFSHomeDirectory: [home] };
  const group = { RecordName: [account], PrimaryGroupID: ['350'], NestedGroups: nested };
  return (file, args, input) => {
    if (file === '/usr/bin/id') { assert.deepEqual(args, ['-u', account]); return '350\n'; }
    if (file === '/usr/bin/plutil') return input;
    assert.equal(file, '/usr/bin/dscl');
    if (args[1] === '-list') return `${account} 350\n${args[2] === '/Users' && args[3] === 'PrimaryGroupID' ? additionalPrimary : ''}`;
    assert.deepEqual(args.slice(0, 3), ['-plist', '.', '-read']);
    const record = args[3] === `/Users/${account}` ? user : group;
    // Local dscl -plist retains IsHidden under its native namespace. Other
    // attributes of the same account, such as RealName, are standard.
    const attributes = Object.fromEntries(Object.entries(record).map(([key, value]) => [
      key === 'IsHidden' && hiddenAttribute === 'native' ? 'dsAttrTypeNative:IsHidden' : `dsAttrTypeStandard:${key}`, value,
    ]));
    if (record === user && standardHidden) attributes['dsAttrTypeStandard:IsHidden'] = [standardHidden];
    return JSON.stringify(attributes);
  };
}

test('Darwin resolves the local Machine role and verifies its private primary group', () => {
  assert.deepEqual(resolveDarwinHarness(account, { run: directoryService() }), { uid: 350, gid: 350, groupMembers: [], home });
  for (const change of [{ hiddenAttribute: 'standard' }, { standardHidden: '1' }]) {
    assert.equal(resolveDarwinHarness(account, { run: directoryService(change) }).uid, 350);
  }
  for (const change of [{ standardHidden: '0' }, { additionalPrimary: 'second account 350\n' }, { nested: ['other-group'] }]) {
    assert.throws(() => resolveDarwinHarness(account, { run: directoryService(change) }), /own uid, private group and home/);
  }
});

test('Darwin plans exactly one broker for adapters on the same managed account', () => {
  const paths = new Map([['/', [0, 0, 0o755]], ['/Library', [0, 0, 0o755]], ['/Library/Application Support', [0, 80, 0o755]],
    [dirname(dir), [0, 0, 0o755]], [dir, [0, 0, 0o755]], [join(dir, account), [349, 350, 0o2750]], [home, [350, 350, 0o700]]]);
  const lstat = (path) => {
    const [uid, gid, mode] = paths.get(path);
    return { uid, gid, mode, isDirectory: () => true, isSymbolicLink: () => false };
  };
  const checked = [];
  const opts = { platform: 'darwin', hqAccount: '_agent-bot-hq', hqUid: 349, lstat, checkACL: (p) => checked.push(p),
    resolve: (name) => resolveDarwinHarness(name, { run: directoryService() }) };
  const config = { dir, accounts: { alpha: account, beta: account } };
  const { endpoints, accountOf } = planHarnessEndpoints(config, opts);
  assert.deepEqual(endpoints, [{ account, uid: 350, gid: 350, home, path: join(dir, account, 'broker.sock'), adapters: ['alpha', 'beta'] }]);
  assert.equal(accountOf('beta'), endpoints[0]);
  assert.deepEqual(checked, [...paths.keys()]);
  assert.throws(() => planHarnessEndpoints(config, { ...opts, hqAccount: 'ordinary' }), /dedicated HQ account/);
  assert.throws(() => planHarnessEndpoints({ accounts: config.accounts }, opts), /explicit directory/);
  assert.throws(() => planHarnessEndpoints({ ...config, dir: '/run/other' }, opts), /explicit directory/);
  paths.set(dir, [349, 0, 0o755]);
  assert.throws(() => planHarnessEndpoints(config, opts), /untrusted Darwin harness directory/);
  checkSocketPath(join(dir, 'a'.repeat(32), 'broker.sock'), 'darwin');
});

test('Darwin accepts no ACL or a deny-only ACL on managed paths', () => {
  const inspect = (acl) => checkDarwinACL(dir, () => `directory metadata\n${acl}`);
  inspect(''); inspect(' 0: group:everyone deny delete\n');
  assert.throws(() => inspect(' 0: group:everyone allow add_file\n'), /unexpected access/);
});

test('a Darwin broker verifies every socket peer before starting a session or reading a frame', { skip: process.platform !== 'darwin' }, async (t) => {
  const scratch = mkdtempSync(join(tmpdir(), 'hqb-'));
  t.after(() => rmSync(scratch, { recursive: true, force: true }));
  const path = join(scratch, 'broker.sock');
  let expected = process.getuid();
  let checked = 0, sessions = 0, frames = 0;
  const server = await listenSocket({ path, auth: 'member',
    authenticatePeer: async (socket) => { checked++; return authenticatePeerUid(socket, expected); },
    newSession: () => { sessions++; return 'test-connection'; }, endSession: () => {},
    dispatch: () => { frames++; return 'ok'; },
  });
  t.after(() => server.close());
  const client = await connectSocket(path);
  assert.equal((await client.request('ping', {})).result, 'ok');
  client.close();
  expected++;
  const other = createConnection(path);
  const closed = new Promise((resolve) => other.once('close', resolve));
  other.on('error', () => {});
  await once(other, 'connect');
  other.write(JSON.stringify({ id: 1, op: 'ping', payload: {} }) + '\n');
  await closed;
  assert.deepEqual([checked, sessions, frames], [2, 1, 1]);
});
