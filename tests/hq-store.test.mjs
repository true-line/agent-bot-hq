// HQ's durable store (hq/store.mjs): committed writes survive a reopen, the
// state directory and file are private, a failed persist rolls the write
// back, and an unreadable store is refused rather than overwritten.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import { createHash } from 'node:crypto';
import { syncBuiltinESMExports } from 'node:module';
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { createCore, bindServices } from '../sdk/services.mjs';
import { coreTable, openStore, StoreError, STORE_FORMAT } from '../hq/store.mjs';
import { tempHome } from './hq-harness.mjs';

const plugin = { name: 'p', services: ['store', 'receipts'], identityServiceRoutes: [] };

function configureStore(dir) {
  const store = openStore(dir);
  const core = createCore({
    persist: () => store.persist(),
    persistReceipt: entry => store.persistReceipt(entry),
    persistPluginWrite: store.persistPluginWrite,
  });
  return { store, core };
}

function open(dir) {
  const { store, core } = configureStore(dir);
  store.load(core);
  core.phases.set('p', 'running');
  return { store, core, services: bindServices(core, plugin) };
}

test('committed tables, blobs and receipts survive a reopen; the file is 0600', async () => {
  const dir = tempHome();
  try {
    const a = open(dir);
    await a.services.store.tx((tx) => tx.put('rows', 'k', { v: 1 }));
    const digest = await a.services.store.blob.put(Buffer.from('hello'));
    await a.services.receipts.append({ kind: 'test' });
    assert.equal(statSync(join(dir, 'store.json')).mode & 0o777, 0o600);

    const b = open(dir);
    assert.deepEqual(await b.services.store.tx((tx) => tx.get('rows', 'k')), { v: 1 });
    assert.equal((await b.services.store.blob.get(digest)).toString(), 'hello');
    assert.equal(b.core.receipts.length, 1);
    assert.equal(b.core.receipts[0].kind, 'test');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a large receipt history reopens in order and accepts another append', async () => {
  const dir = tempHome();
  try {
    const receipts = Array.from({ length: 200_000 }, (_, sequence) => ({ kind: 'audit', sequence, note: 'café' }));
    const path = join(dir, 'store.json');
    writeFileSync(path, JSON.stringify({ format: STORE_FORMAT, tables: [], blobs: [], receipts }), { mode: 0o600 });

    const { store, core } = configureStore(dir);
    const original = core.receipts;
    assert.equal(store.load(core).receipts, receipts.length);
    assert.strictEqual(core.receipts, original);
    assert.deepEqual(core.receipts, receipts);
    core.phases.set('p', 'running');
    assert.equal(await bindServices(core, plugin).receipts.append({ kind: 'tail' }), receipts.length + 1);
    assert.equal(statSync(path).mode & 0o777, 0o600);

    const reopened = open(dir);
    assert.equal(reopened.core.receipts.length, receipts.length + 1);
    assert.deepEqual(reopened.core.receipts.slice(0, -1), receipts);
    assert.equal(reopened.core.receipts.at(-1).kind, 'tail');
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a rolled-back transaction writes nothing to disk', async () => {
  const dir = tempHome();
  try {
    const a = open(dir);
    await a.services.store.tx((tx) => tx.put('rows', 'k', { v: 1 }));
    await assert.rejects(a.services.store.tx((tx) => { tx.put('rows', 'k', { v: 2 }); throw new Error('abort'); }), /abort/);
    const b = open(dir);
    assert.deepEqual(await b.services.store.tx((tx) => tx.get('rows', 'k')), { v: 1 });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a failed persist rolls the write back in memory and raises', async () => {
  const core = createCore({ persist: async () => { throw new Error('disk full'); } });
  core.phases.set('p', 'running');
  const services = bindServices(core, plugin);
  await assert.rejects(services.store.tx((tx) => tx.put('rows', 'k', { v: 1 })), /disk full/);
  assert.equal(await services.store.tx((tx) => tx.get('rows', 'k')), undefined);
  await assert.rejects(services.receipts.append({ kind: 'x' }), /disk full/);
  assert.equal(core.receipts.length, 0);
});

function failPublication(t, store, attempt) {
  const rename = fs.renameSync;
  let writes = 0;
  t.mock.method(fs, 'renameSync', (from, to) => {
    if (to === store.path && ++writes === attempt) throw new Error('fixture write failed');
    return rename(from, to);
  });
  syncBuiltinESMExports();
  return () => { t.mock.restoreAll(); syncBuiltinESMExports(); };
}

const receiptValues = core => core.receipts.map(({ kind, seq }) => [kind, seq]);

for (const attempt of [1, 2]) test(`overlapping receipts remain consistent when write ${attempt} fails`, async (t) => {
  const dir = tempHome();
  const { store, core, services } = open(dir);
  const restore = failPublication(t, store, attempt);
  try {
    const pending = ['first', 'second'].map(kind => services.receipts.append({ kind }));
    assert.deepEqual(core.receipts, [], 'uncommitted receipts must not be visible');
    const results = await Promise.allSettled(pending);
    const kept = attempt === 1 ? 'second' : 'first';
    assert.match(results[attempt - 1].reason.message, /fixture write failed/);
    assert.deepEqual(results[2 - attempt], { status: 'fulfilled', value: 1 });
    assert.deepEqual(receiptValues(core), [[kept, 1]]);
    assert.deepEqual(receiptValues(open(dir).core), [[kept, 1]]);
    assert.equal(await services.receipts.append({ kind: 'next' }), 2);
    const reopened = open(dir);
    assert.deepEqual(receiptValues(reopened.core), [[kept, 1], ['next', 2]]);
    assert.equal(await reopened.services.receipts.append({ kind: 'reopened' }), 3);
  } finally {
    restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('an earlier unrelated state snapshot never saves a later rejected receipt', async (t) => {
  const dir = tempHome();
  const { store, core, services } = open(dir);
  const restore = failPublication(t, store, 2);
  try {
    coreTable(core, 'sample').set('written', true);
    const state = store.persist();
    const receipt = services.receipts.append({ kind: 'rejected' });
    await Promise.all([state, assert.rejects(receipt, /fixture write failed/)]);
    const reopened = open(dir);
    assert.equal(coreTable(reopened.core, 'sample').get('written'), true);
    assert.deepEqual(reopened.core.receipts, []);
    assert.equal(await reopened.services.receipts.append({ kind: 'next' }), 1);
  } finally {
    restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

function blobDigest(bytes) {
  return `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
}

for (const kind of ['blob', 'table']) {
  for (const order of ['before', 'after']) test(`a rejected ${kind} stays out of memory and disk when queued ${order} a receipt`, async (t) => {
    const dir = tempHome();
    const { store, core, services } = open(dir);
    let restore;
    try {
      const existingBlob = Buffer.from('independent committed blob');
      const keptDigest = await services.store.blob.put(existingBlob);
      await services.store.tx(tx => {
        tx.put('rows', 'old', 'keep me');
        tx.put('unrelated', 'old', 'other table');
      });
      await services.receipts.append({ kind: 'existing' });

      restore = failPublication(t, store, order === 'before' ? 1 : 2);
      const bytes = Buffer.from('synthetic overlapping mutation');
      const digest = blobDigest(bytes);
      const appendReceipt = () => services.receipts.append({ kind: 'overlap' });
      let receipt, pending, beforeCommit;
      if (kind === 'blob') {
        if (order === 'after') receipt = appendReceipt();
        pending = services.store.blob.put(bytes);
        beforeCommit = services.store.blob.get(digest);
      } else {
        let staged;
        const prepared = new Promise(resolve => { staged = resolve; });
        pending = services.store.tx(tx => {
          tx.delete('rows', 'old');
          tx.put('rows', 'new', 'uncommitted');
          tx.put('second', 'new', 'uncommitted');
          staged();
        });
        await prepared;
        // The transaction's continuation queues the table write. Yield once
        // here only when that write should precede the receipt in the queue.
        if (order === 'before') await Promise.resolve();
      }
      receipt ??= appendReceipt();
      const settled = Promise.allSettled([pending, receipt]);
      if (kind === 'table') {
        await Promise.resolve();
        beforeCommit = core.tables.get('p\0rows').get('new');
      }

      const [result, saved] = await settled;
      assert.equal(result.status, 'rejected');
      assert.match(result.reason.message, /fixture write failed/);
      assert.deepEqual(saved, { status: 'fulfilled', value: 2 });
      assert.equal(await beforeCommit, undefined);

      const reopened = open(dir);
      assert.deepEqual(receiptValues(reopened.core), [['existing', 1], ['overlap', 2]]);
      assert.deepEqual(await reopened.services.store.blob.get(keptDigest), existingBlob);
      assert.equal(await reopened.services.store.blob.get(digest), undefined);
      await reopened.services.store.tx(tx => {
        assert.deepEqual(tx.list('rows'), [['old', 'keep me']]);
        assert.deepEqual(tx.list('second'), []);
        assert.equal(tx.get('unrelated', 'old'), 'other table');
      });
      if (kind === 'blob') {
        assert.equal(await services.store.blob.put(bytes), digest);
        assert.deepEqual(await open(dir).services.store.blob.get(digest), bytes);
      } else {
        await services.store.tx(tx => {
          tx.delete('rows', 'old');
          tx.put('rows', 'new', 'committed on retry');
          tx.put('second', 'new', 'committed on retry');
        });
        await open(dir).services.store.tx(tx => {
          assert.deepEqual(tx.list('rows'), [['new', 'committed on retry']]);
          assert.deepEqual(tx.list('second'), [['new', 'committed on retry']]);
          assert.equal(tx.get('unrelated', 'old'), 'other table');
        });
      }
    } finally {
      restore?.();
      rmSync(dir, { recursive: true, force: true });
    }
  });
}

for (const failFirst of [false, true]) test(`duplicate blob puts wait for a durable copy (first fails: ${failFirst})`, async (t) => {
  const dir = tempHome();
  const { store, services } = open(dir);
  // A second publication must be needed only if the first put failed.
  const restore = failPublication(t, store, failFirst ? 1 : 2);
  try {
    const bytes = Buffer.from('duplicate synthetic blob');
    const digest = blobDigest(bytes);
    const attempts = [services.store.blob.put(bytes), services.store.blob.put(bytes)];
    const uncommitted = services.store.blob.get(digest);
    const [first, second] = await Promise.allSettled(attempts);
    assert.equal(await uncommitted, undefined);
    if (failFirst) {
      assert.equal(first.status, 'rejected');
      assert.match(first.reason.message, /fixture write failed/);
    } else assert.deepEqual(first, { status: 'fulfilled', value: digest });
    assert.deepEqual(second, { status: 'fulfilled', value: digest });
    assert.deepEqual(await services.store.blob.get(digest), bytes);
    assert.deepEqual(await open(dir).services.store.blob.get(digest), bytes);
  } finally {
    restore();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('in-memory blob writes remain synchronously visible to readers', async () => {
  const core = createCore();
  core.phases.set('p', 'running');
  const { store } = bindServices(core, plugin);
  const bytes = Buffer.from('in-memory blob');
  const written = store.blob.put(bytes);
  const immediate = store.blob.get(blobDigest(bytes));
  assert.deepEqual(await immediate, bytes);
  assert.equal(await written, blobDigest(bytes));
});

test('failure to open the directory leaves a receipt unpublished', async (t) => {
  const dir = tempHome();
  const { core, services } = open(dir);
  const openSync = fs.openSync;
  try {
    await services.receipts.append({ kind: 'initial' });
    t.mock.method(fs, 'openSync', (path, ...args) => {
      if (path === dir) throw new Error('fixture directory open failed');
      return openSync(path, ...args);
    });
    syncBuiltinESMExports();
    await assert.rejects(services.receipts.append({ kind: 'rejected' }), /fixture directory open failed/);
    assert.deepEqual(receiptValues(core), [['initial', 1]]);
    assert.deepEqual(receiptValues(open(dir).core), [['initial', 1]]);
  } finally {
    t.mock.restoreAll();
    syncBuiltinESMExports();
    rmSync(dir, { recursive: true, force: true });
  }
});

test('directory close cannot turn a published receipt into a reported failure', async (t) => {
  const dir = tempHome();
  const { core, services } = open(dir);
  const close = fs.closeSync;
  try {
    t.mock.method(fs, 'closeSync', fd => {
      const directory = fs.fstatSync(fd).isDirectory();
      close(fd);
      if (directory) throw new Error('fixture directory close failed');
    });
    syncBuiltinESMExports();
    assert.equal(await services.receipts.append({ kind: 'saved' }), 1);
    assert.deepEqual(receiptValues(core), [['saved', 1]]);
    assert.deepEqual(receiptValues(open(dir).core), [['saved', 1]]);
  } finally {
    t.mock.restoreAll();
    syncBuiltinESMExports();
    rmSync(dir, { recursive: true, force: true });
  }
});

for (const [condition, legacy, sequence] of [
  ['a legacy gap, duplicate or out-of-order sequence',
    [{ kind: 'old-a', seq: 7 }, { kind: 'old-b', seq: 7 }, { kind: 'old-c', seq: 2 }], 8],
  ['legacy receipts without sequence numbers',
    [{ kind: 'old-a' }, { kind: 'old-b', seq: 1 }, { kind: 'old-c' }], 4],
]) test(`new receipts preserve ${condition}`, async () => {
  const dir = tempHome();
  try {
    const { store, core } = open(dir);
    core.receipts.push(...legacy);
    await store.persist();
    const reopened = open(dir);
    assert.equal(await reopened.services.receipts.append({ kind: 'new' }), sequence);
    assert.deepEqual(open(dir).core.receipts.slice(0, 3), legacy);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('in-memory receipt appends remain synchronously visible', async () => {
  const core = createCore();
  core.phases.set('p', 'running');
  const services = bindServices(core, plugin);
  const first = services.receipts.append({ kind: 'first' });
  const second = services.receipts.append({ kind: 'second' });
  assert.deepEqual(receiptValues(core), [['first', 1], ['second', 2]]);
  assert.deepEqual(await Promise.all([first, second]), [1, 2]);
});

test('the state directory must be private and owned by HQ', () => {
  const dir = tempHome();
  try {
    for (const mode of [0o755, 0o500, 0o1700]) {
      chmodSync(dir, mode);
      assert.throws(() => openStore(dir), (e) => e instanceof StoreError && e.message.includes(`has mode ${mode.toString(8)}; HQ's state directory must be 0700`));
    }
    chmodSync(dir, 0o700);
    assert.throws(() => openStore(dir, { uid: process.getuid() + 1 }), /owned by uid/);
    const fresh = join(dir, 'nested');
    openStore(fresh);
    assert.equal(statSync(fresh).mode & 0o777, 0o700);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('an unreadable or foreign store is refused and left untouched', () => {
  const dir = tempHome();
  try {
    const path = join(dir, 'store.json');
    writeFileSync(path, '{ not json', { mode: 0o600 });
    assert.throws(() => openStore(dir).load(createCore()), /HQ will not overwrite it/);
    assert.equal(readFileSync(path, 'utf8'), '{ not json');
    writeFileSync(path, JSON.stringify({ format: 'something-else' }), { mode: 0o600 });
    assert.throws(() => openStore(dir).load(createCore()), /format/);
    chmodSync(path, 0o644);
    assert.throws(() => openStore(dir).load(createCore()), /must be 0600/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('persist before load is refused', async () => {
  const dir = tempHome();
  try {
    mkdirSync(join(dir, 'x'), { mode: 0o700 });
    await assert.rejects(openStore(join(dir, 'x')).persist(), /persist before load/);
  } finally { rmSync(dir, { recursive: true, force: true }); }
});

test('a temporary file left by a crash mid-write is removed; the intact store loads', async () => {
  const dir = tempHome();
  try {
    const a = open(dir);
    await a.services.store.tx((tx) => tx.put('rows', 'k', { v: 1 }));
    writeFileSync(join(dir, 'store.json.tmp-999'), '{ torn', { mode: 0o600 });
    const b = open(dir);
    assert.equal(existsSync(join(dir, 'store.json.tmp-999')), false);
    assert.deepEqual(await b.services.store.tx((tx) => tx.get('rows', 'k')), { v: 1 });
  } finally { rmSync(dir, { recursive: true, force: true }); }
});
