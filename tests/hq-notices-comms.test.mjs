// Released wire validation + real comms custody, storage, admission and socket.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { spawnSync } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { pathToFileURL } from 'node:url';
import { canonicalBytes } from '../sdk/wire/canonical-json.mjs';
import { fakeIdentityService } from '../sdk/services.mjs';
import { legacySigner } from '../hq/legacy.mjs';
import { bindProof } from '../hq/admission.mjs';
import { DIGEST, SOUL, fakeLegacy, hello, startHQ, tempHome } from './hq-harness.mjs';
import { commsCheckout, credentialFreeGitEnv } from './support/comms-checkout.mjs';
const { brokerPlugin } = await import(pathToFileURL(join(commsCheckout(), 'lib/hq-plugin/broker.mjs')).href);
const harness = 'notice-bot';
const repo = 'Example/Project';
const scope = { harness, repo };
const config = { acceptedDefinitions: { [SOUL]: [DIGEST] }, notices: { harnesses: [harness], scopes: [{ soul_id: SOUL, definition_digest: DIGEST, member_id: 'm_lead', adapter_id: 'fake-adapter', role: 'lead', ...scope }] } };
const notice = (id, over = {}) => Object.fromEntries(Object.entries({ id, lease: `${id}.LEASE_CANARY`, repo, text: id, createdAt: 1, attempts: 4, secret: 'DROP_CANARY', ...over }).filter(([, value]) => value !== undefined));
const code = (r) => r.refusal?.error ?? r.host_refusal?.code;
const durableMailbox = (home) => JSON.parse(readFileSync(join(home, 'store.json'), 'utf8')).tables.filter(([name]) => name.startsWith('agent-comms\0'));
const rows = (t) => [...t.hq.core.tables.get('agent-comms\0notice_mailbox').values()];
let admissionSequence = 0;
async function setup(records, { home = tempHome(), configured = true } = {}) {
  const upstream = [];
  const identity = fakeIdentityService({ routes: {
    'POST /api/daemon/notices/take': (body) => { upstream.push(['take', body]); return { body: { harness, notices: records } }; },
    'POST /api/daemon/notices/ack': (body) => {
      upstream.push(['ack', body]);
      const id = body.ids[0].split('.')[0];
      const snapshot = readFileSync(join(home, 'store.json'), 'utf8');
      assert.ok(snapshot.includes(id), 'custody is durable before upstream ack');
      assert.equal(snapshot.includes('LEASE_CANARY'), false);
      return { body: { acked: [id], stale: [], missing: [] } };
    },
  } });
  const t = await startHQ({ home, config: configured ? config : { acceptedDefinitions: { [SOUL]: [DIGEST] } }, identity,
    enrollment: { ...legacySigner({ run: fakeLegacy().run }), allowsHarness: () => true },
    plugins: [brokerPlugin({ noticeTimers: { setTimer: () => ({ unref() {} }), clearTimer() {} } })] });
  try {
    const pump = t.hq.host.provided('agent-comms').notices;
    const ingest = configured ? await pump.pull() : null;
    const entry = await t.entry();
    const admission = await entry.request('Hello', hello({ request_id: `req_real_${++admissionSequence}` }));
    assert.equal(admission.ok, true, JSON.stringify(admission));
    const a = admission.result;
    const bind = async (runtime = a.admitted_runtimes[0]) => {
      const peer = await t.member();
      const challenge = await peer.request('bind.challenge', { runtime_id: runtime.runtime_id });
      assert.equal(challenge.ok, true, JSON.stringify(challenge));
      assert.equal((await peer.request('bind', { runtime_id: runtime.runtime_id, proof: bindProof(runtime.channel_binding, challenge.result.nonce, runtime.runtime_id) })).ok, true);
      return peer;
    };
    const peer = await bind();
    const query = (operation = 'peek', extra = {}) => ({ contract: 'hq/v1', request_id: 'notice_real', operation, required_capabilities: ['notices-v1'], installation_epoch: a.installation_epoch, lease_generation: a.lease_generation, ...extra });
    return { ...t, pump, ingest, upstream, peer, query, a, bind };
  } catch (error) { await t.done(); throw error; }
}

test('default HQ + real comms: disabled ingestion and absent scope refuse without upstream effects', async () => {
  const t = await setup([notice('disabled')], { configured: false });
  try {
    assert.equal(code(await t.peer.request('notices.consume-one', t.query('consume-one'))), 'caller_mismatch');
    assert.equal(t.upstream.length, 0);
    assert.equal(t.pump.status().configured, false);
  } finally { await t.done(); }
});

test('real custody, scoped sequence order, guarded no-effects and restart/redelivery tombstones', async () => {
  const records = [notice('first', { createdAt: 100 }), notice('second', { createdAt: 0, repo: repo.toUpperCase() }), notice('outside', { repo: 'Other/Repo' }), notice('missing', { repo: undefined }), notice('invalid', { repo: 'Example/Project\n' })];
  let t = await setup(records);
  const home = t.home;
  try {
    assert.equal(rows(t).length, 5);
    const upstreamBefore = t.upstream.length;
    const saved = durableMailbox(home);
    for (const [extra, expected] of [[{ expected_repository: 'Other/Repo' }, 'caller_mismatch'], [{ installation_epoch: 99 }, 'stale_epoch'], [{ lease_generation: 99 }, 'lease_expired'], [{ harness: 'override' }, 'host.invalid_request']]) {
      assert.equal(code(await t.peer.request('notices.consume-one', t.query('consume-one', extra))), expected);
    }
    const specialist = await t.bind(t.a.admitted_runtimes[1]);
    assert.equal(code(await specialist.request('notices.peek', t.query())), 'caller_mismatch');
    assert.deepEqual(durableMailbox(home), saved);
    const peek = await t.peer.request('notices.peek', t.query('peek', { count: 50 }));
    assert.equal(peek.ok, true, JSON.stringify(peek));
    assert.deepEqual(peek.result.notices.map((x) => x.message_id), ['first', 'second']);
    assert.equal(JSON.stringify(peek).includes('LEASE_CANARY'), false);
    assert.equal(JSON.stringify(peek).includes('DROP_CANARY'), false);
    assert.deepEqual(durableMailbox(home), saved, 'peek is read-only');
    const one = await t.peer.request('notices.consume-one', t.query('consume-one'));
    assert.equal(one.ok, true, JSON.stringify(one));
    assert.deepEqual(one.result.notices.map((x) => x.message_id), ['first']);
    assert.equal(rows(t).filter((r) => r.state === 'consumed').length, 1);
    assert.equal(t.upstream.length, upstreamBefore, 'queries never poll upstream');
    await t.done({ keep: true });
    t = await setup(records, { home });
    assert.equal(t.ingest.duplicates, 5);
    const next = await t.peer.request('notices.consume-one', t.query('consume-one'));
    assert.deepEqual(next.result.notices.map((x) => x.message_id), ['second']);
    assert.deepEqual((await t.peer.request('notices.consume-one', t.query('consume-one'))).result.notices, []);
    assert.equal(rows(t).filter((r) => r.state === 'ready').length, 3, 'withheld metadata remains available for operator handling');
  } finally { await t.done(); }
});

test('real mailbox validates before tombstone and full correlated peek budget trims only a suffix', async () => {
  // Eight public records fit the private array exactly, but the correlated
  // result wrapper does not. Every reconstructed source remains below 64 KiB.
  const records = Array.from({ length: 8 }, (_, i) => notice(`budget${i}`, { text: '' }));
  const publicRecord = (n) => ({ message_id: n.id, provenance: ['external-untrusted'], wake_class: 'none', content: { repo, text: n.text, createdAt: 1 } });
  const emptyBytes = canonicalBytes(records.map(publicRecord)).length;
  const fill = 524_288 - emptyBytes;
  records.forEach((n, i) => { n.text = 'x'.repeat(Math.floor(fill / 8) + (i < fill % 8 ? 1 : 0)); });
  assert.equal(canonicalBytes(records.map(publicRecord)).length, 524_288);
  for (const n of records) assert.ok(canonicalBytes({ id: n.id, ...publicRecord(n).content }).length <= 65_536);
  const t = await setup(records);
  try {
    const saved = readFileSync(join(t.home, 'store.json'), 'utf8');
    let validations = 0;
    await assert.rejects(t.pump.consumeOne(scope, (selected) => {
      validations++;
      assert.equal(Object.isFrozen(selected[0].content), true);
      assert.equal(readFileSync(join(t.home, 'store.json'), 'utf8'), saved);
      throw new Error('full-result preparation refused');
    }), /full-result preparation refused/);
    assert.equal(validations, 1);
    assert.equal(readFileSync(join(t.home, 'store.json'), 'utf8'), saved, 'callback failure leaves no tombstone');
    const privateArray = await t.pump.peek({ ...scope, count: 8 });
    assert.equal(privateArray.length, 8);
    const peek = await t.peer.request('notices.peek', t.query('peek', { count: 8 }));
    assert.equal(peek.ok, true, JSON.stringify(peek));
    assert.equal(peek.result.notices.length, 7);
    assert.ok(canonicalBytes(peek.result).length <= 524_288);
    assert.deepEqual(peek.result.notices, privateArray.slice(0, 7));
    assert.equal(readFileSync(join(t.home, 'store.json'), 'utf8'), saved);
    assert.equal((await t.peer.request('notices.consume-one', t.query('consume-one'))).result.notices.length, 1);
  } finally { await t.done(); }
});


test('public comms test fetch ignores inherited scoped headers and credential prompts', () => {
  const home = mkdtempSync(join(tmpdir(), 'public-git-'));
  try {
    const system = join(home, 'system');
    const global = join(home, 'global');
    const template = join(home, 'template');
    mkdirSync(template);
    const scoped = '[http "https://github.com/"]\n extraHeader = X-Scoped: CANARY\n';
    writeFileSync(system, scoped);
    writeFileSync(global, scoped);
    writeFileSync(join(template, 'config'), scoped);
    const inherited = { ...Object.fromEntries(Object.entries(process.env).filter(([key]) => !key.startsWith('GIT_'))), GIT_CONFIG_SYSTEM: system, GIT_CONFIG_GLOBAL: global,
      GIT_CONFIG_COUNT: '1', GIT_CONFIG_KEY_0: 'http.https://github.com/.extraHeader', GIT_CONFIG_VALUE_0: 'X-Injected: CANARY',
      GIT_CONFIG_PARAMETERS: "'http.https://github.com/.extraHeader=X-Parameter: CANARY'", GIT_TEMPLATE_DIR: template,
      GIT_DIR: join(home, 'untrusted.git'), GIT_WORK_TREE: join(home, 'untrusted-tree'), GIT_COMMON_DIR: join(home, 'untrusted-common'),
      GIT_ASKPASS: 'CANARY-ASKPASS', SSH_ASKPASS: 'CANARY-SSH-ASKPASS' };
    const isolated = credentialFreeGitEnv(inherited);
    const init = spawnSync('git', ['-C', home, 'init', '-q', '--template='], { env: isolated, encoding: 'utf8' });
    assert.equal(init.status, 0, init.stderr);
    const query = (env) => spawnSync('git', ['-C', home, 'config', '--get-urlmatch', 'http.extraHeader', 'https://github.com/true-line/agent-bot-comms.git'], { env, encoding: 'utf8' });
    const { GIT_DIR, GIT_WORK_TREE, GIT_COMMON_DIR, ...control } = inherited;
    assert.equal(query(control).status, 0, 'control config is readable');
    assert.match(query(control).stdout, /CANARY/, 'control has scoped headers');
    assert.equal(isolated.GIT_ASKPASS, '/bin/false');
    assert.equal(isolated.SSH_ASKPASS, '/bin/false');
    for (const key of ['GIT_CONFIG_SYSTEM', 'GIT_CONFIG_COUNT', 'GIT_CONFIG_KEY_0', 'GIT_CONFIG_VALUE_0', 'GIT_CONFIG_PARAMETERS', 'GIT_TEMPLATE_DIR', 'GIT_DIR', 'GIT_WORK_TREE', 'GIT_COMMON_DIR']) assert.equal(Object.hasOwn(isolated, key), false, key);
    const checked = query(isolated);
    assert.equal(checked.status, 1, checked.stderr);
    assert.equal(checked.stdout, '', 'no global, system, injected or template header remains');
  } finally { rmSync(home, { recursive: true, force: true }); }
});
