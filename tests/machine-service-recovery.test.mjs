import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { mkdtempSync, rmSync, symlinkSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { machineCommandInHome } from '../hq/machine-channel.mjs';

const action = 'hq-service-recovery';
const id = 'plan-20261119T040000Z-abcd';
const role = '_agent-bot-hq';
const arm = { skip: !['darwin', 'linux'].includes(process.platform) };
function point(key) {
  const { x, y } = key.export({ format: 'jwk' });
  return Buffer.concat([Buffer.from([4]), Buffer.from(x, 'base64url'), Buffer.from(y, 'base64url')]).toString('base64');
}
function proof(c, key, message = [ 'agent-bot-machine-owner/v1', c.action, c.machine_key, c.hq_key, c.owner_key,
  c.plan_id, c.plan_digest, c.nonce, c.expires_at, '' ].join('\n')) {
  return { public_key: point(key.publicKey), signature: sign('sha256', Buffer.from(message), key.privateKey).toString('base64') };
}
function savedPlan() {
  const plan = { version: 3, hq_account: role, dir: 'none', members: [], steps: [
    { kind: 'hq-account', target: role, action: 'none', group: role, mode: '0700', detail: 'healthy role' },
    { kind: 'service', target: 'ai.true-line.agent-bot-hq', action: 'create', owner: 'operator', content: '<verified service>', detail: 'install verified job' },
  ] };
  const plan_canonical = JSON.stringify(plan) + '\n';
  return { plan_id: id, plan_digest: createHash('sha256').update(plan_canonical).digest('hex'), plan_canonical };
}
async function fixture(t, purpose = action, roleUid = 300) {
  const home = mkdtempSync(join(tmpdir(), 'hqr-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  // The test process owns the scratch key files. The protocol fixture models
  // a distinct enrolled macOS system role at UID 300.
  const run = (...args) => machineCommandInHome(args, home, process.getuid(), undefined, false, roleUid);
  const identity = await run('identity');
  const key = generateKeyPairSync('ed25519');
  const owner = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const hex = key.publicKey.export({ type: 'spki', format: 'der' }).subarray(12).toString('hex');
  const client = createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: Buffer.from(identity.public_key, 'hex').toString('base64url') }, format: 'jwk' });
  const socket = join(home, 'daemon.sock');
  const requests = [];
  const state = { saved: purpose === action ? savedPlan() : upgradePlan(), tweak: () => {} };
  let pending;
  const server = createServer((stream) => {
    let input = '';
    stream.on('data', (chunk) => {
      input += chunk;
      if (!input.includes('\n')) return;
      const r = JSON.parse(input);
      assert.equal(r.public_key, Buffer.from(identity.public_key, 'hex').toString('base64'));
      const pieces = [r.verb, '', r.option ?? '', '', r.plan_id ?? '', '', '', '', r.timestamp, r.nonce];
      if (r.verb === purpose) pieces.push('plan_digest', r.plan_digest);
      if (r.option === 'approve' || r.option === 'cancel') pieces.push('challenge_nonce', r.challenge_nonce);
      if (r.option === 'approve') pieces.push('owner_signature', r.owner_signature);
      assert.ok(verify(null, Buffer.from(pieces.join('\n')), client, Buffer.from(r.signature, 'base64')));
      requests.push(r);
      const timestamp = Math.floor(Date.now() / 1000);
      const response = { ok: true, timestamp, nonce: randomBytes(16).toString('base64url'), request_nonce: r.nonce };
      let body;
      if (r.verb === 'status') response.state = 'reported';
      else if (r.verb === 'members-plans') {
        assert.equal(r.option, 'get');
        assert.equal(r.plan_id, id);
        response.state = 'found';
        body = state.saved;
      } else {
        assert.equal(r.verb, purpose);
        assert.equal(r.plan_id, id);
        assert.equal(r.plan_digest, state.saved.plan_digest);
        assert.equal(r.owner_key, undefined);
        if (r.option === 'challenge') {
          response.state = 'challenged';
          pending = { action: purpose, machine_key: hex, hq_key: identity.public_key, owner_key: point(owner.publicKey),
            ...state.saved, nonce: randomBytes(32).toString('hex'), expires_at: timestamp + 120 };
          state.tweak(pending);
          body = pending;
        } else if (!pending || pending.nonce !== r.challenge_nonce) {
          response.ok = false;
          response.diagnostic = 'MM_DAEMON_PEER_REFUSED';
        } else {
          assert.ok(['approve', 'cancel'].includes(r.option));
          response.state = r.option === 'approve' ? 'approved' : 'cancelled';
          body = { plan_id: id, plan_digest: state.saved.plan_digest };
          if (r.option === 'approve') {
            const canonical = ['agent-bot-machine-owner/v1', purpose, hex, identity.public_key, point(owner.publicKey), id, state.saved.plan_digest, pending.nonce, pending.expires_at, ''].join('\n');
            assert.ok(verify('sha256', Buffer.from(canonical), owner.publicKey, Buffer.from(r.owner_signature, 'base64')));
            body.approved_at = new Date(timestamp * 1000).toISOString().replace('.000Z', 'Z');
            body.expires_at = new Date((timestamp + 600) * 1000).toISOString().replace('.000Z', 'Z');
          }
          pending = undefined;
        }
      }
      const bodyBytes = body && JSON.stringify(body).replaceAll('<', '\\u003c');
      const signed = [response.ok, response.diagnostic ?? '', '', response.state ?? '', bodyBytes ?? '', timestamp, response.nonce, response.request_nonce].join('\n');
      response.signature = sign(null, Buffer.from(signed), key.privateKey).toString('base64');
      const line = JSON.stringify(response).slice(0, -1) + (bodyBytes ? ',"body":' + bodyBytes : '') + '}';
      if (response.state === 'challenged') state.raw = line;
      stream.end(line + '\n');
    });
  });
  await new Promise((resolve, reject) => server.once('error', reject).listen(socket, resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const issue = () => run(purpose, 'export', id, '--socket', socket);
  const challengeFile = join(home, 'handoff.json');
  const proofFile = join(home, 'proof.json');
  const approve = () => run(purpose, 'approve', '--challenge-file', challengeFile, '--proof-file', proofFile, '--socket', socket);
  const cancel = () => run(purpose, 'cancel', '--challenge-file', challengeFile, '--socket', socket);
  const pin = () => run('status', '--socket', socket, '--daemon-key', hex);
  return { issue, approve, cancel, pin, state, requests, challengeFile, proofFile, owner, run, socket, home };
}

test('paired recovery preserves the signed Machine line and checks owner proof before forwarding', arm, async (t) => {
  const f = await fixture(t);
  await assert.rejects(f.issue(), /pin saved by verified Machine status/);
  assert.equal(f.requests.length, 0);
  await f.pin();
  const exported = await f.issue();
  assert.equal(exported, f.state.raw);
  assert.deepEqual(f.requests.map((r) => r.option ?? r.verb), ['status', 'get', 'challenge']);
  writeFileSync(f.challengeFile, exported + '\n');
  const c = JSON.parse(exported).body;
  const other = generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const accepted = proof(c, f.owner);
  for (const invalid of [proof(c, other), proof(c, f.owner, 'machine-pair'), { ...accepted, signature: accepted.signature + '=' }]) {
    writeFileSync(f.proofFile, JSON.stringify(invalid));
    await assert.rejects(f.approve(), /owner (proof|signature)/);
    assert.equal(f.requests.length, 3);
  }
  writeFileSync(f.proofFile, JSON.stringify(accepted));
  writeFileSync(f.challengeFile, exported.replace('healthy role', 'changed'));
  await assert.rejects(f.approve(), /signature/);
  assert.equal(f.requests.length, 3);
  writeFileSync(f.challengeFile, exported + '\n');
  assert.equal((await f.approve()).state, 'approved');
  await assert.rejects(f.approve(), /MM_DAEMON_PEER_REFUSED/);
  const replacement = await f.issue();
  writeFileSync(f.challengeFile, replacement + '\n');
  assert.equal((await f.cancel()).state, 'cancelled');
  assert.equal(f.requests.at(-1).owner_signature, undefined);
});

test('paired recovery refuses mismatched plan, recipient, expiry and unsafe transfer files', arm, async (t) => {
  const f = await fixture(t);
  await f.pin();
  for (const tweak of [
    (c) => { c.hq_key = '0'.repeat(64); }, (c) => { c.machine_key = '1'.repeat(64); },
    (c) => { c.expires_at -= 121; }, (c) => { c.expires_at += 1; }, (c) => { c.plan_id = 'plan-20261119T040000Z-bbbb'; },
    (c) => { c.extra = 'unknown'; }, (c) => { c.owner_key = 'invalid'; },
  ]) {
    f.state.tweak = tweak;
    await assert.rejects(f.issue());
  }
  const original = f.state.saved;
  for (const canonical of [original.plan_canonical.replace('"members":[]', '"members":null'),
    original.plan_canonical.replace('"action":"none"', '"action":"create"'), original.plan_canonical.replace('ai.true-line.agent-bot-hq', 'foreign-service'),
    ...['root', role, 'two words'].map((name) => original.plan_canonical.replace('"owner":"operator"', '"owner":' + JSON.stringify(name)))]) {
    f.state.saved = { ...original, plan_canonical: canonical, plan_digest: createHash('sha256').update(canonical).digest('hex') };
    const before = f.requests.length;
    await assert.rejects(f.issue(), /outside the paired HQ service repair scope/);
    assert.equal(f.requests.length, before + 1);
    assert.equal(f.requests.at(-1).option, 'get');
  }
  const before = f.requests.length;
  writeFileSync(f.challengeFile, Buffer.alloc(65538));
  await assert.rejects(f.cancel(), /bounded regular/);
  rmSync(f.challengeFile);
  symlinkSync(f.proofFile, f.challengeFile);
  await assert.rejects(f.cancel());
  assert.equal(f.requests.length, before);
});

function upgradePlan(change = () => {}) {
  const plan = JSON.parse(savedPlan().plan_canonical);
  const previous = {
    service: { archive: '/test/releases/previous/approved.tar', release_dir: '/test/releases/previous/hq',
      artifact_sha256: 'a'.repeat(64), node: '/test/tools/node', node_sha256: 'b'.repeat(64) },
    plist: readFileSync(new URL('./fixtures/darwin-hq-v2.plist', import.meta.url), 'utf8'), owner_uid: 501,
    runtime_directory: { path: '/Library/Application Support/ai.true-line.agent-bot-hq', action: 'create',
      owner: 'root', group: 'wheel', mode: '0755' },
  };
  const next = structuredClone(previous);
  next.service.release_dir = '/test/releases/next/hq';
  next.service.archive = '/test/releases/next/approved.tar';
  next.service.artifact_sha256 = 'c'.repeat(64);
  next.runtime_directory.action = 'none';
  next.plist = previous.plist.replaceAll(previous.service.release_dir, next.service.release_dir)
    .replace(previous.service.artifact_sha256, next.service.artifact_sha256);
  const content = { previous_plan_id: 'plan-20261117T020000Z-1234', previous_plan_digest: 'd'.repeat(64), previous, next };
  const service = plan.steps[1];
  service.action = 'upgrade';
  change(content, service);
  service.content = JSON.stringify(content);
  const plan_canonical = JSON.stringify(plan) + '\n';
  return { plan_id: id, plan_digest: createHash('sha256').update(plan_canonical).digest('hex'), plan_canonical };
}

test('paired service upgrade verifies both signed releases and requires its own owner consent', arm, async (t) => {
  const purpose = 'hq-service-upgrade';
  const f = await fixture(t, purpose);
  await assert.rejects(f.issue(), /pin saved by verified Machine status/);
  assert.equal(f.requests.length, 0);
  await f.pin();
  await assert.rejects(machineCommandInHome([purpose, 'export', id, '--socket', f.socket], f.home,
    process.getuid(), undefined, true), /dedicated HQ/);
  const exported = await f.issue();
  assert.equal(exported, f.state.raw);
  assert.deepEqual(f.requests.map((r) => r.verb), ['status', 'members-plans', purpose]);
  writeFileSync(f.challengeFile, exported + '\n');
  const challenge = JSON.parse(exported).body;
  writeFileSync(f.proofFile, JSON.stringify(proof({ ...challenge, action }, f.owner)));
  await assert.rejects(f.approve(), /invalid owner signature/);
  await assert.rejects(f.run(action, 'cancel', '--challenge-file', f.challengeFile, '--socket', f.socket), /misdirected/);
  assert.equal(f.requests.length, 3);
  writeFileSync(f.proofFile, JSON.stringify(proof(challenge, f.owner)));
  assert.equal((await f.approve()).state, 'approved');
  await assert.rejects(f.approve(), /MM_DAEMON_PEER_REFUSED/);
  // An earlier repair or upgrade may already have found the runtime directory.
  f.state.saved = upgradePlan((c) => { c.previous.runtime_directory.action = 'none'; });
  const fresh = await f.issue();
  writeFileSync(f.challengeFile, fresh + '\n');
  assert.equal((await f.cancel()).state, 'cancelled');
  assert.equal(f.requests.at(-1).owner_signature, undefined);
});

test('paired service upgrade refuses a different job, owner, node, socket or purpose before issuing', arm, async (t) => {
  const f = await fixture(t, 'hq-service-upgrade');
  await f.pin();
  for (const change of [
    (c, step) => { step.action = 'write'; }, (c) => { c.previous_plan_id = id; },
    (c) => { c.extra = 'not part of the plan'; }, (c) => { c.next.extra = true; },
    (c) => { c.previous_plan_digest = ''; }, (c) => { c.next = c.previous; },
    (c) => { c.next.runtime_directory.action = 'create'; }, (c) => { delete c.previous.runtime_directory; },
    (c) => { c.next.owner_uid++; },
    (c) => { c.next.service.release_dir = '/test/../other/hq'; }, (c) => { c.next.service.node = '/other/node'; },
    (c) => { c.next.service.node_sha256 = 'e'.repeat(64); },
    (c) => { c.next.plist = c.next.plist.replace('owner-control.sock', 'another.sock'); },
    (c) => { c.previous.plist = c.previous.plist.replace('operator</string>', 'another</string>'); },
    (c) => { c.next.plist = c.next.plist.replace('run</string>', 'other</string>'); },
  ]) {
    f.state.saved = upgradePlan(change);
    const before = f.requests.length;
    await assert.rejects(f.issue());
    assert.deepEqual(f.requests.slice(before).map(r => r.verb), ['members-plans']);
  }
  f.state.saved = upgradePlan();
  f.state.tweak = (c) => { c.action = action; };
  await assert.rejects(f.issue(), /misdirected/);
});

for (const purpose of ['harness-launch-install', 'harness-launch-retire']) {
  test(`paired ${purpose} submits only an owner proof for that exact operation`, arm, async (t) => {
    const f = await fixture(t, purpose);
    f.state.saved = harnessPlan(purpose);
    await assert.rejects(f.issue(), /pin saved by verified Machine status/);
    await f.pin();
    await assert.rejects(machineCommandInHome([purpose, 'export', id, '--socket', f.socket],
      f.home, process.getuid(), undefined, true), /dedicated HQ/);
    const line = await f.issue();
    assert.equal(line, f.state.raw);
    writeFileSync(f.challengeFile, line + '\n');
    const challenge = JSON.parse(line).body;
    const policy = JSON.parse(JSON.parse(challenge.plan_canonical).steps[0].content);
    assert.deepEqual(policy.adapters[0].args, ['--member', 'a & b', 'quoted "value"', '', '☃\u2028λ']);
    const other = purpose === 'harness-launch-install' ? 'harness-launch-retire' : 'harness-launch-install';
    writeFileSync(f.proofFile, JSON.stringify(proof({ ...challenge, action: other }, f.owner)));
    await assert.rejects(f.approve(), /invalid owner signature/);
    await assert.rejects(f.run(other, 'cancel', '--challenge-file', f.challengeFile, '--socket', f.socket), /misdirected/);
    assert.deepEqual(f.requests.map(r => r.verb), ['status', 'members-plans', purpose]);
    writeFileSync(f.proofFile, JSON.stringify(proof(challenge, f.owner)));
    assert.equal((await f.cancel()).state, 'cancelled');
    assert.equal(f.requests.at(-1).owner_signature, undefined);
    const reissued = await f.issue();
    const fresh = JSON.parse(reissued).body;
    assert.notEqual(fresh.nonce, challenge.nonce);
    await assert.rejects(f.approve(), /MM_DAEMON_PEER_REFUSED/);

    writeFileSync(f.challengeFile, reissued);
    const before = f.requests.length;
    await assert.rejects(f.approve(), /invalid owner signature/);
    assert.equal(f.requests.length, before);
    writeFileSync(f.proofFile, JSON.stringify(proof(fresh, f.owner)));
    assert.equal((await f.approve()).state, 'approved');
    await assert.rejects(f.approve(), /MM_DAEMON_PEER_REFUSED/);
  });
}

function harnessJSON(value) {
  return JSON.stringify(value).replaceAll('\u2028', '\\u2028').replaceAll('\u2029', '\\u2029') + '\n';
}

function harnessPlan(purpose, change = () => {}) {
  const root = '/Library/Application Support/ai.true-line.agent-bot-hq';
  const install = purpose === 'harness-launch-install';
  const members = ['_alpha', '_beta'];
  const p = {
    schema: 'agent-bot-harness-launch/v1', action: install ? 'install' : 'retire', hq_uid: 300,
    launcher: { path: root + '/harness-launch', sha256: 'a'.repeat(64) },
    sandbox: { path: root + '/harness-egress.sb', sha256: 'b'.repeat(64) },
    adapters: [
      { adapter_id: 'first', account: members[0], uid: 301, executable: '/Library/Tools/First Helper', sha256: 'c'.repeat(64), args: ['--member', 'a & b', 'quoted "value"', '', '☃\u2028λ'] },
      { adapter_id: 'second', account: members[1], uid: 302, executable: '/Library/Tools/Second', sha256: 'd'.repeat(64), args: [] },
      { adapter_id: 'third', account: members[0], uid: 301, executable: '/Library/Tools/Third', sha256: 'e'.repeat(64), args: [] },
    ],
    installed_plan_id: install ? '' : 'plan-20261118T040000Z-cdef', installed_plan_digest: install ? '' : harnessPlan('harness-launch-install').plan_digest,
  };
  const file = (target, mode, content) => ({ kind: 'file', target, action: install ? 'create' : 'remove', owner: 'root', group: 'wheel', mode, content });
  const step = file(root + '/harness-launch-policy.json', '0644', '');
  const command = '/Library/Application\\ Support/ai.true-line.agent-bot-hq/harness-launch harness-run';
  const rule = '# Managed by managed-machine harness launch v1.\n' + members.map(account =>
    `_agent-bot-hq ALL = (${account}) NOPASSWD: NOSETENV: sha256:${'a'.repeat(64)} ${command}\n`).join('');
  const permit = file('/private/etc/sudoers.d/agent-bot-hq-harness-launch', '0440', rule);
  const plan = { version: 3, hq_account: role, dir: root + '/ipc', members, steps: [step, permit] };
  change(p, plan);
  step.content ||= harnessJSON(p);
  const plan_canonical = harnessJSON(plan);
  return { plan_id: id, plan_canonical, plan_digest: createHash('sha256').update(plan_canonical).digest('hex') };
}

test('paired harness review refuses changes outside the saved launch-rule purpose before issuing', arm, async (t) => {
  const purpose = 'harness-launch-install';
  const f = await fixture(t, purpose);
  await f.pin();
  const changes = [
    (p, plan) => { plan.hq_account = 'operator'; },
    (p, plan) => { plan.hq_account += '\n'; },
    (p, plan) => { plan.members[0] += '\n'; p.adapters[0].account = plan.members[0]; },
    p => { p.adapters[0].adapter_id += '\n'; },
    p => { p.adapters[0].args.push('\ud800'); },
    (p, plan) => { plan.dir += '/other'; },
    (p, plan) => { plan.members = ['_alpha']; },
    (p, plan) => { plan.steps.push(plan.steps[0]); },
    (p, plan) => { plan.steps[0].detail = 'additional action'; },
    (p, plan) => { plan.steps[0].target += '.other'; },
    (p, plan) => { plan.steps[0].content = JSON.stringify(p, null, 2) + '\n'; },
    (p, plan) => { plan.steps[1].mode = '0644'; },
    (p, plan) => { plan.steps[1].content += '# changed\n'; },
    p => { p.hq_uid = 0; }, p => { p.hq_uid = 399; }, p => { p.adapters[0].uid = p.hq_uid; },
    p => { p.adapters[1].uid = p.adapters[0].uid; }, p => { p.adapters[2].uid++; },
    p => { p.adapters[0].args = Array(32).fill('x'.repeat(1024)); },
    p => { p.adapters[0].args.push('line\nfeed'); }, p => { p.adapters[0].executable += '/..'; },
    p => { p.adapters[0].adapter_id = p.adapters[1].adapter_id; },
    p => { p.adapters[0].env = {}; }, p => { p.sandbox.path += '.other'; },
    p => { p.installed_plan_id = id; },
  ];
  for (const change of changes) {
    f.state.saved = harnessPlan(purpose, change);
    const before = f.requests.length;
    await assert.rejects(f.issue());
    assert.deepEqual(f.requests.slice(before).map(r => r.verb), ['members-plans']);
  }
  f.state.saved = harnessPlan('harness-launch-retire');
  await assert.rejects(f.issue());
  f.state.saved = savedPlan();
  await assert.rejects(f.issue());
});

test('signed handoff accepts the Go canonical vectors and rejects a mismatched install before issuing retirement', arm, async (t) => {
  for (const action of ['install', 'retire']) {
    const purpose = 'harness-launch-' + action;
    const f = await fixture(t, purpose, 311);
    const plan_canonical = readFileSync(new URL('./fixtures/machine-harness-launch/' + action + '.json', import.meta.url), 'utf8');
    f.state.saved = { plan_id: id, plan_digest: createHash('sha256').update(plan_canonical).digest('hex'), plan_canonical };
    await f.pin();
    const challenge = JSON.parse(await f.issue()).body;
    assert.equal(challenge.plan_canonical, plan_canonical);
    if (action === 'install') continue;
    for (const change of [p => { p.installed_plan_digest = 'f'.repeat(64); },
      p => { p.adapters[0].args.push('another argument'); }]) {
      const plan = JSON.parse(plan_canonical);
      const policy = JSON.parse(plan.steps[0].content);
      change(policy);
      plan.steps[0].content = harnessJSON(policy);
      const bytes = harnessJSON(plan);
      f.state.saved = { plan_id: id, plan_digest: createHash('sha256').update(bytes).digest('hex'), plan_canonical: bytes };
      const before = f.requests.length;
      await assert.rejects(f.issue(), /referenced installation digest/);
      assert.deepEqual(f.requests.slice(before).map(r => r.verb), ['members-plans']);
    }
  }
});

test('paired harness review measures the canonical plan at the 32768-byte boundary', arm, async (t) => {
  const purpose = 'harness-launch-install';
  const f = await fixture(t, purpose);
  await f.pin();
  const args = Array(32).fill('');
  const make = () => harnessPlan(purpose, p => { p.adapters[1].args = args; });
  let remaining = 32768 - Buffer.byteLength(make().plan_canonical);
  for (let i = 0; i < args.length; i++) {
    const length = Math.min(remaining, 1024);
    args[i] = 'x'.repeat(length);
    remaining -= length;
  }
  assert.equal(remaining, 0);
  f.state.saved = make();
  assert.equal(Buffer.byteLength(f.state.saved.plan_canonical), 32768);
  await f.issue();
  args[args.length - 1] += 'x';
  f.state.saved = make();
  assert.equal(Buffer.byteLength(f.state.saved.plan_canonical), 32769);
  const before = f.requests.length;
  await assert.rejects(f.issue(), /outside the paired harness launch plan scope/);
  assert.deepEqual(f.requests.slice(before).map(r => r.verb), ['members-plans']);
});
