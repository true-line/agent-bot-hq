import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { mkdtempSync, rmSync, symlinkSync, readFileSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { qualificationApprovalDetail, qualificationPurpose } from '../hq/machine-harness-qualification.mjs';
import { validatedMembersPlan } from '../hq/machine-members-plans.mjs';
import { cooperativeInstallPurpose } from '../hq/machine-soul-cooperative-launch.mjs';
import { protectedInstallPurpose } from '../hq/machine-soul-protected-launch.mjs';
import { soulBridgeAccountsPurpose } from '../hq/machine-soul-runner-accounts.mjs';
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
  const saved = purpose === action ? savedPlan()
    : purpose === qualificationPurpose ? qualificationPlan()
      : purpose === protectedInstallPurpose ? protectedInstallPlan(hex, roleUid)
        : purpose === cooperativeInstallPurpose ? cooperativePlan(hex, roleUid) : upgradePlan();
  const state = { saved, tweak: () => {} };
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
            state.approvedAt = body.approved_at;
            state.expiresAt = body.expires_at;
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

function stage2aUpgradePlan(change = () => {}) {
  return upgradePlan((content, service) => {
    const installation = 'hq-test-123';
    const hash = (domain) => createHash('sha256').update(`agent-bot/stage2a-domain-${domain}/v3\0H-code\0${installation}`).digest('hex');
    const namespace = `/private/var/db/managed-machine/soul-snapshots/hq_${hash('slot').slice(0, 20)}`;
    const snapshot = hash('snapshot').slice(0, 24);
    const root = `${namespace}/snap_${snapshot}`;
    const sha = 'sha256:' + 'a'.repeat(64);
    content.next.service.stage2a = {
      host_id: 'test-host', installation_id: installation, machine_account: '_agent-bot-machine',
      machine_uid: 501, machine_gid: 501, reader_uid: 301, reader_gid: 301,
      authority_key_sha256: sha, guard_module_sha256: sha,
      preloader_path: 'hq/stage2a-h-preloader.mjs', inventory_source: '/test/inventory.jcs',
      inventory_digest: sha, inventory_limits: { max_files: 20, max_file_bytes: 1024, max_total_bytes: 2048 },
      contracts_source: { tag: 'v0.10.2', commit: 'b'.repeat(40), full_digest: sha,
        full_files: 10, runtime_digest: sha, runtime_files: 10 },
      components: [{ component_id: 'hq' }, { component_id: 'node' }],
    };
    const runtime = [`${root}/bin/node`, '--no-addons', '--disallow-code-generation-from-strings',
      '--import', `${root}/hq/stage2a-h-preloader.mjs`, `${root}/hq/main.mjs`, 'run', '--home',
      '/var/agent-bot-hq/.agent-bot-hq', '--owner-account', 'operator'];
    const outer = ['/usr/bin/ruby', '--disable-gems', `${root}/helpers/darwin-owner.rb`, 'launch', ...runtime];
    content.next.stage2a = {
      namespace, root, inventory_path: `${namespace}/inventory_${snapshot}.jcs`,
      public_key_path: '/Library/Application Support/ai.true-line.agent-bot-hq/soul-authority.pub',
      descriptor_path: '/Library/Application Support/ai.true-line.agent-bot-hq/h-v3/descriptor.json',
      ruby_sha256: sha, guard_module_path: `${root}/hq/stage2a-selected-code.mjs`, launcher_sha256: sha,
      runtime_argv: runtime, outer_argv: outer,
    };
    content.next.plist = content.next.plist.replace(/(<key>ProgramArguments<\/key><array>\n)[\s\S]*?(<\/array>)/,
      (_, start, end) => start + outer.map((arg) => `<string>${arg}</string>\n`).join('') + end);
    change(content, service);
  });
}

test('paired service upgrade accepts the Machine v3 H launch and rejects changed launch inputs', arm, async (t) => {
  const f = await fixture(t, 'hq-service-upgrade');
  await f.pin();
  f.state.saved = stage2aUpgradePlan();
  const exported = await f.issue();
  assert.equal(exported, f.state.raw);
  for (const change of [
    (c) => { c.next.stage2a.outer_argv[5] = '--inspect'; },
    (c) => { c.next.stage2a.root += '-other'; },
    (c) => { c.next.stage2a.descriptor_path += '-other'; },
    (c) => { c.next.service.stage2a.preloader_path = 'hq/other.mjs'; },
    (c) => { c.next.plist = c.next.plist.replace('--no-addons', '--inspect'); },
    (c) => { c.previous.stage2a = c.next.stage2a; },
  ]) {
    f.state.saved = stage2aUpgradePlan(change);
    const before = f.requests.length;
    await assert.rejects(f.issue());
    assert.deepEqual(f.requests.slice(before).map((r) => r.verb), ['members-plans']);
  }
});

test('paired v3 upgrade accepts the installed Darwin release path with its fixed space', arm, async (t) => {
  const f = await fixture(t, 'hq-service-upgrade');
  await f.pin();
  const previousRoot = '/Library/Application Support/ai.true-line.agent-bot-hq/releases/daf7c958';
  const previousNode = `${previousRoot}/node`;
  const withInstalledRelease = (change = () => {}) => stage2aUpgradePlan((c, step) => {
    const oldRelease = c.previous.service.release_dir;
    const oldNode = c.previous.service.node;
    c.previous.service.release_dir = `${previousRoot}/hq`;
    c.previous.service.archive = `${previousRoot}/h-daf7-darwin-source.tar`;
    c.previous.service.node = previousNode;
    c.previous.plist = c.previous.plist.replaceAll(oldRelease, c.previous.service.release_dir)
      .replaceAll(oldNode, previousNode);
    c.next.service.node = previousNode;
    change(c, step);
  });
  f.state.saved = withInstalledRelease();
  assert.equal(await f.issue(), f.state.raw);
  for (const change of [
    (c) => {
      const oldNode = c.previous.service.node;
      const otherNode = oldNode.replace('Application Support', 'Other Support');
      c.previous.service.node = otherNode;
      c.previous.plist = c.previous.plist.replaceAll(oldNode, otherNode);
      c.next.service.node = otherNode;
    },
    (c) => { c.previous.service.archive = c.previous.service.archive.replace('releases/', 'releases/../'); },
  ]) {
    f.state.saved = withInstalledRelease(change);
    const before = f.requests.length;
    await assert.rejects(f.issue());
    assert.deepEqual(f.requests.slice(before).map((r) => r.verb), ['members-plans']);
  }
});

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

const accountsPurpose = 'harness-account-provision';
function provisionPlan(change, broker = true) {
  const file = broker ? 'accounts-and-broker' : 'accounts';
  const original = readFileSync(new URL(`./fixtures/machine-harness-accounts/${file}.json`, import.meta.url), 'utf8');
  const plan = JSON.parse(original);
  if (change) change(plan);
  const plan_canonical = change ? harnessJSON(plan) : original;
  return { plan_id: id, plan_digest: createHash('sha256').update(plan_canonical).digest('hex'), plan_canonical };
}

for (const purpose of ['harness-launch-install', 'harness-launch-retire', accountsPurpose]) {
  test(`paired ${purpose} submits only an owner proof for that exact operation`, arm, async (t) => {
    const saved = purpose === accountsPurpose ? provisionPlan() : harnessPlan(purpose);
    const roleUid = purpose === accountsPurpose ? JSON.parse(saved.plan_canonical).steps[0].uid : 300;
    const f = await fixture(t, purpose, roleUid);
    f.state.saved = saved;
    await assert.rejects(f.issue(), /pin saved by verified Machine status/);
    await f.pin();
    await assert.rejects(machineCommandInHome([purpose, 'export', id, '--socket', f.socket],
      f.home, process.getuid(), undefined, true), /dedicated HQ/);
    const line = await f.issue();
    assert.equal(line, f.state.raw);
    writeFileSync(f.challengeFile, line + '\n');
    const challenge = JSON.parse(line).body;
    assert.equal(challenge.plan_canonical, saved.plan_canonical);
    if (purpose !== accountsPurpose) {
      const policy = JSON.parse(JSON.parse(challenge.plan_canonical).steps[0].content);
      assert.deepEqual(policy.adapters[0].args, ['--member', 'a & b', 'quoted "value"', '', '☃\u2028λ']);
    }
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

function protectedInstallPlan(machineKey, roleUid = 300, change = () => {}) {
  const root = '/Library/Application Support/ai.true-line.agent-bot-hq';
  const installation = 'install-one';
  const sha = value => createHash('sha256').update(value).digest('hex').slice(0, 20);
  const runnerAccount = '_abm-sr-' + sha(installation);
  const bridgeAccount = '_abm-br-' + sha('agent-bot-soul-bridge/v1\0' + installation);
  const artifact = root + '/soul-artifacts/' + sha('agent-bot-soul-endpoint-installation/v1\0' + installation) + '.soul';
  const snapshotRoot = '/private/var/db/managed-machine/soul-snapshots/' + sha('agent-bot-soul-endpoint-installation/v1\0' + installation);
  const snapshot = kind => ({ root_path: snapshotRoot + '/snap_' + createHash('sha256')
    .update('agent-bot-machine/stage2a-install-snapshot/v1\0' + kind + '\0' + installation).digest('hex').slice(0, 24),
  device: '', inode: '', generation: '', birthtime_ns: '', owner_uid: 450, owner_gid: 301, mode: '0555' });
  const node = snapshot('inputs').root_path + '/runtime/bin/node';
  const entry = snapshot('inputs').root_path + '/runtime/bin/agent-bot-souls.mjs';
  const soul = 'agent_11111111-1111-1111-1111-111111111111';
  const emptyDirectory = { path: '', device: 0, inode: '', birth_seconds: 0, birth_nanoseconds: 0 };
  const policy = {
    schema: 'agent-bot-machine/stage2a-installed-authority/v1', machine_account: '_agent-bot-machine',
    machine_uid: 450, machine_gid: 450, plan_owner: 'operator', hq_uid: roleUid,
    approved_until: '2026-11-23T00:00:00Z', canonical_plan: null, root_receipt: null,
    claims: emptyDirectory, snapshot_namespace: emptyDirectory, relay_parent: emptyDirectory,
    legacy_spent_start_ids: [], launcher_sha256: 'a'.repeat(64), artifact_path: artifact,
    runner: { soul_id: soul, installation_id: installation, account: runnerAccount, uid: 301, gid: 301,
      package_root: '/reviewed/soul', package_sha256: 'b'.repeat(64) },
    bridge: { soul_id: soul, installation_id: installation, account: bridgeAccount, uid: 302, gid: 302 },
    measurement_binding: {
      contract: 'machine/v2', kind: 'stage2a-measurement-binding', schema_version: 2,
      installation_id: installation, soul_id: soul, start_id: '', launch_id: '', host_id: 'test-host',
      hq_epoch: 'c'.repeat(64), plan_id: '', installed_plan_digest: '', package_sha256: 'b'.repeat(64),
      soul_artifact_sha256: 'd'.repeat(64), profile_in_force: 'managed-protected',
      claimed_definition_digest: 'sha256:' + 'e'.repeat(64), definition_measurement: 'sha256:' + 'f'.repeat(64),
      launch_input_measurement: 'sha256:' + '1'.repeat(64), snapshots: {
        definition: snapshot('definition'), launch_inputs: snapshot('inputs') },
    },
    definition: [
      { path: 'Contents', kind: 'directory', mode: '0555' },
      { path: 'Contents/SoulInfo.json', kind: 'regular', mode: '0444', size: 1, sha256: 'e'.repeat(64) },
      { path: 'Contents/SoulLock.json', kind: 'regular', mode: '0444', size: 1, sha256: 'e'.repeat(64) },
      { path: 'Contents/opt', kind: 'directory', mode: '0555' },
      { path: 'Contents/primitives', kind: 'directory', mode: '0555' },
    ],
    launch_inputs: { files: ['host/adapters.json', 'host/installation.json', 'runtime/bin/agent-bot-souls.mjs', 'runtime/bin/node', 'runtime/lib/test-adapter']
      .map(path => ({ path, kind: 'regular', mode: path === 'runtime/bin/node' ? '0555' : '0444',
        size: path === 'runtime/lib/test-adapter' ? 256 * 1024 * 1024 : 1, sha256: 'f'.repeat(64) })),
      host_projection: { adapters: {}, installation: {} }, selected_command: node, argv: [],
      environment: {}, effective_config: {}, system_images: { product_version: 'test', build_version: 'test',
        darwin_kernel: 'test', selected: [{ path: '/usr/bin/sandbox-exec', signing_requirement: 'test', cdhash: 'a'.repeat(40) }] },
      sandbox_policy_digest: 'sha256:' + '2'.repeat(64), component_digests: { bridge: 'sha256:' + '3'.repeat(64) } },
    node, entry, bridge_executable: { path: '/reviewed/bridge', sha256: '3'.repeat(64) },
    bridge_qualification: { model: 'test-model', request_sha256: 'sha256:' + '4'.repeat(64),
      headers_sha256: 'sha256:' + '5'.repeat(64), client_key_sha256: 'sha256:' + '6'.repeat(64),
      http_host: 'localhost', messages_query: '?fixture=1', response_text: 'pilot response' },
  };
  const plan = {
    version: 3, hq_account: role, dir: 'none', members: [bridgeAccount, runnerAccount].sort(),
    steps: [{ kind: 'soul-protected-launch', target: installation, action: 'write',
      detail: 'install exact pinned launcher, sandbox policies, Machine public key, per-Soul rule and A-owned authority; publish root applied receipt' }],
    purpose: protectedInstallPurpose,
    soul_protected_launch: { schema: 'agent-bot-machine/soul-protected-launch-install/v1',
      machine_public_key: machineKey, artifact_source: '/reviewed/artifact.soul',
      bridge_binary_source: '/reviewed/bridge', definition_source: '/reviewed/definition.json',
      launch_inputs_source: '/reviewed/inputs.json', policy },
  };
  change(plan);
  const plan_canonical = harnessJSON(plan);
  return { plan_id: id, plan_canonical, plan_digest: createHash('sha256').update(plan_canonical).digest('hex') };
}

function runtimeV3InstallPlan(machineKey, change = () => {}) {
  return protectedInstallPlan(machineKey, 300, plan => {
    const request = plan.soul_protected_launch;
    request.schema = 'agent-bot-machine/soul-protected-launch-install/v3';
    const policy = request.policy;
    delete request.policy;
    request.runtime_v3 = {
      inventory_source: '/reviewed/r-inventory.jcs', inventory_digest: 'sha256:' + '7'.repeat(64),
      limits: { max_files: 512, max_file_bytes: 402653184, max_total_bytes: 1073741824 },
      components: ['adapter', 'node', 'souls'].map(component => ({
        component_id: component, source_repository: 'true-line/agent-bot-' + component,
        source_commit: 'a'.repeat(40), artifact_format: 'tar',
        artifact_source: `/reviewed/${component}.tar`, release_artifact_sha256: 'sha256:' + '8'.repeat(64),
        manifest_source: `/reviewed/${component}.jcs`, release_manifest_sha256: 'sha256:' + '9'.repeat(64),
      })),
      source_roots: { adapter: '/reviewed/adapter', node: '/reviewed/node', souls: '/reviewed/souls' },
    };
    request.policy = policy;
    const installation = request.policy.measurement_binding.installation_id;
    const domain = 'R-runtime';
    const hash = value => createHash('sha256').update(value).digest('hex');
    const slot = hash(`agent-bot/stage2a-domain-slot/v3\0${domain}\0${installation}`).slice(0, 20);
    const name = hash(`agent-bot/stage2a-domain-snapshot/v3\0${domain}\0${installation}`).slice(0, 24);
    const sealed = `/private/var/db/managed-machine/soul-snapshots/r_${slot}/snap_${name}`;
    request.policy.node = `${sealed}/runtime/bin/node`;
    request.policy.entry = `${sealed}/runtime/bin/agent-bot-souls.mjs`;
    request.policy.launch_inputs.selected_command = request.policy.node;
    plan.steps[0].detail = 'seal reviewed R runtime in A, persist per-Soul authority and root applied receipt; defer the protected launch rule';
    change(plan);
  });
}

function soulBridgePlan(change = () => {}) {
  const installation = 'install-one';
  const name = '_abm-br-' + createHash('sha256').update('agent-bot-soul-bridge/v1\0' + installation).digest('hex').slice(0, 20);
  const runner = '_abm-sr-' + createHash('sha256').update(installation).digest('hex').slice(0, 20);
  const slot = createHash('sha256').update('agent-bot-soul-endpoint-installation/v1\0' + installation).digest('hex').slice(0, 20);
  const root = '/Library/Application Support/ai.true-line.agent-bot-hq';
  const directory = (target, owner, group, mode, uid, gid) => ({ kind: 'directory', target,
    action: 'create', owner, group, mode, ...(uid === undefined ? {} : { uid, gid }) });
  const plan = { version: 3, hq_account: role, dir: 'none', members: [name], steps: [
    { kind: 'hq-account', target: role, action: 'none', group: role, mode: '0700',
      detail: 'exists; dedicated; home /var/agent-bot-hq; its password is checked at apply', uid: 300, gid: 300 },
    { kind: 'account', target: name, action: 'create', group: name, mode: '0700',
      detail: `Soul bridge home /var/agent-bot-soul-bridge-${name}, shell /usr/bin/false, private group, no password, no other groups`, uid: 302, gid: 302 },
    ...[`${root}/ipc`, `${root}/m`, `${root}/s`, `${root}/r`].map(path => directory(path, 'root', 'wheel', '0755')),
    directory(`${root}/ipc/${name}`, role, name, '2750', 300, 302),
    directory(`${root}/m/${slot}`, runner, name, '2750', 301, 302),
    directory(`${root}/s/${slot}`, name, runner, '2750', 302, 301),
    directory(`${root}/r/${slot}`, role, runner, '2750', 300, 301),
  ], purpose: soulBridgeAccountsPurpose, soul_bridges: [
    { soul_id: 'agent_11111111-1111-1111-1111-111111111111', installation_id: installation, account: name },
  ] };
  change(plan);
  const plan_canonical = harnessJSON(plan);
  return { plan_id: id, plan_canonical, plan_digest: createHash('sha256').update(plan_canonical).digest('hex') };
}

test('paired v3 R-only install and B provisioning preserve signed owner handoff', arm, async t => {
  const r = await fixture(t, protectedInstallPurpose);
  const machineKey = JSON.parse(r.state.saved.plan_canonical).soul_protected_launch.machine_public_key;
  r.state.saved = runtimeV3InstallPlan(machineKey);
  await r.pin();
  const exportedR = await r.issue();
  writeFileSync(r.challengeFile, exportedR + '\n');
  writeFileSync(r.proofFile, JSON.stringify(proof(JSON.parse(exportedR).body, r.owner)));
  assert.equal((await r.approve()).state, 'approved');
  const b = await fixture(t, soulBridgeAccountsPurpose);
  b.state.saved = soulBridgePlan();
  await b.pin();
  const exportedB = await b.issue();
  writeFileSync(b.challengeFile, exportedB + '\n');
  writeFileSync(b.proofFile, JSON.stringify(proof(JSON.parse(exportedB).body, b.owner)));
  assert.equal((await b.approve()).state, 'approved');
  const fresh = await b.issue();
  writeFileSync(b.challengeFile, fresh + '\n');
  assert.equal((await b.cancel()).state, 'cancelled');
});

test('v3 R and B handoffs reject changed scope before owner challenge', arm, async t => {
  const r = await fixture(t, protectedInstallPurpose);
  const machineKey = JSON.parse(r.state.saved.plan_canonical).soul_protected_launch.machine_public_key;
  await r.pin();
  for (const change of [
    p => { p.soul_protected_launch.runtime_v3.source_roots.node = '/private/var/db/managed-machine/soul-snapshots/r_bad'; },
    p => { p.soul_protected_launch.runtime_v3.components[1].release_manifest_sha256 = 'bad'; },
    p => { p.soul_protected_launch.policy.node = '/reviewed/node'; },
    p => { p.steps[0].detail = 'install rule now'; },
  ]) {
    r.state.saved = runtimeV3InstallPlan(machineKey, change);
    await assert.rejects(r.issue(), /unsupported structure|outside the paired protected/);
  }
  const b = await fixture(t, soulBridgeAccountsPurpose);
  await b.pin();
  for (const change of [
    p => { p.steps.at(-1).mode = '2770'; },
    p => { p.steps.at(-2).owner = role; },
    p => { p.steps[1].uid = 300; p.steps[1].gid = 300; },
  ]) {
    b.state.saved = soulBridgePlan(change);
    await assert.rejects(b.issue(), /unsupported structure|outside the paired HQ Soul bridge/);
  }
});

test('v3 R handoff binds the optional two-member owner projection without widening v1', arm, () => {
  const machineKey = 'a'.repeat(64);
  const memberSet = 'sha256:' + 'b'.repeat(64);
  const saved = runtimeV3InstallPlan(machineKey, plan => {
    const request = plan.soul_protected_launch;
    const policy = request.policy;
    policy.bridge_qualification.client_key_sha256 = 'sha256:da4fec28d868ca5cf8f00f43869f703f138bd4211683b8637a751b904860ddf0';
    policy.member_bridge_qualifications = ['adapter', 'souls'].map(member_id => ({
      member_id, ...policy.bridge_qualification,
    }));
    delete request.policy;
    request.owner_plan_member_set_sha256 = memberSet;
    request.policy = policy;
  });
  assert.equal(validatedMembersPlan(id, { state: 'found', body: saved }).soul_protected_launch.owner_plan_member_set_sha256, memberSet);
  const old = protectedInstallPlan(machineKey, 300, plan => {
    plan.soul_protected_launch.owner_plan_member_set_sha256 = memberSet;
  });
  assert.throws(() => validatedMembersPlan(id, { state: 'found', body: old }), /unsupported structure/);
});

test('paired protected Soul install exports the signed plan and forwards exact owner proof', arm, async (t) => {
  const f = await fixture(t, protectedInstallPurpose);
  await assert.rejects(f.issue(), /pin saved by verified Machine status/);
  await f.pin();
  await assert.rejects(machineCommandInHome([protectedInstallPurpose, 'export', id, '--socket', f.socket],
    f.home, process.getuid(), undefined, true), /dedicated HQ/);
  const line = await f.issue();
  assert.equal(line, f.state.raw);
  assert.deepEqual(f.requests.map(r => r.option ?? r.verb), ['status', 'get', 'challenge']);
  const challenge = JSON.parse(line).body;
  assert.equal(challenge.plan_canonical, f.state.saved.plan_canonical);
  writeFileSync(f.challengeFile, line + '\n');
  writeFileSync(f.proofFile, JSON.stringify(proof({ ...challenge, action: 'harness-launch-install' }, f.owner)));
  await assert.rejects(f.approve(), /invalid owner signature/);
  assert.equal(f.requests.length, 3);
  writeFileSync(f.proofFile, JSON.stringify(proof(challenge, f.owner)));
  assert.equal((await f.approve()).state, 'approved');
  assert.ok(f.requests.at(-1).owner_signature);
  await assert.rejects(f.approve(), /MM_DAEMON_PEER_REFUSED/);
});

test('paired protected Soul install rejects altered scope before issuing a challenge', arm, async (t) => {
  const f = await fixture(t, protectedInstallPurpose);
  await f.pin();
  const machineKey = JSON.parse(f.state.saved.plan_canonical).soul_protected_launch.machine_public_key;
  for (const change of [
    p => { p.soul_protected_launch.machine_public_key = 'f'.repeat(64); },
    p => { p.soul_protected_launch.policy.hq_uid = 399; },
    p => { p.soul_protected_launch.policy.artifact_path = '/tmp/other.soul'; },
    p => { p.soul_protected_launch.policy.claims.inode = '1'; },
    p => { p.soul_protected_launch.policy.runner.uid = p.soul_protected_launch.policy.bridge.uid; },
    p => { p.soul_protected_launch.policy.measurement_binding.soul_artifact_sha256 = ''; },
    p => { p.soul_protected_launch.policy.definition = [null]; },
    p => { p.soul_protected_launch.policy.launch_inputs = []; },
    p => { p.soul_protected_launch.policy.bridge_executable = {}; },
    p => { p.soul_protected_launch.policy.bridge_qualification = {}; },
    p => { delete p.soul_protected_launch.policy.measurement_binding.snapshots; },
    p => { p.soul_protected_launch.policy.launch_inputs.files.at(-1).size = 256 * 1024 * 1024 + 1; },
    p => { p.soul_protected_launch.policy.definition[1].size = 256 * 1024 * 1024 + 1; },
    p => { for (const file of p.soul_protected_launch.policy.launch_inputs.files) file.size = 220 * 1024 * 1024; },
    p => { p.steps[0].detail = 'install a different policy'; },
    p => { p.steps.push({ kind: 'file', target: '/tmp/extra', action: 'write' }); },
    p => { p.soul_protected_launch.launch_inputs_source = '/tmp/../other'; },
    p => { p.purpose = 'harness-launch-install'; },
  ]) {
    f.state.saved = protectedInstallPlan(machineKey, 300, change);
    const before = f.requests.length;
    await assert.rejects(f.issue());
    assert.deepEqual(f.requests.slice(before).map(r => r.verb), ['members-plans']);
  }
});

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

test('paired account provisioning checks Machine’s exact account and optional broker steps before challenging', arm, async (t) => {
  const f = await fixture(t, accountsPurpose, 320);
  await f.pin();
  f.state.saved = provisionPlan(undefined, false);
  assert.equal(JSON.parse(await f.issue()).body.plan_canonical, f.state.saved.plan_canonical);
  f.state.saved = provisionPlan(p => {
    const member = p.steps[2];
    member.action = 'repair';
    member.detail = 'exists; home /var/agent-bot-harness-_spec has mode 0755 and is set to 0700; its password is checked at apply';
  });
  await f.issue();
  f.state.saved = provisionPlan(p => {
    p.steps[2].action = 'none';
    p.steps[2].detail = 'exists; home /var/agent-bot-harness-_spec; its password is checked at apply';
    for (const dir of p.steps.slice(3)) dir.action = 'none';
  });
  await f.issue();
  for (const change of [
    p => { delete p.purpose; }, p => { p.purpose = 'harness-launch-install'; },
    p => { p.steps[0].uid = p.steps[0].gid = 321; },
    p => { p.steps[0].action = 'repair'; }, p => { p.steps[0].group = 'wheel'; },
    p => { p.steps[1].uid = p.steps[1].gid = p.steps[0].uid; },
    p => { p.steps[2].uid = p.steps[2].gid = p.steps[1].uid; },
    p => { p.steps[2].uid = p.steps[2].gid = 502; }, p => { p.steps[2].gid++; },
    p => { p.steps[2].mode = '0755'; }, p => { p.steps[2].detail += '\nsubstitute'; },
    p => { p.steps[2].content = 'additional action'; }, p => { p.steps[2].action = 'remove'; },
    p => { p.steps[2].action = 'repair'; }, p => { p.members.reverse(); }, p => { p.steps.pop(); },
    p => { p.dir = '/tmp'; }, p => { p.steps[3].owner = '_lead'; },
    p => { p.steps[4].target = p.steps[5].target; }, p => { p.steps[4].mode = '0777'; },
    p => { p.steps[5].group = '_lead'; }, p => { p.steps.push(JSON.parse(savedPlan().plan_canonical).steps[1]); },
  ]) {
    f.state.saved = provisionPlan(change);
    const before = f.requests.length;
    await assert.rejects(f.issue());
    assert.deepEqual(f.requests.slice(before).map(r => r.verb), ['members-plans']);
  }
  f.state.saved = provisionPlan();
  f.state.tweak = c => { c.expires_at -= 121; };
  await assert.rejects(f.issue(), /expired/);
});

test('paired account scope bounds the canonical bytes even for an otherwise valid batch', arm, async (t) => {
  const f = await fixture(t, accountsPurpose, 320);
  await f.pin();
  const build = count => provisionPlan(p => {
    const [hq, , account, parent, , dir] = p.steps;
    p.members = Array.from({ length: count }, (_, n) => '_harness' + String(n).padStart(2, '0') + 'x'.repeat(22));
    p.steps = [hq, ...p.members.map((name, i) => ({ ...account, target: name, group: name,
      detail: account.detail.replace('_spec', name), uid: i < 20 ? 300 + i : 301 + i, gid: i < 20 ? 300 + i : 301 + i })),
    parent, ...p.members.map(name => ({ ...dir, target: p.dir + '/' + name, group: name }))];
  });
  f.state.saved = build(55);
  assert.ok(Buffer.byteLength(f.state.saved.plan_canonical) < 32768);
  await f.issue();
  f.state.saved = build(65);
  assert.ok(Buffer.byteLength(f.state.saved.plan_canonical) > 32768);
  const before = f.requests.length;
  await assert.rejects(f.issue(), /unsupported structure/);
  assert.deepEqual(f.requests.slice(before).map(r => r.verb), ['members-plans']);
});

function qualificationPlan(change, { previewOnly = false } = {}) {
  const raw = readFileSync(new URL('./fixtures/machine-harness-qualification/plan.json', import.meta.url), 'utf8');
  const plan = JSON.parse(raw);
  if (!previewOnly) plan.steps[0].detail = qualificationApprovalDetail;
  if (change) {
    const run = JSON.parse(plan.steps[0].content);
    change(plan, run);
    plan.steps[0].content = JSON.stringify(run);
  }
  const plan_canonical = JSON.stringify(plan) + '\n';
  return { plan_id: id, plan_digest: createHash('sha256').update(plan_canonical).digest('hex'), plan_canonical };
}

test('paired qualification transfers only the exact signed plan and accepts a purpose-bound proof', arm, async (t) => {
  const f = await fixture(t, qualificationPurpose);
  await assert.rejects(machineCommandInHome(
    [qualificationPurpose, 'export', id, '--socket', f.socket], f.home, process.getuid(), undefined, true,
  ), /requires the dedicated HQ service account/);
  await assert.rejects(f.issue(), /pin saved by verified Machine status/);
  assert.equal(f.requests.length, 0);
  await f.pin();
  const line = await f.issue();
  assert.equal(line, f.state.raw);
  const c = JSON.parse(line).body;
  assert.equal(c.action, qualificationPurpose);
  assert.equal(c.plan_canonical, f.state.saved.plan_canonical);
  assert.notEqual(c.plan_digest, qualificationPlan(undefined, { previewOnly: true }).plan_digest);
  writeFileSync(f.challengeFile, line + '\n');
  const wrongPurpose = ['agent-bot-machine-owner/v1', 'harness-launch-install', c.machine_key, c.hq_key,
    c.owner_key, c.plan_id, c.plan_digest, c.nonce, c.expires_at, ''].join('\n');
  writeFileSync(f.proofFile, JSON.stringify(proof(c, f.owner, wrongPurpose)));
  await assert.rejects(f.approve(), /invalid owner signature/);
  assert.deepEqual(f.requests.map(r => r.option ?? r.verb), ['status', 'get', 'challenge']);
  writeFileSync(f.proofFile, JSON.stringify(proof(c, f.owner)));
  assert.deepEqual(await f.approve(), {
    state: 'approved', plan_id: c.plan_id, plan_digest: c.plan_digest,
    approved_at: f.state.approvedAt, expires_at: f.state.expiresAt,
  });
  await assert.rejects(f.approve(), /MM_DAEMON_PEER_REFUSED/);
  const second = await f.issue();
  writeFileSync(f.challengeFile, second + '\n');
  assert.equal((await f.cancel()).state, 'cancelled');
  f.state.tweak = challenge => {
    Object.assign(challenge, qualificationPlan((_plan, run) => {
      run.request.test_provider.configuration_sha256 = 'f'.repeat(64);
    }));
  };
  await assert.rejects(f.issue(), /challenge differs from the retrieved plan/);
});

test('paired qualification refuses a re-digested plan outside the fixed test scope before challenge', arm, async (t) => {
  const f = await fixture(t, qualificationPurpose);
  await f.pin();
  for (const change of [
    (plan) => { plan.steps[0].action = 'create'; },
    (_plan, run) => { run.one_use = false; },
    (_plan, run) => { run.member_state = 'ambient'; },
    (_plan, run) => { run.gates[3].profile = 'managed-protected'; },
    (_plan, run) => { run.request.runner.command = '/usr/bin/true'; },
    (_plan, run) => { run.request.test_provider.configuration_sha256 = 'missing'; },
  ]) {
    f.state.saved = qualificationPlan(change);
    const before = f.requests.length;
    await assert.rejects(f.issue(), /unsupported structure/);
    assert.equal(f.requests.length, before + 1);
    assert.equal(f.requests.at(-1).option, 'get');
  }
  f.state.saved = qualificationPlan();
  const before = f.requests.length;
  await assert.rejects(f.run('harness-launch-install', 'export', id, '--socket', f.socket),
    /outside the paired HQ qualification plan scope/);
  assert.equal(f.requests.length, before + 1);
  assert.equal(f.requests.at(-1).option, 'get');
});

test('paired qualification keeps legacy previews readable and refuses them for a proof exchange', arm, async (t) => {
  const f = await fixture(t, qualificationPurpose);
  await f.pin();
  const current = f.state.saved;
  const old = qualificationPlan(undefined, { previewOnly: true });
  assert.equal(old.plan_digest, 'bcb92029dfefdc36c87eb6d48b0d851216206b68c659e940fc659c992767889a');
  f.state.saved = old;
  const read = await f.run('members-plans', 'get', id, '--socket', f.socket);
  assert.equal(read.state, 'found');
  const { plan_id, plan_digest, plan_canonical } = read;
  assert.deepEqual({ plan_id, plan_digest, plan_canonical }, old);
  await assert.rejects(f.issue(), /outside the paired HQ qualification plan scope/);
  assert.deepEqual(f.requests.map(r => r.option ?? r.verb), ['status', 'get', 'get']);

  // A correctly signed challenge from an earlier peer still cannot turn
  // preview-only bytes into an approval operation.
  f.state.saved = current;
  f.state.tweak = challenge => Object.assign(challenge, old);
  await assert.rejects(f.issue(), /outside the paired HQ qualification plan scope/);
  const line = f.state.raw;
  writeFileSync(f.challengeFile, line + '\n');
  writeFileSync(f.proofFile, JSON.stringify(proof(JSON.parse(line).body, f.owner)));
  const before = f.requests.length;
  await assert.rejects(f.approve(), /outside the paired HQ qualification plan scope/);
  assert.equal(f.requests.length, before);
});


test('runner account owner handoff binds purpose and HQ role without a harness', arm, async (t) => {
  const installation = 'inst_existing';
  const runner = '_abm-sr-' + createHash('sha256').update(installation).digest('hex').slice(0, 20);
  const plan = { version: 3, hq_account: role, dir: 'none', members: [runner], steps: [
    { kind: 'hq-account', target: role, action: 'none', group: role, mode: '0700',
      detail: 'exists; dedicated; home /var/agent-bot-hq; its password is checked at apply', uid: 300, gid: 300 },
    { kind: 'account', target: runner, action: 'create', group: runner, mode: '0700',
      detail: `Soul runner home /var/agent-bot-soul-runner-${runner}, shell /usr/bin/false, private group, no password, no other groups`,
      uid: 301, gid: 301 },
  ], purpose: 'soul-runner-provision', soul_runners: [
    { soul_id: 'agent_01234567-0123-4567-0123-456789abcdef', installation_id: installation, account: runner },
  ] };
  const plan_canonical = JSON.stringify(plan) + '\n';
  const saved = { plan_id: id, plan_digest: createHash('sha256').update(plan_canonical).digest('hex'), plan_canonical };
  const f = await fixture(t, 'soul-runner-provision', 300);
  f.state.saved = saved;
  await f.pin();
  const line = await f.issue();
  writeFileSync(f.challengeFile, line);
  const challenge = JSON.parse(line).body;
  writeFileSync(f.proofFile, JSON.stringify(proof(challenge, f.owner)));
  assert.equal((await f.approve()).state, 'approved');

  const wrongRole = await fixture(t, 'soul-runner-provision', 302);
  wrongRole.state.saved = saved;
  await wrongRole.pin();
  await assert.rejects(wrongRole.issue(), /outside the paired HQ Soul runner account scope/);
  assert.deepEqual(wrongRole.requests.map(r => r.verb), ['status', 'members-plans']);

  const wrongPurpose = await fixture(t, protectedInstallPurpose, 300);
  wrongPurpose.state.saved = saved;
  await wrongPurpose.pin();
  await assert.rejects(wrongPurpose.issue(), /outside the paired protected Soul launch install plan scope/);
  assert.deepEqual(wrongPurpose.requests.map(r => r.verb), ['status', 'members-plans']);
});

function cooperativePlan(machineKey, roleUid = 300, change = () => {}) {
  const installation = 'installation-1';
  const account = `_abm-sr-${createHash('sha256').update(installation).digest('hex').slice(0, 20)}`;
  const p = { version: 3, hq_account: role, dir: 'none', members: [account], steps: [{
    kind: 'soul-cooperative-launch', target: installation, action: 'write',
    detail: 'seal R runtime and frozen Soul inputs; install fixed per-R launchd WatchPaths job; A:runner-group 2700 staging dir, 2750 request dir, and 2770 completion dir; write A-only signed pending journal before one-use claim; publish applied root receipt'
  }], purpose: cooperativeInstallPurpose, soul_cooperative_launch: {
    schema: 'agent-bot-machine/soul-cooperative-launch-install/v3', purpose: cooperativeInstallPurpose,
    profile_in_force: 'managed-cooperative', host_id: 'host-1', hq_installation_id: 'hq-1',
    h_owner_plan_digest: 'a'.repeat(64), hq_uid: roleUid, machine_uid: 501, machine_gid: 20, hq_epoch: 'a'.repeat(64),
    machine_public_key_base64url: Buffer.from(machineKey, 'hex').toString('base64url'), source_package_path: '/source',
    definition_source: '/source', launch_inputs_source: '/inputs', definition: [], launch_inputs: {},
    definition_measurement: 'sha256:' + 'a'.repeat(64), launch_input_measurement: 'sha256:' + 'b'.repeat(64),
    state_root: '/state', runtime_root: '/runtime', runner: { soul_id: 'agent_12345678-1234-1234-1234-123456789abc', installation_id: installation,
      account, uid: 311, gid: 311, package_root: '/sealed', package_sha256: 'b'.repeat(64) },
    soul_artifact_sha256: 'c'.repeat(64), definition_sha256: 'd'.repeat(64), node_path: '/node',
    node_sha256: 'e'.repeat(64), entry: 'bin/agent-bot-souls.mjs', launcher_path: '/launcher',
    launcher_sha256: 'f'.repeat(64), approved_until: '2030-01-01T00:00:00Z', runtime_v3: {},
    adapter_release: {}, hq_broker: {}, adapter_transport: 'direct-comms', reviewed_start_id: 'st_' + 'a'.repeat(24),
    adapter_code_inputs: ['one']
  } };
  change(p);
  const plan_canonical = JSON.stringify(p) + '\n';
  return { plan_id: id, plan_digest: createHash('sha256').update(plan_canonical).digest('hex'), plan_canonical };
}

test('paired cooperative install exports and approves the exact Machine challenge', arm, async t => {
  const f = await fixture(t, cooperativeInstallPurpose);
  await f.pin();
  const line = await f.issue();
  assert.equal(JSON.parse(line).body.plan_canonical, f.state.saved.plan_canonical);
  writeFileSync(f.challengeFile, line + '\n');
  writeFileSync(f.proofFile, JSON.stringify(proof(JSON.parse(line).body, f.owner)));
  assert.equal((await f.approve()).state, 'approved');
});

test('paired cooperative install rejects wrong pairing and scope before challenge', arm, async t => {
  const f = await fixture(t, cooperativeInstallPurpose);
  await f.pin();
  const machineKey = Buffer.from(JSON.parse(f.state.saved.plan_canonical).soul_cooperative_launch.machine_public_key_base64url, 'base64url').toString('hex');
  for (const change of [p => { p.soul_cooperative_launch.hq_uid = 301; },
    p => { p.soul_cooperative_launch.machine_public_key_base64url = Buffer.alloc(32, 1).toString('base64url'); },
    p => { p.soul_cooperative_launch.profile_in_force = 'managed-protected'; },
    p => { p.steps[0].target = 'other'; }, p => { p.members.push('_other'); },
    p => { delete p.soul_cooperative_launch.runtime_v3; },
    p => { delete p.soul_cooperative_launch.reviewed_start_id; },
    p => { p.soul_cooperative_launch.reviewed_start_id = 'other'; },
    p => {
      const value = p.soul_cooperative_launch.reviewed_start_id;
      delete p.soul_cooperative_launch.reviewed_start_id;
      p.soul_cooperative_launch.reviewed_start_id = value;
    },
    p => { p.soul_cooperative_launch.unexpected = true; }]) {
    f.state.saved = cooperativePlan(machineKey, 300, change);
    await assert.rejects(f.issue(), /unsupported structure|outside the paired cooperative/);
    assert.notEqual(f.requests.at(-1).option, 'challenge');
  }
});

test('cooperative plans exceeding the signed channel limit are refused', () => {
  const saved = cooperativePlan('a'.repeat(64), 300, p => {
    p.soul_cooperative_launch.launch_inputs.payload = 'x'.repeat(64 * 1024);
  });
  assert.throws(() => validatedMembersPlan(id, { state: 'found', body: saved }), /unsupported structure/);
});
