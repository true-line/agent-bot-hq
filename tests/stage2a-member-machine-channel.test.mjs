import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { canonicalBytes } from '../sdk/wire/canonical-json.mjs';
import { machineCommandInHome } from '../hq/machine-channel.mjs';

const sha = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;

test('paired Machine channel carries the exact five protected member prestart verbs', async (t) => {
  const home = mkdtempSync(join(tmpdir(), 'hq-member-machine-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const socket = join(home, 'machine.sock');
  await machineCommandInHome(['identity'], home, process.getuid());
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  writeFileSync(join(home, '.config/agent-machine/daemon.pub'),
    publicKey.export({ format: 'der', type: 'spki' }).subarray(-32), { mode: 0o600 });
  const selectors = { reservation_sha256: sha('reservation'), installation_id: 'inst_fixture',
    start_id: `st_${'1'.repeat(24)}`, launch_id: `ln_${'2'.repeat(24)}`,
    plan_id: 'plan-fixture', plan_digest: '3'.repeat(64), hq_epoch: '4'.repeat(64) };
  const signed = canonicalBytes({ kind: 'signed-fixture' });
  const invocation = canonicalBytes({ kind: 'member-invocation' });
  const map = canonicalBytes({ kind: 'provisional-map' });
  const states = { 'stage2a-member-set-assign': 'member-set-assigned',
    'stage2a-member-provisional-map': 'member-map-withheld',
    'stage2a-member-child-grant': 'member-child-granted',
    'stage2a-member-child-observe': 'member-children-observed',
    'stage2a-member-ready': 'member-ready' };
  const seen = [];
  const server = createServer((stream) => {
    let input = '';
    stream.on('data', (chunk) => {
      input += chunk;
      if (!input.includes('\n')) return;
      try {
        const request = JSON.parse(input.slice(0, input.indexOf('\n')));
        const fields = JSON.parse(Buffer.from(request.stage2a_request, 'base64url').toString());
        seen.push({ verb: request.verb, fields });
        const state = states[request.verb];
        assert.ok(state);
        const body = request.verb === 'stage2a-member-provisional-map'
          ? { accepted: true, sha256: fields.provisional_hq_mapping_sha256 }
          : { envelope_base64url: signed.toString('base64url'), sha256: sha(signed),
            ...(request.verb === 'stage2a-member-child-grant'
              ? { invocation_base64url: invocation.toString('base64url') } : {}) };
        const response = { ok: true, state, timestamp: request.timestamp,
          nonce: randomBytes(16).toString('base64url'), request_nonce: request.nonce, body };
        response.signature = sign(null, Buffer.from([true, '', '', state, JSON.stringify(body),
          response.timestamp, response.nonce, response.request_nonce].join('\n')),
        privateKey).toString('base64');
        stream.end(JSON.stringify(response) + '\n');
      } catch (error) { stream.destroy(error); }
    });
  });
  await new Promise((resolve, reject) => server.once('error', reject).listen(socket, resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const run = (verb, fields) => machineCommandInHome([verb, '--socket', socket], home,
    process.getuid(), fields);
  assert.deepEqual((await run('stage2a-member-set-assign', selectors)).envelope, signed);
  const mapped = await run('stage2a-member-provisional-map', { ...selectors,
    provisional_hq_mapping_base64url: map.toString('base64url'), provisional_hq_mapping_sha256: sha(map) });
  assert.equal(mapped.accepted, true);
  const member = { member_id: 'm_lead', member_selector: `mb_${'5'.repeat(64)}`,
    member_launch_id: `ln_${'6'.repeat(24)}`, grant_sha256: sha('grant'),
    child_launcher_pid: 4101, child_pid: 4201 };
  const granted = await run('stage2a-member-child-grant', { ...selectors,
    member_id: member.member_id, member_selector: member.member_selector,
    nonce: Buffer.alloc(32, 7).toString('base64url'), pid: member.child_launcher_pid });
  assert.deepEqual(granted.invocation, invocation);
  assert.ok(granted.grantLine.includes(Buffer.from(sha(signed))));
  const sibling = { ...member, member_id: 'm_spec', member_selector: `mb_${'7'.repeat(64)}`,
    member_launch_id: `ln_${'8'.repeat(24)}`, child_launcher_pid: 4102, child_pid: 4202 };
  assert.deepEqual((await run('stage2a-member-child-observe', { ...selectors,
    members: [member, sibling] })).envelope, signed);
  const arm = (id) => ({ arm_request: { member_id: id }, arm_result: { member_id: id } });
  assert.deepEqual((await run('stage2a-member-ready', { ...selectors,
    child_observation_envelope_sha256: sha('observation'),
    member_b_authority_envelope_sha256: sha('authority'),
    arms: [arm('m_lead'), arm('m_spec')] })).envelope, signed);
  assert.deepEqual(seen.map((entry) => entry.verb), Object.keys(states));
});
