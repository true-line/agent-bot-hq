import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import test from 'node:test';
import { canonicalBytes } from '../sdk/wire/canonical-json.mjs';
import { machineCommandInHome } from '../hq/machine-channel.mjs';

const hash = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const captureId = Buffer.alloc(32, 7).toString('base64url');
const reservation = hash('reservation');
const startId = `st_${'a'.repeat(24)}`;
const launchId = `ln_${'b'.repeat(24)}`;
const hqEpoch = 'c'.repeat(64);
const planDigest = 'd'.repeat(64);

test('paired ACP capture upload uses closed signed verbs, bounded chunks and digest-only receipt', async (t) => {
  const home = mkdtempSync(join(tmpdir(), 'hq-capture-channel-'));
  t.after(() => rmSync(home, { recursive: true, force: true }));
  const socket = join(home, 'machine.sock');
  const run = (verb, fields) => machineCommandInHome([verb, '--socket', socket], home,
    process.getuid(), fields);
  await machineCommandInHome(['identity'], home, process.getuid());
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  writeFileSync(join(home, '.config/agent-machine/daemon.pub'),
    publicKey.export({ format: 'der', type: 'spki' }).subarray(12), { mode: 0o600 });
  const receipt = canonicalBytes({ kind: 'hq.soul.started', seq: 1 });
  const sealed = canonicalBytes({ kind: 'stage2a.acp.sealed', in: hash('in'), out: hash('out') });
  const observed = [];
  let invalidLookup = false;
  let invalidAppend = false;
  let invalidFinish = false;
  const server = createServer((stream) => {
    let input = '';
    stream.on('data', (chunk) => {
      input += chunk;
      if (!input.includes('\n')) return;
      try {
        const request = JSON.parse(input.slice(0, input.indexOf('\n')));
        const fields = JSON.parse(Buffer.from(request.stage2a_request, 'base64url').toString('utf8'));
        observed.push({ verb: request.verb, fields });
        const state = {
          'stage2a-capture-begin': 'capture-begun',
          'stage2a-capture-append': 'capture-appended',
          'stage2a-capture-finish': 'capture-finished',
          'stage2a-lookup': 'found',
        }[request.verb];
        const body = request.verb === 'stage2a-lookup'
          ? { installation_id: 'installation-1', plan_id: 'plan-1', plan_digest: planDigest,
            runner_account: `_abm-sr-${createHash('sha256').update('installation-1').digest('hex').slice(0, 20)}`,
            bridge_account: `_abm-br-${createHash('sha256').update('agent-bot-soul-bridge/v1\0installation-1').digest('hex').slice(0, 20)}`,
            qualification_start_id: invalidLookup ? 'st_wrong' : startId }
          : request.verb === 'stage2a-capture-begin'
          ? { capture_id: captureId, expires_at_ms: fields.selector.expires_at_ms }
          : request.verb === 'stage2a-capture-append'
            ? { capture_id: captureId, channel: fields.channel,
              next_offset_bytes: fields.offset + Buffer.from(fields.chunk_base64url, 'base64url').length
                - Number(invalidAppend) }
            : { capture_id: captureId, receipt_envelope_base64url: sealed.toString('base64url'),
              receipt_sha256: invalidFinish ? hash('wrong') : hash(sealed) };
        const response = { ok: true, state, timestamp: request.timestamp,
          nonce: randomBytes(16).toString('base64url'), request_nonce: request.nonce, body };
        response.signature = sign(null, Buffer.from([true, '', '', state, JSON.stringify(body),
          response.timestamp, response.nonce, response.request_nonce].join('\n')), privateKey).toString('base64');
        stream.end(JSON.stringify(response) + '\n');
      } catch (error) { stream.destroy(error); }
    });
  });
  await new Promise((resolve, reject) => server.once('error', reject).listen(socket, resolve));
  t.after(() => new Promise((resolve) => server.close(resolve)));
  const selector = { schema: 'agent-bot-machine/stage2a-inner-acp-capture-selector/v1',
    installation_id: 'installation-1', start_id: startId, launch_id: launchId,
    reservation_sha256: reservation, plan_id: 'plan-1', plan_digest: planDigest,
    hq_epoch: hqEpoch, session_id: 'e'.repeat(32), sequence: 6,
    test_plan_sha256: hash('test plan'),
    challenge_base64url: Buffer.alloc(32, 4).toString('base64url'),
    expires_at_ms: Date.now() + 60_000 };
  const begin = { reservation_sha256: reservation, installation_id: selector.installation_id,
    start_id: startId, launch_id: launchId, hq_epoch: hqEpoch, plan_id: selector.plan_id,
    plan_digest: planDigest, selector,
    signature_base64url: Buffer.alloc(64).toString('base64url'),
    child_start_receipt_sha256: hash('child receipt'),
    hq_launch_receipt_base64url: receipt.toString('base64url'),
    hq_launch_receipt_sha256: hash(receipt), acp_in_size_bytes: 3,
    acp_in_sha256: hash('in!'), acp_out_size_bytes: 3, acp_out_sha256: hash('out') };
  const started = await run('stage2a-capture-begin', begin);
  assert.equal(started.capture_id, captureId);
  await assert.rejects(run('stage2a-capture-begin', { ...begin,
    hq_launch_receipt_sha256: hash('wrong') }), /invalid Stage 2a Machine reservation selectors/);
  const chunk = Buffer.from('in!');
  const append = { capture_id: captureId, channel: 'acp_in', offset: 0,
    chunk_base64url: chunk.toString('base64url'), chunk_sha256: hash(chunk) };
  assert.equal((await run('stage2a-capture-append', append)).next_offset_bytes, 3);
  invalidAppend = true;
  await assert.rejects(run('stage2a-capture-append', append),
    /invalid signed Machine ACP capture append/);
  invalidAppend = false;
  await assert.rejects(run('stage2a-capture-append', { ...append, chunk_sha256: hash('wrong') }),
    /invalid Stage 2a Machine reservation selectors/);
  const finished = await run('stage2a-capture-finish', { capture_id: captureId,
    acp_in_sha256: begin.acp_in_sha256, acp_out_sha256: begin.acp_out_sha256 });
  assert.equal(finished.receipt_sha256, hash(sealed));
  assert.deepEqual(finished.receipt_envelope, sealed);
  invalidFinish = true;
  await assert.rejects(run('stage2a-capture-finish', { capture_id: captureId,
    acp_in_sha256: begin.acp_in_sha256, acp_out_sha256: begin.acp_out_sha256 }),
    /Machine ACP capture receipt digest mismatch/);
  assert.equal(observed[0].fields.selector.sequence, 6);
  assert.equal(observed[1].fields.chunk_base64url, chunk.toString('base64url'));
  assert.equal((await run('stage2a-lookup', { package_path: '/tmp/selected.soul' }))
    .qualification_start_id, startId);
  invalidLookup = true;
  await assert.rejects(run('stage2a-lookup', { package_path: '/tmp/selected.soul' }),
    /invalid signed Machine Stage 2a lookup/);
  assert.deepEqual(observed.map(({ verb }) => verb), ['stage2a-capture-begin',
    'stage2a-capture-append', 'stage2a-capture-append', 'stage2a-capture-finish',
    'stage2a-capture-finish', 'stage2a-lookup', 'stage2a-lookup']);
});
