import assert from 'node:assert/strict';
import { test } from 'node:test';
import { createHash, createPrivateKey, createPublicKey, sign } from 'node:crypto';
import { join } from 'node:path';
import { canonicalize } from '../sdk/wire/canonical-json.mjs';
import { verifyCooperativeReservation } from '../hq/cooperative-reservation.mjs';

const PURPOSE = 'agent-bot/soul-cooperative-reservation/v1';
const seed = Buffer.alloc(32, 0x6b); // synthetic, never an enrolled Machine key
const privateKey = createPrivateKey({ key: Buffer.concat([
  Buffer.from('302e020100300506032b657004220420', 'hex'), seed,
]), format: 'der', type: 'pkcs8' });
const publicKey = createPublicKey(privateKey).export({ format: 'der', type: 'spki' }).subarray(-32);
const digest = (value) => createHash('sha256').update(value).digest('hex');
const now = Date.parse('2026-11-22T12:00:00Z');
const request = { startId: 'st_1234567890abcdef12345678',
  packagePath: '/var/agent-bot-hq/candidates/hello.soul', hqEpoch: 'a'.repeat(64) };

function signedFixture(edit = () => {}) {
  const installationId = 'installation-1';
  const installSlot = digest(`agent-bot-soul-endpoint-installation/v1\0${installationId}`).slice(0, 20);
  const directory = join('/Library/Application Support/ai.true-line.agent-bot-hq', 'c', installSlot);
  const socketPath = join(directory, `${digest(`agent-bot-soul-endpoint-start/v1\0${installationId}\0${request.startId}`).slice(0, 20)}.sock`);
  const payload = {
    purpose: PURPOSE, profile_in_force: 'managed-cooperative', host_id: 'test-host',
    plan_id: 'plan-20261122T120000Z-abcd', plan_digest: '1'.repeat(64),
    installed_receipt_sha256: '2'.repeat(64), installation_id: installationId,
    soul_id: 'agent_12345678-1234-1234-1234-123456789abc', start_id: request.startId,
    hq_epoch: request.hqEpoch, runner_uid: 311, runner_gid: 311,
    source_package_path: request.packagePath,
    package_root: join('/Library/Application Support/ai.true-line.agent-bot-hq',
      'cooperative-artifacts', `${installSlot}.soul`), package_sha256: 'b'.repeat(64),
    soul_artifact_sha256: 'c'.repeat(64), definition_sha256: 'd'.repeat(64),
    node_path: '/opt/agent-bot/node', node_sha256: 'e'.repeat(64),
    entry: 'Contents/opt/quickstart-adapter.mjs', launcher_path: '/opt/agent-bot/soul-launcher',
    launcher_sha256: 'f'.repeat(64),
    endpoint: { directory, socket_path: socketPath, owner_uid: 310, group_gid: 311,
      dir_mode: 0o2750, socket_mode: 0o660, peer_uid: 311 },
    issued_at: '2026-11-22T12:00:00Z', expires_at: '2026-11-22T12:00:30Z',
  };
  edit(payload);
  const bytes = Buffer.from(canonicalize(payload));
  const signature = sign(null, Buffer.concat([Buffer.from(PURPOSE + '\0'), bytes]), privateKey);
  return { purpose: PURPOSE, payload_base64url: bytes.toString('base64url'),
    payload_sha256: digest(bytes), signature_base64url: signature.toString('base64url') };
}

const context = () => ({ machinePublicKey: publicKey, hostId: 'test-host', request,
  hqUid: 310, now: () => now + 1000 });

test('accepts a purpose-bound cooperative Machine reservation for the exact HQ start', () => {
  const checked = verifyCooperativeReservation(signedFixture(), context());
  assert.equal(checked.startId, request.startId);
  assert.equal(checked.packagePath, request.packagePath);
  assert.equal(checked.packageDigest, 'b'.repeat(64));
  assert.equal(checked.definitionDigest, `sha256:${'d'.repeat(64)}`);
  assert.equal(checked.uid, 311);
  assert.equal(checked.endpoint.ownerUid, 310);
  assert.equal(checked.endpoint.peerUid, 311);
});

test('refuses altered bytes, wrong issuer, host, source and expired reservation', () => {
  const good = signedFixture();
  const altered = { ...good, payload_base64url: Buffer.from(good.payload_base64url, 'base64url')
    .toString('utf8').replace('bbbbbbbb', 'aaaaaaaa') };
  altered.payload_base64url = Buffer.from(altered.payload_base64url).toString('base64url');
  assert.throws(() => verifyCooperativeReservation(altered, context()));
  assert.throws(() => verifyCooperativeReservation(good, { ...context(), machinePublicKey: Buffer.alloc(32) }));
  assert.throws(() => verifyCooperativeReservation(good, { ...context(), hostId: 'other-host' }));
  assert.throws(() => verifyCooperativeReservation(good, { ...context(),
    request: { ...request, packagePath: '/tmp/other.soul' } }));
  assert.throws(() => verifyCooperativeReservation(good, { ...context(), now: () => now + 30000 }));
});

test('never accepts a signed protected profile or changed H/R socket assignment', () => {
  assert.throws(() => verifyCooperativeReservation(signedFixture((p) => {
    p.profile_in_force = 'managed-protected';
  }), context()));
  assert.throws(() => verifyCooperativeReservation(signedFixture((p) => {
    p.endpoint.peer_uid = 310;
  }), context()));
  assert.throws(() => verifyCooperativeReservation(signedFixture((p) => {
    p.runner_uid = 310;
  }), context()));
});
