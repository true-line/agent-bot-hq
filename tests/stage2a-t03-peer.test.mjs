import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash, generateKeyPairSync, sign } from 'node:crypto';
import { canonicalBytes } from '../sdk/wire/canonical-json.mjs';
import { verifiedT03ChildStart, verifyT03RelayPeer } from '../hq/stage2a-t03-peer.mjs';

const sha = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const { publicKey, privateKey } = generateKeyPairSync('ed25519');
const machinePublicKey = publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
const child = { pid: 600, uid: 321, gid: 321, start_seconds: 1795520000, start_micros: 110000 };
const launcher = { ...child, pid: 500, start_micros: 100000 };
const expected = { reservation_sha256: sha('reservation'), installation_id: 'install_1',
  start_id: `st_${'a'.repeat(24)}`, launch_id: `ln_${'b'.repeat(24)}`,
  plan_id: 'plan_1', plan_digest: 'c'.repeat(64), hq_epoch: 'd'.repeat(64),
  runner_uid: 321, runner_gid: 321, child_launcher_pid: launcher.pid,
  child_pid: child.pid, bind_receipt_sha256: sha('bind'),
  finalization_sha256: sha('final'), relay_socket: '/private/tmp/relay.sock' };
const peer = { uid: child.uid, pid: 700, pid_version: 12,
  start_seconds: child.start_seconds, start_micros: child.start_micros + 100,
  parent_pid: child.pid, parent_uid: child.uid,
  parent_start_seconds: child.start_seconds, parent_start_micros: child.start_micros };

function signedChild(overrides = {}) {
  const payload = { schema: 'agent-bot-machine/stage2a-child-start/v1',
    ...Object.fromEntries(['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
      'plan_id', 'plan_digest', 'hq_epoch', 'bind_receipt_sha256', 'finalization_sha256',
      'relay_socket'].map((key) => [key, expected[key]])),
    child, child_launcher: launcher, expires_at_ms: Date.now() + 60_000, ...overrides };
  const bytes = canonicalBytes(payload);
  const purpose = 'agent-bot/stage2a-child-start/v1';
  const envelope = canonicalBytes({ schema_version: 1, purpose,
    issuer_public_key_base64url: machinePublicKey.toString('base64url'),
    payload_sha256: sha(bytes), payload_base64url: bytes.toString('base64url'),
    signature_base64url: sign(null, Buffer.concat([Buffer.from(`${purpose}\0`), bytes]),
      privateKey).toString('base64url') });
  return { envelope, digest: sha(envelope) };
}

test('T03 peer joins B audit identity to signed A child and live parent and CLI', async () => {
  const signed = signedChild();
  const start = verifiedT03ChildStart(signed.envelope, signed.digest, machinePublicKey, expected);
  const calls = [];
  const observe = async (pid, uid, gid) => {
    calls.push([pid, uid, gid]);
    return pid === child.pid ? child : { ...child, pid: peer.pid,
      start_seconds: peer.start_seconds, start_micros: peer.start_micros };
  };
  assert.deepEqual(await verifyT03RelayPeer(peer, start, { observe }), peer);
  assert.deepEqual(calls, [[600, 321, 321], [700, 321, 321]]);
  assert.throws(() => verifiedT03ChildStart(signed.envelope, sha('wrong'), machinePublicKey, expected));
  const other = signedChild({ child: { ...child, pid: 601 } });
  await assert.rejects(verifyT03RelayPeer(peer,
    verifiedT03ChildStart(other.envelope, other.digest, machinePublicKey, { ...expected, child_pid: 601 }),
    { observe }));
  await assert.rejects(verifyT03RelayPeer({ ...peer, pid_version: '12' }, start, { observe }));
  await assert.rejects(verifyT03RelayPeer({ ...peer, parent_start_micros: 1 }, start, { observe }));
  await assert.rejects(verifyT03RelayPeer(peer, start, { observe: async () => null }));
  const expired = signedChild({ expires_at_ms: Date.now() - 1 });
  assert.throws(() => verifiedT03ChildStart(expired.envelope, expired.digest,
    machinePublicKey, expected));
});
