import assert from 'node:assert/strict';
import { createHash, createPrivateKey, sign } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import test from 'node:test';
import { verifyStage2aProtectedReservationV3, verifyStage2aReservationV3 } from '../hq/stage2a-reservation.mjs';
import { verify } from '../scripts/soul-contracts.mjs';
import { canonicalBytes } from '../sdk/wire/canonical-json.mjs';
import { validate } from '../sdk/wire/schema.mjs';

const { dir } = verify();
const read = (path) => JSON.parse(readFileSync(join(dir, path), 'utf8'));
const vector = read('fixtures/reservation/v3/machine-hr-synthetic.json');
const payloadSchema = read('schemas/machine/v3/stage2a-reservation-payload.schema.json');
const schemas = ['v3/measurement-binding', 'v3/inventory-ref',
  'v2/measurement-binding', 'v2/snapshot-identity'].map((name) =>
  read(`schemas/machine/${name}.schema.json`));
const validatePayload = (payload) => validate(payloadSchema, payload, { schemas }).length === 0;
const sha = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const raw = Buffer.from(vector.reservation_envelope_jcs);
const enrolledMachineKey = Buffer.from(vector.issuer_public_key_base64url, 'base64url');
const selectedH = {
  descriptorDigest: vector.h_descriptor_digest,
  machinePublicKey: enrolledMachineKey.toString('hex'),
};
const clock = () => new Date(vector.verification_at);
const options = (bytes = raw) => ({
  enrolledMachineKey, selectedH, validatePayload, reservationSHA256: sha(bytes), clock,
});
const privateKey = createPrivateKey({
  key: Buffer.concat([Buffer.from('302e020100300506032b657004220420', 'hex'),
    Buffer.from(vector.seed_hex, 'hex')]),
  format: 'der', type: 'pkcs8',
});

// The public test key exercises exact wire verification without authorizing
// a protected start or furnishing authenticated H process state.
function resign(change) {
  const envelope = JSON.parse(raw);
  const payload = JSON.parse(vector.reservation_payload_jcs);
  change(payload);
  const bytes = canonicalBytes(payload);
  const preimage = Buffer.concat([Buffer.from(envelope.purpose + '\0'), bytes]);
  return canonicalBytes({ ...envelope, payload_sha256: sha(bytes),
    payload_base64url: bytes.toString('base64url'),
    signature_base64url: sign(null, preimage, privateKey).toString('base64url') });
}

test('protected v3 signed bytes match the pinned Contracts schema and selected H', async () => {
  const checked = await verifyStage2aReservationV3(raw, options());
  assert.equal(checked.reservationSHA256, sha(raw));
  assert.equal(checked.payload.assignment.h_service_descriptor_digest, selectedH.descriptorDigest);
  assert.equal(checked.payload.measurement_binding.h_service_descriptor_digest, selectedH.descriptorDigest);
  await assert.rejects(verifyStage2aProtectedReservationV3(raw, options()), /invalid Stage 2a reservation/);
});

test('protected v3 refuses either signed H field and the H envelope hash', async () => {
  const mismatched = 'sha256:' + '0'.repeat(64);
  for (const fields of [['assignment'], ['measurement_binding'], ['assignment', 'measurement_binding']]) {
    const bytes = resign((payload) => {
      for (const field of fields) payload[field].h_service_descriptor_digest = mismatched;
    });
    // The schema and A signature still pass for each different digest.
    assert.equal(validatePayload(JSON.parse(Buffer.from(JSON.parse(bytes).payload_base64url, 'base64url'))), true);
    await assert.rejects(verifyStage2aReservationV3(bytes, options(bytes)), /invalid Stage 2a reservation/);
  }
  const envelopeSHA256 = sha(Buffer.from(vector.h_envelope_jcs));
  await assert.rejects(verifyStage2aReservationV3(raw, {
    ...options(), selectedH: { ...selectedH, descriptorDigest: envelopeSHA256 },
  }), /invalid Stage 2a reservation/);
});

test('protected v3 requires enrolled A, exact response bytes, pinned schema and freshness', async () => {
  const otherKey = Buffer.alloc(32);
  const otherSelection = { ...selectedH, machinePublicKey: otherKey.toString('hex') };
  const malformed = resign((payload) => {
    payload.runtime_v3 = { h_service_descriptor_digest: selectedH.descriptorDigest };
  });
  const expiresAt = new Date(JSON.parse(vector.reservation_payload_jcs).expires_at);
  for (const [bytes, overrides] of [
    [raw, { selectedH: otherSelection }],
    [raw, { enrolledMachineKey: otherKey, selectedH: otherSelection }],
    [raw, { reservationSHA256: sha(Buffer.from(vector.reservation_payload_jcs)) }],
    [raw, { validatePayload: undefined }],
    [raw, { clock: () => expiresAt }],
    [raw, { clock: () => new Date(0) }],
    [malformed, {}],
  ]) {
    await assert.rejects(verifyStage2aReservationV3(bytes, { ...options(bytes), ...overrides }),
      /invalid Stage 2a reservation/);
  }
});
