import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createHash, createPrivateKey, sign } from 'node:crypto';
import { canonicalize } from '../sdk/wire/canonical-json.mjs';
import { verifyStage2aReservation } from '../hq/stage2a-reservation.mjs';

const v = JSON.parse(readFileSync(new URL('./fixtures/stage2a-reservation-vector.json', import.meta.url)));
const payload = JSON.parse(v.payload_jcs);
const expected = Object.fromEntries(['host_id','assignment','member_endpoint','measurement_binding','installed_plan_receipt_sha256','admission_challenge_sha256'].map(k => [k, payload[k]]));
const key = Buffer.from(v.issuer_public_key_base64url, 'base64url');
const now = new Date('2026-11-22T14:15:20Z');
// Vector-derived expectations test equality and cryptography only; they do
// not establish the trustworthiness of production expected-state sources.
// This stub does not test schema enforcement; integration must supply the pinned validator.
const options = overrides => ({ enrolledMachineKey: key, expected, clock: () => now, validatePayload: () => true, consume: async () => true, ...overrides });
const envelope = () => JSON.parse(v.envelope_jcs);
const raw = value => Buffer.from(canonicalize(value));
const seed = Buffer.from(v.seed_hex, 'hex');
const privateKey = createPrivateKey({ key: Buffer.concat([Buffer.from('302e020100300506032b657004220420','hex'), seed]), format:'der', type:'pkcs8' });
function resign(p) {
  const bytes = raw(p), e = envelope();
  e.payload_base64url = bytes.toString('base64url');
  e.payload_sha256 = `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
  e.signature_base64url = sign(null, Buffer.concat([Buffer.from(e.purpose + '\0'), bytes]), privateKey).toString('base64url');
  return raw(e);
}
test('exact Machine vector and atomic replay callback', async () => {
  let spent = false;
  const opts = options({ consume: async claim => { assert.equal(claim.startId, payload.assignment.start_id); if (spent) return false; spent = true; return true; } });
  assert.equal((await verifyStage2aReservation(Buffer.from(v.envelope_jcs), opts)).reservationSHA256, v.reservation_sha256);
  await assert.rejects(verifyStage2aReservation(Buffer.from(v.envelope_jcs), opts));
});
test('rejects invalid issuer, purpose, bytes, signature, expiry and missing callback before consuming', async () => {
  const variants = [];
  for (const mutate of [e => e.purpose += 'x', e => e.signature_base64url = 'A'.repeat(86), e => e.payload_sha256 = 'sha256:' + '0'.repeat(64), e => e.payload_base64url += '=']) { const e = envelope(); mutate(e); variants.push([raw(e), options()]); }
  variants.push([Buffer.from(v.envelope_jcs + ' '), options()], [Buffer.from(v.envelope_jcs), options({enrolledMachineKey: Buffer.alloc(32)})],
    [Buffer.from(v.envelope_jcs), options({clock: () => new Date(payload.expires_at)})], [Buffer.from(v.envelope_jcs), options({consume: undefined})]);
  for (const [bytes, opts] of variants) await assert.rejects(verifyStage2aReservation(bytes, opts));
});
test('validly signed changes to each trusted binding are refused before consumption', async () => {
  for (const field of Object.keys(expected)) {
    const changed = structuredClone(payload);
    if (typeof changed[field] === 'string') changed[field] += 'x'; else changed[field].unexpected = true;
    let consumed = false;
    await assert.rejects(verifyStage2aReservation(resign(changed), options({consume: async () => { consumed = true; return true; }})), field);
    assert.equal(consumed, false);
  }
});
test('callback failures refuse', async () => {
  for (const consume of [async () => false, async () => { throw Error('offline'); }]) await assert.rejects(verifyStage2aReservation(Buffer.from(v.envelope_jcs), options({consume})));
  for (const validatePayload of [undefined, () => false, () => { throw Error('unavailable'); }]) await assert.rejects(verifyStage2aReservation(Buffer.from(v.envelope_jcs), options({validatePayload})));
});
test('refuses internally inconsistent signed bindings even if expectations match', async () => {
  for (const mutate of [
    p => { p.measurement_binding.start_id += 'x'; },
    p => { p.measurement_binding.host_id += 'x'; },
    p => { p.measurement_binding.snapshots.definition.owner_gid++; },
    p => { p.member_endpoint.member_socket += 'x'; },
    p => { p.member_endpoint.member_endpoint.owner_uid++; },
  ]) {
    const p = structuredClone(payload); mutate(p);
    const matching = Object.fromEntries(Object.keys(expected).map(k => [k, p[k]]));
    let consumed = false;
    await assert.rejects(verifyStage2aReservation(resign(p), options({ expected: matching, consume: async () => { consumed = true; return true; } })));
    assert.equal(consumed, false);
  }
});
test('expiry during consumption refuses without undoing the consumed claim', async () => {
  let current = now, spent = false;
  const opts = options({ clock: () => current, consume: async () => {
    if (spent) return false;
    spent = true;
    await Promise.resolve();
    current = new Date(payload.expires_at);
    return true;
  }});
  await assert.rejects(verifyStage2aReservation(Buffer.from(v.envelope_jcs), opts));
  assert.equal(spent, true);
  current = now;
  await assert.rejects(verifyStage2aReservation(Buffer.from(v.envelope_jcs), opts));
});
test('clock rollback during consumption refuses without undoing the consumed claim', async () => {
  let current = now, spent = false;
  const opts = options({ clock: () => current, consume: async () => {
    if (spent) return false;
    spent = true;
    await Promise.resolve();
    current = new Date(Date.parse(payload.issued_at) - 1);
    return true;
  }});
  await assert.rejects(verifyStage2aReservation(Buffer.from(v.envelope_jcs), opts));
  assert.equal(spent, true);
  current = now;
  await assert.rejects(verifyStage2aReservation(Buffer.from(v.envelope_jcs), opts));
});
