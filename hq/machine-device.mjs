// The role's Ed25519 channel authenticates Machine. Only a returned public P-256
// identity and a purpose-specific proof cross the admin device custody boundary.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { lstatSync } from 'node:fs';
import { join } from 'node:path';
import { isUtf8 } from 'node:buffer';
import { parseStrict } from '../sdk/wire/strict-json.mjs';
import { fail } from '../sdk/errors.mjs';
import { machineRoleDevice } from './machine-channel.mjs';
import { releaseServerKeys, signatureBytes } from './identity-service.mjs';
import { jwkThumbprint, publicJwk, SIGNATURE_PREFIX } from './signer.mjs';

const only = (v, names) => v && typeof v === 'object' && !Array.isArray(v)
  && Object.keys(v).length === names.length && names.every((name) => Object.hasOwn(v, name));
const decode = (s) => {
  if (typeof s !== 'string' || !/^[\w-]+$/.test(s)) throw new Error('invalid Machine proof encoding');
  const bytes = Buffer.from(s, 'base64url');
  if (s !== bytes.toString('base64url')) throw new Error('invalid Machine proof encoding');
  return bytes;
};
const unavailable = (reason) => fail('credential_unavailable', reason);

// Only inspect names and types. A role's existing key or enrollment record
// must never be opened while diagnosing adoption of Machine custody.
function inspectFiles(home, dir, names) {
  const folder = join(home, dir);
  let parentState;
  try {
    const parent = lstatSync(folder, { throwIfNoEntry: false });
    parentState = !parent ? 'absent' : parent.isDirectory() ? 'directory' : 'unknown';
  } catch { parentState = 'unknown'; }
  return names.map(name => {
    const path = dir + '/' + name;
    let state = parentState;
    if (state === 'directory') {
      try {
        const entry = lstatSync(join(folder, name), { throwIfNoEntry: false });
        state = !entry ? 'absent' : entry.isFile() ? 'present' : 'unknown';
      } catch { state = 'unknown'; }
    }
    return { path, state };
  });
}

function checkLegacy(home) {
  const signer = inspectFiles(home, 'signer', ['device-key.pem', 'pin.json']);
  if (signer.every(file => file.state === 'absent')) return;
  const files = [...signer, ...inspectFiles(home, 'identity', ['device.json', 'device.previous.json', 'pending-receipt.json'])];
  const details = [];
  for (const [state, label] of [['present', 'Found'], ['absent', 'No local entry for'], ['unknown', 'Could not safely inspect']]) {
    const names = files.filter(file => file.state === state).map(file => file.path);
    if (names.length) details.push(label + ' ' + names.join(', ') + '.');
  }
  throw new Error('Paired custody upgrade paused. ' + details.join(' ') +
    ' Verify enrollment history before authorizing a custody change.');
}

export function createMachineSigner({ home, enrollment, request = machineRoleDevice, keysFor = releaseServerKeys, clock = { now: Date.now } }) {
  let current;
  let reason = 'Machine device identity has not been verified';
  function checkReply(response, state) {
    const b = response.body;
    const bound = state === 'bound' || (state === 'identity' && Object.hasOwn(b ?? {}, 'device_id'));
    const fields = ['jwk', 'thumbprint', 'generation', 'key_storage', 'hq_epoch', ...(state === 'proved' ? ['proof'] : []),
      ...(state === 'asserted' ? ['assertion'] : []), ...(bound ? ['device_id', 'receipt_jti', 'receipt_sha256'] : [])];
    if (response.state !== state || !only(b, fields)
      || !only(b.jwk, ['kty', 'crv', 'x', 'y']) || b.key_storage !== 'hardware'
      || !/^(legacy|[a-f0-9]{64})$/.test(b.hq_epoch) || !Number.isSafeInteger(b.generation) || b.generation < 1
      || jwkThumbprint(b.jwk) !== b.thumbprint
      || decode(b.jwk.x).length !== 32 || decode(b.jwk.y).length !== 32
      || (bound && (typeof b.device_id !== 'string' || !b.device_id || b.device_id.length > 256
        || !/^enroll-v1:[a-f0-9]{64}$/.test(b.receipt_jti) || !/^[a-f0-9]{64}$/.test(b.receipt_sha256)))) {
      throw new Error('invalid Machine device identity');
    }
    return { jwk: publicJwk(b.jwk), epoch: b.hq_epoch, generation: b.generation, thumbprint: b.thumbprint,
      ...(bound && { device_id: b.device_id, receipt_jti: b.receipt_jti, receipt_sha256: b.receipt_sha256 }) };
  }
  async function refresh() {
    try {
      checkLegacy(home);
      current = checkReply(await request('identity'), 'identity');
    } catch (error) {
      current = undefined;
      reason = error.message;
      throw error;
    }
  }
  function report() {
    try { checkLegacy(home); } catch (error) { return { available: false, backend: 'machine', reason: error.message }; }
    return current ? { available: true, backend: 'machine', key_storage: 'hardware', alg: 'ES256',
      thumbprint: current.thumbprint, generation: current.generation, key_files: 0 }
      : { available: false, backend: 'machine', reason };
  }
  const signer = {
    source: 'paired Machine/keyd', report,
    async deviceStatus() {
      await refresh();
      const state = await enrollment.deviceStatus();
      return state;
    },
    async enroll(payload) {
      await refresh();
      return enrollment.enroll(payload);
    },
    async enrollmentProof(aud) {
      checkLegacy(home);
      const expected = current;
      if (!expected) unavailable('Machine device identity is unavailable');
      const response = await request('enrollment-proof', { hq_epoch: expected.epoch });
      const actual = checkReply(response, 'proved');
      if (actual.epoch !== expected.epoch || actual.thumbprint !== expected.thumbprint || actual.generation !== expected.generation) throw new Error('Machine device identity changed during enrollment');
      const proof = response.body.proof;
      const parts = typeof proof === 'string' && proof.split('.');
      if (!parts || parts.length !== 3) throw new Error('invalid Machine enrollment proof');
      const [head, body, sig] = parts.map(decode);
      if (!isUtf8(head) || !isUtf8(body)) throw new Error('invalid Machine enrollment proof text');
      const h = parseStrict(head.toString()), p = parseStrict(body.toString());
      if (!only(h, ['alg', 'typ', 'jwk']) || h.alg !== 'ES256' || h.typ !== 'ab-enroll+jwt'
        || !only(h.jwk, ['kty', 'crv', 'x', 'y']) || jwkThumbprint(h.jwk) !== expected.thumbprint
        || !only(p, ['aud', 'iat', 'jti']) || p.aud !== aud || !Number.isSafeInteger(p.iat)
        || Math.abs(clock.now() / 1000 - p.iat) > 120 || typeof p.jti !== 'string' || !/^[A-Za-z0-9_-]{16,128}$/.test(p.jti)
        || sig.length !== 64 || !verify('sha256', Buffer.from(parts.slice(0, 2).join('.')), {
          key: createPublicKey({ key: expected.jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363',
        }, sig)) throw new Error('Machine enrollment proof failed device, audience, freshness or signature verification');
      return proof;
    },
    acceptsRecord(rec) {
      try {
        if (!current?.device_id || rec.device_id !== current.device_id || rec.receipt_jti !== current.receipt_jti
          || rec.jkt !== current.thumbprint || rec.key_generation !== current.generation || rec.key_storage !== 'hardware') return false;
        const bytes = decode(rec.receipt_body);
        if (bytes.length > 8192 || createHash('sha256').update(bytes).digest('hex') !== current.receipt_sha256 || !isUtf8(bytes)) return false;
        const body = parseStrict(bytes.toString());
        return body.device_id === current.device_id && body.jkt === current.thumbprint
          && Array.isArray(body.harnesses) && JSON.stringify(body.harnesses) === JSON.stringify(rec.harnesses);
      } catch { return false; }
    },
    verifyEnrollmentReceipt(receipt, server) {
      checkLegacy(home);
      const bytes = decode(receipt.receipt_body);
      if (bytes.length > 8192 || !isUtf8(bytes) || !/^enroll-v1:[a-f0-9]{64}$/.test(receipt.receipt_jti)
        || !/^[A-Za-z0-9._:-]{1,128}$/.test(receipt.receipt_kid) || decode(receipt.receipt_signature).length !== 64) {
        throw new Error('invalid Identity enrollment receipt');
      }
      const body = parseStrict(bytes.toString());
      if (!current || !body || typeof body !== 'object' || Array.isArray(body)
        || Object.keys(body).some((k) => !['token_type', 'device_id', 'harnesses', 'read_only', 'jkt', 'next'].includes(k))
        || typeof body.device_id !== 'string' || !body.device_id || body.device_id.length > 256 || typeof body.read_only !== 'boolean'
        || body.jkt !== current.thumbprint || body.token_type !== 'N_A' || !Array.isArray(body.harnesses) || body.harnesses.length > 64
        || !body.harnesses.every((h) => typeof h === 'string' && /^[a-z0-9][a-z0-9-]{0,63}$/.test(h))
        || new Set(body.harnesses).size !== body.harnesses.length || (body.next !== undefined && typeof body.next !== 'string')) throw new Error('invalid public device enrollment receipt');
      const now = clock.now();
      const key = keysFor(server).find((k) => k.kid === receipt.receipt_kid && k.status !== 'retired'
        && now >= Date.parse(k.notBefore) && now < Date.parse(k.notAfter));
      if (!key || !verify(null, signatureBytes(200, bytes, receipt.receipt_jti), createPublicKey({
        key: { kty: 'OKP', crv: 'Ed25519', x: key.x }, format: 'jwk',
      }), decode(receipt.receipt_signature))) throw new Error('Identity enrollment receipt signature does not verify');
      return body;
    },
    async bindEnrollment(receipt, server) {
      const body = signer.verifyEnrollmentReceipt(receipt, server);
      const bytes = decode(receipt.receipt_body);
      const result = await request('bind-enrollment', { hq_epoch: current.epoch, ...receipt });
      const bound = checkReply(result, 'bound');
      if (bound.epoch !== current.epoch || bound.generation !== current.generation || bound.thumbprint !== current.thumbprint
        || body.device_id !== bound.device_id || receipt.receipt_jti !== bound.receipt_jti
        || createHash('sha256').update(bytes).digest('hex') !== bound.receipt_sha256) throw new Error('Machine enrollment binding does not match the Identity receipt');
      current = bound;
      return body;
    },
    accessAssertion() { unavailable('Machine credential-use and DPoP operations are unavailable'); },
    custody: {
      checkOperation(method, path) {
        if (method !== 'GET' || !/^\/api\/daemon\/issuances\/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(path)) unavailable('Machine has no authority for this credential operation');
      },
      async openSession() {
        await refresh();
        const expected = current;
        if (!expected?.device_id || await enrollment.deviceStatus() !== 'enrolled') unavailable('Machine has no current administrator-bound device enrollment');
        const response = await request('access-assertion', { hq_epoch: expected.epoch });
        const identity = checkReply(response, 'asserted');
        const assertion = response.body.assertion;
        const parts = typeof assertion === 'string' && assertion.split('.');
        if (!parts || parts.length !== 3 || identity.thumbprint !== expected.thumbprint || identity.generation !== expected.generation || identity.epoch !== expected.epoch) throw new Error('invalid Machine access assertion identity');
        const [head, body, sig] = parts.map(decode);
        const h = parseStrict(head.toString()), p = parseStrict(body.toString());
        if (!isUtf8(head) || !isUtf8(body) || !only(h, ['alg', 'typ']) || h.alg !== 'ES256' || h.typ !== 'JWT'
          || !only(p, ['iss', 'sub', 'aud', 'iat', 'exp', 'jti', 'cnf']) || p.iss !== expected.device_id || p.sub !== p.iss
          || p.aud !== enrollment.progress().server + '/oauth/token' || !Number.isSafeInteger(p.iat) || p.exp !== p.iat + 120
          || Math.abs(clock.now() / 1000 - p.iat) > 120 || p.exp <= clock.now() / 1000 || decode(p.jti).length !== 16
          || !only(p.cnf, ['jwk']) || !only(p.cnf.jwk, ['kty', 'crv', 'x', 'y']) || sig.length !== 64
          || !verify('sha256', Buffer.from(parts.slice(0, 2).join('.')), {
            key: createPublicKey({ key: expected.jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363',
          }, sig)) throw new Error('Machine access assertion failed verification');
        const ephemeralJwk = publicJwk(p.cnf.jwk);
        const session = jwkThumbprint(ephemeralJwk);
        if (session === expected.thumbprint) throw new Error('Machine session key must be distinct from the device key');
        return { assertion, ephemeralJwk, session };
      },
      async bindAccess({ session, body, headers }) {
        if (!current?.device_id) unavailable('Machine access session is unavailable');
        const receipt = { receipt_body: Buffer.from(body).toString('base64url'), receipt_jti: headers['agent-bot-request-jti'],
          receipt_kid: headers['agent-bot-key-id'], receipt_signature: headers['agent-bot-signature'] };
        const epoch = current.epoch;
        const response = await request('bind-access', { hq_epoch: epoch, ...receipt });
        const b = response.body;
        if (response.state !== 'access-bound' || !only(b, ['session', 'expires_at', 'hq_epoch'])
          || b.session !== session || b.hq_epoch !== epoch || !Number.isSafeInteger(b.expires_at)
          || b.expires_at <= clock.now() / 1000 || b.expires_at > clock.now() / 1000 + 900) throw new Error('invalid Machine DPoP session binding');
        return { expiresAt: b.expires_at * 1000 };
      },
      requestProof() { unavailable('Machine has no authorized DPoP action for this operation'); },
    },
    createKey() { unavailable('Device key rotation requires administrator action in Machine/keyd'); },
    sign() { unavailable('Machine approval-record signing is unavailable'); },
    async verify(bytes, signature) {
      try {
        await refresh();
        if (!current.device_id || typeof signature !== 'string') return false;
        const [format, kid, value, ...rest] = signature.split('.');
        if (rest.length || format !== SIGNATURE_PREFIX || kid !== current.thumbprint) return false;
        const sig = decode(value);
        return sig.length === 64 && verify('sha256', bytes, {
          key: createPublicKey({ key: current.jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363',
        }, sig);
      } catch { return false; }
    },
    get enrollment() { return enrollment; },
    enrollmentProgress: () => enrollment.progress?.(),
  };
  enrollment = enrollment(signer);
  return signer;
}
