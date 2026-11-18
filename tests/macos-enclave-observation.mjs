import assert from 'node:assert/strict';
import { createPublicKey, verify } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { pathToFileURL } from 'node:url';
import { publicJwk } from '../hq/signer.mjs';

export function verifyObservation(observation, source, uid, challenge) {
  assert.deepEqual(Object.keys(observation).sort(), ['jwk', 'signature', 'source', 'uid']);
  assert.equal(observation.source, source);
  assert.equal(observation.uid, uid);
  const jwk = publicJwk(observation.jwk);
  assert.deepEqual(jwk, observation.jwk);
  const key = createPublicKey({ key: jwk, format: 'jwk' });
  const signature = Buffer.from(observation.signature, 'base64url');
  assert.equal(signature.length, 64);
  assert.equal(challenge.length, 32);
  assert.equal(verify('sha256', challenge, { key, dsaEncoding: 'ieee-p1363' }, signature), true);
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const uid = Number(process.argv[2]);
  const challenge = Buffer.from(process.argv[3], 'base64');
  verifyObservation(JSON.parse(readFileSync(0, 'utf8')), 'secure-enclave', uid, challenge);
  console.log(`Verified a fresh Secure Enclave ES256 signature from the system LaunchDaemon as _agent-bot-hq (uid ${uid}).`);
}
