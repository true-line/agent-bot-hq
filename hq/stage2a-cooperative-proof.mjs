// Cooperative Machine envelopes use a purpose distinct from protected reservations.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { canonicalize } from '../sdk/wire/canonical-json.mjs';
import { parseStrict } from '../sdk/wire/strict-json.mjs';

const SPKI = Buffer.from('302a300506032b6570032100', 'hex');
export const digest = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
export const SHA256 = /^sha256:[0-9a-f]{64}$/;
const KEYS = 'issuer_public_key_base64url,payload_base64url,payload_sha256,purpose,schema_version,signature_base64url';
const invalid = () => { throw new Error('invalid signed Machine cooperative proof'); };

function decode(value, max, exact) {
  if (typeof value !== 'string' || value.length > Math.ceil(max * 4 / 3)
    || !/^[A-Za-z0-9_-]+$/.test(value)) invalid();
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.length > max || (exact && bytes.length !== max)
    || bytes.toString('base64url') !== value) invalid();
  return bytes;
}

function parseCanonical(bytes) {
  const raw = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const value = parseStrict(raw, { maxDepth: 24 });
  if (canonicalize(value) !== raw) invalid();
  return value;
}

function verifyMachineProof(result, machineKey, purpose, kind) {
  if (!result || Object.keys(result).sort().join(',') !== 'envelope_base64url,sha256'
    || !Buffer.isBuffer(machineKey) || machineKey.length !== 32) invalid();
  const bytes = decode(result.envelope_base64url, 48 * 1024);
  if (digest(bytes) !== result.sha256) invalid();
  const envelope = parseCanonical(bytes);
  if (!envelope || Object.keys(envelope).sort().join(',') !== KEYS
    || envelope.schema_version !== 3 || envelope.purpose !== purpose
    || envelope.issuer_public_key_base64url !== machineKey.toString('base64url')) invalid();
  const payloadBytes = decode(envelope.payload_base64url, 36 * 1024);
  const signature = decode(envelope.signature_base64url, 64, true);
  const key = createPublicKey({ key: Buffer.concat([SPKI, machineKey]), format: 'der', type: 'spki' });
  if (digest(payloadBytes) !== envelope.payload_sha256
    || !verify(null, Buffer.concat([Buffer.from(purpose + '\0'), payloadBytes]), key, signature)) invalid();
  const payload = parseCanonical(payloadBytes);
  if (!payload || payload.contract !== 'machine/v3' || payload.schema_version !== 3
    || payload.kind !== kind) invalid();
  return payload;
}

export function verifyCooperativeProof(result, machineKey, kind) {
  return verifyMachineProof(result, machineKey, `agent-bot/soul-cooperative-${kind}/v3`, `soul-cooperative-${kind}`);
}

export function verifyDirectQualificationPre(result, machineKey) {
  return verifyMachineProof(result, machineKey, 'agent-bot/stage2a-direct-q-pre/v3', 'stage2a-direct-q-pre');
}

export function verifyDirectQualificationCapture(result, machineKey) {
  return verifyMachineProof(result, machineKey, 'agent-bot/stage2a-direct-q-capture/v3', 'stage2a-direct-q-capture');
}

export function match(value, expected) {
  return Boolean(value) && Object.entries(expected).every(([key, field]) => value[key] === field);
}
