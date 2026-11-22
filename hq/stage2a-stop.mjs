// Verify Machine's signed B finalization and role-cutoff records. A local
// signal or a closed ACP socket is never evidence of containment.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { canonicalize } from '../sdk/wire/canonical-json.mjs';
import { parseStrict } from '../sdk/wire/strict-json.mjs';

const PURPOSE = 'agent-bot/stage2a-stop/v1';
const SCHEMA = 'agent-bot-machine/stage2a-stop/v1';
const FINAL_PURPOSE = 'agent-bot/stage2a-finalization/v1';
const FINAL_SCHEMA = 'agent-bot-machine/stage2a-finalization/v1';
const SHA = /^sha256:[0-9a-f]{64}$/;
const exact = (value, fields) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...fields].sort().join(',');
const digest = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const refuse = () => { throw new Error('invalid signed Machine Stage 2a stop'); };

function base64url(value, size) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) refuse();
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value || (size !== undefined && bytes.length !== size)) refuse();
  return bytes;
}

function canonical(bytes) {
  const value = parseStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes), { maxDepth: 16 });
  if (canonicalize(value) !== bytes.toString('utf8')) refuse();
  return value;
}

function verifyEnvelope(envelopeBytes, machinePublicKey, purpose) {
  if (!Buffer.isBuffer(envelopeBytes) || envelopeBytes.length < 1 || envelopeBytes.length > 8192
    || !Buffer.isBuffer(machinePublicKey) || machinePublicKey.length !== 32) refuse();
  const envelope = canonical(envelopeBytes);
  if (!exact(envelope, ['schema_version', 'purpose', 'issuer_public_key_base64url',
    'payload_sha256', 'payload_base64url', 'signature_base64url'])
    || envelope.schema_version !== 1 || envelope.purpose !== purpose
    || !base64url(envelope.issuer_public_key_base64url, 32).equals(machinePublicKey)) refuse();
  const payloadBytes = base64url(envelope.payload_base64url);
  if (!SHA.test(envelope.payload_sha256) || digest(payloadBytes) !== envelope.payload_sha256) refuse();
  const signature = base64url(envelope.signature_base64url, 64);
  const publicKey = createPublicKey({ key: Buffer.concat([
    Buffer.from('302a300506032b6570032100', 'hex'), machinePublicKey,
  ]), format: 'der', type: 'spki' });
  if (!verify(null, Buffer.concat([Buffer.from(`${purpose}\0`), payloadBytes]), publicKey, signature)) refuse();
  return { payload: canonical(payloadBytes), envelope_sha256: digest(envelopeBytes) };
}

export function verifyStage2aStop(envelopeBytes, { machinePublicKey, expected } = {}) {
  if (!exact(expected, ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
    'plan_id', 'plan_digest', 'hq_epoch', 'runner_uid', 'bridge_uid', 'runner_pid', 'bridge_pid'])) refuse();
  const { payload, envelope_sha256 } = verifyEnvelope(envelopeBytes, machinePublicKey, PURPOSE);
  if (!exact(payload, ['schema', 'reservation_sha256', 'installation_id', 'start_id',
    'launch_id', 'plan_id', 'plan_digest', 'hq_epoch', 'runner_uid', 'bridge_uid',
    'runner_pid', 'bridge_pid', 'both_uids_idle', 'stopped_at'])
    || payload.schema !== SCHEMA || payload.both_uids_idle !== true
    || !SHA.test(payload.reservation_sha256)
    || !Number.isSafeInteger(payload.runner_uid) || payload.runner_uid < 300 || payload.runner_uid > 399
    || !Number.isSafeInteger(payload.bridge_uid) || payload.bridge_uid < 300 || payload.bridge_uid > 399
    || payload.runner_uid === payload.bridge_uid
    || !Number.isSafeInteger(payload.runner_pid) || payload.runner_pid === 1 || payload.runner_pid < 0
    || !Number.isSafeInteger(payload.bridge_pid) || payload.bridge_pid === 1 || payload.bridge_pid < 0
    || typeof payload.stopped_at !== 'string' || !Number.isFinite(Date.parse(payload.stopped_at))) refuse();
  for (const [field, value] of Object.entries(expected)) if (payload[field] !== value) refuse();
  return Object.freeze({ envelope_sha256, stopped_at: payload.stopped_at,
    runner_pid: payload.runner_pid, bridge_pid: payload.bridge_pid, both_uids_idle: true });
}

export function verifyStage2aFinalization(envelopeBytes, { machinePublicKey, expected } = {}) {
  const fields = ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
    'plan_id', 'plan_digest', 'hq_epoch', 'bind_receipt_sha256', 'relay_socket', 'bridge_pid'];
  if (!exact(expected, fields)) refuse();
  const { payload, envelope_sha256 } = verifyEnvelope(envelopeBytes, machinePublicKey, FINAL_PURPOSE);
  if (!exact(payload, ['schema', ...fields, 'finalized_at']) || payload.schema !== FINAL_SCHEMA
    || !SHA.test(payload.reservation_sha256) || !SHA.test(payload.bind_receipt_sha256)
    || !Number.isSafeInteger(payload.bridge_pid) || payload.bridge_pid < 2
    || typeof payload.finalized_at !== 'string' || !Number.isFinite(Date.parse(payload.finalized_at))
    || !exact(payload.relay_socket, ['path', 'socket'])
    || !exact(payload.relay_socket.socket, ['uid', 'gid', 'device', 'inode', 'mode'])) refuse();
  for (const field of fields) {
    if (field === 'relay_socket') {
      if (canonicalize(payload.relay_socket) !== canonicalize(expected.relay_socket)) refuse();
    } else if (payload[field] !== expected[field]) refuse();
  }
  return Object.freeze({ envelope_sha256, finalized_at: payload.finalized_at,
    bind_receipt_sha256: payload.bind_receipt_sha256, bridge_pid: payload.bridge_pid });
}
