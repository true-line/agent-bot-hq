// Owner diagnostic for an already Machine-stopped protected start. Only a
// signed, durable stop record may select the paired read-only Live refusal.
import { createHash, randomBytes } from 'node:crypto';
import { parseStrict } from '../sdk/wire/strict-json.mjs';
import { verifyStage2aStop } from './stage2a-stop.mjs';
import { machineRoleStage2aLiveRefusal, verifyStage2aLiveRefusal } from './machine-channel.mjs';

const START = /^st_[0-9a-f]{24}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const sha = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const refuse = () => { throw new Error('stopped protected start diagnostic is unavailable'); };
const fields = ['reservation_sha256', 'installation_id', 'start_id', 'launch_id',
  'plan_id', 'plan_digest', 'hq_epoch', 'runner_uid', 'bridge_uid', 'runner_pid', 'bridge_pid'];
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');

export function createStage2aStoppedRefusal({ machinePublicKey, receipts, persist,
  isActive, probe = machineRoleStage2aLiveRefusal,
  random = () => randomBytes(32).toString('base64url') } = {}) {
  if (!Buffer.isBuffer(machinePublicKey) || machinePublicKey.length !== 32
    || typeof receipts !== 'function' || typeof persist !== 'function'
    || typeof isActive !== 'function' || typeof probe !== 'function'
    || typeof random !== 'function') refuse();
  const attempted = new Set();

  const verifiedStop = (row) => {
    if (!row || row.kind !== 'hq.protected.stop_verified'
      || !exact(row.expected, fields) || !DIGEST.test(row.envelope_sha256 ?? '')
      || typeof row.envelope_base64url !== 'string') refuse();
    const envelope = Buffer.from(row.envelope_base64url, 'base64url');
    if (!envelope.length || envelope.toString('base64url') !== row.envelope_base64url
      || sha(envelope) !== row.envelope_sha256) refuse();
    const checked = verifyStage2aStop(envelope, { machinePublicKey, expected: row.expected });
    if (checked.envelope_sha256 !== row.envelope_sha256 || !checked.both_uids_idle) refuse();
    return row.expected;
  };

  async function recordStop({ expected, envelope, sha256 } = {}) {
    if (!exact(expected, fields) || !Buffer.isBuffer(envelope) || sha(envelope) !== sha256
      || !START.test(expected.start_id ?? '')) refuse();
    verifiedStop({ kind: 'hq.protected.stop_verified', expected,
      envelope_base64url: envelope.toString('base64url'), envelope_sha256: sha256 });
    if (receipts().some((row) => row.kind === 'hq.protected.stop_verified'
      && row.expected?.start_id === expected.start_id)) refuse();
    await persist({ kind: 'hq.protected.stop_verified', expected: { ...expected },
      start_id: expected.start_id, envelope_base64url: envelope.toString('base64url'),
      envelope_sha256: sha256 });
  }

  async function inspect(payload) {
    if (!exact(payload, ['start_id']) || !START.test(payload.start_id)) refuse();
    const matches = receipts().filter((row) => row.kind === 'hq.protected.stop_verified'
      && row.expected?.start_id === payload.start_id);
    if (matches.length !== 1) refuse();
    const expected = verifiedStop(matches[0]);
    if (isActive(expected.reservation_sha256)) refuse();
    if (attempted.has(expected.reservation_sha256)) refuse();
    attempted.add(expected.reservation_sha256);
    const challenge = random();
    if (typeof challenge !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(challenge)
      || Buffer.from(challenge, 'base64url').length !== 32
      || Buffer.from(challenge, 'base64url').toString('base64url') !== challenge) refuse();
    const { runner_uid, bridge_uid, runner_pid, bridge_pid, ...selectors } = expected;
    const response = await probe({ ...selectors, challenge });
    if (response?.diagnostic !== 'MM_DAEMON_UNIMPLEMENTED'
      || typeof response.signed_response_base64url !== 'string'
      || !/^[A-Za-z0-9_-]+$/.test(response.signed_response_base64url)
      || typeof response.signed_request_base64url !== 'string'
      || !/^[A-Za-z0-9_-]+$/.test(response.signed_request_base64url)) refuse();
    const signed = Buffer.from(response.signed_response_base64url, 'base64url');
    const requestRaw = Buffer.from(response.signed_request_base64url, 'base64url');
    if (!signed.length || signed.length > 8192
      || signed.toString('base64url') !== response.signed_response_base64url
      || !requestRaw.length || requestRaw.length > 8192
      || requestRaw.toString('base64url') !== response.signed_request_base64url) refuse();
    let request;
    let sent;
    let proof;
    try {
      request = parseStrict(requestRaw.toString('utf8'));
      sent = parseStrict(Buffer.from(request.stage2a_request, 'base64url').toString('utf8'));
      proof = verifyStage2aLiveRefusal(signed.toString('utf8'), request.nonce, machinePublicKey);
    } catch { refuse(); }
    if (!exact(request, ['verb', 'stage2a_request', 'timestamp', 'nonce', 'public_key', 'signature'])
      || request.verb !== 'stage2a-live'
      || !/^[A-Za-z0-9_-]{22}$/.test(request.nonce ?? '')
      || !exact(sent, [...Object.keys(selectors), 'challenge'])
      || Object.entries({ ...selectors, challenge }).some(([key, value]) => sent[key] !== value)
      || response.request_nonce !== request.nonce
      || proof.request_nonce !== request.nonce
      || proof.daemon_fingerprint !== response.daemon_fingerprint) refuse();
    const evidence = { kind: 'hq.protected.stopped_live_refused', start_id: payload.start_id,
      reservation_sha256: expected.reservation_sha256, stop_envelope_sha256: matches[0].envelope_sha256,
      challenge, diagnostic: response.diagnostic, request_nonce: request.nonce,
      signed_request_sha256: sha(requestRaw), signed_request_base64url: response.signed_request_base64url,
      signed_response_sha256: sha(signed),
      signed_response_base64url: response.signed_response_base64url,
      daemon_fingerprint: proof.daemon_fingerprint };
    await persist(evidence);
    // Raw request and signed response remain in HQ's private 0600 store.
    // The owner receives their digests, never a successful Live body or lease.
    const { signed_request_base64url: ignoredRequest,
      signed_response_base64url: ignoredResponse, ...ownerResult } = evidence;
    return Object.freeze(ownerResult);
  }

  return Object.freeze({ recordStop, inspect });
}
