// Keep the sibling R child's credential metadata opaque to HQ but exact on
// the wire. A owns the signed lease, no-follow path and process validation.
import { canonicalDigest } from '../sdk/wire/canonical-json.mjs';

const WITNESS = ['schema', 'challenge_base64url', 'primary_reservation_sha256',
  'sibling_reservation_sha256', 'sibling_installation_id', 'sibling_start_id',
  'child_receipt_sha256', 'lease_sequence', 'credential_path', 'metadata',
  'metadata_sha256', 'observed_at_ms'];
const METADATA = ['schema', 'path', 'device', 'inode', 'generation', 'uid', 'gid',
  'mode', 'size_bytes', 'birth_seconds', 'birth_nanos', 'modify_seconds',
  'modify_nanos', 'change_seconds', 'change_nanos'];
const DECIMAL = /^(0|[1-9][0-9]{0,19})$/;
const SHA = /^sha256:[0-9a-f]{64}$/;
const exact = (value, fields) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).length === fields.length && fields.every((field) => Object.hasOwn(value, field));
const decimal = (value) => typeof value === 'string' && DECIMAL.test(value);
const refuse = () => { throw new Error('invalid protected T03 sibling credential witness'); };

export function checkedT03SiblingWitness(witness, expected) {
  const m = witness?.metadata;
  if (!exact(witness, WITNESS) || !exact(m, METADATA)
    || witness.schema !== 'agent-bot-machine/stage2a-t03-sibling-credential-witness/v1'
    || m.schema !== 'agent-bot-machine/stage2a-t03-credential-metadata/v1'
    || !SHA.test(witness.primary_reservation_sha256)
    || witness.sibling_reservation_sha256 !== expected.reservation_sha256
    || witness.sibling_installation_id !== expected.installation_id
    || witness.sibling_start_id !== expected.start_id
    || witness.child_receipt_sha256 !== expected.child_receipt_sha256
    || typeof witness.challenge_base64url !== 'string'
    || !/^[A-Za-z0-9_-]{43}$/.test(witness.challenge_base64url)
    || Buffer.from(witness.challenge_base64url, 'base64url').length !== 32
    || Buffer.from(witness.challenge_base64url, 'base64url').toString('base64url') !== witness.challenge_base64url
    || !Number.isSafeInteger(witness.lease_sequence) || witness.lease_sequence < 1
    || !Number.isSafeInteger(witness.observed_at_ms) || witness.observed_at_ms < 1
    || typeof witness.credential_path !== 'string' || !witness.credential_path.startsWith('/')
    || witness.credential_path.length > 512 || /[\x00\r\n]/.test(witness.credential_path)
    || m.path !== witness.credential_path
    || !['device', 'inode', 'generation', 'size_bytes', 'birth_seconds',
      'birth_nanos', 'modify_seconds', 'modify_nanos', 'change_seconds', 'change_nanos']
      .every((field) => decimal(m[field]))
    || ['birth_nanos', 'modify_nanos', 'change_nanos'].some((field) => BigInt(m[field]) >= 1_000_000_000n)
    || !Number.isSafeInteger(m.uid) || m.uid < 0
    || !Number.isSafeInteger(m.gid) || m.gid < 0
    || typeof m.mode !== 'string' || !/^[0-7]{4}$/.test(m.mode)
    || !SHA.test(witness.metadata_sha256)
    || canonicalDigest(m) !== witness.metadata_sha256) refuse();
  return Object.freeze({ ...witness, metadata: Object.freeze({ ...m }) });
}

export function recordT03SiblingWitness(primary, witness) {
  const accepted = primary.siblingWitnesses ??= [];
  const prior = accepted.at(-1);
  if (accepted.length >= 2 || (prior && (witness.lease_sequence <= prior.lease_sequence
    || witness.challenge_base64url === prior.challenge_base64url
    || witness.sibling_reservation_sha256 !== prior.sibling_reservation_sha256
    || witness.metadata_sha256 !== prior.metadata_sha256))) refuse();
  accepted.push(witness);
  if (accepted.length === 2 && primary.siblingWitnessWaiter) {
    primary.siblingWitnessWaiter.resolve();
    primary.siblingWitnessWaiter = undefined;
  }
}

export async function waitForT03SiblingWitnesses(primary, timeoutMS = 20_000) {
  if (primary.siblingWitnesses?.length === 2) return primary.siblingWitnesses;
  if (primary.siblingWitnessWaiter) refuse();
  const pending = Promise.withResolvers();
  primary.siblingWitnessWaiter = pending;
  const timer = setTimeout(() => pending.reject(new Error('protected T03 sibling witness timed out')), timeoutMS);
  try { await pending.promise; }
  finally {
    clearTimeout(timer);
    if (primary.siblingWitnessWaiter === pending) primary.siblingWitnessWaiter = undefined;
  }
  if (primary.siblingWitnesses?.length !== 2) refuse();
  return primary.siblingWitnesses;
}

export function requireT03SiblingAfterAttempt(witnesses, attemptedAtMS) {
  if (!Array.isArray(witnesses) || witnesses.length !== 2
    || !Number.isSafeInteger(attemptedAtMS) || attemptedAtMS < 1
    || witnesses[1].observed_at_ms <= attemptedAtMS) refuse();
}
