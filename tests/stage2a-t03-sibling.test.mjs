import test from 'node:test';
import assert from 'node:assert/strict';
import { canonicalDigest } from '../sdk/wire/canonical-json.mjs';
import { checkedT03SiblingWitness, recordT03SiblingWitness,
  waitForT03SiblingWitnesses, requireT03SiblingAfterAttempt } from '../hq/stage2a-t03-sibling.mjs';

const sha = (digit) => `sha256:${digit.repeat(64)}`;
const expected = { reservation_sha256: sha('1'), installation_id: 'sibling-install',
  start_id: `st_${'2'.repeat(24)}`, child_receipt_sha256: sha('3') };
const metadata = { schema: 'agent-bot-machine/stage2a-t03-credential-metadata/v1',
  path: '/private/sibling/credential', device: '2', inode: '123', generation: '0',
  uid: 321, gid: 321, mode: '0600', size_bytes: '64',
  birth_seconds: '1795520000', birth_nanos: '123', modify_seconds: '1795520000',
  modify_nanos: '124', change_seconds: '1795520000', change_nanos: '125' };
const witness = { schema: 'agent-bot-machine/stage2a-t03-sibling-credential-witness/v1',
  challenge_base64url: Buffer.alloc(32, 1).toString('base64url'),
  primary_reservation_sha256: sha('4'), sibling_reservation_sha256: expected.reservation_sha256,
  sibling_installation_id: expected.installation_id, sibling_start_id: expected.start_id,
  child_receipt_sha256: expected.child_receipt_sha256, lease_sequence: 7,
  credential_path: metadata.path, metadata, metadata_sha256: canonicalDigest(metadata),
  observed_at_ms: 1_795_520_001_000 };

test('HQ forwards only exact sibling metadata and waits for two later-lease acknowledgments', async () => {
  const first = checkedT03SiblingWitness(witness, expected);
  const second = checkedT03SiblingWitness({ ...witness,
    lease_sequence: 8, observed_at_ms: witness.observed_at_ms + 1 }, expected);
  const primary = {};
  recordT03SiblingWitness(primary, first);
  const pending = waitForT03SiblingWitnesses(primary, first.observed_at_ms, 1000);
  recordT03SiblingWitness(primary, second);
  const witnessed = await pending;
  assert.deepEqual(witnessed, [first, second]);
  assert.deepEqual(requireT03SiblingAfterAttempt(witnessed, first.observed_at_ms), witnessed);
  assert.throws(() => recordT03SiblingWitness(primary, second));
  assert.throws(() => recordT03SiblingWitness(primary, checkedT03SiblingWitness({ ...second,
    challenge_base64url: Buffer.alloc(32, 2).toString('base64url'),
    lease_sequence: 9 }, expected)));
  assert.throws(() => checkedT03SiblingWitness({ ...witness, metadata_sha256: sha('0') }, expected));
  assert.throws(() => checkedT03SiblingWitness({ ...witness,
    metadata: { ...metadata, extra: true } }, expected));
  assert.throws(() => checkedT03SiblingWitness({ ...witness,
    metadata: { ...metadata, mode: '000644' } }, expected));
  assert.throws(() => checkedT03SiblingWitness({ ...witness, child_receipt_sha256: sha('0') }, expected));
});

test('HQ refuses a second sibling witness from the same signed lease', async () => {
  const primary = {};
  recordT03SiblingWitness(primary, checkedT03SiblingWitness(witness, expected));
  assert.throws(() => recordT03SiblingWitness(primary, checkedT03SiblingWitness({ ...witness,
    challenge_base64url: Buffer.alloc(32, 2).toString('base64url') }, expected)));
  await assert.rejects(waitForT03SiblingWitnesses(primary, witness.observed_at_ms, 5), /timed out/);
});

test('delayed delivery of a pre-attempt witness cannot satisfy primary completion', async () => {
  const primary = {};
  const first = checkedT03SiblingWitness(witness, expected);
  const second = checkedT03SiblingWitness({ ...witness,
    lease_sequence: witness.lease_sequence + 1,
    observed_at_ms: witness.observed_at_ms + 1 }, expected);
  recordT03SiblingWitness(primary, first);
  // The second ACK may arrive only after the primary result is delivered,
  // but its signed observation time still predates the credential attempt.
  const primaryAttemptMS = second.observed_at_ms + 1;
  recordT03SiblingWitness(primary, second);
  assert.throws(() => requireT03SiblingAfterAttempt(primary.siblingWitnesses, primaryAttemptMS));
  await assert.rejects(waitForT03SiblingWitnesses(primary, primaryAttemptMS, 5), /timed out/);
  const third = checkedT03SiblingWitness({ ...witness, lease_sequence: second.lease_sequence + 1,
    observed_at_ms: primaryAttemptMS + 1 }, expected);
  const pending = waitForT03SiblingWitnesses(primary, primaryAttemptMS, 1000);
  recordT03SiblingWitness(primary, third);
  assert.deepEqual(await pending, [first, third]);
});

test('several pre-attempt Live renewals retain the first ACK and accept a later witness', async () => {
  const primary = {};
  const first = checkedT03SiblingWitness(witness, expected);
  recordT03SiblingWitness(primary, first);
  for (let index = 1; index <= 40; index++) {
    recordT03SiblingWitness(primary, checkedT03SiblingWitness({ ...witness,
      lease_sequence: witness.lease_sequence + index,
      observed_at_ms: witness.observed_at_ms + index }, expected));
  }
  assert.equal(primary.siblingWitnesses.length, 32);
  assert.equal(primary.siblingWitnesses[0], first);
  const attemptedAtMS = witness.observed_at_ms + 41;
  const pending = waitForT03SiblingWitnesses(primary, attemptedAtMS, 1000);
  const later = checkedT03SiblingWitness({ ...witness,
    lease_sequence: witness.lease_sequence + 41,
    observed_at_ms: attemptedAtMS + 1 }, expected);
  recordT03SiblingWitness(primary, later);
  assert.deepEqual(await pending, [first, later]);
});
