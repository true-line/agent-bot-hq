// A protected two-member start has one durable H mapping. The record binds
// the exact A-signed assignment, both child observations and aggregate Ready.
// It is identity evidence only; it is not an ACP or provider grant.
import { canonicalBytes, canonicalDigest } from '../sdk/wire/canonical-json.mjs';
import { createHash } from 'node:crypto';

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const refuse = () => { throw new Error('protected two-member finalization is unavailable'); };
const match = (a, b, fields) => fields.every((field) => a?.[field] === b?.[field]);
const bytes = (value, limit = 16_384) => Buffer.isBuffer(value)
  && value.length > 0 && value.length <= limit;
const sha = (value) => `sha256:${createHash('sha256').update(value).digest('hex')}`;

export function prepareStage2aMemberFinalization({
  prestarted, expected, primaryAssignment, now = Date.now(),
} = {}) {
  const assignment = prestarted?.assignment?.payload;
  const observation = prestarted?.observation?.payload;
  const ready = prestarted?.ready?.payload;
  const aBytes = prestarted?.assignmentBytes;
  const cBytes = prestarted?.observationBytes;
  const rBytes = prestarted?.readyBytes;
  const bBytes = prestarted?.authorityBytes;
  const grants = prestarted?.memberGrants;
  const admitted = expected?.admitted_runtimes;
  if (![aBytes, cBytes, rBytes, bBytes].every((value) => bytes(value))
    || !Number.isSafeInteger(now) || now <= 0
    || !assignment || !observation || !ready
    || assignment.profile_in_force !== 'managed-protected'
    || observation.profile_in_force !== 'managed-protected'
    || ready.profile_in_force !== 'managed-protected'
    || !Array.isArray(assignment.members) || assignment.members.length !== 2
    || !Array.isArray(observation.members) || observation.members.length !== 2
    || !Array.isArray(ready.members) || ready.members.length !== 2
    || !Array.isArray(grants) || grants.length !== 2
    || !Array.isArray(admitted) || admitted.length !== 2) refuse();
  const aSHA = sha(aBytes);
  const cSHA = sha(cBytes);
  const rSHA = sha(rBytes);
  const bSHA = sha(bBytes);
  const scope = ['host_id', 'installation_id', 'soul_id', 'start_id', 'hq_epoch',
    'reservation_sha256'];
  if (!match(assignment, observation, scope) || !match(assignment, ready, scope)
    || observation.assignment_envelope_sha256 !== aSHA
    || ready.assignment_envelope_sha256 !== aSHA
    || ready.child_observation_envelope_sha256 !== cSHA
    || ready.member_b_authority_envelope_sha256 !== bSHA
    || ready.provisional_hq_mapping_sha256 !== observation.provisional_hq_mapping_sha256
    || expected.profile_in_force !== 'managed-protected'
    || expected.installation_id !== assignment.installation_id
    || expected.soul_id !== assignment.soul_id
    || expected.start_id !== assignment.start_id
    || expected.hq_epoch !== assignment.hq_epoch
    || expected.reservation_sha256 !== assignment.reservation_sha256
    || !primaryAssignment
    || !match(primaryAssignment, expected, ['installation_id', 'start_id', 'launch_id',
      'hq_epoch'])
    || !/^ln_[0-9a-f]{24}$/.test(expected.launch_id ?? '')
    || assignment.plan_id !== primaryAssignment.plan_id
    || assignment.plan_digest !== primaryAssignment.plan_digest
    || !DIGEST.test(expected.hq_broker_bind_receipt_sha256 ?? '')
    || !DIGEST.test(observation.provisional_hq_mapping_sha256 ?? '')
    || !Number.isFinite(Date.parse(ready.issued_at))
    || !Number.isFinite(Date.parse(ready.expires_at))
    || Date.parse(ready.issued_at) > now || now >= Date.parse(ready.expires_at)
    || Date.parse(ready.expires_at) - Date.parse(ready.issued_at) > 5000) refuse();
  const rows = assignment.members.map((member, index) => {
    const observed = observation.members[index];
    const armed = ready.members[index];
    const grant = grants[index];
    const runtime = admitted.find((item) => item.member_id === member.member_id);
    if (!runtime || !match(member, observed, ['member_id', 'member_selector', 'launch_id'])
      || !match(member, armed, ['member_id', 'member_selector', 'launch_id'])
      || !match(member, grant, ['member_id', 'member_selector'])
      || !match(observed, armed, ['runtime_id'])
      || runtime.runtime_id !== observed.runtime_id
      || grant.launch_id !== member.launch_id
      || grant.grant_sha256 !== observed.grant_sha256
      || !DIGEST.test(grant.grant_sha256 ?? '')
      || !DIGEST.test(armed.bridge_arm_receipt_sha256 ?? '')
      || canonicalDigest(armed.bridge_arm) !== armed.bridge_arm_receipt_sha256
      || armed.bridge_arm?.child_observation_envelope_sha256 !== cSHA
      || armed.bridge_arm?.state !== 'armed'
      || armed.bridge_arm?.adapter_pid !== observed.child_process?.pid
      || observed.launcher_process?.pid !== observed.child_process?.parent_pid) refuse();
    return Object.freeze({
      member_id: member.member_id, member_selector: member.member_selector,
      member_launch_id: member.launch_id, runtime_id: observed.runtime_id,
      grant_sha256: grant.grant_sha256,
      bridge_arm_receipt_sha256: armed.bridge_arm_receipt_sha256,
      launcher_process: observed.launcher_process,
      child_process: observed.child_process,
    });
  });
  if (rows[0].member_id === rows[1].member_id
    || rows[0].member_launch_id === rows[1].member_launch_id
    || rows[0].runtime_id === rows[1].runtime_id
    || rows[0].child_process.pid === rows[1].child_process.pid
    || rows[0].launcher_process.pid === rows[1].launcher_process.pid) refuse();
  const record = Object.freeze({
    schema: 'agent-bot-hq/stage2a-member-finalization/v1',
    profile_in_force: 'managed-protected',
    ...Object.fromEntries(scope.map((field) => [field, assignment[field]])),
    launch_id: expected.launch_id,
    plan_id: assignment.plan_id,
    plan_digest: assignment.plan_digest,
    assignment_envelope_sha256: aSHA,
    child_observation_envelope_sha256: cSHA,
    ready_envelope_sha256: rSHA,
    member_b_authority_envelope_sha256: bSHA,
    provisional_hq_mapping_sha256: observation.provisional_hq_mapping_sha256,
    bind_receipt_sha256: expected.hq_broker_bind_receipt_sha256,
    members: rows,
    committed_at: new Date(now).toISOString(),
  });
  const canonical = canonicalBytes(record);
  if (canonical.length > 8_192) refuse();
  return Object.freeze({ record, bytes: canonical, sha256: sha(canonical) });
}
