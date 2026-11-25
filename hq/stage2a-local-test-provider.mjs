// Isolated HQ local-test source. No production entry point imports this module.
// Machine owns raw-FD4 proof/MAC, live roles and spends. Its Q producer and the
// installed Comms B ingress are separate prerequisites for a runnable route.
import { createHash } from 'node:crypto';
import { canonicalize } from '../sdk/wire/canonical-json.mjs';
import { parseStrict } from '../sdk/wire/strict-json.mjs';
import { verifyStage2aMachineEnvelope } from './stage2a-stop.mjs';
import { OBSERVED_BODY_LOCAL_TEST_MODE, openLocalProviderService,
  stage2aLocalProviderPort } from './stage2a-qualification-provider.mjs';

const DIGEST = /^sha256:[0-9a-f]{64}$/;
const HEX = /^[0-9a-f]{64}$/;
const START = /^st_[0-9a-f]{24}$/;
const LAUNCH = /^ln_[0-9a-f]{24}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const SELECTORS = ['installation_id', 'start_id', 'launch_id', 'plan_id', 'plan_digest',
  'reservation_digest', 'assignment_envelope_sha256', 'authority_envelope_sha256',
  'member_selectors_sha256'];
const LOCAL_TEST = ['selected_member_id', 'selected_launch_id', 'selected_member_selector',
  'runner_account', 'expected_child_cwd_lexical', 'expected_child_cwd_emitted',
  'expected_child_home_lexical', 'expected_memory_path_lexical', 'body_profile',
  'static_projection_sha256', 'owner_prompt_sha256', 'r_first_brief_sha256',
  'header_shape', 'header_shape_sha256', 'client_key_sha256', 'model', 'http_host',
  'messages_query', 'fixture_config_sha256', 'ancillary_profile', 'ancillary_profile_sha256'];
const ASSIGNMENT = ['contract', 'kind', 'schema_version', 'host_id', 'installation_id',
  'soul_id', 'start_id', 'hq_epoch', 'profile_in_force', 'plan_id', 'plan_digest',
  'owner_plan_member_set_sha256', 'reservation_sha256', 'b_authority',
  'soul_artifact_sha256', 'frozen_soul_info_sha256', 'adapter_manifest_relpath',
  'frozen_adapter_manifest_sha256', 'host_projection_sha256',
  'definition_measurement', 'runner_uid', 'runner_gid', 'bridge', 'members',
  'issued_at', 'expires_at'];
const ASSIGNED_MEMBER = ['member_id', 'role', 'adapter_id', 'adapter_version',
  'command_path', 'command_sha256', 'adjacent_cli_path', 'adjacent_cli_sha256',
  'launch_id', 'member_selector'];
const QUALIFICATION = ['mode', 'model', 'body_profile', 'static_projection_sha256',
  'owner_prompt_sha256', 'r_first_brief_sha256', 'header_shape_sha256',
  'client_key_sha256', 'http_host', 'messages_query', 'response_text_sha256'];
const INGRESS = ['schema', 'kind', 'selectors', 'bind_receipt_sha256', 'peer',
  'peer_sha256', 'observed_body_sha256', 'observed_headers_sha256',
  'static_projection_sha256', 'observed_brief_sha256', 'owner_prompt_sha256',
  'body_profile', 'digest_kind', 'target_received_at', 'attempt_id'];
const PREWRITE = ['schema', 'selectors', 'bind_receipt_sha256',
  'authorization_envelope_sha256', 'ingress_core_sha256', 'observed_body_sha256',
  'observed_headers_sha256', 'static_projection_sha256', 'owner_prompt_sha256',
  'peer', 'peer_sha256', 'response_wire_sha256', 'response_wire_bytes', 'http_status'];
const PURPOSE = 'agent-bot/stage2a-observed-body-local-test-reservation/v1';
const AUTH_PURPOSE = 'agent-bot/stage2a-observed-body-local-test-ingress-authorization/v1';
const PREWRITE_PROOF_PURPOSE = 'agent-bot/stage2a-observed-body-local-test-prewrite-acceptance/v1';
const PROFILE = 'stage2a-stock-observed-local-test/v1';
const refuse = () => { throw new Error('observed-body local-test provider is unavailable'); };
const exact = (v, keys) => v !== null && typeof v === 'object' && !Array.isArray(v)
  && Object.keys(v).length === keys.length && keys.every((key) => Object.hasOwn(v, key));
const same = (a, b, keys) => keys.every((key) => a?.[key] === b?.[key]);
const digest = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const jcsDigest = (value) => digest(Buffer.from(canonicalize(value)));
const parseCanonical = (bytes) => {
  const value = parseStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
  if (!Buffer.from(canonicalize(value)).equals(bytes)) refuse();
  return value;
};
const decode = (value, maxBytes = 8192) => {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) refuse();
  const bytes = Buffer.from(value, 'base64url');
  if (!bytes.length || bytes.length > maxBytes || bytes.toString('base64url') !== value) refuse();
  return bytes;
};
const time = (value) => typeof value === 'string' && Number.isFinite(Date.parse(value));

export function validLocalTestSelectors(value) {
  return exact(value, SELECTORS) && ID.test(value.installation_id)
    && START.test(value.start_id) && LAUNCH.test(value.launch_id)
    && ID.test(value.plan_id) && HEX.test(value.plan_digest)
    && ['reservation_digest', 'assignment_envelope_sha256',
      'authority_envelope_sha256', 'member_selectors_sha256']
      .every((key) => DIGEST.test(value[key]));
}

export function validLocalTestChildPaths(value, selectors) {
  if (!value || typeof value !== 'object' || !selectors
    || typeof selectors.installation_id !== 'string'
    || typeof selectors.start_id !== 'string') return false;
  const runnerAccount = '_abm-sr-' + createHash('sha256')
    .update(selectors.installation_id).digest('hex').slice(0, 20);
  const prefix = `/var/agent-bot-soul-runner-${runnerAccount}/state/child-`;
  const childCWD = value?.expected_child_cwd_lexical;
  const slot = typeof childCWD === 'string' && childCWD.startsWith(prefix)
    && childCWD.endsWith('/work') ? childCWD.slice(prefix.length, -'/work'.length) : '';
  const expectedSlot = createHash('sha256').update(Buffer.from(
    `agent-bot-soul-endpoint-start/v1\0${selectors.installation_id}\0${selectors.start_id}`))
    .digest('hex').slice(0, 20);
  const childRoot = `${prefix}${slot}`;
  const expectedCWD = `${childRoot}/work`;
  const expectedHome = `${childRoot}/home`;
  const emittedCWD = `/private${expectedCWD}`;
  return value.runner_account === runnerAccount
    && slot === expectedSlot
    && value.expected_child_cwd_lexical === expectedCWD
    && value.expected_child_cwd_emitted === emittedCWD
    && value.expected_child_home_lexical === expectedHome
    && value.expected_memory_path_lexical === expectedHome
      + '/.claude/projects/' + emittedCWD.replace(/[^A-Za-z0-9]/g, '-') + '/memory/';
}

export function validLocalTestAncillaryOrder(order, targetAfter) {
  return canonicalize(order) === canonicalize(['first', 'second'])
    && canonicalize(targetAfter) === canonicalize(['first']);
}

function validLocalTest(value, selectors, selectedMember) {
  return exact(value, LOCAL_TEST) && ID.test(value.selected_member_id)
    && value.selected_member_id === selectedMember.member_id
    && value.selected_launch_id === selectedMember.launch_id
    && value.selected_member_selector === selectedMember.member_selector
    && /^mb_[0-9a-f]{64}$/.test(value.selected_member_selector)
    && validLocalTestChildPaths(value, selectors)
    && ID.test(value.model)
    && ID.test(value.http_host) && value.body_profile === PROFILE
    && typeof value.messages_query === 'string' && value.messages_query.length <= 128
    && ['static_projection_sha256', 'owner_prompt_sha256', 'r_first_brief_sha256',
      'header_shape_sha256', 'client_key_sha256', 'fixture_config_sha256',
      'ancillary_profile_sha256'].every((key) => DIGEST.test(value[key]))
    && exact(value.header_shape, ['schema', 'host', 'required_fixed',
      'required_volatile', 'forbidden', 'allow_extra'])
    && value.header_shape.schema === 'stage2a-observed-body-header-shape/v1'
    && value.header_shape.host === value.http_host
    && value.header_shape.allow_extra === false
    && exact(value.ancillary_profile, ['schema', 'body_profile',
      'normalized_body_sha256', 'first_header_shape', 'first_headers_sha256',
      'second_header_shape', 'second_headers_sha256', 'order', 'target_after',
      'max_ancillary', 'ancillary_http_status'])
    && value.ancillary_profile.schema === 'stage2a-stock-ancillary-local-test-profile/v1'
    && value.ancillary_profile.body_profile === 'stage2a-stock-ancillary-one-block/v1'
    && DIGEST.test(value.ancillary_profile.normalized_body_sha256)
    && DIGEST.test(value.ancillary_profile.first_headers_sha256)
    && DIGEST.test(value.ancillary_profile.second_headers_sha256)
    && validLocalTestAncillaryOrder(value.ancillary_profile.order,
      value.ancillary_profile.target_after)
    && value.ancillary_profile.max_ancillary === 2
    && value.ancillary_profile.ancillary_http_status === 422
    && jcsDigest(value.header_shape) === value.header_shape_sha256
    && jcsDigest(value.ancillary_profile) === value.ancillary_profile_sha256;
}

function checkedReservation(bytes, pin, selectors, validateReservation, now) {
  const signed = verifyStage2aMachineEnvelope(bytes, pin, PURPOSE, { maxBytes: 65_536 });
  const p = signed.payload;
  if (!exact(p, ['contract', 'kind', 'schema_version', 'host_id', 'issued_at',
    'expires_at', 'installed_plan_receipt_sha256', 'assignment', 'member_endpoint',
    'measurement_binding', 'admission_challenge_sha256', 'start_scope'])
    || p.contract !== 'machine/local-test-v1'
    || p.kind !== 'stage2a-observed-body-local-test-reservation'
    || p.schema_version !== 1 || !ID.test(p.host_id)
    || !time(p.issued_at) || !time(p.expires_at)
    || Date.parse(p.issued_at) > now() || Date.parse(p.expires_at) <= now()
    || Date.parse(p.expires_at) - Date.parse(p.issued_at) > 30_000
    || !DIGEST.test(p.installed_plan_receipt_sha256)
    || !DIGEST.test(p.admission_challenge_sha256)
    || !exact(p.start_scope, ['mode', 'one_use_start_claim_name'])
    || p.start_scope.mode !== 'provider-pending-local-test/v1'
    || !ID.test(p.start_scope.one_use_start_claim_name)
    || !validLocalTestSelectors(selectors)
    || signed.envelope_sha256 !== selectors.reservation_digest
    || !same(p.assignment, selectors, ['installation_id', 'start_id', 'launch_id',
      'plan_id', 'plan_digest'])
    || validateReservation(p) !== true) refuse();
  return p;
}

const sameSelectors = (a, b) => validLocalTestSelectors(a)
  && validLocalTestSelectors(b) && same(a, b, SELECTORS);

function checkedIngress(core, selectors, localTest, bindReceiptSHA256) {
  if (!exact(core, INGRESS) || core.schema !== 'stage2a-observed-body-local-test-ingress/v1'
    || core.kind !== 'observed-body-local-test-ingress'
    || !sameSelectors(core.selectors, selectors)
    || core.bind_receipt_sha256 !== bindReceiptSHA256
    || !exact(core.peer, ['uid', 'pid', 'pid_version', 'start_seconds', 'start_micros',
      'parent_pid', 'parent_uid', 'parent_start_seconds', 'parent_start_micros'])
    || Object.values(core.peer).some((v) => !Number.isSafeInteger(v) || v < 0)
    || core.peer_sha256 !== jcsDigest(core.peer)
    || !['observed_body_sha256', 'observed_headers_sha256'].every((key) => DIGEST.test(core[key]))
    || core.static_projection_sha256 !== localTest.static_projection_sha256
    || core.observed_brief_sha256 !== localTest.r_first_brief_sha256
    || core.owner_prompt_sha256 !== localTest.owner_prompt_sha256
    || core.body_profile !== PROFILE || core.digest_kind !== 'observed-stock-body/v1'
    || !time(core.target_received_at) || !ID.test(core.attempt_id)) refuse();
}

function checkedAuthorization(result, pin, selectors, core, now) {
  if (!exact(result, ['authorization_envelope_base64url', 'authorization_envelope_sha256'])
    || !DIGEST.test(result.authorization_envelope_sha256)) refuse();
  const bytes = decode(result.authorization_envelope_base64url);
  const signed = verifyStage2aMachineEnvelope(bytes, pin, AUTH_PURPOSE);
  const p = signed.payload;
  if (signed.envelope_sha256 !== result.authorization_envelope_sha256
    || !exact(p, ['schema', 'kind', 'selectors', 'ingress_core_sha256',
      'provider_claim_sha256', 'issued_at', 'expires_at'])
    || p.schema !== 'agent-bot-machine/stage2a-observed-body-local-test-ingress-authorization/v1'
    || p.kind !== 'observed-body-local-test-ingress-authorization'
    || !sameSelectors(p.selectors, selectors)
    || p.ingress_core_sha256 !== jcsDigest(core)
    || !DIGEST.test(p.provider_claim_sha256)
    || !time(p.issued_at) || !time(p.expires_at)
    || Date.parse(p.issued_at) > now() || Date.parse(p.expires_at) <= now()) refuse();
  return p;
}

function checkedPrewriteProof(reply, pin, selectors, hqEpoch, prewrite,
  authorizationIssuedAt, authorizationExpiresAt, policyExpiresAt,
  reservationExpiresAt, now) {
  if (!exact(reply, ['prewrite_receipt', 'prewrite_proof_envelope_base64url',
    'prewrite_proof_envelope_sha256']) || !HEX.test(reply.prewrite_receipt)
    || !DIGEST.test(reply.prewrite_proof_envelope_sha256)) refuse();
  const bytes = decode(reply.prewrite_proof_envelope_base64url);
  const signed = verifyStage2aMachineEnvelope(bytes, pin, PREWRITE_PROOF_PURPOSE);
  const p = signed.payload;
  if (signed.envelope_sha256 !== reply.prewrite_proof_envelope_sha256
    || !exact(p, ['schema', 'kind', 'schema_version', 'selectors', 'hq_epoch',
      'authorization_envelope_sha256', 'prewrite_core_sha256',
      'prewrite_receipt', 'issued_at', 'expires_at'])
    || p.schema !== 'agent-bot-machine/stage2a-observed-body-local-test-prewrite-acceptance/v1'
    || p.kind !== 'observed-body-local-test-prewrite-acceptance'
    || p.schema_version !== 1
    || !sameSelectors(p.selectors, selectors) || p.hq_epoch !== hqEpoch
    || p.authorization_envelope_sha256 !== prewrite.authorization_envelope_sha256
    || p.prewrite_core_sha256 !== jcsDigest(prewrite)
    || p.prewrite_receipt !== reply.prewrite_receipt
    || !time(p.issued_at) || !time(p.expires_at)
    || Date.parse(p.issued_at) < authorizationIssuedAt
    || Date.parse(p.issued_at) > now() || Date.parse(p.expires_at) <= now()
    || Date.parse(p.expires_at) <= Date.parse(p.issued_at)
    || Date.parse(p.expires_at) - Date.parse(p.issued_at) > 30_000
    || Date.parse(p.expires_at) > authorizationExpiresAt
    || Date.parse(p.expires_at) > policyExpiresAt
    || Date.parse(p.expires_at) > reservationExpiresAt) refuse();
  return Object.freeze({ ...reply });
}

// Full nested schema validation remains with the owning Machine parser callback.
// This module verifies the signed member assignment and its selected-member join.
export function createStage2aLocalTestProvider({ reservationEnvelope, memberAssignmentEnvelope, selectors,
  policyEnvelope, machinePublicKey, validateReservation, validateMemberAssignment, verifyPolicy,
  machineChallenge, machineBind, machineIngress, machineProvider, machinePrewrite,
  machineComplete, observeCurrentStart, openService = openLocalProviderService,
  now = Date.now } = {}) {
  if (!Buffer.isBuffer(reservationEnvelope) || !Buffer.isBuffer(memberAssignmentEnvelope)
    || !Buffer.isBuffer(policyEnvelope)
    || !Buffer.isBuffer(machinePublicKey) || machinePublicKey.length !== 32
    || [validateReservation, validateMemberAssignment, verifyPolicy, machineChallenge, machineBind,
      machineIngress, machineProvider, machinePrewrite, machineComplete,
      observeCurrentStart, openService, now].some((fn) => typeof fn !== 'function')) refuse();
  const reservation = checkedReservation(reservationEnvelope, machinePublicKey,
    selectors, validateReservation, now);
  const assignment = verifyStage2aMachineEnvelope(memberAssignmentEnvelope, machinePublicKey,
    'agent-bot/stage2a-member-set-assignment-local-test/v1', { maxBytes: 65_536 });
  const assigned = assignment.payload;
  if (assignment.envelope_sha256 !== selectors.assignment_envelope_sha256
    || !exact(assigned, ASSIGNMENT)
    || assigned?.contract !== 'machine/local-test-v1'
    || assigned.kind !== 'stage2a-member-set-assignment'
    || assigned.schema_version !== 1
    || assigned.profile_in_force !== 'managed-protected'
    || assigned?.reservation_sha256 !== selectors.reservation_digest
    || !same(assigned, selectors, ['installation_id', 'start_id', 'plan_id', 'plan_digest'])
    || !exact(assigned?.b_authority, ['purpose', 'envelope_sha256'])
    || assigned.b_authority.purpose !== PURPOSE
    || assigned.b_authority.envelope_sha256 !== selectors.reservation_digest
    || assigned.host_id !== reservation.host_id
    || assigned.soul_id !== reservation.assignment.soul_id
    || assigned.hq_epoch !== reservation.assignment.hq_epoch
    || assigned.runner_uid !== reservation.assignment.runner_uid
    || assigned.runner_gid !== reservation.assignment.runner_gid
    || assigned.soul_artifact_sha256
      !== `sha256:${reservation.assignment.soul_artifact_sha256}`
    || !time(assigned.issued_at) || !time(assigned.expires_at)
    || Date.parse(assigned.issued_at) > now()
    || Date.parse(assigned.expires_at) <= now()
    || Date.parse(assigned.expires_at) > Date.parse(reservation.expires_at)
    || !Array.isArray(assigned.members) || assigned.members.length !== 2
    || assigned.members.some((member) => !exact(member, ASSIGNED_MEMBER)
      || !ID.test(member.member_id) || !ID.test(member.adapter_id)
      || !ID.test(member.adapter_version)
      || typeof member.command_path !== 'string' || !member.command_path.startsWith('/')
      || typeof member.adjacent_cli_path !== 'string' || !member.adjacent_cli_path.startsWith('/')
      || !DIGEST.test(member.command_sha256) || !DIGEST.test(member.adjacent_cli_sha256)
      || !LAUNCH.test(member?.launch_id)
      || member.member_selector !== `mb_${createHash('sha256').update(
        `agent-bot/stage2a-member-selector/v1\0${selectors.reservation_digest}\0${member.member_id}\0${member.launch_id}`
      ).digest('hex')}`)
    || assigned.members[0].role !== 'lead' || assigned.members[1].role !== 'specialist'
    || new Set(assigned.members.map((member) => member.member_id)).size !== 2
    || new Set(assigned.members.map((member) => member.member_selector)).size !== 2
    || jcsDigest(assigned.members.map((member) => member.member_selector))
      !== selectors.member_selectors_sha256
    || validateMemberAssignment(assigned) !== true) refuse();
  const policy = verifyPolicy(policyEnvelope, selectors, reservation);
  const signedPolicy = verifyStage2aMachineEnvelope(policyEnvelope, machinePublicKey,
    'agent-bot/stage2a-b-member-authority-local-test/v1', { maxBytes: 65_536 });
  const p = signedPolicy.payload;
  if (signedPolicy.envelope_sha256 !== selectors.authority_envelope_sha256
    || p?.contract !== 'machine/local-test-v1'
    || p?.reservation_sha256 !== selectors.reservation_digest
    || p?.member_set_assignment_envelope_sha256 !== selectors.assignment_envelope_sha256
    || !same(p, selectors, ['installation_id', 'start_id', 'plan_id', 'plan_digest'])
    || p.outer_launch_id !== selectors.launch_id
    || p.outer_launch_id !== reservation.assignment.launch_id
    || p.hq_epoch !== assigned.hq_epoch
    || !time(p.expires_at) || Date.parse(p.expires_at) <= now()
    || Date.parse(p.expires_at) > Date.parse(reservation.expires_at)
    || !exact(policy, ['selectors', 'hq_epoch', 'local_test', 'members'])
    || !sameSelectors(policy.selectors, selectors) || !HEX.test(policy.hq_epoch)
    || policy.hq_epoch !== p.hq_epoch
    || canonicalize(policy.local_test) !== canonicalize(p.local_test)
    || canonicalize(policy.members) !== canonicalize(p.members)
    || !Array.isArray(policy.members) || policy.members.length !== 2
    || policy.members.some((member, index) => !same(member, assigned.members[index],
      ['member_id', 'launch_id', 'member_selector']))
    || policy.members[0].member_id !== assigned.members[0].member_id
    || policy.members[1].member_id !== assigned.members[1].member_id
    || !exact(policy.members[0].qualification, QUALIFICATION)
    || policy.members[0].qualification.mode !== OBSERVED_BODY_LOCAL_TEST_MODE
    || !exact(policy.members[1].qualification, ['mode'])
    || policy.members[1].qualification.mode !== 'disabled') refuse();
  const signedAuthorityExpiresAt = Math.min(Date.parse(reservation.expires_at),
    Date.parse(assigned.expires_at), Date.parse(p.expires_at));
  const selectedMember = policy.members.find((member) => member.member_id
    === policy.local_test?.selected_member_id);
  if (!selectedMember || selectedMember !== policy.members[0]
    || !validLocalTest(policy.local_test, selectors, selectedMember)
    || !same(selectedMember.qualification, policy.local_test,
      QUALIFICATION.filter((key) => key !== 'mode' && key !== 'response_text_sha256'))
    || !DIGEST.test(selectedMember.qualification.response_text_sha256)) refuse();
  const localTest = Object.freeze(structuredClone(policy.local_test));
  const responseTextSHA256 = selectedMember.qualification.response_text_sha256;
  const expected = Object.freeze({ ...selectors });
  const service = openService({ installation_id: selectors.installation_id,
    start_id: selectors.start_id, hq_epoch: policy.hq_epoch },
  { mode: OBSERVED_BODY_LOCAL_TEST_MODE });
  if (!service || service.port !== stage2aLocalProviderPort({
    installation_id: selectors.installation_id, start_id: selectors.start_id,
    hq_epoch: policy.hq_epoch }) || typeof service.ready?.then !== 'function'
    || typeof service.invoke !== 'function' || typeof service.close !== 'function'
    || typeof service.probeReachability !== 'function'
    || typeof service.invocationReceipt !== 'function') refuse();

  let phase = 'pending';
  let challenge;
  let boundConnection;
  let bindReceiptSHA256;
  let ingressCore;
  let authorizationSHA256;
  let authorizationIssuedAt;
  let authorizationExpiresAt;
  let providerExpiresAt;
  let providerReceipt;
  let prewriteCore;
  let prewriteReceipt;
  let generation = 0;
  const abort = new AbortController();
  const active = (token, required) => {
    if (token !== generation || abort.signal.aborted || phase !== required) refuse();
  };

  const live = async (beforeFirstByte = true) => {
    const current = await observeCurrentStart(expected);
    const observedAt = now();
    if (current?.phase !== 'finalized' || !sameSelectors(current.selectors, expected)
      || current.bind_receipt_sha256 !== bindReceiptSHA256
      || !Number.isSafeInteger(current.expires_at_ms) || current.expires_at_ms <= observedAt
      || (beforeFirstByte && signedAuthorityExpiresAt <= observedAt)
      || !['runner_pid', 'bridge_pid', 'child_pid'].every((key) =>
        Number.isSafeInteger(current[key]) && current[key] > 1)) refuse();
    return current;
  };

  const closeOnFailure = async (error) => {
    if (phase !== 'stopped') {
      phase = 'refused';
      generation++;
      abort.abort();
    }
    try { await service.close(); }
    catch (closeError) { throw new AggregateError([error, closeError],
      'local-test provider failed and could not close'); }
    throw error;
  };

  return Object.freeze({
    ready: service.ready,
    port: service.port,
    probeReachability: () => service.probeReachability(),
    invocationReceipt: () => providerReceipt,
    async challenge(input, connection) {
      if (phase !== 'pending') refuse();
      phase = 'challenge-attempted';
      const token = generation;
      try {
        if (!connection || !sameSelectors(input, expected)) refuse();
        await service.ready;
        active(token, 'challenge-attempted');
        const reply = await machineChallenge({ selectors: expected, connection },
          { signal: abort.signal });
        active(token, 'challenge-attempted');
        if (!exact(reply, ['nonce', 'algorithm', 'context', 'hq_epoch', 'expires_at'])
          || !HEX.test(reply.nonce) || reply.algorithm !== 'hmac-sha256'
          || reply.context !== 'agent-bot-stage2a-observed-body-local-test-bind-v1'
          || reply.hq_epoch !== policy.hq_epoch || !time(reply.expires_at)
          || Date.parse(reply.expires_at) <= now()) refuse();
        challenge = Object.freeze({ connection, reply });
        phase = 'challenged';
        return reply;
      } catch (error) { return closeOnFailure(error); }
    },
    async bind(input, connection) {
      if (phase !== 'challenged' || challenge.connection !== connection) refuse();
      phase = 'bind-attempted';
      const token = generation;
      try {
        if (Date.parse(challenge.reply.expires_at) <= now()
          || !exact(input, ['selectors', 'proof'])
          || !sameSelectors(input.selectors, expected) || !HEX.test(input.proof)) refuse();
        const reply = await machineBind({ selectors: expected, proof: input.proof,
          nonce: challenge.reply.nonce, connection }, { signal: abort.signal });
        active(token, 'bind-attempted');
        if (!exact(reply, ['bind_receipt']) || !HEX.test(reply.bind_receipt)) refuse();
        bindReceiptSHA256 = digest(Buffer.from(reply.bind_receipt));
        boundConnection = connection;
        phase = 'bound';
        return reply;
      } catch (error) { return closeOnFailure(error); }
    },
    async authorize(frame, connection) {
      if (phase !== 'bound' || boundConnection !== connection) refuse();
      phase = 'ingress-attempted';
      const token = generation;
      try {
        if (!exact(frame, ['core', 'ingress_origin_mac'])
          || !HEX.test(frame.ingress_origin_mac)) refuse();
        checkedIngress(frame.core, expected, localTest, bindReceiptSHA256);
        await live();
        active(token, 'ingress-attempted');
        const authorization = await machineIngress({ core: frame.core,
          ingress_origin_mac: frame.ingress_origin_mac }, { signal: abort.signal });
        active(token, 'ingress-attempted');
        const signedAuthorization = checkedAuthorization(authorization,
          machinePublicKey, expected, frame.core, now);
        authorizationSHA256 = authorization.authorization_envelope_sha256;
        await live();
        active(token, 'ingress-attempted');
        const provided = await machineProvider({ selectors: expected,
          authorization_envelope_sha256: authorizationSHA256,
          model: localTest.model, observed_body_sha256: frame.core.observed_body_sha256 },
        { signal: abort.signal });
        active(token, 'ingress-attempted');
        if (!exact(provided, ['mode', 'fixture_config_base64url', 'fixture_config_sha256',
          'authorization_envelope_sha256', 'observed_body_sha256',
          'provider_config_sha256', 'expires_at_ms'])
          || provided.mode !== OBSERVED_BODY_LOCAL_TEST_MODE
          || provided.authorization_envelope_sha256 !== authorizationSHA256
          || provided.observed_body_sha256 !== frame.core.observed_body_sha256
          || provided.fixture_config_sha256 !== localTest.fixture_config_sha256
          || !DIGEST.test(provided.provider_config_sha256)
          || !Number.isSafeInteger(provided.expires_at_ms)
          || provided.expires_at_ms <= now()
          || provided.expires_at_ms > Date.parse(signedAuthorization.expires_at)) refuse();
        const fixture = parseCanonical(decode(provided.fixture_config_base64url));
        if (!exact(fixture, ['schema', 'model', 'response_text'])
          || fixture.schema !== 'stage2a-observed-body-local-test-fixture/v1'
          || fixture.model !== localTest.model
          || typeof fixture.response_text !== 'string' || !fixture.response_text
          || fixture.response_text.length > 4096
          || jcsDigest(fixture) !== provided.fixture_config_sha256
          || digest(Buffer.from(fixture.response_text)) !== responseTextSHA256) refuse();
        const config = { mode: OBSERVED_BODY_LOCAL_TEST_MODE,
          model: fixture.model, observed_body_sha256: frame.core.observed_body_sha256,
          response_text: fixture.response_text };
        if (jcsDigest(config) !== provided.provider_config_sha256) refuse();
        await service.ready;
        active(token, 'ingress-attempted');
        const refreshed = await live();
        active(token, 'ingress-attempted');
        if (provided.expires_at_ms > refreshed.expires_at_ms) refuse();
        // Direct denial probes may have reached the provider-closed listener.
        // Count only the one POST caused by this authenticated invocation.
        const before = await service.probeReachability();
        active(token, 'ingress-attempted');
        await live();
        active(token, 'ingress-attempted');
        if (signedAuthorityExpiresAt <= now() || provided.expires_at_ms <= now()
          || Date.parse(signedAuthorization.expires_at) <= now()) refuse();
        const response = await service.invoke(config, { signal: abort.signal });
        active(token, 'ingress-attempted');
        if (provided.expires_at_ms <= now()
          || Date.parse(signedAuthorization.expires_at) <= now()) refuse();
        await live();
        active(token, 'ingress-attempted');
        const receipt = service.invocationReceipt();
        const observation = await service.probeReachability();
        active(token, 'ingress-attempted');
        const post = { mode: OBSERVED_BODY_LOCAL_TEST_MODE,
          model: localTest.model, observed_body_sha256: frame.core.observed_body_sha256 };
        if (!exact(response, ['mode', 'model', 'observed_body_sha256', 'response_text',
          'invocation', 'response_sha256'])
          || response.mode !== OBSERVED_BODY_LOCAL_TEST_MODE
          || response.model !== localTest.model
          || response.observed_body_sha256 !== frame.core.observed_body_sha256
          || response.response_text !== fixture.response_text
          || response.invocation !== 1
          || response.response_sha256 !== digest(Buffer.from(fixture.response_text))
          || receipt?.mode !== OBSERVED_BODY_LOCAL_TEST_MODE
          || receipt.observed_body_sha256 !== frame.core.observed_body_sha256
          || receipt.provider_config_sha256 !== provided.provider_config_sha256.slice(7)
          || receipt.request_body_sha256 !== jcsDigest(post)
          || receipt.response_body_sha256 !== jcsDigest(response)
          || receipt.response_body_bytes !== Buffer.byteLength(canonicalize(response))
          || observation?.ipv4?.invocations !== 1 || observation?.ipv6?.invocations !== 1
          || observation.ipv4.last_request_sha256 !== frame.core.observed_body_sha256
          || observation.ipv6.last_request_sha256 !== frame.core.observed_body_sha256
          || observation.ipv4.traffic?.ipv4?.provider_posts
            !== before.ipv4.traffic?.ipv4?.provider_posts + 1
          || observation.ipv6.traffic?.ipv6?.provider_posts
            !== before.ipv6.traffic?.ipv6?.provider_posts) refuse();
        ingressCore = Object.freeze(structuredClone(frame.core));
        authorizationIssuedAt = Date.parse(signedAuthorization.issued_at);
        authorizationExpiresAt = Date.parse(signedAuthorization.expires_at);
        providerExpiresAt = provided.expires_at_ms;
        providerReceipt = Object.freeze({ ...receipt,
          authorization_envelope_sha256: authorizationSHA256,
          ingress_core_sha256: jcsDigest(frame.core),
          fixture_config_sha256: provided.fixture_config_sha256,
          observed_body_sha256: frame.core.observed_body_sha256,
          ipv4: observation.ipv4, ipv6: observation.ipv6 });
        phase = 'responded';
        return Object.freeze({
          authorization_envelope_base64url: authorization.authorization_envelope_base64url,
          authorization_envelope_sha256: authorizationSHA256,
          ingress_core_sha256: jcsDigest(frame.core), provider: response,
          provider_request_body_sha256: jcsDigest(post),
          provider_response_body_sha256: jcsDigest(response) });
      } catch (error) { return closeOnFailure(error); }
    },
    async prewrite(value, connection) {
      if (phase !== 'responded' || boundConnection !== connection) refuse();
      phase = 'prewrite-attempted';
      const token = generation;
      try {
        if (authorizationExpiresAt <= now() || providerExpiresAt <= now()
          || !exact(value, PREWRITE)
          || value.schema !== 'stage2a-observed-body-local-test-prewrite/v1'
        || !sameSelectors(value.selectors, expected)
        || !same(value, ingressCore, ['bind_receipt_sha256',
          'observed_body_sha256', 'observed_headers_sha256',
          'static_projection_sha256', 'owner_prompt_sha256', 'peer_sha256'])
        || canonicalize(value.peer) !== canonicalize(ingressCore.peer)
        || value.authorization_envelope_sha256 !== authorizationSHA256
        || value.ingress_core_sha256 !== jcsDigest(ingressCore)
        || !DIGEST.test(value.response_wire_sha256)
          || !Number.isSafeInteger(value.response_wire_bytes) || value.response_wire_bytes < 1
          || value.http_status !== 200) refuse();
        await live();
        active(token, 'prewrite-attempted');
        const reply = await machinePrewrite(value, { signal: abort.signal });
        active(token, 'prewrite-attempted');
        const proof = checkedPrewriteProof(reply, machinePublicKey, expected,
          policy.hq_epoch, value, authorizationIssuedAt, authorizationExpiresAt,
          Date.parse(signedPolicy.payload.expires_at),
          Date.parse(reservation.expires_at), now);
        prewriteCore = Object.freeze(structuredClone(value));
        prewriteReceipt = proof.prewrite_receipt;
        phase = 'prewrite';
        return proof;
      } catch (error) { return closeOnFailure(error); }
    },
    async complete(frame, connection) {
      if (phase !== 'prewrite' || boundConnection !== connection) refuse();
      phase = 'completion-attempted';
      const token = generation;
      try {
        if (!exact(frame, ['core', 'completion_origin_mac'])
          || !HEX.test(frame.completion_origin_mac)
          || !exact(frame.core, [...PREWRITE, 'prewrite_receipt', 'write_started_at',
          'write_completed_at', 'digest_kind'])
        || frame.core.schema !== 'stage2a-observed-body-local-test-completion/v1'
        || frame.core.prewrite_receipt !== prewriteReceipt
        || frame.core.digest_kind !== 'observed-stock-body/v1'
        || !sameSelectors(frame.core.selectors, expected)
        || !same(frame.core, prewriteCore, PREWRITE.filter((key) =>
          !['schema', 'selectors', 'peer'].includes(key)))
          || canonicalize(frame.core.peer) !== canonicalize(prewriteCore.peer)
          || !time(frame.core.write_started_at) || !time(frame.core.write_completed_at)
          || Date.parse(frame.core.write_started_at) > Date.parse(frame.core.write_completed_at)) refuse();
        await live(false);
        active(token, 'completion-attempted');
        const reply = await machineComplete(frame, { signal: abort.signal });
        active(token, 'completion-attempted');
        const completionSHA256 = jcsDigest(frame.core);
        if (!exact(reply, ['accepted', 'completion_core_sha256', 'completed_run_sha256'])
          || reply.accepted !== true
          || reply.completion_core_sha256 !== completionSHA256
          || !DIGEST.test(reply.completed_run_sha256)) refuse();
        phase = 'complete';
        return Object.freeze({ accepted: true, selectors: expected,
          observed_body_sha256: ingressCore.observed_body_sha256,
          authorization_envelope_sha256: authorizationSHA256,
          completion_core_sha256: completionSHA256,
          completed_run_sha256: reply.completed_run_sha256 });
      } catch (error) { return closeOnFailure(error); }
    },
    async stop() {
      if (phase === 'stopped') return;
      phase = 'stopped';
      generation++;
      abort.abort();
      challenge = undefined;
      boundConnection = undefined;
      await service.close();
    },
  });
}
