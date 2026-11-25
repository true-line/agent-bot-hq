import assert from 'node:assert/strict';
import { createHash, createHmac, generateKeyPairSync, sign } from 'node:crypto';
import { request as httpRequest } from 'node:http';
import { test } from 'node:test';
import { canonicalize } from '../sdk/wire/canonical-json.mjs';
import { createStage2aLocalTestProvider } from '../hq/stage2a-local-test-provider.mjs';
import { OBSERVED_BODY_LOCAL_TEST_MODE, openLocalProviderService } from '../hq/stage2a-qualification-provider.mjs';
import { verifyStage2aMachineEnvelope } from '../hq/stage2a-stop.mjs';

const sha = (bytes) => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const jcs = (value) => Buffer.from(canonicalize(value));
const jcsSHA = (value) => sha(jcs(value));
const NOW = Date.parse('2026-11-24T23:00:00Z');
const key = generateKeyPairSync('ed25519');
const pin = key.publicKey.export({ format: 'der', type: 'spki' }).subarray(-32);
const signed = (purpose, payload) => {
  const bytes = jcs(payload);
  return jcs({ schema_version: 1, purpose,
    issuer_public_key_base64url: pin.toString('base64url'),
    payload_sha256: sha(bytes), payload_base64url: bytes.toString('base64url'),
    signature_base64url: sign(null, Buffer.concat([Buffer.from(`${purpose}\0`), bytes]),
      key.privateKey).toString('base64url') });
};
const prewriteProofReply = (prewrite, payloadChanges = {}, purpose =
  'agent-bot/stage2a-observed-body-local-test-prewrite-acceptance/v1') => {
  const prewrite_receipt = '7'.repeat(64);
  const payload = { schema: 'agent-bot-machine/stage2a-observed-body-local-test-prewrite-acceptance/v1',
    kind: 'observed-body-local-test-prewrite-acceptance', schema_version: 1,
    selectors: prewrite.selectors, hq_epoch: '5'.repeat(64),
    authorization_envelope_sha256: prewrite.authorization_envelope_sha256,
    prewrite_core_sha256: jcsSHA(prewrite),
    prewrite_receipt, issued_at: new Date(NOW).toISOString(),
    expires_at: new Date(NOW + 3000).toISOString(), ...payloadChanges };
  const proof = signed(purpose, payload);
  return { prewrite_receipt,
    prewrite_proof_envelope_base64url: proof.toString('base64url'),
    prewrite_proof_envelope_sha256: sha(proof) };
};
const peer = Object.freeze({ uid: 312, pid: 4100, pid_version: 1,
  start_seconds: 1900000000, start_micros: 5, parent_pid: 4000, parent_uid: 312,
  parent_start_seconds: 1900000000, parent_start_micros: 1 });
const receipt = 'd'.repeat(64);
const bindSHA = sha(Buffer.from(receipt));
const secret = Buffer.from('local-test-fd4-source-only-secret-32');
const nonce = 'e'.repeat(64);
const deferred = () => {
  let resolve;
  const promise = new Promise((done) => { resolve = done; });
  return { promise, resolve };
};

function fixture(startDigit = '1', outerLaunchID, mutateAssignment, mutatePolicy) {
  const reservation = signed('agent-bot/stage2a-observed-body-local-test-reservation/v1', {
    contract: 'machine/local-test-v1', kind: 'stage2a-observed-body-local-test-reservation',
    schema_version: 1, host_id: 'host-m2', issued_at: new Date(NOW - 1000).toISOString(),
    expires_at: new Date(NOW + 20_000).toISOString(),
    installed_plan_receipt_sha256: sha('installed'),
    assignment: { schema: 'agent-bot-machine/soul-start-assignment-local-test/v1',
      installation_id: 'install-m2', start_id: `st_${startDigit.repeat(24)}`,
      launch_id: `ln_${'2'.repeat(24)}`, plan_id: 'plan-m2', plan_digest: '3'.repeat(64),
      soul_id: 'agent_fixture', hq_epoch: '5'.repeat(64), runner_uid: 331,
      runner_gid: 331, soul_artifact_sha256: 'a'.repeat(64) },
    member_endpoint: {}, measurement_binding: {},
    admission_challenge_sha256: sha('challenge'),
    start_scope: { mode: 'provider-pending-local-test/v1', one_use_start_claim_name: 'claim-m2' },
  });
  const makeMember = (member_id, role, launch_id) => ({ member_id, role,
    adapter_id: 'claude-code', adapter_version: '0.109.0',
    command_path: '/fixture/claude-agent-acp', command_sha256: sha('acp'),
    adjacent_cli_path: '/fixture/claude', adjacent_cli_sha256: sha('cli'),
    launch_id, member_selector: `mb_${createHash('sha256').update(
      `agent-bot/stage2a-member-selector/v1\0${sha(reservation)}\0${member_id}\0${launch_id}`
    ).digest('hex')}` });
  const members = [makeMember('lead', 'lead', `ln_${'1'.repeat(24)}`),
    makeMember('specialist', 'specialist', `ln_${'2'.repeat(24)}`)];
  const assignmentPayload = {
    contract: 'machine/local-test-v1', kind: 'stage2a-member-set-assignment',
    schema_version: 1, profile_in_force: 'managed-protected', host_id: 'host-m2',
    soul_id: 'agent_fixture', runner_uid: 331, runner_gid: 331,
    soul_artifact_sha256: `sha256:${'a'.repeat(64)}`,
    frozen_soul_info_sha256: sha('soul-info'),
    adapter_manifest_relpath: 'Contents/opt/stock.json',
    frozen_adapter_manifest_sha256: sha('manifest'),
    host_projection_sha256: sha('host-projection'),
    definition_measurement: sha('definition'), bridge: {},
    owner_plan_member_set_sha256: sha('member-set'),
    issued_at: new Date(NOW - 1000).toISOString(),
    expires_at: new Date(NOW + 20_000).toISOString(),
    reservation_sha256: sha(reservation),
    installation_id: 'install-m2', start_id: `st_${startDigit.repeat(24)}`,
    plan_id: 'plan-m2', plan_digest: '3'.repeat(64), hq_epoch: '5'.repeat(64),
    b_authority: { purpose: 'agent-bot/stage2a-observed-body-local-test-reservation/v1',
      envelope_sha256: sha(reservation) }, members: structuredClone(members) };
  mutateAssignment?.(assignmentPayload);
  const memberAssignment = signed('agent-bot/stage2a-member-set-assignment-local-test/v1',
    assignmentPayload);
  const selectorsBase = { installation_id: 'install-m2',
    start_id: `st_${startDigit.repeat(24)}`, launch_id: `ln_${'2'.repeat(24)}`,
    plan_id: 'plan-m2', plan_digest: '3'.repeat(64), reservation_digest: sha(reservation),
    assignment_envelope_sha256: sha(memberAssignment),
    member_selectors_sha256: jcsSHA(members.map((member) => member.member_selector)) };
  const fixed = { schema: 'stage2a-observed-body-local-test-fixture/v1',
    model: 'claude-haiku-4-5-20251001', response_text: 'fixture response' };
  const headerShape = { schema: 'stage2a-observed-body-header-shape/v1',
    host: 'fixture.invalid', required_fixed: {}, required_volatile: {},
    forbidden: [], allow_extra: false };
  const ancillaryProfile = { schema: 'stage2a-stock-ancillary-local-test-profile/v1',
    body_profile: 'stage2a-stock-ancillary-one-block/v1',
    normalized_body_sha256: sha('ancillary-body'),
    first_header_shape: headerShape, first_headers_sha256: sha('ancillary-A'),
    second_header_shape: headerShape, second_headers_sha256: sha('ancillary-B'),
    order: ['first', 'second'], target_after: ['first'],
    max_ancillary: 2, ancillary_http_status: 422 };
  const runnerAccount = '_abm-sr-' + createHash('sha256').update(selectorsBase.installation_id)
    .digest('hex').slice(0, 20);
  const startSlot = createHash('sha256').update(Buffer.from(
    `agent-bot-soul-endpoint-start/v1\0${selectorsBase.installation_id}\0${selectorsBase.start_id}`))
    .digest('hex').slice(0, 20);
  const childRoot = `/var/agent-bot-soul-runner-${runnerAccount}/state/child-${startSlot}`;
  const childCWD = `${childRoot}/work`;
  const childHome = `${childRoot}/home`;
  const emittedCWD = `/private${childCWD}`;
  const localTest = Object.freeze({ selected_member_id: members[0].member_id,
    selected_launch_id: members[0].launch_id, selected_member_selector: members[0].member_selector,
    runner_account: runnerAccount, expected_child_cwd_lexical: childCWD,
    expected_child_cwd_emitted: emittedCWD,
    expected_child_home_lexical: childHome,
    expected_memory_path_lexical: `${childHome}/.claude/projects/${emittedCWD.replace(/[^A-Za-z0-9]/g, '-')}/memory/`,
    body_profile: 'stage2a-stock-observed-local-test/v1',
    static_projection_sha256: sha('projection'), owner_prompt_sha256: sha('prompt'),
    r_first_brief_sha256: sha('brief'), header_shape: headerShape,
    header_shape_sha256: jcsSHA(headerShape), client_key_sha256: sha('key'),
    model: fixed.model, http_host: 'fixture.invalid', messages_query: 'beta=true',
    fixture_config_sha256: jcsSHA(fixed), ancillary_profile: ancillaryProfile,
    ancillary_profile_sha256: jcsSHA(ancillaryProfile) });
  const policyPayload = {
    contract: 'machine/local-test-v1', reservation_sha256: sha(reservation),
    member_set_assignment_envelope_sha256: sha(memberAssignment),
    installation_id: selectorsBase.installation_id, start_id: selectorsBase.start_id,
    plan_id: selectorsBase.plan_id, plan_digest: selectorsBase.plan_digest,
    outer_launch_id: outerLaunchID ?? selectorsBase.launch_id,
    expires_at: new Date(NOW + 20_000).toISOString(),
    hq_epoch: '5'.repeat(64), local_test: localTest,
    members: members.map((member, index) => ({ ...member,
      qualification: index === 0 ? { mode: OBSERVED_BODY_LOCAL_TEST_MODE,
        model: localTest.model, body_profile: localTest.body_profile,
        static_projection_sha256: localTest.static_projection_sha256,
        owner_prompt_sha256: localTest.owner_prompt_sha256,
        r_first_brief_sha256: localTest.r_first_brief_sha256,
        header_shape_sha256: localTest.header_shape_sha256,
        client_key_sha256: localTest.client_key_sha256,
        http_host: localTest.http_host, messages_query: localTest.messages_query,
        response_text_sha256: sha(fixed.response_text) } : { mode: 'disabled' } })) };
  mutatePolicy?.(policyPayload);
  const policy = signed('agent-bot/stage2a-b-member-authority-local-test/v1', policyPayload);
  const selectors = Object.freeze({ ...selectorsBase, authority_envelope_sha256: sha(policy) });
  const core = Object.freeze({ schema: 'stage2a-observed-body-local-test-ingress/v1',
    kind: 'observed-body-local-test-ingress', selectors, bind_receipt_sha256: bindSHA,
    peer, peer_sha256: jcsSHA(peer), observed_body_sha256: sha('stock-body'),
    observed_headers_sha256: sha('headers'),
    static_projection_sha256: localTest.static_projection_sha256,
    observed_brief_sha256: localTest.r_first_brief_sha256,
    owner_prompt_sha256: localTest.owner_prompt_sha256,
    body_profile: localTest.body_profile, digest_kind: 'observed-stock-body/v1',
    target_received_at: new Date(NOW).toISOString(), attempt_id: 'attempt-1' });
  const ingressKey = createHmac('sha256', secret).update(Buffer.concat([
    Buffer.from('agent-bot-stage2a-observed-body-local-test-ingress-subkey-v1\0'),
    Buffer.from(selectors.reservation_digest)])).digest();
  const mac = createHmac('sha256', ingressKey).update(Buffer.concat([
    Buffer.from('agent-bot-stage2a-observed-body-local-test-ingress-origin-v1\0'),
    jcs(core)])).digest('hex');
  const frame = Object.freeze({ core, ingress_origin_mac: mac });
  const authorization = signed('agent-bot/stage2a-observed-body-local-test-ingress-authorization/v1', {
    schema: 'agent-bot-machine/stage2a-observed-body-local-test-ingress-authorization/v1',
    kind: 'observed-body-local-test-ingress-authorization', selectors,
    ingress_core_sha256: jcsSHA(core), provider_claim_sha256: sha('spent-claim'),
    issued_at: new Date(NOW).toISOString(), expires_at: new Date(NOW + 5000).toISOString() });
  const providerConfig = { mode: OBSERVED_BODY_LOCAL_TEST_MODE, model: fixed.model,
    observed_body_sha256: core.observed_body_sha256, response_text: fixed.response_text };
  const counts = { ingress: 0, provider: 0, prewrite: 0, complete: 0 };
  const options = { reservationEnvelope: reservation, memberAssignmentEnvelope: memberAssignment,
    selectors, policyEnvelope: policy,
    machinePublicKey: pin, now: () => NOW,
    validateReservation: (payload) => payload.assignment.schema
      === 'agent-bot-machine/soul-start-assignment-local-test/v1',
    validateMemberAssignment: (payload) => payload.bridge !== null,
    verifyPolicy: (bytes) => {
      const payload = verifyStage2aMachineEnvelope(bytes, pin,
        'agent-bot/stage2a-b-member-authority-local-test/v1', { maxBytes: 65_536 }).payload;
      return { selectors, hq_epoch: payload.hq_epoch,
        local_test: payload.local_test, members: payload.members };
    },
    machineChallenge: async () => ({ nonce, algorithm: 'hmac-sha256',
      context: 'agent-bot-stage2a-observed-body-local-test-bind-v1',
      hq_epoch: '5'.repeat(64), expires_at: new Date(NOW + 5000).toISOString() }),
    machineBind: async ({ proof }) => {
      if (proof !== '6'.repeat(64)) throw new Error('Machine refused bind proof');
      return { bind_receipt: receipt };
    },
    observeCurrentStart: async () => ({ phase: 'finalized', selectors,
      bind_receipt_sha256: bindSHA, expires_at_ms: NOW + 5000,
      runner_pid: 4000, bridge_pid: 4200, child_pid: 4100 }),
    machineIngress: async (received) => {
      counts.ingress++;
      if (received.ingress_origin_mac !== mac
        || jcsSHA(received.core) !== jcsSHA(core)) throw new Error('Machine refused B-origin MAC');
      return { authorization_envelope_base64url: authorization.toString('base64url'),
        authorization_envelope_sha256: sha(authorization) };
    },
    machineProvider: async (request) => {
      counts.provider++;
      assert.equal(request.authorization_envelope_sha256, sha(authorization));
      assert.equal(request.observed_body_sha256, core.observed_body_sha256);
      return { mode: OBSERVED_BODY_LOCAL_TEST_MODE,
        fixture_config_base64url: jcs(fixed).toString('base64url'),
        fixture_config_sha256: jcsSHA(fixed),
        authorization_envelope_sha256: sha(authorization),
        observed_body_sha256: core.observed_body_sha256,
        provider_config_sha256: jcsSHA(providerConfig), expires_at_ms: NOW + 4000 };
    },
    machinePrewrite: async (prewrite) => { counts.prewrite++;
      return prewriteProofReply(prewrite); },
    machineComplete: async (frame) => { counts.complete++; return { accepted: true,
      completion_core_sha256: jcsSHA(frame.core), completed_run_sha256: sha('completed-run') }; },
  };
  return { options, selectors, localTest, core, frame, counts, fixed };
}

async function post(host, port, body) {
  const bytes = jcs(body);
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host, port, method: 'POST', path: '/stage2a/local-provider/v1',
      agent: false, headers: { 'content-type': 'application/json',
        'content-length': String(bytes.length), connection: 'close' } }, (res) => {
      res.resume(); res.on('end', () => resolve(res.statusCode));
    });
    req.on('error', reject); req.end(bytes);
  });
}

async function bound(value, connection) {
  const provider = createStage2aLocalTestProvider(value.options);
  await provider.ready;
  await provider.challenge(value.selectors, connection);
  await provider.bind({ selectors: value.selectors, proof: '6'.repeat(64) }, connection);
  return provider;
}

function prewriteFor(value, receiptValue) {
  return { schema: 'stage2a-observed-body-local-test-prewrite/v1',
    selectors: value.selectors, bind_receipt_sha256: bindSHA,
    authorization_envelope_sha256: receiptValue.authorization_envelope_sha256,
    ingress_core_sha256: jcsSHA(value.core),
    observed_body_sha256: value.core.observed_body_sha256,
    observed_headers_sha256: value.core.observed_headers_sha256,
    static_projection_sha256: value.core.static_projection_sha256,
    owner_prompt_sha256: value.core.owner_prompt_sha256, peer,
    peer_sha256: value.core.peer_sha256, response_wire_sha256: sha('wire'),
    response_wire_bytes: 64, http_status: 200 };
}

function completionFor(prewrite, prewriteReceipt) {
  return { ...prewrite, schema: 'stage2a-observed-body-local-test-completion/v1',
    prewrite_receipt: prewriteReceipt,
    write_started_at: new Date(NOW + 1).toISOString(),
    write_completed_at: new Date(NOW + 2).toISOString(),
    digest_kind: 'observed-stock-body/v1' };
}

test('same dual-loopback listener denies direct traffic, then accepts one A-authorized POST', async () => {
  const value = fixture();
  const connection = {};
  const provider = await bound(value, connection);
  try {
    const body = { mode: OBSERVED_BODY_LOCAL_TEST_MODE,
      model: value.fixed.model, observed_body_sha256: value.core.observed_body_sha256 };
    assert.equal(await post('127.0.0.1', provider.port, body), 403);
    assert.equal(await post('::1', provider.port, body), 403);
    assert.equal(value.counts.provider, 0);
    const response = await provider.authorize(value.frame, connection);
    assert.equal(response.provider.response_text, 'fixture response');
    assert.equal(response.authorization_envelope_sha256,
      sha(Buffer.from(response.authorization_envelope_base64url, 'base64url')));
    assert.equal(response.ingress_core_sha256, jcsSHA(value.core));
    assert.equal(response.provider_request_body_sha256,
      jcsSHA({ mode: OBSERVED_BODY_LOCAL_TEST_MODE, model: value.fixed.model,
        observed_body_sha256: value.core.observed_body_sha256 }));
    assert.equal(response.provider_response_body_sha256, jcsSHA(response.provider));
    assert.equal(value.counts.ingress, 1);
    assert.equal(value.counts.provider, 1);
    const receiptValue = provider.invocationReceipt();
    assert.equal(receiptValue.request_body_sha256, jcsSHA(body));
    assert.equal(receiptValue.observed_body_sha256, value.core.observed_body_sha256);
    assert.equal(receiptValue.ipv4.traffic.ipv4.provider_posts, 2);
    assert.equal(receiptValue.ipv6.traffic.ipv6.provider_posts, 1);
    const prewrite = prewriteFor(value, receiptValue);
    const prewriteReply = await provider.prewrite(prewrite, connection);
    const prewriteProof = Buffer.from(prewriteReply.prewrite_proof_envelope_base64url, 'base64url');
    assert.equal(prewriteReply.prewrite_proof_envelope_sha256, sha(prewriteProof));
    const accepted = verifyStage2aMachineEnvelope(prewriteProof, pin,
      'agent-bot/stage2a-observed-body-local-test-prewrite-acceptance/v1').payload;
    assert.equal(accepted.prewrite_core_sha256, jcsSHA(prewrite));
    assert.equal(accepted.prewrite_receipt, prewriteReply.prewrite_receipt);
    const completion = completionFor(prewrite, prewriteReply.prewrite_receipt);
    const completionAck = await provider.complete({ core: completion,
      completion_origin_mac: '8'.repeat(64) }, connection);
    assert.equal(completionAck.accepted, true);
    assert.deepEqual(completionAck.selectors, value.selectors);
    assert.equal(completionAck.completion_core_sha256, jcsSHA(completion));
    assert.equal(completionAck.completed_run_sha256, sha('completed-run'));
    assert.deepEqual([value.counts.prewrite, value.counts.complete], [1, 1]);
    await assert.rejects(provider.authorize(value.frame, connection), /unavailable/);
  } finally { await provider.stop(); }
  await assert.rejects(post('127.0.0.1', provider.port, {
    mode: OBSERVED_BODY_LOCAL_TEST_MODE, model: value.fixed.model,
    observed_body_sha256: value.core.observed_body_sha256 }));
});

test('forged or stale Machine prewrite proof is refused before any completion', async () => {
  const cases = [
    (prewrite) => prewriteProofReply(prewrite, {},
      'agent-bot/stage2a-observed-body-local-test-prewrite/v1'),
    (prewrite) => prewriteProofReply(prewrite, { prewrite_core_sha256: sha('wrong core') }),
    (prewrite) => prewriteProofReply({ ...prewrite,
      response_wire_sha256: sha('wrong wire') }),
    (prewrite) => prewriteProofReply({ ...prewrite,
      observed_body_sha256: sha('wrong body') }),
    (prewrite) => prewriteProofReply(prewrite, { hq_epoch: '8'.repeat(64) }),
    (prewrite) => prewriteProofReply(prewrite,
      { authorization_envelope_sha256: sha('wrong authorization') }),
    (prewrite) => prewriteProofReply(prewrite,
      { selectors: { ...prewrite.selectors, launch_id: `ln_${'f'.repeat(24)}` } }),
    (prewrite) => prewriteProofReply(prewrite, { prewrite_receipt: '8'.repeat(64) }),
    (prewrite) => prewriteProofReply(prewrite,
      { expires_at: new Date(NOW).toISOString() }),
    (prewrite) => prewriteProofReply(prewrite,
      { expires_at: new Date(NOW + 6000).toISOString() }),
    (prewrite) => prewriteProofReply(prewrite,
      { issued_at: new Date(NOW - 1000).toISOString() }),
    (prewrite) => ({ ...prewriteProofReply(prewrite),
      prewrite_proof_envelope_sha256: sha('forged envelope') }),
  ];
  for (const replyFor of cases) {
    const value = fixture('6');
    const connection = {};
    value.options.machinePrewrite = async (prewrite) => replyFor(prewrite);
    const provider = await bound(value, connection);
    try {
      await provider.authorize(value.frame, connection);
      const prewrite = prewriteFor(value, provider.invocationReceipt());
      await assert.rejects(provider.prewrite(prewrite, connection));
      assert.equal(value.counts.complete, 0);
      await assert.rejects(provider.complete({}, connection), /unavailable/);
    } finally { await provider.stop(); }
  }
});

test('Machine proof cannot outlive the signed B policy', async () => {
  const value = fixture('5', undefined, undefined,
    (payload) => { payload.expires_at = new Date(NOW + 2000).toISOString(); });
  const connection = {};
  const provider = await bound(value, connection);
  try {
    await provider.authorize(value.frame, connection);
    await assert.rejects(provider.prewrite(
      prewriteFor(value, provider.invocationReceipt()), connection));
    await assert.rejects(provider.complete({}, connection), /unavailable/);
  } finally { await provider.stop(); }
});

test('forged HQ digest cannot reach Machine Provider or invoke the local service', async () => {
  const value = fixture('a');
  const connection = {};
  const provider = await bound(value, connection);
  const forged = { core: { ...value.core, observed_body_sha256: sha('forged') },
    ingress_origin_mac: receipt };
  await assert.rejects(provider.authorize(forged, connection), /Machine refused B-origin MAC/);
  assert.equal(value.counts.provider, 0);
  assert.equal(provider.invocationReceipt(), undefined);
  await assert.rejects(provider.probeReachability());
  await provider.stop();
  await assert.rejects(provider.challenge(value.selectors, connection), /unavailable/);
});

test('wrong A authorization signature stops before Provider RPC or local POST', async () => {
  const value = fixture('9');
  value.options.machineIngress = async () => {
    value.counts.ingress++;
    const forged = signed('agent-bot/stage2a-qualification-candidate/v3',
      { schema: 'old-mode' });
    return { authorization_envelope_base64url: forged.toString('base64url'),
      authorization_envelope_sha256: sha(forged) };
  };
  const connection = {};
  const provider = await bound(value, connection);
  await assert.rejects(provider.authorize(value.frame, connection));
  assert.equal(value.counts.ingress, 1);
  assert.equal(value.counts.provider, 0);
  assert.equal(provider.invocationReceipt(), undefined);
  await assert.rejects(provider.probeReachability());
  await provider.stop();
});

test('invalid postresponse prewrite spends the attempt and bars completion', async () => {
  const value = fixture('8');
  const connection = {};
  const provider = await bound(value, connection);
  try {
    await provider.authorize(value.frame, connection);
    await assert.rejects(provider.prewrite({ schema: 'old-prewrite' }, connection), /unavailable/);
    assert.equal(value.counts.prewrite, 0);
    await assert.rejects(provider.prewrite({ schema: 'old-prewrite' }, connection), /unavailable/);
    await assert.rejects(provider.complete({ core: {}, completion_origin_mac: '8'.repeat(64) },
      connection), /unavailable/);
    assert.equal(value.counts.complete, 0);
    await assert.rejects(provider.probeReachability());
  } finally { await provider.stop(); }
});

test('stop during Machine challenge or bind never revives the listener', async () => {
  for (const stage of ['challenge', 'bind']) {
    const value = fixture(stage === 'challenge' ? '7' : '6');
    const entered = deferred();
    const release = deferred();
    const method = stage === 'challenge' ? 'machineChallenge' : 'machineBind';
    const original = value.options[method];
    value.options[method] = async (...args) => {
      entered.resolve();
      await release.promise;
      return original(...args);
    };
    const connection = {};
    const provider = createStage2aLocalTestProvider(value.options);
    await provider.ready;
    if (stage === 'bind') await provider.challenge(value.selectors, connection);
    const pending = stage === 'challenge'
      ? provider.challenge(value.selectors, connection)
      : provider.bind({ selectors: value.selectors, proof: '6'.repeat(64) }, connection);
    await entered.promise;
    await provider.stop();
    release.resolve();
    await assert.rejects(pending, /unavailable/);
    assert.equal(value.counts.provider, 0);
    await assert.rejects(provider.probeReachability());
  }
});

test('uncertain Machine challenge closes a still provider-closed listener', async () => {
  const value = fixture('f');
  value.options.machineChallenge = async () => { throw new Error('Machine unavailable'); };
  const provider = createStage2aLocalTestProvider(value.options);
  await provider.ready;
  await assert.rejects(provider.challenge(value.selectors, {}), /Machine unavailable/);
  await assert.rejects(provider.probeReachability());
  assert.equal(value.counts.provider, 0);
  await provider.stop();
});

test('stop during Machine ingress prevents every later Provider RPC and POST', async () => {
  const value = fixture('5');
  const entered = deferred();
  const release = deferred();
  const original = value.options.machineIngress;
  value.options.machineIngress = async (...args) => {
    entered.resolve();
    await release.promise;
    return original(...args);
  };
  const connection = {};
  const provider = await bound(value, connection);
  const pending = provider.authorize(value.frame, connection);
  await entered.promise;
  await provider.stop();
  release.resolve();
  await assert.rejects(pending, /unavailable/);
  assert.equal(value.counts.provider, 0);
  assert.equal(value.counts.prewrite, 0);
  assert.equal(value.counts.complete, 0);
  assert.equal(provider.invocationReceipt(), undefined);
});

test('stop during an already started Provider RPC prevents the later HTTP POST', async () => {
  const value = fixture('4');
  const entered = deferred();
  const release = deferred();
  const original = value.options.machineProvider;
  value.options.machineProvider = async (...args) => {
    const reply = await original(...args);
    entered.resolve();
    await release.promise;
    return reply;
  };
  const connection = {};
  const provider = await bound(value, connection);
  const pending = provider.authorize(value.frame, connection);
  await entered.promise;
  assert.equal(value.counts.provider, 1);
  await provider.stop();
  release.resolve();
  await assert.rejects(pending, /unavailable/);
  assert.equal(provider.invocationReceipt(), undefined);
  assert.equal(value.counts.prewrite, 0);
  assert.equal(value.counts.complete, 0);
});

test('stop after HTTP POST finishes prevents late HQ acceptance and later B stages', async () => {
  const value = fixture('c');
  const entered = deferred();
  const release = deferred();
  value.options.openService = (plan, opts) => {
    const real = openLocalProviderService(plan, opts);
    return { ...real, invoke: async (...args) => {
      const response = await real.invoke(...args);
      entered.resolve();
      await release.promise;
      return response;
    } };
  };
  const connection = {};
  const provider = await bound(value, connection);
  const pending = provider.authorize(value.frame, connection);
  await entered.promise; // request.end and the HTTP response have both occurred.
  await provider.stop();
  release.resolve();
  await assert.rejects(pending, /unavailable/);
  assert.equal(provider.invocationReceipt(), undefined);
  await assert.rejects(provider.prewrite({}, connection), /unavailable/);
  await assert.rejects(provider.complete({}, connection), /unavailable/);
  assert.equal(value.counts.prewrite, 0);
  assert.equal(value.counts.complete, 0);
});

test('stop during deferred prewrite or completion prevents late acknowledgement', async () => {
  for (const stage of ['prewrite', 'completion']) {
    const value = fixture(stage === 'prewrite' ? 'd' : 'e');
    const entered = deferred();
    const release = deferred();
    const method = stage === 'prewrite' ? 'machinePrewrite' : 'machineComplete';
    const original = value.options[method];
    value.options[method] = async (...args) => {
      entered.resolve();
      await release.promise;
      return original(...args);
    };
    const connection = {};
    const provider = await bound(value, connection);
    await provider.authorize(value.frame, connection);
    const prewrite = prewriteFor(value, provider.invocationReceipt());
    let pending;
    if (stage === 'prewrite') pending = provider.prewrite(prewrite, connection);
    else {
      const receiptValue = await provider.prewrite(prewrite, connection);
      pending = provider.complete({ core: completionFor(prewrite,
        receiptValue.prewrite_receipt), completion_origin_mac: '8'.repeat(64) }, connection);
    }
    await entered.promise;
    await provider.stop();
    release.resolve();
    await assert.rejects(pending, /unavailable/);
    await assert.rejects(provider.complete({}, connection), /unavailable/);
    assert.equal(value.counts.complete, stage === 'completion' ? 1 : 0);
  }
});

test('Provider expiry during a deferred reachability probe causes zero HTTP POSTs', async () => {
  const value = fixture('3');
  let clock = NOW;
  let posts = 0;
  const entered = deferred();
  const release = deferred();
  value.options.now = () => clock;
  value.options.observeCurrentStart = async () => ({ phase: 'finalized',
    selectors: value.selectors, bind_receipt_sha256: bindSHA,
    expires_at_ms: NOW + 10_000, runner_pid: 4000, bridge_pid: 4200, child_pid: 4100 });
  value.options.openService = (plan, opts) => {
    const real = openLocalProviderService(plan, opts);
    return { ...real,
      probeReachability: async () => {
        entered.resolve();
        await release.promise;
        return real.probeReachability();
      },
      invoke: (...args) => { posts++; return real.invoke(...args); } };
  };
  const connection = {};
  const provider = await bound(value, connection);
  const pending = provider.authorize(value.frame, connection);
  await entered.promise;
  clock = NOW + 4500;
  release.resolve();
  await assert.rejects(pending, /unavailable/);
  assert.equal(posts, 0);
  assert.equal(provider.invocationReceipt(), undefined);
  await assert.rejects(provider.probeReachability());
});

test('expired, future and overlong signed reservations never open a listener', () => {
  const value = fixture('e');
  const original = verifyStage2aMachineEnvelope(value.options.reservationEnvelope,
    pin, 'agent-bot/stage2a-observed-body-local-test-reservation/v1').payload;
  for (const times of [
    { issued_at: new Date(NOW - 31_000).toISOString(),
      expires_at: new Date(NOW - 1).toISOString() },
    { issued_at: new Date(NOW + 1).toISOString(),
      expires_at: new Date(NOW + 5000).toISOString() },
    { issued_at: new Date(NOW - 1000).toISOString(),
      expires_at: new Date(NOW + 30_001).toISOString() },
  ]) {
    let opened = 0;
    const reservationEnvelope = signed(
      'agent-bot/stage2a-observed-body-local-test-reservation/v1',
      { ...original, ...times });
    const selectors = { ...value.selectors, reservation_digest: sha(reservationEnvelope) };
    assert.throws(() => createStage2aLocalTestProvider({ ...value.options,
      reservationEnvelope, selectors,
      openService: () => { opened++; throw new Error('should not open'); } }), /unavailable/);
    assert.equal(opened, 0);
  }
});

test('wrong reservation purpose and old selectors fail before opening a service', async () => {
  const value = fixture('b');
  const wrong = { ...value.options,
    reservationEnvelope: signed('agent-bot/stage2a-reservation/v3',
      { schema: 'old' }) };
  assert.throws(() => createStage2aLocalTestProvider(wrong));
  const provider = createStage2aLocalTestProvider(value.options);
  const connection = {};
  try {
    await provider.ready;
    await assert.rejects(provider.challenge(fixture('c').selectors, connection), /unavailable/);
  } finally { await provider.stop(); }
  const restarted = fixture('c');
  const next = createStage2aLocalTestProvider(restarted.options);
  try {
    await next.ready;
    await assert.rejects(next.challenge(value.selectors, connection), /unavailable/);
  } finally { await next.stop(); }
});

test('signed B policy with a different outer launch fails before opening a listener', () => {
  const value = fixture('d', `ln_${'f'.repeat(24)}`);
  let opened = 0;
  assert.throws(() => createStage2aLocalTestProvider({ ...value.options,
    openService: () => { opened++; throw new Error('should not open'); } }),
  /unavailable/);
  assert.equal(opened, 0);
});

test('signed stable child paths refuse before opening a listener', () => {
  const value = fixture('a', undefined, undefined, (payload) => {
    const root = `/var/agent-bot-soul-runner-${payload.local_test.runner_account}`;
    const cwd = `${root}/work`;
    const home = `${root}/home`;
    payload.local_test = { ...payload.local_test,
      expected_child_cwd_lexical: cwd,
      expected_child_cwd_emitted: `/private${cwd}`,
      expected_child_home_lexical: home,
      expected_memory_path_lexical: `${home}/.claude/projects/${(`/private${cwd}`).replace(/[^A-Za-z0-9]/g, '-')}/memory/` };
  });
  let opened = 0;
  assert.throws(() => createStage2aLocalTestProvider({ ...value.options,
    openService: () => { opened++; throw new Error('should not open'); } }), /unavailable/);
  assert.equal(opened, 0);
});

test('signed inconsistent member qualifications and pins fail before opening a listener', () => {
  for (const mutatePolicy of [
    (payload) => {
      payload.members[0].qualification = { mode: 'disabled' };
      payload.members[1].qualification = { mode: OBSERVED_BODY_LOCAL_TEST_MODE };
    },
    (payload) => { payload.members[0].qualification.static_projection_sha256 = sha('wrong'); },
    (payload) => { payload.members[1].qualification.extra = true; },
    (payload) => { payload.local_test = { ...payload.local_test,
      expected_child_cwd_lexical: payload.local_test.expected_child_cwd_lexical
        .replace(/child-[0-9a-f]{20}/, 'child-short') }; },
    (payload) => { payload.local_test = { ...payload.local_test,
      expected_child_home_lexical: payload.local_test.expected_child_home_lexical
        .replace('/home', '/other') }; },
    (payload) => { payload.local_test = { ...payload.local_test,
      expected_memory_path_lexical: payload.local_test.expected_memory_path_lexical
        .replace('runner--abm', 'runner-_abm') }; },
    (payload) => { const ancillaryProfile = { ...payload.local_test.ancillary_profile,
      target_after: ['first', 'second'] };
    payload.local_test = { ...payload.local_test,
      ancillary_profile: ancillaryProfile, ancillary_profile_sha256: jcsSHA(ancillaryProfile) }; },
    (payload) => { payload.expires_at = 'not-a-time'; },
    (payload) => { payload.expires_at = new Date(NOW - 1).toISOString(); },
  ]) {
    const value = fixture('9', undefined, undefined, mutatePolicy);
    let opened = 0;
    assert.throws(() => createStage2aLocalTestProvider({ ...value.options,
      openService: () => { opened++; throw new Error('should not open'); } }),
    /unavailable/);
    assert.equal(opened, 0);
  }
});

test('signed assignment with wrong kind or member shape fails before opening a listener', () => {
  for (const mutateAssignment of [
    (payload) => { payload.kind = 'stage2a-member-set-assignment-v3'; },
    (payload) => { delete payload.members[0].role; },
    (payload) => { payload.members[1].extra = true; },
  ]) {
    const value = fixture('8', undefined, mutateAssignment);
    let opened = 0;
    assert.throws(() => createStage2aLocalTestProvider({ ...value.options,
      openService: () => { opened++; throw new Error('should not open'); } }),
    /unavailable/);
    assert.equal(opened, 0);
  }
});

test('signed response text pin is checked before the local Provider POST', async () => {
  const value = fixture('7', undefined, undefined,
    (payload) => { payload.members[0].qualification.response_text_sha256 = sha('wrong'); });
  const connection = {};
  const provider = await bound(value, connection);
  try {
    await assert.rejects(provider.authorize(value.frame, connection), /unavailable/);
    assert.equal(provider.invocationReceipt(), undefined);
  } finally { await provider.stop(); }
});
