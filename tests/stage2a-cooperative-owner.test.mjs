import assert from 'node:assert/strict';
import { generateKeyPairSync, randomBytes, sign } from 'node:crypto';
import test from 'node:test';
import { canonicalBytes } from '../sdk/wire/canonical-json.mjs';
import { createStage2aCooperativeMachine } from '../hq/stage2a-cooperative-machine.mjs';
import { digest } from '../hq/stage2a-cooperative-proof.mjs';

test('paired cooperative proof binds reservation, projection, R identity, provider and cutoff', async () => {
  const now = 1785000000000;
  const date = (offset) => new Date(now + offset).toISOString();
  const { publicKey, privateKey } = generateKeyPairSync('ed25519');
  const machineKey = publicKey.export({ type: 'spki', format: 'der' }).subarray(-32);
  const sha = (c) => c.repeat(64);
  const full = (c) => `sha256:${sha(c)}`;
  const installation = { source_package_path: '/owner/soul', host_id: 'host', installation_id: 'install',
    plan_id: 'plan', plan_digest: sha('1'), hq_epoch: sha('2'), hq_installation_id: 'hq-installation',
    h_owner_plan_digest: sha('0'), runner_uid: 550, runner_gid: 550,
    admission_directory: '/c/soul', broker_socket_path: '/broker/soul.sock' };
  const config = { model: 'local', request_sha256: full('7'), response_text: 'approved response' };
  const configBytes = canonicalBytes(config);
  const qualification = { config_sha256: digest(configBytes), config_base64url: configBytes.toString('base64url') };
  const createProof = (kind, body) => {
    const name = kind.startsWith('stage2a-direct-q-') ? kind : `soul-cooperative-${kind}`;
    const purpose = `agent-bot/${name}/v3`;
    const payload = canonicalBytes({ contract: 'machine/v3', kind: name, schema_version: 3, ...body });
    const raw = canonicalBytes({ purpose, schema_version: 3, issuer_public_key_base64url: machineKey.toString('base64url'),
      payload_base64url: payload.toString('base64url'), payload_sha256: digest(payload),
      signature_base64url: sign(null, Buffer.concat([Buffer.from(purpose + '\0'), payload]), privateKey).toString('base64url') });
    return { envelope_base64url: raw.toString('base64url'), sha256: digest(raw) };
  };
  let ids, identity, attachment, reserveRequest, reserveResult, directPre, directCapture, witnessChallenge;
  const witnessNonce = Buffer.alloc(32, 7).toString('base64url');
  let lostReserve = false, expiredResult = false, badResult = false;
  let reserveCalls = 0, resultCalls = 0, projectionCalls = 0;
  let missingDirectAdapter = true;
  let reviewedId, badLookupPath = false;
  const admissionSocket = startId => `${installation.admission_directory}/${digest(
    `agent-bot-soul-endpoint-start/v1\0${installation.installation_id}\0${startId}`).slice(7, 27)}.sock`;
  let badProjection = true;
  let badCutoff = true;
  let malformedProvider = true;
  let watchCalls = 0;
  const machine = createStage2aCooperativeMachine({ now: () => now, hDescriptorDigest: full('b'),
    machinePublicKey: machineKey.toString('hex'),
    exchange: async (verb, request) => {
      let body;
      switch (verb) {
        case 'stage2a-cooperative-lookup-v3':
          body = { ...installation, reviewed_start_id: reviewedId,
            admission_socket_path: badLookupPath ? '/other.sock' : admissionSocket(reviewedId),
            ...(missingDirectAdapter ? {} : { adapter_transport: 'direct-comms' }) };
          break;
        case 'stage2a-cooperative-live-v3':
          watchCalls++;
          body = createProof('live', { ...identity, attach_sha256: attachment.sha256, hq_epoch: request.hq_epoch,
            runner_pid: 101, observed_at: date(0), expires_at: date(5000) });
          break;
        case 'stage2a-cooperative-reserve-v3': {
          reserveCalls++;
          reserveRequest = request;
          const { installation_id, start_id, launch_id, hq_epoch, plan_digest } = request;
          const expires = expiredResult ? date(0) : date(25000);
          ids = { installation_id, start_id, launch_id };
          const a = { ...ids, plan_id: 'plan', hq_epoch, plan_digest, package_root: '/installed/soul',
            expires_at: expires, package_sha256: sha('3'), soul_artifact_sha256: sha('4'),
            soul_id: 'agent_01234567-89ab-cdef-0123-456789abcdef', runner_uid: 550, runner_gid: 550,
            hq_uid: process.getuid(), machine_uid: 551 };
          body = createProof('reservation', { adapter_transport: 'direct-comms', host_id: request.host_id, issued_at: date(-1000),
            expires_at: expires, installed_plan_receipt_sha256: full('9'),
            assignment: a, endpoints: { admission: { directory: installation.admission_directory,
              socket_path: admissionSocket(start_id) },
              broker: { socket_path: installation.broker_socket_path } }, admission_challenge_sha256: badResult ? full('0') : request.admission_challenge_sha256,
            measurement_binding: { ...a, installed_plan_digest: plan_digest, contract: 'machine/v3',
              kind: 'stage2a-measurement-binding', schema_version: 3, host_id: request.host_id,
              profile_in_force: 'managed-cooperative', launch_input_measurement: full('a'),
              h_service_descriptor_digest: full('b'), claimed_definition_digest: full('c') },
            qualification_provider: qualification });
          identity = { ...ids, reservation_sha256: body.sha256, h_service_descriptor_digest: full('b') };
          reserveResult = body;
          if (lostReserve) throw new Error('response lost after publication');
          break;
        }
        case 'stage2a-cooperative-reserve-result-v3':
          resultCalls++;
          assert.deepEqual(request, reserveRequest);
          body = reserveResult;
          break;
        case 'stage2a-cooperative-q-begin-v3':
          assert.equal(request.attach_sha256, attachment.sha256);
          body = directPre;
          break;
        case 'stage2a-cooperative-q-witness-begin-v3':
          assert.equal(request.pre_response_sha256, directPre.sha256);
          body = witnessChallenge;
          break;
        case 'stage2a-cooperative-q-witness-finish-v3':
          assert.equal(request.challenge_base64url, witnessNonce);
          assert.equal(request.cooperative_start_receipt_sha256, full('a'));
          assert.equal(request.hq_refusal_receipt_sha256, full('b'));
          body = { witness_sha256: full('c') };
          break;
        case 'stage2a-cooperative-q-finish-v3':
          assert.equal(request.pre_response_sha256, directPre.sha256);
          assert.equal(request.witness_sha256, full('c'));
          assert.ok(!Object.hasOwn(request, 'hq_refusal_receipt_base64url'));
          body = directCapture;
          break;
        case 'stage2a-cooperative-launch-inputs-v3':
          projectionCalls++;
          body = createProof('launch-projection', { ...identity, launch_input_measurement: full(badProjection ? 'd' : 'a'),
            selected_command: '/sealed/bin/node', argv: ['/sealed/bin/node'], environment: {}, effective_config: {},
            component_digests: {}, host_projection: { adapters: {}, installation: {} } });
          break;
        case 'stage2a-cooperative-attach-v3':
          body = attachment = createProof('attach', { ...identity, runner_uid: 550, runner_pid: request.runner_pid,
            dispatcher_pid: 100, challenge_sha256: digest(Buffer.from(request.admission_challenge_base64url, 'base64url')),
            runner_start_sec: 123, runner_start_usec: 45, attached_at: date(0) });
          break;
        case 'stage2a-cooperative-provider-v3': {
          assert.equal(request.attach_sha256, attachment.sha256);
          const proof = createProof('provider', { ...identity, attach_sha256: attachment.sha256,
            plan_id: request.plan_id, plan_digest: request.plan_digest, hq_epoch: request.hq_epoch, runner_pid: 101,
            model: config.model, request_sha256: config.request_sha256,
            response_sha256: digest(Buffer.from(config.response_text)), provider_config_sha256: qualification.config_sha256,
            issued_at: date(-500), expires_at: date(14500) });
          body = { ...config, provider_config_sha256: qualification.config_sha256,
            config_base64url: qualification.config_base64url, expires_at_ms: now + 14500,
            receipt_envelope_base64url: proof.envelope_base64url, receipt_sha256: proof.sha256 };
          if (malformedProvider) body.response_text += ' changed';
          break;
        }
        case 'stage2a-cooperative-abort-v3':
          body = createProof('abort', { ...request, ...identity, runner_uid: 550, runner_uid_idle: true,
            cancel_sha256: full('5'), aborted_at: date(0) });
          break;
        case 'stage2a-cooperative-stop-v3':
          body = createProof('stop', { ...request, ...identity, attach_sha256: badCutoff ? full('f') : attachment.sha256,
            runner_uid: 550, runner_pid: 101, dispatcher_pid: 100, runner_uid_idle: true,
            cancel_sha256: full('5'), dispatch_completion_sha256: full('6'), stopped_at: date(0) });
          break;
        default: assert.fail(verb);
      }
      return { body, machineKey };
    },
  });
  await assert.rejects(machine.lookup('/owner/soul'), { code: 'profile_insufficient' });
  missingDirectAdapter = false;
  await assert.rejects(machine.lookup('/owner/soul'), /mismatched/);
  const reviewedPlan = async digit => {
    reviewedId = `st_${digit.repeat(24)}`;
    return machine.lookup('/owner/soul');
  };
  badLookupPath = true;
  await assert.rejects(reviewedPlan('a'), /mismatched/);
  badLookupPath = false;
  const plan = await reviewedPlan('a');
  const challenge = randomBytes(32);
  const start = { startId: `st_${'a'.repeat(24)}`, launchId: `ln_${'b'.repeat(24)}`, challenge };
  await assert.rejects(machine.reserve(plan, { ...start, startId: `st_${'f'.repeat(24)}` }), /mismatched/);
  assert.equal(reserveCalls, 0);
  const reserved = await machine.reserve(plan, start);
  assert.equal(machine.verifyReservation(reserved), reserved);
  await assert.rejects(machine.projection(reserved), /mismatched/);
  badProjection = false;
  await machine.projection(reserved);
  const expected = { ...ids, reservation_sha256: reserved.sha256, runner_pid: 101,
    admission_challenge_base64url: challenge.toString('base64url') };
  const proof = await machine.attach(expected);
  await assert.rejects(machine.verifyAttachReceipt(proof, { ...expected, runner_pid: 102 }), /mismatched/);
  const attach = await machine.verifyAttachReceipt(proof, expected);
  const context = { ...ids, reservation_sha256: reserved.sha256, peer_pid: attach.runner_pid,
    peer_uid: attach.runner_uid, hq_epoch: installation.hq_epoch, process_start: attach.process_start,
    soul_id: reserved.payload.assignment.soul_id };
  assert.ok(watchCalls > 0);
  assert.equal(machine.watchHealthy(context), true);
  const request = { model: config.model, prompt_sha256: config.request_sha256 };
  await assert.rejects(machine.provide({ context, request }), /mismatched/);
  machine.markAcp(reserved, context, { destroyed: false });
  await assert.rejects(machine.provide({ context, request }), /mismatched/);
  const qPre = { ...ids, hq_epoch: installation.hq_epoch, reservation_sha256: reserved.sha256,
    attach_sha256: attach.sha256, session_id: '5'.repeat(32), q_challenge_sha256: full('6'),
    test_plan_sha256: full('7'), pre_observation_sha256: full('8'),
    case_nonce_base64url: Buffer.alloc(32, 2).toString('base64url'),
    issued_at: date(-100), expires_at: date(1000) };
  directPre = createProof('stage2a-direct-q-pre', qPre);
  const pre = await machine.beginDirectQualification(reserved);
  assert.deepEqual(pre, directPre);
  directCapture = createProof('stage2a-direct-q-capture', {
    ...ids, hq_epoch: qPre.hq_epoch, reservation_sha256: reserved.sha256, attach_sha256: attach.sha256,
    session_id: qPre.session_id, test_plan_sha256: qPre.test_plan_sha256, pre_response_sha256: pre.sha256,
    hq_refusal_receipt_sha256: full('b'), witness_sha256: full('c'), status: 'unqualified', host_credit: false,
    machine_protected_authority_absent: true, runner_pid: 101, dispatcher_pid: 100,
    runner_start_seconds: 123, runner_start_micros: 45, completed_at: date(0),
    post_observation_sha256: full('1'), q_wire_sha256: full('2'), q_index_sha256: full('3'), q_eof_receipt_sha256: full('4'),
  });
  witnessChallenge = { ...ids, hq_epoch: qPre.hq_epoch, reservation_sha256: reserved.sha256,
    attach_sha256: attach.sha256, session_id: qPre.session_id, pre_response_sha256: full('0'),
    challenge_base64url: witnessNonce };
  await assert.rejects(machine.beginDirectQualificationWitness(reserved, pre), /mismatched/);
  witnessChallenge.pre_response_sha256 = pre.sha256;
  const challengeForWitness = await machine.beginDirectQualificationWitness(reserved, pre);
  const witness = await machine.finishDirectQualificationWitness(reserved, pre, challengeForWitness, {
    cooperative_start_receipt_base64url: 'c3RhcnQ', cooperative_start_receipt_sha256: full('a'),
    hq_refusal_receipt_base64url: 'cmVmdXNhbA', hq_refusal_receipt_sha256: full('b'),
  });
  assert.equal((await machine.finishDirectQualification(reserved, pre, witness, full('b'))).payload.host_credit, false);
  assert.equal(machine.verifyDirectQualificationPre(pre).session_id, qPre.session_id);
  assert.throws(() => machine.verifyDirectQualificationPre(createProof('stage2a-direct-q-pre', {
    ...qPre, attach_sha256: full('9'),
  })), /mismatched/);
  assert.throws(() => machine.verifyDirectQualificationPre(createProof('stage2a-direct-q-pre', {
    ...qPre, expires_at: date(-1),
  })), /mismatched/);
  malformedProvider = false;
  await assert.rejects(machine.provide({ context, request }), /mismatched/, 'unsigned retry cannot undo one-use consumption');
  const projection = await machine.projectLaunch(context);
  assert.deepEqual(projection.machinePublicKey, machineKey);
  await assert.rejects(machine.stop(reserved), /mismatched/);
  assert.equal(machine.watchHealthy(context), false);
  await assert.rejects(machine.projectLaunch(context), /mismatched/);
  badCutoff = false;
  assert.match((await machine.stop(reserved)).sha256, /^sha256:/);
  lostReserve = true;
  const recoveryPlan = await reviewedPlan('c');
  const preAttach = await machine.reserve(recoveryPlan, { ...start, startId: recoveryPlan.reviewed_start_id });
  assert.equal(reserveCalls, 2);
  assert.equal(resultCalls, 1);
  assert.equal(machine.verifyReservation(preAttach), preAttach);
  await machine.projection(preAttach);
  assert.match((await machine.stop(preAttach)).sha256, /^sha256:/);

  expiredResult = true;
  const expiredPlan = await reviewedPlan('d');
  const expired = await machine.reserve(expiredPlan, { ...start, startId: expiredPlan.reviewed_start_id });
  assert.throws(() => machine.verifyReservation(expired), /mismatched/);
  const before = projectionCalls;
  await assert.rejects(machine.projection(expired), /mismatched/);
  assert.equal(projectionCalls, before);
  assert.match((await machine.stop(expired)).sha256, /^sha256:/);

  badResult = true;
  const badPlan = await reviewedPlan('e');
  await assert.rejects(machine.reserve(badPlan, { ...start, startId: badPlan.reviewed_start_id }), /mismatched/);
});

test('owner takeover waits for ticketed ACP and stop fences channels before awaiting Machine', async () => {
  const { Duplex } = await import('node:stream');
  const { createStage2aCooperativeStarter } = await import('../hq/stage2a-cooperative-start.mjs');
  const { createSoulStarter } = await import('../hq/soul-start.mjs');
  const socket = () => new Duplex({ read() {}, write(_chunk, _encoding, done) { done(); } });
  const events = [];
  let openAcp, ready, confirm, launchId;
  const waiting = new Promise((resolve) => { ready = resolve; });
  const signedCutoff = new Promise((resolve) => { confirm = resolve; });
  const installation = { installation_id: 'installation', runner_uid: 551, hq_epoch: '0'.repeat(64),
    reviewed_start_id: `st_${'a'.repeat(24)}` };
  const fakeReservation = { sha256: `sha256:${'0'.repeat(64)}`, payload: {
    assignment: { runner_uid: 551, runner_gid: 551 }, measurement_binding: { claimed_definition_digest: 'definition' },
  } };
  const preProof = { sha256: 'sha256:' + '3'.repeat(64) };
  let witnessed;
  const witnessNonce = Buffer.alloc(32, 3).toString('base64url');
  const witnessDigest = 'sha256:' + 'f'.repeat(64);
  const client = {
    lookup: async () => installation,
    reserve: async (_installation, { startId, launchId: launched }) => {
      assert.equal(startId, installation.reviewed_start_id);
      launchId = launched;
      return fakeReservation;
    },
    projection: async () => { events.push('projection'); return {}; },
    watch() {},
    markAcp: () => { events.push('ticketed'); },
    runnerPid: () => 100,
    watchHealthy: () => true,
    assertLive: async () => true,
    beginDirectQualification: async (reservation) => {
      assert.equal(reservation, fakeReservation);
      return preProof;
    },
    beginDirectQualificationWitness: async (reservation, prior) => {
      assert.equal(reservation, fakeReservation);
      assert.equal(prior, preProof);
      assert.equal(core.receipts.length, 2);
      return witnessNonce;
    },
    finishDirectQualificationWitness: async (reservation, prior, challenge, rows) => {
      assert.equal(reservation, fakeReservation);
      assert.equal(prior, preProof);
      assert.equal(challenge, witnessNonce);
      witnessed = rows;
      return witnessDigest;
    },
    finishDirectQualification: async (reservation, prior, witness, receiptSHA256) => {
      assert.equal(reservation, fakeReservation);
      assert.equal(prior, preProof);
      assert.equal(witness, witnessDigest);
      assert.equal(receiptSHA256, witnessed.hq_refusal_receipt_sha256);
      return witnessed;
    },
    verifyDirectQualificationPre: (input) => {
      assert.equal(input, preProof);
      return { installation_id: installation.installation_id, start_id: installation.reviewed_start_id,
        launch_id: launchId, hq_epoch: installation.hq_epoch, reservation_sha256: fakeReservation.sha256,
        attach_sha256: 'sha256:' + '4'.repeat(64), session_id: '5'.repeat(32),
        q_challenge_sha256: 'sha256:' + '6'.repeat(64), test_plan_sha256: 'sha256:' + '7'.repeat(64),
        case_nonce_base64url: Buffer.alloc(32, 1).toString('base64url'),
        expires_at: new Date(Date.now() + 1000).toISOString() };
    },
    revoke: () => { events.push('revoke'); },
    stop: async () => { events.push('machine-stop'); return signedCutoff; },
  };
  const core = { random: { hex: (n) => randomBytes(n).toString('hex') },
    clock: { now: Date.now }, profile: 'managed-cooperative', receipts: [] };
  core.persistReceipt = async (record) => {
    const receipt = { ...record, seq: core.receipts.length + 1 };
    core.receipts.push(receipt);
    return receipt;
  };
  const stage = createStage2aCooperativeStarter({ machine: client, core,
    readCommittedReceipts: async (seqs) => {
      assert.deepEqual(seqs, [1, 2]);
      return structuredClone(core.receipts);
    },
    openAdmission: async ({ openAcpStream }) => {
      events.push('bound');
      openAcp = openAcpStream;
      ready();
      return { close: () => { events.push('close-listeners'); } };
    } });
  const first = stage.start('/soul');
  await waiting;
  assert.deepEqual(events, ['projection', 'bound']);
  assert.equal(stage.report()[0].state, 'starting');
  const acp = socket();
  openAcp(acp, {});
  const response = await first;
  const token = response[Object.getOwnPropertySymbols(response)[0]];
  assert.equal(token.result.start_id, installation.reviewed_start_id);
  const owner = socket();
  token.open()(owner);
  assert.equal(stage.report()[0].state, 'running');
  const hybrid = createSoulStarter({ core, cooperativeStart: stage, mode: () => 'running',
    protectedStart: { start: () => assert.fail('protected effects must stay closed for the active direct package') } });
  await assert.rejects(hybrid.dispatch('soul.start', {
    auth: 'owner', takeover: true, payload: { package_path: '/soul', requested_profile: 'managed-protected' },
  }), { code: 'profile_insufficient' });
  const persistReceipt = core.persistReceipt;
  core.persistReceipt = undefined;
  await assert.rejects(hybrid.qualifyDirectProtectedClaim(token.result.start_id), /unavailable/);
  core.persistReceipt = persistReceipt;
  const captured = await hybrid.qualifyDirectProtectedClaim(token.result.start_id);
  const raw = Buffer.from(captured.hq_refusal_receipt_base64url, 'base64url');
  assert.equal(captured.hq_refusal_receipt_sha256, digest(raw));
  const receipt = JSON.parse(raw);
  assert.deepEqual(receipt, core.receipts[1]);
  assert.equal(receipt.refusal_code, 'profile_insufficient');
  assert.equal(receipt.pre_response_sha256, preProof.sha256);
  assert.equal(receipt.reservation_sha256, fakeReservation.sha256);
  assert.equal(receipt.cooperative_start_receipt_seq, core.receipts[0].seq);
  assert.equal(receipt.cooperative_start_receipt_sha256, digest(canonicalBytes(core.receipts[0])));
  await assert.rejects(hybrid.qualifyDirectProtectedClaim(token.result.start_id), /already used/);
  const stop = stage.stop(token.result.start_id);
  assert.equal(stage.report()[0].state, 'stopping');
  assert.equal(acp.destroyed, true);
  assert.equal(owner.destroyed, true);
  assert.deepEqual(events, ['projection', 'bound', 'ticketed', 'revoke', 'close-listeners']);
  await assert.rejects(stage.start('/soul'), { code: 'host.launch_busy' });
  confirm(undefined);
  assert.deepEqual(await stop, { start_id: token.result.start_id, state: 'containment_unconfirmed', contained: false });
  assert.equal(stage.report()[0].state, 'containment_unconfirmed');
  assert.deepEqual(events.slice(-1), ['machine-stop']);
});

test('owner stop retries the original reservation result while keeping the start fenced', async () => {
  const { createStage2aCooperativeStarter } = await import('../hq/stage2a-cooperative-start.mjs');
  const installation = { installation_id: 'installation', runner_uid: 551, hq_epoch: '0'.repeat(64),
    reviewed_start_id: `st_${'a'.repeat(24)}` };
  const reservation = { sha256: 'reservation' };
  let original, recovered, reserveCalls = 0, recoverCalls = 0;
  let firstReadFinished;
  const firstRead = new Promise(resolve => { firstReadFinished = resolve; });
  const stage = createStage2aCooperativeStarter({
    machine: {
      lookup: async () => installation,
      async reserve(_installation, selectors) {
        reserveCalls++;
        original = selectors;
        throw new Error('reserve and immediate result replies lost');
      },
      async recoverReservation(actualInstallation, selectors) {
        assert.equal(actualInstallation, installation);
        assert.deepEqual(selectors, original);
        if (++recoverCalls === 1) {
          firstReadFinished();
          throw new Error('read-only result unavailable');
        }
        recovered = reservation;
        return recovered;
      },
      async stop(actualReservation) {
        assert.equal(actualReservation, recovered);
        return { sha256: 'cutoff' };
      },
    },
    core: { random: { hex: n => randomBytes(n).toString('hex') }, clock: { now: Date.now }, receipts: [] },
    openAdmission: () => assert.fail('an unresolved reserve cannot open admission'),
  });

  await assert.rejects(stage.start('/soul'), { code: 'host.launch_unavailable' });
  await firstRead;
  const item = stage.report()[0];
  assert.equal(item.state, 'containment_unconfirmed');
  await assert.rejects(stage.start('/soul'), { code: 'host.launch_busy' });
  assert.deepEqual(await stage.stop(item.start_id), { start_id: item.start_id, state: 'stopped', contained: true });
  assert.deepEqual(stage.report(), []);
  assert.equal(reserveCalls, 1);
  assert.equal(recoverCalls, 2);
});
