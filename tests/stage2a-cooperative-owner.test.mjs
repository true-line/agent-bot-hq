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
    const purpose = `agent-bot/soul-cooperative-${kind}/v3`;
    const payload = canonicalBytes({ contract: 'machine/v3', kind: `soul-cooperative-${kind}`, schema_version: 3, ...body });
    const raw = canonicalBytes({ purpose, schema_version: 3, issuer_public_key_base64url: machineKey.toString('base64url'),
      payload_base64url: payload.toString('base64url'), payload_sha256: digest(payload),
      signature_base64url: sign(null, Buffer.concat([Buffer.from(purpose + '\0'), payload]), privateKey).toString('base64url') });
    return { envelope_base64url: raw.toString('base64url'), sha256: digest(raw) };
  };
  let ids, identity, attachment;
  let missingDirectAdapter = true;
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
          body = { ...installation, ...(missingDirectAdapter ? {} : { adapter_transport: 'direct-comms' }) };
          break;
        case 'stage2a-cooperative-live-v3':
          watchCalls++;
          body = createProof('live', { ...identity, attach_sha256: attachment.sha256, hq_epoch: request.hq_epoch,
            runner_pid: 101, observed_at: date(0), expires_at: date(5000) });
          break;
        case 'stage2a-cooperative-reserve-v3': {
          const { installation_id, start_id, launch_id, hq_epoch, plan_digest } = request;
          ids = { installation_id, start_id, launch_id };
          const a = { ...ids, plan_id: 'plan', hq_epoch, plan_digest, package_root: '/installed/soul',
            expires_at: date(25000), package_sha256: sha('3'), soul_artifact_sha256: sha('4'),
            soul_id: 'agent_01234567-89ab-cdef-0123-456789abcdef', runner_uid: 550, runner_gid: 550,
            hq_uid: process.getuid(), machine_uid: 551 };
          body = createProof('reservation', { adapter_transport: 'direct-comms', host_id: request.host_id, issued_at: date(-1000),
            expires_at: date(25000), installed_plan_receipt_sha256: full('9'),
            assignment: a, endpoints: { admission: { directory: installation.admission_directory },
              broker: { socket_path: installation.broker_socket_path } }, admission_challenge_sha256: request.admission_challenge_sha256,
            measurement_binding: { ...a, installed_plan_digest: plan_digest, contract: 'machine/v3',
              kind: 'stage2a-measurement-binding', schema_version: 3, host_id: request.host_id,
              profile_in_force: 'managed-cooperative', launch_input_measurement: full('a'),
              h_service_descriptor_digest: full('b'), claimed_definition_digest: full('c') },
            qualification_provider: qualification });
          identity = { ...ids, reservation_sha256: body.sha256, h_service_descriptor_digest: full('b') };
          break;
        }
        case 'stage2a-cooperative-launch-inputs-v3':
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
  const plan = await machine.lookup('/owner/soul');
  const challenge = randomBytes(32);
  const start = { startId: `st_${'a'.repeat(24)}`, launchId: `ln_${'b'.repeat(24)}`, challenge };
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
  malformedProvider = false;
  await assert.rejects(machine.provide({ context, request }), /mismatched/, 'unsigned retry cannot undo one-use consumption');
  const projection = await machine.projectLaunch(context);
  assert.deepEqual(projection.machinePublicKey, machineKey);
  await assert.rejects(machine.stop(reserved), /mismatched/);
  assert.equal(machine.watchHealthy(context), false);
  await assert.rejects(machine.projectLaunch(context), /mismatched/);
  badCutoff = false;
  assert.match((await machine.stop(reserved)).sha256, /^sha256:/);
  const preAttach = await machine.reserve(plan, { ...start, startId: `st_${'c'.repeat(24)}` });
  assert.match((await machine.stop(preAttach)).sha256, /^sha256:/);
});

test('owner takeover waits for ticketed ACP and stop fences channels before awaiting Machine', async () => {
  const { Duplex } = await import('node:stream');
  const { createStage2aCooperativeStarter } = await import('../hq/stage2a-cooperative-start.mjs');
  const socket = () => new Duplex({ read() {}, write(_chunk, _encoding, done) { done(); } });
  const events = [];
  let openAcp, ready, confirm;
  const waiting = new Promise((resolve) => { ready = resolve; });
  const signedCutoff = new Promise((resolve) => { confirm = resolve; });
  const installation = { installation_id: 'installation', runner_uid: 551, hq_epoch: '0'.repeat(64) };
  const fakeReservation = { sha256: `sha256:${'0'.repeat(64)}`, payload: {
    assignment: { runner_uid: 551, runner_gid: 551 }, measurement_binding: { claimed_definition_digest: 'definition' },
  } };
  const client = {
    lookup: async () => installation,
    reserve: async () => fakeReservation,
    projection: async () => { events.push('projection'); return {}; },
    watch() {},
    markAcp: () => { events.push('ticketed'); },
    runnerPid: () => 100,
    revoke: () => { events.push('revoke'); },
    stop: async () => { events.push('machine-stop'); return signedCutoff; },
  };
  const core = { random: { hex: (n) => randomBytes(n).toString('hex') },
    clock: { now: Date.now }, receipts: [] };
  const stage = createStage2aCooperativeStarter({ machine: client, core,
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
  const owner = socket();
  token.open()(owner);
  assert.equal(stage.report()[0].state, 'running');
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
