import { isAbsolute, join } from 'node:path';
import { fail } from '../sdk/errors.mjs';
import { canonicalBytes, canonicalDigest } from '../sdk/wire/canonical-json.mjs';
import { verifyStage2aMachineEnvelope } from './stage2a-stop.mjs';
import { digest, match, SHA256, verifyCooperativeProof, verifyDirectQualificationCapture, verifyDirectQualificationPre } from './stage2a-cooperative-proof.mjs';

const HEX256 = /^[0-9a-f]{64}$/;
const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const REVIEWED_START_ID = /^st_[0-9a-f]{24}$/;
const invalid = () => { throw new Error('Machine cooperative authority unavailable or mismatched'); };
const idFields = ['installation_id', 'start_id', 'launch_id'];
const selectionFields = [...idFields, 'plan_id', 'plan_digest', 'hq_epoch'];
const pick = (value, fields) => Object.fromEntries(fields.map((field) => [field, value[field]]));
const instant = (value) => typeof value === 'string' ? Date.parse(value) : NaN;
const pid = (value) => Number.isSafeInteger(value) && value >= 2;
const path = (value) => typeof value === 'string' && isAbsolute(value) && !/[\u0000\r\n]/.test(value);
const fieldsEqual = (value, target, fields) => match(value, pick(target, fields));

function freezeJSON(value) {
  if (value && typeof value === 'object') {
    for (const child of Object.values(value)) freezeJSON(child);
    Object.freeze(value);
  }
  return value;
}

export function createStage2aCooperativeMachine({ exchange, hDescriptorDigest, machinePublicKey, enableBrokeredB = false, verifyBrokeredContainment, now = Date.now }) {
  if (typeof exchange !== 'function' || !SHA256.test(hDescriptorDigest ?? '')
    || !HEX256.test(machinePublicKey ?? '')) invalid();
  const allowsTransport = (value) => value === 'direct-comms' || (enableBrokeredB === true && value === 'brokered-b');
  const active = new Map();
  const owned = (reservation) => {
    const entry = active.get(reservation?.sha256);
    if (entry?.reservation !== reservation) invalid();
    return entry;
  };
  const contextMatches = (entry, context) => {
    const { assignment } = entry.reservation.payload;
    const a = entry.attach;
    return a && fieldsEqual(context, assignment, idFields) && context.soul_id === assignment.soul_id
      && context.hq_epoch === assignment.hq_epoch && context.peer_uid === assignment.runner_uid
      && context.peer_pid === a.runner_pid && context.process_start === a.process_start;
  };
  const call = async (operation, request, entry) => {
    const response = await exchange(`stage2a-cooperative-${operation}-v3`, request);
    if (!Buffer.isBuffer(response?.machineKey) || response.machineKey.toString('hex') !== machinePublicKey
      || (entry && !response.machineKey.equals(entry.machineKey))) invalid();
    return response;
  };
  const proof = (response, kind) => verifyCooperativeProof(response.body, response.machineKey, kind);
  const requestOf = (reservation) => ({ reservation_sha256: reservation.sha256,
    ...pick(reservation.payload.assignment, selectionFields) });
  const identityOf = (reservation) => ({ reservation_sha256: reservation.sha256,
    ...pick(reservation.payload.assignment, idFields),
    h_service_descriptor_digest: reservation.payload.measurement_binding.h_service_descriptor_digest });
  const watchHealthy = (context) => {
    const entry = active.get(context?.reservation_sha256);
    return Boolean(entry && !entry.revoked && entry.liveUntil > now() && contextMatches(entry, context));
  };
  const revoke = (reservation) => {
    const entry = owned(reservation);
    entry.revoked = true;
    clearTimeout(entry.timer);
  };

  const markLost = (entry) => {
    if (!entry.revoked) {
      revoke(entry.reservation);
      entry.onLost?.();
    }
  };

  async function refresh(entry) {
    if (entry.revoked) return false;
    if (entry.liveUntil !== undefined && entry.liveUntil <= now()) {
      markLost(entry);
      return false;
    }
    entry.refresh ??= (async () => {
      try {
        const { reservation, attach } = entry;
        const request = { ...requestOf(reservation), attach_sha256: attach.sha256 };
        const response = await call('live', request, entry);
        const payload = proof(response, 'live');
        const observed = instant(payload.observed_at), until = instant(payload.expires_at);
        if (entry.revoked || (entry.liveUntil !== undefined && entry.liveUntil <= now()) || !match(payload, { ...identityOf(reservation), attach_sha256: attach.sha256,
          hq_epoch: request.hq_epoch, runner_pid: attach.runner_pid })
          || !Number.isFinite(observed) || observed < instant(attach.attached_at) || observed > now()
          || !Number.isFinite(until) || until <= now() || until - observed > 5000) return false;
        entry.liveUntil = until;
        clearTimeout(entry.timer);
        entry.timer = setTimeout(() => { void refresh(entry); }, Math.min(2000, Math.floor((until - now()) / 2)));
        entry.timer.unref?.();
        return true;
      } catch { return false; }
    })().then(healthy => {
      if (!healthy) markLost(entry);
      return healthy;
    }).finally(() => { entry.refresh = undefined; });
    return entry.refresh;
  }

  function reservationRequest(installed, { startId, launchId, challenge }) {
    if (!allowsTransport(installed.adapter_transport) || startId !== installed.reviewed_start_id) invalid();
    return Object.freeze({ profile: 'managed-cooperative', host_id: installed.host_id,
      plan_digest: installed.plan_digest, installation_id: installed.installation_id,
      start_id: startId, launch_id: launchId, hq_epoch: installed.hq_epoch,
      package_path: installed.package_path, admission_challenge_sha256: digest(challenge),
      admission_challenge_base64url: challenge.toString('base64url') });
  }

  function brokeredInputs(body, machineKey, payload, installed) {
    const decode = (prefix, purpose, schemaVersion) => {
      const encoded = body[`${prefix}_envelope_base64url`], sha = body[`${prefix}_sha256`];
      if (typeof encoded !== 'string' || encoded.length > 22_000 || !SHA256.test(sha)) invalid();
      const bytes = Buffer.from(encoded, 'base64url');
      if (bytes.toString('base64url') !== encoded) invalid();
      const signed = verifyStage2aMachineEnvelope(bytes, machineKey, purpose, { schemaVersion, maxBytes: 16_384 });
      if (signed.envelope_sha256 !== sha) invalid();
      return signed.payload;
    };
    const detached = decode('bridge_assignment', 'agent-bot/soul-cooperative-bridge-assignment/v3', 3);
    const members = decode('member_set_assignment', 'agent-bot/stage2a-member-set-assignment/v1', 1);
    const a = payload.assignment;
    const shared = { ...pick(a, selectionFields.filter((field) => field !== 'launch_id')),
      host_id: payload.host_id, reservation_sha256: body.sha256 };
    if (!match(detached, { ...shared, kind: 'soul-cooperative-bridge-assignment',
      contract: 'machine/v3', schema_version: 3, launch_id: a.launch_id,
      bridge_launch_sha256: payload.bridge_launch_sha256, expires_at: payload.expires_at })
      || !match(members, { ...shared, contract: 'machine/v3', kind: 'stage2a-member-set-assignment',
        schema_version: 1, profile_in_force: 'managed-cooperative', soul_id: a.soul_id,
        runner_uid: a.runner_uid, runner_gid: a.runner_gid, expires_at: payload.expires_at })
      || !match(members.b_authority, { purpose: 'agent-bot/soul-cooperative-bridge-assignment/v3',
        envelope_sha256: body.bridge_assignment_sha256 })
      || !match(members.bridge, pick(detached.bridge, ['uid', 'gid', 'account']))
      || detached.endpoints?.broker?.socket_path !== installed.broker_socket_path
      || canonicalDigest(detached.endpoints.member) !== canonicalDigest(payload.endpoints.member)
      || canonicalDigest(detached.endpoints.relay) !== canonicalDigest(payload.endpoints.relay)
      || canonicalDigest(members.bridge.endpoints) !== canonicalDigest(detached.endpoints)
      || !SHA256.test(members.owner_plan_member_set_sha256 ?? '') || members.members?.length !== 2) invalid();
    return Object.freeze({ detached, members });
  }

  function acceptReservation(response, installed, request, recovered = false) {
    const brokered = installed.adapter_transport === 'brokered-b';
    const body = response.body;
    if (!allowsTransport(installed.adapter_transport) || (brokered
      && Object.keys(body ?? {}).sort().join(',') !== ['envelope_base64url', 'sha256',
        'bridge_assignment_envelope_base64url', 'bridge_assignment_sha256',
        'member_set_assignment_envelope_base64url', 'member_set_assignment_sha256'].sort().join(','))) invalid();
    const payload = brokered ? verifyCooperativeProof(pick(body, ['envelope_base64url', 'sha256']),
      response.machineKey, 'reservation') : proof(response, 'reservation');
    const a = payload.assignment, m = payload.measurement_binding;
    const issued = instant(payload.issued_at), expires = instant(payload.expires_at);
    if (!match(payload, pick(request, ['host_id', 'admission_challenge_sha256']))
      || payload.adapter_transport !== installed.adapter_transport
      || !Number.isFinite(issued) || !Number.isFinite(expires) || issued > now() || (!recovered && expires <= now())
      || expires <= issued || expires - issued > 30000 || !SHA256.test(payload.installed_plan_receipt_sha256 ?? '')
      || !a || !fieldsEqual(a, request, ['installation_id', 'start_id', 'launch_id', 'hq_epoch', 'plan_digest'])
      || a.plan_id !== installed.plan_id || a.expires_at !== payload.expires_at
      || a.runner_uid !== installed.runner_uid || a.runner_gid !== installed.runner_gid
      || payload.endpoints?.admission?.directory !== installed.admission_directory
      || payload.endpoints?.admission?.socket_path !== installed.admission_socket_path
      || (brokered ? Object.keys(payload.endpoints ?? {}).sort().join(',') !== 'admission,member,relay'
        : payload.endpoints?.broker?.socket_path !== installed.broker_socket_path)
      || a.hq_uid !== process.getuid?.() || !Number.isSafeInteger(a.runner_uid) || a.runner_uid < 300
      || a.runner_uid === a.hq_uid || a.runner_uid === a.machine_uid || a.runner_gid !== a.runner_uid
      || !/^agent_[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(a.soul_id ?? '')
      || !path(a.package_root) || !HEX256.test(a.package_sha256 ?? '') || !HEX256.test(a.soul_artifact_sha256 ?? '')
      || !fieldsEqual(m, a, ['installation_id', 'start_id', 'launch_id', 'hq_epoch', 'plan_id',
        'package_sha256', 'soul_artifact_sha256', 'soul_id'])
      || !match(m, { contract: 'machine/v3', schema_version: 3, kind: 'stage2a-measurement-binding',
        profile_in_force: 'managed-cooperative', host_id: payload.host_id, installed_plan_digest: a.plan_digest })
      || !SHA256.test(m.launch_input_measurement ?? '') || m.h_service_descriptor_digest !== hDescriptorDigest
      || !SHA256.test(m.claimed_definition_digest ?? '')) invalid();
    const memberInputs = brokered ? brokeredInputs(body, response.machineKey, payload, installed) : undefined;
    const reservation = freezeJSON({ ...body, payload });
    if (active.has(reservation.sha256)) invalid();
    active.set(reservation.sha256, { reservation, machineKey: response.machineKey, expires, memberInputs, revoked: false });
    return reservation;
  }

  return Object.freeze({
    async lookup(packagePath) {
      const { body, machineKey } = await call('lookup', { package_path: packagePath });
      if (body?.source_package_path !== packagePath) invalid();
      const installed = { ...body, package_path: body.source_package_path, machineKey };
      if (!installed || installed.package_path !== packagePath || !ID.test(installed.host_id ?? '')
        || !ID.test(installed.installation_id ?? '') || !ID.test(installed.plan_id ?? '')
        || !HEX256.test(installed.plan_digest ?? '') || !HEX256.test(installed.hq_epoch ?? '')
        || !ID.test(installed.hq_installation_id ?? '') || !HEX256.test(installed.h_owner_plan_digest ?? '')
        || !Number.isSafeInteger(installed.runner_uid) || installed.runner_uid < 300
        || installed.runner_gid !== installed.runner_uid || !path(installed.admission_directory)
        || !path(installed.broker_socket_path) || !Buffer.isBuffer(installed.machineKey) || installed.machineKey.length !== 32) invalid();
      // Only A's installed policy can select an adapter that speaks Comms
      // directly. A stock vendor HTTP client needs the separate pre-ACP B bind.
      if (!allowsTransport(installed.adapter_transport)) {
        fail('profile_insufficient', 'the installed Soul has no approved direct Comms adapter');
      }
      if (typeof installed.reviewed_start_id !== 'string' || !REVIEWED_START_ID.test(installed.reviewed_start_id)) invalid();
      const slot = digest(`agent-bot-soul-endpoint-start/v1\0${installed.installation_id}\0${installed.reviewed_start_id}`).slice(7, 27);
      if (installed.admission_socket_path !== join(installed.admission_directory, `${slot}.sock`)) invalid();
      return Object.freeze(installed);
    },
    async reserve(installed, selectors) {
      const request = reservationRequest(installed, selectors);
      try {
        return acceptReservation(await call('reserve', request, installed), installed, request);
      } catch {
        // A may already have published the one-use start even when the
        // reply is missing or cannot be authenticated. Only read it back.
        return acceptReservation(await call('reserve-result', request, installed), installed, request, true);
      }
    },
    async recoverReservation(installed, selectors) {
      const request = reservationRequest(installed, selectors);
      return acceptReservation(await call('reserve-result', request, installed), installed, request, true);
    },
    verifyReservation(reservation) {
      const entry = owned(reservation);
      if (entry.revoked || now() >= entry.expires) invalid();
      return reservation;
    },
    brokeredMemberInputs(reservation) {
      const entry = owned(reservation);
      if (entry.revoked || now() >= entry.expires || !entry.memberInputs) invalid();
      return Object.freeze({ machinePublicKey: Buffer.from(entry.machineKey),
        assignmentBytes: Buffer.from(reservation.member_set_assignment_envelope_base64url, 'base64url'),
        cooperativeBridgeBytes: Buffer.from(reservation.bridge_assignment_envelope_base64url, 'base64url') });
    },
    async projection(reservation) {
      const entry = owned(reservation);
      if (entry.revoked || now() >= entry.expires) invalid();
      const response = await call('launch-inputs', requestOf(reservation), entry);
      const payload = proof(response, 'launch-projection');
      if (entry.revoked || now() >= entry.expires || !match(payload, identityOf(reservation))
        || payload.launch_input_measurement !== reservation.payload.measurement_binding.launch_input_measurement
        || !path(payload.selected_command) || !Array.isArray(payload.argv)
        || !payload.argv.every(arg => typeof arg === 'string') || Array.isArray(payload.host_projection)
        || !payload.host_projection?.adapters || !payload.host_projection?.installation
        || !payload.environment || !payload.effective_config || !payload.component_digests) invalid();
      entry.projectionProof = Object.freeze({ ...response.body });
      entry.projection = freezeJSON(payload);
      return entry.projection;
    },
    async attach(expected) {
      const entry = active.get(expected?.reservation_sha256);
      if (!entry?.projection || entry.revoked || entry.attachPending || now() >= entry.expires
        || !fieldsEqual(expected, entry.reservation.payload.assignment, idFields)) invalid();
      const expectedAttach = Object.freeze({ ...expected });
      entry.attachPending = (async () => {
        const response = await call('attach', expectedAttach, entry);
        const payload = proof(response, 'attach');
        const assignment = entry.reservation.payload.assignment;
        const attached = instant(payload.attached_at);
        if (!match(payload, identityOf(entry.reservation))
          || payload.challenge_sha256 !== entry.reservation.payload.admission_challenge_sha256
          || payload.runner_uid !== assignment.runner_uid || payload.runner_pid !== expectedAttach.runner_pid
          || !pid(payload.runner_pid) || !pid(payload.dispatcher_pid) || payload.runner_pid === payload.dispatcher_pid
          || !Number.isSafeInteger(payload.runner_start_sec) || payload.runner_start_sec <= 0
          || !Number.isSafeInteger(payload.runner_start_usec) || payload.runner_start_usec < 0 || payload.runner_start_usec >= 1e6
          || !Number.isFinite(attached) || attached < instant(entry.reservation.payload.issued_at)
          || attached >= entry.expires || attached > now()) invalid();
        // Preserve authenticated attachment for cutoff if stop raced the RPC.
        // Only verifyAttachReceipt can publish a live C context.
        entry.attach = Object.freeze({ ...payload, sha256: response.body.sha256,
          process_start: `${payload.runner_start_sec}.${String(payload.runner_start_usec).padStart(6, '0')}` });
        entry.attachRequest = expectedAttach;
        entry.attachResponse = response;
        return response;
      })();
      return entry.attachPending;
    },
    async verifyAttachReceipt(response, expected) {
      const entry = active.get(expected?.reservation_sha256);
      if (!entry?.attach || entry.revoked || entry.attachVerified || now() >= entry.expires
        || response !== entry.attachResponse || !match(expected, entry.attachRequest)) invalid();
      entry.attachVerified = true;
      if (!await refresh(entry)) invalid();
      return entry.attach;
    },
    assertLive: async (context) => {
      const entry = active.get(context?.reservation_sha256);
      return watchHealthy(context) && await refresh(entry);
    },
    watchHealthy,
    watch(reservation, onLost) { owned(reservation).onLost = onLost; },
    revoke,
    abort(context) {
      const entry = active.get(context?.reservation_sha256);
      if (entry && contextMatches(entry, context)) markLost(entry);
    },
    async projectLaunch(context) {
      const entry = active.get(context?.reservation_sha256);
      if (!entry?.projectionProof || !entry.acp || entry.acp.destroyed || !watchHealthy(context)
        || !await refresh(entry) || entry.acp.destroyed || !watchHealthy(context)) invalid();
      return Object.freeze({ ...entry.projectionProof, machinePublicKey: Buffer.from(entry.machineKey) });
    },
    markAcp(reservation, context, socket) {
      const entry = owned(reservation);
      if (entry.acp || !watchHealthy(context) || socket.destroyed) invalid();
      entry.acp = socket;
      entry.acpContext = context;
    },
    async provide({ context, request }) {
      const entry = active.get(context?.reservation_sha256);
      const live = () => entry?.acp && !entry.acp.destroyed && watchHealthy(entry.acpContext);
      if (!live() || entry.memberInputs || !contextMatches(entry, context) || entry.providerSpent
        || !request || Object.keys(request).sort().join(',') !== 'model,prompt_sha256'
        || !ID.test(request.model ?? '') || !SHA256.test(request.prompt_sha256 ?? '')) invalid();
      const reviewed = entry.reservation.payload.qualification_provider;
      if (!reviewed || !SHA256.test(reviewed.config_sha256 ?? '')) invalid();
      entry.providerSpent = true;
      if (!await refresh(entry) || !live()) invalid();
      const exact = requestOf(entry.reservation);
      const selectors = { ...exact, attach_sha256: entry.attach.sha256, ...request };
      const { body } = await call('provider', selectors, entry);
      if (!live() || !match(body, { model: request.model, request_sha256: request.prompt_sha256,
        provider_config_sha256: reviewed.config_sha256, config_base64url: reviewed.config_base64url })
        || typeof body.response_text !== 'string' || !body.response_text || body.response_text.length > 4096) invalid();
      const provided = { model: body.model, request_sha256: body.request_sha256, response_text: body.response_text };
      const config = canonicalBytes(provided);
      if (config.toString('base64url') !== body.config_base64url || digest(config) !== body.provider_config_sha256) invalid();
      const payload = verifyCooperativeProof({ envelope_base64url: body.receipt_envelope_base64url,
        sha256: body.receipt_sha256 }, entry.machineKey, 'provider');
      const issued = instant(payload.issued_at), expires = instant(payload.expires_at);
      if (!match(payload, { ...exact, ...identityOf(entry.reservation), attach_sha256: entry.attach.sha256,
        runner_pid: entry.attach.runner_pid, model: body.model, request_sha256: body.request_sha256,
        response_sha256: digest(Buffer.from(body.response_text)), provider_config_sha256: body.provider_config_sha256 })
        || !Number.isFinite(issued) || issued > now() || !Number.isFinite(expires)
        || expires <= now() || expires - issued > 15000 || expires !== body.expires_at_ms) invalid();
      return Object.freeze({ model: body.model, stop_reason: 'end_turn', text: body.response_text,
        usage: Object.freeze({ input_tokens: 7, output_tokens: 3 }) });
    },
    async beginDirectQualification(reservation) {
      const entry = owned(reservation);
      if (entry.memberInputs || !entry.acp || entry.acp.destroyed || !watchHealthy(entry.acpContext)) invalid();
      const { body } = await call('q-begin', { ...requestOf(reservation), attach_sha256: entry.attach.sha256 }, entry);
      return Object.freeze({ ...body });
    },
    async beginDirectQualificationWitness(reservation, preResult) {
      const entry = owned(reservation);
      if (entry.memberInputs || !entry.acp || entry.acp.destroyed || !watchHealthy(entry.acpContext)) invalid();
      const pre = verifyDirectQualificationPre(preResult, entry.machineKey);
      const { body } = await call('q-witness-begin', { ...requestOf(reservation), attach_sha256: entry.attach.sha256,
        pre_response_sha256: preResult.sha256 }, entry);
      const matches = { ...pick(pre, [...idFields, 'hq_epoch', 'reservation_sha256', 'attach_sha256', 'session_id']),
        pre_response_sha256: preResult.sha256 };
      const challenge = body?.challenge_base64url;
      if (!match(body, matches) || Object.keys(body).length !== Object.keys(matches).length + 1
        || typeof challenge !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(challenge)
        || Buffer.from(challenge, 'base64url').toString('base64url') !== challenge
        || !watchHealthy(entry.acpContext) || entry.acp.destroyed || instant(pre.expires_at) <= now()) invalid();
      return challenge;
    },
    async finishDirectQualificationWitness(reservation, preResult, challenge, rows) {
      const entry = owned(reservation);
      if (entry.memberInputs || !entry.acp || entry.acp.destroyed || !watchHealthy(entry.acpContext)) invalid();
      const { body } = await call('q-witness-finish', { ...requestOf(reservation), attach_sha256: entry.attach.sha256,
        pre_response_sha256: preResult.sha256, challenge_base64url: challenge,
        cooperative_start_receipt_base64url: rows.cooperative_start_receipt_base64url,
        cooperative_start_receipt_sha256: rows.cooperative_start_receipt_sha256,
        hq_refusal_receipt_base64url: rows.hq_refusal_receipt_base64url,
        hq_refusal_receipt_sha256: rows.hq_refusal_receipt_sha256 }, entry);
      if (!body || Object.keys(body).join(',') !== 'witness_sha256' || !SHA256.test(body.witness_sha256 ?? '')
        || !watchHealthy(entry.acpContext) || entry.acp.destroyed) invalid();
      return body.witness_sha256;
    },
    async finishDirectQualification(reservation, preResult, witnessSHA256, refusalSHA256) {
      const entry = owned(reservation);
      if (entry.memberInputs || !entry.acp || entry.acp.destroyed || !watchHealthy(entry.acpContext)
        || !SHA256.test(witnessSHA256 ?? '') || !SHA256.test(refusalSHA256 ?? '')) invalid();
      const pre = verifyDirectQualificationPre(preResult, entry.machineKey);
      const { body } = await call('q-finish', { ...requestOf(reservation), attach_sha256: entry.attach.sha256,
        pre_response_sha256: preResult.sha256, witness_sha256: witnessSHA256 }, entry);
      if (!watchHealthy(entry.acpContext) || entry.acp.destroyed) invalid();
      const payload = verifyDirectQualificationCapture(body, entry.machineKey);
      if (!match(payload, { ...pick(pre, [...idFields, 'hq_epoch', 'reservation_sha256', 'attach_sha256', 'session_id', 'test_plan_sha256']),
        pre_response_sha256: preResult.sha256, witness_sha256: witnessSHA256, hq_refusal_receipt_sha256: refusalSHA256,
        status: 'unqualified', host_credit: false, machine_protected_authority_absent: true,
        runner_pid: entry.attach.runner_pid, dispatcher_pid: entry.attach.dispatcher_pid,
        runner_start_seconds: entry.attach.runner_start_sec, runner_start_micros: entry.attach.runner_start_usec })
        || !['post_observation_sha256', 'q_wire_sha256', 'q_index_sha256', 'q_eof_receipt_sha256'].every(key => SHA256.test(payload[key] ?? ''))
        || !Number.isFinite(instant(payload.completed_at)) || instant(payload.completed_at) < instant(pre.issued_at)
        || instant(payload.completed_at) > now() || instant(payload.completed_at) >= instant(pre.expires_at)) invalid();
      return freezeJSON({ ...body, payload });
    },
    verifyDirectQualificationPre(result) {
      const payload = verifyDirectQualificationPre(result, Buffer.from(machinePublicKey, 'hex'));
      const fields = [...idFields, 'contract', 'kind', 'schema_version', 'hq_epoch', 'reservation_sha256',
        'attach_sha256', 'session_id', 'q_challenge_sha256', 'test_plan_sha256', 'pre_observation_sha256',
        'case_nonce_base64url', 'issued_at', 'expires_at'];
      const entry = active.get(payload.reservation_sha256);
      const issued = instant(payload.issued_at), expiry = instant(payload.expires_at);
      const nonce = payload.case_nonce_base64url;
      if (Object.keys(payload).sort().join(',') !== fields.sort().join(',')
        || !entry?.acp || entry.acp.destroyed || !watchHealthy(entry.acpContext)
        || !fieldsEqual(payload, entry.reservation.payload.assignment, [...idFields, 'hq_epoch'])
        || payload.attach_sha256 !== entry.attach.sha256
        || typeof payload.session_id !== 'string' || !/^[0-9a-f]{32}$/.test(payload.session_id)
        || ![payload.q_challenge_sha256, payload.test_plan_sha256, payload.pre_observation_sha256].every(v => SHA256.test(v ?? ''))
        || typeof nonce !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(nonce)
        || Buffer.from(nonce, 'base64url').toString('base64url') !== nonce
        || !Number.isFinite(issued) || !Number.isFinite(expiry) || issued > now()
        || expiry <= now() || expiry - issued > 120000) invalid();
      return Object.freeze(payload);
    },
    runnerPid: (reservation) => owned(reservation).attach?.runner_pid,
    async stop(reservation) {
      const entry = owned(reservation);
      revoke(reservation);
      await entry.attachPending?.catch(() => {});
      const request = requestOf(reservation);
      const operation = entry.attach ? 'stop' : 'abort';
      const response = await call(operation, request, entry);
      const payload = proof(response, operation);
      const common = { ...request, ...identityOf(reservation),
        runner_uid: reservation.payload.assignment.runner_uid, runner_uid_idle: true };
      const ended = instant(entry.attach ? payload.stopped_at : payload.aborted_at);
      if (!match(payload, common) || !SHA256.test(payload.cancel_sha256 ?? '')
        || !Number.isFinite(ended) || ended > now()
        || ended < instant(entry.attach?.attached_at ?? reservation.payload.issued_at)) invalid();
      if (entry.attach && (!match(payload, { attach_sha256: entry.attach.sha256,
        dispatcher_pid: entry.attach.dispatcher_pid, runner_pid: entry.attach.runner_pid })
        || !SHA256.test(payload.dispatch_completion_sha256 ?? ''))) invalid();
      if (entry.memberInputs && (typeof verifyBrokeredContainment !== 'function'
        || await verifyBrokeredContainment({ reservation, detachedBridge: entry.memberInputs.detached,
          runnerStop: response.body }) !== true)) invalid();
      active.delete(reservation.sha256);
      return Object.freeze({ sha256: response.body.sha256 });
    },
  });
}
