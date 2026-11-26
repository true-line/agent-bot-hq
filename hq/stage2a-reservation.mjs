// Signed Machine reservation verification. The envelope check can be repeated
// during admission; only the first start consumes the one-use claim.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { canonicalize } from '../sdk/wire/canonical-json.mjs';
import { parseStrict } from '../sdk/wire/strict-json.mjs';
import { authenticatedSelectedH } from './stage2a-h-preloader.mjs';

const V1 = Object.freeze({ purpose: 'agent-bot/stage2a-reservation/v1', contract: 'machine/v1', schemaVersion: 1 });
const V2 = Object.freeze({ purpose: 'agent-bot/stage2a-reservation/v2', contract: 'machine/v2', schemaVersion: 2 });
const V3 = Object.freeze({ purpose: 'agent-bot/stage2a-reservation/v3', contract: 'machine/v3', schemaVersion: 3 });
const CANDIDATE_V3 = Object.freeze({ purpose: 'agent-bot/stage2a-qualification-candidate-reservation/v3',
  contract: 'machine/v3', schemaVersion: 3, kind: 'stage2a-qualification-candidate-reservation' });
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const sha = bytes => `sha256:${createHash('sha256').update(bytes).digest('hex')}`;
const fail = () => { throw new Error('invalid Stage 2a reservation'); };
const same = (a, b) => canonicalize(a) === canonicalize(b);
function decode(s, length) {
  if (typeof s !== 'string' || !/^[A-Za-z0-9_-]+$/.test(s)) fail();
  const b = Buffer.from(s, 'base64url');
  if (b.toString('base64url') !== s || (length !== undefined && b.length !== length)) fail();
  return b;
}
function parseCanonical(bytes) {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const value = parseStrict(text, { maxDepth: 32 });
  if (canonicalize(value) !== text) fail();
  return value;
}
const keysEqual = (o, keys) => o && typeof o === 'object' && !Array.isArray(o) && same(Object.keys(o).sort(), keys.sort());

// Expected values must come from independently trusted local state. consume is
// an atomic, durable check-and-mark callback, scoped to issuer/installation/start;
// it must resolve true only once, and throw or return anything else on failure.
// validatePayload must synchronously validate the complete payload against the
// pinned contract schema; it must return true only for valid payloads.
// clock must read trusted current time on every call. A reservation consumed
// before expiry but expired while consuming is refused and remains consumed.
async function verifyReservation(raw, { enrolledMachineKey, expected, clock, consume, validatePayload }, format,
  { consumeClaim = true } = {}) {
  if (!Buffer.isBuffer(raw) || raw.length > 65536 || !Buffer.isBuffer(enrolledMachineKey) || enrolledMachineKey.length !== 32 ||
      (consumeClaim && (!expected || typeof consume !== 'function' || typeof clock !== 'function'))
      || typeof validatePayload !== 'function') fail();
  const time = () => { const now = clock(); if (!(now instanceof Date) || !Number.isFinite(now.getTime())) fail(); return now.getTime(); };
  const e = parseCanonical(raw);
  if (!keysEqual(e, ['schema_version','purpose','issuer_public_key_base64url','payload_sha256','payload_base64url','signature_base64url']) ||
      e.schema_version !== format.schemaVersion || e.purpose !== format.purpose) fail();
  const issuer = decode(e.issuer_public_key_base64url, 32);
  if (!issuer.equals(enrolledMachineKey)) fail();
  const payloadBytes = decode(e.payload_base64url);
  if (e.payload_sha256 !== sha(payloadBytes)) fail();
  const sig = decode(e.signature_base64url, 64);
  const key = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), issuer]), format: 'der', type: 'spki' });
  if (!verify(null, Buffer.concat([Buffer.from(format.purpose + '\0'), payloadBytes]), key, sig)) fail();
  const p = parseCanonical(payloadBytes);
  if (validatePayload(structuredClone(p)) !== true) fail();
  if (!keysEqual(p, ['contract','kind','schema_version','host_id','issued_at','expires_at','installed_plan_receipt_sha256','assignment','member_endpoint','measurement_binding','admission_challenge_sha256',
      ...(format === CANDIDATE_V3 ? ['qualification_attempt'] : [])]) ||
      p.contract !== format.contract || p.kind !== (format.kind ?? 'stage2a-reservation') || p.schema_version !== format.schemaVersion ||
      typeof p.host_id !== 'string' || !p.host_id || !p.assignment || !p.member_endpoint || !p.measurement_binding) fail();
  // Compare complete nested structures, not caller-selected subsets.
  if (expected) {
    for (const field of ['host_id','assignment','member_endpoint','measurement_binding','installed_plan_receipt_sha256','admission_challenge_sha256']) {
      if (!Object.hasOwn(expected, field) || !same(p[field], expected[field])) fail();
    }
  }
  for (const field of ['start_id','launch_id','hq_epoch','plan_id','plan_digest','installation_id']) {
    if (typeof p.assignment[field] !== 'string' || !p.assignment[field]) fail();
  }
  // Cross-field checks from the provisional contracts oracle. Schema
  // validation against the pinned contracts is still required at integration.
  const a = p.assignment, m = p.measurement_binding, ep = a.member, member = p.member_endpoint;
  for (const [ak, mk] of [['installation_id','installation_id'], ['soul_id','soul_id'], ['start_id','start_id'],
    ['launch_id','launch_id'], ['plan_id','plan_id'], ['plan_digest','installed_plan_digest'], ['hq_epoch','hq_epoch'],
    ['package_sha256','package_sha256'], ['soul_artifact_sha256','soul_artifact_sha256']]) {
    if (typeof a[ak] !== 'string' || !a[ak] || a[ak] !== m[mk]) fail();
  }
  if (p.host_id !== m.host_id || !m.snapshots || !m.snapshots.definition || !m.snapshots.launch_inputs ||
      !Number.isSafeInteger(a.runner_gid) || m.snapshots.definition.owner_gid !== a.runner_gid ||
      m.snapshots.launch_inputs.owner_gid !== a.runner_gid || !ep || typeof ep !== 'object' || Array.isArray(ep)) fail();
  const { socket_path, ...endpoint } = ep;
  if (typeof socket_path !== 'string' || !socket_path || member.member_socket !== socket_path ||
      !same(member.member_endpoint, endpoint)) fail();
  const protectedFormat = format !== V1;
  if (protectedFormat && (m.contract !== format.contract || m.schema_version !== format.schemaVersion
    || m.profile_in_force !== 'managed-protected'
    || !Number.isSafeInteger(a.machine_uid) || a.machine_uid <= 399
    || m.snapshots.definition.owner_uid !== a.machine_uid
    || m.snapshots.launch_inputs.owner_uid !== a.machine_uid)) fail();
  if (protectedFormat) {
    const slot = createHash('sha256').update(`agent-bot-soul-endpoint-installation/v1\0${a.installation_id}`)
      .digest('hex').slice(0, 20);
    const namespace = `/private/var/db/managed-machine/soul-snapshots/${slot}/snap_`;
    const roots = [m.snapshots.definition.root_path, m.snapshots.launch_inputs.root_path];
    if (roots[0] === roots[1] || roots.includes(a.package_root)
      || roots.some((root) => typeof root !== 'string' || !root.startsWith(namespace)
        || root.length !== namespace.length + 24)) fail();
  }
  const issued = Date.parse(p.issued_at), expires = Date.parse(p.expires_at);
  if (typeof p.issued_at !== 'string' || typeof p.expires_at !== 'string' || !Number.isFinite(issued) || !Number.isFinite(expires) ||
      expires <= issued || (protectedFormat && expires - issued > 30000)
      || p.assignment.expires_at !== p.expires_at) fail();
  const reservationSHA256 = sha(raw);
  if (!consumeClaim) return { payload: p, reservationSHA256 };
  if (issued > time() || expires <= time()) fail();
  if (await consume({ issuer: e.issuer_public_key_base64url, installationId: p.assignment.installation_id,
    startId: p.assignment.start_id, reservationSHA256, expiresAt: p.expires_at }) !== true) fail();
  const afterConsume = time();
  if (issued > afterConsume || expires <= afterConsume) fail();
  return { payload: p, reservationSHA256 };
}

export const verifyStage2aReservation = (raw, options) => verifyReservation(raw, options, V1);
export const verifyStage2aReservationV2 = (raw, options) => verifyReservation(raw, options, V2);
// This never marks a claim used. Callers must compare the complete signed
// projection with installed Machine state and require a fresh signed Machine
// live response at every bind phase. An expired reservation is still
// authenticated so that Machine can renew the finalized live lease.
export const inspectStage2aReservationV2 = (raw, options) =>
  verifyReservation(raw, options, V2, { consumeClaim: false });

// Machine spends the durable claim before it issues this reservation. This
// checks the fresh response; the caller must also match its issued start and
// installed plan before admitting B or R.
export async function verifyStage2aReservationV3(raw, { enrolledMachineKey, selectedH,
  expected, validatePayload, reservationSHA256, clock = () => new Date() } = {}) {
  if (!Buffer.isBuffer(enrolledMachineKey) || enrolledMachineKey.length !== 32
    || typeof selectedH?.descriptorDigest !== 'string' || !DIGEST.test(selectedH.descriptorDigest)
    || selectedH.machinePublicKey !== enrolledMachineKey.toString('hex')
    || typeof clock !== 'function') fail();
  const { descriptorDigest } = selectedH;
  const checked = await verifyReservation(raw, { enrolledMachineKey, expected, validatePayload },
    V3, { consumeClaim: false });
  const { payload } = checked;
  const now = clock();
  if (checked.reservationSHA256 !== reservationSHA256
    || payload.assignment.h_service_descriptor_digest !== descriptorDigest
    || payload.measurement_binding.h_service_descriptor_digest !== descriptorDigest
    || !(now instanceof Date) || !Number.isFinite(now.getTime())
    || now.getTime() < Date.parse(payload.issued_at) || now.getTime() >= Date.parse(payload.expires_at)) fail();
  return checked;
}

// The protected-start caller gets H only from the authenticated preloader.
export const verifyStage2aProtectedReservationV3 = (raw, options) =>
  verifyStage2aReservationV3(raw, { ...options, selectedH: authenticatedSelectedH() });


// The first-run candidate has its own released purpose and complete payload
// schema. It cannot enter the certified V3 route or a legacy V2 route.
export async function verifyStage2aCandidateReservationV3(raw, { enrolledMachineKey, selectedH,
  installed, validatePayload, reservationSHA256, now = Date.now } = {}) {
  if (!Buffer.isBuffer(enrolledMachineKey) || enrolledMachineKey.length !== 32
    || !DIGEST.test(selectedH?.descriptorDigest ?? '')
    || selectedH.machinePublicKey !== enrolledMachineKey.toString('hex')
    || !installed || selectedH.hostId !== installed.host_id || typeof now !== 'function') fail();
  const checked = await verifyReservation(raw, { enrolledMachineKey, validatePayload },
    CANDIDATE_V3, { consumeClaim: false });
  const { payload } = checked;
  const { assignment, measurement_binding: binding } = payload;
  if (payload.host_id !== installed.host_id || payload.installed_plan_receipt_sha256 !== installed.root_receipt_sha256
    || ['installation_id', 'plan_id', 'plan_digest', 'hq_epoch'].some(field => assignment[field] !== installed[field])
    || assignment.h_service_descriptor_digest !== selectedH.descriptorDigest
    || binding.h_service_descriptor_digest !== selectedH.descriptorDigest
    || assignment.r_inventory_digest !== binding.r_inventory.inventory_digest) fail();
  // Initial starts supply the digest returned by Machine Reserve. Live B
  // reinspection instead uses A's renewed signed live proof.
  if (reservationSHA256 !== undefined) {
    const current = now();
    if (checked.reservationSHA256 !== reservationSHA256 || !Number.isSafeInteger(current)
      || current < Date.parse(payload.issued_at) || current >= Date.parse(payload.expires_at)) fail();
  }
  return checked;
}

export const verifyStage2aProtectedCandidateReservationV3 = (raw, options) =>
  verifyStage2aCandidateReservationV3(raw, { ...options, selectedH: authenticatedSelectedH() });
