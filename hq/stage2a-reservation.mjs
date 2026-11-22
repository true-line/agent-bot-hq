// Provisional: not wired to launch or admission; replace with pinned contract.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { canonicalize } from '../sdk/wire/canonical-json.mjs';
import { parseStrict } from '../sdk/wire/strict-json.mjs';

const V1 = Object.freeze({ purpose: 'agent-bot/stage2a-reservation/v1', contract: 'machine/v1', schemaVersion: 1 });
const V2 = Object.freeze({ purpose: 'agent-bot/stage2a-reservation/v2', contract: 'machine/v2', schemaVersion: 2 });
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
async function verifyReservation(raw, { enrolledMachineKey, expected, clock, consume, validatePayload }, format) {
  if (!Buffer.isBuffer(raw) || raw.length > 65536 || !Buffer.isBuffer(enrolledMachineKey) || enrolledMachineKey.length !== 32 ||
      !expected || typeof consume !== 'function' || typeof clock !== 'function' || typeof validatePayload !== 'function') fail();
  const time = () => { const now = clock(); if (!(now instanceof Date) || !Number.isFinite(now.getTime())) fail(); return now.getTime(); };
  const e = parseCanonical(raw);
  if (!keysEqual(e, ['schema_version','purpose','issuer_public_key_base64url','payload_sha256','payload_base64url','signature_base64url']) ||
      e.schema_version !== 1 || e.purpose !== format.purpose) fail();
  const issuer = decode(e.issuer_public_key_base64url, 32);
  if (!issuer.equals(enrolledMachineKey)) fail();
  const payloadBytes = decode(e.payload_base64url);
  if (e.payload_sha256 !== sha(payloadBytes)) fail();
  const sig = decode(e.signature_base64url, 64);
  const key = createPublicKey({ key: Buffer.concat([Buffer.from('302a300506032b6570032100', 'hex'), issuer]), format: 'der', type: 'spki' });
  if (!verify(null, Buffer.concat([Buffer.from(format.purpose + '\0'), payloadBytes]), key, sig)) fail();
  const p = parseCanonical(payloadBytes);
  if (validatePayload(structuredClone(p)) !== true) fail();
  if (!keysEqual(p, ['contract','kind','schema_version','host_id','issued_at','expires_at','installed_plan_receipt_sha256','assignment','member_endpoint','measurement_binding','admission_challenge_sha256']) ||
      p.contract !== format.contract || p.kind !== 'stage2a-reservation' || p.schema_version !== format.schemaVersion ||
      typeof p.host_id !== 'string' || !p.host_id || !p.assignment || !p.member_endpoint || !p.measurement_binding) fail();
  // Compare complete nested structures, not caller-selected subsets.
  for (const field of ['host_id','assignment','member_endpoint','measurement_binding','installed_plan_receipt_sha256','admission_challenge_sha256']) {
    if (!Object.hasOwn(expected, field) || !same(p[field], expected[field])) fail();
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
  if (format === V2 && (m.contract !== V2.contract || m.schema_version !== 2
    || m.profile_in_force !== 'managed-protected'
    || !Number.isSafeInteger(a.machine_uid) || a.machine_uid <= 399
    || m.snapshots.definition.owner_uid !== a.machine_uid
    || m.snapshots.launch_inputs.owner_uid !== a.machine_uid)) fail();
  const issued = Date.parse(p.issued_at), expires = Date.parse(p.expires_at);
  if (typeof p.issued_at !== 'string' || typeof p.expires_at !== 'string' || !Number.isFinite(issued) || !Number.isFinite(expires) ||
      issued > time() || expires <= time() || expires <= issued || p.assignment.expires_at !== p.expires_at) fail();
  const reservationSHA256 = sha(raw);
  if (await consume({ issuer: e.issuer_public_key_base64url, installationId: p.assignment.installation_id,
    startId: p.assignment.start_id, reservationSHA256, expiresAt: p.expires_at }) !== true) fail();
  const afterConsume = time();
  if (issued > afterConsume || expires <= afterConsume) fail();
  return { payload: p, reservationSHA256 };
}

export const verifyStage2aReservation = (raw, options) => verifyReservation(raw, options, V1);
export const verifyStage2aReservationV2 = (raw, options) => verifyReservation(raw, options, V2);
