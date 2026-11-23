// Independent HQ verification for Machine's cooperative one-use reservation.
// This proof is separate from protected Stage 2a and never authorizes a
// protected claim. Machine's installed authority and durable spend remain the
// source of launch permission. v1 binds R's frozen package only; it does not
// attest to selected H/HQ/Comms/contracts code. Production needs a new signed
// purpose/version that binds A's H descriptor to HQ's startup-loaded digest,
// with A rechecking H bytes at launch. The R digest cannot substitute for it.
import { createHash, createPublicKey, verify } from 'node:crypto';
import { isAbsolute, join, normalize } from 'node:path';
import { canonicalize } from '../sdk/wire/canonical-json.mjs';
import { parseStrict } from '../sdk/wire/strict-json.mjs';

const PURPOSE = 'agent-bot/soul-cooperative-reservation/v1';
const SPKI = Buffer.from('302a300506032b6570032100', 'hex');
const ID = /^st_[0-9a-f]{24}$/;
const SOUL_ID = /^agent_[0-9a-f]{8}(-[0-9a-f]{4}){3}-[0-9a-f]{12}$/;
const HEX = /^[0-9a-f]{64}$/;
const INSTALLATION = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const PLAN_ID = /^plan-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{4}$/;
const UTC = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,9})?Z$/;
const fail = () => { throw new Error('invalid Machine cooperative reservation'); };
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const exact = (object, keys) => object && typeof object === 'object' && !Array.isArray(object)
  && Object.keys(object).length === keys.length && keys.every((key) => Object.hasOwn(object, key));
const absolute = (value) => typeof value === 'string' && value !== '/' && isAbsolute(value)
  && normalize(value) === value && Buffer.byteLength(value) <= 1024 && !/[\x00\r\n]/.test(value);
function decode(value, length) {
  if (typeof value !== 'string' || !/^[A-Za-z0-9_-]+$/.test(value)) fail();
  const bytes = Buffer.from(value, 'base64url');
  if (bytes.toString('base64url') !== value || (length !== undefined && bytes.length !== length)) fail();
  return bytes;
}
function canonicalPayload(bytes) {
  const text = new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  const value = parseStrict(text, { maxDepth: 16 });
  if (canonicalize(value) !== text) fail();
  return value;
}
function endpointFor(installationId, startId, hqUid, runnerUid, runnerGid) {
  const install = sha(`agent-bot-soul-endpoint-installation/v1\0${installationId}`).slice(0, 20);
  const start = sha(`agent-bot-soul-endpoint-start/v1\0${installationId}\0${startId}`).slice(0, 20);
  const directory = join('/Library/Application Support/ai.true-line.agent-bot-hq', 'c', install);
  const socketPath = join(directory, `${start}.sock`);
  if (Buffer.byteLength(socketPath) > 103) fail();
  return { directory, socket_path: socketPath, owner_uid: hqUid, group_gid: runnerGid,
    dir_mode: 0o2750, socket_mode: 0o660, peer_uid: runnerUid };
}
function packageRootFor(installationId) {
  const install = sha(`agent-bot-soul-endpoint-installation/v1\0${installationId}`).slice(0, 20);
  return join('/Library/Application Support/ai.true-line.agent-bot-hq', 'cooperative-artifacts', `${install}.soul`);
}

// The key and host ID must come from the pinned paired Machine channel, not
// from this envelope. The request is HQ's original owner-selected start.
export function verifyCooperativeReservation(signed, { machinePublicKey, hostId, request,
  hqUid, now = () => Date.now() } = {}) {
  if (!exact(signed, ['purpose', 'payload_base64url', 'payload_sha256', 'signature_base64url'])
    || signed.purpose !== PURPOSE || !Buffer.isBuffer(machinePublicKey)
    || machinePublicKey.length !== 32 || !INSTALLATION.test(hostId ?? '')
    || !request || !ID.test(request.startId ?? '')
    || !absolute(request.packagePath)
    || !HEX.test(request.hqEpoch ?? '') || !Number.isSafeInteger(hqUid)
    || hqUid < 300 || hqUid > 399 || typeof now !== 'function') fail();
  const payloadBytes = decode(signed.payload_base64url);
  if (payloadBytes.length > 8192 || !HEX.test(signed.payload_sha256 ?? '')
    || sha(payloadBytes) !== signed.payload_sha256) fail();
  const signature = decode(signed.signature_base64url, 64);
  const key = createPublicKey({ key: Buffer.concat([SPKI, machinePublicKey]), format: 'der', type: 'spki' });
  if (!verify(null, Buffer.concat([Buffer.from(PURPOSE + '\0'), payloadBytes]), key, signature)) fail();
  const p = canonicalPayload(payloadBytes);
  if (!exact(p, ['purpose', 'profile_in_force', 'host_id', 'plan_id', 'plan_digest',
    'installed_receipt_sha256', 'installation_id', 'soul_id', 'start_id', 'hq_epoch',
    'runner_uid', 'runner_gid', 'source_package_path', 'package_root', 'package_sha256',
    'soul_artifact_sha256', 'definition_sha256', 'node_path', 'node_sha256', 'entry',
    'launcher_path', 'launcher_sha256', 'endpoint', 'issued_at', 'expires_at'])
    || p.purpose !== PURPOSE || p.profile_in_force !== 'managed-cooperative'
    || p.host_id !== hostId || p.start_id !== request.startId
    || p.source_package_path !== request.packagePath || p.hq_epoch !== request.hqEpoch
    || !INSTALLATION.test(p.installation_id ?? '') || !SOUL_ID.test(p.soul_id ?? '')
    || !PLAN_ID.test(p.plan_id ?? '')
    || !HEX.test(p.plan_digest ?? '') || !HEX.test(p.installed_receipt_sha256 ?? '')
    || !HEX.test(p.package_sha256 ?? '') || !HEX.test(p.soul_artifact_sha256 ?? '')
    || !HEX.test(p.definition_sha256 ?? '') || !HEX.test(p.node_sha256 ?? '')
    || !HEX.test(p.launcher_sha256 ?? '') || !Number.isSafeInteger(p.runner_uid)
    || p.runner_uid < 300 || p.runner_uid > 399 || p.runner_uid === hqUid
    || p.runner_gid !== p.runner_uid || !absolute(p.source_package_path)
    || !absolute(p.package_root) || p.package_root !== packageRootFor(p.installation_id)
    || p.package_root === p.source_package_path
    || !absolute(p.node_path) || !absolute(p.launcher_path)
    || typeof p.entry !== 'string' || !p.entry || p.entry === '.'
    || p.entry === '..' || p.entry.startsWith('../') || isAbsolute(p.entry)
    || normalize(p.entry) !== p.entry || Buffer.byteLength(p.entry) > 1024
    || /[\x00\r\n]/.test(p.entry)) fail();
  const expectedEndpoint = endpointFor(p.installation_id, p.start_id, hqUid, p.runner_uid, p.runner_gid);
  if (!exact(p.endpoint, Object.keys(expectedEndpoint))
    || canonicalize(p.endpoint) !== canonicalize(expectedEndpoint)) fail();
  const issued = Date.parse(p.issued_at), expires = Date.parse(p.expires_at);
  const time = now();
  if (!UTC.test(p.issued_at ?? '') || !UTC.test(p.expires_at ?? '')
    || !Number.isFinite(issued) || !Number.isFinite(expires) || !Number.isSafeInteger(time)
    || expires <= issued || expires - issued > 30000 || issued > time || expires <= time) fail();
  return Object.freeze({ payload: p, sha256: sha(payloadBytes),
    startId: p.start_id, packagePath: p.source_package_path, hqEpoch: p.hq_epoch,
    uid: p.runner_uid, gid: p.runner_gid, soulId: p.soul_id,
    installationId: p.installation_id, definitionDigest: `sha256:${p.definition_sha256}`,
    packageDigest: p.package_sha256, runnerPackagePath: p.package_root,
    endpoint: Object.freeze({ directory: p.endpoint.directory, socketPath: p.endpoint.socket_path,
      ownerUid: p.endpoint.owner_uid, groupGid: p.endpoint.group_gid,
      dirMode: p.endpoint.dir_mode, socketMode: p.endpoint.socket_mode,
      peerUid: p.endpoint.peer_uid }) });
}
