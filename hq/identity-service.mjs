// HQ's identity-service link (plan §4.7 / row 10). Device assertions stay
// with enrollment's signer. Access tokens and their ephemeral DPoP keys live
// only in this process; replies are authenticated before JSON is parsed.
import { createHash, createPublicKey, randomBytes, verify } from 'node:crypto';
import { isUtf8 } from 'node:buffer';
import { readFileSync } from 'node:fs';
import { parseStrict } from '../sdk/wire/strict-json.mjs';
import { fail, HostError } from '../sdk/errors.mjs';
import { GRANT_JWT_BEARER, validateServiceUrl } from './enrollment.mjs';

const TIMEOUT_MS = 20_000;
const MAX_BODY_BYTES = 1024 * 1024;
const MAX_SKEW_MS = 5 * 60_000;
const WHOAMI_PROOF_WINDOW_SECONDS = 60;
const WHOAMI = '/api/daemon/whoami';
const ISSUANCE_LOOKUP = '/api/daemon/issuances/';
const B64URL = /^[A-Za-z0-9_-]+$/;
const nonce = () => randomBytes(24).toString('base64url');
const hash = (bytes) => createHash('sha256').update(bytes).digest();
const TRANSIENT = Symbol('identity-service transient outage');
const unavailable = (reason, transient = false) => {
  const error = new HostError('credential_unavailable', `identity service: ${reason}`);
  if (transient) error[TRANSIENT] = true;
  throw error;
};
function proofSegment(segment) {
  const bytes = Buffer.from(segment, 'base64url');
  if (bytes.toString('base64url') !== segment || !isUtf8(bytes)) throw new Error();
  return parseStrict(bytes.toString());
}
const ownObject = (v) => v && typeof v === 'object' && !Array.isArray(v);
function dateMillis(value) {
  if (typeof value !== 'string') return NaN;
  const parts = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2}):(\d{2})(?:\.\d+)?(?:Z|[+-](?:[01]\d|2[0-3]):[0-5]\d)$/.exec(value);
  if (!parts) return NaN;
  const [, y, m, d, h, min, sec] = parts.map(Number);
  const days = new Date(Date.UTC(y, m, 0)).getUTCDate();
  return m >= 1 && m <= 12 && d >= 1 && d <= days && h < 24 && min < 60 && sec < 60 ? Date.parse(value) : NaN;
}

// Issuance reconciliation is a read of one operation. Its ID is a single
// path segment using the credential service's operation-ID alphabet.
function validDaemonPath(method, path) {
  if (typeof path !== 'string') return false;
  if (path.startsWith(ISSUANCE_LOOKUP)) {
    return method === 'GET' && /^\/api\/daemon\/issuances\/[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(path);
  }
  return /^\/api\/daemon\/[A-Za-z0-9/_-]+$/.test(path);
}

export function signatureBytes(status, text, jti) {
  return Buffer.from(`agent-bot-sig-v1\n${status}\n${hash(text).toString('hex')}\n${jti}`);
}

// A release pin, never populated by fetching the service on first use. The
// public manifest's dates are operator-provided evidence, not guessed TTLs.
export function validateServerKeys(manifest, server) {
  if (!ownObject(manifest) || Object.keys(manifest).some((k) => !['server', 'keys'].includes(k))
    || manifest.server !== server || !Array.isArray(manifest.keys)) throw new TypeError('server-keys.json names this service and a keys array');
  const seen = new Set(), publicKeys = new Set();
  return Object.freeze(manifest.keys.map((k) => {
    if (!ownObject(k) || Object.keys(k).some((name) => !['kid', 'x', 'notBefore', 'notAfter', 'status'].includes(name))) throw new TypeError('a server key has only kid, x, notBefore, notAfter and status');
    if (typeof k.kid !== 'string' || !B64URL.test(k.kid) || k.kid.length > 128 || seen.has(k.kid)) throw new TypeError('server key ids are unique base64url strings');
    if (typeof k.x !== 'string' || !B64URL.test(k.x) || Buffer.from(k.x, 'base64url').length !== 32 || Buffer.from(k.x, 'base64url').toString('base64url') !== k.x) throw new TypeError('a server key is an Ed25519 public key');
    if (!['active', 'next', 'retired'].includes(k.status)) throw new TypeError('a server key is active, next or retired');
    const before = dateMillis(k.notBefore), after = dateMillis(k.notAfter);
    if (typeof k.notBefore !== 'string' || typeof k.notAfter !== 'string' || !Number.isFinite(before) || !Number.isFinite(after) || before >= after) throw new TypeError('a server key has an ordered validity interval');
    createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: k.x }, format: 'jwk' });
    if (publicKeys.has(k.x)) throw new TypeError('a server public key has exactly one key id and lifecycle record');
    seen.add(k.kid);
    publicKeys.add(k.x);
    return Object.freeze({ ...k });
  }));
}

export function releaseServerKeys(server, file = new URL('../governance/server-keys.json', import.meta.url)) {
  const manifest = JSON.parse(readFileSync(file, 'utf8'));
  const keys = validateServerKeys(manifest, manifest.server);
  return manifest.server === server ? keys : [];
}

export function createIdentityService({
  server,
  enrollment,
  custody,
  keySet = releaseServerKeys(server),
  fetchImpl = globalThis.fetch,
  clock = { now: () => Date.now() },
  timeoutMs = TIMEOUT_MS,
  maxBodyBytes = MAX_BODY_BYTES,
} = {}) {
  validateServiceUrl(server);
  if (!enrollment || typeof enrollment.deviceStatus !== 'function') throw new TypeError('the identity-service link needs HQ enrollment');
  keySet = validateServerKeys({ server, keys: keySet }, server);
  if (!(Number.isSafeInteger(timeoutMs) && timeoutMs > 0 && timeoutMs <= MAX_SKEW_MS)) throw new TypeError('identity-service timeout is at most five minutes');
  if (!(Number.isSafeInteger(maxBodyBytes) && maxBodyBytes > 0 && maxBodyBytes <= MAX_BODY_BYTES)) throw new TypeError('identity-service body cap is at most one MiB');
  let token;
  let refreshing;
  let epoch = 0;
  let closed = false;
  let revoked = false;
  let revocationListenerFailed = false;
  let revocationPersistenceFailed = false;
  let link = 'not-checked';
  const listeners = new Set();
  const requests = new Set();

  const check = () => {
    if (revoked) fail('device_revoked', 'device revoked: re-enroll');
    if (closed) fail('host.context_revoked', 'the identity-service link is closed');
    const now = clock.now();
    if (!keySet.some((k) => k.status !== 'retired' && Date.parse(k.notBefore) <= now && now < Date.parse(k.notAfter))) unavailable('no current release-pinned response-signing key');
  };
  const drop = () => { token = undefined; epoch += 1; };
  const revoke = () => {
    if (revoked) return;
    revoked = true;
    drop();
    // Revocation is effective in memory even if an observer or the local
    // enrollment store fails. Every listener gets its own attempt, before
    // persistence, so a disk error cannot leave HQ's SDK credentials live.
    const attempt = (fn, failed) => {
      try { Promise.resolve(fn()).catch(failed); } catch { failed(); }
    };
    for (const listener of listeners) attempt(listener, () => { revocationListenerFailed = true; });
    attempt(() => enrollment.markRevoked?.('device_revoked'), () => { revocationPersistenceFailed = true; });
  };
  const alive = (generation) => {
    check();
    if (epoch !== generation) fail('host.context_revoked', 'identity credentials were dropped while the request was in flight');
  };
  const freshAccess = (current) => {
    if (current.expiresAt <= clock.now()) {
      if (token === current) token = undefined;
      unavailable('access token expired before the daemon request');
    }
  };

  // Includes reading the response body in the deadline. A fetch that resolves
  // its headers but never ends its body must not hold a credential operation.
  async function request(path, init, jti, accessToken) {
    check();
    const started = clock.now();
    const generation = epoch;
    const controller = new AbortController();
    requests.add(controller);
    let timer;
    const deadline = new Promise((_, reject) => {
      timer = setTimeout(() => { controller.abort(); reject(new Error('deadline')); }, timeoutMs);
    });
    try {
      const work = (async () => {
        if (accessToken) freshAccess(accessToken);
        const response = await fetchImpl(`${server}${path}`, { ...init, redirect: 'error', signal: controller.signal });
        if (response.status >= 300 && response.status < 400) unavailable('redirect refused');
        const declared = response.headers.get('content-length');
        if (declared && Number(declared) > maxBodyBytes) unavailable('response exceeds the body cap');
        let bytes;
        if (response.body?.getReader) {
          const reader = response.body.getReader();
          const cancel = () => { reader.cancel().catch(() => {}); };
          controller.signal.addEventListener('abort', cancel, { once: true });
          const parts = [];
          let size = 0;
          try {
            for (;;) {
              const { value, done } = await reader.read();
              if (done) break;
              size += value.byteLength;
              if (size > maxBodyBytes) { controller.abort(); unavailable('response exceeds the body cap'); }
              parts.push(Buffer.from(value));
            }
          } finally { controller.signal.removeEventListener('abort', cancel); reader.releaseLock(); }
          bytes = Buffer.concat(parts);
        } else {
          bytes = Buffer.from(await response.arrayBuffer());
          if (bytes.length > maxBodyBytes) unavailable('response exceeds the body cap');
        }
        alive(generation);
        if (controller.signal.aborted) unavailable('request failed or timed out');
        const now = clock.now();
        if (now < started || now - started > MAX_SKEW_MS) unavailable('response is outside the request freshness window');
        const kid = response.headers.get('agent-bot-key-id');
        const key = keySet.find((k) => k.kid === kid);
        if (!key || key.status === 'retired' || now < Date.parse(key.notBefore) || now >= Date.parse(key.notAfter)) unavailable('unknown, retired or out-of-window response-signing key');
        const signature = response.headers.get('agent-bot-signature');
        if (response.headers.get('agent-bot-request-jti') !== jti || typeof signature !== 'string' || !B64URL.test(signature)
          || Buffer.from(signature, 'base64url').length !== 64
          || !verify(null, signatureBytes(response.status, bytes, jti), createPublicKey({ key: { kty: 'OKP', crv: 'Ed25519', x: key.x }, format: 'jwk' }), Buffer.from(signature, 'base64url'))) unavailable('response signature or request nonce did not verify');
        if (!isUtf8(bytes)) unavailable('authenticated response is not UTF-8 JSON');
        let body;
        try { body = JSON.parse(bytes.toString('utf8')); } catch { unavailable('authenticated response is not JSON'); }
        if (path === WHOAMI && response.status === 200 && body?.device?.id !== accessToken.deviceId) {
          unavailable('identity lookup returned a different or missing device');
        }
        link = 'ok';
        // The token endpoint also uses invalid_grant for an expired or replayed assertion.
        const grantRevoked = path === '/oauth/token' && response.status === 400
          && body?.error === 'invalid_grant' && body.error_description === 'device_revoked';
        if (grantRevoked || body?.error === 'device_revoked') { revoke(); fail('device_revoked', 'device revoked: re-enroll'); }
        if (body?.error === 'profile_insufficient') fail('profile_insufficient', 'the identity service refused this device key storage under owner policy');
        if (response.status === 200 && path.startsWith(ISSUANCE_LOOKUP) && body?.operation_id !== path.slice(ISSUANCE_LOOKUP.length)) {
          unavailable('issuance reply does not match the requested operation');
        }
        return { status: response.status, headers: Object.fromEntries(response.headers.entries()), text: bytes.toString('utf8'), body };
      })();
      return await Promise.race([work, deadline]);
    } catch (e) {
      if (e?.code === 'device_revoked' || e?.code === 'host.context_revoked' || e?.code === 'profile_insufficient') throw e;
      link = 'unreachable';
      // No raw server body, URL, request, token or arbitrary exception text
      // crosses into logs, receipts or owner diagnostics.
      if (e?.code === 'credential_unavailable') throw e;
      unavailable('request failed or timed out', true);
    } finally {
      clearTimeout(timer);
      requests.delete(controller);
      controller.abort();
    }
  }

  async function reuseAccess(current, generation) {
    await withCustodyCheck(() => current.recheck?.());
    alive(generation);
    freshAccess(current);
    return current;
  }

  async function withCustodyCheck(operation) {
    const previous = token;
    try { return await operation(); }
    catch (error) {
      if (previous?.recheck && token === previous) token = undefined;
      throw error;
    }
  }

  async function access() {
    check();
    // Never reuse a token after the Machine signer has observed custody loss.
    if (token?.recheck && custody?.available?.() === false) token = undefined;
    await withCustodyCheck(async () => {
      let state;
      const refreshCustody = typeof custody?.deviceStatus === 'function';
      try { state = await (refreshCustody ? custody.deviceStatus() : enrollment.deviceStatus()); }
      catch (error) {
        if ((refreshCustody || token?.recheck) && !(error instanceof HostError)) unavailable('Machine enrollment could not be verified');
        throw error;
      }
      check(); // A late status cannot mutate revocation state after closure.
      if (state === 'revoked') { revoke(); fail('device_revoked', 'device revoked: re-enroll'); }
      if (state !== 'enrolled') unavailable('HQ is not enrolled');
    });
    check(); // Closing or revoking during the asynchronous custody check cancels this call.
    if (token && token.expiresAt <= clock.now()) token = undefined;
    if (token && token.expiresAt > clock.now() + 60_000) return reuseAccess(token, epoch);
    if (refreshing) return refreshing;
    const generation = epoch;
    const pending = (async () => {
      const started = clock.now();
      if (!custody) unavailable('Machine has no authorized DPoP session');
      const { session, ephemeralJwk, assertion } = await withCustodyCheck(() => custody.openSession());
      alive(generation);
      let claims;
      try { claims = JSON.parse(Buffer.from(assertion.split('.')[1], 'base64url')); } catch { unavailable('HQ assertion is malformed'); }
      if (typeof claims.jti !== 'string' || claims.jti.length < 8) unavailable('HQ assertion has no request nonce');
      const out = await request('/oauth/token', {
        method: 'POST', headers: { accept: 'application/json', 'content-type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ grant_type: GRANT_JWT_BEARER, assertion }).toString(),
      }, claims.jti);
      alive(generation);
      const result = out.body;
      if (out.status >= 500) unavailable('access token service is temporarily unavailable', true);
      if (out.status !== 200 || result?.token_type !== 'DPoP' || typeof result.access_token !== 'string' || !result.access_token
        || !Number.isSafeInteger(result.expires_in) || result.expires_in <= 0 || result.expires_in > 900) unavailable('access token was refused or malformed');
      const binding = await withCustodyCheck(() => custody.bindAccess({ session, body: out.text, headers: out.headers }));
      alive(generation);
      if (!Number.isSafeInteger(binding.expiresAt) || binding.expiresAt <= clock.now()) unavailable('administrator access session expired');
      const deviceId = typeof claims.iss === 'string' && claims.iss.length > 0 && claims.iss.length <= 256
        && claims.sub === claims.iss ? claims.iss : undefined;
      const candidate = { deviceId, recheck: binding.recheck, proveWhoami: binding.proveWhoami, value: result.access_token, expiresAt: Math.min(started + result.expires_in * 1000, binding.expiresAt), session, publicJwk: ephemeralJwk, harnesses: Array.isArray(result.harnesses) ? result.harnesses.filter((h) => typeof h === 'string') : [] };
      // expires_in is measured conservatively from the request's start.
      // A slow but authenticated response must not cache an expired token.
      freshAccess(candidate);
      token = candidate;
      return token;
    })().catch((e) => {
      // Share the fallback with every concurrent waiter, as well as the
      // refresh itself. Revocation and owner-policy refusals never use it.
      if (e?.[TRANSIENT] && !closed && !revoked && token?.expiresAt > clock.now()) return reuseAccess(token, generation);
      throw e;
    });
    refreshing = pending;
    try { return await pending; } finally { if (refreshing === pending) refreshing = undefined; }
  }

  return {
    keySet,
    get link() { return link; },
    check,
    onRevoke(listener) { listeners.add(listener); },
    status: () => ({ link, revoked, releasePinned: true, trustedKeys: keySet.length, tokenCached: Boolean(token), revocationListenerFailed, revocationPersistenceFailed }),
    async call(method, path, body) {
      check();
      if (typeof method !== 'string' || !/^(GET|POST|PUT|PATCH|DELETE)$/.test(method)
        || !validDaemonPath(method, path)) fail('host.invalid_request', 'the identity link accepts a daemon API method and path only');
      if (path === WHOAMI && (method !== 'GET' || body !== undefined)) fail('host.invalid_request', 'identity lookup requires GET without a body');
      if (path.startsWith(ISSUANCE_LOOKUP) && body !== undefined) fail('host.invalid_request', 'an issuance lookup accepts only its operation ID');
      const allowed = method === 'GET' && (path === WHOAMI || path === '/api/daemon/notices' || path.startsWith(ISSUANCE_LOOKUP))
        || method === 'POST' && ['/api/daemon/notices/take', '/api/daemon/notices/ack', '/api/daemon/notices/release'].includes(path);
      if (!allowed) unavailable('this route requires administrator-side credential use');
      custody?.checkOperation?.(method, path);
      const current = await access();
      const generation = epoch;
      alive(generation);
      freshAccess(current);
      if (path === WHOAMI && !current.deviceId) unavailable('identity lookup requires an assertion for one enrolled device');
      // Notices are scoped twice: the owner selects queues, and HQ refuses
      // a queue outside this enrolled device's current scope before sending.
      if (body?.harness !== undefined && !current.harnesses.includes(body.harness)) fail('host.route_not_allowed', 'the harness is outside this device enrollment');
      const machineWhoami = path === WHOAMI && typeof current.proveWhoami === 'function';
      // For this purpose keyd chooses its own nonce. HQ supplies only the session selector.
      let jti = machineWhoami ? undefined : nonce();
      const ath = hash(current.value).toString('base64url');
      const proof = machineWhoami ? await withCustodyCheck(() => current.proveWhoami())
        : await custody.requestProof({ session: current.session, method, path, body, ath, jti });
      const parts = typeof proof === 'string' && proof.split('.');
      let header, claims;
      try {
        if (!parts || parts.length !== 3) throw new Error();
        header = proofSegment(parts[0]);
        claims = proofSegment(parts[1]);
        const now = clock.now() / 1000;
        if (machineWhoami) {
          if (Object.keys(header).length !== 3 || Object.keys(header.jwk).length !== 4 || Object.keys(claims).length !== 5
            || typeof claims.jti !== 'string' || !/^[a-zA-Z0-9_-]{22}$/.test(claims.jti)
            || Buffer.from(claims.jti, 'base64url').toString('base64url') !== claims.jti
            || Buffer.from(parts[2], 'base64url').toString('base64url') !== parts[2]) throw new Error();
          jti = claims.jti;
        }
        if (header.alg !== 'ES256' || header.typ !== 'dpop+jwt' || !header.jwk || 'd' in header.jwk
          || header.jwk.kty !== 'EC' || header.jwk.crv !== 'P-256' || header.jwk.x !== current.publicJwk.x || header.jwk.y !== current.publicJwk.y
          || claims.htm !== method || claims.htu !== server + path || claims.ath !== ath || claims.jti !== jti
          || !Number.isSafeInteger(claims.iat) || Math.abs(now - claims.iat) > (machineWhoami ? WHOAMI_PROOF_WINDOW_SECONDS : 120)
          || !verify('sha256', Buffer.from(parts.slice(0, 2).join('.')), { key: createPublicKey({ key: current.publicJwk, format: 'jwk' }),
            dsaEncoding: 'ieee-p1363' }, Buffer.from(parts[2], 'base64url'))) throw new Error();
      } catch { unavailable('Machine returned an invalid DPoP request proof'); }
      alive(generation);
      const reply = await request(path, { method, headers: { accept: 'application/json', authorization: `DPoP ${current.value}`, DPoP: proof, ...(body !== undefined ? { 'content-type': 'application/json' } : {}) }, ...(body !== undefined ? { body: JSON.stringify(body) } : {}) }, jti, current);
      alive(generation);
      if (reply.status === 401) drop(); // Never replay an external write automatically.
      return reply;
    },
    mint: async () => unavailable('credential-reference resolution arrives with plan row 18'),
    close() { closed = true; drop(); for (const controller of requests) controller.abort(); },
  };
}
