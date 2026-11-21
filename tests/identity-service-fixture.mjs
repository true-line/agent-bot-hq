// Test-only session custody and a loopback issuer for enrollment, binding and signed self-lookup.
import assert from 'node:assert/strict';
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { signatureBytes } from '../hq/identity-service.mjs';
import { createServer } from 'node:http';

export async function fakeIdentityService({ issuer } = {}) {
  const signing = generateKeyPairSync('ed25519');
  const serverKey = signing.publicKey.export({ format: 'jwk' });
  const state = { requests: [], grants: new Map(), devices: [], mode: 'ok', interval: 1 };
  const sessions = new Map();
  const usedProofs = new Set();
  const json = (res, status, body) => { res.writeHead(status, { 'content-type': 'application/json' }); res.end(JSON.stringify(body)); };
  const server = createServer((req, res) => {
    let raw = '';
    req.on('data', (c) => { raw += c; });
    req.on('end', () => {
      const form = Object.fromEntries(new URLSearchParams(raw));
      state.requests.push({ method: req.method, url: req.url, form });
      if (state.mode === 'redirect') { res.writeHead(302, { location: 'http://127.0.0.1:1/elsewhere' }); res.end(); return; }
      if (req.method === 'GET' && req.url === '/.well-known/agent-bot-server-key') {
        return json(res, 200, { keys: [state.mode === 'bad-key' ? { kty: 'OKP', crv: 'Ed25519', x: 'AA' } : { ...serverKey, kid: 'srv-1' }] });
      }
      if (req.method === 'POST' && req.url === '/oauth/device_authorization') {
        if (state.mode === 'refuse') return json(res, 400, { error: 'invalid_request', error_description: 'software keys are not accepted' });
        try {
          const [h, p, s] = form.proof.split('.');
          const header = JSON.parse(Buffer.from(h, 'base64url'));
          const claims = JSON.parse(Buffer.from(p, 'base64url'));
          const key = createPublicKey({ key: header.jwk, format: 'jwk' });
          const good = header.alg === 'ES256' && header.typ === 'ab-enroll+jwt' && !('kid' in header) && !('d' in header.jwk)
            && claims.aud === (issuer ?? state.url) + '/oauth/device_authorization'
            && verify('sha256', Buffer.from(`${h}.${p}`), { key, dsaEncoding: 'ieee-p1363' }, Buffer.from(s, 'base64url'));
          if (!good) return json(res, 400, { error: 'invalid_proof' });
          const { crv, kty, x, y } = header.jwk;
          const jkt = createHash('sha256').update(JSON.stringify({ crv, kty, x, y })).digest('base64url');
          const device_code = randomBytes(16).toString('hex');
          state.grants.set(device_code, { jkt, form, decision: 'pending' });
          return json(res, 200, {
            device_code, user_code: 'WXYZ-1234', verification_uri: `${state.url}/device`,
            verification_uri_complete: `${state.url}/device?code=WXYZ-1234`, expires_in: 600, interval: state.interval,
            ...(form.enrollment_receipt === 'agent-bot-sig-v1' && { enrollment_receipt: 'agent-bot-sig-v1' }),
          });
        } catch { return json(res, 400, { error: 'invalid_proof' }); }
      }
      if (req.method === 'POST' && req.url === '/oauth/token') {
        if (form.grant_type === 'urn:ietf:params:oauth:grant-type:jwt-bearer') {
          const [h, p, s] = form.assertion.split('.');
          const claims = JSON.parse(Buffer.from(p, 'base64url'));
          const grant = [...state.grants.values()].find((g) => state.devices.some((d) => d.device_id === claims.iss && d.jkt === g.jkt));
          const key = grant && JSON.parse(Buffer.from(grant.form.proof.split('.')[0], 'base64url')).jwk;
          if (!key || claims.sub !== claims.iss || claims.aud !== (issuer ?? state.url) + '/oauth/token'
            || !verify('sha256', Buffer.from(h + '.' + p), { key: createPublicKey({ key, format: 'jwk' }), dsaEncoding: 'ieee-p1363' }, Buffer.from(s, 'base64url'))) {
            return json(res, 400, { error: 'invalid_grant' });
          }
          const status = state.mode === 'assertion-expired' ? 400 : 200;
          const body = status === 400 ? { error: 'invalid_grant', error_description: 'assertion expired or not yet valid' }
            : { device_id: claims.iss, token_type: 'DPoP', access_token: randomBytes(32).toString('base64url'), expires_in: 300, harnesses: grant.form.harnesses.split(' ') };
          if (status === 200) {
            sessions.set(body.access_token, { jwk: claims.cnf.jwk, deviceId: claims.iss, expires: Date.now() + body.expires_in * 1000 });
          }
          res.setHeader('agent-bot-key-id', 'srv-1');
          res.setHeader('agent-bot-request-jti', claims.jti);
          res.setHeader('agent-bot-signature', sign(null, signatureBytes(status, JSON.stringify(body), claims.jti), signing.privateKey).toString('base64url'));
          return json(res, status, body);
        }
        const g = state.grants.get(form.device_code);
        if (form.grant_type !== 'urn:ietf:params:oauth:grant-type:device_code' || !g) return json(res, 400, { error: 'invalid_grant' });
        if (g.decision === 'pending') return json(res, 400, { error: g.slow ? 'slow_down' : 'authorization_pending' });
        if (g.decision === 'denied') return json(res, 400, { error: 'access_denied', error_description: 'the owner denied this device' });
        if (g.receiptErrors?.length) return json(res, 503, { error: g.receiptErrors.shift() });
        const device_id = `dev_${state.devices.length + 1}`;
        state.devices.push({ device_id, jkt: g.jkt, key_storage: g.form.key_storage, device_name: g.form.device_name, platform: g.form.platform, harnesses: g.form.harnesses.split(' ') });
        const body = { token_type: 'N_A', device_id, jkt: g.jkt, read_only: false, harnesses: g.form.harnesses.split(' ') };
        if (g.form.enrollment_receipt === 'agent-bot-sig-v1') {
          const jti = 'enroll-v1:' + createHash('sha256').update(g.form.proof).digest('hex');
          res.setHeader('agent-bot-key-id', 'srv-1');
          res.setHeader('agent-bot-request-jti', jti);
          res.setHeader('agent-bot-signature', sign(null, signatureBytes(200, JSON.stringify(body), jti), signing.privateKey).toString('base64url'));
        }
        return json(res, 200, body);
      }
      if (req.method === 'GET' && req.url === '/api/daemon/whoami') {
        try {
          const token = req.headers.authorization?.match(/^DPoP ([A-Za-z0-9_-]+)$/)?.[1];
          const session = sessions.get(token);
          const parts = req.headers.dpop.split('.');
          const [header, claims] = parts.slice(0, 2).map(part => JSON.parse(Buffer.from(part, 'base64url')));
          if (!session || session.expires <= Date.now() || raw || parts.length !== 3
            || header.typ !== 'dpop+jwt' || header.alg !== 'ES256' || 'd' in header.jwk
            || !['kty', 'crv', 'x', 'y'].every(field => header.jwk[field] === session.jwk[field])
            || claims.htm !== req.method || claims.htu !== (issuer ?? state.url) + req.url
            || claims.ath !== createHash('sha256').update(token).digest('base64url')
            || !Number.isSafeInteger(claims.iat) || Math.abs(Date.now() / 1000 - claims.iat) > 120
            || typeof claims.jti !== 'string' || !/^[A-Za-z0-9_-]{22}$/.test(claims.jti) || usedProofs.has(claims.jti)
            || !verify('sha256', Buffer.from(parts.slice(0, 2).join('.')), {
              key: createPublicKey({ key: session.jwk, format: 'jwk' }), dsaEncoding: 'ieee-p1363',
            }, Buffer.from(parts[2], 'base64url'))) return json(res, 401, { error: 'invalid_dpop_proof' });
          usedProofs.add(claims.jti);
          const body = { device: { id: session.deviceId } };
          res.setHeader('agent-bot-key-id', 'srv-1');
          res.setHeader('agent-bot-request-jti', claims.jti);
          res.setHeader('agent-bot-signature', sign(null, signatureBytes(200, JSON.stringify(body), claims.jti), signing.privateKey).toString('base64url'));
          return json(res, 200, body);
        } catch { return json(res, 401, { error: 'invalid_dpop_proof' }); }
      }
      return json(res, 404, { error: 'not_found' });
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  state.url = `http://127.0.0.1:${server.address().port}`;
  return {
    state,
    url: state.url, key: { kid: 'srv-1', x: serverKey.x, status: 'active', notBefore: '2020-01-01T00:00:00Z', notAfter: '2099-01-01T00:00:00Z' },
    decide: (decision) => { for (const g of state.grants.values()) if (g.decision === 'pending') g.decision = decision; },
    close: () => new Promise((r) => server.close(r)),
  };
}

// Synthetic session custody shared by the fake-issuer unit suite and the real issuer test.
export function testSessionCustody({ server, clock, assertion, beforeOpen, recheck }) {
  const sessions = new Map();
  return {
    async openSession() {
      beforeOpen?.();
      const id = String(sessions.size + 1);
      const { privateKey, publicKey } = generateKeyPairSync('ec', { namedCurve: 'P-256' });
      const ephemeralJwk = publicKey.export({ format: 'jwk' });
      sessions.set(id, { privateKey, ephemeralJwk });
      return { session: id, ephemeralJwk, assertion: await assertion({ ephemeralJwk }) };
    },
    bindAccess({ session }) {
      assert.ok(sessions.has(session));
      return { expiresAt: clock.now() + 900_000, recheck };
    },
    requestProof({ session, method, path, ath, jti }) {
      const { privateKey, ephemeralJwk } = sessions.get(session);
      const header = { alg: 'ES256', typ: 'dpop+jwt', jwk: ephemeralJwk };
      const payload = { htm: method, htu: server + path, iat: Math.floor(clock.now() / 1000), jti, ath };
      const unsigned = [header, payload].map((v) => Buffer.from(JSON.stringify(v)).toString('base64url')).join('.');
      return unsigned + '.' + sign('sha256', Buffer.from(unsigned), { key: privateKey, dsaEncoding: 'ieee-p1363' }).toString('base64url');
    },
  };
}
