// A stand-in identity service for HQ's enrollment tests: the three routes
// the device-code grant uses, checked the way the real service must check
// them (the proof is a JWS by the key it carries, for this audience).
import { createHash, createPublicKey, generateKeyPairSync, randomBytes, sign, verify } from 'node:crypto';
import { signatureBytes } from '../hq/identity-service.mjs';
import { createServer } from 'node:http';

export async function fakeIdentityService({ issuer } = {}) {
  const signing = generateKeyPairSync('ed25519');
  const serverKey = signing.publicKey.export({ format: 'jwk' });
  const state = { requests: [], grants: new Map(), devices: [], mode: 'ok', interval: 1 };
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
            : { device_id: claims.iss, token_type: 'DPoP', access_token: 'disposable-fixture-token', expires_in: 300, harnesses: grant.form.harnesses.split(' ') };
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
