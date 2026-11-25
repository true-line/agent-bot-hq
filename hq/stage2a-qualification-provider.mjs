// The pinned qualification response is disclosed by Machine only after its
// durable one-use claim and current finalized B lease checks succeed.
import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';
import { createServer, request as httpRequest } from 'node:http';
import { parseStrict } from '../sdk/wire/strict-json.mjs';
import { canonicalize } from '../sdk/wire/canonical-json.mjs';
import { machineRoleStage2aProvider } from './machine-channel.mjs';

const ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;
const START = /^st_[0-9a-f]{24}$/;
const LAUNCH = /^ln_[0-9a-f]{24}$/;
const SHA = /^[0-9a-f]{64}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const exact = (value, keys) => value && typeof value === 'object' && !Array.isArray(value)
  && Object.keys(value).sort().join(',') === [...keys].sort().join(',');
const sha = (bytes) => createHash('sha256').update(bytes).digest('hex');
const providerPath = '/stage2a/local-provider/v1';
const observationPath = '/stage2a/local-provider/v1/observation';
export const OBSERVED_BODY_LOCAL_TEST_MODE = 'observed-body-local-test/v1';
const observedProofHeader = 'x-agent-bot-stage2a-provider-auth';
const maxHTTPBytes = 8192;
const serviceTimeout = 5000;

// The destination is derived from the authenticated start, never from B's
// request or owner-supplied URL. A collision refuses this protected start.
export function stage2aLocalProviderPort(plan) {
  if (!SHA.test(plan?.hq_epoch ?? '') || !START.test(plan?.start_id ?? '')
    || !ID.test(plan?.installation_id ?? '')) throw new TypeError('invalid local provider start');
  const value = createHash('sha256').update('agent-bot-stage2a-local-provider-v1\0')
    .update(plan.hq_epoch).update('\0').update(plan.installation_id)
    .update('\0').update(plan.start_id).digest().readUInt16BE(0);
  return 49152 + (value % 16384);
}

export function openLocalProviderService(plan, { mode } = {}) {
  if (mode !== undefined && mode !== OBSERVED_BODY_LOCAL_TEST_MODE) {
    throw new TypeError('unsupported local provider mode');
  }
  const observedMode = mode === OBSERVED_BODY_LOCAL_TEST_MODE;
  // This token never crosses into the Soul, B, Machine config, or a receipt.
  // It distinguishes HQ's internal POST from a local process racing the same
  // reachable listener with a copied digest body after authorization.
  let observedProof = observedMode ? randomBytes(32) : undefined;
  const port = stage2aLocalProviderPort(plan);
  let config;
  let invocations = 0;
  let lastRequestSHA256 = '';
  let lastResponseSHA256 = '';
  let invocationReceipt;
  const traffic = {
    ipv4: { tcp_accepted: 0, http_requests: 0, observation_gets: 0, provider_posts: 0, other_http_requests: 0 },
    ipv6: { tcp_accepted: 0, http_requests: 0, observation_gets: 0, provider_posts: 0, other_http_requests: 0 },
  };
  const trafficSnapshot = () => ({ ipv4: { ...traffic.ipv4 }, ipv6: { ...traffic.ipv6 } });
  const handle = async (request, response) => {
    const family = request.socket.remoteAddress === '127.0.0.1' ? 'ipv4'
      : request.socket.remoteAddress === '::1' ? 'ipv6' : undefined;
    if (family) {
      const counter = traffic[family];
      counter.http_requests++;
      if (request.method === 'GET' && request.url === observationPath) counter.observation_gets++;
      else if (request.method === 'POST' && request.url === providerPath) counter.provider_posts++;
      else counter.other_http_requests++;
    }
    request.setTimeout(serviceTimeout, () => request.destroy());
    const reply = (status, value) => {
      if (response.destroyed || response.writableEnded) return;
      const body = Buffer.from(canonicalize(value));
      response.writeHead(status, { 'content-type': 'application/json',
        'content-length': String(body.length), connection: 'close' });
      response.end(body);
    };
    if (!['127.0.0.1', '::1'].includes(request.socket.remoteAddress)) {
      reply(403, { error: 'wrong_peer' }); return;
    }
    if (request.method === 'GET' && request.url === observationPath) {
      reply(200, { invocations, last_request_sha256: lastRequestSHA256,
        last_response_sha256: lastResponseSHA256, traffic: trafficSnapshot() }); return;
    }
    if (request.method !== 'POST' || request.url !== providerPath
      || request.headers['content-type'] !== 'application/json'
      || request.headers['transfer-encoding'] !== undefined
      || !/^[1-9][0-9]{0,3}$/.test(request.headers['content-length'] ?? '')
      || Number(request.headers['content-length']) > maxHTTPBytes) {
      reply(400, { error: 'invalid_request' }); return;
    }
    if (observedMode) {
      const supplied = request.headers[observedProofHeader];
      const bytes = typeof supplied === 'string' && /^[A-Za-z0-9_-]{43}$/.test(supplied)
        ? Buffer.from(supplied, 'base64url') : undefined;
      if (!observedProof || !bytes || bytes.length !== 32
        || bytes.toString('base64url') !== supplied
        || !timingSafeEqual(bytes, observedProof)) {
        reply(403, { error: 'not_authorized' }); return;
      }
    }
    try {
      const chunks = [];
      let length = 0;
      for await (const chunk of request) {
        length += chunk.length;
        if (length > maxHTTPBytes) throw new Error('request too large');
        chunks.push(chunk);
      }
      const bytes = Buffer.concat(chunks);
      if (bytes.length !== Number(request.headers['content-length'])) throw new Error('length mismatch');
      const input = parseStrict(new TextDecoder('utf-8', { fatal: true }).decode(bytes));
      if (!exact(input, observedMode
        ? ['mode', 'model', 'observed_body_sha256'] : ['model', 'request_sha256'])
        || !Buffer.from(canonicalize(input)).equals(bytes)
        || !config || invocations !== 0 || input.model !== config.model
        || (observedMode
          ? input.mode !== OBSERVED_BODY_LOCAL_TEST_MODE
            || input.observed_body_sha256 !== config.observed_body_sha256
          : input.request_sha256 !== config.request_sha256)) {
        reply(403, { error: 'not_authorized' }); return;
      }
      if (observedMode) {
        observedProof.fill(0);
        observedProof = undefined;
      }
      invocations++;
      lastRequestSHA256 = observedMode ? input.observed_body_sha256 : input.request_sha256;
      lastResponseSHA256 = digest(Buffer.from(config.response_text));
      reply(200, { ...config, invocation: invocations,
        response_sha256: lastResponseSHA256 });
    } catch {
      reply(400, { error: 'invalid_request' });
    }
  };
  const servers = [createServer({ maxHeaderSize: 8192 }, handle),
    createServer({ maxHeaderSize: 8192 }, handle)];
  for (const [index, server] of servers.entries()) {
    const family = index === 0 ? 'ipv4' : 'ipv6';
    server.on('connection', () => { traffic[family].tcp_accepted++; });
    server.headersTimeout = serviceTimeout;
    server.requestTimeout = serviceTimeout;
    server.keepAliveTimeout = 1000;
    server.maxRequestsPerSocket = 1;
    server.maxConnections = 16;
  }
  const closeServer = async (server) => {
    if (!server.listening) return;
    server.closeAllConnections();
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
  };
  const listen = (server, host, ipv6Only = false) => new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen({ host, port, exclusive: true, ipv6Only }, () => {
      server.off('error', reject);
      resolve();
    });
  });
  const ready = (async () => {
    await listen(servers[0], '127.0.0.1');
    try { await listen(servers[1], '::1', true); }
    catch (error) { await closeServer(servers[0]); throw error; }
  })();
  const observe = async (host) => {
    await ready;
    const body = await new Promise((resolve, reject) => {
      const request = httpRequest({ host, port, method: 'GET', path: observationPath,
        agent: false, timeout: serviceTimeout, headers: { connection: 'close' } }, (response) => {
        if (response.statusCode !== 200 || response.headers['content-type'] !== 'application/json'
          || !/^[1-9][0-9]{0,3}$/.test(response.headers['content-length'] ?? '')
          || Number(response.headers['content-length']) > maxHTTPBytes) {
          response.resume(); reject(new Error('local provider observation refused')); return;
        }
        const chunks = [];
        let size = 0;
        response.on('data', (chunk) => {
          size += chunk.length;
          if (size > maxHTTPBytes) { request.destroy(new Error('local provider observation too large')); return; }
          chunks.push(chunk);
        });
        response.once('end', () => {
          if (size !== Number(response.headers['content-length'])) {
            reject(new Error('local provider observation length mismatch')); return;
          }
          resolve(Buffer.concat(chunks));
        });
        response.once('error', reject);
      });
      request.once('timeout', () => request.destroy(new Error('local provider observation timed out')));
      request.once('error', reject);
      request.end();
    });
    const observed = parseStrict(new TextDecoder('utf-8', { fatal: true }).decode(body));
    if (!exact(observed, ['invocations', 'last_request_sha256', 'last_response_sha256', 'traffic'])
      || !Buffer.from(canonicalize(observed)).equals(body)
      || observed.invocations !== invocations || observed.last_request_sha256 !== lastRequestSHA256
      || observed.last_response_sha256 !== lastResponseSHA256
      || !exact(observed.traffic, ['ipv4', 'ipv6'])
      || !['ipv4', 'ipv6'].every((family) => {
        const row = observed.traffic[family];
        return exact(row, ['tcp_accepted', 'http_requests', 'observation_gets', 'provider_posts', 'other_http_requests'])
          && Object.values(row).every((value) => Number.isSafeInteger(value) && value >= 0)
          && Object.keys(row).every((key) => row[key] === traffic[family][key]);
      })) {
      throw new Error('local provider observation differs from its live state');
    }
    return Object.freeze({ url: `http://${host === '::1' ? '[::1]' : host}:${port}${observationPath}`,
      body_sha256: digest(body), observed_at_ms: Date.now(), ...observed });
  };
  return Object.freeze({
    port, ready,
    invocationReceipt: () => invocationReceipt,
    async probeReachability() {
      const ipv4 = await observe('127.0.0.1');
      const ipv6 = await observe('::1');
      if (ipv4.invocations !== ipv6.invocations
        || ipv4.last_request_sha256 !== ipv6.last_request_sha256
        || ipv4.last_response_sha256 !== ipv6.last_response_sha256) {
        throw new Error('local provider loopback families returned different observations');
      }
      return Object.freeze({ ipv4, ipv6 });
    },
    async invoke(approved, { signal } = {}) {
      await ready;
      try {
      if (signal?.aborted) throw new Error('local provider invocation was stopped');
      config = Object.freeze({ ...approved });
      if (invocations !== 0) throw new Error('local provider was already invoked');
      if (observedMode && (!exact(config, ['mode', 'model', 'observed_body_sha256', 'response_text'])
        || config.mode !== OBSERVED_BODY_LOCAL_TEST_MODE
        || !ID.test(config.model) || !DIGEST.test(config.observed_body_sha256)
        || typeof config.response_text !== 'string' || !config.response_text
        || config.response_text.length > 4096)) {
        throw new Error('observed-body local provider config differs from authorization');
      }
      const body = Buffer.from(canonicalize(observedMode
        ? { mode, model: config.model, observed_body_sha256: config.observed_body_sha256 }
        : { model: config.model, request_sha256: config.request_sha256 }));
      const requestedAtMS = Date.now();
      let responseBytes;
      let respondedAtMS;
      const result = await new Promise((resolve, reject) => {
        const request = httpRequest({ host: '127.0.0.1', port, method: 'POST', path: providerPath,
          agent: false, timeout: serviceTimeout, headers: { 'content-type': 'application/json',
            'content-length': String(body.length), connection: 'close',
            ...(observedMode ? { [observedProofHeader]: observedProof.toString('base64url') } : {}) } }, (response) => {
          const responseLength = response.headers['content-length'];
          if (response.statusCode !== 200 || response.headers['content-type'] !== 'application/json'
            || !/^[1-9][0-9]{0,3}$/.test(responseLength ?? '')
            || Number(responseLength) > maxHTTPBytes) {
            response.resume(); reject(new Error('local provider refused')); return;
          }
          const chunks = [];
          let size = 0;
          response.on('data', (chunk) => {
            size += chunk.length;
            if (size > maxHTTPBytes) { request.destroy(new Error('local provider response too large')); return; }
            chunks.push(chunk);
          });
          response.once('end', () => {
            try {
              if (size !== Number(responseLength)) throw new Error('local provider response length mismatch');
              responseBytes = Buffer.concat(chunks);
              respondedAtMS = Date.now();
              resolve(parseStrict(new TextDecoder('utf-8', { fatal: true }).decode(responseBytes)));
            } catch (error) { reject(error); }
          });
          response.once('error', reject);
        });
        const onAbort = () => request.destroy(new Error('local provider invocation was stopped'));
        signal?.addEventListener('abort', onAbort, { once: true });
        request.once('close', () => signal?.removeEventListener('abort', onAbort));
        request.once('timeout', () => request.destroy(new Error('local provider timed out')));
        request.once('error', reject);
        request.end(body);
      });
      if (!exact(result, observedMode
        ? ['mode', 'model', 'observed_body_sha256', 'response_text', 'invocation', 'response_sha256']
        : ['model', 'request_sha256', 'response_text', 'invocation', 'response_sha256'])
        || result.model !== config.model
        || (observedMode
          ? result.mode !== OBSERVED_BODY_LOCAL_TEST_MODE
            || result.observed_body_sha256 !== config.observed_body_sha256
          : result.request_sha256 !== config.request_sha256)
        || result.response_text !== config.response_text
        || result.response_sha256 !== digest(Buffer.from(config.response_text))
        || result.invocation !== 1 || invocations !== 1
        || !Buffer.from(canonicalize(result)).equals(responseBytes)) {
        throw new Error('local provider invocation differs from the signed plan');
      }
      invocationReceipt = Object.freeze({
        url: `http://127.0.0.1:${port}${providerPath}`, method: 'POST', status: 200,
        request_body_sha256: digest(body), response_body_sha256: digest(responseBytes),
        response_body_bytes: responseBytes.length,
        requested_at_ms: requestedAtMS, responded_at_ms: respondedAtMS,
        provider_config_sha256: sha(Buffer.from(canonicalize(config))),
        ...(observedMode ? { mode, observed_body_sha256: config.observed_body_sha256 } : {}),
      });
      return result;
      } catch (error) {
        if (observedProof) { observedProof.fill(0); observedProof = undefined; }
        throw error;
      }
    },
    async close() {
      if (observedProof) { observedProof.fill(0); observedProof = undefined; }
      await ready.catch(() => {});
      await Promise.all(servers.map(closeServer));
    },
  });
}

const digest = (bytes) => `sha256:${sha(bytes)}`;

export function createStage2aQualificationProvider({ plan, machineProvide = machineRoleStage2aProvider,
  now = () => Date.now(), openService = openLocalProviderService } = {}) {
  const fields = ['installation_id', 'start_id', 'launch_id', 'hq_epoch', 'plan_id', 'plan_digest',
    'reservation_sha256', 'soul_artifact_sha256', 'provider_config_sha256'];
  if (!exact(plan, fields) || !ID.test(plan.installation_id) || !START.test(plan.start_id)
    || !LAUNCH.test(plan.launch_id) || !SHA.test(plan.hq_epoch) || !ID.test(plan.plan_id)
    || !SHA.test(plan.plan_digest) || !DIGEST.test(plan.reservation_sha256)
    || !DIGEST.test(plan.soul_artifact_sha256) || !SHA.test(plan.provider_config_sha256)
    || typeof machineProvide !== 'function' || typeof now !== 'function'
    || typeof openService !== 'function') {
    throw new TypeError('qualification provider needs a signed installed plan and paired Machine client');
  }
  const expected = Object.freeze({ ...plan });
  const service = openService(expected);
  if (!service || typeof service.invoke !== 'function' || typeof service.close !== 'function'
    || typeof service.ready?.then !== 'function') {
    throw new TypeError('qualification provider needs an owned local service');
  }
  let attempted = false;
  const provide = async ({ request, observation } = {}) => {
    if (attempted) throw new Error('qualification provider attempt already spent');
    attempted = true;
    if (!exact(request, ['model', 'prompt_sha256']) || !ID.test(request.model)
      || !DIGEST.test(request.prompt_sha256)
      || !observation || typeof observation !== 'object'
      || !['installation_id', 'start_id', 'launch_id', 'hq_epoch', 'plan_id', 'plan_digest',
        'reservation_digest', 'soul_artifact_sha256'].every((field) =>
        observation[field] === expected[field === 'reservation_digest' ? 'reservation_sha256' : field])
      || !DIGEST.test(observation.bind_receipt_sha256 ?? '')) {
      throw new Error('qualification request differs from the signed installed plan');
    }
    const provided = await machineProvide({ reservation_sha256: expected.reservation_sha256,
      installation_id: expected.installation_id, start_id: expected.start_id,
      launch_id: expected.launch_id, plan_id: expected.plan_id, plan_digest: expected.plan_digest,
      hq_epoch: expected.hq_epoch, bind_receipt_sha256: observation.bind_receipt_sha256,
      model: request.model, prompt_sha256: request.prompt_sha256 });
    const configBytes = Buffer.from(provided?.config_base64url ?? '', 'base64url');
    let config;
    try { config = parseStrict(new TextDecoder('utf-8', { fatal: true }).decode(configBytes)); }
    catch { throw new Error('Machine qualification config is not strict UTF-8 JSON'); }
    if (!exact(config, ['model', 'request_sha256', 'response_text'])
      || config.model !== request.model || config.request_sha256 !== request.prompt_sha256
      || config.response_text !== provided.response_text
      || typeof config.response_text !== 'string' || !config.response_text
      || config.response_text.length > 4096
      || !Buffer.from(canonicalize(config)).equals(configBytes)
      || sha(configBytes) !== expected.provider_config_sha256
      || provided.provider_config_sha256 !== expected.provider_config_sha256
      || provided.model !== request.model || provided.request_sha256 !== request.prompt_sha256
      || !Number.isSafeInteger(provided.expires_at_ms) || now() > provided.expires_at_ms) {
      throw new Error('Machine qualification response differs from its signed installed pin');
    }
    await service.invoke(config);
    if (now() > provided.expires_at_ms) {
      throw new Error('Machine qualification response expired during local service invocation');
    }
    return Object.freeze({ model: config.model, stop_reason: 'end_turn', text: config.response_text,
      usage: Object.freeze({ input_tokens: 7, output_tokens: 3 }) });
  };
  provide.ready = service.ready;
  provide.close = () => service.close();
  provide.port = service.port;
  provide.probeReachability = () => service.probeReachability();
  provide.invocationReceipt = () => service.invocationReceipt();
  return provide;
}
