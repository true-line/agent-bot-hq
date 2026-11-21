// HQ's local sockets (plan §7.1, §7.2, §4.9): the control socket for the
// owner, the admission socket for Soul entry points, and the member broker
// socket, whose frames go to the plugin serving the broker. The auth class of a request is
// the socket it arrived on, never a field the client sends: an entry point
// cannot reach owner operations by claiming to be the owner, and the owner's
// client cannot send Hello on the control socket.
//
// Access control. The three sockets in HQ's state directory are Unix domain
// sockets created 0600 in a 0700 directory, so only HQ's own OS account can
// connect. A harness broker lives in that account's private group directory.
// Darwin harness brokers and the system-activated owner listener also
// validate the connected peer's kernel UID before handling input.
// Windows named pipes are not built yet (#89); HQ refuses to start there.
//
// Framing: one JSON object per line (NDJSON), strictly parsed.
//   request   {"id": <string|number>, "op": "<hq/v1 operation, or a broker message kind>", "payload": <any>}
//   result    {"id": ..., "ok": true, "result": <any>}
//   refusal   {"id": ..., "ok": false, "refusal": <common/v1 error response>}
//   host      {"id": ..., "ok": false, "host_refusal": {"code": "host.…", "explanation", "correlation_id"}}
// A registry code goes in `refusal`, shaped exactly as soul-contracts'
// common/v1 error response. A host code has no registry entry, so it goes in
// `host_refusal` and never in a contract record. soul-contracts does not yet
// specify the hq/v1 request envelope; this framing is HQ's until it does.
// A member may opt in with `response: 'stream'` on a request. A trusted
// consumer can then emit bounded `{id, ok: true, chunk}` replies followed
// by the ordinary result (the producer's terminal value) or a refusal.
//
// Takeover (§9 row 16b). A listener created with `takeover: true` (only the
// admission socket) lets the FIRST request on a connection hand the
// connection over: dispatch returns takeover(result, { open, cancel }), the
// socket answers with `result`, and from then on the bytes are no longer
// parsed as requests. The first request on such a listener runs alone, and
// HQ honours the takeover only if not one byte followed its line by then;
// otherwise it calls `cancel`, refuses and closes, so no byte is ever both a
// request and a payload. Dispatch sees `takeover: true` in its meta on the
// one request that may do it. On any other listener a takeover result is an
// internal error and is cancelled.
import { connect as netConnect, createServer } from 'node:net';
import { chmodSync, existsSync, lstatSync, unlinkSync } from 'node:fs';
import { abortable, brokerStreamProducer, MODEL_CATALOG, RESPONSES, validOutputChunk, validOutputTerminal } from '../sdk/broker-stream.mjs';
import { HostError, REGISTRY_CODES } from '../sdk/errors.mjs';
import { redact } from '../sdk/services.mjs';
import { parseStrict } from '../sdk/wire/strict-json.mjs';

export const MAX_LINE_BYTES = 1 << 20;
const MAX_STREAM_BYTES = 8 * MAX_LINE_BYTES;
const MAX_STREAM_CHUNKS = 4096;
const STREAM_TIMEOUT_MS = 120_000;
const REQUEST_KEYS = new Set(['id', 'op', 'payload']);
const REQUEST_ID = /^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/;

const clip = (s) => {
  const text = String(s ?? '').trim() || 'refused';
  return text.length > 512 ? `${text.slice(0, 509)}...` : text;
};

// A dispatch result that takes the connection over. `open()` runs once the
// socket has checked the connection is clean; it may throw a refusal, and
// returns connect(socket), called after the answer is written. `cancel()`
// runs instead when the takeover is not honoured.
const TAKEOVER = Symbol('hq.socket.takeover');
export function takeover(result, { open, cancel }) {
  if (typeof open !== 'function' || typeof cancel !== 'function') throw new TypeError('takeover needs open and cancel');
  return { [TAKEOVER]: { result, open, cancel } };
}
const takeoverOf = (r) => (r && typeof r === 'object' && TAKEOVER in r ? r[TAKEOVER] : undefined);

// Is something listening on `path`? Used to tell a stale socket file from a
// running HQ before replacing it.
function live(path) {
  return new Promise((resolve) => {
    const s = netConnect(path);
    s.once('connect', () => { s.destroy(); resolve(true); });
    s.once('error', () => resolve(false));
  });
}

// A Unix socket path must fit sun_path with its terminating NUL: 104 bytes
// on macOS and the BSDs, 108 on Linux. Past that, listen fails with a bare
// EINVAL, so HQ says what is wrong before it touches anything.
export function checkSocketPath(path, platform = process.platform) {
  const max = (platform === 'linux' ? 108 : 104) - 1;
  const len = Buffer.byteLength(path);
  if (len > max) throw new Error(`socket path ${path} is ${len} bytes; ${platform} allows ${max}. Choose a shorter --home`);
}

// `mode` is the socket file's mode: 0600 for HQ's own sockets, 0660 for a
// harness endpoint whose directory gives it the account's group (hq/harness-accounts.mjs).
// `takeover` enables the hook above for this listener.
export async function listenSocket({ path, auth, dispatch, core, newSession, endSession, mode = 0o600, takeover: canTakeOver = false, activated, authenticatePeer }) {
  if (process.platform === 'win32') throw new Error('HQ on Windows needs a named pipe with an owner DACL, which is not built yet (#89)');
  const authenticate = activated ? activated.authenticate : authenticatePeer;
  if (activated && typeof authenticate !== 'function') throw new Error('an activated listener requires peer authentication');
  checkSocketPath(path);
  if (!activated && existsSync(path)) {
    if (!lstatSync(path).isSocket()) throw new Error(`${path} exists and is not a socket; refusing to replace it`);
    if (await live(path)) throw new Error(`another HQ is listening on ${path}`);
    unlinkSync(path);
  }
  const conns = new Set();

  const log = (level, message, fields) => core.logs.push({ level, plugin: 'hq', at: core.clock.now(), ...redact(core, { message, fields }) });

  function respondError(e, id, op, payload) {
    const correlation = `corr_${core.random.hex(8)}`;
    if (e instanceof HostError && e.code in REGISTRY_CODES) {
      const refusal = { error: e.code, explanation: clip(redact(core, e.message)), correlation_id: correlation };
      if (typeof payload?.request_id === 'string' && REQUEST_ID.test(payload.request_id)) refusal.request_id = payload.request_id;
      log('warn', `refused ${op ?? '?'}: ${e.code}`, { correlation_id: correlation, auth });
      return { id, ok: false, refusal };
    }
    if (e instanceof HostError) {
      log('warn', `refused ${op ?? '?'}: ${e.code}`, { correlation_id: correlation, auth });
      return { id, ok: false, host_refusal: { code: e.code, explanation: clip(redact(core, e.message)), correlation_id: correlation } };
    }
    log('error', `internal error in ${op ?? '?'}: ${e?.message ?? e}`, { correlation_id: correlation, auth });
    return { id, ok: false, host_refusal: { code: 'host.internal', explanation: `internal error; the HQ log has correlation ${correlation}`, correlation_id: correlation } };
  }

  // `offer`: this request may take the connection over.
  async function handle(line, session, offer = false, startStream) {
    let req;
    try {
      req = parseStrict(line);
    } catch (e) {
      return respondError(new HostError('host.invalid_json', `request is not strict JSON: ${e.message}`), null);
    }
    if (!req || typeof req !== 'object' || Array.isArray(req)) return respondError(new HostError('host.invalid_request', 'a request is a JSON object'), null);
    const id = typeof req.id === 'string' || Number.isSafeInteger(req.id) ? req.id : null;
    const stream = auth === 'member' && req.response === 'stream';
    const extra = Object.keys(req).filter((k) => !REQUEST_KEYS.has(k) && !(stream && k === 'response'));
    if (extra.length) return respondError(new HostError('host.invalid_request', `unknown request field ${extra[0]}`), id);
    if (typeof req.op !== 'string') return respondError(new HostError('host.invalid_request', 'a request names its op'), id);
    if (stream && id === null) return respondError(new HostError('host.invalid_request', 'a stream request needs an id'), id);
    if (stream && req.op !== RESPONSES) return respondError(new HostError('host.invalid_request', 'only inference responses support streaming'), id);
    if (auth === 'member' && req.op === RESPONSES && !stream) return respondError(new HostError('host.invalid_request', 'inference responses need a stream request'), id);
    const inference = auth === 'member' && (stream || req.op === MODEL_CATALOG);
    try {
      const deliver = () => dispatch(req.op, { auth, payload: req.payload, session, ...(offer ? { takeover: true } : {}) });
      const result = inference ? await abortable(deliver, startStream()) : await deliver();
      const t = takeoverOf(result);
      if (t) {
        if (offer) return { id, takeover: t };
        try { t.cancel(); } catch { /* the refusal below is the answer */ }
        if (!canTakeOver) throw new Error(`${req.op} tried to take over a ${auth} connection`);
        return respondError(new HostError('host.invalid_request', `${req.op} must be the first and only request on a new connection`), id, req.op);
      }
      const produce = brokerStreamProducer(result);
      if (produce) {
        if (!inference) throw new HostError('host.invalid_request', 'inference requires the member operation');
        return { id, produce, op: req.op, stream };
      }
      return { id, ok: true, result: result === undefined ? null : result };
    } catch (e) {
      return respondError(e, id, req.op, req.payload);
    }
  }

  // An inherited owner listener and each Darwin harness broker gate the peer before opening an HQ
  // session, handling bytes, or dispatching a request. Other listeners keep
  // their existing framing, including admission's first-request takeover.
  let pendingChecks = 0;
  async function onConnection(socket) {
    conns.add(socket);
    socket.once('close', () => conns.delete(socket));
    socket.on('error', () => {});
    if (authenticate) {
      if (pendingChecks >= 16) { socket.destroy(); return; }
      pendingChecks++;
      let accepted = false;
      try { accepted = await authenticate(socket); } catch { /* refuse */ }
      finally { pendingChecks--; }
      if (!accepted || socket.destroyed) { socket.destroy(); return; }
    }
    const session = newSession();
    // Bytes, not text: a takeover hands the rest of the stream on unchanged.
    // Lines split on 0x0a, which never occurs inside a UTF-8 sequence.
    let buf = Buffer.alloc(0);
    let queue = Promise.resolve();
    let lines = 0;
    let first = false; // the first request of a takeover listener is in flight
    let taken = false;
    const send = (obj) => { if (!socket.destroyed) socket.write(`${JSON.stringify(obj)}\n`); };
    async function sendReply(line) {
      let controller;
      const disconnect = () => controller.abort(new Error('member disconnected'));
      let timer;
      const startStream = () => {
        controller = new AbortController();
        if (socket.destroyed || socket.writableEnded) disconnect();
        socket.once('close', disconnect);
        timer = setTimeout(() => controller.abort(new HostError('host.timeout', 'member stream expired')), STREAM_TIMEOUT_MS);
        timer.unref();
        return controller.signal;
      };
      let iterator;
      let done = false;
      let writing = false;
      let bytes = 0;
      let chunks = 0;
      let reply;
      try {
        reply = await handle(line, session, false, startStream);
        if (!reply.produce) { send(reply); return; }
        const { signal } = controller;
        signal.throwIfAborted();
        const { id, produce } = reply;
        if (!reply.stream) {
          const result = await abortable(() => produce(signal), signal);
          const resultFrame = { id, ok: true, result };
          if (Buffer.byteLength(JSON.stringify(resultFrame)) > MAX_LINE_BYTES) throw new HostError('host.internal', 'inference catalog exceeded its byte limit');
          send(resultFrame);
          return;
        }
        iterator = produce(signal)[Symbol.asyncIterator]();
        while (true) {
          const item = await abortable(() => iterator.next(), signal);
          done = item.done === true;
          if (!done && ++chunks > MAX_STREAM_CHUNKS) throw new HostError('host.invalid_request', 'member stream exceeded its chunk limit');
          if (done ? !validOutputTerminal(item.value) : !validOutputChunk(item.value)) throw new HostError('host.internal', 'invalid inference stream output');
          const frame = done ? { id, ok: true, result: item.value ?? null } : { id, ok: true, chunk: item.value };
          const line = `${JSON.stringify(frame)}\n`;
          const length = Buffer.byteLength(line);
          bytes += length;
          if (length > MAX_LINE_BYTES + 1 || bytes > MAX_STREAM_BYTES) throw new HostError('host.invalid_request', 'member stream exceeded its byte limit');
          writing = true;
          await abortable(() => new Promise((resolve, reject) => {
            socket.write(line, (error) => { if (error) reject(error); else resolve(); });
          }), signal);
          writing = false;
          if (done) return;
        }
      } catch (error) {
        // A blocked write cannot deliver a refusal either. Close instead of
        // accumulating writes behind a peer that stopped reading.
        if (writing) socket.destroy();
        else if (!socket.destroyed && !socket.writableEnded) send(respondError(error, reply?.id ?? null, reply?.op));
      } finally {
        clearTimeout(timer);
        socket.off('close', disconnect);
        controller?.abort();
        if (!done && iterator?.return) Promise.resolve().then(() => iterator.return()).catch(() => {});
      }
    }
    const oversize = () => {
      send(respondError(new HostError('host.invalid_request', `request line exceeds ${MAX_LINE_BYTES} bytes`), null));
      socket.end();
      buf = Buffer.alloc(0);
    };

    function takeOver(id, t) {
      taken = true;
      // Closed, already refused (an oversized buffer ends the socket), or
      // bytes after the request: not honoured.
      if (socket.destroyed || socket.writableEnded || buf.length) {
        try { t.cancel(); } catch { /* refused either way */ }
        send(respondError(new HostError('host.invalid_request', 'bytes followed the request before its answer; send nothing until HQ answers'), id));
        socket.end();
        return;
      }
      let connect;
      try {
        connect = t.open();
      } catch (e) {
        send(respondError(e, id));
        socket.end();
        return;
      }
      // Same tick: no data event can fall between the parser and the new owner.
      socket.off('data', onData);
      send({ id, ok: true, result: t.result === undefined ? null : t.result });
      connect(socket);
    }

    function pump() {
      if (taken) return;
      if (first) {
        if (buf.length > MAX_LINE_BYTES) oversize();
        return;
      }
      if (buf.length > MAX_LINE_BYTES && !buf.includes(0x0a)) { oversize(); return; }
      let nl;
      while ((nl = buf.indexOf(0x0a)) !== -1) {
        const raw = buf.subarray(0, nl);
        buf = buf.subarray(nl + 1);
        // A line and its newline can arrive in one chunk, so the limit is
        // checked on every line, not only on an unterminated buffer.
        if (raw.length > MAX_LINE_BYTES) { oversize(); return; }
        const line = raw.toString('utf8');
        if (!line.trim()) continue;
        if (canTakeOver && lines++ === 0) {
          // The first request runs alone; the rest of the buffer waits for it.
          first = true;
          queue = queue.then(() => handle(line, session, true)).then((out) => {
            first = false;
            if (out?.takeover) takeOver(out.id, out.takeover);
            else { send(out); pump(); }
          }, (e) => { first = false; send(respondError(e, null)); pump(); });
          return;
        }
        queue = queue.then(() => sendReply(line)).catch((e) => send(respondError(e, null)));
      }
    }
    function onData(chunk) {
      buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
      pump();
    }
    socket.on('data', onData);
    if (authenticate) socket.resume();
    // The session ends after its queued requests finish, so a request still
    // in flight (a broker bind, say) cannot recreate state after the end.
    socket.on('close', () => { queue = queue.then(() => endSession(session)).catch(() => {}); });
  }

  const server = createServer({ pauseOnConnect: Boolean(authenticate) }, onConnection);
  await new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(activated ? { fd: activated.fd } : path, () => { server.off('error', reject); resolve(); });
  });
  activated?.listener?.adopt(onConnection);
  if (!activated) chmodSync(path, mode);

  return {
    path,
    auth,
    connections: () => conns.size,
    close: () => new Promise((resolve) => {
      for (const s of conns) s.destroy();
      server.close(() => { if (!activated) { try { unlinkSync(path); } catch { /* already gone */ } } resolve(); });
    }),
  };
}

// A minimal client for the CLI and the tests: request(op, payload) resolves
// with the response object, matched by id.
export function connectSocket(path) {
  return new Promise((resolve, reject) => {
    const socket = netConnect(path);
    const pending = new Map();
    let next = 1;
    let buf = '';
    socket.setEncoding('utf8');
    socket.on('data', (chunk) => {
      buf += chunk;
      let nl;
      while ((nl = buf.indexOf('\n')) !== -1) {
        const msg = JSON.parse(buf.slice(0, nl));
        buf = buf.slice(nl + 1);
        const key = pending.has(msg.id) ? msg.id : null;
        const waiter = pending.get(key);
        if (waiter) { pending.delete(key); waiter(msg); }
      }
    });
    let failure;
    const fail = (message) => {
      failure ??= message;
      for (const w of pending.values()) w({ ok: false, transport_error: failure });
      pending.clear();
    };
    const send = (key, text) => new Promise((res) => {
      if (failure || socket.destroyed || !socket.writable) {
        res({ ok: false, transport_error: failure ?? 'connection closed' });
        return;
      }
      pending.set(key, res);
      socket.write(text);
    });
    socket.on('close', () => fail('connection closed'));
    socket.once('error', (e) => { reject(e); fail(e.message); });
    socket.once('connect', () => resolve({
      async request(op, payload) {
        const id = next++;
        return send(id, `${JSON.stringify({ id, op, ...(payload === undefined ? {} : { payload }) })}\n`);
      },
      // Send raw text (tests of the framing); resolves with the next response.
      raw: (text) => send(null, text),
      close: () => new Promise((res) => {
        if (socket.closed || socket.destroyed) { res(); return; }
        socket.once('close', res);
        socket.end();
      }),
    }));
  });
}
