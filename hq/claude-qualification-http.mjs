// Run this sidecar as the untrusted harness account, never as HQ's account.
// It translates the narrow Stage 2a stock Claude Messages probe to one
// authenticated HQ broker request. It has no network listener or provider key.
import { createServer } from 'node:http';
import { chmodSync, lstatSync, unlinkSync } from 'node:fs';
import { dirname } from 'node:path';
import { qualificationPromptDigest } from './qualification-provider.mjs';
import { authenticatePeerUid } from './owner-control.mjs';

const MAX_BODY = 256 * 1024;
const POLICY = Buffer.from('{"policy_limits":{},"restrictions":{},"compliance_taints":[]}');

function exactPrompt(request, prompt) {
  if (!Array.isArray(request?.messages) || request.messages.length !== 1) return false;
  const message = request.messages[0];
  if (message?.role !== 'user' || Object.keys(message).length !== 2
    || !Object.hasOwn(message, 'content')) return false;
  if (typeof message.content === 'string') return message.content === prompt;
  if (!Array.isArray(message.content) || message.content.length !== 1) return false;
  const block = message.content[0];
  return block?.type === 'text' && block.text === prompt
    && Object.keys(block).length === 2;
}

function sse(response, kind, fields = {}) {
  const data = JSON.stringify({ type: kind, ...fields });
  response.write(`event: ${kind}\ndata: ${data}\n\n`);
}

async function bodyOf(request) {
  const size = Number(request.headers['content-length']);
  if (!Number.isSafeInteger(size) || size < 1 || size > MAX_BODY) throw new Error('body size');
  let bytes = 0;
  const chunks = [];
  for await (const chunk of request) {
    bytes += chunk.length;
    if (bytes > size || bytes > MAX_BODY) throw new Error('body size');
    chunks.push(chunk);
  }
  if (bytes !== size) throw new Error('body size');
  return JSON.parse(Buffer.concat(chunks).toString('utf8'));
}

// `memberSession` comes from sdk/member-session.mjs, after a member-token
// bootstrap and HMAC bind. Its captured request is never retried. The plan is
// the same exact prompt/model that Machine authorized for the HQ consumer.
export async function startClaudeQualificationHttp({ socketPath, peerUid, groupGid, memberSession, plan } = {}) {
  if (typeof socketPath !== 'string' || !socketPath || typeof memberSession?.capture !== 'function'
    || !Number.isSafeInteger(peerUid) || peerUid < 1
    || typeof plan?.prompt !== 'string' || !plan.prompt || plan.prompt.length > 4096
    || typeof plan.model !== 'string' || !plan.model) throw new TypeError('qualification HTTP needs a private socket, expected peer UID, member session and exact plan');
  const separatePeer = peerUid !== process.getuid?.();
  if (separatePeer && (!Number.isSafeInteger(groupGid) || groupGid < 1)) {
    throw new TypeError('a separate runner peer needs its reviewed private group GID');
  }
  const parentMode = separatePeer ? 0o2750 : 0o700;
  const socketMode = separatePeer ? 0o660 : 0o600;
  const parent = lstatSync(dirname(socketPath));
  if (!parent.isDirectory() || parent.isSymbolicLink() || parent.uid !== process.getuid?.()
    || (parent.mode & 0o7777) !== parentMode
    || (separatePeer && parent.gid !== groupGid)) throw new Error('qualification HTTP socket parent differs from the reviewed UID, group or mode');
  try { lstatSync(socketPath); throw new Error('qualification HTTP socket already exists'); }
  catch (error) { if (error.code !== 'ENOENT') throw error; }

  const handle = async (request, response) => {
    if (!await authenticatePeerUid(request.socket, peerUid)) { response.writeHead(403); response.end(); return; }
    let path;
    try { path = new URL(request.url, 'http://unix.invalid').pathname; }
    catch { response.writeHead(400); response.end(); return; }
    if (request.method === 'GET' && path === '/api/claude_code/policy_limits') {
      response.writeHead(200, { 'Content-Type': 'application/json', 'Content-Length': POLICY.length }); response.end(POLICY); return;
    }
    if (request.method !== 'POST' || path !== '/v1/messages') { response.writeHead(404); response.end(); return; }
    let message;
    try { message = await bodyOf(request); }
    catch { response.writeHead(422); response.end(); return; }
    // The API key and Authorization headers carry no local authority. A
    // stock ancillary request is refused without touching the HQ broker.
    if (message?.stream !== true || message.model !== plan.model || !exactPrompt(message, plan.prompt)) {
      response.writeHead(422); response.end(); return;
    }
    let result;
    try {
      const captured = await memberSession.capture();
      result = await captured.request('qualification.messages', { model: plan.model, prompt_sha256: qualificationPromptDigest(plan.prompt) });
      if (result?.model !== plan.model || result?.stop_reason !== 'end_turn' || typeof result?.text !== 'string'
        || !result.text || result.text.length > 4096) throw new Error('invalid HQ qualification result');
    } catch { response.writeHead(403); response.end(); return; }
    response.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache' });
    sse(response, 'message_start', { message: { id: 'msg_hq_qualification', type: 'message', role: 'assistant', model: result.model,
      content: [], stop_reason: null, stop_sequence: null, usage: { input_tokens: result.usage?.input_tokens ?? 0, output_tokens: 0 } } });
    sse(response, 'content_block_start', { index: 0, content_block: { type: 'text', text: '' } });
    sse(response, 'content_block_delta', { index: 0, delta: { type: 'text_delta', text: result.text } });
    sse(response, 'content_block_stop', { index: 0 });
    sse(response, 'message_delta', { delta: { stop_reason: 'end_turn', stop_sequence: null }, usage: result.usage ?? { input_tokens: 0, output_tokens: 0 } });
    sse(response, 'message_stop');
    response.end();
  };
  const server = createServer((request, response) => {
    void handle(request, response).catch(() => {
      if (!response.headersSent) response.writeHead(400);
      response.end();
    });
  });
  server.maxHeadersCount = 64;
  server.headersTimeout = 5000;
  server.requestTimeout = 10000;
  await new Promise((resolve, reject) => { server.once('error', reject); server.listen(socketPath, resolve); });
  try {
    chmodSync(socketPath, socketMode);
    const created = lstatSync(socketPath);
    const after = lstatSync(dirname(socketPath));
    if (!created.isSocket() || created.uid !== process.getuid?.() || (separatePeer && created.gid !== groupGid)
      || (created.mode & 0o7777) !== socketMode || after.dev !== parent.dev || after.ino !== parent.ino
      || after.uid !== parent.uid || after.gid !== parent.gid || (after.mode & 0o7777) !== parentMode) {
      throw new Error('qualification HTTP socket identity changed during creation');
    }
  }
  catch (error) { server.close(); try { unlinkSync(socketPath); } catch {} throw error; }
  const inode = lstatSync(socketPath).ino;
  return Object.freeze({ socketPath, async close() {
    await new Promise((resolve) => server.close(resolve));
    try { if (lstatSync(socketPath).ino === inode) unlinkSync(socketPath); } catch (error) { if (error.code !== 'ENOENT') throw error; }
  } });
}
