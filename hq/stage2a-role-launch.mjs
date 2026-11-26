// HQ starts only the installed, sudoers-pinned Soul launcher under Machine's
// assigned R or B account. Machine authorizes the observed process over the
// paired local channel; HQ relays its signed grant over this private pipe.
import { spawn } from 'node:child_process';
import { createHash } from 'node:crypto';
import { parseStrict } from '../sdk/wire/strict-json.mjs';
import { machineRoleStage2aExec, machineRoleStage2aPrepareB } from './machine-channel.mjs';
import { join } from 'node:path';

export const STAGE2A_LAUNCHER = '/Library/Application Support/ai.true-line.agent-bot-hq/soul-launch';
const RUNNER_ACCOUNT = /^_abm-sr-[0-9a-f]{20}$/;
const BRIDGE_ACCOUNT = /^_abm-br-[0-9a-f]{20}$/;
const DIGEST = /^sha256:[0-9a-f]{64}$/;
const NONCE = /^[A-Za-z0-9_-]{43}$/;

// Translate HQ's bigint-safe lstat observation into Machine's signed
// prepare-B request. The directory and socket must be the installed H:B
// endpoint; no owner-selected path or rounded inode enters the claim.
export function stage2aBrokerClaim(installed, observed) {
  const ep = installed?.broker;
  const exact = (value, fields) => value && typeof value === 'object' && !Array.isArray(value)
    && Object.keys(value).sort().join(',') === [...fields].sort().join(',');
  const decimal = (value) => typeof value === 'string' && /^[1-9][0-9]*$/.test(value)
    && value.length <= 20 && BigInt(value) <= 18446744073709551615n;
  const node = (value, mode) => exact(value, ['owner_uid', 'group_gid', 'device', 'inode', 'mode'])
    && value.owner_uid === installed.hq_uid && value.group_gid === installed.bridge_gid
    && decimal(value.device) && decimal(value.inode) && value.mode === mode;
  if (!ep || !observed || observed.directory !== ep.directory
    || observed.socket_path !== ep.socket_path
    || !node(observed.directory_identity, 0o2750)
    || !node(observed.socket_identity, 0o660)) {
    throw new Error('HQ broker identity differs from installed Machine assignment');
  }
  const project = (value) => Object.freeze({ uid: value.owner_uid, gid: value.group_gid,
    device: value.device, inode: value.inode, mode: value.mode });
  return Object.freeze({ path: ep.socket_path,
    parent: project(observed.directory_identity), socket: project(observed.socket_identity) });
}

export async function prepareStage2aBridge({ installed, observed, selectors,
  machinePrepare = machineRoleStage2aPrepareB } = {}) {
  if (!selectors || typeof selectors !== 'object' || Array.isArray(selectors)
    || Object.keys(selectors).sort().join(',') !== [
      'reservation_sha256', 'installation_id', 'start_id', 'launch_id', 'plan_id', 'plan_digest', 'hq_epoch',
    ].sort().join(',') || selectors.installation_id !== installed?.installation_id
    || selectors.plan_id !== installed.plan_id || selectors.plan_digest !== installed.plan_digest
    || selectors.hq_epoch !== installed.hq_epoch) {
    throw new Error('B preparation differs from signed installed assignment');
  }
  const reply = await machinePrepare({ ...selectors, broker: stage2aBrokerClaim(installed, observed) });
  if (!DIGEST.test(reply?.assignment_sha256 ?? '')) {
    throw new Error('Machine did not prepare the signed B assignment');
  }
  return reply;
}

export function stage2aRelayClaim(installed, startId, ready) {
  if (!installed || !/^st_[0-9a-f]{24}$/.test(startId ?? '')
    || !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(installed.installation_id ?? '')
    || !DIGEST.test(ready?.bind_receipt_sha256 ?? '')) {
    throw new Error('invalid signed B readiness selectors');
  }
  const socket = ready.relay_socket;
  if (!socket || socket.uid !== installed.bridge_uid || socket.gid !== installed.runner_gid
    || socket.mode !== 0o660 || !Number.isSafeInteger(socket.device) || socket.device <= 0
    || !Number.isSafeInteger(socket.inode) || socket.inode <= 0) {
    throw new Error('B readiness differs from installed relay account');
  }
  const basename = createHash('sha256').update([
    'agent-bot-soul-endpoint-start/v1', installed.installation_id, startId,
  ].join('\0')).digest('hex').slice(0, 20) + '.sock';
  return Object.freeze({ path: join(installed.relay.directory, basename),
    socket: Object.freeze({ uid: socket.uid, gid: socket.gid,
      device: String(socket.device), inode: String(socket.inode), mode: socket.mode }) });
}

function challengeFrom(line, role) {
  if (line.length > 512) throw new Error('Soul launcher challenge is too large');
  const c = parseStrict(line.toString('utf8'));
  if (!c || typeof c !== 'object' || Array.isArray(c)
    || Object.keys(c).length !== 3 || !['role', 'nonce', 'pid'].every((k) => Object.hasOwn(c, k))
    || c.role !== role || typeof c.nonce !== 'string' || !NONCE.test(c.nonce)
    || Buffer.from(c.nonce, 'base64url').length !== 32
    || Buffer.from(c.nonce, 'base64url').toString('base64url') !== c.nonce
    || !Number.isSafeInteger(c.pid) || c.pid < 2) {
    throw new Error('invalid Soul launcher challenge');
  }
  return c;
}

function firstLine(child, parse, timeoutMs, limit, resume = false, rejectRemainder = false) {
  return new Promise((resolve, reject) => {
    let bytes = Buffer.alloc(0);
    const timer = setTimeout(() => finish(new Error('Soul launcher challenge timed out')), timeoutMs);
    const cleanup = () => {
      clearTimeout(timer);
      child.stdout.off('data', onData);
      child.stdout.off('error', onError);
      child.off('error', onError);
      child.off('close', onClose);
    };
    const finish = (error, value) => { cleanup(); if (error) reject(error); else resolve(value); };
    const onError = (error) => finish(error);
    const onClose = () => finish(new Error('Soul launcher exited before its response'));
    const onData = (chunk) => {
      bytes = Buffer.concat([bytes, chunk]);
      const end = bytes.indexOf(0x0a);
      if (end < 0) {
        if (bytes.length > limit) finish(new Error('Soul launcher response is too large'));
        return;
      }
      try {
        if (rejectRemainder && bytes.length !== end + 1) {
          throw new Error('Soul runner sent bytes before child readiness');
        }
        child.stdout.pause();
        if (bytes.length > end + 1) child.stdout.unshift(bytes.subarray(end + 1));
        finish(null, parse(bytes.subarray(0, end)));
      }
      catch (error) { finish(error); }
    };
    child.stdout.on('data', onData);
    child.stdout.once('error', onError);
    child.once('error', onError);
    child.once('close', onClose);
    if (resume) child.stdout.resume();
  });
}

function bridgeReadyFrom(line, cooperative = false) {
  if (line.length > 1024) throw new Error('Soul bridge readiness is too large');
  const ready = parseStrict(line.toString('utf8'));
  const socket = ready?.relay_socket;
  if (!ready || typeof ready !== 'object' || Array.isArray(ready)
    || Object.keys(ready).length !== (cooperative ? 6 : 2)
    || !Object.hasOwn(ready, 'bind_receipt_sha256') || !Object.hasOwn(ready, 'relay_socket')
    || !DIGEST.test(ready.bind_receipt_sha256)
    || !socket || typeof socket !== 'object' || Array.isArray(socket)
    || Object.keys(socket).length !== 5
    || !['uid', 'gid', 'device', 'inode', 'mode'].every((key) => Object.hasOwn(socket, key)
      && Number.isSafeInteger(socket[key]) && socket[key] >= 0)
    || socket.uid < 300 || socket.uid > 399 || socket.gid < 300 || socket.gid > 399
    || socket.inode === 0 || socket.mode !== 0o660) {
    throw new Error('invalid Soul bridge readiness');
  }
  const extra = cooperative ? ['bridge_pid', 'bridge_start_seconds', 'bridge_start_micros', 'grant_nonce'] : [];
  if (cooperative && (!Number.isSafeInteger(ready.bridge_pid) || ready.bridge_pid < 2
    || !Number.isSafeInteger(ready.bridge_start_seconds) || ready.bridge_start_seconds <= 0
    || !Number.isSafeInteger(ready.bridge_start_micros) || ready.bridge_start_micros < 0 || ready.bridge_start_micros >= 1e6
    || !NONCE.test(ready.grant_nonce ?? '')
    || Buffer.from(ready.grant_nonce, 'base64url').toString('base64url') !== ready.grant_nonce)) {
    throw new Error('invalid cooperative B readiness process');
  }
  return Object.freeze({ bind_receipt_sha256: ready.bind_receipt_sha256,
    relay_socket: Object.freeze({ ...socket }), ...Object.fromEntries(extra.map((key) => [key, ready[key]])) });
}

function runnerActivationFrom(line) {
  if (line.length > 512) throw new Error('Soul runner activation ack is too large');
  const ack = parseStrict(line.toString('utf8'));
  if (!ack || typeof ack !== 'object' || Array.isArray(ack)
    || Object.keys(ack).sort().join(',') !== [
      'schema', 'reservation_sha256', 'start_id', 'launch_id',
      'lease_sha256', 'lease_sequence',
    ].sort().join(',')
    || ack.schema !== 'agent-bot-souls/protected-activation-ack/v1'
    || !DIGEST.test(ack.reservation_sha256)
    || !/^st_[0-9a-f]{24}$/.test(ack.start_id)
    || !/^ln_[0-9a-f]{24}$/.test(ack.launch_id)
    || !DIGEST.test(ack.lease_sha256)
    || !Number.isSafeInteger(ack.lease_sequence) || ack.lease_sequence < 1) {
    throw new Error('invalid Soul runner activation ack');
  }
  return Object.freeze(ack);
}

function runnerChildReadyFrom(line) {
  if (line.length > 512) throw new Error('Soul runner child ack is too large');
  const ack = parseStrict(line.toString('utf8'));
  if (!ack || typeof ack !== 'object' || Array.isArray(ack)
    || Object.keys(ack).sort().join(',') !== [
      'schema', 'reservation_sha256', 'start_id', 'launch_id', 'child_start_sha256',
    ].sort().join(',')
    || ack.schema !== 'agent-bot-souls/protected-child-ready/v1'
    || !DIGEST.test(ack.reservation_sha256)
    || !/^st_[0-9a-f]{24}$/.test(ack.start_id)
    || !/^ln_[0-9a-f]{24}$/.test(ack.launch_id)
    || !DIGEST.test(ack.child_start_sha256)) {
    throw new Error('invalid Soul runner child ack');
  }
  return Object.freeze(ack);
}

function writeGrant(child, bytes) {
  return new Promise((resolve, reject) => {
    if (!Buffer.isBuffer(bytes) || bytes.length < 2 || bytes.length > 65536
      || bytes.at(-1) !== 0x0a || child.exitCode !== null || child.signalCode !== null) {
      reject(new Error('invalid or late Soul launcher grant'));
      return;
    }
    child.stdin.write(bytes, (error) => error ? reject(error) : resolve());
  });
}

function bounded(promise, timeoutMs, label) {
  let timer;
  return Promise.race([
    promise,
    new Promise((_, reject) => { timer = setTimeout(() => reject(new Error(`${label} timed out`)), timeoutMs); }),
  ]).finally(() => clearTimeout(timer));
}

// Machine writes child lifecycle receipts to the fixed wrapper's stderr.
// ACP stdout remains reserved for the stock protocol stream.
function childProgress(child, cooperative, onT03Event) {
  if (!child.stderr || typeof child.stderr.on !== 'function') {
    throw new Error('protected child status pipe is unavailable');
  }
  const kinds = ['child-started', 'child-accepted', 'started'];
  const queue = [];
  let buffer = Buffer.alloc(0);
  let phase = 0;
  let failure;
  let waiter;
  let t03Chain = Promise.resolve();
  const fail = (error) => {
    if (failure) return;
    failure = error;
    if (waiter) { const pending = waiter; waiter = undefined; pending.reject(error); }
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
  };
  const deliver = (value) => {
    if (waiter) { const pending = waiter; waiter = undefined; pending.resolve(value); }
    else queue.push(value);
  };
  child.stderr.on('data', (chunk) => {
    if (failure || (phase === kinds.length && !onT03Event)) return;
    buffer = Buffer.concat([buffer, chunk]);
    while (true) {
      const end = buffer.indexOf(0x0a);
      if (end < 0) {
        if (buffer.length > (phase === kinds.length ? 8192 : 1024)) fail(new Error('protected child status is too large'));
        break;
      }
      if (end > (phase === kinds.length ? 8192 : 1024)) {
        fail(new Error('protected child status is too large')); return;
      }
      let event;
      try { event = parseStrict(buffer.subarray(0, end).toString('utf8')); }
      catch { fail(new Error('invalid protected child status')); return; }
      if (phase === kinds.length) {
        if (!event || typeof event !== 'object' || Array.isArray(event)
          || !['t03-probe-ready', 't03-probe-result', 't03-sibling-credential-witness'].includes(event.kind)
          || Object.keys(event).sort().join(',') !== (event.kind === 't03-probe-ready'
            ? 'kind,ready' : event.kind === 't03-probe-result' ? 'kind,result' : 'kind,witness')
          || !event[event.kind === 't03-probe-ready' ? 'ready'
            : event.kind === 't03-probe-result' ? 'result' : 'witness']
          || typeof event[event.kind === 't03-probe-ready' ? 'ready'
            : event.kind === 't03-probe-result' ? 'result' : 'witness'] !== 'object') {
          fail(new Error('unexpected protected T03 child status')); return;
        }
        t03Chain = t03Chain.then(() => {
          if (failure) return;
          return onT03Event(event);
        }).catch(fail);
        buffer = buffer.subarray(end + 1);
        continue;
      }
      if (!event || typeof event !== 'object' || Array.isArray(event)
        || event.kind !== kinds[phase]) {
        fail(new Error('unexpected protected child status')); return;
      }
      const fields = phase === 0
        ? ['kind', 'child_pid', 'child_launcher_pid', 'grant_sha256',
          ...(cooperative ? ['child_process', 'launcher_process'] : [])]
        : phase === 1 ? ['kind', cooperative ? 'ready_sha256' : 'receipt_sha256', 'lease_sequence'] : ['kind'];
      if (Object.keys(event).sort().join(',') !== fields.sort().join(',')) {
        fail(new Error('unexpected protected child status fields')); return;
      }
      buffer = buffer.subarray(end + 1);
      phase += 1;
      deliver(Object.freeze(event));
    }
    if (phase === kinds.length && !onT03Event) buffer = Buffer.alloc(0);
  });
  child.stderr.once('error', () => fail(new Error('protected child status pipe failed')));
  child.once('close', () => {
    if (phase !== kinds.length) fail(new Error('protected child exited before readiness'));
  });
  return Object.freeze({ next: async (expected, timeoutMs) => {
    if (failure) throw failure;
    const value = queue.length ? queue.shift() : await bounded(new Promise((resolve, reject) => {
      waiter = { resolve, reject };
    }), timeoutMs, 'protected child status').catch((error) => { fail(error); throw error; });
    if (value.kind !== expected) throw new Error('protected child status out of order');
    return value;
  } });
}

// A returned role is *started*, not contained or protected. The caller must
// bind the reservation to an authenticated live start and obtain Machine's
// signed stop/completion before releasing any installation occupancy.
export async function startStage2aRole({ account, role, reservationSHA256,
  machineExec = machineRoleStage2aExec, spawnProcess = spawn, timeoutMs = 12000,
  cooperativeBridge = false, cooperativeChild = false, onT03Event } = {}) {
  if (typeof account !== 'string'
    || !(role === 'runner' && RUNNER_ACCOUNT.test(account)
      || role === 'bridge' && BRIDGE_ACCOUNT.test(account)
      || role === 'child' && RUNNER_ACCOUNT.test(account))
    || (cooperativeBridge && role !== 'bridge') || (cooperativeChild && role !== 'child')
    || !DIGEST.test(reservationSHA256 ?? '')
    || !Number.isSafeInteger(timeoutMs) || timeoutMs < 1 || timeoutMs > 14000) {
    throw new Error('invalid Soul launcher assignment');
  }
  const command = role === 'runner' ? 'soul-run'
    : role === 'bridge' ? (cooperativeBridge ? 'cooperative-soul-bridge' : 'soul-bridge') : cooperativeChild ? 'cooperative-soul-child' : 'soul-child';
  const child = spawnProcess('/usr/bin/sudo', ['-n', '-u', account, '--', STAGE2A_LAUNCHER, command], {
    stdio: ['pipe', 'pipe', role === 'child' ? 'pipe' : 'ignore'], shell: false,
    env: { PATH: '/usr/bin:/bin:/usr/sbin:/sbin', LANG: 'C' },
  });
  const progress = role === 'child' ? childProgress(child, cooperativeChild, onT03Event) : undefined;
  const done = new Promise((resolve) => {
    child.once('close', (exit_code, signal) => resolve({ exit_code, signal, contained: false }));
  });
  child.stdin.on('error', () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM'); });
  child.stdout.on('error', () => { if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM'); });
  try {
    const challenge = await firstLine(child, (line) => challengeFrom(line, cooperativeBridge ? 'cooperative-bridge' : role), timeoutMs, 512);
    const grant = await bounded(machineExec({ reservation_sha256: reservationSHA256,
      role, nonce: challenge.nonce, pid: challenge.pid }), timeoutMs, 'Machine role grant');
    await writeGrant(child, grant?.grantLine);
    let readinessAttempted = false;
    let activationAttempted = false;
    let childReadyAttempted = false;
    return Object.freeze({ pid: challenge.pid, role, stdin: child.stdin, stdout: child.stdout,
      grantSHA256: grant?.sha256, done,
      resumeOutput: () => child.stdout.resume(),
      waitChildStarted: async () => {
        if (role !== 'child' || !DIGEST.test(grant?.sha256 ?? '')) throw new Error('invalid protected child grant');
        const started = await progress.next('child-started', 5000);
        if (!Number.isSafeInteger(started.child_pid) || started.child_pid < 2
          || started.child_pid === challenge.pid || started.child_launcher_pid !== challenge.pid
          || started.grant_sha256 !== grant.sha256) throw new Error('protected child start differs from grant');
        return started;
      },
      sendChildReceipt: async (receipt) => {
        if (role !== 'child' || cooperativeChild || !Buffer.isBuffer(receipt?.envelope)
          || !DIGEST.test(receipt?.sha256 ?? '')
          || !Number.isSafeInteger(receipt?.expires_at_ms)
          || receipt.expires_at_ms <= Date.now()) throw new Error('invalid protected child receipt');
        const line = Buffer.from(JSON.stringify({
          envelope_base64url: receipt.envelope.toString('base64url'),
          sha256: receipt.sha256, expires_at_ms: receipt.expires_at_ms,
        }) + '\n');
        await writeGrant(child, line);
      },
      waitChildAccepted: async (receiptSHA256) => {
        if (role !== 'child' || !DIGEST.test(receiptSHA256 ?? '')) {
          throw new Error('invalid protected child receipt selector');
        }
        const accepted = await progress.next('child-accepted', 5000);
        if ((cooperativeChild ? accepted.ready_sha256 : accepted.receipt_sha256) !== receiptSHA256
          || !Number.isSafeInteger(accepted.lease_sequence)
          || accepted.lease_sequence < 1) throw new Error('protected child receipt was not accepted');
        await progress.next('started', 5000);
        return accepted;
      },
      waitRunnerActivation: async ({ reservationSHA256, startId, launchId } = {}) => {
        if (role !== 'runner' || activationAttempted || !DIGEST.test(reservationSHA256 ?? '')
          || !/^st_[0-9a-f]{24}$/.test(startId ?? '')
          || !/^ln_[0-9a-f]{24}$/.test(launchId ?? '')) {
          throw new Error('invalid Soul runner activation verifier');
        }
        activationAttempted = true;
        try {
          // Protected Hello/Equip can cross several paired Machine calls.
          // The starter independently enforces each five-second signed Live
          // lease while this bounded admission handshake remains open.
          const ack = await firstLine(child, runnerActivationFrom, 30000, 512, true, true);
          if (ack.reservation_sha256 !== reservationSHA256 || ack.start_id !== startId
            || ack.launch_id !== launchId || child.exitCode !== null || child.signalCode !== null) {
            throw new Error('Soul runner activation ack differs from signed start');
          }
          return ack;
        } catch (error) {
          child.stdin.destroy();
          if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
          throw error;
        }
      },
      waitRunnerChildReady: async ({ reservationSHA256, startId, launchId,
        childStartSHA256, childStartEnvelope,
        helloFinalizationSHA256, helloFinalizationEnvelope } = {}) => {
        if (role !== 'runner' || !activationAttempted || childReadyAttempted
          || !DIGEST.test(reservationSHA256 ?? '')
          || !/^st_[0-9a-f]{24}$/.test(startId ?? '')
          || !/^ln_[0-9a-f]{24}$/.test(launchId ?? '')
          || !DIGEST.test(childStartSHA256 ?? '')
          || !Buffer.isBuffer(childStartEnvelope) || childStartEnvelope.length === 0
          || 'sha256:' + createHash('sha256').update(childStartEnvelope).digest('hex')
            !== childStartSHA256
          || !DIGEST.test(helloFinalizationSHA256 ?? '')
          || !Buffer.isBuffer(helloFinalizationEnvelope)
          || helloFinalizationEnvelope.length === 0
          || 'sha256:' + createHash('sha256').update(helloFinalizationEnvelope).digest('hex')
            !== helloFinalizationSHA256) throw new Error('invalid Soul runner child confirmation');
        childReadyAttempted = true;
        const line = Buffer.from(JSON.stringify({
          schema: 'agent-bot-souls/protected-child-start/v1',
          reservation_sha256: reservationSHA256, start_id: startId, launch_id: launchId,
          child_start_sha256: childStartSHA256,
          child_start_envelope_base64url: childStartEnvelope.toString('base64url'),
          hello_finalization_sha256: helloFinalizationSHA256,
          hello_finalization_envelope_base64url: helloFinalizationEnvelope.toString('base64url'),
        }) + '\n');
        try {
          await writeGrant(child, line);
          const ack = await firstLine(child, runnerChildReadyFrom, 5000, 512, true, true);
          if (ack.reservation_sha256 !== reservationSHA256 || ack.start_id !== startId
            || ack.launch_id !== launchId || ack.child_start_sha256 !== childStartSHA256
            || child.exitCode !== null || child.signalCode !== null) {
            throw new Error('Soul runner child ack differs from Machine receipt');
          }
          return ack;
        } catch (error) {
          child.stdin.destroy();
          if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
          throw error;
        }
      },
      waitBridgeReady: async (verify) => {
        if (role !== 'bridge' || readinessAttempted || typeof verify !== 'function') {
          throw new Error('invalid Soul bridge readiness verifier');
        }
        readinessAttempted = true;
        try {
          const ready = await firstLine(child, (line) => bridgeReadyFrom(line, cooperativeBridge), 5000, 1024, true);
          const verified = await bounded(Promise.resolve().then(() => verify(ready)), 5000,
            'Soul bridge readiness verification');
          if (verified !== true || child.exitCode !== null || child.signalCode !== null) {
            throw new Error('Soul bridge readiness was not authenticated');
          }
          return ready;
        } catch (error) {
          child.stdin.destroy();
          if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
          throw error;
        }
      },
      stop: async () => {
        child.stdin.destroy();
        if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
        const killer = setTimeout(() => {
          if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
        }, 3000);
        try { return await done; } finally { clearTimeout(killer); }
      } });
  } catch (error) {
    child.stdin.destroy();
    if (child.exitCode === null && child.signalCode === null) child.kill('SIGTERM');
    throw error;
  }
}
