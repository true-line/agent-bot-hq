// The system manager owns the listener. HQ authenticates every accepted
// stream independently of the socket inode's permissions.
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { createServer } from 'node:net';
import { lstatSync } from 'node:fs';
import { userInfo } from 'node:os';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const darwin = process.platform === 'darwin';
export const OWNER_CONTROL_PATH = darwin ? '/Library/Application Support/ai.true-line.agent-bot-hq/owner-control.sock' : '/run/agent-bot-hq/control.sock';
export const OWNER_PEER_CHECK = darwin ? 'getpeereid' : 'SO_PEERCRED';
const interpreter = darwin ? '/usr/bin/ruby' : '/usr/bin/python3';
const helper = darwin
  ? ['--disable-gems', fileURLToPath(new URL('../helpers/darwin-owner.rb', import.meta.url))]
  : ['-I', '-S', fileURLToPath(new URL('../helpers/linux-owner-peer.py', import.meta.url))];
const helperOptions = { env: {}, timeout: 2000, killSignal: 'SIGKILL' };

function check(args, ...fds) {
  const result = spawnSync(interpreter, [...helper, ...args], {
    ...helperOptions, stdio: ['ignore', 'ignore', 'ignore', ...fds],
  });
  return !result.error && result.status === 0;
}

export function checkOwnerControlSupport() {
  if ((!darwin && process.platform !== 'linux') || !check(['probe'])) {
    throw new Error(`owner control requires a working ${OWNER_PEER_CHECK} helper on this platform`);
  }
  return darwin ? 'darwin-owner-control/v2' : 'linux-owner-control/v1';
}

export function checkOwnerSocketPath(ownerUid) {
  const ancestry = darwin ? ['/', '/Library', '/Library/Application Support', dirname(OWNER_CONTROL_PATH)] : ['/run', dirname(OWNER_CONTROL_PATH)];
  for (const dir of ancestry) {
    const st = lstatSync(dir);
    if (!st.isDirectory() || st.uid !== 0 || (st.mode & 0o022)) throw new Error(`owner control requires a root-managed directory at ${dir}`);
  }
  const socket = lstatSync(OWNER_CONTROL_PATH);
  const expectedUid = darwin ? 0 : ownerUid;
  const expectedMode = darwin ? 0o666 : 0o600;
  if (!socket.isSocket() || socket.uid !== expectedUid || (socket.mode & 0o7777) !== expectedMode) {
    throw new Error(`expected an owner control socket owned by uid ${expectedUid} at mode ${expectedMode.toString(8)}`);
  }
}

export async function activatedOwnerControl(account) {
  checkOwnerControlSupport();
  const service = darwin ? '_agent-bot-hq' : 'agent-bot-hq';
  if (userInfo().username !== service || process.getuid() === 0) throw new Error(`owner control requires the dedicated ${service} service account`);
  if (!/^[a-z_][a-z0-9_-]{0,31}$/.test(account)) throw new Error('invalid owner account name');
  const opts = { encoding: 'utf8', timeout: 2000 };
  let raw;
  if (darwin) {
    raw = execFileSync('/usr/bin/id', ['-u', account], opts).trim();
  } else {
    const entry = execFileSync('/usr/bin/getent', ['passwd', account], opts).trim().split(':');
    if (entry[0] !== account) throw new Error('unknown owner account');
    raw = entry[2];
  }
  const uid = Number(raw);
  if (!/^[0-9]+$/.test(raw) || !Number.isSafeInteger(uid) || uid < 1 || uid >= 0xffffffff || uid === process.getuid()) {
    throw new Error('owner control requires a distinct non-root owner account');
  }
  if (darwin) {
    if (process.env.HQ_LAUNCHD_OWNER_PID !== String(process.pid)) throw new Error('expected a launchd owner-control listener for this process');
  } else {
    const { LISTEN_PID, LISTEN_FDS, LISTEN_FDNAMES } = process.env;
    if (LISTEN_PID !== String(process.pid) || LISTEN_FDS !== '1' || LISTEN_FDNAMES !== 'owner-control') {
      throw new Error('expected one systemd owner-control listener for this process');
    }
  }
  const fd = 3;
  checkOwnerSocketPath(uid);
  const phase = darwin ? 'descriptor' : 'listener';
  if (!check([phase, OWNER_CONTROL_PATH], ...(darwin ? [fd, 4] : [fd]))) throw new Error('owner-control fd is not the expected listening Unix stream socket');
  const listener = darwin ? await prepareOwnerListener(4, () => socketCheck(['listener', OWNER_CONTROL_PATH], fd)) : undefined;
  return { fd, account, uid, listener, authenticate: (socket) => authenticatePeerUid(socket, uid) };
}

// launchd can retain pending requests across a restart. Accept paused streams
// before probing the public path, so the probe can complete even while a
// legitimate owner is waiting. No stream enters HQ until verification succeeds.
export async function prepareOwnerListener(fd, verifyPublic) {
  const waiting = new Set();
  const acceptor = createServer({ pauseOnConnect: true }, (socket) => {
    socket.on('error', () => {});
    waiting.add(socket);
    socket.once('close', () => waiting.delete(socket));
    // Stop accepting from the duplicate at HQ's existing peer-check limit.
    // The manager and fd 3 retain every remaining queued connection.
    if (waiting.size >= 16) acceptor.close();
  });
  await new Promise((resolve, reject) => {
    acceptor.once('error', reject);
    acceptor.listen({ fd }, () => { acceptor.off('error', reject); resolve(); });
  });
  function closeUnused() {
    if (acceptor.listening) acceptor.close();
    for (const socket of waiting) socket.destroy();
    waiting.clear();
  }
  try {
    if (!await verifyPublic()) throw new Error('owner-control fd does not match the published Unix stream socket');
  } catch (e) {
    closeUnused();
    throw e;
  }
  if (acceptor.listening) acceptor.close();
  return {
    closeUnused,
    adopt(onConnection) {
      for (const socket of waiting) if (!socket.destroyed) onConnection(socket);
      waiting.clear();
    },
  };
}

// Node passes the connected stream to fd 3 in the helper using the public
// child_process stdio API. The helper only reads credentials from the kernel.
export function authenticatePeerUid(socket, uid) {
  return socketCheck(['peer', String(uid)], socket);
}

// Observe the connecting PID from the accepted descriptor, with the same
// kernel UID check. This is an HQ-local role gate; Machine must authenticate
// a protected Hello independently before publishing managed provenance.
function observeSocketPeer(socket, uid, operation, maxBytes) {
  return new Promise((resolve) => {
    if (!Number.isSafeInteger(uid) || uid < 1) { resolve(null); return; }
    let probe;
    try {
      probe = spawn(interpreter, [...helper, operation, String(uid)], {
        ...helperOptions, stdio: ['ignore', 'pipe', 'ignore', socket],
      });
    } catch { resolve(null); return; }
    let output = '';
    let overflow = false;
    probe.stdout.on('data', (chunk) => {
      output += chunk.toString('ascii');
      if (output.length > maxBytes) { overflow = true; probe.kill('SIGKILL'); }
    });
    probe.once('error', () => resolve(null));
    probe.once('close', (code) => resolve(code === 0 && !overflow ? output : null));
  });
}

export async function observePeerPid(socket, uid) {
  const output = await observeSocketPeer(socket, uid, 'peer-pid', 32);
  if (!/^[1-9][0-9]{0,9}\n$/.test(output ?? '')) return null;
  const pid = Number(output.trim());
  return Number.isSafeInteger(pid) && pid > 1 ? pid : null;
}

export async function observeDarwinPeerIdentity(socket, expectedUid) {
  if (!darwin) return null;
  const output = await observeSocketPeer(socket, expectedUid, 'peer-audit', 96);
  if (!/^\d+(?: \d+){5}\n$/.test(output ?? '')) return null;
  const values = output.trim().split(' ').map(Number);
  const [uid, gid, pid, pid_version, start_seconds, start_micros] = values;
  if (!values.every(Number.isSafeInteger) || uid !== expectedUid || gid < 1 || pid < 2
    || pid_version < 1 || pid_version > 0xffffffff || start_seconds < 1
    || start_micros < 0 || start_micros >= 1e6) return null;
  return Object.freeze({ uid, gid, pid, pid_version, start_seconds, start_micros });
}

export { authenticatePeerUid as authenticateOwner };

function socketCheck(args, socket) {
  return new Promise((resolve) => {
    const probe = spawn(interpreter, [...helper, ...args], { ...helperOptions, stdio: ['ignore', 'ignore', 'ignore', socket] });
    probe.once('error', () => resolve(false));
    probe.once('close', (code) => resolve(code === 0));
  });
}
