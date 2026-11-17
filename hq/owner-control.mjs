// The system manager owns the listener. HQ authenticates every accepted
// stream independently of the socket inode's permissions.
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { lstatSync } from 'node:fs';
import { userInfo } from 'node:os';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const darwin = process.platform === 'darwin';
export const OWNER_CONTROL_PATH = darwin ? '/private/var/run/agent-bot-hq-control.sock' : '/run/agent-bot-hq/control.sock';
export const OWNER_PEER_CHECK = darwin ? 'getpeereid' : 'SO_PEERCRED';
const interpreter = darwin ? '/usr/bin/ruby' : '/usr/bin/python3';
const helper = darwin
  ? ['--disable-gems', fileURLToPath(new URL('../helpers/darwin-owner.rb', import.meta.url))]
  : ['-I', '-S', fileURLToPath(new URL('../helpers/linux-owner-peer.py', import.meta.url))];
const helperOptions = { env: {}, timeout: 2000, killSignal: 'SIGKILL' };

function check(args, fd) {
  const result = spawnSync(interpreter, [...helper, ...args], {
    ...helperOptions, stdio: ['ignore', 'ignore', 'ignore', ...(fd === undefined ? [] : [fd])],
  });
  return !result.error && result.status === 0;
}

export function checkOwnerControlSupport() {
  if ((!darwin && process.platform !== 'linux') || !check(['probe'])) {
    throw new Error(`owner control requires a working ${OWNER_PEER_CHECK} helper on this platform`);
  }
  return darwin ? 'darwin-owner-control/v1' : 'linux-owner-control/v1';
}

export function checkOwnerSocketPath(ownerUid) {
  const ancestry = darwin ? ['/private', '/private/var', '/private/var/run'] : ['/run', dirname(OWNER_CONTROL_PATH)];
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

export function activatedOwnerControl(account) {
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
  if (!check(['listener', OWNER_CONTROL_PATH], fd)) throw new Error('owner-control fd is not the expected listening Unix stream socket');
  return { fd, account, uid, authenticate: (socket) => authenticateOwner(socket, uid) };
}

// Node passes the connected stream to fd 3 in the helper using the public
// child_process stdio API. The helper only reads credentials from the kernel.
export function authenticateOwner(socket, uid) {
  return new Promise((resolve) => {
    const probe = spawn(interpreter, [...helper, 'peer', String(uid)], { ...helperOptions, stdio: ['ignore', 'ignore', 'ignore', socket] });
    probe.once('error', () => resolve(false));
    probe.once('close', (code) => resolve(code === 0));
  });
}
