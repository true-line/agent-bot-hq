// The Linux system manager owns the listener. HQ authenticates every accepted
// stream independently of the socket inode's permissions.
import { execFileSync, spawn, spawnSync } from 'node:child_process';
import { lstatSync } from 'node:fs';
import { userInfo } from 'node:os';
import { dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

export const OWNER_CONTROL_PATH = '/run/agent-bot-hq/control.sock';
const PYTHON = '/usr/bin/python3';
const HELPER = ['-I', '-S', fileURLToPath(new URL('../helpers/linux-owner-peer.py', import.meta.url))];
const helperOptions = { env: {}, timeout: 2000, killSignal: 'SIGKILL' };

function check(args, fd) {
  const result = spawnSync(PYTHON, [...HELPER, ...args], {
    ...helperOptions, stdio: ['ignore', 'ignore', 'ignore', ...(fd === undefined ? [] : [fd])],
  });
  return !result.error && result.status === 0;
}

export function checkOwnerControlSupport() {
  if (process.platform !== 'linux' || !check(['probe'])) {
    throw new Error('Linux owner control requires /usr/bin/python3 with Unix socket peer credential support');
  }
}

export function checkOwnerSocketPath(ownerUid) {
  for (const dir of ['/run', dirname(OWNER_CONTROL_PATH)]) {
    const st = lstatSync(dir);
    if (!st.isDirectory() || st.uid !== 0 || (st.mode & 0o022)) throw new Error(`owner control requires a root-managed directory at ${dir}`);
  }
  const socket = lstatSync(OWNER_CONTROL_PATH);
  if (!socket.isSocket() || socket.uid !== ownerUid || (socket.mode & 0o7777) !== 0o600) {
    throw new Error(`expected an owner control socket owned by uid ${ownerUid} at mode 0600`);
  }
}

export function activatedOwnerControl(account) {
  checkOwnerControlSupport();
  if (userInfo().username !== 'agent-bot-hq' || process.getuid() === 0) throw new Error('owner control requires the dedicated Linux agent-bot-hq service account');
  if (!/^[a-z_][a-z0-9_-]{0,31}$/.test(account)) throw new Error('invalid owner account name');
  const entry = execFileSync('/usr/bin/getent', ['passwd', account], { encoding: 'utf8', timeout: 2000 }).trim().split(':');
  const uid = Number(entry[2]);
  if (entry[0] !== account || !/^[0-9]+$/.test(entry[2]) || !Number.isSafeInteger(uid) || uid < 1 || uid >= 0xffffffff || uid === process.getuid()) {
    throw new Error('owner control requires a distinct non-root owner account');
  }
  const { LISTEN_PID, LISTEN_FDS, LISTEN_FDNAMES } = process.env;
  if (LISTEN_PID !== String(process.pid) || LISTEN_FDS !== '1' || LISTEN_FDNAMES !== 'owner-control') {
    throw new Error('expected one systemd owner-control listener for this process');
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
    const probe = spawn(PYTHON, [...HELPER, 'peer', String(uid)], { ...helperOptions, stdio: ['ignore', 'ignore', 'ignore', socket] });
    probe.once('error', () => resolve(false));
    probe.once('close', (code) => resolve(code === 0));
  });
}
