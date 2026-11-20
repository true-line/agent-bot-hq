// Only the administrator's independently pinned, protected executable is a
// candidate. It checks live Machine inventory and holds the installation lock
// during every key operation, including calls made directly by the role.
import { createHash } from 'node:crypto';
import { constants, closeSync, fstatSync, lstatSync, openSync, readFileSync } from 'node:fs';
import { userInfo } from 'node:os';
import { join } from 'node:path';
import { spawnSync } from 'node:child_process';
import { machineAccountLayout } from './machine-channel.mjs';
import { createSigner, helperKeyBackend, helperRunner } from './signer.mjs';

const library = '/Library';
const vendor = join(library, 'Application Support', 'ai.true-line.agent-bot-hq');
const directory = join(vendor, 'standalone');
const helper = join(directory, 'hq-signer');
const declaration = join(directory, 'declaration-v1');
const unavailable = () => { throw new Error('standalone Secure Enclave signing requires a verified dedicated-account installation without Agent Machine'); };

function noACL(path) {
  const result = spawnSync('/bin/ls', ['-lde', path], {
    env: { LC_ALL: 'C' }, encoding: 'utf8', timeout: 2000, maxBuffer: 8192,
  });
  if (result.status !== 0 || result.stdout.trimEnd().split('\n').length !== 1) unavailable();
}

function protectedFile(path, mode, max) {
  const fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  try {
    const stat = fstatSync(fd);
    if (!stat.isFile() || stat.uid !== 0 || stat.gid !== 0 || (stat.mode & 0o7777) !== mode
      || stat.nlink !== 1 || stat.size <= 0 || stat.size > max) unavailable();
    noACL(path);
    return readFileSync(fd);
  } finally { closeSync(fd); }
}

function verifyHelper(uid) {
  for (const path of [library, join(library, 'Application Support'), vendor, directory]) {
    const stat = lstatSync(path);
    if (!stat.isDirectory() || stat.uid !== 0 || (stat.mode & 0o7022) !== 0
      || ([vendor, directory].includes(path) && (stat.gid !== 0 || (stat.mode & 0o7777) !== 0o755))) unavailable();
    noACL(path);
  }
  for (const marker of ['machine-retired-v1', 'declaration-pending-v1']) {
    if (lstatSync(join(directory, marker), { throwIfNoEntry: false })) unavailable();
  }
  const marker = protectedFile(declaration, 0o644, 512);
  const digest = createHash('sha256').update(protectedFile(helper, 0o555, 32 * 1024 * 1024)).digest('hex');
  const fields = marker.toString('utf8').split('\n');
  if (fields.length !== 7 || fields[0] !== 'agent-bot-hq/standalone-signing/v1' || fields[1] !== 'role=_agent-bot-hq'
    || fields[2] !== 'uid=' + uid || !/^uuid=[0-9A-F]{8}(?:-[0-9A-F]{4}){3}-[0-9A-F]{12}$/.test(fields[3])
    || fields[4] !== 'no-custom-machine-installation=true' || fields[5] !== 'helper-sha256=' + digest || fields[6] !== '') unavailable();
}

export function standaloneKeyBackend(verify, run = helperRunner({ env: { PATH: '/usr/bin:/bin' } })) {
  const backend = helperKeyBackend({ command: [helper], run(argv, input) {
    verify();
    return run([helper, 'standalone-v1-' + argv[1]], input);
  } });
  return { ...backend, kind: 'secure-enclave', requiresCurrentKey: true };
}

export function createStandaloneSigner(options) {
  if (process.platform !== 'darwin') unavailable();
  const actual = userInfo();
  try { machineAccountLayout(actual, 'darwin', process.getuid(), process.geteuid(), true); }
  catch { unavailable(); }
  return createSigner({ ...options, backend: standaloneKeyBackend(() => verifyHelper(actual.uid)) });
}
