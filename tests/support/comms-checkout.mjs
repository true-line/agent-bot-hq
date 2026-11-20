// Test dependency only: actual reviewed comms broker/mailbox, never a production
// plugin bundle entry. A fresh cache requires the immutable public git source.
import { execFileSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, renameSync, rmSync } from 'node:fs';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';

const COMMIT = '972fcbed06c8ff79bf60bd9129f5da54e22f5772';
const REPOSITORY = 'https://github.com/true-line/agent-bot-comms.git';
export function credentialFreeGitEnv(inherited = process.env) {
  // URL-scoped headers and repository selectors survive generic header resets.
  const env = Object.fromEntries(Object.entries(inherited).filter(([key]) => !key.startsWith('GIT_')));
  return { ...env, GIT_CONFIG_NOSYSTEM: '1', GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0', GIT_ASKPASS: '/bin/false', SSH_ASKPASS: '/bin/false' };
}
export function commsCheckout() {
  const parent = fileURLToPath(new URL('../../.cache/test-dependencies/', import.meta.url));
  const cache = join(parent, `agent-bot-comms-${COMMIT}`);
  const gitEnv = credentialFreeGitEnv();
  const git = (dir, ...args) => execFileSync('git', ['-C', dir, '-c', 'credential.helper=', '-c', 'http.extraHeader=', '-c', 'core.hooksPath=/dev/null', ...args], { encoding: 'utf8', env: gitEnv, stdio: ['ignore', 'pipe', 'pipe'] });
  mkdirSync(parent, { recursive: true });
  if (!existsSync(cache)) {
    const work = mkdtempSync(join(parent, 'comms-fetch-'));
    try {
      git(work, 'init', '-q', '--template=');
      git(work, 'fetch', '-q', '--depth', '1', '--no-tags', REPOSITORY, COMMIT);
      git(work, 'checkout', '-q', '--detach', 'FETCH_HEAD');
      try {
        renameSync(work, cache);
      } catch (error) {
        // Another test process may have published its checkout first.
        if (error.code !== 'EEXIST' && error.code !== 'ENOTEMPTY') throw error;
      }
    } finally {
      rmSync(work, { recursive: true, force: true });
    }
  }
  if (git(cache, 'rev-parse', 'HEAD').trim() !== COMMIT || git(cache, '--no-optional-locks', 'status', '--porcelain', '--untracked-files=all').trim()) throw new Error('test comms checkout must match the clean reviewed commit');
  return cache;
}
