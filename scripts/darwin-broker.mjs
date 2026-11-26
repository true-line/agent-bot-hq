// Build the Darwin package's broker from a clean checkout of its independently
// pinned source. A populated cache, or HQ_COMMS_REPO, needs no network.
import { execFileSync, spawnSync } from 'node:child_process';
import { lstatSync, mkdirSync, readFileSync, readdirSync, realpathSync, writeFileSync } from 'node:fs';
import { isAbsolute, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { readPins, treeDigest } from '../hq/plugins.mjs';

const root = fileURLToPath(new URL('../', import.meta.url));
const COMMS = 'https://github.com/true-line/agent-bot-comms.git';

function stageSource(pin, work) {
  const gitEnv = { PATH: process.env.PATH, HOME: work, GIT_CONFIG_NOSYSTEM: '1',
    GIT_CONFIG_GLOBAL: '/dev/null', GIT_TERMINAL_PROMPT: '0', GIT_NO_REPLACE_OBJECTS: '1',
    GIT_ALLOW_PROTOCOL: process.env.GIT_ALLOW_PROTOCOL ?? 'file:https' };
  const git = (args) => execFileSync('git', ['-c', 'credential.helper=', '-c', 'core.hooksPath=/dev/null', ...args], { env: gitEnv, encoding: 'utf8' });
  let repository;
  if (process.env.HQ_COMMS_REPO !== undefined) {
    if (!isAbsolute(process.env.HQ_COMMS_REPO)) throw new Error('HQ_COMMS_REPO must name a local absolute Git repository');
    repository = realpathSync(process.env.HQ_COMMS_REPO);
  } else {
    repository = join(root, '.cache/comms-broker.git');
    mkdirSync(repository, { recursive: true });
    git(['init', '--bare', '--quiet', repository]);
    if (spawnSync('git', ['-C', repository, 'cat-file', '-e', pin.source_commit + '^{commit}'], { env: gitEnv, stdio: 'ignore' }).status !== 0) {
      git(['-C', repository, 'fetch', '--quiet', '--no-tags', '--depth=1', COMMS,
        pin.source_commit + ':refs/heads/' + pin.source_commit]);
    }
    if (pin.source_tag && spawnSync('git', ['-C', repository, 'show-ref', '--verify', '--quiet', `refs/tags/${pin.source_tag}`], { env: gitEnv, stdio: 'ignore' }).status !== 0) {
      git(['-C', repository, 'fetch', '--quiet', '--no-tags', COMMS, `refs/tags/${pin.source_tag}:refs/tags/${pin.source_tag}`]);
    }
  }
  if (pin.source_tag) {
    const tagged = git(['-C', repository, 'rev-parse', `refs/tags/${pin.source_tag}^{commit}`]).trim();
    if (tagged !== pin.source_commit) throw new Error('Darwin broker release tag does not name the pinned source commit');
  }
  const src = join(work, 'broker-source');
  git(['init', '--quiet', src]);
  git(['-C', src, 'fetch', '--quiet', '--no-tags', '--update-shallow', repository, pin.source_commit]);
  git(['-C', src, 'checkout', '--quiet', '--detach', 'FETCH_HEAD']);
  if (git(['-C', src, 'rev-parse', 'HEAD']).trim() !== pin.source_commit) throw new Error('unexpected broker source commit');
  return src;
}

export function stageDarwinBroker(tree, work) {
  const pin = JSON.parse(readFileSync(join(tree, 'governance/darwin-broker.json'), 'utf8'));
  if (pin.name !== 'agent-comms' || !/^\d+\.\d+\.\d+$/.test(pin.version) ||
      !/^sha256:[0-9a-f]{64}$/.test(pin.sha256) || pin.source_repository !== COMMS ||
      !/^[0-9a-f]{40}$/.test(pin.source_commit) ||
      (pin.source_tag !== undefined && (!/^v\d+\.\d+\.\d+$/.test(pin.source_tag) || pin.source_tag.slice(1) !== pin.version)) ||
      (pin.release_asset_sha256 !== undefined && !/^sha256:[0-9a-f]{64}$/.test(pin.release_asset_sha256))) throw new Error('invalid Darwin broker pin');
  const src = stageSource(pin, work);
  const plugins = join(tree, 'vendor/plugins');
  mkdirSync(plugins);
  execFileSync(process.execPath, [join(src, 'scripts/build-hq-plugin.mjs'), plugins], { cwd: src, env: {}, stdio: ['ignore', 'inherit', 'inherit'] });
  const dir = join(plugins, pin.name);
  if (readdirSync(plugins).length !== 1 || !lstatSync(dir).isDirectory() || treeDigest(dir) !== pin.sha256) {
    throw new Error('built broker tree differs from its reviewed pin');
  }
  const manifest = JSON.parse(readFileSync(join(dir, 'plugin.json'), 'utf8'));
  if (manifest.name !== pin.name || manifest.version !== pin.version) throw new Error('broker manifest identity mismatch');
  const policyPath = join(tree, 'governance/plugins.json');
  const policy = readPins(policyPath);
  const existing = policy.plugins.find((p) => p.name === pin.name);
  if (existing && (existing.version !== pin.version || existing.sha256 !== pin.sha256)) throw new Error('conflicting broker policy');
  if (!existing) policy.plugins.push({ name: pin.name, version: pin.version, sha256: pin.sha256 });
  writeFileSync(policyPath, JSON.stringify(policy, null, 2) + '\n');
  return pin;
}
