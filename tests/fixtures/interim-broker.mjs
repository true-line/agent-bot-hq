// Supply a real local Git source and a separately computed expected plugin tree
// for the release builder fixture. No credentials or external source are used.
import { execFileSync } from 'node:child_process';
import { cpSync, mkdirSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { treeDigest } from '../../hq/plugins.mjs';

export function fixtureBroker(repo, tmp, root) {
  const src = join(tmp, 'comms');
  const template = join(src, 'plugin');
  mkdirSync(template, { recursive: true });
  mkdirSync(join(src, 'scripts'));
  const identity = { name: 'agent-comms', version: '0.0.1' };
  writeFileSync(join(template, 'plugin.json'), JSON.stringify(identity));
  writeFileSync(join(template, 'plugin.mjs'), 'export default {};\n');
  writeFileSync(join(src, 'scripts/build-hq-plugin.mjs'), [
    "import { cpSync } from 'node:fs';",
    "import { join } from 'node:path';",
    "cpSync(new URL('../plugin/', import.meta.url), join(process.argv[2], 'agent-comms'), { recursive: true });",
  ].join('\n'));
  const git = (...args) => execFileSync('git', args, { cwd: src, encoding: 'utf8' }).trim();
  git('init', '-q');
  git('add', '.');
  git('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', '-c', 'commit.gpgSign=false', 'commit', '-qm', 'fixture broker');
  const broker = { ...identity, sha256: treeDigest(template), source_repository: 'https://github.com/true-line/agent-bot-comms.git', source_commit: git('rev-parse', 'HEAD') };
  cpSync(join(root, 'scripts/darwin-broker.mjs'), join(repo, 'scripts/darwin-broker.mjs'));
  cpSync(join(root, 'hq/plugins.mjs'), join(repo, 'hq/plugins.mjs'));
  cpSync(join(root, 'sdk'), join(repo, 'sdk'), { recursive: true });
  cpSync(join(root, 'governance/plugins.json'), join(repo, 'governance/plugins.json'));
  writeFileSync(join(repo, 'governance/darwin-broker.json'), JSON.stringify(broker));
  writeFileSync(join(repo, '.gitignore'), '.cache/\n');
  mkdirSync(join(repo, '.cache'));
  git('clone', '-q', '--bare', src, join(repo, '.cache/comms-broker.git'));
  return broker;
}
