import assert from 'node:assert/strict';
import { execFileSync, spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { test } from 'node:test';
import { fileURLToPath } from 'node:url';

const generator = fileURLToPath(new URL('../scripts/build-homebrew-formula.mjs', import.meta.url));

test('the HQ formula pins the approved public Darwin archive and retains it for service setup', () => {
  const dir = mkdtempSync(join(tmpdir(), 'hq-homebrew-formula-'));
  try {
    const governance = join(dir, 'hq', 'governance');
    const archive = join(dir, 'artifact.tar');
    mkdirSync(governance, { recursive: true });
    const build = (target, privateCandidate = false) => {
      writeFileSync(join(governance, 'interim-release.json'), JSON.stringify({
        schema_version: 1, target_platform: target, owner_control_capability: 'darwin-owner-control/v2',
      }));
      writeFileSync(join(governance, 'soul-contracts.json'), JSON.stringify({ private_candidate: privateCandidate }));
      execFileSync('tar', ['-cf', archive, '-C', dir, 'hq']);
      return createHash('sha256').update(readFileSync(archive)).digest('hex');
    };
    const render = (digest) => spawnSync(process.execPath, [generator, '1.2.3', archive, digest], { encoding: 'utf8' });
    const digest = build('darwin');
    const formula = render(digest);
    assert.equal(formula.status, 0, formula.stderr);
    assert.match(formula.stdout, /class AgentBotHq < Formula/);
    assert.ok(formula.stdout.includes(`sha256 "${digest}"`));
    assert.ok(formula.stdout.includes('/releases/download/v1.2.3/agent-bot-hq-1.2.3-darwin-arm64.tar'));
    assert.match(formula.stdout, /using: :nounzip/);
    assert.match(formula.stdout, /"agent-bot-hq-1.2.3-darwin-arm64.tar" => "agent-bot-hq-darwin-arm64.tar"/);
    assert.match(formula.stdout, /agent-bot-hq check-owner-control/);
    for (const [refused, reason] of [
      [render('0'.repeat(64)), /approved SHA-256/],
      [render(build('linux')), /requires a public Darwin HQ artifact/],
      [render(build('darwin', true)), /requires a public Darwin HQ artifact/],
    ]) {
      assert.equal(refused.status, 1);
      assert.equal(refused.stdout, '');
      assert.match(refused.stderr, reason);
    }
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
});
